//! The [`DependencyScanner`]: finds the proof aggregate responsible for a block's [EIP-8288]
//! dependencies in the batcher data that follows it on L1.
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use crate::{
    BatchStreamProvider, OriginAdvancer, OriginProvider, PipelineError, PipelineErrorKind,
    PipelineResult, Stage,
};
use alloc::{collections::VecDeque, vec::Vec};
use alloy_eips::BlockNumHash;
use alloy_primitives::{B256, Bytes, keccak256, map::HashMap};
use alloy_rlp::Encodable;
use core::fmt::Debug;
use kona_genesis::{RollupConfig, SystemConfig};
use kona_protocol::{Batch, BlockInfo};
use op_alloy_consensus::{ProofAggregatePayload, ProofStatement, SharedProofAggregateVerifier};

use kona_genesis::DEPENDENCY_SCAN_WINDOW;

/// Upper bound on the transaction and aggregate payload bytes a scan decodes after the batch's L1
/// block before it gives up, which bounds the work a block can demand of the proof programs. Only
/// the batcher can post the data a scan reads, but the cap binds an honest sequencer too: every
/// block between a dependent transaction and its aggregate counts, so the sequencer must aggregate
/// before that much transaction data piles up.
pub const DEPENDENCY_SCAN_BYTE_CAP: u64 = 16 * 1024 * 1024;

/// What a scan found for a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Responsible {
    /// The responsible aggregate verified; these are the statements it proves.
    Proven(Vec<ProofStatement>),
    /// No aggregate answers for the block within the window or the byte cap, or the one that does
    /// carries an invalid proof: none of the block's dependencies are proven.
    None,
}

/// A proof aggregate found by the scan.
#[derive(Debug, Clone)]
struct ScannedAggregate {
    /// L1 block whose data completed the aggregate's channel.
    origin: BlockInfo,
    /// Bytes decoded before this aggregate since the scan started.
    bytes_before: u64,
    /// The hash of the aggregate's encoding, once it is verified.
    hash: Option<B256>,
    payload: ProofAggregatePayload,
}

/// Finds the proof aggregate responsible for a block's dependencies.
///
/// For a block `B` whose batch was read at L1 origin `I`, the scan decodes, with the pipeline's own
/// frame and channel rules and without validating any batch, the batcher data of the channels
/// completed in L1 blocks `I` to `I + window` (reading from `channel_timeout` blocks before `I`
/// so that those channels assemble). The responsible aggregate is the first proof aggregate batch
/// among them whose `through` reaches `B`, found within `byte_cap` decoded bytes (transactions and
/// aggregate payloads). The answer depends only on `I` and L1 data, never on the pipeline's own
/// state, so a node that derived continuously and a proof that started at any block agree.
///
/// The stack is any batch decoder over L1 (in the pipeline, a second traversal through
/// `ChannelReader`). The scanner runs it forward only and caches what it decoded, so consecutive
/// blocks share one pass.
#[derive(Debug)]
pub struct DependencyScanner<S> {
    stack: S,
    cfg: alloc::sync::Arc<RollupConfig>,
    verifier: Option<SharedProofAggregateVerifier>,
    window: u64,
    byte_cap: u64,
    /// The L1 block the current pass serves from, if a pass is running.
    anchor: Option<u64>,
    /// Aggregates decoded so far in this pass, in scan order.
    aggregates: VecDeque<ScannedAggregate>,
    /// For each L1 origin seen, the bytes decoded before its first batch.
    origin_bytes: Vec<(u64, u64)>,
    /// Transaction and aggregate payload bytes decoded in this pass.
    bytes: u64,
    /// The highest L1 block whose batcher data the pass has fully decoded.
    scanned_through: Option<BlockInfo>,
    /// The last L1 block the latest decision needed.
    decided_at: Option<BlockInfo>,
    /// Verification results by aggregate hash.
    verified: HashMap<B256, bool>,
}

impl<S> DependencyScanner<S>
where
    S: BatchStreamProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
{
    /// Creates a scanner over `stack` with the default window and byte cap.
    pub fn new(
        stack: S,
        cfg: alloc::sync::Arc<RollupConfig>,
        verifier: Option<SharedProofAggregateVerifier>,
    ) -> Self {
        Self::with_limits(stack, cfg, verifier, DEPENDENCY_SCAN_WINDOW, DEPENDENCY_SCAN_BYTE_CAP)
    }

    /// Creates a scanner with an explicit window and byte cap.
    pub(crate) fn with_limits(
        stack: S,
        cfg: alloc::sync::Arc<RollupConfig>,
        verifier: Option<SharedProofAggregateVerifier>,
        window: u64,
        byte_cap: u64,
    ) -> Self {
        Self {
            stack,
            cfg,
            verifier,
            window,
            byte_cap,
            anchor: None,
            aggregates: VecDeque::new(),
            origin_bytes: Vec::new(),
            bytes: 0,
            scanned_through: None,
            decided_at: None,
            verified: HashMap::default(),
        }
    }

    /// The stack's reset history, for tests.
    #[cfg(test)]
    pub(super) fn stack_resets(&self) -> &[u64]
    where
        S: AsRef<[u64]>,
    {
        self.stack.as_ref()
    }

    /// Drops the current pass, as after a pipeline reset.
    pub fn clear(&mut self) {
        self.anchor = None;
        self.aggregates.clear();
        self.origin_bytes.clear();
        self.bytes = 0;
        self.scanned_through = None;
        self.decided_at = None;
    }

    /// The last L1 block the latest decision needed: the block holding the responsible aggregate,
    /// or where the window or the byte cap ended. A block decided by the scan is derived from L1
    /// data up to here, not just up to where its batch was read.
    pub const fn decided_at(&self) -> Option<BlockInfo> {
        self.decided_at
    }

    /// Finds the aggregate responsible for block `block`, whose batch was read at L1 origin
    /// `inclusion`, and verifies it. `system_config` supplies the batcher address the scan starts
    /// with.
    ///
    /// # Errors
    ///
    /// Returns the L1 providers' errors when the data the scan needs is not available yet: a
    /// temporary error in a node, `EndOfSource` in a proof program whose L1 head ends before the
    /// window does. The block is then undecided.
    pub async fn responsible(
        &mut self,
        block: u64,
        inclusion: BlockInfo,
        system_config: SystemConfig,
    ) -> PipelineResult<Responsible> {
        if self.anchor.is_none_or(|anchor| inclusion.number < anchor) {
            self.start(inclusion, system_config).await?;
        } else {
            self.prune(inclusion.number);
            self.anchor = Some(inclusion.number);
        }
        let window_end = inclusion.number.saturating_add(self.window);
        loop {
            let start_bytes = self.bytes_at(inclusion.number);
            if let Some(index) = self.aggregates.iter().position(|aggregate| {
                aggregate.origin.number >= inclusion.number &&
                    aggregate.origin.number <= window_end &&
                    aggregate.payload.through >= block
            }) {
                let found = &self.aggregates[index];
                self.decided_at = Some(found.origin);
                if found.bytes_before - start_bytes >= self.byte_cap {
                    return Ok(Responsible::None);
                }
                return Ok(self.verify(index));
            }
            if self.bytes - start_bytes >= self.byte_cap {
                self.decided_at = self.stack.origin();
                return Ok(Responsible::None);
            }
            if let Some(through) = self.scanned_through &&
                through.number >= window_end
            {
                self.decided_at = Some(through);
                return Ok(Responsible::None);
            }
            self.step(window_end).await?;
        }
    }

    /// Restarts the pass `channel_timeout` L1 blocks before `inclusion`.
    async fn start(
        &mut self,
        inclusion: BlockInfo,
        system_config: SystemConfig,
    ) -> PipelineResult<()> {
        self.clear();
        let start = inclusion.number.saturating_sub(self.cfg.channel_timeout(inclusion.timestamp));
        self.stack.reset(BlockNumHash { number: start, hash: B256::ZERO }, system_config).await?;
        self.anchor = Some(inclusion.number);
        Ok(())
    }

    /// Forgets what a later block can never need: blocks are decided in order, so their inclusion
    /// blocks never decrease within a pass.
    fn prune(&mut self, inclusion: u64) {
        while self.aggregates.front().is_some_and(|aggregate| aggregate.origin.number < inclusion) {
            self.aggregates.pop_front();
        }
        let first = self.origin_bytes.iter().position(|(number, _)| *number >= inclusion);
        self.origin_bytes.drain(..first.unwrap_or(self.origin_bytes.len()));
        let aggregates = &self.aggregates;
        self.verified
            .retain(|hash, _| aggregates.iter().any(|aggregate| aggregate.hash == Some(*hash)));
    }

    /// Bytes decoded before the first batch at or after L1 block `origin`.
    fn bytes_at(&self, origin: u64) -> u64 {
        self.origin_bytes
            .iter()
            .find(|(number, _)| *number >= origin)
            .map_or(self.bytes, |(_, bytes)| *bytes)
    }

    /// Decodes the next batch, or moves to the next L1 block when the current one is done and is
    /// not the last of the window: the decision needs no L1 block past that one, which may not
    /// exist.
    async fn step(&mut self, window_end: u64) -> PipelineResult<()> {
        let origin = self.stack.origin().ok_or(PipelineError::MissingOrigin.crit())?;
        match self.stack.next_batch().await {
            Ok(batch) => {
                self.record(origin, batch);
                Ok(())
            }
            Err(PipelineErrorKind::Temporary(PipelineError::Eof)) => {
                self.scanned_through = Some(origin);
                if origin.number >= window_end {
                    return Ok(());
                }
                self.stack.advance_origin().await
            }
            // The channel reader drops a malformed channel and asks to be called again.
            Err(PipelineErrorKind::Temporary(PipelineError::NotEnoughData)) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn record(&mut self, origin: BlockInfo, batch: Batch) {
        if self.origin_bytes.last().is_none_or(|(number, _)| *number < origin.number) {
            self.origin_bytes.push((origin.number, self.bytes));
        }
        let bytes =
            |txs: &[Bytes]| txs.iter().map(|tx| tx.len() as u64).fold(0, u64::saturating_add);
        let decoded = match batch {
            Batch::Single(single) => bytes(&single.transactions),
            Batch::Span(span) => span
                .batches
                .iter()
                .map(|element| bytes(&element.transactions))
                .fold(0, u64::saturating_add),
            Batch::ProofAggregate(payload) => {
                // The payload decoded exactly, so its encoded length is the bytes the batcher
                // posted.
                let length = payload.length() as u64;
                self.aggregates.push_back(ScannedAggregate {
                    origin,
                    bytes_before: self.bytes,
                    hash: None,
                    payload,
                });
                length
            }
        };
        self.bytes = self.bytes.saturating_add(decoded);
    }

    /// Verifies the aggregate at `index`, once per hash. Only an aggregate within the limits is
    /// hashed, so an oversized one costs no more than its decoding.
    fn verify(&mut self, index: usize) -> Responsible {
        let Some(verifier) = self.verifier.clone() else { return Responsible::None };
        let aggregate = &mut self.aggregates[index];
        if aggregate.payload.check_limits().is_err() {
            return Responsible::None;
        }
        let hash =
            *aggregate.hash.get_or_insert_with(|| keccak256(aggregate.payload.to_rlp_bytes()));
        let valid = *self
            .verified
            .entry(hash)
            .or_insert_with(|| aggregate.payload.verify(verifier.as_ref()).is_ok());
        if valid {
            Responsible::Proven(aggregate.payload.statements.clone())
        } else {
            Responsible::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::*, *};
    use alloc::{sync::Arc, vec};

    /// A scanner over `blocks` with a channel timeout of 2, a window of 3 and `cap` bytes.
    fn scanner(blocks: Vec<Vec<Batch>>, cap: u64) -> DependencyScanner<Stack> {
        let cfg = RollupConfig { block_time: 2, channel_timeout: 2, ..Default::default() };
        DependencyScanner::with_limits(
            Stack { blocks, ..Default::default() },
            Arc::new(cfg),
            Some(Arc::new(Verifier)),
            3,
            cap,
        )
    }

    async fn responsible(
        scanner: &mut DependencyScanner<Stack>,
        block: u64,
        inclusion: u64,
    ) -> PipelineResult<Responsible> {
        scanner.responsible(block, l1(inclusion), SystemConfig::default()).await
    }

    #[tokio::test]
    async fn finds_the_first_aggregate_reaching_the_block() {
        let blocks = vec![
            vec![],
            vec![],
            vec![],
            vec![batch(5, vec![])],
            vec![batch(6, vec![]), aggregate(4, &[statement(9)], b"ok")],
            vec![batch(7, vec![]), aggregate(6, &[statement(1)], b"ok")],
            vec![batch(8, vec![]), aggregate(8, &[statement(2)], b"ok")],
            vec![],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(
            responsible(&mut scanner, 5, 3).await.unwrap(),
            Responsible::Proven(vec![statement(1)]),
            "the aggregate through 4 does not reach block 5; the one through 6 does"
        );
        assert_eq!(scanner.stack.resets, vec![1], "the pass starts a channel timeout early");
    }

    #[tokio::test]
    async fn an_aggregate_in_the_block_itself_counts() {
        let blocks =
            vec![vec![], vec![batch(5, vec![]), aggregate(5, &[statement(1)], b"ok")], vec![]];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(
            responsible(&mut scanner, 5, 1).await.unwrap(),
            Responsible::Proven(vec![statement(1)])
        );
    }

    #[tokio::test]
    async fn an_invalid_proof_proves_nothing_and_no_later_aggregate_is_consulted() {
        let blocks = vec![
            vec![batch(5, vec![])],
            vec![batch(6, vec![]), aggregate(6, &[statement(1)], b"bad")],
            vec![batch(7, vec![]), aggregate(7, &[statement(1)], b"ok")],
            vec![],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(responsible(&mut scanner, 5, 0).await.unwrap(), Responsible::None);
    }

    #[tokio::test]
    async fn data_before_the_inclusion_block_is_ignored() {
        let blocks = vec![
            vec![batch(9, vec![]), aggregate(9, &[statement(1)], b"ok")],
            vec![batch(5, vec![])],
            vec![],
            vec![],
            vec![],
            vec![],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(responsible(&mut scanner, 5, 1).await.unwrap(), Responsible::None);
    }

    #[tokio::test]
    async fn aggregate_payloads_count_towards_the_byte_cap() {
        let blocks = vec![
            vec![batch(5, vec![]), aggregate(4, &[statement(9)], &[0; 200])],
            vec![batch(6, vec![]), aggregate(6, &[statement(1)], b"ok")],
            vec![],
        ];
        let mut scanner = scanner(blocks, 150);
        assert_eq!(
            responsible(&mut scanner, 5, 0).await.unwrap(),
            Responsible::None,
            "the aggregate through 4 used up the byte cap"
        );
    }

    #[tokio::test]
    async fn the_window_closing_without_an_aggregate_proves_nothing() {
        let blocks = vec![
            vec![batch(5, vec![])],
            vec![],
            vec![],
            vec![],
            vec![batch(6, vec![]), aggregate(6, &[statement(1)], b"ok")],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(
            responsible(&mut scanner, 5, 0).await.unwrap(),
            Responsible::None,
            "the aggregate lands at L1 block 4, past the window of 3"
        );
    }

    #[tokio::test]
    async fn the_block_is_decided_with_l1_ending_at_the_window_end() {
        let blocks = vec![vec![batch(5, vec![])], vec![], vec![], vec![]];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(responsible(&mut scanner, 5, 0).await.unwrap(), Responsible::None);
        assert_eq!(scanner.decided_at(), Some(l1(3)));
    }

    #[tokio::test]
    async fn a_later_block_goes_on_past_a_window_end() {
        let blocks = vec![
            vec![batch(5, vec![])],
            vec![],
            vec![],
            vec![],
            vec![batch(6, vec![]), aggregate(6, &[statement(1)], b"ok")],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(responsible(&mut scanner, 5, 0).await.unwrap(), Responsible::None);
        assert_eq!(
            responsible(&mut scanner, 6, 1).await.unwrap(),
            Responsible::Proven(vec![statement(1)]),
            "the aggregate at L1 block 4 is within the later window"
        );
    }

    #[tokio::test]
    async fn the_block_is_undecided_while_the_window_is_not_on_l1() {
        let blocks = vec![vec![batch(5, vec![])], vec![]];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(
            responsible(&mut scanner, 5, 0).await.unwrap_err(),
            PipelineError::EndOfSource.crit()
        );
    }

    #[tokio::test]
    async fn the_byte_cap_ends_the_scan() {
        let padding = Bytes::from(vec![0u8; 100]);
        let blocks = vec![
            vec![batch(5, vec![padding.clone()])],
            vec![batch(6, vec![padding])],
            vec![batch(7, vec![]), aggregate(7, &[statement(1)], b"ok")],
            vec![],
        ];
        let mut scanner = scanner(blocks, 150);
        assert_eq!(responsible(&mut scanner, 5, 0).await.unwrap(), Responsible::None);
    }

    #[tokio::test]
    async fn consecutive_blocks_share_a_pass() {
        let blocks = vec![
            vec![batch(5, vec![]), batch(6, vec![])],
            vec![batch(7, vec![]), aggregate(6, &[statement(1)], b"ok")],
            vec![batch(8, vec![]), aggregate(8, &[statement(2)], b"ok")],
            vec![],
        ];
        let mut scanner = scanner(blocks, u64::MAX);
        assert_eq!(
            responsible(&mut scanner, 5, 0).await.unwrap(),
            Responsible::Proven(vec![statement(1)])
        );
        assert_eq!(
            responsible(&mut scanner, 6, 0).await.unwrap(),
            Responsible::Proven(vec![statement(1)])
        );
        assert_eq!(
            responsible(&mut scanner, 7, 1).await.unwrap(),
            Responsible::Proven(vec![statement(2)])
        );
        assert_eq!(scanner.stack.resets, vec![0], "one pass served all three");

        // An earlier inclusion block starts a new pass.
        responsible(&mut scanner, 5, 0).await.unwrap();
        assert_eq!(scanner.stack.resets, vec![0, 0]);
    }
}
