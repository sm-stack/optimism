//! The [`DependencyGate`] stage: holds a block whose transactions declare [EIP-8288]
//! dependencies until the aggregate responsible for it is found.
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use super::{DependencyScanner, Responsible};
use crate::{
    AttributesProvider, BatchStreamProvider, L2ChainProvider, OriginAdvancer, OriginProvider,
    PipelineError, PipelineErrorKind, PipelineResult, Stage,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloy_eips::BlockNumHash;
use alloy_primitives::{Bytes, keccak256, map::HashSet};
use async_trait::async_trait;
use core::fmt::Debug;
use kona_genesis::{RollupConfig, SystemConfig};
use kona_protocol::{BlockInfo, L2BlockInfo, SingleBatch};
use op_alloy_consensus::{DeclaredDependencies, ProofStatement, declared_dependencies};

/// A batch the gate holds while its block is undecided.
#[derive(Debug, Clone)]
struct Held {
    batch: SingleBatch,
    /// The L1 origin the batch was read at.
    inclusion: BlockInfo,
    is_last_in_span: bool,
}

/// Holds a batch whose transactions declare dependencies until the [`DependencyScanner`]
/// finds the aggregate responsible for its block. A block is invalid unless that aggregate proves
/// every dependency its transactions declare, and the gate then passes its batch on with no
/// transactions: the block holds only its deposits.
///
/// Such a batch is the last of its channel: the gate flushes the channel, as Holocene does after
/// replacing an invalid block, since the batches after it were built on the block as the sequencer
/// made it. Every other batch passes through unchanged.
#[derive(Debug)]
pub struct DependencyGate<P, S, F> {
    cfg: Arc<RollupConfig>,
    prev: P,
    scanner: DependencyScanner<S>,
    l2: F,
    held: Option<Held>,
    is_last_in_span: bool,
    /// The latest L1 block a decision since the last reset needed. Blocks derived after a decided
    /// block are derived from at least that L1 block.
    decided_at: Option<BlockInfo>,
}

impl<P, S, F> DependencyGate<P, S, F> {
    /// Creates a gate over `prev`.
    pub const fn new(
        cfg: Arc<RollupConfig>,
        prev: P,
        scanner: DependencyScanner<S>,
        l2: F,
    ) -> Self {
        Self { cfg, prev, scanner, l2, held: None, is_last_in_span: false, decided_at: None }
    }
}

/// The transactions of `batch` that declare dependencies.
pub(super) fn dependent_txs(batch: &SingleBatch) -> Vec<(&Bytes, DeclaredDependencies)> {
    batch
        .transactions
        .iter()
        .filter_map(|tx| declared_dependencies(tx).map(|declared| (tx, declared)))
        .collect()
}

/// The scanner handles the end of an L1 block itself; an `Eof` reaching the pipeline would make it
/// advance its own origin.
fn without_eof(err: PipelineErrorKind) -> PipelineErrorKind {
    match err {
        PipelineErrorKind::Temporary(PipelineError::Eof) => PipelineError::NotEnoughData.temp(),
        err => err,
    }
}

impl<P, S, F> DependencyGate<P, S, F>
where
    P: AttributesProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    S: BatchStreamProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    F: L2ChainProvider + Send + Debug,
{
    /// Whether the block of the batch in `held` is valid: every dependency its transactions declare
    /// is proven by the responsible aggregate, or proof aggregation is not active.
    async fn decide(&mut self, parent: L2BlockInfo, held: &Held) -> PipelineResult<bool> {
        let dependent = dependent_txs(&held.batch);
        if dependent.is_empty() || !self.cfg.is_proof_aggregation_active(held.batch.timestamp) {
            return Ok(true);
        }
        let system_config: SystemConfig = self
            .l2
            .system_config_by_l2_hash(parent.block_info.hash, Arc::clone(&self.cfg))
            .await
            .map_err(Into::into)?;
        let block = parent.block_info.number + 1;
        let proven: HashSet<ProofStatement> =
            match self.scanner.responsible(block, held.inclusion, system_config).await? {
                Responsible::Proven(statements) => statements.into_iter().collect(),
                Responsible::None => HashSet::default(),
            };
        if let Some(at) = self.scanner.decided_at() &&
            self.decided_at.is_none_or(|decided| at.number > decided.number)
        {
            self.decided_at = Some(at);
        }
        let unproven = dependent.iter().find(|(_, declared)| {
            !declared.dependencies.iter().all(|dependency| {
                dependency.statement().is_some_and(|statement| proven.contains(&statement))
            })
        });
        if let Some((tx, _)) = unproven {
            let tx = keccak256(tx);
            warn!(target: "dependency_gate", %tx, block, "replacing a block with an unproven dependency with its deposits");
        }
        Ok(unproven.is_none())
    }
}

#[async_trait]
impl<P, S, F> AttributesProvider for DependencyGate<P, S, F>
where
    P: AttributesProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    S: BatchStreamProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    F: L2ChainProvider + Send + Debug,
{
    async fn next_batch(&mut self, parent: L2BlockInfo) -> PipelineResult<SingleBatch> {
        let held = match self.held.take() {
            Some(held) => held,
            None => {
                let batch = self.prev.next_batch(parent).await?;
                let inclusion = self.prev.origin().ok_or(PipelineError::MissingOrigin.crit())?;
                Held { batch, inclusion, is_last_in_span: self.prev.is_last_in_span() }
            }
        };
        let valid = match self.decide(parent, &held).await {
            Ok(valid) => valid,
            Err(err) => {
                self.held = Some(held);
                return Err(without_eof(err));
            }
        };
        let Held { mut batch, is_last_in_span, .. } = held;
        if valid {
            self.is_last_in_span = is_last_in_span;
            return Ok(batch);
        }
        batch.transactions.clear();
        self.prev.flush_channel().await?;
        self.is_last_in_span = true;
        Ok(batch)
    }

    fn is_last_in_span(&self) -> bool {
        self.is_last_in_span
    }

    fn decided_at(&self) -> Option<BlockInfo> {
        self.decided_at
    }
}

#[async_trait]
impl<P, S, F> OriginAdvancer for DependencyGate<P, S, F>
where
    P: AttributesProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    S: Send,
    F: Send,
{
    async fn advance_origin(&mut self) -> PipelineResult<()> {
        self.prev.advance_origin().await
    }
}

impl<P, S, F> OriginProvider for DependencyGate<P, S, F>
where
    P: OriginProvider,
{
    fn origin(&self) -> Option<BlockInfo> {
        self.prev.origin()
    }
}

#[async_trait]
impl<P, S, F> Stage for DependencyGate<P, S, F>
where
    P: AttributesProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    S: BatchStreamProvider + OriginAdvancer + OriginProvider + Stage + Send + Debug,
    F: Send,
{
    async fn reset(
        &mut self,
        l1_origin: BlockNumHash,
        system_config: SystemConfig,
    ) -> PipelineResult<()> {
        self.held = None;
        self.is_last_in_span = false;
        self.decided_at = None;
        self.scanner.clear();
        self.prev.reset(l1_origin, system_config).await
    }

    async fn activate(&mut self) -> PipelineResult<()> {
        self.held = None;
        self.scanner.clear();
        self.prev.activate().await
    }

    async fn flush_channel(&mut self) -> PipelineResult<()> {
        self.held = None;
        self.prev.flush_channel().await
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::*, *};
    use crate::test_utils::TestL2ChainProvider;
    use alloc::{collections::VecDeque, vec};
    use alloy_primitives::B256;
    use kona_protocol::Batch;

    /// Hands out singular batches read at L1 origin `origin`, and counts flushes.
    #[derive(Debug, Default)]
    struct Prev {
        batches: VecDeque<SingleBatch>,
        origin: u64,
        flushes: usize,
        reads: usize,
    }

    #[async_trait]
    impl AttributesProvider for Prev {
        async fn next_batch(&mut self, _: L2BlockInfo) -> PipelineResult<SingleBatch> {
            self.reads += 1;
            self.batches.pop_front().ok_or(PipelineError::Eof.temp())
        }

        fn is_last_in_span(&self) -> bool {
            false
        }
    }

    #[async_trait]
    impl OriginAdvancer for Prev {
        async fn advance_origin(&mut self) -> PipelineResult<()> {
            Ok(())
        }
    }

    impl OriginProvider for Prev {
        fn origin(&self) -> Option<BlockInfo> {
            Some(l1(self.origin))
        }
    }

    #[async_trait]
    impl Stage for Prev {
        async fn reset(&mut self, _: BlockNumHash, _: SystemConfig) -> PipelineResult<()> {
            Ok(())
        }

        async fn activate(&mut self) -> PipelineResult<()> {
            Ok(())
        }

        async fn flush_channel(&mut self) -> PipelineResult<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    const PARENT: B256 = B256::repeat_byte(0xbb);

    /// The parent of L2 block 5.
    fn parent() -> L2BlockInfo {
        L2BlockInfo {
            block_info: BlockInfo { number: 4, hash: PARENT, ..Default::default() },
            ..Default::default()
        }
    }

    /// A gate whose next batch is block 5 with `txs`, read at L1 block 0, over scan `blocks`.
    fn gate(
        txs: Vec<Bytes>,
        blocks: Vec<Vec<Batch>>,
    ) -> DependencyGate<Prev, Stack, TestL2ChainProvider> {
        let mut cfg = RollupConfig { block_time: 2, channel_timeout: 2, ..Default::default() };
        cfg.hardforks.lagoon_time = Some(0);
        let cfg = Arc::new(cfg);
        let mut l2 = TestL2ChainProvider::default();
        l2.system_configs.insert(PARENT, SystemConfig::default());
        let prev = Prev {
            batches: VecDeque::from([SingleBatch {
                timestamp: 10,
                transactions: txs,
                ..Default::default()
            }]),
            ..Default::default()
        };
        let scanner = DependencyScanner::with_limits(
            Stack { blocks, ..Default::default() },
            Arc::clone(&cfg),
            Some(Arc::new(Verifier)),
            3,
            u64::MAX,
        );
        DependencyGate::new(cfg, prev, scanner, l2)
    }

    #[tokio::test]
    async fn a_batch_without_dependencies_passes_without_a_scan() {
        let plain = Bytes::from_static(&[0x02, 0xc0]);
        let mut gate = gate(vec![plain.clone(), aa_tx(0, &[])], vec![]);
        let batch = gate.next_batch(parent()).await.unwrap();
        assert_eq!(batch.transactions, vec![plain, aa_tx(0, &[])]);
        assert!(gate.scanner_resets().is_empty());
        assert_eq!(gate.decided_at(), None);
    }

    #[tokio::test]
    async fn a_covered_batch_passes_unchanged() {
        let tx = aa_tx(0, &[statement(1)]);
        let blocks = vec![vec![batch(6, vec![]), aggregate(5, &[statement(1)], b"ok")], vec![]];
        let mut gate = gate(vec![tx.clone()], blocks);
        let batch = gate.next_batch(parent()).await.unwrap();
        assert_eq!(batch.transactions, vec![tx]);
        assert_eq!(gate.prev.flushes, 0);
        assert!(!gate.is_last_in_span());
        assert_eq!(gate.decided_at(), Some(l1(0)), "decided by the aggregate at L1 block 0");
    }

    /// A plain transaction and a proven one leave with the unproven one: the block holds only
    /// deposits.
    #[tokio::test]
    async fn an_unproven_dependency_empties_the_batch_and_flushes_the_channel() {
        let plain = Bytes::from_static(&[0x02, 0xc0]);
        let proven = aa_tx(0, &[statement(1)]);
        let unproven = aa_tx(1, &[statement(1), statement(2)]);
        let blocks = vec![vec![batch(6, vec![]), aggregate(5, &[statement(1)], b"ok")], vec![]];
        let mut gate = gate(vec![plain, proven, unproven], blocks);
        let batch = gate.next_batch(parent()).await.unwrap();
        assert!(batch.transactions.is_empty());
        assert_eq!(gate.prev.flushes, 1);
        assert!(gate.is_last_in_span());
    }

    #[tokio::test]
    async fn a_block_decided_at_the_window_end_is_derived_from_there() {
        let tx = aa_tx(0, &[statement(1)]);
        let mut gate = gate(vec![tx], vec![vec![], vec![], vec![], vec![], vec![]]);
        let batch = gate.next_batch(parent()).await.unwrap();
        assert!(batch.transactions.is_empty());
        assert_eq!(gate.decided_at(), Some(l1(3)), "the window of 3 ends at L1 block 3");
    }

    #[tokio::test]
    async fn an_undecided_batch_is_held() {
        let tx = aa_tx(0, &[statement(1)]);
        let mut gate = gate(vec![tx.clone()], vec![vec![], vec![]]);
        assert_eq!(gate.next_batch(parent()).await.unwrap_err(), PipelineError::EndOfSource.crit());
        assert_eq!(gate.next_batch(parent()).await.unwrap_err(), PipelineError::EndOfSource.crit());
        assert_eq!(gate.prev.reads, 1, "the held batch is not read again");

        gate.flush_channel().await.unwrap();
        assert_eq!(gate.next_batch(parent()).await.unwrap_err(), PipelineError::Eof.temp());
    }

    #[tokio::test]
    async fn the_latest_decision_holds_until_reset() {
        let tx = aa_tx(0, &[statement(1)]);
        let mut gate = gate(vec![tx], vec![vec![], vec![], vec![], vec![], vec![]]);
        gate.prev.batches.push_back(SingleBatch { timestamp: 12, ..Default::default() });
        gate.next_batch(parent()).await.unwrap();
        let mut next_parent = parent();
        next_parent.block_info.number = 5;
        gate.next_batch(next_parent).await.unwrap();
        assert_eq!(
            gate.decided_at(),
            Some(l1(3)),
            "the block after a decided one is derived from at least the same L1 block"
        );

        gate.reset(BlockNumHash::default(), SystemConfig::default()).await.unwrap();
        assert_eq!(gate.decided_at(), None);
    }

    impl<P, F> DependencyGate<P, Stack, F> {
        fn scanner_resets(&self) -> &[u64] {
            self.scanner.stack_resets()
        }
    }
}
