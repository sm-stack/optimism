//! The aggregation loop: folds the statement sources of sealed blocks into a tree root as the
//! blocks come, then closes, seals and submits the root as an aggregate.

use crate::{
    ahead::{Ahead, ProveAhead},
    api::{AggregatorError, BlockId, BlockStatements, Source, StatementRef},
    backend::Backend,
};
use alloy_primitives::B256;
use op_alloy_consensus::{
    LEANVM_TREE_CLASS_KEY_DIGEST, MAX_PROOF_AGGREGATE_STATEMENTS, MAX_STATEMENT_PROOF_BYTES,
    MAX_STATEMENT_VERIFYING_KEY_BYTES, PROOF_AGGREGATE_PAYLOAD_VERSION, PendingAggregate,
    ProofAggregatePayload, ProofStatement, TARGET_PROOF_AGGREGATE_STATEMENTS,
};
use op_leanvm_tree::{Aggregator, BlockItem, ProgramRef, Signed, TreeAggregate};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

/// How long a run keeps folding blocks after its first before it closes, if it does not fill
/// first: closing every block alone would fill the aggregate queue.
pub const AGGREGATE_DELAY: Duration = Duration::from_secs(20);

/// How often the folder looks for blocks to fold.
const POLL: Duration = Duration::from_secs(1);

/// How often op-aggregator asks the sequencer's status whatever it is doing, folding, sealing or
/// backing off: every request tells the sequencer op-aggregator is there, and without one for
/// several beats (op-reth's `AGGREGATOR_TIMEOUT`) the sequencer takes no dependent transaction.
pub const HEARTBEAT: Duration = Duration::from_secs(5);

/// The longest the folder backs off after failing to fold or prove.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The most sources one request fetches: a program leaf is up to half a megabyte.
const SOURCES_PER_REQUEST: usize = 32;

/// The most members a program leaf publishes.
const MAX_LEAF_MEMBERS: usize = op_leanvm_tree::CLASS_BOUNDS[op_leanvm_tree::PROGRAM_CLASS][4];

/// The largest response a client of the `aggregator` namespace needs to read: a request's worth of
/// the largest sources, hex-encoded, and a megabyte for the rest.
pub const MAX_RESPONSE_BYTES: u32 = (SOURCES_PER_REQUEST *
    2 *
    (MAX_STATEMENT_PROOF_BYTES + MAX_STATEMENT_VERIFYING_KEY_BYTES + 32 * MAX_LEAF_MEMBERS) +
    (1 << 20)) as u32;

/// Folds blocks into aggregates on `backend` for ever, backing off on failures.
///
/// Folding and proving take seconds and leanVM's worker pool, which spans every core unless
/// `LEANVM_NUM_THREADS` caps it, so they run on a blocking thread. The tree class is built on the
/// first block to fold. An aggregate closed while the queue is full is kept and submitted again
/// until the queue takes it; the next run folds the blocks after it meanwhile. A reorg that
/// replaces folded blocks drops the run, which folds again from the last queued aggregate. A
/// block that cannot be folded has its sources forgotten: later aggregates go past it, and
/// derivation replaces it. A failure backs off, doubling up to `MAX_BACKOFF`. Meanwhile a heartbeat
/// ([`HEARTBEAT`]) tells the sequencer op-aggregator is there. With `ahead`, helpers prove the
/// blocks' nodes ahead ([`ProveAhead`]).
pub async fn run<B: Backend + Clone>(backend: B, ahead: Option<ProveAhead>) {
    // The heartbeat lasts as long as the folder: both end when `run` is dropped.
    tokio::join!(heartbeat(backend.clone()), fold_blocks(backend, ahead));
}

/// Asks `backend` for the sequencer's status every [`HEARTBEAT`], for ever.
async fn heartbeat<B: Backend>(backend: B) {
    loop {
        if let Err(err) = backend.status().await {
            debug!(target: "op_aggregator", %err, "the sequencer did not answer the heartbeat");
        }
        tokio::time::sleep(HEARTBEAT).await;
    }
}

/// Folds blocks on `backend` for ever: [`run`]'s folder.
async fn fold_blocks<B: Backend>(backend: B, ahead: Option<ProveAhead>) {
    let mut folder = match &ahead {
        Some(options) => Folder::with_prove_ahead(backend, options),
        None => Folder::new(backend),
    };
    let mut backoff = Duration::ZERO;
    let mut answered = false;
    loop {
        tokio::time::sleep(backoff).await;
        backoff = loop {
            let result = folder.tick(Instant::now()).await;
            if result.is_ok() && !answered {
                answered = true;
                info!(target: "op_aggregator", "folding the sequencer's statements");
            }
            match result {
                // More blocks are waiting: fold them without sleeping.
                Ok(true) => {}
                Ok(false) => break POLL,
                Err(err) => {
                    warn!(target: "op_aggregator", %err, "could not aggregate statements");
                    folder.restart();
                    break (backoff * 2).clamp(POLL, MAX_BACKOFF);
                }
            }
        };
    }
}

/// The run of sealed blocks being folded into one tree root.
struct Run {
    aggregator: Aggregator,
    /// The last block folded.
    through: Option<BlockId>,
    /// When the run folded its first block.
    started: Option<Instant>,
    /// With fixed runs, the last block the run may hold.
    end: Option<u64>,
}

/// The last block of the fixed run holding block `number`, for runs of `run_blocks` blocks: the
/// next block `n` at or after `number` with `(n + 1) % run_blocks == 0`. op-batcher computes the
/// same block, so that the two meet there without asking each other.
const fn run_end(number: u64, run_blocks: u64) -> u64 {
    number / run_blocks * run_blocks + run_blocks - 1
}

/// An aggregate closed but not yet queued, and the block it answers through.
struct Kept {
    aggregate: PendingAggregate,
    through: BlockId,
}

/// The folder's state: the open run, and an aggregate closed but not yet queued.
pub struct Folder<B> {
    backend: B,
    run: Option<Run>,
    kept: Option<Kept>,
    /// The helpers proving first-level nodes ahead, if any.
    ahead: Option<Ahead>,
}

impl<B> std::fmt::Debug for Folder<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Folder")
            .field("through", &self.run.as_ref().and_then(|run| run.through))
            .field("kept", &self.kept.as_ref().map(|kept| kept.through))
            .finish_non_exhaustive()
    }
}

impl<B: Backend> Folder<B> {
    /// A folder with no open run.
    pub const fn new(backend: B) -> Self {
        Self { backend, run: None, kept: None, ahead: None }
    }

    /// A folder with no open run whose helpers prove the first-level nodes of the next blocks
    /// while it folds ([`ProveAhead`]). It folds what [`Self::new`]'s does, sooner.
    pub fn with_prove_ahead(backend: B, options: &ProveAhead) -> Self {
        Self { backend, run: None, kept: None, ahead: Ahead::start(options) }
    }

    /// How the first-level nodes proven ahead served the folds so far; `None` without helpers.
    pub fn prove_ahead_stats(&self) -> Option<op_leanvm_tree::FirstLevelStats> {
        self.ahead.as_ref().map(|ahead| ahead.cache.stats())
    }

    /// Drops the open run: the next tick starts from the last queued or kept aggregate.
    pub fn restart(&mut self) {
        self.run = None;
        if let Some(ahead) = &mut self.ahead {
            ahead.forget();
        }
    }

    /// Queues the kept aggregate if any, closes the run if it is due, and folds the next sealed
    /// block. Returns whether another block is waiting.
    pub async fn tick(&mut self, now: Instant) -> Result<bool, String> {
        if let Some(kept) = self.kept.take() {
            self.submit(kept).await;
        }
        let status = self.backend.status().await.map_err(err)?;
        let after =
            [self.run.as_ref().and_then(|run| run.through), self.kept.as_ref().map(|k| k.through)]
                .into_iter()
                .flatten()
                .max_by_key(|block| block.number);
        // This also tells whether the run's blocks are still canonical, before any closes.
        let next = match self.backend.next_provable_block(after).await {
            Err(AggregatorError::Reorged) => {
                debug!(target: "op_aggregator", "a reorg replaced folded blocks: folding again");
                self.run = None;
                self.kept = None;
                if let Some(ahead) = &mut self.ahead {
                    ahead.forget();
                }
                return Ok(true);
            }
            next => next.map_err(err)?,
        };
        let fixed = status.run_blocks > 0;
        // Bytes end a fixed run early only at a block that does not move: however late this prover
        // is, its runs span those bytes, and being late never makes it close more often. While an
        // aggregate is kept that block lies in the kept aggregate's blocks, not this run's.
        if self.kept.is_none() &&
            let (Some(run), Some(due)) = (&mut self.run, status.due_through)
        {
            run.end = run.end.map(|end| end.min(due));
        }
        // Without fixed runs a run closes after the delay, or when its bytes approach the pause.
        // A fixed run closes once every block up to its end is folded: the next provable block
        // is past the end, or the chain has reached the end with none left.
        let head = status.head.map(|head| head.number);
        let due = self.run.as_ref().is_some_and(|run| {
            if run.through.is_none() {
                return false;
            }
            let Some(end) = run.end else {
                return status.bytes_due ||
                    run.started
                        .is_some_and(|started| now.duration_since(started) >= AGGREGATE_DELAY);
            };
            next.as_ref().map_or_else(
                || head.is_some_and(|head| head >= end),
                |next| next.block.number > end,
            )
        });
        if due && self.kept.is_none() && !status.queue_full {
            let run = self.run.take().expect("due");
            self.close(run).await?;
        }
        let Some(next) = next else { return Ok(false) };
        // A fixed run keeps its boundary while the queue is full or an aggregate is kept: the block
        // past it waits, so the prover falling behind leaves the aggregates whole.
        if self.run.as_ref().and_then(|run| run.end).is_some_and(|end| next.block.number > end) {
            return Ok(false);
        }
        let mut run = match self.run.take() {
            Some(run) => run,
            None => {
                let mut aggregator = blocking(|| {
                    Ok(Aggregator::new().unwrap_or_else(|err| {
                        panic!("the leanVM tree class does not build: {err}")
                    }))
                })
                .await?;
                if let Some(ahead) = &self.ahead {
                    aggregator.set_first_level_cache(ahead.cache.clone());
                }
                let end = fixed.then(|| run_end(next.block.number, status.run_blocks));
                Run { aggregator, through: None, started: None, end }
            }
        };
        if let Some(ahead) = &mut self.ahead {
            plan_ahead(&self.backend, ahead, &run.aggregator, &next, run.end).await;
        }
        // A fixed run shares a channel with its blocks: it may hold the class capacity rather than
        // what three blobs carry alone.
        run.aggregator.set_max_statements(if fixed {
            MAX_PROOF_AGGREGATE_STATEMENTS
        } else {
            TARGET_PROOF_AGGREGATE_STATEMENTS
        });
        let (sources, added) = self.new_sources(&run.aggregator, &next).await?;
        if !run.aggregator.fits(&added) {
            if run.aggregator.is_empty() {
                error!(target: "op_aggregator", block = next.block.number, "a block's statements do not fit one aggregate: forgetting them");
                self.forget(&next).await?;
                return Ok(true);
            }
            if self.kept.is_some() {
                // The block starts the next run, but the queue holds no room for this one: closing
                // it would replace the kept aggregate, whose blocks it does not cover.
                self.run = Some(run);
                return Ok(false);
            }
            // The block starts the next run; close this one first.
            self.close(run).await?;
            return Ok(true);
        }
        let started = Instant::now();
        let (mut run, result) = blocking(move || {
            let result = fold(&mut run.aggregator, &sources);
            Ok((run, result))
        })
        .await?;
        if let Err(reason) = result {
            // A block folds whole or not at all: the run goes on without it. A run that folded
            // nothing ends here, as its end may lie before the next block with statements.
            error!(target: "op_aggregator", block = next.block.number, %reason, "a block's statements do not fold: forgetting them");
            self.run = run.through.is_some().then_some(run);
            self.forget(&next).await?;
            return Ok(true);
        }
        debug!(target: "op_aggregator", block = next.block.number, statements = added.len(), elapsed = ?started.elapsed(), "folded a block's statements");
        run.through = Some(next.block);
        run.started.get_or_insert(now);
        self.run = Some(run);
        Ok(true)
    }

    /// The sources of `block`'s statements that `aggregator` does not hold yet, each once, fetched
    /// from the backend, and every statement folding them adds. Two transactions relying on one
    /// leaf name it by two ids: it is folded once.
    async fn new_sources(
        &mut self,
        aggregator: &Aggregator,
        block: &BlockStatements,
    ) -> Result<(Vec<Source>, HashSet<ProofStatement>), String> {
        let new: Vec<_> =
            block.statements.iter().filter(|s| !aggregator.contains(&s.statement)).collect();
        let ids: Vec<B256> =
            new.iter().map(|s| s.source).collect::<HashSet<_>>().into_iter().collect();
        // Those read ahead are taken; the rest are fetched now.
        let mut fetched = self.ahead.as_mut().map(|a| a.take_prefetched(&ids)).unwrap_or_default();
        let rest: Vec<B256> = ids.iter().filter(|id| !fetched.contains_key(*id)).copied().collect();
        for chunk in rest.chunks(SOURCES_PER_REQUEST) {
            let entries = self.backend.sources(chunk.to_vec()).await.map_err(err)?;
            fetched.extend(entries.into_iter().map(|entry| (entry.id, entry.source)));
        }
        let (sources, added) = order_sources(new, |id| fetched.get(id)).map_err(|id| {
            format!("block {}: the sequencer no longer holds source {id}", block.block.number)
        })?;
        Ok((sources.into_iter().cloned().collect(), added))
    }

    /// Asks the backend to forget the sources of `block`'s statements.
    async fn forget(&self, block: &BlockStatements) -> Result<(), String> {
        let statements = block.statements.iter().map(|s| s.statement).collect();
        self.backend.forget(block.block, statements).await.map_err(|err| {
            format!("could not forget the sources of block {}: {err}", block.block.number)
        })
    }

    /// Closes and seals `run`'s root and submits it.
    async fn close(&mut self, mut run: Run) -> Result<(), String> {
        let through = run.through.ok_or("closing a run that folded nothing")?;
        let started = Instant::now();
        let aggregate = blocking(move || {
            let TreeAggregate { statements, proof } =
                run.aggregator.close()?.ok_or("closing a run that folded nothing")?;
            let aggregate = PendingAggregate {
                version: PROOF_AGGREGATE_PAYLOAD_VERSION,
                aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
                through: through.number,
                statements,
                proof: proof.to_rlp_bytes(),
            };
            ProofAggregatePayload::from(aggregate.clone()).check_limits()?;
            Ok(aggregate)
        })
        .await?;
        debug!(target: "op_aggregator", through = through.number, statements = aggregate.statements.len(), elapsed = ?started.elapsed(), "closed a leanVM tree aggregate");
        self.submit(Kept { aggregate, through }).await;
        Ok(())
    }

    /// Submits `kept`, keeping it for the next tick while the queue is full or the sequencer is
    /// unreachable.
    async fn submit(&mut self, kept: Kept) {
        let through = kept.through.number;
        match self.backend.submit(kept.aggregate.clone(), kept.through.hash).await {
            Ok(()) => {}
            Err(AggregatorError::QueueFull) => self.kept = Some(kept),
            Err(err @ AggregatorError::Other(_)) => {
                warn!(target: "op_aggregator", %err, through, "could not reach the sequencer: keeping the aggregate");
                self.kept = Some(kept);
            }
            Err(AggregatorError::Reorged) => {
                debug!(target: "op_aggregator", through, "a reorg replaced the aggregate's blocks: dropping it");
            }
            Err(err @ AggregatorError::OutOfOrder(_)) => {
                // Queued already, as when an earlier submission's reply was lost.
                warn!(target: "op_aggregator", %err, through, "the sequencer refused the aggregate's order: dropping it");
            }
            Err(err) => {
                error!(target: "op_aggregator", %err, through, "the sequencer refused the aggregate");
            }
        }
    }
}

fn err(err: AggregatorError) -> String {
    err.to_string()
}

/// Runs `f` on a blocking thread.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|err| format!("the prover panicked: {err}"))?
}

/// The sources of a block's `new` statements, in the order they are folded: each once, in the
/// order of the first statement each proves. Also every statement folding them adds. `Err` names
/// a source `source` does not know.
pub(crate) fn order_sources<'a, 's>(
    new: impl IntoIterator<Item = &'s StatementRef>,
    source: impl Fn(&B256) -> Option<&'a Source>,
) -> Result<(Vec<&'a Source>, HashSet<ProofStatement>), B256> {
    let mut sources: Vec<&Source> = Vec::new();
    let mut added = HashSet::new();
    for statement in new {
        let found = source(&statement.source).ok_or(statement.source)?;
        added.extend(found.statements(&statement.statement));
        if !sources.contains(&found) {
            sources.push(found);
        }
    }
    Ok((sources, added))
}

/// Reads the blocks after `next` and their sources, as many as `ahead` proves ahead and none past
/// `end`, the run's last block, and plans the nodes of `next` and of them. A block or source it
/// cannot read ends the plan there: proving ahead is only ever a guess.
async fn plan_ahead<B: Backend>(
    backend: &B,
    ahead: &mut Ahead,
    aggregator: &Aggregator,
    next: &BlockStatements,
    end: Option<u64>,
) {
    let mut blocks = vec![next.clone()];
    while blocks.len() <= ahead.blocks() {
        let after = blocks.last().expect("one block").block;
        match backend.next_provable_block(Some(after)).await {
            Ok(Some(block)) if end.is_none_or(|end| block.block.number <= end) => {
                blocks.push(block)
            }
            _ => break,
        }
    }
    let missing = ahead.missing(aggregator, &blocks);
    let mut fetched = HashMap::with_capacity(missing.len());
    for chunk in missing.chunks(SOURCES_PER_REQUEST) {
        match backend.sources(chunk.to_vec()).await {
            Ok(entries) => {
                fetched.extend(entries.into_iter().map(|entry| (entry.id, entry.source)))
            }
            Err(err) => {
                debug!(target: "op_aggregator", %err, "could not read the sources to prove ahead");
                break;
            }
        }
    }
    ahead.plan(aggregator, &blocks, fetched);
}

/// Folds a block's `sources` into `aggregator` as one block ([`Aggregator::add_block`]): its
/// program leaves and full signature leaves through one fold, the other signatures into the buffer
/// of the next signature leaf.
fn fold(aggregator: &mut Aggregator, sources: &[Source]) -> Result<(), String> {
    let items = sources
        .iter()
        .map(|source| match source {
            Source::Program { verifying_key, proof, members, .. } => {
                Ok(BlockItem::Program(ProgramRef { verifying_key, members, proof }))
            }
            Source::Signature { public_key, message, signature } => {
                Signed::decode(public_key, *message, signature).map(BlockItem::Signature)
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    aggregator.add_block(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{SourceEntry, Status};
    use alloy_primitives::Bytes;
    use op_alloy_consensus::TARGET_PROOF_AGGREGATE_STATEMENTS as TARGET_STATEMENTS;
    use std::sync::{Arc, Mutex};

    const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../op-leanvm-tree/testdata");

    fn testdata(name: &str) -> Bytes {
        std::fs::read(format!("{TESTDATA}/{name}")).unwrap().into()
    }

    /// The fixture's signature `i`: its source and statement.
    fn signature(i: u8) -> (Source, ProofStatement) {
        let (public_key, message, signature) = (
            testdata(&format!("signature-{i}.key")),
            B256::from_slice(&testdata(&format!("signature-{i}.message"))),
            testdata(&format!("signature-{i}.signature")),
        );
        let statement = Signed::decode(&public_key, message, &signature).unwrap().statement();
        (Source::Signature { public_key, message, signature }, statement)
    }

    fn block(number: u64, hash: u8) -> BlockId {
        BlockId { number, hash: B256::repeat_byte(hash) }
    }

    /// A sequencer's bookkeeping in miniature: a chain of blocks each depending on signatures, a
    /// queue that can refuse submissions, and what was submitted and forgotten.
    #[derive(Default)]
    struct State {
        chain: Vec<BlockStatements>,
        sources: HashMap<B256, Source>,
        refuse_submits: usize,
        unreachable_submits: usize,
        refuse_forgets: bool,
        run_blocks: u64,
        due_through: Option<u64>,
        submitted: Vec<PendingAggregate>,
        forgotten: Vec<u64>,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<State>>);

    impl Fake {
        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.0.lock().unwrap()
        }

        /// Makes `block` canonical, replacing any block from its number on, depending on
        /// signatures `signatures`.
        fn include(&self, block: BlockId, signatures: &[u8]) {
            let mut state = self.state();
            state.chain.retain(|b| b.block.number < block.number);
            let statements = signatures
                .iter()
                .map(|i| {
                    let (source, statement) = signature(*i);
                    state.sources.insert(statement.id(), source);
                    StatementRef { statement, source: statement.id() }
                })
                .collect();
            state.chain.push(BlockStatements { block, statements });
        }

        fn last_through(state: &State) -> Option<u64> {
            state.submitted.last().map(|aggregate| aggregate.through)
        }
    }

    #[async_trait::async_trait]
    impl Backend for Fake {
        async fn status(&self) -> Result<Status, AggregatorError> {
            let state = self.state();
            Ok(Status {
                head: state.chain.last().map(|b| b.block),
                safe: None,
                finalized: None,
                last_through: Self::last_through(&state),
                queue_full: false,
                paused: false,
                run_blocks: state.run_blocks,
                bytes_due: false,
                due_through: state.due_through,
            })
        }

        async fn next_provable_block(
            &self,
            after: Option<BlockId>,
        ) -> Result<Option<BlockStatements>, AggregatorError> {
            let state = self.state();
            let last = Self::last_through(&state);
            if let Some(after) = after {
                let covered = last.is_some_and(|last| after.number <= last);
                if !covered && !state.chain.iter().any(|b| b.block == after) {
                    return Err(AggregatorError::Reorged);
                }
            }
            let from = after.map(|b| b.number).max(last);
            Ok(state
                .chain
                .iter()
                .find(|b| from.is_none_or(|from| b.block.number > from) && !b.statements.is_empty())
                .cloned())
        }

        async fn sources(&self, ids: Vec<B256>) -> Result<Vec<SourceEntry>, AggregatorError> {
            let state = self.state();
            Ok(ids
                .into_iter()
                .filter_map(|id| {
                    state.sources.get(&id).map(|s| SourceEntry { id, source: s.clone() })
                })
                .collect())
        }

        async fn forget(
            &self,
            block: BlockId,
            _: Vec<ProofStatement>,
        ) -> Result<(), AggregatorError> {
            let mut state = self.state();
            if state.refuse_forgets {
                return Err(AggregatorError::RateLimited);
            }
            // Its statements are no longer provable, as in the sequencer's pool.
            if let Some(forgotten) = state.chain.iter_mut().find(|b| b.block == block) {
                forgotten.statements.clear();
            }
            state.forgotten.push(block.number);
            Ok(())
        }

        async fn submit(
            &self,
            aggregate: PendingAggregate,
            through_hash: B256,
        ) -> Result<(), AggregatorError> {
            let mut state = self.state();
            if !state
                .chain
                .iter()
                .any(|b| b.block.number == aggregate.through && b.block.hash == through_hash)
            {
                return Err(AggregatorError::Reorged);
            }
            if state.refuse_submits > 0 {
                state.refuse_submits -= 1;
                return Err(AggregatorError::QueueFull);
            }
            if state.unreachable_submits > 0 {
                state.unreachable_submits -= 1;
                return Err(AggregatorError::Other(String::from("connection reset")));
            }
            state.submitted.push(aggregate);
            Ok(())
        }
    }

    /// An aggregate the queue refuses is kept and submitted later; meanwhile the next run folds
    /// the blocks after it.
    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_an_aggregate_the_queue_refuses() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        assert!(folder.tick(start).await.unwrap(), "folded block 1");
        fake.include(block(2, 2), &[1]);
        fake.state().refuse_submits = 1;
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        assert_eq!(folder.kept.as_ref().map(|k| k.through), Some(block(1, 1)), "kept");
        let run = folder.run.as_ref().unwrap();
        assert_eq!(run.through, Some(block(2, 2)), "block 2 starts the next run");
        assert!(run.aggregator.contains(&signature(1).1));
        assert!(!run.aggregator.contains(&signature(0).1));

        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        assert!(folder.kept.is_none());
        let submitted = &fake.state().submitted;
        assert_eq!(submitted.len(), 1);
        assert_eq!(
            (submitted[0].through, submitted[0].statements.clone()),
            (1, vec![signature(0).1])
        );
    }

    /// A reorg replacing a folded block drops the run, which folds the new block instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn drops_a_run_whose_blocks_a_reorg_replaced() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        fake.include(block(1, 0xb1), &[1]);
        folder.tick(start).await.unwrap();
        assert!(folder.run.is_none(), "dropped");
        folder.tick(start).await.unwrap();
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        let state = fake.state();
        assert_eq!(state.submitted.len(), 1);
        assert_eq!(state.submitted[0].statements, vec![signature(1).1]);
        assert!(state.forgotten.is_empty());
    }

    /// A source the sequencer no longer holds fails the tick, and the run starts over.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_source_fails_the_tick() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        fake.state().sources.clear();
        let mut folder = Folder::new(fake.clone());
        let err = folder.tick(Instant::now()).await.unwrap_err();
        assert!(err.contains("no longer holds"), "{err}");
    }

    /// A run that overflows while an aggregate is kept waits for the queue rather than closing,
    /// which would replace the kept aggregate, whose blocks it does not cover.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_overflowing_run_waits_for_the_kept_aggregate() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        fake.include(block(2, 2), &[1]);
        fake.state().refuse_submits = 2;
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        assert_eq!(folder.kept.as_ref().map(|k| k.through), Some(block(1, 1)), "kept");
        assert_eq!(folder.run.as_ref().unwrap().through, Some(block(2, 2)));

        // Block 3 depends on a leaf publishing more statements than any run takes.
        let members: Vec<B256> = (0..=TARGET_STATEMENTS as u64)
            .map(|i| B256::left_padding_from(&i.to_be_bytes()))
            .collect();
        let program = B256::repeat_byte(0x77);
        let statement = ProofStatement { vkey_hash: program, public_values_digest: members[0] };
        {
            let mut state = fake.state();
            let source = Source::Program {
                program,
                verifying_key: Bytes::new(),
                proof: Bytes::new(),
                members,
            };
            state.sources.insert(statement.id(), source);
            state.chain.push(BlockStatements {
                block: block(3, 3),
                statements: vec![StatementRef { statement, source: statement.id() }],
            });
        }
        assert!(!folder.tick(start + AGGREGATE_DELAY).await.unwrap(), "waits for the queue");
        assert_eq!(folder.kept.as_ref().map(|k| k.through), Some(block(1, 1)), "still kept");
        assert_eq!(folder.run.as_ref().unwrap().through, Some(block(2, 2)), "still open");

        // The queue takes the kept aggregate, then the run closes before block 3, which no run
        // takes and is forgotten.
        for _ in 0..3 {
            folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        }
        let state = fake.state();
        let throughs: Vec<u64> = state.submitted.iter().map(|a| a.through).collect();
        assert_eq!(throughs, [1, 2]);
        assert_eq!(state.forgotten, [3]);
    }

    /// Two ids naming equal sources, as two transactions relying on one leaf get, are fetched and
    /// folded once.
    #[tokio::test(flavor = "multi_thread")]
    async fn equal_sources_fold_once() {
        let fake = Fake::default();
        let (source, statement) = signature(0);
        let ids = [B256::repeat_byte(0xa1), B256::repeat_byte(0xa2)];
        {
            let mut state = fake.state();
            for id in ids {
                state.sources.insert(id, source.clone());
            }
        }
        let block = BlockStatements {
            block: block(1, 1),
            statements: ids.map(|id| StatementRef { statement, source: id }).into(),
        };
        let mut folder = Folder::new(fake);
        let aggregator = blocking(Aggregator::new).await.unwrap();
        let (sources, added) = folder.new_sources(&aggregator, &block).await.unwrap();
        assert_eq!(sources, vec![source]);
        assert_eq!(added, HashSet::from([statement]));
    }

    /// A forget the sequencer refuses fails the tick, so that the folder backs off instead of
    /// fetching the block again at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_forget_fails_the_tick() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        let (mut source, statement) = signature(0);
        if let Source::Signature { signature, .. } = &mut source {
            *signature = Bytes::from_static(b"not a signature");
        }
        fake.state().sources.insert(statement.id(), source);
        fake.state().refuse_forgets = true;
        let mut folder = Folder::new(fake.clone());
        let err = folder.tick(Instant::now()).await.unwrap_err();
        assert!(err.contains("could not forget"), "{err}");
        assert!(fake.state().forgotten.is_empty());
    }

    /// An aggregate the sequencer could not be reached with is kept and submitted again.
    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_an_aggregate_the_sequencer_did_not_receive() {
        let fake = Fake::default();
        fake.include(block(1, 1), &[0]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        fake.state().unreachable_submits = 1;
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        assert!(folder.kept.is_some(), "kept");
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        assert!(folder.kept.is_none());
        assert_eq!(fake.state().submitted.len(), 1);
    }

    #[test]
    fn a_run_ends_where_the_batcher_computes_it() {
        assert_eq!(run_end(0, 12), 11);
        assert_eq!(run_end(11, 12), 11);
        assert_eq!(run_end(12, 12), 23);
        assert_eq!((run_end(35, 12) + 1) % 12, 0);
    }

    fn throughs(fake: &Fake) -> Vec<u64> {
        fake.state().submitted.iter().map(|a| a.through).collect()
    }

    /// A fixed run closes at its boundary, whatever its age, and the block past the boundary
    /// starts the next.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fixed_run_closes_at_its_boundary() {
        let fake = Fake::default();
        fake.state().run_blocks = 2;
        fake.include(block(2, 2), &[0]);
        fake.include(block(3, 3), &[1]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        folder.tick(start + 60 * AGGREGATE_DELAY).await.unwrap();
        assert_eq!(folder.run.as_ref().unwrap().through, Some(block(3, 3)));
        assert!(throughs(&fake).is_empty(), "the run ends at block 3, and age does not close it");
        folder.tick(start).await.unwrap();
        assert_eq!(throughs(&fake), [3], "the chain reached the boundary");
        assert_eq!(fake.state().submitted[0].statements.len(), 2);
    }

    /// A block past the boundary closes the run, though the chain's head is its only sign.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_block_past_the_boundary_starts_the_next_run() {
        let fake = Fake::default();
        fake.state().run_blocks = 2;
        fake.include(block(1, 1), &[0]);
        fake.include(block(2, 2), &[1]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        folder.tick(start).await.unwrap();
        assert_eq!(throughs(&fake), [1]);
        assert_eq!(folder.run.as_ref().unwrap().through, Some(block(2, 2)));
    }

    /// While an aggregate waits for room in the queue a fixed run keeps its boundary: the block
    /// past it waits, so that falling behind leaves the aggregates whole.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fixed_run_keeps_its_boundary_while_an_aggregate_is_kept() {
        let fake = Fake::default();
        fake.state().run_blocks = 2;
        fake.state().refuse_submits = 1;
        fake.include(block(1, 1), &[0]);
        fake.include(block(2, 2), &[]);
        fake.include(block(3, 3), &[1]);
        fake.include(block(4, 4), &[]);
        fake.include(block(5, 5), &[2]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        folder.tick(start).await.unwrap();
        assert!(folder.kept.is_some(), "the queue refused the aggregate through block 1");
        fake.state().refuse_submits = 3;
        for _ in 0..3 {
            folder.tick(start).await.unwrap();
        }
        assert_eq!(folder.run.as_ref().unwrap().through, Some(block(3, 3)));
        assert_eq!(folder.run.as_ref().unwrap().end, Some(3), "block 5 waits");
        fake.state().refuse_submits = 0;
        for _ in 0..4 {
            folder.tick(start).await.unwrap();
        }
        assert_eq!(throughs(&fake), [1, 3, 5], "one aggregate per run");
    }

    /// A fixed run that lost its only block leaves nothing open, so the next block with statements
    /// starts a run of its own though it lies past that run's end.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_forgotten_block_leaves_no_empty_fixed_run() {
        let fake = Fake::default();
        fake.state().run_blocks = 2;
        fake.include(block(1, 1), &[0]);
        for source in fake.state().sources.values_mut() {
            if let Source::Signature { signature, .. } = source {
                *signature = Bytes::new();
            }
        }
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        assert!(folder.run.is_none());
        assert_eq!(fake.state().forgotten, [1]);
        fake.state().chain.clear();
        fake.include(block(2, 2), &[1]);
        fake.include(block(3, 3), &[]);
        for _ in 0..3 {
            folder.tick(start).await.unwrap();
        }
        assert_eq!(throughs(&fake), [2]);
    }

    /// The sequencer ends a fixed run early once its bytes approach the pause.
    #[tokio::test(flavor = "multi_thread")]
    async fn bytes_end_a_fixed_run_early() {
        let fake = Fake::default();
        fake.state().run_blocks = 12;
        fake.include(block(1, 1), &[0]);
        fake.include(block(2, 2), &[1]);
        let mut folder = Folder::new(fake.clone());
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        fake.state().due_through = Some(1);
        folder.tick(start).await.unwrap();
        assert_eq!(throughs(&fake), [1]);
    }
}
