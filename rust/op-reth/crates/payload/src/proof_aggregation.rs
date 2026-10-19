//! Sequencer-side queue for SP1 proof aggregation.
//!
//! Users submit the proofs behind their `ProofRegistry` statements to the sequencer off chain.
//! An external aggregator reads them, proves an aggregation program over a batch of statements and
//! hands the aggregate proof back. The payload builder then includes it as the block's proof
//! aggregate (`0x7C`) transaction, directly after the deposits.
//!
//! The pool is in-memory and starts empty on every boot. Every proof it accepts has already been
//! verified natively by the RPC handler, which also checks that the registry holds the statement
//! pending; the pool itself only bounds, stores and hands them out.
//!
//! # DA limits
//!
//! An aggregate carries a 1.27 MB SP1 compressed proof, about 790 kB of estimated DA. The payload
//! builder counts it against the same local limits as mempool transactions: the per-transaction
//! and per-block DA sizes the batcher sets while throttling (`miner_setMaxDASize`) and the
//! maximum uncompressed block size. An aggregate that does not fit waits for a later block. On top
//! of that, the builder includes at most one aggregate every
//! [`proof_aggregate_interval`](crate::config::OpBuilderConfig::proof_aggregate_interval) blocks.
//!
//! These are limitations of that approach:
//!
//! - **Not a consensus rule.** The executor leaves the aggregate out of the Jovian DA footprint: it
//!   adds nothing to the header's `blobGasUsed`, does not raise the base fee, and is not bounded by
//!   the block gas limit. Only the sequencer's policy bounds the DA aggregates add; validators and
//!   the fault proof program accept an aggregate in every block. Counting it in the footprint
//!   instead would make it unincludable on most chains: at the default scalar of 400 it needs about
//!   317M gas of footprint, against block gas limits of 40M to 60M.
//! - **Throttling is reactive.** The batcher sets DA limits only once its backlog passes a
//!   threshold (3.2 MB by default). Any throttle level then caps transactions at 20 kB or less,
//!   which pauses aggregates entirely. Until then the interval alone bounds aggregate DA.
//! - **No price signal.** Aggregate DA is paid for by the statement fee charged when a statement is
//!   submitted to the `ProofRegistry`, not through the base fee, so heavy aggregation does not make
//!   L2 block space more expensive.
//! - **The interval is approximate.** The last inclusion is kept in memory: it resets on restart,
//!   and a payload that never becomes canonical still counts, which only delays the next aggregate.
//!
//! Smaller proofs are the lasting fix; a WHIR-based proof would be roughly a fifth of the size.
//!
//! # Proving cost
//!
//! Every proof program verifies an aggregate's proof in software: about 0.8B Cannon steps, and
//! 582M PGU in the kona-sp1 super-range guest. The registry call adds up to about 0.46B PGU at its
//! 30M system call gas. A ZK range proof covers every block of its span, so its cost grows with
//! how many of them carry an aggregate, and consensus allows one in every block: the interval and
//! the [`MAX_AGGREGATE_STATEMENTS`] limit bind only an honest sequencer. Against a sequencer that
//! fills every block, a range request stays within its 2×10¹¹ PGU limit only for a single chain:
//! at the default 16-way split that holds for 2 s blocks (about 59%), while 1 s blocks need a
//! split of at least 32. Each further chain proven in the same super root adds its blocks to the
//! same request, so adding chains to the dependency set needs a consensus rate limit or an
//! adaptive split first.

use alloy_primitives::B256;
pub use op_alloy_consensus::{PendingAggregate, StatementProof};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
};

/// Upper bound on statement proofs held at once, both waiting for aggregation and held by queued
/// aggregates. With the per-proof size limits below, the pool holds at most about 530 MiB.
pub const MAX_STATEMENT_PROOFS: usize = 256;

/// Failed inclusion attempts after which an aggregate is dropped and its statements go back to
/// waiting for aggregation.
pub const MAX_INCLUSION_FAILURES: u32 = 3;

/// Upper bound on an encoded SP1 compressed proof: the consensus limit on a proof aggregate's
/// proof, applied to statement proofs too. Compressed proofs have a fixed shape of about 1.27 MB
/// regardless of the program.
pub const MAX_PROOF_BYTES: usize = alloy_op_evm::MAX_PROOF_AGGREGATE_PROOF_BYTES;

/// Upper bound on a statement's public values.
pub const MAX_PUBLIC_VALUES_BYTES: usize = 64 * 1024;

/// Upper bound on an encoded `SP1VerifyingKey`, which is about 100 bytes.
pub const MAX_VERIFYING_KEY_BYTES: usize = 4 * 1024;

/// Upper bound on the statements one aggregate may cover. Consensus allows more, up to what the
/// registry call's 30M system call gas can process (about 4,600); the sequencer keeps aggregates
/// small so their registry call stays cheap to prove.
pub const MAX_AGGREGATE_STATEMENTS: usize = 512;

/// Upper bound on aggregates waiting for inclusion.
pub const MAX_PENDING_AGGREGATES: usize = 16;

/// Why the pool refused an insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofAggregationPoolError {
    /// A field exceeds its size limit.
    #[error("{field} exceeds {limit} bytes")]
    TooLarge {
        /// The oversized field.
        field: &'static str,
        /// Its limit in bytes.
        limit: usize,
    },
    /// The pool already holds a proof of the statement.
    #[error("statement proof already queued")]
    AlreadyQueued,
    /// The pool already holds [`MAX_STATEMENT_PROOFS`] statement proofs.
    #[error("statement proof pool is full")]
    StatementProofsFull,
    /// The aggregate covers more than [`MAX_AGGREGATE_STATEMENTS`] statements.
    #[error("aggregate covers more than {MAX_AGGREGATE_STATEMENTS} statements")]
    TooManyStatements,
    /// The pool already holds [`MAX_PENDING_AGGREGATES`] aggregates.
    #[error("pending aggregate queue is full")]
    AggregatesFull,
}

/// An aggregate waiting for inclusion.
#[derive(Debug)]
struct QueuedAggregate {
    aggregate: PendingAggregate,
    /// Proofs of the statements the aggregate covers, kept so the statements can be aggregated
    /// again if the aggregate is dropped before a block includes it.
    statement_proofs: Vec<StatementProof>,
    /// Failed inclusion attempts so far.
    failures: u32,
}

#[derive(Debug, Default)]
struct Inner {
    /// Statement proofs not yet covered by a submitted aggregate, keyed by statement id.
    statement_proofs: BTreeMap<B256, StatementProof>,
    /// Aggregates in submission order.
    aggregates: VecDeque<QueuedAggregate>,
    /// Number of the last block the payload builder included an aggregate in.
    last_inclusion: Option<u64>,
}

impl Inner {
    /// Statement proofs held, including those held by queued aggregates.
    fn held_proofs(&self) -> usize {
        self.statement_proofs.len() +
            self.aggregates.iter().map(|queued| queued.statement_proofs.len()).sum::<usize>()
    }

    fn take_aggregate(&mut self, aggregate: &PendingAggregate) -> Option<QueuedAggregate> {
        let index = self.aggregates.iter().position(|queued| &queued.aggregate == aggregate)?;
        self.aggregates.remove(index)
    }
}

/// Shared handle to the sequencer's proof aggregation queue. Clones share the same state: the RPC
/// handlers write, the payload builder reads.
#[derive(Debug, Clone, Default)]
pub struct ProofAggregationPool {
    inner: Arc<Mutex<Inner>>,
}

impl ProofAggregationPool {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Checks a statement proof's fields against their size limits.
    pub fn check_sizes(
        public_values: &[u8],
        proof: &[u8],
        verifying_key: &[u8],
    ) -> Result<(), ProofAggregationPoolError> {
        for (field, len, limit) in [
            ("public values", public_values.len(), MAX_PUBLIC_VALUES_BYTES),
            ("proof", proof.len(), MAX_PROOF_BYTES),
            ("verifying key", verifying_key.len(), MAX_VERIFYING_KEY_BYTES),
        ] {
            if len > limit {
                return Err(ProofAggregationPoolError::TooLarge { field, limit });
            }
        }
        Ok(())
    }

    /// Checks that a proof of `statement_id` could be queued now, before the caller pays for
    /// verifying it. [`Self::insert_statement_proof`] checks again.
    pub fn check_room(&self, statement_id: B256) -> Result<(), ProofAggregationPoolError> {
        let inner = self.lock();
        if inner.statement_proofs.contains_key(&statement_id) {
            return Err(ProofAggregationPoolError::AlreadyQueued);
        }
        if inner.held_proofs() >= MAX_STATEMENT_PROOFS {
            return Err(ProofAggregationPoolError::StatementProofsFull);
        }
        Ok(())
    }

    /// Adds a verified statement proof. The first proof of a statement wins: any valid proof is as
    /// good as another, and refusing replacements stops a caller from re-verifying one statement
    /// over and over.
    pub fn insert_statement_proof(
        &self,
        proof: StatementProof,
    ) -> Result<B256, ProofAggregationPoolError> {
        Self::check_sizes(&proof.public_values, &proof.proof, &proof.verifying_key)?;
        let id = proof.statement.id();
        let mut inner = self.lock();
        if inner.statement_proofs.contains_key(&id) {
            return Err(ProofAggregationPoolError::AlreadyQueued);
        }
        if inner.held_proofs() >= MAX_STATEMENT_PROOFS {
            return Err(ProofAggregationPoolError::StatementProofsFull);
        }
        inner.statement_proofs.insert(id, proof);
        Ok(id)
    }

    /// Returns the statement proofs waiting to be aggregated, ordered by statement id.
    pub fn statement_proofs(&self) -> Vec<StatementProof> {
        self.lock().statement_proofs.values().cloned().collect()
    }

    /// Drops the proofs of the statements in `ids`, such as statements the registry no longer
    /// holds pending.
    pub fn remove_statement_proofs(&self, ids: &[B256]) {
        let mut inner = self.lock();
        for id in ids {
            inner.statement_proofs.remove(id);
        }
    }

    /// Queues a verified aggregate for inclusion. The statement proofs it covers stop waiting for
    /// aggregation; the aggregate keeps them until it is dropped.
    pub fn submit_aggregate(
        &self,
        aggregate: PendingAggregate,
    ) -> Result<(), ProofAggregationPoolError> {
        if aggregate.statements.len() > MAX_AGGREGATE_STATEMENTS {
            return Err(ProofAggregationPoolError::TooManyStatements);
        }
        let mut inner = self.lock();
        if inner.aggregates.len() >= MAX_PENDING_AGGREGATES {
            return Err(ProofAggregationPoolError::AggregatesFull);
        }
        let statement_proofs = aggregate
            .statements
            .iter()
            .filter_map(|statement| inner.statement_proofs.remove(&statement.id()))
            .collect();
        inner.aggregates.push_back(QueuedAggregate { aggregate, statement_proofs, failures: 0 });
        Ok(())
    }

    /// Returns the oldest aggregate waiting for inclusion, leaving it queued.
    ///
    /// An included aggregate stays queued: the payload may not become canonical. The payload
    /// builder drops it with [`Self::discard_aggregate`] once the registry shows its statements
    /// verified.
    pub fn next_aggregate(&self) -> Option<PendingAggregate> {
        self.lock().aggregates.front().map(|queued| queued.aggregate.clone())
    }

    /// Removes `aggregate` and the statement proofs it holds from the queue, if it is still there.
    pub fn discard_aggregate(&self, aggregate: &PendingAggregate) {
        self.lock().take_aggregate(aggregate);
    }

    /// Removes `aggregate` from the queue and puts the proofs of the statements in `still_pending`
    /// back to wait for aggregation; the rest are dropped.
    pub fn requeue_statements(&self, aggregate: &PendingAggregate, still_pending: &[B256]) {
        let mut inner = self.lock();
        let Some(queued) = inner.take_aggregate(aggregate) else { return };
        for proof in queued.statement_proofs {
            let id = proof.statement.id();
            if still_pending.contains(&id) {
                inner.statement_proofs.entry(id).or_insert(proof);
            }
        }
    }

    /// Records a failed attempt to include `aggregate` and returns the number of failures so far.
    pub fn record_failure(&self, aggregate: &PendingAggregate) -> u32 {
        let mut inner = self.lock();
        inner.aggregates.iter_mut().find(|queued| &queued.aggregate == aggregate).map_or(
            0,
            |queued| {
                queued.failures += 1;
                queued.failures
            },
        )
    }

    /// Whether a block numbered `block_number` may include an aggregate: at least `interval` blocks
    /// after the last block that did. Rebuilding that same block, or a lower one after a reorg,
    /// is allowed.
    pub fn inclusion_allowed(&self, block_number: u64, interval: u64) -> bool {
        self.lock().last_inclusion.is_none_or(|last| {
            block_number <= last || block_number >= last.saturating_add(interval)
        })
    }

    /// Records that the payload builder included an aggregate in block `block_number`.
    pub fn record_inclusion(&self, block_number: u64) {
        self.lock().last_inclusion = Some(block_number);
    }

    /// Number of aggregates waiting for inclusion.
    pub fn pending_aggregates(&self) -> usize {
        self.lock().aggregates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use op_alloy_consensus::ProofStatement;

    fn statement_proof(byte: u8) -> StatementProof {
        StatementProof {
            statement: ProofStatement {
                vkey_hash: B256::repeat_byte(byte),
                public_values_digest: B256::repeat_byte(byte),
            },
            public_values: Bytes::from(vec![byte]),
            proof: Bytes::from(vec![byte; 4]),
            verifying_key: Bytes::from(vec![byte; 2]),
        }
    }

    #[test]
    fn aggregate_consumes_its_statement_proofs() {
        let pool = ProofAggregationPool::default();
        let a = statement_proof(1);
        let b = statement_proof(2);
        pool.insert_statement_proof(a.clone()).unwrap();
        pool.insert_statement_proof(b.clone()).unwrap();

        let aggregate = PendingAggregate {
            aggregation_vkey_hash: B256::repeat_byte(9),
            statements: vec![a.statement],
            proof: Bytes::from_static(b"agg"),
        };
        pool.submit_aggregate(aggregate.clone()).unwrap();

        assert_eq!(pool.statement_proofs(), vec![b]);
        assert_eq!(pool.next_aggregate(), Some(aggregate.clone()));
        // Inclusion does not consume it; only discarding does.
        assert_eq!(pool.next_aggregate(), Some(aggregate.clone()));
        pool.discard_aggregate(&aggregate);
        assert_eq!(pool.next_aggregate(), None);
        assert_eq!(pool.lock().held_proofs(), 1);
    }

    #[test]
    fn rejects_an_aggregate_over_the_statement_limit() {
        let pool = ProofAggregationPool::default();
        let aggregate = PendingAggregate {
            aggregation_vkey_hash: B256::ZERO,
            statements: vec![ProofStatement::default(); MAX_AGGREGATE_STATEMENTS + 1],
            proof: Bytes::new(),
        };
        assert_eq!(
            pool.submit_aggregate(aggregate),
            Err(ProofAggregationPoolError::TooManyStatements)
        );
        assert_eq!(pool.pending_aggregates(), 0);
    }

    #[test]
    fn requeue_restores_only_pending_statements() {
        let pool = ProofAggregationPool::default();
        let (a, b) = (statement_proof(1), statement_proof(2));
        pool.insert_statement_proof(a.clone()).unwrap();
        pool.insert_statement_proof(b.clone()).unwrap();
        let aggregate = PendingAggregate {
            aggregation_vkey_hash: B256::repeat_byte(9),
            statements: vec![a.statement, b.statement],
            proof: Bytes::from_static(b"agg"),
        };
        pool.submit_aggregate(aggregate.clone()).unwrap();
        assert!(pool.statement_proofs().is_empty());
        assert_eq!(pool.lock().held_proofs(), 2, "the aggregate holds its statements' proofs");

        assert_eq!(pool.record_failure(&aggregate), 1);
        assert_eq!(pool.record_failure(&aggregate), 2);

        pool.requeue_statements(&aggregate, &[b.statement.id()]);
        assert_eq!(pool.next_aggregate(), None);
        assert_eq!(pool.statement_proofs(), vec![b]);
        assert_eq!(pool.record_failure(&aggregate), 0, "no longer queued");
    }

    #[test]
    fn proofs_held_by_aggregates_count_towards_the_bound() {
        let pool = ProofAggregationPool::default();
        let mut statements = Vec::new();
        for i in 0..MAX_STATEMENT_PROOFS {
            let mut proof = statement_proof(0);
            proof.statement.vkey_hash = B256::from(alloy_primitives::U256::from(i));
            statements.push(proof.statement);
            pool.insert_statement_proof(proof).unwrap();
        }
        pool.submit_aggregate(PendingAggregate {
            aggregation_vkey_hash: B256::ZERO,
            statements,
            proof: Bytes::new(),
        })
        .unwrap();
        assert!(pool.statement_proofs().is_empty());
        assert_eq!(
            pool.insert_statement_proof(statement_proof(1)),
            Err(ProofAggregationPoolError::StatementProofsFull)
        );
    }

    #[test]
    fn bounded_statement_proofs() {
        let pool = ProofAggregationPool::default();
        for i in 0..MAX_STATEMENT_PROOFS {
            let mut proof = statement_proof(0);
            proof.statement.vkey_hash = B256::from(alloy_primitives::U256::from(i));
            pool.insert_statement_proof(proof).unwrap();
        }
        assert_eq!(
            pool.insert_statement_proof(statement_proof(1)),
            Err(ProofAggregationPoolError::StatementProofsFull)
        );
        assert_eq!(
            pool.check_room(statement_proof(1).statement.id()),
            Err(ProofAggregationPoolError::StatementProofsFull)
        );

        let mut first = statement_proof(0);
        first.statement.vkey_hash = B256::ZERO;
        pool.remove_statement_proofs(&[first.statement.id()]);
        assert_eq!(pool.statement_proofs().len(), MAX_STATEMENT_PROOFS - 1);
        assert!(pool.insert_statement_proof(statement_proof(1)).is_ok());
    }

    #[test]
    fn inclusion_interval() {
        let pool = ProofAggregationPool::default();
        assert!(pool.inclusion_allowed(5, 30), "nothing included yet");

        pool.record_inclusion(10);
        assert!(pool.inclusion_allowed(10, 30), "rebuilding the same block");
        assert!(pool.inclusion_allowed(9, 30), "a lower block after a reorg");
        assert!(!pool.inclusion_allowed(11, 30));
        assert!(!pool.inclusion_allowed(39, 30));
        assert!(pool.inclusion_allowed(40, 30));
        assert!(pool.inclusion_allowed(11, 1), "an interval of 1 allows every block");
        assert!(pool.inclusion_allowed(11, 0), "so does 0");
    }

    #[test]
    fn first_proof_of_a_statement_wins() {
        let pool = ProofAggregationPool::default();
        let original = statement_proof(1);
        pool.insert_statement_proof(original.clone()).unwrap();

        let mut replacement = original.clone();
        replacement.proof = Bytes::from_static(b"other");
        assert_eq!(
            pool.check_room(replacement.statement.id()),
            Err(ProofAggregationPoolError::AlreadyQueued)
        );
        assert_eq!(
            pool.insert_statement_proof(replacement),
            Err(ProofAggregationPoolError::AlreadyQueued)
        );
        assert_eq!(pool.statement_proofs(), vec![original]);
    }

    #[test]
    fn rejects_oversized_fields() {
        let pool = ProofAggregationPool::default();
        let mut proof = statement_proof(1);
        proof.proof = Bytes::from(vec![0; MAX_PROOF_BYTES + 1]);
        assert_eq!(
            pool.insert_statement_proof(proof),
            Err(ProofAggregationPoolError::TooLarge { field: "proof", limit: MAX_PROOF_BYTES })
        );
        assert_eq!(
            ProofAggregationPool::check_sizes(&[0; MAX_PUBLIC_VALUES_BYTES + 1], &[], &[]),
            Err(ProofAggregationPoolError::TooLarge {
                field: "public values",
                limit: MAX_PUBLIC_VALUES_BYTES
            })
        );
        assert_eq!(
            ProofAggregationPool::check_sizes(&[], &[], &[0; MAX_VERIFYING_KEY_BYTES + 1]),
            Err(ProofAggregationPoolError::TooLarge {
                field: "verifying key",
                limit: MAX_VERIFYING_KEY_BYTES
            })
        );
        assert!(pool.statement_proofs().is_empty());
    }
}
