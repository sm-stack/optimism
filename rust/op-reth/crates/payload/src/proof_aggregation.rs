//! Sequencer-side bookkeeping for EIP-8288 dependencies and their proof aggregates.
//!
//! A transaction declares, in its dependency entry, the statements it relies on: members
//! that leaves of the leanVM tree class publish. Each statement has a source the sequencer
//! verifies when the transaction arrives (`optimism_sendRawTransactionWithStatementProofs`): a
//! program leaf proof publishing the member, or a leanSPHINCS signature whose member it is. The
//! sequencer admits the transaction here and to the transaction pool, and includes it in the next
//! block it fits: users get the transaction's effects at once.
//!
//! Derivation then holds each such block until the first proof aggregate whose `through` reaches
//! it, and replaces a block with its deposits unless that aggregate proves all its dependencies.
//! So the sequencer keeps, per block, the statements its transactions depend on and their sources,
//! and hands op-aggregator the sealed blocks one by one
//! ([`ProofAggregationPool::next_provable_block`]) to fold into one tree root: at most
//! [`TARGET_PROOF_AGGREGATE_STATEMENTS`] statements, what three blobs carry, of at most
//! [`MAX_PROOF_AGGREGATE_PROGRAMS`] programs per aggregate, and so per block. An aggregate must
//! prove every provable statement of the blocks it answers for, and is queued in `through` order.
//! op-batcher reads the aggregates the safe head has not reached (`admin_pendingProofAggregates`)
//! and posts each as a proof aggregate batch after the blocks it answers for. An aggregate stays
//! queued until the finalized head reaches its `through` ([`ProofAggregationPool::on_finalized`]):
//! an L1 reorg can move the safe head back and drop the batch that carried it, and the batcher then
//! posts it again.
//!
//! The pool follows the canonical chain ([`ProofAggregationPool::on_canonical_block`], which also
//! rolls back the blocks a reorg replaces): which dependent transactions a block holds is what the
//! chain says, not what a payload attempt tried. If aggregates fall behind, the oldest
//! uncovered block ages and the transaction bytes after it grow; past `MAX_UNCOVERED_AGE` or
//! `MAX_UNCOVERED_BYTES`, or `MAX_UNCOVERED_STATEMENTS` with fixed runs, the sequencer stops
//! admitting and including new dependent transactions, so that the blocks it already built can
//! still be covered within derivation's window and byte cap.
//!
//! With `--rollup.proof-aggregation-run-blocks`, a run ends at every block `n` where
//! `(n + 1) % K == 0`. op-aggregator closes there and op-batcher ends the channel there, each
//! computing the boundary itself, so an aggregate can share the channel of its blocks and hold
//! up to [`MAX_PROOF_AGGREGATE_STATEMENTS`] statements without either asking the other. A block's
//! statements are limited to its share of an aggregate.
//!
//! The pause does not stop blocks already built from being replaced if no aggregate covers them
//! in time.
//!
//! The pool is in-memory and starts empty on every boot: a restart loses the proofs of included
//! but uncovered blocks and the aggregates not yet derived, and derivation then replaces the
//! blocks they answer for.

use alloy_primitives::{B256, Bytes};
pub use op_alloy_consensus::{
    LEANVM_TREE_CLASS_KEY_DIGEST, LeanVmTreeProof, MAX_PROOF_AGGREGATE_PROGRAMS,
    MAX_PROOF_AGGREGATE_STATEMENTS, MAX_STATEMENT_PROOF_BYTES, MAX_STATEMENT_VERIFYING_KEY_BYTES,
    PROOF_AGGREGATE_PAYLOAD_VERSION, PendingAggregate, ProofAggregatePayload, ProofStatement,
    SharedProofAggregateVerifier, TARGET_PROOF_AGGREGATE_STATEMENTS,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// Upper bound on statements whose sources the pool holds at once.
const MAX_STATEMENT_PROOFS: usize = 32_768;

/// Upper bound on the bytes of the sources the pool holds at once, each program leaf counted once
/// however many statements it backs.
const MAX_HELD_SOURCE_BYTES: usize = 256 * 1024 * 1024;

/// Upper bound on queued aggregates the safe head has not reached.
const MAX_PENDING_AGGREGATES: usize = 16;

/// Upper bound on queued aggregates the safe head has reached but the finalized head has not; the
/// oldest are forgotten first if finality stalls.
const MAX_DECIDED_AGGREGATES: usize = 16;

/// Upper bound on admitted transactions not yet included.
const MAX_ADMITTED_TXS: usize = 4096;

/// How long an admitted transaction may wait for inclusion before its admission lapses.
const ADMISSION_TTL: Duration = Duration::from_secs(10 * 60);

/// How long the oldest uncovered block may wait for an aggregate before the sequencer stops taking
/// new dependent transactions. Derivation gives an aggregate 100 L1 blocks (20 minutes) after the
/// block's batch lands; this leaves room for the batcher's lag and for one more aggregation round.
/// It counts from when the pool saw the block.
const MAX_UNCOVERED_AGE: Duration = Duration::from_secs(12 * 60);

/// How long the sequencer goes without a request from op-aggregator, which proves its aggregates,
/// before it takes op-aggregator for gone and stops taking and including dependent transactions:
/// no aggregate would answer for them, and derivation would replace their blocks. op-aggregator
/// asks for the pool's status every few seconds whatever it is proving
/// (`op_aggregator::HEARTBEAT`), so this is several missed beats. It also bounds how long a
/// sequencer whose op-aggregator died goes on including dependent transactions.
pub const AGGREGATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest number of blocks a run may span with `--rollup.proof-aggregation-run-blocks`: above
/// it `MAX_PROOF_AGGREGATE_STATEMENTS / K` falls below [`MAX_LEAF_MEMBERS`], and a block could not
/// hold a full leaf.
pub const MAX_RUN_BLOCKS: u64 = 32;

/// Uncovered statements past which a sequencer with fixed runs stops taking new dependent
/// transactions: twice what one aggregate holds, about a minute of what one prover machine folds.
const MAX_UNCOVERED_STATEMENTS: usize = 2 * MAX_PROOF_AGGREGATE_STATEMENTS;

/// Upper bound on the statements one transaction may rely on.
pub const MAX_STATEMENTS_PER_TX: usize = 16;

/// The most members one program leaf publishes: the program classes' member capacity.
pub const MAX_LEAF_MEMBERS: usize = 128;

/// Upper bound on an encoded leanSPHINCS public key or signature; the RPC checks their exact sizes.
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;

/// Transaction bytes the canonical chain may carry after the oldest uncovered block before the
/// sequencer stops taking new dependent transactions: half of derivation's scan cap
/// (`kona_derive::DEPENDENCY_SCAN_BYTE_CAP`, 16 MiB), which counts from the start of the channel
/// holding the block's batch (the batcher bounds that channel's input to half the cap with fixed
/// runs). The aggregates the safe head has not reached count too,
/// as the batcher may post them after it.
const MAX_UNCOVERED_BYTES: u64 = 8 * 1024 * 1024;

/// Uncovered bytes, counted as for [`MAX_UNCOVERED_BYTES`], past which the open run is due: the
/// aggregator closes it, however young the run, or with fixed runs a run ends at the block that
/// reached them ([`Inner::due_through`]). Half the pause, so that the aggregate is proven and
/// posted before new dependent transactions would pause, even with runs open for minutes at
/// hundreds of transactions per second.
const DUE_UNCOVERED_BYTES: u64 = MAX_UNCOVERED_BYTES / 2;

/// A program leaf proof: a run of a program of one of the leanVM tree's program classes whose
/// output commits to `members`, each a statement of the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLeaf {
    /// The digest of `verifying_key`, verified on admission: the statements' `vkey_hash`.
    pub program: B256,
    /// The normalized program's verifying key.
    pub verifying_key: Bytes,
    /// The leaf proof, in zero knowledge, at the leaf shape of a program class.
    pub proof: Bytes,
    /// The members the run published.
    pub members: Vec<B256>,
}

/// A leanSPHINCS signature over a message: the source of a statement of the signature-member
/// guest, whose member binds the public key and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureSource {
    /// The encoded public key.
    pub public_key: Bytes,
    /// The signed message.
    pub message: B256,
    /// The encoded signature.
    pub signature: Bytes,
}

/// What proves a statement, verified on admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementSource {
    /// A program leaf proof publishing the statement's member; its other members share it.
    Program(Arc<ProgramLeaf>),
    /// A signature whose member is the statement's, which op-aggregator proves in a signature leaf.
    Signature(Arc<SignatureSource>),
}

impl StatementSource {
    /// Every statement folding the source adds to an aggregate: each member of a program leaf,
    /// not only those a transaction depends on.
    pub fn statements(&self, statement: &ProofStatement) -> Vec<ProofStatement> {
        match self {
            Self::Program(leaf) => leaf
                .members
                .iter()
                .map(|member| ProofStatement {
                    vkey_hash: leaf.program,
                    public_values_digest: *member,
                })
                .collect(),
            Self::Signature(_) => vec![*statement],
        }
    }

    /// The bytes the source holds.
    fn bytes(&self) -> usize {
        match self {
            Self::Program(leaf) => {
                leaf.verifying_key.len() + leaf.proof.len() + 32 * leaf.members.len()
            }
            Self::Signature(signed) => signed.public_key.len() + signed.signature.len() + 32,
        }
    }

    /// The address that identifies the source's shared allocation: the statements one
    /// submission's leaf proves share it.
    pub fn address(&self) -> usize {
        match self {
            Self::Program(leaf) => Arc::as_ptr(leaf) as usize,
            Self::Signature(signed) => Arc::as_ptr(signed) as usize,
        }
    }
}

/// A statement and its verified source, as the pool holds it for aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementProof {
    /// The statement.
    pub statement: ProofStatement,
    /// Its source.
    pub source: StatementSource,
}

/// Why the pool refused something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofAggregationPoolError {
    /// A field exceeds its size limit.
    #[error("{field} exceeds {limit} bytes")]
    TooLarge {
        /// The oversized field.
        field: &'static str,
        /// Its limit in bytes.
        limit: usize,
    },
    /// The pool already holds `MAX_STATEMENT_PROOFS` statement proofs, or `MAX_HELD_SOURCE_BYTES`
    /// of their sources.
    #[error("statement proof pool is full")]
    StatementProofsFull,
    /// The pool already holds `MAX_ADMITTED_TXS` admitted transactions.
    #[error("too many transactions are waiting for inclusion")]
    AdmittedTxsFull,
    /// Aggregates are late: the oldest uncovered block is older than `MAX_UNCOVERED_AGE`, or too
    /// many transaction bytes or, with fixed runs, statements are uncovered.
    #[error("dependent transactions are paused until pending dependencies are aggregated")]
    DependenciesPaused,
    /// No op-aggregator proves the sequencer's aggregates: none asked for the pool's state within
    /// [`AGGREGATOR_TIMEOUT`].
    #[error("dependent transactions are paused: no op-aggregator is proving aggregates")]
    AggregatorAbsent,
    /// The transaction was already admitted.
    #[error("transaction already admitted")]
    AlreadyAdmitted,
    /// The transaction relies on none, or on more than `max` statements: more than one aggregate
    /// covers.
    #[error("a transaction must rely on between 1 and {max} statements")]
    WrongStatementCount {
        /// The most statements a transaction may rely on.
        max: usize,
    },
    /// The transaction relies on statements of more programs than one aggregate covers.
    #[error("a transaction may rely on statements of at most {max} programs")]
    TooManyPrograms {
        /// The most programs a transaction's statements may be of.
        max: usize,
    },
    /// The leaves of the transaction's statements publish more members than one block may rely on.
    #[error("a transaction's statement sources may publish at most {max} statements")]
    TooManyFoldedStatements {
        /// The most statements the sources of a transaction's statements may publish.
        max: usize,
    },
    /// No proof of one of the transaction's statements is held or was sent with it.
    #[error("no proof of statement {0}")]
    MissingProof(B256),
    /// The aggregate covers more than [`MAX_PROOF_AGGREGATE_STATEMENTS`] statements.
    #[error("aggregate covers more than {MAX_PROOF_AGGREGATE_STATEMENTS} statements")]
    TooManyStatements,
    /// The pool already holds `MAX_PENDING_AGGREGATES` aggregates.
    #[error("pending aggregate queue is full")]
    AggregatesFull,
    /// The aggregate's `through` does not follow the last queued or finalized aggregate's.
    #[error("aggregate through block {through} is out of order")]
    OutOfOrder {
        /// The aggregate's `through`.
        through: u64,
    },
    /// The aggregate does not prove a statement of a block it answers for.
    #[error("aggregate does not prove statement {0} of a block it answers for")]
    Incomplete(B256),
    /// The aggregate is outside the limits, of another class, or its proof does not verify.
    #[error("invalid aggregate: {0}")]
    InvalidProof(String),
    /// A block the request names, by number and hash, is not canonical: a reorg replaced it, or it
    /// is not sealed yet.
    #[error("a block the request names is no longer canonical")]
    Reorged,
}

/// How many blocks below the canonical head the pool remembers what blocks held, and the proofs of
/// their statements, to undo a reorg.
const REORG_DEPTH: u64 = 64;

/// A dependent transaction included in a block.
#[derive(Debug, Clone)]
struct IncludedTx {
    hash: B256,
    statement_ids: Vec<B256>,
}

/// What the pool remembers of a canonical block.
#[derive(Debug, Clone, Default)]
struct CanonicalBlock {
    /// Its hash.
    hash: B256,
    /// Its dependent transactions.
    txs: Vec<IncludedTx>,
    /// The bytes of all its transactions.
    bytes: u64,
    /// When the pool saw it.
    seen: Option<Instant>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Verified proofs of the statements admitted or recently included transactions depend on.
    proofs: HashMap<B256, StatementProof>,
    /// Admitted transactions not yet in a canonical block: their statement ids and admission time.
    admitted: HashMap<B256, (Vec<B256>, Instant)>,
    /// Recent canonical blocks: the last `REORG_DEPTH`, and every block after the oldest one no
    /// aggregate covers.
    blocks: BTreeMap<u64, CanonicalBlock>,
    /// Verified aggregates, in `through` order, until the finalized head reaches them.
    aggregates: VecDeque<PendingAggregate>,
    /// The highest `through` of the aggregates that left the queue.
    forgotten_through: Option<u64>,
    /// The safe head the pool has seen: the batcher posts the aggregates above it.
    safe: Option<u64>,
    /// The finalized head the pool has seen.
    finalized: Option<u64>,
    /// The canonical head the pool has seen.
    head: Option<u64>,
    /// How many blocks a run spans, if runs are fixed: a run ends at block `n` when
    /// `(n + 1) % run_blocks == 0`. Zero if op-aggregator closes runs on its own.
    run_blocks: u64,
    /// The distinct statements folding the provable blocks after the last aggregate would add.
    uncovered_statements: usize,
    /// The bytes of the held sources, each shared source once: [`Inner::exact_held_bytes`] as of
    /// the last block, plus what admissions added since.
    held_bytes: usize,
    /// When op-aggregator last made a request of the pool.
    aggregator_seen: Option<Instant>,
    /// Whether the pool last reported op-aggregator gone, so that it reports each change once.
    aggregator_reported_absent: Option<bool>,
}

impl Inner {
    /// Whether block `number` hashed `hash` is a canonical block the pool remembers.
    fn canonical(&self, number: u64, hash: B256) -> bool {
        self.blocks.get(&number).is_some_and(|block| block.hash == hash)
    }

    /// The `through` the next aggregate must exceed: the highest block an aggregate answers for,
    /// queued or already finalized.
    fn last_through(&self) -> Option<u64> {
        self.aggregates.back().map(|aggregate| aggregate.through).or(self.forgotten_through)
    }

    /// Whether the safe head has reached `aggregate`'s blocks, so derivation has decided them.
    fn decided(&self, aggregate: &PendingAggregate) -> bool {
        self.safe.is_some_and(|safe| aggregate.through <= safe)
    }

    /// The queued aggregates the safe head has not reached.
    fn undecided(&self) -> impl Iterator<Item = &PendingAggregate> {
        self.aggregates.iter().filter(|aggregate| !self.decided(aggregate))
    }

    /// Whether the queue is full, so that a new aggregate would be refused.
    fn queue_full(&self) -> bool {
        self.undecided().count() >= MAX_PENDING_AGGREGATES
    }

    /// Checks that `aggregate`, whose `through` is the block hashed `through_hash`, may be queued:
    /// there is room, it follows the last queued aggregate, `through` is canonical, and it proves
    /// every provable statement of the blocks it answers for.
    fn admits(
        &self,
        aggregate: &PendingAggregate,
        through_hash: B256,
    ) -> Result<(), ProofAggregationPoolError> {
        if self.queue_full() {
            return Err(ProofAggregationPoolError::AggregatesFull);
        }
        let through = aggregate.through;
        let after = self.last_through();
        if after.is_some_and(|after| through <= after) {
            return Err(ProofAggregationPoolError::OutOfOrder { through });
        }
        if !self.canonical(through, through_hash) {
            return Err(ProofAggregationPoolError::Reorged);
        }
        let proven: HashSet<B256> = aggregate.statements.iter().map(|s| s.id()).collect();
        let unproven = self
            .blocks
            .range(after.map_or(0, |after| after + 1)..=through)
            .flat_map(|(_, block)| self.provable(block))
            .find(|id| !proven.contains(id));
        if let Some(id) = unproven {
            return Err(ProofAggregationPoolError::Incomplete(id));
        }
        Ok(())
    }

    /// Forgets the aggregates the finalized head has reached, and the oldest decided ones past
    /// `MAX_DECIDED_AGGREGATES`.
    fn forget(&mut self) {
        loop {
            let decided =
                self.aggregates.iter().filter(|aggregate| self.decided(aggregate)).count();
            let Some(front) = self.aggregates.front() else { break };
            let finalized = self.finalized.is_some_and(|finalized| front.through <= finalized);
            let excess = self.decided(front) && decided > MAX_DECIDED_AGGREGATES;
            if !(finalized || excess) {
                break;
            }
            let through = self.aggregates.pop_front().map(|aggregate| aggregate.through);
            self.forgotten_through = self.forgotten_through.max(through);
        }
    }

    /// The statements of a block that an aggregate can prove: those whose proofs the pool holds.
    /// A dependent transaction whose proofs were lost (a restart, a takeover) cannot be covered;
    /// derivation replaces its block.
    fn provable(&self, block: &CanonicalBlock) -> HashSet<B256> {
        block
            .txs
            .iter()
            .flat_map(|tx| tx.statement_ids.iter().copied())
            .filter(|id| self.proofs.contains_key(id))
            .collect()
    }

    /// The programs the statements `ids` are of, from the held proofs and `extra`. A statement
    /// without a proof in either counts as a program of its own.
    fn programs_of<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a B256>,
        extra: &[StatementProof],
    ) -> HashSet<B256> {
        ids.into_iter()
            .map(|id| {
                self.proofs
                    .get(id)
                    .or_else(|| extra.iter().find(|proof| &proof.statement.id() == id))
                    .map_or(*id, |proof| proof.statement.vkey_hash)
            })
            .collect()
    }

    /// Every statement an aggregate over the sources of `ids` holds, of the held proofs or else
    /// those in `extra`: each member of their program leaves. A statement whose source neither
    /// holds counts as itself, of a program of its own.
    fn folded_statements<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a B256>,
        extra: &[StatementProof],
    ) -> HashSet<ProofStatement> {
        ids.into_iter()
            .flat_map(|id| {
                self.proofs
                    .get(id)
                    .or_else(|| extra.iter().find(|proof| &proof.statement.id() == id))
                    .map_or_else(
                        || vec![ProofStatement { vkey_hash: *id, public_values_digest: *id }],
                        |proof| proof.source.statements(&proof.statement),
                    )
            })
            .collect()
    }

    /// The bytes of the held sources, each shared source once.
    fn exact_held_bytes(&self) -> usize {
        let mut seen = HashSet::new();
        self.proofs
            .values()
            .filter(|proof| seen.insert(proof.source.address()))
            .map(|proof| proof.source.bytes())
            .sum()
    }

    /// Statement ids still needed by admitted transactions or remembered blocks.
    fn needed(&self) -> HashSet<B256> {
        self.admitted
            .values()
            .flat_map(|(ids, _)| ids.iter().copied())
            .chain(
                self.blocks.values().flat_map(|block| {
                    block.txs.iter().flat_map(|tx| tx.statement_ids.iter().copied())
                }),
            )
            .collect()
    }

    fn prune_proofs(&mut self) {
        let needed = self.needed();
        self.proofs.retain(|id, _| needed.contains(id));
        self.held_bytes = self.exact_held_bytes();
    }

    /// Counts again what the blocks after the last aggregate leave to prove: each statement once,
    /// every member of a program leaf, and none whose proof the pool does not hold, as a new leader
    /// holds none for the blocks it followed.
    fn count_uncovered(&mut self) {
        let covered = self.last_through();
        let ids: HashSet<B256> = self
            .blocks
            .iter()
            .filter(|(number, _)| covered.is_none_or(|covered| **number > covered))
            .flat_map(|(_, block)| self.provable(block))
            .collect();
        self.uncovered_statements = self.folded_statements(&ids, &[]).len();
    }

    /// The most statements a block may rely on: what an empty run of the default mode holds, or
    /// a block's even share of an aggregate with fixed runs, which keeps a run within one.
    const fn block_statement_limit(&self) -> usize {
        match self.run_blocks {
            0 => TARGET_PROOF_AGGREGATE_STATEMENTS,
            k => MAX_PROOF_AGGREGATE_STATEMENTS / k as usize,
        }
    }

    /// The oldest canonical block with provable statements no aggregate covers.
    fn oldest_uncovered(&self) -> Option<u64> {
        let covered = self.last_through();
        self.blocks
            .iter()
            .filter(|(number, _)| covered.is_none_or(|covered| **number > covered))
            .find(|(_, block)| !self.provable(block).is_empty())
            .map(|(number, _)| *number)
    }

    fn paused_at(&self, now: Instant) -> bool {
        let Some(oldest) = self.oldest_uncovered() else { return false };
        let too_old = self.blocks[&oldest]
            .seen
            .is_some_and(|seen| now.duration_since(seen) >= MAX_UNCOVERED_AGE);
        let too_many = self.run_blocks > 0 && self.uncovered_statements >= MAX_UNCOVERED_STATEMENTS;
        too_old || too_many || self.uncovered_bytes(oldest) >= MAX_UNCOVERED_BYTES
    }

    /// The transaction bytes from block `oldest` on, and those of the aggregates the safe head has
    /// not reached, which the batcher may post after them.
    fn uncovered_bytes(&self, oldest: u64) -> u64 {
        let blocks: u64 = self.blocks.range(oldest..).map(|(_, block)| block.bytes).sum();
        blocks + self.undecided().map(aggregate_bytes).sum::<u64>()
    }

    /// Whether the uncovered bytes reached [`DUE_UNCOVERED_BYTES`].
    fn bytes_due(&self) -> bool {
        self.oldest_uncovered()
            .is_some_and(|oldest| self.uncovered_bytes(oldest) >= DUE_UNCOVERED_BYTES)
    }

    /// The block at which the transaction bytes from the oldest uncovered block on reach
    /// [`DUE_UNCOVERED_BYTES`], if they do. Unlike [`Self::bytes_due`] it leaves out the
    /// aggregates, and it does not move as later blocks come, so a run ending there spans those
    /// bytes whatever the prover's lag: a late prover closes no more often for being late.
    fn due_through(&self) -> Option<u64> {
        let oldest = self.oldest_uncovered()?;
        let mut bytes = 0;
        self.blocks.range(oldest..).find_map(|(number, block)| {
            bytes += block.bytes;
            (bytes >= DUE_UNCOVERED_BYTES).then_some(*number)
        })
    }

    /// Forgets the canonical blocks from `first` on, as a reorg replaces them. Their dependent
    /// transactions whose proofs the pool still holds are admitted again: no aggregate could cover
    /// the others, and derivation would replace any block holding them. Any queued aggregate
    /// reaching `first` is dropped: it was proven over the blocks the reorg removed. Coverage and
    /// the safe head below `first` go back with it, so that the replacement blocks get aggregates.
    fn roll_back(&mut self, first: u64) {
        let reverted = self.blocks.split_off(&first);
        for block in reverted.into_values() {
            for tx in block.txs {
                if tx.statement_ids.iter().all(|id| self.proofs.contains_key(id)) {
                    self.admitted.insert(
                        tx.hash,
                        (tx.statement_ids, block.seen.unwrap_or_else(Instant::now)),
                    );
                }
            }
        }
        self.aggregates.retain(|aggregate| aggregate.through < first);
        self.head = first.checked_sub(1);
        let head = self.head;
        let below = |number: Option<u64>| number.and_then(|n| head.map(|head| n.min(head)));
        self.forgotten_through = below(self.forgotten_through);
        self.safe = below(self.safe);
        self.finalized = below(self.finalized);
    }
}

/// About the bytes a proof aggregate batch carrying `aggregate` takes.
fn aggregate_bytes(aggregate: &PendingAggregate) -> u64 {
    (aggregate.proof.len() + aggregate.statements.len() * 2 * 32) as u64
}

/// Shared handle to the sequencer's dependency bookkeeping. Clones share the same state: the RPC
/// handlers, the transaction pool's validator, the payload builder and the canonical chain
/// listener all use it.
#[derive(Clone, Default)]
pub struct ProofAggregationPool {
    inner: Arc<Mutex<Inner>>,
    /// Whether the pool hands out no run to aggregate, so that no aggregate is ever proven.
    no_aggregation: bool,
    /// What verifies a submitted aggregate's proof before it is queued; none only in tests of the
    /// bookkeeping, whose aggregates carry no proof.
    verifier: Option<SharedProofAggregateVerifier>,
    /// How long the pool goes without a request from op-aggregator before it pauses dependent
    /// transactions; none for a pool no aggregator serves, as in tests of the bookkeeping or one
    /// that hands out no run.
    aggregator_timeout: Option<Duration>,
}

impl std::fmt::Debug for ProofAggregationPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofAggregationPool")
            .field("no_aggregation", &self.no_aggregation)
            .field("verifies", &self.verifier.is_some())
            .field("aggregator_timeout", &self.aggregator_timeout)
            .finish_non_exhaustive()
    }
}

/// A block with provable statements: its number and hash, and the proofs of those statements.
pub type ProvableBlock = ((u64, B256), Vec<StatementProof>);

/// The pool's state as op-aggregator reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationStatus {
    /// The canonical head, by number and hash.
    pub head: Option<(u64, B256)>,
    /// The safe head.
    pub safe: Option<u64>,
    /// The finalized head.
    pub finalized: Option<u64>,
    /// The highest `through` of the queued or forgotten aggregates.
    pub last_through: Option<u64>,
    /// Whether a new aggregate would be refused because the queue is full.
    pub queue_full: bool,
    /// Whether new dependent transactions are refused because aggregates are late.
    pub paused: bool,
    /// How many blocks a run spans, if runs are fixed; zero if op-aggregator closes them itself.
    pub run_blocks: u64,
    /// Whether the transactions after the oldest uncovered block approach the bytes at which new
    /// dependent transactions pause: the open run is due, however young.
    pub bytes_due: bool,
    /// With fixed runs, the block a run ends at if it would otherwise reach
    /// [`DUE_UNCOVERED_BYTES`] of transactions before its boundary.
    pub due_through: Option<u64>,
}

impl ProofAggregationPool {
    /// A pool that hands out no run to aggregate: the sequencer admits and includes dependent
    /// transactions but never proves an aggregate for them. For tests of derivation replacing
    /// blocks no aggregate answers for.
    pub fn without_aggregation() -> Self {
        Self { no_aggregation: true, ..Default::default() }
    }

    /// This pool, verifying each submitted aggregate's proof with `verifier` before queueing it.
    pub fn with_verifier(mut self, verifier: SharedProofAggregateVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// This pool, pausing dependent transactions while op-aggregator, which proves its aggregates
    /// over op-reth's authenticated endpoint, has made no request for `timeout`
    /// ([`AGGREGATOR_TIMEOUT`] in a node): from the start until op-aggregator first connects, and
    /// once it goes.
    pub const fn requiring_aggregator(mut self, timeout: Duration) -> Self {
        self.aggregator_timeout = Some(timeout);
        self
    }

    /// This pool, with runs of `blocks` blocks ending where `(n + 1) % blocks == 0`, so that
    /// op-aggregator and op-batcher meet there without asking each other; zero leaves runs to
    /// op-aggregator. `blocks` is at most [`MAX_RUN_BLOCKS`].
    pub fn with_run_blocks(self, blocks: u64) -> Self {
        assert!(blocks <= MAX_RUN_BLOCKS, "a run of {blocks} blocks could not hold a full leaf");
        self.lock().run_blocks = blocks;
        self
    }

    /// How many blocks a run spans, if runs are fixed; zero if op-aggregator closes them itself.
    pub fn run_blocks(&self) -> u64 {
        self.lock().run_blocks
    }

    /// Records a request from op-aggregator: it is there to prove aggregates.
    pub fn aggregator_contacted(&self) {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.aggregator_seen = Some(now);
        self.check_aggregator(&mut inner, now);
    }

    /// Whether op-aggregator is gone at `now`, for a pool that requires one, logging as that
    /// changes. The pool checks on every canonical block, and sets the
    /// `op_proof_aggregation_aggregator_attached` gauge there, so that both follow op-aggregator
    /// going on a chain with no dependent transaction.
    fn check_aggregator(&self, inner: &mut Inner, now: Instant) -> bool {
        let Some(timeout) = self.aggregator_timeout else { return false };
        let absent = inner.aggregator_seen.is_none_or(|seen| now.duration_since(seen) >= timeout);
        if inner.aggregator_reported_absent != Some(absent) {
            inner.aggregator_reported_absent = Some(absent);
            if absent {
                tracing::warn!(target: "payload_builder::proof_aggregation", ?timeout, "no op-aggregator is proving aggregates: pausing dependent transactions, which no aggregate would answer for");
            } else {
                tracing::info!(target: "payload_builder::proof_aggregation", "op-aggregator is proving aggregates: taking dependent transactions");
            }
        }
        absent
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether one block may rely on all of `statement_ids`, whose sources the pool holds: no more
    /// statements than the block limit, nor statements of more programs than the class covers,
    /// counting every member of their program leaves. A statement whose
    /// source the pool does not hold counts as a program of its own.
    pub fn fits_one_aggregate<'a>(
        &self,
        statement_ids: impl IntoIterator<Item = &'a B256>,
    ) -> bool {
        let inner = self.lock();
        let statements = inner.folded_statements(statement_ids, &[]);
        statements.len() <= inner.block_statement_limit() &&
            statements.iter().map(|s| s.vkey_hash).collect::<HashSet<_>>().len() <=
                MAX_PROOF_AGGREGATE_PROGRAMS
    }

    /// Checks a statement source's fields against their size limits.
    pub fn check_sizes(source: &StatementSource) -> Result<(), ProofAggregationPoolError> {
        let fields = match source {
            StatementSource::Program(leaf) => [
                ("proof", leaf.proof.len(), MAX_STATEMENT_PROOF_BYTES),
                ("verifying key", leaf.verifying_key.len(), MAX_STATEMENT_VERIFYING_KEY_BYTES),
                ("member list", leaf.members.len() * 32, MAX_LEAF_MEMBERS * 32),
            ],
            StatementSource::Signature(signed) => [
                ("public key", signed.public_key.len(), MAX_SIGNATURE_BYTES),
                ("signature", signed.signature.len(), MAX_SIGNATURE_BYTES),
                ("message", 32, 32),
            ],
        };
        for (field, len, limit) in fields {
            if len > limit {
                return Err(ProofAggregationPoolError::TooLarge { field, limit });
            }
        }
        Ok(())
    }

    /// Whether a proof of `statement_id` is held.
    pub fn holds_proof(&self, statement_id: &B256) -> bool {
        self.lock().proofs.contains_key(statement_id)
    }

    /// Whether new dependent transactions are paused: aggregates are behind, or no op-aggregator
    /// proves them ([`Self::dependencies_refused`]).
    pub fn dependencies_paused(&self) -> bool {
        self.dependencies_refused().is_some()
    }

    /// Why the sequencer takes no new dependent transactions now, if it does not: no
    /// op-aggregator proves its aggregates ([`ProofAggregationPoolError::AggregatorAbsent`]), or
    /// they are late ([`ProofAggregationPoolError::DependenciesPaused`]).
    pub fn dependencies_refused(&self) -> Option<ProofAggregationPoolError> {
        let now = Instant::now();
        let mut inner = self.lock();
        self.refusal_at(&mut inner, now)
    }

    fn refusal_at(&self, inner: &mut Inner, now: Instant) -> Option<ProofAggregationPoolError> {
        if self.check_aggregator(inner, now) {
            Some(ProofAggregationPoolError::AggregatorAbsent)
        } else if inner.paused_at(now) {
            Some(ProofAggregationPoolError::DependenciesPaused)
        } else {
            None
        }
    }

    /// Admits transaction `hash` depending on `statement_ids`, adding the verified proofs in
    /// `proofs` that the pool does not hold yet. Together with the held ones they must cover every
    /// statement.
    pub fn admit(
        &self,
        hash: B256,
        statement_ids: Vec<B256>,
        proofs: Vec<StatementProof>,
    ) -> Result<(), ProofAggregationPoolError> {
        self.admit_at(hash, statement_ids, proofs, Instant::now())
    }

    fn admit_at(
        &self,
        hash: B256,
        statement_ids: Vec<B256>,
        proofs: Vec<StatementProof>,
        now: Instant,
    ) -> Result<(), ProofAggregationPoolError> {
        if statement_ids.is_empty() || statement_ids.len() > MAX_STATEMENTS_PER_TX {
            return Err(ProofAggregationPoolError::WrongStatementCount {
                max: MAX_STATEMENTS_PER_TX,
            });
        }
        for proof in &proofs {
            Self::check_sizes(&proof.source)?;
        }
        let mut inner = self.lock();
        inner.admitted.retain(|_, (_, admitted)| now.duration_since(*admitted) < ADMISSION_TTL);
        if let Some(refusal) = self.refusal_at(&mut inner, now) {
            return Err(refusal);
        }
        if inner.admitted.contains_key(&hash) {
            return Err(ProofAggregationPoolError::AlreadyAdmitted);
        }
        if inner.admitted.len() >= MAX_ADMITTED_TXS {
            return Err(ProofAggregationPoolError::AdmittedTxsFull);
        }
        let new: Vec<StatementProof> = proofs
            .into_iter()
            .filter(|proof| !inner.proofs.contains_key(&proof.statement.id()))
            .collect();
        if let Some(missing) = statement_ids.iter().find(|id| {
            !inner.proofs.contains_key(*id) && !new.iter().any(|proof| &proof.statement.id() == *id)
        }) {
            return Err(ProofAggregationPoolError::MissingProof(*missing));
        }
        if inner.programs_of(&statement_ids, &new).len() > MAX_PROOF_AGGREGATE_PROGRAMS {
            return Err(ProofAggregationPoolError::TooManyPrograms {
                max: MAX_PROOF_AGGREGATE_PROGRAMS,
            });
        }
        // Else no block could take the transaction, whose admission would lapse unused.
        let max = inner.block_statement_limit();
        if inner.folded_statements(&statement_ids, &new).len() > max {
            return Err(ProofAggregationPoolError::TooManyFoldedStatements { max });
        }
        let mut sources = HashSet::new();
        let new_bytes: usize = new
            .iter()
            .filter(|proof| sources.insert(proof.source.address()))
            .map(|proof| proof.source.bytes())
            .sum();
        if inner.proofs.len() + new.len() > MAX_STATEMENT_PROOFS ||
            inner.held_bytes + new_bytes > MAX_HELD_SOURCE_BYTES
        {
            return Err(ProofAggregationPoolError::StatementProofsFull);
        }
        inner.held_bytes += new_bytes;
        for proof in new {
            inner.proofs.insert(proof.statement.id(), proof);
        }
        inner.admitted.insert(hash, (statement_ids, now));
        Ok(())
    }

    /// Withdraws the admission of `hash`, as when the transaction pool refuses the transaction.
    pub fn unadmit(&self, hash: &B256) {
        let mut inner = self.lock();
        inner.admitted.remove(hash);
        inner.prune_proofs();
    }

    /// The statement ids of admitted transaction `hash`, if it may be included.
    pub fn admitted(&self, hash: &B256) -> Option<Vec<B256>> {
        self.lock().admitted.get(hash).map(|(ids, _)| ids.clone())
    }

    /// Takes canonical block `number` hashed `hash`: the dependent transactions it holds, with
    /// their statement ids, and the bytes of all its transactions. A block at or below the head
    /// seen so far replaces the blocks from it on, as after a reorg.
    pub fn on_canonical_block(
        &self,
        number: u64,
        hash: B256,
        dependent: Vec<(B256, Vec<B256>)>,
        bytes: u64,
    ) {
        self.on_canonical_block_at(number, hash, dependent, bytes, Instant::now());
    }

    fn on_canonical_block_at(
        &self,
        number: u64,
        hash: B256,
        dependent: Vec<(B256, Vec<B256>)>,
        bytes: u64,
        now: Instant,
    ) {
        let mut inner = self.lock();
        if self.aggregator_timeout.is_some() {
            let absent = self.check_aggregator(&mut inner, now);
            reth_metrics::metrics::gauge!("op_proof_aggregation_aggregator_attached")
                .set(f64::from(u8::from(!absent)));
        }
        if inner.head.is_some_and(|head| number <= head) {
            inner.roll_back(number);
        }
        let txs = dependent
            .into_iter()
            .map(|(hash, statement_ids)| {
                inner.admitted.remove(&hash);
                IncludedTx { hash, statement_ids }
            })
            .collect();
        inner.blocks.insert(number, CanonicalBlock { hash, txs, bytes, seen: Some(now) });
        inner.head = Some(number);
        let oldest_kept = number.saturating_sub(REORG_DEPTH);
        let keep_from =
            inner.oldest_uncovered().map_or(oldest_kept, |oldest| oldest.min(oldest_kept));
        inner.blocks = inner.blocks.split_off(&keep_from);
        inner.count_uncovered();
        inner.admitted.retain(|_, (_, admitted)| now.duration_since(*admitted) < ADMISSION_TTL);
        inner.prune_proofs();
    }

    /// The first canonical block after `after`, and after the last queued aggregate's `through`,
    /// whose dependent transactions hold provable statements: its number and hash, and the proofs
    /// of those statements. `None` while there is none, and on a pool that aggregates nothing.
    ///
    /// op-aggregator folds blocks in this order, naming the last block it folded as
    /// `after`, by number and hash: [`ProofAggregationPoolError::Reorged`] if a reorg replaced it.
    pub fn next_provable_block(
        &self,
        after: Option<(u64, B256)>,
    ) -> Result<Option<ProvableBlock>, ProofAggregationPoolError> {
        let inner = self.lock();
        if let Some((number, hash)) = after {
            let covered = inner.last_through().is_some_and(|through| number <= through);
            if !covered && !inner.canonical(number, hash) {
                return Err(ProofAggregationPoolError::Reorged);
            }
        }
        if self.no_aggregation {
            return Ok(None);
        }
        let after = after.map(|(number, _)| number).max(inner.last_through());
        Ok(inner.blocks.range(after.map_or(0, |after| after + 1)..).find_map(|(number, block)| {
            let mut ids: Vec<B256> = inner.provable(block).into_iter().collect();
            ids.sort();
            (!ids.is_empty()).then(|| {
                let proofs = ids.iter().filter_map(|id| inner.proofs.get(id).cloned()).collect();
                ((*number, block.hash), proofs)
            })
        }))
    }

    /// The source the pool holds for statement `id`.
    pub fn source(&self, id: &B256) -> Option<StatementSource> {
        self.lock().proofs.get(id).map(|proof| proof.source.clone())
    }

    /// Drops the sources of those of `statements` that block `number` hashed `hash` depends on,
    /// as op-aggregator asks for a block it cannot fold: later aggregates go past the block, and
    /// derivation replaces it. Returns whether the block is canonical; if not, nothing is dropped.
    pub fn forget_block_proofs<'a>(
        &self,
        (number, hash): (u64, B256),
        statements: impl IntoIterator<Item = &'a ProofStatement>,
    ) -> bool {
        let mut inner = self.lock();
        if !inner.canonical(number, hash) {
            return false;
        }
        let of_block: HashSet<B256> = inner.blocks[&number]
            .txs
            .iter()
            .flat_map(|tx| tx.statement_ids.iter().copied())
            .collect();
        for statement in statements {
            let id = statement.id();
            if of_block.contains(&id) {
                inner.proofs.remove(&id);
            }
        }
        true
    }

    /// The pool's state, as op-aggregator reads it.
    pub fn status(&self) -> AggregationStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> AggregationStatus {
        let inner = self.lock();
        AggregationStatus {
            head: inner
                .head
                .and_then(|head| inner.blocks.get(&head).map(|block| (head, block.hash))),
            safe: inner.safe,
            finalized: inner.finalized,
            last_through: inner.last_through(),
            queue_full: inner.queue_full(),
            paused: inner.paused_at(now),
            run_blocks: inner.run_blocks,
            bytes_due: inner.bytes_due(),
            due_through: if inner.run_blocks > 0 { inner.due_through() } else { None },
        }
    }

    /// Verifies `aggregate`, whose `through` is the block hashed `through_hash`, and queues it.
    /// Its `through` must follow the last queued aggregate's and be canonical, and it must prove
    /// every provable statement of the blocks it answers for. The cheap checks run first, so that
    /// a refused aggregate costs no verification; the proof, which takes milliseconds, is verified
    /// without the lock, and the checks run again before it is queued.
    pub fn submit_aggregate(
        &self,
        aggregate: PendingAggregate,
        through_hash: B256,
    ) -> Result<(), ProofAggregationPoolError> {
        if aggregate.statements.len() > MAX_PROOF_AGGREGATE_STATEMENTS {
            return Err(ProofAggregationPoolError::TooManyStatements);
        }
        self.lock().admits(&aggregate, through_hash)?;
        if let Some(verifier) = &self.verifier {
            ProofAggregatePayload::from(aggregate.clone())
                .verify(&**verifier)
                .map_err(ProofAggregationPoolError::InvalidProof)?;
        }
        let mut inner = self.lock();
        inner.admits(&aggregate, through_hash)?;
        inner.aggregates.push_back(aggregate);
        inner.count_uncovered();
        Ok(())
    }

    /// The queued aggregates the safe head has not reached, in `through` order, for the batcher
    /// to post.
    pub fn pending_aggregates(&self) -> Vec<PendingAggregate> {
        self.lock().undecided().cloned().collect()
    }

    /// Records the safe head `safe`. It may move back, after an L1 reorg: the aggregates above it
    /// are pending again.
    pub fn on_safe(&self, safe: u64) {
        let mut inner = self.lock();
        inner.safe = Some(safe);
        inner.forget();
    }

    /// Records the finalized head `finalized`, and forgets the aggregates it reaches.
    pub fn on_finalized(&self, finalized: u64) {
        let mut inner = self.lock();
        inner.finalized = Some(finalized);
        inner.forget();
    }
}

/// What a canonical block holds that the pool tracks: its dependent transactions, by admission key
/// ([`op_alloy_consensus::DeclaredDependencies::key`]), with their statement ids. Feed it to
/// [`ProofAggregationPool::on_canonical_block`] with the block's transaction bytes.
pub fn dependency_facts<'a>(
    encoded_txs: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<(B256, Vec<B256>)> {
    encoded_txs
        .into_iter()
        .filter_map(op_alloy_consensus::declared_dependencies)
        .map(|declared| (declared.key, declared.statement_ids()))
        .filter(|(_, ids)| !ids.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A statement proof of program `byte` with output `byte`.
    fn proof(byte: u8) -> StatementProof {
        proof_of(byte, byte)
    }

    /// A statement proof of program `program` with member `byte`: a leaf publishing the member.
    fn proof_of(byte: u8, program: u8) -> StatementProof {
        StatementProof {
            statement: ProofStatement {
                vkey_hash: B256::repeat_byte(program),
                public_values_digest: B256::repeat_byte(byte),
            },
            source: StatementSource::Program(Arc::new(ProgramLeaf {
                program: B256::repeat_byte(program),
                verifying_key: Bytes::from(vec![program; 3]),
                proof: Bytes::from(vec![byte; 4]),
                members: vec![B256::repeat_byte(byte)],
            })),
        }
    }

    /// A one-member leaf of program `program`, numbered past what one byte names.
    fn program_leaf(program: u16) -> StatementProof {
        let id = B256::left_padding_from(&(program + 1).to_be_bytes());
        StatementProof {
            statement: ProofStatement { vkey_hash: id, public_values_digest: id },
            source: StatementSource::Program(Arc::new(ProgramLeaf {
                program: id,
                verifying_key: Bytes::new(),
                proof: Bytes::new(),
                members: vec![id],
            })),
        }
    }

    /// A statement of a leaf of program `program` publishing `members` members, of which the
    /// statement is the first.
    fn wide_leaf(leaf: u16, program: u8, members: usize) -> StatementProof {
        let members: Vec<B256> = (0..members)
            .map(|i| {
                B256::left_padding_from(&[leaf.to_be_bytes(), (i as u16).to_be_bytes()].concat())
            })
            .collect();
        StatementProof {
            statement: ProofStatement {
                vkey_hash: B256::repeat_byte(program),
                public_values_digest: members[0],
            },
            source: StatementSource::Program(Arc::new(ProgramLeaf {
                program: B256::repeat_byte(program),
                verifying_key: Bytes::new(),
                proof: Bytes::new(),
                members,
            })),
        }
    }

    /// Admits transaction `byte` depending on `proofs` and makes canonical block `number` hold it.
    fn include_proofs(
        pool: &ProofAggregationPool,
        number: u64,
        byte: u8,
        proofs: Vec<StatementProof>,
    ) {
        let ids: Vec<B256> = proofs.iter().map(|proof| proof.statement.id()).collect();
        pool.admit(tx(byte), ids.clone(), proofs).unwrap();
        pool.on_canonical_block(number, hash(number), vec![(tx(byte), ids)], 0);
    }

    /// The hash of block `number` in these tests' chain.
    fn hash(number: u64) -> B256 {
        B256::left_padding_from(&number.to_be_bytes())
    }

    /// The next block op-aggregator would fold, after the last queued aggregate.
    fn next(pool: &ProofAggregationPool) -> Option<(u64, Vec<StatementProof>)> {
        pool.next_provable_block(None).unwrap().map(|((number, _), proofs)| (number, proofs))
    }

    /// The next block after canonical block `number`.
    fn next_after(pool: &ProofAggregationPool, number: u64) -> Option<(u64, Vec<StatementProof>)> {
        pool.next_provable_block(Some((number, hash(number))))
            .unwrap()
            .map(|((number, _), proofs)| (number, proofs))
    }

    /// Submits `aggregate`, naming its `through` by this chain's hash.
    fn submit(
        pool: &ProofAggregationPool,
        aggregate: PendingAggregate,
    ) -> Result<(), ProofAggregationPoolError> {
        let through = aggregate.through;
        pool.submit_aggregate(aggregate, hash(through))
    }

    fn id(byte: u8) -> B256 {
        proof(byte).statement.id()
    }

    fn tx(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn aggregate(through: u64, bytes: &[u8]) -> PendingAggregate {
        PendingAggregate {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
            through,
            statements: bytes.iter().map(|byte| proof(*byte).statement).collect(),
            proof: Bytes::from_static(b"agg"),
        }
    }

    /// Makes canonical block `number`, holding nothing the pool tracks.
    fn empty(pool: &ProofAggregationPool, number: u64) {
        pool.on_canonical_block(number, hash(number), vec![], 0);
    }

    /// Admits transaction `byte` depending on and bringing the proofs of `bytes`, then makes
    /// canonical block `number` holding it.
    fn include(pool: &ProofAggregationPool, number: u64, byte: u8, bytes: &[u8]) {
        let ids: Vec<B256> = bytes.iter().map(|b| id(*b)).collect();
        pool.admit(tx(byte), ids.clone(), bytes.iter().map(|b| proof(*b)).collect()).unwrap();
        pool.on_canonical_block(number, hash(number), vec![(tx(byte), ids)], 0);
    }

    #[test]
    fn admission_needs_every_proof() {
        let pool = ProofAggregationPool::default();
        assert_eq!(
            pool.admit(tx(1), vec![id(1)], vec![]),
            Err(ProofAggregationPoolError::MissingProof(id(1)))
        );
        pool.admit(tx(1), vec![id(1)], vec![proof(1)]).unwrap();
        // A held proof needs no second copy.
        pool.admit(tx(2), vec![id(1)], vec![]).unwrap();
        assert_eq!(pool.admitted(&tx(2)), Some(vec![id(1)]));
        assert_eq!(
            pool.admit(tx(2), vec![id(1)], vec![]),
            Err(ProofAggregationPoolError::AlreadyAdmitted)
        );
        pool.unadmit(&tx(1));
        pool.unadmit(&tx(2));
        assert!(!pool.holds_proof(&id(1)), "nothing needs the proof any more");
    }

    #[test]
    fn hands_out_provable_blocks_after_the_last_aggregate() {
        let pool = ProofAggregationPool::default();
        assert_eq!(next(&pool), None);
        include(&pool, 10, 1, &[1, 2]);
        empty(&pool, 11);
        include(&pool, 12, 2, &[2, 3]);
        include(&pool, 13, 3, &[4]);
        assert_eq!(pool.admitted(&tx(1)), None, "an included transaction is no longer admitted");

        let (number, proofs) = next(&pool).unwrap();
        assert_eq!(number, 10);
        assert_eq!(proofs.len(), 2);
        let (number, proofs) = next_after(&pool, 10).unwrap();
        assert_eq!(number, 12, "block 11 holds nothing to prove");
        assert_eq!(proofs.len(), 2);

        submit(&pool, aggregate(12, &[1, 2, 3])).unwrap();
        assert_eq!(next(&pool), Some((13, vec![proof(4)])), "after the aggregate's through");
        assert_eq!(next_after(&pool, 13), None);
    }

    #[test]
    fn an_aggregate_must_prove_its_canonical_blocks_in_order() {
        let pool = ProofAggregationPool::default();
        include(&pool, 10, 1, &[1, 2]);
        assert_eq!(
            submit(&pool, aggregate(10, &[1])),
            Err(ProofAggregationPoolError::Incomplete(id(2)))
        );
        assert_eq!(
            submit(&pool, aggregate(11, &[1, 2])),
            Err(ProofAggregationPoolError::Reorged),
            "block 11 is not canonical yet"
        );
        submit(&pool, aggregate(10, &[1, 2])).unwrap();
        assert_eq!(
            submit(&pool, aggregate(10, &[1, 2])),
            Err(ProofAggregationPoolError::OutOfOrder { through: 10 })
        );
    }

    #[test]
    fn a_reorg_admits_the_removed_blocks_transactions_again() {
        let pool = ProofAggregationPool::default();
        include(&pool, 10, 1, &[1]);
        include(&pool, 11, 2, &[2]);
        submit(&pool, aggregate(11, &[1, 2])).unwrap();

        // A reorg replaces block 11 with one holding no dependent transaction.
        empty(&pool, 11);
        assert_eq!(pool.admitted(&tx(2)), Some(vec![id(2)]));
        assert!(pool.pending_aggregates().is_empty(), "it answered for a removed block");
        assert_eq!(next(&pool).unwrap().0, 10);

        // A replacement block at the same height works the same way.
        empty(&pool, 10);
        assert_eq!(pool.admitted(&tx(1)), Some(vec![id(1)]));
        assert_eq!(next(&pool), None);
    }

    /// A replaced block's transaction goes back only with its proofs: included again without them,
    /// it would get its next block replaced too.
    #[test]
    fn a_reorg_leaves_out_a_transaction_whose_proofs_are_lost() {
        let pool = ProofAggregationPool::default();
        include(&pool, 10, 1, &[1]);
        include(&pool, 11, 2, &[2]);
        assert!(pool.forget_block_proofs((10, hash(10)), [&proof(1).statement]));

        empty(&pool, 10);
        assert_eq!(pool.admitted(&tx(1)), None, "its proofs are gone");
        assert_eq!(pool.admitted(&tx(2)), Some(vec![id(2)]));
    }

    /// A dependent transaction whose proofs the pool lost cannot be covered; it must not stall the
    /// aggregates of the blocks around it.
    #[test]
    fn statements_without_proofs_do_not_stall_aggregation() {
        let pool = ProofAggregationPool::default();
        pool.on_canonical_block(10, hash(10), vec![(tx(9), vec![id(9)])], 0);
        include(&pool, 11, 1, &[1]);
        assert_eq!(next(&pool), Some((11, vec![proof(1)])));
        submit(&pool, aggregate(11, &[1])).unwrap();
        assert!(!pool.dependencies_paused());
    }

    #[test]
    fn late_aggregates_pause_dependent_transactions() {
        let pool = ProofAggregationPool::default();
        let start = Instant::now();
        pool.admit_at(tx(1), vec![id(1)], vec![proof(1)], start).unwrap();
        pool.on_canonical_block_at(10, hash(10), vec![(tx(1), vec![id(1)])], 0, start);
        let later = start + MAX_UNCOVERED_AGE;
        assert_eq!(
            pool.admit_at(tx(2), vec![id(1)], vec![], later),
            Err(ProofAggregationPoolError::DependenciesPaused)
        );
        submit(&pool, aggregate(10, &[1])).unwrap();
        assert!(!pool.lock().paused_at(later), "covered");
    }

    /// A pool requiring op-aggregator takes no dependent transaction, and the builder includes
    /// none, until op-aggregator first makes a request, nor once it has made none for the timeout.
    #[test]
    fn dependent_transactions_wait_for_op_aggregator() {
        let timeout = Duration::from_secs(60);
        let pool = ProofAggregationPool::default().requiring_aggregator(timeout);
        let start = Instant::now();
        assert_eq!(
            pool.admit_at(tx(1), vec![id(1)], vec![proof(1)], start),
            Err(ProofAggregationPoolError::AggregatorAbsent),
            "none yet"
        );
        assert_eq!(pool.dependencies_refused(), Some(ProofAggregationPoolError::AggregatorAbsent));
        assert!(pool.dependencies_paused());

        pool.aggregator_contacted();
        let now = Instant::now();
        assert!(!pool.dependencies_paused());
        pool.admit_at(tx(1), vec![id(1)], vec![proof(1)], now).unwrap();

        assert_eq!(
            pool.admit_at(tx(2), vec![id(1)], vec![], now + timeout),
            Err(ProofAggregationPoolError::AggregatorAbsent),
            "gone"
        );
        assert!(!pool.lock().paused_at(now + timeout), "aggregates are not late");
        pool.aggregator_contacted();
        pool.admit_at(tx(2), vec![id(1)], vec![], Instant::now()).unwrap();

        let unattended = ProofAggregationPool::default();
        unattended.admit(tx(3), vec![id(3)], vec![proof(3)]).unwrap();
        assert!(!unattended.dependencies_paused(), "a pool no aggregator serves");
    }

    /// Each canonical block checks op-aggregator, so that the pool reports it gone on a chain no
    /// dependent transaction reaches.
    #[test]
    fn canonical_blocks_report_op_aggregator_gone() {
        let timeout = Duration::from_secs(60);
        let pool = ProofAggregationPool::default().requiring_aggregator(timeout);
        pool.aggregator_contacted();
        assert_eq!(pool.lock().aggregator_reported_absent, Some(false));
        pool.on_canonical_block_at(10, hash(10), vec![], 0, Instant::now() + timeout);
        assert_eq!(pool.lock().aggregator_reported_absent, Some(true));
    }

    /// Half the pausing bytes make the open run due, however young.
    #[test]
    fn half_the_pausing_bytes_make_a_run_due() {
        let pool = ProofAggregationPool::default();
        include(&pool, 10, 1, &[1]);
        pool.on_canonical_block(11, hash(11), vec![], DUE_UNCOVERED_BYTES - 1);
        assert!(!pool.status().bytes_due);
        pool.on_canonical_block(12, hash(12), vec![], 1);
        assert!(pool.status().bytes_due);
        assert!(!pool.dependencies_paused());
    }

    #[test]
    fn bytes_after_the_oldest_uncovered_block_pause_dependent_transactions() {
        let pool = ProofAggregationPool::default();
        include(&pool, 10, 1, &[1]);
        pool.on_canonical_block(11, hash(11), vec![], MAX_UNCOVERED_BYTES - 1);
        assert!(!pool.dependencies_paused());
        pool.on_canonical_block(12, hash(12), vec![], 1);
        assert!(pool.dependencies_paused());
    }

    #[test]
    fn rejects_oversized_fields() {
        let pool = ProofAggregationPool::default();
        let leaf = |edit: &dyn Fn(&mut ProgramLeaf)| {
            let mut leaf = ProgramLeaf {
                program: B256::repeat_byte(1),
                verifying_key: Bytes::new(),
                proof: Bytes::new(),
                members: vec![B256::repeat_byte(1)],
            };
            edit(&mut leaf);
            StatementProof { source: StatementSource::Program(Arc::new(leaf)), ..proof(1) }
        };
        let refused = |proof: StatementProof| pool.admit(tx(1), vec![id(1)], vec![proof]);
        assert_eq!(
            refused(leaf(&|l| l.proof = vec![0; MAX_STATEMENT_PROOF_BYTES + 1].into())),
            Err(ProofAggregationPoolError::TooLarge {
                field: "proof",
                limit: MAX_STATEMENT_PROOF_BYTES
            })
        );
        assert!(matches!(
            refused(leaf(
                &|l| l.verifying_key = vec![0; MAX_STATEMENT_VERIFYING_KEY_BYTES + 1].into()
            )),
            Err(ProofAggregationPoolError::TooLarge { field: "verifying key", .. })
        ));
        assert!(matches!(
            refused(leaf(&|l| l.members = vec![B256::ZERO; MAX_LEAF_MEMBERS + 1])),
            Err(ProofAggregationPoolError::TooLarge { field: "member list", .. })
        ));
        let signature = StatementProof {
            source: StatementSource::Signature(Arc::new(SignatureSource {
                public_key: Bytes::new(),
                message: B256::ZERO,
                signature: vec![0; MAX_SIGNATURE_BYTES + 1].into(),
            })),
            ..proof(1)
        };
        assert!(matches!(
            refused(signature),
            Err(ProofAggregationPoolError::TooLarge { field: "signature", .. })
        ));
    }

    #[test]
    fn dependency_facts_skips_other_transactions() {
        let plain = vec![0x02, 0xc0];
        assert!(dependency_facts([plain.as_slice()]).is_empty());
    }

    #[test]
    fn checks_that_statements_fit_one_aggregate() {
        let pool = ProofAggregationPool::default();
        let proofs: Vec<StatementProof> =
            (0..MAX_PROOF_AGGREGATE_PROGRAMS as u16).map(program_leaf).collect();
        for (i, chunk) in proofs.chunks(MAX_STATEMENTS_PER_TX).enumerate() {
            include_proofs(&pool, i as u64 + 1, i as u8 + 1, chunk.to_vec());
        }
        let ids: Vec<B256> = proofs.iter().map(|proof| proof.statement.id()).collect();
        assert!(pool.fits_one_aggregate(&ids));
        let one_more = program_leaf(MAX_PROOF_AGGREGATE_PROGRAMS as u16).statement.id();
        assert!(!pool.fits_one_aggregate(ids.iter().chain([&one_more])), "one program too many");

        // Each leaf's every member counts, not only the one a transaction depends on.
        let wide = ProofAggregationPool::default();
        let full = TARGET_PROOF_AGGREGATE_STATEMENTS / MAX_LEAF_MEMBERS;
        let leaves: Vec<StatementProof> =
            (0..=full as u16).map(|leaf| wide_leaf(leaf, 0xee, MAX_LEAF_MEMBERS)).collect();
        for (i, leaf) in leaves.iter().enumerate() {
            include_proofs(&wide, i as u64 + 1, i as u8 + 1, vec![leaf.clone()]);
        }
        let ids: Vec<B256> = leaves.iter().map(|leaf| leaf.statement.id()).collect();
        assert!(wide.fits_one_aggregate(&ids[..full]), "full leaves up to the target");
        assert!(!wide.fits_one_aggregate(&ids), "one full leaf past the target");

        let (number, proofs) = next(&pool).unwrap();
        let statements = proofs.iter().map(|proof| proof.statement).collect();
        let proof = LeanVmTreeProof { root: Bytes::from_static(b"root"), seal: Bytes::new() };
        let aggregate = PendingAggregate {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
            through: number,
            statements,
            proof: proof.to_rlp_bytes(),
        };
        ProofAggregatePayload::from(aggregate.clone()).check_limits().unwrap();
        submit(&pool, aggregate).unwrap();
        assert_eq!(next(&pool).unwrap().0, 2);
    }

    #[test]
    fn reports_a_full_queue() {
        let pool = ProofAggregationPool::default();
        for number in 1..=MAX_PENDING_AGGREGATES as u64 {
            include(&pool, number, number as u8, &[number as u8]);
            assert!(!pool.status().queue_full);
            submit(&pool, aggregate(number, &[number as u8])).unwrap();
        }
        assert!(pool.status().queue_full);
        pool.on_safe(1);
        assert!(!pool.status().queue_full, "a slot freed");
    }

    #[test]
    fn a_pool_without_aggregation_hands_out_no_block() {
        let pool = ProofAggregationPool::without_aggregation();
        include(&pool, 1, 1, &[1]);
        assert_eq!(next(&pool), None);
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        assert!(next(&pool).is_some());
    }

    #[test]
    fn forgotten_proofs_leave_their_blocks_unprovable() {
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        include(&pool, 2, 2, &[2]);
        assert!(!pool.forget_block_proofs((1, B256::ZERO), [&proof(1).statement]), "not canonical");
        assert!(
            pool.forget_block_proofs((1, hash(1)), [&proof(2).statement]),
            "a statement of another block"
        );
        assert_eq!(next(&pool).unwrap().0, 1, "nothing was dropped");
        assert!(pool.forget_block_proofs((1, hash(1)), [&proof(1).statement]));
        assert_eq!(next(&pool).unwrap().0, 2, "block 1 holds nothing provable any more");
    }

    /// op-aggregator names blocks by number and hash: a block a reorg replaced, or an
    /// aggregate through one, is refused as such.
    #[test]
    fn names_blocks_by_hash() {
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        include(&pool, 2, 2, &[2]);
        assert_eq!(next_after(&pool, 1).unwrap().0, 2);
        assert_eq!(pool.status().head, Some((2, hash(2))));
        // Another block 1.
        pool.on_canonical_block(1, B256::repeat_byte(0xb1), vec![(tx(1), vec![id(1)])], 0);
        assert_eq!(
            pool.next_provable_block(Some((1, hash(1)))),
            Err(ProofAggregationPoolError::Reorged)
        );
        assert_eq!(
            pool.submit_aggregate(aggregate(1, &[1]), hash(1)),
            Err(ProofAggregationPoolError::Reorged)
        );
        pool.submit_aggregate(aggregate(1, &[1]), B256::repeat_byte(0xb1)).unwrap();
        // A covered block needs no hash: whatever the caller folded through it is queued.
        assert_eq!(pool.next_provable_block(Some((1, B256::ZERO))), Ok(None));
    }

    /// A pool with a verifier verifies an aggregate's proof before anything else of it.
    #[test]
    fn verifies_submitted_aggregates() {
        #[derive(Debug)]
        struct Refuse;
        impl op_alloy_consensus::ProofAggregateVerifier for Refuse {
            fn verify(&self, _: &[ProofStatement], _: &[u8], _: &[u8]) -> Result<(), String> {
                Err(String::from("refused"))
            }
        }
        let pool = ProofAggregationPool::default().with_verifier(Arc::new(Refuse));
        include(&pool, 1, 1, &[1]);
        let mut aggregate = aggregate(1, &[1]);
        aggregate.proof = LeanVmTreeProof { root: Bytes::new(), seal: Bytes::new() }.to_rlp_bytes();
        assert_eq!(
            submit(&pool, aggregate),
            Err(ProofAggregationPoolError::InvalidProof(String::from("refused")))
        );
        assert!(pool.pending_aggregates().is_empty());
    }

    #[test]
    fn refuses_transactions_on_too_many_statements() {
        let pool = ProofAggregationPool::default();
        let proofs: Vec<StatementProof> =
            (0..=MAX_STATEMENTS_PER_TX as u8).map(|i| proof_of(i, 0xa)).collect();
        let ids: Vec<B256> = proofs.iter().map(|proof| proof.statement.id()).collect();
        assert_eq!(
            pool.admit(tx(2), ids, proofs),
            Err(ProofAggregationPoolError::WrongStatementCount { max: MAX_STATEMENTS_PER_TX })
        );

        // Few statements, but leaves publishing more members than one aggregate takes: no block
        // could include the transaction.
        let full = TARGET_PROOF_AGGREGATE_STATEMENTS / MAX_LEAF_MEMBERS;
        let leaves: Vec<StatementProof> =
            (0..=full as u16).map(|leaf| wide_leaf(leaf, 0xee, MAX_LEAF_MEMBERS)).collect();
        let ids: Vec<B256> = leaves.iter().map(|leaf| leaf.statement.id()).collect();
        assert_eq!(
            pool.admit(tx(3), ids.clone(), leaves.clone()),
            Err(ProofAggregationPoolError::TooManyFoldedStatements {
                max: TARGET_PROOF_AGGREGATE_STATEMENTS
            })
        );
        pool.admit(tx(3), ids[..full].to_vec(), leaves[..full].to_vec()).unwrap();
    }

    #[test]
    fn aggregates_stay_queued_until_finalized() {
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        submit(&pool, aggregate(1, &[1])).unwrap();
        include(&pool, 2, 2, &[2]);
        submit(&pool, aggregate(2, &[2])).unwrap();
        assert_eq!(pool.pending_aggregates().len(), 2);

        pool.on_safe(1);
        assert_eq!(
            pool.pending_aggregates().iter().map(|a| a.through).collect::<Vec<_>>(),
            [2],
            "the aggregate through block 1 is decided"
        );
        include(&pool, 3, 3, &[3]);
        assert!(
            matches!(
                submit(&pool, aggregate(1, &[3])),
                Err(ProofAggregationPoolError::OutOfOrder { .. })
            ),
            "a safe aggregate still counts as answering for its blocks"
        );
        pool.on_safe(2);
        assert_eq!(next(&pool).map(|b| b.0), Some(3));

        pool.on_safe(1);
        assert_eq!(
            pool.pending_aggregates().iter().map(|a| a.through).collect::<Vec<_>>(),
            [2],
            "an L1 reorg moved the safe head back: the batcher posts the aggregate again"
        );
        pool.on_finalized(2);
        pool.on_safe(0);
        assert!(pool.pending_aggregates().is_empty(), "finalized aggregates are forgotten");
        assert!(
            matches!(
                submit(&pool, aggregate(2, &[2])),
                Err(ProofAggregationPoolError::OutOfOrder { .. })
            ),
            "a forgotten aggregate still counts as answering for its blocks"
        );
    }

    #[test]
    fn decided_aggregates_are_forgotten_if_finality_stalls() {
        let pool = ProofAggregationPool::default();
        let count = (MAX_PENDING_AGGREGATES + MAX_DECIDED_AGGREGATES) as u64;
        for number in 1..=count {
            include(&pool, number, number as u8, &[number as u8]);
            submit(&pool, aggregate(number, &[number as u8])).unwrap();
            pool.on_safe(number);
        }
        assert_eq!(pool.lock().aggregates.len(), MAX_DECIDED_AGGREGATES);
        assert_eq!(pool.lock().forgotten_through, Some(count - MAX_DECIDED_AGGREGATES as u64));
    }

    #[test]
    fn the_queue_cap_counts_only_undecided_aggregates() {
        let pool = ProofAggregationPool::default();
        let cap = MAX_PENDING_AGGREGATES as u64;
        for number in 1..=cap {
            include(&pool, number, number as u8, &[number as u8]);
            submit(&pool, aggregate(number, &[number as u8])).unwrap();
        }
        let next = cap + 1;
        include(&pool, next, next as u8, &[next as u8]);
        assert_eq!(
            submit(&pool, aggregate(next, &[next as u8])),
            Err(ProofAggregationPoolError::AggregatesFull)
        );
        pool.on_safe(1);
        submit(&pool, aggregate(next, &[next as u8])).unwrap();
    }

    /// An L1 reorg can replace blocks an aggregate the pool forgot answered for: the replacements
    /// need an aggregate of their own.
    #[test]
    fn a_reorg_below_a_forgotten_aggregate_uncovers_the_replacement_blocks() {
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        include(&pool, 2, 2, &[2]);
        submit(&pool, aggregate(2, &[1, 2])).unwrap();
        pool.on_safe(2);
        pool.on_finalized(2);
        assert!(pool.lock().aggregates.is_empty());

        include(&pool, 2, 3, &[3]);
        assert_eq!(next(&pool).map(|b| b.0), Some(2));
        submit(&pool, aggregate(2, &[3])).unwrap();
    }

    #[test]
    fn undecided_aggregate_bytes_pause_dependent_transactions() {
        let pool = ProofAggregationPool::default();
        include(&pool, 1, 1, &[1]);
        let mut big = aggregate(1, &[1]);
        big.proof = Bytes::from(vec![0; MAX_UNCOVERED_BYTES as usize]);
        submit(&pool, big).unwrap();
        include(&pool, 2, 2, &[2]);
        assert!(pool.dependencies_paused(), "the batcher may post the aggregate after block 2");
        pool.on_safe(1);
        assert!(!pool.dependencies_paused());
    }

    #[test]
    fn fixed_runs_share_an_aggregate_among_their_blocks() {
        let pool = ProofAggregationPool::default().with_run_blocks(12);
        assert_eq!(pool.status().run_blocks, 12);
        assert_eq!(pool.lock().block_statement_limit(), MAX_PROOF_AGGREGATE_STATEMENTS / 12);
        assert_eq!(
            ProofAggregationPool::default().lock().block_statement_limit(),
            TARGET_PROOF_AGGREGATE_STATEMENTS
        );
    }

    #[test]
    #[should_panic(expected = "could not hold a full leaf")]
    fn a_run_must_hold_a_full_leaf_per_block() {
        assert!(MAX_PROOF_AGGREGATE_STATEMENTS / MAX_RUN_BLOCKS as usize >= MAX_LEAF_MEMBERS);
        let _ = ProofAggregationPool::default().with_run_blocks(MAX_RUN_BLOCKS + 1);
    }

    /// Six blocks of 12 full leaves each, 9,216 statements.
    fn backlog(pool: &ProofAggregationPool) -> Vec<ProofStatement> {
        (0..6u16)
            .flat_map(|block| {
                let proofs: Vec<StatementProof> =
                    (0..12).map(|leaf| wide_leaf(block * 12 + leaf, 1, 128)).collect();
                let statements: Vec<ProofStatement> =
                    proofs.iter().map(|proof| proof.statement).collect();
                include_proofs(pool, u64::from(block) + 1, block as u8 + 1, proofs);
                statements
            })
            .collect()
    }

    /// With fixed runs a backlog pauses dependent transactions by how much is left to prove, every
    /// member of a leaf counted, well before the age limit. An aggregate covering it lifts the
    /// pause. A block whose proofs the pool does not hold, as after a failover, adds nothing.
    #[test]
    fn uncovered_statements_pause_fixed_runs() {
        let pool = ProofAggregationPool::default().with_run_blocks(2);
        let start = Instant::now();
        let statements = backlog(&pool);
        assert_eq!(pool.lock().uncovered_statements, 9216);
        assert!(pool.lock().paused_at(start));
        submit(&pool, PendingAggregate { statements, ..aggregate(6, &[]) }).unwrap();
        assert_eq!(pool.lock().uncovered_statements, 0);
        assert!(!pool.lock().paused_at(start));

        let standby = ProofAggregationPool::default().with_run_blocks(2);
        let dependent =
            (0..MAX_UNCOVERED_STATEMENTS).map(|i| (tx(1), vec![B256::with_last_byte(i as u8)]));
        standby.on_canonical_block(1, hash(1), dependent.collect(), 0);
        assert_eq!(standby.lock().uncovered_statements, 0);

        let default = ProofAggregationPool::default();
        backlog(&default);
        assert!(!default.lock().paused_at(start), "the default mode pauses by age and bytes");
    }

    /// One transaction's statements of one leaf count its source once.
    #[test]
    fn admission_counts_a_shared_source_once() {
        let pool = ProofAggregationPool::default();
        let leaf = program_leaf(1);
        let shared = StatementProof {
            statement: ProofStatement {
                public_values_digest: B256::repeat_byte(7),
                ..leaf.statement
            },
            source: leaf.source.clone(),
        };
        let bytes = leaf.source.bytes();
        pool.admit(tx(1), vec![leaf.statement.id()], vec![leaf, shared]).unwrap();
        assert_eq!(pool.lock().held_bytes, bytes);
    }

    /// `due_through` is the block where the bytes were reached, and later blocks do not move it.
    #[test]
    fn due_through_stays_where_the_bytes_were_reached() {
        let pool = ProofAggregationPool::default().with_run_blocks(4);
        let start = Instant::now();
        pool.admit(tx(1), vec![id(1)], vec![proof(1)]).unwrap();
        pool.on_canonical_block_at(
            1,
            hash(1),
            vec![(tx(1), vec![id(1)])],
            DUE_UNCOVERED_BYTES / 2,
            start,
        );
        assert_eq!(pool.status().due_through, None);
        pool.on_canonical_block_at(2, hash(2), vec![], DUE_UNCOVERED_BYTES / 2, start);
        assert_eq!(pool.status().due_through, Some(2));
        pool.on_canonical_block_at(3, hash(3), vec![], DUE_UNCOVERED_BYTES, start);
        assert_eq!(pool.status().due_through, Some(2));
        assert_eq!(ProofAggregationPool::default().status().due_through, None);
    }
}
