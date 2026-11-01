//! First-level nodes proven ahead of the fold that takes them.
//!
//! An [`Aggregator`](crate::Aggregator) folds each leaf in three steps: a signature leaf is proven
//! first (signatures only), then a first-level node over the leaf, then the node is folded into the
//! running root. Only the last step depends on the root; the first two depend on the leaf alone. So
//! another prover, in another process with its own leanVM pool, can prove them before the run
//! reaches the leaf ([`LeafRef`]) and hand the node over ([`FirstLevelCache`]).
//!
//! A first-level node proves its leaf's claims and nothing else: nodes over the same statements are
//! interchangeable, whichever proof of the leaf they verified. The cache keys them by the digest of
//! their statement set ([`first_level_key`]), and checks a node handed over in bytes against that
//! set before it holds it.
//!
//! A block's leaves do not depend on each other either: [`Aggregator::add_block`] folds a block's
//! first-level nodes into the root through one node, the top of a [`Subtree`] over them, which
//! other provers can build too, so that the fold, the only sequential step, runs once a block
//! rather than once a leaf. The cache holds the subtree's nodes as it holds first-level nodes, by
//! their statement sets.
//!
//! [`Aggregator::add_block`]: crate::Aggregator::add_block

use super::{
    ClassProver, SIGNATURE_CLASS, Signed, claim, class_prover, classes, member_words,
    program_digest, program_leaf, signature_program,
};
use alloy_primitives::{B256, keccak256};
use leanvm::{
    Output,
    aggregate::{Aggregate, ClaimSet, MixedLeaf, TreeProof},
};
use op_alloy_consensus::ProofStatement;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

/// The cache key of a node over `statements`, first-level or subtree: keccak256 of their ids,
/// sorted, each once.
pub fn first_level_key(statements: &[ProofStatement]) -> B256 {
    let mut ids: Vec<B256> = statements.iter().map(ProofStatement::id).collect();
    ids.sort_unstable();
    ids.dedup();
    key_of_ids(&ids)
}

/// [`first_level_key`] of statements whose ids are `ids`, sorted, each once.
fn key_of_ids(ids: &[B256]) -> B256 {
    keccak256(ids.iter().flat_map(|id| id.0).collect::<Vec<u8>>())
}

/// Builds what proving a first-level node needs, the class and the signature program, so that the
/// first node a prover is asked for does not wait for them.
pub fn prepare_first_level_prover() -> Result<(), String> {
    class_prover()?;
    signature_program();
    Ok(())
}

/// The work of a first-level node, borrowed: a program leaf, or signatures to prove a signature
/// leaf over first.
#[derive(Debug, Clone, Copy)]
pub enum LeafRef<'a> {
    /// A program leaf, as [`crate::verify_program_leaf`] admits it.
    Program {
        /// The normalized program's verifying key.
        verifying_key: &'a [u8],
        /// The members the run published.
        members: &'a [B256],
        /// The leaf proof.
        proof: &'a [u8],
    },
    /// Signatures that verified ([`Signed::verify`]), proven together in one signature leaf.
    Signatures(&'a [Signed]),
}

/// How long a first-level node took: the signature leaf under it, if any, and the node.
#[derive(Debug, Clone, Copy, Default)]
pub struct FirstLevelTiming {
    /// Proving the signature leaf; zero for a program leaf.
    pub leaf: Duration,
    /// Proving the first-level node.
    pub first_level: Duration,
}

impl LeafRef<'_> {
    /// The statements the node proves.
    pub fn statements(&self) -> Result<Vec<ProofStatement>, String> {
        match self {
            Self::Program { verifying_key, members, .. } => {
                let digest = program_digest(verifying_key)?;
                Ok(members
                    .iter()
                    .map(|member| ProofStatement {
                        vkey_hash: digest,
                        public_values_digest: *member,
                    })
                    .collect())
            }
            Self::Signatures(signatures) => Ok(signatures.iter().map(Signed::statement).collect()),
        }
    }

    /// Proves the node, the signature leaf under it first for signatures.
    pub fn prove(&self) -> Result<(Aggregate, FirstLevelTiming), String> {
        let ClassProver { tree, .. } = class_prover()?;
        let mut timing = FirstLevelTiming::default();
        match self {
            Self::Program { verifying_key, members, proof } => {
                let words = member_words(members)?;
                let (class, key, proof) = program_leaf(verifying_key, proof)?;
                let leaf = MixedLeaf {
                    key: &key,
                    proof: &proof,
                    output: Output::new(leanvm_guest::members::output(&words)),
                    members: &words,
                };
                let started = Instant::now();
                let node = tree
                    .aggregate_programs_at(class, &[leaf], None)
                    .map_err(|err| format!("a first-level node: {err}"))?;
                timing.first_level = started.elapsed();
                Ok((node, timing))
            }
            Self::Signatures(signatures) => {
                if signatures.is_empty() {
                    return Err(String::from("a signature leaf of no signatures"));
                }
                let started = Instant::now();
                let triples: Vec<_> = signatures
                    .iter()
                    .map(|signed| (&signed.public_key, &signed.message, &*signed.signature))
                    .collect();
                let batch = leansphincs_members_host::batch(&triples);
                let class = classes()[SIGNATURE_CLASS];
                let program = signature_program();
                let run = class
                    .program
                    .prover(class.shape)
                    .prove(program, &batch.run.advice)
                    .map_err(|err| format!("a signature leaf: {err}"))?;
                timing.leaf = started.elapsed();
                let leaf = MixedLeaf {
                    key: program.verifying_key(),
                    proof: &run.proof,
                    output: run.output,
                    members: &batch.members,
                };
                let started = Instant::now();
                let node = tree
                    .aggregate_programs_at(SIGNATURE_CLASS, &[leaf], None)
                    .map_err(|err| format!("a first-level node: {err}"))?;
                timing.first_level = started.elapsed();
                Ok((node, timing))
            }
        }
    }

    /// Proves the node, for a prover in another process: its proof's bytes, which
    /// [`FirstLevelTicket::fulfil_bytes`] takes back.
    pub fn prove_bytes(&self) -> Result<Vec<u8>, String> {
        self.prove().map(|(node, _)| node.proof.to_bytes())
    }
}

/// What a fold gets from the cache ([`FirstLevelCache::take_or_claim`]).
#[allow(missing_debug_implementations)]
pub enum Taken {
    /// The node, proven ahead (after waiting for it, if it was being proven).
    Ready(Arc<Aggregate>),
    /// No one is proving it: the caller proves it and fulfils the claim.
    Claimed(FirstLevelTicket),
    /// It was still being proven when the wait ran out: the caller proves it, unclaimed.
    TimedOut,
}

/// A slot of the cache: a node being proven, or proven.
enum Slot {
    InFlight,
    Ready(Arc<Aggregate>),
}

/// How the cache served the folds that asked it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FirstLevelStats {
    /// Nodes that were ready.
    pub hits: u64,
    /// Nodes the fold waited for, proven ahead while it asked.
    pub waits: u64,
    /// Nodes the fold proved itself.
    pub misses: u64,
    /// Nodes the fold stopped waiting for and proved itself.
    pub timeouts: u64,
}

struct State {
    slots: HashMap<B256, Slot>,
    /// The ready slots' keys, oldest first: the first evicted.
    ready: VecDeque<B256>,
    stats: FirstLevelStats,
}

/// Nodes, first-level and subtree, shared between provers working ahead and the
/// [`Aggregator`](crate::Aggregator) folding, keyed by [`first_level_key`].
///
/// A node is proven once: a prover claims its key ([`Self::claim`]), and a fold asking for it while
/// it is being proven waits for it ([`Self::take_or_claim`]). A prover that fails drops its claim,
/// and a fold waiting proves the node itself. At most `capacity` ready nodes are kept, the oldest
/// evicted first. Everything held is a pure function of its key, so nodes outliving a reorg or a
/// restart are still right; they are only wasted.
#[allow(missing_debug_implementations)]
pub struct FirstLevelCache {
    state: Mutex<State>,
    changed: Condvar,
    capacity: usize,
    wait: Duration,
}

impl FirstLevelCache {
    /// A cache keeping at most `capacity` ready nodes, whose folds wait at most `wait` for a node
    /// being proven before they prove it themselves: a helper that stalls delays the run by that
    /// much, not for ever.
    pub fn new(capacity: usize, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                slots: HashMap::new(),
                ready: VecDeque::new(),
                stats: FirstLevelStats::default(),
            }),
            changed: Condvar::new(),
            capacity: capacity.max(1),
            wait,
        })
    }

    /// Claims `key` for a prover working ahead: `None` if its node is ready or being proven.
    pub fn claim(self: &Arc<Self>, key: B256) -> Option<FirstLevelTicket> {
        let mut state = self.state.lock().unwrap();
        if state.slots.contains_key(&key) {
            return None;
        }
        state.slots.insert(key, Slot::InFlight);
        Some(FirstLevelTicket { cache: Arc::clone(self), key, done: false })
    }

    /// The node over `key` for a fold: the ready one, after waiting for it if it is being proven,
    /// or a claim for the caller to prove it, or neither once the wait runs out.
    pub fn take_or_claim(self: &Arc<Self>, key: B256) -> Taken {
        let deadline = std::time::Instant::now() + self.wait;
        let mut state = self.state.lock().unwrap();
        let mut waited = false;
        loop {
            match state.slots.get(&key) {
                Some(Slot::Ready(node)) => {
                    let node = Arc::clone(node);
                    if waited {
                        state.stats.waits += 1;
                    } else {
                        state.stats.hits += 1;
                    }
                    return Taken::Ready(node);
                }
                Some(Slot::InFlight) => {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        state.stats.timeouts += 1;
                        return Taken::TimedOut;
                    }
                    waited = true;
                    state = self.changed.wait_timeout(state, left).unwrap().0;
                }
                None => {
                    state.slots.insert(key, Slot::InFlight);
                    state.stats.misses += 1;
                    return Taken::Claimed(FirstLevelTicket {
                        cache: Arc::clone(self),
                        key,
                        done: false,
                    });
                }
            }
        }
    }

    /// Whether `key`'s node is ready.
    pub fn is_ready(&self, key: &B256) -> bool {
        self.peek(key).is_some()
    }

    /// `key`'s node, if it is ready, for a prover building on it: unlike
    /// [`Self::take_or_claim`], it does not count as a fold's.
    pub fn peek(&self, key: &B256) -> Option<Arc<Aggregate>> {
        match self.state.lock().unwrap().slots.get(key) {
            Some(Slot::Ready(node)) => Some(Arc::clone(node)),
            _ => None,
        }
    }

    /// How the cache served the folds so far.
    pub fn stats(&self) -> FirstLevelStats {
        self.state.lock().unwrap().stats
    }

    /// Whether `key`'s node is ready or being proven.
    pub fn contains(&self, key: &B256) -> bool {
        self.state.lock().unwrap().slots.contains_key(key)
    }

    /// Releases `key`'s claim, waking the folds waiting for it.
    fn release(&self, key: B256) {
        self.state.lock().unwrap().slots.remove(&key);
        self.changed.notify_all();
    }
}

/// A claim on a key of a [`FirstLevelCache`]: its holder proves the node and fulfils it. Dropped
/// unfulfilled (a failure, a panic), it releases the key, waking any fold waiting for the node to
/// prove it itself.
#[allow(missing_debug_implementations)]
pub struct FirstLevelTicket {
    cache: Arc<FirstLevelCache>,
    key: B256,
    done: bool,
}

impl FirstLevelTicket {
    /// The key claimed.
    pub const fn key(&self) -> B256 {
        self.key
    }

    /// Holds `node`, a node over the key's statements, which the caller proved.
    pub(crate) fn fulfil(mut self, node: Aggregate) -> Arc<Aggregate> {
        let node = Arc::new(node);
        self.done = true;
        let mut state = self.cache.state.lock().unwrap();
        state.slots.insert(self.key, Slot::Ready(Arc::clone(&node)));
        state.ready.push_back(self.key);
        while state.ready.len() > self.cache.capacity {
            let oldest = state.ready.pop_front().expect("over capacity");
            if oldest != self.key && matches!(state.slots.get(&oldest), Some(Slot::Ready(_))) {
                state.slots.remove(&oldest);
            }
        }
        drop(state);
        self.cache.changed.notify_all();
        node
    }

    /// Verifies `proof`, a node from another prover ([`LeafRef::prove_bytes`],
    /// [`prove_node_bytes`]), as a node over `statements`, whose key this claims, then holds it. A
    /// proof that does not verify releases the key.
    pub fn fulfil_bytes(self, statements: &[ProofStatement], proof: &[u8]) -> Result<(), String> {
        if first_level_key(statements) != self.key {
            return Err(String::from("the statements are not the claimed key's"));
        }
        let proof = TreeProof::from_bytes(proof).map_err(|err| format!("malformed node: {err}"))?;
        let claims = ClaimSet::from_claims(statements.iter().map(claim));
        let ClassProver { tree, .. } = class_prover()?;
        tree.verify_claims(&proof, &claims)
            .map_err(|err| format!("the node does not prove its statements: {err}"))?;
        self.fulfil(Aggregate { proof, claims });
        Ok(())
    }
}

/// Proves a node over `children`, each a node proof ([`TreeProof::to_bytes`]) and the statements
/// it proves, for a prover in another process: the proof's bytes, which
/// [`FirstLevelTicket::fulfil_bytes`] takes back with the children's statements together.
pub fn prove_node_bytes(children: &[(&[u8], &[ProofStatement])]) -> Result<Vec<u8>, String> {
    let ClassProver { tree, .. } = class_prover()?;
    let children = children
        .iter()
        .map(|(proof, statements)| {
            Ok(Aggregate {
                proof: TreeProof::from_bytes(proof)
                    .map_err(|err| format!("malformed node: {err}"))?,
                claims: ClaimSet::from_claims(statements.iter().map(claim)),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let refs: Vec<&Aggregate> = children.iter().collect();
    tree.aggregate(&refs, None)
        .map(|node| node.proof.to_bytes())
        .map_err(|err| format!("a node: {err}"))
}

/// A program leaf of a block, borrowed: its verifying key, members and proof.
#[derive(Debug, Clone, Copy)]
pub struct ProgramRef<'a> {
    /// The normalized program's verifying key.
    pub verifying_key: &'a [u8],
    /// The members the run published.
    pub members: &'a [B256],
    /// The leaf proof.
    pub proof: &'a [u8],
}

/// What a block adds, in the order the aggregator takes it.
#[derive(Debug, Clone)]
pub enum BlockItem<P> {
    /// A program leaf.
    Program(P),
    /// A signature, which must have verified ([`Signed::verify`]).
    Signature(Signed),
}

/// The work of one first-level node of a block: a program leaf, or a signature leaf's worth of
/// signatures.
#[derive(Debug, Clone)]
pub enum Unit<P> {
    /// A program leaf.
    Program(P),
    /// [`SIGNATURES_PER_LEAF`](crate::SIGNATURES_PER_LEAF) signatures, or the last ones of a run.
    Signatures(Vec<Signed>),
}

impl<'a> From<ProgramRef<'a>> for LeafRef<'a> {
    fn from(p: ProgramRef<'a>) -> Self {
        Self::Program { verifying_key: p.verifying_key, members: p.members, proof: p.proof }
    }
}

impl Unit<ProgramRef<'_>> {
    /// The unit as a first-level node's work.
    pub fn leaf(&self) -> LeafRef<'_> {
        match self {
            Self::Program(p) => (*p).into(),
            Self::Signatures(signatures) => LeafRef::Signatures(signatures),
        }
    }
}

/// Groups `items` into first-level units as the aggregator does, after the signatures `buffer`
/// already holds: each program leaf a unit, and every
/// [`SIGNATURES_PER_LEAF`](crate::SIGNATURES_PER_LEAF) signatures one. Returns the units and the
/// signatures left buffered for a later block.
pub fn group_units<P>(
    mut buffer: Vec<Signed>,
    items: impl IntoIterator<Item = BlockItem<P>>,
) -> (Vec<Unit<P>>, Vec<Signed>) {
    let mut units = Vec::new();
    for item in items {
        match item {
            BlockItem::Program(p) => units.push(Unit::Program(p)),
            BlockItem::Signature(signed) => {
                buffer.push(signed);
                if buffer.len() >= crate::SIGNATURES_PER_LEAF {
                    units.push(Unit::Signatures(core::mem::take(&mut buffer)));
                }
            }
        }
    }
    (units, buffer)
}

/// A node of a [`Subtree`] above its units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeNode {
    /// Its key: of the union of its children's statements.
    pub key: B256,
    /// That union.
    pub statements: Vec<ProofStatement>,
    /// Its children's keys, units' or nodes'.
    pub children: Vec<B256>,
}

/// The tree a block's first-level nodes are folded through: pairs of nodes, level by level, the
/// odd one out of a level carried up, so that its top proves every unit's statements and the
/// root folds it once. Its shape is a function of the units' statements alone: any prover builds
/// the same nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subtree {
    /// The units the top is proven from: their keys and statements, each set once, in order.
    pub units: Vec<(B256, Vec<ProofStatement>)>,
    /// The nodes above them, children first.
    pub nodes: Vec<SubtreeNode>,
    /// The top: the root folds it.
    pub top: B256,
}

impl Subtree {
    /// The subtree over units proving `statements`, in order; `None` for no unit. Units of the
    /// same statement set are one; a pair one of whose sets holds the other's is that one, and a
    /// pair whose union is a unit's set is that unit, so units it covers are not proven.
    pub fn new(statements: impl IntoIterator<Item = Vec<ProofStatement>>) -> Option<Self> {
        // Each set with its ids, sorted and each once: a pair's union is a merge of them.
        let mut units: Vec<(B256, Vec<ProofStatement>)> = Vec::new();
        let mut level: Vec<(B256, Vec<(B256, ProofStatement)>)> = Vec::new();
        for statements in statements {
            let mut ids: Vec<(B256, ProofStatement)> =
                statements.iter().map(|s| (s.id(), *s)).collect();
            ids.sort_unstable_by_key(|(id, _)| *id);
            ids.dedup_by_key(|(id, _)| *id);
            let key = key_of_ids(&ids.iter().map(|(id, _)| *id).collect::<Vec<_>>());
            if !units.iter().any(|(k, _)| *k == key) {
                units.push((key, statements));
                level.push((key, ids));
            }
        }
        let mut nodes: Vec<SubtreeNode> = Vec::new();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut pairs = level.into_iter();
            while let Some(left) = pairs.next() {
                let Some(right) = pairs.next() else {
                    next.push(left);
                    break;
                };
                let mut union = left.1.clone();
                union.extend(right.1.iter().copied());
                union.sort_unstable_by_key(|(id, _)| *id);
                union.dedup_by_key(|(id, _)| *id);
                // The union holds both: as large as one, it is that one.
                if union.len() == left.1.len() {
                    next.push(left);
                    continue;
                }
                if union.len() == right.1.len() {
                    next.push(right);
                    continue;
                }
                let key = key_of_ids(&union.iter().map(|(id, _)| *id).collect::<Vec<_>>());
                if !units.iter().any(|(k, _)| *k == key) {
                    nodes.push(SubtreeNode {
                        key,
                        statements: union.iter().map(|(_, s)| *s).collect(),
                        children: vec![left.0, right.0],
                    });
                }
                next.push((key, union));
            }
            level = next;
        }
        let top = level.pop()?.0;
        let mut subtree = Self { units, nodes, top };
        // Only what the top is proven from.
        let reachable = subtree.reachable();
        subtree.units.retain(|(key, _)| reachable.contains(key));
        subtree.nodes.retain(|node| reachable.contains(&node.key));
        Some(subtree)
    }

    /// The keys the top is proven from, and the top: a key of a unit is that unit's, else a
    /// node's, proven from its children.
    fn reachable(&self) -> HashSet<B256> {
        let mut seen = HashSet::new();
        let mut stack = vec![self.top];
        while let Some(key) = stack.pop() {
            if !seen.insert(key) || self.units.iter().any(|(k, _)| *k == key) {
                continue;
            }
            if let Some(node) = self.node(&key) {
                stack.extend(node.children.iter().copied());
            }
        }
        seen
    }

    /// The node of key `key`, if it is a node's.
    pub fn node(&self, key: &B256) -> Option<&SubtreeNode> {
        self.nodes.iter().find(|node| node.key == *key)
    }
}

impl Drop for FirstLevelTicket {
    fn drop(&mut self) {
        if !self.done {
            self.cache.release(self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ticket dropped unfulfilled releases its key, and a fold asking for it then claims it.
    /// (Whether the fold was already waiting when the ticket dropped depends on the threads'
    /// timing; either way it claims the key.)
    #[test]
    fn a_failed_claim_hands_the_key_to_the_waiting_fold() {
        let cache = FirstLevelCache::new(4, Duration::from_secs(60));
        let key = B256::repeat_byte(1);
        let ticket = cache.claim(key).expect("free");
        assert!(cache.claim(key).is_none(), "in flight");
        let waiting = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || match cache.take_or_claim(key) {
                Taken::Claimed(ticket) => Some(ticket.key()),
                _ => None,
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        drop(ticket);
        assert_eq!(waiting.join().unwrap(), Some(key), "the fold proves it itself");
        assert_eq!(cache.stats(), FirstLevelStats { misses: 1, ..Default::default() });
        // That claim, dropped too, leaves the key free.
        assert!(!cache.contains(&key));
    }

    /// The key is a set's: order and repeats do not change it.
    #[test]
    fn the_key_is_of_the_statement_set() {
        let s = |b: u8| ProofStatement {
            vkey_hash: B256::repeat_byte(b),
            public_values_digest: B256::repeat_byte(b + 1),
        };
        assert_eq!(first_level_key(&[s(1), s(3)]), first_level_key(&[s(3), s(1), s(1)]));
        assert_ne!(first_level_key(&[s(1)]), first_level_key(&[s(1), s(3)]));
    }
}

#[cfg(test)]
mod wait_tests {
    use super::*;

    /// A fold stops waiting for a node a stalled prover holds, and proves it unclaimed.
    #[test]
    fn a_fold_stops_waiting_for_a_stalled_prover() {
        let cache = FirstLevelCache::new(4, Duration::from_millis(50));
        let key = B256::repeat_byte(2);
        let _stalled = cache.claim(key).expect("free");
        assert!(matches!(cache.take_or_claim(key), Taken::TimedOut));
        assert_eq!(cache.stats(), FirstLevelStats { timeouts: 1, ..Default::default() });
    }
}
