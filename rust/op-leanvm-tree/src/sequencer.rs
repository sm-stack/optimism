//! What the sequencer runs: the admission checks of program leaves and leanSPHINCS signatures, and
//! the [`Aggregator`] that folds them into one tree root. They need leanVM's guest SDK and the
//! leanSPHINCS guest library, which build only for little-endian targets, so the fault proof
//! program, which runs on big-endian MIPS, leaves this module out.

use super::{
    BlockItem, CLASS_BOUNDS, ClassProver, FirstLevelCache, LeafRef, PROGRAM_CLASS, PROGRAM_CLASSES,
    ProgramRef, SIGNATURE_CLASS, SIGNATURE_PROGRAM_DIGEST, Subtree, Taken, Unit, bytes, class_key,
    class_prover, classes, first_level_key, group_units, statement, words,
};
use alloy_primitives::B256;
use leansphincs::{Message, PublicKey, Signature};
use leanvm::{
    Output, Program, Proof, VerifyingKey,
    aggregate::{Accumulator, Aggregate, LeafShape},
};
use op_alloy_consensus::{
    LeanVmTreeProof, MAX_PROOF_AGGREGATE_PROGRAMS, MAX_PROOF_AGGREGATE_STATEMENTS, ProofStatement,
    TARGET_PROOF_AGGREGATE_STATEMENTS,
};
use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
    time::Instant,
};

/// Checks that `proof` is a leaf proof of a program class: a proof at the class's leaf shape of a
/// run of the program with `verifying_key`, a key of the class, whose output commits to
/// `members`. Returns the key's digest: each member makes a statement of that program.
pub fn verify_program_leaf(
    verifying_key: &[u8],
    members: &[B256],
    proof: &[u8],
) -> Result<B256, String> {
    let members = member_words(members)?;
    let (_, key, proof) = program_leaf(verifying_key, proof)?;
    key.verify(Output::new(leanvm_guest::members::output(&members)), &proof)
        .map_err(|err| format!("the leaf proof does not verify: {err}"))?;
    Ok(B256::from(*key.digest()))
}

/// The program class whose leaf shape (table heights, rate, zero knowledge) is `shape`, if any: a
/// plain proof, or one of the signature class, is of none.
pub fn program_class(shape: LeafShape) -> Option<usize> {
    PROGRAM_CLASSES.into_iter().find(|&class| classes()[class].shape == shape)
}

/// A program leaf's class, key and proof: the program class at whose leaf shape the proof is, and
/// the key must be of that class.
pub(crate) fn program_leaf(
    verifying_key: &[u8],
    proof: &[u8],
) -> Result<(usize, VerifyingKey, Proof), String> {
    let proof = Proof::from_bytes(proof).map_err(|err| format!("malformed leaf proof: {err}"))?;
    let class = LeafShape::of(&proof)
        .ok()
        .and_then(program_class)
        .ok_or("the proof is not at a program class's leaf shape")?;
    Ok((class, class_key(class, verifying_key)?, proof))
}

/// A member list's words, if it holds 1 to the program classes' most members.
pub(crate) fn member_words(members: &[B256]) -> Result<Vec<[u64; 4]>, String> {
    let max = CLASS_BOUNDS[PROGRAM_CLASS][4];
    if members.is_empty() || members.len() > max {
        return Err(format!("{} members, not 1 to {max}", members.len()));
    }
    Ok(members.iter().map(|member| words(*member)).collect())
}

/// The leanSPHINCS signature-member guest, normalized to the signature class.
pub(crate) fn signature_program() -> &'static Program {
    static PROGRAM: OnceLock<Program> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let program = Program::from_elf(leansphincs_members_host::ELF)
            .expect("the signature-member guest is a valid ELF");
        classes()[SIGNATURE_CLASS]
            .program
            .normalize(&program)
            .expect("the signature-member guest fits the signature class")
    })
}

/// The verifying key digest of the signature-member guest normalized to the signature class: the
/// program of every signature statement.
pub fn signature_program_digest() -> B256 {
    B256::from(*signature_program().verifying_key().digest())
}

/// The encoding of a leanSPHINCS public key: its root's and its parameter's two words each,
/// little-endian.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// The encoding of a leanSPHINCS signature: its fields' words in order, each little-endian.
pub const SIGNATURE_BYTES: usize = size_of::<Signature>();

// `Signed::decode` reads a signature from words: it must be made of them.
const _: () = assert!(align_of::<Signature>() == 8 && size_of::<Signature>().is_multiple_of(8));

/// A leanSPHINCS signature over a message: the source of a signature statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub(crate) public_key: PublicKey,
    pub(crate) message: Message,
    pub(crate) signature: Box<Signature>,
}

impl Signed {
    /// Decodes a public key of [`PUBLIC_KEY_BYTES`], a message and a signature of
    /// [`SIGNATURE_BYTES`].
    pub fn decode(public_key: &[u8], message: B256, signature: &[u8]) -> Result<Self, String> {
        let key: [u64; 4] = le_words(public_key)
            .and_then(|words| words.try_into().ok())
            .ok_or_else(|| format!("a public key is {PUBLIC_KEY_BYTES} bytes"))?;
        let signature = le_words(signature)
            .filter(|words| words.len() * 8 == SIGNATURE_BYTES)
            .ok_or_else(|| format!("a signature is {SIGNATURE_BYTES} bytes"))?;
        // SAFETY: `Signature` is `repr(C)` words with no padding, any words are one, and
        // `signature` holds exactly its size, aligned for words.
        let signature = Box::new(unsafe { signature.as_ptr().cast::<Signature>().read() });
        Ok(Self {
            public_key: PublicKey { root: [key[0], key[1]], public_param: [key[2], key[3]] },
            message: words(message),
            signature,
        })
    }

    /// Verifies the signature and returns its member: the statement's `public_values_digest`
    /// under [`signature_program_digest`].
    pub fn verify(&self) -> Result<B256, String> {
        leansphincs::verify(&self.public_key, &self.message, &self.signature)
            .map_err(|err| format!("the signature does not verify: {err:?}"))?;
        Ok(self.member())
    }

    /// The signature's member, `BLAKE2s("sphmem01" || public key || message)`.
    pub fn member(&self) -> B256 {
        bytes(leansphincs_members_host::member(&self.public_key, &self.message))
    }

    /// The statement the signature proves.
    pub fn statement(&self) -> ProofStatement {
        ProofStatement { vkey_hash: SIGNATURE_PROGRAM_DIGEST, public_values_digest: self.member() }
    }

    /// The encodings [`Self::decode`] takes: the public key, the message and the signature.
    pub fn encode(&self) -> (Vec<u8>, B256, Vec<u8>) {
        let le = |words: &[u64]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let key = [
            self.public_key.root[0],
            self.public_key.root[1],
            self.public_key.public_param[0],
            self.public_key.public_param[1],
        ];
        // SAFETY: `Signature` is `repr(C)` words with no padding.
        let signature = unsafe {
            core::slice::from_raw_parts(
                (&raw const *self.signature).cast::<u64>(),
                size_of::<Signature>() / 8,
            )
        };
        (le(&key), bytes(self.message), le(signature))
    }
}

/// `data`'s little-endian words, if it is a whole number of them.
fn le_words(data: &[u8]) -> Option<Vec<u64>> {
    data.len().is_multiple_of(8).then(|| {
        data.chunks_exact(8).map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap())).collect()
    })
}

/// A proven aggregate: the statements a tree root proves, in canonical order, and its proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeAggregate {
    /// The root's statements, in canonical order.
    pub statements: Vec<ProofStatement>,
    /// The root and its seal.
    pub proof: LeanVmTreeProof,
}

/// How a block's nodes came: taken ready from the cache, or proven by the aggregator.
#[derive(Default)]
struct BlockLog {
    taken: usize,
    proven: usize,
}

/// Folds leaves into one tree root as they come, then closes and seals it: the sequencer's
/// aggregation of a run of blocks.
///
/// Leaves are added a block at a time ([`Self::add_block`]): each program leaf through a
/// first-level node of its own, and signatures buffered and proven
/// [`SIGNATURES_PER_LEAF`](crate::SIGNATURES_PER_LEAF) at a time, as a signature leaf costs the
/// same however few it verifies ([`Self::close`] proves the rest). A block's first-level nodes
/// reach the root through one fold. The aggregator tracks the statements of everything added, so
/// that [`Self::fits`] tells before adding whether the root stays within its statement cap
/// ([`TARGET_PROOF_AGGREGATE_STATEMENTS`] unless set otherwise) and the class's group capacity.
#[allow(missing_debug_implementations)]
pub struct Aggregator {
    acc: Accumulator,
    statements: HashSet<ProofStatement>,
    programs: HashSet<B256>,
    signatures: Vec<Signed>,
    max_statements: usize,
    /// Nodes, first-level and subtree, proven ahead, if any prover works ahead
    /// ([`Self::set_first_level_cache`]).
    cache: Option<Arc<FirstLevelCache>>,
}

impl Aggregator {
    /// An empty aggregator. The class is built on the first one, once per process: call it on a
    /// blocking thread.
    pub fn new() -> Result<Self, String> {
        class_prover()?;
        Ok(Self {
            acc: Accumulator::default(),
            statements: HashSet::new(),
            programs: HashSet::new(),
            signatures: Vec::new(),
            max_statements: TARGET_PROOF_AGGREGATE_STATEMENTS,
            cache: None,
        })
    }

    /// Takes nodes, first-level and subtree, from `cache` where provers working ahead put them,
    /// proving only those it lacks (and putting them there too). Without one the aggregator proves
    /// every node itself.
    pub fn set_first_level_cache(&mut self, cache: Arc<FirstLevelCache>) {
        self.cache = Some(cache);
    }

    /// The signatures buffered for the next signature leaf, in the order they were added: a prover
    /// working ahead groups the next ones as [`Self::add_block`] will ([`group_units`]).
    pub fn buffered_signatures(&self) -> &[Signed] {
        &self.signatures
    }

    /// Caps the statements of the root at `max`, at most the class's
    /// [`MAX_PROOF_AGGREGATE_STATEMENTS`]: [`TARGET_PROOF_AGGREGATE_STATEMENTS`], what three blobs
    /// carry, by default; up to the class capacity with fixed runs, whose aggregates share a
    /// channel with their blocks. It bounds what is added from now on.
    pub fn set_max_statements(&mut self, max: usize) {
        self.max_statements = max.min(MAX_PROOF_AGGREGATE_STATEMENTS);
    }

    /// The distinct statements added since the last close.
    pub fn statements(&self) -> usize {
        self.statements.len()
    }

    /// Whether nothing was added since the last close.
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Whether `statement` was added since the last close.
    pub fn contains(&self, statement: &ProofStatement) -> bool {
        self.statements.contains(statement)
    }

    /// Whether adding `statements` keeps the root within its statement cap
    /// ([`Self::set_max_statements`]) and the class's group capacity.
    pub fn fits<'a>(&self, statements: impl IntoIterator<Item = &'a ProofStatement>) -> bool {
        let mut new = HashSet::new();
        let mut programs = HashSet::new();
        for statement in statements {
            if !self.statements.contains(statement) {
                new.insert(statement);
            }
            if !self.programs.contains(&statement.vkey_hash) {
                programs.insert(statement.vkey_hash);
            }
        }
        self.statements.len() + new.len() <= self.max_statements &&
            self.programs.len() + programs.len() <= MAX_PROOF_AGGREGATE_PROGRAMS
    }

    fn record(&mut self, statements: impl IntoIterator<Item = ProofStatement>) {
        for statement in statements {
            self.programs.insert(statement.vkey_hash);
            self.statements.insert(statement);
        }
    }

    /// Folds a program leaf of a program class, which must pass [`verify_program_leaf`] and
    /// [`Self::fits`]: a block of the one leaf ([`Self::add_block`]).
    pub fn add_program_leaf(
        &mut self,
        verifying_key: &[u8],
        members: &[B256],
        proof: &[u8],
    ) -> Result<(), String> {
        self.add_block(vec![BlockItem::Program(ProgramRef { verifying_key, members, proof })])
    }

    /// Buffers a signature, which must have verified ([`Signed::verify`]) and pass
    /// [`Self::fits`], and proves a signature leaf once
    /// [`SIGNATURES_PER_LEAF`](crate::SIGNATURES_PER_LEAF) are buffered: a block of the one
    /// signature ([`Self::add_block`]).
    pub fn add_signature(&mut self, signed: Signed) -> Result<(), String> {
        self.add_block(vec![BlockItem::Signature(signed)])
    }

    /// Adds a block's program leaves (each passing [`verify_program_leaf`]) and signatures (each
    /// verified), which together must pass [`Self::fits`]. Signatures are buffered and proven
    /// [`SIGNATURES_PER_LEAF`](crate::SIGNATURES_PER_LEAF) at a time ([`group_units`]); the block's
    /// first-level nodes are folded into the root through the top of their [`Subtree`], so the
    /// root takes one fold a block. Nodes proven ahead ([`Self::set_first_level_cache`]) are
    /// taken, and the leaves under a node taken are not read again; nor is a leaf whose
    /// statements another leaf of the block covers, so such a leaf is never checked, which is
    /// sound: the root's statements all rest on leaves that were. A failure leaves the
    /// aggregator as it was.
    pub fn add_block(&mut self, items: Vec<BlockItem<ProgramRef<'_>>>) -> Result<(), String> {
        let mut statements = Vec::new();
        for item in &items {
            match item {
                BlockItem::Program(p) => statements.extend(LeafRef::from(*p).statements()?),
                BlockItem::Signature(signed) => statements.push(signed.statement()),
            }
        }
        if !self.fits(&statements) {
            return Err(String::from("the block does not fit the aggregate"));
        }
        let (units, rest) = group_units(self.signatures.clone(), items);
        self.fold_units(&units)?;
        self.record(statements);
        self.signatures = rest;
        Ok(())
    }

    /// Folds the first-level nodes of `units` into the root through their subtree's top.
    fn fold_units(&mut self, units: &[Unit<ProgramRef<'_>>]) -> Result<(), String> {
        let leaves: Vec<LeafRef<'_>> = units.iter().map(Unit::leaf).collect();
        let statements = leaves.iter().map(LeafRef::statements).collect::<Result<Vec<_>, _>>()?;
        let leaves: Vec<(B256, LeafRef<'_>)> =
            statements.iter().map(|s| first_level_key(s)).zip(leaves).collect();
        let Some(subtree) = Subtree::new(statements) else { return Ok(()) };
        let ClassProver { tree, .. } = class_prover()?;
        let mut log = BlockLog::default();
        let started = Instant::now();
        let top = self.node(&subtree, &leaves, subtree.top, &mut log)?;
        let top_elapsed = started.elapsed();
        let started = Instant::now();
        tree.fold(&mut self.acc, &top).map_err(|err| format!("a fold: {err}"))?;
        tracing::debug!(
            target: "op_leanvm_tree",
            units = subtree.units.len(),
            nodes = subtree.nodes.len(),
            taken = log.taken,
            proven = log.proven,
            node = ?top_elapsed,
            fold = ?started.elapsed(),
            "folded a block"
        );
        Ok(())
    }

    /// The node of `key` in `subtree`, whose units are `leaves`, by key: taken from the cache if
    /// a prover working ahead proved it, else proven here, its children first.
    fn node(
        &self,
        subtree: &Subtree,
        leaves: &[(B256, LeafRef<'_>)],
        key: B256,
        log: &mut BlockLog,
    ) -> Result<Arc<Aggregate>, String> {
        let ticket = match &self.cache {
            None => None,
            Some(cache) => match cache.take_or_claim(key) {
                Taken::Ready(node) => {
                    log.taken += 1;
                    return Ok(node);
                }
                Taken::Claimed(ticket) => Some(ticket),
                Taken::TimedOut => None,
            },
        };
        let node = if let Some((_, leaf)) = leaves.iter().find(|(k, _)| *k == key) {
            let (node, timing) = leaf.prove()?;
            tracing::debug!(
                target: "op_leanvm_tree",
                kind = if matches!(leaf, LeafRef::Signatures(_)) { "signatures" } else { "program" },
                leaf = ?timing.leaf,
                first_level = ?timing.first_level,
                "proved a first-level node"
            );
            node
        } else {
            let spec = subtree.node(&key).expect("a key of the subtree");
            let children = spec
                .children
                .iter()
                .map(|child| self.node(subtree, leaves, *child, log))
                .collect::<Result<Vec<_>, _>>()?;
            let refs: Vec<&Aggregate> = children.iter().map(|child| &**child).collect();
            let ClassProver { tree, .. } = class_prover()?;
            let started = Instant::now();
            let node =
                tree.aggregate(&refs, None).map_err(|err| format!("a subtree node: {err}"))?;
            tracing::debug!(target: "op_leanvm_tree", elapsed = ?started.elapsed(), "proved a subtree node");
            node
        };
        log.proven += 1;
        Ok(match ticket {
            Some(ticket) => ticket.fulfil(node),
            None => Arc::new(node),
        })
    }

    /// Proves the buffered signatures, then closes the root, seals it and starts over. `None` if
    /// nothing was added.
    pub fn close(&mut self) -> Result<Option<TreeAggregate>, String> {
        let rest = core::mem::take(&mut self.signatures);
        let folded =
            if rest.is_empty() { Ok(()) } else { self.fold_units(&[Unit::Signatures(rest)]) };
        // Whichever step failed, nothing of this aggregate carries into the next.
        self.statements.clear();
        self.programs.clear();
        let root = self.acc.close();
        folded?;
        let Some(root) = root else { return Ok(None) };
        let ClassProver { tree, prover, .. } = class_prover()?;
        let statements: Vec<ProofStatement> = root.claims.claims().filter_map(statement).collect();
        let seal = tree.seal(prover, &root.proof).map_err(|err| format!("the seal: {err}"))?;
        Ok(Some(TreeAggregate {
            statements,
            proof: LeanVmTreeProof {
                root: root.proof.to_bytes().into(),
                seal: seal.to_bytes().into(),
            },
        }))
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use crate::{FirstLevelStats, prove_node_bytes};

    fn testdata(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// A program fixture: its key, proof and members.
    fn program(name: &str) -> (Vec<u8>, Vec<u8>, Vec<B256>) {
        let members = testdata(&format!("{name}.members"));
        (
            testdata(&format!("{name}.key")),
            testdata(&format!("{name}.proof")),
            members.chunks_exact(32).map(B256::from_slice).collect(),
        )
    }

    fn signature(i: usize) -> Signed {
        Signed::decode(
            &testdata(&format!("signature-{i}.key")),
            B256::from_slice(&testdata(&format!("signature-{i}.message"))),
            &testdata(&format!("signature-{i}.signature")),
        )
        .unwrap()
    }

    fn statement(i: u8) -> ProofStatement {
        ProofStatement {
            vkey_hash: B256::repeat_byte(1),
            public_values_digest: B256::repeat_byte(i),
        }
    }

    /// Units pair level by level, the odd one carried up; a unit repeated is one, and a pair one
    /// of whose sets holds the other's is that one.
    #[test]
    fn a_subtree_pairs_its_units_level_by_level() {
        let sets: Vec<Vec<ProofStatement>> = (1..=5).map(|i| vec![statement(i)]).collect();
        let subtree = Subtree::new(sets.clone()).unwrap();
        let key =
            |is: &[u8]| first_level_key(&is.iter().map(|i| statement(*i)).collect::<Vec<_>>());
        let children: Vec<(B256, Vec<B256>)> =
            subtree.nodes.iter().map(|n| (n.key, n.children.clone())).collect();
        assert_eq!(
            children,
            vec![
                (key(&[1, 2]), vec![key(&[1]), key(&[2])]),
                (key(&[3, 4]), vec![key(&[3]), key(&[4])]),
                (key(&[1, 2, 3, 4]), vec![key(&[1, 2]), key(&[3, 4])]),
                (key(&[1, 2, 3, 4, 5]), vec![key(&[1, 2, 3, 4]), key(&[5])]),
            ]
        );
        assert_eq!(subtree.top, key(&[1, 2, 3, 4, 5]));

        let one = Subtree::new(vec![sets[0].clone(), sets[0].clone()]).unwrap();
        assert_eq!((one.units.len(), one.nodes.len(), one.top), (1, 0, key(&[1])));
        let held = Subtree::new(vec![sets[0].clone(), vec![statement(1), statement(2)]]).unwrap();
        assert_eq!((held.units.len(), held.nodes.len(), held.top), (1, 0, key(&[1, 2])));
        // A pair whose union is a unit's set is that unit: the units it covers are not proven.
        let covered =
            Subtree::new(vec![sets[0].clone(), sets[1].clone(), vec![statement(1), statement(2)]])
                .unwrap();
        assert_eq!(covered.units.iter().map(|u| u.0).collect::<Vec<_>>(), vec![key(&[1, 2])]);
        assert_eq!((covered.nodes.len(), covered.top), (0, key(&[1, 2])));
    }

    /// Signatures fill the buffer's signature leaf before a program leaf after them is a unit;
    /// those past it wait in the buffer.
    #[test]
    fn units_group_signatures_from_the_buffer_on() {
        let buffer: Vec<Signed> = (0..99).map(|i| signature(i % 3)).collect();
        let program = ProgramRef { verifying_key: &[], members: &[], proof: &[] };
        let (units, rest) = group_units(
            buffer,
            [
                BlockItem::Signature(signature(0)),
                BlockItem::Program(program),
                BlockItem::Signature(signature(1)),
            ],
        );
        assert!(matches!(&units[..], [Unit::Signatures(s), Unit::Program(_)] if s.len() == 100));
        assert_eq!(rest, vec![signature(1)]);
    }

    /// A block that does not fold leaves the aggregator as it was: its signatures are not
    /// buffered, its statements not recorded.
    #[test]
    fn a_block_that_fails_changes_nothing() {
        let (key, proof, members) = program("fibonacci-1000");
        let wrong = vec![B256::repeat_byte(7); members.len()];
        let mut aggregator = Aggregator::new().unwrap();
        let block = vec![
            BlockItem::Signature(signature(0)),
            BlockItem::Program(ProgramRef { verifying_key: &key, members: &wrong, proof: &proof }),
        ];
        assert!(aggregator.add_block(block).is_err());
        assert!(aggregator.buffered_signatures().is_empty());
        assert!(aggregator.is_empty());
    }

    /// A block folds into an aggregate of the statements its leaves added one by one do, taking
    /// a subtree node proven elsewhere and proving the rest itself.
    #[test]
    fn a_block_folds_as_its_leaves_one_by_one() {
        let leaves =
            ["fibonacci-1000", "fibonacci-2700", "preimage-8", "preimage-8-zk"].map(program);
        let items = || -> Vec<BlockItem<ProgramRef<'_>>> {
            leaves
                .iter()
                .map(|(key, proof, members)| {
                    BlockItem::Program(ProgramRef { verifying_key: key, members, proof })
                })
                .chain((0..3).map(|i| BlockItem::Signature(signature(i))))
                .collect()
        };
        let mut one_by_one = Aggregator::new().unwrap();
        for item in items() {
            match item {
                BlockItem::Program(p) => {
                    one_by_one.add_program_leaf(p.verifying_key, p.members, p.proof).unwrap()
                }
                BlockItem::Signature(signed) => one_by_one.add_signature(signed).unwrap(),
            }
        }
        let expected = one_by_one.close().unwrap().unwrap().statements;

        // The node over the first two leaves, proven as another process would, then the block.
        let cache = FirstLevelCache::new(16, std::time::Duration::from_secs(60));
        let first: Vec<(Vec<u8>, Vec<ProofStatement>)> = leaves[..2]
            .iter()
            .map(|(key, proof, members)| {
                let leaf = LeafRef::Program { verifying_key: key, members, proof };
                (leaf.prove_bytes().unwrap(), leaf.statements().unwrap())
            })
            .collect();
        let pair: Vec<(&[u8], &[ProofStatement])> =
            first.iter().map(|(proof, s)| (proof.as_slice(), s.as_slice())).collect();
        let mut union: Vec<ProofStatement> = first.iter().flat_map(|(_, s)| s.clone()).collect();
        union.sort_by_key(ProofStatement::id);
        union.dedup();
        let ticket = cache.claim(first_level_key(&union)).unwrap();
        ticket.fulfil_bytes(&union, &prove_node_bytes(&pair).unwrap()).unwrap();

        let mut block = Aggregator::new().unwrap();
        block.set_first_level_cache(cache.clone());
        block.add_block(items()).unwrap();
        assert_eq!(block.buffered_signatures().len(), 3, "the signatures wait for the close");
        assert_eq!(block.close().unwrap().unwrap().statements, expected);
        // The block's top and the pair of the last two leaves, each leaf of that pair, and the
        // signatures' node at the close: proven here; the pair proven elsewhere: taken.
        assert_eq!(cache.stats(), FirstLevelStats { hits: 1, misses: 5, ..Default::default() });
    }
}
