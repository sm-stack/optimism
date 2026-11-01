//! leanVM tree aggregates: one root of a leanVM aggregation tree proves statements of any programs.
//!
//! A tree's circuits are fixed by its class ([`classes`], [`shape`]), not by its leaf programs.
//! Each leaf publishes a list of members, and its first-level node reads the list, checks the
//! leaf's output commits to it, and declares one claim per member labelled by the leaf program's
//! verifying key digest. A statement is that digest and one member. There are three leaf classes:
//!
//! - [`PROGRAM_CLASS`]: small arbitrary programs, normalized to the class's bounds, whose leaf
//!   proofs users submit in zero knowledge ([`verify_program_leaf`]).
//! - [`SIGNATURE_CLASS`]: the leanSPHINCS signature-member guest, whose leaves op-aggregator proves
//!   from raw signatures ([`Signed`]): each signature's member binds its public key and message.
//! - [`LARGE_PROGRAM_CLASS`]: large arbitrary programs, proven in zero knowledge at a lower rate so
//!   that verifying them fits the tree's tier. A program normalized to this class's bounds has
//!   another verifying key, so its statements are another program's.
//!
//! Every first level shares the tree's one tier ([`ZK_PLACEMENT`]), so a root's seal opens that
//! tier alone whatever it holds, and a leaf's shape names its class ([`program_class`]).
//!
//! The root declares the union of its leaves' claims, and its claims on the class's fixed
//! polynomials are settled by a seal: openings against commitments the class key carries.
//!
//! - [`verify`] checks a root and seal against statements: what derivation runs, natively in the
//!   nodes and inside the fault proof program.
//! - [`Aggregator`] folds leaves into one root, closes and seals it: what the sequencer runs.
//!
//! The class key is pinned ([`CLASS_KEY_DIGEST`],
//! `op_alloy_consensus::LEANVM_TREE_CLASS_KEY_DIGEST`). A native process builds the class once and
//! checks it against the pin; with the `embedded-class-key` feature the build script builds it
//! instead and the binary embeds it, for the fault proof program, which runs from scratch every
//! time and whose prestate binds the binary.

mod class;

pub use class::*;

#[cfg(feature = "sequencer")]
mod first_level;
#[cfg(feature = "sequencer")]
mod sequencer;

#[cfg(feature = "sequencer")]
pub use first_level::*;
#[cfg(feature = "sequencer")]
pub use sequencer::*;

use alloy_primitives::B256;
use leanvm::{
    ProofTranscript, VerifyingKey,
    aggregate::{Claim, ClaimSet, SealRoots, Tree, TreeProof},
};
use op_alloy_consensus::{
    MAX_PROOF_AGGREGATE_PROGRAMS, MAX_PROOF_AGGREGATE_STATEMENTS,
    MAX_STATEMENT_VERIFYING_KEY_BYTES, ProofAggregateVerifier, ProofStatement,
    TARGET_PROOF_AGGREGATE_STATEMENTS,
};
use std::sync::OnceLock;

// The consensus limits op-alloy and the sequencer apply are this class's: a root declares fewer
// claims than its capacity over at most its groups, the sequencer's target is within them, and a
// key holds its root, five words and the image. The tree's leaf shape is its first class's, so the
// small program class must come first; the program classes' bounds differ, so a verifying key is of
// one at most.
const _: () = assert!(
    PROGRAM_CLASS == 0 &&
        CLASS_BOUNDS[PROGRAM_CLASS][0] != CLASS_BOUNDS[LARGE_PROGRAM_CLASS][0] &&
        MAX_PROOF_AGGREGATE_STATEMENTS == CLAIM_CAPACITY - 1 &&
        TARGET_PROOF_AGGREGATE_STATEMENTS <= MAX_PROOF_AGGREGATE_STATEMENTS &&
        MAX_PROOF_AGGREGATE_PROGRAMS == GROUP_CAPACITY &&
        32 + 5 * 8 + 8 * CLASS_BOUNDS[PROGRAM_CLASS][3] <= MAX_STATEMENT_VERIFYING_KEY_BYTES &&
        32 + 5 * 8 + 8 * CLASS_BOUNDS[LARGE_PROGRAM_CLASS][3] <=
            MAX_STATEMENT_VERIFYING_KEY_BYTES &&
        CLASS_BOUNDS[LARGE_PROGRAM_CLASS][4] == CLASS_BOUNDS[PROGRAM_CLASS][4] &&
        CLASS_ZERO_KNOWLEDGE[PROGRAM_CLASS] &&
        CLASS_ZERO_KNOWLEDGE[LARGE_PROGRAM_CLASS] &&
        SIGNATURES_PER_LEAF <= CLASS_BOUNDS[SIGNATURE_CLASS][4]
);

/// The [`ProofAggregateVerifier`] of proof aggregates.
///
/// A node should build it with [`LeanVmTreeVerifier::load`], so that a class that fails to load
/// stops the node at startup instead of making every aggregate look invalid.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeanVmTreeVerifier;

impl LeanVmTreeVerifier {
    /// The verifier, its class loaded now: built and checked against the pin natively, or the
    /// embedded class key loaded.
    pub fn load() -> Result<Self, String> {
        class_verifier()?;
        Ok(Self)
    }
}

impl ProofAggregateVerifier for LeanVmTreeVerifier {
    fn verify(
        &self,
        statements: &[ProofStatement],
        root: &[u8],
        seal: &[u8],
    ) -> Result<(), String> {
        verify(statements, root, seal)
    }
}

/// The class's verifier: its tree and the roots its seals open against.
type ClassVerifier = (&'static Tree<'static>, &'static SealRoots);

/// The class key the build script made, which the binary carries and the fault proof program's
/// prestate binds. It is about 1 KB, so it is loaded against the pinned digest all the same.
#[cfg(feature = "embedded-class-key")]
fn class_verifier() -> Result<ClassVerifier, String> {
    static CLASS_KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/class-key.bin"));
    static VERIFIER: OnceLock<Result<(Tree<'static>, SealRoots), String>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let tree = class_tree_from_bytes(CLASS_KEY, &CLASS_KEY_DIGEST)
                .map_err(|err| format!("the embedded class key does not load: {err}"))?;
            let roots =
                tree.seal_roots().cloned().ok_or("a loaded class key carries its seal roots")?;
            Ok((tree, roots))
        })
        .as_ref()
        .map(|(tree, roots)| (tree, roots))
        .map_err(Clone::clone)
}

/// The class built here, checked against the pinned digest: the aggregator's own.
#[cfg(not(feature = "embedded-class-key"))]
fn class_verifier() -> Result<ClassVerifier, String> {
    class_prover().map(|ClassProver { tree, roots, .. }| (tree, roots))
}

/// The class's tree, the commitments to its fixed polynomials, which seal its roots, and their
/// roots: built here, for the aggregator and the native verifier.
#[cfg(any(feature = "sequencer", not(feature = "embedded-class-key")))]
struct ClassProver {
    tree: Tree<'static>,
    /// What seals the aggregator's roots.
    #[cfg_attr(not(feature = "sequencer"), allow(dead_code))]
    prover: leanvm::aggregate::SealProver,
    /// The verifier's roots, natively; the embedded class key carries its own.
    #[cfg_attr(feature = "embedded-class-key", allow(dead_code))]
    roots: SealRoots,
}

#[cfg(any(feature = "sequencer", not(feature = "embedded-class-key")))]
fn build_class() -> Result<ClassProver, String> {
    let tree = class_tree().map_err(|err| format!("the tree class: {err}"))?;
    let prover = tree.seal_prover().map_err(|err| format!("the class's commitments: {err}"))?;
    let roots = prover.roots();
    let key = tree.mixed_verifier_bytes(&roots).map_err(|err| format!("the class key: {err}"))?;
    if Tree::mixed_class_key_digest(&key) != CLASS_KEY_DIGEST {
        return Err(String::from(
            "the tree class differs from the pinned CLASS_KEY_DIGEST: leanVM or the class changed",
        ));
    }
    Ok(ClassProver { tree, prover, roots })
}

#[cfg(any(feature = "sequencer", not(feature = "embedded-class-key")))]
fn class_prover() -> Result<&'static ClassProver, String> {
    static PROVER: OnceLock<Result<ClassProver, String>> = OnceLock::new();
    PROVER.get_or_init(build_class).as_ref().map_err(Clone::clone)
}

/// Checks that `root`, a root of the class, and its `seal` prove exactly `statements`, listed in
/// the canonical order of the root's claim set ([`canonical`]).
pub fn verify(statements: &[ProofStatement], root: &[u8], seal: &[u8]) -> Result<(), String> {
    if statements.is_empty() || statements.len() > MAX_PROOF_AGGREGATE_STATEMENTS {
        return Err(format!(
            "{} statements, not 1 to {MAX_PROOF_AGGREGATE_STATEMENTS}",
            statements.len()
        ));
    }
    let claims = claim_set(statements)?;
    let root = TreeProof::from_bytes(root).map_err(|err| format!("malformed tree root: {err}"))?;
    let seal = ProofTranscript::from_bytes(seal).ok_or("malformed seal")?;
    let (tree, roots) = class_verifier()?;
    tree.verify_claims_sealed(&root, &claims, roots, &seal)
        .map_err(|err| format!("the tree root does not prove its statements: {err}"))
}

/// The claim a statement is: the verifying key digest labels the member.
fn claim(statement: &ProofStatement) -> Claim {
    let [a, b, c, d] = words(statement.vkey_hash);
    Claim { label: [a, b, c, d, 0, 0], member: words(statement.public_values_digest) }
}

/// The statement a claim is, if its label is a verifying key digest.
fn statement(claim: Claim) -> Option<ProofStatement> {
    let [a, b, c, d, 0, 0] = claim.label else { return None };
    Some(ProofStatement {
        vkey_hash: bytes([a, b, c, d]),
        public_values_digest: bytes(claim.member),
    })
}

/// The statements' canonical order: the order of the claim set they make, each once.
pub fn canonical(statements: &[ProofStatement]) -> Vec<ProofStatement> {
    ClaimSet::from_claims(statements.iter().map(claim)).claims().filter_map(statement).collect()
}

/// The claim set `statements` are, if they are listed canonically and each once.
fn claim_set(statements: &[ProofStatement]) -> Result<ClaimSet, String> {
    let set = ClaimSet::from_claims(statements.iter().map(claim));
    if !set.claims().map(statement).eq(statements.iter().copied().map(Some)) {
        return Err(String::from("statements are not in canonical order, each once"));
    }
    Ok(set)
}

/// The digest of `verifying_key`, if it is a key of a program class: the program of the
/// statements its leaves publish. The classes' bounds differ, so a key is of one at most.
pub fn program_digest(verifying_key: &[u8]) -> Result<B256, String> {
    PROGRAM_CLASSES
        .into_iter()
        .find_map(|class| class_key(class, verifying_key).ok())
        .map(|key| B256::from(*key.digest()))
        .ok_or_else(|| String::from("the verifying key is not of a program normalized to a class"))
}

/// A verifying key of leaf class `class`: a program normalized to its bounds.
///
/// The key's encoding is its program commitment's root, then five little-endian words (bytecode
/// height, entry, RAM height, advice height, image length), then the image.
fn class_key(class: usize, bytes: &[u8]) -> Result<VerifyingKey, String> {
    let key = VerifyingKey::from_bytes(bytes).ok_or("malformed verifying key")?;
    let word = |i: usize| u64::from_le_bytes(bytes[32 + 8 * i..40 + 8 * i].try_into().unwrap());
    let [log_bytecode, log_ram, log_advice, image_words, _] = CLASS_BOUNDS[class];
    let fits = word(0) == log_bytecode as u64 &&
        word(2) == log_ram as u64 &&
        word(3) == log_advice as u64 &&
        word(4) == image_words as u64;
    if !fits {
        return Err(String::from("the verifying key is not of a program normalized to its class"));
    }
    Ok(key)
}

/// The verifying key digest of the signature-member guest normalized to the signature class:
/// [`signature_program_digest`], pinned.
pub const SIGNATURE_PROGRAM_DIGEST: B256 = op_alloy_consensus::SIGNATURE_PROGRAM_DIGEST;

/// A 32-byte value's four little-endian words.
fn words(value: B256) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(value[8 * i..8 * i + 8].try_into().unwrap()))
}

/// The 32 bytes of four little-endian words.
fn bytes(words: [u64; 4]) -> B256 {
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    B256::from(out)
}

#[cfg(all(test, feature = "sequencer"))]
mod tests {
    use super::*;
    use crate::sequencer::signature_program;
    use leanvm::Program;
    use op_alloy_consensus::{
        LEANVM_TREE_CLASS_KEY_DIGEST, LeanVmTreeProof, ProofAggregatePayload,
        TARGET_PROOF_AGGREGATE_STATEMENTS,
    };
    use std::sync::Arc;

    /// A program leaf of a program class (`examples/fixtures.rs`): its key, proof and members.
    struct ProgramFixture {
        key: &'static [u8],
        proof: &'static [u8],
        members: &'static [u8],
    }

    macro_rules! program {
        ($name:literal) => {
            ProgramFixture {
                key: include_bytes!(concat!("../testdata/", $name, ".key")),
                proof: include_bytes!(concat!("../testdata/", $name, ".proof")),
                members: include_bytes!(concat!("../testdata/", $name, ".members")),
            }
        };
    }

    macro_rules! signature {
        ($i:literal) => {
            Signed::decode(
                include_bytes!(concat!("../testdata/signature-", $i, ".key")),
                B256::from(*include_bytes!(concat!("../testdata/signature-", $i, ".message"))),
                include_bytes!(concat!("../testdata/signature-", $i, ".signature")),
            )
            .unwrap()
        };
    }

    impl ProgramFixture {
        fn members(&self) -> Vec<B256> {
            self.members.chunks_exact(32).map(B256::from_slice).collect()
        }
    }

    /// The program fixtures, each proven in zero knowledge; the last in the large program class.
    const fn programs() -> [ProgramFixture; 5] {
        [
            program!("fibonacci-1000"),
            program!("fibonacci-2700"),
            program!("preimage-8"),
            program!("preimage-8-zk"),
            program!("fibonacci-1000-large"),
        ]
    }

    fn signatures() -> [Signed; 3] {
        [signature!("0"), signature!("1"), signature!("2")]
    }

    /// First-level nodes proven ahead and handed over as bytes fold as those the aggregator proves
    /// itself: the same statements, served from the cache. A node handed over for other statements
    /// is refused, its key released.
    #[test]
    fn an_aggregator_takes_first_level_nodes_proven_ahead() {
        let cache = FirstLevelCache::new(8, std::time::Duration::from_secs(60));
        let [a, b, ..] = programs();
        let (a_members, b_members) = (a.members(), b.members());
        let ahead = |leaf: LeafRef<'_>| {
            let statements = leaf.statements().unwrap();
            let ticket = cache.claim(first_level_key(&statements)).unwrap();
            ticket.fulfil_bytes(&statements, &leaf.prove_bytes().unwrap()).unwrap();
        };
        let a_leaf = LeafRef::Program { verifying_key: a.key, members: &a_members, proof: a.proof };
        ahead(a_leaf);
        ahead(LeafRef::Signatures(&signatures()));

        let b_statements =
            LeafRef::Program { verifying_key: b.key, members: &b_members, proof: b.proof }
                .statements()
                .unwrap();
        let b_key = first_level_key(&b_statements);
        let ticket = cache.claim(b_key).unwrap();
        assert!(ticket.fulfil_bytes(&b_statements, &a_leaf.prove_bytes().unwrap()).is_err());
        assert!(!cache.contains(&b_key), "the refused node's key is free again");

        let fold = |cache: Option<Arc<FirstLevelCache>>| {
            let mut aggregator = Aggregator::new().unwrap();
            if let Some(cache) = cache {
                aggregator.set_first_level_cache(cache);
            }
            aggregator.add_program_leaf(a.key, &a_members, a.proof).unwrap();
            aggregator.add_program_leaf(b.key, &b_members, b.proof).unwrap();
            for signed in signatures() {
                aggregator.add_signature(signed).unwrap();
            }
            aggregator.close().unwrap().unwrap().statements
        };
        assert_eq!(fold(Some(cache.clone())), fold(None));
        assert_eq!(cache.stats(), FirstLevelStats { hits: 2, misses: 1, ..Default::default() });
    }

    /// A signature's encodings decode back to it.
    #[test]
    fn signatures_encode_as_they_decode() {
        for signed in signatures() {
            let (key, message, signature) = signed.encode();
            assert_eq!(Signed::decode(&key, message, &signature).unwrap(), signed);
        }
    }

    /// The aggregate over the fixtures, as a proof aggregate payload.
    const PAYLOAD: &[u8] = include_bytes!("../testdata/tree.payload");

    fn payload() -> (ProofAggregatePayload, LeanVmTreeProof) {
        let payload = ProofAggregatePayload::from_rlp_bytes(PAYLOAD).unwrap();
        let proof = LeanVmTreeProof::from_rlp_bytes(&payload.proof).unwrap();
        (payload, proof)
    }

    #[test]
    fn op_nodes_embedded_class_key_is_the_class() {
        let ClassProver { tree, roots, .. } = class_prover().unwrap();
        let key = tree.mixed_verifier_bytes(roots).unwrap();
        assert!(
            key == include_bytes!("../../../op-core/types/leanvm_class_key.bin"),
            "op-core's class key is stale: run `cd rust && just leanvm-class-key`"
        );
    }

    #[test]
    fn the_pins_are_op_alloys_and_the_native_class_and_guest_match_them() {
        assert_eq!(B256::from(CLASS_KEY_DIGEST), LEANVM_TREE_CLASS_KEY_DIGEST);
        LeanVmTreeVerifier::load().expect("the class builds to the pinned key");
        assert_eq!(signature_program_digest(), SIGNATURE_PROGRAM_DIGEST);
    }

    #[test]
    fn verifies_the_fixture_aggregate() {
        let (payload, _) = payload();
        payload.verify(&LeanVmTreeVerifier).unwrap();
        // Five program members (the large class's fibonacci is another program than the small
        // one's, with the same member) and three signatures.
        assert_eq!(payload.statements.len(), 8);
        assert_eq!(canonical(&payload.statements), payload.statements);
        let signed: Vec<ProofStatement> = signatures().iter().map(Signed::statement).collect();
        assert!(signed.iter().all(|s| payload.statements.contains(s)), "the signature statements");
    }

    #[test]
    fn rejects_statements_the_root_does_not_prove() {
        let (payload, proof) = payload();
        let reject = |statements: &[ProofStatement], why: &str| {
            assert!(verify(statements, &proof.root, &proof.seal).is_err(), "{why}");
        };
        let mut statements = payload.statements.clone();
        statements[0].public_values_digest.0[0] ^= 1;
        reject(&canonical(&statements), "another member");
        let mut statements = payload.statements.clone();
        statements[2].vkey_hash.0[31] ^= 1;
        reject(&canonical(&statements), "another program");
        reject(&payload.statements[..5], "a subset");
        let mut statements = payload.statements.clone();
        statements.swap(0, 5);
        reject(&statements, "out of canonical order");
        let mut statements = payload.statements.clone();
        statements.push(statements[0]);
        reject(&statements, "a repeat");
        let mut statements = payload.statements;
        statements.push(ProofStatement { vkey_hash: B256::repeat_byte(1), ..statements[0] });
        reject(&canonical(&statements), "an extra statement");
        reject(&[], "no statement");
    }

    #[test]
    fn rejects_a_tampered_root_or_seal() {
        let (payload, proof) = payload();
        let statements = &payload.statements;
        for at in [0, proof.root.len() / 2, proof.root.len() - 1] {
            let mut root = proof.root.to_vec();
            root[at] ^= 1;
            assert!(verify(statements, &root, &proof.seal).is_err(), "root byte {at}");
        }
        for at in [0, 8, proof.seal.len() / 2, proof.seal.len() - 1] {
            let mut seal = proof.seal.to_vec();
            seal[at] ^= 1;
            assert!(verify(statements, &proof.root, &seal).is_err(), "seal byte {at}");
        }
        assert!(verify(statements, &proof.root, &proof.seal[..proof.seal.len() - 1]).is_err());
        assert!(verify(statements, &proof.root, &[]).is_err(), "a node root needs its seal");
        assert!(verify(statements, &proof.seal, &proof.root).is_err(), "swapped");
    }

    #[test]
    fn verifies_program_leaves_of_the_class() {
        for fixture in programs() {
            let digest =
                verify_program_leaf(fixture.key, &fixture.members(), fixture.proof).unwrap();
            assert_eq!(digest.0, *VerifyingKey::from_bytes(fixture.key).unwrap().digest());
        }
        let [fib, _, preimage, zk, large] = programs();
        assert_ne!(
            verify_program_leaf(large.key, &large.members(), large.proof).unwrap(),
            verify_program_leaf(fib.key, &fib.members(), fib.proof).unwrap(),
            "one guest and member, another class: another program"
        );
        assert_eq!(large.members(), fib.members());
        assert!(verify_program_leaf(fib.key, &fib.members(), large.proof).is_err(), "small key");
        assert!(verify_program_leaf(large.key, &fib.members(), fib.proof).is_err(), "large key");
        let zk_members = zk.members();
        assert!(verify_program_leaf(fib.key, &zk_members, zk.proof).is_err(), "zk, another key");
        assert!(
            verify_program_leaf(zk.key, &fib.members(), zk.proof).is_err(),
            "zk, another member"
        );
        assert!(verify_program_leaf(zk.key, &zk_members, &zk.proof[..zk.proof.len() - 1]).is_err());
        let members = fib.members();
        let mut wrong = members.clone();
        wrong[0].0[0] ^= 1;
        assert!(verify_program_leaf(fib.key, &wrong, fib.proof).is_err(), "another member");
        let two = [members[0], members[0]];
        assert!(verify_program_leaf(fib.key, &two, fib.proof).is_err(), "another member list");
        assert!(verify_program_leaf(fib.key, &[], fib.proof).is_err(), "no member");
        let many = vec![members[0]; CLASS_BOUNDS[PROGRAM_CLASS][4] + 1];
        assert!(verify_program_leaf(fib.key, &many, fib.proof).is_err(), "too many members");
        assert!(verify_program_leaf(preimage.key, &members, fib.proof).is_err(), "another key");
        assert!(verify_program_leaf(fib.key, &members, &fib.proof[..fib.proof.len() - 1]).is_err());
        let unnormalized =
            Program::from_elf(include_bytes!("../testdata/fibonacci-members.elf")).unwrap();
        assert!(
            verify_program_leaf(&unnormalized.verifying_key().to_bytes(), &members, fib.proof)
                .is_err(),
            "a key of a program not normalized to the class"
        );
        assert!(
            verify_program_leaf(
                &signature_program().verifying_key().to_bytes(),
                &members,
                fib.proof
            )
            .is_err(),
            "a key of the signature class"
        );
    }

    #[test]
    fn verifies_signatures_and_recomputes_their_members() {
        let [first, second, _] = signatures();
        assert_eq!(first.verify().unwrap(), first.member());
        assert_eq!(first.statement().vkey_hash, SIGNATURE_PROGRAM_DIGEST);
        assert_ne!(first.member(), second.member());

        let key = include_bytes!("../testdata/signature-0.key");
        let message = B256::from(*include_bytes!("../testdata/signature-0.message"));
        let signature = include_bytes!("../testdata/signature-0.signature");
        let mut other = message;
        other.0[0] ^= 1;
        assert!(
            Signed::decode(key, other, signature).unwrap().verify().is_err(),
            "another message"
        );
        let other_key = include_bytes!("../testdata/signature-1.key");
        assert!(Signed::decode(other_key, message, signature).unwrap().verify().is_err());
        let mut flipped = signature.to_vec();
        flipped[100] ^= 1;
        assert!(
            Signed::decode(key, message, &flipped).unwrap().verify().is_err(),
            "a bad signature"
        );
        assert!(Signed::decode(&key[..31], message, signature).is_err());
        assert!(Signed::decode(key, message, &signature[..SIGNATURE_BYTES - 8]).is_err());
        assert!(Signed::decode(key, message, &[signature.as_slice(), &[0; 8]].concat()).is_err());
    }

    #[test]
    fn folds_program_leaves_and_signatures_into_a_verified_root() {
        let mut aggregator = Aggregator::new().unwrap();
        assert_eq!(aggregator.close().unwrap(), None, "nothing to close");
        for fixture in programs() {
            aggregator.add_program_leaf(fixture.key, &fixture.members(), fixture.proof).unwrap();
        }
        for signed in signatures() {
            aggregator.add_signature(signed).unwrap();
        }
        assert_eq!(aggregator.statements(), 8);
        let TreeAggregate { statements, proof } = aggregator.close().unwrap().unwrap();
        assert!(aggregator.is_empty(), "closing starts over");
        assert_eq!(statements, payload().0.statements, "the fixture's statements, canonically");
        verify(&statements, &proof.root, &proof.seal).unwrap();

        // One leaf: a first-level root, whose seal opens only its own columns.
        let [fib, ..] = programs();
        aggregator.add_program_leaf(fib.key, &fib.members(), fib.proof).unwrap();
        let TreeAggregate { statements, proof } = aggregator.close().unwrap().unwrap();
        assert_eq!(statements.len(), 1);
        verify(&statements, &proof.root, &proof.seal).unwrap();

        let mut wrong = fib.members();
        wrong[0].0[0] ^= 1;
        assert!(aggregator.add_program_leaf(fib.key, &wrong, fib.proof).is_err());
    }

    /// A program of the class publishing `members`: assembled, it exits with their output. Each
    /// `salt` makes another program.
    fn members_program(members: &[[u64; 4]], salt: u64) -> Program {
        use leanvm::{
            Region,
            asm::{Asm, Reg},
        };
        let output = leanvm_guest::members::output(members);
        let mut asm = Asm::new();
        for (register, word) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output) {
            asm.li(register, word);
        }
        asm.li(Reg::T0, salt);
        let program =
            Program::new(&asm.exit().finish(), Region::TEXT.base(), vec![], 0, 0).unwrap();
        classes()[PROGRAM_CLASS].program.normalize(&program).unwrap()
    }

    #[test]
    fn folds_a_leaf_publishing_several_members() {
        let members: Vec<[u64; 4]> = (0..3).map(|i| [i, 7, 7, 7]).collect();
        let program = members_program(&members, 0);
        let class = classes()[PROGRAM_CLASS];
        let run = class.program.prover(class.shape).prove(&program, &[]).unwrap();
        let key = program.verifying_key().to_bytes();
        let proof = run.proof.to_bytes();
        let members: Vec<B256> = members.into_iter().map(bytes).collect();
        let digest = verify_program_leaf(&key, &members, &proof).unwrap();
        assert!(verify_program_leaf(&key, &members[..2], &proof).is_err(), "part of the list");

        let mut aggregator = Aggregator::new().unwrap();
        aggregator.add_program_leaf(&key, &members, &proof).unwrap();
        let TreeAggregate { statements, proof } = aggregator.close().unwrap().unwrap();
        assert_eq!(statements.len(), 3, "every member is a statement");
        assert!(statements.iter().all(|s| s.vkey_hash == digest));
        verify(&statements, &proof.root, &proof.seal).unwrap();
    }

    /// A plain proof, of either rate, is of no program class: program leaves are zero knowledge.
    /// Nor is a zero-knowledge proof at another rate or of another member list.
    #[test]
    fn refuses_program_leaves_at_another_class_shape() {
        use leanvm::{
            PerTable, Rate, TableId,
            aggregate::{LeafClass, LeafShape},
        };
        let members: Vec<[u64; 4]> = (0..2).map(|i| [i, 6, 6, 6]).collect();
        let program = members_program(&members, 0);
        let key = program.verifying_key().to_bytes();
        let LeafClass { program: class, shape } = classes()[PROGRAM_CLASS];
        let heights = PerTable::from_fn(|t: TableId| CLASS_LEAF_HEIGHTS[PROGRAM_CLASS][t.index()]);
        let plain = |rate| LeafShape::plain(heights, Rate::new(rate).unwrap()).unwrap();
        let members: Vec<B256> = members.into_iter().map(bytes).collect();
        let mut aggregator = Aggregator::new().unwrap();
        for foreign in [plain(1), plain(2), plain(1).zero_knowledge()] {
            let proof = class.prover(foreign).prove(&program, &[]).unwrap().proof.to_bytes();
            assert!(verify_program_leaf(&key, &members, &proof).is_err());
            assert!(aggregator.add_program_leaf(&key, &members, &proof).is_err());
        }
        let zk = class.prover(shape).prove(&program, &[]).unwrap().proof;
        assert!(zk.is_zero_knowledge());
        let zk = zk.to_bytes();
        assert!(zk.len() <= op_alloy_consensus::MAX_STATEMENT_PROOF_BYTES, "{} bytes", zk.len());
        verify_program_leaf(&key, &members, &zk).unwrap();
        assert!(
            aggregator.add_program_leaf(&key, &members[..1], &zk).is_err(),
            "another member list"
        );
        assert!(aggregator.is_empty(), "a refused leaf adds nothing");
        assert_eq!(aggregator.close().unwrap(), None);
    }

    /// A leaf's shape names its program class; the signature class's leaves are the sequencer's,
    /// never a user's. A program normalized to the large class has another verifying key.
    #[test]
    fn names_the_program_class_by_leaf_shape() {
        assert_eq!(program_class(classes()[PROGRAM_CLASS].shape), Some(PROGRAM_CLASS));
        assert_eq!(program_class(classes()[LARGE_PROGRAM_CLASS].shape), Some(LARGE_PROGRAM_CLASS));
        assert_eq!(program_class(classes()[SIGNATURE_CLASS].shape), None);

        let program = members_program(&[[1, 2, 3, 4]], 0);
        let small = program.verifying_key().to_bytes();
        let large = classes()[LARGE_PROGRAM_CLASS].program.normalize(&program).unwrap();
        let large = large.verifying_key().to_bytes();
        assert_eq!(large.len(), op_alloy_consensus::MAX_STATEMENT_VERIFYING_KEY_BYTES);
        let (small_digest, large_digest) =
            (program_digest(&small).unwrap(), program_digest(&large).unwrap());
        assert_ne!(small_digest, large_digest, "the class's bounds are part of the program");
        assert!(class_key(LARGE_PROGRAM_CLASS, &small).is_err());
        assert!(class_key(PROGRAM_CLASS, &large).is_err());
    }

    /// The tier every first level and node shares: its padded heights and committed words. Raising
    /// any class's first level past one of them doubles that table for every fold, so a class or
    /// guest change that moves them must be deliberate. The signature class's first level already
    /// uses 98.5% of the hash table.
    #[test]
    fn keeps_the_tier() {
        let ClassProver { tree, .. } = class_prover().unwrap();
        let tier =
            [("EMUL", 18), ("EXK", 17), ("HASH", 14), ("SPLIT", 11), ("CAST", 15), ("PUB", 10)];
        let heights = |stats: leanvm::aggregate::CircuitStats| -> Vec<(&'static str, usize)> {
            stats.tables.iter().map(|t| (t.name, t.height_log)).collect()
        };
        let circuits = (0..CLASSES)
            .map(|class| tree.first_stats(class).expect("a first level per class"))
            .chain([tree.node_stats(ARITY).expect("the node")]);
        for stats in circuits {
            assert_eq!(stats.committed, 7_751_680, "committed words");
            assert_eq!(heights(stats), tier);
        }
    }

    /// A full signature leaf: [`SIGNATURES_PER_LEAF`] signatures, the most the signature class
    /// takes. Proving it needs about 5 GiB and a release build.
    #[test]
    #[ignore = "proves a full signature leaf: run in release"]
    fn folds_a_full_signature_leaf() {
        let (secret, public) = leansphincs::key_gen([9; 32]);
        let key: Vec<u8> =
            public.root.iter().chain(&public.public_param).flat_map(|w| w.to_le_bytes()).collect();
        let mut aggregator = Aggregator::new().unwrap();
        for i in 0..SIGNATURES_PER_LEAF as u64 {
            let message = [i, 0, 0, 0];
            let signature = secret.sign(&message).unwrap();
            // SAFETY: `Signature` is `repr(C)` words with no padding.
            let words = unsafe { leanvm_guest::as_words_unchecked(&signature) };
            let signature: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            let signed = Signed::decode(&key, bytes(message), &signature).unwrap();
            signed.verify().unwrap();
            aggregator.add_signature(signed).unwrap();
        }
        let TreeAggregate { statements, proof } = aggregator.close().unwrap().unwrap();
        assert_eq!(statements.len(), SIGNATURES_PER_LEAF);
        verify(&statements, &proof.root, &proof.seal).unwrap();
    }

    #[test]
    fn an_aggregate_fits_the_statement_target_and_the_group_capacity() {
        let aggregator = Aggregator::new().unwrap();
        let statement = |program: u16, member: u16| ProofStatement {
            vkey_hash: B256::left_padding_from(&(program + 1).to_be_bytes()),
            public_values_digest: B256::left_padding_from(&member.to_be_bytes()),
        };
        let full: Vec<_> =
            (0..TARGET_PROOF_AGGREGATE_STATEMENTS as u16).map(|i| statement(1, i)).collect();
        assert!(aggregator.fits(&full));
        let over: Vec<_> =
            (0..=TARGET_PROOF_AGGREGATE_STATEMENTS as u16).map(|i| statement(1, i)).collect();
        assert!(!aggregator.fits(&over), "past the statement target");
        let mut raised = Aggregator::new().unwrap();
        raised.set_max_statements(usize::MAX);
        let capacity: Vec<_> =
            (0..MAX_PROOF_AGGREGATE_STATEMENTS as u16).map(|i| statement(1, i)).collect();
        assert!(raised.fits(&capacity), "up to the class capacity when raised");
        let past: Vec<_> =
            (0..=MAX_PROOF_AGGREGATE_STATEMENTS as u16).map(|i| statement(1, i)).collect();
        assert!(!raised.fits(&past), "never past it");
        let programs: Vec<_> =
            (0..=MAX_PROOF_AGGREGATE_PROGRAMS as u16).map(|p| statement(p, 0)).collect();
        assert!(!aggregator.fits(&programs), "past the group capacity");
        assert!(aggregator.fits(&programs[1..]));
    }

    /// An aggregate of [`TARGET_PROOF_AGGREGATE_STATEMENTS`] statements of
    /// [`MAX_PROOF_AGGREGATE_PROGRAMS`] programs, as op-batcher's zlib channels compress it, fits
    /// three blobs with 4 KiB to spare (about 6 KB today): the batch and frame headers take a few
    /// dozen bytes, and compressors differ by a little more. Members are digests, which do not
    /// compress; the fixture's root and seal are any root's size.
    #[test]
    fn a_target_aggregate_compresses_into_three_blobs() {
        use std::io::Write;
        /// The data one blob carries in the OP Stack's encoding.
        const BLOB_DATA_BYTES: usize = 130_044;
        let (fixture, _) = payload();
        let statements: Vec<ProofStatement> = (0..TARGET_PROOF_AGGREGATE_STATEMENTS as u64)
            .map(|i| ProofStatement {
                vkey_hash: alloy_primitives::keccak256(
                    (i % MAX_PROOF_AGGREGATE_PROGRAMS as u64).to_le_bytes(),
                ),
                public_values_digest: alloy_primitives::keccak256(i.to_be_bytes()),
            })
            .collect();
        let payload = ProofAggregatePayload { statements: canonical(&statements), ..fixture };
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        zlib.write_all(&payload.to_rlp_bytes()).unwrap();
        let compressed = zlib.finish().unwrap().len();
        assert!(compressed + 4096 <= 3 * BLOB_DATA_BYTES, "{compressed} bytes compressed");
    }
}
