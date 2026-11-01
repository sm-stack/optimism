//! Writes this crate's `testdata`: program leaf proofs of the class, leanSPHINCS signatures, and a
//! tree aggregate over both.
//!
//! The guests are leanVM's `programs/fibonacci-members` and `programs/preimage-members` at the
//! pinned revision (`testdata/*.elf`), which commit one member each. Each is normalized to a
//! program class, and each run is proven at the class's leaf shape, in zero knowledge, so every
//! proof differs on every run:
//!
//! - `fibonacci-1000`, `fibonacci-2700`: the fibonacci guest on `n = 1000` and `n = 2700`;
//! - `preimage-8`, `preimage-8-zk`: the preimage guest on an 8-byte message, the words 7 and 9; the
//!   proof hides the message its member digests;
//! - `fibonacci-1000-large`: the fibonacci guest on `n = 1000` normalized to the large program
//!   class, whose verifying key, and so whose statement, is another program's. Proving it takes
//!   about 15 GB.
//!
//! For each it writes `<name>.key` (the normalized program's verifying key), `<name>.proof` and
//! `<name>.members` (its members, 32 bytes each). Then
//! `signature-<i>.{key,message,signature,member}` for three leanSPHINCS signatures from fixed
//! seeds, and `tree.payload`: the payload of an aggregate over the five leaves and the three
//! signatures, answering for L2 block 1. Regenerate with:
//!
//! ```sh
//! cargo run --release -p op-leanvm-tree --example fixtures
//! ```

use std::path::PathBuf;

use alloy_primitives::B256;
use leanvm::Program;
use op_alloy_consensus::{
    LEANVM_TREE_CLASS_KEY_DIGEST, PROOF_AGGREGATE_PAYLOAD_VERSION, ProofAggregatePayload,
};
use op_leanvm_tree::{
    Aggregator, LARGE_PROGRAM_CLASS, PROGRAM_CLASS, Signed, TreeAggregate, classes, verify,
    verify_program_leaf,
};

/// The program runs: a name, a guest, its advice and the leaf class it is proven in.
const RUNS: [(&str, &str, &[u64], usize); 5] = [
    ("fibonacci-1000", "fibonacci-members.elf", &[1000], PROGRAM_CLASS),
    ("fibonacci-2700", "fibonacci-members.elf", &[2700], PROGRAM_CLASS),
    ("preimage-8", "preimage-members.elf", &[8, 7], PROGRAM_CLASS),
    ("preimage-8-zk", "preimage-members.elf", &[8, 9], PROGRAM_CLASS),
    ("fibonacci-1000-large", "fibonacci-members.elf", &[1000], LARGE_PROGRAM_CLASS),
];

fn main() {
    let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let mut aggregator = Aggregator::new().unwrap();
    for (name, elf, advice, class) in RUNS {
        let class = classes()[class];
        let program = Program::from_elf(&std::fs::read(testdata.join(elf)).unwrap()).unwrap();
        let program = class.program.normalize(&program).unwrap();
        let run = class.program.prover(class.shape).prove(&program, advice).unwrap();
        let key = program.verifying_key().to_bytes();
        let proof = run.proof.to_bytes();
        let members = [member_of(name, &program, advice)];
        let digest = verify_program_leaf(&key, &members, &proof).unwrap();
        println!(
            "{name}: {} cycles, key {digest}, proof {} bytes",
            run.stats.cycles(),
            proof.len()
        );
        std::fs::write(testdata.join(format!("{name}.key")), &key).unwrap();
        std::fs::write(testdata.join(format!("{name}.proof")), &proof).unwrap();
        std::fs::write(testdata.join(format!("{name}.members")), members.concat()).unwrap();
        aggregator.add_program_leaf(&key, &members, &proof).unwrap();
    }
    for i in 0..3u8 {
        let (secret, public) = leansphincs::key_gen([i + 1; 32]);
        let message = [u64::from(i), 1, 2, 3];
        let signature = secret.sign(&message).unwrap();
        let key: Vec<u8> =
            public.root.iter().chain(&public.public_param).flat_map(|w| w.to_le_bytes()).collect();
        let message =
            B256::from(core::array::from_fn::<u8, 32, _>(|j| message[j / 8].to_le_bytes()[j % 8]));
        // SAFETY: `Signature` is `repr(C)` words with no padding.
        let words = unsafe { leanvm_guest::as_words_unchecked(&signature) };
        let signature: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let signed = Signed::decode(&key, message, &signature).unwrap();
        let member = signed.verify().unwrap();
        println!("signature-{i}: member {member}");
        std::fs::write(testdata.join(format!("signature-{i}.member")), member).unwrap();
        std::fs::write(testdata.join(format!("signature-{i}.key")), &key).unwrap();
        std::fs::write(testdata.join(format!("signature-{i}.message")), message).unwrap();
        std::fs::write(testdata.join(format!("signature-{i}.signature")), &signature).unwrap();
        aggregator.add_signature(signed).unwrap();
    }
    let TreeAggregate { statements, proof } = aggregator.close().unwrap().unwrap();
    verify(&statements, &proof.root, &proof.seal).unwrap();
    let payload = ProofAggregatePayload {
        version: PROOF_AGGREGATE_PAYLOAD_VERSION,
        through: 1,
        aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
        statements,
        proof: proof.to_rlp_bytes(),
    };
    println!(
        "tree: {} statements, root {} bytes, seal {} bytes, payload {} bytes",
        payload.statements.len(),
        proof.root.len(),
        proof.seal.len(),
        payload.to_rlp_bytes().len()
    );
    std::fs::write(testdata.join("tree.payload"), payload.to_rlp_bytes()).unwrap();
}

/// The one member the guest `name` commits on `advice`, computed natively and checked against the
/// program's execution: the digest of its public values.
fn member_of(name: &str, program: &Program, advice: &[u64]) -> B256 {
    let mut public = leanvm_guest::PublicValues::new();
    if name.starts_with("fibonacci") {
        let (mut a, mut b) = (0u64, 1u64);
        for _ in 0..advice[0] {
            (a, b) = (b, a.wrapping_add(b));
        }
        public.commit(&[advice[0], a]);
    } else {
        let mut hasher = leanvm_guest::Blake2s::new();
        hasher.update(&advice[1].to_le_bytes()[..advice[0] as usize]);
        public.commit(&hasher.finalize_words());
    }
    let member = public.digest();
    let execution = program.execute(advice).unwrap();
    assert_eq!(execution.output, leanvm_guest::members::output(&[member]), "{name}");
    B256::from(core::array::from_fn::<u8, 32, _>(|i| member[i / 8].to_le_bytes()[i % 8]))
}
