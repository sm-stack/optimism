//! End-to-end check that an aggregate this crate proves is accepted by the execution client's
//! verifier for exactly the statements it covers.
//!
//! Needs a real statement proof and proves with SP1, so it is ignored by default. Run with:
//! - `KONA_SP1_ELF_DIR`: holds `proof-aggregation-elf`.
//! - `PROOF_AGGREGATOR_FIXTURE_DIR`: holds `proof.bin` (bincode `SP1Proof::Compressed`) and
//!   `public_values.bin` for a statement, and `program-elf`, the ELF that produced the proof. The
//!   test writes the program's `verifying_key.bin` there, and the aggregate it proved
//!   (`aggregate_proof.bin`, `aggregation_vkey_hash.txt`) for tests that need one ready.

#![allow(missing_docs)]

use std::{fs, path::PathBuf};

use alloy_op_evm::ProofAggregateVerifier;
use alloy_primitives::{B256, Bytes};
use kona_sp1_proof_aggregator::{PROOF_AGGREGATION_ELF, StatementProof, build_stdin, encode_proof};
use op_alloy_consensus::{ProofStatement, statements_commitment};
use op_sp1_proofs::{Sp1ProofAggregateVerifier, vkey_hash_from_words};
use sha2::{Digest, Sha256};
use sp1_sdk::{CpuProver, Elf, HashableKey, ProveRequest, Prover, ProvingKey};

#[tokio::test]
#[ignore = "proves with SP1; needs PROOF_AGGREGATOR_FIXTURE_DIR and KONA_SP1_ELF_DIR"]
async fn aggregate_proof_verifies_against_statements_commitment() {
    let dir = PathBuf::from(std::env::var("PROOF_AGGREGATOR_FIXTURE_DIR").unwrap());
    let read = |name: &str| fs::read(dir.join(name)).unwrap();
    let prover = CpuProver::new().await;

    // The statement: the fixture program's vkey hash and public values digest.
    let program_pk = prover.setup(Elf::from(read("program-elf"))).await.unwrap();
    let vk = program_pk.verifying_key();
    let verifying_key = bincode::serde::encode_to_vec(vk, bincode::config::legacy()).unwrap();
    fs::write(dir.join("verifying_key.bin"), &verifying_key).unwrap();
    let public_values = read("public_values.bin");
    let statement = ProofStatement {
        vkey_hash: vkey_hash_from_words(vk.hash_u32()),
        public_values_digest: B256::from(<[u8; 32]>::from(Sha256::digest(&public_values))),
    };

    let entry = StatementProof {
        statement,
        public_values: public_values.into(),
        proof: read("proof.bin").into(),
        verifying_key: verifying_key.into(),
    };
    let (stdin, statements) = build_stdin(&[entry]).unwrap();
    assert_eq!(statements, vec![statement]);

    let agg_elf = kona_sp1_elfs::load_elf(PROOF_AGGREGATION_ELF).unwrap();
    let agg_pk = prover.setup(Elf::from(agg_elf)).await.unwrap();
    let aggregation_vkey_hash = vkey_hash_from_words(agg_pk.verifying_key().hash_u32());
    let proof = prover.prove(&agg_pk, stdin).compressed().await.unwrap();
    let proof: Bytes = encode_proof(&proof.proof).unwrap();

    fs::write(dir.join("aggregate_proof.bin"), &proof).unwrap();
    fs::write(dir.join("aggregation_vkey_hash.txt"), aggregation_vkey_hash.to_string()).unwrap();

    let commitment = statements_commitment(&statements);
    let verifier = Sp1ProofAggregateVerifier::new();
    verifier.verify(aggregation_vkey_hash, commitment, &proof).expect("aggregate verifies");

    // Bound to exactly these statements and this aggregation program.
    let mut other = statement;
    other.public_values_digest.0[0] ^= 1;
    assert!(
        verifier.verify(aggregation_vkey_hash, statements_commitment(&[other]), &proof).is_err()
    );
    assert!(verifier.verify(statement.vkey_hash, commitment, &proof).is_err());
}
