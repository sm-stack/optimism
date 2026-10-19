//! Proves proof aggregates for an op-reth sequencer.
//!
//! The sequencer queues verified statement proofs (`optimism_submitStatementProof`). The aggregator
//! reads them (`admin_pendingStatementProofs`), proves the `proof-aggregation` SP1 guest over a
//! batch, which verifies each proof recursively, and hands the compressed proof back
//! (`admin_submitProofAggregate`). The sequencer then includes it as the block's proof aggregate
//! (`0x7C`) transaction.

use alloy_primitives::Bytes;
use anyhow::{Context, Result, bail, ensure};
use op_alloy_consensus::ProofStatement;
pub use op_alloy_consensus::{PendingAggregate, StatementProof};
use op_sp1_proofs::vkey_hash_to_words;
use sp1_sdk::{SP1Proof, SP1Stdin};

/// File name of the aggregation guest ELF under `KONA_SP1_ELF_DIR`.
pub const PROOF_AGGREGATION_ELF: &str = "proof-aggregation-elf";

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
    op_sp1_proofs::decode_bincode(bytes, what).map_err(anyhow::Error::msg)
}

/// Builds the aggregation guest's stdin: the statement list, then each statement's proof and
/// verifying key for SP1's deferred verification, in the same order.
pub fn build_stdin(proofs: &[StatementProof]) -> Result<(SP1Stdin, Vec<ProofStatement>)> {
    ensure!(!proofs.is_empty(), "an aggregate needs at least one statement");

    let mut stdin = SP1Stdin::new();
    let mut statements = Vec::with_capacity(proofs.len());
    let mut guest_statements = Vec::with_capacity(proofs.len());
    for (i, entry) in proofs.iter().enumerate() {
        op_sp1_proofs::decode_verifying_key(&entry.verifying_key, entry.statement.vkey_hash)
            .map_err(|err| anyhow::anyhow!("statement {i}: {err}"))?;
        guest_statements.push((
            vkey_hash_to_words(entry.statement.vkey_hash),
            entry.statement.public_values_digest.0,
        ));
        statements.push(entry.statement);
    }
    stdin.write(&guest_statements);
    for (i, entry) in proofs.iter().enumerate() {
        let SP1Proof::Compressed(proof) = decode::<SP1Proof>(&entry.proof, "statement proof")?
        else {
            bail!("statement {i}: proof is not an SP1 compressed proof");
        };
        let vk: sp1_hypercube::SP1VerifyingKey = decode(&entry.verifying_key, "verifying key")?;
        stdin.write_proof(*proof, vk.vk);
    }
    Ok((stdin, statements))
}

/// Encodes a compressed aggregate proof the way the sequencer and the execution client decode it.
pub fn encode_proof(proof: &SP1Proof) -> Result<Bytes> {
    Ok(bincode::serde::encode_to_vec(proof, bincode::config::legacy())
        .context("encode aggregate proof")?
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_batch() {
        assert!(build_stdin(&[]).is_err());
    }

    #[test]
    fn rejects_verifying_key_that_does_not_match() {
        let proof = StatementProof {
            statement: ProofStatement::default(),
            public_values: Bytes::new(),
            proof: Bytes::new(),
            verifying_key: Bytes::from_static(b"not a key"),
        };
        let err = build_stdin(&[proof]).unwrap_err().to_string();
        assert!(err.contains("statement 0"), "{err}");
    }
}
