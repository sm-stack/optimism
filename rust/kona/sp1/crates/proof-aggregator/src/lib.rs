//! Proves proof aggregates for an op-reth sequencer.
//!
//! The sequencer queues verified statement proofs (`optimism_submitStatementProof`). The aggregator
//! reads them (`admin_pendingStatementProofs`), proves the `proof-aggregation` SP1 guest over a
//! batch, which verifies each proof recursively, and hands the compressed proof back
//! (`admin_submitProofAggregate`). The sequencer then includes it as the block's proof aggregate
//! (`0x7C`) transaction.

use alloy_primitives::{B256, Bytes};
use anyhow::{Context, Result, bail, ensure};
use op_alloy_consensus::ProofStatement;
use serde::{Deserialize, Serialize};
use sp1_sdk::{SP1Proof, SP1Stdin};

/// File name of the aggregation guest ELF under `KONA_SP1_ELF_DIR`.
pub const PROOF_AGGREGATION_ELF: &str = "proof-aggregation-elf";

/// A queued statement proof, as `admin_pendingStatementProofs` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementProof {
    /// The statement the proof proves.
    pub statement: ProofStatement,
    /// The public values whose SHA-256 is `statement.public_values_digest`.
    pub public_values: Bytes,
    /// The SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
    /// The proven program's verifying key, bincode-encoded `SP1VerifyingKey`.
    pub verifying_key: Bytes,
}

/// An aggregate for `admin_submitProofAggregate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAggregate {
    /// Verifying key digest of the aggregation program.
    pub aggregation_vkey_hash: B256,
    /// The statements the aggregate covers, in the order the aggregation program verified them.
    pub statements: Vec<ProofStatement>,
    /// The aggregation program's SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
    let (value, read) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .with_context(|| format!("malformed {what}"))?;
    ensure!(read == bytes.len(), "trailing bytes after the {what}");
    Ok(value)
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
        guest_statements
            .push((vk_words(entry.statement.vkey_hash), entry.statement.public_values_digest.0));
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

/// Splits a `vkey_hash` into the eight big-endian words SP1's `verify_sp1_proof` takes.
pub fn vk_words(vkey_hash: B256) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (word, chunk) in words.iter_mut().zip(vkey_hash.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    words
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
    fn vk_words_round_trip() {
        let words = [1, 2, 3, 0x7f00_0000, 5, 6, 7, 8];
        assert_eq!(vk_words(op_sp1_proofs::vkey_hash_from_words(words)), words);
    }

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
