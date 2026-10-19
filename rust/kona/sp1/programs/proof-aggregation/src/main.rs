//! SP1 guest that aggregates `ProofRegistry` statements for a proof aggregate (`0x7C`)
//! transaction.
//!
//! Each statement says that the SP1 program with verifying key digest `vkey` produced a valid
//! proof of public values with SHA-256 digest `public_values_digest`. The guest verifies every
//! statement's proof through SP1's deferred proof verification, so the proofs themselves are
//! checked by the recursion prover and never appear in this program's input. It commits the
//! statements commitment, `keccak256(vkey_hash_0 || public_values_digest_0 || ...)`, as its only
//! public values: exactly the 32 bytes the execution client checks the aggregate proof against.

#![cfg_attr(target_os = "zkvm", no_main)]
#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{B256, keccak256};

/// One statement: the program's verifying key digest as eight words (SP1's `hash_u32`), and the
/// SHA-256 digest of its public values. The host writes a `Vec<Statement>` to stdin, followed by
/// the statements' proofs in the same order.
type Statement = ([u32; 8], [u8; 32]);

/// Entrypoint to the proof aggregation program.
pub fn main() {
    println!("{}", kona_sp1_build_info::BUILD_MARKER);

    let statements = sp1_zkvm::io::read::<Vec<Statement>>();
    let commitment = aggregate(&statements, sp1_lib::verify::verify_sp1_proof);

    sp1_zkvm::io::commit_slice(commitment.as_slice());
}

/// Verifies every statement's proof with `verify_proof`, in input order, and returns the
/// statements commitment.
///
/// # Panics
///
/// Panics if `statements` is empty: the execution client rejects an aggregate without
/// statements, so proving one would only waste the proof.
fn aggregate(statements: &[Statement], mut verify_proof: impl FnMut(&[u32; 8], &[u8; 32])) -> B256 {
    assert!(!statements.is_empty(), "proof aggregate must cover at least one statement");

    let mut preimage = Vec::with_capacity(statements.len() * 64);
    for (vkey, public_values_digest) in statements {
        verify_proof(vkey, public_values_digest);
        preimage.extend_from_slice(&vkey_hash(vkey));
        preimage.extend_from_slice(public_values_digest);
    }
    keccak256(preimage)
}

/// Encodes a verifying key digest the way `ProofStatement::vkey_hash` and the `ProofRegistry`
/// store it: each word big-endian, concatenated.
fn vkey_hash(vkey: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(vkey) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use alloy_primitives::b256;

    use super::*;

    /// The statement in op-alloy's `proof_aggregate_tx_golden_vector`: vkey hash `0x11..11`
    /// (eight words `0x11111111`), public values digest `0x22..22`.
    const GOLDEN: Statement = ([0x1111_1111; 8], [0x22; 32]);

    #[test]
    fn verifies_in_order_and_commits_statements() {
        let other: Statement = ([1, 2, 3, 4, 5, 6, 7, 8], [0x33; 32]);
        let mut calls = Vec::new();

        let commitment = aggregate(&[GOLDEN, other], |vkey, digest| calls.push((*vkey, *digest)));

        assert_eq!(calls, vec![GOLDEN, other]);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&[0x11; 32]);
        preimage.extend_from_slice(&[0x22; 32]);
        preimage.extend_from_slice(&[
            0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0,
            0, 0, 8,
        ]);
        preimage.extend_from_slice(&[0x33; 32]);
        assert_eq!(commitment, keccak256(preimage));
    }

    /// Pins the single-statement commitment so op-alloy's `statements_commitment` and this guest
    /// cannot drift: `keccak256(0x11..11 || 0x22..22)`.
    #[test]
    fn single_statement_commitment_vector() {
        assert_eq!(
            aggregate(&[GOLDEN], |_, _| {}),
            b256!("0x3e92e0db88d6afea9edc4eedf62fffa4d92bcdfc310dccbe943747fe8302e871")
        );
    }

    #[test]
    #[should_panic(expected = "at least one statement")]
    fn rejects_empty_input() {
        aggregate(&[], |_, _| {});
    }
}
