//! Verification of the proof in a proof aggregate transaction with the SP1 compressed verifier.
//!
//! [`Sp1ProofAggregateVerifier`] is the [`ProofAggregateVerifier`] the execution client and the
//! fault proof program both use: it checks the SP1 compressed (STARK) proof itself, in software.
//! Inside the fault proof VM this runs the same code as natively, which is what lets a dispute
//! bisect down to the verifier's instructions.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_op_evm::ProofAggregateVerifier;
use alloy_primitives::B256;
use core::fmt;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_hypercube::{HashableKey, SP1VerifyingKey};
use sp1_primitives::SP1Field;
use sp1_verifier::{SP1Proof, compressed::SP1CompressedVerifier};
use std::sync::OnceLock;

/// Converts a verifying key digest in the statement `vkey_hash` encoding, eight big-endian 32-bit
/// words, into the `KoalaBear` digest the SP1 verifier compares against.
///
/// Returns `None` if a word is not a canonical `KoalaBear` element.
pub fn vkey_hash_to_koalabear(vkey_hash: B256) -> Option<[SP1Field; 8]> {
    let mut out = [SP1Field::zero(); 8];
    for (i, chunk) in vkey_hash.chunks_exact(4).enumerate() {
        let word = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
        if word >= SP1Field::ORDER_U32 {
            return None;
        }
        out[i] = SP1Field::from_canonical_u32(word);
    }
    Some(out)
}

/// Splits a verifying key digest in the `vkey_hash` encoding into the eight words SP1's
/// `verify_sp1_proof` takes (`HashableKey::hash_u32`). The inverse of [`vkey_hash_from_words`].
pub fn vkey_hash_to_words(vkey_hash: B256) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (word, chunk) in words.iter_mut().zip(vkey_hash.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    words
}

/// Encodes a verifying key digest given as eight words (SP1's `HashableKey::hash_u32`) in the
/// `vkey_hash` encoding: each word big-endian, concatenated.
pub fn vkey_hash_from_words(words: [u32; 8]) -> B256 {
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    B256::from(out)
}

/// Decodes `vk`, a bincode-encoded `SP1VerifyingKey`, and checks that it hashes to `vkey_hash`.
///
/// Recursively verifying a proof inside the aggregation program takes the proven program's full
/// verifying key, not just its digest, so statement submitters provide it.
pub fn decode_verifying_key(vk: &[u8], vkey_hash: B256) -> Result<SP1VerifyingKey, String> {
    let (decoded, read): (SP1VerifyingKey, usize) =
        bincode::serde::decode_from_slice(vk, bincode::config::legacy())
            .map_err(|err| format!("malformed verifying key: {err}"))?;
    if read != vk.len() {
        return Err(String::from("trailing bytes after the verifying key"));
    }
    if vkey_hash_from_words(decoded.hash_u32()) != vkey_hash {
        return Err(String::from("verifying key does not hash to the statement's vkey hash"));
    }
    Ok(decoded)
}

/// Verifies proof aggregate proofs as SP1 compressed proofs.
pub struct Sp1ProofAggregateVerifier {
    /// Built on first use: constructing it hashes the recursion verifying key tree, a cost the
    /// fault proof program must not pay for blocks without a proof aggregate.
    verifier: OnceLock<SP1CompressedVerifier>,
}

impl fmt::Debug for Sp1ProofAggregateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sp1ProofAggregateVerifier").finish_non_exhaustive()
    }
}

impl Default for Sp1ProofAggregateVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Sp1ProofAggregateVerifier {
    /// Creates a verifier. The SP1 verifier itself is built on the first verification; share one
    /// instance so that happens once.
    pub const fn new() -> Self {
        Self { verifier: OnceLock::new() }
    }
}

impl Sp1ProofAggregateVerifier {
    /// Verifies `proof`, a bincode-encoded `SP1Proof::Compressed`, for the program with verifying
    /// key digest `vkey_hash` and the given committed public values.
    pub fn verify_with_public_values(
        &self,
        vkey_hash: B256,
        public_values: &[u8],
        proof: &[u8],
    ) -> Result<(), String> {
        let vkey = vkey_hash_to_koalabear(vkey_hash)
            .ok_or_else(|| String::from("aggregation vkey hash is not a KoalaBear digest"))?;
        let (decoded, read): (SP1Proof, usize) =
            bincode::serde::decode_from_slice(proof, bincode::config::legacy())
                .map_err(|err| format!("malformed proof: {err}"))?;
        if read != proof.len() {
            return Err(String::from("trailing bytes after the proof"));
        }
        let SP1Proof::Compressed(proof) = decoded else {
            return Err(String::from("aggregate proof is not an SP1 compressed proof"));
        };
        self.verifier
            .get_or_init(SP1CompressedVerifier::new)
            .verify_compressed_with_public_values(&proof, public_values, &vkey)
            .map_err(|err| err.to_string())
    }
}

impl ProofAggregateVerifier for Sp1ProofAggregateVerifier {
    fn verify(
        &self,
        aggregation_vkey_hash: B256,
        statements_commitment: B256,
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_with_public_values(
            aggregation_vkey_hash,
            statements_commitment.as_slice(),
            proof,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vkey_hash_words_roundtrip() {
        let words = [1, 2, 3, 4, 5, 6, 7, SP1Field::ORDER_U32 - 1];
        let hash = vkey_hash_from_words(words);
        let field = vkey_hash_to_koalabear(hash).unwrap();
        assert_eq!(field.map(|f| f.as_canonical_u32()), words);
        assert_eq!(vkey_hash_to_words(hash), words);
    }

    #[test]
    fn rejects_non_canonical_vkey_word() {
        let hash = vkey_hash_from_words([0, 0, 0, 0, 0, 0, 0, SP1Field::ORDER_U32]);
        assert!(vkey_hash_to_koalabear(hash).is_none());
    }

    #[test]
    fn rejects_malformed_proof() {
        let verifier = Sp1ProofAggregateVerifier::new();
        let err = verifier.verify(B256::ZERO, B256::ZERO, &[1, 2, 3]).unwrap_err();
        assert!(err.contains("malformed proof"), "{err}");
    }

    /// Verifies a real SP1 compressed proof. Set `OP_SP1_PROOFS_FIXTURE_DIR` to a directory with
    /// `proof.bin` (bincode `SP1Proof`), `public_values.bin`, `vkey_hash.bin` (bincode
    /// `[SP1Field; 8]`) and, optionally, `verifying_key.bin` (bincode `SP1VerifyingKey`).
    #[test]
    #[ignore = "needs an SP1 compressed proof fixture"]
    fn verifies_fixture_proof() {
        let dir = std::path::PathBuf::from(
            std::env::var("OP_SP1_PROOFS_FIXTURE_DIR").expect("OP_SP1_PROOFS_FIXTURE_DIR"),
        );
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let (vkey, _): ([SP1Field; 8], usize) =
            bincode::serde::decode_from_slice(&read("vkey_hash.bin"), bincode::config::legacy())
                .unwrap();
        let vkey_hash = vkey_hash_from_words(vkey.map(|f| f.as_canonical_u32()));
        let proof = read("proof.bin");
        let public_values = read("public_values.bin");

        let verifier = Sp1ProofAggregateVerifier::new();
        verifier.verify_with_public_values(vkey_hash, &public_values, &proof).unwrap();

        let mut tampered = public_values.clone();
        tampered[0] ^= 1;
        assert!(verifier.verify_with_public_values(vkey_hash, &tampered, &proof).is_err());
        let mut wrong_vkey = vkey_hash;
        wrong_vkey.0[31] ^= 1;
        assert!(verifier.verify_with_public_values(wrong_vkey, &public_values, &proof).is_err());

        // The program's full verifying key, if the fixture has it, must hash to its vkey hash.
        if let Ok(vk) = std::fs::read(dir.join("verifying_key.bin")) {
            decode_verifying_key(&vk, vkey_hash).unwrap();
            assert!(decode_verifying_key(&vk, wrong_vkey).is_err());
        }
    }
}
