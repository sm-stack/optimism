//! Execution support for claim aggregate (`0x7C`) transactions.
//!
//! A claim aggregate transaction carries one SP1 proof of an aggregation program that recursively
//! verified the proof behind every claim it lists. The block executor verifies that proof through
//! a [`ClaimAggregateVerifier`] supplied by the caller, then calls the `ProofClaimRegistry`
//! predeploy from the system address to mark the listed claims verified. Any failure invalidates
//! the block.

use alloc::{string::String, sync::Arc, vec::Vec};
use alloy_primitives::{Address, B256, Bytes, address, keccak256};
use core::fmt::Debug;

/// Address of the `ProofClaimRegistry` predeploy.
pub const PROOF_CLAIM_REGISTRY_ADDRESS: Address =
    address!("0x4200000000000000000000000000000000000031");

/// Caller of the registry's `finalizeClaims`: the system address used for system calls.
pub const CLAIM_AGGREGATE_SYSTEM_CALLER: Address =
    address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// Verifies the aggregate proof carried by a claim aggregate transaction.
///
/// Each environment supplies its own implementation: native verification in the execution client,
/// the same software verifier inside the fault proof program, and deferred verification inside a
/// zkVM guest.
pub trait ClaimAggregateVerifier: Debug + Send + Sync {
    /// Checks that `proof` is a valid SP1 compressed proof of the program with verifying key digest
    /// `aggregation_vkey_hash` whose public values are exactly the 32 bytes of
    /// `claims_commitment`.
    fn verify(
        &self,
        aggregation_vkey_hash: B256,
        claims_commitment: B256,
        proof: &[u8],
    ) -> Result<(), String>;
}

/// Shared handle to a [`ClaimAggregateVerifier`], as carried by the block execution context.
pub type SharedClaimAggregateVerifier = Arc<dyn ClaimAggregateVerifier>;

/// Selector of `ProofClaimRegistry.finalizeClaims(bytes32,bytes32[])`.
pub fn finalize_claims_selector() -> [u8; 4] {
    keccak256("finalizeClaims(bytes32,bytes32[])")[..4].try_into().expect("4-byte selector")
}

/// Whether `output` is the registry's acknowledgement of `finalizeClaims`: its own selector,
/// returned as an ABI-encoded `bytes4`.
///
/// A call to an address without code also succeeds, so success alone does not show the registry
/// recorded anything.
pub fn is_finalize_claims_ack(output: &[u8]) -> bool {
    output.len() == 32 &&
        output[..4] == finalize_claims_selector() &&
        output[4..].iter().all(|b| *b == 0)
}

/// ABI-encodes `ProofClaimRegistry.finalizeClaims(bytes32 aggregationVkeyHash, bytes32[]
/// claimIds)`.
pub fn finalize_claims_calldata(aggregation_vkey_hash: B256, claim_ids: &[B256]) -> Bytes {
    let selector = finalize_claims_selector();
    let mut out = Vec::with_capacity(4 + 32 * (3 + claim_ids.len()));
    out.extend_from_slice(&selector);
    out.extend_from_slice(aggregation_vkey_hash.as_slice());
    // Offset of the dynamic `bytes32[]` from the start of the arguments: two head words.
    out.extend_from_slice(B256::left_padding_from(&[0x40]).as_slice());
    out.extend_from_slice(
        B256::left_padding_from(&(claim_ids.len() as u64).to_be_bytes()).as_slice(),
    );
    for id in claim_ids {
        out.extend_from_slice(id.as_slice());
    }
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn finalize_claims_calldata_layout() {
        let vkey = B256::repeat_byte(0xaa);
        let ids = [B256::repeat_byte(0x01), B256::repeat_byte(0x02)];
        let data = finalize_claims_calldata(vkey, &ids);
        assert_eq!(&data[..4], &keccak256("finalizeClaims(bytes32,bytes32[])")[..4]);
        assert_eq!(&data[4..36], vkey.as_slice());
        assert_eq!(
            &data[36..68],
            hex!("0000000000000000000000000000000000000000000000000000000000000040")
        );
        assert_eq!(
            &data[68..100],
            hex!("0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(&data[100..132], ids[0].as_slice());
        assert_eq!(&data[132..164], ids[1].as_slice());
        assert_eq!(data.len(), 164);
    }
}
