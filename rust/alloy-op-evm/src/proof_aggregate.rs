//! Execution support for proof aggregate (`0x7C`) transactions.
//!
//! A proof aggregate transaction carries one SP1 proof of an aggregation program that recursively
//! verified the proof behind every statement it lists. The block executor verifies that proof
//! through a [`ProofAggregateVerifier`] supplied by the caller, then calls the `ProofRegistry`
//! predeploy from the system address to mark the listed statements verified. Any failure
//! invalidates the block.

use alloc::{string::String, sync::Arc, vec::Vec};
use alloy_primitives::{Address, B256, Bytes, address, keccak256};
use core::fmt::Debug;

/// Address of the `ProofRegistry` predeploy.
pub const PROOF_REGISTRY_ADDRESS: Address = address!("0x4200000000000000000000000000000000000031");

/// Caller of the registry's `verifyStatements`: the system address used for system calls.
pub const PROOF_AGGREGATE_SYSTEM_CALLER: Address =
    address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// Verifies the aggregate proof carried by a proof aggregate transaction.
///
/// Each environment supplies its own implementation: native verification in the execution client,
/// the same software verifier inside the fault proof program, and deferred verification inside a
/// zkVM guest.
pub trait ProofAggregateVerifier: Debug + Send + Sync {
    /// Checks that `proof` is a valid SP1 compressed proof of the program with verifying key digest
    /// `aggregation_vkey_hash` whose public values are exactly the 32 bytes of
    /// `statements_commitment`.
    fn verify(
        &self,
        aggregation_vkey_hash: B256,
        statements_commitment: B256,
        proof: &[u8],
    ) -> Result<(), String>;
}

/// Shared handle to a [`ProofAggregateVerifier`], as carried by the block execution context.
pub type SharedProofAggregateVerifier = Arc<dyn ProofAggregateVerifier>;

/// Selector of `ProofRegistry.verifyStatements(bytes32,bytes32[])`.
pub fn verify_statements_selector() -> [u8; 4] {
    keccak256("verifyStatements(bytes32,bytes32[])")[..4].try_into().expect("4-byte selector")
}

/// Whether `output` is the registry's acknowledgement of `verifyStatements`: its own selector,
/// returned as an ABI-encoded `bytes4`.
///
/// A call to an address without code also succeeds, so success alone does not show the registry
/// recorded anything.
pub fn is_verify_statements_ack(output: &[u8]) -> bool {
    output.len() == 32 &&
        output[..4] == verify_statements_selector() &&
        output[4..].iter().all(|b| *b == 0)
}

/// ABI-encodes `ProofRegistry.verifyStatements(bytes32 aggregationVkeyHash, bytes32[]
/// statementIds)`.
pub fn verify_statements_calldata(aggregation_vkey_hash: B256, statement_ids: &[B256]) -> Bytes {
    let selector = verify_statements_selector();
    let mut out = Vec::with_capacity(4 + 32 * (3 + statement_ids.len()));
    out.extend_from_slice(&selector);
    out.extend_from_slice(aggregation_vkey_hash.as_slice());
    // Offset of the dynamic `bytes32[]` from the start of the arguments: two head words.
    out.extend_from_slice(B256::left_padding_from(&[0x40]).as_slice());
    out.extend_from_slice(
        B256::left_padding_from(&(statement_ids.len() as u64).to_be_bytes()).as_slice(),
    );
    for id in statement_ids {
        out.extend_from_slice(id.as_slice());
    }
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn verify_statements_calldata_layout() {
        let vkey = B256::repeat_byte(0xaa);
        let ids = [B256::repeat_byte(0x01), B256::repeat_byte(0x02)];
        let data = verify_statements_calldata(vkey, &ids);
        assert_eq!(&data[..4], &keccak256("verifyStatements(bytes32,bytes32[])")[..4]);
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
