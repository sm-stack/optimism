//! [EIP-8430] account abstraction transactions (type `0x79`) with [EIP-8288] dependencies.
//!
//! The transaction runs its phases of calls from the sender, with fees paid by the resolved
//! payer. This chain's profile accepts secp256k1 and STATEMENT authentication only, the account
//! nonce only (`nonce_key == 0`), and the `account_changes` entries `0x01` (delegation) and `0x04`
//! (dependencies). A dependency, declared or a STATEMENT authorization's, is taken as proven during
//! execution; derivation replaces the block with its deposits unless the aggregate responsible for
//! it proves all its dependencies.
//!
//! Where this implementation departs from the EIP text:
//! - OP fees: the payer also pays the L1 data fee and the operator fee, precharged with the gas fee
//!   and settled like it. The base fee goes to the base fee vault instead of being burned.
//! - Dependencies: each pays for its share of the aggregate that goes to L1 through the L1 data
//!   fee, as [`DEPENDENCY_DA_SIZE`](op_alloy_consensus::DEPENDENCY_DA_SIZE) bytes on top of the
//!   transaction's own, in place of EIP-8288's `recursive_stark_gas`. Its L2 gas is verification
//!   alone. `GasPriceOracle.getL1Fee` sees a transaction's bytes only and leaves this share out.
//! - The Transaction Context precompile also reports the sender and the dependencies.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

pub mod context;
pub mod exec;
pub mod keystore;

#[cfg(test)]
mod tests;

use op_alloy_consensus::{Dependency, TxEip8430};
use revm::{
    precompile::crypto,
    primitives::{Address, B256, U256, uint},
};
use std::vec::Vec;

/// An [EIP-8430] transaction as the EVM sees it: the transaction and its dependencies.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AaTxEnv {
    /// The transaction.
    pub tx: TxEip8430,
    /// The dependencies, sorted and deduplicated, the self-reference substituted.
    pub dependencies: Vec<Dependency>,
    /// Whether this is a simulation; see [`Self::simulation`]. Only that constructor sets it, and
    /// it never travels with a serialized transaction.
    #[cfg_attr(feature = "serde", serde(skip))]
    simulated: bool,
}

impl AaTxEnv {
    /// Wraps `tx`, computing its dependencies.
    pub fn new(tx: TxEip8430) -> Self {
        let dependencies = tx.dependencies();
        Self { tx, dependencies, simulated: false }
    }

    /// Wraps `tx` for a simulation (`eth_call`, `eth_estimateGas`), never a block's transaction:
    /// no signature is verified, a secp256k1 authorization standing for the account's admin (a
    /// named payer pays, an open one is taken to be the sender), while a STATEMENT one is checked
    /// against the Keystore as in a block; a phase that reverts ends the execution as a revert with
    /// the failing call's output (so gas estimation cannot settle on a transaction whose later
    /// phase fails, though such a transaction is valid on chain), and success returns the last
    /// call's output. The transaction's fee caps only shape it: the prices paid are the
    /// environment's gas price and priority fee.
    pub fn simulation(tx: TxEip8430) -> Self {
        Self { simulated: true, ..Self::new(tx) }
    }

    /// Whether this is a simulation; see [`Self::simulation`].
    pub const fn is_simulation(&self) -> bool {
        self.simulated
    }
}

/// What an executed [EIP-8430] transaction's receipt needs beyond the execution result.
///
/// The EVM returns it as the output of the transaction's execution result, where receipt builders
/// read it back with [`AaTxOutcome::decode`].
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AaTxOutcome {
    /// The account that paid for the transaction.
    pub payer: Address,
    /// The number of phases that committed.
    pub committed_phases: u64,
    /// Whether every phase committed.
    pub success: bool,
}

impl AaTxOutcome {
    const LEN: usize = 20 + 8 + 1;

    /// Encodes the outcome: `payer || committed_phases || success`, the count big-endian.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0; Self::LEN];
        out[..20].copy_from_slice(self.payer.as_slice());
        out[20..28].copy_from_slice(&self.committed_phases.to_be_bytes());
        out[28] = self.success as u8;
        out
    }

    /// Decodes an outcome written by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = bytes.try_into().ok()?;
        Some(Self {
            payer: Address::from_slice(&bytes[..20]),
            committed_phases: u64::from_be_bytes(bytes[20..28].try_into().expect("8 bytes")),
            success: match bytes[28] {
                0 => false,
                1 => true,
                _ => return None,
            },
        })
    }
}

/// Order of the secp256k1 group.
const SECP256K1N: U256 =
    uint!(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256);

/// The signer of `digest` from an [EIP-8430] secp256k1 signature `r || s || v`, `v` 27 or 28 and
/// `s` in the lower half of the group order, through the installed crypto provider.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
pub fn recover_k1(signature: &[u8], digest: B256) -> Option<Address> {
    let signature: &[u8; 65] = signature.try_into().ok()?;
    let v = signature[64].checked_sub(27).filter(|v| *v <= 1)?;
    let r = U256::from_be_slice(&signature[..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    if r.is_zero() || r >= SECP256K1N || s.is_zero() || s > SECP256K1N >> 1 {
        return None;
    }
    let rs: &[u8; 64] = signature[..64].try_into().expect("64 bytes");
    let recovered = crypto().secp256k1_ecrecover(rs, v, &digest.0).ok()?;
    Some(Address::from_slice(&recovered[12..]))
}
