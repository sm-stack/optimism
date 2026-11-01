//! The [EIP-8288] dependencies a transaction declares, whatever its type: what the sequencer admits
//! it against, what an aggregate must prove, and what derivation checks.
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use alloc::vec::Vec;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::B256;

/// [EIP-8288] dependency scheme of a proof statement: `data_hash` is a member a leanVM leaf
/// published and `verification_key_hash` the digest of the verifying key of the guest that ran,
/// normalized to its leaf class ([`crate::ProofStatement`]). This OP Stack scheme takes the place
/// of `LEANSTARK_SCHEME` (`0x11`), whose `get_deps_hash` is undefined; the leanSPHINCS scheme
/// (`0x10`) is not supported: a signature is the statement of the signature-member guest.
///
/// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
pub const PROOF_STATEMENT_SCHEME: u8 = 0x20;

/// One [EIP-8288] dependency: `(scheme, data_hash, verification_key_hash)`.
///
/// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Dependency {
    /// The verification scheme.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub scheme: u8,
    /// What was proven; the zero hash in a transaction stands for its signature hash.
    pub data_hash: B256,
    /// The verifying key digest.
    pub verification_key_hash: B256,
}

impl Dependency {
    /// The statement this dependency asks to be proven, or `None` for another scheme.
    pub const fn statement(&self) -> Option<crate::ProofStatement> {
        if self.scheme != PROOF_STATEMENT_SCHEME {
            return None;
        }
        Some(crate::ProofStatement {
            vkey_hash: self.verification_key_hash,
            public_values_digest: self.data_hash,
        })
    }
}

/// The dependencies one transaction declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDependencies {
    /// The key the sequencer admits the transaction under: its signature hash, which its unsigned
    /// witnesses do not change, unlike its transaction hash.
    pub key: B256,
    /// The dependencies declared, duplicates included: what the transaction pays for.
    pub declared: usize,
    /// The dependencies, the zero `data_hash` replaced by the signature hash, sorted and
    /// deduplicated.
    pub dependencies: Vec<Dependency>,
}

impl DeclaredDependencies {
    /// The ids of the statements the dependencies ask to be proven ([`crate::ProofStatement::id`]),
    /// in dependency order; dependencies of another scheme have none.
    pub fn statement_ids(&self) -> Vec<B256> {
        self.dependencies.iter().filter_map(Dependency::statement).map(|s| s.id()).collect()
    }
}

/// The dependencies the EIP-2718 transaction `encoded` declares, or `None` if it declares none: a
/// type that cannot, one that does not, or bytes that do not decode as such a type.
pub fn declared_dependencies(encoded: &[u8]) -> Option<DeclaredDependencies> {
    match *encoded.first()? {
        crate::AA_TX_TYPE_ID => {
            crate::TxEip8430::decode_2718(&mut &encoded[..]).ok()?.declared_dependencies()
        }
        _ => None,
    }
}
