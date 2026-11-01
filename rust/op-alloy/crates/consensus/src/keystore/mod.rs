//! The [EIP-8130] Keystore and the OP Stack STATEMENT authenticator that Lagoon deploys: their
//! bytecode (built from `packages/eip8130`, kept identical to `op-core/eip8130`), their addresses,
//! and the Keystore storage a node reads natively to authenticate an [EIP-8430] transaction.
//!
//! [EIP-8130]: https://eips.ethereum.org/EIPS/eip-8130
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385

use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Bytes, Keccak256, U256, address, keccak256};

/// The CREATE2 deployer preinstall both contracts are deployed through, with salt 0.
pub const DETERMINISTIC_DEPLOYMENT_PROXY: Address =
    address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// `KEYSTORE_ADDRESS`: where the deterministic deployment proxy deploys the Keystore.
pub const KEYSTORE_ADDRESS: Address = address!("0x209DaD6e0B17969725C2c7847A70c58Fe442C521");

/// The STATEMENT authenticator: where the deterministic deployment proxy deploys it.
pub const STATEMENT_AUTHENTICATOR: Address = address!("0xC5EF79AD4605c55B7f65328Fdd5Cc7c485679Bc0");

const KEYSTORE_INITCODE: &str = include_str!("keystore.initcode.hex");
const KEYSTORE_RUNTIME: &str = include_str!("keystore.runtime.hex");
const STATEMENT_AUTHENTICATOR_INITCODE: &str = include_str!("statement_authenticator.initcode.hex");
const STATEMENT_AUTHENTICATOR_RUNTIME: &str = include_str!("statement_authenticator.runtime.hex");

fn decode(hex: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(hex.trim()).expect("committed bytecode is hex")
}

/// The Keystore's creation bytecode.
pub fn keystore_initcode() -> Vec<u8> {
    decode(KEYSTORE_INITCODE)
}

/// The Keystore's runtime bytecode, for a chain whose genesis activates Lagoon.
pub fn keystore_runtime() -> Vec<u8> {
    decode(KEYSTORE_RUNTIME)
}

/// The STATEMENT authenticator's creation bytecode.
pub fn statement_authenticator_initcode() -> Vec<u8> {
    decode(STATEMENT_AUTHENTICATOR_INITCODE)
}

/// The STATEMENT authenticator's runtime bytecode.
pub fn statement_authenticator_runtime() -> Vec<u8> {
    decode(STATEMENT_AUTHENTICATOR_RUNTIME)
}

/// The calldata that has the deterministic deployment proxy deploy `initcode`: salt 0, then the
/// initcode.
pub fn deployment_data(initcode: &[u8]) -> Bytes {
    let mut data = Vec::with_capacity(32 + initcode.len());
    data.extend_from_slice(&[0; 32]);
    data.extend_from_slice(initcode);
    data.into()
}

/// Scope grant: ungated initiation.
pub const SCOPE_OPERATOR: u16 = 0x01;
/// Scope grant: paying the account's own gas.
pub const SCOPE_SELF_PAYER: u16 = 0x02;
/// Scope grant: paying gas for another sender.
pub const SCOPE_SPONSOR_PAYER: u16 = 0x04;
/// Scope grant: initiation gated to the actor's policy manager.
pub const SCOPE_POLICY: u16 = 0x08;

/// Account-state flag disabling the account's implicit secp256k1 self actor.
pub const FLAG_REVOKE_DEFAULT_EOA: u8 = 0x01;

/// The Keystore's `_actors` mapping (`actorId => account => ActorRecord`) is at slot 0
/// (`packages/eip8130/storage-layout.txt`).
const ACTORS_SLOT: B256 = B256::ZERO;
/// The Keystore's `_accountState` mapping (`account => AccountState`) is at slot 1.
const ACCOUNT_STATE_SLOT: B256 = B256::with_last_byte(1);

fn mapping_slot(key: B256, slot: B256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(key.as_slice());
    preimage[32..].copy_from_slice(slot.as_slice());
    keccak256(preimage)
}

/// The storage slot of `actor_config(account, actor_id)`; the actor's policy manager is the next
/// slot.
pub fn actor_config_slot(account: Address, actor_id: B256) -> U256 {
    let inner = mapping_slot(actor_id, ACTORS_SLOT);
    mapping_slot(account.into_word(), inner).into()
}

/// The storage slot of the account's packed state.
pub fn account_state_slot(account: Address) -> U256 {
    mapping_slot(account.into_word(), ACCOUNT_STATE_SLOT).into()
}

/// The actorId of an actor identified by an address: the address right-aligned in a word.
pub fn address_actor_id(address: Address) -> B256 {
    address.into_word()
}

/// The actorId of a STATEMENT actor: `keccak256("op-stmt-auth" || vk || tag || key)`.
pub fn statement_actor_id(vk: B256, tag: [u8; 8], key: B256) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(b"op-stmt-auth");
    hasher.update(vk);
    hasher.update(tag);
    hasher.update(key);
    hasher.finalize()
}

/// An actor's configuration as `actor_config` packs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActorConfig {
    /// The authenticator; zero when the actor is not configured.
    pub authenticator: Address,
    /// Unix seconds after which the actor is invalid; 0 for none.
    pub expiry: u64,
    /// Grants; 0 is the admin, which may do everything.
    pub scope: u16,
}

/// A big-endian 6-byte field.
fn uint48(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |acc, byte| (acc << 8) | u64::from(*byte))
}

impl ActorConfig {
    /// Unpacks an `actor_config` slot: the authenticator in the low 20 bytes, then the expiry, then
    /// the scope.
    pub fn decode(word: U256) -> Self {
        let bytes = word.to_be_bytes::<32>();
        Self {
            authenticator: Address::from_slice(&bytes[12..32]),
            expiry: uint48(&bytes[6..12]),
            scope: u16::from_be_bytes([bytes[4], bytes[5]]),
        }
    }

    /// Whether the actor is live at `timestamp`.
    pub const fn is_live(&self, timestamp: u64) -> bool {
        self.expiry == 0 || timestamp <= self.expiry
    }
}

/// The part of an account's packed Keystore state that authentication reads: the implicit self
/// actor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountState {
    /// Flags; see [`FLAG_REVOKE_DEFAULT_EOA`].
    pub flags: u8,
    /// The self actor's expiry; 0 for none.
    pub default_eoa_expiry: u64,
    /// The self actor's scope; 0 for the admin.
    pub default_eoa_scope: u16,
}

impl AccountState {
    /// Unpacks the account-state slot: from the low bytes up, multichainSequence(8),
    /// localSequence(4), localEpoch(4), flags(1), lockUnion(6), defaultEOAExpiry(6),
    /// defaultEOAScope(2), reserved(1).
    pub fn decode(word: U256) -> Self {
        let bytes = word.to_be_bytes::<32>();
        Self {
            flags: bytes[15],
            default_eoa_expiry: uint48(&bytes[3..9]),
            default_eoa_scope: u16::from_be_bytes([bytes[1], bytes[2]]),
        }
    }

    /// The implicit self actor's configuration, or `None` when it is revoked.
    pub const fn self_actor(&self) -> Option<ActorConfig> {
        if self.flags & FLAG_REVOKE_DEFAULT_EOA != 0 {
            return None;
        }
        Some(ActorConfig {
            authenticator: crate::K1_AUTHENTICATOR,
            expiry: self.default_eoa_expiry,
            scope: self.default_eoa_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The addresses follow from the committed initcode (op-core: `TestAddresses`).
    #[test]
    fn addresses() {
        let create2 = |initcode: &[u8]| {
            DETERMINISTIC_DEPLOYMENT_PROXY.create2(B256::ZERO, keccak256(initcode))
        };
        assert_eq!(create2(&keystore_initcode()), KEYSTORE_ADDRESS);
        assert_eq!(create2(&statement_authenticator_initcode()), STATEMENT_AUTHENTICATOR);
        assert!(!keystore_runtime().is_empty());
        assert!(!statement_authenticator_runtime().is_empty());
    }

    /// The bytecode is the same as op-core's.
    #[test]
    fn matches_op_core() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../op-core/eip8130");
        for (name, ours) in [
            ("keystore.initcode.hex", KEYSTORE_INITCODE),
            ("keystore.runtime.hex", KEYSTORE_RUNTIME),
            ("statement_authenticator.initcode.hex", STATEMENT_AUTHENTICATOR_INITCODE),
            ("statement_authenticator.runtime.hex", STATEMENT_AUTHENTICATOR_RUNTIME),
        ] {
            let theirs = std::fs::read_to_string(alloc::format!("{dir}/{name}")).unwrap();
            assert_eq!(theirs.trim(), ours.trim(), "{name}");
        }
    }

    /// The Keystore slots of a STATEMENT actor, as `cast index` computes them (op-core:
    /// `TestSlots`).
    #[test]
    fn slots() {
        use alloy_primitives::b256;
        let account = Address::repeat_byte(0x11);
        let id = statement_actor_id(
            B256::with_last_byte(0x22),
            *b"sphmem01",
            B256::with_last_byte(0x33),
        );
        assert_eq!(id, b256!("0x7811d9b527880533ecaeaff2a300b408a411b7fa4f4688770d087925c4864773"));
        assert_eq!(
            B256::from(actor_config_slot(account, id)),
            b256!("0xf2e218404c42f94d94bb72c5b35d468c08c50fe9d45b9ec2804794dcfb7137d1")
        );
        assert_eq!(
            B256::from(account_state_slot(account)),
            b256!("0x8eec1c9afb183a84aac7003cf8e730bfb6385f6e43761d6425fba4265de3a9eb")
        );
    }

    #[test]
    fn unpacks_actor_config_and_account_state() {
        // reserved, scope 0x0004, expiry 0x010203040506, authenticator 0x..01 (op-core:
        // `TestDecodeActorConfig`).
        let word = U256::from_be_bytes(alloy_primitives::hex!(
            "00000000" "0004" "010203040506" "0000000000000000000000000000000000000001"
        ));
        assert_eq!(
            ActorConfig::decode(word),
            ActorConfig {
                authenticator: crate::K1_AUTHENTICATOR,
                expiry: 0x010203040506,
                scope: 4
            }
        );
        // reserved, defaultEOAScope 0x0002, defaultEOAExpiry 0x0a0b0c0d0e0f, lockUnion,
        // flags 0x00, localEpoch, localSequence, multichainSequence: every neighbour non-zero.
        let mut state = alloy_primitives::hex!(
            "00" "0002" "0a0b0c0d0e0f" "ffffffffffff" "00" "ffffffff" "ffffffff" "ffffffffffffffff"
        );
        let decoded = AccountState::decode(U256::from_be_bytes(state));
        assert_eq!(
            decoded,
            AccountState { flags: 0, default_eoa_expiry: 0x0a0b0c0d0e0f, default_eoa_scope: 2 }
        );
        assert_eq!(
            decoded.self_actor(),
            Some(ActorConfig {
                authenticator: crate::K1_AUTHENTICATOR,
                expiry: 0x0a0b0c0d0e0f,
                scope: 2
            })
        );
        state[15] = FLAG_REVOKE_DEFAULT_EOA;
        assert_eq!(AccountState::decode(U256::from_be_bytes(state)).self_actor(), None);
    }
}
