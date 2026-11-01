//! [EIP-8430] account abstraction transactions (type `0x79`), as this chain profiles them:
//! secp256k1 and STATEMENT authentication only, the account nonce only (`nonce_key == 0`), and the
//! [EIP-8288] dependencies of an `account_changes` entry of type `0x04` and of STATEMENT
//! authorizations.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use crate::{
    dependency::{DeclaredDependencies, Dependency, PROOF_STATEMENT_SCHEME},
    keystore::{self, STATEMENT_AUTHENTICATOR},
};
use alloc::vec::Vec;
use alloy_consensus::{Sealable, Transaction, Typed2718};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718, IsTyped2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{
    Address, B256, Bytes, ChainId, TxHash, TxKind, U256, address, b256, keccak256,
};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// The [EIP-2718] type of an [EIP-8430] transaction.
///
/// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
pub const AA_TX_TYPE_ID: u8 = 0x79;

/// The domain byte of the payer signature hash.
pub const AA_PAYER_TYPE: u8 = 0x7A;

/// The selector of native secp256k1 authentication in a named identity's auth blob.
pub const K1_AUTHENTICATOR: Address = address!("0x0000000000000000000000000000000000000001");

/// The Transaction Context precompile: the current transaction's payer, sender and dependencies.
pub const TX_CONTEXT_ADDRESS: Address = address!("0x813000000000000000000000000000000000aa02");

/// Base intrinsic gas of an [EIP-8430] transaction.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
pub const AA_BASE_COST: u64 = 15_000;

/// Intrinsic gas of one secp256k1 authentication: ecrecover and one cold account-state read.
pub const K1_AUTH_COST: u64 = 5_100;

/// The length of a secp256k1 authorization of a named identity: `K1_AUTHENTICATOR || r || s || v`.
pub const K1_NAMED_AUTH_LEN: usize = 85;

/// The length of a STATEMENT authorization:
/// `STATEMENT_AUTHENTICATOR || vk_hash(32) || tag(8) || key(32)`.
pub const STATEMENT_AUTH_LEN: usize = 92;

/// Intrinsic gas per value-bearing call to another account.
pub const TX_VALUE_COST: u64 = 6_000;

/// Intrinsic gas of a delegation entry: the 23-byte delegation indicator.
pub const DELEGATION_COST: u64 = 4_600;

/// Intrinsic gas of a dependency on the signature program: [EIP-8288]'s
/// `LEANSPHINCS_VERIFICATION_GAS`.
///
/// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
pub const LEANSPHINCS_VERIFICATION_GAS: u64 = 3_000;

/// Intrinsic gas of a dependency on any other program: [EIP-8288]'s
/// `LEANSTARK_VERIFICATION_GAS`. Its `recursive_stark_gas` pays for the proof in the block; here
/// the proof goes to L1, and [`DEPENDENCY_DA_SIZE`] pays for it in the L1 data fee instead.
///
/// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
pub const LEANSTARK_VERIFICATION_GAS: u64 = 30_000;

/// The verifying key digest of the leanSPHINCS signature-member guest normalized to the signature
/// class, pinned against the guest by op-leanvm-tree.
pub const SIGNATURE_PROGRAM_DIGEST: B256 =
    b256!("0x98889a8a7ad3074d3d51f926488ca52c42d0da668cbdb7620eb3efe700a51a9e");

/// The bytes each dependency pays for in the L1 data fee, on top of the transaction's own: its
/// share of the proof aggregate the batcher posts. An aggregate is about 315 KB however few
/// statements it holds, plus about 34 bytes a statement, and how many it will hold is unknown when
/// a transaction executes, so this is an estimate: at this size the aggregate pays for itself from
/// about 156 statements, over-recovers above that and under-recovers on a quiet chain.
pub const DEPENDENCY_DA_SIZE: u64 = 2_048;

/// Most dependencies one dependency entry declares.
pub const MAX_DEPENDENCIES_PER_ENTRY: usize = 256;

/// Most gas the payer's authentication may reserve on top of `gas_limit`.
pub const MAX_AUTHENTICATION_GAS: u64 = 100_000;

/// Values of `valid_after`/`valid_before` at or above this are milliseconds, below it seconds.
pub const TIMESTAMP_MS_THRESHOLD: u64 = 100_000_000_000;

/// The [EIP-7623] floor gas per calldata token.
///
/// [EIP-7623]: https://eips.ethereum.org/EIPS/eip-7623
const FLOOR_PER_TOKEN: u64 = 10;

/// The type of a delegation entry.
pub const DELEGATION_CHANGE: u8 = 0x01;

/// The type of a dependency entry.
pub const DEPENDENCIES_CHANGE: u8 = 0x04;

/// One call of a phase: `rlp([to, value, data])`, dispatched from the sender.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AaCall {
    /// The callee.
    pub to: Address,
    /// Wei moved from the sender to `to`.
    pub value: U256,
    /// Calldata.
    pub data: Bytes,
}

/// An `account_changes` entry: `rlp([type, ...])`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        into = "serde_account_change::AccountChangeJson",
        try_from = "serde_account_change::AccountChangeJson"
    )
)]
pub enum AccountChange {
    /// `rlp([0x01, target])`: delegate the sender's code to `target`, or clear it for the zero
    /// address.
    Delegation {
        /// The delegate.
        target: Address,
    },
    /// `rlp([0x04, [[scheme, data_hash, verification_key_hash], ...]])`: the transaction's
    /// [EIP-8288] dependencies.
    ///
    /// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
    Dependencies {
        /// The dependencies as declared; a zero `data_hash` stands for the sender hash.
        dependencies: Vec<Dependency>,
    },
}

/// `rlp([scheme, data_hash, verification_key_hash])`.
fn dependency_payload_length(dependency: &Dependency) -> usize {
    dependency.scheme.length() +
        dependency.data_hash.length() +
        dependency.verification_key_hash.length()
}

fn encode_dependency(dependency: &Dependency, out: &mut dyn BufMut) {
    Header { list: true, payload_length: dependency_payload_length(dependency) }.encode(out);
    dependency.scheme.encode(out);
    dependency.data_hash.encode(out);
    dependency.verification_key_hash.encode(out);
}

fn dependency_length(dependency: &Dependency) -> usize {
    let payload_length = dependency_payload_length(dependency);
    Header { list: true, payload_length }.length_with_payload()
}

fn decode_dependency(buf: &mut &[u8]) -> alloy_rlp::Result<Dependency> {
    let mut body = list_body(buf)?;
    let dependency = Dependency {
        scheme: u8::decode(&mut body)?,
        data_hash: B256::decode(&mut body)?,
        verification_key_hash: B256::decode(&mut body)?,
    };
    ensure_consumed(body)?;
    Ok(dependency)
}

impl AccountChange {
    const fn ty(&self) -> u8 {
        match self {
            Self::Delegation { .. } => DELEGATION_CHANGE,
            Self::Dependencies { .. } => DEPENDENCIES_CHANGE,
        }
    }

    fn payload_length(&self) -> usize {
        self.ty().length() +
            match self {
                Self::Delegation { target } => target.length(),
                Self::Dependencies { dependencies } => {
                    let payload_length = dependencies.iter().map(dependency_length).sum::<usize>();
                    Header { list: true, payload_length }.length_with_payload()
                }
            }
    }
}

impl Encodable for AccountChange {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.payload_length() }.encode(out);
        self.ty().encode(out);
        match self {
            Self::Delegation { target } => target.encode(out),
            Self::Dependencies { dependencies } => {
                let payload_length = dependencies.iter().map(dependency_length).sum::<usize>();
                Header { list: true, payload_length }.encode(out);
                for dependency in dependencies {
                    encode_dependency(dependency, out);
                }
            }
        }
    }

    fn length(&self) -> usize {
        Header { list: true, payload_length: self.payload_length() }.length_with_payload()
    }
}

impl Decodable for AccountChange {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut body = list_body(buf)?;
        let change = match u8::decode(&mut body)? {
            DELEGATION_CHANGE => Self::Delegation { target: Address::decode(&mut body)? },
            DEPENDENCIES_CHANGE => {
                let mut list = list_body(&mut body)?;
                let mut dependencies = Vec::new();
                while !list.is_empty() {
                    dependencies.push(decode_dependency(&mut list)?);
                }
                Self::Dependencies { dependencies }
            }
            _ => return Err(alloy_rlp::Error::Custom("unknown account change type")),
        };
        ensure_consumed(body)?;
        Ok(change)
    }
}

/// Who pays for the transaction, as the `payer` field encodes it.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "Bytes", try_from = "Bytes"))]
pub enum Payer {
    /// Empty: the sender pays.
    #[default]
    SelfPay,
    /// `0x00`: any key willing to pay, recovered from `payer_auth`.
    Open,
    /// A named payer, authenticated by `payer_auth`.
    Named(Address),
}

impl Payer {
    fn wire(&self) -> &[u8] {
        match self {
            Self::SelfPay => &[],
            Self::Open => &[0],
            Self::Named(address) => address.as_slice(),
        }
    }
}

impl Encodable for Payer {
    fn encode(&self, out: &mut dyn BufMut) {
        self.wire().encode(out);
    }

    fn length(&self) -> usize {
        self.wire().length()
    }
}

impl Decodable for Payer {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = Header::decode_bytes(buf, false)?;
        match bytes {
            [] => Ok(Self::SelfPay),
            [0] => Ok(Self::Open),
            bytes if bytes.len() == 20 => Ok(Self::Named(Address::from_slice(bytes))),
            _ => Err(alloy_rlp::Error::Custom("payer is neither empty, 0x00 nor an address")),
        }
    }
}

impl From<Payer> for Bytes {
    fn from(payer: Payer) -> Self {
        Self::copy_from_slice(payer.wire())
    }
}

impl TryFrom<Bytes> for Payer {
    type Error = &'static str;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        match bytes.as_ref() {
            [] => Ok(Self::SelfPay),
            [0] => Ok(Self::Open),
            bytes if bytes.len() == 20 => Ok(Self::Named(Address::from_slice(bytes))),
            _ => Err("payer is neither empty, 0x00 nor an address"),
        }
    }
}

/// The RPC form of an account change: `{"type": "0x1", "target": ...}` or
/// `{"type": "0x4", "dependencies": [...]}`.
#[cfg(feature = "serde")]
mod serde_account_change {
    use super::{AccountChange, DELEGATION_CHANGE, DEPENDENCIES_CHANGE};
    use crate::dependency::Dependency;
    use alloc::vec::Vec;
    use alloy_primitives::Address;

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(super) struct AccountChangeJson {
        #[serde(rename = "type", with = "alloy_serde::quantity")]
        ty: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<Address>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dependencies: Option<Vec<Dependency>>,
    }

    impl From<AccountChange> for AccountChangeJson {
        fn from(change: AccountChange) -> Self {
            match change {
                AccountChange::Delegation { target } => {
                    Self { ty: DELEGATION_CHANGE, target: Some(target), dependencies: None }
                }
                AccountChange::Dependencies { dependencies } => {
                    Self { ty: DEPENDENCIES_CHANGE, target: None, dependencies: Some(dependencies) }
                }
            }
        }
    }

    impl TryFrom<AccountChangeJson> for AccountChange {
        type Error = &'static str;

        fn try_from(json: AccountChangeJson) -> Result<Self, Self::Error> {
            match json {
                AccountChangeJson {
                    ty: DELEGATION_CHANGE,
                    target: Some(target),
                    dependencies: None,
                } => Ok(Self::Delegation { target }),
                AccountChangeJson {
                    ty: DEPENDENCIES_CHANGE,
                    target: None,
                    dependencies: Some(dependencies),
                } => Ok(Self::Dependencies { dependencies }),
                _ => Err("unknown or malformed account change"),
            }
        }
    }
}

fn optional_address_wire(address: &Option<Address>) -> &[u8] {
    address.as_ref().map_or(&[], |address| address.as_slice())
}

fn decode_optional_address(buf: &mut &[u8]) -> alloy_rlp::Result<Option<Address>> {
    let bytes = Header::decode_bytes(buf, false)?;
    match bytes {
        [] => Ok(None),
        bytes if bytes.len() == 20 => Ok(Some(Address::from_slice(bytes))),
        _ => Err(alloy_rlp::Error::Custom("sender is neither empty nor an address")),
    }
}

fn list_body<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<&'a [u8]> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    let (body, rest) =
        buf.split_at_checked(header.payload_length).ok_or(alloy_rlp::Error::InputTooShort)?;
    *buf = rest;
    Ok(body)
}

const fn ensure_consumed(body: &[u8]) -> alloy_rlp::Result<()> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(alloy_rlp::Error::ListLengthMismatch { expected: 0, got: body.len() })
    }
}

/// Why an [EIP-8430] transaction is invalid without looking at state.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AaTxError {
    /// The chain id is another chain's.
    #[error("wrong chain id")]
    WrongChainId,
    /// `nonce_key` is not `0`: nonce channels and nonce-free mode are not enabled.
    #[error("nonce channels are not enabled")]
    NonceChannel,
    /// More than one delegation or dependency entry.
    #[error("duplicate account change entry")]
    DuplicateChange,
    /// A dependency entry with no dependency or more than [`MAX_DEPENDENCIES_PER_ENTRY`].
    #[error("a dependency entry declares 1 to 256 dependencies")]
    DependencyCount,
    /// A dependency of a scheme other than [`PROOF_STATEMENT_SCHEME`].
    #[error("unsupported dependency scheme")]
    DependencyScheme,
    /// `sender_auth` has the wrong shape for the sender's form.
    #[error("malformed sender authorization")]
    SenderAuthShape,
    /// `payer_auth` has the wrong shape for the payer mode.
    #[error("malformed payer authorization")]
    PayerAuthShape,
    /// A signature that is not canonical or does not recover.
    #[error("invalid signature")]
    InvalidSignature,
    /// A STATEMENT payer of a recovered sender: its payer hash would need the sender recovered
    /// to find the transaction's dependencies.
    #[error("a STATEMENT payer needs a named sender")]
    StatementPayerNeedsNamedSender,
}

/// A STATEMENT actor: whoever proves, with the program whose verifying key digest is `vk`, the
/// statements `BLAKE2s(tag || key || hash)` for the hashes it authorizes. For leanSPHINCS, `vk` is
/// the signature program's digest, `tag` is `"sphmem01"` and `key` the public key, so the
/// statement is the signature's member for message `hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatementActor {
    /// The verifying key digest of the program proving the statement.
    pub vk: B256,
    /// The statement's domain tag.
    pub tag: [u8; 8],
    /// The actor's key.
    pub key: B256,
}

impl StatementActor {
    /// The actor of a STATEMENT authorization, `None` for another shape.
    pub fn decode(auth: &[u8]) -> Option<Self> {
        if auth.len() != STATEMENT_AUTH_LEN || auth[..20] != STATEMENT_AUTHENTICATOR[..] {
            return None;
        }
        Some(Self {
            vk: B256::from_slice(&auth[20..52]),
            tag: auth[52..60].try_into().ok()?,
            key: B256::from_slice(&auth[60..92]),
        })
    }

    /// Intrinsic gas of authenticating by this actor: its dependency, on top of a secp256k1
    /// authentication's price, which covers the cold actor read and an ecrecover it does not run.
    pub fn auth_cost(&self) -> u64 {
        dependency_gas(self.vk).saturating_add(K1_AUTH_COST)
    }

    /// The authorization naming this actor.
    pub fn encode(&self) -> Bytes {
        [STATEMENT_AUTHENTICATOR.as_slice(), self.vk.as_slice(), &self.tag, self.key.as_slice()]
            .concat()
            .into()
    }

    /// The actor's id in the Keystore.
    pub fn actor_id(&self) -> B256 {
        keystore::statement_actor_id(self.vk, self.tag, self.key)
    }

    /// The dependency authorizing `hash`: `(0x20, BLAKE2s(tag || key || hash), vk)`.
    pub fn dependency(&self, hash: B256) -> Dependency {
        use blake2::{Blake2s256, Digest};
        let data_hash = Blake2s256::new()
            .chain_update(self.tag)
            .chain_update(self.key)
            .chain_update(hash)
            .finalize();
        Dependency {
            scheme: PROOF_STATEMENT_SCHEME,
            data_hash: B256::from_slice(&data_hash),
            verification_key_hash: self.vk,
        }
    }
}

/// How a sender or payer is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization<'a> {
    /// A secp256k1 signature `r || s || v` of the role's hash.
    K1(&'a [u8]),
    /// A statement over the role's hash, which the transaction depends on.
    Statement(StatementActor),
}

/// The actor that authorized a sender or payer, which the Keystore must have configured for the
/// account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    /// The secp256k1 key of this address: the account's own, or one it configured.
    Key(Address),
    /// A STATEMENT actor.
    Statement(StatementActor),
}

/// The authorization of a named identity: `K1_AUTHENTICATOR || r || s || v` or a STATEMENT one.
fn named_authorization(auth: &[u8]) -> Option<Authorization<'_>> {
    if auth.len() == K1_NAMED_AUTH_LEN && auth[..20] == K1_AUTHENTICATOR[..] {
        return Some(Authorization::K1(&auth[20..]));
    }
    StatementActor::decode(auth).map(Authorization::Statement)
}

/// An [EIP-8430] account abstraction transaction:
/// `0x79 || rlp([chain_id, sender, nonce_key, nonce_sequence, valid_after, valid_before,
/// max_priority_fee_per_gas, max_fee_per_gas, gas_limit, account_changes, calls, metadata, payer,
/// sender_auth, payer_auth])`.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxEip8430 {
    /// [EIP-155] chain id.
    ///
    /// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,
    /// The named sender, or `None` to recover it from `sender_auth`.
    pub sender: Option<Address>,
    /// The nonce channel: `0`, the account nonce, on this chain.
    pub nonce_key: U256,
    /// The expected sequence of the channel: the account nonce.
    #[cfg_attr(feature = "serde", serde(rename = "nonce", with = "alloy_serde::quantity"))]
    pub nonce_sequence: u64,
    /// Lower bound of the validity window, seconds or milliseconds; `0` for none.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub valid_after: u64,
    /// Upper bound of the validity window, seconds or milliseconds; `0` for none.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub valid_before: u64,
    /// [EIP-1559] priority fee cap.
    ///
    /// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_priority_fee_per_gas: u128,
    /// [EIP-1559] fee cap.
    ///
    /// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_fee_per_gas: u128,
    /// Gas for the sender's intrinsic gas and the calls.
    #[cfg_attr(feature = "serde", serde(rename = "gas", with = "alloy_serde::quantity"))]
    pub gas_limit: u64,
    /// Typed entries applied before the calls.
    pub account_changes: Vec<AccountChange>,
    /// Phases of calls: a phase's calls commit together.
    pub calls: Vec<Vec<AaCall>>,
    /// Opaque bytes, signed and charged, without effect.
    pub metadata: Bytes,
    /// Who pays.
    pub payer: Payer,
    /// The sender's authorization: `r || s || v` for a recovered sender, else
    /// `K1_AUTHENTICATOR || r || s || v` or a STATEMENT authorization ([`StatementActor`]).
    pub sender_auth: Bytes,
    /// The payer's authorization: empty for self-pay, `r || s || v` for an open payer, else
    /// `K1_AUTHENTICATOR || r || s || v` or a STATEMENT authorization ([`StatementActor`]).
    pub payer_auth: Bytes,
}

impl TxEip8430 {
    /// The signed fields, `chain_id` through `payer`, with `sender` encoded as `sender`.
    fn signed_fields_length(&self, sender: &Option<Address>) -> usize {
        self.chain_id.length() +
            optional_address_wire(sender).length() +
            self.nonce_key.length() +
            self.nonce_sequence.length() +
            self.valid_after.length() +
            self.valid_before.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.account_changes.length() +
            self.calls.length() +
            self.metadata.length() +
            self.payer.length()
    }

    fn encode_signed_fields(&self, sender: &Option<Address>, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        optional_address_wire(sender).encode(out);
        self.nonce_key.encode(out);
        self.nonce_sequence.encode(out);
        self.valid_after.encode(out);
        self.valid_before.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.account_changes.encode(out);
        self.calls.encode(out);
        self.metadata.encode(out);
        self.payer.encode(out);
    }

    fn signing_hash(&self, ty: u8, sender: &Option<Address>) -> B256 {
        let payload_length = self.signed_fields_length(sender);
        let header = Header { list: true, payload_length };
        let mut buf = Vec::with_capacity(1 + header.length_with_payload());
        buf.push(ty);
        header.encode(&mut buf);
        self.encode_signed_fields(sender, &mut buf);
        keccak256(&buf)
    }

    /// The sender signature hash: `keccak256(0x79 || rlp([chain_id, ..., payer]))`, the wire
    /// `sender` included, both auth blobs excluded.
    pub fn sender_signature_hash(&self) -> B256 {
        self.signing_hash(AA_TX_TYPE_ID, &self.sender)
    }

    /// The placeholder signature stored for EIP-8430 transactions, whose signatures live in
    /// their auth fields.
    pub const fn signature() -> alloy_primitives::Signature {
        alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false)
    }

    /// The sender signature hash, the transaction's signature hash as the envelope reports it.
    pub fn signature_hash(&self) -> B256 {
        self.sender_signature_hash()
    }

    /// Writes the preimage of [`Self::sender_signature_hash`].
    pub fn encode_for_signing(&self, out: &mut dyn BufMut) {
        out.put_u8(AA_TX_TYPE_ID);
        Header { list: true, payload_length: self.signed_fields_length(&self.sender) }.encode(out);
        self.encode_signed_fields(&self.sender, out);
    }

    /// The length of [`Self::encode_for_signing`]'s output.
    pub fn payload_len_for_signature(&self) -> usize {
        1 + Header { list: true, payload_length: self.signed_fields_length(&self.sender) }
            .length_with_payload()
    }

    /// Network-encodes the transaction: its [EIP-2718] encoding as an RLP string.
    ///
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    pub fn network_encode(&self, out: &mut dyn BufMut) {
        Header { list: false, payload_length: self.eip2718_encoded_length() }.encode(out);
        self.encode_2718(out);
    }

    /// The payer signature hash: the sender hash's fields under `0x7A`, with the resolved
    /// `sender` in place of the wire one.
    pub fn payer_signature_hash(&self, sender: Address) -> B256 {
        self.signing_hash(AA_PAYER_TYPE, &Some(sender))
    }

    fn fields_length(&self) -> usize {
        self.signed_fields_length(&self.sender) +
            self.sender_auth.length() +
            self.payer_auth.length()
    }

    fn rlp_header(&self) -> Header {
        Header { list: true, payload_length: self.fields_length() }
    }

    /// The length of `rlp([...])`, without the type byte.
    pub fn rlp_encoded_length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }

    /// The length of the [EIP-2718] encoding.
    ///
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    pub fn eip2718_encoded_length(&self) -> usize {
        1 + self.rlp_encoded_length()
    }

    fn encode_fields(&self, out: &mut dyn BufMut) {
        self.encode_signed_fields(&self.sender, out);
        self.sender_auth.encode(out);
        self.payer_auth.encode(out);
    }

    /// Decodes `rlp([...])`, without the type byte.
    pub fn rlp_decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut body = list_body(buf)?;
        let tx = Self {
            chain_id: Decodable::decode(&mut body)?,
            sender: decode_optional_address(&mut body)?,
            nonce_key: Decodable::decode(&mut body)?,
            nonce_sequence: Decodable::decode(&mut body)?,
            valid_after: Decodable::decode(&mut body)?,
            valid_before: Decodable::decode(&mut body)?,
            max_priority_fee_per_gas: Decodable::decode(&mut body)?,
            max_fee_per_gas: Decodable::decode(&mut body)?,
            gas_limit: Decodable::decode(&mut body)?,
            account_changes: Decodable::decode(&mut body)?,
            calls: Decodable::decode(&mut body)?,
            metadata: Decodable::decode(&mut body)?,
            payer: Decodable::decode(&mut body)?,
            sender_auth: Decodable::decode(&mut body)?,
            payer_auth: Decodable::decode(&mut body)?,
        };
        ensure_consumed(body)?;
        Ok(tx)
    }

    /// The transaction hash: `keccak256` of the [EIP-2718] encoding, auth blobs included, so a
    /// re-signed payer changes it. The sequencer admits dependencies under the sender hash.
    ///
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    pub fn tx_hash(&self) -> TxHash {
        let mut buf = Vec::with_capacity(self.eip2718_encoded_length());
        self.encode_2718(&mut buf);
        keccak256(&buf)
    }

    /// The checks that need no state and no signature recovery.
    pub fn validate_static(&self, chain_id: ChainId) -> Result<(), AaTxError> {
        if self.chain_id != chain_id {
            return Err(AaTxError::WrongChainId);
        }
        if !self.nonce_key.is_zero() {
            return Err(AaTxError::NonceChannel);
        }
        let (mut delegations, mut dependency_entries) = (0, 0);
        for change in &self.account_changes {
            match change {
                AccountChange::Delegation { .. } => delegations += 1,
                AccountChange::Dependencies { dependencies } => {
                    dependency_entries += 1;
                    if dependencies.is_empty() || dependencies.len() > MAX_DEPENDENCIES_PER_ENTRY {
                        return Err(AaTxError::DependencyCount);
                    }
                    if dependencies.iter().any(|d| d.scheme != PROOF_STATEMENT_SCHEME) {
                        return Err(AaTxError::DependencyScheme);
                    }
                }
            }
        }
        if delegations > 1 || dependency_entries > 1 {
            return Err(AaTxError::DuplicateChange);
        }
        if self.sender_authorization().is_none() {
            return Err(AaTxError::SenderAuthShape);
        }
        match (self.payer, self.payer_authorization()) {
            (Payer::SelfPay, _) if self.payer_auth.is_empty() => {}
            (Payer::SelfPay, _) | (_, None) => return Err(AaTxError::PayerAuthShape),
            (_, Some(Authorization::Statement(_))) if self.sender.is_none() => {
                return Err(AaTxError::StatementPayerNeedsNamedSender);
            }
            _ => {}
        }
        Ok(())
    }

    /// The sender's authorization: a signature for a recovered sender, else the named
    /// authorization. `None` if `sender_auth` has neither shape.
    pub fn sender_authorization(&self) -> Option<Authorization<'_>> {
        match self.sender {
            None => (self.sender_auth.len() == 65).then_some(Authorization::K1(&self.sender_auth)),
            Some(_) => named_authorization(&self.sender_auth),
        }
    }

    /// The payer's authorization: a signature for an open payer, else the named authorization.
    /// `None` for self-pay or a `payer_auth` of neither shape.
    pub fn payer_authorization(&self) -> Option<Authorization<'_>> {
        match self.payer {
            Payer::SelfPay => None,
            Payer::Open => {
                (self.payer_auth.len() == 65).then_some(Authorization::K1(&self.payer_auth))
            }
            Payer::Named(_) => named_authorization(&self.payer_auth),
        }
    }

    /// The resolved sender and the actor that authorized it: the signer of the sender hash for a
    /// recovered sender, else the named sender, authorized by the signer or the STATEMENT actor.
    /// Whether the named sender configured that actor is the Keystore's to say. Requires
    /// [`Self::validate_static`]'s auth shapes.
    #[cfg(feature = "k256")]
    pub fn authenticate_sender(&self) -> Result<(Address, Actor), AaTxError> {
        let actor = match self.sender_authorization().ok_or(AaTxError::SenderAuthShape)? {
            Authorization::K1(signature) => {
                Actor::Key(recover_k1(signature, self.sender_signature_hash())?)
            }
            Authorization::Statement(actor) => Actor::Statement(actor),
        };
        match (self.sender, actor) {
            (Some(sender), _) => Ok((sender, actor)),
            (None, Actor::Key(signer)) => Ok((signer, actor)),
            // A recovered sender has no STATEMENT form (`sender_authorization`).
            (None, Actor::Statement(_)) => Err(AaTxError::SenderAuthShape),
        }
    }

    /// The resolved sender ([`Self::authenticate_sender`]).
    #[cfg(feature = "k256")]
    pub fn recover_sender(&self) -> Result<Address, AaTxError> {
        self.authenticate_sender().map(|(sender, _)| sender)
    }

    /// The resolved payer of a transaction whose resolved sender is `sender`, and the actor that
    /// authorized it; `None` for self-pay, which the sender's actor authorizes. An open payer is
    /// the signer of the payer hash, a named one is authorized by the signer or the STATEMENT
    /// actor.
    #[cfg(feature = "k256")]
    pub fn authenticate_payer(
        &self,
        sender: Address,
    ) -> Result<Option<(Address, Actor)>, AaTxError> {
        if self.payer == Payer::SelfPay {
            return Ok(None);
        }
        let actor = match self.payer_authorization().ok_or(AaTxError::PayerAuthShape)? {
            Authorization::K1(signature) => {
                Actor::Key(recover_k1(signature, self.payer_signature_hash(sender))?)
            }
            Authorization::Statement(actor) => Actor::Statement(actor),
        };
        match (self.payer, actor) {
            (Payer::Named(payer), _) => Ok(Some((payer, actor))),
            (_, Actor::Key(signer)) => Ok(Some((signer, actor))),
            // An open payer has no STATEMENT form (`payer_authorization`).
            _ => Err(AaTxError::PayerAuthShape),
        }
    }

    /// The resolved payer of a transaction whose resolved sender is `sender`
    /// ([`Self::authenticate_payer`]).
    #[cfg(feature = "k256")]
    pub fn recover_payer(&self, sender: Address) -> Result<Address, AaTxError> {
        Ok(self.authenticate_payer(sender)?.map_or(sender, |(payer, _)| payer))
    }

    /// The sender's STATEMENT actor, if it authorizes one.
    fn sender_statement(&self) -> Option<StatementActor> {
        match self.sender_authorization() {
            Some(Authorization::Statement(actor)) => Some(actor),
            _ => None,
        }
    }

    /// The payer's STATEMENT actor, if the transaction names the sender its hash commits to.
    fn payer_statement(&self) -> Option<StatementActor> {
        match self.payer_authorization() {
            Some(Authorization::Statement(actor)) if self.sender.is_some() => Some(actor),
            _ => None,
        }
    }

    /// The dependencies of the STATEMENT authorizations: the sender's over the sender hash and
    /// the payer's over the payer hash of the named sender.
    pub fn authorization_dependencies(&self) -> Vec<Dependency> {
        let sender = self.sender_statement().map(|a| a.dependency(self.sender_signature_hash()));
        let payer = self
            .payer_statement()
            .zip(self.sender)
            .map(|(actor, sender)| actor.dependency(self.payer_signature_hash(sender)));
        sender.into_iter().chain(payer).collect()
    }

    /// How many dependencies the transaction pays for: those it declares, duplicates included, and
    /// one for each STATEMENT authorization. It hashes nothing.
    pub fn dependency_count(&self) -> u64 {
        let authorizations = u64::from(self.sender_statement().is_some()) +
            u64::from(self.payer_statement().is_some());
        self.declared().len() as u64 + authorizations
    }

    /// The delegate of the delegation entry, if any: the zero address clears a delegation.
    pub fn delegation(&self) -> Option<Address> {
        self.account_changes.iter().find_map(|change| match change {
            AccountChange::Delegation { target } => Some(*target),
            AccountChange::Dependencies { .. } => None,
        })
    }

    /// The dependencies as declared, duplicates included.
    fn declared(&self) -> &[Dependency] {
        self.account_changes
            .iter()
            .find_map(|change| match change {
                AccountChange::Dependencies { dependencies } => Some(dependencies.as_slice()),
                AccountChange::Delegation { .. } => None,
            })
            .unwrap_or_default()
    }

    /// The transaction's [EIP-8288] dependencies, sorted and deduplicated: the declared ones,
    /// with a zero `data_hash` replaced by the sender hash, and those of its STATEMENT
    /// authorizations.
    ///
    /// [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288
    pub fn dependencies(&self) -> Vec<Dependency> {
        self.dependencies_with(self.authorization_dependencies())
    }

    fn dependencies_with(&self, authorizations: Vec<Dependency>) -> Vec<Dependency> {
        let mut sender_hash = None;
        let mut dependencies: Vec<Dependency> = self
            .declared()
            .iter()
            .map(|dependency| {
                let mut dependency = *dependency;
                if dependency.data_hash.is_zero() {
                    dependency.data_hash =
                        *sender_hash.get_or_insert_with(|| self.sender_signature_hash());
                }
                dependency
            })
            .chain(authorizations)
            .collect();
        dependencies.sort_unstable();
        dependencies.dedup();
        dependencies
    }

    /// The transaction's dependencies under its admission key, the sender hash, or `None` if it
    /// has none. Each STATEMENT authorization counts as one declared dependency: it pays for one.
    pub fn declared_dependencies(&self) -> Option<DeclaredDependencies> {
        let declared = self.dependency_count() as usize;
        (declared != 0).then(|| DeclaredDependencies {
            key: self.sender_signature_hash(),
            declared,
            dependencies: self.dependencies_with(self.authorization_dependencies()),
        })
    }

    /// The [EIP-7623] tokens of the bytes `tx_payload_cost` covers: the [EIP-2718] encoding with
    /// `payer_auth` empty.
    ///
    /// [EIP-7623]: https://eips.ethereum.org/EIPS/eip-7623
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    fn payload_tokens(&self) -> u64 {
        let empty_payer_auth = Bytes::new();
        let payload_length = self.signed_fields_length(&self.sender) +
            self.sender_auth.length() +
            empty_payer_auth.length();
        let header = Header { list: true, payload_length };
        let mut buf = Vec::with_capacity(1 + header.length_with_payload());
        buf.push(AA_TX_TYPE_ID);
        header.encode(&mut buf);
        self.encode_signed_fields(&self.sender, &mut buf);
        self.sender_auth.encode(&mut buf);
        empty_payer_auth.encode(&mut buf);
        tokens(&buf)
    }

    /// The sender's intrinsic gas and calldata floor for resolved sender `sender`, from one
    /// encoding of the transaction.
    pub fn sender_gas(&self, sender: Address) -> SenderGas {
        let payload_tokens = self.payload_tokens();
        let value_transfers = self
            .calls
            .iter()
            .flatten()
            .filter(|call| !call.value.is_zero() && call.to != sender)
            .count() as u64;
        let fixed = AA_BASE_COST
            .saturating_add(value_transfers.saturating_mul(TX_VALUE_COST))
            .saturating_add(self.account_changes_cost())
            .saturating_add(auth_cost(self.sender_authorization()));
        SenderGas {
            intrinsic: fixed.saturating_add(payload_tokens.saturating_mul(4)),
            floor: fixed.saturating_add(payload_tokens.saturating_mul(FLOOR_PER_TOKEN)),
        }
    }

    /// The gas the sender's `gas_limit` covers before any call runs, for resolved sender `sender`:
    /// [EIP-8430]'s intrinsic gas less the payer's authentication.
    ///
    /// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
    pub fn sender_intrinsic_gas(&self, sender: Address) -> u64 {
        self.sender_gas(sender).intrinsic
    }

    /// The delegation entry's and the dependency entry's intrinsic gas.
    pub fn account_changes_cost(&self) -> u64 {
        let delegation = if self.delegation().is_some() { DELEGATION_COST } else { 0 };
        let dependencies: u64 =
            self.declared().iter().map(|d| dependency_gas(d.verification_key_hash)).sum();
        delegation.saturating_add(dependencies)
    }

    /// The payer's authentication gas, billed on top of `gas_limit`: `0` for self-pay.
    pub fn payer_auth_cost(&self) -> u64 {
        if self.payer == Payer::SelfPay {
            return 0;
        }
        auth_cost(self.payer_authorization()).saturating_add(standard_cost(&self.payer_auth))
    }

    /// The payer's share of the calldata floor, reserved on top of `gas_limit`: `0` for self-pay.
    pub fn payer_gas_reserve(&self) -> u64 {
        if self.payer == Payer::SelfPay {
            return 0;
        }
        auth_cost(self.payer_authorization())
            .saturating_add(FLOOR_PER_TOKEN.saturating_mul(tokens(&self.payer_auth)))
    }

    /// The sender's share of the [EIP-7623] calldata floor: `gas_limit` must cover it.
    ///
    /// [EIP-7623]: https://eips.ethereum.org/EIPS/eip-7623
    pub fn sender_floor(&self, sender: Address) -> u64 {
        self.sender_gas(sender).floor
    }

    /// The gas the block reserves for the transaction and the payer is precharged for:
    /// `gas_limit` and the payer's reserve.
    pub fn effective_gas_limit(&self) -> u64 {
        self.gas_limit.saturating_add(self.payer_gas_reserve())
    }

    /// Whether a block at `timestamp` (seconds) is within the validity window.
    pub const fn is_valid_at(&self, timestamp: u64) -> bool {
        let now = timestamp.saturating_mul(1000);
        let after = normalize_timestamp_ms(self.valid_after);
        let before = normalize_timestamp_ms(self.valid_before);
        (after == 0 || now >= after) && (before == 0 || now <= before)
    }

    /// The number of phases.
    pub const fn phase_count(&self) -> usize {
        self.calls.len()
    }

    /// The heap size, for the transaction pool.
    pub fn size(&self) -> usize {
        core::mem::size_of::<Self>() +
            self.metadata.len() +
            self.sender_auth.len() +
            self.payer_auth.len() +
            self.calls.iter().flatten().map(|call| call.data.len() + 84).sum::<usize>() +
            core::mem::size_of_val(self.declared())
    }
}

/// The sender's share of an [EIP-8430] transaction's gas before any call runs.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderGas {
    /// Intrinsic gas less the payer's authentication; `gas_limit` covers it.
    pub intrinsic: u64,
    /// The sender's share of the [EIP-7623] calldata floor; `gas_limit` must cover it.
    ///
    /// [EIP-7623]: https://eips.ethereum.org/EIPS/eip-7623
    pub floor: u64,
}

/// `value` in milliseconds: seconds below [`TIMESTAMP_MS_THRESHOLD`], `0` kept as no bound.
pub const fn normalize_timestamp_ms(value: u64) -> u64 {
    if value != 0 && value < TIMESTAMP_MS_THRESHOLD { value.saturating_mul(1000) } else { value }
}

/// The intrinsic gas of a dependency on the program `verification_key_hash`.
fn dependency_gas(verification_key_hash: B256) -> u64 {
    if verification_key_hash == SIGNATURE_PROGRAM_DIGEST {
        LEANSPHINCS_VERIFICATION_GAS
    } else {
        LEANSTARK_VERIFICATION_GAS
    }
}

/// The intrinsic gas of an authorization: a STATEMENT one adds its dependency to a secp256k1
/// one's.
fn auth_cost(authorization: Option<Authorization<'_>>) -> u64 {
    match authorization {
        Some(Authorization::Statement(actor)) => actor.auth_cost(),
        _ => K1_AUTH_COST,
    }
}

/// [EIP-7623] tokens: a zero byte is one, any other byte four.
///
/// [EIP-7623]: https://eips.ethereum.org/EIPS/eip-7623
fn tokens(data: &[u8]) -> u64 {
    data.iter().map(|&byte| if byte == 0 { 1 } else { 4 }).sum()
}

/// [EIP-2028] gas: 4 per zero byte, 16 per other byte.
///
/// [EIP-2028]: https://eips.ethereum.org/EIPS/eip-2028
fn standard_cost(data: &[u8]) -> u64 {
    tokens(data).saturating_mul(4)
}

/// A secp256k1 signature as EIP-8430 authorizations carry it: `r || s || v`, `v` 27 or 28.
pub fn k1_auth(signature: &alloy_primitives::Signature) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
    out[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
    out[64] = 27 + signature.v() as u8;
    out
}

/// The signer of `digest` from `r || s || v`, `v` 27 or 28 and `s` in the lower half.
#[cfg(feature = "k256")]
fn recover_k1(signature: &[u8], digest: B256) -> Result<Address, AaTxError> {
    let signature: &[u8; 65] = signature.try_into().map_err(|_| AaTxError::InvalidSignature)?;
    let parity = match signature[64] {
        27 => false,
        28 => true,
        _ => return Err(AaTxError::InvalidSignature),
    };
    let signature = alloy_primitives::Signature::new(
        U256::from_be_slice(&signature[..32]),
        U256::from_be_slice(&signature[32..64]),
        parity,
    );
    alloy_consensus::crypto::secp256k1::recover_signer(&signature, digest)
        .map_err(|_| AaTxError::InvalidSignature)
}

impl Encodable for TxEip8430 {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        self.encode_fields(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxEip8430 {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

impl Typed2718 for TxEip8430 {
    fn ty(&self) -> u8 {
        AA_TX_TYPE_ID
    }
}

impl IsTyped2718 for TxEip8430 {
    fn is_type(ty: u8) -> bool {
        ty == AA_TX_TYPE_ID
    }
}

impl Encodable2718 for TxEip8430 {
    fn type_flag(&self) -> Option<u8> {
        Some(AA_TX_TYPE_ID)
    }

    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        out.put_u8(AA_TX_TYPE_ID);
        self.encode(out);
    }
}

impl Decodable2718 for TxEip8430 {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != AA_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::rlp_decode(buf)?)
    }

    fn fallback_decode(_buf: &mut &[u8]) -> Eip2718Result<Self> {
        Err(Eip2718Error::UnexpectedType(AA_TX_TYPE_ID))
    }
}

impl alloy_consensus::transaction::RlpEcdsaEncodableTx for TxEip8430 {
    fn rlp_encoded_fields_length(&self) -> usize {
        self.fields_length()
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.encode_fields(out);
    }
}

#[cfg(feature = "alloy-compat")]
impl From<TxEip8430> for alloy_rpc_types_eth::TransactionRequest {
    /// A request can describe the sender, the nonce and the fees: calls have no request form.
    fn from(tx: TxEip8430) -> Self {
        Self {
            from: tx.sender,
            transaction_type: Some(AA_TX_TYPE_ID),
            chain_id: Some(tx.chain_id),
            nonce: Some(tx.nonce_sequence),
            gas: Some(tx.effective_gas_limit()),
            max_fee_per_gas: Some(tx.max_fee_per_gas),
            max_priority_fee_per_gas: Some(tx.max_priority_fee_per_gas),
            ..Default::default()
        }
    }
}

/// Serializes a sealed [EIP-8430] transaction as an RPC transaction object: its fields and `hash`.
/// The envelope's tag supplies `type`.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[cfg(feature = "serde")]
pub fn serde_aa_tx_rpc<S>(
    value: &alloy_consensus::Sealed<TxEip8430>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;

    #[derive(Serialize)]
    struct SerdeHelper<'a> {
        hash: B256,
        #[serde(flatten)]
        tx: &'a TxEip8430,
    }

    SerdeHelper { hash: value.hash(), tx: value.inner() }.serialize(serializer)
}

/// Deserializes a sealed [EIP-8430] transaction from an RPC transaction object, recomputing its
/// hash.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[cfg(feature = "serde")]
pub fn serde_aa_tx_rpc_de<'de, D>(
    deserializer: D,
) -> Result<alloy_consensus::Sealed<TxEip8430>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(alloy_consensus::Sealed::new(TxEip8430::deserialize(deserializer)?))
}

impl Sealable for TxEip8430 {
    fn hash_slow(&self) -> B256 {
        self.tx_hash()
    }
}

/// The empty input every [EIP-8430] transaction reports: its calldata lives in its calls.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
static EMPTY_INPUT: Bytes = Bytes::new();

impl Transaction for TxEip8430 {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce_sequence
    }

    fn gas_limit(&self) -> u64 {
        self.effective_gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        base_fee.map_or(self.max_fee_per_gas, |base_fee| {
            (base_fee as u128)
                .saturating_add(self.max_priority_fee_per_gas)
                .min(self.max_fee_per_gas)
        })
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        // No single callee: report the first call's, or the zero address with no calls.
        TxKind::Call(self.calls.iter().flatten().next().map_or(Address::ZERO, |call| call.to))
    }

    fn is_create(&self) -> bool {
        false
    }

    fn value(&self) -> U256 {
        self.calls.iter().flatten().fold(U256::ZERO, |sum, call| sum.saturating_add(call.value))
    }

    fn input(&self) -> &Bytes {
        &EMPTY_INPUT
    }

    fn access_list(&self) -> Option<&AccessList> {
        None
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    /// A key whose address is known: the private key `1`.
    const KEY_ONE: Address = address!("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

    /// `r || s || v` of `digest` by the private key `1` (RFC 6979, low `s`).
    fn sign(digest: B256) -> [u8; 65] {
        use alloy_signer::k256::ecdsa::SigningKey;
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let key = SigningKey::from_slice(&secret).unwrap();
        let (signature, recovery) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = 27 + recovery.to_byte();
        out
    }

    fn transfer() -> TxEip8430 {
        TxEip8430 {
            chain_id: 10,
            sender: None,
            nonce_key: U256::ZERO,
            nonce_sequence: 3,
            valid_after: 0,
            valid_before: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 10,
            gas_limit: 200_000,
            account_changes: vec![AccountChange::Dependencies {
                dependencies: vec![Dependency {
                    scheme: PROOF_STATEMENT_SCHEME,
                    data_hash: B256::ZERO,
                    verification_key_hash: B256::repeat_byte(7),
                }],
            }],
            calls: vec![vec![AaCall {
                to: address!("0x2222222222222222222222222222222222222222"),
                value: U256::from(5),
                data: Bytes::from_static(&[1, 2, 3]),
            }]],
            metadata: Bytes::new(),
            payer: Payer::SelfPay,
            sender_auth: Bytes::new(),
            payer_auth: Bytes::new(),
        }
    }

    fn signed(mut tx: TxEip8430) -> TxEip8430 {
        let signature = sign(tx.sender_signature_hash());
        tx.sender_auth = match tx.sender {
            None => Bytes::copy_from_slice(&signature),
            Some(_) => Bytes::from([K1_AUTHENTICATOR.as_slice(), &signature].concat()),
        };
        tx
    }

    #[test]
    fn round_trips_through_its_2718_encoding() {
        let mut tx = signed(transfer());
        tx.payer = Payer::Open;
        tx.payer_auth = Bytes::from(vec![9; 65]);
        tx.account_changes.push(AccountChange::Delegation { target: Address::repeat_byte(3) });
        let encoded = tx.encoded_2718();
        assert_eq!(encoded[0], AA_TX_TYPE_ID);
        assert_eq!(encoded.len(), tx.eip2718_encoded_length());
        assert_eq!(TxEip8430::decode_2718(&mut encoded.as_slice()).unwrap(), tx);
        for payer in [Payer::SelfPay, Payer::Named(Address::repeat_byte(4))] {
            let tx = TxEip8430 { payer, ..tx.clone() };
            assert_eq!(TxEip8430::decode_2718(&mut tx.encoded_2718().as_slice()).unwrap(), tx);
        }
    }

    #[test]
    #[cfg(feature = "k256")]
    fn recovers_the_sender_and_the_key_of_a_named_one() {
        let tx = signed(transfer());
        tx.validate_static(10).unwrap();
        assert_eq!(tx.recover_sender(), Ok(KEY_ONE));
        assert_eq!(tx.recover_payer(KEY_ONE), Ok(KEY_ONE), "self-pay");

        let named = signed(TxEip8430 { sender: Some(KEY_ONE), ..transfer() });
        named.validate_static(10).unwrap();
        assert_eq!(named.recover_sender(), Ok(KEY_ONE));
        // Another account's key: whether that account configured it is the Keystore's to say.
        let other = signed(TxEip8430 { sender: Some(Address::repeat_byte(1)), ..transfer() });
        assert_eq!(other.authenticate_sender(), Ok((Address::repeat_byte(1), Actor::Key(KEY_ONE))));

        let mut tampered = tx;
        tampered.nonce_sequence += 1;
        assert_ne!(tampered.recover_sender(), Ok(KEY_ONE), "the signature covers the nonce");
    }

    #[test]
    #[cfg(feature = "k256")]
    fn hashes_payers_apart_from_senders() {
        let tx = signed(TxEip8430 { payer: Payer::Named(KEY_ONE), ..transfer() });
        assert_ne!(tx.sender_signature_hash(), tx.payer_signature_hash(KEY_ONE));
        let mut paid = tx.clone();
        paid.payer_auth = Bytes::from(
            [K1_AUTHENTICATOR.as_slice(), &sign(tx.payer_signature_hash(KEY_ONE))].concat(),
        );
        paid.validate_static(10).unwrap();
        assert_eq!(paid.recover_payer(KEY_ONE), Ok(KEY_ONE));
        assert_eq!(paid.sender_signature_hash(), tx.sender_signature_hash(), "auth is not signed");
        assert_ne!(paid.tx_hash(), tx.tx_hash(), "auth is in the transaction hash");
    }

    #[test]
    fn checks_its_shape_statically() {
        let tx = signed(transfer());
        assert_eq!(tx.validate_static(11), Err(AaTxError::WrongChainId));
        let channel = TxEip8430 { nonce_key: U256::from(1), ..tx.clone() };
        assert_eq!(channel.validate_static(10), Err(AaTxError::NonceChannel));
        let mut twice = tx.clone();
        twice.account_changes.push(twice.account_changes[0].clone());
        assert_eq!(twice.validate_static(10), Err(AaTxError::DuplicateChange));
        let none = TxEip8430 {
            account_changes: vec![AccountChange::Dependencies { dependencies: vec![] }],
            ..tx.clone()
        };
        assert_eq!(none.validate_static(10), Err(AaTxError::DependencyCount));
        let mut scheme = tx.clone();
        let AccountChange::Dependencies { dependencies } = &mut scheme.account_changes[0] else {
            unreachable!()
        };
        dependencies[0].scheme = 0x10;
        assert_eq!(scheme.validate_static(10), Err(AaTxError::DependencyScheme));
        let short = TxEip8430 { sender_auth: Bytes::from(vec![0; 64]), ..tx.clone() };
        assert_eq!(short.validate_static(10), Err(AaTxError::SenderAuthShape));
        let open = TxEip8430 { payer: Payer::Open, ..tx };
        assert_eq!(open.validate_static(10), Err(AaTxError::PayerAuthShape));
    }

    #[test]
    fn declares_its_dependencies_under_the_sender_hash() {
        let mut tx = signed(transfer());
        let AccountChange::Dependencies { dependencies } = &mut tx.account_changes[0] else {
            unreachable!()
        };
        dependencies.push(dependencies[0]);
        let declared = tx.declared_dependencies().unwrap();
        assert_eq!(declared.key, tx.sender_signature_hash());
        assert_eq!(declared.declared, 2, "duplicates are declared and paid for");
        assert_eq!(declared.dependencies.len(), 1);
        assert_eq!(declared.dependencies[0].data_hash, tx.sender_signature_hash());
        assert_eq!(crate::declared_dependencies(&tx.encoded_2718()), Some(declared));
        assert_eq!(tx.account_changes_cost(), 2 * LEANSTARK_VERIFICATION_GAS);
        assert!(TxEip8430 { account_changes: vec![], ..tx }.declared_dependencies().is_none());
    }

    #[test]
    fn charges_intrinsic_gas_as_eip_8430() {
        let tx = signed(transfer());
        let payload = tx.encoded_2718();
        assert_eq!(
            tx.sender_intrinsic_gas(KEY_ONE),
            AA_BASE_COST +
                standard_cost(&payload) +
                TX_VALUE_COST +
                LEANSTARK_VERIFICATION_GAS +
                K1_AUTH_COST
        );
        let to_self = TxEip8430 {
            calls: vec![vec![AaCall { to: KEY_ONE, value: U256::from(1), data: Bytes::new() }]],
            ..tx.clone()
        };
        assert_eq!(
            to_self.sender_intrinsic_gas(KEY_ONE) + TX_VALUE_COST,
            to_self.sender_intrinsic_gas(Address::repeat_byte(9)),
            "a value transfer to the sender costs nothing"
        );
        assert_eq!(tx.payer_auth_cost(), 0);
        assert_eq!(tx.effective_gas_limit(), tx.gas_limit);
        let sponsored = TxEip8430 {
            payer: Payer::Named(Address::repeat_byte(4)),
            payer_auth: Bytes::from(vec![1; 85]),
            ..tx.clone()
        };
        assert_eq!(sponsored.payer_auth_cost(), K1_AUTH_COST + 85 * 16);
        assert_eq!(sponsored.payer_gas_reserve(), K1_AUTH_COST + 85 * 40);
        let fixed = AA_BASE_COST + TX_VALUE_COST + LEANSTARK_VERIFICATION_GAS + K1_AUTH_COST;
        assert_eq!(tx.sender_floor(KEY_ONE), fixed + 10 * tokens(&payload));
        // The payer's auth bytes are outside the sender's payload, which encodes them empty.
        let unsigned_payer = TxEip8430 { payer_auth: Bytes::new(), ..sponsored.clone() };
        assert_eq!(
            sponsored.sender_gas(KEY_ONE).intrinsic,
            fixed + standard_cost(&unsigned_payer.encoded_2718())
        );
        assert_eq!(sponsored.sender_gas(KEY_ONE), unsigned_payer.sender_gas(KEY_ONE));
    }

    #[test]
    fn reads_timestamps_in_seconds_or_milliseconds() {
        let tx = TxEip8430 { valid_after: 100, valid_before: 200_000, ..transfer() };
        assert!(!tx.is_valid_at(99) && tx.is_valid_at(100) && tx.is_valid_at(200));
        assert!(!tx.is_valid_at(200_001));
        let ms = TxEip8430 { valid_after: 0, valid_before: 150_000_000_000, ..transfer() };
        assert!(ms.is_valid_at(150_000_000) && !ms.is_valid_at(150_000_001));
    }

    /// The golden transaction shared with op-core (`TestAaTxGoldenVector`) and the span batch
    /// tests: a named sender and payer, both account change types, two phases and metadata. The
    /// auth blobs are fixed bytes of the right shape, not signatures.
    pub(crate) fn golden() -> TxEip8430 {
        TxEip8430 {
            chain_id: 901,
            sender: Some(Address::repeat_byte(0x11)),
            nonce_key: U256::ZERO,
            nonce_sequence: 3,
            valid_after: 1_700_000_000,
            valid_before: 1_700_000_600_000,
            max_priority_fee_per_gas: 1_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 250_000,
            account_changes: vec![
                AccountChange::Delegation { target: Address::repeat_byte(0xde) },
                AccountChange::Dependencies {
                    dependencies: vec![
                        Dependency {
                            scheme: PROOF_STATEMENT_SCHEME,
                            data_hash: B256::ZERO,
                            verification_key_hash: B256::repeat_byte(0xaa),
                        },
                        Dependency {
                            scheme: PROOF_STATEMENT_SCHEME,
                            data_hash: B256::repeat_byte(0xdd),
                            verification_key_hash: B256::repeat_byte(0xaa),
                        },
                    ],
                },
            ],
            calls: vec![
                vec![AaCall {
                    to: Address::repeat_byte(0x22),
                    value: U256::from(1_000),
                    data: Bytes::from_static(&[0xde, 0xad]),
                }],
                vec![
                    AaCall {
                        to: Address::repeat_byte(0x33),
                        value: U256::ZERO,
                        data: Bytes::new(),
                    },
                    AaCall {
                        to: Address::repeat_byte(0x44),
                        value: U256::ZERO,
                        data: Bytes::from_static(&[0xbe, 0xef]),
                    },
                ],
            ],
            metadata: Bytes::from_static(b"op"),
            payer: Payer::Named(Address::repeat_byte(0x55)),
            sender_auth: [&K1_AUTHENTICATOR[..], &[0x66; 65]].concat().into(),
            payer_auth: [&K1_AUTHENTICATOR[..], &[0x77; 65]].concat().into(),
        }
    }

    /// A short account change entry is an error, not the end of `account_changes` (op-core:
    /// `TestAaTxShortAccountChangeDoesNotEndTheList`).
    #[test]
    fn refuses_a_short_account_change() {
        let tx = golden();
        for short in [&[0xc0][..], &[0xc1, 0x01], &[0xc1, 0x04]] {
            // The transaction's later fields sit inside `account_changes`, after the short entry.
            let mut inner = Vec::new();
            tx.account_changes[1].encode(&mut inner);
            inner.extend_from_slice(short);
            tx.calls.encode(&mut inner);
            tx.metadata.encode(&mut inner);
            tx.payer.encode(&mut inner);
            tx.sender_auth.encode(&mut inner);
            tx.payer_auth.encode(&mut inner);
            let mut fields = Vec::new();
            tx.chain_id.encode(&mut fields);
            optional_address_wire(&tx.sender).encode(&mut fields);
            tx.nonce_key.encode(&mut fields);
            tx.nonce_sequence.encode(&mut fields);
            tx.valid_after.encode(&mut fields);
            tx.valid_before.encode(&mut fields);
            tx.max_priority_fee_per_gas.encode(&mut fields);
            tx.max_fee_per_gas.encode(&mut fields);
            tx.gas_limit.encode(&mut fields);
            Header { list: true, payload_length: inner.len() }.encode(&mut fields);
            fields.extend(inner);
            let mut raw = vec![AA_TX_TYPE_ID];
            Header { list: true, payload_length: fields.len() }.encode(&mut raw);
            raw.extend(fields);
            assert!(TxEip8430::decode_2718(&mut raw.as_slice()).is_err());
            assert_eq!(crate::declared_dependencies(&raw), None);
        }
    }

    /// Golden vector shared with op-core (`TestAaTxGoldenVector`): encoding, hashes and the
    /// dependencies with the self-reference substituted.
    #[test]
    fn golden_vector() {
        let tx = golden();
        let mut raw = Vec::new();
        tx.encode_2718(&mut raw);
        assert_eq!(alloy_primitives::hex::encode(&raw), GOLDEN_RAW);
        assert_eq!(TxEip8430::decode_2718(&mut raw.as_slice()).unwrap(), tx);
        let sender_hash = alloy_primitives::b256!(
            "0x9d9a2c330a234279bf45099bf8283fd2a872c853c69f26040b565340d15472ed"
        );
        assert_eq!(
            tx.tx_hash(),
            alloy_primitives::b256!(
                "0x41e6de04bc5d0e7448d620643c8d9d1f6f9f2a035eb6e841099f32482c243433"
            )
        );
        assert_eq!(tx.sender_signature_hash(), sender_hash);
        assert_eq!(
            tx.payer_signature_hash(Address::repeat_byte(0x11)),
            alloy_primitives::b256!(
                "0x07f9d695fece3c6dad9df587790a2439fd142e82268cbd47cb64cbb98ad6fc45"
            )
        );
        let vk = B256::repeat_byte(0xaa);
        assert_eq!(
            tx.dependencies(),
            vec![
                Dependency {
                    scheme: PROOF_STATEMENT_SCHEME,
                    data_hash: sender_hash,
                    verification_key_hash: vk
                },
                Dependency {
                    scheme: PROOF_STATEMENT_SCHEME,
                    data_hash: B256::repeat_byte(0xdd),
                    verification_key_hash: vk
                },
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn golden_rpc_json() {
        let env = crate::OpTxEnvelope::Aa(alloy_consensus::Sealed::new(golden()));
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(json, GOLDEN_JSON);
        let back: crate::OpTxEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    /// [EIP-2718] encoding of the golden transaction ([`golden`]).
    ///
    /// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
    pub(crate) const GOLDEN_RAW: &str = "79f901f38203859411111111111111111111111111111111111111118003846553f10086018bcfee8fc0830f424084773594008303d090f8a6d60194dedededededededededededededededededededef88d04f88af84320a00000000000000000000000000000000000000000000000000000000000000000a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf84320a0dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddda0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf850dcdb9422222222222222222222222222222222222222228203e882deadf2d79433333333333333333333333333333333333333338080d99444444444444444444444444444444444444444448082beef826f70945555555555555555555555555555555555555555b85500000000000000000000000000000000000000016666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666b85500000000000000000000000000000000000000017777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777";

    /// RPC JSON of the golden transaction ([`golden`]).
    #[cfg(feature = "serde")]
    const GOLDEN_JSON: &str = r#"{"type":"0x79","hash":"0x41e6de04bc5d0e7448d620643c8d9d1f6f9f2a035eb6e841099f32482c243433","chainId":"0x385","sender":"0x1111111111111111111111111111111111111111","nonceKey":"0x0","nonce":"0x3","validAfter":"0x6553f100","validBefore":"0x18bcfee8fc0","maxPriorityFeePerGas":"0xf4240","maxFeePerGas":"0x77359400","gas":"0x3d090","accountChanges":[{"type":"0x1","target":"0xdededededededededededededededededededede"},{"type":"0x4","dependencies":[{"scheme":"0x20","dataHash":"0x0000000000000000000000000000000000000000000000000000000000000000","verificationKeyHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"scheme":"0x20","dataHash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","verificationKeyHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}],"calls":[[{"to":"0x2222222222222222222222222222222222222222","value":"0x3e8","data":"0xdead"}],[{"to":"0x3333333333333333333333333333333333333333","value":"0x0","data":"0x"},{"to":"0x4444444444444444444444444444444444444444","value":"0x0","data":"0xbeef"}]],"metadata":"0x6f70","payer":"0x5555555555555555555555555555555555555555","senderAuth":"0x00000000000000000000000000000000000000016666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666","payerAuth":"0x00000000000000000000000000000000000000017777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"}"#;

    /// A leanSPHINCS actor's statement over a message is the signature's member
    /// (op-leanvm-tree's `signature-0` fixture).
    #[test]
    fn a_statement_is_the_signature_member() {
        use alloy_primitives::b256;
        let actor = StatementActor {
            vk: B256::repeat_byte(9),
            tag: *b"sphmem01",
            key: b256!("0xbb9ca6c2f8bc2cb914968c8ecb5a5b3c9d70d9199b842cde14b0726cf4d56991"),
        };
        let message = b256!("0x0000000000000000010000000000000002000000000000000300000000000000");
        let dependency = actor.dependency(message);
        assert_eq!(
            dependency.data_hash,
            b256!("0x4142422d4bcba7a3640cbe9ae6f13998a76d99373b946218926ef6299b8534e0")
        );
        assert_eq!(dependency.verification_key_hash, actor.vk);
        assert_eq!(dependency.scheme, PROOF_STATEMENT_SCHEME);
        assert_eq!(StatementActor::decode(&actor.encode()), Some(actor));
        assert_eq!(actor.encode().len(), STATEMENT_AUTH_LEN);
    }

    /// A STATEMENT authorization names its actor, adds its statement over the role's hash to the
    /// dependencies, and costs a dependency besides a secp256k1 authentication.
    #[test]
    #[cfg(feature = "k256")]
    fn statement_authorizations() {
        let actor = StatementActor {
            vk: B256::repeat_byte(9),
            tag: *b"sphmem01",
            key: B256::repeat_byte(4),
        };
        let account = Address::repeat_byte(0xac);
        let tx = TxEip8430 {
            sender: Some(account),
            account_changes: vec![],
            sender_auth: actor.encode(),
            ..transfer()
        };
        tx.validate_static(10).unwrap();
        assert_eq!(tx.authenticate_sender(), Ok((account, Actor::Statement(actor))));
        assert_eq!(tx.dependencies(), vec![actor.dependency(tx.sender_signature_hash())]);
        let declared = tx.declared_dependencies().unwrap();
        assert_eq!((declared.declared, declared.key), (1, tx.sender_signature_hash()));

        // The same bytes under another authenticator are no authorization, priced as secp256k1.
        let mut other = tx.clone();
        let mut auth = other.sender_auth.to_vec();
        auth[0] ^= 0x01;
        other.sender_auth = auth.into();
        assert_eq!(other.sender_authorization(), None);
        assert_eq!(
            tx.sender_intrinsic_gas(account) - other.sender_intrinsic_gas(account),
            actor.auth_cost() - K1_AUTH_COST
        );

        // A STATEMENT payer of a named sender depends on the payer hash.
        let paid = TxEip8430 {
            payer: Payer::Named(Address::repeat_byte(0xbb)),
            payer_auth: actor.encode(),
            ..tx.clone()
        };
        paid.validate_static(10).unwrap();
        assert_eq!(
            paid.authenticate_payer(account),
            Ok(Some((Address::repeat_byte(0xbb), Actor::Statement(actor))))
        );
        assert!(
            paid.dependencies().contains(&actor.dependency(paid.payer_signature_hash(account)))
        );
        assert_eq!(paid.payer_auth_cost(), actor.auth_cost() + standard_cost(&paid.payer_auth));
        assert_eq!(paid.dependency_count(), 2);
        assert_eq!(paid.declared_dependencies().unwrap().declared, 2);

        // An open payer or a recovered sender has no STATEMENT form, and a STATEMENT payer needs a
        // named sender.
        let open = TxEip8430 { payer: Payer::Open, payer_auth: actor.encode(), ..tx.clone() };
        assert_eq!(open.validate_static(10), Err(AaTxError::PayerAuthShape));
        let recovered = TxEip8430 { sender: None, ..tx };
        assert_eq!(recovered.validate_static(10), Err(AaTxError::SenderAuthShape));
        let unnamed = signed(TxEip8430 { sender: None, ..paid });
        assert_eq!(unnamed.validate_static(10), Err(AaTxError::StatementPayerNeedsNamedSender));
    }

    /// A dependency on the signature program costs less than one on any other, declared or as a
    /// STATEMENT authorization, and each is counted once per declaration.
    #[test]
    fn dependencies_are_priced_by_program() {
        let on = |program: B256, times: usize| TxEip8430 {
            account_changes: vec![AccountChange::Dependencies {
                dependencies: vec![
                    Dependency {
                        scheme: PROOF_STATEMENT_SCHEME,
                        data_hash: B256::repeat_byte(1),
                        verification_key_hash: program,
                    };
                    times
                ],
            }],
            ..transfer()
        };
        let signature = on(SIGNATURE_PROGRAM_DIGEST, 1);
        assert_eq!(signature.account_changes_cost(), LEANSPHINCS_VERIFICATION_GAS);
        assert_eq!(on(B256::repeat_byte(7), 1).account_changes_cost(), LEANSTARK_VERIFICATION_GAS);
        assert_eq!(on(SIGNATURE_PROGRAM_DIGEST, 3).dependency_count(), 3, "duplicates count");
        assert_eq!(TxEip8430 { account_changes: vec![], ..transfer() }.dependency_count(), 0);

        let actor = |vk| StatementActor { vk, tag: *b"sphmem01", key: B256::repeat_byte(4) };
        assert_eq!(
            actor(SIGNATURE_PROGRAM_DIGEST).auth_cost(),
            LEANSPHINCS_VERIFICATION_GAS + K1_AUTH_COST
        );
        assert_eq!(
            actor(B256::repeat_byte(9)).auth_cost(),
            LEANSTARK_VERIFICATION_GAS + K1_AUTH_COST
        );
    }
}
