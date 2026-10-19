//! Proof aggregate transaction types.
//!
//! Users register SP1 statements with the `ProofRegistry` predeploy; the statements stay
//! pending until the sequencer includes a proof aggregate transaction. That transaction carries a
//! single SP1 proof of an aggregation program which recursively verifies the proof behind every
//! statement it lists. Executing it verifies the aggregate proof and marks the listed statements
//! verified. The proofs behind the individual statements never reach the chain.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "serde")]
use alloy_consensus::Sealed;
use alloy_consensus::{Sealable, Transaction, Typed2718, transaction::RlpEcdsaEncodableTx};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718, IsTyped2718},
    eip2930::AccessList,
};
use alloy_primitives::{Address, B256, Bytes, ChainId, TxHash, TxKind, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header, RlpDecodable, RlpEncodable};

use crate::OpTransaction;

/// Type byte for the proof aggregate transaction.
pub const PROOF_AGGREGATE_TX_TYPE_ID: u8 = 0x7C;

/// Current format version for [`ProofAggregatePayload`].
pub const PROOF_AGGREGATE_PAYLOAD_VERSION: u8 = 1;

/// A statement that an SP1 program with verifying key `vkey_hash` produced a valid proof committing
/// to public values whose SHA-256 digest is `public_values_digest`.
///
/// Both fields use the encodings the SP1 zkVM's `verify_sp1_proof` takes, so the aggregation
/// program can verify a statement without converting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProofStatement {
    /// The program's verifying key digest: eight `KoalaBear` words, each big-endian.
    pub vkey_hash: B256,
    /// SHA-256 of the program's committed public values.
    pub public_values_digest: B256,
}

impl ProofStatement {
    /// Returns the statement id the `ProofRegistry` predeploy keys the statement by:
    /// `keccak256(vkey_hash || public_values_digest)`.
    pub fn id(&self) -> B256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.vkey_hash.as_slice());
        buf[32..].copy_from_slice(self.public_values_digest.as_slice());
        keccak256(buf)
    }
}

/// The commitment to an ordered list of statements that the aggregation program commits as its
/// public values: `keccak256(vkey_hash_0 || public_values_digest_0 || vkey_hash_1 || ...)`.
pub fn statements_commitment(statements: &[ProofStatement]) -> B256 {
    let mut buf = Vec::with_capacity(statements.len() * 64);
    for statement in statements {
        buf.extend_from_slice(statement.vkey_hash.as_slice());
        buf.extend_from_slice(statement.public_values_digest.as_slice());
    }
    keccak256(buf)
}

/// Payload for the proof aggregate transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProofAggregatePayload {
    /// Format version.
    pub version: u8,
    /// L2 block number the payload is anchored to.
    ///
    /// Included so otherwise identical payloads in different blocks have distinct transaction
    /// hashes.
    pub block_number: u64,
    /// Verifying key digest of the aggregation program, in the [`ProofStatement::vkey_hash`]
    /// encoding. The registry only accepts the aggregation program it is configured with.
    pub aggregation_vkey_hash: B256,
    /// The statements the aggregate proof covers, in the order the aggregation program verified
    /// them.
    pub statements: Vec<ProofStatement>,
    /// The aggregation program's SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
}

// `version` is pinned rather than left arbitrary because `decode_checked` rejects any other value,
// which would break encode/decode roundtrip property tests.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ProofAggregatePayload {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: PROOF_AGGREGATE_PAYLOAD_VERSION,
            block_number: u64::arbitrary(u)?,
            aggregation_vkey_hash: B256::arbitrary(u)?,
            statements: <Vec<ProofStatement>>::arbitrary(u)?,
            proof: Bytes::arbitrary(u)?,
        })
    }
}

impl ProofAggregatePayload {
    /// The commitment the aggregate proof's public values must equal.
    pub fn statements_commitment(&self) -> B256 {
        statements_commitment(&self.statements)
    }

    /// RLP-encode the payload into bytes.
    pub fn to_rlp_bytes(&self) -> Bytes {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.into()
    }

    /// Decode a payload from an RLP stream, validating the payload version.
    ///
    /// Advances `buf` past the consumed bytes, leaving trailing bytes for the caller.
    pub fn decode_checked(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let payload = Self::decode(buf)?;
        if payload.version != PROOF_AGGREGATE_PAYLOAD_VERSION {
            return Err(alloy_rlp::Error::Custom("unsupported proof aggregate payload version"));
        }
        Ok(payload)
    }

    /// Decode a payload from RLP bytes, rejecting other versions and trailing bytes.
    pub fn from_rlp_bytes(data: &[u8]) -> alloy_rlp::Result<Self> {
        let mut buf = data;
        let payload = Self::decode_checked(&mut buf)?;
        if !buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(payload)
    }
}

/// Parsed proof aggregate transaction metadata for a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProofAggregate {
    /// Transaction index of the proof aggregate transaction within the block.
    pub tx_index: u64,
    /// Decoded payload.
    pub payload: ProofAggregatePayload,
}

/// Errors returned while validating a block's proof aggregate transaction structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofAggregateValidationError {
    /// The block contains a proof aggregate transaction before proof aggregation is active.
    #[error(
        "unexpected proof aggregate transaction at index {tx_index}: proof aggregation not active"
    )]
    UnexpectedProofAggregateTx {
        /// Transaction index.
        tx_index: u64,
    },
    /// The block contains more than one proof aggregate transaction.
    #[error(
        "multiple proof aggregate transactions: first at index {first_index}, duplicate at index {duplicate_index}"
    )]
    MultipleProofAggregateTxs {
        /// First proof aggregate tx index.
        first_index: u64,
        /// Duplicate proof aggregate tx index.
        duplicate_index: u64,
    },
    /// The proof aggregate transaction is not the first transaction after the deposits.
    #[error(
        "proof aggregate transaction at index {tx_index} must directly follow the {deposit_count} deposits"
    )]
    ProofAggregateTxMisplaced {
        /// Proof aggregate tx index.
        tx_index: u64,
        /// Number of deposits leading the block.
        deposit_count: u64,
    },
    /// The payload block number does not match the containing block.
    #[error(
        "payload block number {payload_block_number} does not match block number {block_number}"
    )]
    BlockNumberMismatch {
        /// Block number encoded in the payload.
        payload_block_number: u64,
        /// Containing block number.
        block_number: u64,
    },
    /// The payload lists no statements.
    #[error("proof aggregate transaction at index {tx_index} lists no statements")]
    EmptyStatements {
        /// Proof aggregate tx index.
        tx_index: u64,
    },
}

impl ProofAggregateValidationError {
    /// Returns this error as an owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

/// Parse and validate the block-level proof aggregate transaction, if present.
///
/// Enforces the consensus structure rules: proof aggregate transactions are only valid after
/// activation, at most one may be present, it must directly follow the block's leading deposits, it
/// must be anchored to the containing block number, and it must list at least one statement.
///
/// # Errors
///
/// Returns [`ProofAggregateValidationError`] if the transaction is not valid for the block.
pub fn parse_proof_aggregate_from_transactions<'a, I, T>(
    transactions: I,
    block_number: u64,
    proof_aggregation_active: bool,
) -> Result<Option<ParsedProofAggregate>, ProofAggregateValidationError>
where
    I: IntoIterator<Item = &'a T>,
    T: OpTransaction + 'a,
{
    let mut parsed = None::<ParsedProofAggregate>;
    let mut deposit_count = 0u64;
    let mut in_deposit_prefix = true;

    for (idx, tx) in transactions.into_iter().enumerate() {
        let tx_index = idx as u64;
        if in_deposit_prefix && tx.is_deposit() {
            deposit_count += 1;
            continue;
        }
        in_deposit_prefix = false;

        let Some(aggregate) = tx.as_proof_aggregate() else {
            continue;
        };

        if !proof_aggregation_active {
            return Err(ProofAggregateValidationError::UnexpectedProofAggregateTx { tx_index });
        }
        if let Some(first) = &parsed {
            return Err(ProofAggregateValidationError::MultipleProofAggregateTxs {
                first_index: first.tx_index,
                duplicate_index: tx_index,
            });
        }
        if tx_index != deposit_count {
            return Err(ProofAggregateValidationError::ProofAggregateTxMisplaced {
                tx_index,
                deposit_count,
            });
        }

        let payload = aggregate.inner().payload.clone();
        if payload.block_number != block_number {
            return Err(ProofAggregateValidationError::BlockNumberMismatch {
                payload_block_number: payload.block_number,
                block_number,
            });
        }
        if payload.statements.is_empty() {
            return Err(ProofAggregateValidationError::EmptyStatements { tx_index });
        }

        parsed = Some(ParsedProofAggregate { tx_index, payload });
    }

    Ok(parsed)
}

/// Proof aggregate transaction carrying a [`ProofAggregatePayload`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(into = "ProofAggregatePayload", from = "ProofAggregatePayload")
)]
pub struct TxProofAggregate {
    /// Decoded payload.
    pub payload: ProofAggregatePayload,
    /// RLP-encoded payload bytes used as the transaction input.
    pub input: Bytes,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for TxProofAggregate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Keep `payload` and the cached `input` bytes in sync for fuzzed values.
        Ok(Self::new(ProofAggregatePayload::arbitrary(u)?))
    }
}

impl From<ProofAggregatePayload> for TxProofAggregate {
    fn from(payload: ProofAggregatePayload) -> Self {
        Self::new(payload)
    }
}

impl From<TxProofAggregate> for ProofAggregatePayload {
    fn from(tx: TxProofAggregate) -> Self {
        tx.payload
    }
}

impl TxProofAggregate {
    /// Construct a proof aggregate transaction from its decoded payload.
    pub fn new(payload: ProofAggregatePayload) -> Self {
        let input = payload.to_rlp_bytes();
        Self { payload, input }
    }

    /// Returns the canonical signature for proof aggregate transactions, which are unsigned.
    pub const fn signature() -> alloy_primitives::Signature {
        alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false)
    }

    /// Returns the canonical signer address for proof aggregate transactions.
    pub const fn signer_address(&self) -> Address {
        Address::ZERO
    }

    /// Decodes the transaction from RLP bytes.
    pub fn rlp_decode(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::new(ProofAggregatePayload::decode_checked(data)?))
    }

    /// Encoded length of the transaction body.
    pub fn rlp_encoded_length(&self) -> usize {
        self.input.len()
    }

    /// Encoded length including the type byte.
    pub fn eip2718_encoded_length(&self) -> usize {
        self.rlp_encoded_length() + 1
    }

    fn network_header(&self) -> Header {
        Header { list: false, payload_length: self.eip2718_encoded_length() }
    }

    /// Encoded length including the outer network RLP header.
    pub fn network_encoded_length(&self) -> usize {
        self.network_header().length_with_payload()
    }

    /// Network encode the transaction.
    pub fn network_encode(&self, out: &mut dyn BufMut) {
        self.network_header().encode(out);
        self.encode_2718(out);
    }

    /// Calculates a heuristic for the in-memory size of the transaction.
    pub fn size(&self) -> usize {
        core::mem::size_of::<ProofAggregatePayload>() +
            self.input.len() +
            self.payload.proof.len() +
            self.payload.statements.len() * core::mem::size_of::<ProofStatement>()
    }

    /// Calculate the transaction hash.
    pub fn tx_hash(&self) -> TxHash {
        let mut buf = Vec::with_capacity(self.eip2718_encoded_length());
        self.encode_2718(&mut buf);
        keccak256(&buf)
    }
}

impl Typed2718 for TxProofAggregate {
    fn ty(&self) -> u8 {
        PROOF_AGGREGATE_TX_TYPE_ID
    }
}

impl IsTyped2718 for TxProofAggregate {
    fn is_type(ty: u8) -> bool {
        ty == PROOF_AGGREGATE_TX_TYPE_ID
    }
}

impl RlpEcdsaEncodableTx for TxProofAggregate {
    fn rlp_encoded_fields_length(&self) -> usize {
        self.input.len()
    }

    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        // `input` already stores the canonical RLP-encoded payload, so it is written as-is instead
        // of being wrapped in an additional RLP list.
        out.put_slice(self.input.as_ref());
    }
}

impl Transaction for TxProofAggregate {
    fn chain_id(&self) -> Option<ChainId> {
        None
    }
    fn nonce(&self) -> u64 {
        0
    }
    fn gas_limit(&self) -> u64 {
        0
    }
    fn gas_price(&self) -> Option<u128> {
        None
    }
    fn max_fee_per_gas(&self) -> u128 {
        0
    }
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        None
    }
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }
    fn priority_fee_or_price(&self) -> u128 {
        0
    }
    fn effective_gas_price(&self, _: Option<u64>) -> u128 {
        0
    }
    fn is_dynamic_fee(&self) -> bool {
        false
    }
    fn kind(&self) -> TxKind {
        // The executor drives the registry call itself; expose a zero-address call placeholder.
        TxKind::Call(Default::default())
    }
    fn is_create(&self) -> bool {
        false
    }
    fn value(&self) -> U256 {
        U256::ZERO
    }
    fn input(&self) -> &Bytes {
        &self.input
    }
    fn access_list(&self) -> Option<&AccessList> {
        None
    }
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }
    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

impl Encodable2718 for TxProofAggregate {
    fn type_flag(&self) -> Option<u8> {
        Some(PROOF_AGGREGATE_TX_TYPE_ID)
    }
    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }
    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(PROOF_AGGREGATE_TX_TYPE_ID);
        out.put_slice(self.input.as_ref());
    }
}

impl Decodable2718 for TxProofAggregate {
    fn typed_decode(ty: u8, data: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != PROOF_AGGREGATE_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::rlp_decode(data)?)
    }

    fn fallback_decode(_data: &mut &[u8]) -> Eip2718Result<Self> {
        // Proof aggregate transactions have no untyped form.
        Err(Eip2718Error::UnexpectedType(PROOF_AGGREGATE_TX_TYPE_ID))
    }
}

impl Encodable for TxProofAggregate {
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_slice(self.input.as_ref());
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxProofAggregate {
    fn decode(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(data)
    }
}

impl Sealable for TxProofAggregate {
    fn hash_slow(&self) -> B256 {
        self.tx_hash()
    }
}

#[cfg(feature = "alloy-compat")]
impl From<TxProofAggregate> for alloy_rpc_types_eth::TransactionRequest {
    fn from(tx: TxProofAggregate) -> Self {
        Self {
            from: Some(tx.signer_address()),
            transaction_type: Some(PROOF_AGGREGATE_TX_TYPE_ID),
            gas: Some(0),
            nonce: Some(0),
            value: Some(U256::ZERO),
            input: tx.input.into(),
            ..Default::default()
        }
    }
}

/// Build a proof aggregate transaction.
pub fn build_proof_aggregate_tx(
    block_number: u64,
    aggregation_vkey_hash: B256,
    statements: Vec<ProofStatement>,
    proof: Bytes,
) -> TxProofAggregate {
    TxProofAggregate::new(ProofAggregatePayload {
        version: PROOF_AGGREGATE_PAYLOAD_VERSION,
        block_number,
        aggregation_vkey_hash,
        statements,
        proof,
    })
}

/// Proof aggregate transactions serialize as full RPC transaction objects when embedded in a
/// [`crate::OpTxEnvelope`] response, with the canonical `input` field so go-ethereum types can
/// decode them.
#[cfg(feature = "serde")]
pub fn serde_proof_aggregate_tx_rpc<S>(
    value: &Sealed<TxProofAggregate>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;

    #[derive(Serialize)]
    struct SerdeHelper<'a> {
        hash: B256,
        #[serde(rename = "type", with = "alloy_serde::quantity")]
        tx_type: u8,
        #[serde(with = "alloy_serde::quantity")]
        gas: u64,
        value: U256,
        input: &'a Bytes,
    }

    SerdeHelper {
        hash: value.hash(),
        tx_type: PROOF_AGGREGATE_TX_TYPE_ID,
        gas: 0,
        value: U256::ZERO,
        input: &value.inner().input,
    }
    .serialize(serializer)
}

/// Deserialize a proof aggregate transaction from its RPC representation, the counterpart to
/// [`serde_proof_aggregate_tx_rpc`]. The payload is decoded from `input`; the RPC-provided `hash`
/// is reused so the sealed transaction round-trips without recomputation.
#[cfg(feature = "serde")]
pub fn serde_proof_aggregate_tx_rpc_de<'de, D>(
    deserializer: D,
) -> Result<Sealed<TxProofAggregate>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SerdeHelper {
        hash: B256,
        input: Bytes,
    }

    let SerdeHelper { hash, input } = SerdeHelper::deserialize(deserializer)?;
    let payload =
        ProofAggregatePayload::from_rlp_bytes(input.as_ref()).map_err(serde::de::Error::custom)?;
    Ok(Sealed::new_unchecked(TxProofAggregate::new(payload), hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{b256, bytes};

    fn sample() -> TxProofAggregate {
        build_proof_aggregate_tx(
            7,
            b256!("0x00000001000000020000000300000004000000050000000600000007000000ff"),
            vec![
                ProofStatement {
                    vkey_hash: B256::repeat_byte(0x11),
                    public_values_digest: B256::ZERO,
                },
                ProofStatement {
                    vkey_hash: B256::repeat_byte(0x22),
                    public_values_digest: B256::repeat_byte(0x33),
                },
            ],
            bytes!("deadbeef"),
        )
    }

    #[test]
    fn roundtrip_2718() {
        let tx = sample();
        let encoded = tx.encoded_2718();
        assert_eq!(encoded[0], PROOF_AGGREGATE_TX_TYPE_ID);
        let decoded = TxProofAggregate::decode_2718_exact(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut payload = sample().payload;
        payload.version = 2;
        let raw = payload.to_rlp_bytes();
        assert!(ProofAggregatePayload::from_rlp_bytes(&raw).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut raw = sample().input.to_vec();
        raw.push(0);
        assert!(ProofAggregatePayload::from_rlp_bytes(&raw).is_err());
    }

    #[test]
    fn commitment_is_concatenated_keccak() {
        let statements = sample().payload.statements;
        let mut buf = Vec::new();
        for statement in &statements {
            buf.extend_from_slice(statement.vkey_hash.as_slice());
            buf.extend_from_slice(statement.public_values_digest.as_slice());
        }
        assert_eq!(statements_commitment(&statements), keccak256(buf));
        assert_eq!(statements_commitment(&[]), keccak256([]));
    }

    /// Golden vector shared with op-core's `TestProofAggregateTxHashGoldenVector` (Go): the
    /// canonical encoding and hash of a 0x7C transaction.
    #[test]
    fn proof_aggregate_tx_golden_vector() {
        let tx = build_proof_aggregate_tx(
            42,
            B256::repeat_byte(0xaa),
            vec![ProofStatement {
                vkey_hash: B256::repeat_byte(0x11),
                public_values_digest: B256::repeat_byte(0x22),
            }],
            bytes!("deadbeef"),
        );
        assert_eq!(
            alloy_primitives::hex::encode(tx.encoded_2718()),
            "7cf86e012aa0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0\
             1111111111111111111111111111111111111111111111111111111111111111a022222222222222222222\
             2222222222222222222222222222222222222222222284deadbeef"
        );
        assert_eq!(
            tx.tx_hash(),
            b256!("0x03f4ebe12e9cb4814835bdb10dff45302f484edc3eaeff030cdb6c518dcde956")
        );
    }

    /// Golden vector shared with `ProofRegistry_StatementId_Test` in contracts-bedrock.
    #[test]
    fn statement_id_matches_registry_encoding() {
        let statement = sample().payload.statements[1];
        assert_eq!(
            statement.id(),
            b256!("0xf3357627f4934d47fe409005b05c900777a6d97ec3788304e2d9c7b4d322cd4d")
        );
    }
}
