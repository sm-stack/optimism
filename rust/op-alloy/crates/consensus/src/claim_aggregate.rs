//! Claim aggregate transaction types.
//!
//! Users register SP1 proof claims with the `ProofClaimRegistry` predeploy; the claims stay
//! pending until the sequencer includes a claim aggregate transaction. That transaction carries a
//! single SP1 proof of an aggregation program which recursively verifies the proof behind every
//! claim it lists. Executing it verifies the aggregate proof and marks the listed claims verified.
//! The individual claim proofs never reach the chain.

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

/// Type byte for the claim aggregate transaction.
pub const CLAIM_AGGREGATE_TX_TYPE_ID: u8 = 0x7C;

/// Current format version for [`ClaimAggregatePayload`].
pub const CLAIM_AGGREGATE_PAYLOAD_VERSION: u8 = 1;

/// A claim that an SP1 program with verifying key `vkey_hash` produced a valid proof committing to
/// public values whose SHA-256 digest is `public_values_digest`.
///
/// Both fields use the encodings the SP1 zkVM's `verify_sp1_proof` takes, so the aggregation
/// program can verify a claim without converting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProofClaim {
    /// The program's verifying key digest: eight `KoalaBear` words, each big-endian.
    pub vkey_hash: B256,
    /// SHA-256 of the program's committed public values.
    pub public_values_digest: B256,
}

impl ProofClaim {
    /// Returns the claim id the `ProofClaimRegistry` predeploy keys the claim by:
    /// `keccak256(vkey_hash || public_values_digest)`.
    pub fn id(&self) -> B256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.vkey_hash.as_slice());
        buf[32..].copy_from_slice(self.public_values_digest.as_slice());
        keccak256(buf)
    }
}

/// The commitment to an ordered list of claims that the aggregation program commits as its public
/// values: `keccak256(vkey_hash_0 || public_values_digest_0 || vkey_hash_1 || ...)`.
pub fn claims_commitment(claims: &[ProofClaim]) -> B256 {
    let mut buf = Vec::with_capacity(claims.len() * 64);
    for claim in claims {
        buf.extend_from_slice(claim.vkey_hash.as_slice());
        buf.extend_from_slice(claim.public_values_digest.as_slice());
    }
    keccak256(buf)
}

/// Payload for the claim aggregate transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ClaimAggregatePayload {
    /// Format version.
    pub version: u8,
    /// L2 block number the payload is anchored to.
    ///
    /// Included so otherwise identical payloads in different blocks have distinct transaction
    /// hashes.
    pub block_number: u64,
    /// Verifying key digest of the aggregation program, in the [`ProofClaim::vkey_hash`]
    /// encoding. The registry only accepts the aggregation program it is configured with.
    pub aggregation_vkey_hash: B256,
    /// The claims the aggregate proof covers, in the order the aggregation program verified them.
    pub claims: Vec<ProofClaim>,
    /// The aggregation program's SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
}

// `version` is pinned rather than left arbitrary because `decode_checked` rejects any other value,
// which would break encode/decode roundtrip property tests.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ClaimAggregatePayload {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: CLAIM_AGGREGATE_PAYLOAD_VERSION,
            block_number: u64::arbitrary(u)?,
            aggregation_vkey_hash: B256::arbitrary(u)?,
            claims: <Vec<ProofClaim>>::arbitrary(u)?,
            proof: Bytes::arbitrary(u)?,
        })
    }
}

impl ClaimAggregatePayload {
    /// The commitment the aggregate proof's public values must equal.
    pub fn claims_commitment(&self) -> B256 {
        claims_commitment(&self.claims)
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
        if payload.version != CLAIM_AGGREGATE_PAYLOAD_VERSION {
            return Err(alloy_rlp::Error::Custom("unsupported claim aggregate payload version"));
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

/// Parsed claim aggregate transaction metadata for a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClaimAggregate {
    /// Transaction index of the claim aggregate transaction within the block.
    pub tx_index: u64,
    /// Decoded payload.
    pub payload: ClaimAggregatePayload,
}

/// Errors returned while validating a block's claim aggregate transaction structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimAggregateValidationError {
    /// The block contains a claim aggregate transaction before proof claims are active.
    #[error("unexpected claim aggregate transaction at index {tx_index}: proof claims not active")]
    UnexpectedClaimAggregateTx {
        /// Transaction index.
        tx_index: u64,
    },
    /// The block contains more than one claim aggregate transaction.
    #[error(
        "multiple claim aggregate transactions: first at index {first_index}, duplicate at index {duplicate_index}"
    )]
    MultipleClaimAggregateTxs {
        /// First claim aggregate tx index.
        first_index: u64,
        /// Duplicate claim aggregate tx index.
        duplicate_index: u64,
    },
    /// The claim aggregate transaction is not the first transaction after the deposits.
    #[error(
        "claim aggregate transaction at index {tx_index} must directly follow the {deposit_count} deposits"
    )]
    ClaimAggregateTxMisplaced {
        /// Claim aggregate tx index.
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
    /// The payload lists no claims.
    #[error("claim aggregate transaction at index {tx_index} lists no claims")]
    EmptyClaims {
        /// Claim aggregate tx index.
        tx_index: u64,
    },
}

impl ClaimAggregateValidationError {
    /// Returns this error as an owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

/// Parse and validate the block-level claim aggregate transaction, if present.
///
/// Enforces the consensus structure rules: claim aggregate transactions are only valid after
/// activation, at most one may be present, it must directly follow the block's leading deposits, it
/// must be anchored to the containing block number, and it must list at least one claim.
///
/// # Errors
///
/// Returns [`ClaimAggregateValidationError`] if the transaction is not valid for the block.
pub fn parse_claim_aggregate_from_transactions<'a, I, T>(
    transactions: I,
    block_number: u64,
    proof_claims_active: bool,
) -> Result<Option<ParsedClaimAggregate>, ClaimAggregateValidationError>
where
    I: IntoIterator<Item = &'a T>,
    T: OpTransaction + 'a,
{
    let mut parsed = None::<ParsedClaimAggregate>;
    let mut deposit_count = 0u64;
    let mut in_deposit_prefix = true;

    for (idx, tx) in transactions.into_iter().enumerate() {
        let tx_index = idx as u64;
        if in_deposit_prefix && tx.is_deposit() {
            deposit_count += 1;
            continue;
        }
        in_deposit_prefix = false;

        let Some(aggregate) = tx.as_claim_aggregate() else {
            continue;
        };

        if !proof_claims_active {
            return Err(ClaimAggregateValidationError::UnexpectedClaimAggregateTx { tx_index });
        }
        if let Some(first) = &parsed {
            return Err(ClaimAggregateValidationError::MultipleClaimAggregateTxs {
                first_index: first.tx_index,
                duplicate_index: tx_index,
            });
        }
        if tx_index != deposit_count {
            return Err(ClaimAggregateValidationError::ClaimAggregateTxMisplaced {
                tx_index,
                deposit_count,
            });
        }

        let payload = aggregate.inner().payload.clone();
        if payload.block_number != block_number {
            return Err(ClaimAggregateValidationError::BlockNumberMismatch {
                payload_block_number: payload.block_number,
                block_number,
            });
        }
        if payload.claims.is_empty() {
            return Err(ClaimAggregateValidationError::EmptyClaims { tx_index });
        }

        parsed = Some(ParsedClaimAggregate { tx_index, payload });
    }

    Ok(parsed)
}

/// Claim aggregate transaction carrying a [`ClaimAggregatePayload`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(into = "ClaimAggregatePayload", from = "ClaimAggregatePayload")
)]
pub struct TxClaimAggregate {
    /// Decoded payload.
    pub payload: ClaimAggregatePayload,
    /// RLP-encoded payload bytes used as the transaction input.
    pub input: Bytes,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for TxClaimAggregate {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Keep `payload` and the cached `input` bytes in sync for fuzzed values.
        Ok(Self::new(ClaimAggregatePayload::arbitrary(u)?))
    }
}

impl From<ClaimAggregatePayload> for TxClaimAggregate {
    fn from(payload: ClaimAggregatePayload) -> Self {
        Self::new(payload)
    }
}

impl From<TxClaimAggregate> for ClaimAggregatePayload {
    fn from(tx: TxClaimAggregate) -> Self {
        tx.payload
    }
}

impl TxClaimAggregate {
    /// Construct a claim aggregate transaction from its decoded payload.
    pub fn new(payload: ClaimAggregatePayload) -> Self {
        let input = payload.to_rlp_bytes();
        Self { payload, input }
    }

    /// Returns the canonical signature for claim aggregate transactions, which are unsigned.
    pub const fn signature() -> alloy_primitives::Signature {
        alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false)
    }

    /// Returns the canonical signer address for claim aggregate transactions.
    pub const fn signer_address(&self) -> Address {
        Address::ZERO
    }

    /// Decodes the transaction from RLP bytes.
    pub fn rlp_decode(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::new(ClaimAggregatePayload::decode_checked(data)?))
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
        core::mem::size_of::<ClaimAggregatePayload>() +
            self.input.len() +
            self.payload.proof.len() +
            self.payload.claims.len() * core::mem::size_of::<ProofClaim>()
    }

    /// Calculate the transaction hash.
    pub fn tx_hash(&self) -> TxHash {
        let mut buf = Vec::with_capacity(self.eip2718_encoded_length());
        self.encode_2718(&mut buf);
        keccak256(&buf)
    }
}

impl Typed2718 for TxClaimAggregate {
    fn ty(&self) -> u8 {
        CLAIM_AGGREGATE_TX_TYPE_ID
    }
}

impl IsTyped2718 for TxClaimAggregate {
    fn is_type(ty: u8) -> bool {
        ty == CLAIM_AGGREGATE_TX_TYPE_ID
    }
}

impl RlpEcdsaEncodableTx for TxClaimAggregate {
    fn rlp_encoded_fields_length(&self) -> usize {
        self.input.len()
    }

    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        // `input` already stores the canonical RLP-encoded payload, so it is written as-is instead
        // of being wrapped in an additional RLP list.
        out.put_slice(self.input.as_ref());
    }
}

impl Transaction for TxClaimAggregate {
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

impl Encodable2718 for TxClaimAggregate {
    fn type_flag(&self) -> Option<u8> {
        Some(CLAIM_AGGREGATE_TX_TYPE_ID)
    }
    fn encode_2718_len(&self) -> usize {
        self.eip2718_encoded_length()
    }
    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(CLAIM_AGGREGATE_TX_TYPE_ID);
        out.put_slice(self.input.as_ref());
    }
}

impl Decodable2718 for TxClaimAggregate {
    fn typed_decode(ty: u8, data: &mut &[u8]) -> Eip2718Result<Self> {
        if ty != CLAIM_AGGREGATE_TX_TYPE_ID {
            return Err(Eip2718Error::UnexpectedType(ty));
        }
        Ok(Self::rlp_decode(data)?)
    }

    fn fallback_decode(_data: &mut &[u8]) -> Eip2718Result<Self> {
        // Claim aggregate transactions have no untyped form.
        Err(Eip2718Error::UnexpectedType(CLAIM_AGGREGATE_TX_TYPE_ID))
    }
}

impl Encodable for TxClaimAggregate {
    fn encode(&self, out: &mut dyn BufMut) {
        out.put_slice(self.input.as_ref());
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxClaimAggregate {
    fn decode(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(data)
    }
}

impl Sealable for TxClaimAggregate {
    fn hash_slow(&self) -> B256 {
        self.tx_hash()
    }
}

#[cfg(feature = "alloy-compat")]
impl From<TxClaimAggregate> for alloy_rpc_types_eth::TransactionRequest {
    fn from(tx: TxClaimAggregate) -> Self {
        Self {
            from: Some(tx.signer_address()),
            transaction_type: Some(CLAIM_AGGREGATE_TX_TYPE_ID),
            gas: Some(0),
            nonce: Some(0),
            value: Some(U256::ZERO),
            input: tx.input.into(),
            ..Default::default()
        }
    }
}

/// Build a claim aggregate transaction.
pub fn build_claim_aggregate_tx(
    block_number: u64,
    aggregation_vkey_hash: B256,
    claims: Vec<ProofClaim>,
    proof: Bytes,
) -> TxClaimAggregate {
    TxClaimAggregate::new(ClaimAggregatePayload {
        version: CLAIM_AGGREGATE_PAYLOAD_VERSION,
        block_number,
        aggregation_vkey_hash,
        claims,
        proof,
    })
}

/// Claim aggregate transactions serialize as full RPC transaction objects when embedded in a
/// [`crate::OpTxEnvelope`] response, with the canonical `input` field so go-ethereum types can
/// decode them.
#[cfg(feature = "serde")]
pub fn serde_claim_aggregate_tx_rpc<S>(
    value: &Sealed<TxClaimAggregate>,
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
        tx_type: CLAIM_AGGREGATE_TX_TYPE_ID,
        gas: 0,
        value: U256::ZERO,
        input: &value.inner().input,
    }
    .serialize(serializer)
}

/// Deserialize a claim aggregate transaction from its RPC representation, the counterpart to
/// [`serde_claim_aggregate_tx_rpc`]. The payload is decoded from `input`; the RPC-provided `hash`
/// is reused so the sealed transaction round-trips without recomputation.
#[cfg(feature = "serde")]
pub fn serde_claim_aggregate_tx_rpc_de<'de, D>(
    deserializer: D,
) -> Result<Sealed<TxClaimAggregate>, D::Error>
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
        ClaimAggregatePayload::from_rlp_bytes(input.as_ref()).map_err(serde::de::Error::custom)?;
    Ok(Sealed::new_unchecked(TxClaimAggregate::new(payload), hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{b256, bytes};

    fn sample() -> TxClaimAggregate {
        build_claim_aggregate_tx(
            7,
            b256!("0x00000001000000020000000300000004000000050000000600000007000000ff"),
            vec![
                ProofClaim { vkey_hash: B256::repeat_byte(0x11), public_values_digest: B256::ZERO },
                ProofClaim {
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
        assert_eq!(encoded[0], CLAIM_AGGREGATE_TX_TYPE_ID);
        let decoded = TxClaimAggregate::decode_2718_exact(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut payload = sample().payload;
        payload.version = 2;
        let raw = payload.to_rlp_bytes();
        assert!(ClaimAggregatePayload::from_rlp_bytes(&raw).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut raw = sample().input.to_vec();
        raw.push(0);
        assert!(ClaimAggregatePayload::from_rlp_bytes(&raw).is_err());
    }

    #[test]
    fn commitment_is_concatenated_keccak() {
        let claims = sample().payload.claims;
        let mut buf = Vec::new();
        for claim in &claims {
            buf.extend_from_slice(claim.vkey_hash.as_slice());
            buf.extend_from_slice(claim.public_values_digest.as_slice());
        }
        assert_eq!(claims_commitment(&claims), keccak256(buf));
        assert_eq!(claims_commitment(&[]), keccak256([]));
    }

    #[test]
    fn claim_id_matches_registry_encoding() {
        let claim = sample().payload.claims[1];
        assert_eq!(claim.id(), keccak256([[0x22u8; 32], [0x33u8; 32]].concat()));
    }
}
