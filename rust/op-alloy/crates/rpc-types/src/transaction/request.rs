use alloc::{vec, vec::Vec};
use alloy_consensus::{
    Sealed, SignableTransaction, Signed, TxEip1559, TxEip4844, TypedTransaction,
};
use alloy_eips::eip7702::SignedAuthorization;
use alloy_network_primitives::TransactionBuilder7702;
use alloy_primitives::{Address, Signature, TxKind, U256};
#[cfg(feature = "std")]
use alloy_primitives::{Bytes, ChainId};
use alloy_rpc_types_eth::{AccessList, TransactionInput, TransactionRequest};
use op_alloy_consensus::{
    AA_TX_TYPE_ID, AaCall, AccountChange, OpTxEnvelope, OpTypedTransaction, POST_EXEC_TX_TYPE_ID,
    Payer, TxDeposit, TxEip8430, TxPostExec,
};
use serde::{Deserialize, Serialize};

/// Builder for [`OpTypedTransaction`]: a standard transaction request, plus the fields of an
/// [EIP-8430] transaction when it describes one.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
///
/// Deserializing an EIP-8430 request (typed `0x79`, or carrying any EIP-8430 field) checks it as
/// EIP-8430's RPC extension asks: `sender` and `from` must agree, and `from` takes `sender` when it
/// is absent, so the node resolves the nonce of the account that sends; the standard call fields
/// (`to`, `value`, `input`, access and authorization lists) must be empty, since calls live in
/// `calls`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RequestRepr")]
pub struct OpTransactionRequest {
    #[serde(flatten)]
    inner: TransactionRequest,
    /// The EIP-8430 fields, all absent for other transaction types.
    #[serde(flatten)]
    aa: AaRequestFields,
}

/// The wire form of [`OpTransactionRequest`], before its EIP-8430 checks.
#[derive(Deserialize)]
struct RequestRepr {
    #[serde(flatten)]
    inner: TransactionRequest,
    #[serde(flatten)]
    aa: AaRequestFields,
}

impl TryFrom<RequestRepr> for OpTransactionRequest {
    type Error = &'static str;

    fn try_from(RequestRepr { mut inner, aa }: RequestRepr) -> Result<Self, Self::Error> {
        let request = Self { inner: inner.clone(), aa: aa.clone() };
        if !request.is_aa() {
            return Ok(request);
        }
        if inner.transaction_type.is_some_and(|ty| ty != AA_TX_TYPE_ID) {
            return Err("EIP-8430 fields on a request of another type");
        }
        if inner.to.is_some() ||
            inner.value.is_some_and(|value| !value.is_zero()) ||
            inner.input.input().is_some_and(|input| !input.is_empty()) ||
            inner.access_list.as_ref().is_some_and(|list| !list.is_empty()) ||
            inner.authorization_list.as_ref().is_some_and(|list| !list.is_empty())
        {
            return Err(
                "an EIP-8430 request carries its calls in `calls`, not in to, value or input",
            );
        }
        match (aa.sender, inner.from) {
            (Some(sender), Some(from)) if sender != from => {
                return Err("an EIP-8430 request's sender and from differ");
            }
            (Some(sender), None) => inner.from = Some(sender),
            _ => {}
        }
        Ok(Self { inner, aa })
    }
}

/// The fields an [EIP-8430] transaction adds to a transaction request (EIP-8430's RPC extension):
/// `eth_call` and `eth_estimateGas` execute a request carrying them, or typed `0x79`, as an
/// EIP-8430 transaction. `nonce` and `gas` are the standard fields; the sender is `sender` or
/// `from`.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AaRequestFields {
    /// The named sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<Address>,
    /// The nonce channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<U256>,
    /// Lower bound of the validity window.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "alloy_serde::quantity::opt")]
    pub valid_after: Option<u64>,
    /// Upper bound of the validity window.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "alloy_serde::quantity::opt")]
    pub valid_before: Option<u64>,
    /// Typed entries applied before the calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_changes: Option<Vec<AccountChange>>,
    /// Phases of calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<Vec<AaCall>>>,
    /// Opaque bytes, signed and charged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<alloy_primitives::Bytes>,
    /// Who pays: its wire bytes, empty for self-pay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<Payer>,
    /// The sender's authorization: a STATEMENT one is used as it is, another only by its shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_auth: Option<alloy_primitives::Bytes>,
    /// The payer's authorization: a STATEMENT one is used as it is, another only by its shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_auth: Option<alloy_primitives::Bytes>,
}

impl From<TransactionRequest> for OpTransactionRequest {
    fn from(inner: TransactionRequest) -> Self {
        Self::from_request(inner)
    }
}

impl AsRef<TransactionRequest> for OpTransactionRequest {
    fn as_ref(&self) -> &TransactionRequest {
        &self.inner
    }
}

impl AsMut<TransactionRequest> for OpTransactionRequest {
    fn as_mut(&mut self) -> &mut TransactionRequest {
        &mut self.inner
    }
}

impl OpTransactionRequest {
    /// A request with no EIP-8430 fields.
    pub fn from_request(inner: TransactionRequest) -> Self {
        Self { inner, aa: AaRequestFields::default() }
    }

    /// The EIP-8430 fields.
    pub const fn aa(&self) -> &AaRequestFields {
        &self.aa
    }

    /// Mutable access to the EIP-8430 fields.
    pub const fn aa_mut(&mut self) -> &mut AaRequestFields {
        &mut self.aa
    }

    /// Whether the request describes an EIP-8430 transaction: typed `0x79`, or carrying any of
    /// its fields.
    pub fn is_aa(&self) -> bool {
        self.inner.transaction_type == Some(AA_TX_TYPE_ID) || self.aa != AaRequestFields::default()
    }

    /// The EIP-8430 transaction the request describes, for a simulation (`eth_call`,
    /// `eth_estimateGas`), with the chain id, the nonce and the effective gas limit the node
    /// resolved.
    ///
    /// Signatures are never verified, so authorizations only need their shape, and are priced as
    /// non-zero bytes so that a zero-filled dummy never underestimates: a supplied blob keeps its
    /// length and a named role's authenticator (a STATEMENT one, which names its actor, is kept
    /// whole), a missing one is a secp256k1 placeholder of the role's form. Missing fee caps are
    /// full-width placeholders, so the transaction's own encoding never prices higher than the
    /// simulation; they only shape it, as the simulation pays the prices the node resolved for
    /// the request.
    pub fn aa_simulation_tx(&self, chain_id: u64, nonce: u64, gas: u64) -> TxEip8430 {
        const PLACEHOLDER_FEE: u128 = u64::MAX as u128;
        let fields = &self.aa;
        let payer = fields.payer.unwrap_or_default();
        // A blob of `len` non-zero bytes, keeping a named role's authenticator. A STATEMENT
        // authorization carries no signature, only its actor, so it is kept as it is.
        let shape = |supplied: Option<&alloy_primitives::Bytes>, named: bool, len: usize| {
            if let Some(blob) = supplied
                .filter(|blob| named && op_alloy_consensus::StatementActor::decode(blob).is_some())
            {
                return blob.clone();
            }
            let mut blob = supplied.map_or_else(|| vec![0xff; len], |blob| vec![0xff; blob.len()]);
            if named {
                let authenticator = supplied
                    .and_then(|blob| blob.get(..20))
                    .unwrap_or(op_alloy_consensus::K1_AUTHENTICATOR.as_slice());
                let n = authenticator.len().min(blob.len());
                blob[..n].copy_from_slice(&authenticator[..n]);
            }
            alloy_primitives::Bytes::from(blob)
        };
        let named_sender = fields.sender.is_some();
        let sender_auth =
            shape(fields.sender_auth.as_ref(), named_sender, if named_sender { 85 } else { 65 });
        let payer_auth = match payer {
            Payer::SelfPay => alloy_primitives::Bytes::new(),
            Payer::Open => shape(fields.payer_auth.as_ref(), false, 65),
            Payer::Named(_) => shape(fields.payer_auth.as_ref(), true, 85),
        };
        let mut tx = TxEip8430 {
            chain_id,
            sender: fields.sender,
            nonce_key: fields.nonce_key.unwrap_or_default(),
            nonce_sequence: nonce,
            valid_after: fields.valid_after.unwrap_or_default(),
            valid_before: fields.valid_before.unwrap_or_default(),
            max_priority_fee_per_gas: self
                .inner
                .max_priority_fee_per_gas
                .unwrap_or(PLACEHOLDER_FEE),
            max_fee_per_gas: self
                .inner
                .max_fee_per_gas
                .or(self.inner.gas_price)
                .unwrap_or(PLACEHOLDER_FEE),
            gas_limit: 0,
            account_changes: fields.account_changes.clone().unwrap_or_default(),
            calls: fields.calls.clone().unwrap_or_default(),
            metadata: fields.metadata.clone().unwrap_or_default(),
            payer,
            sender_auth,
            payer_auth,
        };
        tx.gas_limit = gas.saturating_sub(tx.payer_gas_reserve());
        tx
    }

    /// Sets the `from` field in the call to the provided address
    #[inline]
    pub const fn from(mut self, from: Address) -> Self {
        self.inner.from = Some(from);
        self
    }

    /// Sets the transactions type for the transactions.
    #[doc(alias = "tx_type")]
    pub const fn transaction_type(mut self, transaction_type: u8) -> Self {
        self.inner.transaction_type = Some(transaction_type);
        self
    }

    /// Sets the gas limit for the transaction.
    pub const fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.inner.gas = Some(gas_limit);
        self
    }

    /// Sets the nonce for the transaction.
    pub const fn nonce(mut self, nonce: u64) -> Self {
        self.inner.nonce = Some(nonce);
        self
    }

    /// Sets the maximum fee per gas for the transaction.
    pub const fn max_fee_per_gas(mut self, max_fee_per_gas: u128) -> Self {
        self.inner.max_fee_per_gas = Some(max_fee_per_gas);
        self
    }

    /// Sets the maximum priority fee per gas for the transaction.
    pub const fn max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: u128) -> Self {
        self.inner.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        self
    }

    /// Sets the recipient address for the transaction.
    #[inline]
    pub const fn to(mut self, to: Address) -> Self {
        self.inner.to = Some(TxKind::Call(to));
        self
    }

    /// Sets the value (amount) for the transaction.
    pub const fn value(mut self, value: U256) -> Self {
        self.inner.value = Some(value);
        self
    }

    /// Sets the access list for the transaction.
    pub fn access_list(mut self, access_list: AccessList) -> Self {
        self.inner.access_list = Some(access_list);
        self
    }

    /// Sets the input data for the transaction.
    pub fn input(mut self, input: TransactionInput) -> Self {
        self.inner.input = input;
        self
    }

    /// Builds [`OpTypedTransaction`] from this builder. See [`TransactionRequest::build_typed_tx`]
    /// for more info.
    ///
    /// Note that EIP-4844 transactions are not supported by Optimism and will be converted into
    /// EIP-1559 transactions.
    pub fn build_typed_tx(self) -> Result<OpTypedTransaction, Self> {
        // An EIP-8430 transaction has no typed form to build from a request yet.
        if self.is_aa() {
            return Err(self);
        }
        let tx = self.inner.build_typed_tx().map_err(Self::from_request)?;
        match tx {
            TypedTransaction::Legacy(tx) => Ok(OpTypedTransaction::Legacy(tx)),
            TypedTransaction::Eip1559(tx) => Ok(OpTypedTransaction::Eip1559(tx)),
            TypedTransaction::Eip2930(tx) => Ok(OpTypedTransaction::Eip2930(tx)),
            TypedTransaction::Eip4844(tx) => {
                let tx: TxEip4844 = tx.into();
                Ok(OpTypedTransaction::Eip1559(TxEip1559 {
                    chain_id: tx.chain_id,
                    nonce: tx.nonce,
                    gas_limit: tx.gas_limit,
                    max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
                    max_fee_per_gas: tx.max_fee_per_gas,
                    to: TxKind::Call(tx.to),
                    value: tx.value,
                    access_list: tx.access_list,
                    input: tx.input,
                }))
            }
            TypedTransaction::Eip7702(tx) => Ok(OpTypedTransaction::Eip7702(tx)),
        }
    }
}

impl From<OpTransactionRequest> for TransactionRequest {
    fn from(value: OpTransactionRequest) -> Self {
        value.inner
    }
}

impl From<TxDeposit> for OpTransactionRequest {
    fn from(tx: TxDeposit) -> Self {
        let TxDeposit {
            source_hash: _,
            from,
            to,
            mint: _,
            value,
            gas_limit,
            is_system_transaction: _,
            input,
        } = tx;

        Self::from_request(TransactionRequest {
            from: Some(from),
            to: Some(to),
            value: Some(value),
            gas: Some(gas_limit),
            input: input.into(),
            ..Default::default()
        })
    }
}

impl From<Sealed<TxDeposit>> for OpTransactionRequest {
    fn from(value: Sealed<TxDeposit>) -> Self {
        value.into_inner().into()
    }
}

impl From<TxPostExec> for OpTransactionRequest {
    fn from(tx: TxPostExec) -> Self {
        Self::from_request(TransactionRequest {
            from: Some(tx.signer_address()),
            transaction_type: Some(POST_EXEC_TX_TYPE_ID),
            gas: Some(0),
            nonce: Some(0),
            value: Some(U256::ZERO),
            input: tx.input.into(),
            ..Default::default()
        })
    }
}

impl From<TxEip8430> for OpTransactionRequest {
    fn from(tx: TxEip8430) -> Self {
        Self {
            inner: TransactionRequest {
                from: tx.sender,
                transaction_type: Some(AA_TX_TYPE_ID),
                chain_id: Some(tx.chain_id),
                nonce: Some(tx.nonce_sequence),
                gas: Some(tx.effective_gas_limit()),
                max_fee_per_gas: Some(tx.max_fee_per_gas),
                max_priority_fee_per_gas: Some(tx.max_priority_fee_per_gas),
                ..Default::default()
            },
            aa: AaRequestFields {
                sender: tx.sender,
                nonce_key: Some(tx.nonce_key),
                valid_after: Some(tx.valid_after),
                valid_before: Some(tx.valid_before),
                account_changes: Some(tx.account_changes),
                calls: Some(tx.calls),
                metadata: Some(tx.metadata),
                payer: Some(tx.payer),
                sender_auth: Some(tx.sender_auth),
                payer_auth: Some(tx.payer_auth),
            },
        }
    }
}

impl<T> From<Signed<T, Signature>> for OpTransactionRequest
where
    T: SignableTransaction<Signature> + Into<TransactionRequest>,
{
    fn from(value: Signed<T, Signature>) -> Self {
        #[cfg(feature = "k256")]
        let from = value.recover_signer().ok();
        #[cfg(not(feature = "k256"))]
        let from = None;

        let mut inner: TransactionRequest = value.strip_signature().into();
        inner.from = from;

        Self::from_request(inner)
    }
}

impl From<OpTypedTransaction> for OpTransactionRequest {
    fn from(tx: OpTypedTransaction) -> Self {
        match tx {
            OpTypedTransaction::Legacy(tx) => Self::from_request(tx.into()),
            OpTypedTransaction::Eip2930(tx) => Self::from_request(tx.into()),
            OpTypedTransaction::Eip1559(tx) => Self::from_request(tx.into()),
            OpTypedTransaction::Eip7702(tx) => Self::from_request(tx.into()),
            OpTypedTransaction::Deposit(tx) => tx.into(),
            OpTypedTransaction::PostExec(tx) => tx.into(),
            OpTypedTransaction::Aa(tx) => tx.into(),
        }
    }
}

impl From<OpTxEnvelope> for OpTransactionRequest {
    fn from(value: OpTxEnvelope) -> Self {
        match value {
            OpTxEnvelope::Eip2930(tx) => tx.into(),
            OpTxEnvelope::Eip1559(tx) => tx.into(),
            OpTxEnvelope::Eip7702(tx) => tx.into(),
            OpTxEnvelope::Deposit(tx) => tx.into(),
            OpTxEnvelope::PostExec(tx) => tx.into_inner().into(),
            OpTxEnvelope::Aa(tx) => tx.into_inner().into(),
            _ => Default::default(),
        }
    }
}

impl From<super::Transaction> for OpTransactionRequest {
    fn from(tx: super::Transaction) -> Self {
        let recovered = tx.inner.into_recovered();
        let from = recovered.signer();
        let mut req: Self = recovered.into_inner().into();
        req.inner.from = Some(from);
        req
    }
}

impl TransactionBuilder7702 for OpTransactionRequest {
    fn authorization_list(&self) -> Option<&Vec<SignedAuthorization>> {
        self.as_ref().authorization_list()
    }

    fn set_authorization_list(&mut self, authorization_list: Vec<SignedAuthorization>) {
        self.as_mut().set_authorization_list(authorization_list);
    }
}

#[cfg(feature = "std")]
impl alloy_network::TransactionBuilder for OpTransactionRequest {
    fn chain_id(&self) -> Option<ChainId> {
        self.as_ref().chain_id()
    }

    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.as_mut().set_chain_id(chain_id);
    }

    fn nonce(&self) -> Option<u64> {
        self.as_ref().nonce()
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.as_mut().set_nonce(nonce);
    }

    fn take_nonce(&mut self) -> Option<u64> {
        self.as_mut().nonce.take()
    }

    fn input(&self) -> Option<&Bytes> {
        self.as_ref().input()
    }

    fn set_input<T: Into<Bytes>>(&mut self, input: T) {
        self.as_mut().set_input(input);
    }

    fn from(&self) -> Option<Address> {
        self.as_ref().from()
    }

    fn set_from(&mut self, from: Address) {
        self.as_mut().set_from(from);
    }

    fn kind(&self) -> Option<TxKind> {
        self.as_ref().kind()
    }

    fn clear_kind(&mut self) {
        self.as_mut().clear_kind();
    }

    fn set_kind(&mut self, kind: TxKind) {
        self.as_mut().set_kind(kind);
    }

    fn value(&self) -> Option<U256> {
        self.as_ref().value()
    }

    fn set_value(&mut self, value: U256) {
        self.as_mut().set_value(value);
    }

    fn gas_price(&self) -> Option<u128> {
        self.as_ref().gas_price()
    }

    fn set_gas_price(&mut self, gas_price: u128) {
        self.as_mut().set_gas_price(gas_price);
    }

    fn max_fee_per_gas(&self) -> Option<u128> {
        self.as_ref().max_fee_per_gas()
    }

    fn set_max_fee_per_gas(&mut self, max_fee_per_gas: u128) {
        self.as_mut().set_max_fee_per_gas(max_fee_per_gas);
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.as_ref().max_priority_fee_per_gas()
    }

    fn set_max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: u128) {
        self.as_mut().set_max_priority_fee_per_gas(max_priority_fee_per_gas);
    }

    fn gas_limit(&self) -> Option<u64> {
        self.as_ref().gas_limit()
    }

    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.as_mut().set_gas_limit(gas_limit);
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.as_ref().access_list()
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        self.as_mut().set_access_list(access_list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A standard request serializes as before, and an EIP-8430 request carries its fields flat.
    #[test]
    fn serializes_eip_8430_fields_flat() {
        let plain = OpTransactionRequest::default().to(Address::repeat_byte(1));
        let json = serde_json::to_value(&plain).unwrap();
        assert_eq!(json, serde_json::to_value(plain.as_ref()).unwrap());
        assert!(!plain.is_aa());

        let json = serde_json::json!({
            "type": "0x79",
            "from": "0x1111111111111111111111111111111111111111",
            "calls": [[{"to": "0x2222222222222222222222222222222222222222", "value": "0x1", "data": "0x"}]],
            "payer": "0x3333333333333333333333333333333333333333",
            "gas": "0x30d40"
        });
        let request: OpTransactionRequest = serde_json::from_value(json).unwrap();
        assert!(request.is_aa());
        assert_eq!(request.as_ref().gas, Some(200_000));
        assert_eq!(request.aa().payer, Some(Payer::Named(Address::repeat_byte(0x33))));
        assert_eq!(
            request.aa().calls,
            Some(vec![vec![AaCall {
                to: Address::repeat_byte(0x22),
                value: U256::from(1),
                data: Default::default()
            }]])
        );
        let back: OpTransactionRequest =
            serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();
        assert_eq!(back, request);
    }

    /// Deserialization keeps `from` in step with `sender` and refuses what EIP-8430's RPC extension
    /// rules out.
    #[test]
    fn checks_eip_8430_requests() {
        let parse = |json| serde_json::from_value::<OpTransactionRequest>(json);
        let calls = serde_json::json!([[{"to": "0x2222222222222222222222222222222222222222", "value": "0x0", "data": "0x"}]]);
        let sender = "0x1111111111111111111111111111111111111111";

        let request = parse(serde_json::json!({"sender": sender, "calls": calls})).unwrap();
        assert_eq!(request.as_ref().from, Some(Address::repeat_byte(0x11)), "from takes sender");

        for bad in [
            serde_json::json!({"sender": sender, "from": "0x3333333333333333333333333333333333333333", "calls": calls}),
            serde_json::json!({"type": "0x2", "calls": calls}),
            serde_json::json!({"calls": calls, "to": sender}),
            serde_json::json!({"calls": calls, "input": "0x01"}),
            serde_json::json!({"calls": calls, "value": "0x1"}),
        ] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }

        // A payer alone makes the request EIP-8430, and it builds no typed transaction.
        let request =
            parse(serde_json::json!({"payer": "0x3333333333333333333333333333333333333333"}))
                .unwrap();
        assert!(request.is_aa());
        assert!(request.build_typed_tx().is_err());
    }

    /// Authorizations are priced as non-zero bytes of their shape, and missing fee caps as
    /// full-width placeholders, so a simulation never prices below the signed transaction.
    #[test]
    fn simulates_with_non_zero_authorizations() {
        let named_payer = Address::repeat_byte(0x33);
        let zeros: alloy_primitives::Bytes =
            [&op_alloy_consensus::K1_AUTHENTICATOR[..], &[0; 65]].concat().into();
        let mut request = OpTransactionRequest::default();
        request.aa_mut().payer = Some(Payer::Named(named_payer));
        request.aa_mut().payer_auth = Some(zeros);
        request.aa_mut().calls = Some(vec![vec![]]);
        let tx = request.aa_simulation_tx(10, 3, 300_000);
        assert_eq!(&tx.payer_auth[..20], op_alloy_consensus::K1_AUTHENTICATOR.as_slice());
        assert!(tx.payer_auth[20..].iter().all(|byte| *byte == 0xff));
        assert_eq!(tx.sender_auth.len(), 65);
        assert!(tx.sender_auth.iter().all(|byte| *byte == 0xff));
        assert_eq!(tx.max_fee_per_gas, u64::MAX as u128);
        assert_eq!(tx.effective_gas_limit(), 300_000);
        assert_eq!((tx.chain_id, tx.nonce_sequence), (10, 3));
        tx.validate_static(10).unwrap();

        request.as_mut().max_fee_per_gas = Some(7);
        assert_eq!(request.aa_simulation_tx(10, 3, 300_000).max_fee_per_gas, 7);

        // A STATEMENT authorization names its actor and carries no signature: it is kept.
        let statement = op_alloy_consensus::StatementActor {
            vk: alloy_primitives::B256::repeat_byte(1),
            tag: *b"sphmem01",
            key: alloy_primitives::B256::ZERO,
        }
        .encode();
        request.aa_mut().sender = Some(Address::repeat_byte(0x11));
        request.aa_mut().sender_auth = Some(statement.clone());
        request.aa_mut().payer_auth = Some(statement.clone());
        let tx = request.aa_simulation_tx(10, 3, 300_000);
        assert_eq!((tx.sender_auth, tx.payer_auth), (statement.clone(), statement));
    }
}
