use crate::{
    conditional::MaybeConditionalTransaction, estimated_da_size::DataAvailabilitySized,
    interop::MaybeInteropTransaction,
};
use alloy_consensus::{BlobTransactionValidationError, Typed2718, transaction::Recovered};
use alloy_eips::{
    eip2718::{Encodable2718, WithEncoded},
    eip2930::AccessList,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256};
use alloy_rpc_types_eth::erc4337::TransactionConditional;
use c_kzg::KzgSettings;
use core::fmt::Debug;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{InMemorySize, SignedTransaction};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};
use std::{
    borrow::Cow,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// Marker for no-interop transactions
pub(crate) const NO_INTEROP_TX: u64 = 0;

/// Pool transaction for OP.
///
/// This type wraps the actual transaction and caches values that are frequently used by the pool.
/// For payload building this lazily tracks values that are required during payload building:
///  - Estimated compressed size of this transaction
#[derive(Debug, Clone, derive_more::Deref)]
pub struct OpPooledTransaction<
    Cons = OpTransactionSigned,
    Pooled = op_alloy_consensus::OpPooledTransaction,
> {
    #[deref]
    inner: EthPooledTransaction<Cons>,
    /// The estimated size of this transaction, lazily computed.
    estimated_tx_compressed_size: OnceLock<u64>,
    /// The pooled transaction type.
    _pd: core::marker::PhantomData<Pooled>,

    /// Optional conditional attached to this transaction.
    conditional: Option<Box<TransactionConditional>>,

    /// Optional interop deadline attached to this transaction.
    interop: Arc<AtomicU64>,

    /// Cached EIP-2718 encoded bytes of the transaction, lazily computed.
    encoded_2718: OnceLock<Bytes>,

    /// Worst-case cost including the OP fees reserved at validation, see
    /// [`OpPooledTx::set_op_fee_reservation`].
    op_cost: U256,
}

impl<Cons: SignedTransaction, Pooled> OpPooledTransaction<Cons, Pooled> {
    /// Create new instance of [Self].
    pub fn new(transaction: Recovered<Cons>, encoded_length: usize) -> Self {
        let inner = EthPooledTransaction::new(transaction, encoded_length);
        let op_cost = sender_cost(&inner);
        Self {
            inner,
            op_cost,
            estimated_tx_compressed_size: Default::default(),
            conditional: None,
            interop: Arc::new(AtomicU64::new(NO_INTEROP_TX)),
            _pd: core::marker::PhantomData,
            encoded_2718: Default::default(),
        }
    }

    /// Returns the estimated compressed size of a transaction in bytes.
    /// This value is computed based on the following formula:
    /// `max(minTransactionSize, intercept + fastlzCoef*fastlzSize) / 1e6`
    /// Uses cached EIP-2718 encoded bytes to avoid recomputing the encoding for each estimation.
    pub fn estimated_compressed_size(&self) -> u64 {
        *self
            .estimated_tx_compressed_size
            .get_or_init(|| op_alloy_flz::tx_estimated_size_fjord_bytes(self.encoded_2718()))
    }

    /// Returns lazily computed EIP-2718 encoded bytes of the transaction.
    pub fn encoded_2718(&self) -> &Bytes {
        self.encoded_2718.get_or_init(|| self.inner.transaction().encoded_2718().into())
    }

    /// Conditional setter.
    pub fn with_conditional(mut self, conditional: TransactionConditional) -> Self {
        self.conditional = Some(Box::new(conditional));
        self
    }
}

impl<Cons, Pooled> MaybeConditionalTransaction for OpPooledTransaction<Cons, Pooled> {
    fn set_conditional(&mut self, conditional: TransactionConditional) {
        self.conditional = Some(Box::new(conditional))
    }

    fn conditional(&self) -> Option<&TransactionConditional> {
        self.conditional.as_deref()
    }
}

impl<Cons, Pooled> MaybeInteropTransaction for OpPooledTransaction<Cons, Pooled> {
    fn set_interop_deadline(&self, deadline: u64) {
        self.interop.store(deadline, Ordering::Relaxed);
    }

    fn interop_deadline(&self) -> Option<u64> {
        let interop = self.interop.load(Ordering::Relaxed);
        if interop > NO_INTEROP_TX {
            return Some(interop);
        }
        None
    }
}

impl<Cons: SignedTransaction, Pooled> DataAvailabilitySized for OpPooledTransaction<Cons, Pooled> {
    fn estimated_da_size(&self) -> u64 {
        self.estimated_compressed_size()
    }
}

impl<Cons, Pooled> PoolTransaction for OpPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled>,
    Pooled: SignedTransaction + TryFrom<Cons, Error: core::error::Error>,
{
    type TryFromConsensusError = <Pooled as TryFrom<Cons>>::Error;
    type Consensus = Cons;
    type Pooled = Pooled;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction().clone()
    }

    fn consensus_ref(&self) -> Recovered<&Self::Consensus> {
        Recovered::new_unchecked(self.inner.transaction.inner(), self.inner.transaction.signer())
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn into_consensus_with2718(self) -> WithEncoded<Recovered<Self::Consensus>> {
        let encoding = self.encoded_2718().clone();
        self.inner.transaction.into_encoded_with(encoding)
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_len = tx.encode_2718_len();
        Self::new(tx.convert(), encoded_len)
    }

    fn hash(&self) -> &TxHash {
        self.inner.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        self.inner.transaction.signer()
    }

    fn sender_ref(&self) -> &Address {
        self.inner.transaction.signer_ref()
    }

    fn cost(&self) -> &U256 {
        &self.op_cost
    }

    fn encoded_length(&self) -> usize {
        self.inner.encoded_length
    }
}

impl<Cons: Typed2718, Pooled> Typed2718 for OpPooledTransaction<Cons, Pooled> {
    fn ty(&self) -> u8 {
        self.inner.ty()
    }
}

impl<Cons: InMemorySize, Pooled> InMemorySize for OpPooledTransaction<Cons, Pooled> {
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl<Cons, Pooled> alloy_consensus::Transaction for OpPooledTransaction<Cons, Pooled>
where
    Cons: alloy_consensus::Transaction,
    Pooled: Debug + Send + Sync + 'static,
{
    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.inner.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.inner.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.inner.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.is_create()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.authorization_list()
    }
}

impl<Cons, Pooled> EthPoolTransaction for OpPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled>,
    Pooled: SignedTransaction + TryFrom<Cons>,
    <Pooled as TryFrom<Cons>>::Error: core::error::Error,
{
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecarVariant,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(self.ty()))
    }
}

/// OP-specific pool transaction behaviour: gives the payload builder access to conditionals and
/// encoded bytes, and lets the validator reserve the OP fees in [`PoolTransaction::cost`].
pub trait OpPooledTx:
    MaybeConditionalTransaction + MaybeInteropTransaction + PoolTransaction + DataAvailabilitySized
{
    /// Returns the EIP-2718 encoded bytes of the transaction.
    fn encoded_2718(&self) -> Cow<'_, Bytes>;

    /// Adds the OP fees the sender must also cover (L1 data fee and operator fee) to
    /// [`PoolTransaction::cost`], replacing any previous reservation.
    ///
    /// The pool sums `cost()` over a sender's consecutive nonces to decide which are executable, so
    /// without the reservation it marks transactions pending that cannot pay their L1 data fee.
    fn set_op_fee_reservation(&mut self, fee: U256);
}

impl<Cons, Pooled> OpPooledTx for OpPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled>,
    Pooled: SignedTransaction + TryFrom<Cons>,
    <Pooled as TryFrom<Cons>>::Error: core::error::Error,
{
    fn encoded_2718(&self) -> Cow<'_, Bytes> {
        Cow::Borrowed(self.encoded_2718())
    }

    fn set_op_fee_reservation(&mut self, fee: U256) {
        self.op_cost = sender_cost(&self.inner).saturating_add(fee);
    }
}

/// What the pool reserves against a transaction's sender.
///
/// An EIP-8430 transaction reserves nothing: its payer may be another account, and reserving
/// `gas_limit * max_fee_per_gas` against the sender would park every sponsored transaction whose
/// sender cannot pay. The validator checks the payer's balance instead.
fn sender_cost<Cons: SignedTransaction>(inner: &EthPooledTransaction<Cons>) -> U256 {
    if inner.transaction().ty() == op_alloy_consensus::AA_TX_TYPE_ID {
        U256::ZERO
    } else {
        inner.cost
    }
}

#[cfg(test)]
mod tests {
    use crate::{OpPooledTransaction, OpTransactionValidator};
    use alloy_consensus::transaction::Recovered;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{TxKind, U256};
    use op_alloy_consensus::TxDeposit;
    use reth_optimism_chainspec::OP_MAINNET;
    use reth_optimism_evm::OpEvmConfig;
    use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::{
        TransactionOrigin, TransactionValidationOutcome, blobstore::InMemoryBlobStore,
        error::InvalidPoolTransactionError, validate::EthTransactionValidatorBuilder,
    };
    #[tokio::test]
    async fn validate_optimism_transaction() {
        let client = MockEthProvider::<OpPrimitives>::new()
            .with_chain_spec(OP_MAINNET.clone())
            .with_genesis_block();
        let evm_config = OpEvmConfig::optimism(OP_MAINNET.clone());
        let validator = EthTransactionValidatorBuilder::new(client, evm_config)
            .no_shanghai()
            .no_cancun()
            .build(InMemoryBlobStore::default());
        let validator = OpTransactionValidator::new(validator);

        let origin = TransactionOrigin::External;
        let signer = Default::default();
        let deposit_tx = TxDeposit {
            source_hash: Default::default(),
            from: signer,
            to: TxKind::Create,
            mint: 0,
            value: U256::ZERO,
            gas_limit: 0,
            is_system_transaction: false,
            input: Default::default(),
        };
        let signed_tx: OpTransactionSigned = deposit_tx.into();
        let signed_recovered = Recovered::new_unchecked(signed_tx, signer);
        let len = signed_recovered.encode_2718_len();
        let pooled_tx: OpPooledTransaction = OpPooledTransaction::new(signed_recovered, len);
        let outcome = validator.validate_one(origin, pooled_tx).await;

        let err = match outcome {
            TransactionValidationOutcome::Invalid(_, err) => err,
            _ => panic!("Expected invalid transaction"),
        };
        assert_eq!(err.to_string(), "transaction type not supported");
    }

    /// A non-deposit transaction may use at most `block_gas_limit - L1_INFO_GAS_OVERHEAD` gas:
    /// the L1-info deposit is present in every block and always consumes gas, so a tx asking for
    /// the full block gas limit can never be included. Mirrors op-geth's `EffectiveGasLimit`
    /// (`core/txpool/validation.go`); such a tx must be rejected at admission, not silently stuck.
    #[tokio::test]
    async fn rejects_tx_exceeding_l1_info_reserved_gas_limit() {
        use crate::validator::L1_INFO_GAS_OVERHEAD;
        use alloy_consensus::{SignableTransaction, TxEip1559};
        use alloy_primitives::{Address, Signature};
        use reth_provider::test_utils::ExtendedAccount;

        let client = MockEthProvider::<OpPrimitives>::new()
            .with_chain_spec(OP_MAINNET.clone())
            .with_genesis_block();
        let signer = Address::with_last_byte(1);
        client.add_account(signer, ExtendedAccount::new(0, U256::MAX));

        let evm_config = OpEvmConfig::optimism(OP_MAINNET.clone());
        let validator = EthTransactionValidatorBuilder::new(client, evm_config)
            .build(InMemoryBlobStore::default());
        let validator = OpTransactionValidator::new(validator);

        let block_gas_limit = validator.block_gas_limit();
        let effective_limit = block_gas_limit - L1_INFO_GAS_OVERHEAD;

        let make_tx = |gas_limit: u64| -> OpPooledTransaction {
            let tx: OpTransactionSigned = TxEip1559 {
                chain_id: 10,
                nonce: 0,
                gas_limit,
                max_fee_per_gas: 1_000_000_000,
                to: TxKind::Call(Address::with_last_byte(0x42)),
                ..Default::default()
            }
            .into_signed(Signature::test_signature())
            .into();
            let recovered = Recovered::new_unchecked(tx, signer);
            let len = recovered.encode_2718_len();
            OpPooledTransaction::new(recovered, len)
        };

        // At the full block gas limit: <= the inner full-limit check (so it alone wouldn't
        // reject), but above the L1-info-reserved limit => rejected by the reservation.
        let outcome =
            validator.validate_one(TransactionOrigin::External, make_tx(block_gas_limit)).await;
        assert!(
            matches!(
                outcome,
                TransactionValidationOutcome::Invalid(
                    _,
                    InvalidPoolTransactionError::ExceedsGasLimit(..)
                )
            ),
            "tx at the full block gas limit must be rejected by the L1-info reservation, got: {outcome:?}"
        );

        // At the effective limit => accepted.
        let outcome =
            validator.validate_one(TransactionOrigin::External, make_tx(effective_limit)).await;
        assert!(outcome.is_valid(), "tx at the effective limit must be accepted, got: {outcome:?}");
    }

    /// EIP-8430 admission: the payer's balance and signature, the calldata floor, and dependencies
    /// only through the proof aggregation RPC.
    #[tokio::test]
    async fn validates_eip_8430_transactions() {
        use crate::InvalidAaTx;
        use alloy_consensus::Sealed;
        use alloy_primitives::{Address, B256, Bytes};
        use op_alloy_consensus::{
            AaCall, AccountChange, Dependency, OpTxEnvelope, PROOF_STATEMENT_SCHEME, Payer,
            TxEip8430, aa::k1_auth,
        };
        use reth_optimism_chainspec::OpChainSpecBuilder;
        use reth_provider::test_utils::ExtendedAccount;
        use std::sync::Arc;

        let chain_spec =
            Arc::new(OpChainSpecBuilder::optimism_mainnet().lagoon_activated().build());
        let client = MockEthProvider::<OpPrimitives>::new()
            .with_chain_spec(chain_spec.clone())
            .with_genesis_block();
        let sign = |secret: u8, digest: B256| {
            k1_auth(
                &alloy_consensus::crypto::secp256k1::sign_message(
                    B256::with_last_byte(secret),
                    digest,
                )
                .unwrap(),
            )
        };
        // The account of key `secret`: the signer of any transaction it signs.
        let address = |secret: u8| {
            let mut tx = TxEip8430::default();
            tx.sender_auth = sign(secret, tx.sender_signature_hash()).to_vec().into();
            tx.recover_sender().unwrap()
        };
        let (sender, payer) = (address(1), address(2));
        client.add_account(sender, ExtendedAccount::new(0, U256::from(10u64.pow(18))));
        let evm_config = OpEvmConfig::optimism(chain_spec);
        let validator = EthTransactionValidatorBuilder::new(client, evm_config)
            .build(InMemoryBlobStore::default());
        let validator = OpTransactionValidator::new(validator);

        let pooled = |mut tx: TxEip8430| -> OpPooledTransaction {
            tx.sender_auth = sign(1, tx.sender_signature_hash()).to_vec().into();
            if let Payer::Named(_) = tx.payer {
                let mut auth = op_alloy_consensus::K1_AUTHENTICATOR.to_vec();
                auth.extend(sign(2, tx.payer_signature_hash(sender)));
                tx.payer_auth = auth.into();
            }
            let tx: OpTransactionSigned = OpTxEnvelope::Aa(Sealed::new(tx));
            let recovered = Recovered::new_unchecked(tx, sender);
            let len = recovered.encode_2718_len();
            OpPooledTransaction::new(recovered, len)
        };
        let base = TxEip8430 {
            chain_id: 10,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 100_000,
            calls: vec![vec![AaCall {
                to: Address::with_last_byte(0x42),
                value: U256::ZERO,
                data: Bytes::new(),
            }]],
            ..Default::default()
        };
        let refusal = |outcome: TransactionValidationOutcome<OpPooledTransaction>| match outcome {
            TransactionValidationOutcome::Invalid(_, InvalidPoolTransactionError::Other(err)) => {
                err.as_any().downcast_ref::<InvalidAaTx>().map(|e| e.to_string())
            }
            other => panic!("expected an EIP-8430 refusal, got {other:?}"),
        };
        let validate = |tx| validator.validate_one(TransactionOrigin::External, pooled(tx));

        let outcome = validate(base.clone()).await;
        assert!(outcome.is_valid(), "{outcome:?}");

        let sponsored = TxEip8430 {
            payer: Payer::Named(payer),
            payer_auth: Bytes::from(vec![0; 85]),
            ..base.clone()
        };
        assert_eq!(
            refusal(validate(sponsored).await).unwrap(),
            InvalidAaTx::PayerFunds.to_string()
        );

        let dependent = TxEip8430 {
            account_changes: vec![AccountChange::Dependencies {
                dependencies: vec![Dependency {
                    scheme: PROOF_STATEMENT_SCHEME,
                    data_hash: B256::ZERO,
                    verification_key_hash: B256::repeat_byte(1),
                }],
            }],
            gas_limit: 200_000,
            ..base.clone()
        };
        assert_eq!(
            refusal(validate(dependent).await).unwrap(),
            InvalidAaTx::Dependencies.to_string()
        );

        let short = TxEip8430 { gas_limit: 20_000, ..base };
        assert!(refusal(validate(short).await).unwrap().contains("below the calldata floor"));
    }

    /// An account with code enters the pool through its Keystore actors. Its own key may not act
    /// for it (EIP-3607) and nothing may delegate over its code, which neither a delegation nor
    /// an empty code hash count as.
    #[tokio::test]
    async fn admits_an_account_with_code_through_its_actors() {
        use crate::{DependencyAdmissions, InvalidAaTx};
        use alloy_consensus::Sealed;
        use alloy_primitives::{Address, B256, Bytes};
        use op_alloy_consensus::{
            AaCall, AccountChange, K1_AUTHENTICATOR, OpTxEnvelope, StatementActor, TxEip8430,
            aa::k1_auth,
            keystore::{
                KEYSTORE_ADDRESS, STATEMENT_AUTHENTICATOR, actor_config_slot, address_actor_id,
            },
        };
        use op_revm::transaction::error::AaTxInvalid;
        use reth_optimism_chainspec::OpChainSpecBuilder;
        use reth_primitives_traits::transaction::error::InvalidTransactionError;
        use reth_provider::test_utils::ExtendedAccount;
        use std::sync::Arc;

        let chain_spec =
            Arc::new(OpChainSpecBuilder::optimism_mainnet().lagoon_activated().build());
        let client = MockEthProvider::<OpPrimitives>::new()
            .with_chain_spec(chain_spec.clone())
            .with_genesis_block();
        let sign = |secret: u8, digest: B256| {
            k1_auth(
                &alloy_consensus::crypto::secp256k1::sign_message(
                    B256::with_last_byte(secret),
                    digest,
                )
                .unwrap(),
            )
        };
        let address = |secret: u8| {
            let mut tx = TxEip8430::default();
            tx.sender_auth = sign(secret, tx.sender_signature_hash()).to_vec().into();
            tx.recover_sender().unwrap()
        };
        let funded = || ExtendedAccount::new(0, U256::from(10u64.pow(18)));
        let (contract, admin) = (address(1), address(2));
        client.add_account(contract, funded().with_bytecode(Bytes::from_static(&[0x00])));
        let delegated = Address::repeat_byte(0xad);
        let delegation = [&[0xef, 0x01, 0x00], Address::repeat_byte(0xde).as_slice()].concat();
        client.add_account(delegated, funded().with_bytecode(delegation.into()));
        let empty = Address::repeat_byte(0xae);
        client.add_account(empty, funded().with_bytecode(Bytes::new()));
        let actor = StatementActor {
            vk: B256::repeat_byte(0x5a),
            tag: *b"sphmem01",
            key: B256::repeat_byte(0x4b),
        };
        // An admin actor's word: the authenticator in its low 20 bytes.
        let word = |authenticator: Address| U256::from_be_slice(authenticator.as_slice());
        let slots = [
            (actor_config_slot(contract, actor.actor_id()), word(STATEMENT_AUTHENTICATOR)),
            (actor_config_slot(contract, address_actor_id(admin)), word(K1_AUTHENTICATOR)),
        ];
        client.add_account(
            KEYSTORE_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO)
                .extend_storage(slots.map(|(slot, value)| (B256::from(slot), value))),
        );
        let evm_config = OpEvmConfig::optimism(chain_spec);
        let validator = EthTransactionValidatorBuilder::new(client, evm_config)
            .build(InMemoryBlobStore::default());
        let base = TxEip8430 {
            chain_id: 10,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 100_000,
            sender_auth: vec![0; 65].into(),
            calls: vec![vec![AaCall {
                to: Address::with_last_byte(0x42),
                value: U256::ZERO,
                data: Bytes::new(),
            }]],
            ..Default::default()
        };
        let by_statement =
            TxEip8430 { sender: Some(contract), sender_auth: actor.encode(), ..base.clone() };
        let statements = by_statement.declared_dependencies().unwrap().statement_ids();
        let validator = OpTransactionValidator::new(validator).with_dependency_admissions(
            DependencyAdmissions::new(move |_| Some(statements.clone())),
        );

        let validate = |tx: TxEip8430, sender: Address| {
            let tx: OpTransactionSigned = OpTxEnvelope::Aa(Sealed::new(tx));
            let recovered = Recovered::new_unchecked(tx, sender);
            let len = recovered.encode_2718_len();
            let pooled: OpPooledTransaction = OpPooledTransaction::new(recovered, len);
            validator.validate_one(TransactionOrigin::External, pooled)
        };
        // `tx` naming `contract` as its sender, signed by the key of `secret`.
        let named = |tx: TxEip8430, secret: u8| {
            let mut tx =
                TxEip8430 { sender: Some(contract), sender_auth: vec![0; 85].into(), ..tx };
            let mut auth = K1_AUTHENTICATOR.to_vec();
            auth.extend(sign(secret, tx.sender_signature_hash()));
            tx.sender_auth = auth.into();
            tx
        };
        let has_code = |outcome| {
            matches!(
                outcome,
                TransactionValidationOutcome::Invalid(
                    _,
                    InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::SignerAccountHasBytecode
                    ),
                )
            )
        };

        assert!(has_code(validate(base.clone(), contract).await), "recovered to the address");
        assert!(has_code(validate(named(base.clone(), 1), contract).await), "named by its key");

        for sender in [delegated, empty] {
            let outcome = validate(base.clone(), sender).await;
            assert!(outcome.is_valid(), "{outcome:?}");
        }
        let outcome = validate(named(base.clone(), 2), contract).await;
        assert!(outcome.is_valid(), "{outcome:?}");
        let outcome = validate(by_statement, contract).await;
        assert!(outcome.is_valid(), "{outcome:?}");

        let delegating = TxEip8430 {
            account_changes: vec![AccountChange::Delegation { target: admin }],
            ..base
        };
        match validate(named(delegating, 2), contract).await {
            TransactionValidationOutcome::Invalid(_, InvalidPoolTransactionError::Other(error)) => {
                assert_eq!(
                    error.as_any().downcast_ref::<InvalidAaTx>().unwrap().to_string(),
                    InvalidAaTx::Keystore(AaTxInvalid::DelegationOverCode).to_string()
                );
            }
            other => panic!("expected the delegation to be refused, got {other:?}"),
        }
    }
}
