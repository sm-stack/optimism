use crate::{InvalidAaTx, InvalidCrossTx, OpPooledTx, interop_filter::InteropFilterClient};
use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::Decodable2718;
use alloy_primitives::{B256, U256};
use op_alloy_consensus::{
    AA_TX_TYPE_ID, Actor, MAX_AUTHENTICATION_GAS, TxEip8430, keystore::KEYSTORE_ADDRESS,
};
use op_revm::{
    L1BlockInfo, OpSpecId,
    aa::keystore::{Authorizer, Authorizers, authorize},
    transaction::error::AaTxInvalid,
};
use parking_lot::RwLock;
use reth_chainspec::ChainSpecProvider;
use reth_evm::{ConfigureEvm, execute::BlockExecutionError};
use reth_optimism_evm::{RethL1BlockInfo, revm_spec_by_timestamp_after_bedrock};
use reth_optimism_forks::OpHardforks;
use reth_primitives_traits::{
    Block, BlockBody, BlockTy, GotExpected, SealedBlock,
    transaction::error::InvalidTransactionError,
};
use reth_storage_api::{AccountInfoReader, BlockReaderIdExt, StateProviderFactory};
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError, validate::ValidTransaction,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// The timeout for cross-chain transaction validation against the interop filter.
pub(crate) const CHECK_ACCESS_LIST_TIMEOUT_SECS: u64 = 7200;

/// Gas reserved on every L2 block for the L1-info deposit transaction.
///
/// The L1-info deposit is injected as the first transaction of every OP block and always
/// consumes some gas, so a non-deposit transaction can never use the full block gas limit.
/// Mirrors op-geth's `l1InfoGasOverhead` (`core/txpool/validation.go`) so the tx-pool does not
/// admit transactions that could never be included.
pub(crate) const L1_INFO_GAS_OVERHEAD: u64 = 70_000;

/// Tracks additional infos for the current block.
#[derive(Debug, Default)]
pub struct OpL1BlockInfo {
    /// The current L1 block info.
    l1_block_info: RwLock<L1BlockInfo>,
    /// Current block timestamp.
    timestamp: AtomicU64,
}

impl OpL1BlockInfo {
    /// Returns the most recent timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp.load(Ordering::Relaxed)
    }
}

/// Answers which statements a transaction with EIP-8288 dependencies was admitted with, verified
/// (`optimism_sendRawTransactionWithStatementProofs`), by its admission key
/// ([`op_alloy_consensus::DeclaredDependencies::key`]), so the pool may hold it. Shared with the
/// sequencer's proof aggregation pool; the default admits nothing.
#[derive(Clone)]
pub struct DependencyAdmissions(Arc<AdmittedStatements>);

/// The statement ids a transaction was admitted with, by its admission key.
type AdmittedStatements = dyn Fn(&B256) -> Option<Vec<B256>> + Send + Sync;

impl DependencyAdmissions {
    /// Admissions answered by `admitted`.
    pub fn new(admitted: impl Fn(&B256) -> Option<Vec<B256>> + Send + Sync + 'static) -> Self {
        Self(Arc::new(admitted))
    }

    /// Whether the transaction declaring `declared` was admitted with exactly its statements. The
    /// key leaves the authorizations out, and a STATEMENT authorization adds a statement, so the
    /// same key may come with other statements than those admitted.
    pub fn admits(&self, declared: &op_alloy_consensus::DeclaredDependencies) -> bool {
        (self.0)(&declared.key).is_some_and(|ids| ids == declared.statement_ids())
    }
}

impl Default for DependencyAdmissions {
    fn default() -> Self {
        Self::new(|_| None)
    }
}

impl core::fmt::Debug for DependencyAdmissions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DependencyAdmissions").finish_non_exhaustive()
    }
}

/// Validator for Optimism transactions.
#[derive(Debug, Clone)]
pub struct OpTransactionValidator<Client, Tx, Evm> {
    /// The type that performs the actual validation.
    inner: Arc<EthTransactionValidator<Client, Tx, Evm>>,
    /// Additional block info required for validation.
    block_info: Arc<OpL1BlockInfo>,
    /// If true, ensure that the transaction's sender, or an EIP-8430 transaction's payer, has
    /// enough balance to cover the L1 gas fee derived from the tracked L1 block info that is
    /// extracted from the first transaction in the L2 block.
    require_l1_data_gas_fee: bool,
    /// Client used to check transaction validity with the interop filter.
    interop_client: Option<InteropFilterClient>,
    /// tracks activated forks relevant for transaction validation
    fork_tracker: Arc<OpForkTracker>,
    /// Which transactions with dependencies were admitted with verified proofs.
    dependency_admissions: DependencyAdmissions,
}

impl<Client, Tx, Evm> OpTransactionValidator<Client, Tx, Evm> {
    /// Returns the configured chain spec
    pub fn chain_spec(&self) -> Arc<Client::ChainSpec>
    where
        Client: ChainSpecProvider,
    {
        self.inner.chain_spec()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.inner.client()
    }

    /// Returns the current block timestamp.
    fn block_timestamp(&self) -> u64 {
        self.block_info.timestamp.load(Ordering::Relaxed)
    }

    /// Whether to ensure that the transaction's sender, or an EIP-8430 transaction's payer, has
    /// enough balance to also cover the L1 gas fee.
    pub fn require_l1_data_gas_fee(self, require_l1_data_gas_fee: bool) -> Self {
        Self { require_l1_data_gas_fee, ..self }
    }

    /// Returns whether this validator also requires the transaction's sender, or an EIP-8430
    /// transaction's payer, to have enough balance to cover the L1 gas fee.
    pub const fn requires_l1_data_gas_fee(&self) -> bool {
        self.require_l1_data_gas_fee
    }
}

impl<Client, Tx, Evm> OpTransactionValidator<Client, Tx, Evm>
where
    Client:
        ChainSpecProvider<ChainSpec: OpHardforks> + StateProviderFactory + BlockReaderIdExt + Sync,
    Tx: EthPoolTransaction + OpPooledTx,
    Evm: ConfigureEvm,
{
    /// Returns the most recent block gas limit seen by the validator.
    pub fn block_gas_limit(&self) -> u64 {
        self.inner.block_gas_limit()
    }

    /// Create a new [`OpTransactionValidator`].
    pub fn new(inner: EthTransactionValidator<Client, Tx, Evm>) -> Self {
        let this = Self::with_block_info(inner, OpL1BlockInfo::default());
        if let Ok(Some(block)) =
            this.inner.client().block_by_number_or_tag(alloy_eips::BlockNumberOrTag::Latest)
        {
            // genesis block has no txs, so we can't extract L1 info, we set the block info to empty
            // so that we will accept txs into the pool before the first block
            if block.header().number() == 0 {
                this.block_info.timestamp.store(block.header().timestamp(), Ordering::Relaxed);
            } else {
                this.update_l1_block_info(block.header(), block.body().transactions().first());
            }
        }

        this
    }

    /// Create a new [`OpTransactionValidator`] with the given [`OpL1BlockInfo`].
    pub fn with_block_info(
        inner: EthTransactionValidator<Client, Tx, Evm>,
        block_info: OpL1BlockInfo,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            block_info: Arc::new(block_info),
            require_l1_data_gas_fee: true,
            interop_client: None,
            fork_tracker: Arc::new(OpForkTracker { interop: AtomicBool::from(false) }),
            dependency_admissions: DependencyAdmissions::default(),
        }
    }

    /// Sets which transactions with dependencies the pool may hold.
    pub fn with_dependency_admissions(mut self, admissions: DependencyAdmissions) -> Self {
        self.dependency_admissions = admissions;
        self
    }

    /// Sets the interop filter client and safety level.
    pub fn with_interop(mut self, interop_client: InteropFilterClient) -> Self {
        self.interop_client = Some(interop_client);
        self
    }

    /// Update the L1 block info for the given header and system transaction, if any.
    ///
    /// Note: this supports optional system transaction, in case this is used in a dev setup
    pub fn update_l1_block_info<H, T>(&self, header: &H, tx: Option<&T>)
    where
        H: BlockHeader,
        T: Transaction,
    {
        self.block_info.timestamp.store(header.timestamp(), Ordering::Relaxed);

        if let Some(Ok(l1_block_info)) = tx.map(reth_optimism_evm::extract_l1_info_from_tx) {
            *self.block_info.l1_block_info.write() = l1_block_info;
        }

        if self.chain_spec().is_interop_active_at_timestamp(header.timestamp()) {
            self.fork_tracker.interop.store(true, Ordering::Relaxed);
        }
    }

    /// Validates a single transaction.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    ///
    /// This behaves the same as [`OpTransactionValidator::validate_one_with_state`], but creates
    /// a new state provider internally.
    pub async fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        self.validate_one_with_state(origin, transaction, &mut None).await
    }

    /// Validates a single transaction with a provided state provider.
    ///
    /// This allows reusing the same state provider across multiple transaction validations.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    ///
    /// This behaves the same as [`EthTransactionValidator::validate_one_with_state`], but in
    /// addition applies OP validity checks:
    /// - ensures tx is not eip4844
    /// - ensures cross chain transactions are valid wrt locally configured safety level
    /// - ensures that the account has enough balance to cover the L1 gas cost
    pub async fn validate_one_with_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        state: &mut Option<Box<dyn AccountInfoReader + Send>>,
    ) -> TransactionValidationOutcome<Tx> {
        if transaction.is_eip4844() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }
        if transaction.ty() == AA_TX_TYPE_ID {
            return self.validate_aa_tx(transaction, state);
        }

        // Reserve gas for the L1-info deposit that is present in every OP block, mirroring
        // op-geth's `EffectiveGasLimit` (`core/txpool/validation.go`). The L1-info deposit is
        // injected as the first transaction of every block and always consumes some gas, so a
        // non-deposit transaction can never use the full block gas limit. The inner validator
        // caps at the full block gas limit, which would admit a transaction in
        // `(block_gas_limit - L1_INFO_GAS_OVERHEAD, block_gas_limit]` that can never be included
        // (it would sit in the pool until it expires). Reject it up front, as op-geth does.
        //
        // This is done before the interop `is_valid_cross_tx` check below: the gas check is cheap,
        // stateless and deterministic, whereas cross-tx validation is `async` and potentially
        // network-bound (access-list filtering, up to `CHECK_ACCESS_LIST_TIMEOUT_SECS`). Rejecting
        // an over-gas-limit transaction here avoids that work and is better admission-DoS hygiene.
        let gas_limit = transaction.gas_limit();
        let effective_gas_limit = self.inner.block_gas_limit().saturating_sub(L1_INFO_GAS_OVERHEAD);
        if gas_limit > effective_gas_limit {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::ExceedsGasLimit(gas_limit, effective_gas_limit),
            );
        }

        // Interop cross tx validation
        match self.is_valid_cross_tx(&transaction).await {
            Some(Err(err)) => {
                let err = match err {
                    InvalidCrossTx::CrossChainTxPreInterop => {
                        InvalidTransactionError::TxTypeNotSupported.into()
                    }
                    err => InvalidPoolTransactionError::Other(Box::new(err)),
                };
                return TransactionValidationOutcome::Invalid(transaction, err);
            }
            Some(Ok(_)) => {
                // valid interop tx
                transaction
                    .set_interop_deadline(self.block_timestamp() + CHECK_ACCESS_LIST_TIMEOUT_SECS);
            }
            _ => {}
        }

        let outcome = self.inner.validate_one_with_state(origin, transaction, state);

        self.apply_op_checks(outcome)
    }

    /// Validates an EIP-8430 transaction.
    ///
    /// Its payer, not its sender, pays, so the generic balance check does not apply. Admission
    /// checks what needs no EVM execution: activation, the static rules, the payer's signature, the
    /// validity window, the size, the gas limits (the block's, EIP-7825's and the calldata floor),
    /// the minimum tip, the sender's nonce, the payer's balance against
    /// `max_fee_per_gas * effective_gas_limit` plus the L1 data and operator fees, EIP-3607 for a
    /// sender's own key, and the EIP-8130 Keystore's authorization of the sender's and the payer's
    /// actors. A secp256k1 sender's signature was checked when the transaction was recovered. A
    /// transaction with EIP-8288 dependencies is admitted only once the proof aggregation RPC has
    /// verified its statement proofs.
    fn validate_aa_tx(
        &self,
        transaction: Tx,
        state: &mut Option<Box<dyn AccountInfoReader + Send>>,
    ) -> TransactionValidationOutcome<Tx> {
        let invalid = |transaction, error: InvalidAaTx| {
            TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::Other(Box::new(error)),
            )
        };
        if !self.chain_spec().is_aa_tx_active_at_timestamp(self.block_timestamp()) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }
        let encoded = transaction.encoded_2718().into_owned();
        let size = encoded.len();
        let Ok(aa_tx) = TxEip8430::decode_2718(&mut &encoded[..]) else {
            return invalid(transaction, InvalidAaTx::Malformed);
        };
        if let Err(error) = aa_tx.validate_static(self.inner.chain_id()) {
            return invalid(transaction, error.into());
        }
        // The recovery checked the signatures; the Keystore must authorize the actors behind them.
        let sender = transaction.sender();
        let sender_actor = match aa_tx.sender {
            // A recovered sender is the signer.
            None => Actor::Key(sender),
            Some(_) => match aa_tx.authenticate_sender() {
                Ok((_, actor)) => actor,
                Err(error) => return invalid(transaction, error.into()),
            },
        };
        let payer_actor = match aa_tx.authenticate_payer(sender) {
            Ok(payer) => payer,
            Err(error) => return invalid(transaction, error.into()),
        };
        let payer = payer_actor.map_or(sender, |(payer, _)| payer);
        if !aa_tx.is_valid_at(self.block_timestamp()) {
            return invalid(transaction, InvalidAaTx::OutsideValidityWindow);
        }
        if aa_tx.payer_gas_reserve() > MAX_AUTHENTICATION_GAS {
            return invalid(transaction, InvalidAaTx::PayerAuthenticationGas);
        }
        // A transaction with dependencies enters only once
        // `optimism_sendRawTransactionWithStatementProofs` admitted it with verified proofs.
        if let Some(declared) = aa_tx.declared_dependencies() &&
            !self.dependency_admissions.admits(&declared)
        {
            return invalid(transaction, InvalidAaTx::Dependencies);
        }
        if size > self.inner.max_tx_input_bytes() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::OversizedData {
                    size,
                    limit: self.inner.max_tx_input_bytes(),
                },
            );
        }
        let gas_limit = aa_tx.effective_gas_limit();
        let block_limit = self.inner.block_gas_limit().saturating_sub(L1_INFO_GAS_OVERHEAD);
        let effective_gas_limit =
            block_limit.min(op_revm::revm::primitives::eip7825::TX_GAS_LIMIT_CAP);
        if gas_limit > effective_gas_limit {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::ExceedsGasLimit(gas_limit, effective_gas_limit),
            );
        }
        let floor = aa_tx.sender_floor(sender);
        if aa_tx.gas_limit < floor {
            return invalid(
                transaction,
                InvalidAaTx::BelowFloor { gas_limit: aa_tx.gas_limit, floor },
            );
        }
        if let Some(minimum) = *self.inner.minimum_priority_fee() &&
            aa_tx.max_priority_fee_per_gas < minimum
        {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::PriorityFeeBelowMinimum {
                    minimum_priority_fee: minimum,
                },
            );
        }

        if state.is_none() {
            match self.client().latest() {
                Ok(provider) => *state = Some(Box::new(provider)),
                Err(error) => {
                    return TransactionValidationOutcome::Error(
                        *transaction.hash(),
                        Box::new(error),
                    );
                }
            }
        }
        let provider = state.as_ref().expect("provider is set");
        let account = |address| provider.basic_account(&address).map(Option::unwrap_or_default);
        let (sender_account, payer_account) = match (account(sender), account(payer)) {
            (Ok(sender), Ok(payer)) => (sender, payer),
            (Err(error), _) | (_, Err(error)) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error));
            }
        };
        if aa_tx.nonce_sequence < sender_account.nonce {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::NonceNotConsistent {
                    tx: aa_tx.nonce_sequence,
                    state: sender_account.nonce,
                }
                .into(),
            );
        }
        // The payer also owes the L1 data fee, its dependencies' share included, and the operator
        // fee. A sequencer proves a dependency for the transaction it admits, so a payer who cannot
        // pay for that stays out. The fees are priced at admission, for this transaction alone: the
        // builder skips one whose payer falls short later.
        let op_fees = if self.requires_l1_data_gas_fee() {
            match self.op_fees(&encoded, gas_limit, aa_tx.dependency_count()) {
                Ok(fees) => fees,
                Err(error) => {
                    return TransactionValidationOutcome::Error(
                        *transaction.hash(),
                        Box::new(error),
                    );
                }
            }
        } else {
            U256::ZERO
        };
        let gas_fee = U256::from(gas_limit) * U256::from(aa_tx.max_fee_per_gas);
        if payer_account.balance < gas_fee.saturating_add(op_fees) {
            return invalid(transaction, InvalidAaTx::PayerFunds);
        }
        let keystore = match self.client().latest() {
            Ok(keystore) => keystore,
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error));
            }
        };
        // What execution refuses of a sender with code: a delegation over it, and EIP-3607's key
        // recovering to the address. The account's other actors may send.
        match self.inner.validate_sender_bytecode(&transaction, &sender_account, &keystore) {
            Ok(Err(_)) if aa_tx.delegation().is_some() => {
                return invalid(
                    transaction,
                    InvalidAaTx::Keystore(AaTxInvalid::DelegationOverCode),
                );
            }
            Ok(Err(error)) if sender_actor == Actor::Key(sender) => {
                return TransactionValidationOutcome::Invalid(transaction, error);
            }
            Ok(_) => {}
            Err(outcome) => return outcome,
        }
        let authorizers = Authorizers {
            sender: Authorizer::Actor(sender_actor),
            payer: payer_actor.map(|(payer, actor)| (payer, Authorizer::Actor(actor))),
        };
        match authorize(&aa_tx, sender, authorizers, self.block_timestamp(), |slot| {
            keystore.storage(KEYSTORE_ADDRESS, slot.into()).map(Option::unwrap_or_default)
        }) {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => return invalid(transaction, InvalidAaTx::Keystore(reason)),
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error));
            }
        }

        TransactionValidationOutcome::Valid {
            balance: sender_account.balance,
            state_nonce: sender_account.nonce,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(transaction),
            propagate: true,
            authorities: None,
        }
    }

    /// The fees a transaction owes on top of its L2 gas, at the tracked L1 block info: the L1 data
    /// fee, with `dependencies`' share for an EIP-8430 transaction, and the operator fee.
    fn op_fees(
        &self,
        encoded: &[u8],
        gas_limit: u64,
        dependencies: u64,
    ) -> Result<U256, BlockExecutionError> {
        let mut l1_block_info = self.block_info.l1_block_info.read().clone();
        let timestamp = self.block_timestamp();
        let data_fee =
            l1_block_info.l1_tx_data_fee(self.chain_spec(), timestamp, encoded, false)?;
        let spec_id = revm_spec_by_timestamp_after_bedrock(self.chain_spec(), timestamp);
        Ok(data_fee
            .saturating_add(l1_block_info.dependency_l1_cost(dependencies))
            .saturating_add(operator_fee_addition(&l1_block_info, spec_id, encoded, gas_limit)))
    }

    /// Performs the necessary opstack specific checks based on top of the regular eth outcome.
    fn apply_op_checks(
        &self,
        outcome: TransactionValidationOutcome<Tx>,
    ) -> TransactionValidationOutcome<Tx> {
        if !self.requires_l1_data_gas_fee() {
            // no need to check L1 gas fee
            return outcome;
        }
        // ensure that the account has enough balance to cover the L1 gas cost
        if let TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            transaction: mut valid_tx,
            propagate,
            bytecode_hash,
            authorities,
        } = outcome
        {
            let encoded = valid_tx.transaction().encoded_2718();

            // Also reserve the operator fee (introduced in Isthmus). The Isthmus exec-engine spec
            // mandates this pool behavior: "the transaction pool must reject transactions that do
            // not have enough balance to cover the worst-case cost of the transaction fee. This
            // worst-case cost of a transaction now includes the worst-case operator fee."
            // <https://specs.optimism.io/protocol/isthmus/exec-engine.html#operator-fee>
            // (Jovian changes the formula: <https://specs.optimism.io/protocol/jovian/exec-engine.html#operator-fee>.)
            // Reserving only the L1 data fee above lets a sender covering L2 gas + value + L1 data
            // fee — but not the operator fee — be admitted to the pool and then fail at execution.
            let cost_addition = match self.op_fees(&encoded, valid_tx.transaction().gas_limit(), 0)
            {
                Ok(fees) => fees,
                Err(err) => {
                    return TransactionValidationOutcome::Error(*valid_tx.hash(), Box::new(err));
                }
            };

            // Fold the OP fees into `cost()` so the pool's cumulative per-sender balance check
            // accounts for them too. This check only sees one transaction against the on-chain
            // balance; a sender's later nonces must also cover the OP fees of the earlier ones, or
            // the pool marks them pending although execution rejects them for insufficient funds.
            // The fees are priced at admission.
            match &mut valid_tx {
                ValidTransaction::Valid(tx) |
                ValidTransaction::ValidWithSidecar { transaction: tx, .. } => {
                    tx.set_op_fee_reservation(cost_addition)
                }
            }
            let cost = *valid_tx.transaction().cost();

            // Checks for max cost
            if cost > balance {
                return TransactionValidationOutcome::Invalid(
                    valid_tx.into_transaction(),
                    InvalidTransactionError::InsufficientFunds(
                        GotExpected { got: balance, expected: cost }.into(),
                    )
                    .into(),
                );
            }

            return TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
                bytecode_hash,
                authorities,
            };
        }
        outcome
    }

    /// Wrapper for is valid cross tx
    pub async fn is_valid_cross_tx(&self, tx: &Tx) -> Option<Result<(), InvalidCrossTx>> {
        // We don't need to check for deposit transaction in here, because they won't come from
        // txpool
        self.interop_client
            .as_ref()?
            .is_valid_cross_tx(
                tx.access_list(),
                tx.hash(),
                self.block_info.timestamp.load(Ordering::Relaxed),
                Some(CHECK_ACCESS_LIST_TIMEOUT_SECS),
                self.fork_tracker.is_interop_activated(),
            )
            .await
    }
}

/// UPSTREAM-MIRROR(delegate): reth@rev:8d359d0
/// `reth_transaction_pool::validate::EthTransactionValidator`
///
/// Wraps the Ethereum validator. Re-check newly defaulted batch methods and upstream overrides;
/// inheriting a generic default can lose the inner validator's shared-state batching.
impl<Client, Tx, Evm> TransactionValidator for OpTransactionValidator<Client, Tx, Evm>
where
    Client:
        ChainSpecProvider<ChainSpec: OpHardforks> + StateProviderFactory + BlockReaderIdExt + Sync,
    Tx: EthPoolTransaction + OpPooledTx,
    Evm: ConfigureEvm,
{
    type Transaction = Tx;
    type Block = BlockTy<Evm::Primitives>;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        self.validate_one(origin, transaction).await
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block);
        self.update_l1_block_info(
            new_tip_block.header(),
            new_tip_block.body().transactions().first(),
        );
    }
}

/// Keeps track of whether certain forks are activated
#[derive(Debug)]
pub(crate) struct OpForkTracker {
    /// Tracks if interop is activated at the block's timestamp.
    interop: AtomicBool,
}

impl OpForkTracker {
    /// Returns `true` if Lagoon fork is activated.
    pub(crate) fn is_interop_activated(&self) -> bool {
        self.interop.load(Ordering::Relaxed)
    }
}

/// Operator fee to reserve for a non-deposit transaction in the tx-pool balance check.
///
/// Implements the pool-admission rule from the Isthmus exec-engine spec (the pool must reserve the
/// worst-case operator fee): <https://specs.optimism.io/protocol/isthmus/exec-engine.html#operator-fee>.
/// The charge delegates to [`L1BlockInfo::operator_fee_charge`], so the fork-dependent formula
/// (Isthmus vs the Jovian 100× multiplier,
/// <https://specs.optimism.io/protocol/jovian/exec-engine.html#operator-fee>) stays in one place.
/// `apply_op_checks` otherwise reserves only the L1 data fee, so a sender covering L2 gas + value +
/// L1 data fee — but not the operator fee — would be admitted to the pool and then fail at
/// execution.
///
/// Returns zero before Isthmus or when the operator fee params are unset:
/// [`L1BlockInfo::operator_fee_charge`] panics on a missing scalar/constant, so both must be
/// present before the charge is computed. Uses the transaction's `gas_limit` (worst-case spend),
/// matching the spec's worst-case reservation.
fn operator_fee_addition(
    l1_block_info: &L1BlockInfo,
    spec_id: OpSpecId,
    encoded: &[u8],
    gas_limit: u64,
) -> U256 {
    if spec_id.is_enabled_in(OpSpecId::ISTHMUS) &&
        l1_block_info.operator_fee_scalar.is_some() &&
        l1_block_info.operator_fee_constant.is_some()
    {
        l1_block_info.operator_fee_charge(encoded, U256::from(gas_limit), spec_id)
    } else {
        U256::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::operator_fee_addition;
    use alloy_primitives::U256;
    use op_revm::{L1BlockInfo, OpSpecId};

    /// A non-deposit EIP-2718 encoding: first byte is a tx-type (0x02 = EIP-1559), not the `0x7E`
    /// deposit marker, and non-empty — so `operator_fee_charge` does not short-circuit.
    const NON_DEPOSIT_ENCODED: &[u8] = &[0x02, 0xAB, 0xCD];

    fn l1_info_with_operator_fee(scalar: u64, constant: u64) -> L1BlockInfo {
        L1BlockInfo {
            operator_fee_scalar: Some(U256::from(scalar)),
            operator_fee_constant: Some(U256::from(constant)),
            ..Default::default()
        }
    }

    #[test]
    fn operator_fee_added_when_isthmus_and_params_present() {
        let l1 = l1_info_with_operator_fee(1, 2);
        let gas_limit = 21_000u64;
        let expected =
            l1.operator_fee_charge(NON_DEPOSIT_ENCODED, U256::from(gas_limit), OpSpecId::ISTHMUS);
        assert!(expected > U256::ZERO);
        assert_eq!(
            operator_fee_addition(&l1, OpSpecId::ISTHMUS, NON_DEPOSIT_ENCODED, gas_limit),
            expected
        );
    }

    #[test]
    fn operator_fee_uses_jovian_formula_in_jovian() {
        // Jovian changes the operator fee formula (`gas × scalar × 100 + constant`) from the
        // Isthmus one (`gas × scalar ÷ 1e6 + constant`) — a ~100× difference for the same params.
        // The reservation passes `spec_id` straight through to `operator_fee_charge`, so this pins
        // it to the fork: if the delegation ever drifts, the Jovian path here breaks.
        // <https://specs.optimism.io/protocol/jovian/exec-engine.html#operator-fee>
        let l1 = l1_info_with_operator_fee(1, 2);
        let gas_limit = 21_000u64;

        let expected =
            l1.operator_fee_charge(NON_DEPOSIT_ENCODED, U256::from(gas_limit), OpSpecId::JOVIAN);
        assert_eq!(
            operator_fee_addition(&l1, OpSpecId::JOVIAN, NON_DEPOSIT_ENCODED, gas_limit),
            expected
        );

        // Same params, higher fork: Jovian's multiplier makes the reservation strictly larger than
        // Isthmus — so a fork mix-up can't go unnoticed.
        let isthmus = operator_fee_addition(&l1, OpSpecId::ISTHMUS, NON_DEPOSIT_ENCODED, gas_limit);
        assert!(
            expected > isthmus,
            "Jovian reservation ({expected}) must exceed Isthmus ({isthmus}) for the same params"
        );
    }

    #[test]
    fn operator_fee_zero_before_isthmus() {
        // Params present but spec pre-Isthmus → op-geth charges no operator fee.
        let l1 = l1_info_with_operator_fee(1, 2);
        assert_eq!(
            operator_fee_addition(&l1, OpSpecId::BEDROCK, NON_DEPOSIT_ENCODED, 21_000),
            U256::ZERO
        );
    }

    #[test]
    fn operator_fee_zero_and_no_panic_when_params_unset() {
        // Pre-Isthmus L1 info has no operator fee params; `operator_fee_charge` would panic on the
        // missing scalar/constant, so the guard must return zero without calling it.
        let l1 = L1BlockInfo::default();
        assert!(l1.operator_fee_scalar.is_none() && l1.operator_fee_constant.is_none());
        assert_eq!(
            operator_fee_addition(&l1, OpSpecId::ISTHMUS, NON_DEPOSIT_ENCODED, 21_000),
            U256::ZERO
        );
    }

    #[test]
    fn operator_fee_zero_for_deposit_input() {
        // A deposit-typed (0x7E) encoding is exempt from the operator fee.
        let l1 = l1_info_with_operator_fee(1, 2);
        assert_eq!(
            operator_fee_addition(&l1, OpSpecId::ISTHMUS, &[0x7E, 0x00], 21_000),
            U256::ZERO
        );
    }

    /// The pool must classify a sender's consecutive nonces against the full OP cost, not just the
    /// L2 `cost()`. Each tx below is affordable on its own (so both pass admission against the same
    /// on-chain balance), but the sender cannot pay the L1 data fee of both. Without the L1 fee in
    /// the pool's cumulative accounting, nonce 1 is marked pending and the payload builder retries
    /// it every block, failing with insufficient funds.
    #[tokio::test]
    async fn pool_parks_descendant_unaffordable_with_l1_fee() {
        use crate::{OpL1BlockInfo, OpPooledTransaction, OpTransactionValidator};
        use alloy_consensus::{SignableTransaction, TxEip1559, transaction::Recovered};
        use alloy_eips::eip2718::Encodable2718;
        use alloy_primitives::{Address, Signature, TxKind};
        use parking_lot::RwLock;
        use reth_optimism_chainspec::OP_MAINNET;
        use reth_optimism_evm::{OpEvmConfig, RethL1BlockInfo};
        use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_transaction_pool::{
            CoinbaseTipOrdering, Pool, PoolConfig, PoolTransaction, TransactionOrigin,
            TransactionPool, blobstore::InMemoryBlobStore,
            validate::EthTransactionValidatorBuilder,
        };
        use std::sync::atomic::AtomicU64;

        let signer = Address::with_last_byte(1);
        let make_tx = |nonce: u64| -> OpPooledTransaction {
            let tx: OpTransactionSigned = TxEip1559 {
                chain_id: 10,
                nonce,
                gas_limit: 21_000,
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
        let (tx0, tx1) = (make_tx(0), make_tx(1));

        let mut l1_block_info = L1BlockInfo {
            l1_base_fee: U256::from(1_000_000_000_000u64),
            l1_base_fee_scalar: U256::from(1_000_000),
            ..Default::default()
        };
        let l1_fee =
            l1_block_info.l1_tx_data_fee(OP_MAINNET.clone(), 0, tx0.encoded_2718(), false).unwrap();
        let l2_cost = *tx0.cost();
        assert!(l1_fee > l2_cost, "test needs the L1 fee to dominate, as on ink-mainnet");

        // Covers either tx alone (and both txs' L2 cost), but not both txs' full OP cost.
        let balance = l2_cost * U256::from(2) + l1_fee + l1_fee / U256::from(2);

        let client = MockEthProvider::<OpPrimitives>::new()
            .with_chain_spec(OP_MAINNET.clone())
            .with_genesis_block();
        client.add_account(signer, ExtendedAccount::new(0, balance));
        let inner =
            EthTransactionValidatorBuilder::new(client, OpEvmConfig::optimism(OP_MAINNET.clone()))
                .build(InMemoryBlobStore::default());
        let validator = OpTransactionValidator::with_block_info(
            inner,
            OpL1BlockInfo {
                l1_block_info: RwLock::new(l1_block_info),
                timestamp: AtomicU64::new(0),
            },
        );
        let pool = Pool::new(
            validator,
            CoinbaseTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );

        pool.add_transaction(TransactionOrigin::External, tx0).await.unwrap();
        pool.add_transaction(TransactionOrigin::External, tx1).await.unwrap();

        let pending: Vec<_> =
            pool.get_pending_transactions_by_sender(signer).iter().map(|tx| tx.nonce()).collect();
        let queued: Vec<_> =
            pool.get_queued_transactions_by_sender(signer).iter().map(|tx| tx.nonce()).collect();
        assert_eq!(pending, vec![0], "only nonce 0 is executable");
        assert_eq!(queued, vec![1], "nonce 1 cannot cover its L1 data fee after nonce 0");
    }

    /// The payer of a 0x79 transaction covers its L1 data fee, dependencies included, and its
    /// operator fee to enter the pool.
    #[tokio::test]
    async fn pool_refuses_a_payer_short_of_the_dependency_fee() {
        use crate::{DependencyAdmissions, OpPooledTransaction};
        use alloy_eips::Encodable2718;
        use alloy_primitives::{Address, B256, Sealed};
        use op_alloy_consensus::{
            AaCall, AccountChange, Dependency, OpTxEnvelope, PROOF_STATEMENT_SCHEME, TxEip8430,
        };
        use parking_lot::RwLock;
        use reth_optimism_chainspec::OpChainSpecBuilder;
        use reth_optimism_evm::{OpEvmConfig, RethL1BlockInfo};
        use reth_optimism_primitives::OpPrimitives;
        use reth_primitives_traits::Recovered;
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_transaction_pool::{
            TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
            blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
        };
        use std::sync::{Arc, atomic::AtomicU64};

        use super::{OpL1BlockInfo, OpTransactionValidator};

        let signer = Address::with_last_byte(1);
        let tx = TxEip8430 {
            chain_id: 10,
            max_fee_per_gas: 10,
            gas_limit: 500_000,
            sender_auth: vec![0; 65].into(),
            calls: vec![vec![AaCall { to: Address::with_last_byte(0x42), ..Default::default() }]],
            account_changes: vec![AccountChange::Dependencies {
                dependencies: vec![Dependency {
                    scheme: PROOF_STATEMENT_SCHEME,
                    data_hash: B256::repeat_byte(0xdd),
                    verification_key_hash: B256::repeat_byte(0xaa),
                }],
            }],
            ..Default::default()
        };
        let gas_limit = tx.effective_gas_limit();
        let gas_fee = U256::from(gas_limit) * U256::from(tx.max_fee_per_gas);
        let statements = tx.declared_dependencies().unwrap().statement_ids();
        let hash = tx.sender_signature_hash();
        let envelope = OpTxEnvelope::Aa(Sealed::new_unchecked(tx, hash));
        let encoded = envelope.encoded_2718();
        let chain_spec =
            Arc::new(OpChainSpecBuilder::optimism_mainnet().lagoon_activated().build());
        let l1_info = || L1BlockInfo {
            l1_base_fee: U256::from(1_000_000),
            l1_base_fee_scalar: U256::from(1_000_000),
            ..l1_info_with_operator_fee(1_000, 1_000_000)
        };
        let operator_fee = operator_fee_addition(&l1_info(), OpSpecId::LAGOON, &encoded, gas_limit);
        assert!(operator_fee > U256::ZERO);
        let fee = l1_info().l1_tx_data_fee(chain_spec.clone(), 0, &encoded, false).unwrap() +
            l1_info().dependency_l1_cost(1) +
            operator_fee;

        let validate = |balance: U256| {
            let chain_spec = chain_spec.clone();
            let statements = statements.clone();
            let envelope = envelope.clone();
            let size = encoded.len();
            async move {
                let client = MockEthProvider::<OpPrimitives>::new()
                    .with_chain_spec(chain_spec.clone())
                    .with_genesis_block();
                client.add_account(signer, ExtendedAccount::new(0, balance));
                let inner =
                    EthTransactionValidatorBuilder::new(client, OpEvmConfig::optimism(chain_spec))
                        .build(InMemoryBlobStore::default());
                let validator = OpTransactionValidator::with_block_info(
                    inner,
                    OpL1BlockInfo {
                        l1_block_info: RwLock::new(l1_info()),
                        timestamp: AtomicU64::new(0),
                    },
                )
                .with_dependency_admissions(DependencyAdmissions::new(move |_| {
                    Some(statements.clone())
                }));
                let tx: OpPooledTransaction =
                    OpPooledTransaction::new(Recovered::new_unchecked(envelope, signer), size);
                validator.validate_transaction(TransactionOrigin::External, tx).await
            }
        };

        let short = validate(gas_fee + fee - U256::from(1)).await;
        assert!(matches!(short, TransactionValidationOutcome::Invalid(..)), "{short:?}");
        let enough = validate(gas_fee + fee).await;
        assert!(matches!(enough, TransactionValidationOutcome::Valid { .. }), "{enough:?}");
    }

    /// A transaction is admitted with exactly its statements: one under the same key with another
    /// STATEMENT authorization, which adds another statement, is not.
    #[test]
    fn admissions_match_the_statements() {
        use crate::DependencyAdmissions;
        use alloy_primitives::B256;
        use op_alloy_consensus::{DeclaredDependencies, Dependency, PROOF_STATEMENT_SCHEME};
        let declared = |data: u8| DeclaredDependencies {
            key: B256::repeat_byte(1),
            declared: 1,
            dependencies: vec![Dependency {
                scheme: PROOF_STATEMENT_SCHEME,
                data_hash: B256::repeat_byte(data),
                verification_key_hash: B256::repeat_byte(9),
            }],
        };
        let admitted = declared(2).statement_ids();
        let admissions = DependencyAdmissions::new(move |key| {
            (*key == B256::repeat_byte(1)).then(|| admitted.clone())
        });
        assert!(admissions.admits(&declared(2)));
        assert!(!admissions.admits(&declared(3)), "same key, another statement");
        assert!(!DependencyAdmissions::default().admits(&declared(2)));
    }
}
