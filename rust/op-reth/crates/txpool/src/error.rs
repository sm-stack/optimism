use crate::interop_filter::InteropTxValidatorError;
use reth_transaction_pool::error::PoolTransactionError;
use std::any::Any;

/// Wrapper for [`InteropTxValidatorError`] to implement [`PoolTransactionError`] for it.
#[derive(thiserror::Error, Debug)]
pub enum InvalidCrossTx {
    /// Errors produced by interop filter validation.
    #[error(transparent)]
    ValidationError(#[from] InteropTxValidatorError),
    /// Error caused by a cross chain tx before the Lagoon hardfork (interop activation) is active
    #[error("cross chain tx is invalid before interop")]
    CrossChainTxPreInterop,
    /// Rejected because failsafe mode is active — all interop txs are blocked.
    #[error("interop failsafe is active")]
    FailsafeEnabled,
}

impl InvalidCrossTx {
    /// Whether a validation verdict means the tx is definitively invalid and must be evicted.
    ///
    /// Distinct from [`is_bad_transaction`](Self::is_bad_transaction), which decides peer
    /// penalization. Only a decisive invalid verdict is evicted; transient or non-decisive results
    /// (quorum miss, timeout, data-unavailable, disagreement) are retained so an unreachable
    /// interop filter cannot drain the pool. Failsafe is handled by the whole-pool eviction.
    pub const fn is_definitive_invalid(&self) -> bool {
        match self {
            Self::CrossChainTxPreInterop => true,
            Self::ValidationError(err) => err.is_definitive_invalid(),
            Self::FailsafeEnabled => false,
        }
    }
}

impl PoolTransactionError for InvalidCrossTx {
    fn is_bad_transaction(&self) -> bool {
        match self {
            Self::CrossChainTxPreInterop => true,
            Self::ValidationError(_) | Self::FailsafeEnabled => false,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Why an EIP-8430 transaction is refused at admission.
#[derive(thiserror::Error, Debug)]
pub enum InvalidAaTx {
    /// The bytes are not an EIP-8430 transaction.
    #[error("malformed EIP-8430 transaction")]
    Malformed,
    /// A state-independent validity rule failed, or the payer's signature does not verify.
    #[error(transparent)]
    Static(#[from] op_alloy_consensus::AaTxError),
    /// The current block is outside the validity window.
    #[error("outside the validity window")]
    OutsideValidityWindow,
    /// The payer's authentication reserves more than `MAX_AUTHENTICATION_GAS`.
    #[error("the payer authentication reserves too much gas")]
    PayerAuthenticationGas,
    /// `gas_limit` does not cover the sender's calldata floor.
    #[error("gas limit {gas_limit} below the calldata floor {floor}")]
    BelowFloor {
        /// The transaction's gas limit.
        gas_limit: u64,
        /// The sender's share of the calldata floor.
        floor: u64,
    },
    /// The payer cannot cover `max_fee_per_gas * effective_gas_limit` plus the L1 data and operator
    /// fees.
    #[error("the payer cannot cover the maximum gas, L1 data and operator fees")]
    PayerFunds,
    /// The transaction declares EIP-8288 dependencies: it must be sent with their proofs
    /// (`optimism_sendRawTransactionWithStatementProofs`), which verifies and admits them, so an
    /// aggregate can prove them.
    #[error("transactions with dependencies must be sent with their proofs")]
    Dependencies,
    /// The EIP-8130 Keystore does not authorize the sender's or the payer's actor.
    #[error("{0}")]
    Keystore(op_revm::transaction::error::AaTxInvalid),
}

impl PoolTransactionError for InvalidAaTx {
    fn is_bad_transaction(&self) -> bool {
        !matches!(
            self,
            Self::OutsideValidityWindow | Self::PayerFunds | Self::Dependencies | Self::Keystore(_)
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop_filter::InteropTxValidatorError;
    use op_alloy_rpc_types::SuperchainDAError;
    use rstest::rstest;

    #[rstest]
    #[case::invalid_entry(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::InvalidEntry(
            SuperchainDAError::ConflictingData,
        )),
        true,
        false
    )]
    #[case::rejected(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::Rejected {
            code: -32602,
            message: "failed to parse access entry".to_string(),
        }),
        true,
        false
    )]
    #[case::pre_interop(InvalidCrossTx::CrossChainTxPreInterop, true, true)]
    #[case::outer_failsafe(InvalidCrossTx::FailsafeEnabled, false, false)]
    #[case::quorum_not_reached(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::QuorumNotReached {
            received: 1,
            required: 2,
        }),
        false,
        false
    )]
    #[case::data_unavailable(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::DataUnavailable { code: -321401 }),
        false,
        false
    )]
    #[case::timeout(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::Timeout(2)),
        false,
        false
    )]
    #[case::disagreement(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::Disagreement {
            valid: 1,
            invalid: 1,
        }),
        false,
        false
    )]
    #[case::inner_failsafe(
        InvalidCrossTx::ValidationError(InteropTxValidatorError::FailsafeEnabled),
        false,
        false
    )]
    fn invalid_cross_tx_predicates(
        #[case] err: InvalidCrossTx,
        #[case] expected_definitive_invalid: bool,
        #[case] expected_bad_transaction: bool,
    ) {
        assert_eq!(err.is_definitive_invalid(), expected_definitive_invalid);
        assert_eq!(err.is_bad_transaction(), expected_bad_transaction);
    }
}
