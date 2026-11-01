//! Contains the `[OpTransactionError]` type.
use core::fmt::Display;
use revm::context_interface::{
    result::{EVMError, InvalidTransaction},
    transaction::TransactionError,
};

/// Optimism transaction validation error.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OpTransactionError {
    /// Base transaction error.
    Base(InvalidTransaction),
    /// System transactions are not supported post-regolith hardfork.
    ///
    /// Before the Regolith hardfork, there was a special field in the `Deposit` transaction
    /// type that differentiated between `system` and `user` deposit transactions. This field
    /// was deprecated in the Regolith hardfork, and this error is thrown if a `Deposit` transaction
    /// is found with this field set to `true` after the hardfork activation.
    ///
    /// In addition, this error is internal, and bubbles up into an
    /// [`OpHaltReason::FailedDeposit`][crate::OpHaltReason::FailedDeposit] error in the `revm`
    /// handler for the consumer to easily handle. This is due to a state transition rule on OP
    /// Stack chains where, if for any reason a deposit transaction fails, the transaction
    /// must still be included in the block, the sender nonce is bumped, the `mint` value persists,
    /// and special gas accounting rules are applied. Normally on L1, [`EVMError::Transaction`]
    /// errors are cause for non-inclusion, so a special [`OpHaltReason`][crate::OpHaltReason]
    /// variant was introduced to handle this case for failed deposit transactions.
    DepositSystemTxPostRegolith,
    /// Deposit transaction halts bubble up to the global main return handler, wiping state and
    /// only increasing the nonce + persisting the mint value.
    ///
    /// This is a catch-all error for any deposit transaction that results in an
    /// [`OpHaltReason`][crate::OpHaltReason] error post-regolith hardfork. This allows for a
    /// consumer to easily handle special cases where a deposit transaction fails during
    /// validation, but must still be included in the block.
    ///
    /// In addition, this error is internal, and bubbles up into an
    /// [`OpHaltReason::FailedDeposit`][crate::OpHaltReason::FailedDeposit] error in the `revm`
    /// handler for the consumer to easily handle. This is due to a state transition rule on OP
    /// Stack chains where, if for any reason a deposit transaction fails, the transaction
    /// must still be included in the block, the sender nonce is bumped, the `mint` value persists,
    /// and special gas accounting rules are applied. Normally on L1, [`EVMError::Transaction`]
    /// errors are cause for non-inclusion, so a special [`OpHaltReason`][crate::OpHaltReason]
    /// variant was introduced to handle this case for failed deposit transactions.
    HaltedDepositPostRegolith,
    /// Missing enveloped transaction bytes for non-deposit transaction.
    ///
    /// Non-deposit transactions on Optimism must have `enveloped_tx` field set
    /// to properly calculate L1 costs.
    MissingEnvelopedTx,
    /// An invalid [EIP-8430] transaction.
    ///
    /// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
    AaTx(AaTxInvalid),
}

/// Why an [EIP-8430] transaction cannot be included.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AaTxInvalid {
    /// Lagoon is not active.
    NotActive,
    /// The transaction environment carries no transaction.
    MissingTransaction,
    /// The transaction breaks a rule that needs no state.
    Static(op_alloy_consensus::AaTxError),
    /// The caller is not the named sender.
    WrongSender,
    /// The block is outside the validity window.
    OutsideValidityWindow,
    /// The payer's authentication reserves more than
    /// [`op_alloy_consensus::MAX_AUTHENTICATION_GAS`].
    PayerAuthenticationGas,
    /// The payer signature does not recover.
    PayerSignature,
    /// The delegation entry would replace code that is not a delegation.
    DelegationOverCode,
    /// The sender signature does not recover.
    SenderSignature,
    /// The sender did not configure the actor that authorized it, or revoked it.
    SenderActor,
    /// The payer did not configure the actor that authorized it, or revoked it.
    PayerActor,
    /// The actor that authorized the sender or the payer expired.
    ActorExpired,
    /// The sender's actor may not initiate transactions.
    SenderScope,
    /// The sender's actor may only call its policy manager, without value.
    Policy,
    /// The payer's actor may not pay for this transaction.
    PayerScope,
    /// Only the sender's admin secp256k1 key may delegate its code.
    DelegationNeedsAdmin,
}

impl Display for AaTxInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotActive => write!(f, "EIP-8430 transactions are not active"),
            Self::MissingTransaction => write!(f, "EIP-8430 environment without its transaction"),
            Self::Static(error) => write!(f, "invalid EIP-8430 transaction: {error}"),
            Self::WrongSender => write!(f, "the caller is not the named sender"),
            Self::OutsideValidityWindow => write!(f, "the block is outside the validity window"),
            Self::PayerAuthenticationGas => {
                write!(f, "the payer authentication reserves too much gas")
            }
            Self::PayerSignature => write!(f, "invalid payer signature"),
            Self::DelegationOverCode => write!(f, "delegation over non-delegation code"),
            Self::SenderSignature => write!(f, "invalid sender signature"),
            Self::SenderActor => write!(f, "the sender's actor is not configured"),
            Self::PayerActor => write!(f, "the payer's actor is not configured"),
            Self::ActorExpired => write!(f, "the authorizing actor expired"),
            Self::SenderScope => write!(f, "the sender's actor may not initiate transactions"),
            Self::Policy => write!(f, "the sender's actor may only call its policy manager"),
            Self::PayerScope => write!(f, "the payer's actor may not pay for this transaction"),
            Self::DelegationNeedsAdmin => {
                write!(f, "only the sender's admin secp256k1 key may delegate")
            }
        }
    }
}

impl core::error::Error for AaTxInvalid {}

impl TransactionError for OpTransactionError {}

impl Display for OpTransactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Base(error) => error.fmt(f),
            Self::DepositSystemTxPostRegolith => {
                write!(f, "deposit system transactions post regolith hardfork are not supported")
            }
            Self::HaltedDepositPostRegolith => {
                write!(
                    f,
                    "deposit transaction halted post-regolith; error will be bubbled up to main return handler"
                )
            }
            Self::MissingEnvelopedTx => {
                write!(f, "missing enveloped transaction bytes for non-deposit transaction")
            }
            Self::AaTx(reason) => reason.fmt(f),
        }
    }
}

impl core::error::Error for OpTransactionError {}

impl From<InvalidTransaction> for OpTransactionError {
    fn from(value: InvalidTransaction) -> Self {
        Self::Base(value)
    }
}

impl<DBError> From<OpTransactionError> for EVMError<DBError, OpTransactionError> {
    fn from(value: OpTransactionError) -> Self {
        Self::Transaction(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::string::ToString;

    #[test]
    fn test_display_op_errors() {
        assert_eq!(
            OpTransactionError::Base(InvalidTransaction::NonceTooHigh { tx: 2, state: 1 })
                .to_string(),
            "nonce 2 too high, expected 1"
        );
        assert_eq!(
            OpTransactionError::DepositSystemTxPostRegolith.to_string(),
            "deposit system transactions post regolith hardfork are not supported"
        );
        assert_eq!(
            OpTransactionError::HaltedDepositPostRegolith.to_string(),
            "deposit transaction halted post-regolith; error will be bubbled up to main return handler"
        );
        assert_eq!(
            OpTransactionError::MissingEnvelopedTx.to_string(),
            "missing enveloped transaction bytes for non-deposit transaction"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_json_op_transaction_error() {
        let response = r#""DepositSystemTxPostRegolith""#;

        let op_transaction_error: OpTransactionError = serde_json::from_str(response).unwrap();
        assert_eq!(op_transaction_error, OpTransactionError::DepositSystemTxPostRegolith);
    }
}
