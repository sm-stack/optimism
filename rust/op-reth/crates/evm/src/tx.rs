//! OP transaction environment types.

pub use alloy_op_evm::OpTx;

/// Converter that builds an [`OpTx`] from an
/// [`OpTransactionRequest`](op_alloy_rpc_types::OpTransactionRequest).
///
/// Implements `TxEnvConverter` for use in `RpcConverter`, bypassing the orphan rule
/// issue with `TryIntoTxEnv` (neither `OpTransactionRequest` nor the trait is local).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpTxEnvConverter;

#[cfg(feature = "rpc")]
mod rpc_impl {
    use super::*;
    use alloy_evm::rpc::{EthTxEnvError, TryIntoTxEnv};
    use op_alloy_rpc_types::OpTransactionRequest;
    use reth_evm::ConfigureEvm;
    use reth_rpc_eth_api::transaction::TxEnvConverter;

    impl<Evm> TxEnvConverter<OpTransactionRequest, Evm> for OpTxEnvConverter
    where
        Evm: ConfigureEvm,
        reth_evm::TxEnvFor<Evm>: From<OpTx>,
    {
        type Error = EthTxEnvError;

        fn convert_tx_env(
            &self,
            req: OpTransactionRequest,
            evm_env: &reth_evm::EvmEnvFor<Evm>,
        ) -> Result<reth_evm::TxEnvFor<Evm>, Self::Error> {
            let base: revm::context::TxEnv = req.as_ref().clone().try_into_tx_env(evm_env)?;
            if req.is_aa() {
                return Ok(aa_simulation(&req, base).into());
            }
            let op_tx = OpTx(op_revm::OpTransaction {
                base,
                enveloped_tx: Some(alloy_primitives::Bytes::new()),
                deposit: Default::default(),
                aa: None,
            });
            Ok(op_tx.into())
        }
    }

    /// The EIP-8430 transaction a request describes (EIP-8430's RPC extension), as a simulation:
    /// the transaction [`OpTransactionRequest::aa_simulation_tx`] builds from the chain id, nonce
    /// and effective gas limit the standard conversion resolved in `base`, sent by `base`'s
    /// caller (the request's `sender` or `from`, which deserialization keeps in step).
    pub(crate) fn aa_simulation(req: &OpTransactionRequest, base: revm::context::TxEnv) -> OpTx {
        use alloy_eips::Encodable2718;
        let tx =
            req.aa_simulation_tx(base.chain_id.unwrap_or_default(), base.nonce, base.gas_limit);
        let encoded = tx.encoded_2718().into();
        // The request's prices, as the standard conversion resolved them, are what the
        // simulation pays; the transaction's fee caps only shape it.
        let tx_env = revm::context::TxEnv {
            gas_price: base.gas_price,
            gas_priority_fee: base.gas_priority_fee,
            ..alloy_op_evm::tx::aa_tx_env(&tx, base.caller)
        };
        OpTx(op_revm::OpTransaction {
            base: tx_env,
            enveloped_tx: Some(encoded),
            deposit: Default::default(),
            aa: Some(alloc::sync::Arc::new(op_revm::aa::AaTxEnv::simulation(tx))),
        })
    }
}

#[cfg(all(test, feature = "rpc"))]
mod tests {
    use super::rpc_impl::aa_simulation;
    use alloy_evm::TransactionEnvMut;
    use alloy_primitives::Address;
    use op_alloy_consensus::{K1_AUTHENTICATOR, Payer};
    use op_alloy_rpc_types::OpTransactionRequest;

    /// A request typed `0x79` becomes an EIP-8430 simulation: the sender from `from`, the gas as
    /// the effective gas limit, and placeholder authorizations of the payer mode's shape. Setting
    /// the gas limit, as gas estimation does, reaches the transaction.
    #[test]
    fn builds_an_eip_8430_simulation_from_a_request() {
        let request: OpTransactionRequest = serde_json::from_value(serde_json::json!({
            "type": "0x79",
            "from": "0x1111111111111111111111111111111111111111",
            "calls": [[{"to": "0x2222222222222222222222222222222222222222", "value": "0x0", "data": "0x"}]],
            "payer": "0x3333333333333333333333333333333333333333",
        }))
        .unwrap();
        let base = revm::context::TxEnv {
            caller: Address::repeat_byte(0x11),
            gas_limit: 300_000,
            chain_id: Some(10),
            gas_price: 5,
            ..Default::default()
        };
        let mut op_tx = aa_simulation(&request, base);
        let env = op_tx.0.aa.clone().unwrap();
        assert!(env.is_simulation());
        assert_eq!(env.tx.payer, Payer::Named(Address::repeat_byte(0x33)));
        assert_eq!(env.tx.sender_auth.len(), 65);
        assert_eq!(&env.tx.payer_auth[..20], K1_AUTHENTICATOR.as_slice());
        assert_eq!(env.tx.payer_auth.len(), 85);
        assert_eq!(env.tx.effective_gas_limit(), 300_000);
        assert_eq!(op_tx.0.base.caller, Address::repeat_byte(0x11));
        // The request's price is paid; the unset fee caps only shape the transaction.
        assert_eq!((op_tx.0.base.gas_price, op_tx.0.base.gas_priority_fee), (5, None));
        assert_eq!(env.tx.max_fee_per_gas, u64::MAX as u128);
        env.tx.validate_static(10).unwrap();

        op_tx.set_gas_limit(150_000);
        let env = op_tx.0.aa.clone().unwrap();
        assert_eq!(env.tx.effective_gas_limit(), 150_000);
        assert_eq!(op_tx.0.base.gas_limit, 150_000);
    }
}
