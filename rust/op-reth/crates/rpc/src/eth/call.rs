use crate::{OpEthApi, OpEthApiError, eth::RpcNodeCore};
use alloy_primitives::U256;
use op_alloy_consensus::Payer;
use op_revm::transaction::OpTxTr;
use reth_evm::{EvmEnvFor, TxEnvFor};
use reth_rpc_eth_api::{
    FromEthApiError, FromEvmError, RpcConvert,
    helpers::{Call, EthCall, estimate::EstimateCall},
};
use reth_rpc_eth_types::EthApiError;
use revm::{Database, context_interface::Transaction};

impl<N, Rpc> EthCall for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
    TxEnvFor<N::Evm>: OpTxTr,
{
}

impl<N, Rpc> EstimateCall for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
    TxEnvFor<N::Evm>: OpTxTr,
{
}

impl<N, Rpc> Call for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
    TxEnvFor<N::Evm>: OpTxTr,
{
    /// The gas the transaction's payer can afford at its gas price: for an EIP-8430 transaction
    /// the payer is the named payer, or the sender for self-pay; an open payer is unknown until it
    /// signs, so its gas is not capped. Other transactions defer to the caller's allowance.
    fn caller_gas_allowance(
        &self,
        mut db: impl Database<Error: Into<EthApiError>>,
        _evm_env: &EvmEnvFor<Self::Evm>,
        tx_env: &TxEnvFor<Self::Evm>,
    ) -> Result<u64, Self::Error> {
        let Some(aa) = tx_env.aa_tx() else {
            return reth_evm::call::caller_gas_allowance(&mut db, tx_env)
                .map_err(Self::Error::from_eth_err);
        };
        let payer = match aa.tx.payer {
            Payer::SelfPay => tx_env.caller(),
            Payer::Named(payer) => payer,
            Payer::Open => return Ok(u64::MAX),
        };
        let balance = db
            .basic(payer)
            .map_err(|err| Self::Error::from_eth_err(err.into()))?
            .map(|account| account.balance)
            .unwrap_or_default();
        Ok(balance.checked_div(U256::from(tx_env.gas_price())).unwrap_or_default().saturating_to())
    }

    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.eth_api.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.eth_api.max_simulate_blocks()
    }

    #[inline]
    fn compute_state_root_for_eth_simulate(&self) -> bool {
        self.inner.eth_api.compute_state_root_for_eth_simulate()
    }

    #[inline]
    fn evm_memory_limit(&self) -> u64 {
        self.inner.eth_api.evm_memory_limit()
    }
}
