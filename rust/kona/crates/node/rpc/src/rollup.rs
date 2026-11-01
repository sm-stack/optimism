//! Implements the rollup client rpc endpoints. These endpoints serve data about the rollup state.
//!
//! Implemented in the op-node in <https://github.com/ethereum-optimism/optimism/blob/174e55f0a1e73b49b80a561fd3fedd4fea5770c6/op-service/sources/rollupclient.go#L16>

use alloy_eips::BlockNumberOrTag;
use async_trait::async_trait;
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorCode, ErrorObject},
};
use kona_engine::EngineState;
use kona_genesis::RollupConfig;
use kona_protocol::{BlockInfo, SyncStatus};
use std::fmt::Debug;
use tokio::sync::watch;

use crate::{
    EngineRpcClient, L1State, L1WatcherQueries, OutputResponse, RollupNodeApiServer,
    SafeHeadResponse, l1_watcher::L1WatcherQuerySender,
};

/// `RollupRpc`
///
/// This is a server implementation of [`crate::RollupNodeApiServer`].
#[derive(Debug)]
pub struct RollupRpc<EngineRpcClient_> {
    /// The channel to send [`kona_engine::EngineQueries`]s.
    pub engine_client: EngineRpcClient_,
    /// The channel to send [`crate::L1WatcherQueries`]s.
    pub l1_watcher_sender: L1WatcherQuerySender,
    /// The current L1 block, served as `current_l1`.
    ///
    /// This is the L1 block that the derivation process is last idled at.
    /// This may not be fully derived into L2 data yet.
    /// The safe L2 blocks were produced/included fully from the L1 chain up to _but excluding_
    /// this L1 block. If the node is synced, this matches the `head_l1`, minus the verifier
    /// confirmation distance.
    pub current_l1: watch::Receiver<Option<BlockInfo>>,
}

impl<EngineRpcClient_: EngineRpcClient> RollupRpc<EngineRpcClient_> {
    /// The identifier for the Metric that tracks rollup RPC calls.
    pub const RPC_IDENT: &'static str = "rollup_rpc";

    /// Constructs a new [`RollupRpc`] given a sender channel.
    pub const fn new(
        engine_client: EngineRpcClient_,
        l1_watcher_sender: L1WatcherQuerySender,
        current_l1: watch::Receiver<Option<BlockInfo>>,
    ) -> Self {
        Self { engine_client, l1_watcher_sender, current_l1 }
    }

    /// Reads the L1 block derivation has reached. Call this before querying the engine state.
    ///
    /// op-node serves its sync status from one atomic snapshot. Here the engine state comes from
    /// another actor, so reading it after this keeps the snapshot consistent: derivation moves past
    /// an L1 block only after the engine has recorded the safe blocks derived from it. A safe head
    /// read earlier than `current_l1` could be behind it, which op-batcher reads as a stall.
    fn current_l1(&self) -> Option<BlockInfo> {
        *self.current_l1.borrow()
    }

    // Important note: we zero-out the fields that can't be derived yet to follow op-node's
    // behaviour.
    fn sync_status_from_actor_queries(
        current_l1: Option<BlockInfo>,
        l1_sync_status: L1State,
        l2_sync_status: EngineState,
    ) -> SyncStatus {
        SyncStatus {
            current_l1: current_l1.unwrap_or_default(),
            current_l1_finalized: l1_sync_status.current_l1_finalized.unwrap_or_default(),
            head_l1: l1_sync_status.head_l1.unwrap_or_default(),
            safe_l1: l1_sync_status.safe_l1.unwrap_or_default(),
            finalized_l1: l1_sync_status.finalized_l1.unwrap_or_default(),
            unsafe_l2: l2_sync_status.sync_state.unsafe_head(),
            local_safe_l2: l2_sync_status.sync_state.local_safe_head(),
            safe_l2: l2_sync_status.sync_state.safe_head(),
            finalized_l2: l2_sync_status.sync_state.finalized_head(),
        }
    }
}

#[async_trait]
impl<EngineRpcClient_: EngineRpcClient + 'static> RollupNodeApiServer
    for RollupRpc<EngineRpcClient_>
{
    async fn op_output_at_block(&self, block_num: BlockNumberOrTag) -> RpcResult<OutputResponse> {
        kona_macros::inc!(gauge, Self::RPC_IDENT, "method" => "op_outputAtBlock");

        let current_l1 = self.current_l1();
        let (l1_sync_status_send, l1_sync_status_recv) = tokio::sync::oneshot::channel();

        let ((l2_block_info, output_root, l2_sync_status), l1_sync_status) =
            tokio::try_join!(self.engine_client.output_at_block(block_num), async {
                self.l1_watcher_sender
                    .send(L1WatcherQueries::L1State(l1_sync_status_send))
                    .await
                    .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;

                l1_sync_status_recv.await.map_err(|_| ErrorObject::from(ErrorCode::InternalError))
            })?;

        let sync_status =
            Self::sync_status_from_actor_queries(current_l1, l1_sync_status, l2_sync_status);

        Ok(OutputResponse::from_v0(output_root, sync_status, l2_block_info))
    }

    /// This RPC endpoint is not supported. It is not necessary to track the safe head for every L1
    /// block post-interop anymore so we can remove this method from the rpc interface.
    async fn op_safe_head_at_l1_block(
        &self,
        _block_num: BlockNumberOrTag,
    ) -> RpcResult<SafeHeadResponse> {
        kona_macros::inc!(gauge, Self::RPC_IDENT, "method" => "op_safeHeadAtL1Block");
        return Err(ErrorObject::from(ErrorCode::MethodNotFound));
    }

    async fn op_sync_status(&self) -> RpcResult<SyncStatus> {
        kona_macros::inc!(gauge, Self::RPC_IDENT, "method" => "op_syncStatus");

        let current_l1 = self.current_l1();
        let (l1_sync_status_send, l1_sync_status_recv) = tokio::sync::oneshot::channel();

        let (l1_sync_status, l2_sync_status) = tokio::try_join!(
            async {
                self.l1_watcher_sender
                    .send(L1WatcherQueries::L1State(l1_sync_status_send))
                    .await
                    .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;
                l1_sync_status_recv.await.map_err(|_| ErrorObject::from(ErrorCode::InternalError))
            },
            self.engine_client.get_state()
        )
        .map_err(|_| ErrorObject::from(ErrorCode::InternalError))?;

        return Ok(Self::sync_status_from_actor_queries(
            current_l1,
            l1_sync_status,
            l2_sync_status,
        ));
    }

    async fn op_rollup_config(&self) -> RpcResult<RollupConfig> {
        kona_macros::inc!(gauge, Self::RPC_IDENT, "method" => "op_rollupConfig");

        self.engine_client.get_config().await
    }

    async fn op_version(&self) -> RpcResult<String> {
        kona_macros::inc!(gauge, Self::RPC_IDENT, "method" => "op_version");

        const RPC_VERSION: &str = env!("CARGO_PKG_VERSION");

        return Ok(RPC_VERSION.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use kona_protocol::{L2BlockInfo, OutputRoot};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn l1(number: u64) -> BlockInfo {
        BlockInfo::new(B256::repeat_byte(number as u8), number, B256::ZERO, number * 12)
    }

    /// An engine whose state is only read after derivation moves `current_l1` on to
    /// `advanced_l1`, as when the engine records a safe head and derivation then moves past the L1
    /// block it was derived from.
    #[derive(Debug, Clone)]
    struct AdvancingEngine {
        current_l1: Arc<watch::Sender<Option<BlockInfo>>>,
        advanced_l1: BlockInfo,
    }

    impl AdvancingEngine {
        fn state(&self) -> EngineState {
            self.current_l1.send_replace(Some(self.advanced_l1));
            EngineState::default()
        }
    }

    #[async_trait]
    impl EngineRpcClient for AdvancingEngine {
        async fn get_config(&self) -> RpcResult<RollupConfig> {
            unimplemented!()
        }

        async fn get_state(&self) -> RpcResult<EngineState> {
            Ok(self.state())
        }

        async fn output_at_block(
            &self,
            _: BlockNumberOrTag,
        ) -> RpcResult<(L2BlockInfo, OutputRoot, EngineState)> {
            Ok((
                L2BlockInfo::default(),
                OutputRoot::from_parts(B256::ZERO, B256::ZERO, B256::ZERO),
                self.state(),
            ))
        }

        async fn dev_get_task_queue_length(&self) -> RpcResult<usize> {
            unimplemented!()
        }

        async fn dev_subscribe_to_engine_queue_length(&self) -> RpcResult<watch::Receiver<usize>> {
            unimplemented!()
        }

        async fn dev_subscribe_to_engine_state(&self) -> RpcResult<watch::Receiver<EngineState>> {
            unimplemented!()
        }
    }

    /// Builds a [`RollupRpc`] whose derivation has reached L1 block 3 and moves on to block 5
    /// while the engine state is read, with an L1 watcher reporting head 9.
    fn rollup_rpc() -> RollupRpc<AdvancingEngine> {
        let (current_l1_tx, current_l1_rx) = watch::channel(Some(l1(3)));
        let engine = AdvancingEngine { current_l1: Arc::new(current_l1_tx), advanced_l1: l1(5) };
        let (l1_watcher_tx, mut l1_watcher_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(L1WatcherQueries::L1State(sender)) = l1_watcher_rx.recv().await {
                let _ = sender.send(L1State {
                    current_l1_finalized: None,
                    head_l1: Some(l1(9)),
                    safe_l1: None,
                    finalized_l1: None,
                });
            }
        });
        RollupRpc::new(engine, l1_watcher_tx, current_l1_rx)
    }

    /// `current_l1` is the derivation origin, not the L1 head, and is read before the engine
    /// state: a safe head read afterwards is never behind it.
    #[tokio::test]
    async fn sync_status_reads_current_l1_before_engine_state() {
        let status = rollup_rpc().op_sync_status().await.unwrap();
        assert_eq!(status.current_l1, l1(3));
        assert_eq!(status.head_l1, l1(9));
    }

    #[tokio::test]
    async fn output_at_block_reads_current_l1_before_engine_state() {
        let output = rollup_rpc().op_output_at_block(BlockNumberOrTag::Latest).await.unwrap();
        assert_eq!(output.sync_status.current_l1, l1(3));
        assert_eq!(output.sync_status.head_l1, l1(9));
    }
}
