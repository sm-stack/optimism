//! What the folder asks of the sequencer: the `aggregator` namespace, over RPC or, in tests, in
//! process.

use crate::api::{
    AggregatorApiClient, AggregatorError, BlockId, BlockStatements, SourceEntry, Status,
};
use alloy_primitives::B256;
use jsonrpsee::core::client::{ClientT, Error as ClientError};
use op_alloy_consensus::{PendingAggregate, ProofStatement};

/// The sequencer's aggregation bookkeeping, as [`crate::Folder`] uses it. op-reth implements it
/// over its pool; [`RpcBackend`] reaches that implementation over op-reth's authenticated RPC.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    /// See [`crate::api::AggregatorApiServer::status`].
    async fn status(&self) -> Result<Status, AggregatorError>;

    /// See [`crate::api::AggregatorApiServer::next_provable_block`].
    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> Result<Option<BlockStatements>, AggregatorError>;

    /// See [`crate::api::AggregatorApiServer::sources`].
    async fn sources(&self, ids: Vec<B256>) -> Result<Vec<SourceEntry>, AggregatorError>;

    /// See [`crate::api::AggregatorApiServer::forget`].
    async fn forget(
        &self,
        block: BlockId,
        statements: Vec<ProofStatement>,
    ) -> Result<(), AggregatorError>;

    /// See [`crate::api::AggregatorApiServer::submit`].
    async fn submit(
        &self,
        aggregate: PendingAggregate,
        through_hash: B256,
    ) -> Result<(), AggregatorError>;
}

/// [`Backend`] over an RPC client of op-reth's `aggregator` namespace.
#[derive(Debug, Clone)]
pub struct RpcBackend<C>(pub C);

fn from_client(err: ClientError) -> AggregatorError {
    match err {
        ClientError::Call(object) => AggregatorError::from_error_object(&object),
        err => AggregatorError::Other(err.to_string()),
    }
}

#[async_trait::async_trait]
impl<C: ClientT + Send + Sync> Backend for RpcBackend<C> {
    async fn status(&self) -> Result<Status, AggregatorError> {
        self.0.status().await.map_err(from_client)
    }

    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> Result<Option<BlockStatements>, AggregatorError> {
        self.0.next_provable_block(after).await.map_err(from_client)
    }

    async fn sources(&self, ids: Vec<B256>) -> Result<Vec<SourceEntry>, AggregatorError> {
        self.0.sources(ids).await.map_err(from_client)
    }

    async fn forget(
        &self,
        block: BlockId,
        statements: Vec<ProofStatement>,
    ) -> Result<(), AggregatorError> {
        self.0.forget(block, statements).await.map_err(from_client)
    }

    async fn submit(
        &self,
        aggregate: PendingAggregate,
        through_hash: B256,
    ) -> Result<(), AggregatorError> {
        self.0.submit(aggregate, through_hash).await.map_err(from_client)
    }
}
