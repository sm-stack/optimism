//! The `aggregator` RPC namespace the sequencer's op-reth serves to op-aggregator, on its
//! authenticated endpoint, and the types it carries.

use alloy_primitives::{B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use op_alloy_consensus::{PendingAggregate, ProofStatement};
use serde::{Deserialize, Serialize};

/// A block, named by number and hash. A hash names one block on every node and across restarts,
/// which a local reorg counter does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockId {
    /// The block number.
    #[serde(with = "alloy_serde::quantity")]
    pub number: u64,
    /// The block hash.
    pub hash: B256,
}

/// What proves a statement, as the sequencer verified it on admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Source {
    /// A program leaf proof publishing `members`, each a statement of `program`.
    #[serde(rename_all = "camelCase")]
    Program {
        /// The digest of `verifying_key`: the statements' `vkey_hash`.
        program: B256,
        /// The normalized program's verifying key.
        verifying_key: Bytes,
        /// The leaf proof, in zero knowledge, at the leaf shape of a program class.
        proof: Bytes,
        /// The members the run published.
        members: Vec<B256>,
    },
    /// A leanSPHINCS signature, whose statement the aggregator proves in a signature leaf.
    #[serde(rename_all = "camelCase")]
    Signature {
        /// The encoded public key.
        public_key: Bytes,
        /// The signed message.
        message: B256,
        /// The encoded signature.
        signature: Bytes,
    },
}

impl Source {
    /// Every statement folding the source adds to an aggregate, given one it proves: each member
    /// of a program leaf, or the signature's one statement.
    pub fn statements(&self, statement: &ProofStatement) -> Vec<ProofStatement> {
        match self {
            Self::Program { program, members, .. } => members
                .iter()
                .map(|member| ProofStatement { vkey_hash: *program, public_values_digest: *member })
                .collect(),
            Self::Signature { .. } => vec![*statement],
        }
    }
}

/// A statement of a block and the id of its source: the id of a statement the same source proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementRef {
    /// The statement.
    pub statement: ProofStatement,
    /// Its source's id, which [`AggregatorApiServer::sources`] resolves. Statements one source
    /// proves share an id within a block.
    pub source: B256,
}

/// The provable statements of a block: those whose sources the sequencer holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockStatements {
    /// The block.
    pub block: BlockId,
    /// Its provable statements, sorted by id.
    pub statements: Vec<StatementRef>,
}

/// A source and its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceEntry {
    /// The id the source was named by.
    pub id: B256,
    /// The source.
    pub source: Source,
}

/// What the sequencer's aggregation bookkeeping looks like now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// The canonical head.
    pub head: Option<BlockId>,
    /// The safe head.
    #[serde(with = "alloy_serde::quantity::opt")]
    pub safe: Option<u64>,
    /// The finalized head.
    #[serde(with = "alloy_serde::quantity::opt")]
    pub finalized: Option<u64>,
    /// The highest `through` of the queued or forgotten aggregates: the next aggregate answers for
    /// the blocks after it.
    #[serde(with = "alloy_serde::quantity::opt")]
    pub last_through: Option<u64>,
    /// Whether the aggregate queue is full, so that a submission would be refused.
    pub queue_full: bool,
    /// Whether new dependent transactions are refused because aggregates are late.
    pub paused: bool,
    /// How many blocks a run spans, if runs are fixed: a run ends at block `n` when
    /// `(n + 1) % run_blocks == 0`, where the batcher ends the channel holding it, and may hold
    /// the class capacity. Zero if op-aggregator closes runs itself.
    #[serde(default, with = "alloy_serde::quantity")]
    pub run_blocks: u64,
    /// Whether the transactions after the oldest uncovered block approach the bytes at which the
    /// sequencer pauses new dependent transactions: the open run is due, however young.
    #[serde(default)]
    pub bytes_due: bool,
    /// With fixed runs, the block a run ends at if it would otherwise reach those bytes before its
    /// boundary. It does not move with the prover's lag, so a late prover closes no more often.
    #[serde(default, with = "alloy_serde::quantity::opt")]
    pub due_through: Option<u64>,
}

/// Why the sequencer refused a request. Each variant is an RPC error code, so that a client tells
/// them apart.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AggregatorError {
    /// A block the request named is no longer canonical: the caller drops what it built on it.
    #[error("a block the request names is no longer canonical")]
    Reorged,
    /// The aggregate queue is full: the caller keeps the aggregate and submits it again.
    #[error("the aggregate queue is full")]
    QueueFull,
    /// The aggregate does not follow the last queued one, or reaches past the canonical head.
    #[error("the aggregate through block {0} is out of order")]
    OutOfOrder(u64),
    /// The aggregate misses a provable statement of a block it answers for.
    #[error("the aggregate does not prove statement {0} of a block it answers for")]
    Incomplete(B256),
    /// The aggregate is outside the limits, of another class, or its proof does not verify.
    #[error("invalid aggregate: {0}")]
    Invalid(String),
    /// Too many blocks were forgotten recently.
    #[error("too many blocks forgotten recently")]
    RateLimited,
    /// Anything else, as the transport or the server reported it.
    #[error("{0}")]
    Other(String),
}

/// The first of the error codes the namespace uses, one per [`AggregatorError`] variant.
const CODE_BASE: i32 = -38200;

impl AggregatorError {
    const fn code(&self) -> i32 {
        CODE_BASE -
            match self {
                Self::Reorged => 0,
                Self::QueueFull => 1,
                Self::OutOfOrder(_) => 2,
                Self::Incomplete(_) => 3,
                Self::Invalid(_) => 4,
                Self::RateLimited => 5,
                Self::Other(_) => 6,
            }
    }

    /// The RPC error carrying this error: its message, and its value as data.
    pub fn to_error_object(&self) -> ErrorObjectOwned {
        let data = match self {
            Self::OutOfOrder(through) => Some(serde_json::json!(through)),
            Self::Incomplete(id) => Some(serde_json::json!(id)),
            Self::Invalid(reason) | Self::Other(reason) => Some(serde_json::json!(reason)),
            Self::Reorged | Self::QueueFull | Self::RateLimited => None,
        };
        ErrorObjectOwned::owned(self.code(), self.to_string(), data)
    }

    /// The error an RPC error object carries, by its code. An unknown code is [`Self::Other`].
    pub fn from_error_object(object: &ErrorObjectOwned) -> Self {
        fn data<T: serde::de::DeserializeOwned>(object: &ErrorObjectOwned) -> Option<T> {
            object.data().and_then(|data| serde_json::from_str(data.get()).ok())
        }
        let other = || Self::Other(object.message().into());
        match CODE_BASE.checked_sub(object.code()) {
            Some(0) => Self::Reorged,
            Some(1) => Self::QueueFull,
            Some(2) => data(object).map_or_else(other, Self::OutOfOrder),
            Some(3) => data(object).map_or_else(other, Self::Incomplete),
            Some(4) => {
                data(object).map_or_else(|| Self::Invalid(object.message().into()), Self::Invalid)
            }
            Some(5) => Self::RateLimited,
            Some(6) => data(object).map_or_else(other, Self::Other),
            _ => other(),
        }
    }
}

impl From<AggregatorError> for ErrorObjectOwned {
    fn from(err: AggregatorError) -> Self {
        err.to_error_object()
    }
}

/// The methods the sequencer's op-reth serves to op-aggregator.
#[rpc(server, client, namespace = "aggregator")]
pub trait AggregatorApi {
    /// The bookkeeping's state.
    #[method(name = "status")]
    async fn status(&self) -> RpcResult<Status>;

    /// The first canonical block after `after`, and after the last queued aggregate's `through`,
    /// with provable statements, and those statements. `Reorged` if `after` is no longer
    /// canonical.
    #[method(name = "nextProvableBlock")]
    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> RpcResult<Option<BlockStatements>>;

    /// The sources of the statements `ids` names, of those still held.
    #[method(name = "sources")]
    async fn sources(&self, ids: Vec<B256>) -> RpcResult<Vec<SourceEntry>>;

    /// Drops the sources of `statements` of `block`, a block the caller cannot fold: later
    /// aggregates go past it, and derivation replaces it. Nothing happens if `block` is no longer
    /// canonical.
    #[method(name = "forget")]
    async fn forget(&self, block: BlockId, statements: Vec<ProofStatement>) -> RpcResult<()>;

    /// Verifies `aggregate`, whose `through` is the block hashed `through_hash`, and queues it for
    /// the batcher.
    #[method(name = "submit")]
    async fn submit(&self, aggregate: PendingAggregate, through_hash: B256) -> RpcResult<()>;
}

/// Serves a [`crate::Backend`] as the `aggregator` namespace: op-reth implements the backend once
/// and serves it on its authenticated endpoint with this.
#[derive(Debug, Clone)]
pub struct Served<B>(pub B);

#[jsonrpsee::core::async_trait]
impl<B: crate::Backend + 'static> AggregatorApiServer for Served<B> {
    async fn status(&self) -> RpcResult<Status> {
        Ok(self.0.status().await?)
    }

    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> RpcResult<Option<BlockStatements>> {
        Ok(self.0.next_provable_block(after).await?)
    }

    async fn sources(&self, ids: Vec<B256>) -> RpcResult<Vec<SourceEntry>> {
        Ok(self.0.sources(ids).await?)
    }

    async fn forget(&self, block: BlockId, statements: Vec<ProofStatement>) -> RpcResult<()> {
        Ok(self.0.forget(block, statements).await?)
    }

    async fn submit(&self, aggregate: PendingAggregate, through_hash: B256) -> RpcResult<()> {
        Ok(self.0.submit(aggregate, through_hash).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error survives a round trip through its RPC error object; an unknown code is Other.
    #[test]
    fn errors_round_trip() {
        for err in [
            AggregatorError::Reorged,
            AggregatorError::QueueFull,
            AggregatorError::OutOfOrder(7),
            AggregatorError::Incomplete(B256::repeat_byte(3)),
            AggregatorError::Invalid(String::from("the proof does not verify")),
            AggregatorError::RateLimited,
            AggregatorError::Other(String::from("unreachable")),
        ] {
            assert_eq!(AggregatorError::from_error_object(&err.to_error_object()), err);
        }
        let unknown = ErrorObjectOwned::owned(i32::MAX, "?", None::<()>);
        assert_eq!(
            AggregatorError::from_error_object(&unknown),
            AggregatorError::Other("?".into())
        );
    }
}
