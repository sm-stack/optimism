//! The `aggregator` namespace over the sequencer's proof aggregation pool: what op-aggregator
//! reads and submits on the authenticated endpoint, wrapped in [`op_aggregator::api::Served`].
//! Every submitted aggregate is verified before it is queued, and every request tells the pool
//! op-aggregator is there ([`ProofAggregationPool::aggregator_contacted`]): without it the
//! sequencer takes no dependent transaction.

use alloy_primitives::B256;
use jsonrpsee::core::async_trait;
use op_aggregator::api::{
    AggregatorError, BlockId, BlockStatements, Source, SourceEntry, StatementRef, Status,
};
use op_alloy_consensus::{PendingAggregate, ProofStatement};
use reth_optimism_payload_builder::proof_aggregation::{
    ProofAggregationPool, ProofAggregationPoolError, StatementSource,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::warn;

/// The most blocks op-aggregator may have forgotten within [`FORGET_WINDOW`]: derivation replaces a
/// forgotten block with its deposits, the one harm a misbehaving aggregator can do beyond delaying
/// aggregates.
const MAX_FORGETS: usize = 8;

/// The window [`MAX_FORGETS`] counts over.
const FORGET_WINDOW: Duration = Duration::from_secs(10 * 60);

// The sequencer takes op-aggregator for gone only after several missed heartbeats.
const _: () = assert!(
    reth_optimism_payload_builder::proof_aggregation::AGGREGATOR_TIMEOUT.as_secs() >=
        4 * op_aggregator::HEARTBEAT.as_secs()
);

/// The `aggregator` namespace over `pool`.
#[derive(Debug, Clone)]
pub struct OpAggregatorApi {
    pool: ProofAggregationPool,
    /// When op-aggregator forgot blocks lately.
    forgets: Arc<Mutex<VecDeque<Instant>>>,
}

impl OpAggregatorApi {
    /// The namespace for op-aggregator: at most 8 forgotten blocks per 10 minutes.
    pub fn new(pool: ProofAggregationPool) -> Self {
        Self { pool, forgets: Arc::default() }
    }

    /// Counts a forget against the limit.
    fn admit_forget(&self, block: BlockId) -> Result<(), AggregatorError> {
        let mut forgets = self.forgets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        while forgets.front().is_some_and(|at| now.duration_since(*at) >= FORGET_WINDOW) {
            forgets.pop_front();
        }
        if forgets.len() >= MAX_FORGETS {
            warn!(target: "rpc::aggregator", block = block.number, "op-aggregator forgets too many blocks: refused");
            return Err(AggregatorError::RateLimited);
        }
        forgets.push_back(now);
        Ok(())
    }
}

/// A source as the namespace carries it.
fn wire(source: StatementSource) -> Source {
    match source {
        StatementSource::Program(leaf) => Source::Program {
            program: leaf.program,
            verifying_key: leaf.verifying_key.clone(),
            proof: leaf.proof.clone(),
            members: leaf.members.clone(),
        },
        StatementSource::Signature(signed) => Source::Signature {
            public_key: signed.public_key.clone(),
            message: signed.message,
            signature: signed.signature.clone(),
        },
    }
}

fn from_pool(err: ProofAggregationPoolError) -> AggregatorError {
    match err {
        ProofAggregationPoolError::Reorged => AggregatorError::Reorged,
        ProofAggregationPoolError::AggregatesFull => AggregatorError::QueueFull,
        ProofAggregationPoolError::OutOfOrder { through } => AggregatorError::OutOfOrder(through),
        ProofAggregationPoolError::Incomplete(id) => AggregatorError::Incomplete(id),
        ProofAggregationPoolError::InvalidProof(reason) => AggregatorError::Invalid(reason),
        err @ ProofAggregationPoolError::TooManyStatements => {
            AggregatorError::Invalid(err.to_string())
        }
        // Admission's errors: no aggregator request returns them.
        err @ (ProofAggregationPoolError::TooLarge { .. } |
        ProofAggregationPoolError::StatementProofsFull |
        ProofAggregationPoolError::AdmittedTxsFull |
        ProofAggregationPoolError::DependenciesPaused |
        ProofAggregationPoolError::AggregatorAbsent |
        ProofAggregationPoolError::AlreadyAdmitted |
        ProofAggregationPoolError::WrongStatementCount { .. } |
        ProofAggregationPoolError::TooManyPrograms { .. } |
        ProofAggregationPoolError::TooManyFoldedStatements { .. } |
        ProofAggregationPoolError::MissingProof(_)) => AggregatorError::Other(err.to_string()),
    }
}

#[async_trait]
impl op_aggregator::Backend for OpAggregatorApi {
    async fn status(&self) -> Result<Status, AggregatorError> {
        self.pool.aggregator_contacted();
        let status = self.pool.status();
        Ok(Status {
            head: status.head.map(|(number, hash)| BlockId { number, hash }),
            safe: status.safe,
            finalized: status.finalized,
            last_through: status.last_through,
            queue_full: status.queue_full,
            paused: status.paused,
            run_blocks: status.run_blocks,
            bytes_due: status.bytes_due,
            due_through: status.due_through,
        })
    }

    /// The next provable block, each source named by the id of the first statement it proves.
    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> Result<Option<BlockStatements>, AggregatorError> {
        self.pool.aggregator_contacted();
        let next = self
            .pool
            .next_provable_block(after.map(|block| (block.number, block.hash)))
            .map_err(from_pool)?;
        Ok(next.map(|((number, hash), proofs)| {
            let mut ids: HashMap<usize, B256> = HashMap::new();
            let statements = proofs
                .iter()
                .map(|proof| StatementRef {
                    statement: proof.statement,
                    source: *ids
                        .entry(proof.source.address())
                        .or_insert_with(|| proof.statement.id()),
                })
                .collect();
            BlockStatements { block: BlockId { number, hash }, statements }
        }))
    }

    async fn sources(&self, ids: Vec<B256>) -> Result<Vec<SourceEntry>, AggregatorError> {
        self.pool.aggregator_contacted();
        Ok(ids
            .into_iter()
            .filter_map(|id| {
                self.pool.source(&id).map(|source| SourceEntry { id, source: wire(source) })
            })
            .collect())
    }

    async fn forget(
        &self,
        block: BlockId,
        statements: Vec<ProofStatement>,
    ) -> Result<(), AggregatorError> {
        self.pool.aggregator_contacted();
        self.admit_forget(block)?;
        let canonical = self.pool.forget_block_proofs((block.number, block.hash), &statements);
        warn!(target: "rpc::aggregator", block = block.number, statements = statements.len(), canonical, "forgetting the sources of a block that does not fold: derivation replaces it with its deposits");
        Ok(())
    }

    async fn submit(
        &self,
        aggregate: PendingAggregate,
        through_hash: B256,
    ) -> Result<(), AggregatorError> {
        self.pool.aggregator_contacted();
        // Verifying the proof takes milliseconds of every core.
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || pool.submit_aggregate(aggregate, through_hash))
            .await
            .map_err(|err| AggregatorError::Other(err.to_string()))?
            .map_err(from_pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use op_aggregator::Backend;
    use reth_optimism_payload_builder::proof_aggregation::{ProgramLeaf, StatementProof};

    fn leaf(members: &[u8]) -> StatementSource {
        StatementSource::Program(Arc::new(ProgramLeaf {
            program: B256::repeat_byte(7),
            verifying_key: Bytes::from_static(b"key"),
            proof: Bytes::from_static(b"proof"),
            members: members.iter().map(|m| B256::repeat_byte(*m)).collect(),
        }))
    }

    fn statement(member: u8) -> ProofStatement {
        ProofStatement {
            vkey_hash: B256::repeat_byte(7),
            public_values_digest: B256::repeat_byte(member),
        }
    }

    /// Each of op-aggregator's requests tells the pool it is there.
    #[tokio::test]
    async fn requests_attach_op_aggregator() {
        let block = BlockId { number: 10, hash: B256::ZERO };
        for request in 0..5 {
            let pool =
                ProofAggregationPool::default().requiring_aggregator(Duration::from_secs(60));
            assert_eq!(
                pool.dependencies_refused(),
                Some(ProofAggregationPoolError::AggregatorAbsent)
            );
            let api = OpAggregatorApi::new(pool.clone());
            match request {
                0 => {
                    let _ = api.status().await;
                }
                1 => {
                    let _ = api.next_provable_block(None).await;
                }
                2 => {
                    let _ = api.sources(vec![]).await;
                }
                3 => {
                    let _ = api.forget(block, vec![]).await;
                }
                _ => {
                    let aggregate = PendingAggregate {
                        version: 0,
                        aggregation_vkey_hash: B256::ZERO,
                        through: 10,
                        statements: vec![],
                        proof: Bytes::new(),
                    };
                    let _ = api.submit(aggregate, B256::ZERO).await;
                }
            }
            assert_eq!(pool.dependencies_refused(), None, "request {request}");
        }
    }

    /// Statements of one leaf share a source id, which resolves to the leaf; forgets are
    /// limited.
    #[tokio::test]
    async fn names_sources_by_statement_and_limits_forgets() {
        let pool = ProofAggregationPool::default();
        let source = leaf(&[1, 2]);
        let proofs: Vec<StatementProof> = [1, 2]
            .map(|m| StatementProof { statement: statement(m), source: source.clone() })
            .into();
        let ids: Vec<B256> = proofs.iter().map(|p| p.statement.id()).collect();
        pool.admit(B256::repeat_byte(0xaa), ids.clone(), proofs).unwrap();
        let hash = B256::repeat_byte(0x10);
        pool.on_canonical_block(10, hash, vec![(B256::repeat_byte(0xaa), ids)], 0);

        let api = OpAggregatorApi::new(pool.clone());
        let block = api.next_provable_block(None).await.unwrap().unwrap();
        assert_eq!(block.block, BlockId { number: 10, hash });
        assert_eq!(block.statements.len(), 2);
        assert_eq!(block.statements[0].source, block.statements[1].source, "one leaf, one id");
        let entries = api.sources(vec![block.statements[0].source, B256::ZERO]).await.unwrap();
        assert_eq!(entries.len(), 1, "an unknown id is left out");
        assert_eq!(entries[0].source, wire(source));
        assert_eq!(
            api.next_provable_block(Some(BlockId { number: 10, hash: B256::ZERO })).await,
            Err(AggregatorError::Reorged)
        );

        let other = BlockId { number: 10, hash: B256::ZERO };
        for _ in 0..MAX_FORGETS {
            api.forget(other, vec![]).await.unwrap();
        }
        assert_eq!(api.forget(other, vec![]).await, Err(AggregatorError::RateLimited));
    }
}
