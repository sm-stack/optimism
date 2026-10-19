//! RPC for SP1 proof aggregation on the sequencer.
//!
//! Users register a statement with the `ProofRegistry` predeploy on chain and send the proof behind
//! it here, off chain: `optimism_submitStatementProof`. An external aggregator reads the queued
//! proofs with `admin_pendingStatementProofs`, proves the aggregation program over a batch of them
//! and returns the aggregate with `admin_submitProofAggregate`. The payload builder then includes
//! it in the next block.
//!
//! The registry's `verifyStatements` reverts the whole aggregate if any statement it lists is not
//! pending, so every statement is checked against the latest registry state on the way in and
//! again when the aggregator reads or submits it. Every proof is verified natively before it is
//! queued. Nodes other than the sequencer forward submissions to it.

use alloy_op_evm::{PROOF_REGISTRY_ADDRESS, STATEMENT_STATUS_PENDING, statement_status_slot};
use alloy_primitives::{B256, Bytes};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::{
        ErrorObject, ErrorObjectOwned,
        error::{
            INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, SERVER_IS_BUSY_CODE, SERVER_IS_BUSY_MSG,
        },
    },
};
use op_alloy_consensus::{ProofStatement, statements_commitment};
use op_sp1_proofs::Sp1ProofAggregateVerifier;
use reth_optimism_payload_builder::proof_aggregation::{
    MAX_PROOF_BYTES, PendingAggregate, ProofAggregationPool, ProofAggregationPoolError,
    StatementProof,
};
use reth_storage_api::StateProviderFactory;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::SequencerClient;

/// Upper bound on SP1 verifications running at once. A user submission that finds every slot
/// taken is refused rather than queued.
pub const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// User-facing proof submission.
#[cfg_attr(not(test), rpc(server, namespace = "optimism"))]
#[cfg_attr(test, rpc(server, client, namespace = "optimism"))]
pub trait ProofStatementApi {
    /// Verifies `proof`, an SP1 compressed proof of the program `vkey_hash` committing to
    /// `public_values`, and queues it for aggregation. Returns the statement id.
    ///
    /// `verifying_key` is the program's bincode-encoded `SP1VerifyingKey`, which must hash to
    /// `vkey_hash`: the aggregation program needs the full key to verify the proof recursively.
    ///
    /// The statement must already be registered with the `ProofRegistry`, which charges its fee,
    /// and still be pending there in the latest block.
    #[method(name = "submitStatementProof")]
    async fn submit_statement_proof(
        &self,
        vkey_hash: B256,
        public_values: Bytes,
        proof: Bytes,
        verifying_key: Bytes,
    ) -> RpcResult<B256>;
}

/// Aggregator-facing methods, served on the admin namespace.
#[cfg_attr(not(test), rpc(server, namespace = "admin"))]
#[cfg_attr(test, rpc(server, client, namespace = "admin"))]
pub trait ProofAggregationAdminApi {
    /// Returns the verified statement proofs not yet covered by an aggregate, after dropping those
    /// whose statements the registry no longer holds pending.
    #[method(name = "pendingStatementProofs")]
    fn pending_statement_proofs(&self) -> RpcResult<Vec<StatementProof>>;

    /// Verifies an aggregate proof over `aggregate.statements` and queues it for inclusion. Every
    /// statement must be pending in the registry and listed once.
    #[method(name = "submitProofAggregate")]
    async fn submit_proof_aggregate(&self, aggregate: PendingAggregate) -> RpcResult<()>;
}

/// Server for both proof aggregation APIs, sharing the payload builder's pool.
#[derive(Clone)]
pub struct OpProofAggregationApi<Provider> {
    pool: ProofAggregationPool,
    provider: Provider,
    /// Set on nodes other than the sequencer, which forward user submissions to it.
    sequencer_client: Option<SequencerClient>,
    verifier: Arc<Sp1ProofAggregateVerifier>,
    verification_permits: Arc<Semaphore>,
}

impl<Provider> fmt::Debug for OpProofAggregationApi<Provider> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpProofAggregationApi")
            .field("pool", &self.pool)
            .field("sequencer_client", &self.sequencer_client)
            .finish_non_exhaustive()
    }
}

impl<Provider> OpProofAggregationApi<Provider> {
    /// Creates a server over `pool`, which must be the pool the payload builder reads, reading the
    /// registry from `provider`. With a `sequencer_client`, user submissions are forwarded to the
    /// sequencer instead.
    pub fn new(
        pool: ProofAggregationPool,
        provider: Provider,
        sequencer_client: Option<SequencerClient>,
    ) -> Self {
        Self {
            pool,
            provider,
            sequencer_client,
            verifier: Arc::new(Sp1ProofAggregateVerifier::new()),
            verification_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
        }
    }

    /// Runs `verify` on a blocking thread, holding `permit` until it finishes even if the caller
    /// goes away: SP1 verification takes tens of milliseconds. A rejection is reported as invalid
    /// params.
    async fn verify_blocking(
        &self,
        permit: OwnedSemaphorePermit,
        verify: impl FnOnce(&Sp1ProofAggregateVerifier) -> Result<(), String> + Send + 'static,
    ) -> RpcResult<()> {
        let verifier = self.verifier.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify(&verifier)
        })
        .await
        .map_err(|err| internal_error(err.to_string()))?
        .map_err(invalid_params)
    }
}

impl<Provider: StateProviderFactory> OpProofAggregationApi<Provider> {
    /// Returns the statements among `ids` that the registry does not hold pending in the latest
    /// block.
    fn not_pending(&self, ids: impl IntoIterator<Item = B256>) -> RpcResult<Vec<B256>> {
        let state = self.provider.latest().map_err(|err| internal_error(err.to_string()))?;
        let mut not_pending = Vec::new();
        for id in ids {
            let status = state
                .storage(PROOF_REGISTRY_ADDRESS, statement_status_slot(id))
                .map_err(|err| internal_error(err.to_string()))?
                .unwrap_or_default();
            if status != STATEMENT_STATUS_PENDING {
                not_pending.push(id);
            }
        }
        Ok(not_pending)
    }

    /// Fails unless the registry holds every statement in `ids` pending.
    fn ensure_pending(&self, ids: impl IntoIterator<Item = B256>) -> RpcResult<()> {
        self.not_pending(ids)?.first().map_or(Ok(()), |id| {
            Err(invalid_params(format!("statement {id} is not pending in the ProofRegistry")))
        })
    }
}

fn invalid_params(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(INVALID_PARAMS_CODE, message, None::<()>)
}

fn internal_error(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(INTERNAL_ERROR_CODE, message, None::<()>)
}

fn busy(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(SERVER_IS_BUSY_CODE, message, None::<()>)
}

fn pool_error(err: ProofAggregationPoolError) -> ErrorObjectOwned {
    match err {
        ProofAggregationPoolError::StatementProofsFull |
        ProofAggregationPoolError::AggregatesFull => busy(err.to_string()),
        ProofAggregationPoolError::TooLarge { .. } | ProofAggregationPoolError::AlreadyQueued => {
            invalid_params(err.to_string())
        }
    }
}

#[async_trait]
impl<Provider> ProofStatementApiServer for OpProofAggregationApi<Provider>
where
    Provider: StateProviderFactory + Send + Sync + 'static,
{
    async fn submit_statement_proof(
        &self,
        vkey_hash: B256,
        public_values: Bytes,
        proof: Bytes,
        verifying_key: Bytes,
    ) -> RpcResult<B256> {
        ProofAggregationPool::check_sizes(&public_values, &proof, &verifying_key)
            .map_err(pool_error)?;
        if let Some(sequencer) = &self.sequencer_client {
            return sequencer
                .request(
                    "optimism_submitStatementProof",
                    (vkey_hash, public_values, proof, verifying_key),
                )
                .await
                .map_err(Into::into);
        }

        // Cheap checks first, so a submission that cannot be queued costs no verification.
        let statement = ProofStatement {
            vkey_hash,
            public_values_digest: B256::from(<[u8; 32]>::from(Sha256::digest(&public_values))),
        };
        let id = statement.id();
        self.ensure_pending([id])?;
        self.pool.check_room(id).map_err(pool_error)?;
        let permit = self
            .verification_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy(String::from(SERVER_IS_BUSY_MSG)))?;

        let (values, bytes, vk) = (public_values.clone(), proof.clone(), verifying_key.clone());
        self.verify_blocking(permit, move |verifier| {
            op_sp1_proofs::decode_verifying_key(&vk, vkey_hash)
                .map_err(|reason| format!("verifying key rejected: {reason}"))?;
            verifier
                .verify_with_public_values(vkey_hash, &values, &bytes)
                .map_err(|reason| format!("proof rejected: {reason}"))
        })
        .await?;
        self.pool
            .insert_statement_proof(StatementProof {
                statement,
                public_values,
                proof,
                verifying_key,
            })
            .map_err(pool_error)
    }
}

#[async_trait]
impl<Provider> ProofAggregationAdminApiServer for OpProofAggregationApi<Provider>
where
    Provider: StateProviderFactory + Send + Sync + 'static,
{
    fn pending_statement_proofs(&self) -> RpcResult<Vec<StatementProof>> {
        let proofs = self.pool.statement_proofs();
        let stale = self.not_pending(proofs.iter().map(|proof| proof.statement.id()))?;
        self.pool.remove_statement_proofs(&stale);
        Ok(proofs.into_iter().filter(|proof| !stale.contains(&proof.statement.id())).collect())
    }

    async fn submit_proof_aggregate(&self, aggregate: PendingAggregate) -> RpcResult<()> {
        if aggregate.statements.is_empty() {
            return Err(invalid_params(String::from("aggregate covers no statements")));
        }
        if aggregate.proof.len() > MAX_PROOF_BYTES {
            return Err(pool_error(ProofAggregationPoolError::TooLarge {
                field: "proof",
                limit: MAX_PROOF_BYTES,
            }));
        }
        let ids: Vec<B256> = aggregate.statements.iter().map(ProofStatement::id).collect();
        if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            return Err(invalid_params(String::from("aggregate lists a statement twice")));
        }
        self.ensure_pending(ids)?;

        let permit = self
            .verification_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|err| internal_error(err.to_string()))?;
        let (vkey, commitment, proof) = (
            aggregate.aggregation_vkey_hash,
            statements_commitment(&aggregate.statements),
            aggregate.proof.clone(),
        );
        self.verify_blocking(permit, move |verifier| {
            verifier
                .verify_with_public_values(vkey, commitment.as_slice(), &proof)
                .map_err(|reason| format!("proof rejected: {reason}"))
        })
        .await?;
        self.pool.submit_aggregate(aggregate).map_err(pool_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};

    /// A provider whose registry holds each statement in `pending` pending.
    fn registry(pending: &[ProofStatement]) -> MockEthProvider {
        let provider = MockEthProvider::new();
        provider.add_account(
            PROOF_REGISTRY_ADDRESS,
            ExtendedAccount::new(1, U256::ZERO).extend_storage(
                pending
                    .iter()
                    .map(|statement| (statement_status_slot(statement.id()), U256::from(1))),
            ),
        );
        provider
    }

    fn api(pending: &[ProofStatement]) -> OpProofAggregationApi<MockEthProvider> {
        OpProofAggregationApi::new(ProofAggregationPool::default(), registry(pending), None)
    }

    fn statement(public_values: &[u8]) -> ProofStatement {
        ProofStatement {
            vkey_hash: B256::ZERO,
            public_values_digest: B256::from(<[u8; 32]>::from(Sha256::digest(public_values))),
        }
    }

    fn statement_proof(public_values: &'static [u8]) -> StatementProof {
        StatementProof {
            statement: statement(public_values),
            public_values: Bytes::from_static(public_values),
            proof: Bytes::from_static(b"proof"),
            verifying_key: Bytes::from_static(b"vk"),
        }
    }

    async fn submit(
        api: &OpProofAggregationApi<MockEthProvider>,
        public_values: &'static [u8],
    ) -> ErrorObjectOwned {
        api.submit_statement_proof(
            B256::ZERO,
            Bytes::from_static(public_values),
            Bytes::from_static(b"x"),
            Bytes::from_static(b"vk"),
        )
        .await
        .unwrap_err()
    }

    #[tokio::test]
    async fn rejects_statement_not_pending() {
        let api = api(&[]);
        let err = submit(&api, b"pv").await;
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("not pending"), "{err}");
    }

    #[tokio::test]
    async fn rejects_oversized_proof() {
        let api = api(&[statement(b"pv")]);
        let err = api
            .submit_statement_proof(
                B256::ZERO,
                Bytes::from_static(b"pv"),
                Bytes::from(vec![0; MAX_PROOF_BYTES + 1]),
                Bytes::from_static(b"vk"),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("proof exceeds"), "{err}");
    }

    #[tokio::test]
    async fn rejects_invalid_statement_proof() {
        let api = api(&[statement(b"pv")]);
        let err = submit(&api, b"pv").await;
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("verifying key rejected"), "{err}");
        assert!(api.pool.statement_proofs().is_empty());
        // The permit is released once verification ends.
        assert_eq!(api.verification_permits.available_permits(), MAX_CONCURRENT_VERIFICATIONS);
    }

    #[tokio::test]
    async fn refuses_when_every_verification_slot_is_taken() {
        let api = api(&[statement(b"pv")]);
        let _held = api
            .verification_permits
            .clone()
            .acquire_many_owned(MAX_CONCURRENT_VERIFICATIONS as u32)
            .await
            .unwrap();
        assert_eq!(submit(&api, b"pv").await.code(), SERVER_IS_BUSY_CODE);
    }

    #[tokio::test]
    async fn refuses_a_statement_already_queued() {
        let queued = statement_proof(b"pv");
        let api = api(&[queued.statement]);
        api.pool.insert_statement_proof(queued).unwrap();
        let err = submit(&api, b"pv").await;
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("already queued"), "{err}");
    }

    #[tokio::test]
    async fn pending_statement_proofs_drops_statements_no_longer_pending() {
        let (kept, stale) = (statement_proof(b"kept"), statement_proof(b"stale"));
        let api = api(&[kept.statement]);
        api.pool.insert_statement_proof(kept.clone()).unwrap();
        api.pool.insert_statement_proof(stale).unwrap();

        assert_eq!(api.pending_statement_proofs().unwrap(), vec![kept.clone()]);
        assert_eq!(api.pool.statement_proofs(), vec![kept]);
    }

    #[tokio::test]
    async fn rejects_empty_or_invalid_aggregate() {
        let pending = statement(b"pv");
        let api = api(&[pending]);
        let aggregate = |statements: Vec<ProofStatement>| PendingAggregate {
            aggregation_vkey_hash: B256::ZERO,
            statements,
            proof: Bytes::from_static(b"x"),
        };
        let rejection = async |statements| {
            let err = api.submit_proof_aggregate(aggregate(statements)).await.unwrap_err();
            assert_eq!(err.code(), INVALID_PARAMS_CODE);
            err.message().to_owned()
        };

        assert!(rejection(vec![]).await.contains("no statements"));
        assert!(rejection(vec![pending, pending]).await.contains("twice"));
        assert!(rejection(vec![pending, statement(b"other")]).await.contains("not pending"));
        assert!(rejection(vec![pending]).await.contains("proof rejected"));
        assert_eq!(api.pool.pending_aggregates(), 0);
    }
}
