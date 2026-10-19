//! RPC for SP1 proof aggregation on the sequencer.
//!
//! Users register a statement with the `ProofRegistry` predeploy on chain and send the proof behind
//! it here, off chain: `optimism_submitStatementProof`. An external aggregator reads the queued
//! proofs with `admin_pendingStatementProofs`, proves the aggregation program over a batch of them
//! and returns the aggregate with `admin_submitProofAggregate`. The payload builder then includes
//! it in the next block. Every proof is verified natively before it is queued.

use alloy_primitives::{B256, Bytes};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::{ErrorObject, ErrorObjectOwned, error::INVALID_PARAMS_CODE},
};
use op_alloy_consensus::{ProofStatement, statements_commitment};
use op_sp1_proofs::Sp1ProofAggregateVerifier;
use reth_optimism_payload_builder::proof_aggregation::{
    PendingAggregate, ProofAggregationPool, StatementProof,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

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
    /// The statement must also be submitted to the `ProofRegistry`, which charges its fee; an
    /// aggregate covering a statement the registry does not hold pending is not included.
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
    /// Returns the verified statement proofs not yet covered by an aggregate.
    #[method(name = "pendingStatementProofs")]
    fn pending_statement_proofs(&self) -> RpcResult<Vec<StatementProof>>;

    /// Verifies an aggregate proof over `aggregate.statements` and queues it for inclusion.
    #[method(name = "submitProofAggregate")]
    async fn submit_proof_aggregate(&self, aggregate: PendingAggregate) -> RpcResult<()>;
}

/// Server for both proof aggregation APIs, sharing the payload builder's pool.
#[derive(Debug, Clone)]
pub struct OpProofAggregationApi {
    pool: ProofAggregationPool,
    verifier: Arc<Sp1ProofAggregateVerifier>,
}

impl OpProofAggregationApi {
    /// Creates a server over `pool`, which must be the pool the payload builder reads.
    pub fn new(pool: ProofAggregationPool) -> Self {
        Self { pool, verifier: Arc::new(Sp1ProofAggregateVerifier::new()) }
    }

    /// Runs `verify` on a blocking thread: SP1 verification takes tens of milliseconds.
    async fn verify_blocking(
        &self,
        verify: impl FnOnce(&Sp1ProofAggregateVerifier) -> Result<(), String> + Send + 'static,
    ) -> RpcResult<()> {
        let verifier = self.verifier.clone();
        tokio::task::spawn_blocking(move || verify(&verifier))
            .await
            .map_err(|err| internal_error(err.to_string()))?
            .map_err(|reason| invalid_params(format!("proof rejected: {reason}")))
    }
}

fn invalid_params(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(INVALID_PARAMS_CODE, message, None::<()>)
}

fn internal_error(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(jsonrpsee::types::error::INTERNAL_ERROR_CODE, message, None::<()>)
}

#[async_trait]
impl ProofStatementApiServer for OpProofAggregationApi {
    async fn submit_statement_proof(
        &self,
        vkey_hash: B256,
        public_values: Bytes,
        proof: Bytes,
        verifying_key: Bytes,
    ) -> RpcResult<B256> {
        op_sp1_proofs::decode_verifying_key(&verifying_key, vkey_hash)
            .map_err(|reason| invalid_params(format!("verifying key rejected: {reason}")))?;
        let statement = ProofStatement {
            vkey_hash,
            public_values_digest: B256::from(<[u8; 32]>::from(Sha256::digest(&public_values))),
        };
        let (values, bytes) = (public_values.clone(), proof.clone());
        self.verify_blocking(move |verifier| {
            verifier.verify_with_public_values(vkey_hash, &values, &bytes)
        })
        .await?;
        self.pool
            .insert_statement_proof(StatementProof {
                statement,
                public_values,
                proof,
                verifying_key,
            })
            .map_err(|err| internal_error(err.to_string()))
    }
}

#[async_trait]
impl ProofAggregationAdminApiServer for OpProofAggregationApi {
    fn pending_statement_proofs(&self) -> RpcResult<Vec<StatementProof>> {
        Ok(self.pool.statement_proofs())
    }

    async fn submit_proof_aggregate(&self, aggregate: PendingAggregate) -> RpcResult<()> {
        if aggregate.statements.is_empty() {
            return Err(invalid_params(String::from("aggregate covers no statements")));
        }
        let (vkey, commitment, proof) = (
            aggregate.aggregation_vkey_hash,
            statements_commitment(&aggregate.statements),
            aggregate.proof.clone(),
        );
        self.verify_blocking(move |verifier| {
            verifier.verify_with_public_values(vkey, commitment.as_slice(), &proof)
        })
        .await?;
        self.pool.submit_aggregate(aggregate).map_err(|err| internal_error(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_invalid_statement_proof() {
        let api = OpProofAggregationApi::new(ProofAggregationPool::default());
        let err = api
            .submit_statement_proof(
                B256::ZERO,
                Bytes::from_static(b"pv"),
                Bytes::from_static(b"x"),
                Bytes::from_static(b"vk"),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(api.pool.statement_proofs().is_empty());
    }

    #[tokio::test]
    async fn rejects_empty_or_invalid_aggregate() {
        let api = OpProofAggregationApi::new(ProofAggregationPool::default());
        let empty = PendingAggregate {
            aggregation_vkey_hash: B256::ZERO,
            statements: vec![],
            proof: Bytes::new(),
        };
        assert_eq!(
            api.submit_proof_aggregate(empty).await.unwrap_err().code(),
            INVALID_PARAMS_CODE
        );

        let bogus = PendingAggregate {
            aggregation_vkey_hash: B256::ZERO,
            statements: vec![ProofStatement::default()],
            proof: Bytes::from_static(b"x"),
        };
        assert_eq!(
            api.submit_proof_aggregate(bogus).await.unwrap_err().code(),
            INVALID_PARAMS_CODE
        );
        assert_eq!(api.pool.pending_aggregates(), 0);
    }
}
