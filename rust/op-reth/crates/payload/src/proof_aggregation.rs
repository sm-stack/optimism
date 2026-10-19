//! Sequencer-side queue for SP1 proof aggregation.
//!
//! Users submit the proofs behind their `ProofRegistry` statements to the sequencer off chain.
//! An external aggregator reads them, proves an aggregation program over a batch of statements and
//! hands the aggregate proof back. The payload builder then includes it as the block's proof
//! aggregate (`0x7C`) transaction, directly after the deposits.
//!
//! The pool is in-memory and starts empty on every boot. Every proof it accepts has already been
//! verified natively by the RPC handler; the pool itself only stores and hands them out.

use alloy_primitives::{B256, Bytes};
use op_alloy_consensus::ProofStatement;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
};

/// Upper bound on statement proofs held at once, so unaggregated submissions cannot grow the
/// pool without limit.
pub const MAX_STATEMENT_PROOFS: usize = 4096;

/// Upper bound on aggregates waiting for inclusion.
pub const MAX_PENDING_AGGREGATES: usize = 16;

/// A verified proof behind a `ProofRegistry` statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementProof {
    /// The statement the proof proves.
    pub statement: ProofStatement,
    /// The public values whose SHA-256 is `statement.public_values_digest`.
    pub public_values: Bytes,
    /// The SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
    /// The proven program's verifying key, bincode-encoded `SP1VerifyingKey`. The aggregation
    /// program needs the full key, not just `statement.vkey_hash`, to verify the proof
    /// recursively.
    pub verifying_key: Bytes,
}

/// A verified aggregate proof waiting to be included in a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAggregate {
    /// Verifying key digest of the aggregation program.
    pub aggregation_vkey_hash: B256,
    /// The statements the aggregate covers, in the order the aggregation program verified them.
    pub statements: Vec<ProofStatement>,
    /// The aggregation program's SP1 compressed proof, bincode-encoded `SP1Proof`.
    pub proof: Bytes,
}

/// Why the pool refused an insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofAggregationPoolError {
    /// The pool already holds [`MAX_STATEMENT_PROOFS`] statement proofs.
    #[error("statement proof pool is full")]
    StatementProofsFull,
    /// The pool already holds [`MAX_PENDING_AGGREGATES`] aggregates.
    #[error("pending aggregate queue is full")]
    AggregatesFull,
}

#[derive(Debug, Default)]
struct Inner {
    /// Statement proofs not yet covered by a submitted aggregate, keyed by statement id.
    statement_proofs: BTreeMap<B256, StatementProof>,
    /// Aggregates in submission order.
    aggregates: VecDeque<PendingAggregate>,
}

/// Shared handle to the sequencer's proof aggregation queue. Clones share the same state: the RPC
/// handlers write, the payload builder reads.
#[derive(Debug, Clone, Default)]
pub struct ProofAggregationPool {
    inner: Arc<Mutex<Inner>>,
}

impl ProofAggregationPool {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adds a verified statement proof. Re-submitting a statement replaces its proof.
    pub fn insert_statement_proof(
        &self,
        proof: StatementProof,
    ) -> Result<B256, ProofAggregationPoolError> {
        let id = proof.statement.id();
        let mut inner = self.lock();
        if !inner.statement_proofs.contains_key(&id) &&
            inner.statement_proofs.len() >= MAX_STATEMENT_PROOFS
        {
            return Err(ProofAggregationPoolError::StatementProofsFull);
        }
        inner.statement_proofs.insert(id, proof);
        Ok(id)
    }

    /// Returns the statement proofs waiting to be aggregated, ordered by statement id.
    pub fn statement_proofs(&self) -> Vec<StatementProof> {
        self.lock().statement_proofs.values().cloned().collect()
    }

    /// Queues a verified aggregate for inclusion and drops the statement proofs it covers.
    pub fn submit_aggregate(
        &self,
        aggregate: PendingAggregate,
    ) -> Result<(), ProofAggregationPoolError> {
        let mut inner = self.lock();
        if inner.aggregates.len() >= MAX_PENDING_AGGREGATES {
            return Err(ProofAggregationPoolError::AggregatesFull);
        }
        for statement in &aggregate.statements {
            inner.statement_proofs.remove(&statement.id());
        }
        inner.aggregates.push_back(aggregate);
        Ok(())
    }

    /// Returns the oldest aggregate waiting for inclusion, leaving it queued.
    ///
    /// An included aggregate stays queued: the payload may not become canonical. It is removed
    /// by [`Self::discard_aggregate`] once a later block fails to include it, which is what happens
    /// when the registry already marked its statements verified.
    pub fn next_aggregate(&self) -> Option<PendingAggregate> {
        self.lock().aggregates.front().cloned()
    }

    /// Removes `aggregate` from the queue, if it is still there.
    pub fn discard_aggregate(&self, aggregate: &PendingAggregate) {
        self.lock().aggregates.retain(|queued| queued != aggregate);
    }

    /// Number of aggregates waiting for inclusion.
    pub fn pending_aggregates(&self) -> usize {
        self.lock().aggregates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_proof(byte: u8) -> StatementProof {
        StatementProof {
            statement: ProofStatement {
                vkey_hash: B256::repeat_byte(byte),
                public_values_digest: B256::repeat_byte(byte),
            },
            public_values: Bytes::from(vec![byte]),
            proof: Bytes::from(vec![byte; 4]),
            verifying_key: Bytes::from(vec![byte; 2]),
        }
    }

    #[test]
    fn aggregate_consumes_its_statement_proofs() {
        let pool = ProofAggregationPool::default();
        let a = statement_proof(1);
        let b = statement_proof(2);
        pool.insert_statement_proof(a.clone()).unwrap();
        pool.insert_statement_proof(b.clone()).unwrap();

        let aggregate = PendingAggregate {
            aggregation_vkey_hash: B256::repeat_byte(9),
            statements: vec![a.statement],
            proof: Bytes::from_static(b"agg"),
        };
        pool.submit_aggregate(aggregate.clone()).unwrap();

        assert_eq!(pool.statement_proofs(), vec![b]);
        assert_eq!(pool.next_aggregate(), Some(aggregate.clone()));
        // Inclusion does not consume it; only discarding does.
        assert_eq!(pool.next_aggregate(), Some(aggregate.clone()));
        pool.discard_aggregate(&aggregate);
        assert_eq!(pool.next_aggregate(), None);
    }

    #[test]
    fn bounded_statement_proofs() {
        let pool = ProofAggregationPool::default();
        for i in 0..MAX_STATEMENT_PROOFS {
            let mut proof = statement_proof(0);
            proof.statement.vkey_hash = B256::from(alloy_primitives::U256::from(i));
            pool.insert_statement_proof(proof).unwrap();
        }
        assert_eq!(
            pool.insert_statement_proof(statement_proof(1)),
            Err(ProofAggregationPoolError::StatementProofsFull)
        );
        // Replacing an existing statement's proof is still allowed when full.
        let mut existing = statement_proof(0);
        existing.statement.vkey_hash = B256::ZERO;
        assert!(pool.insert_statement_proof(existing).is_ok());
    }
}
