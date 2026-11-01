//! Test doubles shared by the dependency stages' tests.

use crate::{
    BatchStreamProvider, OriginAdvancer, OriginProvider, PipelineError, PipelineResult, Stage,
};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use alloy_eips::{BlockNumHash, eip2718::Encodable2718};
use alloy_primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use kona_genesis::SystemConfig;
use kona_protocol::{Batch, BlockInfo, SingleBatch};
use op_alloy_consensus::{
    AaCall, AccountChange, Dependency, LEANVM_TREE_CLASS_KEY_DIGEST, LeanVmTreeProof,
    PROOF_AGGREGATE_PAYLOAD_VERSION, PROOF_STATEMENT_SCHEME, ProofAggregatePayload,
    ProofAggregateVerifier, ProofStatement, TxEip8430,
};

/// Accepts exactly the root `ok`.
#[derive(Debug)]
pub(super) struct Verifier;

impl ProofAggregateVerifier for Verifier {
    fn verify(&self, _: &[ProofStatement], root: &[u8], _: &[u8]) -> Result<(), String> {
        if root == b"ok" { Ok(()) } else { Err(String::from("bad proof")) }
    }
}

/// Batches per L1 block, by block number; the stack ends after the last one.
#[derive(Debug, Default)]
pub(super) struct Stack {
    pub(super) blocks: Vec<Vec<Batch>>,
    pub(super) current: u64,
    pub(super) next: usize,
    pub(super) resets: Vec<u64>,
}

impl AsRef<[u64]> for Stack {
    fn as_ref(&self) -> &[u64] {
        &self.resets
    }
}

#[async_trait]
impl BatchStreamProvider for Stack {
    async fn next_batch(&mut self) -> PipelineResult<Batch> {
        let batch = self.blocks[self.current as usize].get(self.next).cloned();
        self.next += 1;
        batch.ok_or(PipelineError::Eof.temp())
    }

    fn flush(&mut self) {}
}

#[async_trait]
impl OriginAdvancer for Stack {
    async fn advance_origin(&mut self) -> PipelineResult<()> {
        if self.current as usize + 1 >= self.blocks.len() {
            return Err(PipelineError::EndOfSource.crit());
        }
        self.current += 1;
        self.next = 0;
        Ok(())
    }
}

impl OriginProvider for Stack {
    fn origin(&self) -> Option<BlockInfo> {
        Some(l1(self.current))
    }
}

#[async_trait]
impl Stage for Stack {
    async fn reset(&mut self, origin: BlockNumHash, _: SystemConfig) -> PipelineResult<()> {
        self.resets.push(origin.number);
        self.current = origin.number;
        self.next = 0;
        Ok(())
    }

    async fn activate(&mut self) -> PipelineResult<()> {
        Ok(())
    }

    async fn flush_channel(&mut self) -> PipelineResult<()> {
        Ok(())
    }
}

pub(super) fn l1(number: u64) -> BlockInfo {
    BlockInfo { number, timestamp: number * 12, ..Default::default() }
}

pub(super) fn statement(byte: u8) -> ProofStatement {
    ProofStatement {
        vkey_hash: B256::repeat_byte(byte),
        public_values_digest: B256::repeat_byte(byte),
    }
}

/// A proof aggregate batch answering through block `through`, whose tree root is `root`.
pub(super) fn aggregate(through: u64, statements: &[ProofStatement], root: &'static [u8]) -> Batch {
    let proof = LeanVmTreeProof { root: Bytes::from_static(root), seal: Bytes::new() };
    Batch::ProofAggregate(ProofAggregatePayload {
        version: PROOF_AGGREGATE_PAYLOAD_VERSION,
        through,
        aggregation_vkey_hash: LEANVM_TREE_CLASS_KEY_DIGEST,
        statements: statements.to_vec(),
        proof: proof.to_rlp_bytes(),
    })
}

/// A singular batch for L2 block `block` (2 second blocks from genesis 0).
pub(super) fn batch(block: u64, txs: Vec<Bytes>) -> Batch {
    Batch::Single(SingleBatch { timestamp: block * 2, transactions: txs, ..Default::default() })
}

/// An encoded EIP-8430 transaction declaring `statements` as dependencies (an empty entry for
/// none), made distinct by `nonce`.
pub(super) fn aa_tx(nonce: u64, statements: &[ProofStatement]) -> Bytes {
    let dependencies = statements
        .iter()
        .map(|statement| Dependency {
            scheme: PROOF_STATEMENT_SCHEME,
            data_hash: statement.public_values_digest,
            verification_key_hash: statement.vkey_hash,
        })
        .collect();
    TxEip8430 {
        chain_id: 10,
        nonce_sequence: nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 10,
        gas_limit: 100_000,
        account_changes: vec![AccountChange::Dependencies { dependencies }],
        calls: vec![vec![AaCall {
            to: Address::repeat_byte(0x42),
            value: U256::ZERO,
            data: Bytes::new(),
        }]],
        sender_auth: Bytes::from(vec![0x5e; 65]),
        ..Default::default()
    }
    .encoded_2718()
    .into()
}
