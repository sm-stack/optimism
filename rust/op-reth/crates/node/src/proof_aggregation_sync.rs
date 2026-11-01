//! Keeps the sequencer's proof aggregation pool in step with the canonical chain and its safe and
//! finalized heads.

use alloy_consensus::BlockHeader;
use alloy_eips::{Typed2718, eip2718::Encodable2718};
use futures_util::StreamExt;
use op_alloy_consensus::AA_TX_TYPE_ID;
use reth_chain_state::{CanonStateNotificationStream, ForkChoiceStream};
use reth_optimism_payload_builder::proof_aggregation::{ProofAggregationPool, dependency_facts};
use reth_primitives_traits::{BlockBody, NodePrimitives, SealedHeader};

/// Feeds every canonical block to `pool`, so that what the pool believes blocks hold (dependent
/// transactions) is what the chain holds rather than what a payload attempt tried. A reorg needs no
/// call of its own: its new blocks start where the reverted ones did, and the pool rolls back from
/// the first. (Unwinding the head to an ancestor sends no notification; the next block built on
/// it rolls back the same way.)
pub async fn sync_proof_aggregation_pool<N>(
    pool: ProofAggregationPool,
    mut stream: CanonStateNotificationStream<N>,
) where
    N: NodePrimitives,
{
    while let Some(notification) = stream.next().await {
        for block in notification.committed().blocks_iter() {
            let txs = block.body().transactions();
            let bytes = txs.iter().map(|tx| tx.encode_2718_len() as u64).sum();
            let encoded: Vec<Vec<u8>> = txs
                .iter()
                .filter(|tx| tx.ty() == AA_TX_TYPE_ID)
                .map(|tx| tx.encoded_2718())
                .collect();
            let dependent = dependency_facts(encoded.iter().map(Vec::as_slice));
            pool.on_canonical_block(block.header().number(), block.hash(), dependent, bytes);
        }
    }
}

/// Feeds every new safe and finalized head to `pool`: the batcher posts the aggregates above the
/// safe head, and the pool forgets those the finalized head reaches.
pub async fn sync_proof_aggregation_forkchoice<H>(
    pool: ProofAggregationPool,
    safe: ForkChoiceStream<SealedHeader<H>>,
    finalized: ForkChoiceStream<SealedHeader<H>>,
) where
    H: BlockHeader + Clone + Send + Sync + 'static,
{
    let safe = safe.map(|header| (false, header.number()));
    let finalized = finalized.map(|header| (true, header.number()));
    let mut heads = futures_util::stream::select(safe, finalized);
    while let Some((finalized, number)) = heads.next().await {
        if finalized {
            pool.on_finalized(number);
        } else {
            pool.on_safe(number);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes};
    use op_aggregator::{AGGREGATE_DELAY, Folder};
    use op_alloy_consensus::{ProofAggregatePayload, ProofStatement};
    use op_leanvm_tree::{LeanVmTreeVerifier, Signed};
    use reth_optimism_payload_builder::proof_aggregation::{
        ProgramLeaf, ProofAggregationPool, SignatureSource, StatementProof, StatementSource,
    };
    use reth_optimism_rpc::aggregator::OpAggregatorApi;
    use std::{sync::Arc, time::Instant};

    const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../op-leanvm-tree/testdata");

    fn testdata(name: &str) -> Bytes {
        std::fs::read(format!("{TESTDATA}/{name}")).unwrap().into()
    }

    /// The fixture's program leaf `name`, as the pool holds its statement.
    fn program(name: &str) -> StatementProof {
        let key = testdata(&format!("{name}.key"));
        let proof = testdata(&format!("{name}.proof"));
        let members: Vec<B256> =
            testdata(&format!("{name}.members")).chunks_exact(32).map(B256::from_slice).collect();
        let vkey_hash = op_leanvm_tree::verify_program_leaf(&key, &members, &proof).unwrap();
        StatementProof {
            statement: ProofStatement { vkey_hash, public_values_digest: members[0] },
            source: StatementSource::Program(Arc::new(ProgramLeaf {
                program: vkey_hash,
                verifying_key: key,
                proof,
                members,
            })),
        }
    }

    /// The fixture's signature `i`, as the pool holds its statement.
    fn signature(i: u8) -> StatementProof {
        let source = SignatureSource {
            public_key: testdata(&format!("signature-{i}.key")),
            message: B256::from_slice(&testdata(&format!("signature-{i}.message"))),
            signature: testdata(&format!("signature-{i}.signature")),
        };
        StatementProof {
            statement: Signed::decode(&source.public_key, source.message, &source.signature)
                .unwrap()
                .statement(),
            source: StatementSource::Signature(Arc::new(source)),
        }
    }

    /// The hash of block `number` in these tests' chain.
    fn hash(number: u64) -> B256 {
        B256::left_padding_from(&number.to_be_bytes())
    }

    /// A pool verifying aggregates as the sequencer's does.
    fn pool() -> ProofAggregationPool {
        ProofAggregationPool::default().with_verifier(Arc::new(LeanVmTreeVerifier))
    }

    /// Admits a transaction depending on `proofs` and makes canonical block `number` hold it.
    fn include(pool: &ProofAggregationPool, number: u64, proofs: Vec<StatementProof>) {
        let ids: Vec<B256> = proofs.iter().map(|proof| proof.statement.id()).collect();
        let tx = alloy_primitives::keccak256(ids.concat());
        pool.admit(tx, ids.clone(), proofs).unwrap();
        pool.on_canonical_block(number, hash(number), vec![(tx, ids)], 0);
    }

    /// op-aggregator's folder over the namespace it reads, in process. The aggregate it closes
    /// passes the pool's verification and answers for both blocks.
    #[tokio::test(flavor = "multi_thread")]
    async fn folds_blocks_and_closes_a_verified_aggregate() {
        let pool = pool();
        include(&pool, 5, vec![program("fibonacci-2700"), signature(0)]);
        include(&pool, 6, vec![program("preimage-8"), signature(1), signature(0)]);
        let mut folder = Folder::new(OpAggregatorApi::new(pool.clone()));
        let start = Instant::now();
        assert!(folder.tick(start).await.unwrap(), "folded block 5");
        assert!(folder.tick(start).await.unwrap(), "folded block 6");
        assert!(!folder.tick(start).await.unwrap(), "nothing more to fold");
        assert!(pool.pending_aggregates().is_empty(), "not due yet");

        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        let aggregates = pool.pending_aggregates();
        assert_eq!(aggregates.len(), 1);
        let aggregate = aggregates[0].clone();
        assert_eq!(aggregate.through, 6);
        assert_eq!(aggregate.statements.len(), 4, "two program members and two signatures");
        ProofAggregatePayload::from(aggregate).verify(&LeanVmTreeVerifier).unwrap();
    }

    /// A block whose sources do not fold has them forgotten, so that it stalls nothing. A block
    /// folds whole or not at all, so the run goes on without it, and the tick asks for the next
    /// block.
    #[tokio::test(flavor = "multi_thread")]
    async fn forgets_a_block_that_does_not_fold() {
        let pool = pool();
        let mut broken = program("preimage-8");
        let StatementSource::Program(leaf) = &broken.source else { unreachable!() };
        let mut leaf = (**leaf).clone();
        leaf.proof = Bytes::from_static(b"not a proof");
        broken.source = StatementSource::Program(Arc::new(leaf));
        include(&pool, 5, vec![broken]);
        let mut folder = Folder::new(OpAggregatorApi::new(pool.clone()));
        assert!(folder.tick(Instant::now()).await.unwrap(), "the run goes on without the block");
        assert_eq!(pool.next_provable_block(None), Ok(None), "its sources are forgotten");
    }

    /// A reorg replacing a folded block drops the run: the aggregate proves the new block.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reorg_drops_the_folded_blocks() {
        let pool = pool();
        include(&pool, 5, vec![signature(0)]);
        let mut folder = Folder::new(OpAggregatorApi::new(pool.clone()));
        let start = Instant::now();
        folder.tick(start).await.unwrap();
        // A reorg replaces block 5 with one depending on another signature.
        pool.on_canonical_block(4, hash(4), vec![], 0);
        let ids = vec![signature(1).statement.id()];
        let tx = B256::repeat_byte(0x51);
        pool.admit(tx, ids.clone(), vec![signature(1)]).unwrap();
        pool.on_canonical_block(5, B256::repeat_byte(0x55), vec![(tx, ids)], 0);
        folder.tick(start).await.unwrap();
        folder.tick(start).await.unwrap();
        folder.tick(start + AGGREGATE_DELAY).await.unwrap();
        let aggregates = pool.pending_aggregates();
        assert_eq!(aggregates.len(), 1);
        assert_eq!(aggregates[0].statements, vec![signature(1).statement]);
    }
}
