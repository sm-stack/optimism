//! A folder whose helpers (`op-aggregator prove-worker`) prove first-level nodes ahead submits the
//! aggregate a folder without them does.

use alloy_primitives::{B256, Bytes, keccak256};
use op_aggregator::{
    Backend, Folder, ProveAhead,
    api::{AggregatorError, BlockId, BlockStatements, Source, SourceEntry, StatementRef, Status},
};
use op_alloy_consensus::{PendingAggregate, ProofStatement};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../op-leanvm-tree/testdata");

fn testdata(name: &str) -> Bytes {
    std::fs::read(format!("{TESTDATA}/{name}")).unwrap().into()
}

fn block(number: u64) -> BlockId {
    BlockId { number, hash: keccak256(number.to_be_bytes()) }
}

/// Blocks depending on program leaves, a fixed run ending at the last, and what was submitted.
#[derive(Default)]
struct Chain {
    blocks: Vec<BlockStatements>,
    sources: HashMap<B256, Source>,
    submitted: Vec<PendingAggregate>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Chain>>);

impl Fake {
    /// A chain of `blocks`, each depending on the program leaves it names.
    fn with_blocks(blocks: &[&[&str]]) -> Self {
        let fake = Self::default();
        let mut chain = fake.0.lock().unwrap();
        for (i, names) in blocks.iter().enumerate() {
            let mut statements: Vec<StatementRef> = Vec::new();
            for name in *names {
                let verifying_key = testdata(&format!("{name}.key"));
                let members: Vec<B256> = testdata(&format!("{name}.members"))
                    .chunks_exact(32)
                    .map(B256::from_slice)
                    .collect();
                let program = op_leanvm_tree::program_digest(&verifying_key).unwrap();
                let of: Vec<ProofStatement> = members
                    .iter()
                    .map(|m| ProofStatement { vkey_hash: program, public_values_digest: *m })
                    .collect();
                let id = of[0].id();
                let proof = testdata(&format!("{name}.proof"));
                chain
                    .sources
                    .insert(id, Source::Program { program, verifying_key, proof, members });
                statements
                    .extend(of.into_iter().map(|statement| StatementRef { statement, source: id }));
            }
            statements.sort_by_key(|s| s.statement.id());
            chain.blocks.push(BlockStatements { block: block(i as u64 + 1), statements });
        }
        drop(chain);
        fake
    }
}

#[async_trait::async_trait]
impl Backend for Fake {
    async fn status(&self) -> Result<Status, AggregatorError> {
        let chain = self.0.lock().unwrap();
        let head = chain.blocks.last().map(|b| b.block);
        Ok(Status {
            head,
            safe: None,
            finalized: None,
            last_through: chain.submitted.last().map(|a| a.through),
            queue_full: false,
            paused: false,
            run_blocks: head.map_or(0, |head| head.number + 1),
            bytes_due: false,
            due_through: None,
        })
    }

    async fn next_provable_block(
        &self,
        after: Option<BlockId>,
    ) -> Result<Option<BlockStatements>, AggregatorError> {
        let chain = self.0.lock().unwrap();
        let from = after.map(|b| b.number).max(chain.submitted.last().map(|a| a.through));
        Ok(chain.blocks.iter().find(|b| from.is_none_or(|from| b.block.number > from)).cloned())
    }

    async fn sources(&self, ids: Vec<B256>) -> Result<Vec<SourceEntry>, AggregatorError> {
        let chain = self.0.lock().unwrap();
        Ok(ids
            .into_iter()
            .map(|id| SourceEntry { id, source: chain.sources[&id].clone() })
            .collect())
    }

    async fn forget(&self, _: BlockId, _: Vec<ProofStatement>) -> Result<(), AggregatorError> {
        panic!("nothing is forgotten")
    }

    async fn submit(&self, aggregate: PendingAggregate, _: B256) -> Result<(), AggregatorError> {
        self.0.lock().unwrap().submitted.push(aggregate);
        Ok(())
    }
}

/// Ticks `folder` until it submits an aggregate. The clock stands still, so that the run closes
/// at the last block, its boundary, however long folding takes, never after `AGGREGATE_DELAY`.
async fn submitted<B: Backend>(folder: &mut Folder<B>, fake: &Fake) -> PendingAggregate {
    let now = Instant::now();
    for _ in 0..50 {
        folder.tick(now).await.unwrap();
        if let Some(aggregate) = fake.0.lock().unwrap().submitted.first() {
            return aggregate.clone();
        }
    }
    panic!("no aggregate");
}

/// A folder proving ahead and one that does not submit the same aggregate of `blocks`; the
/// helpers proved some of the nodes the first took.
async fn same_aggregate(blocks: &[&[&str]]) {
    let ahead = ProveAhead {
        workers: 2,
        blocks: 4,
        threads: Some(2),
        command: vec![env!("CARGO_BIN_EXE_op-aggregator").into(), "prove-worker".into()],
    };
    let fake = Fake::with_blocks(blocks);
    let mut folder = Folder::with_prove_ahead(fake.clone(), &ahead);
    let with = submitted(&mut folder, &fake).await;
    let stats = folder.prove_ahead_stats().unwrap();
    assert!(stats.hits + stats.waits > 0, "the helpers proved some nodes: {stats:?}");

    let fake = Fake::with_blocks(blocks);
    let without = submitted(&mut Folder::new(fake.clone()), &fake).await;
    assert_eq!(with.statements, without.statements);
    assert_eq!(with.through, without.through);
}

#[tokio::test(flavor = "multi_thread")]
async fn proving_ahead_folds_the_same_aggregate() {
    same_aggregate(&[
        &["fibonacci-1000"],
        &["fibonacci-2700"],
        &["preimage-8"],
        &["preimage-8-zk"],
    ])
    .await;
}

/// Blocks of two leaves each: the helpers prove their subtrees' nodes too.
#[tokio::test(flavor = "multi_thread")]
async fn proving_block_subtrees_ahead_folds_the_same_aggregate() {
    same_aggregate(&[&["fibonacci-1000", "fibonacci-2700"], &["preimage-8", "preimage-8-zk"]])
        .await;
}
