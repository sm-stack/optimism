//! Proving ahead: the nodes of the block being folded and of the blocks after it, proven by helper
//! processes while the folder folds, so that its fold takes them ready.
//!
//! A leaf costs a first-level node (and, for signatures, the signature leaf under it), which
//! depends on the leaf alone. A block's first-level nodes are joined into one by the nodes of
//! their [`Subtree`], which depend on the block alone, and only its top's fold into the run's root
//! depends on the root: one sequential step a block. leanVM's thread pool runs one parallel step
//! at a time per process, so proofs run on threads of one process queue behind each other; each
//! helper process has a pool of its own. A helper proves a subtree node once its children are
//! ready, from their proofs. The helpers hand nodes back as proofs, which the folder checks
//! against their statements before it takes them ([`FirstLevelTicket::fulfil_bytes`]): there is
//! still one tree and one root.
//!
//! The folder's own logic is unchanged: what the helpers prove is a guess of what it will fold
//! (the units of the next blocks, signatures grouped as its aggregator will group them, and their
//! subtrees), and a wrong guess only costs the work.

use crate::{
    api::{BlockStatements, Source},
    folder::order_sources,
};
use alloy_primitives::{B256, Bytes};
use op_alloy_consensus::ProofStatement;
use op_leanvm_tree::{
    Aggregator, BlockItem, FirstLevelCache, FirstLevelTicket, LeafRef, ProgramRef, Signed, Subtree,
    Unit, first_level_key, group_units, prepare_first_level_prover, prove_node_bytes,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
    time::Duration,
};
use tracing::{debug, warn};

/// Nodes the blocks proven ahead usually need, and some: a block of `n` units takes about `2n`
/// nodes, and a run of the class capacity in full signature leaves is about 41 units (100
/// statements a leaf, 4097 claims), so several such blocks fit. Program leaves are a unit each and
/// a run's limits count statements and programs, not units, so a block of them can take more.
/// Those of blocks guessed but not folded are evicted first; each node holds a proof of about
/// 160 KB.
const CACHE_CAPACITY: usize = 512;

/// How often a helper thread with only subtree nodes waiting looks again for one whose children
/// the fold proved: nodes a helper proves wake it.
const DEPS_POLL: Duration = Duration::from_millis(20);

/// How long a fold waits for a node a helper is proving before it proves the node itself: several
/// times a signature leaf and its node on a helper's share of the cores, so it only cuts short a
/// helper that stalled.
const FOLD_WAIT: Duration = Duration::from_secs(20);

/// How to prove ahead.
#[derive(Debug, Clone)]
pub struct ProveAhead {
    /// Helper processes, each proving one node at a time. Zero proves nothing ahead.
    pub workers: usize,
    /// Blocks after the one being folded whose leaves are proven ahead.
    pub blocks: usize,
    /// leanVM threads per helper (`LEANVM_NUM_THREADS`); `None` leaves its default, every core.
    pub threads: Option<usize>,
    /// The helper's command line: a binary that runs [`prove_worker`] on its standard streams, as
    /// `op-aggregator prove-worker` does.
    pub command: Vec<OsString>,
}

/// A node to prove, as a helper reads it: one JSON object per line.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Job {
    /// A program leaf.
    #[serde(rename_all = "camelCase")]
    Program {
        /// The normalized program's verifying key.
        verifying_key: Bytes,
        /// The members the run published.
        members: Vec<B256>,
        /// The leaf proof.
        proof: Bytes,
    },
    /// Signatures to prove one signature leaf over, then its node.
    Signatures {
        /// Each signature's encodings, as [`Source::Signature`] carries them.
        signatures: Vec<(Bytes, B256, Bytes)>,
    },
    /// A node over other nodes: a subtree node of a block.
    Node {
        /// Its children, in order.
        children: Vec<NodeChild>,
    },
}

/// A child of a [`Job::Node`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeChild {
    /// The child's proof ([`op_leanvm_tree::FirstLevelCache`] holds it as a tree proof).
    pub proof: Bytes,
    /// The statements it proves.
    pub statements: Vec<ProofStatement>,
}

/// A helper's answer, one JSON object per line: the node's proof, or why it has none.
type Answer = Result<Bytes, String>;

impl Job {
    fn prove(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Program { verifying_key, members, proof } => {
                LeafRef::Program { verifying_key, members, proof }.prove_bytes()
            }
            Self::Signatures { signatures } => {
                let signed = signatures
                    .iter()
                    .map(|(key, message, signature)| Signed::decode(key, *message, signature))
                    .collect::<Result<Vec<_>, _>>()?;
                LeafRef::Signatures(&signed).prove_bytes()
            }
            Self::Node { children } => {
                let children: Vec<(&[u8], &[ProofStatement])> = children
                    .iter()
                    .map(|child| (child.proof.as_ref(), child.statements.as_slice()))
                    .collect();
                prove_node_bytes(&children)
            }
        }
    }
}

/// The helper's loop: builds the prover, then reads one [`Job`] a line from `input`, proves its
/// node and writes the [`Answer`] as one line to `output`, until `input` ends. `output` carries
/// the answers only: a helper logs nothing to it.
pub fn prove_worker(input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
    prepare_first_level_prover().map_err(std::io::Error::other)?;
    for line in input.lines() {
        let line = line?;
        let answer: Answer = serde_json::from_str::<Job>(&line)
            .map_err(|err| format!("malformed job: {err}"))
            .and_then(|job| job.prove())
            .map(Bytes::from);
        serde_json::to_writer(&mut output, &answer)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}

/// What a planned node takes: a job ready to send, or a subtree node over its children's nodes,
/// sent once they are ready.
#[derive(Debug, Clone)]
enum Work {
    Job(Job),
    Node(Vec<(B256, Vec<ProofStatement>)>),
}

/// A planned node: its key, its statements and its work.
#[derive(Debug, Clone)]
struct Planned {
    key: B256,
    statements: Vec<ProofStatement>,
    work: Work,
}

impl Planned {
    /// The keys of the nodes it is proven from.
    fn deps(&self) -> impl Iterator<Item = &B256> {
        match &self.work {
            Work::Job(_) => [].iter(),
            Work::Node(children) => children.iter(),
        }
        .map(|(key, _)| key)
    }
}

/// A program leaf of a block, as read ahead.
#[derive(Debug, Clone, Copy)]
struct ProgramSource<'a> {
    verifying_key: &'a Bytes,
    members: &'a [B256],
    proof: &'a Bytes,
}

impl ProgramSource<'_> {
    fn leaf(&self) -> LeafRef<'_> {
        ProgramRef { verifying_key: self.verifying_key, members: self.members, proof: self.proof }
            .into()
    }
}

/// The nodes of a block's units and of their subtree, children first: those its top is proven
/// from ([`Subtree::new`]), as the aggregator proves them.
fn plan_block(units: &[Unit<ProgramSource<'_>>]) -> Vec<Planned> {
    let mut leaves: Vec<Planned> = Vec::new();
    for unit in units {
        let (statements, job) = match unit {
            Unit::Program(p) => {
                let Ok(statements) = p.leaf().statements() else { continue };
                let job = Job::Program {
                    verifying_key: p.verifying_key.clone(),
                    members: p.members.to_vec(),
                    proof: p.proof.clone(),
                };
                (statements, job)
            }
            Unit::Signatures(group) => {
                let signatures = group
                    .iter()
                    .map(|signed| {
                        let (key, message, signature) = signed.encode();
                        (key.into(), message, signature.into())
                    })
                    .collect();
                (group.iter().map(Signed::statement).collect(), Job::Signatures { signatures })
            }
        };
        leaves.push(Planned {
            key: first_level_key(&statements),
            statements,
            work: Work::Job(job),
        });
    }
    let Some(subtree) = Subtree::new(leaves.iter().map(|p| p.statements.clone())) else {
        return Vec::new();
    };
    let mut planned: Vec<Planned> = subtree
        .units
        .iter()
        .map(|(key, _)| leaves.iter().find(|p| p.key == *key).expect("a unit's").clone())
        .collect();
    for node in subtree.nodes {
        let children = node
            .children
            .iter()
            .map(|child| {
                let of = planned.iter().find(|p| p.key == *child).expect("children first");
                (*child, of.statements.clone())
            })
            .collect();
        planned.push(Planned {
            key: node.key,
            statements: node.statements,
            work: Work::Node(children),
        });
    }
    planned
}

/// The jobs waiting for a helper, latest plan only.
#[derive(Default)]
struct Queue {
    jobs: VecDeque<Planned>,
    stopped: bool,
}

/// A helper process, while one runs, where stopping can kill it.
type Slot = Arc<Mutex<Option<Child>>>;

/// The helpers, their queue, the cache they fill and the sources read ahead.
pub(crate) struct Ahead {
    pub(crate) cache: Arc<FirstLevelCache>,
    queue: Arc<(Mutex<Queue>, Condvar)>,
    workers: Vec<JoinHandle<()>>,
    helpers: Vec<Slot>,
    blocks: usize,
    /// Sources read for the blocks ahead, which the fold of those blocks takes.
    prefetched: HashMap<B256, Source>,
}

impl std::fmt::Debug for Ahead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ahead").field("workers", &self.workers.len()).finish_non_exhaustive()
    }
}

impl Ahead {
    /// Starts `options.workers` helpers, which build their prover at once; `None` for none.
    pub(crate) fn start(options: &ProveAhead) -> Option<Self> {
        if options.workers == 0 || options.command.is_empty() {
            return None;
        }
        let cache = FirstLevelCache::new(CACHE_CAPACITY, FOLD_WAIT);
        let queue = Arc::new((Mutex::new(Queue::default()), Condvar::new()));
        let helpers: Vec<Slot> = (0..options.workers).map(|_| Slot::default()).collect();
        let workers = helpers
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let (cache, queue, slot, options) =
                    (cache.clone(), queue.clone(), slot.clone(), options.clone());
                std::thread::Builder::new()
                    .name(format!("prove-ahead-{index}"))
                    .spawn(move || work(&cache, &queue, &slot, &options))
                    .expect("spawning a prove-ahead thread")
            })
            .collect();
        Some(Self {
            cache,
            queue,
            workers,
            helpers,
            blocks: options.blocks,
            prefetched: HashMap::new(),
        })
    }

    /// The sources read ahead for `ids`, taken: the fold reads the rest.
    pub(crate) fn take_prefetched(&mut self, ids: &[B256]) -> HashMap<B256, Source> {
        ids.iter().filter_map(|id| self.prefetched.remove_entry(id)).collect()
    }

    /// Drops the sources read ahead and the jobs not started, after a reorg or a restart: the
    /// blocks they were read for may be gone.
    pub(crate) fn forget(&mut self) {
        self.prefetched.clear();
        self.queue.0.lock().unwrap().jobs.clear();
    }

    /// How many blocks after the one being folded to prove ahead.
    pub(crate) const fn blocks(&self) -> usize {
        self.blocks
    }

    /// The source ids of `blocks` not read ahead yet.
    pub(crate) fn missing(&self, aggregator: &Aggregator, blocks: &[BlockStatements]) -> Vec<B256> {
        let ids: HashSet<B256> = blocks
            .iter()
            .flat_map(|block| &block.statements)
            .filter(|s| {
                !aggregator.contains(&s.statement) && !self.prefetched.contains_key(&s.source)
            })
            .map(|s| s.source)
            .collect();
        ids.into_iter().collect()
    }

    /// Plans the nodes of `blocks`, the block about to be folded first, with `fetched` sources
    /// read for them, and queues them in place of the last plan. The folder will fold each block's
    /// sources as [`order_sources`] lists them: each program leaf is a unit, the signatures are
    /// grouped as `aggregator` will group them, from its buffer on, and the units are joined by
    /// their [`Subtree`]. The plan ends at the first source not read. The fold proves the next
    /// block's first unit itself, at once: a helper would start it no sooner.
    pub(crate) fn plan(
        &mut self,
        aggregator: &Aggregator,
        blocks: &[BlockStatements],
        fetched: HashMap<B256, Source>,
    ) {
        self.prefetched.extend(fetched);
        // Only the planned blocks' sources stay read ahead.
        let wanted: HashSet<B256> =
            blocks.iter().flat_map(|b| &b.statements).map(|s| s.source).collect();
        self.prefetched.retain(|id, _| wanted.contains(id));

        let mut jobs = Vec::new();
        let mut buffer: Vec<Signed> = aggregator.buffered_signatures().to_vec();
        // The statements the blocks before add, which the aggregator holds by then.
        let mut folded: HashSet<ProofStatement> = HashSet::new();
        for (index, block) in blocks.iter().enumerate() {
            let new = block
                .statements
                .iter()
                .filter(|s| !aggregator.contains(&s.statement) && !folded.contains(&s.statement));
            let Ok((sources, added)) = order_sources(new, |id| self.prefetched.get(id)) else {
                break;
            };
            folded.extend(added);
            let items = sources.into_iter().filter_map(|source| match source {
                Source::Program { verifying_key, proof, members, .. } => {
                    Some(BlockItem::Program(ProgramSource { verifying_key, members, proof }))
                }
                Source::Signature { public_key, message, signature } => {
                    Signed::decode(public_key, *message, signature).ok().map(BlockItem::Signature)
                }
            });
            let (units, rest) = group_units(buffer, items);
            buffer = rest;
            let mut planned = plan_block(&units);
            // The fold starts on the block about to be folded at once, from its first unit: a
            // helper would start that unit no sooner.
            if index == 0 && planned.first().is_some_and(|p| matches!(p.work, Work::Job(_))) {
                planned.remove(0);
            }
            jobs.extend(planned);
        }
        let jobs: VecDeque<Planned> =
            jobs.into_iter().filter(|job| !self.cache.contains(&job.key)).collect();
        debug!(target: "op_aggregator", blocks = blocks.len(), jobs = jobs.len(), "planned nodes to prove ahead");
        let (queue, wake) = &*self.queue;
        queue.lock().unwrap().jobs = jobs;
        wake.notify_all();
    }
}

#[cfg(test)]
impl Ahead {
    /// Helpers that never start: the plan stays queued.
    fn idle() -> Self {
        Self {
            cache: FirstLevelCache::new(CACHE_CAPACITY, FOLD_WAIT),
            queue: Default::default(),
            workers: Vec::new(),
            helpers: Vec::new(),
            blocks: 4,
            prefetched: HashMap::new(),
        }
    }

    fn queued(&self) -> Vec<B256> {
        self.queue.0.lock().unwrap().jobs.iter().map(|job| job.key).collect()
    }
}

impl Drop for Ahead {
    fn drop(&mut self) {
        let (queue, wake) = &*self.queue;
        queue.lock().unwrap().stopped = true;
        wake.notify_all();
        // A helper mid-proof is killed, so that its thread reads the end of its answers at once.
        for slot in &self.helpers {
            kill(slot);
        }
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                warn!(target: "op_aggregator", "a prove-ahead thread panicked");
            }
        }
    }
}

/// Kills the helper in `slot`, if one runs.
fn kill(slot: &Slot) {
    if let Some(mut child) = slot.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// A helper process's streams; its process is in `slot`.
struct Helper {
    slot: Slot,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Helper {
    /// Starts a helper in `slot`, unless the helpers are stopping.
    fn spawn(
        options: &ProveAhead,
        slot: &Slot,
        queue: &Mutex<Queue>,
    ) -> std::io::Result<Option<Self>> {
        let mut held = slot.lock().unwrap();
        if queue.lock().unwrap().stopped {
            return Ok(None);
        }
        let mut command = Command::new(&options.command[0]);
        command.args(&options.command[1..]).stdin(Stdio::piped()).stdout(Stdio::piped());
        if let Some(threads) = options.threads {
            command.env("LEANVM_NUM_THREADS", threads.to_string());
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        *held = Some(child);
        Ok(Some(Self { slot: slot.clone(), stdin, stdout }))
    }

    /// Has the helper prove `job`.
    fn prove(&mut self, job: &Job) -> std::io::Result<Answer> {
        serde_json::to_writer(&mut self.stdin, job)?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        let mut line = String::new();
        if self.stdout.read_line(&mut line)? == 0 {
            return Err(std::io::Error::other("the helper exited"));
        }
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        kill(&self.slot);
    }
}

/// A helper thread: starts its helper process, then takes the next planned node no one else is
/// proving, has the helper prove it, and fills the cache with it.
fn work(
    cache: &Arc<FirstLevelCache>,
    queue: &(Mutex<Queue>, Condvar),
    slot: &Slot,
    options: &ProveAhead,
) {
    let mut helper: Option<Helper> = None;
    loop {
        if helper.is_none() {
            match Helper::spawn(options, slot, &queue.0) {
                Ok(Some(spawned)) => helper = Some(spawned),
                Ok(None) => return,
                Err(err) => {
                    warn!(target: "op_aggregator", %err, "could not start a prove-ahead helper");
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            }
        }
        let (queue, wake) = queue;
        let planned = {
            let mut queue = queue.lock().unwrap();
            loop {
                if queue.stopped {
                    return;
                }
                // The first node not taken whose children are ready; the nodes others took or
                // proved leave the queue.
                queue.jobs.retain(|planned| !cache.contains(&planned.key));
                let ready = queue.jobs.iter().position(|p| p.deps().all(|key| cache.is_ready(key)));
                if let Some(index) = ready {
                    break queue.jobs.remove(index).expect("in the queue");
                }
                // A helper that proves a node wakes the others; children the fold proves wake no
                // one, so with nodes waiting on children, look again soon.
                queue = if queue.jobs.is_empty() {
                    wake.wait(queue).unwrap()
                } else {
                    wake.wait_timeout(queue, DEPS_POLL).unwrap().0
                };
            }
        };
        let Planned { key, statements, work } = planned;
        let Some(ticket) = cache.claim(key) else { continue };
        let job = match work {
            Work::Job(job) => job,
            Work::Node(children) => {
                let children: Option<Vec<NodeChild>> = children
                    .into_iter()
                    .map(|(key, statements)| {
                        let proof = cache.peek(&key)?.proof.to_bytes().into();
                        Some(NodeChild { proof, statements })
                    })
                    .collect();
                // A child evicted since: the fold proves the node.
                let Some(children) = children else { continue };
                Job::Node { children }
            }
        };
        if !fulfil(ticket, &statements, &job, helper.as_mut().expect("started")) {
            // The next loop starts another helper.
            helper = None;
        }
        wake.notify_all();
    }
}

/// Has `helper` prove `job`, a node over `statements`, and fills `ticket` with it. Returns whether
/// the helper is still usable; a node it could not prove, or one that does not verify, releases
/// the ticket.
fn fulfil(
    ticket: FirstLevelTicket,
    statements: &[ProofStatement],
    job: &Job,
    helper: &mut Helper,
) -> bool {
    match helper.prove(job) {
        Ok(Ok(proof)) => {
            if let Err(err) = ticket.fulfil_bytes(statements, &proof) {
                warn!(target: "op_aggregator", %err, "a helper's node does not verify");
            }
        }
        Ok(Err(error)) => {
            debug!(target: "op_aggregator", %error, "a helper could not prove a node");
        }
        Err(err) => {
            warn!(target: "op_aggregator", %err, "a prove-ahead helper failed: starting another");
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::StatementRef;

    const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../op-leanvm-tree/testdata");

    fn testdata(name: &str) -> Bytes {
        std::fs::read(format!("{TESTDATA}/{name}")).unwrap().into()
    }

    /// The source of the program leaf `name`, and its statements.
    fn program(name: &str) -> (B256, Source, Vec<ProofStatement>) {
        let verifying_key = testdata(&format!("{name}.key"));
        let members: Vec<B256> =
            testdata(&format!("{name}.members")).chunks_exact(32).map(B256::from_slice).collect();
        let program = op_leanvm_tree::program_digest(&verifying_key).unwrap();
        let statements: Vec<ProofStatement> = members
            .iter()
            .map(|m| ProofStatement { vkey_hash: program, public_values_digest: *m })
            .collect();
        let proof = testdata(&format!("{name}.proof"));
        (statements[0].id(), Source::Program { program, verifying_key, proof, members }, statements)
    }

    fn block(number: u64, leaves: &[&(B256, Source, Vec<ProofStatement>)]) -> BlockStatements {
        let statements = leaves
            .iter()
            .flat_map(|(id, _, statements)| {
                statements
                    .iter()
                    .map(|statement| StatementRef { statement: *statement, source: *id })
            })
            .collect();
        BlockStatements {
            block: crate::api::BlockId { number, hash: B256::with_last_byte(number as u8) },
            statements,
        }
    }

    /// The plan leaves the next block's first unit to the fold, plans each unit of the blocks
    /// after once, as the folder will fold them, with their subtree's nodes, and ends at the first
    /// source not read.
    #[test]
    fn plans_the_nodes_the_folder_will_fold() {
        let [a, b, c, d] =
            ["fibonacci-1000", "fibonacci-2700", "preimage-8", "preimage-8-zk"].map(program);
        let blocks = [
            block(1, &[&a, &b]),
            block(2, &[&a, &c]),
            block(3, &[&c]),
            block(4, &[&d]),
            block(5, &[&b]),
        ];
        let fetched: HashMap<B256, Source> =
            [&a, &b, &c].into_iter().map(|(id, source, _)| (*id, source.clone())).collect();
        let mut ahead = Ahead::idle();
        let aggregator = Aggregator::new().unwrap();
        ahead.plan(&aggregator, &blocks, fetched);
        let key =
            |(_, _, statements): &(B256, Source, Vec<ProofStatement>)| first_level_key(statements);
        let pair: Vec<ProofStatement> = a.2.iter().chain(&b.2).copied().collect();
        // Block 1: `a` to the fold, then `b` and the node over both; block 2: `c`, `a` folded
        // already; block 3: nothing new; block 4: `d` not read, which ends the plan.
        assert_eq!(ahead.queued(), vec![key(&b), first_level_key(&pair), key(&c)]);
    }

    /// The nodes the plan queues for a block, proven by a helper in the order the helpers take
    /// them, are those the aggregator folds the block through: it takes the block's top and
    /// proves nothing. Three units: one carried up a level.
    #[test]
    fn the_fold_takes_the_subtree_the_helpers_prove() {
        let [a, b, c] = ["fibonacci-1000", "fibonacci-2700", "preimage-8"].map(program);
        // An empty block first: the fold proves the first unit of the block it is about to fold.
        let blocks = [block(1, &[]), block(2, &[&a, &b, &c])];
        let fetched: HashMap<B256, Source> =
            [&a, &b, &c].into_iter().map(|(id, source, _)| (*id, source.clone())).collect();
        let mut ahead = Ahead::idle();
        let mut aggregator = Aggregator::new().unwrap();
        ahead.plan(&aggregator, &blocks, fetched);
        let planned: Vec<Planned> = ahead.queue.0.lock().unwrap().jobs.drain(..).collect();
        assert_eq!(planned.len(), 5, "three units and two nodes");
        for Planned { key, statements, work } in planned {
            let job = match work {
                Work::Job(job) => job,
                Work::Node(children) => Job::Node {
                    children: children
                        .into_iter()
                        .map(|(key, statements)| NodeChild {
                            proof: ahead.cache.peek(&key).unwrap().proof.to_bytes().into(),
                            statements,
                        })
                        .collect(),
                },
            };
            // Through the helper's loop, as JSON.
            let mut output = Vec::new();
            let input = format!("{}\n", serde_json::to_string(&job).unwrap());
            prove_worker(input.as_bytes(), &mut output).unwrap();
            let answer: Answer = serde_json::from_slice(&output).unwrap();
            let ticket = ahead.cache.claim(key).unwrap();
            ticket.fulfil_bytes(&statements, &answer.unwrap()).unwrap();
        }
        aggregator.set_first_level_cache(ahead.cache.clone());
        let items = [&a, &b, &c]
            .into_iter()
            .map(|(_, source, _)| {
                let Source::Program { verifying_key, proof, members, .. } = source else {
                    unreachable!()
                };
                BlockItem::Program(ProgramRef { verifying_key, members, proof })
            })
            .collect();
        aggregator.add_block(items).unwrap();
        assert_eq!(
            ahead.cache.stats(),
            op_leanvm_tree::FirstLevelStats { hits: 1, ..Default::default() }
        );
    }

    /// The helper proves the node a job names, and the folder's side takes it; a line that is no
    /// job gets an error back, and the helper goes on.
    #[test]
    fn a_helper_proves_the_node_the_folder_takes() {
        let members: Vec<B256> =
            testdata("fibonacci-1000.members").chunks_exact(32).map(B256::from_slice).collect();
        let job = Job::Program {
            verifying_key: testdata("fibonacci-1000.key"),
            members: members.clone(),
            proof: testdata("fibonacci-1000.proof"),
        };
        let input = format!("not a job\n{}\n", serde_json::to_string(&job).unwrap());
        let mut output = Vec::new();
        prove_worker(input.as_bytes(), &mut output).unwrap();
        let answers: Vec<Answer> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(answers[0].as_ref().unwrap_err().starts_with("malformed job"));

        let Job::Program { verifying_key, proof, .. } = &job else { unreachable!() };
        let statements =
            LeafRef::Program { verifying_key, members: &members, proof }.statements().unwrap();
        let cache = FirstLevelCache::new(4, FOLD_WAIT);
        let ticket = cache.claim(first_level_key(&statements)).unwrap();
        ticket.fulfil_bytes(&statements, answers[1].as_ref().unwrap()).unwrap();
        assert!(cache.contains(&first_level_key(&statements)));
    }
}
