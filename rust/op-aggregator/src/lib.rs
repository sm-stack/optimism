//! op-aggregator proves the sequencer's proof aggregates.
//!
//! The sequencer's op-reth admits dependent transactions with the sources of their statements,
//! includes them, and queues aggregates for op-batcher. Proving an aggregate is the heavy part:
//! signature leaves, a first-level node per leaf, a fold per node, and a seal, on every core and
//! several gigabytes, so op-reth leaves it to this crate's binary, which a sequencer must run.
//! [`Folder`] does it over a [`Backend`]: op-reth's authenticated `aggregator` namespace ([`api`]),
//! from the same machine or another. Until op-aggregator makes its first request, and once it has
//! made none for a while, the sequencer takes no dependent transaction. op-reth verifies every
//! aggregate it is given before queueing it, so the folder can delay aggregates but never get an
//! invalid one posted.

mod ahead;
pub mod api;
mod backend;
pub mod cpu;
mod folder;

pub use ahead::{Job, NodeChild, ProveAhead, prove_worker};
pub use backend::{Backend, RpcBackend};
pub use folder::{AGGREGATE_DELAY, Folder, HEARTBEAT, MAX_RESPONSE_BYTES, run};
