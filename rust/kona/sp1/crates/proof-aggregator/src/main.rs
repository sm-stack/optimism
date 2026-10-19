//! `proof-aggregator`: polls an op-reth sequencer for statement proofs, proves aggregates over
//! them, and submits the aggregates back.
//!
//! The prover comes from the environment (`SP1_PROVER=cpu|cuda|network`, plus the network
//! settings), and the aggregation guest ELF from `KONA_SP1_ELF_DIR`.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use kona_sp1_proof_aggregator::{
    PROOF_AGGREGATION_ELF, PendingAggregate, StatementProof, build_stdin, encode_proof,
};
use sp1_sdk::{Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(about = "Proves proof aggregates for an op-reth sequencer")]
struct Args {
    /// op-reth RPC serving the `admin` namespace.
    #[arg(long, env = "PROOF_AGGREGATOR_RPC_URL")]
    rpc_url: String,
    /// Maximum statements per aggregate.
    #[arg(long, env = "PROOF_AGGREGATOR_BATCH_SIZE", default_value_t = 16)]
    batch_size: usize,
    /// Seconds between polls when no statement proofs are queued.
    #[arg(long, env = "PROOF_AGGREGATOR_POLL_SECS", default_value_t = 2)]
    poll_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let rpc = HttpClientBuilder::default().build(&args.rpc_url).context("build RPC client")?;
    let elf = kona_sp1_elfs::load_elf(PROOF_AGGREGATION_ELF)?;
    let prover = ProverClient::from_env().await;
    let pk = prover.setup(Elf::from(elf)).await.context("set up aggregation program")?;
    let aggregation_vkey_hash = op_sp1_proofs::vkey_hash_from_words(pk.verifying_key().hash_u32());
    info!(%aggregation_vkey_hash, "aggregation program ready");

    loop {
        match aggregate_once(&rpc, &prover, &pk, aggregation_vkey_hash, args.batch_size).await {
            Ok(Some(count)) => info!(statements = count, "submitted proof aggregate"),
            Ok(None) => tokio::time::sleep(Duration::from_secs(args.poll_secs)).await,
            Err(err) => {
                warn!(%err, "aggregation round failed");
                tokio::time::sleep(Duration::from_secs(args.poll_secs)).await;
            }
        }
    }
}

/// Proves and submits one aggregate over the oldest queued statement proofs. Returns the number
/// of statements covered, or `None` when nothing is queued.
async fn aggregate_once<P: Prover>(
    rpc: &HttpClient,
    prover: &P,
    pk: &P::ProvingKey,
    aggregation_vkey_hash: alloy_primitives::B256,
    batch_size: usize,
) -> Result<Option<usize>> {
    let mut proofs: Vec<StatementProof> =
        rpc.request("admin_pendingStatementProofs", rpc_params![]).await?;
    if proofs.is_empty() {
        return Ok(None);
    }
    proofs.truncate(batch_size);

    let (stdin, statements) = build_stdin(&proofs)?;
    let proof = prover
        .prove(pk, stdin)
        .compressed()
        .await
        .map_err(|err| anyhow::anyhow!("prove aggregate: {err}"))?;
    let aggregate =
        PendingAggregate { aggregation_vkey_hash, statements, proof: encode_proof(&proof.proof)? };
    let count = aggregate.statements.len();
    rpc.request::<(), _>("admin_submitProofAggregate", rpc_params![aggregate]).await?;
    Ok(Some(count))
}
