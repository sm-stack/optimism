//! op-aggregator: folds the sequencer's statement sources into proof aggregates, reaching op-reth
//! on its authenticated RPC endpoint. A sequencer with proof aggregation needs it: op-reth proves
//! no aggregate itself, and takes no dependent transaction while op-aggregator is not there.
//!
//! `op-aggregator prove-worker` is the helper `--prove-ahead-workers` starts: it proves the
//! first-level nodes it reads on its standard input ([`op_aggregator::prove_worker`]).

use clap::Parser;
use eyre::WrapErr;
use jsonrpsee::http_client::HttpClientBuilder;
use op_aggregator::RpcBackend;
use reth_rpc_layer::{AuthClientLayer, JwtSecret};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Proves the sequencer's proof aggregates")]
struct Args {
    /// The sequencer op-reth's authenticated RPC endpoint (`--authrpc.addr`/`--authrpc.port`).
    #[arg(long, env = "OP_AGGREGATOR_L2_AUTH_RPC")]
    l2_auth_rpc: String,
    /// The JWT secret op-reth's authenticated endpoint checks (`--authrpc.jwtsecret`).
    #[arg(long, env = "OP_AGGREGATOR_JWT_SECRET")]
    jwt_secret: PathBuf,
    /// Logs one JSON object per line, as reth's `--log.stdout.format json` does.
    #[arg(long = "log.json", env = "OP_AGGREGATOR_LOG_JSON")]
    log_json: bool,
    /// Helper processes proving the first-level nodes of the next blocks while the folder folds,
    /// each a leanVM pool of its own and a proof's memory (several GB). Zero proves nothing ahead.
    /// With helpers, the folder's own leanVM threads (`LEANVM_NUM_THREADS`) default to its share
    /// of the cores too.
    #[arg(long, env = "OP_AGGREGATOR_PROVE_AHEAD_WORKERS", default_value_t = 0)]
    prove_ahead_workers: usize,
    /// Blocks after the one being folded whose leaves the helpers prove.
    #[arg(long, env = "OP_AGGREGATOR_PROVE_AHEAD_BLOCKS", default_value_t = 4)]
    prove_ahead_blocks: usize,
    /// leanVM threads per helper; by default the cores shared out between the folder and its
    /// helpers.
    #[arg(long, env = "OP_AGGREGATOR_PROVE_AHEAD_THREADS")]
    prove_ahead_threads: Option<usize>,
}

/// A proof allocates and frees gigabytes of buffers. glibc unmaps a large block on free, so every
/// proof faults its pages in again, its threads contending on the page tables: on a 32-core c7a,
/// signature leaves and folds took 2.2-2.3x as long as with jemalloc keeping its freed pages, as
/// leanVM's CLI does (`leanvm::Prover`'s documentation leaves the allocator to its host). The price
/// is that the process, and each prove-ahead helper, keeps its peak resident until it exits.
#[cfg(unix)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc's configuration, read before its first allocation, as leanVM's CLI sets it: dirty pages
/// never decay, and on Linux its mappings ask for transparent huge pages (the kernel's mode decides
/// whether they get them), 4% faster again. Under the `_rjem_` prefix jemalloc's symbols carry by
/// default, and unprefixed where a workspace build unifies op-reth's jemalloc, which overrides the
/// system allocator.
#[cfg(all(target_os = "linux", not(target_arch = "arm")))]
mod malloc_conf {
    const CONF: [u8; 49] = *b"dirty_decay_ms:-1,thp:always,metadata_thp:always\0";
    #[unsafe(export_name = "_rjem_malloc_conf")]
    static PREFIXED: &[u8; 49] = &CONF;
    #[unsafe(export_name = "malloc_conf")]
    static UNPREFIXED: &[u8; 49] = &CONF;
}

/// jemalloc's configuration where it has no huge page support, and would warn about the option.
#[cfg(all(unix, not(all(target_os = "linux", not(target_arch = "arm")))))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8; 18] = b"dirty_decay_ms:-1\0";

fn main() -> eyre::Result<()> {
    // The helper's standard output carries its answers only.
    if std::env::args().nth(1).as_deref() == Some("prove-worker") {
        check_cpu()?;
        let stdin = std::io::stdin().lock();
        return op_aggregator::prove_worker(stdin, std::io::stdout().lock())
            .wrap_err("proving first-level nodes");
    }
    // `--help` and `--version` answer on any CPU.
    let args = Args::parse();
    check_cpu()?;
    if args.prove_ahead_workers > 0 && std::env::var_os("LEANVM_NUM_THREADS").is_none() {
        // SAFETY: no other thread runs yet: the runtime starts after.
        unsafe {
            std::env::set_var("LEANVM_NUM_THREADS", share(args.prove_ahead_workers).to_string())
        };
    }
    fold(args)
}

/// Fails if this CPU lacks a feature the binary was built to use, before anything runs leanVM,
/// whose kernels would end in an illegal instruction.
fn check_cpu() -> eyre::Result<()> {
    let missing = op_aggregator::cpu::missing();
    if !missing.is_empty() {
        eyre::bail!(
            "this op-aggregator was built for CPUs with {}, which this one lacks: run a build for \
             this CPU (the x86-64 release image needs Intel Ice Lake or AMD Zen 4 and later)",
            missing.join(", ")
        );
    }
    Ok(())
}

/// The cores each of the folder and its `workers` helpers gets.
fn share(workers: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    (cores / (workers + 1)).max(1)
}

#[tokio::main]
async fn fold(args: Args) -> eyre::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if args.log_json {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let secret = JwtSecret::from_file(&args.jwt_secret)
        .wrap_err_with(|| format!("reading the JWT secret at {}", args.jwt_secret.display()))?;
    let client = HttpClientBuilder::default()
        .max_response_size(op_aggregator::MAX_RESPONSE_BYTES)
        .set_http_middleware(tower::ServiceBuilder::new().layer(AuthClientLayer::new(secret)))
        .build(&args.l2_auth_rpc)
        .wrap_err("building the op-reth client")?;
    if !op_aggregator::cpu::fast_kernels() {
        tracing::warn!(target: "op_aggregator", "built without leanVM's fast kernels: proving is about six times slower (build with -C target-cpu=x86-64-v3 -C target-feature=+vpclmulqdq,+pclmulqdq,+gfni,+aes, or +aes,+sha3 on AArch64)");
    }
    // "folding the sequencer's statements" follows once the sequencer answers.
    tracing::info!(target: "op_aggregator", url = %args.l2_auth_rpc, "reaching the sequencer");
    let ahead = (args.prove_ahead_workers > 0).then(|| op_aggregator::ProveAhead {
        workers: args.prove_ahead_workers,
        blocks: args.prove_ahead_blocks,
        threads: Some(args.prove_ahead_threads.unwrap_or_else(|| share(args.prove_ahead_workers))),
        command: vec![
            std::env::current_exe().expect("the running binary").into_os_string(),
            "prove-worker".into(),
        ],
    });
    op_aggregator::run(RpcBackend(client), ahead).await;
    Ok(())
}
