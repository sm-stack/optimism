# op-aggregator

Proves an OP Stack sequencer's proof aggregates. The sequencer's op-reth takes transactions
that depend on statements, with the statements' sources (program leaf proofs and leanSPHINCS
signatures), and includes them at once. op-aggregator folds those sources into leanVM tree roots,
seals them, and submits them to op-reth, which verifies each aggregate before queueing it for
op-batcher. Derivation replaces a block with its deposits unless the aggregate responsible for it
proves all its dependencies, so every sequencer with proof aggregation runs op-aggregator: op-reth proves no aggregate itself.

## Running

op-aggregator reaches op-reth's authenticated RPC endpoint (`aggregator` namespace):

```sh
op-aggregator --l2-auth-rpc http://sequencer:8551 --jwt-secret /path/to/jwt.hex
```

Every request it makes tells op-reth it is there, and it asks for op-reth's status every five
seconds whatever it is proving (`HEARTBEAT`). Until its first request, and once it has made none
for 30 seconds (`AGGREGATOR_TIMEOUT`), the sequencer refuses new dependent transactions
(`optimism_sendRawTransactionWithStatementProofs` answers "no op-aggregator is proving aggregates")
and its builder includes none of those already admitted. op-reth checks on every block, logs each
change, and exports it as the gauge `op_proof_aggregation_aggregator_attached`: alert when it is 0
on a sequencer.

If op-aggregator stops, a restarted one folds the blocks it missed. If none comes back within
derivation's window, derivation replaces every block with a dependency no aggregate proves,
including those the sequencer built in the 30 seconds before it noticed.

The gauge shows that op-aggregator is running, not that it keeps up. If aggregates fall behind,
the sequencer pauses dependent transactions once the oldest unproven block is 12 minutes old
(`MAX_UNCOVERED_AGE`), or too many transaction bytes or, with fixed runs, statements are unproven,
whatever the gauge says.

With `--rollup.proof-aggregation-run-blocks K` on op-reth, a run ends at every block `n` where
`(n + 1) % K == 0`, and op-batcher ends the channel holding it there, so an aggregate can share the
channel of its blocks and hold up to 4,096 statements. op-aggregator reads K from the sequencer's
status. A block then holds at most `4096 / K` statements. Without it, a run closes after 20 s or
at 1,700 statements.

Nodes that forward transactions to the sequencer (`--rollup.sequencer-http`) do not wait for
op-aggregator. Other nodes without that flag do, and report the gauge as 0, so scope the alert to
the sequencer. Under op-conductor, every sequencer that can become the leader needs its own
op-aggregator; otherwise a new leader takes no dependent transaction until one reaches it. op-up's
interop devnet starts no op-aggregator: run one against its op-reth to send dependent transactions
there.

## Hardware

Proving takes every core and several gigabytes. On a 32-core machine, helpers that prove the next
blocks' first-level nodes while the folder folds raise throughput up to 2.4 times, with one tree
and one aggregate as before:

```sh
op-aggregator ... --prove-ahead-workers 2 --prove-ahead-blocks 4
```

Each helper takes about 2 to 4 GiB more. With signatures only, over about 400 a block, three
helpers do better.

## CPU and builds

leanVM picks its kernels when it is compiled, not when it runs. Built for a generic CPU, it proves
about six times slower; built for a CPU with carry-less vector multiplication, it ends in an illegal
instruction on one without. The release image is built for:

- x86-64: `-C target-cpu=x86-64-v3 -C target-feature=+vpclmulqdq,+pclmulqdq,+gfni,+aes`, which
  needs Intel Ice Lake or AMD Zen 4 and later;
- AArch64: `-C target-feature=+aes,+sha3` (AWS Graviton 3 and later).

op-aggregator checks the CPU before it proves anything, and exits with the features it lacks
rather than crashing. A build without the fast kernels runs anywhere and logs a warning at
startup. To check a binary's kernels:

```sh
objdump -d op-aggregator | grep -cE '\svpclmul'   # x86-64: nonzero with the fast kernels
objdump -d op-aggregator | grep -cw pmull         # AArch64
```

op-reth and the other images stay generic: they only verify proofs, in milliseconds.
