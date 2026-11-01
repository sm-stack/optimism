package sysgo

import (
	"strings"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/shared/rustbin"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/logpipe"
)

// opAggregatorReadyMessage is the line op-aggregator logs once the sequencer answered its first
// request: from then on the sequencer takes dependent transactions.
const opAggregatorReadyMessage = "folding the sequencer's statements"

// StartOpAggregator runs op-aggregator against el, an op-reth sequencer, until the test ends: it
// proves the sequencer's proof aggregates, reading its statement sources and submitting aggregates
// on the authenticated RPC endpoint. Without it the sequencer takes no dependent transaction,
// unless it runs with --testing.disable-proof-aggregation. It returns once the sequencer answered
// op-aggregator. The test fails if op-aggregator exits before it ends.
func StartOpAggregator(t devtest.T, el *OpReth) {
	require := t.Require()
	execPath, err := rustbin.Spec{
		SrcDir:  "rust",
		Package: "op-aggregator",
		Binary:  "op-aggregator",
	}.EnsureExists(t.Ctx(), t.Logger())
	require.NoError(err, "op-aggregator binary not available (build with 'cd rust && cargo build -p op-aggregator', or set RUST_JIT_BUILD=1)")

	// The endpoint is a TCP proxy in front of op-reth, which serves HTTP and WebSocket on one port.
	addr, ok := strings.CutPrefix(el.EngineRPC(), "ws://")
	require.True(ok, "op-reth's authenticated endpoint %q is not ws://", el.EngineRPC())
	authRPC := "http://" + addr

	logger := t.Logger().New("component", "op-aggregator")
	logOut := logpipe.ToLoggerWithMinLevel(logger.New("src", "stdout"), log.LevelInfo)
	logErr := logpipe.ToLoggerWithMinLevel(logger.New("src", "stderr"), log.LevelWarn)
	ready := make(chan struct{}, 1)
	onLogEntry := func(e logpipe.LogEntry) {
		if strings.Contains(e.LogMessage(), opAggregatorReadyMessage) {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
	sub := NewSubProcess(t,
		logpipe.LogCallback(func(line []byte) {
			e := logpipe.ParseRustStructuredLogs(line)
			logOut(e)
			onLogEntry(e)
		}),
		logpipe.LogCallback(func(line []byte) { logErr(logpipe.ParseRustStructuredLogs(line)) }),
	)
	args := []string{"--l2-auth-rpc", authRPC, "--jwt-secret", el.JWTPath(), "--log.json"}
	require.NoError(sub.Start(execPath, args, []string{"RUST_LOG=info"}), "must start op-aggregator")

	// Wait for the startup line, but fail fast if the process exits first.
	select {
	case <-ready:
	case <-sub.Exited():
		select {
		case <-ready:
		default:
			require.FailNow("op-aggregator exited before its startup line was emitted")
		}
	case <-t.Ctx().Done():
		require.NoError(t.Ctx().Err(), "need op-aggregator startup")
	}
	// Runs before the stop SubProcess.Start registered: a crash mid-test would otherwise end as an
	// ordinary stop.
	t.Cleanup(func() {
		select {
		case <-sub.Exited():
			t.Errorf("op-aggregator exited before the test ended")
		default:
		}
	})
	logger.Info("op-aggregator is ready", "authRPC", authRPC)
}
