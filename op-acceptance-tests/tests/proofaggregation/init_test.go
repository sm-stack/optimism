package proofaggregation

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	bss "github.com/ethereum-optimism/optimism/op-batcher/batcher"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// newProofAggregationSystem builds an op-reth sequencer, the op-aggregator proving its
// aggregates, and an op-reth verifier on a chain with Lagoon, which activates EIP-8430 transactions
// and proof aggregation, at genesis.
func newProofAggregationSystem(t devtest.T) *sdmtest.RethSystem {
	return newSystem(t)
}

// newSystem builds the system, applying sequencerOpts to the sequencer's op-reth.
func newSystem(t devtest.T, sequencerOpts ...sysgo.OpRethOption) *sdmtest.RethSystem {
	return finish(t, newRuntime(t, nil, sequencerOpts...))
}

// newHoldingSystem is newSystem with runs of runBlocks blocks and a batcher holding each channel
// ending a run up to hold for the aggregate of its blocks.
func newHoldingSystem(t devtest.T, hold time.Duration, runBlocks uint64, sequencerOpts ...sysgo.OpRethOption) *sdmtest.RethSystem {
	return finish(t, newRuntime(t, []sysgo.BatcherOption{holding(hold)}, append(sequencerOpts, fixedRuns(runBlocks))...))
}

// finish starts op-aggregator, which proves the sequencer's aggregates, and finishes the system.
func finish(t devtest.T, runtime *sysgo.MixedSingleChainRuntime) *sdmtest.RethSystem {
	sequencer, ok := runtime.Nodes[0].EL.(*sysgo.OpReth)
	t.Require().True(ok, "the sequencer's execution client is op-reth")
	sysgo.StartOpAggregator(t, sequencer)
	return sdmtest.FinishRethSystem(t, runtime, false)
}

// newSystemWithoutOpAggregator is newProofAggregationSystem without op-aggregator: no one proves
// the sequencer's aggregates.
func newSystemWithoutOpAggregator(t devtest.T) *sdmtest.RethSystem {
	return sdmtest.FinishRethSystem(t, newRuntime(t, nil), false)
}

// holding makes the batcher hold each channel ending a run up to hold for the aggregate of its
// blocks.
func holding(hold time.Duration) sysgo.BatcherOption {
	return func(_ sysgo.ComponentTarget, cfg *bss.CLIConfig) { cfg.ProofAggregateHold = hold }
}

// fixedRuns makes the sequencer end a run every runBlocks blocks.
func fixedRuns(runBlocks uint64) sysgo.OpRethOption {
	return sysgo.OpRethWithExtraArgs("--rollup.proof-aggregation-run-blocks", strconv.FormatUint(runBlocks, 10))
}

// newRuntime builds an op-reth sequencer and an op-reth verifier, applying batcherOpts to the
// batcher and sequencerOpts to the sequencer's op-reth.
func newRuntime(t devtest.T, batcherOpts []sysgo.BatcherOption, sequencerOpts ...sysgo.OpRethOption) *sysgo.MixedSingleChainRuntime {
	sysgo.SkipOnOpGeth(t, "the sequencer's proof aggregate queue lives in op-reth")

	clKind := sysgo.ResolveMixedL2CLKind()
	return sysgo.NewMixedSingleChainRuntime(t, sysgo.MixedSingleChainPresetConfig{
		NodeSpecs: []sysgo.MixedSingleChainNodeSpec{
			{
				ELKey:       "sequencer-op-reth",
				CLKey:       "sequencer",
				ELKind:      sysgo.MixedL2ELOpReth,
				CLKind:      clKind,
				IsSequencer: true,
				OpRethOpts:  append(sysgo.ResolveMixedL2ELOpts(t), sequencerOpts...),
			},
			{
				ELKey:  "verifier-op-reth",
				CLKey:  "verifier",
				ELKind: sysgo.MixedL2ELOpReth,
				CLKind: clKind,
			},
		},
		InteropAtGenesis: true,
		BatcherOptions:   batcherOpts,
	})
}

// newSystemWithoutAggregation is newProofAggregationSystem with a sequencer that hands
// op-aggregator nothing to prove, but takes and includes dependent transactions as if it did.
func newSystemWithoutAggregation(t devtest.T) *sdmtest.RethSystem {
	return newSystem(t, sysgo.OpRethWithExtraArgs("--testing.disable-proof-aggregation"))
}

// fixture is a statement and the source the sequencer needs for it.
type fixture struct {
	// vkeyHash is the digest of the verifying key of the guest normalized to its leaf class.
	vkeyHash common.Hash
	// member is the statement's member.
	member common.Hash
	// submission is the statement's source as optimism_sendRawTransactionWithStatementProofs takes
	// it.
	submission map[string]any
}

// fixtureDir holds op-leanvm-tree's committed fixtures: program leaf proofs of the class and
// leanSPHINCS signatures.
const fixtureDir = "../../../rust/op-leanvm-tree/testdata"

// fibonacciDigest is the verifying key digest of leanVM's fibonacci member guest normalized to the
// program class (op-leanvm-tree's testdata/fibonacci-1000.key).
var fibonacciDigest = common.HexToHash("0x190e7e20d9f3e0fed3c49a09ea7100c17b46ac7acfd036a849159fc00d2a5e8c")

// largeFibonacciDigest is the verifying key digest of the same guest normalized to the large
// program class (op-leanvm-tree's testdata/fibonacci-1000-large.key): another program.
var largeFibonacciDigest = common.HexToHash("0xdf17c6524b9509f44c6741832fe0bebdee26de88d417f62b899810dce2c12a54")

// signatureProgramDigest is the verifying key digest of the leanSPHINCS signature-member guest
// normalized to the signature class: op-leanvm-tree's SIGNATURE_PROGRAM_DIGEST.
var signatureProgramDigest = common.HexToHash("0x98889a8a7ad3074d3d51f926488ca52c42d0da668cbdb7620eb3efe700a51a9e")

// readTestdata reads op-leanvm-tree's fixture name.
func readTestdata(t devtest.T, name string) []byte {
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	t.Require().NoError(err, "read fixture %s", name)
	return data
}

// readProgramFixture loads a program statement: the normalized fibonacci member guest's verifying
// key and a zero-knowledge leaf proof of its run on n = 1000, which publishes one member.
func readProgramFixture(t devtest.T) fixture {
	return readProgramLeaf(t, "fibonacci-1000", fibonacciDigest)
}

// readLargeProgramFixture loads a statement of the large program class: the fibonacci guest
// normalized to it and proven at its leaf shape (rate 1/8), which op-aggregator folds in the same
// tier as any other leaf.
func readLargeProgramFixture(t devtest.T) fixture {
	return readProgramLeaf(t, "fibonacci-1000-large", largeFibonacciDigest)
}

// readProgramLeaf loads op-leanvm-tree's program fixture name: a leaf proof publishing one member
// of the guest whose normalized verifying key digest is digest.
func readProgramLeaf(t devtest.T, name string, digest common.Hash) fixture {
	members := readTestdata(t, name+".members")
	t.Require().Len(members, 32)
	return fixture{
		vkeyHash: digest,
		member:   common.Hash(members),
		submission: map[string]any{
			"type":         "program",
			"vkeyHash":     digest,
			"members":      []common.Hash{common.Hash(members)},
			"proof":        hexutil.Bytes(readTestdata(t, name+".proof")),
			"verifyingKey": hexutil.Bytes(readTestdata(t, name+".key")),
		},
	}
}

// readSignatureFixture loads a signature statement: a leanSPHINCS signature over a message, whose
// member binds the public key and the message. op-aggregator proves its leaf.
func readSignatureFixture(t devtest.T) fixture {
	member := readTestdata(t, "signature-0.member")
	t.Require().Len(member, 32)
	message := readTestdata(t, "signature-0.message")
	t.Require().Len(message, 32)
	return fixture{
		vkeyHash: signatureProgramDigest,
		member:   common.Hash(member),
		submission: map[string]any{
			"type":      "signature",
			"publicKey": hexutil.Bytes(readTestdata(t, "signature-0.key")),
			"message":   common.Hash(message),
			"signature": hexutil.Bytes(readTestdata(t, "signature-0.signature")),
		},
	}
}
