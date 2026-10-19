package proofaggregation

import (
	"os"
	"path/filepath"

	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	"github.com/ethereum-optimism/optimism/op-core/devfeatures"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
)

// fixtureDirEnv names the directory holding a ready SP1 statement proof and an aggregate proof
// over it (see readFixture). Proving one takes minutes and ~10 GB on a CPU, so the test consumes
// pre-proven fixtures instead and skips when they are absent.
const fixtureDirEnv = "PROOF_AGGREGATION_FIXTURE_DIR"

// newProofAggregationSystem builds an op-reth sequencer and an op-reth verifier on a chain with
// Lagoon at genesis and the ProofRegistry predeploy installed (PROOF_AGGREGATION dev feature).
func newProofAggregationSystem(t devtest.T) *sdmtest.RethSystem {
	sysgo.SkipOnOpGeth(t, "proof aggregate transactions are produced and verified by op-reth")

	clKind := sysgo.ResolveMixedL2CLKind()
	runtime := sysgo.NewMixedSingleChainRuntime(t, sysgo.MixedSingleChainPresetConfig{
		NodeSpecs: []sysgo.MixedSingleChainNodeSpec{
			{
				ELKey:       "sequencer-op-reth",
				CLKey:       "sequencer",
				ELKind:      sysgo.MixedL2ELOpReth,
				CLKind:      clKind,
				IsSequencer: true,
				OpRethOpts:  sysgo.ResolveMixedL2ELOpts(t),
			},
			{
				ELKey:  "verifier-op-reth",
				CLKey:  "verifier",
				ELKind: sysgo.MixedL2ELOpReth,
				CLKind: clKind,
			},
		},
		DeployerOptions:  []sysgo.DeployerOption{sysgo.WithDevFeatureEnabled(devfeatures.ProofAggregationFlag)},
		InteropAtGenesis: true,
	})
	return sdmtest.FinishRethSystem(t, runtime, false)
}

// fixture is a statement and the proofs the sequencer needs for it.
type fixture struct {
	// vkeyHash is the statement program's verifying key digest, eight big-endian words.
	vkeyHash [32]byte
	// publicValues are the statement program's public values.
	publicValues []byte
	// proof is the statement's SP1 compressed proof (bincode SP1Proof).
	proof []byte
	// verifyingKey is the statement program's bincode SP1VerifyingKey.
	verifyingKey []byte
	// aggregateProof is the aggregation program's proof over exactly this statement.
	aggregateProof []byte
	// aggregationVkeyHash is the aggregation program's verifying key digest.
	aggregationVkeyHash string
}

// readFixture loads the fixture `kona-sp1-proof-aggregator`'s prove_aggregate test writes, plus
// `vkey_hash.bin`, the statement program's digest as eight little-endian u32s (bincode
// [KoalaBear; 8]).
func readFixture(t devtest.T) fixture {
	dir := os.Getenv(fixtureDirEnv)
	if dir == "" {
		t.Skipf("%s unset: no pre-proven statement and aggregate proofs", fixtureDirEnv)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		t.Require().NoError(err, "read fixture %s", name)
		return data
	}
	var f fixture
	words := read("vkey_hash.bin")
	t.Require().Len(words, 32)
	for i := 0; i < 8; i++ {
		for j := 0; j < 4; j++ {
			f.vkeyHash[4*i+j] = words[4*i+3-j]
		}
	}
	f.publicValues = read("public_values.bin")
	f.proof = read("proof.bin")
	f.verifyingKey = read("verifying_key.bin")
	f.aggregateProof = read("aggregate_proof.bin")
	f.aggregationVkeyHash = string(read("aggregation_vkey_hash.txt"))
	return f
}
