package proofaggregation

import (
	"testing"

	sfp "github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/superfaultproofs"
	"github.com/ethereum-optimism/optimism/op-core/devfeatures"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
)

// TestFaultProofProgramAcceptsProofAggregateBlock runs the kona interop fault proof program over
// the super-root transition into the block that carries a proof aggregate. The program must derive
// the block from L1, verify the aggregate proof itself, and agree with the valid transitions and
// reject the invalid ones exactly as for any other block.
//
// Proof aggregation is gated on Lagoon, the interop fork, so the block is proven in super-root
// mode. Set SUPERFAULTPROOFS_WITNESS_DIR to keep each run's preimages for an offline Cannon replay.
func TestFaultProofProgramAcceptsProofAggregateBlock(gt *testing.T) {
	t := devtest.SerialT(gt)
	f := readFixture(t)
	sysgo.SkipOnOpGeth(t, "proof aggregate transactions are produced and verified by op-reth")
	sys := presets.NewSingleChainInterop(t,
		presets.WithDeployerOptions(sysgo.WithDevFeatureEnabled(devfeatures.ProofAggregationFlag)))

	sfp.RunSingleChainSuperFaultProofSmokeTestAt(t, sys,
		func(t devtest.T, sys *presets.SingleChainInterop) uint64 {
			return includeProofAggregate(t, chain{EL: sys.L2ELA, Funder: sys.FunderA, Network: sys.L2ChainA}, f)
		},
		sfp.NewKonaProofRunner())
}
