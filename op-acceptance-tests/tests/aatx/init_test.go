package aatx

import (
	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
)

// newAaTxSystem builds an op-reth sequencer and an op-reth verifier on a chain with Lagoon, the
// fork that activates EIP-8430 transactions, at genesis.
func newAaTxSystem(t devtest.T) *sdmtest.RethSystem {
	sysgo.SkipOnOpGeth(t, "EIP-8430 transactions are executed by op-reth")

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
		InteropAtGenesis: true,
	})
	return sdmtest.FinishRethSystem(t, runtime, false)
}
