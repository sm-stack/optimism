package proofaggregation

import (
	"testing"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
)

// TestProofAggregateVerifiesSubmittedStatement walks a statement through proof aggregation: a user
// registers it on chain and gives the sequencer its proof off chain, the sequencer includes an
// aggregate proof covering it, the registry then reports it verified, and a verifier node derives
// the block carrying the aggregate with the same hash.
func TestProofAggregateVerifiesSubmittedStatement(gt *testing.T) {
	t := devtest.SerialT(gt)
	f := readFixture(t)
	sys := newProofAggregationSystem(t)
	sys.L2Batcher.Start()

	configureRegistry(t, sys, common.HexToHash(f.aggregationVkeyHash), 131_072)
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)
	submitStatement(t, sys, user, f)
	t.Require().False(isVerified(t, sys.L2EL, f), "a submitted statement starts pending")

	submitStatementProof(t, sys.L2EL, f)
	t.Require().Len(pendingStatementProofs(t, sys.L2EL), 1, "the sequencer queues the verified proof")

	from := sys.L2EL.BlockRefByLabel(eth.Unsafe).Number
	submitAggregate(t, sys.L2EL, f)
	t.Require().Empty(pendingStatementProofs(t, sys.L2EL), "the aggregate consumes the statement proof")

	aggregateBlock := waitForProofAggregateBlock(t, sys.L2EL, from)
	t.Require().True(isVerified(t, sys.L2EL, f), "the aggregate marks the statement verified")

	sys.L2ELVerifier.Reached(eth.Safe, aggregateBlock, 180)
	t.Require().Equal(sys.L2EL.BlockRefByNumber(aggregateBlock).Hash,
		sys.L2ELVerifier.BlockRefByNumber(aggregateBlock).Hash,
		"the verifier derives the block carrying the proof aggregate")
	t.Require().True(isVerified(t, sys.L2ELVerifier, f), "the verifier agrees the statement is verified")
}
