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
	aggregateBlock := includeProofAggregate(t, chain{EL: sys.L2EL, Funder: sys.FunderL2, Network: sys.L2Network}, f)
	t.Require().True(isVerified(t, sys.L2EL, f), "the aggregate marks the statement verified")

	sys.L2ELVerifier.Reached(eth.Safe, aggregateBlock, 180)
	t.Require().Equal(sys.L2EL.BlockRefByNumber(aggregateBlock).Hash,
		sys.L2ELVerifier.BlockRefByNumber(aggregateBlock).Hash,
		"the verifier derives the block carrying the proof aggregate")
	t.Require().True(isVerified(t, sys.L2ELVerifier, f), "the verifier agrees the statement is verified")
}

// includeProofAggregate runs the user and sequencer flow up to the block that carries the
// aggregate: configure the registry, submit the statement and its proof, then the aggregate.
// Returns that block's number.
func includeProofAggregate(t devtest.T, c chain, f fixture) uint64 {
	configureRegistry(t, c, common.HexToHash(f.aggregationVkeyHash), 131_072)
	user := c.Funder.NewFundedEOA(eth.OneEther)
	submitStatement(t, c, user, f)
	t.Require().False(isVerified(t, c.EL, f), "a submitted statement starts pending")

	submitStatementProof(t, c.EL, f)
	t.Require().Len(pendingStatementProofs(t, c.EL), 1, "the sequencer queues the verified proof")

	from := c.EL.BlockRefByLabel(eth.Unsafe).Number
	submitAggregate(t, c.EL, f)
	t.Require().Empty(pendingStatementProofs(t, c.EL), "the aggregate consumes the statement proof")

	return waitForProofAggregateBlock(t, c.EL, from)
}
