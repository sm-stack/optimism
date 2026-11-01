package proofaggregation

import (
	"testing"
	"time"

	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-service/bigs"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestTransactionActsOnADependencyBeforeItsAggregate sends an EIP-8430 transaction that declares a
// program statement in its dependency entry, with the leaf proof publishing its member attached. The
// sequencer verifies the proof and includes the transaction at once, and a contract reads the
// dependency through the Transaction Context precompile and acts on it in that block. op-aggregator, a separate
// process reading the sequencer's statement sources over op-reth's authenticated endpoint, then
// folds the leaf into a leanVM tree root and submits it; op-reth verifies it and queues it for the
// batcher, which posts it in a later channel. The aggregate answers for the transaction's block: a
// verifier, kona-node or op-node, verifies the root and its seal and derives the block the
// sequencer preconfirmed.
func TestTransactionActsOnADependencyBeforeItsAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	runDependencyFlow(t, readProgramFixture(t))
}

// TestTransactionActsOnASignatureBeforeItsAggregate runs the same flow on a leanSPHINCS
// signature: the transaction depends on the signature's member, and the user sends the raw
// signature. The sequencer verifies it and includes the transaction at once, and op-aggregator
// proves the signature leaf when it folds the block.
func TestTransactionActsOnASignatureBeforeItsAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	runDependencyFlow(t, readSignatureFixture(t))
}

// TestTransactionActsOnALargeProgramDependencyBeforeItsAggregate runs the same flow on a leaf
// of the large program class, proven at rate 1/8 so that its first level shares the tree's tier:
// the sequencer routes it to its class by its shape, and a verifier derives the block.
func TestTransactionActsOnALargeProgramDependencyBeforeItsAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	runDependencyFlow(t, readLargeProgramFixture(t))
}

// TestSequencerRefusesDependentTransactionsWithoutOpAggregator sends a transaction depending
// on a statement to a sequencer no op-aggregator serves: no aggregate would answer for its block,
// and derivation would replace the block, so the sequencer refuses it.
func TestSequencerRefusesDependentTransactionsWithoutOpAggregator(gt *testing.T) {
	t := devtest.SerialT(gt)
	f := readProgramFixture(t)
	sys := newSystemWithoutOpAggregator(t)
	c := chain{EL: sys.L2EL, Funder: sys.FunderL2}
	user := c.Funder.NewFundedEOA(eth.OneEther)
	consumer := deployConsumer(t, user)
	err := trySendWithProof(t, c.EL, dependentTx(t, c.EL, user, consumer, f), f)
	t.Require().ErrorContains(err, "no op-aggregator is proving aggregates")
}

// runDependencyFlow sends a transaction depending on f's statement, checks that it acts at
// once, and that a verifier derives the preconfirmed block once the sequencer's aggregate lands.
func runDependencyFlow(t devtest.T, f fixture) {
	runDependencyFlowOn(t, newProofAggregationSystem(t), f)
}

// runDependencyFlowOn is runDependencyFlow on sys. It returns the transaction's block.
func runDependencyFlowOn(t devtest.T, sys *sdmtest.RethSystem, f fixture) uint64 {
	sys.L2Batcher.Start()
	c := chain{EL: sys.L2EL, Funder: sys.FunderL2}

	receipt, consumer := sendDependentTx(t, c, f)
	txBlock := bigs.Uint64Strict(receipt.BlockNumber)
	t.Require().Equal(common.BigToHash(common.Big1), storageAt(t, sys.L2EL, consumer, common.Hash{}, txBlock),
		"the consumer acts on the dependency in the transaction's own block")

	aggregate := waitForPendingAggregate(t, c.EL, txBlock)
	t.Require().Equal(uint8(optypes.ProofAggregatePayloadVersion), aggregate.Version)
	t.Require().Contains(aggregate.Statements, optypes.ProofStatement{VkeyHash: f.vkeyHash, PublicValuesDigest: f.member},
		"the sequencer's aggregate proves the dependency")
	sys.L2ELVerifier.Reached(eth.Safe, txBlock, 180)
	t.Require().Equal(receipt.BlockHash, sys.L2ELVerifier.BlockRefByNumber(txBlock).Hash,
		"the verifier derives the preconfirmed block, dependent transaction included")
	return txBlock
}

// sendDependentTx deploys a consumer and sends an EIP-8430 transaction calling it that depends on
// the fixture's statement. No aggregate exists yet: the sequencer includes it at once, and its
// phase commits.
func sendDependentTx(t devtest.T, c chain, f fixture) (*optypes.Receipt, common.Address) {
	user := c.Funder.NewFundedEOA(eth.OneEther)
	consumer := deployConsumer(t, user)
	hash := sendWithProof(t, c.EL, dependentTx(t, c.EL, user, consumer, f), f)
	receipt := c.EL.WaitForOpReceipt(hash)
	t.Require().Equal(uint8(optypes.AaTxType), receipt.Type)
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	t.Require().NotNil(receipt.CommittedPhases)
	t.Require().Equal(uint64(1), *receipt.CommittedPhases)
	return receipt, consumer
}

// TestBlockWithoutAnAggregateIsReplaced sends a transaction depending on a statement to a sequencer
// that hands op-aggregator nothing to prove. The sequencer includes it at once, but once
// derivation's window passes with no aggregate answering for its block, a verifier derives that
// block with only its deposits, the consumer it called never acted, and the sequencer reorgs onto
// that block. The window is 100 L1 blocks, so this takes about ten minutes of L1 time; running
// the whole package needs a timeout above the default 30 minutes. The empty aggregate queue shows
// no aggregate was proven, though op-aggregator ran.
func TestBlockWithoutAnAggregateIsReplaced(gt *testing.T) {
	t := devtest.SerialT(gt)
	f := readProgramFixture(t)
	sys := newSystemWithoutAggregation(t)
	sys.L2Batcher.Start()

	receipt, consumer := sendDependentTx(t, chain{EL: sys.L2EL, Funder: sys.FunderL2}, f)
	txBlock := bigs.Uint64Strict(receipt.BlockNumber)
	t.Require().Equal(common.BigToHash(common.Big1), storageAt(t, sys.L2EL, consumer, common.Hash{}, txBlock),
		"the sequencer acts on the dependency before any aggregate")

	// DEPENDENCY_SCAN_WINDOW (100) L1 blocks of 6 seconds pass before the block is decided.
	t.Require().NoError(sys.L2ELVerifier.ReachedWithProgressFn(eth.Safe, eth.Unsafe, txBlock,
		20*time.Minute, 2*time.Minute)())
	derived := sys.L2ELVerifier.BlockRefByNumber(txBlock).Hash
	t.Require().NotEqual(receipt.BlockHash, derived,
		"the verifier derives another block than the sequencer preconfirmed")
	requireOnlyDeposits(t, sys.L2ELVerifier, txBlock)
	t.Require().Equal(common.Hash{}, storageAt(t, sys.L2ELVerifier, consumer, common.Hash{}, txBlock),
		"the consumer never acted on the unproven dependency")

	sys.L2EL.Reached(eth.Safe, txBlock, 60)
	t.Require().Equal(derived, sys.L2EL.BlockRefByNumber(txBlock).Hash,
		"the sequencer reorgs onto the derived block")
	t.Require().Empty(pendingAggregates(t, sys.L2EL), "no aggregate was proven")
}
