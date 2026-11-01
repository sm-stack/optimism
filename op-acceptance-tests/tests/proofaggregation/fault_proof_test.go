package proofaggregation

import (
	"testing"
	"time"

	sfp "github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/superfaultproofs"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/trace/super"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl/proofs"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	sharedchallenger "github.com/ethereum-optimism/optimism/op-devstack/shared/challenger"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
	"github.com/ethereum-optimism/optimism/op-service/bigs"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

// TestFaultProofProgramProvesABlockAnsweredByALaterAggregate runs the kona interop fault proof
// program over the super-root transition into the block that carries an EIP-8430 transaction
// depending on a leanSPHINCS signature. To derive the block the program must find, in later L1
// data, the aggregate answering for it and verify that aggregate's tree root itself; it must agree
// with the valid transitions and reject the invalid ones exactly as for any other block. The super
// roots come from op-supernode, which verifies the aggregate with the pinned leanVM class.
//
// Proof aggregation is gated on Lagoon, the interop fork, so the block is proven in super-root
// mode. Set SUPERFAULTPROOFS_WITNESS_DIR to keep each run's preimages for an offline Cannon replay.
func TestFaultProofProgramProvesABlockAnsweredByALaterAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	sysgo.SkipOnOpGeth(t, "the sequencer's proof aggregate queue lives in op-reth")
	f := readSignatureFixture(t)
	sys := presets.NewSingleChainInterop(t, presets.WithOpAggregator())

	var receipt *optypes.Receipt
	sfp.RunSingleChainSuperFaultProofSmokeTestAt(t, sys,
		func(t devtest.T, sys *presets.SingleChainInterop) uint64 {
			c := chain{EL: sys.L2ELA, Funder: sys.FunderA}
			receipt, _ = sendDependentTx(t, c, f)
			txBlock := bigs.Uint64Strict(receipt.BlockNumber)
			waitForPendingAggregate(t, c.EL, txBlock)
			return txBlock
		},
		sfp.NewKonaProofRunner())
	txBlock := bigs.Uint64Strict(receipt.BlockNumber)
	t.Require().Equal(receipt.BlockHash, sys.L2ELA.BlockRefByNumber(txBlock).Hash,
		"the proven block is the preconfirmed one, dependent transaction included")
}

// TestFaultProofProgramProvesABlockNoAggregateAnswersFor runs the kona interop fault proof program
// over the super-root transition into a block whose dependent transaction no aggregate proves. The
// program must scan the whole of derivation's window and derive the block with only its deposits,
// as op-supernode does. The window is 100 L1 blocks, so this takes about ten minutes of L1 time.
func TestFaultProofProgramProvesABlockNoAggregateAnswersFor(gt *testing.T) {
	t := devtest.SerialT(gt)
	sysgo.SkipOnOpGeth(t, "the sequencer's proof aggregate queue lives in op-reth")
	f := readSignatureFixture(t)
	sys := presets.NewSingleChainInterop(t,
		presets.WithOpRethOption(sysgo.OpRethWithExtraArgs("--testing.disable-proof-aggregation")))

	var receipt *optypes.Receipt
	sfp.RunSingleChainSuperFaultProofSmokeTestAtWithin(t, sys,
		func(t devtest.T, sys *presets.SingleChainInterop) uint64 {
			receipt, _ = sendDependentTx(t, chain{EL: sys.L2ELA, Funder: sys.FunderA}, f)
			return bigs.Uint64Strict(receipt.BlockNumber)
		},
		20*time.Minute,
		sfp.NewKonaProofRunner())
	txBlock := bigs.Uint64Strict(receipt.BlockNumber)
	t.Require().NotEqual(receipt.BlockHash, sys.L2ELA.BlockRefByNumber(txBlock).Hash,
		"the proven block is not the preconfirmed one")
	requireOnlyDeposits(t, sys.L2ELA, txBlock)
	t.Require().Empty(pendingAggregates(t, sys.L2ELA), "no aggregate was proven")
}

// aggregateVerificationStep is a Cannon step inside the kona interop program's verification of a
// leanVM tree root. Deriving the block an aggregate answers for reaches the aggregate within about
// 0.3 to 0.9 billion steps, depending on how many channels precede it, and verifying the root then
// takes about 0.8 billion more, so the step falls inside the verification either way. It sits just
// past a snapshot, so the proofs at and just below it replay a short way.
const aggregateVerificationStep = 4*cannonSnapshotFreq + 1_000

// cannonSnapshotFreq is how many steps apart the challenger's Cannon saves snapshots. Each writes
// the whole VM memory, so the devstack default of 10 million steps makes a trace of billions of
// steps run several times slower.
const cannonSnapshotFreq = 250_000_000

// TestChallengerStepsThroughAnAggregateVerification plays a super-cannon-kona dispute game over the
// block that carries an EIP-8430 transaction depending on a leanSPHINCS signature. An attacker
// disputes the transition that derives that block, then bisects its execution trace down to a
// single instruction inside the verification of the aggregate answering for the block. The honest
// op-challenger must run the kona interop program in Cannon through the verification and counter
// the attacker's last claim with an on-chain step.
func TestChallengerStepsThroughAnAggregateVerification(gt *testing.T) {
	t := devtest.SerialT(gt)
	sysgo.SkipOnOpGeth(t, "the sequencer's proof aggregate queue lives in op-reth")
	f := readSignatureFixture(t)
	sys := presets.NewSingleChainInterop(t, presets.WithOpAggregator(), presets.WithoutHonestProposer(),
		presets.WithChallengerOptions(sharedchallenger.WithCannonKonaSnapshotFreq(cannonSnapshotFreq)))

	c := chain{EL: sys.L2ELA, Funder: sys.FunderA}
	receipt, _ := sendDependentTx(t, c, f)
	txBlock := bigs.Uint64Strict(receipt.BlockNumber)
	waitForPendingAggregate(t, c.EL, txBlock)
	timestamp := sys.L2ChainA.Escape().RollupConfig().TimestampForBlock(txBlock)
	sys.SuperRoots.AwaitValidatedTimestamp(timestamp)
	t.Require().Equal(receipt.BlockHash, sys.L2ELA.BlockRefByNumber(txBlock).Hash,
		"the safe block is the preconfirmed one, dependent transaction included")

	attacker := sys.FunderL1.NewFundedEOA(eth.ThousandEther)
	game := sys.DisputeGameFactory().StartSuperCannonKonaGame(attacker, proofs.WithL2SequenceNumber(timestamp))
	// The honest trace answers only once op-supernode has fully processed the game's L1 head.
	l1Head, err := sys.L1EL.EthClient().BlockRefByHash(t.Ctx(), game.L1Head())
	t.Require().NoError(err)
	sys.SuperRoots.AwaitFullyProcessedL1(l1Head.Number)

	start := game.StartingL2SequenceNumber()
	t.Require().Greater(timestamp, start, "the game must start before the block it disputes")
	// The super trace reads trace index i as step (i+1)%128 of the transition out of
	// start+(i+1)/128, so this index is step 1 out of timestamp-1: the only chain's block at
	// timestamp, derived from the super root at timestamp-1.
	transition := (timestamp - start - 1) * super.StepsPerTimestamp
	// DisputeL2SequenceNumber treats trace index i as sequence number start+1+i, as in an output
	// root game. transition is even, so the attacker lands on that index and attacks it.
	claim := game.DisputeL2SequenceNumber(attacker, game.RootClaim(), start+1+transition)
	claim = claim.WaitForCounterClaim()
	claim = game.DisputeToStep(attacker, claim, aggregateVerificationStep)
	game.LogGameData()
	claim.WaitForCountered()
}
