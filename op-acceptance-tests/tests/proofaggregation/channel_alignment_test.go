package proofaggregation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	bss "github.com/ethereum-optimism/optimism/op-batcher/batcher"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive"
	"github.com/ethereum-optimism/optimism/op-service/bigs"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/retry"
)

// testRunBlocks is the run length of these tests.
const testRunBlocks = 4

// endsRun returns whether ch's last block ends a run.
func endsRun(ch postedChannel) bool {
	return (slices.Max(ch.blocks)+1)%testRunBlocks == 0
}

// answersFor returns whether an aggregate in ch reaches block.
func answersFor(ch postedChannel, block uint64) bool {
	return slices.ContainsFunc(ch.aggregates, func(through uint64) bool { return through >= block })
}

// TestBatcherHoldsAChannelForItsBlocksAggregate runs the dependency flow with a batcher that holds
// each channel ending a run for the aggregate of its blocks. Sequencer, aggregator and batcher all
// end the run at the same block; the aggregate is written as the channel's last item, so it lands
// in the channel of the block it answers for.
func TestBatcherHoldsAChannelForItsBlocksAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newHoldingSystem(t, 30*time.Second, testRunBlocks)
	txBlock := runDependencyFlowOn(t, sys, readProgramFixture(t))

	carrying := channelsCarrying(t, sys, txBlock)
	t.Require().Len(carrying, 1, "block %d is posted once: its aggregate came with it, so derivation never stalled", txBlock)
	ch := carrying[0]
	t.Require().True(answersFor(ch, txBlock), "the aggregate of the transaction's block shares its channel")
	t.Require().True(endsRun(ch), "the channel ends at the run's boundary, block %d", slices.Max(ch.blocks))
}

// TestBatcherPostsAQuietChannelWithItsAggregate gives channels a duration of five L1 blocks, as on a
// quiet chain: the run's boundary comes first, and the channel goes there with its aggregate.
func TestBatcherPostsAQuietChannelWithItsAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	quiet := func(_ sysgo.ComponentTarget, cfg *bss.CLIConfig) { cfg.MaxChannelDuration = 5 }
	sys := finish(t, newRuntime(t, []sysgo.BatcherOption{holding(30 * time.Second), quiet}, fixedRuns(testRunBlocks)))
	txBlock := runDependencyFlowOn(t, sys, readProgramFixture(t))
	ch := channelsCarrying(t, sys, txBlock)[0]
	t.Require().True(answersFor(ch, txBlock), "the aggregate shares its block's channel")
	t.Require().True(endsRun(ch), "the boundary beats the channel's duration")
}

// TestBatcherPostsALateAggregateByTheNextBoundary holds channels too briefly to wait for an
// aggregate, which then rides a later channel as it comes. The verifier derives the block from
// it, and the batcher posts the block once: a safe head waiting for a late aggregate is not a
// stalled one.
func TestBatcherPostsALateAggregateByTheNextBoundary(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newHoldingSystem(t, time.Millisecond, testRunBlocks)
	txBlock := runDependencyFlowOn(t, sys, readProgramFixture(t))
	t.Require().Len(channelsCarrying(t, sys, txBlock), 1, "block %d is posted once", txBlock)
	t.Require().True(slices.ContainsFunc(postedChannels(t, sys), func(ch postedChannel) bool {
		return answersFor(ch, txBlock)
	}), "the aggregate is posted")
}

// TestBatcherReleasesAHeldChannelWithoutItsAggregate holds the channel of a dependent transaction's
// block for a sequencer that proves no aggregate: the hold ends at its deadline, and the channel
// lands without one.
func TestBatcherReleasesAHeldChannelWithoutItsAggregate(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newHoldingSystem(t, 3*time.Second, testRunBlocks, sysgo.OpRethWithExtraArgs("--testing.disable-proof-aggregation"))
	sys.L2Batcher.Start()

	receipt, _ := sendDependentTx(t, chain{EL: sys.L2EL, Funder: sys.FunderL2}, readProgramFixture(t))
	ch := channelsCarrying(t, sys, bigs.Uint64Strict(receipt.BlockNumber))[0]
	t.Require().Empty(ch.aggregates, "the channel lands at the hold's deadline, with no aggregate")
	t.Require().True(endsRun(ch), "the channel was held to its run's boundary")
}

// postedChannel is what a channel posted to L1 carries: the L2 blocks of its batches, and the
// through of each aggregate, in order.
type postedChannel struct {
	blocks     []uint64
	aggregates []uint64
}

// channelsCarrying waits until the batcher has posted a channel carrying the batch of L2 block
// `block`, and returns every such channel posted so far, in posting order. A batcher that mistakes
// a safe head held for an aggregate for a stalled one starts afresh and posts the block again.
func channelsCarrying(t devtest.T, sys *sdmtest.RethSystem, block uint64) []postedChannel {
	carrying, err := retry.Do(t.Ctx(), 120, &retry.FixedStrategy{Dur: time.Second}, func() ([]postedChannel, error) {
		var carrying []postedChannel
		for _, ch := range postedChannels(t, sys) {
			if slices.Contains(ch.blocks, block) {
				carrying = append(carrying, ch)
			}
		}
		if len(carrying) == 0 {
			return nil, fmt.Errorf("no channel carrying block %d posted yet", block)
		}
		return carrying, nil
	})
	t.Require().NoError(err, "the channel carrying block %d", block)
	return carrying
}

// postedChannels decodes every complete channel posted to the batch inbox so far.
func postedChannels(t devtest.T, sys *sdmtest.RethSystem) []postedChannel {
	cfg := sys.L2Network.Escape().RollupConfig()
	l1 := sys.L1EL.EthClient()
	head := sys.L1EL.BlockRefByLabel(eth.Unsafe)
	frames := make(map[derive.ChannelID][]derive.Frame)
	var channels []postedChannel
	for n := uint64(0); n <= head.Number; n++ {
		info, txs, err := l1.InfoAndTxsByNumber(t.Ctx(), n)
		t.Require().NoError(err)
		for _, tx := range txs {
			if to := tx.To(); to == nil || *to != cfg.BatchInboxAddress {
				continue
			}
			parsed, err := derive.ParseFrames(tx.Data())
			t.Require().NoError(err, "the batcher's frames")
			for _, f := range parsed {
				if slices.ContainsFunc(frames[f.ID], func(g derive.Frame) bool { return g.FrameNumber == f.FrameNumber }) {
					continue // resubmitted
				}
				frames[f.ID] = append(frames[f.ID], f)
				if f.IsLast {
					channels = append(channels, decodeChannel(t, sys, frames[f.ID], info.Time()))
					delete(frames, f.ID)
				}
			}
		}
	}
	return channels
}

// decodeChannel decodes a complete channel's frames, included in L1 at time l1Time.
func decodeChannel(t devtest.T, sys *sdmtest.RethSystem, frames []derive.Frame, l1Time uint64) postedChannel {
	cfg := sys.L2Network.Escape().RollupConfig()
	slices.SortFunc(frames, func(a, b derive.Frame) int { return int(a.FrameNumber) - int(b.FrameNumber) })
	var data []byte
	for _, f := range frames {
		data = append(data, f.Data...)
	}
	read, err := derive.BatchReader(bytes.NewReader(data), rollup.NewChainSpec(cfg).MaxRLPBytesPerChannel(l1Time), cfg.IsFjord(l1Time))
	t.Require().NoError(err)
	var ch postedChannel
	for {
		batchData, err := read()
		if errors.Is(err, io.EOF) {
			return ch
		}
		t.Require().NoError(err)
		switch batchData.GetBatchType() {
		case derive.ProofAggregateBatchType:
			aggregate, err := derive.GetProofAggregateBatch(batchData)
			t.Require().NoError(err)
			ch.aggregates = append(ch.aggregates, aggregate.Payload.Through)
		case derive.SpanBatchType:
			spanBatch, err := derive.DeriveSpanBatch(batchData, cfg)
			t.Require().NoError(err)
			for _, b := range spanBatch.Batches {
				number, err := cfg.TargetBlockNumber(b.Timestamp)
				t.Require().NoError(err)
				ch.blocks = append(ch.blocks, number)
			}
		}
	}
}
