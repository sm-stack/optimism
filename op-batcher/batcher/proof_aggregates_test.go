package batcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum-optimism/optimism/op-batcher/metrics"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive/params"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

// lagoonTestRollupConfig is defaultTestRollupConfig with Lagoon active from genesis and 2 s blocks.
var lagoonTestRollupConfig = func() *rollup.Config {
	cfg := *defaultTestRollupConfig
	cfg.LagoonTime = new(uint64)
	cfg.BlockTime = 2
	return &cfg
}()

func testAggregatePayload(through uint64) *optypes.ProofAggregatePayload {
	return &optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             through,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements:          []optypes.ProofStatement{{VkeyHash: common.Hash{1}, PublicValuesDigest: common.Hash{2}}},
		Proof:               []byte("proof"),
	}
}

// newAggregateTestChannelManager returns a cleared channel manager under Lagoon.
func newAggregateTestChannelManager(t *testing.T, batchType uint) *channelManager {
	l := testlog.Logger(t, log.LevelError)
	m := NewChannelManager(l, metrics.NoopMetrics, channelManagerTestConfig(1_000_000, batchType), lagoonTestRollupConfig)
	m.Clear(eth.BlockID{})
	return m
}

// addBlocks adds blocks from..to (inclusive) to m as a chain.
func addBlocks(t *testing.T, m *channelManager, from, to uint64) {
	parent := m.tip
	for n := from; n <= to; n++ {
		block := newMiniL2BlockWithNumberParent(0, new(big.Int).SetUint64(n), parent)
		require.NoError(t, m.AddL2Block(mustPayloadFromGeth(block)))
		parent = block.Hash()
	}
}

// channelItems closes the current channel and decodes what it holds: block numbers, and
// "aggregate" for an aggregate.
func channelItems(t *testing.T, m *channelManager, firstBlock uint64) []string {
	return builderItems(t, m.currentChannel.ChannelBuilder, firstBlock)
}

// builderItems closes cb and decodes what it holds, as channelItems does.
func builderItems(t *testing.T, cb *ChannelBuilder, firstBlock uint64) []string {
	cb.Close()
	require.NoError(t, cb.OutputFrames())
	return frameItems(t, cb, firstBlock)
}

// frameItems decodes the pending frames of cb, whose frames are all output, as channelItems does.
func frameItems(t *testing.T, cb *ChannelBuilder, firstBlock uint64) []string {
	var data []byte
	for cb.HasPendingFrame() {
		frame := cb.NextFrame()
		frames, err := derive.ParseFrames(append([]byte{params.DerivationVersion0}, frame.data...))
		require.NoError(t, err)
		for _, f := range frames {
			data = append(data, f.Data...)
		}
	}
	read, err := derive.BatchReader(bytes.NewReader(data), 100_000_000, true)
	require.NoError(t, err)
	var items []string
	block := firstBlock
	for {
		batchData, err := read()
		if err == io.EOF {
			return items
		}
		require.NoError(t, err)
		switch batchData.GetBatchType() {
		case derive.ProofAggregateBatchType:
			items = append(items, "aggregate")
		case derive.SingularBatchType:
			items = append(items, eth.BlockID{Number: block}.String())
			block++
		default:
			spanBatch, err := derive.DeriveSpanBatch(batchData, defaultTestRollupConfig)
			require.NoError(t, err)
			for range spanBatch.Batches {
				items = append(items, eth.BlockID{Number: block}.String())
				block++
			}
		}
	}
}

func blockItem(n uint64) string { return eth.BlockID{Number: n}.String() }

func TestChannelManagerWritesAProofAggregateAfterItsBlocks(t *testing.T) {
	for _, batchType := range []uint{derive.SingularBatchType, derive.SpanBatchType} {
		m := newAggregateTestChannelManager(t, batchType)
		addBlocks(t, m, 1, 2)
		require.NoError(t, addAggregate(m, testAggregatePayload(3)))
		addBlocks(t, m, 3, 5)
		require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
		require.NoError(t, m.processBlocks())
		require.ErrorIs(t, m.currentChannel.FullErr(), ErrProofAggregateWritten, "batch type %d", batchType)

		require.Equal(t, []string{blockItem(1), blockItem(2), blockItem(3), "aggregate"}, channelItems(t, m, 1),
			"batch type %d: the aggregate through 3 follows block 3 and ends the channel", batchType)
		require.NotNil(t, m.aggregates[0].channel)
		require.Equal(t, 2, m.pendingBlocks(), "blocks 4 and 5 go into the next channel")
	}
}

func TestChannelManagerRequeuesAProofAggregateOfAnInvalidatedChannel(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 1, 2)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	written := m.aggregates[0].channel
	require.NotNil(t, written)

	m.handleChannelInvalidated(written)
	require.Nil(t, m.aggregates[0].channel, "the aggregate goes into the rebuilt channel")
	require.Zero(t, m.blockCursor)
}

func TestChannelManagerRequeuesNewerBlocksWhenAnAggregateOnlyChannelIsInvalidated(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 1, 1)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	m.currentChannel.Close()
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	addBlocks(t, m, 2, 4)
	for range 2 {
		require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
		require.NoError(t, m.processBlocks())
	}
	require.Len(t, m.channelQueue, 3)
	ch0, ch1, ch2 := m.channelQueue[0], m.channelQueue[1], m.channelQueue[2]
	require.Len(t, ch0.ChannelBuilder.blocks, 1)
	require.Empty(t, ch1.ChannelBuilder.blocks, "the aggregate fills its own channel")
	require.Same(t, ch1, m.aggregates[0].channel)
	require.Len(t, ch2.ChannelBuilder.blocks, 3)
	require.Equal(t, 4, m.blockCursor)

	m.handleChannelInvalidated(ch1)
	require.Equal(t, []*channel{ch0}, m.channelQueue)
	require.Equal(t, 1, m.blockCursor, "blocks 2 to 4 of the dropped newer channel are requeued")
	require.Nil(t, m.aggregates[0].channel, "the aggregate is requeued")
}

func TestChannelManagerDropsProofAggregatesOfSafeBlocks(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 1, 3)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	require.NoError(t, addAggregate(m, testAggregatePayload(2)))
	require.NoError(t, addAggregate(m, testAggregatePayload(2)), "a repeated aggregate is ignored")
	require.Len(t, m.aggregates, 2)

	m.PruneSafeBlocks(2)
	require.Len(t, m.aggregates, 0, "blocks 1 and 2 are safe")
	require.NoError(t, addAggregate(m, testAggregatePayload(2)), "an aggregate for safe blocks is ignored")
	require.Empty(t, m.aggregates)
	require.NoError(t, addAggregate(m, testAggregatePayload(3)))
	require.Len(t, m.aggregates, 1)
}

// An aggregate through a block before the queued ones must not be written: its block's index in
// the queue would be negative.
func TestChannelManagerIgnoresAProofAggregateWhileNoBlocksAreQueued(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	require.Empty(t, m.aggregates, "the source returns it again once blocks are queued")

	addBlocks(t, m, 5, 6)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NotPanics(t, func() { require.NoError(t, m.processBlocks()) })
}

func TestChannelManagerDropsProofAggregatesWhenPruningEmptiesTheQueue(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 1, 2)
	require.NoError(t, addAggregate(m, testAggregatePayload(2)))
	m.PruneSafeBlocks(2)
	require.Empty(t, m.aggregates, "blocks 1 and 2 are safe")

	addBlocks(t, m, 3, 4)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NotPanics(t, func() { require.NoError(t, m.processBlocks()) })
}

func TestChannelManagerSkipsAProofAggregateOfPrunedBlocks(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 5, 6)
	m.aggregates = append(m.aggregates, &pendingAggregate{payload: testAggregatePayload(1)})
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NotPanics(t, func() { require.NoError(t, m.processBlocks()) })
	require.Nil(t, m.aggregates[0].channel)
}

func TestChannelManagerDropsAProofAggregateBeforeLagoon(t *testing.T) {
	l := testlog.Logger(t, log.LevelError)
	m := NewChannelManager(l, metrics.NoopMetrics, channelManagerTestConfig(1_000_000, derive.SpanBatchType), defaultTestRollupConfig)
	m.Clear(eth.BlockID{})
	addBlocks(t, m, 1, 2)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	require.Empty(t, m.aggregates)
	require.Equal(t, []string{blockItem(1), blockItem(2)}, channelItems(t, m, 1))
}

func TestChannelManagerRejectsAnInvalidProofAggregate(t *testing.T) {
	m := newAggregateTestChannelManager(t, derive.SpanBatchType)
	addBlocks(t, m, 1, 2)
	untrusted := testAggregatePayload(1)
	untrusted.AggregationVkeyHash = common.Hash{1}
	require.ErrorContains(t, addAggregate(m, untrusted), "untrusted class")
	oversized := testAggregatePayload(1)
	oversized.Proof = make([]byte, optypes.MaxProofAggregateProofBytes+1)
	require.ErrorContains(t, addAggregate(m, oversized), "byte limit")
	require.Empty(t, m.aggregates)
}

func TestChannelBuilderAProofAggregateOnlyChannelEndsAtItsBlock(t *testing.T) {
	l := testlog.Logger(t, log.LevelError)
	cfg := channelManagerTestConfig(1_000_000, derive.SpanBatchType)
	co, err := NewChannelOut(cfg, lagoonTestRollupConfig)
	require.NoError(t, err)
	cb := NewChannelBuilderWithChannelOut(l, cfg, lagoonTestRollupConfig, 0, co)
	through := eth.BlockID{Hash: common.Hash{1}, Number: 7}
	require.NoError(t, cb.AddProofAggregate(testAggregatePayload(7), through, 0))
	require.Equal(t, through, cb.LatestL2(), "pruned once block 7 is safe")
}

func TestChannelBuilderClosesOnceAProofAggregateIsWritten(t *testing.T) {
	l := testlog.Logger(t, log.LevelError)
	cfg := channelManagerTestConfig(1_000_000, derive.SpanBatchType)
	co, err := NewChannelOut(cfg, lagoonTestRollupConfig)
	require.NoError(t, err)
	cb := NewChannelBuilderWithChannelOut(l, cfg, lagoonTestRollupConfig, 0, co)
	require.NoError(t, addMiniBlock(cb))
	require.False(t, cb.IsFull())
	require.NoError(t, cb.AddProofAggregate(testAggregatePayload(0), eth.BlockID{}, 0))
	require.True(t, cb.IsFull())
	require.ErrorIs(t, cb.FullErr(), ErrProofAggregateWritten)
	_, err = cb.AddBlock(mustSizedBlockFromGeth(newMiniL2Block(0)))
	require.ErrorIs(t, err, ErrProofAggregateWritten)
}

// largeAggregate is an aggregate through `through` whose proof is 10 KB that does not compress.
func largeAggregate(through uint64) *optypes.ProofAggregatePayload {
	payload := testAggregatePayload(through)
	for i := 0; len(payload.Proof) < 10_000; i++ {
		h := crypto.Keccak256([]byte{byte(i), byte(i >> 8)})
		payload.Proof = append(payload.Proof, h...)
	}
	return payload
}

// twoBlockChannel is a channel of batch type batchType with a one-frame target of 2,000 bytes,
// holding blocks 1 and 2.
func twoBlockChannel(t *testing.T, batchType uint) *ChannelBuilder {
	cfg := channelManagerTestConfig(2_000, batchType)
	cfg.InitShadowCompressor(derive.Zlib)
	co, err := NewChannelOut(cfg, lagoonTestRollupConfig)
	require.NoError(t, err)
	cb := NewChannelBuilderWithChannelOut(testlog.Logger(t, log.LevelError), cfg, lagoonTestRollupConfig, 0, co)
	var parent common.Hash
	for n := uint64(1); n <= 2; n++ {
		block := newMiniL2BlockWithNumberParent(0, new(big.Int).SetUint64(n), parent)
		_, err := cb.AddBlock(mustSizedBlockFromGeth(block))
		require.NoError(t, err)
		parent = block.Hash()
	}
	require.False(t, cb.IsFull())
	return cb
}

// In a span-batch channel, an aggregate too large for the target is still written after the
// channel's blocks, as its last item, whether they are its blocks or later ones: it adds frames
// past the target instead of leaving the channel part-filled and starting a channel of its own.
func TestChannelBuilderLetsAnAggregatePassTheTarget(t *testing.T) {
	for _, through := range []uint64{2, 0} {
		t.Run(fmt.Sprintf("through=%d", through), func(t *testing.T) {
			cb := twoBlockChannel(t, derive.SpanBatchType)
			require.NoError(t, cb.AddProofAggregate(largeAggregate(through), eth.BlockID{Number: through}, 0))
			require.ErrorIs(t, cb.FullErr(), ErrProofAggregateWritten)
			require.Equal(t, []string{blockItem(1), blockItem(2), "aggregate"}, builderItems(t, cb, 1))
		})
	}
}

// A singular-batch channel's compressor refuses a write past its target once it holds anything,
// so the aggregate is refused and goes first in a channel of its own, as before.
func TestChannelBuilderRefusesAnAggregatePastASingularChannelsTarget(t *testing.T) {
	cb := twoBlockChannel(t, derive.SingularBatchType)
	require.ErrorIs(t, cb.AddProofAggregate(largeAggregate(2), eth.BlockID{Number: 2}, 0), derive.ErrCompressorFull)
	require.Equal(t, []string{blockItem(1), blockItem(2)}, builderItems(t, cb, 1))
}

// A span channel full by its target, having refused a block, still takes an aggregate while held:
// after the blocks it kept, without the refused one.
func TestChannelBuilderTakesAHeldAggregatePastAFullTarget(t *testing.T) {
	cfg := channelManagerTestConfig(1_000, derive.SpanBatchType)
	co, err := NewChannelOut(cfg, lagoonTestRollupConfig)
	require.NoError(t, err)
	cb := NewChannelBuilderWithChannelOut(testlog.Logger(t, log.LevelError), cfg, lagoonTestRollupConfig, 0, co)
	var parent common.Hash
	for n := uint64(1); !cb.IsFull(); n++ {
		require.Less(t, n, uint64(10_000), "the channel never filled")
		block := newMiniL2BlockWithNumberParent(10, new(big.Int).SetUint64(n), parent)
		_, err := cb.AddBlock(mustSizedBlockFromGeth(block))
		if err != nil {
			require.ErrorIs(t, err, derive.ErrCompressorFull)
		}
		parent = block.Hash()
	}
	kept := uint64(cb.blocks.Len())
	require.True(t, cb.Holdable())
	require.ErrorIs(t, cb.AddProofAggregate(largeAggregate(kept), eth.BlockID{Number: kept}, 0), derive.ErrCompressorFull, "not held")
	require.NoError(t, cb.AddHeldProofAggregate(largeAggregate(kept), eth.BlockID{Number: kept}, 0))
	require.NoError(t, cb.AddHeldProofAggregate(largeAggregate(kept), eth.BlockID{Number: kept}, 0), "a second one too")
	require.False(t, cb.Holdable(), "an aggregate ends the channel")
	var want []string
	for n := uint64(1); n <= kept; n++ {
		want = append(want, blockItem(n))
	}
	require.Equal(t, append(want, "aggregate", "aggregate"), builderItems(t, cb, 1))
	require.ErrorIs(t, cb.AddHeldProofAggregate(largeAggregate(kept), eth.BlockID{Number: kept}, 0), ErrProofAggregateWritten, "its frames are output")
}

// pastDuration is an L1 head past the duration of a hold test's channels.
var pastDuration = eth.BlockID{Number: 10}

// holdRunBlocks is the run length of a hold test: runs end at blocks 3, 7, 11 and so on.
const holdRunBlocks = 4

// newHoldTestChannelManager returns a cleared channel manager under Lagoon whose span channels close
// two L1 blocks after they open, whose proof aggregation runs span holdRunBlocks blocks, and whose
// channels are held for 6s by a clock the test sets.
func newHoldTestChannelManager(t *testing.T, rollupCfg *rollup.Config) (*channelManager, *time.Time) {
	cfg := channelManagerTestConfig(1_000_000, derive.SpanBatchType)
	cfg.MaxChannelDuration = 2
	cfg.SeqWindowSize = 1_000
	m := NewChannelManager(testlog.Logger(t, log.LevelError), metrics.NoopMetrics, cfg, rollupCfg)
	m.Clear(eth.BlockID{})
	m.SetProofAggregateHold(6 * time.Second)
	m.SetRunBlocks(holdRunBlocks)
	now := time.Unix(1_000, 0)
	m.now = func() time.Time { return now }
	return m, &now
}

// addDependentBlocks adds blocks from..to (inclusive) to m, marking `dependent` as depending on a
// proof statement.
func addDependentBlocks(t *testing.T, m *channelManager, from, to uint64, dependent ...uint64) {
	addBlocks(t, m, from, to)
	for i := range m.blocks {
		if slices.Contains(dependent, m.blocks[i].NumberU64()) {
			m.blocks[i].dependent = true
		}
	}
}

// heldChannel fills a channel with blocks 1 to 3, block 2 depending on a statement, up to the run's
// boundary, and checks it is held, with no channel after it.
func heldChannel(t *testing.T, m *channelManager) *channelHold {
	addDependentBlocks(t, m, 1, 3, 2)
	_, err := m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.ErrorIs(t, err, io.EOF)
	require.NotNil(t, m.hold, "held")
	require.ErrorIs(t, m.hold.channel.FullErr(), ErrRunBoundary)
	require.Equal(t, uint64(3), m.hold.last.Number)
	require.Zero(t, m.hold.channel.TotalFrames())
	return m.hold
}

// A channel with a dependent block ends at the run's boundary, and one without goes on.
func TestChannelManagerEndsADependentChannelAtTheRunBoundary(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 5, 2)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary)
	require.Equal(t, uint64(3), m.currentChannel.LatestL2().Number)

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addBlocks(t, m, 1, 5)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	require.False(t, m.currentChannel.IsFull(), "no block depends on a statement")
}

// With fixed runs an aggregate keeps the channel open, and the channel then ends at the boundary.
// Without them each aggregate ends its channel.
func TestChannelManagerKeepsAChannelOpenForAnAggregate(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addBlocks(t, m, 1, 2)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	require.False(t, m.currentChannel.IsFull(), "kept open")
	addBlocks(t, m, 3, 4)
	require.NoError(t, m.processBlocks())
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary, "it holds an aggregate")
	require.Equal(t, uint64(3), m.currentChannel.LatestL2().Number)
	require.Equal(t, []string{blockItem(1), "aggregate", blockItem(2), blockItem(3)}, frameItemsOf(t, m, 1))

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	m.SetRunBlocks(0)
	m.SetProofAggregateHold(0)
	addBlocks(t, m, 1, 3)
	require.NoError(t, addAggregate(m, testAggregatePayload(2)))
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrProofAggregateWritten)
}

// frameItemsOf outputs the frames of the current, full channel and decodes them.
func frameItemsOf(t *testing.T, m *channelManager, firstBlock uint64) []string {
	require.NoError(t, m.currentChannel.OutputFrames())
	return frameItems(t, m.currentChannel.ChannelBuilder, firstBlock)
}

// The run length a channel uses is the one set when it opened.
func TestChannelManagerAppliesARunLengthFromTheNextChannel(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 2, 1)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	m.SetRunBlocks(2)
	addBlocks(t, m, 3, 3)
	require.NoError(t, m.processBlocks())
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary, "block 3 ends this channel's run, of 4")
	require.Equal(t, uint64(2), m.runBlocks)
	require.Equal(t, uint64(holdRunBlocks), m.currentChannel.runBlocks)
}

// A channel past its duration in a run waits for the boundary, for at most a run's time, and not
// past a safety timeout. One holding no dependent block goes at its duration.
func TestChannelManagerDefersTheDurationToTheRunBoundary(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 2, 2)
	_, err := m.getReadyChannel(pastDuration, pubInfo{})
	require.ErrorIs(t, err, io.EOF)
	require.False(t, m.currentChannel.IsFull(), "deferred to block 3")
	addBlocks(t, m, 3, 3)
	_, err = m.getReadyChannel(pastDuration, pubInfo{})
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary)
	require.NotNil(t, m.hold, "held at the boundary")

	m, now := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 2, 2)
	_, err = m.getReadyChannel(pastDuration, pubInfo{})
	require.ErrorIs(t, err, io.EOF)
	*now = now.Add(time.Duration(holdRunBlocks*lagoonTestRollupConfig.BlockTime) * time.Second)
	_, err = m.getReadyChannel(pastDuration, pubInfo{})
	require.NoError(t, err, "the sequencer stopped: it goes without its boundary")
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrMaxDurationReached)
	require.Nil(t, m.hold, "mid-run")

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 2, 2)
	// The blocks' L1 origin is 100, and the sequencing window 1,000 blocks.
	_, err = m.getReadyChannel(eth.BlockID{Number: 1_100}, pubInfo{})
	require.NoError(t, err)
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrSeqWindowClose, "a safety timeout does not wait")

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addBlocks(t, m, 1, 2)
	_, err = m.getReadyChannel(pastDuration, pubInfo{})
	require.NoError(t, err)
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrMaxDurationReached)
}

// A channel closed for its size mid-run goes at once, and the next one ends at the same boundary
// and waits for the aggregate of both.
func TestChannelManagerCarriesTheRunIntoTheNextChannel(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	rec := &holdMetrics{Metricer: metrics.NoopMetrics}
	m.metr = rec
	addDependentBlocks(t, m, 1, 1, 1)
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	require.NoError(t, m.processBlocks())
	m.currentChannel.setFullErr(derive.ErrCompressorFull)
	first := m.currentChannel
	require.False(t, m.startHold(eth.BlockID{}, pubInfo{}), "not at the boundary")
	require.NoError(t, m.outputFrames())
	require.Equal(t, 1, rec.early)

	addBlocks(t, m, 2, 3)
	_, err := m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err, "the first channel's frames")
	require.Same(t, first, m.channelQueue[0])
	m.channelQueue[0].frameCursor = m.channelQueue[0].frames.Len()
	_, err = m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.ErrorIs(t, err, io.EOF)
	require.NotSame(t, first, m.currentChannel)
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary)
	require.Equal(t, uint64(1), m.currentChannel.lastDependent)
	require.NotNil(t, m.hold, "held for block 1's aggregate")
}

// A channel whose input nears derivation's dependency scan byte cap closes at once, unheld.
func TestChannelManagerClosesNearTheDependencyScanCap(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	m.SetChannelOutFactory(func(cfg ChannelConfig, rollupCfg *rollup.Config) (derive.ChannelOut, error) {
		co, err := NewChannelOut(cfg, rollupCfg)
		return largeInputChannelOut{co}, err
	})
	addDependentBlocks(t, m, 1, 1, 1)
	_, err := m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err)
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrDependencyScanCapNear)
	require.Nil(t, m.hold)
}

// largeInputChannelOut reports its input as derivation's whole dependency scan byte cap.
type largeInputChannelOut struct{ derive.ChannelOut }

func (largeInputChannelOut) InputBytes() int { return derive.DependencyScanByteCap }

// holdMetrics records the proof aggregate metrics.
type holdMetrics struct {
	metrics.Metricer
	holds, releases, written []string
	early, changes           int
}

func (m *holdMetrics) RecordProofAggregateHold() { m.holds = append(m.holds, "hold") }
func (m *holdMetrics) RecordProofAggregateHoldReleased(reason string, held time.Duration) {
	m.releases = append(m.releases, fmt.Sprintf("%s %s", reason, held))
}
func (m *holdMetrics) RecordProofAggregateWritten(placement string) {
	m.written = append(m.written, placement)
}
func (m *holdMetrics) RecordProofAggregateChannelBeforeBoundary() { m.early++ }
func (m *holdMetrics) RecordProofAggregateRunBlocksChanged()      { m.changes++ }

// A hold, the aggregate written to it and its release are recorded.
func TestChannelManagerRecordsHoldMetrics(t *testing.T) {
	m, now := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	rec := &holdMetrics{Metricer: metrics.NoopMetrics}
	m.metr = rec
	heldChannel(t, m)
	*now = now.Add(2 * time.Second)
	require.NoError(t, addAggregate(m, largeAggregate(3)))
	_, err := m.getReadyChannel(pastDuration, pubInfo{})
	require.NoError(t, err)
	require.Equal(t, []string{"hold"}, rec.holds)
	require.Equal(t, []string{"held"}, rec.written)
	require.Equal(t, []string{"aggregate_written 2s"}, rec.releases)
	require.Zero(t, rec.early)
}

// A held channel is submitted with the aggregate as its last item once an aggregate through its
// last dependent block arrives; no channel is built after it meanwhile.
func TestChannelManagerHoldsAChannelForItsAggregate(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	h := heldChannel(t, m)
	addBlocks(t, m, 4, 5)
	_, err := m.getReadyChannel(pastDuration, pubInfo{})
	require.ErrorIs(t, err, io.EOF, "still held")
	require.Len(t, m.channelQueue, 1, "no channel after the held one")

	require.NoError(t, addAggregate(m, largeAggregate(1)))
	_, err = m.getReadyChannel(pastDuration, pubInfo{})
	require.ErrorIs(t, err, io.EOF, "an aggregate before the dependent block does not answer for it")
	require.NoError(t, addAggregate(m, largeAggregate(2)))
	ch, err := m.getReadyChannel(pastDuration, pubInfo{})
	require.NoError(t, err)
	require.Same(t, h.channel, ch)
	require.Nil(t, m.hold, "released")
	require.Equal(t, []string{blockItem(1), blockItem(2), blockItem(3), "aggregate", "aggregate"}, frameItems(t, ch.ChannelBuilder, 1))
	require.Equal(t, 2, m.pendingBlocks(), "blocks 4 and 5 go into the next channel")
}

// A hold ends without the aggregate when the deadline passes or a publish is forced.
func TestChannelManagerReleasesAHeldChannel(t *testing.T) {
	for name, release := range map[string]func(now *time.Time) pubInfo{
		"deadline": func(now *time.Time) pubInfo {
			*now = now.Add(6 * time.Second)
			return pubInfo{}
		},
		"forced": func(*time.Time) pubInfo { return pubInfo{forcePublish: true} },
	} {
		t.Run(name, func(t *testing.T) {
			m, now := newHoldTestChannelManager(t, lagoonTestRollupConfig)
			h := heldChannel(t, m)
			ch, err := m.getReadyChannel(pastDuration, release(now))
			require.NoError(t, err)
			require.Same(t, h.channel, ch)
			require.Nil(t, m.hold)
			require.Equal(t, []string{blockItem(1), blockItem(2), blockItem(3)}, frameItems(t, ch.ChannelBuilder, 1))
		})
	}
}

// An aggregate that missed its hold rides the next channel, which ends at the next boundary.
func TestChannelManagerPostsALateAggregateByTheNextBoundary(t *testing.T) {
	m, now := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	h := heldChannel(t, m)
	*now = now.Add(6 * time.Second)
	ch, err := m.getReadyChannel(pastDuration, pubInfo{})
	require.NoError(t, err)
	require.Same(t, h.channel, ch)
	ch.frameCursor = ch.frames.Len()

	require.NoError(t, addAggregate(m, largeAggregate(3)))
	addBlocks(t, m, 4, 7)
	_, err = m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err)
	require.Nil(t, m.hold, "nothing to wait for")
	require.ErrorIs(t, m.currentChannel.FullErr(), ErrRunBoundary)
	require.Equal(t, []string{"aggregate", blockItem(4), blockItem(5), blockItem(6), blockItem(7)}, frameItems(t, m.currentChannel.ChannelBuilder, 4))
}

// No channel is held for a forced publish, before proof aggregation, when holding is off, without
// a dependent block, or mid-run; an invalidated channel is no longer held.
func TestChannelManagerHoldsOnlyWhenItMay(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 3, 2)
	_, err := m.getReadyChannel(eth.BlockID{}, pubInfo{forcePublish: true})
	require.NoError(t, err)
	require.Nil(t, m.hold, "forced")

	m, _ = newHoldTestChannelManager(t, defaultTestRollupConfig)
	addDependentBlocks(t, m, 1, 3, 2)
	_, err = m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err)
	require.Nil(t, m.hold, "before proof aggregation")

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	m.SetProofAggregateHold(0)
	addDependentBlocks(t, m, 1, 3, 2)
	_, err = m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err)
	require.Nil(t, m.hold, "off")

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	addBlocks(t, m, 1, 3)
	require.NoError(t, addAggregate(m, testAggregatePayload(1)))
	_, err = m.getReadyChannel(eth.BlockID{}, pubInfo{})
	require.NoError(t, err)
	require.Nil(t, m.hold, "no dependent block")

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	h := heldChannel(t, m)
	m.handleChannelInvalidated(h.channel)
	require.Nil(t, m.hold, "invalidated")
	require.Zero(t, m.blockCursor)

	m, _ = newHoldTestChannelManager(t, lagoonTestRollupConfig)
	addDependentBlocks(t, m, 1, 3, 2)
	// The blocks' L1 origin is 100, and the sequencing window 1,000 blocks.
	_, err = m.getReadyChannel(eth.BlockID{Number: 1_100}, pubInfo{})
	require.NoError(t, err)
	require.Nil(t, m.hold, "near the sequencing window")
}

// The run length needs a hold, brotli and span batches, and a hold needs a run length.
func TestCheckRunBlocks(t *testing.T) {
	cfg := channelManagerTestConfig(1_000_000, derive.SpanBatchType)
	cfg.CompressorConfig.CompressionAlgo = derive.Brotli
	require.NoError(t, checkRunBlocks(12, time.Second, cfg))
	require.NoError(t, checkRunBlocks(0, 0, cfg))
	require.ErrorContains(t, checkRunBlocks(33, time.Second, cfg), "exceeds")
	require.ErrorContains(t, checkRunBlocks(0, time.Second, cfg), "run length")
	require.ErrorContains(t, checkRunBlocks(12, 0, cfg), "hold")

	zlib := cfg
	zlib.CompressorConfig.CompressionAlgo = derive.Zlib
	require.ErrorContains(t, checkRunBlocks(12, time.Second, zlib), "brotli")

	singular := cfg
	singular.BatchType = derive.SingularBatchType
	require.ErrorContains(t, checkRunBlocks(12, time.Second, singular), "span batches")
}

// An aggregate written keep-open that fills the channel ends it: the channel out has flushed its
// stream, so another write would restart compression mid-channel.
func TestKeepOpenAggregateFillingTheChannelEndsIt(t *testing.T) {
	cfg := channelManagerTestConfig(1_000, derive.SpanBatchType)
	m := NewChannelManager(testlog.Logger(t, log.LevelError), metrics.NoopMetrics, cfg, lagoonTestRollupConfig)
	m.Clear(eth.BlockID{})
	require.NoError(t, m.ensureChannelWithSpace(eth.BlockID{}))
	payload := testAggregatePayload(1)
	payload.Proof = make([]byte, 64_000)
	_, _ = rand.New(rand.NewSource(1)).Read(payload.Proof)
	require.NoError(t, m.currentChannel.AddProofAggregateKeepingOpen(payload, eth.BlockID{Number: 1}, 0))
	require.True(t, m.currentChannel.IsFull(), "the aggregate filled it")
}

// runBlocksSource serves a run length.
type runBlocksSource struct {
	ProofAggregateSource
	k uint64
}

func (s *runBlocksSource) RunBlocks(context.Context) (uint64, error) { return s.k, nil }

// The run length is read, refused if the batcher cannot post it, and reported when it changes.
func TestLoadRunBlocks(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	m.defaultCfg.CompressorConfig.CompressionAlgo = derive.Brotli
	m.SetRunBlocks(0)
	rec := &holdMetrics{Metricer: metrics.NoopMetrics}
	source := &runBlocksSource{k: 12}
	l := &BatchSubmitter{channelMgr: m}
	l.Log, l.Metr, l.ProofAggregates, l.RollupConfig = m.log, rec, source, lagoonTestRollupConfig
	l.Config.NetworkTimeout = time.Second

	require.NoError(t, l.loadRunBlocks(context.Background()))
	require.Equal(t, uint64(12), m.runBlocks)
	require.Zero(t, rec.changes, "the first read")

	source.k = 6
	require.NoError(t, l.loadRunBlocks(context.Background()))
	require.Equal(t, uint64(6), m.runBlocks)
	require.Equal(t, 1, rec.changes)

	source.k = 0
	require.ErrorContains(t, l.loadRunBlocks(context.Background()), "run length")
	require.Equal(t, uint64(6), m.runBlocks, "not applied")
}

// A block is dependent if a transaction of it declares a proof statement.
func TestSizedBlockDetectsDependentTransactions(t *testing.T) {
	payload := mustPayloadFromGeth(newMiniL2Block(0))
	require.False(t, ToSizedBlock(payload).dependent)

	tx := &optypes.AaTx{
		ChainID:              1,
		NonceKey:             new(big.Int),
		MaxPriorityFeePerGas: big.NewInt(1),
		MaxFeePerGas:         big.NewInt(1),
		GasLimit:             100_000,
		SenderAuth:           make([]byte, 65),
		AccountChanges: []optypes.AccountChange{{
			Type: optypes.AccountChangeDependencies,
			Dependencies: []optypes.Dependency{{
				Scheme:              optypes.ProofStatementScheme,
				DataHash:            common.Hash{1},
				VerificationKeyHash: common.Hash{2},
			}},
		}},
	}
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)
	payload.Transactions = append(payload.Transactions, raw)
	require.True(t, ToSizedBlock(payload).dependent)
}

// A held channel has output no frames: the sync loop must not take it for a submitted channel
// whose blocks never became safe, and start afresh.
func TestComputeSyncActionsKeepsAHeldChannel(t *testing.T) {
	m, _ := newHoldTestChannelManager(t, lagoonTestRollupConfig)
	heldChannel(t, m)
	status := eth.SyncStatus{
		HeadL1:      eth.L1BlockRef{Number: 20, Hash: common.Hash{20}},
		CurrentL1:   eth.L1BlockRef{Number: 20, Hash: common.Hash{20}},
		LocalSafeL2: eth.L2BlockRef{Number: 0, Hash: common.Hash{1}},
		UnsafeL2:    eth.L2BlockRef{Number: 3, Hash: m.tip},
	}
	actions, outOfSync := computeSyncActions(status, eth.L1BlockRef{Number: 19}, m.blocks, m.channelQueue, m.log)
	require.False(t, outOfSync)
	require.Nil(t, actions.clearState, "%v", actions)
}

// pendingAggregatesService serves admin_pendingProofAggregates and admin_proofAggregationRunBlocks.
type pendingAggregatesService struct {
	response json.RawMessage
}

func (s *pendingAggregatesService) PendingProofAggregates() (json.RawMessage, error) {
	return s.response, nil
}

func (s *pendingAggregatesService) ProofAggregationRunBlocks() hexutil.Uint64 { return 12 }

// TestRPCProofAggregateSourceDecodesPendingAggregates checks the decoding against op-alloy's
// PendingAggregate serde format: camelCase fields, through as a hex quantity, hashes and bytes
// as 0x-prefixed hex, and version as a number.
func TestRPCProofAggregateSourceDecodesPendingAggregates(t *testing.T) {
	server := rpc.NewServer()
	t.Cleanup(server.Stop)
	service := &pendingAggregatesService{response: json.RawMessage(`[{
		"version": 4,
		"aggregationVkeyHash": "` + optypes.LeanVmTreeClassKeyDigest.Hex() + `",
		"through": "0x2a",
		"statements": [
			{
				"vkeyHash": "0x0101010101010101010101010101010101010101010101010101010101010101",
				"publicValuesDigest": "0x0202020202020202020202020202020202020202020202020202020202020202"
			}
		],
		"proof": "0xdeadbeef"
	}, {
		"version": 4,
		"aggregationVkeyHash": "` + optypes.LeanVmTreeClassKeyDigest.Hex() + `",
		"through": "0x2b",
		"statements": [],
		"proof": "0xc28080"
	}]`)}
	require.NoError(t, server.RegisterName("admin", service))
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)

	source := NewRPCProofAggregateSource(client)
	k, err := source.RunBlocks(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(12), k)
	got, err := source.PendingProofAggregates(context.Background())
	require.NoError(t, err)
	require.Equal(t, []*optypes.ProofAggregatePayload{{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             42,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements: []optypes.ProofStatement{{
			VkeyHash:           common.BytesToHash(bytes.Repeat([]byte{1}, 32)),
			PublicValuesDigest: common.BytesToHash(bytes.Repeat([]byte{2}, 32)),
		}},
		Proof: []byte{0xde, 0xad, 0xbe, 0xef},
	}, {
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             43,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements:          []optypes.ProofStatement{},
		Proof:               []byte{0xc2, 0x80, 0x80},
	}}, got)
}

// addAggregate validates and queues payload, as the source loop does.
func addAggregate(m *channelManager, payload *optypes.ProofAggregatePayload) error {
	a, err := newPendingAggregate(payload)
	if err != nil {
		return err
	}
	m.addProofAggregate(a)
	return nil
}
