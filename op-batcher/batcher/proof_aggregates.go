package batcher

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

// ProofAggregateSource provides the proof aggregates the sequencer has verified and not yet seen
// derived, for the batcher to post.
type ProofAggregateSource interface {
	// PendingProofAggregates returns the aggregates to post.
	PendingProofAggregates(ctx context.Context) ([]*optypes.ProofAggregatePayload, error)
	// RunBlocks returns how many L2 blocks a proof aggregation run spans: a run ends at block n when
	// (n + 1) % K == 0. 0 means runs have no fixed end, and aggregates end the channel they join.
	RunBlocks(ctx context.Context) (uint64, error)
}

// maxRunBlocks is the longest run the sequencer accepts: at this length a block may still hold a
// full leaf's statements.
const maxRunBlocks = 32

// holdPollInterval is how often the batcher looks for aggregates while it holds a channel.
const holdPollInterval = time.Second

// checkRunBlocks refuses a run length the batcher cannot post with hold and cfg: with fixed runs an
// aggregate holds up to the class capacity, which only a channel holding its blocks carries, so a
// hold, span batches and a compression deduplicating its statements are required; without them no
// channel ends at a known block for a hold to wait at.
func checkRunBlocks(k uint64, hold time.Duration, cfg ChannelConfig) error {
	switch {
	case k > maxRunBlocks:
		return fmt.Errorf("run of %d blocks exceeds %d", k, maxRunBlocks)
	case k == 0 && hold > 0:
		return errors.New("holding channels for proof aggregates requires the sequencer to set a run length")
	case k == 0:
		return nil
	case hold == 0:
		return errors.New("fixed proof aggregation runs require a proof aggregate hold")
	case !cfg.CompressorConfig.CompressionAlgo.IsBrotli():
		return errors.New("fixed proof aggregation runs require brotli compression")
	case cfg.BatchType != derive.SpanBatchType:
		return errors.New("fixed proof aggregation runs require span batches")
	}
	return nil
}

// aggregateKey identifies a proof aggregate cheaply. Aggregates through the same block over the
// same statements are interchangeable: derivation takes the first one it reads.
type aggregateKey struct {
	through    uint64
	statements common.Hash
}

// pendingAggregate is a proof aggregate whose blocks are not yet safe.
type pendingAggregate struct {
	payload *optypes.ProofAggregatePayload
	key     aggregateKey
	// channel is the channel the aggregate was written to, or nil.
	channel *channel
}

// newPendingAggregate checks what can be checked of payload without verifying its proof, which
// also keeps an aggregate too large for any channel out of the queue, and keys it.
func newPendingAggregate(payload *optypes.ProofAggregatePayload) (*pendingAggregate, error) {
	if err := payload.CheckLimits(); err != nil {
		return nil, fmt.Errorf("invalid proof aggregate: %w", err)
	}
	return &pendingAggregate{
		payload: payload,
		key:     aggregateKey{through: payload.Through, statements: statementsHash(payload.Statements)},
	}, nil
}

// statementsHash is the keccak256 of each statement's VkeyHash || PublicValuesDigest, concatenated.
func statementsHash(statements []optypes.ProofStatement) common.Hash {
	buf := make([]byte, 0, 64*len(statements))
	for _, s := range statements {
		buf = append(buf, s.VkeyHash[:]...)
		buf = append(buf, s.PublicValuesDigest[:]...)
	}
	return crypto.Keccak256Hash(buf)
}

// addProofAggregate queues a proof aggregate. It is written into a channel after the block it
// answers through and before the next one, so it lands on L1 at or after the batches of every
// block it answers for, where derivation's dependency scan looks for it. An aggregate already
// queued, or answering only for safe blocks, is ignored, as is any aggregate while no blocks are
// queued: the source returns it again until its blocks are safe.
func (s *channelManager) addProofAggregate(a *pendingAggregate) {
	if slices.ContainsFunc(s.aggregates, func(b *pendingAggregate) bool { return b.key == a.key }) {
		return
	}
	first, ok := s.blocks.Peek()
	if !ok || a.payload.Through < first.NumberU64() {
		return
	}
	s.log.Info("Queued proof aggregate", "through", a.payload.Through, "statements", len(a.payload.Statements), "statements_hash", a.key.statements)
	s.aggregates = append(s.aggregates, a)
	slices.SortStableFunc(s.aggregates, func(a, b *pendingAggregate) int {
		return cmp.Compare(a.payload.Through, b.payload.Through)
	})
}

// writeAggregates writes the queued aggregates that answer only for blocks before the block at
// index next into the current channel, which held is set for when the channel is held for them.
// An aggregate through a block before proof aggregation activates is dropped: derivation then
// drops a channel holding one.
func (s *channelManager) writeAggregates(next int, held bool) error {
	if next == 0 {
		return nil
	}
	latest, ok := s.blocks.PeekN(next - 1)
	if !ok {
		return nil
	}
	first, _ := s.blocks.Peek()
	for i := 0; i < len(s.aggregates); i++ {
		a := s.aggregates[i]
		if a.channel != nil {
			continue
		}
		if a.payload.Through > latest.NumberU64() {
			break
		}
		if a.payload.Through < first.NumberU64() {
			// Its blocks are safe; pruneAggregates drops it.
			continue
		}
		through, ok := s.blocks.PeekN(int(a.payload.Through - first.NumberU64()))
		if !ok {
			continue
		}
		if !s.rollupCfg.IsProofAggregation(uint64(through.Timestamp)) {
			s.log.Warn("Dropping proof aggregate through a block before proof aggregation", "through", eth.ToBlockID(through), "statements_hash", a.key.statements)
			s.aggregates = slices.Delete(s.aggregates, i, i+1)
			i--
			continue
		}
		add, placement := s.currentChannel.AddProofAggregate, "ends_channel"
		switch {
		case held:
			add, placement = s.currentChannel.AddHeldProofAggregate, "held"
		case s.currentChannel.runBlocks > 0:
			// Kept open, the channel goes at the run's boundary, held for the aggregate of its own
			// blocks.
			add, placement = s.currentChannel.AddProofAggregateKeepingOpen, "keeps_open"
		}
		if err := add(a.payload, eth.ToBlockID(through), uint64(latest.Timestamp)); err != nil {
			return err
		}
		s.metr.RecordProofAggregateWritten(placement)
		a.channel = s.currentChannel
		s.log.Info("Added proof aggregate to channel", "id", s.currentChannel.ID(), "through", a.payload.Through, "statements_hash", a.key.statements)
	}
	return nil
}

// channelHold is the current channel, at the end of a run, held back for the proof aggregate of its
// blocks: written last, the aggregate shares the channel with the blocks it answers for. Channels
// after it are not submitted before it, so none is built meanwhile.
type channelHold struct {
	channel *channel
	// last is the channel's last block.
	last     eth.BlockID
	started  time.Time
	deadline time.Time
}

// startHold holds the current channel back for its blocks' proof aggregate if holding is on, the
// channel ends a run with dependent blocks, is full by the boundary, its size or its duration with
// no frames output, proof aggregation applies to its last block, and l1Head is not near its
// sequencing window. A forced publish is never held. Reports whether it holds.
func (s *channelManager) startHold(l1Head eth.BlockID, pi pubInfo) bool {
	c := s.currentChannel
	if s.holdFor == 0 || s.hold != nil || pi.forcePublish || !c.Holdable() || c.lastDependent == 0 ||
		!c.EndsOnRunBoundary() || c.NearSeqWindow(l1Head.Number) {
		return false
	}
	last := c.blocks[c.blocks.Len()-1]
	if !s.rollupCfg.IsProofAggregation(uint64(last.Timestamp)) {
		return false
	}
	s.hold = &channelHold{
		channel:  c,
		last:     eth.ToBlockID(last),
		started:  s.now(),
		deadline: s.now().Add(s.holdFor),
	}
	s.metr.RecordProofAggregateHold()
	s.log.Info("Holding channel for its proof aggregate", "id", c.ID(), "last", s.hold.last, "full_reason", c.FullErr(), "deadline", s.hold.deadline)
	return true
}

// updateHold writes the queued aggregates the held channel can take, then releases it, outputting
// its frames, once an aggregate through its last dependent block is written, the deadline passed,
// l1Head nears the sequencing window, the channel takes no more, or a publish is forced. Reports
// whether the channel is still held.
func (s *channelManager) updateHold(l1Head eth.BlockID, pi pubInfo) (bool, error) {
	h := s.hold
	if h == nil {
		return false, nil
	}
	if h.channel != s.currentChannel {
		// Every path replacing the current channel drops the hold; this one did not.
		s.log.Error("Dropping a hold on a channel that is no longer current", "id", h.channel.ID())
		s.hold = nil
		return false, nil
	}
	var reason string
	var chFullErr *ChannelFullError
	if err := s.writeAggregates(s.blockCursor, true); errors.As(err, &chFullErr) {
		reason = "channel takes no aggregate"
	} else if err != nil {
		s.log.Error("Failed to write a proof aggregate to the held channel", "id", h.channel.ID(), "err", err)
		reason = "write failed"
	}
	switch {
	case reason != "":
	case slices.ContainsFunc(s.aggregates, func(a *pendingAggregate) bool {
		return a.channel != nil && a.payload.Through >= h.channel.lastDependent
	}):
		reason = "aggregate written"
	case pi.forcePublish:
		reason = "forced publish"
	case !s.now().Before(h.deadline):
		reason = "deadline passed"
	case h.channel.NearSeqWindow(l1Head.Number):
		reason = "near the sequencing window"
	default:
		return true, nil
	}
	s.hold = nil
	s.log.Info("Released held channel", "id", h.channel.ID(), "last", h.last, "reason", reason)
	s.metr.RecordProofAggregateHoldReleased(strings.ReplaceAll(reason, " ", "_"), s.now().Sub(h.started))
	return false, s.outputFrames()
}

// maxAlignedChannelInputBytes closes a channel with fixed proof aggregation runs: an aggregate
// written after its blocks must stay within derivation's dependency scan byte cap, which counts
// from the start of the channel holding those blocks. Half the cap leaves room for the channels
// completed in the same L1 block before it.
const maxAlignedChannelInputBytes = derive.DependencyScanByteCap / 2

// unwriteAggregates requeues the aggregates written to invalidated channels.
func (s *channelManager) unwriteAggregates(channels []*channel) {
	for _, a := range s.aggregates {
		if slices.Contains(channels, a.channel) {
			a.channel = nil
		}
	}
}

// pruneAggregates drops the aggregates that answer only for blocks up to safe.
func (s *channelManager) pruneAggregates(safe uint64) {
	s.aggregates = slices.DeleteFunc(s.aggregates, func(a *pendingAggregate) bool {
		return a.payload.Through <= safe
	})
}

// proofAggregateLoop polls the source for proof aggregates and the run length every PollInterval,
// and for aggregates every holdPollInterval while a channel is held, waking the publishing loop to
// end the hold.
func (l *BatchSubmitter) proofAggregateLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(min(l.Config.PollInterval, holdPollInterval))
	defer ticker.Stop()
	var nextPoll time.Time
	for {
		select {
		case now := <-ticker.C:
			l.channelMgrMutex.Lock()
			holding := l.channelMgr.hold != nil
			l.channelMgrMutex.Unlock()
			if polled := !now.Before(nextPoll); polled {
				nextPoll = now.Add(l.Config.PollInterval)
				if err := l.loadRunBlocks(ctx); err != nil {
					l.Log.Error("Failed to read the proof aggregation run length", "err", err)
				}
			} else if !holding {
				continue
			}
			l.loadProofAggregates(ctx)
			if holding {
				select {
				case l.holdWake <- struct{}{}:
				default:
				}
			}
		case <-ctx.Done():
			l.Log.Info("proofAggregateLoop returning")
			return
		}
	}
}

// runBlocksStartTimeout bounds how long a starting batcher that holds channels waits for the
// sequencer to report its run length: without it the batcher cannot tell where runs end.
const runBlocksStartTimeout = 5 * time.Minute

// awaitRunBlocks reads the run length as the batcher starts. A batcher that holds no channels goes
// on if the sequencer is not up yet, as it would for any other aggregate poll; one that holds
// channels waits for it. Both refuse a run length they cannot post.
func (l *BatchSubmitter) awaitRunBlocks(ctx context.Context) error {
	deadline := time.Now().Add(runBlocksStartTimeout)
	for {
		k, err := l.readRunBlocks(ctx)
		if err == nil {
			return l.applyRunBlocks(k)
		}
		if l.channelMgr.holdFor == 0 {
			l.Log.Warn("Failed to read the proof aggregation run length", "err", err)
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		l.Log.Warn("Waiting for the proof aggregation run length", "err", err)
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// loadRunBlocks reads the run length from the source and refuses one this batcher cannot post.
func (l *BatchSubmitter) loadRunBlocks(ctx context.Context) error {
	k, err := l.readRunBlocks(ctx)
	if err != nil {
		return err
	}
	return l.applyRunBlocks(k)
}

func (l *BatchSubmitter) readRunBlocks(ctx context.Context) (uint64, error) {
	cCtx, cancel := context.WithTimeout(ctx, l.Config.NetworkTimeout)
	defer cancel()
	return l.ProofAggregates.RunBlocks(cCtx)
}

// applyRunBlocks takes the run length `k`. One that changes after the first read is reported once:
// batcher and sequencer are out of step until the next channel.
func (l *BatchSubmitter) applyRunBlocks(k uint64) error {
	l.channelMgrMutex.Lock()
	defer l.channelMgrMutex.Unlock()
	if l.runBlocksRead && k != l.lastRunBlocks {
		l.Log.Error("The proof aggregation run length changed", "was", l.lastRunBlocks, "now", k)
		l.Metr.RecordProofAggregateRunBlocksChanged()
	}
	first := !l.runBlocksRead
	l.runBlocksRead, l.lastRunBlocks = true, k
	if err := checkRunBlocks(k, l.channelMgr.holdFor, l.channelMgr.defaultCfg); err != nil {
		return err
	}
	if first && k > 0 {
		cfg := l.channelMgr.defaultCfg
		if cfg.MaxChannelDuration == 0 {
			l.Log.Warn("Without a channel duration a stopped sequencer leaves a dependent block's channel open until the sequencing window")
		}
		if run := time.Duration(k*l.RollupConfig.BlockTime) * time.Second; l.channelMgr.holdFor >= run {
			l.Log.Warn("Holding channels for longer than a run lets the batcher fall behind when aggregates stop", "hold", l.channelMgr.holdFor, "run", run)
		}
	}
	l.channelMgr.SetRunBlocks(k)
	return nil
}

// loadProofAggregates queues the proof aggregates the source has pending.
func (l *BatchSubmitter) loadProofAggregates(ctx context.Context) {
	cCtx, cancel := context.WithTimeout(ctx, l.Config.NetworkTimeout)
	defer cancel()
	payloads, err := l.ProofAggregates.PendingProofAggregates(cCtx)
	if err != nil {
		l.Log.Warn("Failed to fetch pending proof aggregates", "err", err)
		return
	}
	aggregates := make([]*pendingAggregate, 0, len(payloads))
	for _, p := range payloads {
		a, err := newPendingAggregate(p)
		if err != nil {
			l.Log.Warn("Dropping proof aggregate", "through", p.Through, "err", err)
			continue
		}
		aggregates = append(aggregates, a)
	}
	l.channelMgrMutex.Lock()
	defer l.channelMgrMutex.Unlock()
	for _, a := range aggregates {
		l.channelMgr.addProofAggregate(a)
	}
}

// rpcProofAggregateSource reads admin_pendingProofAggregates from the sequencer's execution
// client.
type rpcProofAggregateSource struct {
	client *rpc.Client
}

// NewRPCProofAggregateSource returns a source reading admin_pendingProofAggregates from client.
func NewRPCProofAggregateSource(client *rpc.Client) ProofAggregateSource {
	return &rpcProofAggregateSource{client: client}
}

// pendingAggregateJSON is op-alloy's PendingAggregate.
type pendingAggregateJSON struct {
	Version             uint8                    `json:"version"`
	AggregationVkeyHash common.Hash              `json:"aggregationVkeyHash"`
	Through             hexutil.Uint64           `json:"through"`
	Statements          []optypes.ProofStatement `json:"statements"`
	Proof               hexutil.Bytes            `json:"proof"`
}

func (s *rpcProofAggregateSource) PendingProofAggregates(ctx context.Context) ([]*optypes.ProofAggregatePayload, error) {
	var pending []pendingAggregateJSON
	if err := s.client.CallContext(ctx, &pending, "admin_pendingProofAggregates"); err != nil {
		return nil, err
	}
	out := make([]*optypes.ProofAggregatePayload, len(pending))
	for i, p := range pending {
		out[i] = &optypes.ProofAggregatePayload{
			Version:             p.Version,
			Through:             uint64(p.Through),
			AggregationVkeyHash: p.AggregationVkeyHash,
			Statements:          p.Statements,
			Proof:               p.Proof,
		}
	}
	return out, nil
}

func (s *rpcProofAggregateSource) RunBlocks(ctx context.Context) (uint64, error) {
	var k hexutil.Uint64
	err := s.client.CallContext(ctx, &k, "admin_proofAggregationRunBlocks")
	return uint64(k), err
}
