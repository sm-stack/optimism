package derive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum-optimism/optimism/op-core/forks"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
)

const (
	// DependencyScanByteCap bounds the transaction and aggregate payload bytes a scan decodes after
	// the batch's L1 block before it gives up, which bounds the work a block can demand of the proof
	// programs.
	DependencyScanByteCap = 16 * 1024 * 1024
)

// ProofAggregateVerifier checks that root, a root of the leanVM tree class
// LeanVmTreeClassKeyDigest, and seal prove exactly statements, as op-alloy's
// ProofAggregateVerifier does.
type ProofAggregateVerifier func(statements []optypes.ProofStatement, root, seal []byte) error

// verifyAggregate checks the limits, then verifies the aggregate's tree root and seal with verify,
// as op-alloy's ProofAggregatePayload::verify does: the statements are proven iff it returns nil.
// With a nil verify, no aggregate proves anything.
func verifyAggregate(verify ProofAggregateVerifier, p *optypes.ProofAggregatePayload) error {
	if err := p.CheckLimits(); err != nil {
		return err
	}
	proof, err := optypes.DecodeLeanVmTreeProof(p.Proof)
	if err != nil {
		return err
	}
	if verify == nil {
		return errors.New("no proof aggregate verifier")
	}
	return verify(p.Statements, proof.Root, proof.Seal)
}

// scannedAggregate is a proof aggregate the scan decoded.
type scannedAggregate struct {
	// origin is the L1 block whose data completed the aggregate's channel.
	origin eth.L1BlockRef
	// bytesBefore is the bytes decoded before it since the pass started.
	bytesBefore uint64
	// encoded is the aggregate's encoding: the bytes the batcher posted.
	encoded []byte
	// hash is the hash of encoded, once the aggregate is verified.
	hash    *common.Hash
	payload *optypes.ProofAggregatePayload
}

type originBytes struct {
	number uint64
	bytes  uint64
}

// DependencyScanner finds the proof aggregate responsible for a block's EIP-8288 dependencies,
// as kona-derive's DependencyScanner does.
//
// For a block B whose batch was read at L1 origin I, the scan decodes, with the pipeline's own
// frame and channel rules and without validating any batch, the batcher data of the channels
// completed in L1 blocks I to I + window (reading from channel_timeout blocks before I so that
// those channels assemble). The responsible aggregate is the first proof aggregate batch among
// them whose through reaches B, found within byteCap decoded bytes (transactions and aggregate
// payloads). The answer depends only on I and L1 data, never on the pipeline's own state.
//
// The scanner reads L1 on its own stages, forward only, and keeps what it decoded, so consecutive
// blocks share one pass.
type DependencyScanner struct {
	log     log.Logger
	spec    *rollup.ChainSpec
	verify  ProofAggregateVerifier
	window  uint64
	byteCap uint64

	source scanSource

	// anchor is the L1 block the current pass serves from, if hasAnchor.
	anchor    uint64
	hasAnchor bool
	// aggregates decoded so far in this pass, in scan order.
	aggregates []scannedAggregate
	// originBytes holds, for each L1 origin seen, the bytes decoded before its first batch.
	originBytes []originBytes
	// bytes is the transaction and aggregate payload bytes decoded in this pass.
	bytes uint64
	// scannedThrough is the highest L1 block whose batcher data the pass has fully decoded.
	scannedThrough *eth.L1BlockRef
	// decidedAt is the last L1 block the latest decision needed.
	decidedAt *eth.L1BlockRef
	// verified caches verification results by aggregate hash.
	verified map[common.Hash]bool
}

// scanSource is the batch decoder a scan runs over L1.
type scanSource interface {
	// ResetTo restarts decoding at L1 block number, with sysCfg.
	ResetTo(ctx context.Context, number uint64, sysCfg eth.SystemConfig) error
	// Origin returns the L1 block being decoded.
	Origin() eth.L1BlockRef
	// NextBatch returns the next batch, io.EOF when the origin's batches are exhausted, or
	// NotEnoughData when it must be called again.
	NextBatch(ctx context.Context) (Batch, error)
	// AdvanceL1Block moves to the next L1 block, or returns io.EOF when it is not available yet.
	AdvanceL1Block(ctx context.Context) error
}

// scanStages decodes batches with the pipeline's own stages, on a traversal of its own.
type scanStages struct {
	cfg       *rollup.Config
	l1        L1Fetcher
	traversal *L1Traversal
	reader    *ChannelInReader
	stages    []ResettableStage
}

func newScanStages(log log.Logger, cfg *rollup.Config, l1 L1Fetcher, l1Blobs L1BlobsFetcher) *scanStages {
	metrics := scannerMetrics{}
	traversal := NewL1Traversal(log, cfg, l1)
	retrieval := NewL1Retrieval(log, NewDataSourceFactory(log, withoutAltDA(cfg), l1, l1Blobs, nil), traversal)
	frames := NewFrameQueue(log, cfg, retrieval)
	channels := NewChannelMux(log, rollup.NewChainSpec(cfg), frames, metrics)
	reader := NewChannelInReader(cfg, log, channels, metrics)
	reader.proofAggregates = true
	return &scanStages{
		cfg:       cfg,
		l1:        l1,
		traversal: traversal,
		reader:    reader,
		stages:    []ResettableStage{traversal, retrieval, frames, channels, reader},
	}
}

// withoutAltDA returns cfg for a data source that reads calldata and blobs only. The scanner does
// not resolve alt-DA commitments, as kona does not: the pipeline's alt-DA fetcher tracks challenge
// state per L1 origin, which a scan reading ahead would corrupt.
func withoutAltDA(cfg *rollup.Config) *rollup.Config {
	if !cfg.AltDAEnabled() {
		return cfg
	}
	c := *cfg
	c.AltDAConfig = nil
	return &c
}

func (s *scanStages) ResetTo(ctx context.Context, number uint64, sysCfg eth.SystemConfig) error {
	base, err := s.l1.L1BlockRefByNumber(ctx, number)
	if err != nil {
		return NewTemporaryError(fmt.Errorf("failed to fetch L1 block %d to start a dependency scan: %w", number, err))
	}
	for _, stage := range s.stages {
		if err := stage.Reset(ctx, base, sysCfg); err != nil && !errors.Is(err, io.EOF) {
			return NewTemporaryError(fmt.Errorf("failed to reset the dependency scan at %s: %w", base, err))
		}
	}
	return nil
}

func (s *scanStages) Origin() eth.L1BlockRef {
	return s.traversal.Origin()
}

func (s *scanStages) NextBatch(ctx context.Context) (Batch, error) {
	return s.reader.NextBatch(ctx)
}

// AdvanceL1Block moves to the next L1 block and, at a fork activation, transforms the stages as the
// pipeline transforms its own.
func (s *scanStages) AdvanceL1Block(ctx context.Context) error {
	prev := s.traversal.Origin()
	if err := s.traversal.AdvanceL1Block(ctx); err != nil {
		return err
	}
	if fork := s.cfg.IsActivationBlock(prev.Time, s.traversal.Origin().Time); fork != forks.None {
		for _, stage := range s.stages {
			if tf, ok := stage.(ForkTransformer); ok {
				tf.Transform(fork)
			}
		}
	}
	return nil
}

// NewDependencyScanner creates a scanner reading L1 through its own stages over l1 and l1Blobs,
// verifying aggregates with verify. With a nil verify, a block whose responsible aggregate is
// within the limits stops derivation with a critical error.
func NewDependencyScanner(log log.Logger, cfg *rollup.Config, l1 L1Fetcher, l1Blobs L1BlobsFetcher, verify ProofAggregateVerifier) *DependencyScanner {
	log = log.New("stage", "dependency-scanner")
	return newDependencyScanner(log, cfg, newScanStages(log, cfg, l1, l1Blobs), verify, rollup.DependencyScanWindow, DependencyScanByteCap)
}

func newDependencyScanner(log log.Logger, cfg *rollup.Config, source scanSource, verify ProofAggregateVerifier, window, byteCap uint64) *DependencyScanner {
	return &DependencyScanner{
		log:      log,
		spec:     rollup.NewChainSpec(cfg),
		verify:   verify,
		window:   window,
		byteCap:  byteCap,
		source:   source,
		verified: make(map[common.Hash]bool),
	}
}

// Clear drops the current pass, as after a pipeline reset.
func (s *DependencyScanner) Clear() {
	s.hasAnchor = false
	s.aggregates = nil
	s.originBytes = nil
	s.bytes = 0
	s.scannedThrough = nil
	s.decidedAt = nil
}

// DecidedAt returns the last L1 block the latest decision needed: the block holding the
// responsible aggregate, or where the window or the byte cap ended.
func (s *DependencyScanner) DecidedAt() (eth.L1BlockRef, bool) {
	if s.decidedAt == nil {
		return eth.L1BlockRef{}, false
	}
	return *s.decidedAt, true
}

// Responsible finds the aggregate responsible for block, whose batch was read at L1 origin
// inclusion, verifies it, and returns the statements it proves: none if no aggregate answers for
// the block within the window or the byte cap, or the one that does carries an invalid proof.
// sysCfg supplies the batcher address the scan starts with.
//
// It returns io.EOF when the L1 data the scan needs is not available yet; the block is then
// undecided.
func (s *DependencyScanner) Responsible(ctx context.Context, block uint64, inclusion eth.L1BlockRef, sysCfg eth.SystemConfig) (map[optypes.ProofStatement]struct{}, error) {
	if !s.hasAnchor || inclusion.Number < s.anchor {
		if err := s.start(ctx, inclusion, sysCfg); err != nil {
			return nil, err
		}
	} else {
		s.prune(inclusion.Number)
		s.anchor = inclusion.Number
	}
	windowEnd := inclusion.Number + s.window
	for {
		startBytes := s.bytesAt(inclusion.Number)
		for i := range s.aggregates {
			found := &s.aggregates[i]
			if found.origin.Number < inclusion.Number || found.origin.Number > windowEnd ||
				found.payload.Through < block {
				continue
			}
			origin := found.origin
			s.decidedAt = &origin
			if found.bytesBefore-startBytes >= s.byteCap {
				return nil, nil
			}
			return s.proven(found)
		}
		if s.bytes-startBytes >= s.byteCap {
			origin := s.source.Origin()
			s.decidedAt = &origin
			return nil, nil
		}
		if s.scannedThrough != nil && s.scannedThrough.Number >= windowEnd {
			through := *s.scannedThrough
			s.decidedAt = &through
			return nil, nil
		}
		if err := s.step(ctx, windowEnd); err != nil {
			return nil, err
		}
	}
}

// start restarts the pass channel_timeout L1 blocks before inclusion.
func (s *DependencyScanner) start(ctx context.Context, inclusion eth.L1BlockRef, sysCfg eth.SystemConfig) error {
	s.Clear()
	start := inclusion.Number - min(inclusion.Number, s.spec.ChannelTimeout(inclusion.Time))
	if err := s.source.ResetTo(ctx, start, sysCfg); err != nil {
		return err
	}
	s.anchor, s.hasAnchor = inclusion.Number, true
	return nil
}

// prune forgets what a later block can never need: blocks are decided in order, so their inclusion
// blocks never decrease within a pass.
func (s *DependencyScanner) prune(inclusion uint64) {
	// Copy what is kept, so that the dropped aggregates' proofs can be collected.
	first := 0
	for first < len(s.aggregates) && s.aggregates[first].origin.Number < inclusion {
		first++
	}
	s.aggregates = slices.Clone(s.aggregates[first:])
	first = len(s.originBytes)
	for i, o := range s.originBytes {
		if o.number >= inclusion {
			first = i
			break
		}
	}
	s.originBytes = slices.Clone(s.originBytes[first:])
	kept := make(map[common.Hash]bool, len(s.verified))
	for _, a := range s.aggregates {
		if a.hash == nil {
			continue
		}
		if valid, ok := s.verified[*a.hash]; ok {
			kept[*a.hash] = valid
		}
	}
	s.verified = kept
}

// bytesAt returns the bytes decoded before the first batch at or after L1 block origin.
func (s *DependencyScanner) bytesAt(origin uint64) uint64 {
	for _, o := range s.originBytes {
		if o.number >= origin {
			return o.bytes
		}
	}
	return s.bytes
}

// step decodes the next batch, or moves to the next L1 block when the current one is done and
// is not the last of the window: the decision needs no L1 block past that one, which may not exist.
func (s *DependencyScanner) step(ctx context.Context, windowEnd uint64) error {
	origin := s.source.Origin()
	batch, err := s.source.NextBatch(ctx)
	switch {
	case err == nil:
		s.record(origin, batch)
		return nil
	case errors.Is(err, io.EOF):
		s.scannedThrough = &origin
		if origin.Number >= windowEnd {
			return nil
		}
		return s.source.AdvanceL1Block(ctx)
	case errors.Is(err, NotEnoughData):
		// The channel reader dropped a malformed channel and asks to be called again.
		return nil
	default:
		return err
	}
}

func (s *DependencyScanner) record(origin eth.L1BlockRef, batch Batch) {
	if n := len(s.originBytes); n == 0 || s.originBytes[n-1].number < origin.Number {
		s.originBytes = append(s.originBytes, originBytes{number: origin.Number, bytes: s.bytes})
	}
	if aggregate, ok := asProofAggregateBatch(batch); ok {
		// The payload decoded exactly, so its encoding is the bytes the batcher posted. Encoding a
		// decoded payload cannot fail.
		encoded, _ := rlp.EncodeToBytes(&aggregate.Payload)
		s.aggregates = append(s.aggregates, scannedAggregate{
			origin:      origin,
			bytesBefore: s.bytes,
			encoded:     encoded,
			payload:     &aggregate.Payload,
		})
		s.bytes += uint64(len(encoded))
		return
	}
	var txs [][]byte
	if single, ok := batch.AsSingularBatch(); ok {
		txs = txBytes(single.Transactions)
	} else if span, ok := batch.AsSpanBatch(); ok {
		for _, e := range span.Batches {
			txs = append(txs, txBytes(e.Transactions)...)
		}
	}
	for _, tx := range txs {
		s.bytes += uint64(len(tx))
	}
}

func txBytes[T ~[]byte](txs []T) [][]byte {
	out := make([][]byte, len(txs))
	for i, tx := range txs {
		out[i] = tx
	}
	return out
}

// proven verifies the aggregate, once per hash, and returns the statements it proves. Only an
// aggregate within the limits is hashed, as in kona.
func (s *DependencyScanner) proven(a *scannedAggregate) (map[optypes.ProofStatement]struct{}, error) {
	if a.payload.CheckLimits() != nil {
		return nil, nil
	}
	if s.verify == nil {
		// Proving nothing would replace a block an aggregate may prove, and derive another chain
		// than a node that verifies it: stop instead.
		return nil, NewCriticalError(fmt.Errorf("cannot verify the proof aggregate through block %d: the derivation pipeline was built without a proof aggregate verifier", a.payload.Through))
	}
	if a.hash == nil {
		hash := crypto.Keccak256Hash(a.encoded)
		a.hash = &hash
	}
	valid, ok := s.verified[*a.hash]
	if !ok {
		if err := verifyAggregate(s.verify, a.payload); err != nil {
			s.log.Warn("Proof aggregate does not verify", "through", a.payload.Through, "hash", *a.hash, "err", err)
		} else {
			valid = true
		}
		s.verified[*a.hash] = valid
	}
	if !valid {
		return nil, nil
	}
	proven := make(map[optypes.ProofStatement]struct{}, len(a.payload.Statements))
	for _, statement := range a.payload.Statements {
		proven[statement] = struct{}{}
	}
	return proven, nil
}

// scannerMetrics drops the metrics of the scanner's stages, which would otherwise count the
// pipeline's L1 data twice.
type scannerMetrics struct{}

func (scannerMetrics) RecordL1Ref(string, eth.L1BlockRef) {}
func (scannerMetrics) RecordL2Ref(string, eth.L2BlockRef) {}
func (scannerMetrics) RecordChannelInputBytes(int)        {}
func (scannerMetrics) RecordHeadChannelOpened()           {}
func (scannerMetrics) RecordChannelTimedOut()             {}
func (scannerMetrics) RecordFrame()                       {}
func (scannerMetrics) RecordDerivedBatches(string)        {}
func (scannerMetrics) SetDerivationIdle(bool)             {}
func (scannerMetrics) RecordPipelineReset()               {}
