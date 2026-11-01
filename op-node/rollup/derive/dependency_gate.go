package derive

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
)

// ErrWaitingForL1 is returned by a stage that holds a batch until L1 data past the pipeline's
// origin is available. Unlike io.EOF, it does not mean the origin's data was consumed, so the
// pipeline idles without advancing its origin.
var ErrWaitingForL1 = errors.New("waiting for later L1 data")

// heldBatch is a batch the gate holds while its block is undecided.
type heldBatch struct {
	batch *SingularBatch
	// inclusion is the L1 origin the batch was read at.
	inclusion  eth.L1BlockRef
	concluding bool
}

// DependencyGate holds a batch whose transactions declare EIP-8288 dependencies until the
// DependencyScanner finds the aggregate responsible for its block, as kona-derive's DependencyGate
// does. A block is invalid unless that aggregate proves every dependency its transactions declare,
// and the gate then passes its batch on with no transactions: the block holds only its deposits.
//
// Such a batch is the last of its channel: the gate flushes the channel, as Holocene does after
// replacing an invalid block, since the batches after it were built on the block as the sequencer
// made it. Every other batch passes through unchanged.
type DependencyGate struct {
	log     log.Logger
	cfg     *rollup.Config
	prev    SingularBatchProvider
	scanner *DependencyScanner
	l2      SystemConfigL2Fetcher

	held *heldBatch
	// decidedAt is the latest L1 block a decision since the last reset needed. Blocks derived
	// after a decided block are derived from at least that L1 block.
	decidedAt *eth.L1BlockRef
}

var (
	_ SingularBatchProvider = (*DependencyGate)(nil)
	_ DependencyDecider     = (*DependencyGate)(nil)
)

// DependencyDecider is a batch provider that decides blocks' dependencies from L1 data past the
// pipeline's origin.
type DependencyDecider interface {
	// DecidedAt returns the latest L1 block a decision since the last reset needed, if any.
	DecidedAt() (eth.L1BlockRef, bool)
}

// NewDependencyGate creates a gate over prev.
func NewDependencyGate(log log.Logger, cfg *rollup.Config, prev SingularBatchProvider, scanner *DependencyScanner, l2 SystemConfigL2Fetcher) *DependencyGate {
	return &DependencyGate{log: log, cfg: cfg, prev: prev, scanner: scanner, l2: l2}
}

func (g *DependencyGate) Origin() eth.L1BlockRef {
	return g.prev.Origin()
}

// DecidedAt returns the latest L1 block a dependency decision since the last reset needed.
func (g *DependencyGate) DecidedAt() (eth.L1BlockRef, bool) {
	if g.decidedAt == nil {
		return eth.L1BlockRef{}, false
	}
	return *g.decidedAt, true
}

// dependentTx is a transaction of a batch that declares dependencies.
type dependentTx struct {
	raw          []byte
	dependencies []optypes.Dependency
}

// dependentTxs returns the transactions of batch that declare dependencies, read as kona-derive
// reads them.
func dependentTxs(batch *SingularBatch) []dependentTx {
	var out []dependentTx
	for _, raw := range batch.Transactions {
		if deps, ok := optypes.DeclaredDependencies(raw); ok {
			out = append(out, dependentTx{raw: raw, dependencies: deps})
		}
	}
	return out
}

// decide returns whether the block of the batch is valid: every dependency its transactions declare
// is proven by the responsible aggregate, or proof aggregation is not active.
func (g *DependencyGate) decide(ctx context.Context, parent eth.L2BlockRef, held *heldBatch) (bool, error) {
	dependent := dependentTxs(held.batch)
	if len(dependent) == 0 || !g.cfg.IsProofAggregation(held.batch.Timestamp) {
		return true, nil
	}
	sysCfg, err := g.l2.SystemConfigByL2Hash(ctx, parent.Hash)
	if err != nil {
		return false, NewTemporaryError(fmt.Errorf("failed to fetch the system config of %s: %w", parent, err))
	}
	block := parent.Number + 1
	proven, err := g.scanner.Responsible(ctx, block, held.inclusion, sysCfg)
	if err != nil {
		return false, err
	}
	if at, ok := g.scanner.DecidedAt(); ok && (g.decidedAt == nil || at.Number > g.decidedAt.Number) {
		g.decidedAt = &at
	}
	for _, d := range dependent {
		for _, dep := range d.dependencies {
			statement, ok := dep.Statement()
			if _, isProven := proven[statement]; !ok || !isProven {
				g.log.Warn("Replacing a block with an unproven dependency with its deposits",
					"tx", crypto.Keccak256Hash(d.raw), "block", block)
				return false, nil
			}
		}
	}
	return true, nil
}

func (g *DependencyGate) NextBatch(ctx context.Context, parent eth.L2BlockRef) (*SingularBatch, bool, error) {
	held := g.held
	g.held = nil
	if held == nil {
		batch, concluding, err := g.prev.NextBatch(ctx, parent)
		if err != nil {
			return nil, false, err
		}
		held = &heldBatch{batch: batch, inclusion: g.prev.Origin(), concluding: concluding}
	}
	valid, err := g.decide(ctx, parent, held)
	if err != nil {
		g.held = held
		if errors.Is(err, io.EOF) && !errors.Is(err, ErrTemporary) {
			// The scan needs L1 blocks past the head: hold the batch, without letting the pipeline
			// advance its own origin.
			return nil, false, fmt.Errorf("dependency scan for block %d: %w", parent.Number+1, ErrWaitingForL1)
		}
		return nil, false, err
	}
	if valid {
		return held.batch, held.concluding, nil
	}
	batch := *held.batch
	batch.Transactions = nil
	g.prev.FlushChannel()
	return &batch, true, nil
}

func (g *DependencyGate) Reset(ctx context.Context, base eth.L1BlockRef, sysCfg eth.SystemConfig) error {
	g.held = nil
	g.decidedAt = nil
	g.scanner.Clear()
	return io.EOF
}

func (g *DependencyGate) FlushChannel() {
	g.held = nil
	g.prev.FlushChannel()
}
