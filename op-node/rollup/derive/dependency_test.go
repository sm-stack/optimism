package derive

import (
	"context"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

// The tests mirror kona-derive's dependency scanner and gate tests.

// fakeScanSource hands out batches per L1 block, by block number; L1 ends after the last one.
type fakeScanSource struct {
	blocks  [][]Batch
	current uint64
	next    int
	resets  []uint64
}

func (f *fakeScanSource) ResetTo(_ context.Context, number uint64, _ eth.SystemConfig) error {
	f.resets = append(f.resets, number)
	f.current, f.next = number, 0
	return nil
}

func (f *fakeScanSource) Origin() eth.L1BlockRef {
	return testL1(f.current)
}

func (f *fakeScanSource) NextBatch(context.Context) (Batch, error) {
	batches := f.blocks[f.current]
	if f.next >= len(batches) {
		return nil, io.EOF
	}
	f.next++
	return batches[f.next-1], nil
}

func (f *fakeScanSource) AdvanceL1Block(context.Context) error {
	if int(f.current)+1 >= len(f.blocks) {
		return io.EOF
	}
	f.current, f.next = f.current+1, 0
	return nil
}

func testL1(number uint64) eth.L1BlockRef {
	return eth.L1BlockRef{Number: number, Time: number * 12}
}

// testVerifier accepts exactly the root "ok".
func testVerifier(_ []optypes.ProofStatement, root, _ []byte) error {
	if string(root) != "ok" {
		return errors.New("bad proof")
	}
	return nil
}

func testStatement(b byte) optypes.ProofStatement {
	var h common.Hash
	for i := range h {
		h[i] = b
	}
	return optypes.ProofStatement{VkeyHash: h, PublicValuesDigest: h}
}

// testAggregate is a proof aggregate batch through block through, whose tree root is root.
func testAggregate(through uint64, statements []optypes.ProofStatement, root string) Batch {
	proof, err := rlp.EncodeToBytes(&optypes.LeanVmTreeProof{Root: []byte(root)})
	if err != nil {
		panic(err)
	}
	return &ProofAggregateBatch{Payload: optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             through,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements:          statements,
		Proof:               proof,
	}}
}

// testAaTx is an EIP-8430 transaction declaring statements as dependencies (no dependency entry
// for none), made distinct by nonce.
func testAaTx(t *testing.T, nonce uint64, statements []optypes.ProofStatement) hexutil.Bytes {
	tx := &optypes.AaTx{
		ChainID:              10,
		NonceKey:             new(big.Int),
		NonceSequence:        nonce,
		MaxPriorityFeePerGas: big.NewInt(1),
		MaxFeePerGas:         big.NewInt(10),
		GasLimit:             100_000,
		Calls:                [][]optypes.AaCall{{{To: common.Address{0x42}, Value: new(big.Int)}}},
		SenderAuth:           make([]byte, 65),
	}
	if len(statements) > 0 {
		deps := make([]optypes.Dependency, len(statements))
		for i, s := range statements {
			deps[i] = optypes.Dependency{Scheme: optypes.ProofStatementScheme, DataHash: s.PublicValuesDigest, VerificationKeyHash: s.VkeyHash}
		}
		tx.AccountChanges = []optypes.AccountChange{{Type: optypes.AccountChangeDependencies, Dependencies: deps}}
	}
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)
	return raw
}

// testBatch is a singular batch for L2 block, with 2 second blocks from genesis 0.
func testBatch(block uint64, txs ...hexutil.Bytes) Batch {
	return &SingularBatch{Timestamp: block * 2, Transactions: txs}
}

func testScannerConfig() *rollup.Config {
	lagoon := uint64(0)
	return &rollup.Config{BlockTime: 2, ChannelTimeoutBedrock: 2, LagoonTime: &lagoon}
}

// testScanner scans blocks with a channel timeout of 2, a window of 3 and byteCap.
func testScanner(t *testing.T, blocks [][]Batch, byteCap uint64) (*DependencyScanner, *fakeScanSource) {
	source := &fakeScanSource{blocks: blocks}
	return newDependencyScanner(testlog.Logger(t, log.LevelDebug), testScannerConfig(), source, testVerifier, 3, byteCap), source
}

func provenSet(statements ...optypes.ProofStatement) map[optypes.ProofStatement]struct{} {
	out := make(map[optypes.ProofStatement]struct{})
	for _, s := range statements {
		out[s] = struct{}{}
	}
	return out
}

func TestScannerFindsTheFirstAggregateReachingTheBlock(t *testing.T) {
	scanner, source := testScanner(t, [][]Batch{
		{},
		{},
		{},
		{testBatch(5)},
		{testBatch(6), testAggregate(4, []optypes.ProofStatement{testStatement(9)}, "ok")},
		{testBatch(7), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{testBatch(8), testAggregate(8, []optypes.ProofStatement{testStatement(2)}, "ok")},
		{},
	}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(3), eth.SystemConfig{})
	require.NoError(t, err)
	require.Equal(t, provenSet(testStatement(1)), proven, "the aggregate through 4 does not reach block 5; the one through 6 does")
	require.Equal(t, []uint64{1}, source.resets, "the pass starts a channel timeout early")
}

func TestScannerCountsAnAggregateInTheBlockItself(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{
		{},
		{testBatch(5), testAggregate(5, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(1), eth.SystemConfig{})
	require.NoError(t, err)
	require.Equal(t, provenSet(testStatement(1)), proven)
}

func TestScannerTrustsNoLaterAggregateAfterAnInvalidProof(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(5)},
		{testBatch(6), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "bad")},
		{testBatch(7), testAggregate(7, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven)
}

func TestScannerIgnoresDataBeforeTheInclusionBlock(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(9), testAggregate(9, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{testBatch(5)},
		{},
		{},
		{},
		{},
	}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(1), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven)
}

func TestScannerCountsAggregatePayloadBytes(t *testing.T) {
	big := testAggregate(4, []optypes.ProofStatement{testStatement(9)}, string(make([]byte, 200)))
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(5), big},
		{testBatch(6), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	}, 150)
	proven, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven, "the aggregate through 4 used up the byte cap")
}

func TestScannerProvesNothingWhenTheWindowCloses(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(5)},
		{},
		{},
		{},
		{testBatch(6), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "ok")},
	}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven, "the aggregate lands at L1 block 4, past the window of 3")
	decidedAt, ok := scanner.DecidedAt()
	require.True(t, ok)
	require.Equal(t, testL1(3), decidedAt)
}

func TestScannerDecidesWithL1EndingAtTheWindowEnd(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{{testBatch(5)}, {}, {}, {}}, ^uint64(0))
	proven, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven)
	decidedAt, ok := scanner.DecidedAt()
	require.True(t, ok)
	require.Equal(t, testL1(3), decidedAt)
}

func TestScannerGoesOnPastAWindowEndForALaterBlock(t *testing.T) {
	statement := testStatement(1)
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(5)},
		{},
		{},
		{},
		{testBatch(6), testAggregate(6, []optypes.ProofStatement{statement}, "ok")},
	}, ^uint64(0))
	ctx := context.Background()
	proven, err := scanner.Responsible(ctx, 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven)
	proven, err = scanner.Responsible(ctx, 6, testL1(1), eth.SystemConfig{})
	require.NoError(t, err)
	require.Contains(t, proven, statement, "the aggregate at L1 block 4 is within the later window")
}

func TestScannerLeavesTheBlockUndecidedWhileTheWindowIsNotOnL1(t *testing.T) {
	scanner, _ := testScanner(t, [][]Batch{{testBatch(5)}, {}}, ^uint64(0))
	_, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.ErrorIs(t, err, io.EOF)
}

func TestScannerStopsAtTheByteCap(t *testing.T) {
	padding := make(hexutil.Bytes, 100)
	scanner, _ := testScanner(t, [][]Batch{
		{testBatch(5, padding)},
		{testBatch(6, padding)},
		{testBatch(7), testAggregate(7, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	}, 150)
	proven, err := scanner.Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven)
}

func TestScannerSharesAPassBetweenConsecutiveBlocks(t *testing.T) {
	scanner, source := testScanner(t, [][]Batch{
		{testBatch(5), testBatch(6)},
		{testBatch(7), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{testBatch(8), testAggregate(8, []optypes.ProofStatement{testStatement(2)}, "ok")},
		{},
	}, ^uint64(0))
	ctx := context.Background()
	for _, c := range []struct {
		block, inclusion uint64
		want             optypes.ProofStatement
	}{{5, 0, testStatement(1)}, {6, 0, testStatement(1)}, {7, 1, testStatement(2)}} {
		proven, err := scanner.Responsible(ctx, c.block, testL1(c.inclusion), eth.SystemConfig{})
		require.NoError(t, err)
		require.Equal(t, provenSet(c.want), proven, "block %d", c.block)
	}
	require.Equal(t, []uint64{0}, source.resets, "one pass served all three")

	// An earlier inclusion block starts a new pass.
	_, err := scanner.Responsible(ctx, 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Equal(t, []uint64{0, 0}, source.resets)
}

// fakeBatchProvider hands out singular batches read at L1 origin 0, and counts flushes and reads.
type fakeBatchProvider struct {
	batches []*SingularBatch
	flushes int
	reads   int
}

func (f *fakeBatchProvider) Reset(context.Context, eth.L1BlockRef, eth.SystemConfig) error {
	return io.EOF
}

func (f *fakeBatchProvider) FlushChannel() { f.flushes++ }

func (f *fakeBatchProvider) Origin() eth.L1BlockRef { return testL1(0) }

func (f *fakeBatchProvider) NextBatch(context.Context, eth.L2BlockRef) (*SingularBatch, bool, error) {
	f.reads++
	if len(f.batches) == 0 {
		return nil, false, io.EOF
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, false, nil
}

type fakeSystemConfigs struct{}

func (fakeSystemConfigs) SystemConfigByL2Hash(context.Context, common.Hash) (eth.SystemConfig, error) {
	return eth.SystemConfig{}, nil
}

// testGateParent is the parent of L2 block 5.
var testGateParent = eth.L2BlockRef{Number: 4, Hash: common.Hash{0xbb}}

// testGate is a gate whose next batch is block 5 with txs, read at L1 block 0, over scan blocks.
func testGate(t *testing.T, txs []hexutil.Bytes, blocks [][]Batch) (*DependencyGate, *fakeBatchProvider, *fakeScanSource) {
	prev := &fakeBatchProvider{batches: []*SingularBatch{{Timestamp: 10, Transactions: txs}}}
	scanner, source := testScanner(t, blocks, ^uint64(0))
	gate := NewDependencyGate(testlog.Logger(t, log.LevelDebug), testScannerConfig(), prev, scanner, fakeSystemConfigs{})
	return gate, prev, source
}

func TestGatePassesABatchWithoutDependenciesWithoutAScan(t *testing.T) {
	plain := hexutil.Bytes{0x02, 0xc0}
	noDeps := testAaTx(t, 0, nil)
	gate, _, source := testGate(t, []hexutil.Bytes{plain, noDeps}, nil)
	batch, concluding, err := gate.NextBatch(context.Background(), testGateParent)
	require.NoError(t, err)
	require.False(t, concluding)
	require.Equal(t, []hexutil.Bytes{plain, noDeps}, batch.Transactions)
	require.Empty(t, source.resets)
	_, ok := gate.DecidedAt()
	require.False(t, ok)
}

func TestGatePassesACoveredBatchUnchanged(t *testing.T) {
	tx := testAaTx(t, 0, []optypes.ProofStatement{testStatement(1)})
	gate, prev, _ := testGate(t, []hexutil.Bytes{tx}, [][]Batch{
		{testBatch(6), testAggregate(5, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	})
	batch, concluding, err := gate.NextBatch(context.Background(), testGateParent)
	require.NoError(t, err)
	require.Equal(t, []hexutil.Bytes{tx}, batch.Transactions)
	require.Zero(t, prev.flushes)
	require.False(t, concluding)
	decidedAt, ok := gate.DecidedAt()
	require.True(t, ok)
	require.Equal(t, testL1(0), decidedAt, "decided by the aggregate at L1 block 0")
}

// A plain transaction and a proven one leave with the unproven one: the block holds only deposits.
func TestGateEmptiesABatchWithAnUnprovenDependencyAndFlushesTheChannel(t *testing.T) {
	plain := hexutil.Bytes{0x02, 0xc0}
	proven := testAaTx(t, 0, []optypes.ProofStatement{testStatement(1)})
	unproven := testAaTx(t, 1, []optypes.ProofStatement{testStatement(1), testStatement(2)})
	gate, prev, _ := testGate(t, []hexutil.Bytes{plain, proven, unproven}, [][]Batch{
		{testBatch(6), testAggregate(5, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	})
	batch, concluding, err := gate.NextBatch(context.Background(), testGateParent)
	require.NoError(t, err)
	require.Empty(t, batch.Transactions)
	require.Equal(t, 1, prev.flushes)
	require.True(t, concluding)
}

func TestGateDerivesABlockDecidedAtTheWindowEndFromThere(t *testing.T) {
	tx := testAaTx(t, 0, []optypes.ProofStatement{testStatement(1)})
	gate, _, _ := testGate(t, []hexutil.Bytes{tx}, [][]Batch{{}, {}, {}, {}, {}})
	batch, _, err := gate.NextBatch(context.Background(), testGateParent)
	require.NoError(t, err)
	require.Empty(t, batch.Transactions)
	decidedAt, ok := gate.DecidedAt()
	require.True(t, ok)
	require.Equal(t, testL1(3), decidedAt, "the window of 3 ends at L1 block 3")
}

func TestGateHoldsAnUndecidedBatch(t *testing.T) {
	tx := testAaTx(t, 0, []optypes.ProofStatement{testStatement(1)})
	gate, prev, _ := testGate(t, []hexutil.Bytes{tx}, [][]Batch{{}, {}})
	ctx := context.Background()
	for range 2 {
		_, _, err := gate.NextBatch(ctx, testGateParent)
		require.ErrorIs(t, err, ErrWaitingForL1)
		require.NotErrorIs(t, err, io.EOF, "the pipeline must not advance its own origin")
	}
	require.Equal(t, 1, prev.reads, "the held batch is not read again")

	gate.FlushChannel()
	_, _, err := gate.NextBatch(ctx, testGateParent)
	require.ErrorIs(t, err, io.EOF)
}

func TestGateKeepsTheLatestDecisionUntilReset(t *testing.T) {
	tx := testAaTx(t, 0, []optypes.ProofStatement{testStatement(1)})
	gate, prev, _ := testGate(t, []hexutil.Bytes{tx}, [][]Batch{{}, {}, {}, {}, {}})
	prev.batches = append(prev.batches, &SingularBatch{Timestamp: 12})
	ctx := context.Background()
	_, _, err := gate.NextBatch(ctx, testGateParent)
	require.NoError(t, err)
	_, _, err = gate.NextBatch(ctx, eth.L2BlockRef{Number: 5})
	require.NoError(t, err)
	decidedAt, ok := gate.DecidedAt()
	require.True(t, ok, "the block after a decided one is derived from at least the same L1 block")
	require.Equal(t, testL1(3), decidedAt)

	require.ErrorIs(t, gate.Reset(ctx, testL1(0), eth.SystemConfig{}), io.EOF)
	_, ok = gate.DecidedAt()
	require.False(t, ok)
}

type stubAttributesBuilder struct{}

func (stubAttributesBuilder) PreparePayloadAttributes(context.Context, eth.L2BlockRef, eth.BlockID) (*eth.PayloadAttributes, error) {
	return &eth.PayloadAttributes{}, nil
}

// decidingBatchProvider is a batch provider that reports a dependency decision.
type decidingBatchProvider struct {
	fakeBatchProvider
	decidedAt *eth.L1BlockRef
}

func (d *decidingBatchProvider) DecidedAt() (eth.L1BlockRef, bool) {
	if d.decidedAt == nil {
		return eth.L1BlockRef{}, false
	}
	return *d.decidedAt, true
}

func TestAttributesAreDerivedFromTheLaterOfTheOriginAndTheDecision(t *testing.T) {
	parent := eth.L2BlockRef{Number: 4, Hash: common.Hash{0xbb}, Time: 8}
	cfg := &rollup.Config{BlockTime: 2}
	for _, c := range []struct {
		name      string
		decidedAt *eth.L1BlockRef
		want      eth.L1BlockRef
	}{
		{"no decision", nil, testL1(0)},
		{"decided later", &eth.L1BlockRef{Number: 3, Time: 36}, testL1(3)},
	} {
		t.Run(c.name, func(t *testing.T) {
			prev := &decidingBatchProvider{decidedAt: c.decidedAt}
			prev.batches = []*SingularBatch{{ParentHash: parent.Hash, Timestamp: 10}}
			aq := NewAttributesQueue(testlog.Logger(t, log.LevelError), cfg, stubAttributesBuilder{}, prev)
			attrs, err := aq.NextAttributes(context.Background(), parent)
			require.NoError(t, err)
			require.Equal(t, c.want, attrs.DerivedFrom)
		})
	}
}

// fakeL1 serves an empty L1 chain of n blocks, 12 seconds apart.
type fakeL1 struct {
	testutils.MockL1Source
	n uint64
}

func (f *fakeL1) ref(number uint64) eth.L1BlockRef {
	return eth.L1BlockRef{Number: number, Time: number * 12, Hash: common.Hash{byte(number + 1)}, ParentHash: common.Hash{byte(number)}}
}

func (f *fakeL1) L1BlockRefByNumber(_ context.Context, number uint64) (eth.L1BlockRef, error) {
	if number >= f.n {
		return eth.L1BlockRef{}, ethereum.NotFound
	}
	return f.ref(number), nil
}

func (f *fakeL1) FetchReceipts(_ context.Context, hash common.Hash) (eth.BlockInfo, optypes.Receipts, error) {
	return nil, nil, nil
}

func (f *fakeL1) InfoAndTxsByHash(_ context.Context, hash common.Hash) (eth.BlockInfo, types.Transactions, error) {
	return nil, nil, nil
}

func TestScanStagesTransformAtHolocene(t *testing.T) {
	holocene := uint64(24)
	cfg := &rollup.Config{BlockTime: 2, HoloceneTime: &holocene}
	stages := newScanStages(testlog.Logger(t, log.LevelError), cfg, &fakeL1{n: 3}, nil)
	ctx := context.Background()
	require.NoError(t, stages.ResetTo(ctx, 0, eth.SystemConfig{}))
	channels := stages.stages[3].(*ChannelMux)
	require.IsType(t, &ChannelBank{}, channels.RawChannelProvider)

	require.NoError(t, stages.AdvanceL1Block(ctx))
	require.IsType(t, &ChannelBank{}, channels.RawChannelProvider)
	require.NoError(t, stages.AdvanceL1Block(ctx))
	require.IsType(t, &ChannelAssembler{}, channels.RawChannelProvider, "L1 block 2 activates Holocene")
	require.ErrorIs(t, stages.AdvanceL1Block(ctx), io.EOF)
}

func TestScanStagesIgnoreAltDA(t *testing.T) {
	cfg := &rollup.Config{AltDAConfig: &rollup.AltDAConfig{}}
	require.False(t, withoutAltDA(cfg).AltDAEnabled())
	require.True(t, cfg.AltDAEnabled(), "the pipeline's own config is untouched")
}

// waitingBatchProvider holds every batch until later L1 data arrives.
type waitingBatchProvider struct{ fakeBatchProvider }

func (*waitingBatchProvider) NextBatch(context.Context, eth.L2BlockRef) (*SingularBatch, bool, error) {
	return nil, false, ErrWaitingForL1
}

type countingTraversal struct {
	L1Traversal
	advances int
}

func (c *countingTraversal) AdvanceL1Block(context.Context) error {
	c.advances++
	return nil
}

func TestPipelineIdlesWithoutAdvancingWhileWaitingForL1(t *testing.T) {
	traversal := &countingTraversal{}
	aq := NewAttributesQueue(testlog.Logger(t, log.LevelError), &rollup.Config{}, stubAttributesBuilder{}, &waitingBatchProvider{})
	dp := &DerivationPipeline{
		log:       testlog.Logger(t, log.LevelError),
		rollupCfg: &rollup.Config{},
		traversal: traversal,
		attrib:    aq,
		origin:    aq.Origin(),
		metrics:   scannerMetrics{},
	}
	_, err := dp.Step(context.Background(), eth.L2BlockRef{})
	require.Equal(t, io.EOF, err, "the deriver treats the pipeline as idle")
	require.Zero(t, traversal.advances, "the origin's data is not consumed yet")
}
