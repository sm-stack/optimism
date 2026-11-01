package derive

import (
	"bytes"
	"compress/zlib"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

// oneChannel hands out one channel, read at origin.
type oneChannel struct {
	data   []byte
	origin eth.L1BlockRef
}

func (c *oneChannel) Reset(context.Context, eth.L1BlockRef, eth.SystemConfig) error { return io.EOF }
func (c *oneChannel) FlushChannel()                                                 {}
func (c *oneChannel) Origin() eth.L1BlockRef                                        { return c.origin }

func (c *oneChannel) NextRawChannel(context.Context) ([]byte, error) {
	if c.data == nil {
		return nil, io.EOF
	}
	data := c.data
	c.data = nil
	return data, nil
}

// channelOf compresses the batches into channel data.
func channelOf(t *testing.T, batches ...InnerBatchData) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	for _, b := range batches {
		require.NoError(t, rlp.Encode(w, NewBatchData(b)))
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// readAll reads batches until the channel ends, returning their kinds.
func readAll(t *testing.T, reader *ChannelInReader) []string {
	var kinds []string
	for range 10 {
		batch, err := reader.NextBatch(context.Background())
		if err == io.EOF {
			return kinds
		}
		if err == NotEnoughData {
			continue
		}
		require.NoError(t, err)
		if _, ok := asProofAggregateBatch(batch); ok {
			kinds = append(kinds, "aggregate")
		} else {
			single, ok := batch.AsSingularBatch()
			require.True(t, ok)
			kinds = append(kinds, hexutil.EncodeUint64(single.Timestamp))
		}
	}
	t.Fatal("channel did not end")
	return nil
}

func TestChannelReaderProofAggregateBatches(t *testing.T) {
	lagoon := uint64(100)
	cfg := &rollup.Config{LagoonTime: &lagoon}
	aggregate := &ProofAggregateBatch{Payload: optypes.ProofAggregatePayload{
		Version: optypes.ProofAggregatePayloadVersion, Through: 5, Proof: []byte("ok"),
	}}
	data := channelOf(t, &SingularBatch{Timestamp: 1}, aggregate, &SingularBatch{Timestamp: 2})
	reader := func(time uint64, scanner bool) *ChannelInReader {
		r := NewChannelInReader(cfg, testlog.Logger(t, log.LevelError), &oneChannel{data: data, origin: eth.L1BlockRef{Time: time}}, scannerMetrics{})
		r.proofAggregates = scanner
		return r
	}

	require.Equal(t, []string{"0x1", "0x2"}, readAll(t, reader(100, false)),
		"the pipeline skips the aggregate and keeps reading the channel")
	require.Equal(t, []string{"0x1", "aggregate", "0x2"}, readAll(t, reader(100, true)),
		"the scanner reads it")
	require.Equal(t, []string{"0x1"}, readAll(t, reader(99, true)),
		"before Lagoon the type is unknown and ends the channel")
}

// TestProofAggregateBatchGoldenVector shares its vector with kona's
// test_proof_aggregate_batch_golden_vector: the type byte, then op-alloy's payload_golden_vector.
// Trailing bytes are rejected.
func TestProofAggregateBatchGoldenVector(t *testing.T) {
	item := hexutil.MustDecode("0x02f86e0429a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0" +
		"1111111111111111111111111111111111111111111111111111111111111111a0" +
		"222222222222222222222222222222222222222222222222222222222222222284deadbeef")
	batch := &ProofAggregateBatch{Payload: optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             41,
		AggregationVkeyHash: common.BytesToHash(bytes.Repeat([]byte{0xaa}, 32)),
		Statements: []optypes.ProofStatement{{
			VkeyHash:           common.BytesToHash(bytes.Repeat([]byte{0x11}, 32)),
			PublicValuesDigest: common.BytesToHash(bytes.Repeat([]byte{0x22}, 32)),
		}},
		Proof: hexutil.MustDecode("0xdeadbeef"),
	}}
	enc, err := NewBatchData(batch).MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, item, enc)
	var decoded BatchData
	require.NoError(t, decoded.UnmarshalBinary(item))
	require.Equal(t, batch, decoded.inner)
	require.Error(t, decoded.UnmarshalBinary(append(item, 0)), "trailing bytes")
}

func TestProofAggregateBatchRoundTrip(t *testing.T) {
	batch := &ProofAggregateBatch{Payload: optypes.ProofAggregatePayload{
		Version:    optypes.ProofAggregatePayloadVersion,
		Through:    41,
		Statements: []optypes.ProofStatement{{}},
		Proof:      []byte{1, 2, 3},
	}}
	enc, err := NewBatchData(batch).MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, byte(ProofAggregateBatchType), enc[0])
	var decoded BatchData
	require.NoError(t, decoded.UnmarshalBinary(enc))
	require.Equal(t, batch, decoded.inner)

	require.Error(t, decoded.UnmarshalBinary(append(enc, 0)), "trailing bytes")
}
