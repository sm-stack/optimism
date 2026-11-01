package reassemble

import (
	"bytes"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive"
	"github.com/ethereum-optimism/optimism/op-node/rollup/derive/params"
)

func TestProcessFramesDecodesAProofAggregateBatch(t *testing.T) {
	rollupCfg := &rollup.Config{L2ChainID: big.NewInt(1234)}
	co, err := derive.NewSpanChannelOut(100_000, derive.Zlib, rollup.NewChainSpec(rollupCfg))
	require.NoError(t, err)
	payload := &optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             7,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements:          []optypes.ProofStatement{{}},
		Proof:               []byte("proof"),
	}
	require.NoError(t, co.AddProofAggregate(payload, 0))
	require.NoError(t, co.Close())
	var buf bytes.Buffer
	_, err = co.OutputFrame(&buf, 100_000)
	require.ErrorIs(t, err, io.EOF, "the channel fits one frame")
	frames, err := derive.ParseFrames(append([]byte{params.DerivationVersion0}, buf.Bytes()...))
	require.NoError(t, err)
	require.Len(t, frames, 1)

	ch := ProcessFrames(Config{}, rollupCfg, frames[0].ID, []FrameWithMetadata{{Frame: frames[0]}})
	require.True(t, ch.IsReady)
	require.False(t, ch.InvalidBatches)
	require.Equal(t, []int{derive.ProofAggregateBatchType}, ch.BatchTypes)
	require.Equal(t, []derive.Batch{&derive.ProofAggregateBatch{Payload: *payload}}, ch.Batches)
}
