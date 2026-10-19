package derive

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

// testProofAggregateTxRaw is op-alloy's golden proof aggregate transaction, the same bytes
// kona's span batch tests pin.
func testProofAggregateTxRaw() []byte {
	return hexutil.MustDecode("0x7cf86e012aa0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0" +
		"1111111111111111111111111111111111111111111111111111111111111111a0" +
		"222222222222222222222222222222222222222222222222222222222222222284deadbeef")
}

func TestSpanBatchTxsProofAggregateRoundTripFullTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x7c7331))
	chainID := big.NewInt(901)
	signer := types.NewPragueSigner(chainID)

	rawNormalTx, err := testutils.RandomDynamicFeeTx(rng, signer).MarshalBinary()
	require.NoError(t, err)
	txs := [][]byte{testProofAggregateTxRaw(), rawNormalTx}

	sbt, err := newSpanBatchTxs(txs, chainID)
	require.NoError(t, err)
	require.Equal(t, []int{optypes.ProofAggregateTxType, types.DynamicFeeTxType}, sbt.txTypes)
	require.Equal(t, uint(1), sbt.zeroToBits.Bit(0))
	// The stored tx data is the canonical encoding verbatim, as kona stores it.
	require.Equal(t, hexutil.Bytes(testProofAggregateTxRaw()), sbt.txDatas[0])
	require.NoError(t, sbt.checkPostExecSlots())

	full, err := sbt.fullTxs(chainID)
	require.NoError(t, err)
	require.Equal(t, txs, full)
}

// TestSpanBatchTxsProofAggregateEncodeDecode runs the golden proof aggregate through the span
// batch wire encoding and back, the path derivation takes on batcher bytes.
func TestSpanBatchTxsProofAggregateEncodeDecode(t *testing.T) {
	chainID := big.NewInt(901)
	sbt, err := newSpanBatchTxs([][]byte{testProofAggregateTxRaw()}, chainID)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, sbt.encode(&buf))
	var decoded spanBatchTxs
	decoded.totalBlockTxCount = sbt.totalBlockTxCount
	require.NoError(t, decoded.decode(bytes.NewReader(buf.Bytes())))
	require.NoError(t, decoded.recoverV(chainID))
	require.NoError(t, decoded.checkPostExecSlots())

	full, err := decoded.fullTxs(chainID)
	require.NoError(t, err)
	require.Equal(t, [][]byte{testProofAggregateTxRaw()}, full)

	txData, txType, err := ReadTxData(bytes.NewReader(testProofAggregateTxRaw()))
	require.NoError(t, err)
	require.Equal(t, optypes.ProofAggregateTxType, txType)
	require.Equal(t, testProofAggregateTxRaw(), txData)
}

func TestSpanBatchTxsCheckProofAggregateSlots(t *testing.T) {
	chainID := big.NewInt(901)
	honest := func(t *testing.T) *spanBatchTxs {
		sbt, err := newSpanBatchTxs([][]byte{testProofAggregateTxRaw()}, chainID)
		require.NoError(t, err)
		return sbt
	}
	for name, mutate := range map[string]func(*spanBatchTxs){
		"zero-to bit cleared": func(s *spanBatchTxs) { s.zeroToBits.SetBit(s.zeroToBits, 0, 0) },
		"y parity bit set":    func(s *spanBatchTxs) { s.yParityBits.SetBit(s.yParityBits, 0, 1) },
		"signature non-zero":  func(s *spanBatchTxs) { s.txSigs[0].r = uint256.NewInt(1) },
		"nonce non-zero":      func(s *spanBatchTxs) { s.txNonces[0] = 1 },
		"gas non-zero":        func(s *spanBatchTxs) { s.txGases[0] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			sbt := honest(t)
			mutate(sbt)
			require.ErrorContains(t, sbt.checkPostExecSlots(), "proof aggregate tx at index 0")
		})
	}
}

func TestCheckSequencerTxDataProofAggregate(t *testing.T) {
	lgr, logs := testlog.CaptureLogger(t, log.LevelWarn)
	raw := testProofAggregateTxRaw()

	require.Equal(t, BatchValidity(BatchDrop), checkSequencerTxData(lgr, 0, raw, true, true, false))
	require.NotNil(t, logs.FindLog(testlog.NewMessageContainsFilter("before proof aggregation is active")))
	require.Equal(t, BatchValidity(BatchAccept), checkSequencerTxData(lgr, 0, raw, true, true, true))
}
