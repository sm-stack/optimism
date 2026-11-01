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
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

// testAaTxRaw is op-alloy's golden EIP-8430 transaction (`aa::tests::golden`), the same bytes kona's
// span batch tests pin (`test_aa_tx_span_batch_golden_vector`).
func testAaTxRaw() []byte {
	return hexutil.MustDecode("0x79f901f38203859411111111111111111111111111111111111111118003846553f10086018bcfee8fc0830f424084773594" +
		"008303d090f8a6d60194dedededededededededededededededededededef88d04f88af84320a00000000000000000000000" +
		"000000000000000000000000000000000000000000a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaf84320a0dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddda0aaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf850dcdb9422222222222222222222222222222222222222228203" +
		"e882deadf2d79433333333333333333333333333333333333333338080d99444444444444444444444444444444444444444" +
		"448082beef826f70945555555555555555555555555555555555555555b85500000000000000000000000000000000000000" +
		"0166666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" +
		"66666666666666666666666666666666b8550000000000000000000000000000000000000001777777777777777777777777" +
		"7777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" +
		"777777")
}

func TestSpanBatchTxsAaTxRoundTripFullTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x8430))
	chainID := big.NewInt(901)
	signer := types.NewPragueSigner(chainID)

	rawNormalTx, err := testutils.RandomDynamicFeeTx(rng, signer).MarshalBinary()
	require.NoError(t, err)
	txs := [][]byte{rawNormalTx, testAaTxRaw()}

	sbt, err := newSpanBatchTxs(txs, chainID)
	require.NoError(t, err)
	require.Equal(t, []int{types.DynamicFeeTxType, optypes.AaTxType}, sbt.txTypes)
	require.Equal(t, uint(1), sbt.zeroToBits.Bit(1))
	// The stored tx data is the canonical encoding verbatim, as kona stores it.
	require.Equal(t, hexutil.Bytes(testAaTxRaw()), sbt.txDatas[1])
	require.NoError(t, sbt.checkPostExecSlots())

	full, err := sbt.fullTxs(chainID)
	require.NoError(t, err)
	require.Equal(t, txs, full)
}

// TestSpanBatchTxsAaTxEncodeDecode runs the golden EIP-8430 transaction through the span batch wire
// encoding and back, the path derivation takes on batcher bytes.
func TestSpanBatchTxsAaTxEncodeDecode(t *testing.T) {
	chainID := big.NewInt(901)
	sbt, err := newSpanBatchTxs([][]byte{testAaTxRaw()}, chainID)
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
	require.Equal(t, [][]byte{testAaTxRaw()}, full)
}

// Derivation carries a 0x79 payload without decoding it, like kona: a malformed one reaches the
// execution client, which rejects it, rather than invalidating the whole span batch.
func TestSpanBatchTxsAaTxPayloadNotDecoded(t *testing.T) {
	chainID := big.NewInt(901)
	sbt, err := newSpanBatchTxs([][]byte{testAaTxRaw()}, chainID)
	require.NoError(t, err)
	sbt.txDatas[0] = hexutil.Bytes{optypes.AaTxType, 0xc0}

	var buf bytes.Buffer
	require.NoError(t, sbt.encode(&buf))
	var decoded spanBatchTxs
	decoded.totalBlockTxCount = 1
	require.NoError(t, decoded.decode(bytes.NewReader(buf.Bytes())))
	require.NoError(t, decoded.recoverV(chainID))
	require.NoError(t, decoded.checkPostExecSlots())
	full, err := decoded.fullTxs(chainID)
	require.NoError(t, err)
	require.Equal(t, [][]byte{{optypes.AaTxType, 0xc0}}, full)
}

func TestSpanBatchTxsCheckAaTxSlots(t *testing.T) {
	chainID := big.NewInt(901)
	honest := func(t *testing.T) *spanBatchTxs {
		sbt, err := newSpanBatchTxs([][]byte{testAaTxRaw()}, chainID)
		require.NoError(t, err)
		return sbt
	}
	for name, mutate := range map[string]func(*spanBatchTxs){
		"zero-to bit cleared": func(s *spanBatchTxs) { s.zeroToBits.SetBit(s.zeroToBits, 0, 0) },
		"y parity bit set":    func(s *spanBatchTxs) { s.yParityBits.SetBit(s.yParityBits, 0, 1) },
		"signature non-zero":  func(s *spanBatchTxs) { s.txSigs[0].r = uint256.NewInt(1) },
		"nonce non-zero":      func(s *spanBatchTxs) { s.txNonces[0] = 3 },
		"gas non-zero":        func(s *spanBatchTxs) { s.txGases[0] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			sbt := honest(t)
			mutate(sbt)
			require.ErrorContains(t, sbt.checkPostExecSlots(), "EIP-8430 tx at index 0")
		})
	}
}

func TestSpanBatchTxsRejectsMalformedAaTx(t *testing.T) {
	_, err := newSpanBatchTxs([][]byte{{optypes.AaTxType, 0xc1}}, big.NewInt(901))
	require.ErrorContains(t, err, "failed to decode EIP-8430 tx")
}

func TestCheckSequencerTxDataAaTx(t *testing.T) {
	lgr, logs := testlog.CaptureLogger(t, log.LevelWarn)
	raw := testAaTxRaw()

	lagoon := uint64(10)
	cfg := &rollup.Config{IsthmusTime: new(uint64), LagoonTime: &lagoon}
	require.Equal(t, BatchValidity(BatchDrop), checkSequencerTxData(lgr, cfg, 9, 0, raw))
	require.NotNil(t, logs.FindLog(testlog.NewMessageContainsFilter("EIP-8430 transactions before Lagoon")))
	require.Equal(t, BatchValidity(BatchAccept), checkSequencerTxData(lgr, cfg, 10, 0, raw))
}

// A 0x06 transaction (the removed frame transaction) is no transaction type: the batch stage accepts
// it whatever the fork and execution rejects it, as kona does (`test_check_batch_accepts_an_unknown_type`).
func TestCheckSequencerTxDataUnknownType(t *testing.T) {
	lgr := testlog.Logger(t, log.LevelWarn)
	lagoon := uint64(10)
	cfg := &rollup.Config{IsthmusTime: new(uint64), LagoonTime: &lagoon}
	for _, ts := range []uint64{9, 10} {
		require.Equal(t, BatchValidity(BatchAccept), checkSequencerTxData(lgr, cfg, ts, 0, []byte{0x06, 0xc0}))
	}
}
