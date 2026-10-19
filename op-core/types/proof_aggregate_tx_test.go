package types_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// proofAggregateGoldenPayload is the RLP payload of op-alloy's
// build_proof_aggregate_tx(42, 0xaa..aa, [{0x11..11, 0x22..22}], 0xdeadbeef).
const proofAggregateGoldenPayload = "0xf86e012aa0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0" +
	"1111111111111111111111111111111111111111111111111111111111111111a0" +
	"222222222222222222222222222222222222222222222222222222222222222284deadbeef"

// TestProofAggregateTxHashGoldenVector pins the cross-client proof aggregate (0x7C) encoding
// and hash: keccak256(0x7C || Data). The same vector is asserted by op-alloy's
// proof_aggregate_tx_golden_vector test.
func TestProofAggregateTxHashGoldenVector(t *testing.T) {
	data := hexutil.MustDecode(proofAggregateGoldenPayload)
	tx := &optypes.ProofAggregateTx{Data: data}

	raw, err := tx.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, append([]byte{optypes.ProofAggregateTxType}, data...), raw)
	require.Equal(t, "0x03f4ebe12e9cb4814835bdb10dff45302f484edc3eaeff030cdb6c518dcde956", tx.Hash().Hex())
	require.Equal(t, crypto.Keccak256Hash(raw), tx.Hash())
}

func TestUnmarshalProofAggregateTx(t *testing.T) {
	data := hexutil.MustDecode(proofAggregateGoldenPayload)
	raw, err := (&optypes.ProofAggregateTx{Data: data}).MarshalBinary()
	require.NoError(t, err)

	decoded, err := optypes.UnmarshalProofAggregateTx(raw)
	require.NoError(t, err)
	require.Equal(t, data, decoded.Data)

	_, err = optypes.UnmarshalProofAggregateTx(nil)
	require.ErrorContains(t, err, "empty")
	_, err = optypes.UnmarshalProofAggregateTx([]byte{optypes.PostExecTxType, 0x01})
	require.ErrorContains(t, err, "type byte")
	_, err = optypes.UnmarshalProofAggregateTx([]byte{optypes.ProofAggregateTxType})
	require.ErrorContains(t, err, "payload is empty")
}

func TestProofAggregateTxJSONRoundTrip(t *testing.T) {
	tx := &optypes.ProofAggregateTx{Data: hexutil.MustDecode(proofAggregateGoldenPayload)}
	enc, err := json.Marshal(tx)
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(enc, &fields))
	require.Equal(t, "0x7c", fields["type"])
	require.Equal(t, tx.Hash().Hex(), fields["hash"])

	var dec optypes.ProofAggregateTx
	require.NoError(t, json.Unmarshal(enc, &dec))
	require.Equal(t, tx.Data, dec.Data)
}

func TestProofAggregateTxUnmarshalJSONErrors(t *testing.T) {
	for name, input := range map[string]string{
		"wrong type":  `{"type":"0x7d","input":"0x01"}`,
		"empty input": `{"type":"0x7c","input":"0x"}`,
		"no input":    `{"type":"0x7c"}`,
		"nonzero gas": `{"type":"0x7c","input":"0x01","gas":"0x1"}`,
		"with to":     `{"type":"0x7c","input":"0x01","to":"0x0000000000000000000000000000000000000001"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var tx optypes.ProofAggregateTx
			require.Error(t, json.Unmarshal([]byte(input), &tx))
		})
	}
}

// TestProofAggregateReceiptRoundTrip pins the 0x7C receipt consensus encoding: the same layout as
// a post-exec receipt under its own type byte, as op-alloy's OpReceipt::ProofAggregate encodes it.
func TestProofAggregateReceiptRoundTrip(t *testing.T) {
	r := &optypes.Receipt{}
	r.Type = optypes.ProofAggregateTxType
	r.Status = 1
	r.CumulativeGasUsed = 21000

	raw, err := r.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, byte(optypes.ProofAggregateTxType), raw[0])

	var decoded optypes.Receipt
	require.NoError(t, decoded.UnmarshalBinary(raw))
	require.Equal(t, uint8(optypes.ProofAggregateTxType), decoded.Type)
	require.Equal(t, uint64(1), decoded.Status)
	require.Equal(t, uint64(21000), decoded.CumulativeGasUsed)

	var leaf bytes.Buffer
	optypes.Receipts{&decoded}.EncodeIndex(0, &leaf)
	require.Equal(t, raw, leaf.Bytes(), "the receipts-trie leaf is the consensus encoding")

	require.Error(t, decoded.UnmarshalBinary([]byte{optypes.ProofAggregateTxType, 0xff}))
}
