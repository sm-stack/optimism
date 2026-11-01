package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// proofAggregatePayloadGolden is op-alloy's payload_golden_vector: a version 4 payload through
// block 41 with vkey 0xaa..aa, one statement {0x11..11, 0x22..22} and proof 0xdeadbeef.
const proofAggregatePayloadGolden = "0xf86e0429a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf844f842a0" +
	"1111111111111111111111111111111111111111111111111111111111111111a0" +
	"222222222222222222222222222222222222222222222222222222222222222284deadbeef"

func TestProofAggregatePayloadGoldenVector(t *testing.T) {
	payload := &optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             41,
		AggregationVkeyHash: common.Hash{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
		Statements: []optypes.ProofStatement{{
			VkeyHash:           common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			PublicValuesDigest: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		}},
		Proof: hexutil.MustDecode("0xdeadbeef"),
	}
	enc, err := rlp.EncodeToBytes(payload)
	require.NoError(t, err)
	require.Equal(t, proofAggregatePayloadGolden, hexutil.Encode(enc))

	decoded, err := optypes.DecodeProofAggregatePayload(enc)
	require.NoError(t, err)
	require.Equal(t, payload, decoded)
}

func TestDecodeProofAggregatePayloadRejectsOtherVersionsAndTrailingBytes(t *testing.T) {
	enc := hexutil.MustDecode(proofAggregatePayloadGolden)
	_, err := optypes.DecodeProofAggregatePayload(append(enc, 0))
	require.Error(t, err)

	for _, version := range []byte{3, 5} {
		other := append([]byte{}, enc...)
		other[2] = version
		_, err = optypes.DecodeProofAggregatePayload(other)
		require.ErrorContains(t, err, "version")
	}
}

// TestLeanVmTreeProofGoldenVector shares its vector with op-alloy's
// leanvm_tree_proof_golden_vector.
func TestLeanVmTreeProofGoldenVector(t *testing.T) {
	proof := &optypes.LeanVmTreeProof{Root: []byte("root"), Seal: []byte("seal")}
	enc, err := rlp.EncodeToBytes(proof)
	require.NoError(t, err)
	require.Equal(t, "0xca84726f6f74847365616c", hexutil.Encode(enc))
	decoded, err := optypes.DecodeLeanVmTreeProof(enc)
	require.NoError(t, err)
	require.Equal(t, proof, decoded)
	_, err = optypes.DecodeLeanVmTreeProof(append(enc, 0))
	require.Error(t, err, "trailing bytes")
}

func TestProofAggregateLimits(t *testing.T) {
	statement := optypes.ProofStatement{VkeyHash: common.Hash{1}, PublicValuesDigest: common.Hash{2}}
	payload := func() *optypes.ProofAggregatePayload {
		return &optypes.ProofAggregatePayload{
			Version:             optypes.ProofAggregatePayloadVersion,
			Through:             9,
			AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
			Statements:          []optypes.ProofStatement{statement},
			Proof:               []byte("tree"),
		}
	}
	require.NoError(t, payload().CheckLimits())
	other := payload()
	other.AggregationVkeyHash = common.Hash{}
	require.ErrorContains(t, other.CheckLimits(), "untrusted class")
	many := payload()
	many.Statements = make([]optypes.ProofStatement, optypes.MaxProofAggregateStatements+1)
	require.ErrorContains(t, many.CheckLimits(), "statement limit")
	large := payload()
	large.Proof = make([]byte, optypes.MaxProofAggregateProofBytes+1)
	require.ErrorContains(t, large.CheckLimits(), "byte limit")
	edge := payload()
	edge.Statements = make([]optypes.ProofStatement, optypes.MaxProofAggregateStatements)
	edge.Proof = make([]byte, optypes.MaxProofAggregateProofBytes)
	require.NoError(t, edge.CheckLimits(), "exactly at the limits")
	versioned := payload()
	versioned.Version = optypes.ProofAggregatePayloadVersion + 1
	require.ErrorContains(t, versioned.CheckLimits(), "unknown payload version")
}
