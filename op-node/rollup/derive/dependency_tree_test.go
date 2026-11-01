package derive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

// treePayload is a proof aggregate carrying proof.
func treePayload(t *testing.T, proof *optypes.LeanVmTreeProof) *optypes.ProofAggregatePayload {
	enc, err := rlp.EncodeToBytes(proof)
	require.NoError(t, err)
	return &optypes.ProofAggregatePayload{
		Version:             optypes.ProofAggregatePayloadVersion,
		Through:             9,
		AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
		Statements:          []optypes.ProofStatement{{VkeyHash: common.Hash{0xaa}, PublicValuesDigest: common.Hash{1}}},
		Proof:               enc,
	}
}

// Without a tree verifier no aggregate proves anything; with one, the payload's root and seal reach
// it, as in op-alloy's verifies_a_leanvm_tree.
func TestAggregatesNeedATreeVerifier(t *testing.T) {
	proof := &optypes.LeanVmTreeProof{Root: []byte("root"), Seal: []byte("seal")}
	payload := treePayload(t, proof)
	require.ErrorContains(t, verifyAggregate(nil, payload), "no proof aggregate verifier")

	verify := func(statements []optypes.ProofStatement, root, seal []byte) error {
		require.Equal(t, payload.Statements, statements)
		if !bytes.Equal(root, proof.Root) || !bytes.Equal(seal, proof.Seal) {
			return errors.New("bad tree proof")
		}
		return nil
	}
	require.NoError(t, verifyAggregate(verify, payload))
	require.Error(t, verifyAggregate(verify, treePayload(t, &optypes.LeanVmTreeProof{Root: []byte("x"), Seal: proof.Seal})))

	malformed := treePayload(t, proof)
	malformed.Proof = []byte("tree")
	require.ErrorContains(t, verifyAggregate(verify, malformed), "malformed leanVM tree proof")
	otherClass := treePayload(t, proof)
	otherClass.AggregationVkeyHash = common.Hash{}
	require.ErrorContains(t, verifyAggregate(verify, otherClass), "untrusted class")
	otherVersion := treePayload(t, proof)
	otherVersion.Version = optypes.ProofAggregatePayloadVersion + 1
	require.ErrorContains(t, verifyAggregate(verify, otherVersion), "unknown payload version")
}

// Without a verifier the scanner stops at an aggregate it would have to verify, rather than replace
// a block the aggregate may prove; with no aggregate in the window it decides as usual.
func TestScannerWithoutAVerifierStopsAtAnAggregate(t *testing.T) {
	scanner := func(blocks [][]Batch) *DependencyScanner {
		return newDependencyScanner(testlog.Logger(t, log.LevelDebug), testScannerConfig(), &fakeScanSource{blocks: blocks}, nil, 3, ^uint64(0))
	}
	_, err := scanner([][]Batch{
		{testBatch(5)},
		{testBatch(6), testAggregate(6, []optypes.ProofStatement{testStatement(1)}, "ok")},
		{},
	}).Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.ErrorIs(t, err, ErrCritical)

	proven, err := scanner([][]Batch{{testBatch(5)}, {}, {}, {}, {}}).
		Responsible(context.Background(), 5, testL1(0), eth.SystemConfig{})
	require.NoError(t, err)
	require.Empty(t, proven, "no aggregate answers for the block")
}

// The Go tree verifier of the pinned class accepts op-leanvm-tree's fixture aggregate and refuses
// it for statements the root does not prove.
func TestLeanVmTreeVerifierVerifiesTheFixtureAggregate(t *testing.T) {
	verify, err := LeanVmTreeVerifier()
	require.NoError(t, err)
	encoded, err := os.ReadFile("../../../rust/op-leanvm-tree/testdata/tree.payload")
	require.NoError(t, err)
	payload, err := optypes.DecodeProofAggregatePayload(encoded)
	require.NoError(t, err)
	require.NoError(t, verifyAggregate(verify, payload))

	other := *payload
	other.Statements = slices.Clone(payload.Statements)
	other.Statements[0].PublicValuesDigest[0] ^= 1
	require.Error(t, verifyAggregate(verify, &other), "another member")
	other.Statements = payload.Statements[1:]
	require.Error(t, verifyAggregate(verify, &other), "a subset")
	other.Statements = slices.Clone(payload.Statements)
	slices.Reverse(other.Statements)
	require.Error(t, verifyAggregate(verify, &other), "out of canonical order")

	classKey := slices.Clone(optypes.LeanVmTreeClassKey)
	classKey[len(classKey)-1] ^= 1
	_, err = NewLeanVmTreeVerifier(classKey)
	require.Error(t, err, "a class key of another digest")
}

// Statements are in canonical order when their claims are: labels, then members, compared as
// little-endian words, first word first, as op-leanvm-tree's canonical order. Bytewise order is
// not that order.
func TestTreeStatementsAreOrderedByLittleEndianWords(t *testing.T) {
	order := func(statements ...optypes.ProofStatement) error {
		converted := make([]leanvmclaims.Statement, len(statements))
		for i, s := range statements {
			converted[i] = leanvmclaims.Statement{VkeyHash: s.VkeyHash, PublicValuesDigest: s.PublicValuesDigest}
		}
		_, err := leanvmclaims.ClaimsFromStatements(converted)
		return err
	}
	// Bytewise ascending, but descending in little-endian word 0.
	a := optypes.ProofStatement{VkeyHash: common.Hash{0: 0x01, 1: 0x02}}
	b := optypes.ProofStatement{VkeyHash: common.Hash{0: 0x02, 1: 0x01}}
	require.Error(t, order(a, b))
	require.NoError(t, order(b, a))
	// Within a program, members order the same way.
	m := func(member common.Hash) optypes.ProofStatement {
		return optypes.ProofStatement{VkeyHash: common.Hash{1}, PublicValuesDigest: member}
	}
	require.Error(t, order(m(common.Hash{0: 0x01, 1: 0x02}), m(common.Hash{0: 0x02, 1: 0x01})))
	require.NoError(t, order(m(common.Hash{0: 0x02, 1: 0x01}), m(common.Hash{0: 0x01, 1: 0x02})))
	require.Error(t, order(m(common.Hash{1}), m(common.Hash{1})), "a repeat")
}
