package types_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// dependencyVectors are EIP-8430 transactions and proof aggregate payloads with what kona's
// dependency gate and scanner make of them (testdata/dependency_vectors.json, written by kona-derive's
// write_go_dependency_vectors). Go derivation must read every one of them the same way.
type dependencyVectors struct {
	AaTxs      []txVector `json:"aaTxs"`
	Aggregates []struct {
		What           string            `json:"what"`
		Payload        hexutil.Bytes     `json:"payload"`
		Decodes        bool              `json:"decodes"`
		Through        uint64            `json:"through"`
		Vkey           common.Hash       `json:"vkey"`
		StatementsHash common.Hash       `json:"statementsHash"`
		StatementCount int               `json:"statementCount"`
		Statements     [][2]common.Hash  `json:"statements"`
		Proof          hexutil.Bytes     `json:"proof"`
		TreeProof      *[2]hexutil.Bytes `json:"treeProof"`
		LimitsOK       bool              `json:"limitsOk"`
	} `json:"aggregates"`
	Limits struct {
		MaxStatements    int  `json:"maxStatements"`
		MaxProofBytes    int  `json:"maxProofBytes"`
		AtLimitsOK       bool `json:"atLimitsOk"`
		PastStatementsOK bool `json:"pastStatementsOk"`
		PastProofOK      bool `json:"pastProofOk"`
	} `json:"limits"`
}

// txVector is a transaction encoding with what kona's decoder and dependency gate make of it.
type txVector struct {
	What      string        `json:"what"`
	Tx        hexutil.Bytes `json:"tx"`
	Decodes   bool          `json:"decodes"`
	Count     *int          `json:"count"`
	Dependent bool          `json:"dependent"`
	Deps      [][3]any      `json:"deps"`
}

func loadDependencyVectors(t *testing.T) *dependencyVectors {
	data, err := os.ReadFile("testdata/dependency_vectors.json")
	require.NoError(t, err)
	var v dependencyVectors
	require.NoError(t, json.Unmarshal(data, &v))
	return &v
}

// TestAaTxDependenciesMatchKona checks that Go decodes every EIP-8430 encoding of the corpus as
// op-alloy does, and reads the same dependencies from it.
func TestAaTxDependenciesMatchKona(t *testing.T) {
	vectors := loadDependencyVectors(t)
	require.NotEmpty(t, vectors.AaTxs)
	for i, v := range vectors.AaTxs {
		_, dependent := optypes.DeclaredDependencies(v.Tx)
		require.Equal(t, v.Dependent, dependent, "tx %d (%s) %s", i, v.What, v.Tx)
		tx, err := optypes.DecodeAaTxLenient(v.Tx)
		require.Equal(t, v.Decodes, err == nil, "tx %d (%s) %s: %v", i, v.What, v.Tx, err)
		if err != nil {
			continue
		}
		require.Equal(t, *v.Count, tx.DependencyDeclarationCount(), "tx %d", i)
		deps := tx.Dependencies()
		require.Len(t, deps, len(v.Deps), "tx %d", i)
		for j, d := range deps {
			require.Equal(t, v.Deps[j][0], float64(d.Scheme), "tx %d dep %d", i, j)
			require.Equal(t, v.Deps[j][1], d.DataHash.Hex(), "tx %d dep %d", i, j)
			require.Equal(t, v.Deps[j][2], d.VerificationKeyHash.Hex(), "tx %d dep %d", i, j)
		}
	}
}

// TestProofAggregateLimitsMatchKona pins the limits a payload is checked against to kona's, and
// kona's verdicts on payloads at and just past them, which the vectors record instead of carrying
// payloads of megabytes: Go rebuilds them.
func TestProofAggregateLimitsMatchKona(t *testing.T) {
	limits := loadDependencyVectors(t).Limits
	require.Equal(t, limits.MaxStatements, optypes.MaxProofAggregateStatements)
	require.Equal(t, limits.MaxProofBytes, optypes.MaxProofAggregateProofBytes)
	withinLimits := func(statements, proofBytes int) bool {
		return (&optypes.ProofAggregatePayload{
			Version:             optypes.ProofAggregatePayloadVersion,
			Through:             1,
			AggregationVkeyHash: optypes.LeanVmTreeClassKeyDigest,
			Statements:          make([]optypes.ProofStatement, statements),
			Proof:               make([]byte, proofBytes),
		}).CheckLimits() == nil
	}
	require.Equal(t, limits.AtLimitsOK, withinLimits(limits.MaxStatements, limits.MaxProofBytes))
	require.Equal(t, limits.PastStatementsOK, withinLimits(limits.MaxStatements+1, limits.MaxProofBytes))
	require.Equal(t, limits.PastProofOK, withinLimits(limits.MaxStatements, limits.MaxProofBytes+1))
}

func TestProofAggregatesMatchKona(t *testing.T) {
	vectors := loadDependencyVectors(t)
	require.NotEmpty(t, vectors.Aggregates)
	for i, v := range vectors.Aggregates {
		p, err := optypes.DecodeProofAggregatePayload(v.Payload)
		require.Equal(t, v.Decodes, err == nil, "aggregate %d (%s) %s: %v", i, v.What, v.Payload, err)
		if err != nil {
			continue
		}
		require.Equal(t, v.Through, p.Through, "aggregate %d", i)
		require.Equal(t, v.Vkey, p.AggregationVkeyHash, "aggregate %d", i)
		require.Equal(t, []byte(v.Proof), p.Proof, "aggregate %d", i)
		require.Len(t, p.Statements, v.StatementCount, "aggregate %d", i)
		var concatenated []byte
		for _, s := range p.Statements {
			concatenated = append(concatenated, s.VkeyHash[:]...)
			concatenated = append(concatenated, s.PublicValuesDigest[:]...)
		}
		require.Equal(t, v.StatementsHash, crypto.Keccak256Hash(concatenated), "aggregate %d", i)
		if v.Statements != nil {
			require.Len(t, v.Statements, v.StatementCount, "aggregate %d", i)
			for j, s := range p.Statements {
				require.Equal(t, v.Statements[j], [2]common.Hash{s.VkeyHash, s.PublicValuesDigest}, "aggregate %d", i)
			}
		}
		require.Equal(t, v.LimitsOK, p.CheckLimits() == nil, "aggregate %d", i)
		tree, err := optypes.DecodeLeanVmTreeProof(p.Proof)
		require.Equal(t, v.TreeProof != nil, err == nil, "aggregate %d (%s) tree proof: %v", i, v.What, err)
		if err == nil {
			require.Equal(t, []byte(v.TreeProof[0]), tree.Root, "aggregate %d root", i)
			require.Equal(t, []byte(v.TreeProof[1]), tree.Seal, "aggregate %d seal", i)
		}
	}
}
