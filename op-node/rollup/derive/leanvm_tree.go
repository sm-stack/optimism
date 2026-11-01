package derive

import (
	"fmt"
	"sync"

	"github.com/sm-stack/go-zkvm-verifier/experimental/leanvmclaims"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// NewLeanVmTreeVerifier authenticates classKey, the leanVM tree class key, against
// optypes.LeanVmTreeClassKeyDigest and op-leanvm-tree's ZK_PLACEMENT, zero-knowledge first levels
// in the tree's shared tier, and returns the verifier of the proof aggregates it roots, as
// op-leanvm-tree's LeanVmTreeVerifier: a statement is the claim labelled by its verifying key
// digest whose member is its public values digest, and the statements must be listed in the
// canonical order of the root's claim set, each once.
func NewLeanVmTreeVerifier(classKey []byte) (ProofAggregateVerifier, error) {
	v, err := leanvmclaims.NewClassVerifierWithPlacement(classKey, optypes.LeanVmTreeClassKeyDigest, leanvmclaims.ZKShared)
	if err != nil {
		return nil, fmt.Errorf("leanVM tree class key: %w", err)
	}
	return func(statements []optypes.ProofStatement, root, seal []byte) error {
		converted := make([]leanvmclaims.Statement, len(statements))
		for i, s := range statements {
			converted[i] = leanvmclaims.Statement{VkeyHash: s.VkeyHash, PublicValuesDigest: s.PublicValuesDigest}
		}
		claims, err := leanvmclaims.ClaimsFromStatements(converted)
		if err != nil {
			return fmt.Errorf("statements are not in canonical order, each once: %w", err)
		}
		return v.VerifySealed(claims, root, seal)
	}, nil
}

var leanVmTreeVerifier = sync.OnceValues(func() (ProofAggregateVerifier, error) {
	return NewLeanVmTreeVerifier(optypes.LeanVmTreeClassKey)
})

// LeanVmTreeVerifier returns the verifier of the pinned class (optypes.LeanVmTreeClassKey), built
// once per process: op-supernode's virtual nodes, and every restart of one, share it.
func LeanVmTreeVerifier() (ProofAggregateVerifier, error) { return leanVmTreeVerifier() }
