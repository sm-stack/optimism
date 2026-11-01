package types_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2s"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// TestLeanVmTreeClassKeyIsThePinnedClass checks the embedded class key against its pin, the
// BLAKE2s-256 of the key's domain and bytes.
func TestLeanVmTreeClassKeyIsThePinnedClass(t *testing.T) {
	digest := blake2s.Sum256(append([]byte("leanvm/mixed-class-key/v4"), optypes.LeanVmTreeClassKey...))
	require.Equal(t, optypes.LeanVmTreeClassKeyDigest, common.Hash(digest))
}
