package eip8130

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
)

// The addresses op-alloy computes (`keystore::tests::addresses`); a change to the bytecode moves them.
func TestAddresses(t *testing.T) {
	require.Equal(t, common.HexToAddress(keystoreAddressHex), KeystoreAddress())
	require.Equal(t, common.HexToAddress(statementAuthenticatorAddressHex), StatementAuthenticatorAddress())
	require.Equal(t, StatementAuthenticatorAddress(), optypes.StatementAuthenticator)
	require.NotEmpty(t, KeystoreRuntime())
	require.NotEmpty(t, StatementAuthenticatorRuntime())
}

func TestDecodeActorConfig(t *testing.T) {
	// authenticator 0x..01, expiry 0x010203040506, scope 0x0004, packed by solc from the low bytes up.
	word := common.HexToHash("0x00000000" + "0004" + "010203040506" + "0000000000000000000000000000000000000001")
	require.Equal(t, ActorConfig{Authenticator: common.BytesToAddress([]byte{1}), Expiry: 0x010203040506, Scope: 4},
		DecodeActorConfig(word))
}

// The Keystore slots of a STATEMENT actor, as `cast index` computes them (op-alloy: `keystore::tests::slots`).
func TestSlots(t *testing.T) {
	account := common.HexToAddress("0x1111111111111111111111111111111111111111")
	id := StatementActorID(common.HexToHash("0x22"), [8]byte([]byte("sphmem01")), common.HexToHash("0x33"))
	require.Equal(t, common.HexToHash("0x7811d9b527880533ecaeaff2a300b408a411b7fa4f4688770d087925c4864773"), id)
	require.Equal(t, common.HexToHash("0xf2e218404c42f94d94bb72c5b35d468c08c50fe9d45b9ec2804794dcfb7137d1"),
		ActorConfigSlot(account, id))
}

// TestBytecodeIsBuilt rebuilds packages/eip8130 and compares the bytecode with the committed hex, when forge is
// available.
func TestBytecodeIsBuilt(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the contracts")
	}
	forge, err := exec.LookPath("forge")
	if err != nil {
		t.Skip("forge is not installed")
	}
	root, err := filepath.Abs("../../packages/eip8130")
	require.NoError(t, err)
	out := t.TempDir()
	cmd := exec.Command(forge, "build", "--root", root, "--out", out, "--cache-path", t.TempDir())
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	for _, c := range []struct {
		name              string
		initcode, runtime []byte
	}{
		{"Keystore", KeystoreInitcode(), KeystoreRuntime()},
		{"StatementAuthenticator", StatementAuthenticatorInitcode(), StatementAuthenticatorRuntime()},
	} {
		artifact, err := os.ReadFile(filepath.Join(out, c.name+".sol", c.name+".json"))
		require.NoError(t, err)
		require.Contains(t, string(artifact), strings.TrimPrefix(common.Bytes2Hex(c.initcode), "0x"), c.name)
		require.Contains(t, string(artifact), common.Bytes2Hex(c.runtime), c.name)
	}
}

func TestGenesisAccounts(t *testing.T) {
	accounts := GenesisAccounts()
	require.Len(t, accounts, 2)
	require.Equal(t, KeystoreRuntime(), accounts[KeystoreAddress()].Code)
	require.Equal(t, StatementAuthenticatorRuntime(), accounts[StatementAuthenticatorAddress()].Code)
	for _, account := range accounts {
		require.Equal(t, uint64(1), account.Nonce)
		require.Empty(t, account.Storage)
	}
}

const (
	keystoreAddressHex               = "0x209DaD6e0B17969725C2c7847A70c58Fe442C521"
	statementAuthenticatorAddressHex = "0xC5EF79AD4605c55B7f65328Fdd5Cc7c485679Bc0"
)
