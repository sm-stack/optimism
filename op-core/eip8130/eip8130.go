// Package eip8130 holds the EIP-8130 Keystore and the OP Stack STATEMENT authenticator that Lagoon deploys: their
// bytecode (built from packages/eip8130), their addresses, and the Keystore storage layout of an actor, for tests to
// read. op-revm reads the Keystore natively; no Go client does.
package eip8130

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum-optimism/optimism/op-core/predeploys"
)

var (
	//go:embed keystore.initcode.hex
	keystoreInitcodeHex string
	//go:embed keystore.runtime.hex
	keystoreRuntimeHex string
	//go:embed statement_authenticator.initcode.hex
	statementAuthenticatorInitcodeHex string
	//go:embed statement_authenticator.runtime.hex
	statementAuthenticatorRuntimeHex string

	keystoreInitcode               = mustDecode(keystoreInitcodeHex)
	keystoreRuntime                = mustDecode(keystoreRuntimeHex)
	statementAuthenticatorInitcode = mustDecode(statementAuthenticatorInitcodeHex)
	statementAuthenticatorRuntime  = mustDecode(statementAuthenticatorRuntimeHex)

	keystoreAddress               = create2Address(keystoreInitcode)
	statementAuthenticatorAddress = create2Address(statementAuthenticatorInitcode)
)

// DeterministicDeploymentProxy is the CREATE2 deployer preinstall both contracts are deployed through, with salt 0.
var DeterministicDeploymentProxy = predeploys.DeterministicDeploymentProxyAddr

func mustDecode(hex string) []byte {
	return hexutil.MustDecode("0x" + strings.TrimSpace(hex))
}

// KeystoreInitcode returns the Keystore's creation bytecode.
func KeystoreInitcode() []byte { return bytes.Clone(keystoreInitcode) }

// KeystoreRuntime returns the Keystore's runtime bytecode, for a chain whose genesis activates Lagoon.
func KeystoreRuntime() []byte { return bytes.Clone(keystoreRuntime) }

// StatementAuthenticatorInitcode returns the STATEMENT authenticator's creation bytecode.
func StatementAuthenticatorInitcode() []byte { return bytes.Clone(statementAuthenticatorInitcode) }

// StatementAuthenticatorRuntime returns the STATEMENT authenticator's runtime bytecode.
func StatementAuthenticatorRuntime() []byte { return bytes.Clone(statementAuthenticatorRuntime) }

// create2Address is where the deterministic deployment proxy deploys initcode with salt 0.
func create2Address(initcode []byte) common.Address {
	return crypto.CreateAddress2(DeterministicDeploymentProxy, [32]byte{}, crypto.Keccak256(initcode))
}

// KeystoreAddress returns KEYSTORE_ADDRESS.
func KeystoreAddress() common.Address { return keystoreAddress }

// StatementAuthenticatorAddress returns the STATEMENT authenticator's address.
func StatementAuthenticatorAddress() common.Address { return statementAuthenticatorAddress }

// DeploymentData returns the calldata that has the deterministic deployment proxy deploy initcode: salt 0, then the
// initcode.
func DeploymentData(initcode []byte) []byte {
	return append(make([]byte, 32), initcode...)
}

// GenesisAccounts returns the accounts Lagoon's activation deposits create, for a chain that activates Lagoon at
// genesis and so never runs them: each contract at its address with its runtime code and the nonce a contract
// creation leaves. Neither has a constructor, immutables or storage, so these are the accounts the deposits create;
// only the nonces of the deposits' sender and of the proxy, which the deposits bump, differ.
func GenesisAccounts() types.GenesisAlloc {
	return types.GenesisAlloc{
		KeystoreAddress():               {Code: KeystoreRuntime(), Nonce: 1, Balance: new(big.Int)},
		StatementAuthenticatorAddress(): {Code: StatementAuthenticatorRuntime(), Nonce: 1, Balance: new(big.Int)},
	}
}

// actorsSlot holds the Keystore's `_actors` mapping, actorId => account => ActorRecord
// (packages/eip8130/storage-layout.txt).
var actorsSlot = common.Hash{}

func mappingSlot(key common.Hash, slot common.Hash) common.Hash {
	return crypto.Keccak256Hash(key[:], slot[:])
}

// ActorConfigSlot returns the storage slot of actor_config(account, actorId) in the Keystore; the actor's policy
// manager is the next slot.
func ActorConfigSlot(account common.Address, actorID common.Hash) common.Hash {
	return mappingSlot(common.BytesToHash(account.Bytes()), mappingSlot(actorID, actorsSlot))
}

// ActorConfig is an actor's packed configuration: authenticator, expiry (Unix seconds, 0 for none) and scope.
type ActorConfig struct {
	Authenticator common.Address
	Expiry        uint64
	Scope         uint16
}

// DecodeActorConfig unpacks an actor_config slot (solc packing: authenticator in the low 20 bytes, then expiry,
// then scope).
func DecodeActorConfig(word common.Hash) ActorConfig {
	return ActorConfig{
		Authenticator: common.BytesToAddress(word[12:32]),
		Expiry:        uint48(word[6:12]),
		Scope:         binary.BigEndian.Uint16(word[4:6]),
	}
}

func uint48(b []byte) uint64 {
	var buf [8]byte
	copy(buf[2:], b)
	return binary.BigEndian.Uint64(buf[:])
}

// StatementActorID returns the actorId of a STATEMENT actor: keccak256("op-stmt-auth" || vk || tag || key).
func StatementActorID(vk common.Hash, tag [8]byte, key common.Hash) common.Hash {
	return crypto.Keccak256Hash([]byte("op-stmt-auth"), vk[:], tag[:], key[:])
}
