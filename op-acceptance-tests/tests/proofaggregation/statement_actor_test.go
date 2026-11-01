package proofaggregation

import (
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum-optimism/optimism/op-core/eip8130"
	"github.com/ethereum-optimism/optimism/op-core/predeploys"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-devstack/sysgo"
	"github.com/ethereum-optimism/optimism/op-service/bigs"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txintent/bindings"
	"github.com/ethereum-optimism/optimism/op-service/txintent/contractio"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestStatementActorSendsForAnAccount has an account configure a leanSPHINCS key as a STATEMENT actor in the
// EIP-8130 Keystore, then send an EIP-8430 transaction that names the account as its sender and is authorized by
// that key: the authorization is the statement that the key signed the sender hash, which the transaction depends
// on. The user hands the sequencer the raw signature, as for any signature statement; the sequencer verifies it,
// op-reth reads the Keystore natively and accepts the actor, and op-aggregator proves the signature when it folds
// the block, which a verifier then derives. Once the account revokes the actor, op-reth refuses it.
func TestStatementActorSendsForAnAccount(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newProofAggregationSystem(t)
	sys.L2Batcher.Start()
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)
	sender := user.Address()

	// The transaction follows the account change that configures the actor. Its sender hash leaves the
	// authorization out, so the key signs it before the account names the key.
	recipient := common.Address{0x82, 0x88}
	tx := baseAaTx(t, sys.L2EL, user, 1)
	tx.Sender = &sender
	tx.Calls = [][]optypes.AaCall{{{To: recipient, Value: big.NewInt(1)}}}
	signed := leanSphincsSign(t, 7, tx.SenderSignatureHash())
	key := common.Hash(signed.PublicKey)
	actor := optypes.StatementAuthorization(signatureProgramDigest, optypes.LeanSphincsTag, key)
	tx.SenderAuth = actor
	dependency, ok := optypes.StatementDependency(actor, tx.SenderSignatureHash())
	t.Require().True(ok)
	t.Require().Equal(signed.Member, dependency.DataHash, "the key's statement over the sender hash")
	t.Require().Equal([]optypes.Dependency{dependency}, tx.Dependencies())

	actorID := eip8130.StatementActorID(signatureProgramDigest, optypes.LeanSphincsTag, key)
	registered := applyAccountChange(t, sys.L2EL, user, 0, authorizeStatementActor, actorID)
	config := eip8130.DecodeActorConfig(storageAt(t, sys.L2EL, eip8130.KeystoreAddress(),
		eip8130.ActorConfigSlot(sender, actorID), bigs.Uint64Strict(registered.BlockNumber)))
	t.Require().Equal(eip8130.StatementAuthenticatorAddress(), config.Authenticator, "the Keystore holds the actor")

	hash := sendWithProof(t, sys.L2EL, tx, fixture{
		vkeyHash:   signatureProgramDigest,
		member:     signed.Member,
		submission: signed.submission(),
	})
	// The same transaction authorized by another key keeps the admission key, the sender hash, but
	// depends on another statement: the pool refuses it.
	swapped := *tx
	swapped.SenderAuth = optypes.StatementAuthorization(signatureProgramDigest, optypes.LeanSphincsTag,
		common.Hash{0x0e})
	raw, err := swapped.MarshalBinary()
	t.Require().NoError(err)
	err = sys.L2EL.Escape().L2EthClient().RPC().CallContext(t.Ctx(), new(common.Hash), "eth_sendRawTransaction",
		hexutil.Bytes(raw))
	t.Require().ErrorContains(err, "must be sent with their proofs")

	receipt := sys.L2EL.WaitForOpReceipt(hash)
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	t.Require().NotNil(receipt.CommittedPhases)
	t.Require().Equal(uint64(1), *receipt.CommittedPhases)
	block := bigs.Uint64Strict(receipt.BlockNumber)
	balance, err := sys.L2EL.Escape().EthClient().BalanceAt(t.Ctx(), recipient, new(big.Int).SetUint64(block))
	t.Require().NoError(err)
	t.Require().Equal(big.NewInt(1), balance, "the account's call ran")

	// The transaction's L1 fee, its dependency's share of the aggregate included, is what the vault received.
	vaultBefore, err := sys.L2EL.Escape().EthClient().BalanceAt(t.Ctx(), predeploys.L1FeeVaultAddr, new(big.Int).SetUint64(block-1))
	t.Require().NoError(err)
	vaultAfter, err := sys.L2EL.Escape().EthClient().BalanceAt(t.Ctx(), predeploys.L1FeeVaultAddr, new(big.Int).SetUint64(block))
	t.Require().NoError(err)
	t.Require().Zero(receipt.L1Fee.Cmp(new(big.Int).Sub(vaultAfter, vaultBefore)), "l1Fee %v", receipt.L1Fee)
	// One dependency, 2,048 L1 bytes at 16 gas, on top of the transaction's own.
	t.Require().Greater(bigs.Uint64Strict(receipt.L1GasUsed), uint64(2_048*16))

	aggregate := waitForPendingAggregate(t, sys.L2EL, block)
	t.Require().Contains(aggregate.Statements,
		optypes.ProofStatement{VkeyHash: signatureProgramDigest, PublicValuesDigest: signed.Member})
	sys.L2ELVerifier.Reached(eth.Safe, block, 180)
	t.Require().Equal(receipt.BlockHash, sys.L2ELVerifier.BlockRefByNumber(block).Hash,
		"the verifier derives the block, the statement-authorized transaction included")

	// The actor still authorizes the account's transactions, until the account revokes it.
	request := map[string]any{
		"type":       "0x79",
		"sender":     sender,
		"senderAuth": hexutil.Bytes(actor),
		"calls":      [][]map[string]any{{{"to": recipient, "value": "0x1", "data": "0x"}}},
	}
	rpc := sys.L2EL.Escape().L2EthClient().RPC()
	var estimate hexutil.Uint64
	t.Require().NoError(rpc.CallContext(t.Ctx(), &estimate, "eth_estimateGas", request))
	var k1Estimate hexutil.Uint64
	k1Request := maps.Clone(request)
	delete(k1Request, "senderAuth")
	t.Require().NoError(rpc.CallContext(t.Ctx(), &k1Estimate, "eth_estimateGas", k1Request))
	t.Require().GreaterOrEqual(uint64(estimate), uint64(k1Estimate)+leanSphincsVerificationGas,
		"it pays for the STATEMENT authentication")
	applyAccountChange(t, sys.L2EL, user, 1, revokeActor, actorID)
	err = rpc.CallContext(t.Ctx(), &estimate, "eth_estimateGas", request)
	t.Require().ErrorContains(err, "the sender's actor is not configured")
}

// TestCreatedAccountSends has the Keystore deploy an account whose only actor is a leanSPHINCS key, so that no
// secp256k1 key ever controls it, and that account send an EIP-8430 transaction. EIP-3607 refuses a key acting for an
// address with code, not the account's actors: the sequencer includes the transaction and a verifier derives it.
func TestCreatedAccountSends(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newProofAggregationSystem(t)
	sys.L2Batcher.Start()
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)

	key := common.Hash(leanSphincsSign(t, 9, common.Hash{}).PublicKey)
	account := createAccount(t, sys.L2EL, user, key)
	user.Transfer(account, eth.OneHundredthEther)

	recipient := common.Address{0x82, 0x89}
	tx := baseAaTx(t, sys.L2EL, user, 0)
	tx.NonceSequence = 1 // what CREATE2 leaves
	tx.Sender = &account
	tx.Calls = [][]optypes.AaCall{{{To: recipient, Value: big.NewInt(1)}}}
	signed := leanSphincsSign(t, 9, tx.SenderSignatureHash())
	tx.SenderAuth = optypes.StatementAuthorization(signatureProgramDigest, optypes.LeanSphincsTag, key)
	hash := sendWithProof(t, sys.L2EL, tx, fixture{
		vkeyHash:   signatureProgramDigest,
		member:     signed.Member,
		submission: signed.submission(),
	})

	receipt := sys.L2EL.WaitForOpReceipt(hash)
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	block := bigs.Uint64Strict(receipt.BlockNumber)
	balance, err := sys.L2EL.Escape().EthClient().BalanceAt(t.Ctx(), recipient, new(big.Int).SetUint64(block))
	t.Require().NoError(err)
	t.Require().Equal(big.NewInt(1), balance, "the account's call ran")
	sys.L2ELVerifier.Reached(eth.Safe, block, 180)
	t.Require().Equal(receipt.BlockHash, sys.L2ELVerifier.BlockRefByNumber(block).Hash,
		"the verifier derives the block, the account's transaction included")
}

// TestRevokedSelfKeyKeepsItsOtherPaths has an EOA move to a leanSPHINCS key and revoke its secp256k1 self key in the
// Keystore. EIP-8130 scopes that revocation to the Keystore's consumers: the key no longer authorizes an EIP-8430
// transaction, but it still signs an ordinary transaction, and an L1 deposit from it spends the account's L2 funds.
// Only an account `createAccount` deploys has no such key.
func TestRevokedSelfKeyKeepsItsOtherPaths(gt *testing.T) {
	t := devtest.SerialT(gt)
	sysgo.SkipOnOpGeth(t, "EIP-8430 transactions are op-reth only")
	sys := presets.NewSingleChainInterop(t, presets.WithOpAggregator())
	l1User := sys.FunderL1.NewFundedEOA(eth.OneEther)
	user := l1User.AsEL(sys.L2ELA)
	sys.FunderA.Fund(user, eth.OneEther)
	sender := user.Address()

	key := common.Hash(leanSphincsSign(t, 11, common.Hash{}).PublicKey)
	actorID := eip8130.StatementActorID(signatureProgramDigest, optypes.LeanSphincsTag, key)
	applyAccountChange(t, sys.L2ELA, user, 0, authorizeStatementActor, actorID)
	applyAccountChange(t, sys.L2ELA, user, 1, revokeActor, common.BytesToHash(sender.Bytes()))

	recipient := sys.FunderA.NewFundedEOA(eth.ZeroWei)
	tx := baseAaTx(t, sys.L2ELA, user, 0)
	tx.Calls = [][]optypes.AaCall{{{To: recipient.Address(), Value: big.NewInt(1)}}}
	sig, err := crypto.Sign(tx.SenderSignatureHash().Bytes(), user.Key().Priv())
	t.Require().NoError(err)
	sig[64] += 27
	tx.SenderAuth = sig
	raw, err := tx.MarshalBinary()
	t.Require().NoError(err)
	err = sys.L2ELA.Escape().L2EthClient().RPC().CallContext(t.Ctx(), new(common.Hash), "eth_sendRawTransaction",
		hexutil.Bytes(raw))
	t.Require().ErrorContains(err, "the sender's actor is not configured", "the Keystore refuses the revoked key")

	user.Transfer(recipient.Address(), eth.OneGWei)
	recipient.VerifyBalanceExact(eth.OneGWei)

	portal := bindings.NewBindings[bindings.OptimismPortal2](bindings.WithClient(sys.L1EL.EthClient()),
		bindings.WithTo(sys.L2ChainA.DepositContractAddr()), bindings.WithTest(t))
	deposit := portal.DepositTransaction(recipient.Address(), eth.OneGWei, 100_000, false, []byte{})
	_, err = contractio.Write(deposit, t.Ctx(), l1User.Plan())
	t.Require().NoError(err, "the L1 deposit")
	recipient.WaitForBalance(eth.OneGWei.Add(eth.OneGWei))
}

// leanSphincsVerificationGas is op-alloy's LEANSPHINCS_VERIFICATION_GAS, what a leanSPHINCS authorization costs over a
// secp256k1 one.
const leanSphincsVerificationGas uint64 = 3_000

// signedMessage is a leanSPHINCS signature as the op-leanvm-tree `sign` example prints it.
type signedMessage struct {
	PublicKey hexutil.Bytes `json:"publicKey"`
	Message   common.Hash   `json:"message"`
	Signature hexutil.Bytes `json:"signature"`
	Member    common.Hash   `json:"member"`
}

// submission is the signature as optimism_sendRawTransactionWithStatementProofs takes it.
func (s signedMessage) submission() map[string]any {
	return map[string]any{
		"type":      "signature",
		"publicKey": s.PublicKey,
		"message":   s.Message,
		"signature": s.Signature,
	}
}

// leanSphincsSign signs message with the leanSPHINCS key of seed, with op-leanvm-tree's `sign` example, which it
// builds first (cargo skips an up-to-date build).
func leanSphincsSign(t devtest.T, seed int, message common.Hash) signedMessage {
	const rustDir = "../../../rust"
	build := exec.CommandContext(t.Ctx(), "cargo", "build", "--locked", "-q", "-p", "op-leanvm-tree",
		"--features", "sequencer", "--example", "sign")
	build.Dir = rustDir
	output, err := build.CombinedOutput()
	t.Require().NoError(err, "build the leanSPHINCS signer: %s", output)
	targetDir := os.Getenv("CARGO_TARGET_DIR")
	if targetDir == "" {
		targetDir = filepath.Join(rustDir, "target")
	}
	out, err := exec.CommandContext(t.Ctx(), filepath.Join(targetDir, "debug", "examples", "sign"),
		strconv.Itoa(seed), message.Hex()).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		t.Require().NoError(err, "sign with leanSPHINCS: %s", exit.Stderr)
	}
	t.Require().NoError(err, "sign with leanSPHINCS")
	var signed signedMessage
	t.Require().NoError(json.Unmarshal(out, &signed))
	t.Require().Len(signed.PublicKey, 32)
	return signed
}

// The Keystore's account change types.
const (
	authorizeStatementActor uint8 = 0 // AuthorizeActor, with the STATEMENT authenticator, no expiry, admin
	revokeActor             uint8 = 1 // RevokeActor
)

// keystoreABI is the part of the Keystore's ABI the test calls.
const keystoreABI = `[{"type":"function","name":"createAccount","inputs":[{"name":"userSalt","type":"bytes32"},{"name":"bytecode","type":"bytes"},{"name":"initialActors","type":"tuple[]","components":[{"name":"actorId","type":"bytes32"},{"name":"authenticator","type":"address"},{"name":"scope","type":"uint16"},{"name":"policyData","type":"bytes"}]}],"outputs":[{"name":"account","type":"address"}],"stateMutability":"nonpayable"},{"type":"function","name":"applySignedAccountChanges","inputs":[{"name":"account","type":"address"},{"name":"batch","type":"tuple","components":[{"name":"channel","type":"uint8"},{"name":"sequence","type":"uint64"},{"name":"changes","type":"tuple[]","components":[{"name":"changeType","type":"uint8"},{"name":"payload","type":"bytes"}]},{"name":"signature","type":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"}]`

// initialActor is a Keystore InitialActor.
type initialActor struct {
	ActorID       [32]byte `abi:"actorId"`
	Authenticator common.Address
	Scope         uint16
	PolicyData    []byte
}

// createAccount has the Keystore deploy an account with a leanSPHINCS key as its only actor, an admin, and returns
// its address.
func createAccount(t devtest.T, el *dsl.L2ELNode, user *dsl.EOA, key common.Hash) common.Address {
	parsed, err := abi.JSON(strings.NewReader(keystoreABI))
	t.Require().NoError(err)
	data, err := parsed.Pack("createAccount", [32]byte{}, []byte{byte(vm.STOP)}, []initialActor{{
		ActorID:       eip8130.StatementActorID(signatureProgramDigest, optypes.LeanSphincsTag, key),
		Authenticator: eip8130.StatementAuthenticatorAddress(),
	}})
	t.Require().NoError(err)
	keystore := eip8130.KeystoreAddress()
	returned, err := el.Escape().EthClient().Call(t.Ctx(), ethereum.CallMsg{To: &keystore, Data: data},
		rpc.LatestBlockNumber)
	t.Require().NoError(err, "createAccount's address")
	account := common.BytesToAddress(returned)
	receipt, err := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&keystore), txplan.WithData(data)).
		Included.Eval(t.Ctx())
	t.Require().NoError(err, "createAccount")
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	return account
}

// accountChange is a Keystore AccountChange.
type accountChange struct {
	ChangeType uint8
	Payload    []byte
}

// signedAccountChanges is a Keystore SignedAccountChanges batch.
type signedAccountChanges struct {
	Channel   uint8
	Sequence  uint64
	Changes   []accountChange
	Signature []byte
}

// applyAccountChange has user sign one change of its Keystore configuration, on the local channel at sequence,
// and relay it.
func applyAccountChange(t devtest.T, el *dsl.L2ELNode, user *dsl.EOA, sequence uint64, changeType uint8,
	actorID common.Hash) *types.Receipt {
	payload := actorID.Bytes()
	if changeType == authorizeStatementActor {
		// abi.encode(actorId, ActorConfig(authenticator, expiry 0, scope 0), "")
		payload = append(payload, common.LeftPadBytes(eip8130.StatementAuthenticatorAddress().Bytes(), 32)...)
		payload = append(payload, make([]byte, 64)...)
		payload = append(payload, common.LeftPadBytes([]byte{0xa0}, 32)...)
		payload = append(payload, make([]byte, 32)...)
	}
	word := func(v uint64) []byte { return common.LeftPadBytes(new(big.Int).SetUint64(v).Bytes(), 32) }
	changeHash := crypto.Keccak256(crypto.Keccak256([]byte("AccountChange(uint8 changeType,bytes payload)")),
		word(uint64(changeType)), crypto.Keccak256(payload))
	chainID, ok := el.ChainID().Uint64()
	t.Require().True(ok)
	digest := crypto.Keccak256(
		crypto.Keccak256([]byte("SignedAccountChangeBatch(address account,uint256 chainId,uint64 sequence,AccountChange[] changes)"+
			"AccountChange(uint8 changeType,bytes payload)")),
		common.LeftPadBytes(user.Address().Bytes(), 32), word(chainID), word(sequence), crypto.Keccak256(changeHash))
	sig, err := crypto.Sign(digest, user.Key().Priv())
	t.Require().NoError(err)
	sig[64] += 27

	parsed, err := abi.JSON(strings.NewReader(keystoreABI))
	t.Require().NoError(err)
	data, err := parsed.Pack("applySignedAccountChanges", user.Address(), signedAccountChanges{
		Sequence:  sequence,
		Changes:   []accountChange{{ChangeType: changeType, Payload: payload}},
		Signature: append(common.BytesToAddress([]byte{1}).Bytes(), sig...),
	})
	t.Require().NoError(err)
	keystore := eip8130.KeystoreAddress()
	receipt, err := txplan.NewPlannedTx(user.Plan(), txplan.WithTo(&keystore), txplan.WithData(data)).
		Included.Eval(t.Ctx())
	t.Require().NoError(err, "applySignedAccountChanges")
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	return receipt
}
