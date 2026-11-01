package aatx

import (
	"math/big"
	"testing"

	"github.com/ethereum-optimism/optimism/op-core/eip8130"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/bigs"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestAaTransactionTransfersValue sends value from an EOA with a self-paid EIP-8430 transaction.
func TestAaTransactionTransfersValue(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)
	recipient := common.Address{0x84, 0x30, 0x1}
	amount := big.NewInt(1_000_000_000)

	tx := aaTx(t, sys.L2EL, user.Address(), [][]optypes.AaCall{{{To: recipient, Value: amount}}})
	signAsSender(t, tx, user.Key().Priv())
	receipt := send(t, sys.L2EL, tx)

	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status)
	t.Require().Equal(uint64(1), *receipt.CommittedPhases)
	t.Require().Equal(user.Address(), *receipt.Payer, "a self-paid transaction's payer is its sender")
	balance, err := sys.L2EL.Escape().EthClient().BalanceAt(t.Ctx(), recipient, receipt.BlockNumber)
	t.Require().NoError(err)
	t.Require().Equal(amount, balance)
}

// TestAaTransactionPaidBySponsor has a named payer pay for a sender that holds no ether and does
// not exist yet. Its second phase calls a contract that reverts: the first phase stays committed,
// the receipt reports one committed phase, and the sender's nonce still advances.
func TestAaTransactionPaidBySponsor(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	payer := sys.FunderL2.NewFundedEOA(eth.OneEther)
	senderKey, err := crypto.GenerateKey()
	t.Require().NoError(err)
	sender := dsl.NewKey(t, senderKey).Address()
	// A contract whose code is REVERT(0, 0).
	deployed, err := txplan.NewPlannedTx(payer.Plan(),
		txplan.WithData(common.FromHex("0x6005"+"80"+"600b"+"6000"+"39"+"6000"+"f3"+"60006000fd"))).Included.Eval(t.Ctx())
	t.Require().NoError(err, "deploy the reverter")
	reverter := deployed.ContractAddress

	tx := aaTx(t, sys.L2EL, sender, [][]optypes.AaCall{
		{{To: common.Address{0x84, 0x30, 0x2}, Value: new(big.Int)}},
		{{To: reverter, Value: new(big.Int)}},
	})
	tx.Payer = payer.Address().Bytes()
	tx.PayerAuth = make([]byte, 85)
	signAsSender(t, tx, senderKey)
	sponsor(t, tx, sender, payer.Key().Priv())

	before := payer.GetBalance()
	receipt := send(t, sys.L2EL, tx)
	t.Require().Equal(types.ReceiptStatusFailed, receipt.Status)
	t.Require().Equal(uint64(1), *receipt.CommittedPhases)
	t.Require().Equal(payer.Address(), *receipt.Payer)
	payer.VerifyBalanceLessThan(before)
	nonce, err := sys.L2EL.Escape().EthClient().NonceAt(t.Ctx(), sender, receipt.BlockNumber)
	t.Require().NoError(err)
	t.Require().Equal(uint64(1), nonce)
}

// TestVerifierDerivesAaTransactionBlock has the batcher post a block holding an EIP-8430
// transaction and a verifier derive it from L1.
func TestVerifierDerivesAaTransactionBlock(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	sys.L2Batcher.Start()
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)

	tx := aaTx(t, sys.L2EL, user.Address(), [][]optypes.AaCall{{{To: common.Address{0x84, 0x30, 0x3}, Value: new(big.Int)}}})
	signAsSender(t, tx, user.Key().Priv())
	receipt := send(t, sys.L2EL, tx)
	block := bigs.Uint64Strict(receipt.BlockNumber)

	sys.L2ELVerifier.Reached(eth.Safe, block, 180)
	t.Require().Equal(sys.L2EL.BlockRefByNumber(block).Hash, sys.L2ELVerifier.BlockRefByNumber(block).Hash,
		"the verifier derives the block with the EIP-8430 transaction")
}

// TestAaTransactionGasIsEstimated estimates an EIP-8430 request with eth_estimateGas (EIP-8430's RPC
// extension: the request carries its calls), sends the transaction with exactly that gas, and sees
// it succeed. eth_call of a request whose phase reverts reports the revert.
func TestAaTransactionGasIsEstimated(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	user := sys.FunderL2.NewFundedEOA(eth.OneEther)
	// A contract that sets storage slot 0 to 1: SSTORE(0, 1); STOP.
	deployed, err := txplan.NewPlannedTx(user.Plan(),
		txplan.WithData(common.FromHex("0x6006"+"80"+"600b"+"6000"+"39"+"6000"+"f3"+"600160005500"))).Included.Eval(t.Ctx())
	t.Require().NoError(err, "deploy the writer")
	writer := deployed.ContractAddress
	reverter, err := txplan.NewPlannedTx(user.Plan(),
		txplan.WithData(common.FromHex("0x6005"+"80"+"600b"+"6000"+"39"+"6000"+"f3"+"60006000fd"))).Included.Eval(t.Ctx())
	t.Require().NoError(err, "deploy the reverter")

	request := func(to common.Address) map[string]any {
		return map[string]any{
			"type":  "0x79",
			"from":  user.Address(),
			"calls": [][]map[string]any{{{"to": to, "value": "0x0", "data": "0x"}}},
		}
	}
	rpc := sys.L2EL.Escape().L2EthClient().RPC()
	var estimate hexutil.Uint64
	t.Require().NoError(rpc.CallContext(t.Ctx(), &estimate, "eth_estimateGas", request(writer)))

	tx := aaTx(t, sys.L2EL, user.Address(), [][]optypes.AaCall{{{To: writer, Value: new(big.Int)}}})
	tx.GasLimit = uint64(estimate)
	signAsSender(t, tx, user.Key().Priv())
	receipt := send(t, sys.L2EL, tx)
	t.Require().Equal(types.ReceiptStatusSuccessful, receipt.Status, "the estimated gas suffices")
	t.Require().LessOrEqual(receipt.GasUsed, uint64(estimate))

	var out hexutil.Bytes
	err = rpc.CallContext(t.Ctx(), &out, "eth_call", request(reverter.ContractAddress), "latest")
	t.Require().ErrorContains(err, "revert")
}

// TestKeystoreIsAtGenesis checks a chain that activates Lagoon at genesis has the contracts the activation
// deposits would have deployed.
func TestKeystoreIsAtGenesis(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	genesis := sys.L2EL.BlockRefByNumber(0).Hash
	for addr, runtime := range map[common.Address][]byte{
		eip8130.KeystoreAddress():               eip8130.KeystoreRuntime(),
		eip8130.StatementAuthenticatorAddress(): eip8130.StatementAuthenticatorRuntime(),
	} {
		code, err := sys.L2EL.Escape().EthClient().CodeAtHash(t.Ctx(), addr, genesis)
		t.Require().NoError(err)
		t.Require().Equal(runtime, code, "%s", addr)
	}
}

// TestNamedSenderNeedsAConfiguredKey sends a transaction naming an account as its sender, signed by a key the
// account never configured in the EIP-8130 Keystore: the signature is valid, but the pool refuses the transaction, so
// nobody can hold another account's nonce or name it to pay.
func TestNamedSenderNeedsAConfiguredKey(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := newAaTxSystem(t)
	victim := sys.FunderL2.NewFundedEOA(eth.OneEther)
	forger := sys.FunderL2.NewFundedEOA(eth.OneEther)

	tx := aaTx(t, sys.L2EL, victim.Address(), [][]optypes.AaCall{{{To: forger.Address(), Value: big.NewInt(1)}}})
	named := victim.Address()
	tx.Sender = &named
	tx.SenderAuth = append(k1Authenticator.Bytes(), k1Signature(t, forger.Key().Priv(), tx.SenderSignatureHash())...)
	raw, err := tx.MarshalBinary()
	t.Require().NoError(err)
	err = sys.L2EL.Escape().L2EthClient().RPC().CallContext(t.Ctx(), new(common.Hash), "eth_sendRawTransaction",
		hexutil.Bytes(raw))
	t.Require().ErrorContains(err, "the sender's actor is not configured")
}
