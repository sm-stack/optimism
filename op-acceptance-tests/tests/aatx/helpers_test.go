package aatx

import (
	"crypto/ecdsa"
	"math/big"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// k1Authenticator selects native secp256k1 authentication in a named identity's auth blob.
var k1Authenticator = common.BytesToAddress([]byte{1})

// aaTx is an unsigned, self-paid EIP-8430 transaction from sender running phases, at the
// sender's pending nonce and twice the current base fee.
func aaTx(t devtest.T, el *dsl.L2ELNode, sender common.Address, phases [][]optypes.AaCall) *optypes.AaTx {
	head, err := el.Escape().EthClient().InfoByLabel(t.Ctx(), eth.Unsafe)
	t.Require().NoError(err)
	nonce, err := el.Escape().EthClient().PendingNonceAt(t.Ctx(), sender)
	t.Require().NoError(err)
	chainID, ok := el.ChainID().Uint64()
	t.Require().True(ok, "chain ID does not fit a uint64")
	tip := big.NewInt(1_000_000)
	return &optypes.AaTx{
		ChainID:              chainID,
		NonceKey:             new(big.Int),
		NonceSequence:        nonce,
		MaxPriorityFeePerGas: tip,
		MaxFeePerGas:         new(big.Int).Add(new(big.Int).Mul(head.BaseFee(), big.NewInt(2)), tip),
		GasLimit:             200_000,
		Calls:                phases,
	}
}

// k1Signature is key's signature over digest as an authorization carries it: r || s || v, v 27
// or 28.
func k1Signature(t devtest.T, key *ecdsa.PrivateKey, digest common.Hash) []byte {
	sig, err := crypto.Sign(digest.Bytes(), key)
	t.Require().NoError(err)
	sig[64] += 27
	return sig
}

// signAsSender fills the sender authorization of tx, whose sender is recovered.
func signAsSender(t devtest.T, tx *optypes.AaTx, key *ecdsa.PrivateKey) {
	tx.SenderAuth = k1Signature(t, key, tx.SenderSignatureHash())
}

// sponsor names payer and fills its authorization, after the sender signed: the payer hash covers
// the resolved sender.
func sponsor(t devtest.T, tx *optypes.AaTx, sender common.Address, payer *ecdsa.PrivateKey) {
	tx.PayerAuth = append(k1Authenticator.Bytes(), k1Signature(t, payer, tx.PayerSignatureHash(sender))...)
}

// send submits tx through eth_sendRawTransaction and waits for its receipt.
func send(t devtest.T, el *dsl.L2ELNode, tx *optypes.AaTx) *optypes.Receipt {
	raw, err := tx.MarshalBinary()
	t.Require().NoError(err)
	var hash common.Hash
	err = el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &hash, "eth_sendRawTransaction", hexutil.Bytes(raw))
	t.Require().NoError(err, "eth_sendRawTransaction")
	t.Require().Equal(tx.Hash(), hash)
	receipt := el.WaitForOpReceipt(hash)
	t.Require().Equal(uint8(optypes.AaTxType), receipt.Type)
	t.Require().NotNil(receipt.CommittedPhases)
	return receipt
}
