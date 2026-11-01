package proofaggregation

import (
	"fmt"
	"math/big"
	"time"

	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/retry"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// consumerRuntime is a contract that acts on a statement its caller's transaction depends on: it
// asks the Transaction Context precompile (EIP-8430) whether the transaction declares the data
// hash and verifying key passed in its calldata (`isTransactionDependency(vk, data)`), and if so
// sets storage slot 0 to 1. Otherwise it reverts.
const consumerRuntime = "638dd4ca91" + "60e0" + "1b" + "6000" + "52" + // MSTORE(0, selector << 224)
	"6020" + "35" + "6004" + "52" + // MSTORE(4, vk_hash = calldata[32:64])
	"6000" + "35" + "6024" + "52" + // MSTORE(36, data_hash = calldata[0:32])
	"6020" + "6000" + "6044" + "6000" + "73813000000000000000000000000000000000aa02" + "5a" + "fa" + // STATICCALL
	"15" + "6047" + "57" + // fail if the call failed
	"6000" + "51" + "15" + "6047" + "57" + // fail if not declared
	"6001" + "6000" + "55" + "00" + // SSTORE(0, 1); STOP
	"5b" + "6000" + "80" + "fd" // fail: REVERT(0, 0)

// consumerInitCode deploys consumerRuntime (76 bytes, after these 11).
const consumerInitCode = "0x604c" + "80" + "600b" + "6000" + "39" + "6000" + "f3" + consumerRuntime

// chain is the part of a devstack system the proof aggregation flow drives.
type chain struct {
	EL     *dsl.L2ELNode
	Funder *dsl.FunderEOA
}

// deployConsumer deploys the consumer contract from user.
func deployConsumer(t devtest.T, user *dsl.EOA) common.Address {
	deployed, err := txplan.NewPlannedTx(user.Plan(), txplan.WithData(common.FromHex(consumerInitCode))).
		Included.Eval(t.Ctx())
	t.Require().NoError(err, "deploy the consumer")
	return deployed.ContractAddress
}

// dependentTx is an EIP-8430 transaction from user that declares the fixture's statement as an
// EIP-8288 dependency and calls consumer, which acts on it. The user signs and pays.
func dependentTx(t devtest.T, el *dsl.L2ELNode, user *dsl.EOA, consumer common.Address, f fixture) *optypes.AaTx {
	tx := baseAaTx(t, el, user, 0)
	tx.AccountChanges = []optypes.AccountChange{{
		Type: optypes.AccountChangeDependencies,
		Dependencies: []optypes.Dependency{{
			Scheme:              optypes.ProofStatementScheme,
			DataHash:            f.member,
			VerificationKeyHash: f.vkeyHash,
		}},
	}}
	tx.Calls = [][]optypes.AaCall{{{To: consumer, Value: new(big.Int), Data: append(f.member[:], f.vkeyHash[:]...)}}}
	sig, err := crypto.Sign(tx.SenderSignatureHash().Bytes(), user.Key().Priv())
	t.Require().NoError(err)
	sig[64] += 27
	tx.SenderAuth = sig
	return tx
}

// baseAaTx is an unsigned EIP-8430 transaction from user, at its pending nonce plus ahead, with fees
// for the current base fee and no account changes or calls.
func baseAaTx(t devtest.T, el *dsl.L2ELNode, user *dsl.EOA, ahead uint64) *optypes.AaTx {
	head, err := el.Escape().EthClient().InfoByLabel(t.Ctx(), eth.Unsafe)
	t.Require().NoError(err)
	nonce, err := el.Escape().EthClient().PendingNonceAt(t.Ctx(), user.Address())
	t.Require().NoError(err)
	chainID, ok := el.ChainID().Uint64()
	t.Require().True(ok, "chain ID does not fit a uint64")
	tip := big.NewInt(1_000_000)
	return &optypes.AaTx{
		ChainID:              chainID,
		NonceKey:             new(big.Int),
		NonceSequence:        nonce + ahead,
		MaxPriorityFeePerGas: tip,
		MaxFeePerGas:         new(big.Int).Add(new(big.Int).Mul(head.BaseFee(), big.NewInt(2)), tip),
		GasLimit:             500_000,
	}
}

// sendWithProof hands tx and the source of its dependency to the sequencer.
func sendWithProof(t devtest.T, el *dsl.L2ELNode, tx *optypes.AaTx, f fixture) common.Hash {
	t.Require().NoError(trySendWithProof(t, el, tx, f), "optimism_sendRawTransactionWithStatementProofs")
	return tx.Hash()
}

// trySendWithProof is sendWithProof, returning the sequencer's refusal.
func trySendWithProof(t devtest.T, el *dsl.L2ELNode, tx *optypes.AaTx, f fixture) error {
	raw, err := tx.MarshalBinary()
	t.Require().NoError(err)
	var sent common.Hash
	err = el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &sent,
		"optimism_sendRawTransactionWithStatementProofs", hexutil.Bytes(raw), []map[string]any{f.submission})
	if err == nil {
		t.Require().Equal(tx.Hash(), sent)
	}
	return err
}

// pendingAggregate is an aggregate as admin_pendingProofAggregates returns it.
type pendingAggregate struct {
	Version    uint8                    `json:"version"`
	Through    hexutil.Uint64           `json:"through"`
	Statements []optypes.ProofStatement `json:"statements"`
}

// pendingAggregates returns the aggregates the sequencer hands the batcher.
func pendingAggregates(t devtest.T, el *dsl.L2ELNode) []pendingAggregate {
	var pending []pendingAggregate
	err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &pending, "admin_pendingProofAggregates")
	t.Require().NoError(err, "admin_pendingProofAggregates")
	return pending
}

// waitForPendingAggregate waits until the sequencer hands the batcher an aggregate answering
// for block `block`, as admin_pendingProofAggregates returns it, and returns it.
func waitForPendingAggregate(t devtest.T, el *dsl.L2ELNode, block uint64) pendingAggregate {
	aggregate, err := retry.Do(t.Ctx(), 60, &retry.FixedStrategy{Dur: time.Second}, func() (pendingAggregate, error) {
		var pending []pendingAggregate
		if err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &pending, "admin_pendingProofAggregates"); err != nil {
			return pendingAggregate{}, err
		}
		for _, p := range pending {
			if uint64(p.Through) >= block {
				return p, nil
			}
		}
		return pendingAggregate{}, fmt.Errorf("no pending aggregate through block %d", block)
	})
	t.Require().NoError(err, "admin_pendingProofAggregates")
	return aggregate
}

// requireOnlyDeposits requires block number on el to hold deposits and nothing else.
func requireOnlyDeposits(t devtest.T, el *dsl.L2ELNode, number uint64) {
	_, txs, err := el.Escape().EthClient().InfoAndTxsByNumber(t.Ctx(), number)
	t.Require().NoError(err)
	t.Require().NotEmpty(txs, "the L1 attributes deposit")
	for _, tx := range txs {
		t.Require().Equal(uint8(optypes.DepositTxType), tx.Type(), "block %d holds %s", number, tx.Hash())
	}
}

// storageAt reads a storage slot of address at block.
func storageAt(t devtest.T, el *dsl.L2ELNode, address common.Address, slot common.Hash, block uint64) common.Hash {
	value, err := el.Escape().EthClient().GetStorageAt(t.Ctx(), address, slot, hexutil.Uint64(block).String())
	t.Require().NoError(err, "eth_getStorageAt")
	return value
}
