package proofaggregation

import (
	"crypto/sha256"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum-optimism/optimism/op-acceptance-tests/tests/sdm/sdmtest"
	"github.com/ethereum-optimism/optimism/op-chain-ops/devkeys"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txplan"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// proofRegistry is the ProofRegistry predeploy.
var proofRegistry = common.HexToAddress("0x4200000000000000000000000000000000000031")

const proofRegistryABI = `[
	{"type":"function","name":"submitStatement","stateMutability":"payable","inputs":[{"name":"_vkeyHash","type":"bytes32"},{"name":"_publicValues","type":"bytes"}],"outputs":[{"name":"statementId_","type":"bytes32"}]},
	{"type":"function","name":"setAggregationVkeyHash","stateMutability":"nonpayable","inputs":[{"name":"_aggregationVkeyHash","type":"bytes32"}],"outputs":[]},
	{"type":"function","name":"setBlobGasPerStatement","stateMutability":"nonpayable","inputs":[{"name":"_blobGasPerStatement","type":"uint256"}],"outputs":[]},
	{"type":"function","name":"statementFee","stateMutability":"view","inputs":[],"outputs":[{"name":"fee_","type":"uint256"}]},
	{"type":"function","name":"isVerified","stateMutability":"view","inputs":[{"name":"_vkeyHash","type":"bytes32"},{"name":"_publicValuesDigest","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}]}
]`

func registryABI(t devtest.T) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(proofRegistryABI))
	t.Require().NoError(err)
	return parsed
}

func pack(t devtest.T, method string, args ...any) []byte {
	data, err := registryABI(t).Pack(method, args...)
	t.Require().NoError(err, "pack %s", method)
	return data
}

// callRegistry runs a view call on the registry at the latest block and decodes its single output.
func callRegistry(t devtest.T, el *dsl.L2ELNode, method string, args ...any) any {
	var out hexutil.Bytes
	err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &out, "eth_call",
		map[string]any{"to": proofRegistry, "data": hexutil.Bytes(pack(t, method, args...))}, "latest")
	t.Require().NoError(err, "eth_call %s", method)
	values, err := registryABI(t).Unpack(method, out)
	t.Require().NoError(err, "unpack %s", method)
	t.Require().Len(values, 1)
	return values[0]
}

// configureRegistry has the L2 ProxyAdmin owner set the aggregation program and the blob gas
// each statement pays for.
func configureRegistry(t devtest.T, sys *sdmtest.RethSystem, aggregationVkeyHash common.Hash, blobGasPerStatement uint64) {
	priv := sys.L2Network.Escape().Keys().Secret(devkeys.L2ProxyAdminOwnerRole.Key(sys.L2Network.ChainID().ToBig()))
	owner := dsl.NewKey(t, priv).User(sys.L2EL)
	sys.FunderL2.Fund(owner, eth.OneEther)

	owner.Transact(owner.Plan(), txplan.WithTo(&proofRegistry),
		txplan.WithData(pack(t, "setAggregationVkeyHash", aggregationVkeyHash)))
	owner.Transact(owner.Plan(), txplan.WithTo(&proofRegistry),
		txplan.WithData(pack(t, "setBlobGasPerStatement", new(big.Int).SetUint64(blobGasPerStatement))))
}

// submitStatement registers the fixture's statement on chain, paying the current fee.
func submitStatement(t devtest.T, sys *sdmtest.RethSystem, user *dsl.EOA, f fixture) {
	fee := callRegistry(t, sys.L2EL, "statementFee").(*big.Int)
	t.Require().Positive(fee.Sign(), "configured registry charges a fee")
	user.Transact(user.Plan(), txplan.WithTo(&proofRegistry),
		txplan.WithValue(eth.WeiBig(fee)),
		txplan.WithData(pack(t, "submitStatement", f.vkeyHash, f.publicValues)))
}

func isVerified(t devtest.T, el *dsl.L2ELNode, f fixture) bool {
	return callRegistry(t, el, "isVerified", f.vkeyHash, sha256.Sum256(f.publicValues)).(bool)
}

// submitStatementProof hands the statement's proof to the sequencer off chain.
func submitStatementProof(t devtest.T, el *dsl.L2ELNode, f fixture) common.Hash {
	var id common.Hash
	err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &id, "optimism_submitStatementProof",
		common.Hash(f.vkeyHash), hexutil.Bytes(f.publicValues), hexutil.Bytes(f.proof), hexutil.Bytes(f.verifyingKey))
	t.Require().NoError(err, "optimism_submitStatementProof")
	return id
}

type rpcStatement struct {
	VkeyHash           common.Hash `json:"vkeyHash"`
	PublicValuesDigest common.Hash `json:"publicValuesDigest"`
}

type rpcStatementProof struct {
	Statement rpcStatement `json:"statement"`
}

func pendingStatementProofs(t devtest.T, el *dsl.L2ELNode) []rpcStatementProof {
	var out []rpcStatementProof
	err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), &out, "admin_pendingStatementProofs")
	t.Require().NoError(err, "admin_pendingStatementProofs")
	return out
}

// submitAggregate hands the aggregator's proof over the fixture's statement to the sequencer, as
// the proof-aggregator process does.
func submitAggregate(t devtest.T, el *dsl.L2ELNode, f fixture) {
	aggregate := map[string]any{
		"aggregationVkeyHash": common.HexToHash(f.aggregationVkeyHash),
		"statements": []rpcStatement{{
			VkeyHash:           f.vkeyHash,
			PublicValuesDigest: sha256.Sum256(f.publicValues),
		}},
		"proof": hexutil.Bytes(f.aggregateProof),
	}
	err := el.Escape().L2EthClient().RPC().CallContext(t.Ctx(), nil, "admin_submitProofAggregate", aggregate)
	t.Require().NoError(err, "admin_submitProofAggregate")
}

// waitForProofAggregateBlock returns the number of the first block after `from` that carries a
// proof aggregate (0x7C) transaction, checking it directly follows the deposits.
func waitForProofAggregateBlock(t devtest.T, el *dsl.L2ELNode, from uint64) uint64 {
	deadline := time.Now().Add(2 * time.Minute)
	next := from + 1
	for time.Now().Before(deadline) {
		head := el.BlockRefByLabel(eth.Unsafe).Number
		for ; next <= head; next++ {
			block := sdmtest.GetBlockWithTxs(t, el, next)
			for i, tx := range block.Transactions {
				if uint64(tx.Type) != optypes.ProofAggregateTxType {
					continue
				}
				for _, prev := range block.Transactions[:i] {
					t.Require().Equal(uint64(optypes.DepositTxType), uint64(prev.Type),
						"proof aggregate must directly follow the deposits")
				}
				return next
			}
		}
		time.Sleep(time.Second)
	}
	t.Require().FailNow("no proof aggregate transaction was included")
	return 0
}
