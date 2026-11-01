package derive

import (
	"math/big"
	"testing"

	"github.com/ethereum-optimism/optimism/op-core/eip8130"
	"github.com/ethereum-optimism/optimism/op-core/forks"
	"github.com/ethereum-optimism/optimism/op-core/predeploys"
	optypes "github.com/ethereum-optimism/optimism/op-core/types"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func TestInteropSetFeatureDeposit(t *testing.T) {
	encoded, err := interopSetFeatureDeposit().MarshalBinary()
	require.NoError(t, err)

	from, dep := toDepositTxn(t, encoded)
	require.Equal(t, L1InfoDepositerAddress, from)
	require.NotNil(t, dep.To())
	require.Equal(t, predeploys.L1BlockAddr, *dep.To())
	require.Equal(t, big.NewInt(0), dep.Value())
	require.Equal(t, big.NewInt(0), dep.Mint())
	require.Equal(t, interopSetFeatureGas, dep.Gas())

	expected := UpgradeDepositSource{Intent: "Interop pre: setFeature(INTEROP)"}
	require.Equal(t, expected.SourceHash(), dep.SourceHash())

	// Calldata: setFeature(bytes32) selector + "INTEROP" right-padded to 32 bytes.
	require.Len(t, dep.Data(), 4+32)
	var expectedFeature [32]byte
	copy(expectedFeature[:], "INTEROP")
	require.Equal(t, expectedFeature[:], dep.Data()[4:])
}

func TestInteropETHLiquidityFundingDeposit(t *testing.T) {
	encoded, err := interopETHLiquidityFundingDeposit().MarshalBinary()
	require.NoError(t, err)

	from, dep := toDepositTxn(t, encoded)
	require.Equal(t, L1InfoDepositerAddress, from)
	require.NotNil(t, dep.To())
	require.Equal(t, predeploys.ETHLiquidityAddr, *dep.To())
	require.Equal(t, InteropETHLiquidityFundingAmount(), dep.Mint())
	require.Equal(t, InteropETHLiquidityFundingAmount(), dep.Value())
	require.Equal(t, interopETHLiquidityFundGas, dep.Gas())

	expected := UpgradeDepositSource{Intent: "Interop post: ETHLiquidity Funding"}
	require.Equal(t, expected.SourceHash(), dep.SourceHash())
}

func TestLagoonActivationUpgradeTransactions(t *testing.T) {
	bundleTxs, gotGas, err := UpgradeTransactions(forks.Lagoon)
	require.NoError(t, err)

	// Derive the expectation from the deposits themselves rather than from the getters under test,
	// so this cannot pass by agreeing with a wrong implementation.
	var bundleTxGas uint64
	for _, tx := range bundleTxs {
		_, dep := toDepositTxn(t, tx)
		bundleTxGas += dep.Gas()
	}
	wantGas := bundleTxGas + interopSetFeatureGas + interopETHLiquidityFundGas +
		keystoreDeployGas + statementAuthenticatorDeployGas
	require.Equal(t, wantGas, gotGas, "UpgradeTransactions must report the full activation reservation")

	// The Keystore deployments follow the bundle on every chain.
	keystoreTxs, err := keystoreDeposits()
	require.NoError(t, err)
	activationTxs := append(append([]hexutil.Bytes{}, bundleTxs...), keystoreTxs...)

	// Only the tx set varies with the dependency set; the reserved gas covers the wrappers either
	// way, so the reconstruction can subtract it without knowing the dependency set.
	singleChainTxs, singleChainGas, err := LagoonActivationUpgradeTransactions(false)
	require.NoError(t, err)
	require.Equal(t, activationTxs, singleChainTxs)
	require.Equal(t, wantGas, singleChainGas)

	multiChainTxs, multiChainGas, err := LagoonActivationUpgradeTransactions(true)
	require.NoError(t, err)
	require.Len(t, multiChainTxs, len(activationTxs)+2)
	require.Equal(t, activationTxs, multiChainTxs[1:len(multiChainTxs)-1])
	require.Equal(t, wantGas, multiChainGas)

	// Only the multi-chain branch's deposits actually sum to the reservation.
	var multiChainTxGas uint64
	for _, tx := range multiChainTxs {
		_, dep := toDepositTxn(t, tx)
		multiChainTxGas += dep.Gas()
	}
	require.Equal(t, wantGas, multiChainTxGas)

	setFeatureTx, err := interopSetFeatureDeposit().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(setFeatureTx), multiChainTxs[0])

	fundingTx, err := interopETHLiquidityFundingDeposit().MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(fundingTx), multiChainTxs[len(multiChainTxs)-1])
}

// TestLagoonUpgradeGasAddEqualsStrip pins the invariant that the gas added to the Lagoon activation
// block's gas limit equals the gas the system-config reconstruction subtracts again for the next
// block. The reconstruction sees only the rollup config and a timestamp — never the dependency set
// — so the added amount must be identical in both the single-chain and multi-chain branches.
func TestLagoonUpgradeGasAddEqualsStrip(t *testing.T) {
	const blockTime = uint64(2)
	lagoonTime := uint64(1000)

	cfg := &rollup.Config{BlockTime: blockTime}
	cfg.ActivateAtGenesis(forks.Karst)
	cfg.SetActivationTime(forks.Lagoon, &lagoonTime)
	require.True(t, cfg.IsActivationBlockForFork(lagoonTime, forks.Lagoon))

	stripped := upgradeGasToStrip(cfg, lagoonTime)
	require.NotZero(t, stripped, "Lagoon must strip a non-zero amount")

	for _, activateInteropContracts := range []bool{false, true} {
		_, added, err := LagoonActivationUpgradeTransactions(activateInteropContracts)
		require.NoError(t, err)
		require.Equalf(t, added, stripped,
			"activateInteropContracts=%v: gas added to the activation block must equal the gas stripped for the next block",
			activateInteropContracts)
	}
}

func TestUpgradeTransactionsInterop(t *testing.T) {
	txs, gas, err := UpgradeTransactions(forks.Lagoon)
	require.NoError(t, err)

	// 26 implementation deployments + L2CM deployment + upgradePredeploys = 28.
	require.Len(t, txs, 28)

	// First tx: StorageSetter implementation deployment (qualified intent).
	first := UpgradeDepositSource{Intent: "Interop 0: Deploy StorageSetter Implementation"}
	_, dep0 := toDepositTxn(t, txs[0])
	require.Equal(t, first.SourceHash(), dep0.SourceHash())

	// Last tx: L2ProxyAdmin upgradePredeploys.
	last := UpgradeDepositSource{Intent: "Interop 27: L2ProxyAdmin Upgrade Predeploys"}
	_, depLast := toDepositTxn(t, txs[len(txs)-1])
	require.Equal(t, last.SourceHash(), depLast.SourceHash())

	// The reserved gas deliberately exceeds these transactions' own limits: it also covers the
	// Keystore deployments and the two wrapper deposits that only a multi-chain activation emits.
	// See UpgradeGas.
	var sumGas uint64
	for _, tx := range txs {
		_, dep := toDepositTxn(t, tx)
		sumGas += dep.Gas()
	}
	require.Equal(t, sumGas+interopSetFeatureGas+interopETHLiquidityFundGas+keystoreDeployGasTotal(), gas)
}

// The Keystore deployments call the deterministic deployment proxy with salt 0 and the committed
// initcode, from the depositor account, so the contracts land at the addresses op-core/eip8130
// computes.
func TestLagoonKeystoreDeployments(t *testing.T) {
	for _, dep := range []*optypes.DepositTx{keystoreDeployDeposit(), statementAuthenticatorDeployDeposit()} {
		require.Equal(t, eip8130.DeterministicDeploymentProxy, *dep.To)
		require.Equal(t, L1InfoDepositerAddress, dep.From)
		require.Zero(t, dep.Mint.Sign())
		require.Zero(t, dep.Value.Sign())
		require.Equal(t, make([]byte, 32), dep.Data[:32])
	}
	require.Equal(t, eip8130.KeystoreInitcode(), keystoreDeployDeposit().Data[32:])
	require.Equal(t, eip8130.StatementAuthenticatorInitcode(), statementAuthenticatorDeployDeposit().Data[32:])

	// The same hashes as kona's `keystore_deployments_follow_the_bundle`.
	txs, err := keystoreDeposits()
	require.NoError(t, err)
	require.Equal(t, common.HexToHash("0x562344a5a0eec51d8df4b158d6e4c8cb33e32e3ff279a400bbbe3e15a2c14a4a"), crypto.Keccak256Hash(txs[0]))
	require.Equal(t, common.HexToHash("0xe5aa8aa037a5bc9285cdeb6de163fa0f47e42765e44a447df351c93eda751aca"), crypto.Keccak256Hash(txs[1]))
}

// deterministicDeploymentProxyCode is the deterministic deployment proxy's runtime (Preinstalls.sol).
var deterministicDeploymentProxyCode = common.FromHex("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3")

// TestLagoonKeystoreDeploymentsFitTheirGas runs both deployments through the deterministic deployment proxy: each
// fits its gas limit with room to spare, the EIP-7623 floor included, and leaves the runtime code genesis installs.
func TestLagoonKeystoreDeploymentsFitTheirGas(t *testing.T) {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	require.NoError(t, err)
	statedb.SetCode(eip8130.DeterministicDeploymentProxy, deterministicDeploymentProxyCode, tracing.CodeChangeUnspecified)
	for _, dep := range []*optypes.DepositTx{keystoreDeployDeposit(), statementAuthenticatorDeployDeposit()} {
		var zeros, nonZeros uint64
		for _, b := range dep.Data {
			if b == 0 {
				zeros++
			} else {
				nonZeros++
			}
		}
		intrinsic := params.TxGas + zeros*params.TxDataZeroGas + nonZeros*params.TxDataNonZeroGasEIP2028
		floor := params.TxGas + (zeros+nonZeros*4)*params.TxCostFloorPerToken
		require.Less(t, floor, dep.Gas)
		_, left, err := runtime.Call(*dep.To, dep.Data, &runtime.Config{
			ChainConfig: params.MergedTestChainConfig,
			Origin:      dep.From,
			GasLimit:    dep.Gas - intrinsic,
			State:       statedb,
		})
		require.NoError(t, err)
		used := dep.Gas - left
		require.Less(t, used, dep.Gas*9/10, "deployment uses %d of %d gas", used, dep.Gas)
	}
	for addr, want := range eip8130.GenesisAccounts() {
		require.Equal(t, want.Code, statedb.GetCode(addr))
		require.Equal(t, want.Nonce, statedb.GetNonce(addr))
	}
}
