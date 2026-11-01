//! Module containing the Interop network upgrade activation.
//!
//! Interop's activation block always executes the Interop NUT bundle. Chains in a
//! multi-chain dependency set additionally wrap the bundle with:
//!  1. A pre-bundle `L1Block.setFeature(INTEROP)` call.
//!  2. A post-bundle `ETHLiquidity` funding deposit with mint and value set to `u128::MAX`.
//!
//! Every chain also deploys the EIP-8130 Keystore and the STATEMENT authenticator right after the
//! bundle, through the deterministic deployment proxy (salt 0).

use alloc::{string::String, vec::Vec};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256, address, keccak256};
use kona_genesis::Predeploys;
use op_alloy_consensus::{TxDeposit, UpgradeDepositSource, keystore};

use crate::Hardfork;

include!(concat!(env!("OUT_DIR"), "/interop_nut_bundle.rs"));

/// The depositor account that may invoke `L1Block.setFeature`.
/// Matches the per-fork constant used by ecotone/isthmus/jovian.
const DEPOSITOR_ACCOUNT: Address = address!("0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");

/// Gas limit for the pre-bundle `setFeature(INTEROP)` wrapper tx.
const SET_FEATURE_GAS: u64 = 100_000;
/// Gas limit for the post-bundle `ETHLiquidity` funding wrapper tx.
const ETH_LIQUIDITY_FUND_GAS: u64 = 50_000;
/// Bootstrap mint and value for the post-bundle `ETHLiquidity` funding deposit.
const ETH_LIQUIDITY_FUND_AMOUNT: u128 = u128::MAX;

/// Gas limit for the Keystore deployment.
const KEYSTORE_DEPLOY_GAS: u64 = 3_000_000;
/// Gas limit for the STATEMENT authenticator deployment.
const STATEMENT_AUTHENTICATOR_DEPLOY_GAS: u64 = 300_000;

/// `bytes32` representation of the INTEROP feature constant (right-padded ASCII).
const INTEROP_FEATURE: [u8; 32] = *b"INTEROP\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// The Lagoon hardfork.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lagoon;

impl Lagoon {
    /// Returns the pre-bundle `L1Block.setFeature(INTEROP)` deposit.
    fn set_feature_tx() -> TxDeposit {
        let selector = &keccak256(b"setFeature(bytes32)")[..4];
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(selector);
        data.extend_from_slice(&INTEROP_FEATURE);

        let source =
            UpgradeDepositSource { intent: String::from("Interop pre: setFeature(INTEROP)") };
        TxDeposit {
            source_hash: source.source_hash(),
            from: DEPOSITOR_ACCOUNT,
            to: TxKind::Call(Predeploys::L1_BLOCK_INFO),
            mint: 0,
            value: U256::ZERO,
            gas_limit: SET_FEATURE_GAS,
            is_system_transaction: false,
            input: Bytes::from(data),
        }
    }

    /// Returns the post-bundle `ETHLiquidity` funding deposit.
    fn eth_liquidity_funding_tx() -> TxDeposit {
        let selector = Bytes::copy_from_slice(&keccak256(b"fund()")[..4]);

        let source =
            UpgradeDepositSource { intent: String::from("Interop post: ETHLiquidity Funding") };
        TxDeposit {
            source_hash: source.source_hash(),
            from: DEPOSITOR_ACCOUNT,
            to: TxKind::Call(Predeploys::ETH_LIQUIDITY),
            mint: ETH_LIQUIDITY_FUND_AMOUNT,
            value: U256::from(ETH_LIQUIDITY_FUND_AMOUNT),
            gas_limit: ETH_LIQUIDITY_FUND_GAS,
            is_system_transaction: false,
            input: selector,
        }
    }

    /// Returns a deposit having the deterministic deployment proxy deploy `initcode`.
    fn deployment_tx(intent: &str, gas_limit: u64, initcode: &[u8]) -> TxDeposit {
        TxDeposit {
            source_hash: UpgradeDepositSource { intent: String::from(intent) }.source_hash(),
            from: DEPOSITOR_ACCOUNT,
            to: TxKind::Call(keystore::DETERMINISTIC_DEPLOYMENT_PROXY),
            mint: 0,
            value: U256::ZERO,
            gas_limit,
            is_system_transaction: false,
            input: keystore::deployment_data(initcode),
        }
    }

    /// Returns the deposits deploying the Keystore and the STATEMENT authenticator.
    fn keystore_deposits() -> [TxDeposit; 2] {
        [
            Self::deployment_tx(
                "Lagoon: deploy EIP-8130 Keystore",
                KEYSTORE_DEPLOY_GAS,
                &keystore::keystore_initcode(),
            ),
            Self::deployment_tx(
                "Lagoon: deploy STATEMENT authenticator",
                STATEMENT_AUTHENTICATOR_DEPLOY_GAS,
                &keystore::statement_authenticator_initcode(),
            ),
        ]
    }

    /// Returns the JSON bundle deposit transactions that execute on every
    /// Interop activation block, even for single-chain dependency sets.
    fn bundle_deposits() -> Vec<TxDeposit> {
        let bundle = interop_nut_bundle();
        bundle.to_deposit_transactions().expect("Interop NUT bundle is invalid")
    }

    /// Returns the gas the wrapper deposits occupy in the activation block. Summed from the
    /// deposits themselves, so the reservation cannot drift from what they actually cost.
    fn wrapper_gas() -> u64 {
        Self::set_feature_tx().gas_limit + Self::eth_liquidity_funding_tx().gas_limit
    }

    /// Returns the gas the Keystore deployments occupy in the activation block.
    const fn keystore_gas() -> u64 {
        KEYSTORE_DEPLOY_GAS + STATEMENT_AUTHENTICATOR_DEPLOY_GAS
    }

    /// Returns all deposit transactions for the Interop activation block.
    pub fn deposits(activate_interop_contracts: bool) -> Vec<TxDeposit> {
        let bundle_deposits = Self::bundle_deposits();
        let wrapper_count = if activate_interop_contracts { 2 } else { 0 };
        let mut deposits = Vec::with_capacity(wrapper_count + bundle_deposits.len() + 2);
        if activate_interop_contracts {
            deposits.push(Self::set_feature_tx());
        }
        deposits.extend(bundle_deposits);
        deposits.extend(Self::keystore_deposits());
        if activate_interop_contracts {
            deposits.push(Self::eth_liquidity_funding_tx());
        }
        deposits
    }

    /// Returns the encoded Interop activation transactions for a chain.
    pub fn txs_for_activation(
        &self,
        activate_interop_contracts: bool,
    ) -> impl Iterator<Item = Bytes> + '_ {
        Self::deposits(activate_interop_contracts).into_iter().map(|tx| {
            let mut encoded = Vec::new();
            tx.encode_2718(&mut encoded);
            Bytes::from(encoded)
        })
    }
}

impl Hardfork for Lagoon {
    fn txs(&self) -> impl Iterator<Item = Bytes> + '_ {
        self.txs_for_activation(true)
    }

    /// Returns the gas added to the Lagoon activation block's gas limit.
    ///
    /// This covers the bundle and the Keystore deployments, and always the `setFeature` and
    /// `ETHLiquidity` funding wrappers, even for a single-chain activation that does not emit
    /// them, so that the amount cannot vary with the dependency set — which the system config
    /// reconstructed from the block never sees.
    fn upgrade_gas(&self) -> u64 {
        interop_nut_bundle().total_gas() + Self::wrapper_gas() + Self::keystore_gas()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, b256};

    #[test]
    fn deposits_have_correct_count() {
        // 1 setFeature + 28 bundle txs + 2 Keystore deployments + 1 ETHLiquidity funding = 32
        assert_eq!(Lagoon::deposits(true).len(), 32);
        assert_eq!(Lagoon::deposits(false).len(), 30);
    }

    #[test]
    fn first_tx_is_set_feature() {
        let deps = Lagoon::deposits(true);
        assert_eq!(deps[0].to, TxKind::Call(Predeploys::L1_BLOCK_INFO));
        assert_eq!(deps[0].mint, 0);
        assert_eq!(deps[0].value, U256::ZERO);
        let expected =
            UpgradeDepositSource { intent: String::from("Interop pre: setFeature(INTEROP)") }
                .source_hash();
        assert_eq!(deps[0].source_hash, expected);
    }

    #[test]
    fn last_tx_is_eth_liquidity_funding_with_max_mint_and_value() {
        let deps = Lagoon::deposits(true);
        let last = deps.last().unwrap();
        assert_eq!(last.to, TxKind::Call(Predeploys::ETH_LIQUIDITY));
        assert_eq!(last.mint, u128::MAX);
        assert_eq!(last.value, U256::from(u128::MAX));
    }

    #[test]
    fn upgrade_gas_sums_all_three_pieces() {
        // The wrappers are reserved unconditionally, so a single-chain activation emits only the
        // bundle's deposits but still reserves gas for the wrappers it skips.
        let bundle_gas = interop_nut_bundle().total_gas();
        assert_eq!(
            Lagoon {}.upgrade_gas(),
            bundle_gas + SET_FEATURE_GAS + ETH_LIQUIDITY_FUND_GAS + Lagoon::keystore_gas()
        );
    }

    #[test]
    fn first_bundle_tx_uses_qualified_intent() {
        let deps = Lagoon::deposits(true);
        // deps[0] = wrapper, deps[1] = first bundle tx
        // The build script generates the bundle with a capitalized fork name
        // ("interop" → "Interop"), so the qualified intent on the kona side is
        // "Interop 0: ...". This matches the hardcoded intent literals in
        // op-node's lagoon_activation_transactions.go to preserve
        // source_hash determinism. The bundle prefix stays concept-level
        // "Interop" even though the fork was renamed to Lagoon.
        let expected_intent = "Interop 0: Deploy StorageSetter Implementation";
        let expected = UpgradeDepositSource { intent: String::from(expected_intent) }.source_hash();
        assert_eq!(deps[1].source_hash, expected);
    }

    /// The Keystore deployments follow the bundle and call the deterministic deployment proxy with
    /// salt 0 and the committed initcode (op-node: `TestLagoonKeystoreDeployments`).
    #[test]
    fn keystore_deployments_follow_the_bundle() {
        let deps = Lagoon::deposits(false);
        let [keystore_tx, authenticator_tx] = deps.last_chunk::<2>().unwrap();
        for tx in [keystore_tx, authenticator_tx] {
            assert_eq!(tx.to, TxKind::Call(keystore::DETERMINISTIC_DEPLOYMENT_PROXY));
            assert_eq!(tx.from, DEPOSITOR_ACCOUNT);
            assert_eq!(&tx.input[..32], &[0u8; 32]);
        }
        assert_eq!(&keystore_tx.input[32..], keystore::keystore_initcode().as_slice());
        assert_eq!(
            &authenticator_tx.input[32..],
            keystore::statement_authenticator_initcode().as_slice()
        );
        // The same hashes as op-node's `TestLagoonKeystoreDeployments`.
        let hash = |tx: &TxDeposit| keccak256(tx.encoded_2718());
        for (tx, expected) in
            [(keystore_tx, KEYSTORE_DEPOSIT_HASH), (authenticator_tx, AUTHENTICATOR_DEPOSIT_HASH)]
        {
            assert_eq!(hash(tx), expected);
        }

        // A multi-chain activation wraps the same deposits.
        let wrapped = Lagoon::deposits(true);
        assert_eq!(wrapped[1..wrapped.len() - 1], deps[..]);
    }

    const KEYSTORE_DEPOSIT_HASH: B256 =
        b256!("0x562344a5a0eec51d8df4b158d6e4c8cb33e32e3ff279a400bbbe3e15a2c14a4a");
    const AUTHENTICATOR_DEPOSIT_HASH: B256 =
        b256!("0xe5aa8aa037a5bc9285cdeb6de163fa0f47e42765e44a447df351c93eda751aca");
}
