//! Execution tests for EIP-8430 transactions.

use super::{AaTxEnv, AaTxOutcome};
use crate::{
    DefaultOp, OpBuilder, OpSpecId, OpTransaction,
    api::default_ctx::OpContext,
    constants::L1_FEE_RECIPIENT,
    transaction::{OpTransactionError, error::AaTxInvalid},
};
use alloy_eips::Encodable2718;
use k256::ecdsa::SigningKey;
use op_alloy_consensus::{
    AaCall, AccountChange, Dependency, K1_AUTHENTICATOR, PROOF_STATEMENT_SCHEME, Payer,
    StatementActor, TX_CONTEXT_ADDRESS, TxEip8430, keystore,
};
use revm::{
    Context, ExecuteEvm,
    bytecode::Bytecode,
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::result::{EVMError, ExecutionResult, InvalidTransaction},
    database::InMemoryDB,
    primitives::{Address, B256, Bytes, TxKind, U256, address, keccak256},
    state::{AccountInfo, EvmState},
};
use std::{sync::Arc, vec, vec::Vec};

const CHAIN_ID: u64 = 10;
const RECIPIENT: Address = address!("0x00000000000000000000000000000000000b0b00");
const CONTRACT: Address = address!("0x00000000000000000000000000000000000c0c00");
const CONTRACT2: Address = address!("0x00000000000000000000000000000000000c0c01");
const DELEGATE: Address = address!("0x00000000000000000000000000000000000d0d00");
const FUNDS: u64 = 1_000_000_000_000_000_000;
const TIMESTAMP: u64 = 1_000;

/// `SSTORE(slot, value)` then `STOP`.
fn sstore_code(slot: u8, value: u8) -> Bytes {
    Bytes::from(vec![0x60, value, 0x60, slot, 0x55, 0x00])
}

/// `LOG0(0, 0)` then `STOP`.
fn log_code() -> Bytes {
    Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xa0, 0x00])
}

/// `REVERT(0, 0)`.
fn revert_code() -> Bytes {
    Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd])
}

/// Calls the Transaction Context precompile with `selector || args` and stores the first returned
/// word at `slot`, and the call's success at `slot + 1`.
fn context_reader_code(selector: [u8; 4], args: &[B256], slot: u8) -> Bytes {
    let mut code = vec![0x63];
    code.extend_from_slice(&selector);
    code.extend_from_slice(&[0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52]); // MSTORE(0, selector << 224)
    for (index, arg) in args.iter().enumerate() {
        code.push(0x7f);
        code.extend_from_slice(arg.as_slice());
        code.extend_from_slice(&[0x60, 4 + 32 * index as u8, 0x52]);
    }
    // STATICCALL(gas, TX_CONTEXT, 0, 4 + 32 * args, 0, 32)
    code.extend_from_slice(&[0x60, 0x20, 0x60, 0x00, 0x60, 4 + 32 * args.len() as u8, 0x60, 0x00]);
    code.push(0x73);
    code.extend_from_slice(TX_CONTEXT_ADDRESS.as_slice());
    code.extend_from_slice(&[0x5a, 0xfa]);
    code.extend_from_slice(&[0x60, slot + 1, 0x55]); // SSTORE(slot + 1, success)
    code.extend_from_slice(&[0x60, 0x00, 0x51, 0x60, slot, 0x55, 0x00]); // SSTORE(slot, MLOAD(0))
    code.into()
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn key_address(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// `r || s || v` with `v` 27 or 28.
fn k1_signature(key: &SigningKey, digest: B256) -> Vec<u8> {
    let (signature, recovery) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(27 + recovery.to_byte());
    bytes
}

fn account(balance: u64, code: Option<Bytes>) -> AccountInfo {
    let mut info = AccountInfo { balance: U256::from(balance), ..Default::default() };
    if let Some(code) = code {
        info = info.with_code(Bytecode::new_raw(code));
    }
    info
}

fn call(to: Address) -> AaCall {
    AaCall { to, value: U256::ZERO, data: Bytes::new() }
}

fn aa_tx(calls: Vec<Vec<AaCall>>) -> TxEip8430 {
    TxEip8430 {
        chain_id: CHAIN_ID,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 10,
        gas_limit: 500_000,
        calls,
        ..Default::default()
    }
}

/// Signs `tx` as `key`'s recovered sender.
fn sign(mut tx: TxEip8430, key: &SigningKey) -> TxEip8430 {
    tx.sender_auth = k1_signature(key, tx.sender_signature_hash()).into();
    tx
}

/// Names `payer` and signs `tx` for it, after the sender signed.
fn sponsor(mut tx: TxEip8430, sender: Address, payer: &SigningKey) -> TxEip8430 {
    let mut auth = K1_AUTHENTICATOR.to_vec();
    auth.extend(k1_signature(payer, tx.payer_signature_hash(sender)));
    tx.payer_auth = auth.into();
    tx
}

fn op_tx(tx: &TxEip8430, sender: Address) -> OpTransaction<TxEnv> {
    OpTransaction {
        base: TxEnv {
            tx_type: 0x79,
            caller: sender,
            gas_limit: tx.effective_gas_limit(),
            gas_price: tx.max_fee_per_gas,
            gas_priority_fee: Some(tx.max_priority_fee_per_gas),
            kind: TxKind::Call(sender),
            nonce: tx.nonce_sequence,
            chain_id: Some(tx.chain_id),
            ..Default::default()
        },
        enveloped_tx: Some(tx.encoded_2718().into()),
        deposit: Default::default(),
        aa: Some(Arc::new(AaTxEnv::new(tx.clone()))),
    }
}

fn context(db: InMemoryDB, spec: OpSpecId) -> OpContext<InMemoryDB> {
    let mut cfg = CfgEnv::new_with_spec(spec);
    cfg.chain_id = CHAIN_ID;
    Context::op().with_db(db).with_cfg(cfg).with_block(BlockEnv {
        gas_limit: 30_000_000,
        basefee: 2,
        timestamp: U256::from(TIMESTAMP),
        ..Default::default()
    })
}

type Outcome = Result<
    (ExecutionResult<crate::OpHaltReason>, EvmState),
    EVMError<core::convert::Infallible, OpTransactionError>,
>;

fn run_at(db: InMemoryDB, tx: &TxEip8430, sender: Address, spec: OpSpecId) -> Outcome {
    let mut evm = context(db, spec).build_op();
    evm.transact(op_tx(tx, sender)).map(|r| (r.result, r.state))
}

fn run(db: InMemoryDB, tx: &TxEip8430, sender: Address) -> Outcome {
    run_at(db, tx, sender, OpSpecId::LAGOON)
}

fn outcome(result: &ExecutionResult<crate::OpHaltReason>) -> AaTxOutcome {
    AaTxOutcome::decode(result.output().expect("output")).expect("outcome")
}

fn invalid(result: Outcome) -> AaTxInvalid {
    match result {
        Err(EVMError::Transaction(OpTransactionError::AaTx(reason))) => reason,
        other => panic!("expected an invalid EIP-8430 transaction, got {other:?}"),
    }
}

fn storage(state: &EvmState, address: Address, slot: u64) -> U256 {
    state
        .get(&address)
        .and_then(|account| account.storage.get(&U256::from(slot)))
        .map_or(U256::ZERO, |slot| slot.present_value)
}

fn funded_sender(db: &mut InMemoryDB, key: &SigningKey) -> Address {
    let sender = key_address(key);
    db.insert_account_info(sender, account(FUNDS, None));
    sender
}

#[test]
fn outcome_round_trip() {
    let outcome =
        AaTxOutcome { payer: Address::repeat_byte(7), committed_phases: 3, success: true };
    assert_eq!(AaTxOutcome::decode(&outcome.encode()), Some(outcome));
    assert_eq!(AaTxOutcome::decode(&[0; 28]), None);
    let mut bad = outcome.encode();
    bad[28] = 2;
    assert_eq!(AaTxOutcome::decode(&bad), None);
}

#[test]
fn self_paid_call_charges_intrinsic_and_execution_gas() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(CONTRACT, account(0, Some(sstore_code(0, 7))));

    let tx = sign(aa_tx(vec![vec![call(CONTRACT)]]), &key);
    let (result, state) = run(db, &tx, sender).unwrap();

    let outcome = outcome(&result);
    assert_eq!(outcome, AaTxOutcome { payer: sender, committed_phases: 1, success: true });
    assert_eq!(storage(&state, CONTRACT, 0), U256::from(7));
    assert_eq!(state[&sender].info.nonce, 1);
    // A cold target (2,600) and a fresh SSTORE (22,100) after two pushes.
    let gas_used = result.tx_gas_used();
    assert_eq!(gas_used, tx.sender_intrinsic_gas(sender) + 2_600 + 6 + 22_100);
    // Priority fee 1 on top of base fee 2.
    assert_eq!(state[&sender].info.balance, U256::from(FUNDS - gas_used * 3));
}

#[test]
fn a_reverting_phase_stops_the_transaction_and_keeps_earlier_phases() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(CONTRACT, account(0, Some(log_code())));
    db.insert_account_info(CONTRACT2, account(0, Some(sstore_code(0, 1))));
    db.insert_account_info(RECIPIENT, account(0, Some(revert_code())));

    let tx = sign(
        aa_tx(vec![
            vec![call(CONTRACT)],
            vec![call(CONTRACT2), call(RECIPIENT)],
            vec![call(CONTRACT2)],
        ]),
        &key,
    );
    let (result, state) = run(db, &tx, sender).unwrap();

    let outcome = outcome(&result);
    assert_eq!(outcome.committed_phases, 1);
    assert!(!outcome.success);
    // Phase 0's log survives; phase 1's write is undone with its failed call, and phase 2 does
    // not run.
    assert_eq!(result.logs().len(), 1);
    assert_eq!(storage(&state, CONTRACT2, 0), U256::ZERO);
    assert_eq!(state[&sender].info.nonce, 1);
}

#[test]
fn a_named_payer_pays_the_fees() {
    let key = signing_key(0x11);
    let payer_key = signing_key(0x22);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let payer = funded_sender(&mut db, &payer_key);
    db.insert_account_info(RECIPIENT, account(0, None));

    let mut transfer = call(RECIPIENT);
    transfer.value = U256::from(1_000);
    let mut tx = aa_tx(vec![vec![transfer]]);
    tx.payer = Payer::Named(payer);
    tx.payer_auth = Bytes::from(vec![0; 85]);
    let tx = sponsor(sign(tx, &key), sender, &payer_key);
    let (result, state) = run(db, &tx, sender).unwrap();

    assert_eq!(outcome(&result).payer, payer);
    assert!(outcome(&result).success);
    assert_eq!(state[&RECIPIENT].info.balance, U256::from(1_000));
    assert_eq!(state[&sender].info.balance, U256::from(FUNDS - 1_000));
    let gas_used = result.tx_gas_used();
    assert!(gas_used >= tx.sender_intrinsic_gas(sender) + tx.payer_auth_cost());
    assert_eq!(state[&payer].info.balance, U256::from(FUNDS - gas_used * 3));
}

/// A named payer's signature by a key the payer did not configure.
#[test]
fn a_payer_signature_by_another_key_is_invalid() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let payer = funded_sender(&mut db, &signing_key(0x22));

    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.payer = Payer::Named(payer);
    tx.payer_auth = Bytes::from(vec![0; 85]);
    let tx = sponsor(sign(tx, &key), sender, &signing_key(0x33));
    assert_eq!(invalid(run(db, &tx, sender)), AaTxInvalid::PayerActor);
}

#[test]
fn validity_rules() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);

    let tx = sign(aa_tx(vec![vec![call(RECIPIENT)]]), &key);
    assert_eq!(invalid(run_at(db.clone(), &tx, sender, OpSpecId::KARST)), AaTxInvalid::NotActive);

    let mut expired = aa_tx(vec![vec![call(RECIPIENT)]]);
    expired.valid_before = TIMESTAMP - 1;
    let expired = sign(expired, &key);
    assert_eq!(invalid(run(db.clone(), &expired, sender)), AaTxInvalid::OutsideValidityWindow);

    let mut channel = aa_tx(vec![vec![call(RECIPIENT)]]);
    channel.nonce_key = U256::from(1);
    let channel = sign(channel, &key);
    assert!(matches!(invalid(run(db.clone(), &channel, sender)), AaTxInvalid::Static(_)));

    let mut stale = aa_tx(vec![vec![call(RECIPIENT)]]);
    stale.nonce_sequence = 1;
    let stale = sign(stale, &key);
    assert!(matches!(
        run(db.clone(), &stale, sender),
        Err(EVMError::Transaction(OpTransactionError::Base(_)))
    ));

    let mut short = aa_tx(vec![vec![call(RECIPIENT)]]);
    short.gas_limit = 20_000;
    let short = sign(short, &key);
    assert!(matches!(
        run(db, &short, sender),
        Err(EVMError::Transaction(OpTransactionError::Base(_)))
    ));
}

#[test]
fn the_delegation_entry_sets_the_senders_code() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(DELEGATE, account(0, Some(sstore_code(5, 9))));

    let mut tx = aa_tx(vec![vec![call(sender)]]);
    tx.account_changes = vec![AccountChange::Delegation { target: DELEGATE }];
    let tx = sign(tx, &key);
    let (result, state) = run(db, &tx, sender).unwrap();

    assert!(outcome(&result).success);
    let code = state[&sender].info.code.clone().unwrap();
    assert_eq!(code.eip7702_address(), Some(DELEGATE));
    // The call to the sender ran the delegate's code in the sender's storage.
    assert_eq!(storage(&state, sender, 5), U256::from(9));
    assert_eq!(state[&sender].info.nonce, 1);
}

#[test]
fn the_context_precompile_reports_the_transaction() {
    let key = signing_key(0x11);
    let payer_key = signing_key(0x22);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let payer = funded_sender(&mut db, &payer_key);
    let vk = B256::repeat_byte(0xaa);
    let data = B256::repeat_byte(0xdd);
    let readers = [
        context_reader_code([0xbe, 0xad, 0x3f, 0x50], &[], 0),
        context_reader_code([0x69, 0x0b, 0x3a, 0x9d], &[], 2),
        context_reader_code([0x0b, 0x08, 0x9f, 0x96], &[], 4),
        context_reader_code([0x8d, 0xd4, 0xca, 0x91], &[vk, data], 6),
        context_reader_code([0x8d, 0xd4, 0xca, 0x91], &[vk, B256::repeat_byte(0xee)], 8),
    ];
    let addresses: Vec<Address> =
        (0..readers.len()).map(|i| Address::with_last_byte(0xc0 + i as u8)).collect();
    for (address, code) in addresses.iter().zip(readers) {
        db.insert_account_info(*address, account(0, Some(code)));
    }

    let mut tx = aa_tx(vec![addresses.iter().map(|a| call(*a)).collect()]);
    tx.account_changes = vec![AccountChange::Dependencies {
        dependencies: vec![
            Dependency {
                scheme: PROOF_STATEMENT_SCHEME,
                data_hash: data,
                verification_key_hash: vk,
            },
            Dependency {
                scheme: PROOF_STATEMENT_SCHEME,
                data_hash: B256::ZERO,
                verification_key_hash: vk,
            },
        ],
    }];
    tx.gas_limit = 1_000_000;
    tx.payer = Payer::Named(payer);
    tx.payer_auth = Bytes::from(vec![0; 85]);
    let tx = sponsor(sign(tx, &key), sender, &payer_key);
    let (result, state) = run(db, &tx, sender).unwrap();
    assert!(outcome(&result).success, "{result:?}");

    let word = |reader: usize, slot: u64| storage(&state, addresses[reader], slot);
    for (reader, slot) in [(0, 1), (1, 3), (2, 5), (3, 7), (4, 9)] {
        assert_eq!(word(reader, slot), U256::from(1), "call {reader} succeeded");
    }
    assert_eq!(word(0, 0), U256::from_be_slice(sender.as_slice()));
    assert_eq!(word(1, 2), U256::from_be_slice(payer.as_slice()));
    assert_eq!(word(2, 4), U256::from(2));
    assert_eq!(word(3, 6), U256::from(1));
    assert_eq!(word(4, 8), U256::ZERO);
}

#[test]
fn the_context_precompile_substitutes_the_self_reference() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let vk = B256::repeat_byte(0xaa);
    // A zero data hash declares the transaction's own sender hash.
    let mut tx = aa_tx(vec![vec![call(CONTRACT)]]);
    tx.account_changes = vec![AccountChange::Dependencies {
        dependencies: vec![Dependency {
            scheme: PROOF_STATEMENT_SCHEME,
            data_hash: B256::ZERO,
            verification_key_hash: vk,
        }],
    }];
    let sender_hash = tx.sender_signature_hash();
    db.insert_account_info(
        CONTRACT,
        account(0, Some(context_reader_code([0x8d, 0xd4, 0xca, 0x91], &[vk, sender_hash], 0))),
    );
    let tx = sign(tx, &key);
    let (result, state) = run(db, &tx, sender).unwrap();
    assert!(outcome(&result).success);
    assert_eq!(storage(&state, CONTRACT, 1), U256::from(1));
    assert_eq!(storage(&state, CONTRACT, 0), U256::from(1));
}

#[test]
fn the_context_precompile_reports_the_origin_for_other_transactions() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(
        CONTRACT,
        account(0, Some(context_reader_code([0x69, 0x0b, 0x3a, 0x9d], &[], 0))),
    );
    let mut evm = context(db, OpSpecId::LAGOON).build_op();
    let tx = OpTransaction::builder()
        .base(
            TxEnv::builder()
                .caller(sender)
                .kind(TxKind::Call(CONTRACT))
                .gas_limit(100_000)
                .gas_price(10)
                .chain_id(Some(CHAIN_ID)),
        )
        .build_fill();
    let result = evm.transact(tx).unwrap();
    assert!(result.result.is_success(), "{:?}", result.result);
    assert_eq!(storage(&result.state, CONTRACT, 1), U256::from(1));
    assert_eq!(storage(&result.state, CONTRACT, 0), U256::from_be_slice(sender.as_slice()));
}

/// `MSTORE(0x100, 0x2a)` then `STOP`.
fn mstore_code() -> Bytes {
    Bytes::from(vec![0x60, 0x2a, 0x61, 0x01, 0x00, 0x52, 0x00])
}

/// `SSTORE(0, MSIZE)` then `STOP`.
fn store_msize_code() -> Bytes {
    Bytes::from(vec![0x59, 0x60, 0x00, 0x55, 0x00])
}

/// `INVALID`.
fn halt_code() -> Bytes {
    Bytes::from(vec![0xfe])
}

#[test]
fn every_call_starts_with_empty_memory() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(CONTRACT, account(0, Some(mstore_code())));
    db.insert_account_info(CONTRACT2, account(0, Some(store_msize_code())));

    let tx = sign(aa_tx(vec![vec![call(CONTRACT), call(CONTRACT2)]]), &key);
    let (result, state) = run(db, &tx, sender).unwrap();

    assert!(outcome(&result).success);
    assert_eq!(storage(&state, CONTRACT2, 0), U256::ZERO, "the second call sees no memory");
}

#[test]
fn the_effective_gas_limit_is_capped() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);

    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.gas_limit = revm::primitives::eip7825::TX_GAS_LIMIT_CAP + 1;
    let tx = sign(tx, &key);
    assert!(matches!(
        run(db, &tx, sender),
        Err(EVMError::Transaction(OpTransactionError::Base(
            revm::context_interface::result::InvalidTransaction::TxGasLimitGreaterThanCap { .. }
        )))
    ));
}

#[test]
fn a_value_the_sender_cannot_cover_fails_its_phase_without_consuming_gas() {
    let key = signing_key(0x11);
    let payer_key = signing_key(0x22);
    let mut db = InMemoryDB::default();
    let sender = key_address(&key);
    db.insert_account_info(sender, account(10, None));
    let payer = funded_sender(&mut db, &payer_key);
    db.insert_account_info(RECIPIENT, account(1, None));

    let mut transfer = call(RECIPIENT);
    transfer.value = U256::from(11);
    let mut tx = aa_tx(vec![vec![transfer]]);
    tx.payer = Payer::Named(payer);
    tx.payer_auth = Bytes::from(vec![0; 85]);
    let tx = sponsor(sign(tx, &key), sender, &payer_key);
    let (result, state) = run(db, &tx, sender).unwrap();

    assert_eq!(outcome(&result).committed_phases, 0);
    assert_eq!(state[&RECIPIENT].info.balance, U256::from(1));
    // The access to the cold recipient is all the call used; the calldata floor binds above it.
    let used = tx.sender_intrinsic_gas(sender) + 2_600 + tx.payer_auth_cost();
    let floor = tx.sender_floor(sender) + tx.payer_gas_reserve();
    assert_eq!(result.tx_gas_used(), used.max(floor));
    assert_eq!(state[&payer].info.balance, U256::from(FUNDS - result.tx_gas_used() * 3));
}

#[test]
fn a_halting_call_consumes_the_pool() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(CONTRACT, account(0, Some(halt_code())));

    let tx = sign(aa_tx(vec![vec![call(CONTRACT)]]), &key);
    let (result, _) = run(db, &tx, sender).unwrap();

    assert!(!outcome(&result).success);
    assert_eq!(result.tx_gas_used(), tx.gas_limit);
}

#[test]
fn the_calldata_floor_binds_a_cheap_transaction() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);

    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.metadata = Bytes::from(vec![0xff; 2_000]);
    let tx = sign(tx, &key);
    let (result, _) = run(db, &tx, sender).unwrap();

    let floor = tx.sender_floor(sender);
    assert!(floor > tx.sender_intrinsic_gas(sender) + 2_600);
    assert_eq!(result.tx_gas_used(), floor);
    assert_eq!(result.gas().floor_gas(), floor);
}

fn simulate(db: InMemoryDB, tx: &TxEip8430, sender: Address) -> Outcome {
    let mut op_tx = op_tx(tx, sender);
    op_tx.aa = Some(Arc::new(AaTxEnv::simulation(tx.clone())));
    let mut evm = context(db, OpSpecId::LAGOON).build_op();
    evm.transact(op_tx).map(|r| (r.result, r.state))
}

/// `MSTORE(0, 0x2a); RETURN(0, 32)`.
fn return_code() -> Bytes {
    Bytes::from(vec![0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3])
}

/// A simulation verifies no signature (a named payer pays on a placeholder authorization),
/// returns the last call's output, and ends a reverting phase as a revert.
#[test]
fn a_simulation_returns_call_output_and_reverts_with_its_phase() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let payer = funded_sender(&mut db, &signing_key(0x22));
    db.insert_account_info(CONTRACT, account(0, Some(return_code())));
    db.insert_account_info(CONTRACT2, account(0, Some(revert_code())));

    let mut tx = aa_tx(vec![vec![call(CONTRACT)]]);
    tx.payer = Payer::Named(payer);
    tx.payer_auth = [&K1_AUTHENTICATOR[..], &[0xff; 65]].concat().into();
    tx.sender_auth = Bytes::from(vec![0xff; 65]);
    let (result, state) = simulate(db.clone(), &tx, sender).unwrap();
    assert!(result.is_success(), "{result:?}");
    assert_eq!(result.output().unwrap().as_ref(), U256::from(0x2a).to_be_bytes::<32>());
    assert!(state[&payer].info.balance < U256::from(FUNDS), "the named payer pays");

    tx.calls = vec![vec![call(CONTRACT)], vec![call(CONTRACT2)]];
    let (result, _) = simulate(db, &tx, sender).unwrap();
    assert!(matches!(result, ExecutionResult::Revert { .. }), "{result:?}");
}

/// A simulation pays the environment's prices, whatever fee caps shape its transaction.
#[test]
fn a_simulation_pays_the_requested_price() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.max_fee_per_gas = u64::MAX as u128;
    tx.max_priority_fee_per_gas = u64::MAX as u128;
    tx.sender_auth = Bytes::from(vec![0xff; 65]);
    let mut op_tx = op_tx(&tx, sender);
    op_tx.base.gas_price = 2;
    op_tx.base.gas_priority_fee = Some(0);
    op_tx.aa = Some(Arc::new(AaTxEnv::simulation(tx)));
    let mut evm = context(db, OpSpecId::LAGOON).build_op();
    let result = evm.transact(op_tx).unwrap();
    assert!(result.result.is_success(), "{:?}", result.result);
    let paid = U256::from(FUNDS) - result.state[&sender].info.balance;
    assert_eq!(paid, U256::from(result.result.tx_gas_used() * 2));
}

/// Only a simulation is a simulation.
#[test]
fn a_transaction_is_not_a_simulation() {
    let tx = aa_tx(vec![vec![call(CONTRACT)]]);
    assert!(!AaTxEnv::new(tx.clone()).is_simulation());
    assert!(AaTxEnv::simulation(tx).is_simulation());
}

// The Keystore.

fn keystore_word(authenticator: Address, expiry: u64, scope: u16) -> U256 {
    let mut word = [0u8; 32];
    word[4..6].copy_from_slice(&scope.to_be_bytes());
    word[6..12].copy_from_slice(&expiry.to_be_bytes()[2..]);
    word[12..].copy_from_slice(authenticator.as_slice());
    U256::from_be_bytes(word)
}

fn keystore_slot(db: &mut InMemoryDB, slot: U256, value: U256) {
    if !db.cache.accounts.contains_key(&keystore::KEYSTORE_ADDRESS) {
        db.insert_account_info(
            keystore::KEYSTORE_ADDRESS,
            account(0, Some(keystore::keystore_runtime().into())),
        );
    }
    db.insert_account_storage(keystore::KEYSTORE_ADDRESS, slot, value).unwrap();
}

/// Configures `actor` for `account`, with `manager` as its policy manager.
fn configure(
    db: &mut InMemoryDB,
    account: Address,
    id: B256,
    authenticator: Address,
    expiry: u64,
    scope: u16,
    manager: Option<Address>,
) {
    let slot = keystore::actor_config_slot(account, id);
    keystore_slot(db, slot, keystore_word(authenticator, expiry, scope));
    if let Some(manager) = manager {
        keystore_slot(db, slot + U256::from(1), U256::from_be_slice(manager.as_slice()));
    }
}

/// Sets the account's inline self key: `flags`, expiry and scope.
fn configure_self(db: &mut InMemoryDB, account: Address, flags: u8, expiry: u64, scope: u16) {
    let mut word = [0u8; 32];
    word[1..3].copy_from_slice(&scope.to_be_bytes());
    word[3..9].copy_from_slice(&expiry.to_be_bytes()[2..]);
    word[15] = flags;
    keystore_slot(db, keystore::account_state_slot(account), U256::from_be_bytes(word));
}

fn statement_actor() -> StatementActor {
    StatementActor { vk: B256::repeat_byte(0x5a), tag: *b"sphmem01", key: B256::repeat_byte(0x4b) }
}

/// Names `account` as the sender, authorized by `key`.
fn sign_named(mut tx: TxEip8430, account: Address, key: &SigningKey) -> TxEip8430 {
    tx.sender = Some(account);
    tx.sender_auth = Bytes::from(vec![0; 85]);
    let signature = k1_signature(key, tx.sender_signature_hash());
    tx.sender_auth = [K1_AUTHENTICATOR.as_slice(), &signature].concat().into();
    tx
}

/// The account's own key acts unless the account revoked it or it expired.
#[test]
fn the_self_key_acts_until_revoked_or_expired() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let tx = sign(aa_tx(vec![vec![call(RECIPIENT)]]), &key);
    assert!(outcome(&run(db.clone(), &tx, sender).unwrap().0).success, "an empty Keystore");

    let mut revoked = db.clone();
    configure_self(&mut revoked, sender, keystore::FLAG_REVOKE_DEFAULT_EOA, 0, 0);
    assert_eq!(invalid(run(revoked, &tx, sender)), AaTxInvalid::SenderActor);
    let mut expired = db.clone();
    configure_self(&mut expired, sender, 0, TIMESTAMP - 1, 0);
    assert_eq!(invalid(run(expired, &tx, sender)), AaTxInvalid::ActorExpired);
    let mut live = db;
    configure_self(&mut live, sender, 0, TIMESTAMP, 0);
    assert!(outcome(&run(live, &tx, sender).unwrap().0).success, "live through its expiry");
}

/// Another key sends for a named account once the account configured it as a secp256k1 actor.
#[test]
fn a_configured_key_sends_for_a_named_account() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    let tx = sign_named(aa_tx(vec![vec![call(RECIPIENT)]]), account_address, &key);
    assert_eq!(invalid(run(db.clone(), &tx, account_address)), AaTxInvalid::SenderActor);

    let id = keystore::address_actor_id(key_address(&key));
    let mut wrong = db.clone();
    configure(&mut wrong, account_address, id, keystore::STATEMENT_AUTHENTICATOR, 0, 0, None);
    assert_eq!(invalid(run(wrong, &tx, account_address)), AaTxInvalid::SenderActor);

    configure(&mut db, account_address, id, K1_AUTHENTICATOR, 0, 0, None);
    let (result, state) = run(db, &tx, account_address).unwrap();
    assert!(outcome(&result).success);
    assert_eq!(state[&account_address].info.nonce, 1);
    assert_eq!(outcome(&result).payer, account_address);
}

/// EIP-3607: a key recovering to an address with code may not send for it, named or recovered. A
/// simulation knows no signer, so it goes on.
#[test]
fn a_key_may_not_send_for_the_code_at_its_address() {
    let key = signing_key(0x11);
    let own = key_address(&key);
    let mut db = InMemoryDB::default();
    db.insert_account_info(own, account(FUNDS, Some(return_code())));
    let recovered = sign(aa_tx(vec![vec![call(RECIPIENT)]]), &key);
    let named = sign_named(aa_tx(vec![vec![call(RECIPIENT)]]), own, &key);
    for tx in [&recovered, &named] {
        assert!(matches!(
            run(db.clone(), tx, own),
            Err(EVMError::Transaction(OpTransactionError::Base(
                InvalidTransaction::RejectCallerWithCode
            )))
        ));
    }
    assert!(simulate(db, &named, own).unwrap().0.is_success());
}

/// A transaction may not delegate over an account's code, whichever actor authorizes it.
#[test]
fn no_actor_delegates_over_code() {
    let key = signing_key(0x11);
    let admin = signing_key(0x22);
    let own = key_address(&key);
    let account_address = Address::repeat_byte(0xac);
    let mut db = InMemoryDB::default();
    db.insert_account_info(own, account(FUNDS, Some(return_code())));
    db.insert_account_info(account_address, account(FUNDS, Some(return_code())));
    let id = keystore::address_actor_id(key_address(&admin));
    configure(&mut db, account_address, id, K1_AUTHENTICATOR, 0, 0, None);

    let mut delegating = aa_tx(vec![vec![call(RECIPIENT)]]);
    delegating.account_changes = vec![AccountChange::Delegation { target: DELEGATE }];
    let by_own = sign(delegating.clone(), &key);
    assert_eq!(invalid(run(db.clone(), &by_own, own)), AaTxInvalid::DelegationOverCode);
    let by_admin = sign_named(delegating, account_address, &admin);
    assert_eq!(invalid(run(db, &by_admin, account_address)), AaTxInvalid::DelegationOverCode);
}

/// An account `createAccount` deployed, with code, nonce 1 and no self key, sends through its
/// actors, a secp256k1 key or a STATEMENT one, once they are configured.
#[test]
fn an_account_with_code_sends_through_its_actors() {
    let key = signing_key(0x11);
    let account_address = Address::repeat_byte(0xac);
    let mut db = InMemoryDB::default();
    let mut created = account(FUNDS, Some(return_code()));
    created.nonce = 1;
    db.insert_account_info(account_address, created);
    configure_self(&mut db, account_address, keystore::FLAG_REVOKE_DEFAULT_EOA, 0, 0);
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.nonce_sequence = 1;

    let by_key = sign_named(tx.clone(), account_address, &key);
    assert_eq!(invalid(run(db.clone(), &by_key, account_address)), AaTxInvalid::SenderActor);
    let actor = statement_actor();
    let mut by_statement = tx;
    by_statement.sender = Some(account_address);
    by_statement.sender_auth = actor.encode();
    assert_eq!(invalid(run(db.clone(), &by_statement, account_address)), AaTxInvalid::SenderActor);

    let id = keystore::address_actor_id(key_address(&key));
    configure(&mut db, account_address, id, K1_AUTHENTICATOR, 0, 0, None);
    let authenticator = keystore::STATEMENT_AUTHENTICATOR;
    configure(&mut db, account_address, actor.actor_id(), authenticator, 0, 0, None);
    for tx in [&by_key, &by_statement] {
        let (result, state) = run(db.clone(), tx, account_address).unwrap();
        assert!(outcome(&result).success);
        assert_eq!(outcome(&result).payer, account_address);
        assert_eq!(state[&account_address].info.nonce, 2);
        assert!(!state[&account_address].info.code.as_ref().unwrap().is_empty());
    }
}

/// A STATEMENT actor sends: the transaction depends on its statement over the sender hash, which
/// the precompile and the STATEMENT authenticator report, and pays for it.
#[test]
fn a_statement_actor_sends_and_depends_on_its_statement() {
    let actor = statement_actor();
    let mut db = InMemoryDB::default();
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    let mut tx = aa_tx(vec![vec![call(CONTRACT)]]);
    tx.sender = Some(account_address);
    tx.sender_auth = actor.encode();
    tx.validate_static(CHAIN_ID).unwrap();
    let sender_hash = tx.sender_signature_hash();
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&actor.tag);
    db.insert_account_info(
        CONTRACT,
        account(
            0,
            Some(context_reader_code(
                [0x80, 0xf9, 0x9a, 0x80],
                &[actor.vk, B256::from(tag), actor.key, sender_hash],
                0,
            )),
        ),
    );
    assert_eq!(invalid(run(db.clone(), &tx, account_address)), AaTxInvalid::SenderActor);

    configure(
        &mut db,
        account_address,
        actor.actor_id(),
        keystore::STATEMENT_AUTHENTICATOR,
        0,
        0,
        None,
    );
    let (result, state) = run(db, &tx, account_address).unwrap();
    assert!(outcome(&result).success, "{result:?}");
    assert_eq!(storage(&state, CONTRACT, 1), U256::from(1), "the call succeeded");
    assert_eq!(storage(&state, CONTRACT, 0), U256::from(1), "the statement is a dependency");
    assert_eq!(tx.dependencies(), vec![actor.dependency(sender_hash)]);
    assert!(result.tx_gas_used() >= actor.auth_cost());
}

/// The STATEMENT authenticator authenticates a hash exactly when the transaction depends on the
/// actor's statement over it.
#[test]
fn the_statement_authenticator_follows_the_dependencies() {
    let key = signing_key(0x11);
    let actor = statement_actor();
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    db.insert_account_info(
        keystore::STATEMENT_AUTHENTICATOR,
        account(0, Some(keystore::statement_authenticator_runtime().into())),
    );
    let hash = B256::repeat_byte(0x77);
    // authenticate(bytes32 hash, bytes data), data = vk || tag || key.
    let mut calldata = keccak256("authenticate(bytes32,bytes)")[..4].to_vec();
    calldata.extend_from_slice(hash.as_slice());
    calldata.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
    calldata.extend_from_slice(&U256::from(72).to_be_bytes::<32>());
    calldata.extend_from_slice(actor.vk.as_slice());
    calldata.extend_from_slice(&actor.tag);
    calldata.extend_from_slice(actor.key.as_slice());
    calldata.resize(4 + 32 * 3 + 96, 0);
    let mut tx = aa_tx(vec![vec![AaCall {
        to: keystore::STATEMENT_AUTHENTICATOR,
        value: U256::ZERO,
        data: calldata.into(),
    }]]);
    tx.sender_auth = Bytes::from(vec![0xff; 65]);

    let (result, _) = simulate(db.clone(), &tx, sender).unwrap();
    assert_eq!(
        result.output().unwrap().as_ref(),
        B256::ZERO.as_slice(),
        "no dependency: {result:?}"
    );

    tx.account_changes =
        vec![AccountChange::Dependencies { dependencies: vec![actor.dependency(hash)] }];
    let (result, _) = simulate(db, &tx, sender).unwrap();
    assert_eq!(result.output().unwrap().as_ref(), actor.actor_id().as_slice());
}

/// An actor initiates with the operator scope, or only toward its policy manager with the policy
/// scope; paying needs the self-payer scope for its own transaction and the sponsor-payer scope for
/// another's.
#[test]
fn scopes_gate_initiation_and_payment() {
    let key = signing_key(0x11);
    let payer_key = signing_key(0x22);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let payer = funded_sender(&mut db, &payer_key);
    let to_recipient = sign(aa_tx(vec![vec![call(RECIPIENT)]]), &key);
    let to_contract = sign(aa_tx(vec![vec![call(CONTRACT)]]), &key);
    let with_scope = |scope: u16| {
        let mut db = db.clone();
        configure_self(&mut db, sender, 0, 0, scope);
        db
    };
    let ok = |db: InMemoryDB, tx: &TxEip8430| outcome(&run(db, tx, sender).unwrap().0).success;

    assert_eq!(
        invalid(run(with_scope(keystore::SCOPE_SELF_PAYER), &to_recipient, sender)),
        AaTxInvalid::SenderScope
    );
    assert_eq!(
        invalid(run(with_scope(keystore::SCOPE_OPERATOR), &to_recipient, sender)),
        AaTxInvalid::PayerScope
    );
    assert!(ok(with_scope(keystore::SCOPE_OPERATOR | keystore::SCOPE_SELF_PAYER), &to_recipient));

    let policy = keystore::SCOPE_POLICY | keystore::SCOPE_SELF_PAYER;
    let mut managed = with_scope(policy);
    configure(
        &mut managed,
        sender,
        keystore::address_actor_id(sender),
        K1_AUTHENTICATOR,
        0,
        policy,
        Some(CONTRACT),
    );
    assert!(ok(managed.clone(), &to_contract));
    assert_eq!(invalid(run(managed, &to_recipient, sender)), AaTxInvalid::Policy);

    let sponsored = |tx: TxEip8430| {
        let mut tx = tx;
        tx.payer = Payer::Named(payer);
        tx.payer_auth = Bytes::from(vec![0; 85]);
        sponsor(sign(tx, &key), sender, &payer_key)
    };
    let tx = sponsored(aa_tx(vec![vec![call(RECIPIENT)]]));
    let mut self_payer_only = db.clone();
    configure_self(&mut self_payer_only, payer, 0, 0, keystore::SCOPE_SELF_PAYER);
    assert_eq!(invalid(run(self_payer_only, &tx, sender)), AaTxInvalid::PayerScope);
    let mut sponsor_payer = db;
    configure_self(&mut sponsor_payer, payer, 0, 0, keystore::SCOPE_SPONSOR_PAYER);
    assert!(ok(sponsor_payer, &tx));
}

/// Only the account's admin secp256k1 key delegates its code.
#[test]
fn only_an_admin_key_delegates() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.account_changes = vec![AccountChange::Delegation { target: DELEGATE }];
    let tx = sign(tx, &key);
    configure_self(&mut db, sender, 0, 0, keystore::SCOPE_OPERATOR | keystore::SCOPE_SELF_PAYER);
    assert_eq!(invalid(run(db, &tx, sender)), AaTxInvalid::DelegationNeedsAdmin);

    let actor = statement_actor();
    let mut db = InMemoryDB::default();
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    configure(
        &mut db,
        account_address,
        actor.actor_id(),
        keystore::STATEMENT_AUTHENTICATOR,
        0,
        0,
        None,
    );
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.account_changes = vec![AccountChange::Delegation { target: DELEGATE }];
    tx.sender = Some(account_address);
    tx.sender_auth = actor.encode();
    assert_eq!(invalid(run(db, &tx, account_address)), AaTxInvalid::DelegationNeedsAdmin);
}

/// A STATEMENT payer pays for another account's transaction once its account configured it with
/// the sponsor-payer scope; expired, or another actor, it is refused.
#[test]
fn a_statement_actor_pays() {
    let key = signing_key(0x11);
    let actor = statement_actor();
    let mut db = InMemoryDB::default();
    let payer = Address::repeat_byte(0xba);
    db.insert_account_info(payer, account(FUNDS, None));
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.payer = Payer::Named(payer);
    tx.payer_auth = actor.encode();
    let tx = sign_named(tx, account_address, &key);
    configure(
        &mut db,
        account_address,
        keystore::address_actor_id(key_address(&key)),
        K1_AUTHENTICATOR,
        0,
        0,
        None,
    );
    assert_eq!(invalid(run(db.clone(), &tx, account_address)), AaTxInvalid::PayerActor);

    let configured = |expiry, scope| {
        let mut db = db.clone();
        configure(
            &mut db,
            payer,
            actor.actor_id(),
            keystore::STATEMENT_AUTHENTICATOR,
            expiry,
            scope,
            None,
        );
        db
    };
    assert_eq!(
        invalid(run(configured(0, keystore::SCOPE_SELF_PAYER), &tx, account_address)),
        AaTxInvalid::PayerScope
    );
    assert_eq!(
        invalid(run(configured(TIMESTAMP - 1, 0), &tx, account_address)),
        AaTxInvalid::ActorExpired
    );
    let (result, state) =
        run(configured(0, keystore::SCOPE_SPONSOR_PAYER), &tx, account_address).unwrap();
    assert!(outcome(&result).success);
    assert_eq!(outcome(&result).payer, payer);
    assert!(state[&payer].info.balance < U256::from(FUNDS));
    let sender_hash = tx.sender_signature_hash();
    assert_eq!(
        tx.dependencies(),
        vec![actor.dependency(tx.payer_signature_hash(account_address))],
        "the payer's statement, over the payer hash {sender_hash}"
    );
}

/// An expired configured key, a policy call that moves value, and a non-self admin key's
/// delegation.
#[test]
fn configured_keys_expire_and_follow_their_scope() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    db.insert_account_info(DELEGATE, account(0, Some(sstore_code(5, 9))));
    let id = keystore::address_actor_id(key_address(&key));
    let tx = sign_named(aa_tx(vec![vec![call(RECIPIENT)]]), account_address, &key);

    let mut expired = db.clone();
    configure(&mut expired, account_address, id, K1_AUTHENTICATOR, TIMESTAMP - 1, 0, None);
    assert_eq!(invalid(run(expired, &tx, account_address)), AaTxInvalid::ActorExpired);

    let policy = keystore::SCOPE_POLICY | keystore::SCOPE_SELF_PAYER;
    let mut managed = db.clone();
    configure(&mut managed, account_address, id, K1_AUTHENTICATOR, 0, policy, Some(CONTRACT));
    let to_manager = sign_named(aa_tx(vec![vec![call(CONTRACT)]]), account_address, &key);
    assert!(outcome(&run(managed.clone(), &to_manager, account_address).unwrap().0).success);
    let mut with_value = aa_tx(vec![vec![AaCall { value: U256::from(1), ..call(CONTRACT) }]]);
    with_value = sign_named(with_value, account_address, &key);
    assert_eq!(invalid(run(managed, &with_value, account_address)), AaTxInvalid::Policy);

    configure(&mut db, account_address, id, K1_AUTHENTICATOR, 0, 0, None);
    let mut delegating = aa_tx(vec![vec![call(account_address)]]);
    delegating.account_changes = vec![AccountChange::Delegation { target: DELEGATE }];
    let delegating = sign_named(delegating, account_address, &key);
    let (result, state) = run(db, &delegating, account_address).unwrap();
    assert!(outcome(&result).success);
    assert_eq!(
        state[&account_address].info.code.clone().unwrap().eip7702_address(),
        Some(DELEGATE)
    );
}

/// A simulation takes a secp256k1 authorization for the account's admin: an account that revoked
/// its own key still simulates a transaction its configured key would sign.
#[test]
fn a_simulation_of_a_revoked_self_key_account() {
    let mut db = InMemoryDB::default();
    let account_address = Address::repeat_byte(0xac);
    db.insert_account_info(account_address, account(FUNDS, None));
    configure_self(&mut db, account_address, keystore::FLAG_REVOKE_DEFAULT_EOA, 0, 0);
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    tx.sender = Some(account_address);
    tx.sender_auth = [K1_AUTHENTICATOR.as_slice(), &[0xff; 65]].concat().into();
    let (result, _) = simulate(db, &tx, account_address).unwrap();
    assert!(result.is_success(), "{result:?}");
}

/// The native reading of the Keystore's storage agrees with the Keystore's own: its
/// `getActorConfig` and `getPolicyManager` over the same slots.
#[test]
fn native_reads_agree_with_the_keystore() {
    let key = signing_key(0x11);
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);
    let account_address = Address::repeat_byte(0xac);
    let actor = statement_actor();
    configure(
        &mut db,
        account_address,
        actor.actor_id(),
        keystore::STATEMENT_AUTHENTICATOR,
        TIMESTAMP + 5,
        keystore::SCOPE_POLICY,
        Some(CONTRACT),
    );
    configure_self(&mut db, account_address, 0, TIMESTAMP + 7, keystore::SCOPE_SELF_PAYER);
    let view = |signature: &str, id: B256| -> Bytes {
        let mut data = keccak256(signature)[..4].to_vec();
        data.extend_from_slice(account_address.into_word().as_slice());
        data.extend_from_slice(id.as_slice());
        let mut tx = aa_tx(vec![vec![AaCall {
            to: keystore::KEYSTORE_ADDRESS,
            value: U256::ZERO,
            data: data.into(),
        }]]);
        tx.sender_auth = Bytes::from(vec![0xff; 65]);
        let (result, _) = simulate(db.clone(), &tx, sender).unwrap();
        result.output().unwrap().clone()
    };
    let config = |output: Bytes| {
        let word = |i: usize| U256::from_be_slice(&output[32 * i..32 * i + 32]);
        keystore::ActorConfig {
            authenticator: Address::from_word(word(0).into()),
            expiry: word(1).to(),
            scope: word(2).to(),
        }
    };
    let get_config = "getActorConfig(address,bytes32)";
    let read = |slot| db.cache.accounts[&keystore::KEYSTORE_ADDRESS].storage[&slot];

    let explicit = config(view(get_config, actor.actor_id()));
    let slot = keystore::actor_config_slot(account_address, actor.actor_id());
    assert_eq!(explicit, keystore::ActorConfig::decode(read(slot)));
    assert_eq!(explicit.expiry, TIMESTAMP + 5);
    let manager = view("getPolicyManager(address,bytes32)", actor.actor_id());
    assert_eq!(Address::from_word(B256::from_slice(&manager)), CONTRACT);
    assert_eq!(Address::from_word(read(slot + U256::from(1)).into()), CONTRACT);

    let own = config(view(get_config, keystore::address_actor_id(account_address)));
    let state = keystore::AccountState::decode(read(keystore::account_state_slot(account_address)));
    assert_eq!(Some(own), state.self_actor());
    assert_eq!((own.expiry, own.scope), (TIMESTAMP + 7, keystore::SCOPE_SELF_PAYER));
}

/// L1 fees of 1.7e13 / 1e6 = 1.7e7 wei a byte.
fn priced_l1() -> crate::L1BlockInfo {
    crate::L1BlockInfo {
        l2_block: Some(U256::ZERO),
        l1_base_fee: U256::from(1_000_000),
        l1_base_fee_scalar: U256::from(1_000_000),
        l1_blob_base_fee: Some(U256::from(1_000_000)),
        l1_blob_base_fee_scalar: Some(U256::from(1_000_000)),
        operator_fee_scalar: Some(U256::ZERO),
        operator_fee_constant: Some(U256::ZERO),
        ..Default::default()
    }
}

fn run_priced(db: InMemoryDB, tx: &TxEip8430, sender: Address) -> Outcome {
    let mut evm = context(db, OpSpecId::LAGOON).with_chain(priced_l1()).build_op();
    evm.transact(op_tx(tx, sender)).map(|r| (r.result, r.state))
}

/// A dependent transaction, with each dependency counted once per declaration.
fn two_dependencies() -> (SigningKey, TxEip8430) {
    let key = signing_key(0x11);
    let mut tx = aa_tx(vec![vec![call(RECIPIENT)]]);
    let dependency = Dependency {
        scheme: PROOF_STATEMENT_SCHEME,
        data_hash: B256::repeat_byte(0xdd),
        verification_key_hash: B256::repeat_byte(0xaa),
    };
    tx.account_changes =
        vec![AccountChange::Dependencies { dependencies: vec![dependency, dependency] }];
    let tx = sign(tx, &key);
    (key, tx)
}

/// The L1 data fee `tx` owes: its bytes', and its dependencies' share of the aggregate.
fn l1_fee(tx: &TxEip8430) -> U256 {
    let mut info = priced_l1();
    let bytes = info.calculate_tx_l1_cost(&tx.encoded_2718(), OpSpecId::LAGOON);
    bytes + info.dependency_l1_cost(tx.dependency_count())
}

/// Each dependency pays for its share of the aggregate in the L1 data fee, which reaches the L1 fee
/// vault with the rest.
#[test]
fn dependencies_pay_their_share_of_the_aggregate() {
    let (key, tx) = two_dependencies();
    let mut db = InMemoryDB::default();
    let sender = funded_sender(&mut db, &key);

    // 1.7e7 wei a byte, 2,048 bytes a dependency, twice.
    assert_eq!(priced_l1().dependency_l1_cost(2), U256::from(2u64 * 2_048 * 17_000_000));
    let (result, state) = run_priced(db, &tx, sender).unwrap();
    assert!(outcome(&result).success, "{result:?}");
    let fee = l1_fee(&tx);
    assert_eq!(state[&L1_FEE_RECIPIENT].info.balance, fee);
    assert_eq!(
        state[&sender].info.balance,
        U256::from(FUNDS) - U256::from(result.tx_gas_used() * 3) - fee
    );
}

/// A payer who cannot cover the dependencies' L1 fee is refused, as for any other fee.
#[test]
fn a_payer_short_of_the_dependency_fee_is_refused() {
    let (key, tx) = two_dependencies();
    let sender = key_address(&key);
    let max_cost = U256::from(tx.effective_gas_limit()) * U256::from(tx.max_fee_per_gas);
    let balance = |funds: U256| {
        let mut db = InMemoryDB::default();
        db.insert_account_info(sender, AccountInfo { balance: funds, ..Default::default() });
        db
    };
    assert!(run_priced(balance(max_cost + l1_fee(&tx)), &tx, sender).is_ok());
    assert!(matches!(
        run_priced(balance(max_cost + l1_fee(&tx) - U256::from(1)), &tx, sender),
        Err(EVMError::Transaction(OpTransactionError::Base(
            InvalidTransaction::LackOfFundForMaxFee { .. }
        )))
    ));
}
