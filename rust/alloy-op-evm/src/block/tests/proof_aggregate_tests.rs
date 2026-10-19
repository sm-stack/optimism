use std::sync::{Arc, Mutex};

use super::*;
use crate::proof_aggregate::{PROOF_REGISTRY_ADDRESS, ProofAggregateVerifier};
use alloy_evm::block::CommitChanges;
use op_alloy::consensus::{OpReceiptEnvelope, ProofStatement, build_proof_aggregate_tx};

/// Registry stand-in that logs its calldata (`LOG0(0, calldatasize)`) and returns `ack` as an
/// ABI-encoded `bytes4`.
fn logging_registry(ack: [u8; 4]) -> Vec<u8> {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x36, 0x5f, 0xa0];
    // PUSH4 ack, PUSH1 0xe0, SHL, PUSH0, MSTORE, PUSH1 0x20, PUSH0, RETURN
    code.push(0x63);
    code.extend_from_slice(&ack);
    code.extend_from_slice(&[0x60, 0xe0, 0x1b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    code
}

fn acking_registry() -> Vec<u8> {
    logging_registry(crate::proof_aggregate::VERIFY_STATEMENTS_SELECTOR)
}

/// Registry stand-in that always reverts.
const REVERTING_REGISTRY: [u8; 3] = [0x5f, 0x5f, 0xfd];
/// An account without code: calls to it succeed with empty output.
const NO_CODE: [u8; 0] = [];

const AGGREGATION_VKEY: B256 = B256::repeat_byte(0xaa);

/// Verifier stand-in that records its inputs and returns a fixed outcome.
#[derive(Debug)]
struct MockVerifier {
    accept: bool,
    calls: Mutex<Vec<(B256, B256, Vec<u8>)>>,
}

impl MockVerifier {
    fn new(accept: bool) -> Arc<Self> {
        Arc::new(Self { accept, calls: Mutex::new(Vec::new()) })
    }
}

impl ProofAggregateVerifier for MockVerifier {
    fn verify(
        &self,
        aggregation_vkey_hash: B256,
        statements_commitment: B256,
        proof: &[u8],
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push((
            aggregation_vkey_hash,
            statements_commitment,
            proof.to_vec(),
        ));
        if self.accept { Ok(()) } else { Err("mock rejection".to_string()) }
    }
}

fn statements() -> Vec<ProofStatement> {
    vec![
        ProofStatement {
            vkey_hash: B256::repeat_byte(1),
            public_values_digest: B256::repeat_byte(2),
        },
        ProofStatement {
            vkey_hash: B256::repeat_byte(3),
            public_values_digest: B256::repeat_byte(4),
        },
    ]
}

fn aggregate_tx(block_number: u64, statements: Vec<ProofStatement>) -> Recovered<OpTxEnvelope> {
    Recovered::new_unchecked(
        OpTxEnvelope::ProofAggregate(
            build_proof_aggregate_tx(
                block_number,
                AGGREGATION_VKEY,
                statements,
                Bytes::from_static(b"proof"),
            )
            .seal_slow(),
        ),
        Address::ZERO,
    )
}

/// Every fork through Lagoon active from genesis, so proof aggregation is active.
fn all_forks_active() -> OpChainHardforks {
    let forks: Vec<(OpHardfork, ForkCondition)> = OpHardfork::op_mainnet()
        .into_iter()
        .filter(|(fork, _)| fork.idx() < OpHardfork::Jovian.idx())
        .chain(OpHardfork::Jovian.forks_from().map(|fork| (fork, ForkCondition::Timestamp(0))))
        .collect();
    OpChainHardforks::new(forks)
}

/// Every fork before Lagoon active from genesis, so proof aggregation is not.
fn pre_lagoon_forks() -> OpChainHardforks {
    let forks: Vec<(OpHardfork, ForkCondition)> = OpHardfork::op_mainnet()
        .into_iter()
        .filter(|(fork, _)| fork.idx() < OpHardfork::Jovian.idx())
        .chain(OpHardfork::Jovian.forks_from().map(|fork| {
            let condition = if fork.idx() < OpHardfork::Lagoon.idx() {
                ForkCondition::Timestamp(0)
            } else {
                ForkCondition::Never
            };
            (fork, condition)
        }))
        .collect();
    OpChainHardforks::new(forks)
}

fn db_with_registry(code: &[u8]) -> State<InMemoryDB> {
    let mut db = prepare_jovian_db(DEFAULT_DA_FOOTPRINT_GAS_SCALAR);
    db.insert_account(
        PROOF_REGISTRY_ADDRESS,
        AccountInfo::from_bytecode(Bytecode::new_raw(Bytes::copy_from_slice(code))),
    );
    db
}

fn executor<'a>(
    db: &'a mut State<InMemoryDB>,
    receipt_builder: &'a OpAlloyReceiptBuilder,
    hardforks: &'a OpChainHardforks,
    verifier: Option<Arc<MockVerifier>>,
) -> JovianTestExecutor<'a> {
    let mut executor = build_executor(
        db,
        receipt_builder,
        hardforks,
        DEFAULT_GAS_LIMIT,
        0,
        None,
        0,
        Address::ZERO,
        Inspect::Disabled,
    );
    executor.ctx.proof_aggregate_verifier =
        verifier.map(|verifier| verifier as SharedProofAggregateVerifier);
    executor
}

fn assert_invalid(result: Result<GasOutput, BlockExecutionError>, needle: &str) {
    let err = result.expect_err("proof aggregate must be rejected").to_string();
    assert!(err.contains("invalid proof aggregate transaction"), "{err}");
    assert!(err.contains(needle), "expected `{needle}` in `{err}`");
}

#[test]
fn verifies_aggregate_and_records_statements() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let verifier = MockVerifier::new(true);
    let mut executor = executor(&mut db, &receipt_builder, &hardforks, Some(verifier.clone()));

    let gas =
        executor.execute_transaction(&aggregate_tx(0, statements())).expect("valid aggregate");
    assert_eq!(gas.tx_gas_used(), 0);
    assert_eq!(executor.gas_used, 0);

    let calls = verifier.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[(
            AGGREGATION_VKEY,
            op_alloy::consensus::statements_commitment(&statements()),
            b"proof".to_vec()
        )]
    );

    let OpReceiptEnvelope::ProofAggregate(receipt) = &executor.receipts[0] else {
        panic!("expected a proof aggregate receipt, got {:?}", executor.receipts[0]);
    };
    assert!(receipt.receipt.status.coerce_status());
    assert_eq!(receipt.receipt.cumulative_gas_used, 0);
    let ids: Vec<B256> = statements().iter().map(ProofStatement::id).collect();
    let [log] = receipt.receipt.logs.as_slice() else { panic!("expected one registry log") };
    assert_eq!(log.address, PROOF_REGISTRY_ADDRESS);
    assert_eq!(log.data.data, verify_statements_calldata(AGGREGATION_VKEY, &ids));
}

#[test]
fn rejects_proof_the_verifier_rejects() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(false)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "aggregate proof rejected: mock rejection",
    );
}

#[test]
fn rejects_without_a_verifier() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor = executor(&mut db, &receipt_builder, &hardforks, None);
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "no proof aggregate verifier configured",
    );
}

#[test]
fn rejects_before_activation() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = pre_lagoon_forks();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "proof aggregation not active",
    );
}

#[test]
fn rejects_aggregate_after_a_user_tx() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    executor
        .execute_transaction(&recovered_legacy(TxLegacy {
            gas_limit: 50_000,
            to: TxKind::Call(Address::repeat_byte(0x11)),
            ..Default::default()
        }))
        .expect("user tx executes");
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "does not directly follow the deposits",
    );
}

#[test]
fn rejects_a_second_aggregate() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    executor.execute_transaction(&aggregate_tx(0, statements())).expect("first aggregate");
    assert_invalid(executor.execute_transaction(&aggregate_tx(0, statements())), "duplicate");
}

#[test]
fn rejects_block_number_mismatch() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(1, statements())),
        "does not match block number",
    );
}

#[test]
fn rejects_empty_statements() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(executor.execute_transaction(&aggregate_tx(0, vec![])), "lists no statements");
}

#[test]
fn rejects_registry_without_code() {
    let mut db = db_with_registry(&NO_CODE);
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "registry did not acknowledge",
    );
}

#[test]
fn rejects_wrong_registry_acknowledgement() {
    let mut db = db_with_registry(&logging_registry([0xde, 0xad, 0xbe, 0xef]));
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "registry did not acknowledge",
    );
}

#[test]
fn rejects_when_the_registry_reverts() {
    let mut db = db_with_registry(&REVERTING_REGISTRY);
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "registry rejected the proof aggregate",
    );
}

#[test]
fn registry_rejection_skips_proof_verification() {
    let mut db = db_with_registry(&REVERTING_REGISTRY);
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let verifier = MockVerifier::new(true);
    let mut executor = executor(&mut db, &receipt_builder, &hardforks, Some(verifier.clone()));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, statements())),
        "registry rejected the proof aggregate",
    );
    assert!(verifier.calls.lock().unwrap().is_empty(), "the proof must not be verified");
}

fn user_tx() -> Recovered<OpTxEnvelope> {
    recovered_legacy(TxLegacy {
        gas_limit: 50_000,
        to: TxKind::Call(Address::repeat_byte(0x11)),
        ..Default::default()
    })
}

#[test]
fn declined_candidates_leave_placement_state_untouched() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));

    // A declined user transaction does not count as preceding the aggregate.
    let declined = executor
        .execute_transaction_with_commit_condition(&user_tx(), |_| CommitChanges::No)
        .expect("user tx executes");
    assert!(declined.is_none());
    // Nor does a declined aggregate count as the block's aggregate.
    let declined = executor
        .execute_transaction_with_commit_condition(&aggregate_tx(0, statements()), |_| {
            CommitChanges::No
        })
        .expect("aggregate executes");
    assert!(declined.is_none());

    executor.execute_transaction(&aggregate_tx(0, statements())).expect("aggregate commits");
    assert!(executor.proof_aggregate_seen);
    assert!(!executor.non_deposit_tx_seen);
    executor.execute_transaction(&user_tx()).expect("user tx commits");
    assert!(executor.non_deposit_tx_seen);
}

#[test]
fn executed_prefix_from_tx_types() {
    use op_alloy::consensus::PROOF_AGGREGATE_TX_TYPE_ID;
    assert_eq!(ExecutedPrefix::from_tx_types([]), ExecutedPrefix::default());
    assert_eq!(
        ExecutedPrefix::from_tx_types([DEPOSIT_TRANSACTION_TYPE, DEPOSIT_TRANSACTION_TYPE]),
        ExecutedPrefix::default()
    );
    assert_eq!(
        ExecutedPrefix::from_tx_types([DEPOSIT_TRANSACTION_TYPE, PROOF_AGGREGATE_TX_TYPE_ID]),
        ExecutedPrefix { non_deposit_tx_seen: false, proof_aggregate_seen: true }
    );
    assert_eq!(
        ExecutedPrefix::from_tx_types([DEPOSIT_TRANSACTION_TYPE, 0x02]),
        ExecutedPrefix { non_deposit_tx_seen: true, proof_aggregate_seen: false }
    );
}

#[test]
fn resumed_executor_keeps_the_prefix_placement_state() {
    use op_alloy::consensus::PROOF_AGGREGATE_TX_TYPE_ID;
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let resumed = |db, prefix: &[u8]| {
        let mut executor =
            executor(db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
        executor
            .resume_at_tx_index(prefix.len() as u64, ExecutedPrefix::from_tx_types(prefix.to_vec()))
            .expect("resume");
        executor.execute_transaction(&aggregate_tx(0, statements()))
    };

    let mut db = db_with_registry(&acking_registry());
    resumed(&mut db, &[DEPOSIT_TRANSACTION_TYPE]).expect("aggregate directly after the deposits");

    let mut db = db_with_registry(&acking_registry());
    assert_invalid(
        resumed(&mut db, &[DEPOSIT_TRANSACTION_TYPE, PROOF_AGGREGATE_TX_TYPE_ID]),
        "duplicate",
    );

    let mut db = db_with_registry(&acking_registry());
    assert_invalid(
        resumed(&mut db, &[DEPOSIT_TRANSACTION_TYPE, 0x02]),
        "does not directly follow the deposits",
    );
}
