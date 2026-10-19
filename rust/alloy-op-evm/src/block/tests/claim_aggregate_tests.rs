use std::sync::{Arc, Mutex};

use super::*;
use crate::claim_aggregate::{ClaimAggregateVerifier, PROOF_CLAIM_REGISTRY_ADDRESS};
use op_alloy::consensus::{OpReceiptEnvelope, ProofClaim, build_claim_aggregate_tx};

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
    logging_registry(crate::claim_aggregate::finalize_claims_selector())
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

impl ClaimAggregateVerifier for MockVerifier {
    fn verify(
        &self,
        aggregation_vkey_hash: B256,
        claims_commitment: B256,
        proof: &[u8],
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push((aggregation_vkey_hash, claims_commitment, proof.to_vec()));
        if self.accept { Ok(()) } else { Err("mock rejection".to_string()) }
    }
}

fn claims() -> Vec<ProofClaim> {
    vec![
        ProofClaim { vkey_hash: B256::repeat_byte(1), public_values_digest: B256::repeat_byte(2) },
        ProofClaim { vkey_hash: B256::repeat_byte(3), public_values_digest: B256::repeat_byte(4) },
    ]
}

fn aggregate_tx(block_number: u64, claims: Vec<ProofClaim>) -> Recovered<OpTxEnvelope> {
    Recovered::new_unchecked(
        OpTxEnvelope::ClaimAggregate(
            build_claim_aggregate_tx(
                block_number,
                AGGREGATION_VKEY,
                claims,
                Bytes::from_static(b"proof"),
            )
            .seal_slow(),
        ),
        Address::ZERO,
    )
}

/// Every fork through Lagoon active from genesis, so proof claims are active.
fn all_forks_active() -> OpChainHardforks {
    let forks: Vec<(OpHardfork, ForkCondition)> = OpHardfork::op_mainnet()
        .into_iter()
        .filter(|(fork, _)| fork.idx() < OpHardfork::Jovian.idx())
        .chain(OpHardfork::Jovian.forks_from().map(|fork| (fork, ForkCondition::Timestamp(0))))
        .collect();
    OpChainHardforks::new(forks)
}

/// Every fork before Lagoon active from genesis, so proof claims are not.
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
        PROOF_CLAIM_REGISTRY_ADDRESS,
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
    executor.ctx.claim_aggregate_verifier =
        verifier.map(|verifier| verifier as SharedClaimAggregateVerifier);
    executor
}

fn assert_invalid(result: Result<GasOutput, BlockExecutionError>, needle: &str) {
    let err = result.expect_err("claim aggregate must be rejected").to_string();
    assert!(err.contains("invalid claim aggregate transaction"), "{err}");
    assert!(err.contains(needle), "expected `{needle}` in `{err}`");
}

#[test]
fn verifies_and_finalizes_claims() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let verifier = MockVerifier::new(true);
    let mut executor = executor(&mut db, &receipt_builder, &hardforks, Some(verifier.clone()));

    let gas = executor.execute_transaction(&aggregate_tx(0, claims())).expect("valid aggregate");
    assert_eq!(gas.tx_gas_used(), 0);
    assert_eq!(executor.gas_used, 0);

    let calls = verifier.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[(AGGREGATION_VKEY, op_alloy::consensus::claims_commitment(&claims()), b"proof".to_vec())]
    );

    let OpReceiptEnvelope::ClaimAggregate(receipt) = &executor.receipts[0] else {
        panic!("expected a claim aggregate receipt, got {:?}", executor.receipts[0]);
    };
    assert!(receipt.receipt.status.coerce_status());
    assert_eq!(receipt.receipt.cumulative_gas_used, 0);
    let ids: Vec<B256> = claims().iter().map(ProofClaim::id).collect();
    let [log] = receipt.receipt.logs.as_slice() else { panic!("expected one registry log") };
    assert_eq!(log.address, PROOF_CLAIM_REGISTRY_ADDRESS);
    assert_eq!(log.data.data, finalize_claims_calldata(AGGREGATION_VKEY, &ids));
}

#[test]
fn rejects_proof_the_verifier_rejects() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(false)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, claims())),
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
        executor.execute_transaction(&aggregate_tx(0, claims())),
        "no claim aggregate verifier configured",
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
        executor.execute_transaction(&aggregate_tx(0, claims())),
        "proof claims not active",
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
        executor.execute_transaction(&aggregate_tx(0, claims())),
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
    executor.execute_transaction(&aggregate_tx(0, claims())).expect("first aggregate");
    assert_invalid(executor.execute_transaction(&aggregate_tx(0, claims())), "duplicate");
}

#[test]
fn rejects_block_number_mismatch() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(1, claims())),
        "does not match block number",
    );
}

#[test]
fn rejects_empty_claims() {
    let mut db = db_with_registry(&acking_registry());
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(executor.execute_transaction(&aggregate_tx(0, vec![])), "lists no claims");
}

#[test]
fn rejects_registry_without_code() {
    let mut db = db_with_registry(&NO_CODE);
    let receipt_builder = OpAlloyReceiptBuilder::default();
    let hardforks = all_forks_active();
    let mut executor =
        executor(&mut db, &receipt_builder, &hardforks, Some(MockVerifier::new(true)));
    assert_invalid(
        executor.execute_transaction(&aggregate_tx(0, claims())),
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
        executor.execute_transaction(&aggregate_tx(0, claims())),
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
        executor.execute_transaction(&aggregate_tx(0, claims())),
        "registry rejected the claim aggregate",
    );
}
