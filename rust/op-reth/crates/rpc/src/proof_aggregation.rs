//! RPC for EIP-8430 transactions with [EIP-8288] dependencies on the sequencer.
//!
//! A transaction declares, in its dependency entry, the statements it relies on: members
//! that leaves of the leanVM tree class publish. A user sends it with the source of each statement
//! (`optimism_sendRawTransactionWithStatementProofs`): a leaf proof of a program publishing the
//! member, or a leanSPHINCS signature whose member it is. Every source is verified natively, the
//! transaction is admitted to the sequencer's dependency bookkeeping and added to the transaction
//! pool, and the payload builder includes it like any other transaction.
//!
//! op-aggregator, on the authenticated endpoint, folds the sources of sealed blocks into tree
//! roots, proving signature leaves from the raw signatures, and submits them; the sequencer
//! verifies and queues each, and derivation replaces a block with its deposits unless the
//! aggregate answering for it proves all its dependencies. Nodes other than the sequencer
//! forward submissions to it. op-batcher reads the queued aggregates with
//! `admin_pendingProofAggregates` and posts them as proof aggregate batches.
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Bytes, U64};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::{
        ErrorObject, ErrorObjectOwned,
        error::{
            INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, SERVER_IS_BUSY_CODE, SERVER_IS_BUSY_MSG,
        },
    },
};
use op_alloy_consensus::{OpTxEnvelope, ProofStatement};
use reth_optimism_payload_builder::proof_aggregation::{
    MAX_STATEMENTS_PER_TX, PendingAggregate, ProgramLeaf, ProofAggregationPool,
    ProofAggregationPoolError, SignatureSource, StatementProof, StatementSource,
};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionPool,
    error::{PoolError, PoolErrorKind},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::SequencerClient;

// The pool's bound on a program leaf's members is the program classes'; they share it.
const _: () = assert!(
    reth_optimism_payload_builder::proof_aggregation::MAX_LEAF_MEMBERS ==
        op_leanvm_tree::CLASS_BOUNDS[op_leanvm_tree::PROGRAM_CLASS][4]
);

/// Upper bound on the program leaves one transaction brings: each costs the sequencer a
/// first-level node and a fold, whatever the statements it backs.
const MAX_PROGRAM_LEAVES_PER_TX: usize = 4;

/// A submission and the statements of it the transaction depends on.
struct Submitted {
    submission: StatementProofSubmission,
    relied: Vec<ProofStatement>,
}

/// Upper bound on statement proof verifications running at once. A user submission that finds
/// every slot taken is refused rather than queued.
const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// The source of statements, as a user submits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StatementProofSubmission {
    /// A leaf proof of a program of the tree's program class, which publishes `members`: each is a
    /// statement of the program.
    #[serde(rename_all = "camelCase")]
    Program {
        /// The digest of the verifying key of the program normalized to the program class.
        vkey_hash: B256,
        /// The members the run published, in the order it committed them.
        members: Vec<B256>,
        /// The leanVM proof of the run, in zero knowledge, at the leaf shape of a program class:
        /// the small one, or for large runs the large one at rate 1/8. The shape names the class.
        proof: Bytes,
        /// The normalized program's verifying key, whose digest must be `vkey_hash`.
        verifying_key: Bytes,
    },
    /// A leanSPHINCS signature over `message`: the statement of the signature-member guest whose
    /// member is `BLAKE2s("sphmem01" || public key || message)`. op-aggregator proves it.
    #[serde(rename_all = "camelCase")]
    Signature {
        /// The public key: its root's and parameter's two words each, little-endian.
        public_key: Bytes,
        /// The signed message.
        message: B256,
        /// The signature: its fields' words in order, each little-endian.
        signature: Bytes,
    },
}

impl StatementProofSubmission {
    /// The statements the submission proves.
    fn statements(&self) -> Result<Vec<ProofStatement>, String> {
        Ok(match self {
            Self::Program { vkey_hash, members, .. } => members
                .iter()
                .map(|member| ProofStatement {
                    vkey_hash: *vkey_hash,
                    public_values_digest: *member,
                })
                .collect(),
            Self::Signature { public_key, message, signature } => {
                vec![op_leanvm_tree::Signed::decode(public_key, *message, signature)?.statement()]
            }
        })
    }

    /// The pool's record of the source.
    fn source(&self) -> StatementSource {
        match self.clone() {
            Self::Program { vkey_hash, members, proof, verifying_key } => {
                StatementSource::Program(Arc::new(ProgramLeaf {
                    program: vkey_hash,
                    verifying_key,
                    proof,
                    members,
                }))
            }
            Self::Signature { public_key, message, signature } => {
                StatementSource::Signature(Arc::new(SignatureSource {
                    public_key,
                    message,
                    signature,
                }))
            }
        }
    }

    /// Checks the leaf proof against its verifying key and members, or the signature.
    fn verify(&self) -> Result<(), String> {
        match self {
            Self::Program { vkey_hash, members, proof, verifying_key } => {
                let digest = op_leanvm_tree::verify_program_leaf(verifying_key, members, proof)
                    .map_err(|reason| format!("proof rejected: {reason}"))?;
                if digest != *vkey_hash {
                    return Err(format!("the verifying key's digest is {digest}"));
                }
                Ok(())
            }
            Self::Signature { public_key, message, signature } => {
                op_leanvm_tree::Signed::decode(public_key, *message, signature)?
                    .verify()
                    .map(drop)
                    .map_err(|reason| format!("signature rejected: {reason}"))
            }
        }
    }
}

/// User-facing submission of transactions with dependencies.
#[cfg_attr(not(test), rpc(server, namespace = "optimism"))]
#[cfg_attr(test, rpc(server, client, namespace = "optimism"))]
pub trait ProofStatementApi {
    /// Adds `tx`, an EIP-2718 encoded EIP-8430 transaction with a dependency entry, to the
    /// transaction pool once the proof of each dependency is verified, and returns its hash.
    ///
    /// `proofs` hold the proof of each dependency the sequencer does not hold a proof of yet. The
    /// dependencies' share of the aggregate that later proves them is paid through the
    /// transaction's L1 data fee. While aggregates are late, new submissions are refused.
    #[method(name = "sendRawTransactionWithStatementProofs")]
    async fn send_raw_transaction_with_statement_proofs(
        &self,
        tx: Bytes,
        proofs: Vec<StatementProofSubmission>,
    ) -> RpcResult<B256>;
}

/// Batcher-facing methods, served on the admin namespace.
#[cfg_attr(not(test), rpc(server, namespace = "admin"))]
#[cfg_attr(test, rpc(server, client, namespace = "admin"))]
pub trait ProofAggregationAdminApi {
    /// Returns the queued aggregates, in `through` order, for op-batcher to post. An aggregate
    /// stays until the safe head reaches its `through`.
    #[method(name = "pendingProofAggregates")]
    fn pending_proof_aggregates(&self) -> RpcResult<Vec<PendingAggregate>>;

    /// How many blocks a run spans, if runs are fixed: a run ends at block `n` when
    /// `(n + 1) % K == 0`, where op-batcher ends the channel holding it. Zero if op-aggregator
    /// closes runs on its own.
    #[method(name = "proofAggregationRunBlocks")]
    fn proof_aggregation_run_blocks(&self) -> RpcResult<U64>;
}

/// Server for both APIs, sharing the payload builder's pool.
#[derive(Clone)]
pub struct OpProofAggregationApi<Pool> {
    pool: ProofAggregationPool,
    /// The transaction pool admitted transactions go to.
    tx_pool: Pool,
    /// The chain transactions must be for.
    chain_id: u64,
    /// Set on nodes other than the sequencer, which forward user submissions to it.
    sequencer_client: Option<SequencerClient>,
    verification_permits: Arc<Semaphore>,
}

impl<Pool> fmt::Debug for OpProofAggregationApi<Pool> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpProofAggregationApi")
            .field("pool", &self.pool)
            .field("sequencer_client", &self.sequencer_client)
            .finish_non_exhaustive()
    }
}

impl<Pool> OpProofAggregationApi<Pool> {
    /// Creates a server for chain `chain_id` over `pool`, which must be the pool the payload
    /// builder reads, adding admitted transactions to `tx_pool`. With a `sequencer_client`, user
    /// submissions are forwarded to the sequencer instead.
    pub fn new(
        pool: ProofAggregationPool,
        tx_pool: Pool,
        chain_id: u64,
        sequencer_client: Option<SequencerClient>,
    ) -> Self {
        Self {
            pool,
            tx_pool,
            chain_id,
            sequencer_client,
            verification_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
        }
    }

    /// Takes a verification slot, or refuses the submission if every slot is taken.
    fn try_verification_permit(&self) -> RpcResult<OwnedSemaphorePermit> {
        self.verification_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy(String::from(SERVER_IS_BUSY_MSG)))
    }

    /// Runs `verify` on a blocking thread, holding `permit` until it finishes even if the caller
    /// goes away: a leanVM verification takes milliseconds. A rejection is reported as invalid
    /// params.
    async fn verify_blocking(
        &self,
        permit: OwnedSemaphorePermit,
        verify: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> RpcResult<()> {
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify()
        })
        .await
        .map_err(|err| internal_error(err.to_string()))?
        .map_err(invalid_params)
    }
}

fn invalid_params(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(INVALID_PARAMS_CODE, message, None::<()>)
}

fn internal_error(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(INTERNAL_ERROR_CODE, message, None::<()>)
}

fn busy(message: String) -> ErrorObjectOwned {
    ErrorObject::owned(SERVER_IS_BUSY_CODE, message, None::<()>)
}

fn pool_error(err: ProofAggregationPoolError) -> ErrorObjectOwned {
    match err {
        ProofAggregationPoolError::StatementProofsFull |
        ProofAggregationPoolError::AdmittedTxsFull |
        ProofAggregationPoolError::DependenciesPaused |
        ProofAggregationPoolError::AggregatorAbsent |
        ProofAggregationPoolError::AggregatesFull => busy(err.to_string()),
        ProofAggregationPoolError::TooLarge { .. } |
        ProofAggregationPoolError::AlreadyAdmitted |
        ProofAggregationPoolError::WrongStatementCount { .. } |
        ProofAggregationPoolError::TooManyPrograms { .. } |
        ProofAggregationPoolError::TooManyFoldedStatements { .. } |
        ProofAggregationPoolError::TooManyStatements |
        ProofAggregationPoolError::OutOfOrder { .. } |
        ProofAggregationPoolError::Incomplete(_) |
        ProofAggregationPoolError::InvalidProof(_) |
        ProofAggregationPoolError::Reorged => invalid_params(err.to_string()),
        // A proof the pool held when the request was checked has since been dropped.
        ProofAggregationPoolError::MissingProof(_) => {
            invalid_params(format!("{err}; send the transaction again with it"))
        }
    }
}

#[async_trait]
impl<Pool> ProofStatementApiServer for OpProofAggregationApi<Pool>
where
    Pool: TransactionPool + Clone + 'static,
{
    async fn send_raw_transaction_with_statement_proofs(
        &self,
        tx: Bytes,
        proofs: Vec<StatementProofSubmission>,
    ) -> RpcResult<B256> {
        let max_statements = MAX_STATEMENTS_PER_TX;
        if proofs.len() > max_statements {
            return Err(pool_error(ProofAggregationPoolError::WrongStatementCount {
                max: max_statements,
            }));
        }
        for submission in &proofs {
            ProofAggregationPool::check_sizes(&submission.source()).map_err(pool_error)?;
        }
        if let Some(sequencer) = &self.sequencer_client {
            return sequencer
                .request("optimism_sendRawTransactionWithStatementProofs", (tx, proofs))
                .await
                .map_err(Into::into);
        }
        if let Some(refusal) = self.pool.dependencies_refused() {
            return Err(pool_error(refusal));
        }

        let envelope = OpTxEnvelope::decode_2718_exact(&tx)
            .map_err(|err| invalid_params(format!("malformed transaction: {err}")))?;
        // The checks that need no state, as the transaction pool applies them, before paying for
        // proof verification.
        let declared = match &envelope {
            OpTxEnvelope::Aa(sealed) => {
                let aa_tx = sealed.inner();
                aa_tx.validate_static(self.chain_id).map_err(|err| {
                    invalid_params(format!("invalid EIP-8430 transaction: {err}"))
                })?;
                let sender = aa_tx
                    .recover_sender()
                    .map_err(|err| invalid_params(format!("invalid sender signature: {err}")))?;
                aa_tx
                    .recover_payer(sender)
                    .map_err(|err| invalid_params(format!("invalid payer signature: {err}")))?;
                aa_tx.declared_dependencies()
            }
            _ => {
                return Err(invalid_params(String::from(
                    "only EIP-8430 transactions declare dependencies",
                )));
            }
        };
        let dependencies = declared.as_ref().map_or(&[][..], |d| d.dependencies.as_slice());
        if dependencies.is_empty() || dependencies.len() > max_statements {
            return Err(pool_error(ProofAggregationPoolError::WrongStatementCount {
                max: max_statements,
            }));
        }
        let statements = dependencies
            .iter()
            .enumerate()
            .map(|(i, dependency)| {
                dependency.statement().ok_or_else(|| {
                    invalid_params(format!("dependency {i} is not a proof statement"))
                })
            })
            .collect::<RpcResult<Vec<_>>>()?;
        let ids: Vec<B256> = statements.iter().map(ProofStatement::id).collect();

        let leaves = proofs
            .iter()
            .filter(|proof| matches!(proof, StatementProofSubmission::Program { .. }))
            .count();
        if leaves > MAX_PROGRAM_LEAVES_PER_TX {
            return Err(invalid_params(format!(
                "a transaction may bring at most {MAX_PROGRAM_LEAVES_PER_TX} program leaves"
            )));
        }
        // Each submission's statements the transaction depends on; a program leaf may publish
        // others, which its aggregate then proves as well.
        let mut submitted: Vec<Submitted> = Vec::new();
        let mut covered: HashSet<B256> = HashSet::new();
        for (i, submission) in proofs.into_iter().enumerate() {
            let mut relied: Vec<ProofStatement> = submission
                .statements()
                .map_err(|reason| invalid_params(format!("proof {i}: {reason}")))?
                .into_iter()
                .filter(|statement| ids.contains(&statement.id()))
                .collect();
            // A leaf may publish a member more than once.
            let mut seen = HashSet::new();
            relied.retain(|statement| seen.insert(statement.id()));
            if relied.is_empty() {
                return Err(invalid_params(format!(
                    "proof {i} is for no statement the transaction depends on"
                )));
            }
            if !relied.iter().all(|statement| covered.insert(statement.id())) {
                return Err(invalid_params(String::from("the submission lists a statement twice")));
            }
            submitted.push(Submitted { submission, relied });
        }
        if let Some(id) = ids.iter().find(|id| !covered.contains(*id) && !self.pool.holds_proof(id))
        {
            return Err(invalid_params(format!("no proof of dependency {id}")));
        }

        let to_verify: Vec<Submitted> = submitted
            .into_iter()
            .filter(|submitted| !submitted.relied.iter().all(|s| self.pool.holds_proof(&s.id())))
            .collect();
        if !to_verify.is_empty() {
            let permit = self.try_verification_permit()?;
            let checked: Vec<StatementProofSubmission> =
                to_verify.iter().map(|submitted| submitted.submission.clone()).collect();
            self.verify_blocking(permit, move || {
                checked.iter().enumerate().try_for_each(|(i, submission)| {
                    submission.verify().map_err(|reason| format!("statement {i}: {reason}"))
                })
            })
            .await?;
        }

        let proofs = to_verify
            .into_iter()
            .flat_map(|Submitted { submission, relied }| {
                let source = submission.source();
                relied
                    .into_iter()
                    .map(move |statement| StatementProof { statement, source: source.clone() })
            })
            .collect();
        let hash = envelope.tx_hash();
        let key = declared.expect("it declares dependencies").key;
        self.pool.admit(key, ids, proofs).map_err(pool_error)?;
        let recovered = match recover_raw_transaction(&tx) {
            Ok(recovered) => recovered,
            Err(err) => {
                self.pool.unadmit(&key);
                return Err(invalid_params(format!("malformed transaction: {err}")));
            }
        };
        match self
            .tx_pool
            .add_transaction(TransactionOrigin::Private, Pool::Transaction::from_pooled(recovered))
            .await
        {
            // A resubmission after the admission lapsed: the pool still holds the transaction.
            Ok(_) | Err(PoolError { kind: PoolErrorKind::AlreadyImported, .. }) => Ok(hash),
            Err(err) => {
                self.pool.unadmit(&key);
                Err(invalid_params(format!("transaction pool refused the transaction: {err}")))
            }
        }
    }
}

impl<Pool> ProofAggregationAdminApiServer for OpProofAggregationApi<Pool>
where
    Pool: Send + Sync + 'static,
{
    fn pending_proof_aggregates(&self) -> RpcResult<Vec<PendingAggregate>> {
        Ok(self.pool.pending_aggregates())
    }

    fn proof_aggregation_run_blocks(&self) -> RpcResult<U64> {
        Ok(U64::from(self.pool.run_blocks()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Sealed, Signed, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use op_alloy_consensus::PROOF_STATEMENT_SCHEME;
    use reth_optimism_txpool::OpPooledTransaction;
    use reth_transaction_pool::noop::NoopTransactionPool;

    type Api = OpProofAggregationApi<NoopTransactionPool<OpPooledTransaction>>;

    /// An API whose transaction pool refuses every transaction.
    fn api() -> Api {
        OpProofAggregationApi::new(
            ProofAggregationPool::default(),
            NoopTransactionPool::<OpPooledTransaction>::new(),
            10,
            None,
        )
    }

    /// A program submission of member `byte` whose verifying key and proof are garbage.
    fn submission(byte: u8) -> StatementProofSubmission {
        StatementProofSubmission::Program {
            vkey_hash: B256::ZERO,
            members: vec![B256::repeat_byte(byte)],
            proof: Bytes::from_static(b"x"),
            verifying_key: Bytes::from_static(b"vk"),
        }
    }

    /// The one statement `submission` proves.
    fn statement(submission: &StatementProofSubmission) -> ProofStatement {
        let statements = submission.statements().unwrap();
        assert_eq!(statements.len(), 1);
        statements[0]
    }

    /// An EIP-8430 transaction depending on the statements of members `bytes`.
    fn aa_tx(bytes: &[u8]) -> Bytes {
        aa_tx_on(&bytes.iter().map(|byte| statement(&submission(*byte))).collect::<Vec<_>>())
    }

    /// An EIP-8430 transaction depending on `statements`, signed by the private key `1`.
    fn aa_tx_on(statements: &[ProofStatement]) -> Bytes {
        let dependencies = statements
            .iter()
            .map(|statement| op_alloy_consensus::Dependency {
                scheme: PROOF_STATEMENT_SCHEME,
                data_hash: statement.public_values_digest,
                verification_key_hash: statement.vkey_hash,
            })
            .collect();
        let mut tx = op_alloy_consensus::TxEip8430 {
            chain_id: 10,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 10,
            gas_limit: 500_000,
            // A dependency entry must declare at least one dependency, so none means no entry.
            account_changes: if statements.is_empty() {
                vec![]
            } else {
                vec![op_alloy_consensus::AccountChange::Dependencies { dependencies }]
            },
            calls: vec![vec![op_alloy_consensus::AaCall {
                to: Address::repeat_byte(0x22),
                value: U256::ZERO,
                data: Bytes::new(),
            }]],
            ..Default::default()
        };
        let signature = alloy_consensus::crypto::secp256k1::sign_message(
            B256::with_last_byte(1),
            tx.sender_signature_hash(),
        )
        .unwrap();
        tx.sender_auth = op_alloy_consensus::aa::k1_auth(&signature).to_vec().into();
        OpTxEnvelope::Aa(Sealed::new(tx)).encoded_2718().into()
    }

    const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../op-leanvm-tree/testdata");

    fn testdata(name: &str) -> Bytes {
        std::fs::read(format!("{TESTDATA}/{name}")).unwrap().into()
    }

    /// The fixture's program leaf: fibonacci(1000), normalized to the small program class.
    fn program_submission() -> StatementProofSubmission {
        fixture_submission("fibonacci-1000")
    }

    /// The program leaf of fixture `name`.
    fn fixture_submission(name: &str) -> StatementProofSubmission {
        let key = testdata(&format!("{name}.key"));
        let proof = testdata(&format!("{name}.proof"));
        let members: Vec<B256> =
            testdata(&format!("{name}.members")).chunks_exact(32).map(B256::from_slice).collect();
        StatementProofSubmission::Program {
            vkey_hash: op_leanvm_tree::verify_program_leaf(&key, &members, &proof).unwrap(),
            members,
            proof,
            verifying_key: key,
        }
    }

    /// The fixture's first leanSPHINCS signature.
    fn signature_submission() -> StatementProofSubmission {
        StatementProofSubmission::Signature {
            public_key: testdata("signature-0.key"),
            message: B256::from_slice(&testdata("signature-0.message")),
            signature: testdata("signature-0.signature"),
        }
    }

    async fn rejection(api: &Api, tx: Bytes, proofs: Vec<StatementProofSubmission>) -> String {
        let err = api.send_raw_transaction_with_statement_proofs(tx, proofs).await.unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        err.message().to_owned()
    }

    #[tokio::test]
    async fn verifies_program_leaves() {
        let api = api();
        let proof = program_submission();
        // The proof verifies, so the submission reaches the transaction pool, which refuses it.
        let err = rejection(&api, aa_tx_on(&[statement(&proof)]), vec![proof.clone()]).await;
        assert!(err.contains("transaction pool refused"), "{err}");

        let edit = |f: &dyn Fn(&mut B256, &mut Vec<B256>, &mut Bytes)| {
            let mut edited = proof.clone();
            let StatementProofSubmission::Program { vkey_hash, members, verifying_key, .. } =
                &mut edited
            else {
                unreachable!()
            };
            f(vkey_hash, members, verifying_key);
            edited
        };
        let wrong_member = edit(&|_, members, _| members[0].0[0] ^= 1);
        let err = rejection(&api, aa_tx_on(&[statement(&wrong_member)]), vec![wrong_member]).await;
        assert!(err.contains("proof rejected"), "{err}");

        let wrong_key = edit(&|vkey_hash, _, _| *vkey_hash = B256::repeat_byte(1));
        let err = rejection(&api, aa_tx_on(&[statement(&wrong_key)]), vec![wrong_key]).await;
        assert!(err.contains("verifying key's digest"), "{err}");

        let elf = edit(&|_, _, key| *key = testdata("fibonacci-members.elf"));
        let err = rejection(&api, aa_tx_on(&[statement(&elf)]), vec![elf]).await;
        assert!(err.contains("verifying key"), "a guest ELF is no verifying key: {err}");
    }

    #[tokio::test]
    async fn verifies_large_program_leaves() {
        let api = api();
        let large = fixture_submission("fibonacci-1000-large");
        let small = program_submission();
        assert_ne!(statement(&large).vkey_hash, statement(&small).vkey_hash);
        let err = rejection(&api, aa_tx_on(&[statement(&large)]), vec![large.clone()]).await;
        assert!(err.contains("transaction pool refused"), "{err}");

        // A large class's proof under the small class's key of the same program is refused.
        let StatementProofSubmission::Program { verifying_key, .. } = small else { unreachable!() };
        let mut mixed = large;
        let StatementProofSubmission::Program { verifying_key: key, .. } = &mut mixed else {
            unreachable!()
        };
        *key = verifying_key;
        let err = rejection(&api, aa_tx_on(&[statement(&mixed)]), vec![mixed]).await;
        assert!(err.contains("verifying key"), "{err}");
    }

    #[tokio::test]
    async fn verifies_signatures() {
        let api = api();
        let signed = signature_submission();
        assert_eq!(statement(&signed).vkey_hash, op_leanvm_tree::SIGNATURE_PROGRAM_DIGEST);
        let err = rejection(&api, aa_tx_on(&[statement(&signed)]), vec![signed.clone()]).await;
        assert!(err.contains("transaction pool refused"), "{err}");

        let StatementProofSubmission::Signature { public_key, message, signature } = signed else {
            unreachable!()
        };
        let mut flipped = signature.to_vec();
        flipped[100] ^= 1;
        let bad = StatementProofSubmission::Signature {
            public_key: public_key.clone(),
            message,
            signature: flipped.into(),
        };
        let err = rejection(&api, aa_tx_on(&[statement(&bad)]), vec![bad]).await;
        assert!(err.contains("signature rejected"), "{err}");

        let short = StatementProofSubmission::Signature {
            public_key,
            message,
            signature: signature.slice(..signature.len() - 8),
        };
        let err = rejection(&api, aa_tx(&[1]), vec![short]).await;
        assert!(err.contains("proof 0: a signature is"), "{err}");
    }

    #[tokio::test]
    async fn rejects_a_transaction_that_is_not_an_eip_8430_transaction() {
        let signed = Signed::new_unhashed(
            TxEip1559 { chain_id: 10, to: TxKind::Call(Address::ZERO), ..Default::default() },
            Signature::test_signature(),
        );
        let tx = OpTxEnvelope::Eip1559(signed).encoded_2718().into();
        assert!(
            rejection(&api(), tx, vec![submission(1)]).await.contains("only EIP-8430 transactions")
        );
    }

    #[tokio::test]
    async fn rejects_proofs_that_do_not_match_the_dependencies() {
        let api = api();
        assert!(rejection(&api, aa_tx(&[]), vec![]).await.contains("between 1 and"));
        assert!(rejection(&api, aa_tx(&[1]), vec![]).await.contains("no proof of dependency"));
        assert!(
            rejection(&api, aa_tx(&[1]), vec![submission(1), submission(2)])
                .await
                .contains("no statement the transaction depends on")
        );
        assert!(
            rejection(&api, aa_tx(&[1]), vec![submission(1), submission(1)])
                .await
                .contains("twice")
        );
        assert!(
            rejection(&api, aa_tx(&[1]), vec![submission(1)])
                .await
                .contains("statement 0: proof rejected")
        );
        assert!(!api.pool.holds_proof(&statement(&submission(1)).id()));
        let many: Vec<_> = (1..=MAX_PROGRAM_LEAVES_PER_TX as u8 + 1).map(submission).collect();
        let bytes: Vec<u8> = (1..=MAX_PROGRAM_LEAVES_PER_TX as u8 + 1).collect();
        assert!(rejection(&api, aa_tx(&bytes), many).await.contains("at most"));
    }

    /// A transaction whose proofs are held needs none, and an admission the transaction pool
    /// refuses is withdrawn.
    #[tokio::test]
    async fn withdraws_the_admission_when_the_transaction_pool_refuses() {
        let api = api();
        let proof =
            StatementProof { statement: statement(&submission(1)), source: submission(1).source() };
        let id = proof.statement.id();
        api.pool.admit(B256::repeat_byte(1), vec![id], vec![proof]).unwrap();

        let tx = aa_tx(&[1]);
        let message = rejection(&api, tx.clone(), vec![]).await;
        assert!(message.contains("transaction pool refused"), "{message}");
        let key = op_alloy_consensus::declared_dependencies(&tx).unwrap().key;
        assert_eq!(api.pool.admitted(&key), None);
        assert!(api.pool.holds_proof(&id), "the other transaction still needs the proof");
    }

    /// An EIP-8430 transaction is admitted under its sender hash; one whose sender signature does
    /// not verify is refused before any proof is verified.
    #[tokio::test]
    async fn admits_an_eip_8430_transaction_under_its_sender_hash() {
        let api = api();
        let proof =
            StatementProof { statement: statement(&submission(1)), source: submission(1).source() };
        let id = proof.statement.id();
        api.pool.admit(B256::repeat_byte(1), vec![id], vec![proof]).unwrap();

        let tx = aa_tx_on(&[statement(&submission(1))]);
        let message = rejection(&api, tx.clone(), vec![]).await;
        assert!(message.contains("transaction pool refused"), "{message}");
        let declared = op_alloy_consensus::declared_dependencies(&tx).unwrap();
        let aa_tx = op_alloy_consensus::TxEip8430::decode_2718(&mut tx.as_ref()).unwrap();
        assert_eq!(declared.key, aa_tx.sender_signature_hash());

        let mut forged = aa_tx;
        forged.sender_auth = Bytes::from(vec![0x11; 65]);
        let forged = OpTxEnvelope::Aa(Sealed::new(forged)).encoded_2718().into();
        let message = rejection(&api, forged, vec![submission(1)]).await;
        assert!(message.contains("invalid sender signature"), "{message}");
    }
}
