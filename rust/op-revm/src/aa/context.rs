//! The Transaction Context precompile ([EIP-8430]) at [`TX_CONTEXT_ADDRESS`].
//!
//! An executing [EIP-8430] transaction publishes its resolved sender, its payer and its
//! dependencies to transient storage of the precompile's address before its calls run (see
//! [`publish`]). No code runs at that address, so EVM code cannot write these slots, and the
//! journal drops them when the transaction ends. For any other transaction nothing is published
//! and the sender and payer getters return `tx.origin`.
//!
//! The precompile reads the slots back through whichever precompile provider is installed, so a
//! provider only needs a transient-storage read and the transaction's caller. Calls cost
//! [`OUTPUT_WORD_GAS`] per 32 bytes returned, and `isTransactionStatement` its hash besides
//! ([`STATEMENT_HASH_GAS`]). A call with value, a call through `DELEGATECALL` or
//! `CALLCODE`, an unknown selector and an index past the end revert without using gas.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385

use crate::OpSpecId;
use op_alloy_consensus::{Dependency, StatementActor, TX_CONTEXT_ADDRESS};
use revm::{
    context_interface::{ContextTr, JournalTr, Transaction},
    handler::precompile_output_to_interpreter_result,
    interpreter::{CallInputs, InterpreterResult},
    precompile::{
        Precompile, PrecompileError, PrecompileHalt, PrecompileId, PrecompileOutput,
        PrecompileResult,
    },
    primitives::{Address, B256, Bytes, U256, keccak256},
};
use std::vec::Vec;

/// Gas per 32 bytes the precompile returns.
pub const OUTPUT_WORD_GAS: u64 = 3;

/// Gas of the BLAKE2s hash `isTransactionStatement` computes: SHA-256's for its 80 bytes.
pub const STATEMENT_HASH_GAS: u64 = 60 + 12 * 3;

/// `getTransactionPayer()`.
const GET_PAYER: [u8; 4] = [0x69, 0x0b, 0x3a, 0x9d];
/// `getTransactionSender()`.
const GET_SENDER: [u8; 4] = [0xbe, 0xad, 0x3f, 0x50];
/// `getTransactionDependencyCount()`.
const GET_DEPENDENCY_COUNT: [u8; 4] = [0x0b, 0x08, 0x9f, 0x96];
/// `getTransactionDependency(uint256)`.
const GET_DEPENDENCY: [u8; 4] = [0x5e, 0x9f, 0xee, 0x6e];
/// `isTransactionDependency(bytes32,bytes32)`.
const IS_DEPENDENCY: [u8; 4] = [0x8d, 0xd4, 0xca, 0x91];
/// `isTransactionStatement(bytes32,bytes8,bytes32,bytes32)`: whether the transaction depends on
/// the statement `(0x20, BLAKE2s(tag || key || hash), vk)` (a STATEMENT actor's authorization of
/// `hash`).
const IS_STATEMENT: [u8; 4] = [0x80, 0xf9, 0x9a, 0x80];

/// Transient slot of the resolved sender.
const SENDER_SLOT: U256 = U256::ZERO;
/// Transient slot of the resolved payer.
const PAYER_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);
/// Transient slot of the number of dependencies.
const COUNT_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
/// First transient slot of the dependency list: dependency `i` takes `scheme`, `data_hash` and
/// `verification_key_hash` at `3i + 3` onwards.
const FIRST_DEPENDENCY_SLOT: u64 = 3;

/// The transient slot marking `(verification_key_hash, data_hash)` as a declared statement.
fn membership_slot(verification_key_hash: B256, data_hash: B256) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(verification_key_hash.as_slice());
    preimage[32..].copy_from_slice(data_hash.as_slice());
    keccak256(preimage).into()
}

fn dependency_slot(index: u64, field: u64) -> U256 {
    U256::from(FIRST_DEPENDENCY_SLOT + 3 * index + field)
}

/// Publishes an [EIP-8430] transaction's context for the precompile. The resolved sender and
/// payer of such a transaction are never zero (no key recovers to the zero address, and the
/// Keystore configures no actor for it), so a zero slot means another transaction type.
///
/// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
pub fn publish<J: JournalTr>(
    journal: &mut J,
    sender: Address,
    payer: Address,
    dependencies: &[Dependency],
) {
    journal.tstore(TX_CONTEXT_ADDRESS, SENDER_SLOT, sender.into_word().into());
    journal.tstore(TX_CONTEXT_ADDRESS, PAYER_SLOT, payer.into_word().into());
    journal.tstore(TX_CONTEXT_ADDRESS, COUNT_SLOT, U256::from(dependencies.len()));
    for (index, dependency) in dependencies.iter().enumerate() {
        let index = index as u64;
        journal.tstore(
            TX_CONTEXT_ADDRESS,
            dependency_slot(index, 0),
            U256::from(dependency.scheme),
        );
        journal.tstore(TX_CONTEXT_ADDRESS, dependency_slot(index, 1), dependency.data_hash.into());
        journal.tstore(
            TX_CONTEXT_ADDRESS,
            dependency_slot(index, 2),
            dependency.verification_key_hash.into(),
        );
        if let Some(statement) = dependency.statement() {
            journal.tstore(
                TX_CONTEXT_ADDRESS,
                membership_slot(statement.vkey_hash, statement.public_values_digest),
                U256::from(1),
            );
        }
    }
}

/// A call to the precompile, as every precompile provider sees it.
#[derive(Debug)]
pub struct ContextCall<'a> {
    /// Calldata.
    pub input: &'a [u8],
    /// Gas given to the call.
    pub gas_limit: u64,
    /// The EIP-8037 state gas reservoir, returned untouched.
    pub reservoir: u64,
    /// Whether the call carries value.
    pub with_value: bool,
    /// Whether the call executes in the precompile's own context (not `DELEGATECALL` or
    /// `CALLCODE`).
    pub direct: bool,
    /// `tx.origin`.
    pub origin: Address,
}

/// Runs a call to the precompile, reading the published context with `tload`.
pub fn run(call: ContextCall<'_>, mut tload: impl FnMut(U256) -> U256) -> PrecompileOutput {
    let revert = PrecompileOutput::revert(0, Bytes::new(), call.reservoir);
    if call.with_value || !call.direct {
        return revert;
    }
    let address_or_origin = |word: U256| {
        if word.is_zero() { call.origin } else { Address::from_word(word.into()) }
    };
    let (selector, args) = match call.input.split_first_chunk::<4>() {
        Some((selector, args)) => (*selector, args),
        None => return revert,
    };
    // The gas is known before any work: the words returned, and the hash `isTransactionStatement`
    // computes.
    let gas_used = match (selector, args.len()) {
        (GET_PAYER | GET_SENDER | GET_DEPENDENCY_COUNT, 0) | (IS_DEPENDENCY, 64) => OUTPUT_WORD_GAS,
        (GET_DEPENDENCY, 32) => 3 * OUTPUT_WORD_GAS,
        (IS_STATEMENT, 128) => OUTPUT_WORD_GAS + STATEMENT_HASH_GAS,
        _ => return revert,
    };
    if gas_used > call.gas_limit {
        return PrecompileOutput::halt(PrecompileHalt::OutOfGas, call.reservoir);
    }
    let output: Vec<u8> = match (selector, args.len()) {
        (GET_PAYER, 0) => address_or_origin(tload(PAYER_SLOT)).into_word().to_vec(),
        (GET_SENDER, 0) => address_or_origin(tload(SENDER_SLOT)).into_word().to_vec(),
        (GET_DEPENDENCY_COUNT, 0) => tload(COUNT_SLOT).to_be_bytes::<32>().to_vec(),
        (GET_DEPENDENCY, 32) => {
            let index = U256::from_be_slice(args);
            if index >= tload(COUNT_SLOT) {
                return revert;
            }
            let index = index.to::<u64>();
            (0..3)
                .flat_map(|field| tload(dependency_slot(index, field)).to_be_bytes::<32>())
                .collect()
        }
        (IS_DEPENDENCY, 64) => {
            let verification_key_hash = B256::from_slice(&args[..32]);
            let data_hash = B256::from_slice(&args[32..]);
            tload(membership_slot(verification_key_hash, data_hash)).to_be_bytes::<32>().to_vec()
        }
        (IS_STATEMENT, 128) => {
            // A `bytes8` is left-aligned in its word, the rest zero.
            if args[40..64].iter().any(|byte| *byte != 0) {
                return revert;
            }
            let actor = StatementActor {
                vk: B256::from_slice(&args[..32]),
                tag: args[32..40].try_into().expect("8 bytes"),
                key: B256::from_slice(&args[64..96]),
            };
            let statement = actor.dependency(B256::from_slice(&args[96..]));
            tload(membership_slot(statement.verification_key_hash, statement.data_hash))
                .to_be_bytes::<32>()
                .to_vec()
        }
        _ => return revert,
    };
    PrecompileOutput::new(gas_used, output.into(), call.reservoir)
}

/// Serves the call if it is to the precompile and `spec` has it: every
/// [`revm::handler::PrecompileProvider`] runs this before its own lookup, because the precompile's
/// static entry ([`TX_CONTEXT`]) cannot see the transaction.
pub fn intercept<CTX: ContextTr>(
    spec: OpSpecId,
    context: &mut CTX,
    inputs: &CallInputs,
) -> Option<InterpreterResult> {
    (inputs.bytecode_address == TX_CONTEXT_ADDRESS && spec.is_enabled_in(OpSpecId::LAGOON))
        .then(|| run_in_context(context, inputs))
}

/// Runs a call to the precompile for a [`revm::handler::PrecompileProvider`].
pub fn run_in_context<CTX: ContextTr>(context: &mut CTX, inputs: &CallInputs) -> InterpreterResult {
    // Every getter takes 4, 36, 68 or 132 bytes: refuse any other input before copying it out of
    // the caller's memory.
    let input = if matches!(inputs.input.len(), 4 | 36 | 68 | 132) {
        inputs.input.bytes(context)
    } else {
        Bytes::new()
    };
    let call = ContextCall {
        input: &input,
        gas_limit: inputs.gas_limit,
        reservoir: inputs.reservoir,
        with_value: inputs.transfers_value(),
        direct: inputs.scheme.is_call() || inputs.scheme.is_static_call(),
        origin: context.tx().caller(),
    };
    let output = run(call, |slot| context.journal_mut().tload(TX_CONTEXT_ADDRESS, slot));
    precompile_output_to_interpreter_result(output, inputs.gas_limit)
}

/// The precompile's entry in a static precompile set.
///
/// It reserves the address (warm, and a precompile for delegation and `EXTCODE*` purposes), but
/// it cannot see the transaction: every precompile provider runs [`run`] in its place, and the
/// entry itself always fails.
pub const TX_CONTEXT: Precompile = Precompile::new(
    PrecompileId::Custom(std::borrow::Cow::Borrowed("TxContext")),
    TX_CONTEXT_ADDRESS,
    unreachable_context,
);

fn unreachable_context(_input: &[u8], _gas_limit: u64, _reservoir: u64) -> PrecompileResult {
    Err(PrecompileError::Fatal("the transaction context precompile needs its provider".into()))
}
