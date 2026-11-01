//! Execution of [EIP-8430] transactions.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385

use super::{
    AaTxOutcome, context,
    keystore::{self, Authorizer, Authorizers},
    recover_k1,
};
use crate::{
    L1BlockInfo, OpHaltReason, OpSpecId,
    api::exec::OpContextTr,
    constants::{BASE_FEE_RECIPIENT, L1_FEE_RECIPIENT, OPERATOR_FEE_RECIPIENT},
    handler::{IsTxError, OpHandler},
    transaction::{OpTransactionError, OpTxTr, error::AaTxInvalid},
};
use op_alloy_consensus::{
    AaCall, AaTxError, Actor, Authorization, MAX_AUTHENTICATION_GAS, Payer, SenderGas,
    keystore::KEYSTORE_ADDRESS,
};
use revm::{
    Database,
    bytecode::Bytecode,
    context::{
        LocalContextTr, journaled_state::account::JournaledAccountTr, result::InvalidTransaction,
    },
    context_interface::{
        Block, Cfg, ContextTr, JournalTr, Transaction,
        cfg::GasId,
        result::{ExecutionResult, FromStringError, Output, ResultGas, SuccessReason},
    },
    handler::{
        EvmTr, FrameResult, Handler, evm::FrameTr, handle_reservoir_remaining_gas,
        handler::EvmTrError,
    },
    interpreter::{
        CallInput, CallInputs, CallScheme, CallValue, FrameInput, GasTracker, SharedMemory,
        interpreter_action::FrameInit,
    },
    primitives::{Address, Bytes, KECCAK_EMPTY, U256},
};
use std::boxed::Box;

/// How one call ended.
struct CallRun {
    succeeded: bool,
    gas_used: u64,
    refunded: i64,
    /// What the call returned, or its revert data.
    output: Bytes,
}

impl<EVM, ERROR, FRAME> OpHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Context: OpContextTr, Frame = FRAME>,
    ERROR: EvmTrError<EVM> + From<OpTransactionError> + FromStringError + IsTxError,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
    Self: Handler<Evm = EVM, Error = ERROR, HaltReason = OpHaltReason>,
{
    /// Runs an [EIP-8430] transaction. `run_call` executes one top-level call (with or without an
    /// inspector).
    ///
    /// A valid transaction always ends in [`ExecutionResult::Success`], whether or not its phases
    /// all committed: committed phases keep their state and logs, and the payer pays either way.
    /// The output is the [`AaTxOutcome`], whose `success` is the receipt's status; read that
    /// rather than [`ExecutionResult::is_success`].
    ///
    /// [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
    pub fn run_aa_tx(
        &mut self,
        evm: &mut EVM,
        mut run_call: impl FnMut(&mut Self, &mut EVM, FrameInit) -> Result<FrameResult, ERROR>,
    ) -> Result<ExecutionResult<OpHaltReason>, ERROR> {
        match self.run_aa_tx_inner(evm, &mut run_call) {
            Ok(result) => Ok(result),
            Err(error) => self.catch_error(evm, error),
        }
    }

    fn run_aa_tx_inner(
        &mut self,
        evm: &mut EVM,
        run_call: &mut impl FnMut(&mut Self, &mut EVM, FrameInit) -> Result<FrameResult, ERROR>,
    ) -> Result<ExecutionResult<OpHaltReason>, ERROR> {
        let invalid = |reason| ERROR::from(OpTransactionError::AaTx(reason));
        let Some(env) = evm.ctx().tx().aa_tx().cloned() else {
            return Err(invalid(AaTxInvalid::MissingTransaction));
        };
        let tx = &env.tx;
        let sender = evm.ctx().tx().caller();
        // A simulation's transaction has the signed one's shape, fee caps included, so it is
        // priced in gas like it; the prices it pays are the request's, in the environment.
        let (max_fee_per_gas, max_priority_fee_per_gas) = if env.is_simulation() {
            let tx_env = evm.ctx_ref().tx();
            (tx_env.gas_price(), tx_env.max_priority_fee_per_gas().unwrap_or_default())
        } else {
            (tx.max_fee_per_gas, tx.max_priority_fee_per_gas)
        };

        // Validation that needs no state.
        let ctx = evm.ctx();
        let spec = ctx.cfg().spec();
        if !spec.is_enabled_in(OpSpecId::LAGOON) {
            return Err(invalid(AaTxInvalid::NotActive));
        }
        tx.validate_static(ctx.cfg().chain_id()).map_err(|e| invalid(AaTxInvalid::Static(e)))?;
        if tx.sender.is_some_and(|named| named != sender) {
            return Err(invalid(AaTxInvalid::WrongSender));
        }
        if !tx.is_valid_at(ctx.block().timestamp().saturating_to()) {
            return Err(invalid(AaTxInvalid::OutsideValidityWindow));
        }
        let basefee = ctx.block().basefee() as u128;
        if !ctx.cfg().is_base_fee_check_disabled() && max_fee_per_gas < basefee {
            return Err(
                OpTransactionError::Base(InvalidTransaction::GasPriceLessThanBasefee).into()
            );
        }
        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(
                OpTransactionError::Base(InvalidTransaction::PriorityFeeGreaterThanMaxFee).into()
            );
        }
        if tx.payer_gas_reserve() > MAX_AUTHENTICATION_GAS {
            return Err(invalid(AaTxInvalid::PayerAuthenticationGas));
        }
        let effective_gas_limit = tx.effective_gas_limit();
        if !ctx.cfg().is_block_gas_limit_disabled() && effective_gas_limit > ctx.block().gas_limit()
        {
            return Err(
                OpTransactionError::Base(InvalidTransaction::CallerGasLimitMoreThanBlock).into()
            );
        }
        // EIP-7825 caps the effective gas limit, as EIP-8430 asks.
        let cap = ctx.cfg().tx_gas_limit_cap();
        if !ctx.cfg().is_amsterdam_eip8037_enabled() && effective_gas_limit > cap {
            return Err(OpTransactionError::Base(InvalidTransaction::TxGasLimitGreaterThanCap {
                gas_limit: effective_gas_limit,
                cap,
            })
            .into());
        }
        let SenderGas { intrinsic: sender_intrinsic_gas, floor: sender_floor } =
            tx.sender_gas(sender);
        if tx.gas_limit < sender_floor {
            return Err(OpTransactionError::Base(InvalidTransaction::GasFloorMoreThanGasLimit {
                gas_floor: sender_floor,
                gas_limit: tx.gas_limit,
            })
            .into());
        }
        // Who authorized the sender and the payer. A simulation verifies no signature: a
        // secp256k1 authorization stands for the account's admin.
        let simulated = env.is_simulation();
        let k1 = |signature, digest, error| {
            recover_k1(signature, digest).map(Actor::Key).ok_or_else(|| invalid(error))
        };
        let sender_authorizer = match tx.sender_authorization() {
            Some(Authorization::Statement(actor)) => Authorizer::Actor(Actor::Statement(actor)),
            Some(Authorization::K1(_)) if simulated => Authorizer::Admin,
            // The caller of a recovered sender is the signer.
            Some(Authorization::K1(_)) if tx.sender.is_none() => {
                Authorizer::Actor(Actor::Key(sender))
            }
            Some(Authorization::K1(signature)) => Authorizer::Actor(k1(
                signature,
                tx.sender_signature_hash(),
                AaTxInvalid::SenderSignature,
            )?),
            None => return Err(invalid(AaTxInvalid::Static(AaTxError::SenderAuthShape))),
        };
        let payer_authorizer = match (tx.payer, tx.payer_authorization()) {
            (Payer::SelfPay, _) => None,
            (Payer::Named(named), Some(Authorization::Statement(actor))) => {
                Some((named, Authorizer::Actor(Actor::Statement(actor))))
            }
            (Payer::Named(named), Some(Authorization::K1(_))) if simulated => {
                Some((named, Authorizer::Admin))
            }
            (Payer::Open, Some(Authorization::K1(_))) if simulated => {
                Some((sender, Authorizer::Admin))
            }
            (Payer::Named(named), Some(Authorization::K1(signature))) => {
                let signer =
                    k1(signature, tx.payer_signature_hash(sender), AaTxInvalid::PayerSignature)?;
                Some((named, Authorizer::Actor(signer)))
            }
            (Payer::Open, Some(Authorization::K1(signature))) => {
                let signer =
                    k1(signature, tx.payer_signature_hash(sender), AaTxInvalid::PayerSignature)?;
                let Actor::Key(address) = signer else { unreachable!("a key") };
                Some((address, Authorizer::Actor(signer)))
            }
            // `validate_static` admits no other shape.
            _ => return Err(invalid(AaTxInvalid::Static(AaTxError::PayerAuthShape))),
        };
        let payer = payer_authorizer.map_or(sender, |(payer, _)| payer);
        let authorizers = Authorizers { sender: sender_authorizer, payer: payer_authorizer };

        // Warm the coinbase and precompiles before any account is loaded.
        self.mainnet.load_accounts(evm)?;

        // Fees: the L1 block info is cached per block, as for other transactions.
        let (block, tx_env, cfg, journal, chain, _) = evm.ctx().all_mut();
        if chain.l2_block != Some(block.number()) {
            *chain = L1BlockInfo::try_fetch(journal.db_mut(), block.number(), spec)?;
        }
        let fees_charged = !cfg.is_fee_charge_disabled();
        let Some(enveloped) = tx_env.enveloped_tx().cloned() else {
            return Err(OpTransactionError::MissingEnvelopedTx.into());
        };
        let effective_price = max_fee_per_gas.min(basefee.saturating_add(max_priority_fee_per_gas));
        let l1_cost = if fees_charged {
            chain
                .calculate_tx_l1_cost(&enveloped, spec)
                .saturating_add(chain.dependency_l1_cost(tx.dependency_count()))
        } else {
            U256::ZERO
        };
        let operator_fee = |chain: &L1BlockInfo, gas: u64| {
            if fees_charged {
                chain.operator_fee_charge(&enveloped, U256::from(gas), spec)
            } else {
                U256::ZERO
            }
        };
        let fees_at = |chain: &L1BlockInfo, gas: u64, price: u128| {
            U256::from(gas) * U256::from(price) + l1_cost + operator_fee(chain, gas)
        };
        let precharge = if fees_charged {
            fees_at(chain, effective_gas_limit, effective_price)
        } else {
            U256::ZERO
        };

        // The sender's nonce and code, before anything changes state.
        let sender_account = journal.load_account_with_code(sender)?;
        let state_nonce = sender_account.data.info.nonce;
        let sender_code = sender_account.data.info.code.clone().unwrap_or_default();
        if !cfg.is_nonce_check_disabled() && state_nonce != tx.nonce_sequence {
            let error = if tx.nonce_sequence > state_nonce {
                InvalidTransaction::NonceTooHigh { tx: tx.nonce_sequence, state: state_nonce }
            } else {
                InvalidTransaction::NonceTooLow { tx: tx.nonce_sequence, state: state_nonce }
            };
            return Err(OpTransactionError::Base(error).into());
        }
        if !sender_code.is_empty() && !sender_code.is_eip7702() {
            if tx.delegation().is_some() {
                return Err(invalid(AaTxInvalid::DelegationOverCode));
            }
            // EIP-3607 refuses a key recovering to a contract's address. The account's other actors
            // are not that key, and the Keystore below checks them like any others.
            if !cfg.is_eip3607_disabled() &&
                authorizers.sender == Authorizer::Actor(Actor::Key(sender))
            {
                return Err(
                    OpTransactionError::Base(InvalidTransaction::RejectCallerWithCode).into()
                );
            }
        }

        // The Keystore, read before the transaction changes it: each authorizer configured for
        // its account, live, and allowed its role.
        let now = block.timestamp().saturating_to();
        keystore::authorize(tx, sender, authorizers, now, |slot| {
            journal.db_mut().storage(KEYSTORE_ADDRESS, slot)
        })?
        .map_err(invalid)?;

        // Fees precharged from the payer.
        if fees_charged {
            let max_cost = fees_at(chain, effective_gas_limit, max_fee_per_gas);
            let balance_check = !cfg.is_balance_check_disabled();
            let mut payer_account = journal.load_account_mut(payer)?;
            let balance = *payer_account.balance();
            if balance < max_cost {
                if balance_check {
                    return Err(OpTransactionError::Base(
                        InvalidTransaction::LackOfFundForMaxFee {
                            fee: Box::new(max_cost),
                            balance: Box::new(balance),
                        },
                    )
                    .into());
                }
                payer_account.set_balance(balance.max(precharge));
            }
            let balance = *payer_account.balance();
            payer_account.set_balance(balance - precharge);
        } else {
            journal.load_account(payer)?;
        }

        // The nonce, the account changes and the context, in that order.
        let journal = evm.ctx().journal_mut();
        journal.load_account_mut(sender)?.bump_nonce();
        if let Some(target) = tx.delegation() {
            let (code, hash) = if target.is_zero() {
                (Bytecode::default(), KECCAK_EMPTY)
            } else {
                let code = Bytecode::new_eip7702(target);
                let hash = code.hash_slow();
                (code, hash)
            };
            journal.touch_account(sender);
            journal.set_code_with_hash(sender, code, hash);
        }
        context::publish(journal, sender, payer, &env.dependencies);

        // The phases, from one pool of gas.
        let mut pool = tx.gas_limit - sender_intrinsic_gas;
        let mut refund_counter = 0i64;
        let mut committed_phases = 0u64;
        let mut last_output = Bytes::new();
        'phases: for phase in &tx.calls {
            let checkpoint = evm.ctx().journal_mut().checkpoint();
            let phase_refund = refund_counter;
            for call in phase {
                let run = self.run_aa_call(evm, run_call, sender, call, pool)?;
                pool -= run.gas_used;
                last_output = run.output;
                if !run.succeeded {
                    evm.ctx().journal_mut().checkpoint_revert(checkpoint);
                    refund_counter = phase_refund;
                    break 'phases;
                }
                refund_counter += run.refunded;
            }
            evm.ctx().journal_mut().checkpoint_commit();
            committed_phases += 1;
        }
        let success = committed_phases == tx.calls.len() as u64;

        // Settlement.
        let execution_gas_used = tx.gas_limit - sender_intrinsic_gas - pool;
        // Payer authentication is never refundable, so it stays out of the refund cap.
        let sender_gas_used = sender_intrinsic_gas + execution_gas_used;
        let before_refund = sender_gas_used + tx.payer_auth_cost();
        let refund = (refund_counter.max(0) as u64)
            .min(sender_gas_used / evm.ctx().cfg().gas_params().max_refund_quotient());
        let floor = sender_floor + tx.payer_gas_reserve();
        let gas_used = (before_refund - refund).max(floor);

        if fees_charged {
            let ctx = evm.ctx();
            let coinbase = ctx.block().beneficiary();
            let charged = fees_at(ctx.chain(), gas_used, effective_price);
            let operator_fee = operator_fee(ctx.chain(), gas_used);
            let journal = ctx.journal_mut();
            journal.balance_incr(payer, precharge.saturating_sub(charged))?;
            journal.balance_incr(
                coinbase,
                U256::from(gas_used) * U256::from(effective_price.saturating_sub(basefee)),
            )?;
            journal.balance_incr(
                BASE_FEE_RECIPIENT,
                U256::from(gas_used) * U256::from(basefee.min(effective_price)),
            )?;
            journal.balance_incr(L1_FEE_RECIPIENT, l1_cost)?;
            journal.balance_incr(OPERATOR_FEE_RECIPIENT, operator_fee)?;
        }

        let ctx = evm.ctx();
        let logs = ctx.journal_mut().take_logs();
        ctx.journal_mut().commit_tx();
        ctx.chain_mut().clear_tx_l1_cost();
        ctx.local_mut().clear();
        evm.frame_stack().clear();

        if env.is_simulation() {
            let gas = ResultGas::new_with_state_gas(before_refund, refund, floor, 0);
            return Ok(if success {
                ExecutionResult::Success {
                    reason: SuccessReason::Stop,
                    gas,
                    logs,
                    output: Output::Call(last_output),
                }
            } else {
                ExecutionResult::Revert { gas, logs, output: last_output }
            });
        }
        let output = AaTxOutcome { payer, committed_phases, success }.encode();
        Ok(ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::new_with_state_gas(before_refund, refund, floor, 0),
            logs,
            output: Output::Call(output.to_vec().into()),
        })
    }

    /// Runs one call of a phase with all of the pool's gas: the access charges, the
    /// account-creation charge of a value transfer, and the call itself.
    fn run_aa_call(
        &mut self,
        evm: &mut EVM,
        run_call: &mut impl FnMut(&mut Self, &mut EVM, FrameInit) -> Result<FrameResult, ERROR>,
        sender: Address,
        call: &AaCall,
        pool: u64,
    ) -> Result<CallRun, ERROR> {
        let failed =
            |gas_used| CallRun { succeeded: false, gas_used, refunded: 0, output: Bytes::new() };
        let mut gas = GasTracker::new(pool, pool, 0);

        // EIP-2929 cold access to the target and to its delegate; warm accounts cost nothing.
        let ctx = evm.ctx();
        let cold_cost = {
            let params = ctx.cfg().gas_params();
            params.warm_storage_read_cost() + params.cold_account_additional_cost()
        };
        let account = ctx.journal_mut().load_account_with_code(call.to)?;
        let target_empty = account.data.info.is_empty();
        let code = account.data.info.code.clone().unwrap_or_default();
        let mut known_bytecode = (account.data.info.code_hash, code.clone());
        if account.is_cold && !gas.record_regular_cost(cold_cost) {
            return Ok(failed(pool));
        }
        if let Some(delegate) = code.eip7702_address() {
            let account = evm.ctx().journal_mut().load_account_with_code(delegate)?;
            known_bytecode = (
                account.data.info.code_hash,
                account.data.info.code.clone().unwrap_or_else(Bytecode::default),
            );
            if account.is_cold && !gas.record_regular_cost(cold_cost) {
                return Ok(failed(pool));
            }
        }

        // A value transfer the sender cannot cover fails like `CALL`, returning the call's gas.
        let value = if call.value.is_zero() {
            CallValue::Apparent(U256::ZERO)
        } else {
            let balance = evm.ctx().journal_mut().load_account(sender)?.data.info.balance;
            if balance < call.value {
                return Ok(failed(pool - gas.remaining()));
            }
            if target_empty {
                let new_account = evm.ctx().cfg().gas_params().get(GasId::new_account_cost());
                if !gas.record_regular_cost(new_account) {
                    return Ok(failed(pool));
                }
            }
            CallValue::Transfer(call.value)
        };

        let inputs = CallInputs {
            input: CallInput::Bytes(call.data.clone()),
            return_memory_offset: 0..0,
            gas_limit: gas.remaining(),
            reservoir: gas.reservoir(),
            bytecode_address: call.to,
            known_bytecode,
            target_address: call.to,
            caller: sender,
            value,
            scheme: CallScheme::Call,
            is_static: false,
            charged_new_account_state_gas: false,
        };
        // Each call starts with fresh, empty memory.
        let ctx = evm.ctx();
        ctx.local_mut().clear();
        let mut memory = SharedMemory::new_with_buffer(ctx.local().shared_memory_buffer().clone());
        memory.set_memory_limit(ctx.cfg().memory_limit());
        let init = FrameInit { depth: 0, memory, frame_input: FrameInput::Call(Box::new(inputs)) };
        let mut result = run_call(self, evm, init)?;

        // Settle like a parent frame settles a child: a revert returns its unused gas, a halt
        // consumes all of it.
        let instruction_result = result.instruction_result();
        gas.spend_all();
        handle_reservoir_remaining_gas(
            instruction_result,
            &mut gas,
            result.gas_mut().tracker_mut(),
        );
        let output = result.interpreter_result().output.clone();
        if !instruction_result.is_ok() {
            return Ok(CallRun { output, ..failed(pool - gas.remaining()) });
        }
        Ok(CallRun {
            succeeded: true,
            gas_used: pool - gas.remaining(),
            refunded: result.gas().refunded(),
            output,
        })
    }
}
