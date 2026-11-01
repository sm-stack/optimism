//! Native authentication of [EIP-8430] senders and payers against the [EIP-8130] Keystore: the
//! actor that authorized each must be configured for its account, live, and granted the scope its
//! role needs. The Keystore is read from storage, before the transaction changes any, by the EVM
//! and by the transaction pool alike.
//!
//! [EIP-8430]: https://github.com/ethereum/EIPs/pull/12385
//! [EIP-8130]: https://eips.ethereum.org/EIPS/eip-8130

use crate::transaction::error::AaTxInvalid;
use op_alloy_consensus::{
    Actor, K1_AUTHENTICATOR, TxEip8430,
    keystore::{
        AccountState, ActorConfig, SCOPE_OPERATOR, SCOPE_POLICY, SCOPE_SELF_PAYER,
        SCOPE_SPONSOR_PAYER, STATEMENT_AUTHENTICATOR, account_state_slot, actor_config_slot,
        address_actor_id,
    },
};
use revm::primitives::{Address, B256, U256};

/// The actor that authorized a sender or payer, as the Keystore is asked about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorizer {
    /// An actor the Keystore must have configured for the account.
    Actor(Actor),
    /// The account's admin, taken on trust: a simulation's secp256k1 authorization, whose signer
    /// is unknown.
    Admin,
}

/// Who authorized a transaction's sender and payer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorizers {
    /// The sender's authorizer.
    pub sender: Authorizer,
    /// The payer and its authorizer, or `None` for self-pay, which the sender's authorizes.
    pub payer: Option<(Address, Authorizer)>,
}

/// An actor the Keystore resolved for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resolved {
    /// The actor's id, `None` for an admin taken on trust.
    id: Option<B256>,
    /// Its configuration.
    config: ActorConfig,
    /// Whether it is a secp256k1 key.
    is_key: bool,
}

impl Resolved {
    /// Whether the actor is the account's admin, which may do everything.
    const fn is_admin(&self) -> bool {
        self.config.scope == 0
    }

    const fn grants(&self, scope: u16) -> bool {
        self.is_admin() || self.config.scope & scope != 0
    }

    /// Whether it may pay for its account's own transaction (`sponsor` false) or another's.
    const fn may_pay(&self, sponsor: bool) -> bool {
        self.grants(if sponsor { SCOPE_SPONSOR_PAYER } else { SCOPE_SELF_PAYER })
    }
}

/// Checks the Keystore authorizes `tx` from `sender`: each authorizer configured for its account
/// and live at `timestamp`, the sender's allowed to initiate the calls (an admin or operator
/// anything; a policy-scoped actor only zero-value calls to its policy manager) and, if the
/// transaction delegates, an admin secp256k1 key; the payer's allowed to pay. `read` reads a
/// Keystore storage slot.
pub fn authorize<E>(
    tx: &TxEip8430,
    sender: Address,
    authorizers: Authorizers,
    timestamp: u64,
    mut read: impl FnMut(U256) -> Result<U256, E>,
) -> Result<Result<(), AaTxInvalid>, E> {
    let sender_actor = match resolve(sender, authorizers.sender, timestamp, &mut read)? {
        Ok(actor) => actor,
        Err(Refusal::NotConfigured) => return Ok(Err(AaTxInvalid::SenderActor)),
        Err(Refusal::Expired) => return Ok(Err(AaTxInvalid::ActorExpired)),
    };
    if !sender_actor.grants(SCOPE_OPERATOR) {
        let (Some(id), true) = (sender_actor.id, sender_actor.config.scope & SCOPE_POLICY != 0)
        else {
            return Ok(Err(AaTxInvalid::SenderScope));
        };
        // The policy manager is the slot after the actor's config.
        let manager =
            Address::from_word(read(actor_config_slot(sender, id) + U256::from(1))?.into());
        if !tx.calls.iter().flatten().all(|call| call.to == manager && call.value.is_zero()) {
            return Ok(Err(AaTxInvalid::Policy));
        }
    }
    if tx.delegation().is_some() && !(sender_actor.is_admin() && sender_actor.is_key) {
        return Ok(Err(AaTxInvalid::DelegationNeedsAdmin));
    }
    let (payer, payer_actor) = match authorizers.payer {
        None => (sender, sender_actor),
        Some((payer, authorizer)) => match resolve(payer, authorizer, timestamp, &mut read)? {
            Ok(actor) => (payer, actor),
            Err(Refusal::NotConfigured) => return Ok(Err(AaTxInvalid::PayerActor)),
            Err(Refusal::Expired) => return Ok(Err(AaTxInvalid::ActorExpired)),
        },
    };
    Ok(if payer_actor.may_pay(payer != sender) { Ok(()) } else { Err(AaTxInvalid::PayerScope) })
}

/// Why the Keystore refused an actor.
enum Refusal {
    /// The account has not configured the actor with the authenticator that authorized it, or
    /// revoked it.
    NotConfigured,
    /// The actor expired.
    Expired,
}

/// Resolves `authorizer` for `account` at `timestamp`, as the Keystore authenticates it
/// (`_authenticateK1`, `_resolveExplicitActor`): a key that is the account's own is the inline self
/// actor, unless revoked; any other key, and a STATEMENT actor, must be configured for the account
/// with the matching authenticator. Either must be live.
fn resolve<E>(
    account: Address,
    authorizer: Authorizer,
    timestamp: u64,
    read: &mut impl FnMut(U256) -> Result<U256, E>,
) -> Result<Result<Resolved, Refusal>, E> {
    let Authorizer::Actor(actor) = authorizer else {
        let config = ActorConfig { authenticator: K1_AUTHENTICATOR, expiry: 0, scope: 0 };
        return Ok(Ok(Resolved { id: None, config, is_key: true }));
    };
    let (id, config, authenticator) = match actor {
        Actor::Key(signer) if signer == account => {
            let state = AccountState::decode(read(account_state_slot(account))?);
            let Some(config) = state.self_actor() else { return Ok(Err(Refusal::NotConfigured)) };
            (address_actor_id(account), config, K1_AUTHENTICATOR)
        }
        Actor::Key(signer) => {
            let id = address_actor_id(signer);
            (id, ActorConfig::decode(read(actor_config_slot(account, id))?), K1_AUTHENTICATOR)
        }
        Actor::Statement(statement) => {
            let id = statement.actor_id();
            let config = ActorConfig::decode(read(actor_config_slot(account, id))?);
            (id, config, STATEMENT_AUTHENTICATOR)
        }
    };
    Ok(if config.authenticator != authenticator {
        Err(Refusal::NotConfigured)
    } else if !config.is_live(timestamp) {
        Err(Refusal::Expired)
    } else {
        Ok(Resolved { id: Some(id), config, is_key: matches!(actor, Actor::Key(_)) })
    })
}
