//! Who this delegate answers, and the one place that decides it.
//!
//! # The delegate's address is public; its secrets are not
//!
//! A delegate is addressed by the hash of its WASM and its parameters.
//! Harvest's parameters are empty (`DELEGATE_PARAMETERS = &[]`) and the WASM
//! is committed in this repository, so **anyone can compute this delegate's
//! key**. Nothing about reaching it is privileged.
//!
//! What IS privileged is what it holds: reputation private keys, the
//! transaction ledger, the seller's store registrations, the Bitcoin watch
//! list, and the account key every invoice address is derived from. Those live
//! in the node's own secret store, per-user and persistent — so a caller that
//! gets one request through has changed the seller's state permanently, not
//! for the duration of a page load.
//!
//! The runtime attests the caller in `origin`. Any web app the user has ever
//! opened on this node can send this delegate an application message, and the
//! runtime will faithfully report a *different* `WebApp` id. Reading that id is
//! the only thing standing between a hostile page and the seller's money.
//!
//! # One policy, checked in one way
//!
//! Every request family routes through [`authorize`], which delegates to
//! `freenet-migrate`'s [`OriginPolicy`] — the same mechanism, and the same
//! pinned contract id, that [`crate::migration`]'s secret export has always
//! used. A second, hand-rolled comparison living beside it is how the two
//! drift apart and one of them ends up weaker, so there is deliberately only
//! this one.

use freenet_migrate::OriginPolicy;
use freenet_stdlib::prelude::{DelegateError, MessageOrigin};

/// The only caller this delegate serves.
///
/// `SameWebApp` pinned to the Harvest container's contract id. The successor
/// generation of the delegate is different WASM, but it is driven by the same
/// web app, and the container id is what the runtime attests. Any other origin
/// — another web app the user has granted access to, another delegate, or a
/// caller the runtime could not attest at all — is refused.
///
/// The id is Harvest's own: a web-app container's instance id covers both the
/// container WASM and its parameters (`published-contract/webapp.parameters`),
/// so it is not a value every Freenet web app shares.
pub(crate) fn harvest_webapp_policy() -> Result<OriginPolicy, DelegateError> {
    harvest_common::HARVEST_WEBAPP_CONTRACT_ID
        .parse()
        .map(OriginPolicy::SameWebApp)
        .map_err(|e| DelegateError::Other(format!("canonical webapp contract id is invalid: {e}")))
}

/// Refuse anyone but the Harvest web app.
///
/// Fails closed on `origin: None` — the runtime supplies `None` when it cannot
/// say who is asking, and that is not a caller to hand a seller's payment key
/// to. `OriginPolicy::authorize` is what enforces that; see its docs.
///
/// The refusal is a message rather than a silence on purpose. A rejected
/// caller that got an empty success back would look, to a legitimate Harvest
/// page hitting this for some unforeseen reason, exactly like a request that
/// worked — and the first symptom would be a seller wondering why nothing
/// saved.
pub(crate) fn authorize(origin: Option<&MessageOrigin>) -> Result<(), DelegateError> {
    harvest_webapp_policy()?.authorize(origin).map_err(|_| {
        DelegateError::Other(format!(
            "refused: this delegate answers only the Harvest web app ({expected}), and this \
             request came from {caller}",
            expected = harvest_common::HARVEST_WEBAPP_CONTRACT_ID,
            caller = describe(origin),
        ))
    })
}

/// Name the refused caller in a way a developer reading a node log can act on.
fn describe(origin: Option<&MessageOrigin>) -> String {
    match origin {
        None => "a caller the node could not attest".to_string(),
        Some(MessageOrigin::WebApp(id)) => format!("web app {id}"),
        Some(MessageOrigin::Delegate(key)) => format!("delegate {key}"),
        // `MessageOrigin` is `#[non_exhaustive]`; a kind this build does not
        // know about is still refused by `authorize` above, and this only
        // decides how it is described.
        Some(other) => format!("an unrecognised origin kind ({other:?})"),
    }
}

#[cfg(test)]
pub(crate) mod test_origins {
    use freenet_stdlib::prelude::{ContractInstanceId, MessageOrigin};

    /// The origin the runtime attests for the real Harvest web app.
    pub(crate) fn harvest() -> MessageOrigin {
        MessageOrigin::WebApp(
            harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                .parse::<ContractInstanceId>()
                .expect("canonical webapp id"),
        )
    }

    /// Some other web app the user has opened on this node. It needs no
    /// relationship to Harvest whatsoever — reaching the delegate is not the
    /// privileged part.
    pub(crate) fn a_different_web_app() -> MessageOrigin {
        MessageOrigin::WebApp(ContractInstanceId::new([9u8; 32]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{CodeHash, DelegateKey};
    use test_origins::{a_different_web_app, harvest};

    fn refusal(origin: Option<&MessageOrigin>) -> String {
        match authorize(origin).expect_err("must be refused") {
            DelegateError::Other(message) => message,
            other => panic!("expected a refusal message, got {other:?}"),
        }
    }

    #[test]
    fn the_harvest_web_app_is_authorized() {
        authorize(Some(&harvest())).expect("the Harvest web app must be able to call its delegate");
    }

    /// The property the whole module exists for.
    ///
    /// Mutated red by switching [`harvest_webapp_policy`] to
    /// `OriginPolicy::Any`.
    #[test]
    fn another_web_app_is_refused() {
        let MessageOrigin::WebApp(attacker) = a_different_web_app() else {
            panic!("the fixture is a web app origin");
        };
        let message = refusal(Some(&MessageOrigin::WebApp(attacker)));
        assert!(
            message.contains("Harvest web app"),
            "the refusal must say what was expected: {message}"
        );
        assert!(
            message.contains(&attacker.encode()),
            "the refusal must name the caller: {message}"
        );
    }

    #[test]
    fn an_unattested_caller_is_refused() {
        let message = refusal(None);
        assert!(
            message.contains("could not attest"),
            "an unattested caller must be described as such: {message}"
        );
    }

    #[test]
    fn another_delegate_is_refused() {
        let origin = MessageOrigin::Delegate(DelegateKey::new([7u8; 32], CodeHash::new([7u8; 32])));
        assert!(refusal(Some(&origin)).contains("delegate "));
    }
}
