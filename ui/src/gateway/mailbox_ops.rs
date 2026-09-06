//! Reaching a seller's mailbox, from a buyer who has never met them.
//!
//! # How a buyer finds the address at all
//!
//! Nothing publishes it. `StoreInfoV1` names the reputation contract and not
//! the mailbox, and the store's state does not carry it either -- the id is
//! known at creation time and nowhere else (see
//! `store_ops::create_store_contracts`). So the buyer DERIVES it: a mailbox
//! lives at `BLAKE3(BLAKE3(wasm) || cbor(MailboxParameters))`, and
//! `MailboxParameters`' only field is the seller's Ed25519 verifying key,
//! which the buyer already recovers from the store's ghostkey certificate in
//! order to decide whether to trust the store at all.
//!
//! That the key comes from `ghostkey_cert::store_verifying_key` rather than
//! from anything the seller says about themselves is load-bearing: it is
//! returned only when the certificate verifies AGAINST THIS STORE, so a
//! scammer who pastes somebody else's genuine certificate onto their store
//! gets no key, rather than getting the victim's -- which would send the
//! buyer's message into the victim's mailbox while reporting success.
//!
//! # What this cannot reach
//!
//! A mailbox published by a different build of Harvest. The code hash is this
//! build's `mailbox_contract.wasm`, so a seller whose mailbox predates it
//! lives at an address derived here from the wrong hash. Unlike
//! `store_ops::store_contract_key`, there is no recorded key to fall back on:
//! a buyer has no registration for someone else's store. The failure is a
//! contract that does not exist, which the node answers with silence, so the
//! UI cannot distinguish it from a slow network and must not claim delivery.
//! `components::message_view` says exactly that.

use freenet_stdlib::prelude::{ContractCode, ContractKey};
use harvest_common::mailbox::EncryptedMessage;

use super::store_ops::MAILBOX_CONTRACT_WASM;

/// The `ContractKey` of the mailbox belonging to the holder of
/// `owner_verifying_key`, as this build addresses it.
///
/// Both halves come from the same two inputs the seller's own PUT used: the
/// parameters from [`crate::migrate::mailbox_params`], which is the one place
/// they are derived, and the code hash of the bundled mailbox WASM.
pub fn mailbox_contract_key(
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<ContractKey, String> {
    let params =
        crate::migrate::encode_params(&crate::migrate::mailbox_params(owner_verifying_key))?;
    let code_hash = *ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// The `ContractKey` of a mailbox whose instance id is already known.
///
/// The seller's own mailbox is reached this way rather than by re-deriving
/// it: the id they are READING came from their delegate's registration, and
/// replying into a different one than they are reading would put the answer
/// somewhere the buyer is not looking. Same reasoning, and the same residual,
/// as `store_ops::store_contract_key`'s reconstructed path -- the code hash
/// is this build's, so a mailbox published by an older build is addressed
/// wrongly here.
pub fn mailbox_key_from_id(instance_id: &[u8]) -> Result<ContractKey, String> {
    let id: [u8; 32] = instance_id
        .try_into()
        .map_err(|_| format!("mailbox contract id is {} bytes, not 32", instance_id.len()))?;
    let code_hash = *ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec()).hash();
    Ok(ContractKey::from_id_and_code(
        freenet_stdlib::prelude::ContractInstanceId::new(id),
        code_hash,
    ))
}

/// Bytes of a mailbox update carrying new messages.
///
/// The mailbox contract's delta is `MailboxDelta`, a bare
/// `Vec<EncryptedMessage>` -- NOT the per-field `Option` struct the store
/// contract's `#[composable]` macro generates. The two are different wire
/// shapes and the contract rejects the wrong one outright, so the mistake
/// `store_ops::listings_delta_bytes` documents is available here in the
/// opposite direction. Pinned by
/// `the_delta_is_the_shape_the_mailbox_contract_decodes`.
pub fn mailbox_delta_bytes(messages: Vec<EncryptedMessage>) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&messages).map_err(|e| format!("serialize mailbox delta: {e}"))
}

/// Write one encrypted message into a seller's mailbox.
///
/// # What "sent" means here, and what it does not
///
/// `update_contract` resolves when the WebSocket SEND to the local node
/// succeeds. It does not mean the update reached the contract, that the
/// contract accepted it, or that the seller will ever see it -- the node
/// answers an `UpdateResponse` with no correlation id, so there is nothing to
/// match a confirmation against even if one arrived. Callers must not report
/// delivery; see `components::message_view` for the wording that does not.
///
/// # The GET first: what is known, what is not, and how it fails
///
/// **What is known.** A buyer has never touched this contract, so their node
/// very likely does not hold it -- and an update has to be applied by the
/// contract's own WASM, which the node must have. A client GET primes the
/// local store, so issuing one first is the cheapest way to give the node the
/// contract it is about to be asked to update.
///
/// **What is NOT known, and cannot be established from this repository.**
/// Whether the update succeeds when the node does not yet hold the contract.
/// It might fetch the contract itself; it might refuse. Nothing here can
/// answer that, because answering it needs a running node, and the only
/// harness that talks to one is `tests/rehearsal/`, which is compile-checked
/// in CI and never executed there. **This path has not been run against a
/// live node.**
///
/// **The ordering is not guaranteed.** Both `get_contract` and
/// `update_contract` resolve when the WebSocket SEND succeeds, not when the
/// node has done anything, so the update can be dispatched while the fetch is
/// still in flight. There is nothing to await: a GET that dead-ends produces
/// no response at all -- which is why `state::subscribe_to_own_store` needs a
/// deadline before it can conclude anything -- so "wait for the GET" means
/// "block the buyer's message behind a timeout that usually fires for a
/// reason unrelated to them".
///
/// **What it looks like when the race is lost.** The node rejects or drops
/// the update. `update_contract` has already returned `Ok` (the send
/// succeeded), so the UI shows the message as handed over. It never appears
/// in the mailbox, so it stays in the "not yet visible" list
/// (`state::AppState::unconfirmed_sent`) indefinitely, and the seller never
/// receives it. The buyer is not told it failed, because nothing told this
/// code it failed -- an `UpdateResponse` carries no correlation id, so even a
/// rejection that did come back could not be matched to this send.
///
/// **What must NOT be done about it here.** Not a sleep, and not a retry
/// loop: both would paper over a question that has an answer, and a retry
/// that re-sends a message the node actually did apply would deposit it
/// twice (deduped by nonce, but only because the nonce is reused -- a fresh
/// seal would not be). Characterising this needs the rehearsal harness and a
/// node; until then it is a stated residual, recorded in
/// `docs/untested-invariants.md`.
///
/// The GET does NOT subscribe. Subscription is a separate decision made once,
/// on the buyer's first message, by `components::message_view` -- a reader
/// who never writes advertises no interest in anybody's mailbox.
#[cfg(target_arch = "wasm32")]
pub async fn send_message(
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
    message: EncryptedMessage,
) -> Result<(), String> {
    let key = mailbox_contract_key(owner_verifying_key)?;

    // Failure here is logged rather than returned: the update below is worth
    // attempting either way, and a buyer told "could not send" because a
    // priming fetch failed would be told something misleading.
    if let Err(e) = super::get_contract(key.id(), false).await {
        dioxus::logger::tracing::warn!(
            "Could not prime the seller's mailbox contract before writing to it: {e}"
        );
    }

    write_to_mailbox(&key, message).await
}

/// Write into a mailbox whose key is already known.
///
/// The seller's own replies take this path: they are already subscribed to
/// their mailbox, so there is nothing to prime, and the id comes from their
/// delegate's registration rather than from a derivation.
#[cfg(target_arch = "wasm32")]
pub async fn reply_to_mailbox(
    mailbox_instance_id: &[u8],
    message: EncryptedMessage,
) -> Result<(), String> {
    write_to_mailbox(&mailbox_key_from_id(mailbox_instance_id)?, message).await
}

/// The one place a message becomes a contract update.
#[cfg(target_arch = "wasm32")]
async fn write_to_mailbox(key: &ContractKey, message: EncryptedMessage) -> Result<(), String> {
    use freenet_stdlib::prelude::{StateDelta, UpdateData};

    let delta = mailbox_delta_bytes(vec![message])?;
    super::update_contract(key, UpdateData::Delta(StateDelta::from(delta))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_stdlib::prelude::{Parameters, WrappedContract};
    use std::sync::Arc;

    fn seller() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[9u8; 32]).verifying_key()
    }

    /// The derived key must be the key the NODE computes for the same
    /// contract and parameters.
    ///
    /// The comparison is against `freenet-stdlib`'s own `WrappedContract`,
    /// which is what decides the address on the network -- not against a
    /// second hand-rolled derivation, which would only prove this file agrees
    /// with itself. Same argument as `migrate`'s re-export of
    /// `predecessor_ids`.
    ///
    /// Observed red on 2026-09-05 by hashing `STORE_CONTRACT_WASM` instead.
    #[test]
    fn the_derived_mailbox_key_is_the_one_the_node_computes() {
        let vk = seller();
        let params: Parameters<'static> =
            crate::migrate::encode_params(&crate::migrate::mailbox_params(&vk))
                .expect("encode mailbox parameters");
        let expected = *WrappedContract::new(
            Arc::new(ContractCode::from(MAILBOX_CONTRACT_WASM.to_vec())),
            params,
        )
        .key();

        let derived = mailbox_contract_key(&vk).expect("derive");
        assert_eq!(
            derived.id(),
            expected.id(),
            "the buyer would address a contract the seller never published"
        );
        // Separately, for the reason spelled out on
        // `the_two_ways_to_address_a_mailbox_agree`: `ContractKey`'s
        // `PartialEq` ignores the code hash, so `assert_eq!` on the keys
        // alone would not notice a wrong one.
        assert_eq!(derived.code_hash(), expected.code_hash());
    }

    /// The two ways to reach a mailbox must agree.
    ///
    /// A buyer derives the key from the seller's verifying key; the seller
    /// rebuilds it from the instance id their delegate recorded. If those
    /// disagreed, a seller would reply into a contract the buyer never reads
    /// -- and both sides would report success.
    ///
    /// **The code hash is compared explicitly, and that is not pedantry.**
    /// `ContractKey`'s `PartialEq` compares the instance id only, so
    /// `assert_eq!(derived, from_id)` on its own passes even when the two
    /// carry different code hashes -- which was checked rather than assumed:
    /// the first version of this test was written that way and survived the
    /// mutation below unchanged.
    ///
    /// Observed red on 2026-09-05 by hashing `STORE_CONTRACT_WASM` in
    /// `mailbox_key_from_id`, but only once the code-hash assertion was
    /// added.
    #[test]
    fn the_two_ways_to_address_a_mailbox_agree() {
        let derived = mailbox_contract_key(&seller()).expect("derive");
        let from_id = mailbox_key_from_id(derived.id().as_bytes()).expect("rebuild");

        assert_eq!(derived.id(), from_id.id(), "different instance");
        assert_eq!(
            derived.code_hash(),
            from_id.code_hash(),
            "same instance, different code hash -- the seller would reply into a contract \
             addressed by a hash the buyer is not reading"
        );
    }

    /// Two sellers do not share a mailbox, so the test above is not passing
    /// because the derivation ignores its argument.
    #[test]
    fn two_sellers_have_different_mailboxes() {
        let one = mailbox_contract_key(&seller()).expect("derive");
        let two = mailbox_contract_key(&SigningKey::from_bytes(&[10u8; 32]).verifying_key())
            .expect("derive");
        assert_ne!(one, two);
    }

    /// The delta a buyer sends has to be the shape the mailbox contract
    /// decodes, and the contract is the only thing that would otherwise say
    /// so -- at which point the message is already lost with an error that
    /// does not name the cause.
    ///
    /// Checked by round-tripping through the exact types
    /// `contracts/mailbox-contract` uses: `MailboxDelta` for the decode, then
    /// `MailboxStateV1::apply_delta` for the merge.
    ///
    /// Observed red on 2026-09-05 by wrapping the messages in a
    /// `StoreStateV1Delta`-style map, which is the mistake the store
    /// contract's own delta helpers exist to prevent.
    #[test]
    fn the_delta_is_the_shape_the_mailbox_contract_decodes() {
        use harvest_common::mailbox::{ConversationId, MailboxDelta, MailboxStateV1};

        let message = EncryptedMessage {
            conversation_id: ConversationId([4u8; 32]),
            sender_public_key: vec![5u8; 32],
            ciphertext: vec![6u8; 48],
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            nonce: [7u8; 24],
        };

        let bytes = mailbox_delta_bytes(vec![message.clone()]).expect("serialize");
        let decoded: MailboxDelta = harvest_common::from_cbor(&bytes)
            .expect("the mailbox contract decodes the delta as a MailboxDelta");

        let mut state = MailboxStateV1::default();
        state
            .apply_delta(&Some(decoded))
            .expect("the contract merges it");

        assert_eq!(state.messages, vec![message]);
    }
}
