use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::messaging::{MailboxEntry, MessageContent};

/// Buyer-to-seller messaging.
///
/// # What this component may and may not claim
///
/// An earlier version told the buyer "Messages are end-to-end encrypted. The
/// seller cannot see who you are unless you choose to share identifying
/// information", offered a textarea and a Send button, and then -- on submit
/// -- logged a line and pushed a notification. Nothing was encrypted and
/// nothing was sent. The version after that removed the claim and disabled
/// the box, because the seller published no key to encrypt to.
///
/// A seller now publishes one ([`harvest_common::store::StoreInfoV1::
/// encryption_public_key`]) and the box works. The claims below are therefore
/// re-enabled -- but only the ones that are true, and each is stated at the
/// strength it actually holds:
///
/// * **Encrypted to the seller.** True. The message is sealed to the key
///   published in the store's signed details, and the matching secret never
///   leaves the seller's delegate.
/// * **Not anonymous against a network observer.** Writing to a mailbox
///   contract is a contract update, and the mailbox's address is derived from
///   the seller's identity. Anybody watching knows this node wrote to this
///   seller. The message CONTENT is hidden; the fact of contact is not.
/// * **No reply.** A buyer has no identity and no mailbox, so the seller has
///   no channel to answer through. Saying "messaged" without saying this
///   would leave a buyer waiting for a response Harvest cannot deliver.
/// * **Handed over, not delivered.** `update_contract` resolves when the
///   local node accepts the send. Nothing confirms the contract took it or
///   that the seller ever looks. The button is an action label and says
///   "Send"; what must not claim delivery is the CONFIRMATION, and the list
///   of what was written says "handed to your Freenet node" instead.
///
/// # Why a store can still be unmessageable
///
/// Two independent reasons, and the notice names whichever applies:
///
/// 1. The seller published no encryption key -- every store created before
///    the field existed, and any seller whose delegate has not minted one.
/// 2. The store's ghostkey certificate does not verify against this store, so
///    [`crate::ghostkey_cert::store_verifying_key`] yields nothing and the
///    mailbox address cannot be derived. This also covers a store published
///    by a NEWER build of Harvest, which is indistinguishable here from a
///    stolen certificate.
#[component]
pub fn MessageView(store_contract_id: Vec<u8>) -> Element {
    let app_state = APP_STATE.read();
    let store = app_state.browsing_stores.get(&store_contract_id);
    let info = store.and_then(|s| s.info.as_ref());
    let store_name = info
        .map(|i| i.store_name.as_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("this store")
        .to_string();

    // A store the connected identity owns is read, not written to: the
    // seller is the mailbox's audience, and there is nobody for them to
    // compose to.
    let owned = app_state
        .store_owner_fingerprint(&store_contract_id)
        .is_some();

    if owned {
        let entries = app_state.mailbox_entries(&store_contract_id);
        drop(app_state);
        return rsx! { Inbox { entries: entries } };
    }

    let seller_key = info.and_then(|i| i.encryption_public_key);
    // Reached once, when the store's state arrived, rather than recomputed
    // here: recovering it verifies a certificate chain including a blind-RSA
    // notary signature, and this component re-renders on every keystroke in
    // the box below. See `state::BrowsingStore::seller_verifying_key`.
    let seller_identity = store.and_then(|s| s.seller_verifying_key);
    let sent = store.map(|s| s.sent_messages.clone()).unwrap_or_default();
    let loaded = info.is_some();
    drop(app_state);

    rsx! {
        div { class: "card",
            h3 { "Contact {store_name}" }

            match (loaded, seller_key, seller_identity) {
                (false, _, _) => rsx! {
                    p { class: "text-muted text-italic", "Loading this store's details..." }
                },
                (true, Some(key), Some(identity)) => rsx! {
                    Compose {
                        store_contract_id: store_contract_id.clone(),
                        seller_encryption_key: key,
                        seller_verifying_key: identity,
                    }
                },
                // The seller published no key. Nothing can be encrypted to
                // them, and putting plaintext into a world-readable contract
                // would be worse than sending nothing.
                (true, None, _) => rsx! {
                    Unavailable {
                        why: "This seller has not published an encryption key, so there is no \
                              way to send them a private message. Stores created before Harvest \
                              supported messaging are in this state until the seller publishes \
                              their details again.".to_string()
                    }
                },
                // A key was published, but this build cannot work out where
                // the seller's mailbox is -- see the component docs.
                (true, Some(_), None) => rsx! {
                    Unavailable {
                        why: "Harvest cannot confirm this store's identity, so it cannot work \
                              out where the seller's mailbox is. Either the store's ghostkey \
                              certificate does not check out, or the store was published by a \
                              newer version of Harvest than this one. A message sent anyway \
                              could land in a stranger's mailbox, so nothing is sent."
                              .to_string()
                    }
                },
            }

            if !sent.is_empty() {
                SentList { sent: sent }
            }
        }
    }
}

/// The compose box, shown only when a message can genuinely be sealed and
/// addressed.
#[component]
fn Compose(
    store_contract_id: Vec<u8>,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);

    let can_send = !draft().trim().is_empty();

    rsx! {
        p { class: "text-muted",
            style: "margin-bottom: 1rem;",
            "Your message is encrypted to this seller's published key before it leaves your "
            "browser, and only they can read it -- the matching secret never leaves their "
            "Harvest delegate. Anyone watching the network can still see that you wrote to "
            "this store, just not what you said."
        }
        p { class: "text-warning",
            style: "margin-bottom: 1rem;",
            "The seller cannot reply through Harvest yet -- there is no buyer inbox to reply "
            "to. Include a contact route in your message if you need an answer."
        }

        div { class: "form-group",
            label { class: "form-label", "Your Message" }
            textarea {
                class: "form-textarea",
                value: "{draft}",
                placeholder: "Ask about a listing, or arrange a trade.",
                oninput: move |event| draft.set(event.value()),
            }
        }

        if let Some(message) = problem() {
            p { class: "text-warning", "{message}" }
        }

        button {
            class: "btn btn-primary",
            disabled: !can_send,
            onclick: move |_| {
                let text = draft().trim().to_string();
                if text.is_empty() {
                    return;
                }
                match send(&store_contract_id, &seller_encryption_key, &seller_verifying_key, text) {
                    Ok(()) => {
                        draft.set(String::new());
                        problem.set(None);
                    }
                    Err(e) => problem.set(Some(e)),
                }
            },
            "Send to seller"
        }
    }
}

/// Seal one message and hand it to the local node.
///
/// Returns an error rather than notifying, so the compose box can say what
/// went wrong beside the box the buyer just typed into rather than in a
/// notification list somewhere else on the page.
///
/// The local record is written only after the send is dispatched, so a
/// message that could not be sealed does not appear as one the buyer wrote.
fn send(
    store_contract_id: &[u8],
    seller_encryption_key: &[u8; 32],
    seller_verifying_key: &[u8; 32],
    text: String,
) -> Result<(), String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    let plaintext = crate::messaging::PlaintextMessage {
        conversation_id: harvest_common::mailbox::ConversationId::random(),
        content: MessageContent::Text(text.clone()),
    };
    let sealed = crate::messaging::seal_to_seller(seller_encryption_key, &plaintext)?;

    dispatch(seller, sealed);

    APP_STATE
        .write()
        .record_sent_message(store_contract_id, text);
    Ok(())
}

/// Hand a sealed message to the local node.
///
/// Fire-and-forget, and the caller must not read it as delivery: see
/// `gateway::mailbox_ops::send_message`. A failure to even reach the node is
/// reported as a notification, which is the only channel left once the
/// compose box has been told the send was dispatched.
fn dispatch(
    _seller: ed25519_dalek::VerifyingKey,
    _sealed: harvest_common::mailbox::EncryptedMessage,
) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::mailbox_ops::send_message(&_seller, _sealed).await {
            dioxus::logger::tracing::error!("Failed to send message: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Your message could not be sent: {e}"));
        }
    });
}

/// Why this store cannot be messaged, said plainly and with the compose box
/// gone rather than disabled -- a disabled box invites a buyer to keep
/// trying.
#[component]
fn Unavailable(why: String) -> Element {
    rsx! {
        p { class: "text-warning", "{why}" }
        p { class: "text-muted",
            style: "font-size: 0.85rem;",
            "Use whatever contact route the store's payment instructions give you instead."
        }
    }
}

/// What this browser has handed to the node for this store.
#[component]
fn SentList(sent: Vec<crate::state::SentMessage>) -> Element {
    rsx! {
        div { style: "margin-top: 1.5rem;",
            h4 { "Messages you wrote" }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "Handed to your Freenet node. Harvest cannot confirm the seller received it, "
                "and this list is gone when you reload the page -- your copy is encrypted to "
                "the seller and not to you."
            }
            for message in sent.iter().rev() {
                {
                    let when = message.sent_at.format("%Y-%m-%d %H:%M UTC").to_string();
                    rsx! {
                        div { class: "card",
                            style: "margin-top: 0.5rem;",
                            p { style: "white-space: pre-wrap;", "{message.text}" }
                            p { class: "text-muted", style: "font-size: 0.8rem;", "{when}" }
                        }
                    }
                }
            }
        }
    }
}

/// The seller's own mailbox.
///
/// Unreadable entries are shown rather than hidden. The mailbox is
/// open-write, so anyone may deposit bytes in it, and a seller who saw only
/// the readable ones could not tell "nobody wrote" from "I cannot read what
/// they wrote".
#[component]
fn Inbox(entries: Vec<MailboxEntry>) -> Element {
    if entries.is_empty() {
        return rsx! {
            div { class: "card",
                h3 { "Messages" }
                p { class: "text-muted text-italic", "No one has written to this store yet." }
            }
        };
    }

    let unreadable = entries
        .iter()
        .filter(|entry| matches!(entry, MailboxEntry::Unreadable { .. }))
        .count();

    rsx! {
        div { class: "card",
            h3 { "Messages" }
            p { class: "section-count", "{entries.len()} message(s)" }
            p { class: "text-warning",
                style: "font-size: 0.85rem;",
                "Harvest cannot reply to these yet -- the sender has no inbox to reply to. "
                "Any contact route is in the message itself."
            }
            if unreadable > 0 {
                p { class: "text-muted",
                    style: "font-size: 0.85rem;",
                    "{unreadable} of these cannot be read. Anyone can write to this mailbox, "
                    "so some entries are junk or were encrypted to a key you do not hold."
                }
            }
            for entry in entries.iter() {
                MessageCard { entry: entry.clone() }
            }
        }
    }
}

#[component]
fn MessageCard(entry: MailboxEntry) -> Element {
    let when = entry.timestamp().format("%Y-%m-%d %H:%M UTC").to_string();
    rsx! {
        div { class: "card", style: "margin-top: 0.5rem;",
            match &entry {
                MailboxEntry::Readable { content, .. } => rsx! {
                    p { style: "white-space: pre-wrap;", "{describe(content)}" }
                },
                MailboxEntry::Unreadable { why, .. } => rsx! {
                    p { class: "text-muted text-italic", "Cannot be read: {why}" }
                },
            }
            p { class: "text-muted",
                style: "font-size: 0.8rem;",
                // Chosen by whoever wrote the message and signed by nobody
                // (see `harvest_common::mailbox`), so it is labelled as a
                // claim rather than shown as a fact.
                "Sender's timestamp: {when}"
            }
        }
    }
}

/// What to show for one message's content.
///
/// Only `Text` is something a buyer can compose today; the other variants
/// exist for the feedback-token exchange, which is not built. They are named
/// rather than rendered as empty, so a seller who receives one is told
/// something arrived that this build cannot present rather than being shown a
/// blank message.
fn describe(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(text) => text.clone(),
        MessageContent::InitiateTransaction { message, .. } => {
            format!("{message}\n\n(This message also carries a feedback-token request, which this version of Harvest cannot act on.)")
        }
        MessageContent::AcceptTransaction { message, .. } => {
            format!("{message}\n\n(This message also carries a blind signature, which this version of Harvest cannot act on.)")
        }
        MessageContent::Decline { reason } => format!("Declined: {reason}"),
    }
}
