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
/// * **Replies work, and are lost by a reload.** The seller answers into
///   their own mailbox and the buyer reads it out of the same contract. The
///   buyer's keys live in the tab and nowhere else -- there is no buyer
///   delegate and `localStorage` throws in the gateway's sandboxed iframe --
///   so a buyer who reloads before the answer arrives can never read it. That
///   has to be on screen BEFORE they send, not discovered afterwards.
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
        return rsx! {
            Inbox { store_contract_id: store_contract_id.clone(), entries: entries }
        };
    }

    let seller_key = info.and_then(|i| i.encryption_public_key);
    // Reached once, when the store's state arrived, rather than recomputed
    // here: recovering it verifies a certificate chain including a blind-RSA
    // notary signature, and this component re-renders on every keystroke in
    // the box below. See `state::BrowsingStore::seller_verifying_key`.
    let seller_identity = store.and_then(|s| s.seller_verifying_key);
    let thread = app_state.conversation_thread(&store_contract_id);
    let unconfirmed = app_state.unconfirmed_sent(&store_contract_id);
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

            if !thread.is_empty() || !unconfirmed.is_empty() {
                Thread { thread: thread, unconfirmed: unconfirmed }
            }
        }
    }
}

/// The buyer's conversation with one store: what they wrote, what came back,
/// and what has not been seen landing yet.
#[component]
fn Thread(
    thread: Vec<crate::messaging::ConversationMessage>,
    unconfirmed: Vec<crate::state::SentMessage>,
) -> Element {
    rsx! {
        div { style: "margin-top: 1.5rem;",
            h4 { "Your conversation" }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "This conversation is gone when you reload the page: the key that reads it "
                "lives in this tab and nowhere else. A reply that arrives after a reload "
                "cannot be read by anyone, including you."
            }

            for message in thread.iter() {
                {
                    let when = message.timestamp.format("%Y-%m-%d %H:%M UTC").to_string();
                    let who = if message.from_seller { "Seller" } else { "You" };
                    rsx! {
                        div { class: "card",
                            style: "margin-top: 0.5rem;",
                            p { class: "text-muted", style: "font-size: 0.8rem;", "{who}" }
                            p { style: "white-space: pre-wrap;", "{describe(&message.content)}" }
                            p { class: "text-muted",
                                style: "font-size: 0.8rem;",
                                "Sender's timestamp: {when}"
                            }
                        }
                    }
                }
            }

            // Handed to the node, not yet seen in the seller's mailbox. Kept
            // separate from the thread above rather than shown as sent,
            // because "the node accepted it" and "it is in the mailbox" are
            // different claims and only the second is evidence.
            for message in unconfirmed.iter() {
                div { class: "card",
                    style: "margin-top: 0.5rem;",
                    p { class: "text-muted", style: "font-size: 0.8rem;", "You — not yet visible" }
                    p { style: "white-space: pre-wrap;", "{message.text}" }
                    p { class: "text-warning",
                        style: "font-size: 0.8rem;",
                        "Handed to your Freenet node. It has not appeared in the seller's "
                        "mailbox yet, so Harvest cannot say it arrived."
                    }
                }
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

    let sealed = APP_STATE.write().compose_to_seller(
        store_contract_id,
        seller_encryption_key,
        text.clone(),
    )?;

    // Subscribe to the seller's mailbox, once, on the first message. This is
    // what makes a reply reachable: without it the buyer never fetches the
    // contract again and the answer sits there unread.
    //
    // Deliberately NOT done merely by opening a storefront. Subscribing
    // advertises a standing interest in that mailbox to the network, which is
    // a longer-lived signal than a single write -- so a reader who never
    // messages anyone advertises nothing.
    let mailbox = crate::gateway::mailbox_ops::mailbox_contract_key(&seller)?;
    APP_STATE
        .write()
        .register_store_mailbox(store_contract_id, mailbox.id().as_bytes());

    dispatch(seller, sealed.clone());

    APP_STATE
        .write()
        .record_sent_message(store_contract_id, text, sealed.nonce);
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

/// The seller's own mailbox.
///
/// Unreadable entries are shown rather than hidden. The mailbox is
/// open-write, so anyone may deposit bytes in it, and a seller who saw only
/// the readable ones could not tell "nobody wrote" from "I cannot read what
/// they wrote".
#[component]
fn Inbox(store_contract_id: Vec<u8>, entries: Vec<MailboxEntry>) -> Element {
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

    // Grouped by conversation, newest conversation first, because a reply
    // belongs to a conversation rather than to a message -- and because an
    // ungrouped list of a busy mailbox gives the seller no way to see which
    // messages are one exchange.
    let mut conversations: Vec<(Vec<u8>, Vec<MailboxEntry>)> = Vec::new();
    for entry in entries.iter() {
        match conversations
            .iter_mut()
            .find(|(tag, _)| tag == entry.conversation())
        {
            Some((_, group)) => group.push(entry.clone()),
            None => conversations.push((entry.conversation().to_vec(), vec![entry.clone()])),
        }
    }

    rsx! {
        div { class: "card",
            h3 { "Messages" }
            p { class: "section-count",
                "{entries.len()} message(s) in {conversations.len()} conversation(s)"
            }
            if unreadable > 0 {
                p { class: "text-muted",
                    style: "font-size: 0.85rem;",
                    "{unreadable} of these cannot be read. Anyone can write to this mailbox, "
                    "so some entries are junk or were encrypted to a key you do not hold."
                }
            }
            for (tag, group) in conversations.iter() {
                Conversation {
                    key: "{bs58::encode(tag).into_string()}",
                    store_contract_id: store_contract_id.clone(),
                    tag: tag.clone(),
                    entries: group.clone(),
                }
            }
        }
    }
}

/// One exchange with one buyer, and the box to answer it.
#[component]
fn Conversation(store_contract_id: Vec<u8>, tag: Vec<u8>, entries: Vec<MailboxEntry>) -> Element {
    let mut draft = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);

    // A conversation with nothing readable in it cannot be replied to: the
    // reply has to name the conversation id, which only a decrypted message
    // carries. Saying so beside the exchange is better than a Send button
    // that refuses.
    let readable = entries
        .iter()
        .any(|entry| matches!(entry, MailboxEntry::Readable { .. }));

    rsx! {
        div { class: "card", style: "margin-top: 1rem;",
            p { class: "text-muted", style: "font-size: 0.8rem;",
                "Conversation {short_tag(&tag)}"
            }
            for entry in entries.iter() {
                MessageCard { entry: entry.clone() }
            }

            if readable {
                div { class: "form-group", style: "margin-top: 0.5rem;",
                    textarea {
                        class: "form-textarea",
                        value: "{draft}",
                        placeholder: "Reply to this buyer.",
                        oninput: move |event| draft.set(event.value()),
                    }
                }
                if let Some(message) = problem() {
                    p { class: "text-warning", "{message}" }
                }
                button {
                    class: "btn btn-primary",
                    disabled: draft().trim().is_empty(),
                    onclick: {
                        let store_contract_id = store_contract_id.clone();
                        let tag = tag.clone();
                        move |_| {
                            let text = draft().trim().to_string();
                            if text.is_empty() {
                                return;
                            }
                            match reply(&store_contract_id, &tag, text) {
                                Ok(()) => {
                                    draft.set(String::new());
                                    problem.set(None);
                                }
                                Err(e) => problem.set(Some(e)),
                            }
                        }
                    },
                    "Reply"
                }
                p { class: "text-muted", style: "font-size: 0.8rem;",
                    "Your reply goes into this mailbox encrypted to this buyer alone. They can "
                    "only read it while the browser tab they wrote from is still open."
                }
            } else {
                p { class: "text-muted text-italic", style: "font-size: 0.85rem;",
                    "Nothing here can be read, so there is nothing to reply to."
                }
            }
        }
    }
}

/// Enough of a conversation tag to tell two apart on screen, and no more --
/// the whole thing is 44 characters of base58 that means nothing to a reader.
fn short_tag(tag: &[u8]) -> String {
    let encoded = bs58::encode(tag).into_string();
    encoded.chars().take(8).collect()
}

/// Seal a seller's reply and hand it to the node.
fn reply(store_contract_id: &[u8], tag: &[u8], text: String) -> Result<(), String> {
    let (sealed, mailbox) = {
        let state = APP_STATE.read();
        let sealed = state.compose_reply(store_contract_id, tag, text)?;
        let mailbox = state
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.mailbox_contract_id.clone())
            .ok_or("this store's mailbox id is not known, so there is nowhere to reply into")?;
        (sealed, mailbox)
    };
    dispatch_reply(mailbox, sealed);
    Ok(())
}

/// Hand a sealed reply to the local node. Fire-and-forget for the same
/// reason `dispatch` is; see `gateway::mailbox_ops::send_message`.
fn dispatch_reply(_mailbox: Vec<u8>, _sealed: harvest_common::mailbox::EncryptedMessage) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::mailbox_ops::reply_to_mailbox(&_mailbox, _sealed).await {
            dioxus::logger::tracing::error!("Failed to send reply: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Your reply could not be sent: {e}"));
        }
    });
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
