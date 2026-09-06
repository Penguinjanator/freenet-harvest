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
/// * **Replies work, and survive a reload on THIS device.** The seller
///   answers into their own mailbox and the buyer reads it out of the same
///   contract. The key that reads it is kept by this node's harvest delegate,
///   because the browser has no durable storage at all here -- the gateway's
///   sandboxed iframe has no `allow-same-origin`, so `localStorage`,
///   `sessionStorage`, IndexedDB and cookies all throw. It does NOT follow
///   the buyer to another device, and that has to be on screen BEFORE they
///   send rather than discovered when they need the answer. See
///   `docs/buyer-conversation-persistence.md`.
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
        // The only authorship this client can establish: what it sent itself.
        let authored: Vec<[u8; 32]> = entries
            .iter()
            .map(|entry| entry.digest())
            .filter(|digest| app_state.authored_here(&store_contract_id, digest))
            .collect();
        drop(app_state);
        return rsx! {
            Inbox {
                store_contract_id: store_contract_id.clone(),
                entries: entries,
                authored: authored,
            }
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
    // What this node is keeping, which is what the buyer can ask it to
    // forget. Empty until the delegate answers, and empty for a store this
    // node has never written to.
    let kept: Vec<([u8; 32], i64, bool)> = store
        .map(|store| {
            store
                .conversations
                .iter()
                .map(|conversation| {
                    (
                        conversation.buyer_public_key,
                        conversation.created_at,
                        conversation.backed_up,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let authored_here: Vec<[u8; 32]> = thread
        .iter()
        .map(|message| message.digest)
        .filter(|digest| app_state.authored_here(&store_contract_id, digest))
        .collect();
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
                Thread {
                    thread: thread,
                    unconfirmed: unconfirmed,
                    authored_here: authored_here,
                }
            }

            KeptConversations {
                store_contract_id: store_contract_id.clone(),
                kept: kept,
            }
        }
    }
}

/// What this node is keeping so the seller's replies stay readable, and the
/// control that removes it.
///
/// # Why this is on screen at all
///
/// Keeping the conversation is what makes a reply readable after the tab
/// closes, and the same record is a durable local note that this node
/// contacted this store. The buyer is the only person who can weigh those
/// against each other, so the control is theirs -- and a control only a
/// programmer can reach is not one.
///
/// It removes the record rather than emptying it (the delegate deletes the
/// key, and re-reads it afterwards to check), so what is claimed here is what
/// happens. It cannot be undone: the messages stay in the seller's mailbox
/// and become unreadable by everyone, including the buyer.
#[component]
fn KeptConversations(store_contract_id: Vec<u8>, kept: Vec<([u8; 32], i64, bool)>) -> Element {
    // Which one is a click away from being destroyed, if any. Two steps
    // because there is no undo and no second copy anywhere.
    let mut confirming = use_signal(|| Option::<[u8; 32]>::None);
    let unsaved = kept.iter().filter(|(_, _, backed_up)| !backed_up).count();

    rsx! {
        div { style: "margin-top: 1.5rem;",
            if !kept.is_empty() {
                h4 { "Kept on this device" }
                p { class: "text-muted", style: "font-size: 0.85rem;",
                    "This node is keeping the key that reads {kept.len()} conversation(s) with "
                    "this store, so a reply is still readable after you close this tab."
                }
                if unsaved > 0 {
                    p { class: "text-warning", style: "font-size: 0.85rem;",
                        "{unsaved} of them exist on this device and nowhere else. If you lose "
                        "this machine you lose the conversation, and anything the seller sent "
                        "you in it. Make a backup you can keep somewhere else."
                    }
                }
            }
            for (tag, created_at, backed_up) in kept.iter() {
                {
                    let tag = *tag;
                    let backed_up = *backed_up;
                    let when = chrono::DateTime::from_timestamp(*created_at, 0)
                        .map(|when| when.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_else(|| "an unknown time".to_string());
                    let store_contract_id = store_contract_id.clone();
                    rsx! {
                        div { class: "card", style: "margin-top: 0.5rem;",
                            p { class: "text-muted", style: "font-size: 0.8rem;",
                                "Conversation {short_tag(&tag)}, started {when}"
                            }
                            if backed_up {
                                p { class: "text-muted", style: "font-size: 0.8rem;",
                                    "You have said you hold a copy of this elsewhere."
                                }
                            } else {
                                p { class: "text-warning", style: "font-size: 0.8rem;",
                                    "On this device only."
                                }
                            }
                            ConversationBackupControl {
                                store_contract_id: store_contract_id.clone(),
                                tag: tag,
                            }
                            if confirming() == Some(tag) {
                                p { class: "text-warning", style: "font-size: 0.85rem;",
                                    "Forget this conversation? Your messages and the seller's "
                                    "replies stay in the seller's mailbox and become unreadable "
                                    "by everyone, including you. This cannot be undone."
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        APP_STATE.write().forget_conversation(&store_contract_id, &tag);
                                        confirming.set(None);
                                    },
                                    "Yes, forget it"
                                }
                                button {
                                    class: "btn",
                                    onclick: move |_| confirming.set(None),
                                    "Keep it"
                                }
                            } else {
                                button {
                                    class: "btn",
                                    onclick: move |_| confirming.set(Some(tag)),
                                    "Forget this conversation"
                                }
                            }
                        }
                    }
                }
            }

            Restore {}
        }
    }
}

/// Saving ONE conversation, and saying you have.
///
/// # What the string is
///
/// It holds the secret itself -- that is what makes it work on another
/// machine, and what makes it worth exactly as much as the conversation it
/// restores. Anyone who has it can read that conversation and, once a
/// seller's reply carries a pre-signed statement, file the complaint it
/// authorizes as though they were the buyer. That is said beside the string
/// rather than in a tooltip, because it is the whole basis on which a person
/// decides where to put it.
///
/// # Why one conversation at a time
///
/// A store-wide backup is too easy to leave out of date: taken on Monday,
/// silently incomplete on Tuesday, with nothing about the artefact saying
/// which conversations it covered. And a "saved" marker set from a store-wide
/// export would falsely cover a conversation created after it. Per
/// conversation the marker means something checkable: THIS one exists in more
/// than one place.
///
/// # Why "I have saved this" is a separate button
///
/// Showing a backup is not saving one. A buyer who opens the panel, reads the
/// string and closes the tab has saved nothing, so revealing it must not
/// clear the warning -- only the buyer saying they have it does. The delegate
/// gates that marker for the same reason: the party that benefits from the
/// warning stopping is not the party that loses the conversation.
#[component]
fn ConversationBackupControl(store_contract_id: Vec<u8>, tag: [u8; 32]) -> Element {
    // The string, once the delegate has answered, and only for THIS
    // conversation -- one is on screen at a time and it must never appear
    // under another conversation's heading.
    let backup = APP_STATE
        .read()
        .conversation_backup_on_screen
        .as_ref()
        .filter(|backup| {
            backup.store_contract_id == store_contract_id && backup.buyer_public_key == tag
        })
        .map(|backup| backup.text().to_string());

    rsx! {
        if let Some(backup) = backup {
            p { class: "text-warning", style: "font-size: 0.85rem;",
                "Save this somewhere only you can reach. Anyone who has it can read this "
                "conversation, and can use it to complain about this seller as though they "
                "were you. It is not a password you can change: it is the conversation."
            }
            textarea {
                class: "form-textarea",
                readonly: true,
                rows: 3,
                value: "{backup}",
            }
            button {
                class: "btn btn-primary",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    move |_| {
                        let mut app = APP_STATE.write();
                        app.mark_conversation_backed_up(&store_contract_id, &tag);
                        app.conversation_backup_on_screen = None;
                    }
                },
                "I have saved this"
            }
            button {
                class: "btn",
                onclick: move |_| {
                    APP_STATE.write().conversation_backup_on_screen = None;
                },
                "Hide it"
            }
        } else {
            button {
                class: "btn",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    move |_| APP_STATE.write().export_conversation(&store_contract_id, &tag)
                },
                "Back up this conversation"
            }
        }
    }
}

/// Putting a saved conversation back.
///
/// Offered even on a device holding nothing: restoring onto a new machine is
/// the case the whole mechanism exists for, and there is nothing kept there
/// to hang the control off. One string covers one conversation, so a buyer
/// restoring a machine pastes several in a row.
#[component]
fn Restore() -> Element {
    let mut paste = use_signal(String::new);

    rsx! {
        div { style: "margin-top: 1rem;",
            h4 { "Restore a conversation" }
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "A backup is a single line of text holding the key to ONE conversation. Paste "
                "one here to read that conversation on this device; paste them one after "
                "another if you saved several."
            }
            div { class: "form-group",
                textarea {
                    class: "form-textarea",
                    rows: 3,
                    placeholder: "Paste a Harvest conversation backup here.",
                    value: "{paste}",
                    oninput: move |event| paste.set(event.value()),
                }
            }
            button {
                class: "btn",
                disabled: paste().trim().is_empty(),
                onclick: move |_| {
                    let pasted = paste().trim().to_string();
                    if pasted.is_empty() {
                        return;
                    }
                    APP_STATE.write().import_conversation(pasted);
                    paste.set(String::new());
                },
                "Restore"
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
    /// Entry digests this browser wrote. The ONLY authorship anything here
    /// can establish -- see `state::AppState::authored_here`. Digests rather
    /// than nonces because a nonce is public and a substitute shares it.
    authored_here: Vec<[u8; 32]>,
) -> Element {
    rsx! {
        div { style: "margin-top: 1.5rem;",
            h4 { "Your conversation" }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "This conversation survives a reload on this device: the key that reads it is "
                "kept by your Freenet node. It does not follow you to another browser or "
                "another device, where the same messages cannot be read by anyone."
            }
            p { class: "text-muted",
                style: "font-size: 0.85rem;",
                "Only messages this tab sent are marked as yours. Everything else is shown "
                "by which direction it was encrypted for, which is not proof of who wrote "
                "it -- both sides of a conversation hold both keys."
            }

            for message in thread.iter() {
                {
                    let when = message.timestamp.format("%Y-%m-%d %H:%M UTC").to_string();
                    let who = attribution(
                        authored_here.contains(&message.digest),
                        message.addressing,
                        Role::Buyer,
                    );
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
        p { class: "text-muted",
            style: "margin-bottom: 1rem;",
            "The seller replies into the same mailbox and their answer appears here. Reading "
            "it needs a key your node keeps for you, so it survives closing this tab but does "
            "not follow you to another device -- come back to this one for the answer."
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
    deliver_to_seller(store_contract_id, seller, text, sealed)
}

/// Subscribe, dispatch, and record -- everything a buyer's outgoing message
/// needs once it is sealed.
///
/// Shared with the buy form rather than copied, because the subscribe is the
/// part that is easy to leave out of a second copy: without it the buyer
/// never fetches the mailbox again, and the seller's acceptance -- the one
/// thing that tells them which commitment is theirs -- sits there unread.
///
/// `record_as` is what the buyer's own record calls this message. It is not
/// the message: a request carries structured fields, and the local record
/// exists to say "you wrote this", not to reproduce it.
pub(crate) fn deliver_to_seller(
    store_contract_id: &[u8],
    seller: ed25519_dalek::VerifyingKey,
    record_as: String,
    sealed: harvest_common::mailbox::EncryptedMessage,
) -> Result<(), String> {
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
        .record_sent_message(store_contract_id, record_as, &sealed);
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
fn Inbox(
    store_contract_id: Vec<u8>,
    entries: Vec<MailboxEntry>,
    authored: Vec<[u8; 32]>,
) -> Element {
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
                    authored: authored.clone(),
                }
            }
        }
    }
}

/// One exchange with one buyer, and the box to answer it.
#[component]
fn Conversation(
    store_contract_id: Vec<u8>,
    tag: Vec<u8>,
    entries: Vec<MailboxEntry>,
    authored: Vec<[u8; 32]>,
) -> Element {
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
            p { class: "text-muted", style: "font-size: 0.8rem;",
                "Only messages this tab sent are marked as yours. Everything else is shown by "
                "the direction it was encrypted for, which is not proof of who wrote it -- "
                "both sides of a conversation hold both keys."
            }
            for entry in entries.iter() {
                MessageCard {
                    entry: entry.clone(),
                    authored_here: authored.contains(&entry.digest()),
                }
            }

            // A request to buy is the one message in a seller's inbox that
            // has an action attached, so it gets the control rather than
            // leaving the seller to copy a listing id into the invoice form
            // by hand -- which is also how the reply-to tag would get lost.
            if let Some((listing_id, quantity)) = pending_request(&entries) {
                super::buy_view::AcceptRequest {
                    store_contract_id: store_contract_id.clone(),
                    tag: tag.clone(),
                    listing_id: listing_id,
                    quantity: quantity,
                }
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
                    "read it whenever they come back from the same device they wrote from -- "
                    "and never from a different one, so a buyer who has changed device will "
                    "not see it."
                }
            } else {
                p { class: "text-muted text-italic", style: "font-size: 0.85rem;",
                    "Nothing here can be read, so there is nothing to reply to."
                }
            }
        }
    }
}

/// Which side of a conversation this browser is on. Decides how an
/// unattributed message is described, and nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Buyer,
    Seller,
}

/// What to put above a message, given what is actually known about it.
///
/// # Why this is not "Seller" and "You"
///
/// It was, and it was wrong. `Addressing` says which direction key
/// authenticated a message, and BOTH parties hold both keys -- the buyer
/// needs the seller-to-buyer key to read replies at all. So a buyer can place
/// a message in the seller's mailbox that authenticates as though the seller
/// wrote it, and the seller's own screen would have shown it as their own
/// words. Verified: a seller's inbox displayed "as agreed, I confess" as the
/// seller's own reply, written by the buyer.
///
/// Only one thing here is knowable: what this browser sent itself. That gets
/// a name. Everything else is described by direction, in words that say
/// direction -- "addressed to", not "from" -- and the surrounding notice says
/// plainly that direction is not authorship.
///
/// Anything whose authenticity actually matters must carry its own signature;
/// see [`harvest_common::mailbox::MessageDirection`].
fn attribution(
    authored_here: bool,
    addressing: crate::messaging::Addressing,
    role: Role,
) -> &'static str {
    use crate::messaging::Addressing;
    if authored_here {
        return "You, from this tab";
    }
    match (role, addressing) {
        (Role::Buyer, Addressing::ToBuyer) => "Addressed to you",
        (Role::Buyer, Addressing::ToSeller) => "Addressed to the seller",
        (Role::Seller, Addressing::ToSeller) => "Addressed to you",
        (Role::Seller, Addressing::ToBuyer) => "Addressed to this buyer",
    }
}

/// The request to buy this conversation is waiting on, if any.
///
/// Newest first, so a buyer who asked twice gets the second ask acted on
/// rather than the first. `entries` is a seller's own inbox view, which
/// `mailbox_entries` returns newest-first.
///
/// # Why direction is not checked here, and where it IS
///
/// This is the seller's side, and it deliberately mirrors the buyer's rule
/// (`state::AppState::buyer_purchases`, which ignores an acceptance not
/// addressed to the buyer) only in spirit. A request the SELLER composed
/// would be one they wrote to themselves, which costs them their own money
/// and nobody else's -- so the asymmetry is real rather than an oversight,
/// and `MailboxEntry` does not carry direction anyway. What protects the
/// buyer is that accepting publishes a commitment the buyer then has to
/// recognise as answering their own request.
fn pending_request(entries: &[MailboxEntry]) -> Option<(harvest_common::listing::ListingId, u32)> {
    entries.iter().find_map(|entry| match entry {
        MailboxEntry::Readable {
            content:
                MessageContent::OrderRequest {
                    listing_id,
                    quantity,
                    ..
                },
            ..
        } => Some((listing_id.clone(), *quantity)),
        _ => None,
    })
}

/// Enough of a conversation tag to tell two apart on screen, and no more --
/// the whole thing is 44 characters of base58 that means nothing to a reader.
///
/// One implementation, in `state`, because the same shortening appears in
/// notifications this component does not render: two would drift, and a
/// buyer matching a warning against a line on screen needs them identical.
fn short_tag(tag: &[u8]) -> String {
    crate::state::short_conversation_tag(tag)
}

/// Seal a seller's reply and hand it to the node.
fn reply(store_contract_id: &[u8], tag: &[u8], text: String) -> Result<(), String> {
    let text_for_record = text.clone();
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
    dispatch_reply(mailbox, sealed.clone());

    // Recorded for the same reason the buyer's messages are: it is the only
    // thing this browser can know about authorship. Without it the seller's
    // own reply comes back from the mailbox indistinguishable from one a
    // buyer wrote in that direction.
    APP_STATE
        .write()
        .record_sent_message(store_contract_id, text_for_record, &sealed);
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
fn MessageCard(entry: MailboxEntry, authored_here: bool) -> Element {
    let when = entry.timestamp().format("%Y-%m-%d %H:%M UTC").to_string();
    let who = match &entry {
        MailboxEntry::Readable { addressing, .. } => {
            Some(attribution(authored_here, *addressing, Role::Seller))
        }
        MailboxEntry::Unreadable { .. } => None,
    };
    rsx! {
        div { class: "card", style: "margin-top: 0.5rem;",
            if let Some(who) = who {
                p { class: "text-muted", style: "font-size: 0.8rem;", "{who}" }
            }
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
        MessageContent::OrderRequest {
            quantity,
            shipping,
            note,
            ..
        } => {
            let mut described = format!("Wants to buy {quantity}.\n\nShip to:\n{shipping}");
            if !note.trim().is_empty() {
                described.push_str(&format!("\n\n{note}"));
            }
            described
        }
        MessageContent::OrderAccepted { order_id } => {
            format!("Accepted -- invoice {} is published.", order_id.short())
        }
    }
}

#[cfg(test)]
mod inbox_tests {
    use super::*;
    use harvest_common::listing::ListingId;

    fn readable(content: MessageContent) -> MailboxEntry {
        MailboxEntry::Readable {
            conversation: vec![1u8; 32],
            conversation_id: harvest_common::mailbox::ConversationId([2u8; 32]),
            addressing: crate::messaging::Addressing::ToSeller,
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest: [0u8; 32],
            content,
        }
    }

    /// **The seller is offered an Accept only when there is a request to
    /// accept.**
    ///
    /// An accept control on an ordinary question would publish a commitment
    /// against an order nobody asked for.
    #[test]
    fn an_ordinary_message_offers_nothing_to_accept() {
        let entries = vec![readable(MessageContent::Text("is this in stock?".into()))];
        assert!(pending_request(&entries).is_none());
    }

    /// **A request carries the listing and quantity through to the accept
    /// control.**
    ///
    /// Not merely "there is a request": the two values are what the invoice
    /// is issued against, and a control that found the request but dropped
    /// the listing id would invoice for something else.
    #[test]
    fn a_request_carries_its_listing_and_quantity() {
        let listing = ListingId([9u8; 16]);
        let entries = vec![
            readable(MessageContent::Text("hello".into())),
            readable(MessageContent::OrderRequest {
                listing_id: listing.clone(),
                quantity: 4,
                shipping: "12 Example St".into(),
                note: String::new(),
            }),
        ];
        assert_eq!(pending_request(&entries), Some((listing, 4)));
    }

    /// **An unreadable entry is not a request.**
    ///
    /// The mailbox is open-write, so most of what arrives at a busy store is
    /// junk; an accept control that appeared for it would invite the seller
    /// to publish a commitment against nothing.
    #[test]
    fn an_unreadable_entry_is_not_a_request() {
        let entries = vec![MailboxEntry::Unreadable {
            conversation: vec![1u8; 32],
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest: [0u8; 32],
            why: "not for us".to_string(),
        }];
        assert!(pending_request(&entries).is_none());
    }
}
