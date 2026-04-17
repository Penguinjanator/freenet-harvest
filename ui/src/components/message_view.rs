use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::messaging::{MessageContent, PlaintextMessage};

/// Message compose and display component for buyer-seller communication.
#[component]
pub fn MessageView(store_contract_id: Vec<u8>) -> Element {
    let app_state = APP_STATE.read();
    let mut message_input = use_signal(String::new);

    // Get the store info and any messages
    let store = app_state.browsing_stores.get(&store_contract_id);
    let store_name = store
        .and_then(|s| s.info.as_ref())
        .map(|i| i.store_name.as_str())
        .unwrap_or("Store");

    rsx! {
        div { class: "card",
            h3 { "Contact {store_name}" }

            p { class: "text-muted",
                style: "margin-bottom: 1rem;",
                "Messages are end-to-end encrypted. The seller cannot see who you are "
                "unless you choose to share identifying information."
            }

            // Message compose area
            div { class: "form-group",
                label { class: "form-label", "Your Message" }
                textarea {
                    class: "form-textarea",
                    placeholder: "Hi, I'm interested in...",
                    value: "{message_input}",
                    oninput: move |e| message_input.set(e.value()),
                }
            }

            button {
                class: "btn btn-primary",
                disabled: message_input().trim().is_empty(),
                onclick: {
                    let store_id = store_contract_id.clone();
                    move |_| {
                        let content = message_input().trim().to_string();
                        message_input.set(String::new());
                        send_message(store_id.clone(), content);
                    }
                },
                "Send Message"
            }

            // Display any existing messages in this conversation
            if let Some(store) = store {
                if !store.mailbox_messages.is_empty() {
                    div {
                        style: "margin-top: 1.5rem;",
                        h3 { "Messages" }
                        p { class: "text-muted",
                            style: "font-size: 0.85rem;",
                            "Encrypted messages in this mailbox (decryption requires the conversation key)."
                        }
                        p { class: "section-count",
                            "{store.mailbox_messages.len()} encrypted message(s)"
                        }
                    }
                }
            }
        }
    }
}

fn send_message(_store_contract_id: Vec<u8>, _content: String) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::messaging::{EphemeralKeypair, MessageContent, PlaintextMessage};
        use harvest_common::mailbox::ConversationId;

        let store_contract_id = _store_contract_id;
        let content = _content;

        wasm_bindgen_futures::spawn_local(async move {
            // Generate ephemeral keypair for this conversation
            let keypair = EphemeralKeypair::generate();
            let our_public = keypair.public_key;

            // For now, we need the seller's public key to encrypt.
            // This would come from the store info or a key exchange protocol.
            // For the initial implementation, log and notify the user.
            dioxus::logger::tracing::info!(
                "Would send encrypted message to store {:?}: {}",
                &store_contract_id[..8.min(store_contract_id.len())],
                content
            );

            APP_STATE.write().notifications.push(
                "Message ready to send. Full encryption requires the seller's public key, \
                 which will be available after the key exchange protocol is implemented."
                    .into(),
            );

            // TODO: Complete flow:
            // 1. Get seller's X25519 public key (from store info or discovery)
            // 2. Derive shared AES key via X25519 + BLAKE3
            // 3. Create PlaintextMessage with ConversationId::random()
            // 4. Encrypt with encrypt_message()
            // 5. Send as delta update to the mailbox contract
        });
    }
}
