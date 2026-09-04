use dioxus::prelude::*;

use crate::gateway::APP_STATE;

/// Buyer-seller messaging, which does not work yet.
///
/// # Why this renders a notice instead of a compose box
///
/// The previous version of this component told the buyer "Messages are
/// end-to-end encrypted. The seller cannot see who you are unless you choose
/// to share identifying information", offered a textarea and a Send button,
/// and then -- on submit -- logged a line and pushed a notification. Nothing
/// was encrypted, nothing was sent, and `crate::messaging`'s
/// `encrypt_message`/`decrypt_message` have no callers outside their own
/// tests.
///
/// That is the worst shape a missing feature can take. The claim was not
/// decoration: it is exactly the sentence a buyer reads while deciding how
/// much to disclose to a stranger, and it was false in both halves -- the
/// message was not encrypted because it was not sent at all.
///
/// So the component says what is true. The compose box is kept, and
/// disabled, rather than removed: a buyer looking for "how do I contact this
/// seller" should find the answer ("you can't yet") where they went looking
/// for it, not find nothing and assume they missed it.
///
/// What is still missing, and why it is not a small change: the buyer needs
/// the seller's X25519 public key to derive a conversation key, and nothing
/// publishes one. `StoreInfoV1` carries a certificate and a reputation
/// contract id, not an encryption key. Until a key exchange exists there is
/// no honest way to encrypt anything, and sending unencrypted text to a
/// public contract would be worse than sending nothing.
#[component]
pub fn MessageView(store_contract_id: Vec<u8>) -> Element {
    let app_state = APP_STATE.read();
    let store = app_state.browsing_stores.get(&store_contract_id);
    let store_name = store
        .and_then(|s| s.info.as_ref())
        .map(|i| i.store_name.as_str())
        .unwrap_or("Store");
    let message_count = store.map(|s| s.mailbox_messages.len()).unwrap_or(0);

    rsx! {
        div { class: "card",
            h3 { "Contact {store_name}" }

            p { class: "text-warning",
                style: "margin-bottom: 1rem;",
                "Messaging is not built yet. Harvest cannot send this seller a message, "
                "and nothing you type below leaves this page. Use whatever contact route "
                "the store's payment instructions give you instead."
            }

            div { class: "form-group",
                label { class: "form-label", "Your Message" }
                textarea {
                    class: "form-textarea",
                    disabled: true,
                    placeholder: "Messaging isn't available yet.",
                }
            }

            if message_count > 0 {
                div {
                    style: "margin-top: 1.5rem;",
                    h3 { "Messages" }
                    p { class: "text-muted",
                        style: "font-size: 0.85rem;",
                        "This store's mailbox contract holds encrypted messages. Harvest "
                        "cannot decrypt them: the key exchange that would produce the "
                        "conversation key does not exist yet."
                    }
                    p { class: "section-count",
                        "{message_count} encrypted message(s)"
                    }
                }
            }
        }
    }
}
