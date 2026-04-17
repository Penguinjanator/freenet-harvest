use dioxus::prelude::*;

use crate::gateway::APP_STATE;

/// Manage your own store: create listings, view your reputation.
#[component]
pub fn MyStore() -> Element {
    let app_state = APP_STATE.read();

    rsx! {
        div {
            h2 { "My Store" }

            // Show available ghostkey identities
            if app_state.ghostkeys.is_empty() {
                NoIdentity {}
            } else {
                IdentityList { ghostkeys: app_state.ghostkeys.clone(), my_stores: app_state.my_stores.clone() }
            }
        }
    }
}

#[component]
fn NoIdentity() -> Element {
    rsx! {
        div {
            style: "border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; text-align: center;",
            p {
                style: "font-size: 1.1rem; color: #666;",
                "No ghostkey identities found."
            }
            p {
                style: "color: #888;",
                "To create a store, you need a ghostkey identity. Visit the "
                a { href: "#", "Ghostkey Manager" }
                " to import or create one via a Freenet donation."
            }
        }
    }
}

#[component]
fn IdentityList(
    ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,
    my_stores: std::collections::HashMap<String, Vec<harvest_common::StoreRegistration>>,
) -> Element {
    rsx! {
        div {
            h3 { "Your Identities" }
            for key in &ghostkeys {
                div {
                    style: "border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;",
                    div {
                        style: "display: flex; justify-content: space-between; align-items: center;",
                        div {
                            strong {
                                if let Some(ref label) = key.label {
                                    "{label}"
                                } else {
                                    "{truncate_fingerprint(&key.fingerprint)}"
                                }
                            }
                            span {
                                style: "margin-left: 0.5rem; font-size: 0.8rem; color: #888;",
                                "({key.notary_info})"
                            }
                        }
                        div {
                            if let Some(stores) = my_stores.get(&key.fingerprint) {
                                span {
                                    style: "color: #2d5016; font-size: 0.85rem;",
                                    "{stores.len()} store(s)"
                                }
                            } else {
                                button {
                                    style: "background: #2d5016; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem;",
                                    onclick: {
                                        let fp = key.fingerprint.clone();
                                        move |_| {
                                            let fp = fp.clone();
                                            create_store(fp);
                                        }
                                    },
                                    "Create Store"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Initiate store creation for a ghostkey identity.
///
/// This triggers:
/// 1. InitReputationKeys on the harvest delegate (generates RSA keypair)
/// 2. The response handler will receive the RSA public key
/// 3. The UI will then need to PUT the store + reputation + mailbox contracts
///
/// For now, we just send the InitReputationKeys request. The full flow
/// will be completed once we can test against a real Freenet node.
fn create_store(_ghostkey_fingerprint: String) {
    #[cfg(target_arch = "wasm32")]
    {
        let ghostkey_fingerprint = _ghostkey_fingerprint;
        use harvest_common::{to_cbor, HarvestDelegateRequest};

        wasm_bindgen_futures::spawn_local(async move {
            let request = HarvestDelegateRequest::InitReputationKeys {
                ghostkey_fingerprint: ghostkey_fingerprint.clone(),
            };
            let payload = match to_cbor(&request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize request: {}", e);
                    return;
                }
            };

            // We need the harvest delegate key to send the message.
            // For now, log that we would send it. The delegate key will be
            // known after register_delegate() is called during app startup.
            dioxus::logger::tracing::info!(
                "Would send InitReputationKeys for {} ({} bytes payload)",
                ghostkey_fingerprint,
                payload.len()
            );
        });
    }
}

fn truncate_fingerprint(fp: &str) -> String {
    if fp.len() > 12 {
        format!("{}...", &fp[..12])
    } else {
        fp.to_string()
    }
}
