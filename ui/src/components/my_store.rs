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
                IdentityList {
                    ghostkeys: app_state.ghostkeys.clone(),
                    my_stores: app_state.my_stores.clone(),
                    has_harvest_delegate: app_state.harvest_delegate_key.is_some(),
                }
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
                "Ghostkey Manager to import or create one via a Freenet donation."
            }
        }
    }
}

#[component]
fn IdentityList(
    ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,
    my_stores: std::collections::HashMap<String, Vec<harvest_common::StoreRegistration>>,
    has_harvest_delegate: bool,
) -> Element {
    rsx! {
        div {
            h3 { "Your Identities" }

            if !has_harvest_delegate {
                p {
                    style: "color: #c4a000; font-size: 0.85rem; margin-bottom: 1rem;",
                    "Harvest delegate not yet registered. Store creation will be available once the delegate is loaded."
                }
            }

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
                                    disabled: !has_harvest_delegate,
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

/// Initiate the store creation flow for a ghostkey identity.
///
/// Full flow:
/// 1. Send InitReputationKeys to harvest delegate (generates RSA keypair)
/// 2. Wait for RSA public key response
/// 3. Sign StoreInfoV1 via ghostkey delegate
/// 4. PUT reputation, store, and mailbox contracts
/// 5. Register store with harvest delegate
///
/// Steps 2-5 are handled reactively in the response handler as responses
/// arrive from the delegates and gateway.
fn create_store(_ghostkey_fingerprint: String) {
    #[cfg(target_arch = "wasm32")]
    {
        let ghostkey_fingerprint = _ghostkey_fingerprint;
        wasm_bindgen_futures::spawn_local(async move {
            let app_state = APP_STATE.read();
            let delegate_key = match &app_state.harvest_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!("Harvest delegate not registered");
                    return;
                }
            };
            drop(app_state);

            // Step 1: Initialize RSA keys for this identity
            let request = harvest_common::HarvestDelegateRequest::InitReputationKeys {
                ghostkey_fingerprint: ghostkey_fingerprint.clone(),
            };
            let payload = match harvest_common::to_cbor(&request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize request: {}", e);
                    return;
                }
            };

            if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
                dioxus::logger::tracing::error!("Failed to send InitReputationKeys: {}", e);
                return;
            }

            dioxus::logger::tracing::info!(
                "Sent InitReputationKeys for {} -- waiting for RSA key response",
                ghostkey_fingerprint
            );

            // The response handler will receive ReputationKeysInitialized
            // and store the RSA public key in APP_STATE.rsa_public_keys.
            // The remaining steps (contract creation) will be triggered
            // from a use_effect watching for the RSA key to appear.
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
