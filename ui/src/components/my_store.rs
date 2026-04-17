use dioxus::prelude::*;
use harvest_common::listing::Listing;

use super::listing_form::ListingForm;
use crate::gateway::APP_STATE;

/// Manage your own store: create listings, view your reputation.
#[component]
pub fn MyStore() -> Element {
    let app_state = APP_STATE.read();

    rsx! {
        div {
            h2 { "My Store" }

            if app_state.ghostkeys.is_empty() {
                NoIdentity {}
            } else {
                IdentityList {
                    ghostkeys: app_state.ghostkeys.clone(),
                    my_stores: app_state.my_stores.clone(),
                    rsa_keys: app_state.rsa_public_keys.clone(),
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
    rsa_keys: std::collections::HashMap<String, Vec<u8>>,
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

            for gk in &ghostkeys {
                IdentityCard {
                    identity: gk.clone(),
                    has_store: my_stores.contains_key(&gk.fingerprint),
                    has_rsa_key: rsa_keys.contains_key(&gk.fingerprint),
                    has_harvest_delegate: has_harvest_delegate,
                }
            }
        }
    }
}

#[component]
fn IdentityCard(
    identity: ghostkey_common::GhostKeyInfo,
    has_store: bool,
    has_rsa_key: bool,
    has_harvest_delegate: bool,
) -> Element {
    let mut show_listing_form = use_signal(|| false);
    let fp = identity.fingerprint.clone();

    rsx! {
        div {
            style: "border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;",
            div {
                style: "display: flex; justify-content: space-between; align-items: center;",
                div {
                    strong {
                        if let Some(ref label) = identity.label {
                            "{label}"
                        } else {
                            "{truncate_fingerprint(&identity.fingerprint)}"
                        }
                    }
                    span {
                        style: "margin-left: 0.5rem; font-size: 0.8rem; color: #888;",
                        "({identity.notary_info})"
                    }
                }
                div { style: "display: flex; gap: 0.5rem;",
                    if has_store {
                        button {
                            style: "background: #2d5016; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem;",
                            onclick: move |_| show_listing_form.toggle(),
                            if show_listing_form() { "Cancel" } else { "Add Listing" }
                        }
                    } else if has_rsa_key {
                        span {
                            style: "color: #c4a000; font-size: 0.85rem;",
                            "RSA keys ready -- creating contracts..."
                        }
                    } else {
                        button {
                            style: "background: #2d5016; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem;",
                            disabled: !has_harvest_delegate,
                            onclick: {
                                let fp = identity.fingerprint.clone();
                                move |_| {
                                    create_store(fp.clone());
                                }
                            },
                            "Create Store"
                        }
                    }
                }
            }

            // Show listing form when toggled
            if show_listing_form() {
                ListingForm {
                    seller_fingerprint: fp.clone(),
                    on_submit: move |listing: Listing| {
                        show_listing_form.set(false);
                        sign_and_submit_listing(fp.clone(), listing);
                    },
                }
            }
        }
    }
}

/// Step 1 of store creation: request RSA keys from the harvest delegate.
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
        });
    }
}

/// Sign a listing via the ghostkey delegate and submit it to the store contract.
fn sign_and_submit_listing(_fingerprint: String, _listing: Listing) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let listing = _listing;

        wasm_bindgen_futures::spawn_local(async move {
            // Serialize the listing to CBOR for signing
            let listing_bytes = match harvest_common::to_cbor(&listing) {
                Ok(b) => b,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize listing: {}", e);
                    return;
                }
            };

            // Send SignMessage to the ghostkey delegate
            let app_state = APP_STATE.read();
            let gk_delegate_key = match &app_state.ghostkey_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!(
                        "Ghostkey delegate not registered -- cannot sign listing"
                    );
                    APP_STATE.write().notifications.push(
                        "Cannot sign listing: ghostkey delegate not available. \
                         Make sure the Ghostkey Manager has been opened at least once."
                            .into(),
                    );
                    return;
                }
            };
            drop(app_state);

            let sign_request = ghostkey_common::GhostkeyRequest::SignMessage {
                fingerprint: fingerprint.clone(),
                message: listing_bytes,
            };
            let payload = match ghostkey_common::to_cbor(&sign_request) {
                Ok(p) => p,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize sign request: {}", e);
                    return;
                }
            };

            if let Err(e) = crate::gateway::send_delegate_message(&gk_delegate_key, payload).await {
                dioxus::logger::tracing::error!("Failed to send SignMessage: {}", e);
                return;
            }

            dioxus::logger::tracing::info!(
                "Sent listing for signing (fingerprint: {}, title: {})",
                fingerprint,
                listing.title
            );

            // The response handler will receive GhostkeyResponse::SignResult
            // and needs to construct the AuthorizedListing and submit it to
            // the store contract. This requires storing the pending listing
            // so the response handler can match it up.
            APP_STATE.write().pending_listing = Some(crate::state::PendingListing {
                fingerprint,
                listing,
            });
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
