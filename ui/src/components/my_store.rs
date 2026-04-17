use dioxus::prelude::*;
use harvest_common::listing::Listing;

use super::listing_form::ListingForm;
use crate::gateway::APP_STATE;

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
        div { class: "card empty-state",
            p { "No ghostkey identities found." }
            p {
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
                p { class: "text-warning",
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
    let mut show_store_form = use_signal(|| false);
    let fp = identity.fingerprint.clone();

    rsx! {
        div { class: "identity-card",
            div {
                span { class: "identity-name",
                    if let Some(ref label) = identity.label {
                        "{label}"
                    } else {
                        "{truncate_fingerprint(&identity.fingerprint)}"
                    }
                }
                span { class: "identity-tier", "({identity.notary_info})" }
            }
            div {
                if has_store {
                    button {
                        class: if show_listing_form() { "btn btn-sm btn-outline" } else { "btn btn-sm btn-primary" },
                        onclick: move |_| show_listing_form.toggle(),
                        if show_listing_form() { "Cancel" } else { "Add Listing" }
                    }
                } else if has_rsa_key {
                    span { class: "text-warning", "Creating contracts..." }
                } else {
                    button {
                        class: if show_store_form() { "btn btn-sm btn-outline" } else { "btn btn-sm btn-primary" },
                        disabled: !has_harvest_delegate,
                        onclick: move |_| show_store_form.toggle(),
                        if show_store_form() { "Cancel" } else { "Create Store" }
                    }
                }
            }
        }

        if show_store_form() {
            StoreCreationForm {
                fingerprint: identity.fingerprint.clone(),
                on_submit: move |details: StoreDetails| {
                    show_store_form.set(false);
                    initiate_store_creation(identity.fingerprint.clone(), details);
                },
            }
        }

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

struct StoreDetails {
    store_name: String,
    description: String,
    payment_instructions: String,
}

#[component]
fn StoreCreationForm(fingerprint: String, on_submit: EventHandler<StoreDetails>) -> Element {
    let mut store_name = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut payment_instructions = use_signal(String::new);

    rsx! {
        div { class: "card",
            h3 { "Create Your Store" }

            div { class: "form-group",
                label { class: "form-label", "Store Name" }
                input {
                    class: "form-input",
                    r#type: "text",
                    placeholder: "e.g. Mountain Valley Crafts",
                    value: "{store_name}",
                    oninput: move |e| store_name.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Description" }
                textarea {
                    class: "form-textarea",
                    placeholder: "Tell buyers about your store...",
                    value: "{description}",
                    oninput: move |e| description.set(e.value()),
                }
            }

            div { class: "form-group",
                label { class: "form-label", "Payment Instructions" }
                textarea {
                    class: "form-textarea",
                    placeholder: "How should buyers pay? e.g. BTC: bc1q..., or contact me to arrange",
                    value: "{payment_instructions}",
                    oninput: move |e| payment_instructions.set(e.value()),
                }
            }

            button {
                class: "btn btn-primary",
                disabled: store_name().trim().is_empty(),
                onclick: move |_| {
                    on_submit.call(StoreDetails {
                        store_name: store_name().trim().to_string(),
                        description: description().trim().to_string(),
                        payment_instructions: payment_instructions().trim().to_string(),
                    });
                },
                "Create Store"
            }
        }
    }
}

/// Initiate the full store creation flow:
/// 1. Set pending_store_creation with store details
/// 2. Send InitReputationKeys to harvest delegate
/// 3. When RSA key arrives, state.rs triggers create_store_contracts
fn initiate_store_creation(_fingerprint: String, _details: StoreDetails) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let details = _details;

        wasm_bindgen_futures::spawn_local(async move {
            // First, we need the ghostkey's verifying key and certificate.
            // For now, we'll need the ghostkey delegate to provide these.
            // The certificate PEM and verifying key bytes come from
            // GhostkeyResponse::GhostKeyDetail or GhostkeyResponse::Certificate.
            //
            // For the initial implementation, we store the pending creation
            // with placeholder values -- the verifying key will come from
            // the ghostkey certificate when we have inter-delegate communication.
            //
            // TODO: Request GhostKeyDetail from ghostkey delegate to get
            // certificate_pem and extract verifying key bytes.

            let app_state = APP_STATE.read();
            let delegate_key = match &app_state.harvest_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!("Harvest delegate not registered");
                    return;
                }
            };
            drop(app_state);

            // Store the pending creation details
            APP_STATE.write().pending_store_creation = Some(crate::state::PendingStoreCreation {
                ghostkey_fingerprint: fingerprint.clone(),
                // These will be filled in from the ghostkey certificate
                // For now, use placeholder -- this will be fixed when we
                // wire up ghostkey delegate communication
                seller_verifying_key_bytes: [0u8; 32],
                certificate_pem: String::new(),
                store_name: details.store_name,
                description: details.description,
                payment_instructions: details.payment_instructions,
            });

            // Send InitReputationKeys to harvest delegate
            let request = harvest_common::HarvestDelegateRequest::InitReputationKeys {
                ghostkey_fingerprint: fingerprint.clone(),
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
                "Sent InitReputationKeys for {} -- store creation pending",
                fingerprint
            );
        });
    }
}

fn sign_and_submit_listing(_fingerprint: String, _listing: Listing) {
    #[cfg(target_arch = "wasm32")]
    {
        let fingerprint = _fingerprint;
        let listing = _listing;

        wasm_bindgen_futures::spawn_local(async move {
            let listing_bytes = match harvest_common::to_cbor(&listing) {
                Ok(b) => b,
                Err(e) => {
                    dioxus::logger::tracing::error!("Failed to serialize listing: {}", e);
                    return;
                }
            };

            let app_state = APP_STATE.read();
            let gk_delegate_key = match &app_state.ghostkey_delegate_key {
                Some(k) => k.clone(),
                None => {
                    dioxus::logger::tracing::error!(
                        "Ghostkey delegate not registered -- cannot sign listing"
                    );
                    APP_STATE
                        .write()
                        .notifications
                        .push("Cannot sign listing: ghostkey delegate not available.".into());
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
