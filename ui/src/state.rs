//! Application state managed via Dioxus GlobalSignal.
//!
//! Centralizes all reactive state so the response handler and UI components
//! can read/write from a single source of truth.

use dioxus::logger::tracing::info;
use harvest_common::listing::AuthorizedListing;
use harvest_common::mailbox::EncryptedMessage;
use harvest_common::reputation::FeedbackEntry;
use harvest_common::store::StoreInfoV1;
use harvest_common::{HarvestDelegateResponse, StoreRegistration};
use std::collections::HashMap;

/// The main application state.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// The harvest delegate key (set after registration during app startup).
    pub harvest_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// The ghostkey delegate key (set after registration during app startup).
    pub ghostkey_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// Stores we're currently browsing, keyed by store contract ID.
    pub browsing_stores: HashMap<Vec<u8>, BrowsingStore>,

    /// Maps reputation contract IDs back to their store contract IDs,
    /// so reputation state can be matched to the right store.
    pub reputation_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Maps mailbox contract IDs back to their store contract IDs.
    pub mailbox_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Our own stores (ghostkey fingerprint -> list of registrations).
    pub my_stores: HashMap<String, Vec<StoreRegistration>>,

    /// Ghostkey identities available to us.
    pub ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,

    /// RSA public keys for our identities (fingerprint -> DER bytes).
    pub rsa_public_keys: HashMap<String, Vec<u8>>,

    /// Pending messages/events for the UI to display.
    pub notifications: Vec<String>,
}

/// State for a store we're browsing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BrowsingStore {
    pub info: Option<StoreInfoV1>,
    pub listings: Vec<AuthorizedListing>,
    /// Reputation contract ID (extracted from StoreInfoV1 on first load).
    pub reputation_contract_id: Option<Vec<u8>>,
    /// Mailbox contract ID (will be set when we know it).
    pub mailbox_contract_id: Option<Vec<u8>>,
    /// Negative feedback entries from the reputation contract.
    pub feedback: Vec<FeedbackEntry>,
    /// Encrypted messages from the mailbox contract.
    pub mailbox_messages: Vec<EncryptedMessage>,
}

impl AppState {
    /// Start browsing a store: subscribe to it and prepare state.
    pub fn begin_browsing(&mut self, store_contract_id: Vec<u8>) {
        self.browsing_stores.entry(store_contract_id).or_default();
    }

    /// Handle full contract state received from a GET response.
    pub fn on_contract_state(&mut self, contract_id: Vec<u8>, state_bytes: Vec<u8>) {
        if state_bytes.is_empty() {
            return;
        }

        // Try store contract first
        if let Ok(store_state) =
            harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(&state_bytes)
        {
            info!(
                "Received store state for {:?}",
                &contract_id[..8.min(contract_id.len())]
            );
            let reputation_id = store_state.info.info.reputation_contract_id.to_vec();

            let store = self.browsing_stores.entry(contract_id.clone()).or_default();
            store.info = Some(store_state.info.info);
            store.listings = store_state.listings.listings;
            store.reputation_contract_id = Some(reputation_id.clone());

            // Register the reverse mapping so incoming reputation state
            // can be matched to this store
            self.reputation_to_store.insert(reputation_id, contract_id);
            return;
        }

        // Try reputation contract
        if let Ok(reputation_state) =
            harvest_common::from_cbor::<harvest_common::reputation::ReputationStateV1>(&state_bytes)
        {
            info!(
                "Received reputation state ({} entries)",
                reputation_state.feedback.len()
            );

            // Look up which store this reputation belongs to
            if let Some(store_id) = self.reputation_to_store.get(&contract_id).cloned() {
                if let Some(store) = self.browsing_stores.get_mut(&store_id) {
                    store.feedback = reputation_state.feedback;
                }
            } else {
                info!("Reputation state for unknown store -- caching by contract ID");
                // Cache it; will be linked when the store state arrives
                let store = self.browsing_stores.entry(contract_id).or_default();
                store.feedback = reputation_state.feedback;
            }
            return;
        }

        // Try mailbox contract
        if let Ok(mailbox_state) =
            harvest_common::from_cbor::<harvest_common::mailbox::MailboxStateV1>(&state_bytes)
        {
            info!(
                "Received mailbox state ({} messages)",
                mailbox_state.messages.len()
            );

            if let Some(store_id) = self.mailbox_to_store.get(&contract_id).cloned() {
                if let Some(store) = self.browsing_stores.get_mut(&store_id) {
                    store.mailbox_messages = mailbox_state.messages;
                }
            }
            return;
        }

        info!(
            "Received unknown contract state ({} bytes)",
            state_bytes.len()
        );
    }

    /// Handle a contract update notification (delta).
    pub fn on_contract_update(&mut self, contract_id: Vec<u8>, update_bytes: Vec<u8>) {
        // Deltas for our contract types can be applied incrementally.
        // For reputation, a delta is Vec<FeedbackEntry> (new entries to append).
        // For store, a delta is StoreStateV1Delta (composable).
        // For now, we re-GET the full state on update notification.
        // This is correct but inefficient -- proper delta application can be
        // added once the basic flow works end-to-end.
        self.on_contract_state(contract_id, update_bytes);
    }

    /// Handle a response from the harvest delegate.
    pub fn on_delegate_response(&mut self, response: HarvestDelegateResponse) {
        match response {
            HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                info!("RSA keys initialized for {}", ghostkey_fingerprint);
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint, rsa_public_key_der);
            }

            HarvestDelegateResponse::RsaPublicKey {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint, rsa_public_key_der);
            }

            HarvestDelegateResponse::StoreRegistered {
                ghostkey_fingerprint,
            } => {
                info!("Store registered for {}", ghostkey_fingerprint);
            }

            HarvestDelegateResponse::StoreList {
                ghostkey_fingerprint,
                stores,
            } => {
                self.my_stores.insert(ghostkey_fingerprint, stores);
            }

            HarvestDelegateResponse::Error { message } => {
                self.notifications
                    .push(format!("Delegate error: {message}"));
            }

            _ => {
                info!("Unhandled delegate response: {:?}", response);
            }
        }
    }

    /// Handle a response from the ghostkey delegate.
    pub fn on_ghostkey_response(&mut self, response: ghostkey_common::GhostkeyResponse) {
        match response {
            ghostkey_common::GhostkeyResponse::GhostKeyList { keys } => {
                info!("Received {} ghostkeys", keys.len());
                self.ghostkeys = keys;
            }

            ghostkey_common::GhostkeyResponse::Error { message } => {
                self.notifications
                    .push(format!("Ghostkey error: {message}"));
            }

            _ => {
                info!("Unhandled ghostkey response: {:?}", response);
            }
        }
    }
}
