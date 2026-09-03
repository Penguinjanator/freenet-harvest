//! Application state managed via Dioxus GlobalSignal.
//!
//! Centralizes all reactive state so the response handler and UI components
//! can read/write from a single source of truth.

use dioxus::logger::tracing::info;
use harvest_common::listing::AuthorizedListing;
use harvest_common::mailbox::EncryptedMessage;
use harvest_common::payment::AuthorizedOrder;
use harvest_common::reputation::FeedbackEntry;
use harvest_common::store::StoreInfoV1;
use harvest_common::{
    BitcoinDelegateResponse, BridgeEndpoint, HarvestDelegateResponse, StoreRegistration,
    WatchedPayment,
};
use std::collections::{HashMap, HashSet};

use freenet_bitcoin_common::BitcoinNetwork;

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

    /// Ghostkey identities available to us. Each successful
    /// `RequestAnyAccess` response merges (deduped by fingerprint) into
    /// this list rather than replacing it, so users can connect a
    /// second key without losing visibility into the first.
    pub ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,

    /// Set while a `RequestAnyAccess` is in flight, so the UI can
    /// disable the "Connect" button and rapid double-clicks don't queue
    /// multiple delegate prompts. Cleared on every terminal response
    /// (GhostKeyList success, AccessDenied, NoIdentityAvailable, Error).
    pub request_any_access_in_flight: bool,

    /// RSA public keys for our identities (fingerprint -> DER bytes).
    pub rsa_public_keys: HashMap<String, Vec<u8>>,

    /// Store creation pending RSA key response. When InitReputationKeys
    /// is sent, the store details are stored here. When ReputationKeysInitialized
    /// arrives, the response handler picks this up and creates the contracts.
    pub pending_store_creation: Option<PendingStoreCreation>,

    /// A listing that's been submitted for signing and is waiting for
    /// the ghostkey delegate's SignResult response.
    pub pending_listing: Option<PendingListing>,

    /// Signed listings ready to be submitted to the store contract.
    /// The UI should pick these up and send them as contract updates.
    pub signed_listings_ready: Vec<AuthorizedListing>,

    /// Pending messages/events for the UI to display.
    pub notifications: Vec<String>,

    /// Bitcoin/Payments state: bridge config, private watch list, and live
    /// on-chain data mirrored from subscribed Bitcoin contracts.
    pub bitcoin: BitcoinState,
}

/// Details for a store being created, waiting for RSA key generation.
#[derive(Clone, Debug)]
pub struct PendingStoreCreation {
    pub ghostkey_fingerprint: String,
    pub seller_verifying_key_bytes: [u8; 32],
    pub certificate_pem: String,
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
}

/// A listing awaiting signature from the ghostkey delegate.
#[derive(Clone, Debug)]
pub struct PendingListing {
    pub fingerprint: String,
    pub listing: harvest_common::listing::Listing,
    /// Store contract ID to submit the signed listing to.
    pub store_contract_id: Option<Vec<u8>>,
}

/// State for a store we're browsing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BrowsingStore {
    pub info: Option<StoreInfoV1>,
    pub listings: Vec<AuthorizedListing>,
    /// Orders placed against this store (buyer or seller side -- the store
    /// contract carries both). Payments-first UI groups these by status.
    pub orders: Vec<AuthorizedOrder>,
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

        // Try Bitcoin tip / address contracts first. Which one a contract id
        // names is decided when we start subscribing to it (see
        // `register_tip_contract` / `register_watch_contract`), not by
        // guessing from the bytes -- a tip and an address state are both
        // small single-field composables and could in principle both fail
        // to deserialize as each other only by luck of field naming.
        if let Some(&network) = self.bitcoin.tip_contract_network.get(&contract_id) {
            if let Ok(tip_state) = freenet_bitcoin_common::from_cbor::<
                freenet_bitcoin_common::BitcoinTipStateV1,
            >(&state_bytes)
            {
                self.apply_tip_state(network, &tip_state);
                return;
            }
        }
        if let Some(&network) = self.bitcoin.address_contract_network.get(&contract_id) {
            if let Ok(addr_state) = freenet_bitcoin_common::from_cbor::<
                freenet_bitcoin_common::BitcoinAddressStateV1,
            >(&state_bytes)
            {
                self.apply_address_state(contract_id, network, &addr_state);
                return;
            }
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
            store.orders = store_state.orders.orders.into_values().collect();
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

    /// Handle a response from the harvest delegate.
    pub fn on_delegate_response(&mut self, response: HarvestDelegateResponse) {
        match response {
            HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                info!("RSA keys initialized for {}", ghostkey_fingerprint);
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint.clone(), rsa_public_key_der.clone());

                // If we have a pending store creation for this fingerprint,
                // trigger the contract creation flow
                if let Some(pending) = self.pending_store_creation.take() {
                    if pending.ghostkey_fingerprint == ghostkey_fingerprint {
                        #[cfg(target_arch = "wasm32")]
                        {
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::create_store_contracts(
                                    pending.ghostkey_fingerprint,
                                    pending.seller_verifying_key_bytes,
                                    rsa_public_key_der,
                                    pending.certificate_pem,
                                    pending.store_name,
                                    pending.description,
                                    pending.payment_instructions,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!("Store creation failed: {}", e);
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!("Store creation failed: {e}"));
                                }
                            });
                        }
                    } else {
                        // Wrong fingerprint -- put it back
                        self.pending_store_creation = Some(pending);
                    }
                }
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
                // If any ghostkey has verifying_key_bytes and we have a pending
                // store creation for it, fill in the key
                for key in &keys {
                    if let Some(ref vk_bytes) = key.verifying_key_bytes {
                        if let Some(ref mut pending) = self.pending_store_creation {
                            if pending.ghostkey_fingerprint == key.fingerprint
                                && pending.seller_verifying_key_bytes == [0u8; 32]
                                && vk_bytes.len() == 32
                            {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(vk_bytes);
                                pending.seller_verifying_key_bytes = arr;
                                info!(
                                    "Filled verifying key for pending store creation: {}",
                                    key.fingerprint
                                );
                            }
                        }
                    }
                }
                // Merge new keys into the existing list (dedup by
                // fingerprint, prefer the newer entry). Wholesale
                // replacement would drop previously-connected keys
                // when a second `RequestAnyAccess` returns a single
                // newly-shared key.
                for key in keys {
                    if let Some(slot) = self
                        .ghostkeys
                        .iter_mut()
                        .find(|k| k.fingerprint == key.fingerprint)
                    {
                        *slot = key;
                    } else {
                        self.ghostkeys.push(key);
                    }
                }
                self.request_any_access_in_flight = false;
            }

            ghostkey_common::GhostkeyResponse::SignResult {
                scoped_payload,
                signature,
                certificate_pem,
            } => {
                info!("Received signature from ghostkey delegate");
                if let Some(pending) = self.pending_listing.take() {
                    let authorized = AuthorizedListing {
                        listing: pending.listing,
                        scoped_payload,
                        signature,
                        certificate_pem,
                    };
                    info!(
                        "Constructed AuthorizedListing: {}",
                        authorized.listing.title
                    );

                    // Submit to the store contract if we know which one
                    #[cfg(target_arch = "wasm32")]
                    if let Some(store_id) = pending.store_contract_id {
                        let listing = authorized.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Err(e) =
                                crate::gateway::store_ops::submit_listing_by_id(&store_id, listing)
                                    .await
                            {
                                dioxus::logger::tracing::error!("Failed to submit listing: {}", e);
                                crate::gateway::APP_STATE
                                    .write()
                                    .notifications
                                    .push(format!("Failed to submit listing: {e}"));
                            }
                        });
                    }

                    self.signed_listings_ready.push(authorized);
                } else {
                    info!("SignResult received but no pending listing");
                }
            }

            ghostkey_common::GhostkeyResponse::Certificate {
                fingerprint,
                certificate_pem,
            } => {
                info!("Received certificate for {}", fingerprint);
                // If we have a pending store creation for this fingerprint,
                // fill in the certificate PEM. The verifying key is extracted
                // by the store creation code from the certificate at contract
                // creation time.
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                        info!("Updated pending store creation with certificate");
                    }
                }
            }

            ghostkey_common::GhostkeyResponse::GhostKeyDetail {
                fingerprint,
                certificate_pem,
                ..
            } => {
                info!("Received ghostkey detail for {}", fingerprint);
                // Also update pending store creation if applicable
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                    }
                }
            }

            ghostkey_common::GhostkeyResponse::Error { message } => {
                self.notifications
                    .push(format!("Ghostkey error: {message}"));
                self.pending_listing = None;
                self.request_any_access_in_flight = false;
            }

            // The user denied a `RequestAnyAccess` prompt. Surface a
            // notification, clear the in-flight flag so the button is
            // enabled again, and clear any pending listing/store
            // creation that was waiting on this grant. Without this
            // cleanup, a subsequent successful SignResult would
            // consume the stale pending listing.
            ghostkey_common::GhostkeyResponse::AccessDenied { .. } => {
                self.notifications.push(
                    "Ghostkey access was denied. Click 'Connect a ghostkey' again to retry.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // The vault has no ghostkeys at all. Tell the user where
            // to go to create one. Same cleanup as AccessDenied.
            ghostkey_common::GhostkeyResponse::NoIdentityAvailable => {
                self.notifications.push(
                    "No ghostkey identities found. Open the Ghostkey Vault to create one, then come back and click 'Connect a ghostkey'.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // Per-fingerprint denial: the user denied a specific-key
            // prompt, or the vault revoked the grant between connect
            // and sign. Same cleanup as the access-denial arms.
            ghostkey_common::GhostkeyResponse::PermissionDenied { fingerprint, .. } => {
                self.notifications
                    .push(format!("Ghostkey access denied for {fingerprint}."));
                self.request_any_access_in_flight = false;
                self.pending_listing = None;
                self.pending_store_creation = None;
            }

            // Vault-only responses Harvest doesn't act on. The
            // explicit arms above cover every user-visible failure
            // mode in the current ghostkey-common protocol; this
            // wildcard is just for vault-management responses
            // (PermissionGranted / PermissionRevoked / PermissionList /
            // KeyNotFound / VerifyResult / Deleted / LabelSet, etc).
            // A future response variant with a failure semantic
            // would slip through here -- worth re-auditing on every
            // ghostkey-common bump.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                info!("Unhandled ghostkey response: {:?}", response);
            }
        }
    }

    /// Handle a response from the Bitcoin surface of the harvest delegate.
    pub fn on_bitcoin_delegate_response(&mut self, response: BitcoinDelegateResponse) {
        match response {
            BitcoinDelegateResponse::Watched { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(watch) => self.upsert_watch(watch),
                    Err(e) => self.notifications.push(format!(
                        "Couldn't watch address: {}",
                        friendly_bridge_error(&e)
                    )),
                }
            }

            BitcoinDelegateResponse::Unwatched { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                if let Err(e) = result {
                    self.notifications.push(format!(
                        "Couldn't stop watching: {}",
                        friendly_bridge_error(&e)
                    ));
                }
                // The delegate is authoritative on the watch list; refresh
                // from it rather than guessing locally which row to drop,
                // so a partial failure never leaves the UI out of sync.
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = crate::gateway::bitcoin_ops::list_watched().await {
                        dioxus::logger::tracing::error!("Failed to refresh watch list: {e}");
                    }
                });
            }

            BitcoinDelegateResponse::WatchList { watches } => {
                for w in &watches {
                    self.register_watch_contract(w);
                }
                self.bitcoin.watches = watches;
                self.bitcoin.watches_loaded = true;
            }

            BitcoinDelegateResponse::OrderAssociated { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                if let Err(e) = result {
                    self.notifications
                        .push(format!("Couldn't link payment to order: {e}"));
                }
            }

            BitcoinDelegateResponse::BridgeConfigured { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(()) => {
                        #[cfg(target_arch = "wasm32")]
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Err(e) = crate::gateway::bitcoin_ops::get_bridge().await {
                                dioxus::logger::tracing::error!(
                                    "Failed to refresh bridge config: {e}"
                                );
                            }
                        });
                    }
                    Err(e) => self
                        .notifications
                        .push(format!("Couldn't configure bridge: {e}")),
                }
            }

            BitcoinDelegateResponse::Bridge { endpoint } => {
                self.bitcoin.bridge_loaded = true;
                self.bitcoin.bridge = endpoint.clone();
                if let Some(ep) = endpoint {
                    // Covers the (currently hypothetical) case of a
                    // well-known/pinned deployment -- see
                    // `gateway::bitcoin_config`.
                    self.register_tip_contract(ep.network);
                    // The real discovery path today: ask the bridge itself
                    // over plain HTTP, which the delegate cannot do on our
                    // behalf (no outbound-HTTP host function exists for
                    // delegates). See `gateway::bitcoin_bridge_http`.
                    #[cfg(target_arch = "wasm32")]
                    {
                        let url = ep.url.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            crate::gateway::bitcoin_bridge_http::refresh_bridge_status(url).await;
                        });
                    }
                } else {
                    // No bridge configured yet -- true first run. Try the
                    // default, which is the user's OWN machine.
                    //
                    // This is what makes the first-run panel show live Bitcoin
                    // data with no credential and no configuration, for anyone
                    // running their own bridge. If none is running the fetch
                    // fails and the panel keeps saying no bridge is
                    // configured, which is the honest outcome; it never
                    // invents data.
                    #[cfg(target_arch = "wasm32")]
                    {
                        let url = crate::gateway::bitcoin_config::default_bridge_url().to_string();
                        wasm_bindgen_futures::spawn_local(async move {
                            crate::gateway::bitcoin_bridge_http::refresh_bridge_status(url).await;
                        });
                    }
                }
            }

            // `BitcoinDelegateRequest`/`Response` are `#[non_exhaustive]` in
            // harvest-common, so a future variant lands here silently rather
            // than failing to build. Worth re-auditing on every bump.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                info!("Unhandled bitcoin delegate response: {:?}", response);
            }
        }
    }

    /// Fold a chain-tip contract's state into the live view for `network`.
    fn apply_tip_state(
        &mut self,
        network: BitcoinNetwork,
        state: &freenet_bitcoin_common::BitcoinTipStateV1,
    ) {
        let recent = state.blocks.recent(8);
        let last_block_time = recent.first().map(|b| b.block_time);
        let view = self.bitcoin.tips.entry(network).or_insert_with(|| TipView {
            network,
            tip_height: None,
            last_block_time: None,
            recent_blocks: Vec::new(),
        });
        view.tip_height = state.tip_height();
        view.last_block_time = last_block_time;
        view.recent_blocks = recent
            .into_iter()
            .map(|b| BlockRow {
                height: b.anchor.height,
                tx_count: b.tx_count,
                block_time: b.block_time,
            })
            .collect();
    }

    /// Fold an address contract's state into the live view for that watch.
    fn apply_address_state(
        &mut self,
        contract_id: Vec<u8>,
        network: BitcoinNetwork,
        state: &freenet_bitcoin_common::BitcoinAddressStateV1,
    ) {
        // `min_confirmations = 1`: this is the generic watch-list view, not
        // an order-specific check, so "confirmed" here means "on chain at
        // all" rather than meeting any particular order's threshold. Orders
        // apply their own `required_confirmations` via `verify_payment_proof`
        // when a payment is actually being proven.
        let tip_height = self
            .bitcoin
            .tips
            .get(&network)
            .and_then(|t| t.tip_height)
            .unwrap_or(0);
        let confirmed_sats = state.claims.confirmed_value_sats(tip_height, 1);
        let pending_sats = state.claims.pending_value_sats(tip_height, 1);

        let mut txs: Vec<TxRow> = state
            .claims
            .outpoint_statuses()
            .into_iter()
            .map(|(op, status)| {
                let (value_sats, row_status) = match status {
                    freenet_bitcoin_common::OutpointStatus::Unconfirmed { value_sats } => {
                        (value_sats, TxRowStatus::Unconfirmed)
                    }
                    freenet_bitcoin_common::OutpointStatus::Confirmed { value_sats, anchor } => (
                        value_sats,
                        TxRowStatus::Confirmed {
                            anchor_height: anchor.height,
                        },
                    ),
                    freenet_bitcoin_common::OutpointStatus::Retracted => {
                        (0, TxRowStatus::Retracted)
                    }
                };
                TxRow {
                    // Reversed (big-endian) byte order -- the form block
                    // explorers and wallets display, not Bitcoin's internal
                    // little-endian order.
                    txid_display: op.txid.to_display_string(),
                    value_sats,
                    status: row_status,
                }
            })
            .collect();
        // Newest first: unconfirmed, then confirmed by descending height,
        // then retracted last.
        txs.sort_by_key(|t| std::cmp::Reverse(tx_sort_rank(&t.status)));

        let view = self
            .bitcoin
            .addresses
            .entry(contract_id)
            .or_insert_with(|| AddressView {
                network,
                scanned_to: None,
                confirmed_sats: 0,
                pending_sats: 0,
                txs: Vec::new(),
            });
        view.network = network;
        view.scanned_to = state.scanned_to();
        view.confirmed_sats = confirmed_sats;
        view.pending_sats = pending_sats;
        view.txs = txs;
    }

    /// Note that `watch` names an address contract, recording the network it
    /// belongs to and subscribing to it if we haven't already.
    fn register_watch_contract(&mut self, watch: &WatchedPayment) {
        let Some(contract_id_bs58) = watch.contract_id.as_deref() else {
            return;
        };
        let Ok(bytes) = bs58::decode(contract_id_bs58).into_vec() else {
            return;
        };
        if bytes.len() != 32 {
            return;
        }
        self.bitcoin
            .address_contract_network
            .insert(bytes.clone(), watch.network);
        if self.bitcoin.subscribed.insert(bytes.clone()) {
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::bitcoin_ops::subscribe_contract(&bytes).await {
                    dioxus::logger::tracing::error!("Failed to subscribe address contract: {e}");
                }
            });
        }
    }

    /// Insert or replace a watch by its stable key, and ensure we're
    /// subscribed to its address contract.
    fn upsert_watch(&mut self, watch: WatchedPayment) {
        self.register_watch_contract(&watch);
        match self
            .bitcoin
            .watches
            .iter_mut()
            .find(|w| w.key() == watch.key())
        {
            Some(existing) => *existing = watch,
            None => self.bitcoin.watches.push(watch),
        }
    }

    /// Ensure the given network's chain-tip contract is subscribed, if we
    /// know its contract id from a well-known/pinned deployment. See
    /// `crate::gateway::bitcoin_config` for where that id would come from --
    /// there is no such deployment today, so this is a no-op. The real
    /// discovery path is `register_tip_contract_with_id`, driven by the
    /// bridge's own `/v1/status` self-report (see
    /// `gateway::bitcoin_bridge_http::refresh_bridge_status`).
    pub fn register_tip_contract(&mut self, network: BitcoinNetwork) {
        let Some(id_bs58) = crate::gateway::bitcoin_config::well_known_tip_contract_id(network)
        else {
            return;
        };
        self.register_tip_contract_with_id(network, id_bs58);
    }

    /// Register a network's chain-tip contract id, from wherever it was
    /// discovered, and subscribe to it if we haven't already.
    pub fn register_tip_contract_with_id(&mut self, network: BitcoinNetwork, id_bs58: &str) {
        let Ok(bytes) = bs58::decode(id_bs58).into_vec() else {
            dioxus::logger::tracing::warn!(
                "Bridge reported a tip contract id that isn't valid bs58: {id_bs58}"
            );
            return;
        };
        if bytes.len() != 32 {
            dioxus::logger::tracing::warn!(
                "Bridge reported a tip contract id that isn't 32 bytes: {id_bs58}"
            );
            return;
        }
        self.bitcoin
            .tip_contract_network
            .insert(bytes.clone(), network);
        self.bitcoin.tips.entry(network).or_insert_with(|| TipView {
            network,
            tip_height: None,
            last_block_time: None,
            recent_blocks: Vec::new(),
        });
        if self.bitcoin.subscribed.insert(bytes.clone()) {
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::bitcoin_ops::subscribe_contract(&bytes).await {
                    dioxus::logger::tracing::error!("Failed to subscribe tip contract: {e}");
                }
            });
        }
    }
}

/// Ordering key for a transaction row: unconfirmed first, then confirmed by
/// descending anchor height, then retracted last.
fn tx_sort_rank(status: &TxRowStatus) -> (u8, u32) {
    match status {
        TxRowStatus::Unconfirmed => (2, u32::MAX),
        TxRowStatus::Confirmed { anchor_height } => (1, *anchor_height),
        TxRowStatus::Retracted => (0, 0),
    }
}

/// Map a raw bridge/delegate error string to something a user can act on.
/// The delegate's errors are `String`s meant for logs (see
/// `BitcoinDelegateResponse::Watched`'s `Result<_, String>`), not a typed
/// error channel, so this is a best-effort keyword match rather than an
/// exhaustive mapping.
pub fn friendly_bridge_error(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("ghost key") || lower.contains("ghostkey") || lower.contains("not authorized")
    {
        "This bridge is only available to Ghost Key holders. Connect a Ghost Key and try again."
            .to_string()
    } else if lower.contains("rate limit") {
        "The bridge is rate-limiting requests right now -- try again shortly.".to_string()
    } else if lower.contains("unsupported network") {
        "This bridge doesn't support that Bitcoin network.".to_string()
    } else if lower.contains("not synced") || lower.contains("still syncing") {
        "The bridge is still syncing with the Bitcoin chain -- try again shortly.".to_string()
    } else {
        raw.to_string()
    }
}

/// Bitcoin/Payments state: bridge config, the user's private watch list, and
/// live on-chain data mirrored from subscribed Bitcoin contracts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BitcoinState {
    /// The bridge the harvest delegate is configured to use, if any.
    pub bridge: Option<BridgeEndpoint>,
    /// Whether we've heard back from `GetBridge` at least once -- lets the
    /// UI distinguish "still loading" from "no bridge configured".
    pub bridge_loaded: bool,
    /// The user's private watch list, as reported by the delegate.
    pub watches: Vec<WatchedPayment>,
    pub watches_loaded: bool,
    /// Bitcoin delegate request ids awaiting a response, so a specific
    /// button can show "watching..." rather than a global spinner.
    pub in_flight: HashSet<u64>,
    pub next_request_id: u64,
    /// Per-network live chain tip, once that network's tip contract is
    /// subscribed.
    pub tips: HashMap<BitcoinNetwork, TipView>,
    /// Per-contract-id live address view (claims folded into balances/txs),
    /// keyed by the address contract's instance id bytes.
    pub addresses: HashMap<Vec<u8>, AddressView>,
    /// Contract instance ids (tip and address) we've already issued a
    /// GET+subscribe for, so state churn doesn't resubscribe repeatedly.
    pub subscribed: HashSet<Vec<u8>>,
    /// Tip contract id -> network, so an incoming state/update routes to
    /// the right `TipView` without guessing from the bytes.
    pub tip_contract_network: HashMap<Vec<u8>, BitcoinNetwork>,
    /// Address contract id -> network, same purpose for `AddressView`.
    pub address_contract_network: HashMap<Vec<u8>, BitcoinNetwork>,
}

impl BitcoinState {
    /// Allocate the next request id for a `BitcoinDelegateRequest`.
    pub fn next_request_id(&mut self) -> u64 {
        self.next_request_id += 1;
        self.next_request_id
    }
}

/// Live view of one network's chain tip, mirrored from its
/// `BitcoinTipContract`.
#[derive(Clone, Debug, PartialEq)]
pub struct TipView {
    pub network: BitcoinNetwork,
    pub tip_height: Option<u32>,
    /// Header timestamp (Bitcoin's clock) of the most recent block. Display
    /// only -- e.g. "X minutes ago" computed against the browser's own
    /// clock, never trusted as authoritative.
    pub last_block_time: Option<u32>,
    /// Newest first.
    pub recent_blocks: Vec<BlockRow>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockRow {
    pub height: u32,
    pub tx_count: u32,
    pub block_time: u32,
}

/// Live view of one watched address, mirrored from its
/// `BitcoinAddressContract`.
#[derive(Clone, Debug, PartialEq)]
pub struct AddressView {
    pub network: BitcoinNetwork,
    /// The highest height any trusted bridge has scanned this script to.
    /// `None` means "not synchronized yet", distinct from "no activity".
    pub scanned_to: Option<u32>,
    pub confirmed_sats: u64,
    pub pending_sats: u64,
    /// Newest first (see `tx_sort_rank`).
    pub txs: Vec<TxRow>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TxRow {
    pub txid_display: String,
    pub value_sats: u64,
    pub status: TxRowStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TxRowStatus {
    Unconfirmed,
    Confirmed { anchor_height: u32 },
    Retracted,
}
