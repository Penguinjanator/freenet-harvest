//! Application state managed via Dioxus GlobalSignal.
//!
//! Centralizes all reactive state so the response handler and UI components
//! can read/write from a single source of truth.

use dioxus::logger::tracing::{info, warn};
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

    /// The store the Browse tab shows. `browsing_stores` also holds
    /// placeholder entries -- one is created the moment a link is opened and
    /// before any state arrives, and another whenever reputation state turns
    /// up for a store we haven't loaded -- so "whichever entry the map
    /// iterates first" is not a safe answer to "which store is on screen".
    pub active_store_id: Option<Vec<u8>>,

    /// Why the store named by a link could not be opened, if it couldn't.
    /// Without this the Browse tab sits on "Loading store..." forever: a GET
    /// that fails after it left the client is only logged, and nothing in the
    /// response path can attribute the failure back to the link that caused
    /// it. bs58 has no checksum either, so a one-character typo in a store id
    /// usually still decodes to 32 valid-looking bytes and is dispatched as a
    /// GET for a contract that does not exist.
    pub store_link_error: Option<String>,

    /// Maps reputation contract IDs back to their store contract IDs,
    /// so reputation state can be matched to the right store.
    pub reputation_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Maps mailbox contract IDs back to their store contract IDs.
    pub mailbox_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Our own stores (ghostkey fingerprint -> list of registrations).
    pub my_stores: HashMap<String, Vec<StoreRegistration>>,

    /// Store contracts we have already asked the gateway for. Every
    /// `StoreList` answer names every store the ghostkey owns, and a
    /// ghostkey re-connecting in the same session produces another answer,
    /// so without this each repeat costs a fresh GET+subscribe per store --
    /// and each of those re-triggers the reputation follow-on GET too.
    pub subscribed_stores: HashSet<Vec<u8>>,

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

    /// Signature requests sent to the ghostkey delegate and not yet
    /// answered, oldest first.
    ///
    /// `SignResult` carries no correlation id, so arrival order is the only
    /// thing tying an answer to its request. A single field could not stay
    /// correct once two kinds of signature existed: publishing a store signs
    /// its info, and the seller can start a listing immediately afterwards,
    /// so both can be outstanding at once and the wrong one would consume the
    /// answer. A queue keeps them in the order they were asked for.
    pub pending_signatures: std::collections::VecDeque<PendingSignature>,

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

/// Something waiting on the ghostkey delegate's `SignResult`.
#[derive(Clone, Debug)]
pub enum PendingSignature {
    Listing(PendingListing),
    StoreInfo(PendingStoreInfo),
}

/// A store's own details, awaiting signature so they can be published.
///
/// `AuthorizedStoreInfoV1::verify` skips verification only at version 0, so
/// anything a buyer can actually read has to carry a real signature over the
/// ghostkey delegate's `ScopedPayload` -- the same round-trip a listing makes.
#[derive(Clone, Debug)]
pub struct PendingStoreInfo {
    pub info: StoreInfoV1,
    pub store_contract_id: Vec<u8>,
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

/// GET-and-subscribe a contract we learned about from a delegate
/// registration or from another contract's state. Failures are logged rather
/// than propagated: these are background refreshes, not user actions.
fn subscribe_in_background(what: &'static str, contract_id: Vec<u8>) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::get_contract_by_id(&contract_id).await {
            dioxus::logger::tracing::error!("Failed to subscribe to {what} contract: {e}");
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (what, contract_id);
}

impl AppState {
    /// Start browsing a store: prepare its state and make it the store the
    /// Browse tab shows. The caller is responsible for the GET/subscribe.
    pub fn begin_browsing(&mut self, store_contract_id: Vec<u8>) {
        self.browsing_stores
            .entry(store_contract_id.clone())
            .or_default();
        self.active_store_id = Some(store_contract_id);
        self.store_link_error = None;
    }

    /// Record that a store opened from a link could not be loaded, so the
    /// Browse tab can say so instead of showing "Loading store..." forever.
    ///
    /// Returns whether an error was recorded. Two things that look like
    /// failures aren't: a state that arrived while the timeout was still
    /// running, and a store the user has since navigated away from -- the
    /// message is shown for whichever store is active, so reporting a stale
    /// one would blame the wrong link.
    pub fn note_store_link_failed(&mut self, store_contract_id: &[u8], reason: &str) -> bool {
        if self.active_store_id.as_deref() != Some(store_contract_id) {
            return false;
        }
        if self
            .browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| store.info.is_some())
        {
            return false;
        }
        warn!("Store link could not be opened: {reason}");
        self.store_link_error = Some(reason.to_string());
        true
    }

    /// Fold the delegate's answer to `ListStores` into what we already know,
    /// rather than replacing it.
    ///
    /// The delegate's registry cannot round-trip everything a registration
    /// holds. `HarvestDelegateRequest::RegisterStore` has no field for the
    /// store's `ContractKey`, so the delegate stores `None` and every
    /// registration it hands back has `store_contract_key: None`. The key is
    /// recorded exactly once, locally, when the store is created
    /// (`gateway::store_ops::create_store`) -- and it is what
    /// `submit_listing_by_id` needs. Replacing wholesale therefore left the
    /// seller with a rendered "Add Listing" button that always failed with
    /// "store may not be fully created yet", for a store created weeks ago.
    ///
    /// The answer can also be missing a store outright: `RegisterStore` and
    /// `ListStores` can be in flight at the same time, so a store created
    /// moments ago may not be in the registry yet.
    ///
    /// Nothing in Harvest deletes a store, so a registration we already hold
    /// is never stale. The invariant is "never lose a locally-known
    /// registration"; the delegate's answer only adds, and only fills in
    /// fields we don't already have.
    pub fn merge_store_registrations(
        &mut self,
        ghostkey_fingerprint: &str,
        stores: Vec<StoreRegistration>,
    ) {
        // Don't create the entry for an answer that carries nothing. A
        // storeless seller would otherwise get an empty vec that says
        // "asked, owns none" and reads identically to "owns some" at every
        // `contains_key`, and the log would report keeping 0 stores.
        if stores.is_empty() {
            return;
        }

        let known = self
            .my_stores
            .entry(ghostkey_fingerprint.to_string())
            .or_default();

        for mut registration in stores {
            match known
                .iter_mut()
                .find(|s| s.store_contract_id == registration.store_contract_id)
            {
                Some(existing) => {
                    if registration.store_contract_key.is_none() {
                        registration.store_contract_key = existing.store_contract_key.take();
                    }
                    *existing = registration;
                }
                None => known.push(registration),
            }
        }
    }

    /// The store the Browse tab is showing.
    ///
    /// Prefer the store a link named; fall back to any store whose state has
    /// actually arrived. `browsing_stores` also holds placeholder entries --
    /// one is created the moment a link is opened, before any state arrives,
    /// and another whenever reputation state turns up for a store we haven't
    /// loaded -- so "whichever entry the map iterates first" picks
    /// arbitrarily among them and can show "no store" while a perfectly good
    /// one is loaded.
    ///
    /// Both `StoreView` and the document title resolve the shown store, and
    /// they answered differently until they shared this: the title took the
    /// map's first loaded entry, so with two stores open the page was titled
    /// after one the user was not looking at.
    pub fn displayed_store(&self) -> Option<(&Vec<u8>, &BrowsingStore)> {
        self.active_store_id
            .as_ref()
            .and_then(|id| self.browsing_stores.get_key_value(id))
            .filter(|(_, store)| store.info.is_some())
            .or_else(|| {
                self.browsing_stores
                    .iter()
                    .find(|(_, store)| store.info.is_some())
            })
    }

    /// Record that we have asked the gateway for a store contract. Returns
    /// `true` the first time, so the caller subscribes exactly once.
    pub fn note_store_subscribed(&mut self, store_contract_id: &[u8]) -> bool {
        self.subscribed_stores.insert(store_contract_id.to_vec())
    }

    /// Record which store a mailbox contract belongs to, and subscribe to the
    /// mailbox so its state actually arrives.
    ///
    /// `mailbox_to_store` is the only route from an incoming mailbox state
    /// back to the store it belongs to. It cannot be recovered from contract
    /// state: `StoreInfoV1` names the store's reputation contract but not its
    /// mailbox, so the mapping has to come from the delegate's
    /// `StoreRegistration` -- which means it only ever exists for our own
    /// stores, not for a store we are browsing as a buyer.
    ///
    /// A mailbox belongs to exactly one store, so a second store claiming one
    /// that is already mapped is a bug somewhere upstream. The first mapping
    /// is kept: re-pointing it would silently strand the first store's
    /// messages, since it would still show a `mailbox_contract_id` that
    /// nothing routes back to it any more.
    pub fn register_store_mailbox(&mut self, store_contract_id: &[u8], mailbox_contract_id: &[u8]) {
        if mailbox_contract_id.len() != 32 || mailbox_contract_id.iter().all(|&b| b == 0) {
            warn!("Store registration has no usable mailbox contract id -- not subscribing");
            return;
        }

        if let Some(owner) = self.mailbox_to_store.get(mailbox_contract_id) {
            if owner != store_contract_id {
                warn!(
                    "Mailbox {} is already registered to a different store -- keeping the \
                     first mapping and ignoring the second",
                    bs58::encode(mailbox_contract_id).into_string()
                );
                return;
            }
            // Already ours: every `StoreList` answer re-registers, and the
            // map doubles as the record of what we have already asked for.
            return;
        }

        self.browsing_stores
            .entry(store_contract_id.to_vec())
            .or_default()
            .mailbox_contract_id = Some(mailbox_contract_id.to_vec());
        self.mailbox_to_store
            .insert(mailbox_contract_id.to_vec(), store_contract_id.to_vec());
        subscribe_in_background("mailbox", mailbox_contract_id.to_vec());
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

            // A store the seller just created, or one they own, arrives
            // without anyone having followed a link. Show it, unless a link
            // has already named the store this tab is for.
            if self.active_store_id.is_none() {
                self.active_store_id = Some(contract_id.clone());
            }

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

            match self.mailbox_to_store.get(&contract_id).cloned() {
                Some(store_id) => match self.browsing_stores.get_mut(&store_id) {
                    Some(store) => store.mailbox_messages = mailbox_state.messages,
                    None => warn!(
                        "Mailbox {:?} maps to a store we have no state for -- dropping messages",
                        &contract_id[..8.min(contract_id.len())]
                    ),
                },
                // Only a store registered with the harvest delegate has a
                // known mailbox id, so this is expected for any mailbox we
                // subscribed to some other way -- but it means the messages
                // go nowhere, which is worth saying out loud rather than
                // falling off the end of the function silently.
                None => warn!(
                    "Mailbox state for {:?}, which belongs to no store we know -- dropping {} message(s)",
                    &contract_id[..8.min(contract_id.len())],
                    mailbox_state.messages.len()
                ),
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
                info!(
                    "Delegate reports {} store(s) for {}",
                    stores.len(),
                    ghostkey_fingerprint
                );
                self.merge_store_registrations(&ghostkey_fingerprint, stores);

                // Nothing else re-fetches these after a reload: the seller's
                // own store is subscribed at creation time and never again,
                // so without this the Browse tab is empty for the very seller
                // who owns the store.
                let registrations: Vec<(Vec<u8>, Vec<u8>)> = self
                    .my_stores
                    .get(&ghostkey_fingerprint)
                    .map(|stores| {
                        stores
                            .iter()
                            .map(|s| (s.store_contract_id.clone(), s.mailbox_contract_id.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                for (store_contract_id, mailbox_contract_id) in registrations {
                    if self.note_store_subscribed(&store_contract_id) {
                        subscribe_in_background("store", store_contract_id.clone());
                    }
                    self.register_store_mailbox(&store_contract_id, &mailbox_contract_id);
                }
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

                // Learning which identities we can act for is the first
                // moment we can ask the delegate what stores each of them
                // owns. We can't do this at startup: `ListStores` is
                // scoped to a fingerprint, and no fingerprint is known
                // until the vault shares one -- Harvest deliberately does
                // not call `ListGhostKeys` any more (see the comment in
                // `components::App`). Without this, `my_stores` stays
                // empty after every page reload and the seller is offered
                // "Create Store" for a store they already have.
                #[cfg(target_arch = "wasm32")]
                for fingerprint in keys.iter().map(|k| k.fingerprint.clone()) {
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(e) =
                            crate::gateway::store_ops::list_stores(fingerprint.clone()).await
                        {
                            dioxus::logger::tracing::error!(
                                "Failed to list stores for {fingerprint}: {e}"
                            );
                        }
                    });
                }
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
                match self.pending_signatures.pop_front() {
                    Some(PendingSignature::Listing(pending)) => {
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
                                if let Err(e) = crate::gateway::store_ops::submit_listing_by_id(
                                    &store_id, listing,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!(
                                        "Failed to submit listing: {}",
                                        e
                                    );
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!("Failed to submit listing: {e}"));
                                }
                            });
                        }

                        self.signed_listings_ready.push(authorized);
                    }
                    Some(PendingSignature::StoreInfo(pending)) => {
                        let authorized = harvest_common::store::AuthorizedStoreInfoV1 {
                            info: pending.info,
                            scoped_payload,
                            signature,
                        };
                        info!(
                            "Constructed AuthorizedStoreInfoV1: {}",
                            authorized.info.store_name
                        );

                        #[cfg(target_arch = "wasm32")]
                        {
                            let store_id = pending.store_contract_id;
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::submit_store_info_by_id(
                                    &store_id, authorized,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!(
                                        "Failed to publish store details: {}",
                                        e
                                    );
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!(
                                        "Store created, but its name and description could not \
                                         be published: {e}"
                                    ));
                                }
                            });
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        let _ = authorized;
                    }
                    None => {
                        warn!("SignResult received with nothing waiting for a signature");
                    }
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
                self.pending_signatures.clear();
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
                self.pending_signatures.clear();
                self.pending_store_creation = None;
            }

            // The vault has no ghostkeys at all. Tell the user where
            // to go to create one. Same cleanup as AccessDenied.
            ghostkey_common::GhostkeyResponse::NoIdentityAvailable => {
                self.notifications.push(
                    "No ghostkey identities found. Open the Ghostkey Vault to create one, then come back and click 'Connect a ghostkey'.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
            }

            // Per-fingerprint denial: the user denied a specific-key
            // prompt, or the vault revoked the grant between connect
            // and sign. Same cleanup as the access-denial arms.
            ghostkey_common::GhostkeyResponse::PermissionDenied { fingerprint, .. } => {
                self.notifications
                    .push(format!("Ghostkey access denied for {fingerprint}."));
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "fp-1";

    fn registration(id: u8, key: Option<Vec<u8>>) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: vec![id.wrapping_add(1); 32],
            mailbox_contract_id: vec![id.wrapping_add(2); 32],
            store_contract_key: key,
        }
    }

    fn store_list(stores: Vec<StoreRegistration>) -> HarvestDelegateResponse {
        HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores,
        }
    }

    /// The delegate cannot store a store's `ContractKey` -- `RegisterStore`
    /// has no field for it -- so every registration it hands back is keyless.
    /// Losing the key breaks "Add Listing" for a store that exists, which is
    /// what a wholesale replace did. See `merge_store_registrations`.
    #[test]
    fn a_store_list_answer_keeps_a_locally_known_contract_key() {
        let key = vec![0xAB; 40];
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, Some(key.clone()))]);

        state.on_delegate_response(store_list(vec![registration(1, None)]));

        let stores = &state.my_stores[FINGERPRINT];
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].store_contract_key, Some(key));
    }

    /// `RegisterStore` and `ListStores` can be in flight at once, so a store
    /// created moments ago need not be in the answer at all.
    #[test]
    fn a_store_list_answer_never_drops_a_store_it_does_not_name() {
        let key = vec![0xCD; 40];
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, Some(key.clone()))]);

        state.on_delegate_response(store_list(vec![]));
        state.on_delegate_response(store_list(vec![registration(2, None)]));

        let stores = &state.my_stores[FINGERPRINT];
        assert_eq!(stores.len(), 2);
        let kept = stores
            .iter()
            .find(|s| s.store_contract_id == vec![1u8; 32])
            .expect("the locally-known store should survive");
        assert_eq!(kept.store_contract_key, Some(key));
    }

    /// An answer with nothing in it must not leave an empty vec behind: a
    /// seller who owns no store would otherwise be recorded as having an
    /// entry, which reads the same as owning one at every `contains_key`.
    #[test]
    fn an_empty_answer_records_nothing_for_a_storeless_seller() {
        let mut state = AppState::default();
        state.on_delegate_response(store_list(vec![]));

        assert!(!state.my_stores.contains_key(FINGERPRINT));
    }

    /// A registration the delegate knows about but we don't is added, key and
    /// all -- the merge is not "ignore the delegate".
    #[test]
    fn a_store_list_answer_adds_stores_we_did_not_know_about() {
        let mut state = AppState::default();
        state.on_delegate_response(store_list(vec![registration(7, None)]));

        assert_eq!(state.my_stores[FINGERPRINT].len(), 1);
        assert_eq!(
            state.my_stores[FINGERPRINT][0].store_contract_id,
            vec![7u8; 32]
        );
    }

    fn loaded_store(name: &str) -> BrowsingStore {
        BrowsingStore {
            info: Some(StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: FINGERPRINT.to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: name.to_string(),
                description: String::new(),
                payment_instructions: String::new(),
            }),
            ..Default::default()
        }
    }

    /// With several stores loaded, the shown store is the active one -- not
    /// whichever the HashMap iterates first. Both `StoreView` and the
    /// document title depend on this answer.
    #[test]
    fn the_displayed_store_is_the_active_one() {
        let mut state = AppState::default();
        for byte in 1..=8u8 {
            state
                .browsing_stores
                .insert(vec![byte; 32], loaded_store(&format!("store {byte}")));
        }
        state.active_store_id = Some(vec![5u8; 32]);

        let (id, store) = state.displayed_store().expect("a store is loaded");
        assert_eq!(id, &vec![5u8; 32]);
        assert_eq!(store.info.as_ref().unwrap().store_name, "store 5");
    }

    /// A placeholder entry -- created the moment a link is opened -- is not a
    /// loaded store, and must not shadow one that is.
    #[test]
    fn a_placeholder_active_store_falls_back_to_a_loaded_one() {
        let mut state = AppState::default();
        state
            .browsing_stores
            .insert(vec![1u8; 32], loaded_store("loaded"));
        state.begin_browsing(vec![2u8; 32]);

        let (id, _) = state.displayed_store().expect("the loaded store");
        assert_eq!(id, &vec![1u8; 32]);
    }

    #[test]
    fn no_loaded_store_displays_nothing() {
        let mut state = AppState::default();
        state.begin_browsing(vec![2u8; 32]);
        assert!(state.displayed_store().is_none());
    }

    fn sign_result() -> ghostkey_common::GhostkeyResponse {
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            certificate_pem: String::new(),
        }
    }

    fn pending_listing() -> PendingSignature {
        PendingSignature::Listing(PendingListing {
            fingerprint: FINGERPRINT.to_string(),
            listing: harvest_common::listing::Listing {
                id: harvest_common::listing::ListingId([1u8; 16]),
                title: "Beans".to_string(),
                description: String::new(),
                kind: harvest_common::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::Utc::now(),
            },
            store_contract_id: None,
        })
    }

    fn pending_store_info() -> PendingSignature {
        PendingSignature::StoreInfo(PendingStoreInfo {
            info: loaded_store("Bean Shop").info.expect("info"),
            store_contract_id: vec![1u8; 32],
        })
    }

    /// `SignResult` carries no correlation id, so the queue's order is the
    /// only thing matching an answer to its request. A store's info and a
    /// listing can be outstanding at the same time -- publishing a store
    /// signs its info, and the seller can start a listing right after -- and
    /// answering them out of order would attach the store's signature to the
    /// listing.
    #[test]
    fn signatures_are_answered_in_the_order_they_were_asked_for() {
        let mut state = AppState::default();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(pending_listing());

        // First answer belongs to the store info, not the listing.
        state.on_ghostkey_response(sign_result());
        assert!(
            state.signed_listings_ready.is_empty(),
            "the listing must not have consumed the store info's signature"
        );
        assert_eq!(state.pending_signatures.len(), 1);

        // Second answer is the listing's.
        state.on_ghostkey_response(sign_result());
        assert_eq!(state.signed_listings_ready.len(), 1);
        assert_eq!(state.signed_listings_ready[0].listing.title, "Beans");
        assert!(state.pending_signatures.is_empty());
    }

    /// An answer with nothing queued must be dropped, not applied to
    /// whatever is queued next.
    #[test]
    fn a_signature_with_nothing_waiting_is_dropped() {
        let mut state = AppState::default();
        state.on_ghostkey_response(sign_result());
        assert!(state.signed_listings_ready.is_empty());
    }

    /// A delegate error or a denied prompt invalidates everything queued --
    /// none of it will ever be answered, and a leftover entry would consume
    /// the next unrelated signature.
    #[test]
    fn a_denied_prompt_clears_the_whole_queue() {
        let mut state = AppState::default();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(pending_listing());

        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::Error {
            message: "nope".to_string(),
        });
        assert!(state.pending_signatures.is_empty());
    }

    /// A mailbox belongs to one store. Re-pointing the map at a second one
    /// would leave the first store showing a `mailbox_contract_id` that
    /// nothing routes back to it, so its messages would vanish on arrival.
    #[test]
    fn a_mailbox_stays_with_the_first_store_that_claimed_it() {
        let mut state = AppState::default();
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);
        state.register_store_mailbox(&[2u8; 32], &[9u8; 32]);

        assert_eq!(state.mailbox_to_store[&vec![9u8; 32]], vec![1u8; 32]);
        assert_eq!(
            state.browsing_stores[&vec![1u8; 32]].mailbox_contract_id,
            Some(vec![9u8; 32])
        );
        assert!(
            !state.browsing_stores.contains_key(&vec![2u8; 32]),
            "the losing store must not be left pointing at a mailbox it does not own"
        );
    }

    /// Re-registering the same pair is the normal case -- every `StoreList`
    /// answer does it -- and must not be reported as a collision.
    #[test]
    fn re_registering_the_same_mailbox_is_not_a_collision() {
        let mut state = AppState::default();
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);

        assert_eq!(state.mailbox_to_store[&vec![9u8; 32]], vec![1u8; 32]);
        assert_eq!(state.mailbox_to_store.len(), 1);
    }

    /// A link whose store never arrives has to end in a message, not in
    /// "Loading store..." forever. See `note_store_link_failed`.
    #[test]
    fn a_store_that_never_arrives_becomes_an_error() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        assert_eq!(state.store_link_error, None);

        assert!(state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error.as_deref(), Some("didn't load"));
    }

    /// A store whose state arrived while the timeout was still running is not
    /// a failure, and must not be reported as one.
    #[test]
    fn a_store_that_did_arrive_is_not_reported_as_failed() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state
            .browsing_stores
            .get_mut(&vec![9u8; 32])
            .expect("begin_browsing creates the entry")
            .info = Some(StoreInfoV1 {
            version: 1,
            certificate_pem: String::new(),
            seller_fingerprint: FINGERPRINT.to_string(),
            reputation_contract_id: [0u8; 32],
            store_name: "Loaded".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
        });

        assert!(!state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error, None);
    }

    /// Opening another link clears the previous failure, or the error from a
    /// dead link outlives it.
    #[test]
    fn opening_another_link_clears_a_previous_error() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state.note_store_link_failed(&[9u8; 32], "didn't load");
        state.begin_browsing(vec![10u8; 32]);
        assert_eq!(state.store_link_error, None);
    }

    /// A timeout that fires for a store the user has already navigated away
    /// from must not blame the link they are looking at now.
    #[test]
    fn a_timeout_for_an_abandoned_store_is_ignored() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state.begin_browsing(vec![10u8; 32]);

        assert!(!state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error, None);
    }

    /// Every `StoreList` answer names every store, and a ghostkey
    /// reconnecting produces another answer, so the GET+subscribe has to be
    /// deduped the way `register_store_mailbox` already dedupes its own.
    #[test]
    fn a_store_is_only_subscribed_once() {
        let mut state = AppState::default();
        assert!(state.note_store_subscribed(&[1u8; 32]));
        assert!(!state.note_store_subscribed(&[1u8; 32]));
        assert!(state.note_store_subscribed(&[2u8; 32]));

        state.on_delegate_response(store_list(vec![registration(3, None)]));
        state.on_delegate_response(store_list(vec![registration(3, None)]));
        assert_eq!(state.subscribed_stores.len(), 3);
    }
}
