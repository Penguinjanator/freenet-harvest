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

    /// Ghostkey certificates by fingerprint, as the delegate reports them.
    ///
    /// A store's details carry the seller's certificate so a buyer can check
    /// the trust chain, and the certificate has to be inside the record
    /// *before* it is signed -- the copy `SignResult` returns alongside the
    /// signature arrives a round-trip too late to be part of what was signed.
    pub certificates: HashMap<String, String>,

    /// Store details the seller has entered and asked to publish, waiting on
    /// the certificate that has to travel inside the signed record. See
    /// `start_store_edit_if_ready`.
    pub pending_store_edit: Option<PendingStoreEdit>,

    /// Signed listings ready to be submitted to the store contract.
    /// The UI should pick these up and send them as contract updates.
    pub signed_listings_ready: Vec<AuthorizedListing>,

    /// Pending messages/events for the UI to display.
    pub notifications: Vec<String>,

    /// Bitcoin/Payments state: bridge config, private watch list, and live
    /// on-chain data mirrored from subscribed Bitcoin contracts.
    pub bitcoin: BitcoinState,
}

/// Details for a store being created, waiting on the two delegate responses
/// that supply the rest of its inputs. See `start_store_creation_if_ready`.
#[derive(Clone, Debug)]
pub struct PendingStoreCreation {
    pub ghostkey_fingerprint: String,
    pub seller_verifying_key_bytes: [u8; 32],
    /// Filled by the ghostkey delegate's `Certificate` (or `GhostKeyDetail`)
    /// response. Empty until it arrives.
    pub certificate_pem: String,
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
    /// Filled by the harvest delegate's `ReputationKeysInitialized` response.
    /// `None` until it arrives.
    pub rsa_public_key_der: Option<Vec<u8>>,
}

/// Publish the three contracts of a store whose inputs are all present.
///
/// Split out of `AppState::start_store_creation_if_ready` so the gate itself
/// compiles and is testable off-target: everything below here needs a browser.
#[cfg(target_arch = "wasm32")]
fn spawn_store_creation(pending: PendingStoreCreation) {
    let PendingStoreCreation {
        ghostkey_fingerprint,
        seller_verifying_key_bytes,
        certificate_pem,
        store_name,
        description,
        payment_instructions,
        rsa_public_key_der,
    } = pending;
    // The gate only releases once this is `Some`; treat it as a no-op rather
    // than a panic if that ever stops being true.
    let Some(rsa_public_key_der) = rsa_public_key_der else {
        return;
    };

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::store_ops::create_store_contracts(
            ghostkey_fingerprint,
            seller_verifying_key_bytes,
            rsa_public_key_der,
            certificate_pem,
            store_name,
            description,
            payment_instructions,
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

/// Ask the ghostkey delegate for an identity's certificate.
#[cfg(target_arch = "wasm32")]
fn request_certificate(fingerprint: String) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::ReadableExt;

        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            dioxus::logger::tracing::error!("Ghostkey delegate not registered");
            return;
        };
        let request = ghostkey_common::GhostkeyRequest::GetCertificate { fingerprint };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                dioxus::logger::tracing::error!("Failed to serialize GetCertificate: {e}");
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            dioxus::logger::tracing::error!("Failed to request certificate: {e}");
        }
    });
}

/// Ask the ghostkey delegate to sign a store's details.
///
/// The request is already queued by the time this runs, because the answer
/// can arrive as soon as the send returns and an answer matching nothing is
/// dropped. If the send itself fails, withdraw it again: nothing will ever
/// answer it.
#[cfg(target_arch = "wasm32")]
fn spawn_store_info_signature(fingerprint: String, pending: PendingStoreInfo) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};

        let queued = PendingSignature::StoreInfo(pending.clone());
        let withdraw = |reason: String| {
            dioxus::logger::tracing::error!("{reason}");
            let mut state = crate::gateway::APP_STATE.write();
            state.withdraw_pending_signature(&queued);
            state
                .notifications
                .push(format!("Could not publish your store's details: {reason}"));
        };

        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            withdraw("ghostkey delegate not registered".to_string());
            return;
        };
        let message = match harvest_common::to_cbor(&pending.info) {
            Ok(message) => message,
            Err(e) => {
                withdraw(format!("serialize store details for signing: {e}"));
                return;
            }
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint,
            message,
        };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                withdraw(format!("serialize SignMessage: {e}"));
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            withdraw(format!("send store details for signing: {e}"));
        }
    });
}

/// The details a seller types about their own store.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StoreDetails {
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
}

/// Why a store the seller owns needs its details published.
///
/// Each of these is a state a store can genuinely be in today, not a
/// hypothetical: stores created before the details were ever published sit at
/// version 0, and a creation interrupted between the PUT and the signed
/// update leaves the same thing behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreDetailsGap {
    /// Still at version 0, the uninitialized state -- nothing has ever been
    /// published, so the store has no name, no description, and no link to
    /// the seller's reputation.
    NeverPublished,
    /// Published, but with no name a buyer can read.
    NoName,
    /// Published, but naming no reputation contract, so the seller's
    /// feedback history cannot be reached from the store.
    NoReputationLink,
}

impl StoreDetailsGap {
    /// What to tell the seller is wrong, and what publishing will fix.
    pub fn message(self) -> &'static str {
        match self {
            StoreDetailsGap::NeverPublished => {
                "This store's details were never published. Buyers who open your link see a \
                 storefront with no name, no description and no payment instructions, and your \
                 reputation record cannot be reached from it. Publishing the details below fixes \
                 all three."
            }
            StoreDetailsGap::NoName => {
                "This store has no name. Buyers who open your link see an unnamed storefront. \
                 Publishing the details below fixes it."
            }
            StoreDetailsGap::NoReputationLink => {
                "This store does not name your reputation contract, so buyers cannot reach your \
                 feedback history from it. Publishing the details below restores the link."
            }
        }
    }
}

/// Whether a store's published details need repairing, and why.
///
/// `None` for a store whose state has not arrived yet: absence of information
/// is not evidence of a gap, and reporting one here would flash a repair
/// prompt at every seller on every load.
pub fn store_details_gap(info: Option<&StoreInfoV1>) -> Option<StoreDetailsGap> {
    let info = info?;
    if info.version == 0 {
        // Version 0 is the default state, which `AuthorizedStoreInfoV1::verify`
        // skips entirely -- nothing in it was ever signed or published.
        return Some(StoreDetailsGap::NeverPublished);
    }
    if info.store_name.trim().is_empty() {
        return Some(StoreDetailsGap::NoName);
    }
    if info.reputation_contract_id == [0u8; 32] {
        return Some(StoreDetailsGap::NoReputationLink);
    }
    None
}

/// Store details entered by the seller and waiting on the certificate.
#[derive(Clone, Debug)]
pub struct PendingStoreEdit {
    pub ghostkey_fingerprint: String,
    pub store_contract_id: Vec<u8>,
    /// Taken from the seller's own `StoreRegistration`, which is the one
    /// place this survives -- the store's published state does not have it
    /// whenever there is anything to repair.
    pub reputation_contract_id: [u8; 32],
    /// One past whatever the network holds now, so the contract's
    /// last-writer-wins merge takes this over what is already there.
    pub next_version: u32,
    pub details: StoreDetails,
}

impl PendingStoreEdit {
    /// The record to sign and publish, once the certificate is known.
    fn store_info(&self, certificate_pem: String) -> StoreInfoV1 {
        StoreInfoV1 {
            version: self.next_version,
            certificate_pem,
            seller_fingerprint: self.ghostkey_fingerprint.clone(),
            reputation_contract_id: self.reputation_contract_id,
            store_name: self.details.store_name.clone(),
            description: self.details.description.clone(),
            payment_instructions: self.details.payment_instructions.clone(),
        }
    }
}

/// Something waiting on the ghostkey delegate's `SignResult`.
#[derive(Clone, Debug)]
pub enum PendingSignature {
    Listing(PendingListing),
    StoreInfo(PendingStoreInfo),
}

impl PendingSignature {
    /// The exact bytes this request handed the delegate as
    /// `SignMessage::message`, which is what comes back inside the
    /// `ScopedPayload`. See `signed_message_bytes`.
    fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            PendingSignature::Listing(pending) => harvest_common::to_cbor(&pending.listing),
            PendingSignature::StoreInfo(pending) => harvest_common::to_cbor(&pending.info),
        }
    }
}

/// The message a `SignResult`'s scoped payload was built around, i.e. the
/// bytes the caller originally asked to have signed.
///
/// The delegate wraps the request's `message` verbatim as
/// `ScopedPayload::payload` and signs the wrapper, and every verifier -- the
/// store contract included, via `verify_scoped_signature` -- checks that
/// inner payload against a byte-for-byte re-encoding of the object it is
/// verifying. So these bytes identify which request an answer belongs to,
/// exactly and independently of arrival order.
///
/// `None` if the payload will not deserialize, which means the answer is
/// unusable rather than merely unmatched: a signature the contract cannot
/// verify is not worth applying to anything.
fn signed_message_bytes(scoped_payload: &[u8]) -> Option<Vec<u8>> {
    harvest_common::from_cbor::<ghostkey_common::ScopedPayload>(scoped_payload)
        .ok()
        .map(|scoped| scoped.payload)
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

    /// Drop a queued signature request that nothing will ever answer.
    ///
    /// Matched on the bytes it asked to have signed, the same way an incoming
    /// answer is matched, so this cannot withdraw a different request that
    /// happens to sit at the same position.
    fn withdraw_pending_signature(&mut self, withdrawn: &PendingSignature) {
        let Ok(bytes) = withdrawn.signed_bytes() else {
            return;
        };
        self.pending_signatures
            .retain(|pending| !pending.signed_bytes().is_ok_and(|queued| queued == bytes));
    }

    /// Publish new details for a store the seller owns -- the entry point for
    /// both editing a working store and repairing one whose details never
    /// reached the network.
    ///
    /// Everything except what the seller typed is taken from state rather
    /// than passed in, which is what makes this safe to call from a form:
    /// the store has to be one of theirs (`my_stores` is the only source of
    /// the owning fingerprint), and the reputation contract id comes from
    /// that registration rather than from the store's published state, which
    /// is exactly the field that is missing whenever there is anything to
    /// repair.
    ///
    /// Errors are returned rather than swallowed so the form can say why
    /// nothing happened.
    pub fn publish_store_details(
        &mut self,
        store_contract_id: &[u8],
        details: StoreDetails,
    ) -> Result<(), String> {
        let (ghostkey_fingerprint, registration) = self
            .my_stores
            .iter()
            .find_map(|(fingerprint, stores)| {
                stores
                    .iter()
                    .find(|store| store.store_contract_id == store_contract_id)
                    .map(|store| (fingerprint.clone(), store))
            })
            .ok_or("this store is not one of yours -- nothing to publish details for")?;

        let reputation_contract_id: [u8; 32] = registration
            .reputation_contract_id
            .as_slice()
            .try_into()
            .map_err(|_| {
                format!(
                    "this store's reputation contract id is {} bytes, not 32 -- cannot publish \
                     details that would point buyers at nothing",
                    registration.reputation_contract_id.len()
                )
            })?;

        // One past whatever is published now. A store that has never
        // published anything is at version 0, so this is 1 -- the first
        // version the contract actually verifies.
        let next_version = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.info.as_ref())
            .map_or(0, |info| info.version)
            .saturating_add(1);

        self.pending_store_edit = Some(PendingStoreEdit {
            ghostkey_fingerprint: ghostkey_fingerprint.clone(),
            store_contract_id: store_contract_id.to_vec(),
            reputation_contract_id,
            next_version,
            details,
        });

        if !self.start_store_edit_if_ready() {
            // The certificate has to be inside the record before it is
            // signed, so ask for it and finish when it lands.
            info!("Store details are waiting on the certificate for {ghostkey_fingerprint}");
            #[cfg(target_arch = "wasm32")]
            request_certificate(ghostkey_fingerprint);
        }
        Ok(())
    }

    /// Sign and publish a pending edit once the certificate it needs is
    /// known. Returns whether it went ahead.
    ///
    /// Called both when the edit is submitted (the certificate is usually
    /// already cached by then) and whenever a certificate arrives, so
    /// neither order needs special handling.
    fn start_store_edit_if_ready(&mut self) -> bool {
        let Some(edit) = self.pending_store_edit.as_ref() else {
            return false;
        };
        let Some(certificate_pem) = self
            .certificates
            .get(&edit.ghostkey_fingerprint)
            .filter(|pem| !pem.is_empty())
            .cloned()
        else {
            return false;
        };
        let Some(edit) = self.pending_store_edit.take() else {
            return false;
        };

        let info = edit.store_info(certificate_pem);
        info!(
            "Publishing details for store {:?} at version {}",
            &edit.store_contract_id[..8.min(edit.store_contract_id.len())],
            info.version
        );
        self.queue_store_info_signature(edit.ghostkey_fingerprint, edit.store_contract_id, info);
        true
    }

    /// Queue a store-info signature request and ask the delegate for it.
    ///
    /// The queueing is deliberately not behind a target gate: it is the part
    /// that decides what gets published, so it stays testable off-target.
    /// Only the delegate round-trip needs a browser.
    fn queue_store_info_signature(
        &mut self,
        ghostkey_fingerprint: String,
        store_contract_id: Vec<u8>,
        info: StoreInfoV1,
    ) {
        let pending = PendingStoreInfo {
            info,
            store_contract_id,
        };
        self.pending_signatures
            .push_back(PendingSignature::StoreInfo(pending.clone()));

        #[cfg(target_arch = "wasm32")]
        spawn_store_info_signature(ghostkey_fingerprint, pending);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = ghostkey_fingerprint;
    }

    /// Publish a new store's contracts, once every input creation needs has
    /// arrived.
    ///
    /// `initiate_store_creation` fires two requests together -- `GetCertificate`
    /// to the ghostkey delegate and `InitReputationKeys` to the harvest
    /// delegate -- and the two answer independently, in whichever order they
    /// happen to. So neither response can assume it is the last one, and the
    /// decision to proceed belongs here rather than in either handler.
    ///
    /// Before this gate, `ReputationKeysInitialized` took the pending creation
    /// and went ahead on its own. A certificate arriving second was then
    /// written into a slot already emptied, and silently discarded: the store
    /// published with an empty `certificate_pem`, leaving a buyer no trust
    /// chain to check the seller against. That was already wrong for the
    /// reputation contract; it became worse once the certificate started
    /// travelling inside the *signed* `StoreInfoV1`, where correcting it means
    /// a fresh signature rather than an edit.
    ///
    /// Waiting is the safe direction only because every response meaning the
    /// certificate will never arrive -- `Error`, `AccessDenied`,
    /// `NoIdentityAvailable`, `PermissionDenied`, `KeyNotFound` -- clears
    /// `pending_store_creation` and tells the user. Otherwise a creation sits
    /// here forever on an answer that is not coming.
    ///
    /// That claim was false in two ways when it was first written, and both
    /// are worth remembering because neither showed up as a failing test.
    /// `Error` cleared `pending_store_edit` but not `pending_store_creation`;
    /// and `KeyNotFound`, which is a flat "there is no such key" for a waiting
    /// `GetCertificate`, fell into the wildcard arm and cleared nothing at
    /// all. Underneath both, no ghostkey error reached
    /// `on_ghostkey_response` in the first place -- the gateway routed every
    /// one of them to the Harvest handler by trial CBOR decode. See
    /// `gateway::response_handler::DelegateSender`.
    fn start_store_creation_if_ready(&mut self) {
        let ready = matches!(
            self.pending_store_creation.as_ref(),
            Some(pending)
                if !pending.certificate_pem.is_empty()
                    && pending.rsa_public_key_der.is_some()
        );
        if !ready {
            return;
        }
        let Some(pending) = self.pending_store_creation.take() else {
            return;
        };

        info!(
            "Store creation inputs complete for {} -- publishing contracts",
            pending.ghostkey_fingerprint
        );

        #[cfg(target_arch = "wasm32")]
        spawn_store_creation(pending);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = pending;
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

                if let Some(pending) = self.pending_store_creation.as_mut() {
                    if pending.ghostkey_fingerprint == ghostkey_fingerprint {
                        pending.rsa_public_key_der = Some(rsa_public_key_der);
                    }
                }
                self.start_store_creation_if_ready();
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
                // Match the answer to its request by the bytes that were
                // signed, not by queue position. `SignResult` carries no
                // correlation id, so position is the obvious choice -- but it
                // is only correct while answers come back in the order they
                // were asked for, and it fails silently when they do not: the
                // signature is grafted onto the wrong object, and what lands
                // on the network is a record whose signature does not cover
                // it. The contract then rejects it with nothing to say about
                // why, which is indistinguishable from never having sent it.
                //
                // The scoped payload names its own request (see
                // `signed_message_bytes`), so use that instead. An answer
                // matching nothing outstanding is dropped rather than applied
                // to whatever happens to be at the head of the queue: those
                // bytes could not verify against any object we hold, so
                // there is nothing useful to do with them.
                let matched = signed_message_bytes(&scoped_payload).and_then(|message| {
                    self.pending_signatures
                        .iter()
                        .position(|pending| {
                            pending.signed_bytes().is_ok_and(|bytes| bytes == message)
                        })
                        .and_then(|at| self.pending_signatures.remove(at))
                });
                match matched {
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
                        warn!(
                            "SignResult matches none of the {} outstanding signature request(s) \
                             -- dropping it",
                            self.pending_signatures.len()
                        );
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
                self.certificates
                    .insert(fingerprint.clone(), certificate_pem.clone());
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                        info!("Updated pending store creation with certificate");
                    }
                }
                self.start_store_creation_if_ready();
                self.start_store_edit_if_ready();
            }

            ghostkey_common::GhostkeyResponse::GhostKeyDetail {
                fingerprint,
                certificate_pem,
                ..
            } => {
                info!("Received ghostkey detail for {}", fingerprint);
                self.certificates
                    .insert(fingerprint.clone(), certificate_pem.clone());
                // Also update pending store creation if applicable
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                    }
                }
                self.start_store_creation_if_ready();
                self.start_store_edit_if_ready();
            }

            ghostkey_common::GhostkeyResponse::Error { message } => {
                self.notifications
                    .push(format!("Ghostkey error: {message}"));
                self.pending_signatures.clear();
                // A failed `GetCertificate` surfaces here, and a creation or
                // an edit waiting on that certificate would otherwise sit
                // unfinished and unmentioned. `start_store_creation_if_ready`
                // waits for the certificate precisely because it trusts this
                // to happen.
                self.pending_store_creation = None;
                self.pending_store_edit = None;
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
                self.pending_store_edit = None;
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
                self.pending_store_edit = None;
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
                self.pending_store_edit = None;
            }

            // Terminal for a waiting `GetCertificate`: the vault is telling
            // us the key does not exist, so no certificate is coming and
            // nothing is left to wait for. This used to fall into the
            // wildcard below and clear nothing, which left a seller's store
            // creation pending forever with no message.
            ghostkey_common::GhostkeyResponse::KeyNotFound { fingerprint } => {
                self.notifications.push(format!(
                    "Ghostkey {fingerprint} was not found in the vault."
                ));
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
                self.pending_store_edit = None;
            }

            // Vault-only responses Harvest doesn't act on. The
            // explicit arms above cover every user-visible failure
            // mode in the current ghostkey-common protocol; this
            // wildcard is just for vault-management responses
            // (PermissionGranted / PermissionRevoked / PermissionList /
            // VerifyResult / Deleted / LabelSet, etc).
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

/// Whether anything is actually synchronizing a watched script, as the watch
/// row should report it.
///
/// # Why `LocalOnly` is every manual watch today
///
/// Watching an address is two separate things: recording it privately (which
/// works), and asking a bridge to synchronize the script so its transactions
/// land in a `BitcoinAddressContract` the UI can subscribe to (which nothing
/// does). The second half has no implementation and cannot get one where it
/// was assumed to live:
///
/// * The delegate cannot make the request. `OutboundDelegateMsg` has no HTTP
///   variant -- the whole set is application messages, user input, context,
///   and contract GET/PUT/UPDATE/SUBSCRIBE -- so a delegate has no outbound
///   HTTP capability at all. `handlers`' `Watch` arm persists the record and
///   answers `Watched { result: Ok(..) }`, which is the truth about what it
///   did, not a claim that a bridge was told.
/// * The page cannot make it either, once published. A webapp is served with
///   `connect-src` limited to its own gateway, so `fetch` to a bridge URL is
///   refused by the content-security policy. `gateway::bitcoin_config`'s
///   module docs record the same refusal for `/v1/status`, which is why the
///   tip contract id became a build-time constant.
///
/// So a manual watch keeps `contract_id: None` and `bridge_synced: false`
/// forever, `register_watch_contract` returns immediately because there is no
/// contract id to subscribe to, and no transaction can ever appear. Saying
/// "Waiting for bridge to sync…" describes a wait that never ends. This
/// function exists so the row says that instead.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WatchSyncStatus {
    /// A bridge reported a failure for this script.
    Failed(String),
    /// A bridge is synchronizing it and named the address contract carrying
    /// the results, so transactions can appear.
    Live,
    /// A bridge is synchronizing it but named no address contract, so there
    /// is nothing for the UI to subscribe to.
    SyncedWithoutContract,
    /// Recorded on this device and nowhere else.
    LocalOnly,
}

impl WatchSyncStatus {
    /// What to tell the user, or `None` when there is nothing to say because
    /// the watch is working.
    pub fn message(&self) -> Option<String> {
        match self {
            WatchSyncStatus::Failed(text) => Some(text.clone()),
            WatchSyncStatus::Live => None,
            WatchSyncStatus::SyncedWithoutContract => Some(
                "A bridge is watching this address but didn't say which Freenet contract \
                 carries the results, so there is nothing for Harvest to read."
                    .to_string(),
            ),
            WatchSyncStatus::LocalOnly => Some(
                "Recorded on this device only. No bridge has been asked to watch this \
                 address, so its transactions will not appear here."
                    .to_string(),
            ),
        }
    }
}

/// Classify a watch. See [`WatchSyncStatus`] for why `LocalOnly` is the
/// answer for every manual watch today.
pub fn watch_sync_status(watch: &WatchedPayment) -> WatchSyncStatus {
    if let Some(error) = watch.last_error.as_deref() {
        return WatchSyncStatus::Failed(friendly_bridge_error(error));
    }
    if !watch.bridge_synced {
        return WatchSyncStatus::LocalOnly;
    }
    // A bridge confirmed the script but the address contract is what the UI
    // actually reads, so a watch without one is not live however the bridge
    // answered.
    if watch.contract_id.is_none() {
        return WatchSyncStatus::SyncedWithoutContract;
    }
    WatchSyncStatus::Live
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

    /// A `SignResult` carrying a scoped payload that names no request we
    /// made -- the bytes will not even deserialize.
    fn sign_result() -> ghostkey_common::GhostkeyResponse {
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            certificate_pem: String::new(),
        }
    }

    /// A `SignResult` shaped the way the ghostkey delegate answers: the
    /// request's own message, wrapped verbatim as `ScopedPayload::payload`.
    fn sign_result_for(pending: &PendingSignature) -> ghostkey_common::GhostkeyResponse {
        let scoped = ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: pending.signed_bytes().expect("serialize signed message"),
        };
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: harvest_common::to_cbor(&scoped).expect("serialize scoped payload"),
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

    /// `SignResult` carries no correlation id, so an answer has to be matched
    /// to its request by the bytes it was signed over. Queue position cannot
    /// do it: a store's info and a listing can be outstanding at once --
    /// publishing a store signs its info, and the seller can start a listing
    /// right after -- and nothing guarantees the two delegate round-trips
    /// finish in the order they began.
    ///
    /// Answer the *second* request first. Under position-matching the store
    /// info would swallow the listing's signature and both records would go
    /// out carrying a signature that does not cover them.
    #[test]
    fn an_answer_goes_to_the_request_whose_bytes_it_carries() {
        let mut state = AppState::default();
        let listing = pending_listing();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(listing.clone());

        state.on_ghostkey_response(sign_result_for(&listing));

        assert_eq!(
            state.signed_listings_ready.len(),
            1,
            "the listing's own answer must reach the listing"
        );
        assert_eq!(state.signed_listings_ready[0].listing.title, "Beans");
        assert_eq!(
            state.pending_signatures.len(),
            1,
            "the store info is still waiting for its own answer"
        );
        assert!(matches!(
            state.pending_signatures.front(),
            Some(PendingSignature::StoreInfo(_))
        ));
    }

    /// And the signature it carries has to be the one attached: the scoped
    /// payload is what the store contract re-encodes and compares against, so
    /// pairing it with the wrong record produces something no verifier
    /// accepts.
    #[test]
    fn the_signature_attached_is_the_one_that_was_answered() {
        let mut state = AppState::default();
        let listing = pending_listing();
        state.pending_signatures.push_back(listing.clone());

        state.on_ghostkey_response(sign_result_for(&listing));

        let signed = state
            .signed_listings_ready
            .first()
            .expect("a signed listing");
        assert_eq!(
            signed.scoped_payload,
            harvest_common::to_cbor(&ghostkey_common::ScopedPayload {
                requestor: harvest_common::expected_harvest_requestor(),
                payload: listing.signed_bytes().expect("signed bytes"),
            })
            .expect("serialize"),
            "the scoped payload must wrap this listing's own bytes"
        );
    }

    /// An answer with nothing queued must be dropped, not applied to
    /// whatever is queued next.
    #[test]
    fn a_signature_with_nothing_waiting_is_dropped() {
        let mut state = AppState::default();
        state.on_ghostkey_response(sign_result());
        assert!(state.signed_listings_ready.is_empty());
    }

    /// An answer that matches nothing outstanding is dropped rather than
    /// spent on whatever happens to be queued. Those bytes cannot verify
    /// against any record we hold, so applying them would publish something
    /// the contract rejects -- and would consume a request that is still
    /// legitimately waiting for its own answer.
    #[test]
    fn an_unrecognised_signature_does_not_consume_a_queued_request() {
        let mut state = AppState::default();
        state.pending_signatures.push_back(pending_listing());

        state.on_ghostkey_response(sign_result());

        assert!(
            state.signed_listings_ready.is_empty(),
            "nothing should have been signed"
        );
        assert_eq!(
            state.pending_signatures.len(),
            1,
            "the queued listing must still be waiting for its own answer"
        );
    }

    fn pending_creation() -> PendingStoreCreation {
        PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [7u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
        }
    }

    fn rsa_keys_initialized(fingerprint: &str) -> HarvestDelegateResponse {
        HarvestDelegateResponse::ReputationKeysInitialized {
            ghostkey_fingerprint: fingerprint.to_string(),
            rsa_public_key_der: vec![9u8; 8],
        }
    }

    fn certificate(fingerprint: &str) -> ghostkey_common::GhostkeyResponse {
        ghostkey_common::GhostkeyResponse::Certificate {
            fingerprint: fingerprint.to_string(),
            certificate_pem: "-----BEGIN CERT-----".to_string(),
        }
    }

    /// A seller who has asked to create a store, with neither delegate
    /// answer in yet.
    fn state_awaiting_creation() -> AppState {
        AppState {
            pending_store_creation: Some(pending_creation()),
            ..AppState::default()
        }
    }

    /// The race this exists to close. `initiate_store_creation` asks the
    /// ghostkey delegate for the certificate and the harvest delegate for the
    /// RSA key at the same time, and they answer independently. The RSA
    /// answer used to take the pending creation and publish immediately, so a
    /// certificate arriving second was written into a slot that was already
    /// empty and thrown away -- and the store went onto the network with no
    /// certificate for a buyer to check the seller against.
    ///
    /// The RSA answer must therefore leave the creation waiting.
    #[test]
    fn the_rsa_key_alone_does_not_start_store_creation() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));

        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("creation must wait for the certificate, not publish without it");
        assert!(pending.certificate_pem.is_empty());
        assert!(pending.rsa_public_key_der.is_some(), "the key was recorded");
    }

    /// The certificate landing second completes the inputs and releases the
    /// creation -- carrying the certificate with it, which is the whole point.
    #[test]
    fn the_certificate_arriving_second_is_not_lost() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));
        assert!(state.pending_store_creation.is_some());

        state.on_ghostkey_response(certificate(FINGERPRINT));

        assert!(
            state.pending_store_creation.is_none(),
            "both inputs are present, so creation must have started"
        );
    }

    /// And the other order works too: neither response is privileged, so
    /// whichever lands second is the one that releases the creation.
    #[test]
    fn the_rsa_key_arriving_second_is_not_lost() {
        let mut state = state_awaiting_creation();

        state.on_ghostkey_response(certificate(FINGERPRINT));
        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("creation must wait for the RSA key");
        assert!(!pending.certificate_pem.is_empty(), "the cert was recorded");

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));
        assert!(state.pending_store_creation.is_none());
    }

    /// Both answers name a fingerprint, and an answer for a different
    /// identity must not complete this creation's inputs.
    #[test]
    fn another_identitys_answers_do_not_start_this_creation() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized("someone-else"));
        state.on_ghostkey_response(certificate("someone-else"));

        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("this creation is still waiting on its own answers");
        assert!(pending.certificate_pem.is_empty());
        assert!(pending.rsa_public_key_der.is_none());
    }

    const STORE_ID: [u8; 32] = [1u8; 32];
    /// `registration(1, ..)` files the store's reputation contract under this.
    const REPUTATION_ID: [u8; 32] = [2u8; 32];

    fn published_info(version: u32, name: &str, reputation_contract_id: [u8; 32]) -> StoreInfoV1 {
        StoreInfoV1 {
            version,
            certificate_pem: String::new(),
            seller_fingerprint: FINGERPRINT.to_string(),
            reputation_contract_id,
            store_name: name.to_string(),
            description: String::new(),
            payment_instructions: String::new(),
        }
    }

    /// A seller who owns one store, optionally with published details.
    fn seller_with_store(published: Option<StoreInfoV1>) -> AppState {
        let mut state = AppState {
            my_stores: HashMap::from([(FINGERPRINT.to_string(), vec![registration(1, None)])]),
            ..AppState::default()
        };
        if let Some(info) = published {
            state
                .browsing_stores
                .entry(STORE_ID.to_vec())
                .or_default()
                .info = Some(info);
        }
        state
    }

    fn typed_details() -> StoreDetails {
        StoreDetails {
            store_name: "Bean Shop".to_string(),
            description: "Coffee".to_string(),
            payment_instructions: "BTC: bc1q...".to_string(),
        }
    }

    /// The store info queued for signing, if any.
    fn queued_store_info(state: &AppState) -> Option<&StoreInfoV1> {
        state
            .pending_signatures
            .iter()
            .find_map(|pending| match pending {
                PendingSignature::StoreInfo(store_info) => Some(&store_info.info),
                PendingSignature::Listing(_) => None,
            })
    }

    /// Version 0 is the uninitialized state: nothing was ever signed or
    /// published, so the store has no name and no reputation link. This is
    /// every store created before details were published at all, and every
    /// store left behind by a creation interrupted before its signed update.
    #[test]
    fn a_store_at_version_zero_needs_publishing() {
        assert_eq!(
            store_details_gap(Some(&published_info(0, "", [0u8; 32]))),
            Some(StoreDetailsGap::NeverPublished)
        );
    }

    #[test]
    fn a_published_store_without_a_name_needs_repair() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "   ", REPUTATION_ID))),
            Some(StoreDetailsGap::NoName)
        );
    }

    /// The half nobody would notice. A store can carry a perfectly good name
    /// and still name no reputation contract, which leaves the seller's
    /// feedback history unreachable from it.
    #[test]
    fn a_published_store_without_a_reputation_link_needs_repair() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", [0u8; 32]))),
            Some(StoreDetailsGap::NoReputationLink)
        );
    }

    /// Nothing to repair means no prompt, which is what keeps this from
    /// nagging -- or republishing -- a store that is already fine.
    #[test]
    fn a_healthy_store_needs_nothing() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", REPUTATION_ID))),
            None
        );
    }

    /// A store whose state has not arrived yet is not a store with a gap.
    /// Reporting one here would flash the repair prompt on every load.
    #[test]
    fn a_store_that_has_not_loaded_yet_needs_nothing() {
        assert_eq!(store_details_gap(None), None);
    }

    /// The reputation contract id must come from the seller's own
    /// registration, not from the store's published state -- that field is
    /// all-zero in exactly the case being repaired, so copying it forward
    /// would publish a store that still points buyers at nothing.
    #[test]
    fn repairing_a_store_restores_the_reputation_link() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "-----BEGIN CERT-----".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(
            info.reputation_contract_id, REPUTATION_ID,
            "the reputation link must come from the registration, not the empty published state"
        );
        assert_ne!(info.reputation_contract_id, [0u8; 32]);
    }

    /// The rest of the repaired record: the seller's own text, the identity
    /// fields a buyer needs, and a version past the one the contract skips
    /// verifying.
    #[test]
    fn repairing_a_store_publishes_what_the_seller_typed() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "-----BEGIN CERT-----".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.version, 1, "version 0 is the unverified state");
        assert_eq!(info.store_name, "Bean Shop");
        assert_eq!(info.description, "Coffee");
        assert_eq!(info.payment_instructions, "BTC: bc1q...");
        assert_eq!(info.seller_fingerprint, FINGERPRINT);
        assert_eq!(info.certificate_pem, "-----BEGIN CERT-----");
    }

    /// Editing a store that is already published has to win the contract's
    /// last-writer-wins merge, so it lands one past whatever is there.
    #[test]
    fn editing_a_published_store_moves_past_its_current_version() {
        let mut state = seller_with_store(Some(published_info(3, "Old Name", REPUTATION_ID)));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.version, 4);
        assert_eq!(info.store_name, "Bean Shop");
    }

    /// A store stranded mid-creation may have no state locally at all. It
    /// still publishes at version 1 rather than being skipped.
    #[test]
    fn a_store_with_no_local_state_still_publishes_at_version_one() {
        let mut state = seller_with_store(None);
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        assert_eq!(
            queued_store_info(&state).expect("queued").version,
            1,
            "nothing published means the next version is the first one"
        );
    }

    /// The certificate travels inside the signed record, so it has to be
    /// known before signing. Without it the edit waits rather than
    /// publishing a record with no trust chain -- the same failure the
    /// creation gate exists to prevent.
    #[test]
    fn an_edit_waits_for_the_certificate() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        assert!(
            state.pending_signatures.is_empty(),
            "nothing may be signed before the certificate is known"
        );
        assert!(state.pending_store_edit.is_some(), "the edit is waiting");

        state.on_ghostkey_response(certificate(FINGERPRINT));

        assert!(state.pending_store_edit.is_none(), "the edit went ahead");
        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.certificate_pem, "-----BEGIN CERT-----");
        assert_eq!(info.reputation_contract_id, REPUTATION_ID);
    }

    /// `my_stores` is the only source of the owning fingerprint and of the
    /// reputation contract id, so a store that is not in it cannot be
    /// published to at all -- which is also what stops this firing for a
    /// store the user is merely browsing.
    #[test]
    fn details_cannot_be_published_for_a_store_the_user_does_not_own() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));

        let err = state
            .publish_store_details(&[9u8; 32], typed_details())
            .expect_err("a browsed store is not the seller's to publish");

        assert!(err.contains("not one of yours"), "unhelpful error: {err}");
        assert!(state.pending_store_edit.is_none());
        assert!(state.pending_signatures.is_empty());
    }

    /// An edit waiting on a certificate that will never arrive must not sit
    /// there unfinished and unmentioned.
    #[test]
    fn a_denied_prompt_clears_a_waiting_edit() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state.harvest_delegate_key = Some(delegate_key(0xA1));
        state.ghostkey_delegate_key = Some(delegate_key(0xB2));
        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");
        assert!(state.pending_store_edit.is_some());

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::AccessDenied {
                requestor: harvest_common::expected_harvest_requestor(),
            },
        );

        assert!(state.pending_store_edit.is_none());
    }

    // -----------------------------------------------------------------
    // Delegate routing
    //
    // These go through `gateway::response_handler`'s real router rather than
    // calling `on_ghostkey_response` directly. Calling it directly is what
    // made the original version of `a_denied_prompt_clears_the_whole_queue`
    // green and vacuous: the handler was correct and unreachable, because the
    // router classified every ghostkey error as a Harvest one by trial CBOR
    // decode. A test that skips the router cannot see that.
    // -----------------------------------------------------------------

    fn delegate_key(seed: u8) -> freenet_stdlib::prelude::DelegateKey {
        freenet_stdlib::prelude::DelegateKey::new(
            [seed; 32],
            freenet_stdlib::prelude::CodeHash::new([seed; 32]),
        )
    }

    /// An `AppState` that knows both delegate keys, as it does once the app
    /// has finished registering them.
    fn state_with_delegates() -> AppState {
        AppState {
            harvest_delegate_key: Some(delegate_key(0xA1)),
            ghostkey_delegate_key: Some(delegate_key(0xB2)),
            ..AppState::default()
        }
    }

    /// Deliver one CBOR payload as if the gateway had reported it arriving
    /// from `from`, through the same code path the live app uses.
    fn deliver(state: &mut AppState, from: &freenet_stdlib::prelude::DelegateKey, payload: &[u8]) {
        use crate::gateway::response_handler::{
            apply_delegate_response, decode_delegate_message, delegate_sender,
        };
        let sender = delegate_sender(
            from,
            state.harvest_delegate_key.as_ref(),
            state.ghostkey_delegate_key.as_ref(),
        );
        match decode_delegate_message(sender, payload) {
            Ok(response) => apply_delegate_response(state, response),
            Err(e) => panic!("the router rejected a well-formed payload: {e}"),
        }
    }

    fn from_ghostkey(state: &mut AppState, response: &ghostkey_common::GhostkeyResponse) {
        let payload = harvest_common::to_cbor(response).expect("a response must serialize");
        deliver(state, &delegate_key(0xB2), &payload);
    }

    /// A delegate error or a denied prompt invalidates everything queued --
    /// none of it will ever be answered, and a leftover entry would consume
    /// the next unrelated signature.
    #[test]
    fn a_denied_prompt_clears_the_whole_queue() {
        let mut state = state_with_delegates();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(pending_listing());

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::Error {
                message: "nope".to_string(),
            },
        );
        assert!(state.pending_signatures.is_empty());
    }

    /// The bug this routing exists to prevent, stated as a property.
    ///
    /// `HarvestDelegateResponse::Error { message: String }` and
    /// `GhostkeyResponse::Error { message: String }` are byte-identical CBOR,
    /// so nothing about the payload can tell them apart. Only the key can.
    #[test]
    fn an_error_is_attributed_to_the_delegate_that_sent_it_not_to_its_shape() {
        use crate::gateway::response_handler::{
            decode_delegate_message, delegate_sender, DelegateResponse, DelegateSender,
        };

        let harvest = delegate_key(0xA1);
        let ghostkey = delegate_key(0xB2);
        let gk_error = ghostkey_common::GhostkeyResponse::Error {
            message: "vault said no".to_string(),
        };
        let hv_error = HarvestDelegateResponse::Error {
            message: "vault said no".to_string(),
        };

        let gk_bytes = harvest_common::to_cbor(&gk_error).unwrap();
        let hv_bytes = harvest_common::to_cbor(&hv_error).unwrap();
        assert_eq!(
            gk_bytes, hv_bytes,
            "the two error payloads must be indistinguishable -- if they ever \
             stop being, this test is no longer testing anything"
        );

        assert_eq!(
            delegate_sender(&ghostkey, Some(&harvest), Some(&ghostkey)),
            DelegateSender::Ghostkey
        );
        assert!(matches!(
            decode_delegate_message(DelegateSender::Ghostkey, &gk_bytes),
            Ok(DelegateResponse::Ghostkey(_))
        ));
        assert!(matches!(
            decode_delegate_message(DelegateSender::Harvest, &hv_bytes),
            Ok(DelegateResponse::Harvest(_))
        ));
    }

    /// A key belonging to neither delegate is not guessed at. Guessing is
    /// what produced the misrouting in the first place.
    #[test]
    fn a_message_from_an_unregistered_delegate_is_not_decoded() {
        use crate::gateway::response_handler::{
            decode_delegate_message, delegate_sender, DelegateSender,
        };

        let harvest = delegate_key(0xA1);
        let ghostkey = delegate_key(0xB2);
        let stranger = delegate_key(0xFF);
        assert_eq!(
            delegate_sender(&stranger, Some(&harvest), Some(&ghostkey)),
            DelegateSender::Unknown
        );

        let payload = harvest_common::to_cbor(&HarvestDelegateResponse::Error {
            message: "x".to_string(),
        })
        .unwrap();
        assert!(decode_delegate_message(DelegateSender::Unknown, &payload).is_err());
    }

    /// `start_store_creation_if_ready` waits for the certificate rather than
    /// publishing a store without one, which is only safe because every
    /// response meaning "no certificate is coming" clears the pending
    /// creation. A ghostkey `Error` is one of those, and it has to survive
    /// the trip through the router to do its job.
    #[test]
    fn a_ghostkey_error_clears_a_waiting_store_creation() {
        let mut state = state_with_delegates();
        state.pending_store_creation = Some(PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [3u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
        });

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::Error {
                message: "no access".to_string(),
            },
        );

        assert!(
            state.pending_store_creation.is_none(),
            "a creation waiting on a certificate that will never arrive must not sit there"
        );
        assert!(
            !state.notifications.is_empty(),
            "and the seller has to be told"
        );
    }

    /// `KeyNotFound` is a flat "there is no such key" -- terminal for a
    /// waiting `GetCertificate`. It used to fall into the wildcard arm, which
    /// logs and clears nothing.
    #[test]
    fn key_not_found_clears_a_waiting_store_creation() {
        let mut state = state_with_delegates();
        state.pending_store_creation = Some(PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [3u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
        });
        state.pending_signatures.push_back(pending_store_info());
        state.request_any_access_in_flight = true;

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::KeyNotFound {
                fingerprint: FINGERPRINT.to_string(),
            },
        );

        assert!(state.pending_store_creation.is_none());
        assert!(state.pending_signatures.is_empty());
        assert!(!state.request_any_access_in_flight);
        assert!(!state.notifications.is_empty());
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

    // -----------------------------------------------------------------
    // What a watch row can honestly say
    // -----------------------------------------------------------------

    /// A watch exactly as `WatchForm` builds one and the delegate stores it.
    fn manual_watch() -> WatchedPayment {
        WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xde, 0xad],
            address: "tb1qexample".to_string(),
            label: None,
            order_id: None,
            expected_amount_sats: None,
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    /// The bug this replaced: the row said "Waiting for bridge to sync…"
    /// for a watch that nothing had asked a bridge about, and nothing ever
    /// would -- neither the delegate (no outbound HTTP in
    /// `OutboundDelegateMsg`) nor the page (the gateway's CSP limits
    /// `connect-src` to its own gateway). A wait that never ends must not be
    /// described as a wait.
    #[test]
    fn a_watch_nobody_asked_a_bridge_about_says_so() {
        let status = watch_sync_status(&manual_watch());
        assert_eq!(status, WatchSyncStatus::LocalOnly);
        let message = status.message().expect("a dead watch has to say so");
        assert!(
            message.contains("No bridge has been asked"),
            "the row must name the missing step, got: {message}"
        );
        assert!(
            !message.to_lowercase().contains("waiting"),
            "nothing is being waited for, got: {message}"
        );
    }

    /// A bridge that answered and named the address contract carrying the
    /// results is the one case with nothing to warn about.
    #[test]
    fn a_synced_watch_with_an_address_contract_has_nothing_to_report() {
        let watch = WatchedPayment {
            bridge_synced: true,
            contract_id: Some("11111111111111111111111111111111".to_string()),
            ..manual_watch()
        };
        assert_eq!(watch_sync_status(&watch), WatchSyncStatus::Live);
        assert_eq!(watch_sync_status(&watch).message(), None);
    }

    /// `bridge_synced` alone is not enough. The UI reads transactions out of
    /// the address contract, so a watch without one shows nothing however
    /// the bridge answered -- and must not be reported as working.
    #[test]
    fn a_synced_watch_with_no_address_contract_is_not_live() {
        let watch = WatchedPayment {
            bridge_synced: true,
            ..manual_watch()
        };
        assert_eq!(
            watch_sync_status(&watch),
            WatchSyncStatus::SyncedWithoutContract
        );
        assert!(watch_sync_status(&watch).message().is_some());
    }

    /// An error the bridge reported outranks everything else, and arrives
    /// already translated -- the row renders it verbatim.
    #[test]
    fn a_bridge_error_is_reported_in_the_users_terms() {
        let watch = WatchedPayment {
            last_error: Some("not authorized".to_string()),
            ..manual_watch()
        };
        assert_eq!(
            watch_sync_status(&watch),
            WatchSyncStatus::Failed(friendly_bridge_error("not authorized"))
        );
        assert!(watch_sync_status(&watch)
            .message()
            .expect("a failure has to say so")
            .contains("Ghost Key"));
    }
}
