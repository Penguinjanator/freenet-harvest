use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::feedback::FeedbackToken;
use crate::listing::{AuthorizedListing, Listing};

pub type RequestId = u64;

/// Requests from the UI to the Harvest delegate.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum HarvestDelegateRequest {
    // === RSA Key Management (for feedback token blind signing) ===
    /// Generate and store an RSA-PSS keypair for a ghostkey identity's reputation.
    InitReputationKeys { ghostkey_fingerprint: String },

    /// Get the RSA public key (PKCS#1 DER) for a reputation identity.
    GetRsaPublicKey { ghostkey_fingerprint: String },

    // === Blind Signing (seller signs buyer's feedback token) ===
    /// Blind-sign a buyer's feedback token.
    BlindSignFeedbackToken {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        blinded_token: Vec<u8>,
    },

    // === Listing Management ===
    /// Create and sign a new listing using the seller's ghostkey.
    CreateListing {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        listing: Listing,
    },

    // === Transaction State ===
    /// Record that a feedback token exchange has started with a buyer.
    BeginTransaction {
        request_id: RequestId,
        /// Identifier for this transaction (e.g. listing ID + buyer ephemeral key).
        transaction_id: String,
        /// Our unblinded feedback token (held locally, never sent to counterparty).
        our_token: FeedbackToken,
        /// The blinded version we sent to the counterparty for signing.
        our_blinded_token: Vec<u8>,
    },

    /// Record receipt of a blind signature on our feedback token.
    RecordBlindSignature {
        request_id: RequestId,
        transaction_id: String,
        blind_signature: Vec<u8>,
    },

    /// Get stored transaction history.
    ListTransactions,

    // === Store Registry ===
    /// Register a store's contracts with a ghostkey identity so the delegate
    /// knows which contracts to subscribe to for notifications.
    RegisterStore {
        ghostkey_fingerprint: String,
        store_contract_id: Vec<u8>,
        reputation_contract_id: Vec<u8>,
        mailbox_contract_id: Vec<u8>,
    },

    /// List all stores registered for a ghostkey identity.
    ListStores { ghostkey_fingerprint: String },
}

/// Responses from the Harvest delegate to the UI.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum HarvestDelegateResponse {
    ReputationKeysInitialized {
        ghostkey_fingerprint: String,
        rsa_public_key_der: Vec<u8>,
    },

    RsaPublicKey {
        ghostkey_fingerprint: String,
        rsa_public_key_der: Vec<u8>,
    },

    BlindSignatureResult {
        request_id: RequestId,
        result: Result<Vec<u8>, String>,
    },

    ListingCreated {
        request_id: RequestId,
        result: Result<AuthorizedListing, String>,
    },

    TransactionRecorded {
        request_id: RequestId,
        result: Result<(), String>,
    },

    BlindSignatureRecorded {
        request_id: RequestId,
        result: Result<(), String>,
    },

    TransactionList {
        transactions: Vec<TransactionRecord>,
    },

    /// A subscribed contract's state changed (new mailbox message, feedback, etc.).
    ContractUpdate {
        contract_key: Vec<u8>,
        update_data: Vec<u8>,
    },

    /// Full contract state from a GET response.
    ContractState {
        contract_key: Vec<u8>,
        state: Vec<u8>,
    },

    StoreRegistered {
        ghostkey_fingerprint: String,
    },

    StoreList {
        ghostkey_fingerprint: String,
        stores: Vec<StoreRegistration>,
    },

    Error {
        message: String,
    },
}

/// A store's contract IDs, registered with the delegate for notifications.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreRegistration {
    pub store_contract_id: Vec<u8>,
    pub reputation_contract_id: Vec<u8>,
    pub mailbox_contract_id: Vec<u8>,
}

/// A record of a feedback token exchange, stored locally by the delegate.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TransactionRecord {
    pub transaction_id: String,
    /// Our unblinded feedback token (can be submitted to counterparty's reputation contract).
    pub our_token: FeedbackToken,
    /// The blinded version we sent for signing.
    pub our_blinded_token: Vec<u8>,
    /// The blind signature we received (None until counterparty signs).
    pub blind_signature: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}
