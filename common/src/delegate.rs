use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::feedback::FeedbackToken;
use crate::listing::{AuthorizedListing, Listing};

pub type RequestId = u64;

/// The parameters the harvest delegate is registered under.
///
/// A delegate lives at `BLAKE3(BLAKE3(wasm) || parameters)` exactly as a
/// contract does, so this value is half of its address. It is empty because the
/// delegate needs no per-instance configuration -- but "empty" is a decision,
/// not an absence, and it belongs in one place rather than being spelled
/// `Parameters::from(Vec::<u8>::new())` at each registration site. Changing it
/// re-keys the delegate and strands every secret it holds; the address guard
/// (`common/src/bin/harvest-addresses.rs`) reads this constant, so such a
/// change shows up as a moved address rather than as nothing at all.
pub const DELEGATE_PARAMETERS: &[u8] = &[];

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

    // === Buyer-to-seller messaging ===
    /// Mint (or return) this identity's long-term X25519 public key.
    ///
    /// The private half stays in the delegate under
    /// `harvest:x25519_sk:{fingerprint}`; the public half is what the seller
    /// publishes in [`crate::store::StoreInfoV1::encryption_public_key`] so a
    /// buyer has something to encrypt to. Idempotent: a second call returns
    /// the key the first one minted, because re-minting would strand every
    /// message already in flight to the old one.
    InitEncryptionKey { ghostkey_fingerprint: String },

    /// Derive the conversation keys for a batch of buyer ephemeral public
    /// keys, so the UI can decrypt what is sitting in the mailbox.
    ///
    /// # Why the delegate answers keys rather than plaintext
    ///
    /// The long-term X25519 secret is the thing that must not leave: it
    /// decrypts every conversation this seller will ever have, including ones
    /// that have not happened yet. A conversation key decrypts one buyer's
    /// messages and nothing else, and the plaintext is going to the UI in any
    /// case -- that is where the seller reads it.
    ///
    /// Doing the AEAD here instead would mean a second copy of the padding,
    /// CBOR and AES-GCM path inside the delegate, and `harvest-common` is
    /// compiled into all three contracts, so it cannot host that code without
    /// putting `aes-gcm` in every contract's WASM. One crypto path, in
    /// `harvest-ui`'s `messaging`, is the trade.
    ///
    /// # This is a DH oracle, deliberately
    ///
    /// A caller who reaches this can derive a shared secret against any
    /// public key it likes. That is what makes it a read of the seller's
    /// mailbox and why it is behind `origin::authorize` along with everything
    /// else -- see the module docs on `harvest-delegate`'s `origin`.
    DeriveConversationKeys {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        /// Raw 32-byte X25519 public keys, as they appear in
        /// [`crate::mailbox::EncryptedMessage::sender_public_key`].
        peer_public_keys: Vec<Vec<u8>>,
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

    // === Migration markers ===
    /// Has the contract migration named by `marker` already completed?
    ///
    /// `marker` is an opaque, ASCII-only id minted by
    /// `harvest-ui`'s `migrate::marker_key` -- artifact, contract instance and
    /// current code hash, hex-encoded. The delegate stores it under its own
    /// `harvest:migrate:` prefix rather than treating it as a raw secret key,
    /// so a caller cannot address anything else in the delegate's namespace
    /// with it.
    ///
    /// The answer is a plain `present: bool`, and every failure -- an
    /// unreadable store, a malformed marker, no answer at all -- has to be
    /// read as **not** present. An unreadable marker treated as "done" skips
    /// the migration; treated as "not done" it repeats a walk that only ever
    /// adds. See `harvest-ui`'s `migrate` module docs.
    GetMigrationMarker { marker: String },

    /// Record that the migration named by `marker` finished.
    ///
    /// `note` is the human-readable outcome line, stored as the marker's
    /// value so a later reader can see what sealed it. Only the presence of
    /// the key is load-bearing.
    SetMigrationMarker { marker: String, note: String },
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

    /// This identity's long-term X25519 public key, minted or recalled.
    EncryptionKeyReady {
        ghostkey_fingerprint: String,
        /// Raw 32 bytes. A `Vec` rather than `[u8; 32]` because every other
        /// key on this wire is one, and a length mismatch is then a message
        /// the UI can report rather than a decode failure with no context.
        x25519_public_key: Vec<u8>,
    },

    /// Conversation keys for the peer public keys that were asked about.
    ///
    /// One entry per key the delegate could derive against, in no particular
    /// order; a peer key that was malformed is simply absent, and
    /// [`ConversationKey::peer_public_key`] is what pairs an answer with its
    /// question. Positional correlation would put one buyer's key against
    /// another buyer's messages the first time an entry was dropped.
    ConversationKeys {
        request_id: RequestId,
        /// Echoed so a reader of a node log can see which identity was asked
        /// about, and so the UI is not correlating on `request_id` alone.
        ghostkey_fingerprint: String,
        result: Result<Vec<ConversationKey>, String>,
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

    /// Whether the migration named by `marker` is already recorded as done.
    ///
    /// `present: false` is the answer to every uncertainty as well as to a
    /// genuine absence -- see `HarvestDelegateRequest::GetMigrationMarker`.
    MigrationMarker {
        marker: String,
        present: bool,
    },

    /// The outcome of a `SetMigrationMarker`.
    ///
    /// `recorded: false` means the host refused the write. It is reported
    /// rather than swallowed so the log says why the same walk runs again next
    /// load, but nothing has to act on it: an unwritten marker repeats a walk
    /// that only ever adds.
    MigrationMarkerRecorded {
        marker: String,
        recorded: bool,
    },

    Error {
        message: String,
    },
}

/// One buyer's ephemeral public key and the conversation key derived from it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConversationKey {
    /// The buyer ephemeral public key this was derived against, echoed back
    /// so the caller does not have to rely on ordering.
    pub peer_public_key: Vec<u8>,
    /// AES-256 key, from [`crate::mailbox::conversation_key_from_dh`].
    pub key: [u8; 32],
}

/// A store's contract IDs, registered with the delegate for notifications.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreRegistration {
    pub store_contract_id: Vec<u8>,
    pub reputation_contract_id: Vec<u8>,
    pub mailbox_contract_id: Vec<u8>,
    /// Serialized ContractKey for the store contract (needed for updates).
    /// This includes both the instance ID and the code hash.
    #[serde(default)]
    pub store_contract_key: Option<Vec<u8>>,
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
