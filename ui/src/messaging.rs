//! Encrypted messaging for buyer-seller communication.
//!
//! Uses X25519 key exchange + AES-256-GCM for end-to-end encryption.
//! Messages are padded to size buckets before encryption to reduce
//! traffic analysis (see harvest_common::mailbox::pad_to_bucket).
//!
//! # Nothing calls this yet
//!
//! `encrypt_message` and `decrypt_message` have no callers outside this
//! module's own tests. The missing half is the seller's X25519 public key:
//! `StoreInfoV1` publishes a certificate and a reputation contract id and no
//! encryption key, so a buyer has nothing to derive a conversation key
//! against. `components::message_view` says so on screen rather than
//! offering a compose box that silently discards what is typed into it.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use harvest_common::mailbox::{pad_to_bucket, unpad_from_bucket, ConversationId, EncryptedMessage};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// A plaintext message exchanged between buyer and seller.
/// Serialized to CBOR, padded, then encrypted.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlaintextMessage {
    /// The conversation this message belongs to.
    pub conversation_id: ConversationId,
    /// Message content.
    pub content: MessageContent,
}

/// The content of a message -- can be text, a feedback token exchange,
/// or a transaction-related message.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MessageContent {
    /// Free-form text message.
    Text(String),
    /// Buyer's initial contact with feedback token request.
    InitiateTransaction {
        listing_id: Vec<u8>,
        message: String,
        blinded_feedback_token: Vec<u8>,
        target_reputation_contract: [u8; 32],
    },
    /// Seller's response with blind signature on the feedback token.
    AcceptTransaction {
        message: String,
        blind_signature: Vec<u8>,
    },
    /// Either party declining or cancelling.
    Decline { reason: String },
}

/// An ephemeral keypair for a conversation. The buyer generates this
/// per-store to prevent cross-store linkability.
pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl EphemeralKeypair {
    /// Generate a new ephemeral keypair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random();
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    /// Perform X25519 key exchange and derive an AES-256 key.
    pub fn derive_shared_key(self, their_public_key: &PublicKey) -> [u8; 32] {
        let shared_secret: SharedSecret = self.secret.diffie_hellman(their_public_key);
        // Use BLAKE3 to derive the AES key from the shared secret
        let key = blake3::hash(shared_secret.as_bytes());
        *key.as_bytes()
    }
}

/// Encrypt a plaintext message for a recipient.
///
/// Returns an `EncryptedMessage` ready to be sent to the mailbox contract.
pub fn encrypt_message(
    plaintext: &PlaintextMessage,
    sender_public_key: &PublicKey,
    aes_key: &[u8; 32],
) -> Result<EncryptedMessage, String> {
    // Serialize the plaintext to CBOR
    let plaintext_bytes =
        harvest_common::to_cbor(plaintext).map_err(|e| format!("serialize plaintext: {e}"))?;

    // Pad to reduce size-based analysis
    let padded = pad_to_bucket(&plaintext_bytes);

    // Generate a random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("generate nonce: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    // Build the mailbox nonce (24 bytes: 12-byte AES nonce + 12 bytes random)
    let mut mailbox_nonce = [0u8; 24];
    mailbox_nonce[..12].copy_from_slice(&nonce_bytes);
    getrandom::getrandom(&mut mailbox_nonce[12..]).map_err(|e| format!("generate nonce: {e}"))?;

    Ok(EncryptedMessage {
        conversation_id: plaintext.conversation_id.clone(),
        sender_public_key: sender_public_key.as_bytes().to_vec(),
        ciphertext,
        timestamp: chrono::Utc::now(),
        nonce: mailbox_nonce,
    })
}

/// Decrypt an encrypted message from the mailbox contract.
pub fn decrypt_message(
    encrypted: &EncryptedMessage,
    aes_key: &[u8; 32],
) -> Result<PlaintextMessage, String> {
    // Extract the AES nonce from the first 12 bytes of the mailbox nonce
    let nonce = Nonce::from_slice(&encrypted.nonce[..12]);

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let padded = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| format!("decrypt: {e}"))?;

    // Unpad
    let plaintext_bytes = unpad_from_bucket(&padded).map_err(|e| format!("unpad: {e}"))?;

    // Deserialize from CBOR
    harvest_common::from_cbor(&plaintext_bytes).map_err(|e| format!("deserialize plaintext: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keypair = EphemeralKeypair::generate();
        let their_keypair = EphemeralKeypair::generate();

        let their_public = their_keypair.public_key;
        let our_public = keypair.public_key;

        // Both sides derive the same shared key
        let our_key = keypair.derive_shared_key(&their_public);
        let their_key = their_keypair.derive_shared_key(&our_public);
        assert_eq!(our_key, their_key);

        let conversation_id = ConversationId::random();
        let plaintext = PlaintextMessage {
            conversation_id: conversation_id.clone(),
            content: MessageContent::Text("Hello from buyer!".into()),
        };

        let encrypted = encrypt_message(&plaintext, &our_public, &our_key).unwrap();
        assert_ne!(
            encrypted.ciphertext,
            harvest_common::to_cbor(&plaintext).unwrap()
        );

        let decrypted = decrypt_message(&encrypted, &their_key).unwrap();
        assert_eq!(decrypted.conversation_id, conversation_id);
        match decrypted.content {
            MessageContent::Text(s) => assert_eq!(s, "Hello from buyer!"),
            _ => panic!("wrong message type"),
        }
    }
}
