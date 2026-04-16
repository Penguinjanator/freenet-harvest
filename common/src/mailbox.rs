use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 30-day TTL for mailbox messages.
pub const MESSAGE_TTL_SECS: i64 = 30 * 24 * 3600;

/// Message size buckets for padding (bytes). Ciphertexts are padded to the next
/// bucket boundary to reduce size-based traffic analysis.
pub const SIZE_BUCKETS: &[usize] = &[1024, 4096, 16384, 65536];

/// Pad data to the next size bucket boundary. Returns the padded data.
/// The first 4 bytes encode the original length (little-endian u32) so the
/// receiver can strip padding.
pub fn pad_to_bucket(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let padded_len = SIZE_BUCKETS
        .iter()
        .find(|&&bucket| bucket >= len + 4) // +4 for length prefix
        .copied()
        .unwrap_or(len + 4); // if larger than all buckets, no padding

    let mut result = Vec::with_capacity(padded_len);
    result.extend_from_slice(&(len as u32).to_le_bytes());
    result.extend_from_slice(data);
    result.resize(padded_len, 0);
    result
}

/// Remove padding from bucket-padded data.
pub fn unpad_from_bucket(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded data too short for length prefix".into());
    }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len + 4 > padded.len() {
        return Err(format!(
            "length prefix {len} exceeds padded data size {}",
            padded.len() - 4
        ));
    }
    Ok(padded[4..4 + len].to_vec())
}

/// Opaque conversation identifier chosen by the buyer.
///
/// Privacy: this is a random 32-byte value, NOT derived from party identities.
/// Deriving it from fingerprints would let a passive observer who knows the
/// seller's fingerprint (public on the store contract) confirm whether a
/// suspected buyer is communicating with that seller.
///
/// The buyer generates a random ConversationId and includes it in their first
/// (encrypted) message. The seller learns the ConversationId only after
/// decrypting the message.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConversationId(pub [u8; 32]);

impl ConversationId {
    /// Generate a random conversation ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom should not fail");
        Self(bytes)
    }
}

/// An encrypted message in a mailbox.
///
/// The mailbox is an open-write contract: anyone can submit encrypted messages.
/// Content is opaque ciphertext; the contract validates structure, not content.
///
/// Privacy notes:
/// - Buyers MUST use a fresh ephemeral key per store to prevent cross-store linkability.
/// - Ciphertext SHOULD be padded via `pad_to_bucket()` before encryption to reduce
///   size-based traffic analysis.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct EncryptedMessage {
    pub conversation_id: ConversationId,
    /// Sender's public key bytes. Buyers MUST use a fresh ephemeral key per store
    /// to prevent cross-store linkability.
    pub sender_public_key: Vec<u8>,
    /// Encrypted payload (plaintext format is application-defined).
    /// SHOULD be padded to a size bucket before encryption.
    pub ciphertext: Vec<u8>,
    /// When the message was created.
    pub timestamp: DateTime<Utc>,
    /// Unique nonce for deduplication.
    pub nonce: [u8; 24],
}

/// Immutable parameters for a mailbox contract.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MailboxParameters {
    /// The mailbox owner's Ed25519 verifying key (for identity linkage).
    pub owner_verifying_key: VerifyingKey,
}

/// Mailbox contract state: a collection of encrypted messages with TTL-based pruning.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct MailboxStateV1 {
    pub messages: Vec<EncryptedMessage>,
}

/// Summary for delta computation: set of known message nonces.
pub type MailboxSummary = HashSet<[u8; 24]>;

/// Delta: new messages to add.
pub type MailboxDelta = Vec<EncryptedMessage>;

impl MailboxStateV1 {
    /// Verify state: no duplicate nonces, all messages within TTL.
    pub fn verify(&self, now: DateTime<Utc>) -> Result<(), String> {
        let mut seen_nonces = HashSet::new();
        for msg in &self.messages {
            if !seen_nonces.insert(msg.nonce) {
                return Err("duplicate message nonce".into());
            }
            let age = now.signed_duration_since(msg.timestamp).num_seconds();
            if age > MESSAGE_TTL_SECS {
                return Err(format!(
                    "message older than TTL: {age}s > {MESSAGE_TTL_SECS}s"
                ));
            }
        }
        Ok(())
    }

    pub fn summarize(&self) -> MailboxSummary {
        self.messages.iter().map(|m| m.nonce).collect()
    }

    pub fn delta(&self, old_summary: &MailboxSummary) -> Option<MailboxDelta> {
        let new_messages: Vec<_> = self
            .messages
            .iter()
            .filter(|m| !old_summary.contains(&m.nonce))
            .cloned()
            .collect();
        if new_messages.is_empty() {
            None
        } else {
            Some(new_messages)
        }
    }

    /// Apply a delta: add new messages, prune expired ones.
    pub fn apply_delta(
        &mut self,
        delta: &Option<MailboxDelta>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if let Some(new_messages) = delta {
            let existing_nonces: HashSet<_> = self.messages.iter().map(|m| m.nonce).collect();

            for msg in new_messages {
                if existing_nonces.contains(&msg.nonce) {
                    continue;
                }
                // Accept messages within a reasonable time window
                let age = now.signed_duration_since(msg.timestamp).num_seconds();
                if age > MESSAGE_TTL_SECS {
                    continue; // silently drop expired messages
                }
                self.messages.push(msg.clone());
            }
        }

        // Prune expired messages
        self.messages
            .retain(|m| now.signed_duration_since(m.timestamp).num_seconds() <= MESSAGE_TTL_SECS);

        // Sort deterministically by nonce for CRDT convergence
        self.messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_id_random_is_unique() {
        let id1 = ConversationId::random();
        let id2 = ConversationId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello harvest marketplace";
        let padded = pad_to_bucket(data);
        assert_eq!(padded.len(), 1024); // fits in first bucket
        let unpadded = unpad_from_bucket(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_bucket_selection() {
        // Small message -> 1KB bucket
        let small = vec![0u8; 100];
        assert_eq!(pad_to_bucket(&small).len(), 1024);

        // 2KB message -> 4KB bucket
        let medium = vec![0u8; 2000];
        assert_eq!(pad_to_bucket(&medium).len(), 4096);

        // 10KB message -> 16KB bucket
        let large = vec![0u8; 10000];
        assert_eq!(pad_to_bucket(&large).len(), 16384);
    }

    #[test]
    fn test_unpad_rejects_corrupt_data() {
        assert!(unpad_from_bucket(&[0, 0, 0]).is_err()); // too short
        assert!(unpad_from_bucket(&[255, 255, 0, 0]).is_err()); // length exceeds data
    }
}
