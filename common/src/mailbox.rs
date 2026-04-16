use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 30-day TTL for mailbox messages.
pub const MESSAGE_TTL_SECS: i64 = 30 * 24 * 3600;

/// Conversation identifier: BLAKE3(sorted(party_a_fingerprint, party_b_fingerprint)).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConversationId(pub [u8; 32]);

impl ConversationId {
    pub fn new(fingerprint_a: &str, fingerprint_b: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        if fingerprint_a <= fingerprint_b {
            hasher.update(fingerprint_a.as_bytes());
            hasher.update(fingerprint_b.as_bytes());
        } else {
            hasher.update(fingerprint_b.as_bytes());
            hasher.update(fingerprint_a.as_bytes());
        }
        Self(*hasher.finalize().as_bytes())
    }
}

/// An encrypted message in a mailbox.
///
/// The mailbox is an open-write contract: anyone can submit encrypted messages.
/// Content is opaque ciphertext; the contract validates structure, not content.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct EncryptedMessage {
    pub conversation_id: ConversationId,
    /// Sender's public key bytes (ephemeral for anonymous buyers, persistent for sellers).
    pub sender_public_key: Vec<u8>,
    /// Encrypted payload (plaintext format is application-defined).
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
                return Err(format!("message older than TTL: {age}s > {MESSAGE_TTL_SECS}s"));
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
    fn test_conversation_id_symmetric() {
        let id1 = ConversationId::new("alice", "bob");
        let id2 = ConversationId::new("bob", "alice");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_conversation_id_unique() {
        let id1 = ConversationId::new("alice", "bob");
        let id2 = ConversationId::new("alice", "carol");
        assert_ne!(id1, id2);
    }
}
