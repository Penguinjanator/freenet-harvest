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
    /// A deterministic reference "now" derived from the state itself.
    ///
    /// A contract must NOT read the host clock: its verdict has to be a pure
    /// function of its inputs, or two peers evaluating identical bytes at
    /// different moments disagree and never converge. `freenet_stdlib::time::now()`
    /// is deprecated for contracts for exactly this reason and is staged to
    /// trap (freenet-core#5465).
    ///
    /// So TTL is measured against the newest message the mailbox holds, not
    /// against wall-clock time. Every peer computes the same value from the
    /// same bytes. The trade is that a mailbox which stops receiving stops
    /// ageing -- pruning resumes the moment a new message arrives, which is
    /// also the only moment the size matters.
    pub fn reference_now(&self) -> Option<DateTime<Utc>> {
        self.messages.iter().map(|m| m.timestamp).max()
    }

    /// Verify state: no duplicate nonces.
    ///
    /// TTL is deliberately NOT enforced here. It used to be, and it made a
    /// mailbox permanently invalid the moment any single message aged out:
    /// `verify` rejected the WHOLE state rather than pruning, so the mailbox
    /// could never shed anything and never recover. Pruning belongs in
    /// `apply_delta`, which is where it now lives.
    pub fn verify(&self) -> Result<(), String> {
        let mut seen_nonces = HashSet::new();
        for msg in &self.messages {
            if !seen_nonces.insert(msg.nonce) {
                return Err("duplicate message nonce".into());
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
    ///
    /// "Expired" is measured against [`Self::reference_now`] -- the newest
    /// timestamp present once the delta is merged -- not against a host clock,
    /// so every peer prunes identically from identical bytes.
    pub fn apply_delta(&mut self, delta: &Option<MailboxDelta>) -> Result<(), String> {
        if let Some(new_messages) = delta {
            let existing_nonces: HashSet<_> = self.messages.iter().map(|m| m.nonce).collect();

            for msg in new_messages {
                if existing_nonces.contains(&msg.nonce) {
                    continue;
                }
                self.messages.push(msg.clone());
            }
        }

        // Prune expired messages
        // Derived after the merge so an incoming message can advance the
        // reference point, which is what lets a live mailbox shed old entries.
        let reference = self.reference_now();
        self.messages.retain(|m| {
            reference
                .map(|r| r.signed_duration_since(m.timestamp).num_seconds() <= MESSAGE_TTL_SECS)
                .unwrap_or(true)
        });

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

#[cfg(test)]
mod determinism_tests {
    use super::*;

    fn msg(nonce: u8, secs: i64) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; 32],
            ciphertext: vec![0u8; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce: [nonce; 24],
        }
    }

    /// The property the clock removal exists for: two peers that receive the
    /// same messages in different orders must end up with byte-identical
    /// state. With `Utc::now()` they could not -- each read its own wall clock
    /// and pruned a different set.
    #[test]
    fn pruning_is_order_independent() {
        let base = 1_700_000_000;
        let old = msg(1, base);
        let recent = msg(2, base + MESSAGE_TTL_SECS + 10);
        let newer = msg(3, base + MESSAGE_TTL_SECS + 20);

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(vec![old.clone(), recent.clone(), newer.clone()]))
            .unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(vec![newer, recent, old])).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "identical messages in a different order must produce identical bytes"
        );
    }

    /// TTL still does something: a message older than the window relative to
    /// the newest one is dropped.
    #[test]
    fn messages_older_than_the_window_are_pruned() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![
            msg(1, base),
            msg(2, base + MESSAGE_TTL_SECS + 100),
        ]))
        .unwrap();
        assert_eq!(m.messages.len(), 1, "the stale message should be gone");
        assert_eq!(m.messages[0].nonce, [2u8; 24]);
    }

    /// A mailbox whose messages all fit the window keeps every one.
    #[test]
    fn a_fresh_mailbox_keeps_everything() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![
            msg(1, base),
            msg(2, base + 60),
            msg(3, base + 120),
        ]))
        .unwrap();
        assert_eq!(m.messages.len(), 3);
    }

    /// The regression that made a mailbox permanently unusable: `verify` used
    /// to reject the WHOLE state if any single message had aged out, so it
    /// could never shed anything and never recover.
    #[test]
    fn an_old_message_does_not_invalidate_the_whole_mailbox() {
        let mut m = MailboxStateV1::default();
        m.messages.push(msg(1, 0)); // epoch: ancient by any measure
        assert!(
            m.verify().is_ok(),
            "an aged message must not make the entire mailbox invalid"
        );
    }
}
