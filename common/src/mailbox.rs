use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// How many messages one mailbox contract will hold.
///
/// This is the mailbox's only retention rule. That it is a count rather than
/// an age is a security property and not a preference -- see
/// [`MailboxStateV1::apply_delta`], which explains why nothing here may be
/// dropped for being old.
pub const MAX_MESSAGES: usize = 512;

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

/// Drop the lowest-ranked messages if `messages` is over [`MAX_MESSAGES`].
///
/// Rank is `(timestamp, nonce)`, highest kept. Both fields are chosen by
/// whoever wrote the message, so this ordering is grindable and is not offered
/// as a defence -- see [`MailboxStateV1::apply_delta`] for what the cap does
/// and does not buy. What it has to be is *total* and a pure function of
/// message content, so that two replicas holding the same set of messages keep
/// the same subset. Ranking by anything else available here has the same
/// property and the same weakness, and `(timestamp, nonce)` at least leaves a
/// mailbox carrying only honest traffic behaving as a recency window, which is
/// what the age-based rule it replaces was for.
fn enforce_message_cap(messages: &mut Vec<EncryptedMessage>) {
    if messages.len() <= MAX_MESSAGES {
        return;
    }
    messages.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.nonce.cmp(&a.nonce))
    });
    messages.truncate(MAX_MESSAGES);
}

impl MailboxStateV1 {
    /// Verify state: no duplicate nonces, and no more than [`MAX_MESSAGES`]
    /// messages.
    ///
    /// Age is deliberately not checked here, and the cap deliberately is. The
    /// distinction is whether a state can turn invalid while nobody touches
    /// it. A TTL check used to live here and made a mailbox permanently
    /// invalid the moment any single message aged out: `verify` rejected the
    /// WHOLE state rather than pruning, so the mailbox could never shed
    /// anything and never recover. Being over the cap is a property of the
    /// bytes rather than of the passage of time -- [`Self::apply_delta`] never
    /// produces such a state -- so rejecting it cannot strand an honest
    /// mailbox, and it is what stops a peer being handed one directly.
    pub fn verify(&self) -> Result<(), String> {
        if self.messages.len() > MAX_MESSAGES {
            return Err(format!(
                "mailbox holds {} messages, cap is {MAX_MESSAGES}",
                self.messages.len()
            ));
        }
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

    /// Apply a delta: add the messages we do not hold, then bound the state
    /// by [`MAX_MESSAGES`].
    ///
    /// # Why retention is not time-based
    ///
    /// It used to be. Messages older than a 30-day TTL were dropped, measured
    /// against the newest timestamp the mailbox held rather than against a
    /// host clock -- a contract may not read one, because its verdict has to
    /// be a pure function of its inputs or two peers evaluating identical
    /// bytes at different moments disagree and never converge
    /// (`freenet_stdlib::time::now()` is deprecated for contracts for exactly
    /// this reason and is staged to trap, freenet-core#5465).
    ///
    /// Deterministic is not the same as trustworthy. The mailbox is
    /// open-write by design -- a buyer must be able to reach a seller they
    /// have no prior relationship with -- and `EncryptedMessage::timestamp` is
    /// signed by nobody. "The newest timestamp the mailbox holds" was
    /// therefore whatever the last writer typed. One message dated far in the
    /// future became the reference, immediately pruned every legitimate
    /// message as outside the window, and then discarded normally-dated
    /// arrivals until real time reached the forged date -- while the forged
    /// message itself survived, being the newest. An unauthenticated,
    /// permanent denial of a targeted mailbox for the cost of a single
    /// contract update, requiring no key and no relationship with either
    /// party.
    ///
    /// No bounded version of that idea survives the threat model, because any
    /// reference derived from message content is derived from attacker
    /// content. The k-th newest timestamp needs k forged messages; a median
    /// needs a majority, which an empty mailbox hands over for one message; a
    /// cap on how far one merge may advance the reference is not a pure
    /// function of the message SET, so two peers that received the same
    /// messages in different batches would advance it a different number of
    /// times and never converge. The reference has to be authenticated, or it
    /// has to go.
    ///
    /// It goes. Nothing is dropped here for being old.
    ///
    /// # What bounds the state instead
    ///
    /// Age was only ever a proxy for size; the comment this one replaces said
    /// so itself ("pruning resumes the moment a new message arrives, which is
    /// also the only moment the size matters"). [`MAX_MESSAGES`] bounds size
    /// directly, and [`enforce_message_cap`] chooses what goes by a total
    /// order over message content, so two replicas holding the same set keep
    /// the same subset and converge as they exchange what the other is
    /// missing.
    ///
    /// # What remains open
    ///
    /// A cap is a smaller weapon, not no weapon. An attacker willing to pay
    /// for [`MAX_MESSAGES`] contract updates can fill a mailbox, and because
    /// eviction is a deterministic function of content they can pick
    /// timestamps that keep their own messages at the top of that order and
    /// hold the space. What changes is the cost curve: the timestamp defect
    /// cost exactly one message and was permanent, whereas this scales with
    /// what an attacker spends, and is the ordinary exposure of any open-write
    /// contract with bounded state. It is reduced here, not closed.
    ///
    /// Closing it needs an authenticated retention signal. The natural one is
    /// a checkpoint signed by the mailbox owner, whose verifying key is
    /// already in `MailboxParameters`: only the owner could advance retention,
    /// and an attacker could prune nothing. This type cannot do that on its
    /// own -- neither `verify` nor `apply_delta` is given
    /// `MailboxParameters`, so a signature cannot be checked from here at all,
    /// and threading the parameters through is a change to the contract's
    /// state interface and to every caller of it. Admission control on writes
    /// (payment, or proof-of-work) is the other direction, and bounds the
    /// flood rather than the retention.
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

        enforce_message_cap(&mut self.messages);

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
        indexed(nonce as u32, secs)
    }

    /// A message whose nonce is derived from `i`, so a test can build more
    /// than 256 distinct ones -- which any test that exercises
    /// [`MAX_MESSAGES`] needs.
    fn indexed(i: u32, secs: i64) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; 32],
            ciphertext: vec![0u8; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// `MAX_MESSAGES + 100` messages, so eviction actually runs.
    fn over_cap() -> Vec<EncryptedMessage> {
        let base = 1_700_000_000;
        (0..(MAX_MESSAGES as u32 + 100))
            .map(|i| indexed(i, base + i as i64))
            .collect()
    }

    /// The property the clock removal exists for: two peers that receive the
    /// same messages in different orders must end up with byte-identical
    /// state. With `Utc::now()` they could not -- each read its own wall clock
    /// and dropped a different set.
    #[test]
    fn merging_is_order_independent() {
        let forward = over_cap();
        let backward: Vec<_> = forward.iter().rev().cloned().collect();

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(forward)).unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(backward)).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "identical messages in a different order must produce identical bytes"
        );
    }

    /// The same property across BATCHING rather than ordering, and the reason
    /// no "cap how far one merge may advance the retention reference" scheme
    /// can work here: peers do not agree on how many merges they performed, so
    /// anything counted per-merge diverges. Everything retention depends on
    /// has to be a pure function of the message set.
    #[test]
    fn merging_is_batch_independent() {
        let all = over_cap();

        let mut one_shot = MailboxStateV1::default();
        one_shot.apply_delta(&Some(all.clone())).unwrap();

        let mut dribbled = MailboxStateV1::default();
        for chunk in all.chunks(7) {
            dribbled.apply_delta(&Some(chunk.to_vec())).unwrap();
        }

        assert_eq!(
            crate::to_cbor(&one_shot).unwrap(),
            crate::to_cbor(&dribbled).unwrap(),
            "the same messages delivered in different batch sizes must produce \
             identical bytes"
        );
    }

    /// Age is not a reason to drop anything any more. The message here is from
    /// the epoch and the mailbox's other traffic is from 2023; under the TTL
    /// rule this replaced, the old one was discarded.
    #[test]
    fn age_alone_never_drops_a_message() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(1, 0), msg(2, base)])).unwrap();
        assert_eq!(m.messages.len(), 2);
        assert!(m.messages.iter().any(|x| x.timestamp.timestamp() == 0));
    }

    /// A mailbox under the cap keeps every message it is given.
    #[test]
    fn a_mailbox_under_the_cap_keeps_everything() {
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

    /// The cap IS checked by `verify`, unlike age: a state can only be over it
    /// if someone built it that way, and `apply_delta` never produces one.
    #[test]
    fn an_over_cap_state_is_rejected() {
        let m = MailboxStateV1 {
            messages: over_cap(),
        };
        assert!(m.verify().is_err());
    }
}

#[cfg(test)]
mod retention_security_tests {
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

    /// Ten years past the honest traffic -- a value any writer may put in a
    /// message, because nothing signs it and the contract has no clock to
    /// check it against.
    const FORGED: i64 = 1_700_000_000 + 10 * 365 * 24 * 3600;

    /// The mailbox is open-write by design: a buyer must be able to reach a
    /// seller they have no prior relationship with. So one unauthenticated
    /// writer must not be able to remove another writer's message.
    #[test]
    fn one_forged_timestamp_cannot_empty_the_mailbox() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(1, base), msg(2, base + 60)]))
            .unwrap();
        assert_eq!(m.messages.len(), 2, "precondition: both messages accepted");

        m.apply_delta(&Some(vec![msg(200, FORGED)])).unwrap();

        assert!(
            m.messages.iter().any(|x| x.nonce == [1u8; 24]),
            "a message dated far in the future must not evict earlier messages"
        );
        assert!(
            m.messages.iter().any(|x| x.nonce == [2u8; 24]),
            "a message dated far in the future must not evict earlier messages"
        );
    }

    /// The half that makes the damage permanent rather than momentary: after a
    /// forged message lands, normally-dated messages must still be accepted.
    /// Otherwise the channel stays dead until real time reaches the forged
    /// date.
    #[test]
    fn a_forged_timestamp_does_not_reject_later_honest_messages() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(200, FORGED)])).unwrap();

        m.apply_delta(&Some(vec![msg(1, base)])).unwrap();

        assert!(
            m.messages.iter().any(|x| x.nonce == [1u8; 24]),
            "an honestly-dated message must survive a mailbox holding a forged one"
        );
    }

    /// Retention has to bound the state, because that is the only thing it was
    /// ever for. With time-based pruning gone, a count cap is what does it.
    #[test]
    fn the_message_cap_bounds_the_state() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        let flood: Vec<_> = (0..MAX_MESSAGES + 50)
            .map(|i| {
                let mut msg = msg(0, base + i as i64);
                msg.nonce = {
                    let mut n = [0u8; 24];
                    n[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    n
                };
                msg
            })
            .collect();
        m.apply_delta(&Some(flood)).unwrap();
        assert_eq!(m.messages.len(), MAX_MESSAGES);
    }
}
