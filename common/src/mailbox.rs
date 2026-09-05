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

/// The largest plaintext that gets padded at all.
///
/// [`pad_to_bucket`] does NOT pad data larger than this -- it returns it with
/// a length prefix and nothing else. That is not a silent hole any more:
/// [`MAX_MESSAGE_BYTES`] is set so that a message whose plaintext exceeded
/// this could not fit, and [`MailboxStateV1::apply_delta`] refuses it. So
/// every message that reaches a mailbox IS padded to a bucket, and the size
/// privacy the buckets buy holds for everything a reader can see.
pub const LARGEST_BUCKET: usize = SIZE_BUCKETS[SIZE_BUCKETS.len() - 1];

/// The AES-256-GCM authentication tag the ciphertext carries beyond its
/// plaintext.
///
/// `harvest-common` does no encryption -- that is `harvest-ui`'s `messaging`
/// -- but it has to size the envelope it stores, and the tag is part of what
/// arrives. A cipher change that altered this would make [`MAX_MESSAGE_BYTES`]
/// refuse legitimate top-bucket messages, which is the safe direction and a
/// loud one.
pub const AEAD_TAG_BYTES: usize = 16;

/// An X25519 public key, which is what a message's routing tag is.
pub const SENDER_KEY_BYTES: usize = 32;

/// A conservative upper bound on the CBOR bytes one message costs beyond its
/// two variable-length fields.
///
/// Measured at 145 bytes for an empty message and 150 for a full one (the
/// difference is CBOR's longer length prefixes), so this carries deliberate
/// slack. The slack is in the safe direction -- it over-charges, so the
/// budget binds slightly early -- and
/// `the_byte_charge_is_never_less_than_the_encoded_size` is what keeps that
/// true rather than this comment.
pub const MESSAGE_ENVELOPE_BYTES: usize = 192;

/// The largest message a mailbox will accept.
///
/// Set to exactly a full top-bucket message so that TWO things follow, rather
/// than being a round number someone picked:
///
/// * every accepted message is padded (see [`LARGEST_BUCKET`]), so the
///   bucketing actually delivers the size privacy it claims; and
/// * no single message can consume the whole of [`MAX_MAILBOX_BYTES`], which
///   is what stops one oversized entry pruning a mailbox to nothing.
///
/// It also bounds `sender_public_key`, which is a `Vec<u8>` on the wire and
/// was otherwise unbounded.
pub const MAX_MESSAGE_BYTES: usize =
    MESSAGE_ENVELOPE_BYTES + SENDER_KEY_BYTES + LARGEST_BUCKET + AEAD_TAG_BYTES;

/// How many bytes of message one mailbox contract will hold.
///
/// # Why a count cap was not a bound
///
/// [`MAX_MESSAGES`] caps entries, and each entry holds a
/// contract-controlled `ciphertext` and a contract-controlled
/// `sender_public_key`. A count cap READS like a memory bound and is not one:
/// multiply it by the largest value the other side may send. Before this
/// existed, `pad_to_bucket` stopped padding above its top bucket rather than
/// refusing, so a single message could be arbitrarily large and a mailbox
/// with it -- 512 entries of no particular size.
///
/// # Why this number
///
/// 512 messages at the smallest bucket -- which is what text traffic
/// produces -- comes to roughly 580 KiB, so honest use never reaches this and
/// the cap binds only on abuse. At the largest bucket it admits about 63
/// messages, which also bounds what a buyer pays to read a mailbox somebody
/// has flooded (see `docs/messaging-privacy.md`).
pub const MAX_MAILBOX_BYTES: usize = 4 * 1024 * 1024;

/// The bytes of a message that are authenticated but not encrypted.
///
/// # Why every field except the ciphertext is bound in
///
/// AES-GCM authenticates what it encrypts and nothing else, so before this
/// existed only `ciphertext` was protected. Every other field of
/// [`EncryptedMessage`] could be edited by anyone who could read the mailbox
/// -- which is everyone -- and the result still authenticated:
///
/// * **`nonce`.** Only its first 12 bytes are the AES-GCM nonce; bytes 12..24
///   are padding that feeds deduplication and nothing else. Randomising them
///   re-submits the same ciphertext as a new message. That is a replay, and
///   it also occupies mailbox slots the attacker cannot read but can refill
///   at will.
/// * **`timestamp`.** It is the primary key of the eviction ranking (see
///   [`enforce_message_cap`]), so re-dating a genuine message moves somebody
///   else's traffic up or down the order that decides what survives a flood.
/// * **`sender_public_key`.** The conversation's routing tag.
/// * **`conversation_id`.** The cleartext copy of the id the ciphertext also
///   carries.
///
/// Binding them costs no wire bytes: associated data is derived from fields
/// that are transmitted anyway, never sent. It is defined here rather than
/// beside the cipher because both ends must derive it identically and this is
/// the crate they share -- the same argument as
/// [`conversation_key_from_dh`], and the same silent failure if they drift.
///
/// # The layout
///
/// A domain-separating label, then fixed-width fields, then the ONE
/// variable-length field last and length-prefixed. That ordering is what
/// makes the encoding unambiguous: no two different messages can produce the
/// same bytes by shifting a boundary.
pub fn message_aad(
    conversation_id: &ConversationId,
    sender_public_key: &[u8],
    timestamp: &DateTime<Utc>,
    nonce: &[u8; 24],
) -> Vec<u8> {
    const LABEL: &[u8] = b"harvest-mailbox-envelope-v1";

    let mut aad = Vec::with_capacity(LABEL.len() + 32 + 24 + 12 + 8 + sender_public_key.len());
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(&conversation_id.0);
    aad.extend_from_slice(nonce);
    // Seconds and sub-second nanoseconds together, so the binding is exact
    // rather than truncated to whatever unit happened to be convenient. Both
    // are infallible, unlike `timestamp_nanos_opt`.
    aad.extend_from_slice(&timestamp.timestamp().to_le_bytes());
    aad.extend_from_slice(&timestamp.timestamp_subsec_nanos().to_le_bytes());
    aad.extend_from_slice(&(sender_public_key.len() as u64).to_le_bytes());
    aad.extend_from_slice(sender_public_key);
    aad
}

/// [`message_aad`] for a message that already exists, which is what the
/// decrypting side has.
pub fn message_aad_for(message: &EncryptedMessage) -> Vec<u8> {
    message_aad(
        &message.conversation_id,
        &message.sender_public_key,
        &message.timestamp,
        &message.nonce,
    )
}

/// **No single message may consume the mailbox.**
///
/// The fact `enforce_message_cap`'s prefix rule rests on, held by the
/// compiler rather than by a test: if one message could fill the budget, and
/// it ranked first -- which is free, because timestamps are unsigned -- the
/// mailbox would prune to nothing behind it. Retuning either constant into
/// that corner fails the BUILD rather than a test somebody might not run.
const _: () = assert!(
    MAX_MESSAGE_BYTES * 2 <= MAX_MAILBOX_BYTES,
    "one message must not be able to crowd out every other"
);

/// What one message costs against [`MAX_MAILBOX_BYTES`].
///
/// Both variable-length fields are charged, plus a constant envelope. It is a
/// model of the CBOR size rather than the CBOR size itself, because computing
/// the real thing means serializing every message on every merge -- and
/// because a model that can be proved to over-charge is a bound, whereas one
/// that might under-charge is a proxy. `the_byte_charge_is_never_less_than_
/// the_encoded_size` is what makes it the former.
pub fn message_bytes(message: &EncryptedMessage) -> usize {
    MESSAGE_ENVELOPE_BYTES + message.sender_public_key.len() + message.ciphertext.len()
}

/// Pad data to the next size bucket boundary. Returns the padded data.
/// The first 4 bytes encode the original length (little-endian u32) so the
/// receiver can strip padding.
///
/// **Data larger than [`LARGEST_BUCKET`] is NOT padded** -- it comes back with
/// a length prefix and nothing else, so its size is exactly its size and the
/// bucketing provides no privacy for it whatsoever.
///
/// That used to be a silent hole; it is now closed at the other end.
/// [`MAX_MESSAGE_BYTES`] is set to exactly a full top-bucket message, so a
/// message built from unpadded data cannot fit in a mailbox and
/// [`MailboxStateV1::apply_delta`] drops it. Every message a reader can see
/// has therefore been padded. Pinned by
/// `every_message_a_mailbox_accepts_has_been_padded`.
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

/// Which way along a conversation a message travels.
///
/// # Why the two directions do not share a key
///
/// Both ends compute the same X25519 shared secret, so a single key derived
/// from it would encrypt and decrypt in both directions -- and then **a copy
/// of the buyer's own message reads as a reply from the seller**. Anyone can
/// read the mailbox and anyone can write to it, so mounting that is a copy
/// and a paste: no key, no relationship with either party. What the buyer
/// would see is a reply, in the seller's own mailbox, decrypting correctly,
/// saying whatever the buyer had earlier said. In the phase this mechanism
/// exists for, the thing the seller sends back is the buyer's sole
/// authorization to complain, so "a message that reads as coming from the
/// seller" is not a cosmetic confusion.
///
/// Separating the directions makes that impossible rather than detectable: a
/// buyer-to-seller ciphertext simply does not authenticate under the
/// seller-to-buyer key. It costs one BLAKE3 invocation and no wire bytes.
///
/// Replay is separately impossible, but NOT for the reason this comment gave
/// until 2026-09-05. It said that changing the nonce to evade dedup changes
/// the AES nonce with it -- true only of the first 12 of the 24 bytes. Bytes
/// 12..24 fed deduplication and nothing else, so randomising them resubmitted
/// the same ciphertext as a new message, and it was verified working. What
/// closes it is [`message_aad`], which authenticates the whole envelope.
/// Neither of those is what direction separation guards; this guards the
/// direction.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageDirection {
    /// Written by the buyer, read by the seller.
    BuyerToSeller,
    /// Written by the seller, read by the buyer.
    SellerToBuyer,
}

impl MessageDirection {
    /// The BLAKE3 key-derivation context for this direction.
    ///
    /// Contexts are hard-coded, globally unique strings, as BLAKE3's
    /// `derive_key` requires. They carry a date and a version because
    /// changing one silently breaks every conversation in flight -- so a
    /// future change must add a context rather than edit one, and this is
    /// where a reader finds that out.
    const fn context(self) -> &'static str {
        match self {
            MessageDirection::BuyerToSeller => "harvest mailbox v1 2026-09-05 buyer-to-seller",
            MessageDirection::SellerToBuyer => "harvest mailbox v1 2026-09-05 seller-to-buyer",
        }
    }
}

/// Turn a raw X25519 shared secret into the AES-256 key one direction of a
/// conversation uses.
///
/// # Why this is in `harvest-common` rather than beside either caller
///
/// The two ends run in different crates and on different machines. A buyer's
/// browser computes it from an ephemeral secret it generated
/// (`harvest-ui`'s `messaging::BuyerConversation`); the seller's harvest
/// delegate computes it from the long-term secret it holds, because that
/// secret must not leave the delegate. If those two derivations ever disagree
/// -- one adds a domain separator, one changes hash -- nothing errors: the
/// AES-GCM tag simply fails to verify and every message in the conversation
/// reads as corrupt, on both sides, forever. There is no negotiation and no
/// version byte to catch it.
///
/// So it is written once, here, and pinned by known-answer tests whose
/// expected values came from an independent BLAKE3 implementation rather than
/// from this function.
pub fn conversation_key_from_dh(shared_secret: &[u8; 32], direction: MessageDirection) -> [u8; 32] {
    blake3::derive_key(direction.context(), shared_secret)
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
    /// **The BUYER's ephemeral X25519 public key for this conversation, in
    /// both directions.** The field name predates replies and is kept because
    /// renaming it changes the CBOR and orphans every mailbox already on the
    /// network.
    ///
    /// For a buyer-to-seller message it is the sender's key, which is what
    /// the name says. For a seller's reply it is the RECIPIENT's -- the
    /// seller echoes the buyer's key back rather than naming themselves.
    ///
    /// It is the conversation's routing tag: the only field in the clear that
    /// says which conversation a message belongs to.
    /// [`ConversationId`] cannot do that job because it is inside the
    /// ciphertext, which is the whole point of it.
    ///
    /// Buyers MUST use a fresh ephemeral key per store to prevent cross-store
    /// linkability.
    ///
    /// # What echoing it costs
    ///
    /// An observer can pair a reply with the message it answers, so the
    /// thread structure of a conversation is public: how many messages, in
    /// which direction, and when. What it does NOT reveal is who either party
    /// is -- the key is freshly random per conversation and tied to no
    /// identity -- or what was said.
    ///
    /// The alternative is a tag nobody can link, which costs the buyer a
    /// decryption attempt against every entry in the mailbox rather than
    /// against their own conversation. Both were considered; the leak is
    /// small next to what a public per-store mailbox reveals anyway (entry
    /// count, arrival times, padded sizes), and it is written down in
    /// `docs/messaging-privacy.md` rather than left implicit.
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
    ///
    /// `pub(crate)` on purpose -- see [`MailboxParameters::new`].
    pub(crate) owner_verifying_key: VerifyingKey,
}

impl MailboxParameters {
    /// The only way to build these parameters from outside `harvest-common`.
    ///
    /// The field set of this struct is hashed into the mailbox's address, so a
    /// second place building it by hand can address a different contract. See
    /// [`crate::store::StoreParameters::new`] for the incident that argument
    /// comes from.
    pub fn new(owner_verifying_key: VerifyingKey) -> Self {
        Self {
            owner_verifying_key,
        }
    }
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

/// Drop the lowest-ranked messages until `messages` satisfies BOTH
/// [`MAX_MESSAGES`] and [`MAX_MAILBOX_BYTES`].
///
/// Rank is `(timestamp, nonce)`, highest kept. Both fields are chosen by
/// whoever wrote the message, so this ordering is grindable and is not offered
/// as a defence -- see [`MailboxStateV1::apply_delta`] for what the caps do
/// and do not buy. What it has to be is *total* and a pure function of
/// message content, so that two replicas holding the same set of messages keep
/// the same subset. Ranking by anything else available here has the same
/// property and the same weakness, and `(timestamp, nonce)` at least leaves a
/// mailbox carrying only honest traffic behaving as a recency window, which is
/// what the age-based rule it replaces was for.
///
/// # Why both caps are one pass, and why the kept set is a PREFIX
///
/// The kept set is the longest prefix of that ranking which satisfies both
/// budgets: the walk stops at the first message that does not fit rather than
/// skipping it and trying smaller ones behind it. Packing greedily would keep
/// more bytes, and it would also mean a lower-ranked message could survive
/// while a higher-ranked one was dropped -- a rule that is still
/// deterministic, but whose convergence argument is a bin-packing walk rather
/// than "both peers keep the same prefix of the same total order". The
/// simpler argument is worth more here than the extra bytes, because
/// divergence in this function is silent and permanent.
///
/// A prefix rule has one failure mode, and it is closed elsewhere rather than
/// here: if the FIRST message did not fit, nothing would be kept at all. That
/// is why [`MAX_MESSAGE_BYTES`] is far below [`MAX_MAILBOX_BYTES`] and why
/// [`MailboxStateV1::apply_delta`] refuses an oversized message on the way in
/// -- an attacker can put their message at the top of this ranking for free,
/// so "one message empties the mailbox" would have been cheaper and more
/// total than the unbounded growth the budget exists to stop.
/// Keep one message per nonce, chosen by CONTENT rather than by arrival.
///
/// # Why this exists at all
///
/// [`MailboxStateV1::verify`] rejects a state holding a duplicate nonce, so a
/// state carrying one is permanently invalid: it cannot be updated, cannot
/// converge, and pruning never removes it, because pruning truncates a sorted
/// prefix and both copies sit in it together. Producing such a state has to
/// be impossible here, and it was not: the dedup set used to be snapshotted
/// from `self.messages` before the loop and never updated inside it, so a
/// delta naming one message twice stored both. One contract update, no key,
/// no relationship with either party.
///
/// # Why the winner is decided by content
///
/// Two DIFFERENT messages may share a nonce -- an attacker submits both, in
/// different orders, to different peers. First-arrival-wins makes the two
/// peers keep different bytes forever, which for a contract is as bad as
/// invalidity and much harder to notice. So the survivor is the one that
/// ranks highest under a total order over the fields, and both peers reach it
/// from the same set regardless of the order they saw it in.
///
/// The order is `(timestamp, ciphertext, sender_public_key, conversation_id)`,
/// which is total because it ends in fields that together cannot tie without
/// the messages being equal. Like every other ranking here it is made of
/// attacker-chosen values and is not offered as a defence -- it is offered as
/// a function of the SET, which is what convergence needs.
fn dedupe_by_nonce(messages: &mut Vec<EncryptedMessage>) {
    messages.sort_by(|a, b| {
        a.nonce.cmp(&b.nonce).then_with(|| {
            b.timestamp
                .cmp(&a.timestamp)
                .then_with(|| b.ciphertext.cmp(&a.ciphertext))
                .then_with(|| b.sender_public_key.cmp(&a.sender_public_key))
                .then_with(|| b.conversation_id.0.cmp(&a.conversation_id.0))
        })
    });
    // Duplicates are now adjacent with the winner first, so this keeps the
    // winner and drops the rest.
    messages.dedup_by(|later, kept| later.nonce == kept.nonce);
}

fn enforce_message_cap(messages: &mut Vec<EncryptedMessage>) {
    let over_count = messages.len() > MAX_MESSAGES;
    let over_bytes = messages.iter().map(message_bytes).sum::<usize>() > MAX_MAILBOX_BYTES;
    if !over_count && !over_bytes {
        return;
    }

    messages.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.nonce.cmp(&a.nonce))
    });

    let mut bytes = 0usize;
    let mut kept = 0usize;
    for message in messages.iter() {
        if kept == MAX_MESSAGES {
            break;
        }
        let with_this = bytes + message_bytes(message);
        if with_this > MAX_MAILBOX_BYTES {
            break;
        }
        bytes = with_this;
        kept += 1;
    }
    messages.truncate(kept);
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
            for msg in new_messages {
                // Refused rather than stored and pruned. Storing it first
                // would put it at the head of the eviction ranking (its
                // timestamp is free to choose) and prune the mailbox to
                // nothing behind it -- see `enforce_message_cap`. Dropping an
                // incoming message is recoverable in a way that invalidating
                // existing state is not, which is the same reason `verify`
                // does not check the byte budget at all.
                if message_bytes(msg) > MAX_MESSAGE_BYTES {
                    continue;
                }
                self.messages.push(msg.clone());
            }
        }

        // Everything is pushed and THEN deduplicated, rather than filtered on
        // the way in against a set captured beforehand. That shape is what
        // produced a state `verify` rejects: the set did not learn about the
        // messages the loop itself added, so one delta naming a message twice
        // stored both. Deduplicating the whole collection afterwards cannot
        // have that defect, and it also REPAIRS a state that already carries
        // a duplicate -- which matters, because this was live on `main` and a
        // mailbox on the network may be holding one now.
        //
        // It runs before the cap, not after, so a duplicate cannot occupy two
        // of the slots the cap is about to hand out.
        dedupe_by_nonce(&mut self.messages);
        enforce_message_cap(&mut self.messages);

        // Sort deterministically by nonce for CRDT convergence
        self.messages.sort_by(|a, b| a.nonce.cmp(&b.nonce));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer tests for the one function both ends of a conversation
    /// must compute identically.
    ///
    /// The expected values are `b3sum --derive-key <context>` over 32 bytes
    /// of `0x07`, taken from the `b3sum` CLI rather than from this crate -- a
    /// test that asks the implementation what it does and then asserts it
    /// does that would pass under any change at all, which is exactly the
    /// failure this repository keeps finding.
    ///
    /// If these go red, do not update the constants. A changed derivation
    /// makes every existing conversation permanently undecryptable in both
    /// directions, with no error anywhere -- just AES-GCM tags that stop
    /// verifying. Add a context, do not edit one.
    ///
    /// Observed red on 2026-09-05 against the undirected predecessor
    /// (`blake3::hash`, one key for both directions).
    #[test]
    fn the_conversation_key_derivation_is_pinned() {
        assert_eq!(
            conversation_key_from_dh(&[7u8; 32], MessageDirection::BuyerToSeller),
            hex_literal("efd38d9d8791a47b0c4e3be38542cb297b25167aa680d84b9be0ef51dfe202c1"),
        );
        assert_eq!(
            conversation_key_from_dh(&[7u8; 32], MessageDirection::SellerToBuyer),
            hex_literal("6565da998392cff761fc670a61bb365826b464e99449827bd1f4631033ab96a2"),
        );
    }

    /// **The two directions must not share a key.**
    ///
    /// Stated separately from the known-answer tests because it is the
    /// property, and the constants above are only one way of holding it: a
    /// future edit that changed both contexts to the same string would update
    /// two constants and keep this test red.
    #[test]
    fn the_two_directions_do_not_share_a_key() {
        let secret = [7u8; 32];
        assert_ne!(
            conversation_key_from_dh(&secret, MessageDirection::BuyerToSeller),
            conversation_key_from_dh(&secret, MessageDirection::SellerToBuyer),
            "one key for both directions means a copy of the buyer's own message reads as \
             a reply from the seller"
        );
    }

    /// Parse a hex string into 32 bytes, so the constants above can be read
    /// against `b3sum`'s output without transcribing them into byte syntax.
    fn hex_literal(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        bytes.try_into().expect("32 bytes")
    }

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

    /// A message whose nonce is derived from `i`, so a flood can be built out
    /// of more than 256 distinct messages.
    fn indexed(i: u32, secs: i64) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            nonce,
            ..msg(0, secs)
        }
    }

    /// **THIS TEST PINS A KNOWN GAP. IF IT FAILS, THAT IS GOOD NEWS.**
    ///
    /// It asserts what the mailbox does TODAY, which is the wrong thing: a
    /// funded attacker still evicts every honest message. It exists so that
    /// closing the gap cannot happen quietly -- whoever closes it will see
    /// this go red, and the correct response is to invert the assertions and
    /// rewrite this comment, not to make the test pass again.
    ///
    /// The gap: `enforce_message_cap` ranks by `(timestamp, nonce)`, and both
    /// are chosen by whoever wrote the message. Nothing authenticates who may
    /// occupy space in an open-write mailbox, so an attacker who pays for
    /// [`MAX_MESSAGES`] contract updates, each dated later than the honest
    /// traffic, holds every slot. `MailboxStateV1::apply_delta` documents this
    /// in prose; this is the executable half.
    ///
    /// What would close it, and so break this test: admission control on
    /// writes (payment or proof-of-work), a per-sender quota, or an
    /// owner-authenticated notion of which messages are protected. Note that
    /// an owner-signed *retention checkpoint* alone would NOT break it -- that
    /// closes the separate question of reintroducing time-based retention
    /// safely, and a flood still fills the cap underneath it. Any of these
    /// needs something `apply_delta` does not currently receive, which is why
    /// the gap is open rather than merely unfixed: neither `verify` nor
    /// `apply_delta` is given `MailboxParameters`, so the owner's verifying
    /// key -- the only authenticated identity this contract has -- is not
    /// reachable from the code that would have to use it.
    ///
    /// The second half of the test is the PRICE, and it is the part that
    /// silently rots if the cap is retuned: one message short of the cap
    /// evicts nothing. That is the whole difference from the timestamp defect
    /// this replaced, where the price was one message.
    #[test]
    fn known_gap_a_funded_flood_still_evicts_every_honest_message() {
        let base = 1_700_000_000;
        let honest = || {
            vec![
                indexed(1, base),
                indexed(2, base + 60),
                indexed(3, base + 120),
            ]
        };
        // Dated after the honest traffic, which is free: nothing signs a
        // timestamp. Ranking highest-first is what makes these the survivors.
        let flood = |count: u32| -> Vec<EncryptedMessage> {
            (0..count)
                .map(|i| indexed(1_000 + i, base + 1_000_000 + i as i64))
                .collect()
        };

        // The price. One short of filling the cap, and every honest message
        // is still there -- an attacker gets nothing for a partial spend.
        let mut under = MailboxStateV1::default();
        under.apply_delta(&Some(honest())).unwrap();
        under
            .apply_delta(&Some(flood(MAX_MESSAGES as u32 - 3)))
            .unwrap();
        assert_eq!(under.messages.len(), MAX_MESSAGES);
        for honest_nonce in honest().iter().map(|m| m.nonce) {
            assert!(
                under.messages.iter().any(|m| m.nonce == honest_nonce),
                "a flood that does not fill the cap must evict nothing"
            );
        }

        // The gap. Pay for a full cap's worth and the honest messages are
        // gone. THIS IS THE ASSERTION TO INVERT when the gap closes.
        let mut over = MailboxStateV1::default();
        over.apply_delta(&Some(honest())).unwrap();
        over.apply_delta(&Some(flood(MAX_MESSAGES as u32))).unwrap();
        assert_eq!(over.messages.len(), MAX_MESSAGES);
        for honest_nonce in honest().iter().map(|m| m.nonce) {
            assert!(
                !over.messages.iter().any(|m| m.nonce == honest_nonce),
                "KNOWN GAP no longer reproduces: an honest message survived a \
                 full-cap flood. If you just made that happen, invert this \
                 assertion -- the mailbox now resists a funded flood."
            );
        }
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

/// The byte budget: that it exists, that pruning is how it is met, and the
/// two things that would break if either changed.
#[cfg(test)]
mod byte_budget_tests {
    use super::*;

    fn total_bytes(state: &MailboxStateV1) -> usize {
        state.messages.iter().map(message_bytes).sum()
    }

    /// A message of `ciphertext` bytes, distinct by index.
    fn sized(i: u32, secs: i64, ciphertext: usize) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; SENDER_KEY_BYTES],
            ciphertext: vec![0u8; ciphertext],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// Enough top-bucket messages to blow the byte budget several times over
    /// while staying under the COUNT cap -- so a failure here is about bytes
    /// and cannot be the count cap doing the work.
    fn over_budget_but_under_count() -> Vec<EncryptedMessage> {
        let base = 1_700_000_000;
        let count = (MAX_MAILBOX_BYTES / MAX_MESSAGE_BYTES) * 3;
        assert!(
            count < MAX_MESSAGES,
            "this fixture must not rely on the count cap"
        );
        (0..count as u32)
            .map(|i| sized(i, base + i as i64, LARGEST_BUCKET + AEAD_TAG_BYTES))
            .collect()
    }

    /// The bound itself.
    ///
    /// Observed red on 2026-09-05 against `enforce_message_cap` as it was --
    /// count-only -- which kept every one of these.
    #[test]
    fn the_mailbox_is_bounded_in_bytes_and_not_only_in_count() {
        let flood = over_budget_but_under_count();
        let uncapped: usize = flood.iter().map(message_bytes).sum();
        assert!(
            uncapped > MAX_MAILBOX_BYTES,
            "precondition: the fixture must exceed the budget"
        );

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(flood)).unwrap();

        assert!(
            total_bytes(&m) <= MAX_MAILBOX_BYTES,
            "mailbox holds {} bytes, budget is {MAX_MAILBOX_BYTES}",
            total_bytes(&m)
        );
        assert!(
            !m.messages.is_empty(),
            "pruning to the budget must not empty the mailbox"
        );
    }

    /// **Convergence across the byte budget**, which is the property that
    /// matters: two peers given the same messages in different ORDERS must
    /// prune to byte-identical state.
    ///
    /// The existing `merging_is_order_independent` crosses the count cap
    /// only. A byte budget met by a different rule -- one that packed
    /// greedily by size, say -- could satisfy that test and diverge here.
    #[test]
    fn merging_is_order_independent_across_the_byte_budget() {
        let forward = over_budget_but_under_count();
        let backward: Vec<_> = forward.iter().rev().cloned().collect();

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(forward)).unwrap();
        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(backward)).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "the same messages in a different order pruned to different state"
        );
    }

    /// The same across BATCHING, for the reason the count-cap version gives:
    /// peers do not agree on how many merges they performed, so anything
    /// counted per-merge diverges.
    #[test]
    fn merging_is_batch_independent_across_the_byte_budget() {
        let all = over_budget_but_under_count();

        let mut one_shot = MailboxStateV1::default();
        one_shot.apply_delta(&Some(all.clone())).unwrap();

        let mut dribbled = MailboxStateV1::default();
        for chunk in all.chunks(3) {
            dribbled.apply_delta(&Some(chunk.to_vec())).unwrap();
        }

        assert_eq!(
            crate::to_cbor(&one_shot).unwrap(),
            crate::to_cbor(&dribbled).unwrap(),
            "the same messages in different batch sizes pruned to different state"
        );
    }

    /// **One oversized message must not empty the mailbox.**
    ///
    /// Pruning keeps a prefix of the ranking, so if the highest-ranked
    /// message did not fit, nothing after it would be reached and the mailbox
    /// would prune to nothing. An attacker who can pick a timestamp can put
    /// their message at the top of that ranking for free, so this would have
    /// been a cheaper and more total attack than the unbounded growth the
    /// budget exists to stop.
    ///
    /// It is closed by refusing the message on the way in rather than by
    /// special-casing the pruning: `MAX_MESSAGE_BYTES` is far below
    /// `MAX_MAILBOX_BYTES`, so the first-message-does-not-fit case is
    /// unreachable.
    #[test]
    fn an_oversized_message_is_refused_rather_than_emptying_the_mailbox() {
        let base = 1_700_000_000;
        let honest = vec![sized(1, base, 1024), sized(2, base + 60, 1024)];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(honest)).unwrap();
        assert_eq!(m.messages.len(), 2, "precondition");

        // Dated after the honest traffic, which is free, so ranking cannot
        // save us -- and larger than the whole budget.
        let mut monster = sized(99, base + 1_000_000, MAX_MAILBOX_BYTES * 2);
        monster.nonce = [0xFF; 24];
        m.apply_delta(&Some(vec![monster])).unwrap();

        assert_eq!(
            m.messages.len(),
            2,
            "an oversized message must be refused, not stored and not fatal"
        );
        assert!(total_bytes(&m) <= MAX_MAILBOX_BYTES);
    }

    /// A message with an absurd routing tag is refused by the same rule --
    /// `sender_public_key` is a `Vec<u8>` on the wire and nothing else
    /// bounds it.
    #[test]
    fn an_oversized_routing_tag_is_refused() {
        let mut message = sized(1, 1_700_000_000, 64);
        message.sender_public_key = vec![7u8; MAX_MESSAGE_BYTES];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![message])).unwrap();
        assert!(m.messages.is_empty());
    }

    /// **The accounting must never under-charge**, or the budget is a proxy
    /// rather than a bound.
    ///
    /// Checked against the real CBOR encoding across the shapes that vary:
    /// empty, small, top-bucket, and a far-future timestamp (which encodes
    /// longer).
    #[test]
    fn the_byte_charge_is_never_less_than_the_encoded_size() {
        let mut shapes = vec![
            sized(0, 0, 0),
            sized(1, 1_700_000_000, 1024 + AEAD_TAG_BYTES),
            sized(2, 1_700_000_000, LARGEST_BUCKET + AEAD_TAG_BYTES),
        ];
        let mut late = sized(3, 253_402_300_000, LARGEST_BUCKET + AEAD_TAG_BYTES);
        late.timestamp = DateTime::from_timestamp(253_402_300_000, 999_000_000).unwrap();
        shapes.push(late);
        let mut empty_tag = sized(4, 1_700_000_000, 64);
        empty_tag.sender_public_key = Vec::new();
        shapes.push(empty_tag);

        for message in shapes {
            let encoded = crate::to_cbor(&message).unwrap().len();
            assert!(
                message_bytes(&message) >= encoded,
                "charged {} for a message that encodes to {encoded}",
                message_bytes(&message)
            );
        }
    }

    /// Every message a mailbox accepts has been padded to a bucket, so the
    /// size privacy the buckets claim holds for everything a reader sees.
    ///
    /// The link is `MAX_MESSAGE_BYTES`: it is exactly a full top-bucket
    /// message, so a message built from data `pad_to_bucket` declined to pad
    /// cannot fit. Raise the constant and this goes red.
    #[test]
    fn every_message_a_mailbox_accepts_has_been_padded() {
        // The smallest plaintext `pad_to_bucket` refuses to pad.
        let unpadded = pad_to_bucket(&vec![0u8; LARGEST_BUCKET]);
        assert!(
            unpadded.len() > LARGEST_BUCKET,
            "precondition: this size is past the top bucket"
        );

        let message = sized(1, 1_700_000_000, unpadded.len() + AEAD_TAG_BYTES);
        assert!(
            message_bytes(&message) > MAX_MESSAGE_BYTES,
            "an unpadded message must not fit in a mailbox"
        );

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![message])).unwrap();
        assert!(m.messages.is_empty());
    }

    /// **`verify` deliberately does NOT check the byte budget.**
    ///
    /// The count cap IS checked there, and the argument given for it is that
    /// `apply_delta` never produces an over-cap state, so only a hand-built
    /// state is rejected. That argument does not transfer, and the difference
    /// is what this test exists to hold: the count cap has been enforced
    /// since the mailbox existed, so no honest state was ever over it. The
    /// byte budget is NEW. Mailboxes already on the network were produced by
    /// an honest `apply_delta` under the old rules and may exceed it, and a
    /// `verify` that rejected them would make them permanently invalid --
    /// never convergeable again, with no way back. That is a worse failure
    /// than the unbounded growth being fixed, and this repository has already
    /// been bitten by exactly it once (the TTL check that rejected a whole
    /// mailbox because one message had aged out).
    ///
    /// So an over-budget state is accepted and pruned on the next merge,
    /// which only ever shrinks it.
    ///
    /// **Residual, stated rather than discovered later:** between arriving
    /// and the next update, a peer may hold an over-budget state. Nothing
    /// here bounds that; the node's own maximum state size does.
    #[test]
    fn verify_accepts_an_over_budget_state_so_an_existing_mailbox_is_never_stranded() {
        let m = MailboxStateV1 {
            messages: over_budget_but_under_count(),
        };
        assert!(
            total_bytes(&m) > MAX_MAILBOX_BYTES,
            "precondition: the fixture is over budget"
        );
        assert!(
            m.verify().is_ok(),
            "a state that was legal when it was written must not become permanently invalid"
        );
    }

    /// **THIS TEST PINS A KNOWN GAP, AND IT IS ONE THIS CHANGE MADE WORSE.**
    ///
    /// `enforce_message_cap` ranks by `(timestamp, nonce)`, both chosen by
    /// whoever wrote the message, so eviction is grindable -- that was
    /// already true and is pinned by
    /// `known_gap_a_funded_flood_still_evicts_every_honest_message`.
    ///
    /// What the byte budget changes is the PRICE. Filling the count cap took
    /// [`MAX_MESSAGES`] contract updates; filling the byte budget takes about
    /// [`MAX_MAILBOX_BYTES`] / [`MAX_MESSAGE_BYTES`] of them, roughly 63 --
    /// an eighth of the updates for the same total eviction. The budget bounds
    /// what a flood costs the NETWORK and cheapens what it costs the
    /// ATTACKER, and both halves are real.
    ///
    /// That is a deliberate trade and not an oversight: unbounded state is
    /// the worse of the two, and the flood was already affordable. It is
    /// recorded here so that closing the flood gap is understood to need
    /// admission control -- payment, proof-of-work, or a per-sender quota --
    /// rather than a retuned cap.
    #[test]
    fn known_gap_a_byte_budget_flood_evicts_with_far_fewer_messages() {
        let base = 1_700_000_000;
        let honest: Vec<_> = (0..3).map(|i| sized(i, base + i as i64, 1024)).collect();

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(honest.clone())).unwrap();

        // Dated after the honest traffic, which is free.
        let flood: Vec<_> = (0..(MAX_MAILBOX_BYTES / MAX_MESSAGE_BYTES + 1) as u32)
            .map(|i| {
                sized(
                    1_000 + i,
                    base + 1_000_000 + i as i64,
                    LARGEST_BUCKET + AEAD_TAG_BYTES,
                )
            })
            .collect();
        let flood_size = flood.len();
        assert!(
            flood_size <= MAX_MESSAGES / 4,
            "the point of this test is that the flood is far smaller than the count cap: \
             {flood_size} vs {MAX_MESSAGES}"
        );

        m.apply_delta(&Some(flood)).unwrap();

        for honest_nonce in honest.iter().map(|h| h.nonce) {
            assert!(
                !m.messages.iter().any(|kept| kept.nonce == honest_nonce),
                "KNOWN GAP no longer reproduces: an honest message survived a byte-budget \
                 flood of {flood_size} messages. If you just made that happen, invert this \
                 assertion."
            );
        }
    }
}

/// Nonce deduplication: the thing `verify` rejects a state for, and therefore
/// the thing `apply_delta` must never produce.
#[cfg(test)]
mod dedup_tests {
    use super::*;

    fn message(nonce: [u8; 24], secs: i64, ciphertext: u8) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; SENDER_KEY_BYTES],
            ciphertext: vec![ciphertext; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// **A delta naming one message twice must not brick the mailbox.**
    ///
    /// `verify` rejects a state holding a duplicate nonce, and pruning only
    /// truncates a sorted prefix -- it never removes a duplicate -- so both
    /// copies survive together and no later merge repairs it. The mailbox is
    /// then permanently invalid: it cannot be updated, cannot converge, and
    /// there is no way back.
    ///
    /// The cost is one contract update with no key and no relationship to
    /// either party, because both of the mailbox contract's update paths hand
    /// attacker bytes to this function: `UpdateData::Delta` deserialises them
    /// straight into a `MailboxDelta`, and `UpdateData::State` filters the
    /// incoming state against what is already held but not against itself.
    ///
    /// Observed red on 2026-09-05 against the snapshot-before-the-loop form,
    /// which is what shipped: `duplicate message nonce`.
    #[test]
    fn a_delta_naming_one_message_twice_leaves_a_valid_state() {
        let twice = message([7u8; 24], 1_700_000_000, 0xAA);

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![twice.clone(), twice.clone()]))
            .unwrap();

        assert_eq!(m.messages.len(), 1, "one message, stored once");
        m.verify()
            .expect("apply_delta must never produce a state verify rejects");
    }

    /// The same through the path a hostile `UpdateData::State` takes: the
    /// contract filters the incoming state against what it already holds and
    /// hands the rest here, so internal duplicates arrive intact.
    #[test]
    fn a_delta_carrying_many_copies_of_one_message_leaves_a_valid_state() {
        let flood = vec![message([3u8; 24], 1_700_000_000, 0xBB); 64];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(flood)).unwrap();

        assert_eq!(m.messages.len(), 1);
        m.verify().expect("still valid");
    }

    /// **A mailbox already bricked must repair itself on the next merge.**
    ///
    /// This defect is pre-existing on `main`, so a mailbox on the live
    /// network can be holding a duplicate right now. Fixing only the
    /// production of duplicates would leave those permanently invalid, which
    /// is the outcome the fix exists to prevent.
    #[test]
    fn an_already_duplicated_state_is_repaired_by_the_next_merge() {
        let duplicated = message([5u8; 24], 1_700_000_000, 0xCC);
        let mut m = MailboxStateV1 {
            messages: vec![duplicated.clone(), duplicated],
        };
        assert!(m.verify().is_err(), "precondition: this state is invalid");

        m.apply_delta(&None).unwrap();

        assert_eq!(m.messages.len(), 1);
        m.verify().expect("a merge must heal a state it can heal");
    }

    /// **Two DIFFERENT messages sharing a nonce must converge.**
    ///
    /// A separate defect from the one above and reachable the same way: an
    /// attacker submits both, in different orders, to different peers. If the
    /// winner is decided by arrival order, the two peers keep different bytes
    /// and never converge -- which for a contract is as bad as invalidity and
    /// harder to notice.
    ///
    /// Observed red on 2026-09-05 against first-arrival-wins, which is what
    /// the snapshot form did across batches.
    #[test]
    fn two_different_messages_sharing_a_nonce_converge() {
        let one = message([2u8; 24], 1_700_000_000, 0x11);
        let other = message([2u8; 24], 1_700_000_000, 0x22);

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(vec![one.clone()])).unwrap();
        a.apply_delta(&Some(vec![other.clone()])).unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(vec![other])).unwrap();
        b.apply_delta(&Some(vec![one])).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "two peers given the same pair in different orders kept different bytes"
        );
        a.verify().expect("valid");
    }

    /// And within a single delta, for the same reason.
    #[test]
    fn a_nonce_collision_inside_one_delta_converges() {
        let one = message([4u8; 24], 1_700_000_000, 0x33);
        let other = message([4u8; 24], 1_700_000_000, 0x44);

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(vec![one.clone(), other.clone()]))
            .unwrap();
        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(vec![other, one])).unwrap();

        assert_eq!(crate::to_cbor(&a).unwrap(), crate::to_cbor(&b).unwrap());
    }

    /// Deduplication must not swallow distinct messages -- the guard above is
    /// only worth having if ordinary traffic still lands.
    #[test]
    fn distinct_messages_are_all_kept() {
        let base = 1_700_000_000;
        let messages: Vec<_> = (0..8u8)
            .map(|i| message([i; 24], base + i as i64, i))
            .collect();

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(messages)).unwrap();

        assert_eq!(m.messages.len(), 8);
        m.verify().expect("valid");
    }
}
