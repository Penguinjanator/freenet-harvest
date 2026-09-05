//! Encrypted messaging for buyer-seller communication.
//!
//! Uses X25519 key exchange + AES-256-GCM for end-to-end encryption.
//! Messages are padded to size buckets before encryption to reduce
//! traffic analysis (see harvest_common::mailbox::pad_to_bucket).
//!
//! # The exchange is one-sided, and that is the design
//!
//! A buyer has no identity in Harvest -- no ghostkey, no account, nothing to
//! register -- so there is nobody to run a two-sided handshake with. Instead
//! the SELLER publishes a long-term X25519 public key in
//! [`harvest_common::store::StoreInfoV1::encryption_public_key`], and each
//! buyer generates an ephemeral keypair per message, encrypts to the seller's
//! key, and writes the result into the seller's mailbox contract along with
//! their ephemeral PUBLIC key. The seller's harvest delegate holds the
//! matching secret and answers the derived conversation key; nothing else
//! ever sees it.
//!
//! # Replies, and why they need no buyer mailbox
//!
//! Contract state is public and the mailbox is open-write, so the seller
//! replies **into their own mailbox**, encrypted under the same conversation
//! the buyer opened. The buyer already knows that mailbox's address -- they
//! derived it to send in the first place -- and reads their replies out of
//! it. No buyer mailbox, no buyer identity, no second contract.
//!
//! Two things make that work rather than merely sound plausible:
//!
//! * **Direction separation.** Both ends compute one X25519 shared secret, so
//!   a single key would decrypt in both directions and a copy of the buyer's
//!   own message would read as a reply from the seller. The two directions
//!   get different keys; see [`harvest_common::mailbox::MessageDirection`].
//! * **A routing tag in the clear.** The buyer's ephemeral public key rides on
//!   every message in the conversation, in both directions, so the buyer
//!   finds their own thread without attempting to decrypt the whole mailbox.
//!   What that leaks is written down on
//!   [`harvest_common::mailbox::EncryptedMessage::sender_public_key`] and in
//!   `docs/messaging-privacy.md`.
//!
//! # What this module does NOT do
//!
//! **Survive a reload.** The buyer's conversation keys live in the tab and
//! nowhere else. There is no buyer delegate, and `localStorage` throws inside
//! the gateway's sandboxed iframe, so there is nowhere durable to put them. A
//! buyer who reloads before the seller answers can never read that reply --
//! the ciphertext is in the mailbox forever and the key is gone. This is the
//! sharpest remaining limitation and `components::message_view` says it on
//! screen.
//!
//! **Anything for a seller who has published no key.** `encryption_public_key`
//! is `None` for every store created before it existed, and for a seller whose
//! delegate has not minted one. There is no fallback: encrypting to a key that
//! does not exist is not possible, and writing plaintext into a world-readable
//! contract would be worse than sending nothing.
//!
//! **Forward secrecy against the seller's delegate.** The seller's key is
//! long-term, so anyone who later obtains it can read every message ever sent
//! to that store. The buyer's half is ephemeral, which is what stops one
//! buyer's messages linking across stores; it does not protect the archive.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use harvest_common::mailbox::{
    conversation_key_from_dh, message_aad, message_aad_for, pad_to_bucket, unpad_from_bucket,
    ConversationId, EncryptedMessage, MessageDirection,
};
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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

/// Both keys of one conversation, derived from a single X25519 exchange.
///
/// Held together because every party needs both: the seller reads with
/// `to_seller` and writes with `from_seller`, and the buyer does the reverse.
/// Two separate values that must be derived from the same shared secret are
/// exactly the "paired fields that must co-occur" shape, so they are one
/// type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConversationKeys {
    /// Encrypts what the buyer writes.
    pub to_seller: [u8; 32],
    /// Encrypts what the seller writes back.
    pub from_seller: [u8; 32],
}

impl ConversationKeys {
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Self {
        Self {
            to_seller: conversation_key_from_dh(shared_secret, MessageDirection::BuyerToSeller),
            from_seller: conversation_key_from_dh(shared_secret, MessageDirection::SellerToBuyer),
        }
    }
}

/// Deliberately opaque: a `Debug` that printed these would put both
/// conversation keys into a browser console and, from there, into any log a
/// user pastes into a bug report.
impl std::fmt::Debug for ConversationKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConversationKeys(redacted)")
    }
}

/// The buyer's half of one conversation with one store.
///
/// Opened per store per tab. The ephemeral SECRET is consumed in
/// [`Self::open`] and never stored -- the derived keys are all that is needed
/// afterwards, and keeping the secret would only widen what a leak costs.
///
/// It does not survive a reload, and there is nowhere to put it that would:
/// see the module docs.
#[derive(Clone, Debug, PartialEq)]
pub struct BuyerConversation {
    /// The routing tag every message in this conversation carries, in both
    /// directions.
    pub buyer_public_key: [u8; 32],
    /// Chosen once and echoed by the seller, so a decrypted message that
    /// names a different conversation can be rejected rather than displayed.
    pub conversation_id: ConversationId,
    keys: ConversationKeys,
}

impl BuyerConversation {
    /// Open a conversation with the holder of `seller_public_key`.
    pub fn open(seller_public_key: &[u8; 32]) -> Result<Self, String> {
        let secret = EphemeralSecret::random();
        let buyer_public_key = *PublicKey::from(&secret).as_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(*seller_public_key));
        if !shared.was_contributory() {
            return Err(
                "this store's published encryption key is not usable (the key exchange \
                        produced no shared secret), so nothing can be encrypted to it"
                    .to_string(),
            );
        }
        Ok(Self {
            buyer_public_key,
            conversation_id: ConversationId::random(),
            keys: ConversationKeys::from_shared_secret(shared.as_bytes()),
        })
    }

    /// Seal one message for the seller.
    pub fn seal(&self, text: String) -> Result<EncryptedMessage, String> {
        seal(
            &self.keys.to_seller,
            &self.buyer_public_key,
            &self.conversation_id,
            MessageContent::Text(text),
        )
    }

    /// This conversation's messages, in both directions, out of a mailbox
    /// that also holds everybody else's.
    ///
    /// # Why this filters and `read_mailbox` does not
    ///
    /// A buyer is one conversation in a mailbox that may hold up to
    /// [`harvest_common::mailbox::MAX_MESSAGES`] of them. Reporting the rest
    /// as "cannot be read" would be 511 lines of noise about other people's
    /// traffic. The seller is the opposite case: unreadable entries in their
    /// OWN mailbox are something they need told about, so `read_mailbox`
    /// reports them.
    ///
    /// The tag filter is a fast path and not a security boundary. An attacker
    /// can read the tag out of the public mailbox and stamp it on anything
    /// they like -- so the AEAD is what decides, and a forged entry simply
    /// fails to authenticate. What the tag bounds is WORK: without it a buyer
    /// would attempt decryption against every entry in the mailbox.
    pub fn read(&self, messages: &[EncryptedMessage]) -> Vec<ConversationMessage> {
        let mut thread: Vec<ConversationMessage> = messages
            .iter()
            .filter(|message| message.sender_public_key == self.buyer_public_key)
            .filter_map(|message| {
                // The seller's reply first: it is the one the buyer is
                // waiting for, and the common case for an entry they did not
                // write themselves.
                for (key, from_seller) in [
                    (&self.keys.from_seller, true),
                    (&self.keys.to_seller, false),
                ] {
                    let Ok(plaintext) = decrypt_message(message, key) else {
                        continue;
                    };
                    // The conversation id is inside the ciphertext, so only
                    // someone holding the key could have set it -- which is
                    // the seller. Checking it stops a reply being spliced
                    // from one of this buyer's conversations into another.
                    if plaintext.conversation_id != self.conversation_id {
                        continue;
                    }
                    return Some(ConversationMessage {
                        from_seller,
                        timestamp: message.timestamp,
                        nonce: message.nonce,
                        content: plaintext.content,
                    });
                }
                None
            })
            .collect();
        // Oldest first: a conversation reads top to bottom, unlike the
        // seller's inbox, which is a queue and reads newest first.
        thread.sort_by_key(|message| (message.timestamp, message.nonce));
        thread
    }
}

/// One message of a conversation, as the buyer sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct ConversationMessage {
    /// Whether the seller wrote it. Decided by WHICH key authenticated the
    /// ciphertext, not by anything the message claims about itself.
    pub from_seller: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The mailbox nonce, so a caller can tell whether a message it sent has
    /// actually appeared in the mailbox.
    pub nonce: [u8; 24],
    pub content: MessageContent,
}

/// Seal the seller's reply into their own mailbox.
///
/// `buyer_public_key` is echoed as the routing tag rather than replaced with
/// the seller's own key: it is what lets the buyer find their thread, and
/// naming the seller instead would tell every reader which entries are
/// replies while telling the buyer nothing.
pub fn seal_reply(
    keys: &ConversationKeys,
    buyer_public_key: &[u8],
    conversation_id: &ConversationId,
    text: String,
) -> Result<EncryptedMessage, String> {
    let tag: [u8; 32] = buyer_public_key.try_into().map_err(|_| {
        format!(
            "conversation tag is {} bytes, not 32",
            buyer_public_key.len()
        )
    })?;
    seal(
        &keys.from_seller,
        &tag,
        conversation_id,
        MessageContent::Text(text),
    )
}

/// The one place a message is built, whichever direction it travels.
///
/// # Why the size is checked HERE
///
/// `MailboxStateV1::apply_delta` refuses a message over
/// [`harvest_common::mailbox::MAX_MESSAGE_BYTES`], and it refuses it
/// silently -- a contract has nobody to report to. So a compose box that did
/// not check would seal an unacceptable message, dispatch it, and show the
/// sender "handed to your Freenet node"; it would then never appear, looking
/// exactly like the write race and never resolving.
///
/// The check is the real one rather than a character limit: it charges the
/// finished message with the same `message_bytes` the contract uses, so the
/// two cannot disagree about what fits. A character limit would have to model
/// CBOR and UTF-8 and would be wrong at the boundary.
fn seal(
    key: &[u8; 32],
    tag: &[u8; 32],
    conversation_id: &ConversationId,
    content: MessageContent,
) -> Result<EncryptedMessage, String> {
    let message = encrypt_message(
        &PlaintextMessage {
            conversation_id: conversation_id.clone(),
            content,
        },
        tag,
        key,
    )?;

    let charged = harvest_common::mailbox::message_bytes(&message);
    if charged > harvest_common::mailbox::MAX_MESSAGE_BYTES {
        return Err(format!(
            "that message is too long: it comes to {charged} bytes once encrypted and padded, \
             and a mailbox will not accept more than {}. Nothing was sent.",
            harvest_common::mailbox::MAX_MESSAGE_BYTES
        ));
    }
    Ok(message)
}

/// One message in a seller's mailbox, as far as this browser can read it.
///
/// Two variants rather than dropping what will not decrypt. The mailbox is
/// open-write -- anyone at all may deposit bytes in it -- so unreadable
/// entries are the NORMAL case, not a fault: junk, spam, messages encrypted
/// to a key this seller no longer holds. Silently hiding them would leave the
/// seller with a count that never matches what they see and no way to tell
/// "nobody wrote to me" from "I cannot read what they wrote".
#[derive(Clone, Debug, PartialEq)]
pub enum MailboxEntry {
    /// Decrypted successfully. The AES-GCM tag verified, so these bytes were
    /// written by someone holding the conversation key -- which for an
    /// honestly-derived key means the holder of `conversation`, or this
    /// seller themselves.
    Readable {
        /// The conversation's routing tag: the buyer's ephemeral public key.
        conversation: Vec<u8>,
        /// The conversation id the buyer chose, recovered from inside the
        /// ciphertext.
        ///
        /// Carried out rather than discarded because the seller needs it to
        /// reply: a reply naming a different id is refused by the buyer
        /// (`a_reply_naming_another_conversation_is_not_shown`), so the only
        /// place a seller can learn the right one is a message they decrypted.
        conversation_id: ConversationId,
        /// Whether the seller wrote it. Decided by WHICH direction key
        /// authenticated the ciphertext, so it cannot be spoofed by a copy of
        /// somebody else's message.
        from_seller: bool,
        timestamp: chrono::DateTime<chrono::Utc>,
        content: MessageContent,
    },
    /// Present and not readable, with the reason.
    Unreadable {
        conversation: Vec<u8>,
        timestamp: chrono::DateTime<chrono::Utc>,
        why: String,
    },
}

impl MailboxEntry {
    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            MailboxEntry::Readable { timestamp, .. }
            | MailboxEntry::Unreadable { timestamp, .. } => *timestamp,
        }
    }

    /// The conversation this entry belongs to, readable or not.
    pub fn conversation(&self) -> &[u8] {
        match self {
            MailboxEntry::Readable { conversation, .. }
            | MailboxEntry::Unreadable { conversation, .. } => conversation,
        }
    }
}

/// Read a mailbox with whatever conversation keys are on hand.
///
/// `keys` maps a conversation's routing tag to the key pair the seller's
/// delegate derived for it. A message whose tag is absent from the map is
/// [`MailboxEntry::Unreadable`] with "no key yet" rather than an error: the
/// keys arrive from the delegate a round trip after the mailbox state does,
/// so this is the ordinary state of the screen for a moment.
///
/// A message that has a key and still fails is also `Unreadable`, and the two
/// reasons are kept distinct because they mean different things -- the first
/// resolves itself, the second does not.
///
/// Pure, so the seller's whole read path is testable without a browser or a
/// node.
pub fn read_mailbox(
    messages: &[EncryptedMessage],
    keys: &std::collections::HashMap<Vec<u8>, ConversationKeys>,
) -> Vec<MailboxEntry> {
    let mut entries: Vec<MailboxEntry> = messages
        .iter()
        .map(|message| {
            let conversation = message.sender_public_key.clone();
            let Some(pair) = keys.get(&conversation) else {
                return MailboxEntry::Unreadable {
                    conversation,
                    timestamp: message.timestamp,
                    why: "waiting for the key from your delegate".to_string(),
                };
            };
            // Inbound first: it is what a seller opens their mailbox for, and
            // their own replies are the smaller half.
            let mut last_error = String::new();
            for (key, from_seller) in [(&pair.to_seller, false), (&pair.from_seller, true)] {
                match decrypt_message(message, key) {
                    Ok(plaintext) => {
                        return MailboxEntry::Readable {
                            conversation,
                            conversation_id: plaintext.conversation_id,
                            from_seller,
                            timestamp: message.timestamp,
                            content: plaintext.content,
                        }
                    }
                    Err(why) => last_error = why,
                }
            }
            MailboxEntry::Unreadable {
                conversation,
                timestamp: message.timestamp,
                why: last_error,
            }
        })
        .collect();
    // Newest first. `timestamp` is chosen by whoever wrote the message and is
    // signed by nobody (see `harvest_common::mailbox`), so this is a display
    // order and NOT evidence about when anything happened.
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp()));
    entries
}

/// Encrypt a plaintext message under a conversation key.
///
/// `tag` is the conversation's routing tag -- the buyer's ephemeral public
/// key, whichever direction this message travels. See
/// [`harvest_common::mailbox::EncryptedMessage::sender_public_key`].
///
/// Returns an `EncryptedMessage` ready to be sent to the mailbox contract.
pub fn encrypt_message(
    plaintext: &PlaintextMessage,
    tag: &[u8; 32],
    aes_key: &[u8; 32],
) -> Result<EncryptedMessage, String> {
    // Serialize the plaintext to CBOR
    let plaintext_bytes =
        harvest_common::to_cbor(plaintext).map_err(|e| format!("serialize plaintext: {e}"))?;

    // Pad to reduce size-based analysis
    let padded = pad_to_bucket(&plaintext_bytes);

    // The whole 24-byte mailbox nonce is drawn first, because it is bound
    // into the authenticated data below -- it cannot be assembled after the
    // ciphertext the way it used to be. Its first 12 bytes are the AES-GCM
    // nonce; the rest exist so that deduplication has more entropy than the
    // cipher needs.
    let mut mailbox_nonce = [0u8; 24];
    getrandom::getrandom(&mut mailbox_nonce).map_err(|e| format!("generate nonce: {e}"))?;
    let timestamp = chrono::Utc::now();

    // Every field of the message except the ciphertext, authenticated but not
    // encrypted. See `harvest_common::mailbox::message_aad` for what each one
    // costs to leave unbound -- the sharpest is the nonce padding, whose
    // mutation was a working replay.
    let aad = message_aad(
        &plaintext.conversation_id,
        tag.as_slice(),
        &timestamp,
        &mailbox_nonce,
    );

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&mailbox_nonce[..12]),
            Payload {
                msg: padded.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;

    Ok(EncryptedMessage {
        conversation_id: plaintext.conversation_id.clone(),
        sender_public_key: tag.to_vec(),
        ciphertext,
        timestamp,
        nonce: mailbox_nonce,
    })
}

/// Decrypt an encrypted message from the mailbox contract.
pub fn decrypt_message(
    encrypted: &EncryptedMessage,
    aes_key: &[u8; 32],
) -> Result<PlaintextMessage, String> {
    // The AES nonce is the first 12 bytes of the mailbox nonce; the whole 24
    // are bound into the associated data, so a change to any of the rest --
    // or to any other envelope field -- fails the tag rather than passing
    // unnoticed.
    let nonce = Nonce::from_slice(&encrypted.nonce[..12]);
    let aad = message_aad_for(encrypted);

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let padded = cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("decrypt: {e}"))?;

    // Unpad
    let plaintext_bytes = unpad_from_bucket(&padded).map_err(|e| format!("unpad: {e}"))?;

    // Deserialize from CBOR
    harvest_common::from_cbor(&plaintext_bytes).map_err(|e| format!("deserialize plaintext: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use harvest_common::mailbox::MAX_MESSAGES;
    use std::collections::HashMap;
    use x25519_dalek::StaticSecret;

    /// A seller, reconstructed from nothing but a long-term secret -- which
    /// is what the harvest delegate holds. Deliberately NOT built out of this
    /// module's own types, so a test cannot pass because the buyer's half and
    /// the seller's half drifted together.
    struct Seller {
        secret: StaticSecret,
    }

    impl Seller {
        fn new(seed: u8) -> Self {
            Self {
                secret: StaticSecret::from([seed; 32]),
            }
        }

        fn public_key(&self) -> [u8; 32] {
            *PublicKey::from(&self.secret).as_bytes()
        }

        /// The keys the delegate would answer for one conversation tag.
        fn keys_for(&self, tag: &[u8]) -> ConversationKeys {
            let peer: [u8; 32] = tag.try_into().expect("32-byte tag");
            let shared = self
                .secret
                .diffie_hellman(&PublicKey::from(peer))
                .to_bytes();
            ConversationKeys {
                to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                from_seller: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            }
        }

        fn inbox(&self, messages: &[EncryptedMessage]) -> Vec<MailboxEntry> {
            let mut keys = HashMap::new();
            for message in messages {
                if message.sender_public_key.len() == 32 {
                    keys.insert(
                        message.sender_public_key.clone(),
                        self.keys_for(&message.sender_public_key),
                    );
                }
            }
            read_mailbox(messages, &keys)
        }
    }

    fn text(entry: &MailboxEntry) -> String {
        match entry {
            MailboxEntry::Readable {
                content: MessageContent::Text(text),
                ..
            } => text.clone(),
            other => panic!("expected readable text, got {other:?}"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seller = Seller::new(11);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let sealed = buyer.seal("Hello from buyer!".into()).expect("seal");
        assert_ne!(
            sealed.ciphertext,
            harvest_common::to_cbor(&"Hello from buyer!").unwrap()
        );

        let inbox = seller.inbox(&[sealed]);
        assert_eq!(text(&inbox[0]), "Hello from buyer!");
    }

    /// The whole buyer path, against a seller who exists only as an X25519
    /// secret -- which is all the delegate is, from this module's point of
    /// view.
    #[test]
    fn a_sealed_message_is_readable_by_the_seller_who_holds_the_secret() {
        let seller = Seller::new(17);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let sealed = buyer
            .seal("is the blue one still available?".into())
            .expect("seal");

        assert_ne!(
            sealed.sender_public_key,
            seller.public_key().to_vec(),
            "the tag must be the BUYER's key, not the seller's"
        );
        assert_eq!(sealed.sender_public_key, buyer.buyer_public_key.to_vec());

        let inbox = seller.inbox(&[sealed]);
        assert_eq!(text(&inbox[0]), "is the blue one still available?");
        match &inbox[0] {
            MailboxEntry::Readable { from_seller, .. } => {
                assert!(!from_seller, "an inbound message is not the seller's own")
            }
            other => panic!("expected readable: {other:?}"),
        }
    }

    /// The seller replies into their own mailbox and the buyer reads it --
    /// with no buyer mailbox, no buyer identity and no second contract.
    #[test]
    fn the_seller_replies_into_their_own_mailbox_and_the_buyer_reads_it() {
        let seller = Seller::new(23);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let question = buyer.seal("do you ship to Ireland?".into()).expect("seal");

        // The seller reads it, learns the conversation, and answers.
        let keys = seller.keys_for(&question.sender_public_key);
        let reply = seal_reply(
            &keys,
            &question.sender_public_key,
            &buyer.conversation_id,
            "yes, ten euro postage".into(),
        )
        .expect("reply");

        let mailbox = vec![question.clone(), reply.clone()];
        let thread = buyer.read(&mailbox);

        assert_eq!(thread.len(), 2, "the buyer sees both halves");
        assert!(!thread[0].from_seller, "oldest first: the buyer's question");
        assert!(thread[1].from_seller, "then the seller's reply");
        assert_eq!(
            thread[1].content,
            MessageContent::Text("yes, ten euro postage".into())
        );
        assert_eq!(
            thread[0].nonce, question.nonce,
            "the buyer's own message is identified by its nonce, so a caller can tell it landed"
        );
    }

    /// **A copy of the buyer's own message must not read as a reply.**
    ///
    /// Anyone can read the mailbox and anyone can write to it, so this attack
    /// is a copy and a paste: no key, no relationship with either party. The
    /// message it would forge is the one the buyer is waiting for, and in the
    /// phase this mechanism exists for that message is the buyer's only
    /// authorization to complain.
    ///
    /// Direction separation makes it impossible rather than detectable.
    /// Observed red on 2026-09-05 by deriving both keys under
    /// `MessageDirection::BuyerToSeller`.
    #[test]
    fn a_copy_of_the_buyers_own_message_does_not_read_as_a_reply() {
        let seller = Seller::new(29);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let original = buyer.seal("I will pay tomorrow".into()).expect("seal");

        // The forgery: the same ciphertext under a nonce the mailbox has not
        // seen, so its dedup does not refuse it.
        //
        // Only bytes 12..24 are touched. The first 12 ARE the AES-GCM nonce,
        // so changing those breaks decryption for a reason that has nothing
        // to do with direction -- an earlier version of this test replaced
        // the whole 24 bytes and passed for that reason, which made it a test
        // of the wrong thing. Bytes 12..24 are dedup padding and feed nothing
        // else, so this is the mutation an attacker would actually make.
        let mut forged = original.clone();
        forged.nonce[12..].copy_from_slice(&[0xAB; 12]);

        let thread = buyer.read(&[original.clone(), forged]);

        assert!(
            thread.iter().all(|message| !message.from_seller),
            "a copy of the buyer's own message was presented as a reply from the seller"
        );
        // And the original is still readable, so the assertion above is not
        // passing because nothing decrypted at all.
        assert_eq!(thread.len(), 1, "the re-nonced copy does not authenticate");
        assert_eq!(
            thread[0].content,
            MessageContent::Text("I will pay tomorrow".into())
        );
    }

    /// **A message must not be replayable.**
    ///
    /// The mailbox dedupes on the full 24-byte nonce, but only the first 12
    /// are the AES-GCM nonce -- bytes 12..24 are padding that feeds dedup and
    /// nothing else. Randomise them and the same ciphertext arrives again as
    /// a new message: the buyer sees whatever they were told, twice, and an
    /// attacker chooses when.
    ///
    /// That matters beyond duplication. The eviction ranking is
    /// `(timestamp, nonce)`, so a replay is also a way to occupy mailbox
    /// slots with content the attacker cannot read but can resubmit at will.
    ///
    /// Closed by authenticating the whole envelope, not just the ciphertext:
    /// every field of `EncryptedMessage` except the ciphertext itself is
    /// bound in as AES-GCM associated data, so ANY change to any of them
    /// fails the tag. The wire layout is unchanged -- associated data is
    /// derived from the fields, never transmitted.
    ///
    /// Observed red on 2026-09-05, before the associated data existed: the
    /// replay decrypted and the buyer's thread held two identical messages.
    #[test]
    fn a_replayed_message_with_fresh_padding_does_not_authenticate() {
        let seller = Seller::new(61);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let original = buyer
            .seal("send it to the usual address".into())
            .expect("seal");

        let mut replayed = original.clone();
        replayed.nonce[12..].copy_from_slice(&[0x5A; 12]);
        assert_ne!(
            replayed.nonce, original.nonce,
            "precondition: the mailbox would treat this as a new message"
        );
        assert_eq!(
            replayed.nonce[..12],
            original.nonce[..12],
            "precondition: the AES nonce is untouched, so only the envelope binding can refuse it"
        );

        let thread = buyer.read(&[original.clone(), replayed.clone()]);
        assert_eq!(
            thread.len(),
            1,
            "a replay was accepted: the buyer sees the same message twice"
        );

        // The seller's side refuses it too, and for the same reason.
        let inbox = seller.inbox(&[original, replayed]);
        assert_eq!(inbox.len(), 2, "both entries are present in the mailbox");
        let readable = inbox
            .iter()
            .filter(|entry| matches!(entry, MailboxEntry::Readable { .. }))
            .count();
        assert_eq!(readable, 1, "only the genuine message authenticates");
    }

    /// The other envelope fields are bound too, so a message cannot be
    /// re-timestamped to change where it ranks for eviction, nor re-tagged
    /// into another conversation.
    ///
    /// Re-timestamping is the sharper of the two: the eviction ranking is
    /// `(timestamp, nonce)`, so moving a genuine message to the top of it is
    /// a way to make somebody else's traffic survive a flood -- or, with the
    /// nonce unchanged, to have it replace itself at a rank of the attacker's
    /// choosing.
    #[test]
    fn the_whole_envelope_is_authenticated() {
        let seller = Seller::new(67);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let original = buyer.seal("hello".into()).expect("seal");

        let mut re_timestamped = original.clone();
        re_timestamped.timestamp =
            chrono::DateTime::from_timestamp(2_000_000_000, 0).expect("timestamp");

        let mut re_tagged = original.clone();
        re_tagged.sender_public_key = vec![0x77; 32];

        let mut re_labelled = original.clone();
        re_labelled.conversation_id = ConversationId([0x88; 32]);

        for (what, tampered) in [
            ("timestamp", re_timestamped),
            ("routing tag", re_tagged),
            ("conversation id", re_labelled),
        ] {
            assert_eq!(
                buyer.read(&[tampered]).len(),
                0,
                "a message with an altered {what} authenticated"
            );
        }

        // And the untouched original still reads, so the assertions above are
        // not passing because nothing decrypts.
        assert_eq!(buyer.read(&[original]).len(), 1);
    }

    /// A reply carrying a different conversation id is not shown, even though
    /// it decrypts.
    ///
    /// Only the seller holds the key, so this is not an outsider attack -- it
    /// is a splice, moving an answer from one of this buyer's conversations
    /// into another. Cheap to refuse, and it makes `conversation_id` mean
    /// something rather than being carried and ignored.
    #[test]
    fn a_reply_naming_another_conversation_is_not_shown() {
        let seller = Seller::new(31);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let keys = seller.keys_for(&buyer.buyer_public_key);

        let honest = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "yours".into(),
        )
        .expect("reply");
        let spliced = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &ConversationId([0xEE; 32]),
            "somebody else's".into(),
        )
        .expect("reply");

        let thread = buyer.read(&[honest, spliced]);
        assert_eq!(thread.len(), 1);
        assert_eq!(thread[0].content, MessageContent::Text("yours".into()));
    }

    /// A buyer sees their own conversation and nobody else's, out of a
    /// mailbox holding both.
    #[test]
    fn a_buyer_sees_only_their_own_conversation() {
        let seller = Seller::new(37);
        let alice = BuyerConversation::open(&seller.public_key()).expect("open");
        let bob = BuyerConversation::open(&seller.public_key()).expect("open");

        let mailbox = vec![
            alice.seal("alice here".into()).expect("seal"),
            bob.seal("bob here".into()).expect("seal"),
        ];

        let alices = alice.read(&mailbox);
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].content, MessageContent::Text("alice here".into()));

        // The seller sees both, and they are separate conversations.
        let inbox = seller.inbox(&mailbox);
        assert_eq!(inbox.len(), 2);
        assert_ne!(inbox[0].conversation(), inbox[1].conversation());
    }

    /// **The worst case a buyer can be pushed into**, which is not the same
    /// as the common case.
    ///
    /// The routing tag is in the clear in a public mailbox, so an attacker
    /// can read a buyer's tag and stamp it on a full cap's worth of entries.
    /// The buyer then attempts decryption against all of them. This asserts
    /// the buyer still finds their own thread and reports nothing else --
    /// the cost of doing so is measured separately and recorded in
    /// `docs/messaging-privacy.md`.
    #[test]
    fn a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread() {
        let seller = Seller::new(41);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let mine = buyer.seal("mine".into()).expect("seal");
        let mut mailbox = vec![mine.clone()];
        for i in 0..(MAX_MESSAGES - 1) {
            let mut junk = mine.clone();
            junk.nonce = {
                let mut nonce = [0u8; 24];
                nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
                nonce
            };
            junk.ciphertext = vec![0xCD; 1024];
            mailbox.push(junk);
        }
        assert_eq!(mailbox.len(), MAX_MESSAGES);

        let thread = buyer.read(&mailbox);
        assert_eq!(thread.len(), 1, "only the real message authenticates");
        assert_eq!(thread[0].content, MessageContent::Text("mine".into()));
    }

    /// Two conversations with the same seller carry different tags, so a
    /// passive observer cannot tell they came from one buyer.
    ///
    /// This is what `EphemeralSecret` is for, and it is a property that a
    /// perfectly reasonable optimisation -- one keypair per store, reused --
    /// would silently delete.
    #[test]
    fn each_conversation_carries_a_fresh_tag() {
        let seller = Seller::new(43);
        let first = BuyerConversation::open(&seller.public_key()).expect("open");
        let second = BuyerConversation::open(&seller.public_key()).expect("open");

        assert_ne!(first.buyer_public_key, second.buyer_public_key);
        assert_ne!(first.conversation_id, second.conversation_id);

        let a = first.seal("hello".into()).expect("seal");
        let b = first.seal("hello".into()).expect("seal");
        assert_ne!(a.nonce, b.nonce, "nonces must not repeat within one thread");
    }

    /// The seller's read path, over a mailbox holding one readable message,
    /// one whose key has not arrived, one written to somebody else, and one
    /// of the seller's own replies.
    #[test]
    fn a_mailbox_is_read_with_the_keys_on_hand_and_says_so_when_it_cannot_be() {
        let seller = Seller::new(21);
        let stranger = Seller::new(99);

        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let unkeyed_buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let foreign_buyer = BuyerConversation::open(&stranger.public_key()).expect("open");

        let mine = buyer.seal("readable".into()).expect("seal");
        let unkeyed = unkeyed_buyer.seal("no key yet".into()).expect("seal");
        let foreign = foreign_buyer.seal("not for us".into()).expect("seal");
        let own_reply = seal_reply(
            &seller.keys_for(&buyer.buyer_public_key),
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "answered".into(),
        )
        .expect("reply");

        let mut keys = HashMap::new();
        keys.insert(
            mine.sender_public_key.clone(),
            seller.keys_for(&mine.sender_public_key),
        );
        // The foreign message DOES get a key -- the one our secret derives
        // against its tag -- and it is the wrong key, which is the point.
        keys.insert(
            foreign.sender_public_key.clone(),
            seller.keys_for(&foreign.sender_public_key),
        );
        keys.insert(
            own_reply.sender_public_key.clone(),
            seller.keys_for(&own_reply.sender_public_key),
        );

        let entries = read_mailbox(
            &[
                mine.clone(),
                unkeyed.clone(),
                foreign.clone(),
                own_reply.clone(),
            ],
            &keys,
        );
        assert_eq!(entries.len(), 4, "nothing may be dropped");

        // Located by (tag, timestamp) rather than by position, because
        // `read_mailbox` reorders.
        let by_nonce = |nonce: [u8; 24]| -> &MailboxEntry {
            let index = [mine.nonce, unkeyed.nonce, foreign.nonce, own_reply.nonce]
                .iter()
                .position(|candidate| *candidate == nonce)
                .expect("known nonce");
            let sources = [&mine, &unkeyed, &foreign, &own_reply];
            let source = sources[index];
            entries
                .iter()
                .find(|entry| {
                    entry.conversation() == source.sender_public_key
                        && entry.timestamp() == source.timestamp
                })
                .expect("every message must appear")
        };

        assert_eq!(text(by_nonce(mine.nonce)), "readable");
        match by_nonce(unkeyed.nonce) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                why.contains("waiting"),
                "a missing key must be reported as temporary: {why}"
            ),
            other => panic!("expected an unreadable entry: {other:?}"),
        }
        match by_nonce(foreign.nonce) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                !why.contains("waiting"),
                "a message that will never decrypt must not read as merely pending: {why}"
            ),
            other => panic!("a message we hold no key for must not read as decrypted: {other:?}"),
        }
        match by_nonce(own_reply.nonce) {
            MailboxEntry::Readable {
                from_seller,
                content,
                ..
            } => {
                assert!(
                    from_seller,
                    "the seller's own reply must be labelled as theirs"
                );
                assert_eq!(content, &MessageContent::Text("answered".into()));
            }
            other => panic!("the seller must be able to read their own reply: {other:?}"),
        }
    }

    /// Newest first, so a busy mailbox shows the message that just arrived.
    #[test]
    fn a_mailbox_is_read_newest_first() {
        let at = |secs: i64, nonce: u8| EncryptedMessage {
            conversation_id: ConversationId([0u8; 32]),
            sender_public_key: vec![nonce; 32],
            ciphertext: vec![1u8; 16],
            timestamp: chrono::DateTime::from_timestamp(secs, 0).expect("timestamp"),
            nonce: [nonce; 24],
        };

        let entries = read_mailbox(&[at(100, 1), at(300, 3), at(200, 2)], &HashMap::new());
        let order: Vec<i64> = entries.iter().map(|e| e.timestamp().timestamp()).collect();
        assert_eq!(order, vec![300, 200, 100]);
    }

    /// **A message too large to be accepted must be refused where the buyer
    /// can be told**, not sealed and dispatched into silence.
    ///
    /// Found by accident on 2026-09-05: a measurement fixture asked for a
    /// message near the top padding bucket, and every one of them was
    /// silently dropped by `apply_delta` because the CBOR envelope pushed it
    /// past `MAX_MESSAGE_BYTES`. The buyer's UI would have shown "handed to
    /// your Freenet node" and the message would never have appeared --
    /// indistinguishable, from the buyer's side, from the write race.
    ///
    /// Observed red before `seal` learned to check.
    #[test]
    fn a_message_too_large_for_a_mailbox_is_refused_at_the_compose_box() {
        use harvest_common::mailbox::{message_bytes, MailboxStateV1, MAX_MESSAGE_BYTES};

        let seller = Seller::new(53);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let error = buyer
            .seal("x".repeat(harvest_common::mailbox::LARGEST_BUCKET))
            .expect_err("a message that no mailbox would accept must be refused");
        assert!(
            error.contains("too long"),
            "the refusal must be something a compose box can show: {error}"
        );

        // The largest message that IS accepted really is accepted, so the
        // check is not simply refusing everything near the limit.
        let big = buyer
            .seal("x".repeat(60_000))
            .expect("a large but legal message must still send");
        assert!(message_bytes(&big) <= MAX_MESSAGE_BYTES);
        let mut state = MailboxStateV1::default();
        state.apply_delta(&Some(vec![big.clone()])).unwrap();
        assert_eq!(
            state.messages.len(),
            1,
            "a message the compose box accepted must be one a mailbox accepts"
        );
    }

    /// The same for the seller's side, which composes into the same mailbox
    /// under the same cap.
    #[test]
    fn an_oversized_reply_is_refused_at_the_compose_box() {
        let seller = Seller::new(59);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let keys = seller.keys_for(&buyer.buyer_public_key);

        let error = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "x".repeat(harvest_common::mailbox::LARGEST_BUCKET),
        )
        .expect_err("must be refused");
        assert!(error.contains("too long"), "got: {error}");
    }

    /// A low-order "public key" is refused rather than encrypted to under a
    /// key the whole world can compute.
    #[test]
    fn opening_a_conversation_with_an_all_zero_key_is_refused() {
        let error = BuyerConversation::open(&[0u8; 32]).expect_err("must be refused");
        assert!(
            error.contains("not usable"),
            "the refusal must say why: {error}"
        );
    }
}
