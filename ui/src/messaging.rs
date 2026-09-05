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
//! # What this module does NOT do
//!
//! **Replies.** The seller has no way to send anything back, because the
//! buyer has no mailbox to write to and no identity to address. A seller
//! reading a message here can act on it, but Harvest gives them no channel to
//! answer through. `components::message_view` says so on screen rather than
//! implying a conversation.
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

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use harvest_common::mailbox::{
    conversation_key_from_dh, pad_to_bucket, unpad_from_bucket, ConversationId, EncryptedMessage,
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
    ///
    /// Returns `None` for a non-contributory exchange -- a low-order peer
    /// point, which makes the shared secret all zeros and the "conversation
    /// key" a constant anyone can compute. The seller's delegate refuses the
    /// same case (`harvest-delegate`'s `messaging`), so this is the buyer's
    /// half of one rule rather than a second one.
    ///
    /// The derivation itself is [`conversation_key_from_dh`], in
    /// `harvest-common`, because the seller computes the same value inside
    /// their delegate. If the two ever disagreed nothing would error: the
    /// AES-GCM tag would simply stop verifying and every message would read
    /// as corrupt.
    pub fn derive_shared_key(self, their_public_key: &PublicKey) -> Option<[u8; 32]> {
        let shared_secret: SharedSecret = self.secret.diffie_hellman(their_public_key);
        if !shared_secret.was_contributory() {
            return None;
        }
        Some(conversation_key_from_dh(shared_secret.as_bytes()))
    }
}

/// Encrypt one message for a seller, from a buyer who has no identity.
///
/// The ephemeral secret is generated here and dropped when this returns, so
/// **the buyer cannot decrypt what they just sent** and could not read a
/// reply even if one existed. That is not an oversight to fix later by
/// keeping the secret around: a buyer has nowhere durable to keep it, and a
/// secret held only in a browser tab is gone on the next reload anyway. The
/// UI keeps the plaintext it was handed, locally, so the buyer can see what
/// they wrote; see `components::message_view`.
pub fn seal_to_seller(
    seller_public_key: &[u8; 32],
    plaintext: &PlaintextMessage,
) -> Result<EncryptedMessage, String> {
    let keypair = EphemeralKeypair::generate();
    let our_public = keypair.public_key;
    let key = keypair
        .derive_shared_key(&PublicKey::from(*seller_public_key))
        .ok_or(
            "this store's published encryption key is not usable (the key exchange produced \
             no shared secret), so nothing can be encrypted to it",
        )?;
    encrypt_message(plaintext, &our_public, &key)
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
    /// honestly-derived key means the holder of `sender_public_key`.
    Readable {
        sender_public_key: Vec<u8>,
        timestamp: chrono::DateTime<chrono::Utc>,
        content: MessageContent,
    },
    /// Present and not readable, with the reason.
    Unreadable {
        sender_public_key: Vec<u8>,
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
}

/// Read a mailbox with whatever conversation keys are on hand.
///
/// `keys` maps a sender's public key to the conversation key the seller's
/// delegate derived for it. A message whose sender is absent from the map is
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
    keys: &std::collections::HashMap<Vec<u8>, [u8; 32]>,
) -> Vec<MailboxEntry> {
    let mut entries: Vec<MailboxEntry> = messages
        .iter()
        .map(|message| {
            let Some(key) = keys.get(&message.sender_public_key) else {
                return MailboxEntry::Unreadable {
                    sender_public_key: message.sender_public_key.clone(),
                    timestamp: message.timestamp,
                    why: "waiting for the key from your delegate".to_string(),
                };
            };
            match decrypt_message(message, key) {
                Ok(plaintext) => MailboxEntry::Readable {
                    sender_public_key: message.sender_public_key.clone(),
                    timestamp: message.timestamp,
                    content: plaintext.content,
                },
                Err(why) => MailboxEntry::Unreadable {
                    sender_public_key: message.sender_public_key.clone(),
                    timestamp: message.timestamp,
                    why,
                },
            }
        })
        .collect();
    // Newest first. `timestamp` is chosen by whoever wrote the message and is
    // signed by nobody (see `harvest_common::mailbox`), so this is a display
    // order and NOT evidence about when anything happened.
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp()));
    entries
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
        let our_key = keypair
            .derive_shared_key(&their_public)
            .expect("contributory");
        let their_key = their_keypair
            .derive_shared_key(&our_public)
            .expect("contributory");
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

    /// The whole buyer path, against a seller reconstructed from nothing but
    /// a long-term secret.
    ///
    /// The seller half here is deliberately NOT this module's code: it is
    /// X25519 plus [`conversation_key_from_dh`], which is what the harvest
    /// delegate actually runs. So this fails if the buyer's derivation drifts
    /// from the shared one -- the failure that produces no error anywhere,
    /// only messages that stop decrypting.
    #[test]
    fn a_sealed_message_is_readable_by_the_seller_who_holds_the_secret() {
        use x25519_dalek::StaticSecret;

        let seller_secret = StaticSecret::from([17u8; 32]);
        let seller_public = *PublicKey::from(&seller_secret).as_bytes();

        let plaintext = PlaintextMessage {
            conversation_id: ConversationId::random(),
            content: MessageContent::Text("is the blue one still available?".into()),
        };
        let sealed = seal_to_seller(&seller_public, &plaintext).expect("seal");

        assert_ne!(
            sealed.sender_public_key, seller_public,
            "the buyer must send their OWN ephemeral public key, not the seller's"
        );

        // The seller's side, as the delegate computes it.
        let peer: [u8; 32] = sealed
            .sender_public_key
            .clone()
            .try_into()
            .expect("32 bytes");
        let key = conversation_key_from_dh(
            &seller_secret
                .diffie_hellman(&PublicKey::from(peer))
                .to_bytes(),
        );

        let read = decrypt_message(&sealed, &key).expect("the seller must be able to read it");
        match read.content {
            MessageContent::Text(text) => assert_eq!(text, "is the blue one still available?"),
            other => panic!("wrong content: {other:?}"),
        }
        assert_eq!(read.conversation_id, plaintext.conversation_id);
    }

    /// Two messages to the same seller carry different sender keys, so a
    /// passive observer cannot tell they came from one buyer.
    ///
    /// This is what `EphemeralKeypair` is for, and it is a property that a
    /// perfectly reasonable optimisation -- reusing a keypair per store to
    /// save an allocation -- would silently delete.
    #[test]
    fn each_sealed_message_carries_a_fresh_sender_key() {
        let seller_public =
            *PublicKey::from(&x25519_dalek::StaticSecret::from([3u8; 32])).as_bytes();
        let plaintext = PlaintextMessage {
            conversation_id: ConversationId::random(),
            content: MessageContent::Text("hello".into()),
        };

        let first = seal_to_seller(&seller_public, &plaintext).expect("seal");
        let second = seal_to_seller(&seller_public, &plaintext).expect("seal");

        assert_ne!(first.sender_public_key, second.sender_public_key);
        assert_ne!(first.nonce, second.nonce, "nonces must not repeat either");
    }

    /// The seller's read path, end to end, over a mailbox holding one
    /// readable message, one whose key has not arrived, and one written by
    /// somebody the key does not belong to.
    ///
    /// The third is the one worth having. A wrong conversation key cannot
    /// silently produce wrong plaintext -- AES-GCM authenticates -- so the
    /// only way it can go wrong is by being reported as readable when it is
    /// not, and this asserts it is not.
    #[test]
    fn a_mailbox_is_read_with_the_keys_on_hand_and_says_so_when_it_cannot_be() {
        use std::collections::HashMap;
        use x25519_dalek::StaticSecret;

        let seller_secret = StaticSecret::from([21u8; 32]);
        let seller_public = *PublicKey::from(&seller_secret).as_bytes();

        let mine = seal_to_seller(
            &seller_public,
            &PlaintextMessage {
                conversation_id: ConversationId::random(),
                content: MessageContent::Text("readable".into()),
            },
        )
        .expect("seal");
        let unkeyed = seal_to_seller(
            &seller_public,
            &PlaintextMessage {
                conversation_id: ConversationId::random(),
                content: MessageContent::Text("no key yet".into()),
            },
        )
        .expect("seal");
        // Written to a DIFFERENT seller, so our key cannot open it -- the
        // shape a junk deposit into an open-write mailbox takes.
        let stranger_public = *PublicKey::from(&StaticSecret::from([99u8; 32])).as_bytes();
        let foreign = seal_to_seller(
            &stranger_public,
            &PlaintextMessage {
                conversation_id: ConversationId::random(),
                content: MessageContent::Text("not for us".into()),
            },
        )
        .expect("seal");

        let key_for = |message: &EncryptedMessage| -> [u8; 32] {
            let peer: [u8; 32] = message.sender_public_key.clone().try_into().expect("32");
            conversation_key_from_dh(
                &seller_secret
                    .diffie_hellman(&PublicKey::from(peer))
                    .to_bytes(),
            )
        };

        let mut keys = HashMap::new();
        keys.insert(mine.sender_public_key.clone(), key_for(&mine));
        // The foreign message DOES get a key -- the one our secret derives
        // against its sender -- and it is the wrong key, which is the point.
        keys.insert(foreign.sender_public_key.clone(), key_for(&foreign));

        let entries = read_mailbox(&[mine.clone(), unkeyed.clone(), foreign.clone()], &keys);
        assert_eq!(entries.len(), 3, "nothing may be dropped");

        let find = |message: &EncryptedMessage| {
            entries
                .iter()
                .find(|e| match e {
                    MailboxEntry::Readable {
                        sender_public_key, ..
                    }
                    | MailboxEntry::Unreadable {
                        sender_public_key, ..
                    } => sender_public_key == &message.sender_public_key,
                })
                .expect("every message must appear")
                .clone()
        };

        match find(&mine) {
            MailboxEntry::Readable {
                content: MessageContent::Text(text),
                ..
            } => assert_eq!(text, "readable"),
            other => panic!("the keyed message should be readable: {other:?}"),
        }
        match find(&unkeyed) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                why.contains("waiting"),
                "a missing key must be reported as temporary: {why}"
            ),
            other => panic!("expected an unreadable entry: {other:?}"),
        }
        match find(&foreign) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                !why.contains("waiting"),
                "a message that will never decrypt must not read as merely pending: {why}"
            ),
            other => panic!("a message we hold no key for must not read as decrypted: {other:?}"),
        }
    }

    /// Newest first, so a busy mailbox shows the message that just arrived.
    #[test]
    fn a_mailbox_is_read_newest_first() {
        use std::collections::HashMap;

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

    /// A low-order "public key" is refused rather than encrypted to under a
    /// key the whole world can compute.
    #[test]
    fn sealing_to_an_all_zero_key_is_refused() {
        let plaintext = PlaintextMessage {
            conversation_id: ConversationId::random(),
            content: MessageContent::Text("hello".into()),
        };
        let error = seal_to_seller(&[0u8; 32], &plaintext).expect_err("must be refused");
        assert!(
            error.contains("not usable"),
            "the refusal must say why: {error}"
        );
    }
}
