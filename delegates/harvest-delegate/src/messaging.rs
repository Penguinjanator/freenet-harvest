//! The seller's long-term X25519 secret, and the only thing it is used for.
//!
//! # What this holds and why it cannot live anywhere else
//!
//! A buyer has no identity in Harvest -- no ghostkey, no account, nothing to
//! register. Their Bitcoin payment is their whole commitment. So the key
//! exchange is one-sided: the buyer generates an ephemeral keypair per order
//! and encrypts to a key the SELLER published, and the seller's half of that
//! exchange has to outlive any one page load or no buyer could ever reach
//! them.
//!
//! That makes it a durable secret, which in Harvest means the delegate's own
//! secret store -- the same place the reputation signing key and the Bitcoin
//! account key live. It is reached only through [`crate::origin::authorize`],
//! along with every other request family; see that module for what the gate
//! is worth and what it is not.
//!
//! # What leaves, and what does not
//!
//! The secret itself never leaves. [`derive_conversation_keys`] answers
//! per-buyer conversation keys, which decrypt one buyer's messages and
//! nothing else; the secret decrypts every conversation the seller will ever
//! have, including ones that have not happened yet.
//!
//! The alternative -- decrypting here and answering plaintext -- would need
//! the padding, CBOR and AES-GCM path inside the delegate. That path lives in
//! `harvest-ui`'s `messaging`, and the only crate both sides share is
//! `harvest-common`, which is compiled into all three contracts. Moving it
//! there would put `aes-gcm` in every contract's WASM to serve code no
//! contract executes. One crypto path, in the UI, is the trade that was made.
//!
//! # The buyer's half, which is not symmetrical with the seller's
//!
//! The second half of this module keeps the BUYER's per-conversation
//! ephemeral secrets, and it exists for a different reason. The seller's
//! secret is here because it must outlive a page load or no buyer could ever
//! reach them. The buyer's is here because there is nowhere else at all: the
//! Freenet webapp iframe carries no `allow-same-origin`, so the page runs on
//! an opaque origin where `localStorage`, `sessionStorage`, IndexedDB and
//! cookies all throw. Without this the buyer's keys die with the tab, and the
//! seller's reply -- which after Phase 2 carries the buyer's only capability
//! to complain against the seller's bond -- becomes unreadable by anyone,
//! including the buyer who asked for it.
//!
//! Nothing here is keyed by a ghostkey fingerprint, because the buyer has no
//! identity to key by. See `docs/buyer-conversation-persistence.md` for the
//! whole design, including the two things it does not solve: a buyer who
//! changes device, and the durable local record this leaves of who they
//! contacted.

use crate::secrets::RemovableSecrets;
use freenet_migrate::SecretStore;
use harvest_common::delegate::{
    ConversationKey, ConversationSecret, HarvestDelegateResponse, RecalledConversation, RequestId,
};
use harvest_common::mailbox::{conversation_key_from_dh, MessageDirection};
use x25519_dalek::{PublicKey, StaticSecret};

/// Where this identity's X25519 secret lives.
///
/// Under `harvest:` like everything else the delegate writes, because the
/// migration export is defined by that prefix -- a key builder that stopped
/// starting with it would be silently left behind by every future migration.
/// Pinned by `handlers::all_secret_key_shapes` and the export test that reads
/// it.
pub(crate) fn x25519_sk_key(fp: &str) -> Vec<u8> {
    format!("harvest:x25519_sk:{fp}").into_bytes()
}

/// Mint this identity's X25519 keypair, or recall the one already minted.
///
/// Idempotent on purpose. The public half goes into a signed `StoreInfoV1`
/// that lives on the network permanently, and buyers encrypt to whatever they
/// read there. Minting a second key would leave every message already sent to
/// the first one undecryptable, with no error anywhere -- so a key that
/// exists is returned unchanged, and the UI may call this on every connect.
pub(crate) fn init_encryption_key<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    let key = x25519_sk_key(ghostkey_fingerprint);

    let secret = match store.get_secret(&key).and_then(seed_from_stored) {
        Some(existing) => existing,
        None => {
            let mut seed = [0u8; 32];
            // The delegate host's own RNG, via this crate's registered
            // `getrandom` implementation (see `lib.rs`). Not
            // `StaticSecret::random`, which would reach `rand_core::OsRng`
            // and give the crate a second entropy path to reason about.
            if let Err(e) = getrandom::getrandom(&mut seed) {
                return HarvestDelegateResponse::Error {
                    message: format!("could not generate an encryption key: {e}"),
                };
            }
            // The write, and only then the answer. A public key handed back
            // whose private half was never stored is published by the seller
            // into a permanent record, and every buyer who reads it encrypts
            // to a key nobody holds -- their messages arrive, look sent, and
            // can never be read. Reporting the failure leaves the seller with
            // no published key, which the UI can say out loud and which is
            // recoverable.
            if !store.set_secret(&key, &seed) {
                return HarvestDelegateResponse::Error {
                    message: "could not store the encryption key -- the node refused the write, \
                              so no key was published"
                        .into(),
                };
            }
            StaticSecret::from(seed)
        }
    };

    HarvestDelegateResponse::EncryptionKeyReady {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        x25519_public_key: PublicKey::from(&secret).as_bytes().to_vec(),
    }
}

/// Read a stored 32-byte seed back as a secret, or `None` if the stored value
/// is not one.
///
/// A wrong-length value is treated as absent rather than as a reason to fail:
/// the only way to get one is for something outside this module to write the
/// key, and re-minting is the recoverable answer. It is not silent -- the
/// caller mints a new key, whose public half differs from whatever was
/// published, which the seller sees as messaging having stopped working.
fn seed_from_stored(stored: Vec<u8>) -> Option<StaticSecret> {
    let seed: [u8; 32] = stored.try_into().ok()?;
    Some(StaticSecret::from(seed))
}

/// Derive one conversation key per buyer ephemeral public key.
///
/// Malformed and low-order peer keys are dropped rather than answered, so the
/// result may be shorter than the request. That is why every entry echoes the
/// [`ConversationKey::peer_public_key`] it belongs to: correlating by
/// position would, the first time an entry was dropped, hand one buyer's
/// conversation key to another buyer's messages.
pub(crate) fn derive_conversation_keys<S: SecretStore>(
    store: &S,
    request_id: RequestId,
    ghostkey_fingerprint: &str,
    peer_public_keys: &[Vec<u8>],
) -> HarvestDelegateResponse {
    let Some(secret) = store
        .get_secret(&x25519_sk_key(ghostkey_fingerprint))
        .and_then(seed_from_stored)
    else {
        return HarvestDelegateResponse::ConversationKeys {
            request_id,
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
            result: Err(format!(
                "no encryption key for ghostkey {ghostkey_fingerprint} -- call \
                 InitEncryptionKey first"
            )),
        };
    };

    let derived = peer_public_keys
        .iter()
        .filter_map(|peer| {
            let bytes: [u8; 32] = peer.as_slice().try_into().ok()?;
            let shared = secret.diffie_hellman(&PublicKey::from(bytes));
            // A low-order point makes the shared secret all zeros, so the
            // "conversation key" would be a constant anyone can compute --
            // and a message decrypted under it looks, to the seller, exactly
            // like one from a buyer who established a private channel.
            if !shared.was_contributory() {
                return None;
            }
            let shared = shared.to_bytes();
            Some(ConversationKey {
                peer_public_key: peer.clone(),
                buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            })
        })
        .collect();

    HarvestDelegateResponse::ConversationKeys {
        request_id,
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        result: Ok(derived),
    }
}

// ---------------------------------------------------------------------------
// The buyer's half: conversation secrets that outlive a browser tab.
// ---------------------------------------------------------------------------

/// How many buyer conversations one node keeps, across every store.
///
/// # Why a COUNT is a real bound here, unlike in the mailbox
///
/// This repository has the count-cap-over-contract-controlled-values pattern
/// written up, and the reflex on seeing a count cap is to call it a fake
/// bound. It is worth saying why that reflex does not apply here rather than
/// making the next reader re-derive it.
///
/// That pattern bites when a count caps entries whose values are
/// **contract-controlled and variable** -- the mailbox, where `ciphertext`
/// was attacker-supplied and unbounded, so 512 entries meant nothing about
/// bytes. Here both halves are bounded:
///
/// * the VALUE is three 32-byte arrays and an `i64`, so its CBOR is a fixed
///   shape a caller cannot inflate;
/// * the KEY is `harvest:buyer_conv:` plus two base58 32-byte values, because
///   [`store_buyer_conversation`] refuses a `store_contract_id` that is not
///   32 bytes. Without that refusal the key would be caller-sized and this
///   cap would bound entries while bounding no bytes at all -- which is
///   exactly the pattern above. Pinned by
///   `a_store_id_that_is_not_a_contract_id_is_refused`.
///
/// So this is about 60 KiB at the cap, and the cap is what stops a page
/// opening conversations in a loop from growing the secret store without
/// limit.
pub(crate) const MAX_BUYER_CONVERSATIONS: usize = 256;

/// A contract instance id, which is what a store is named by.
const STORE_CONTRACT_ID_BYTES: usize = 32;

const BUYER_CONVERSATION_PREFIX_STR: &str = "harvest:buyer_conv:";

/// Every buyer conversation this delegate holds, whichever store it is with.
///
/// Under `harvest:` like everything else the delegate writes, because the
/// migration export is defined by that prefix. A re-key that left these
/// behind would destroy every buyer's ability to read a reply -- the same
/// loss this whole mechanism exists to prevent, arriving by another route.
/// Pinned by `buyer_conversations_are_under_the_exported_prefix`.
pub(crate) const BUYER_CONVERSATION_PREFIX: &[u8] = BUYER_CONVERSATION_PREFIX_STR.as_bytes();

/// Where one buyer conversation lives:
/// `harvest:buyer_conv:{store id}:{routing tag}`, both base58.
///
/// # Why the key names both halves
///
/// Because both are recoverable after a reload and nothing else is. The store
/// id is in the URL the buyer followed, and the tag is the buyer's ephemeral
/// public key, which every message in the conversation carries in the clear.
/// Naming them makes recall a prefix listing rather than a scan of every
/// secret the delegate holds.
///
/// The `:` terminator matters: it is not in the base58 alphabet, so one
/// store's prefix cannot be a prefix of another store's keys, and
/// [`list_buyer_conversations`] cannot hand back a neighbouring store's
/// conversations. Pinned by `conversations_are_scoped_to_their_store`.
///
/// **What this leaves behind is deliberate and is documented rather than
/// hidden.** The key records that this node held a conversation with that
/// store, so the record is a durable local artefact of who the buyer
/// contacted -- see `docs/messaging-privacy.md`. It is removable:
/// [`forget_buyer_conversation`] deletes the key outright rather than
/// emptying it.
pub(crate) fn buyer_conversation_key(
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut key = buyer_conversation_store_prefix(store_contract_id);
    key.extend_from_slice(bs58::encode(buyer_public_key).into_string().as_bytes());
    key
}

/// Every conversation held for ONE store.
fn buyer_conversation_store_prefix(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{BUYER_CONVERSATION_PREFIX_STR}{}:",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// What is kept for one conversation.
///
/// The routing tag is NOT a field: it is the public half of `secret`, so
/// [`recall`] derives it. A stored copy would be a second source for one
/// value that could disagree with the key it is filed under, and a
/// conversation recalled under a tag no mailbox message carries would read as
/// an empty thread with nothing to explain it.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct BuyerConversationRecord {
    /// The buyer's ephemeral X25519 secret. Prints as `redacted`; see
    /// [`ConversationSecret`].
    pub(crate) secret: ConversationSecret,
    /// The seller key this conversation was opened against. [`recall`]
    /// derives with THIS rather than with anything a caller supplies, so the
    /// recall path is not a Diffie-Hellman oracle against stored secrets.
    pub(crate) seller_public_key: [u8; 32],
    pub(crate) conversation_id: [u8; 32],
    /// Unix seconds, as the buyer's browser reported them, used only for
    /// eviction order. See `HarvestDelegateRequest::StoreBuyerConversation`
    /// for why the delegate does not read the host clock here.
    pub(crate) created_at: i64,
}

/// Every conversation the delegate holds, with whichever store, as
/// `(key, record)`.
///
/// A key whose value does not decode is reported with `None` rather than
/// dropped: it still occupies a key, so the cap has to be able to see it --
/// and it is the first thing evicted, since it recalls nothing.
fn held_conversations<S: SecretStore>(
    store: &S,
) -> Vec<(Vec<u8>, Option<BuyerConversationRecord>)> {
    store
        .list_secrets(BUYER_CONVERSATION_PREFIX)
        .into_iter()
        .map(|key| {
            let record = store.get_secret(&key).and_then(|bytes| {
                harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok()
            });
            (key, record)
        })
        .collect()
}

/// Keep a buyer's conversation, evicting the oldest if every slot is taken.
///
/// The routing tag is derived from the secret, so what is answered and what
/// is filed can never disagree about which conversation this is.
pub(crate) fn store_buyer_conversation<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    request_id: RequestId,
    store_contract_id: &[u8],
    record: &BuyerConversationRecord,
) -> HarvestDelegateResponse {
    let stored = |result| HarvestDelegateResponse::BuyerConversationStored { request_id, result };

    if store_contract_id.len() != STORE_CONTRACT_ID_BYTES {
        return stored(Err(format!(
            "a store is named by a {STORE_CONTRACT_ID_BYTES}-byte contract id, and this one is \
             {} bytes -- refusing to keep a conversation under a name that is not a store",
            store_contract_id.len()
        )));
    }

    let bytes = match harvest_common::to_cbor(record) {
        Ok(bytes) => bytes,
        Err(e) => return stored(Err(format!("could not serialize the conversation: {e}"))),
    };

    let buyer_public_key = *PublicKey::from(&StaticSecret::from(record.secret.0)).as_bytes();
    let key = buyer_conversation_key(store_contract_id, &buyer_public_key);

    // Only a NEW key consumes a slot. Re-storing the same conversation --
    // which the UI does whenever it re-sends into a thread it already has --
    // must not evict anything.
    if !store.has_secret(&key) {
        if let Err(why) = make_room(store) {
            return stored(Err(why));
        }
    }

    if store.set_secret(&key, &bytes) {
        stored(Ok(()))
    } else {
        // Reported rather than swallowed: the UI has already told the buyer
        // their message was sent, and a conversation that was not kept
        // becomes unreadable the moment the tab closes.
        stored(Err(
            "could not keep this conversation -- the node refused the write, so a reply \
             will not be readable after this tab closes"
                .to_string(),
        ))
    }
}

/// Free a slot if every one is taken, oldest first.
///
/// Eviction rather than refusal, because refusing would mean the conversation
/// the buyer is having RIGHT NOW is the one that cannot be saved.
///
/// There is deliberately no age-based expiry anywhere here. That would be the
/// mailbox's TTL mistake at a higher cost: it would discard precisely the
/// capability the buyer needs later, at a time the buyer has no way to
/// predict.
fn make_room<S: SecretStore + RemovableSecrets>(store: &mut S) -> Result<(), String> {
    let mut held = held_conversations(store);
    while held.len() >= MAX_BUYER_CONVERSATIONS {
        // An undecodable entry first -- it recalls nothing, so discarding it
        // costs nothing -- then the oldest, then the lowest key so the choice
        // is deterministic rather than dependent on listing order.
        let Some(victim) = held
            .iter()
            .enumerate()
            .min_by_key(|(_, (key, record))| {
                (record.as_ref().map(|record| record.created_at), key.clone())
            })
            .map(|(index, _)| index)
        else {
            // Unreachable while `held.len() >= MAX_BUYER_CONVERSATIONS`, and
            // a `break` rather than an `expect` so a future change to the cap
            // cannot turn this into a panic inside a delegate.
            break;
        };
        let (key, _) = held.remove(victim);
        if !store.remove_secret(&key) {
            // Refusing to grow past the cap is the safe direction: the
            // alternative is an unbounded secret store on a node whose host
            // is already refusing writes.
            return Err(
                "could not make room for this conversation -- the node refused to remove an \
                 older one, so a reply will not be readable after this tab closes"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Recall every conversation stored for one store, as derived keys.
///
/// The keys are derived here, from the stored secret and the SELLER key the
/// conversation was opened against, so the secret never leaves. Deriving
/// against a caller-supplied key instead would make this a Diffie-Hellman
/// oracle against every secret the node holds.
pub(crate) fn list_buyer_conversations<S: SecretStore>(
    store: &S,
    store_contract_id: &[u8],
) -> HarvestDelegateResponse {
    let prefix = buyer_conversation_store_prefix(store_contract_id);
    let conversations = store
        .list_secrets(&prefix)
        .into_iter()
        .filter_map(|key| store.get_secret(&key))
        .filter_map(|bytes| harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok())
        .filter_map(|record| recall(&record))
        .collect();

    HarvestDelegateResponse::BuyerConversationList {
        store_contract_id: store_contract_id.to_vec(),
        conversations,
    }
}

/// One stored record as the two keys that read its thread.
fn recall(record: &BuyerConversationRecord) -> Option<RecalledConversation> {
    let secret = StaticSecret::from(record.secret.0);
    let shared = secret.diffie_hellman(&PublicKey::from(record.seller_public_key));
    // The same refusal as the seller's side: a low-order peer makes the
    // shared secret all zeros, so the "conversation key" would be a constant
    // anyone can compute.
    if !shared.was_contributory() {
        return None;
    }
    let shared = shared.to_bytes();

    Some(RecalledConversation {
        buyer_public_key: *PublicKey::from(&secret).as_bytes(),
        conversation_id: record.conversation_id,
        buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
        seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
        created_at: record.created_at,
    })
}

/// Discard one conversation, permanently.
///
/// # Why this deletes rather than empties
///
/// This is the buyer's control over the record their node keeps of who they
/// contacted, and the key itself carries the store id. Emptying the value
/// would leave that key in place, so a "forget" that emptied would be a
/// control that lies: the conversation would stop being readable while the
/// evidence of it stayed. `SecretStore` cannot express deletion, which is why
/// this takes the extra [`RemovableSecrets`] bound -- see that trait for what
/// the node actually does with the request.
///
/// The answer is checked rather than assumed: the key is re-read afterwards
/// and a key that is still there is reported as a failure. A buyer stops
/// being careful on the strength of a control like this, so it must not
/// report a success it cannot stand behind.
pub(crate) fn forget_buyer_conversation<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    request_id: RequestId,
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> HarvestDelegateResponse {
    let key = buyer_conversation_key(store_contract_id, buyer_public_key);

    let result = if !store.has_secret(&key) {
        // Already gone. Reported as success: the buyer asked for it not to be
        // there, and it is not there.
        Ok(())
    } else if store.remove_secret(&key) && !store.has_secret(&key) {
        Ok(())
    } else {
        Err(
            "could not forget this conversation -- the node refused to remove it, so it is \
             still stored here"
                .to_string(),
        )
    };

    HarvestDelegateResponse::BuyerConversationForgotten { request_id, result }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const FP: &str = "fp1";

    fn public_key(response: &HarvestDelegateResponse) -> Vec<u8> {
        match response {
            HarvestDelegateResponse::EncryptionKeyReady {
                x25519_public_key, ..
            } => x25519_public_key.clone(),
            other => panic!("expected an EncryptionKeyReady, got {other:?}"),
        }
    }

    fn keys(response: &HarvestDelegateResponse) -> Vec<ConversationKey> {
        match response {
            HarvestDelegateResponse::ConversationKeys { result, .. } => {
                result.clone().expect("derivation should have succeeded")
            }
            other => panic!("expected ConversationKeys, got {other:?}"),
        }
    }

    fn error_message(response: &HarvestDelegateResponse) -> String {
        match response {
            HarvestDelegateResponse::Error { message } => message.clone(),
            HarvestDelegateResponse::ConversationKeys { result, .. } => match result {
                Err(message) => message.clone(),
                Ok(keys) => panic!("expected a refusal, got {} key(s)", keys.len()),
            },
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A key is minted once and then recalled.
    ///
    /// Re-minting is the failure that matters: the seller publishes the
    /// public half in their store info, and a second call answering a
    /// DIFFERENT key would leave every message already encrypted to the first
    /// one undecryptable, with nothing anywhere reporting a problem. The UI
    /// calls this on every connect, so "idempotent" is the normal path rather
    /// than an edge case.
    #[test]
    fn the_encryption_key_is_minted_once_and_then_recalled() {
        let mut store = MemSecrets::default();

        let first = public_key(&init_encryption_key(&mut store, FP));
        assert_eq!(first.len(), 32, "an X25519 public key is 32 bytes");
        assert_ne!(first, vec![0u8; 32], "the key must not be all zeros");

        let second = public_key(&init_encryption_key(&mut store, FP));
        assert_eq!(first, second, "a second call minted a different key");
    }

    /// Two identities on one node get different keys, so the test above is
    /// not passing because the "key" is a constant.
    #[test]
    fn two_identities_get_different_keys() {
        let mut store = MemSecrets::default();
        let one = public_key(&init_encryption_key(&mut store, "fp1"));
        let two = public_key(&init_encryption_key(&mut store, "fp2"));
        assert_ne!(one, two);
    }

    /// **A public key must never be handed back when its private half was not
    /// stored.**
    ///
    /// The seller publishes whatever comes back here into a signed
    /// `StoreInfoV1`, which is on the network permanently. If the write
    /// failed, every buyer who reads that store encrypts to a key nobody
    /// holds: their messages arrive, look fine to them, and the seller can
    /// never read one. Reporting the failure means the seller publishes no
    /// key and buyers are told messaging is unavailable, which is recoverable.
    #[test]
    fn a_failed_write_is_reported_rather_than_answered_with_a_key() {
        let mut store = MemSecrets::default();
        store.writes_fail = true;

        let message = error_message(&init_encryption_key(&mut store, FP));
        assert!(
            message.contains("could not"),
            "the refusal must say the key was not stored: {message}"
        );
        assert!(
            store.is_empty(),
            "precondition: the store really did refuse the write"
        );
    }

    /// The property the whole scheme rests on: the seller derives, from their
    /// long-term secret and the buyer's ephemeral public key, exactly the key
    /// the buyer derived from their ephemeral secret and the seller's
    /// published public key.
    ///
    /// If this ever stops holding, nothing errors. AES-GCM tags simply fail
    /// to verify and every message in every conversation reads as corrupt.
    #[test]
    fn the_seller_derives_the_key_the_buyer_derived() {
        let mut store = MemSecrets::default();
        let seller_public_bytes = public_key(&init_encryption_key(&mut store, FP));
        let seller_public: [u8; 32] = seller_public_bytes.clone().try_into().expect("32 bytes");

        // The buyer's side, computed the way `harvest-ui`'s
        // `messaging::EphemeralKeypair::derive_shared_key` computes it: X25519
        // against the seller's published key, then
        // `conversation_key_from_dh`.
        let buyer_secret = StaticSecret::from([42u8; 32]);
        let buyer_public = PublicKey::from(&buyer_secret);
        let shared = buyer_secret
            .diffie_hellman(&PublicKey::from(seller_public))
            .to_bytes();
        let buyers_write_key = conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller);
        let buyers_read_key = conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer);

        let derived = keys(&derive_conversation_keys(
            &store,
            7,
            FP,
            &[buyer_public.as_bytes().to_vec()],
        ));

        assert_eq!(derived.len(), 1);
        assert_eq!(
            derived[0].peer_public_key,
            buyer_public.as_bytes().to_vec(),
            "the answer must echo the key it was derived against"
        );
        assert_eq!(
            derived[0].buyer_to_seller, buyers_write_key,
            "the seller cannot read what the buyer wrote"
        );
        assert_eq!(
            derived[0].seller_to_buyer, buyers_read_key,
            "the buyer cannot read what the seller replies"
        );
        assert_ne!(
            derived[0].buyer_to_seller, derived[0].seller_to_buyer,
            "one key for both directions makes a copied message read as a reply"
        );
    }

    /// Answers are paired by peer key, not by position, and a malformed entry
    /// does not shift the others onto the wrong buyer.
    ///
    /// This is the mutation that matters: with positional correlation, one
    /// dropped entry silently hands buyer A's conversation key to buyer B's
    /// messages, and the symptom is "some messages will not decrypt" rather
    /// than anything that names the cause.
    #[test]
    fn a_malformed_peer_key_does_not_shift_the_others() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP);

        let a = PublicKey::from(&StaticSecret::from([1u8; 32]));
        let b = PublicKey::from(&StaticSecret::from([2u8; 32]));

        let all = keys(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[a.as_bytes().to_vec(), b.as_bytes().to_vec()],
        ));
        let with_a_dud = keys(&derive_conversation_keys(
            &store,
            2,
            FP,
            &[
                a.as_bytes().to_vec(),
                vec![0u8; 5], // not a public key at all
                b.as_bytes().to_vec(),
            ],
        ));

        assert_eq!(all.len(), 2);
        assert_eq!(
            with_a_dud.len(),
            2,
            "the malformed entry should be dropped, not answered"
        );
        for expected in &all {
            let found = with_a_dud
                .iter()
                .find(|k| k.peer_public_key == expected.peer_public_key)
                .expect("every well-formed peer key must still be answered");
            assert_eq!(
                &found.buyer_to_seller, &expected.buyer_to_seller,
                "a key moved to another buyer"
            );
            assert_eq!(&found.seller_to_buyer, &expected.seller_to_buyer);
        }
    }

    /// A low-order peer point makes X25519 produce an all-zero shared secret,
    /// so the "conversation key" is a constant anyone can compute. Refusing
    /// it costs one branch.
    ///
    /// The damage is modest -- the mailbox is open-write, so an attacker can
    /// already deposit whatever they like -- but a message the seller decrypts
    /// under a key the whole world knows reads to them exactly like a message
    /// from a buyer who established a private channel, and that is a
    /// distinction the UI has no other way to draw.
    #[test]
    fn a_low_order_peer_key_is_refused() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP);

        let good = PublicKey::from(&StaticSecret::from([3u8; 32]));
        let derived = keys(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[vec![0u8; 32], good.as_bytes().to_vec()],
        ));

        assert_eq!(
            derived.len(),
            1,
            "the all-zero point must not yield a conversation key"
        );
        assert_eq!(derived[0].peer_public_key, good.as_bytes().to_vec());
    }

    /// Whatever this module writes has to be under the prefix a migration
    /// export carries, or the seller's encryption key is silently left behind
    /// the next time the delegate re-keys -- and every buyer then encrypts to
    /// a published key whose private half is gone.
    ///
    /// Driven through the real writer rather than asserted against
    /// `handlers::all_secret_key_shapes`, which is a hand-maintained list and
    /// so cannot notice a key nobody added to it.
    ///
    /// Observed red on 2026-09-05 by changing `x25519_sk_key`'s prefix --
    /// under which `migration::tests::every_secret_the_delegate_writes_is_
    /// under_the_exported_prefix` stayed GREEN, because the list it reads had
    /// been updated to match. That is the gap this test closes.
    #[test]
    fn everything_this_module_writes_is_under_the_exported_prefix() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP);

        let everything = store.list_secrets(b"");
        assert!(
            !everything.is_empty(),
            "precondition: something was written"
        );
        for key in everything {
            assert!(
                key.starts_with(b"harvest:"),
                "the delegate wrote {}, which no export would carry",
                String::from_utf8_lossy(&key)
            );
        }
    }

    /// An identity with no key yet is told so, rather than being handed an
    /// empty list that reads as "this buyer sent nothing".
    #[test]
    fn deriving_without_a_key_is_an_error_not_an_empty_answer() {
        let store = MemSecrets::default();
        let peer = PublicKey::from(&StaticSecret::from([5u8; 32]));

        let message = error_message(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[peer.as_bytes().to_vec()],
        ));
        assert!(
            message.contains("no encryption key"),
            "the error must say what is missing: {message}"
        );
    }
}

/// The buyer's conversation store: the thing that makes a reply readable
/// after the tab that sent the question is gone.
#[cfg(test)]
mod buyer_conversation_tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const STORE: &[u8] = &[3u8; 32];
    const OTHER_STORE: &[u8] = &[4u8; 32];

    /// One buyer's side of a conversation, plus the seller who can read it.
    struct Opened {
        seller: StaticSecret,
        buyer_public_key: [u8; 32],
        record: BuyerConversationRecord,
    }

    fn open(seed: u8) -> Opened {
        let secret = StaticSecret::from(seed_bytes(seed as u32));
        let seller = StaticSecret::from([200u8.wrapping_sub(seed); 32]);
        Opened {
            buyer_public_key: *PublicKey::from(&secret).as_bytes(),
            record: BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: *PublicKey::from(&seller).as_bytes(),
                conversation_id: [seed; 32],
                created_at: 1_700_000_000 + seed as i64,
            },
            seller,
        }
    }

    /// A distinct 32-byte seed per index, so the cap test can build more than
    /// [`MAX_BUYER_CONVERSATIONS`] different buyers.
    fn seed_bytes(i: u32) -> [u8; 32] {
        let mut seed = [1u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        seed
    }

    fn stored(response: &HarvestDelegateResponse) -> &Result<(), String> {
        match response {
            HarvestDelegateResponse::BuyerConversationStored { result, .. } => result,
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }
    }

    fn forgotten(response: &HarvestDelegateResponse) -> &Result<(), String> {
        match response {
            HarvestDelegateResponse::BuyerConversationForgotten { result, .. } => result,
            other => panic!("expected BuyerConversationForgotten, got {other:?}"),
        }
    }

    fn listed(response: &HarvestDelegateResponse) -> Vec<RecalledConversation> {
        match response {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
                conversations.clone()
            }
            other => panic!("expected BuyerConversationList, got {other:?}"),
        }
    }

    /// The whole point: a conversation stored now is recallable later, with
    /// the keys that read it.
    ///
    /// The keys are checked against what the SELLER derives, from the seller's
    /// own secret, rather than against the delegate's own arithmetic repeated
    /// -- a recalled conversation whose keys only agree with themselves would
    /// read nothing out of the mailbox.
    #[test]
    fn a_stored_conversation_comes_back_with_usable_keys() {
        let mut store = MemSecrets::default();
        let opened = open(9);

        stored(&store_buyer_conversation(
            &mut store,
            1,
            STORE,
            &opened.record,
        ))
        .as_ref()
        .expect("must store");

        let back = listed(&list_buyer_conversations(&store, STORE));
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].conversation_id, opened.record.conversation_id);
        assert_eq!(back[0].created_at, opened.record.created_at);

        // The routing tag has to be the one the mailbox carries, which is the
        // public half of the stored secret.
        assert_eq!(back[0].buyer_public_key, opened.buyer_public_key);

        let shared = opened
            .seller
            .diffie_hellman(&PublicKey::from(opened.buyer_public_key))
            .to_bytes();
        assert_eq!(
            back[0].buyer_to_seller,
            conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller)
        );
        assert_eq!(
            back[0].seller_to_buyer,
            conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer)
        );
    }

    /// **The secret itself never comes back.**
    ///
    /// Recall answers derived keys, the same shape as the seller's side. A
    /// secret handed to the UI on every reload would be a secret in every
    /// browser log and bug report, for no gain: the UI needs the keys.
    #[test]
    fn the_secret_never_leaves_the_delegate() {
        let mut store = MemSecrets::default();
        let opened = open(11);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);

        let response = list_buyer_conversations(&store, STORE);
        let encoded = harvest_common::to_cbor(&response).expect("cbor");
        let secret = opened.record.secret.0;
        assert!(
            !encoded.windows(secret.len()).any(|window| window == secret),
            "the conversation secret appeared in the recall answer"
        );
    }

    /// Conversations are scoped to their store, so browsing one store does
    /// not hand back the keys for another.
    #[test]
    fn conversations_are_scoped_to_their_store() {
        let mut store = MemSecrets::default();
        let here = open(21);
        let elsewhere = open(22);

        store_buyer_conversation(&mut store, 1, STORE, &here.record);
        store_buyer_conversation(&mut store, 2, OTHER_STORE, &elsewhere.record);

        let recalled = listed(&list_buyer_conversations(&store, STORE));
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].buyer_public_key, here.buyer_public_key);
    }

    /// **A failed write is reported, not swallowed.**
    ///
    /// By the time this runs the UI has told the buyer their message was
    /// sent. If the secret was not kept, the seller's reply becomes
    /// unreadable after a reload -- and that is exactly the failure this
    /// whole mechanism exists to prevent, so it must not happen quietly.
    #[test]
    fn a_failed_write_is_reported() {
        let mut store = MemSecrets::refusing_writes();
        let opened = open(13);

        let response = store_buyer_conversation(&mut store, 7, STORE, &opened.record);
        let message = stored(&response)
            .as_ref()
            .expect_err("a refused write must be reported");
        assert!(
            message.contains("readable"),
            "the error must say what the buyer loses: {message}"
        );
    }

    /// **A store id that is not a contract id is refused, and nothing is
    /// written.**
    ///
    /// The id is base58-encoded into the secret's key, so a caller-sized id
    /// would be a caller-sized key -- and then [`MAX_BUYER_CONVERSATIONS`]
    /// would bound entries while bounding no bytes, which is the exact
    /// count-cap-over-variable-values trap this codebase has been bitten by.
    #[test]
    fn a_store_id_that_is_not_a_contract_id_is_refused() {
        let mut store = MemSecrets::default();
        let opened = open(29);

        let response = store_buyer_conversation(&mut store, 1, &[7u8; 4096], &opened.record);
        let message = stored(&response)
            .as_ref()
            .expect_err("an oversized store id must be refused");
        assert!(message.contains("32-byte"), "{message}");
        assert!(store.is_empty(), "a refused store id still wrote a secret");
    }

    /// **Forgetting leaves NOTHING behind, not an emptied value.**
    ///
    /// The key names the store, so a "forget" that emptied the value would
    /// stop the conversation being readable while leaving a durable record
    /// that this node talked to that store. A control that lies about what it
    /// does is worse than no control, because the buyer stops being careful
    /// on the strength of it.
    #[test]
    fn a_forgotten_conversation_leaves_nothing_behind() {
        let mut store = MemSecrets::default();
        let opened = open(15);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);
        assert_eq!(listed(&list_buyer_conversations(&store, STORE)).len(), 1);

        forgotten(&forget_buyer_conversation(
            &mut store,
            2,
            STORE,
            &opened.buyer_public_key,
        ))
        .as_ref()
        .expect("must forget");

        assert!(
            listed(&list_buyer_conversations(&store, STORE)).is_empty(),
            "a forgotten conversation was still recalled"
        );
        assert!(
            store.list_secrets(BUYER_CONVERSATION_PREFIX).is_empty(),
            "the key survived the forget, so the node still records which store this was: {:?}",
            store
                .list_secrets(BUYER_CONVERSATION_PREFIX)
                .iter()
                .map(|key| String::from_utf8_lossy(key).into_owned())
                .collect::<Vec<_>>()
        );
    }

    /// A removal the node refuses is reported as a failure, and the
    /// conversation is still there afterwards.
    ///
    /// The buyer must not be told a record is gone while it is on their disk.
    #[test]
    fn a_refused_removal_is_not_reported_as_forgotten() {
        let mut store = MemSecrets::default();
        let opened = open(16);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);
        store.removals_fail = true;

        let response = forget_buyer_conversation(&mut store, 2, STORE, &opened.buyer_public_key);
        let message = forgotten(&response)
            .as_ref()
            .expect_err("a refused removal must be reported");
        assert!(message.contains("still stored"), "{message}");
        assert_eq!(
            listed(&list_buyer_conversations(&store, STORE)).len(),
            1,
            "the conversation should still be there, since removal failed"
        );
    }

    /// Forgetting one conversation forgets exactly that one.
    #[test]
    fn forgetting_one_conversation_leaves_the_others() {
        let mut store = MemSecrets::default();
        let kept = open(31);
        let discarded = open(32);
        let elsewhere = open(33);
        store_buyer_conversation(&mut store, 1, STORE, &kept.record);
        store_buyer_conversation(&mut store, 2, STORE, &discarded.record);
        store_buyer_conversation(&mut store, 3, OTHER_STORE, &elsewhere.record);

        forgotten(&forget_buyer_conversation(
            &mut store,
            4,
            STORE,
            &discarded.buyer_public_key,
        ))
        .as_ref()
        .expect("must forget");

        let here = listed(&list_buyer_conversations(&store, STORE));
        assert_eq!(here.len(), 1);
        assert_eq!(here[0].buyer_public_key, kept.buyer_public_key);
        assert_eq!(
            listed(&list_buyer_conversations(&store, OTHER_STORE)).len(),
            1,
            "another store's conversation was forgotten too"
        );
    }

    /// Forgetting something that is not there is success: the buyer asked for
    /// it not to be there, and it is not there.
    #[test]
    fn forgetting_a_conversation_that_is_not_there_is_success() {
        let mut store = MemSecrets::default();
        forgotten(&forget_buyer_conversation(&mut store, 1, STORE, &[9u8; 32]))
            .as_ref()
            .expect("must report success");
    }

    /// **The cap bounds the store, and evicts the OLDEST.**
    ///
    /// Eviction rather than refusal: refusing would mean the conversation the
    /// buyer is having right now is the one that cannot be saved, which is
    /// the wrong one to lose.
    #[test]
    fn the_cap_bounds_the_store_and_evicts_the_oldest() {
        let mut store = MemSecrets::default();

        let mut oldest = [0u8; 32];
        let mut newest = [0u8; 32];
        for i in 0..(MAX_BUYER_CONVERSATIONS + 8) {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            let buyer_public_key = *PublicKey::from(&secret).as_bytes();
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
            };
            if i == 0 {
                oldest = buyer_public_key;
            }
            newest = buyer_public_key;
            stored(&store_buyer_conversation(
                &mut store, i as u64, STORE, &record,
            ))
            .as_ref()
            .expect("must store");
        }

        let kept = listed(&list_buyer_conversations(&store, STORE));
        assert_eq!(
            kept.len(),
            MAX_BUYER_CONVERSATIONS,
            "the cap did not bound the store"
        );
        assert!(
            !kept.iter().any(|c| c.buyer_public_key == oldest),
            "the oldest conversation should have been the one evicted"
        );
        // And the newest survives, so the assertion above is not passing
        // because everything was discarded.
        assert!(
            kept.iter().any(|c| c.buyer_public_key == newest),
            "the conversation the buyer is having right now was the one dropped"
        );
    }

    /// Re-storing a conversation the delegate already holds evicts nothing.
    ///
    /// The UI re-sends the same conversation whenever the buyer writes into a
    /// thread it already has, so a full store would otherwise shed one real
    /// conversation per message sent.
    #[test]
    fn re_storing_a_held_conversation_evicts_nothing() {
        let mut store = MemSecrets::default();
        let mut first = [0u8; 32];
        for i in 0..MAX_BUYER_CONVERSATIONS {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            if i == 0 {
                first = *PublicKey::from(&secret).as_bytes();
            }
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
            };
            store_buyer_conversation(&mut store, i as u64, STORE, &record);
        }
        assert_eq!(
            listed(&list_buyer_conversations(&store, STORE)).len(),
            MAX_BUYER_CONVERSATIONS
        );

        // The oldest one again -- which is also the one eviction would take.
        let secret = StaticSecret::from(seed_bytes(0));
        let record = BuyerConversationRecord {
            secret: ConversationSecret(secret.to_bytes()),
            seller_public_key: [7u8; 32],
            conversation_id: [2u8; 32],
            created_at: 1_700_000_000,
        };
        stored(&store_buyer_conversation(&mut store, 999, STORE, &record))
            .as_ref()
            .expect("must store");

        let kept = listed(&list_buyer_conversations(&store, STORE));
        assert_eq!(
            kept.len(),
            MAX_BUYER_CONVERSATIONS,
            "re-storing a held conversation changed how many are held"
        );
        assert!(
            kept.iter().any(|c| c.buyer_public_key == first),
            "re-storing a conversation evicted it"
        );
    }

    /// An entry whose value does not decode is evicted before a real one.
    ///
    /// It recalls nothing, so discarding it costs nothing -- and it still
    /// occupies a key, so something has to be able to reclaim it or the cap
    /// slowly fills with rubbish that cannot be read or removed.
    #[test]
    fn an_undecodable_entry_is_evicted_before_a_real_one() {
        let mut store = MemSecrets::default();
        let junk = buyer_conversation_key(STORE, &[0xAAu8; 32]);
        store.set_secret(&junk, b"not a conversation");

        let mut oldest = [0u8; 32];
        for i in 0..(MAX_BUYER_CONVERSATIONS - 1) {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            if i == 0 {
                oldest = *PublicKey::from(&secret).as_bytes();
            }
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
            };
            store_buyer_conversation(&mut store, i as u64, STORE, &record);
        }

        // One more, which must displace the junk rather than a conversation.
        let secret = StaticSecret::from(seed_bytes(9_000));
        let record = BuyerConversationRecord {
            secret: ConversationSecret(secret.to_bytes()),
            seller_public_key: [7u8; 32],
            conversation_id: [1u8; 32],
            created_at: 1_800_000_000,
        };
        stored(&store_buyer_conversation(&mut store, 1, STORE, &record))
            .as_ref()
            .expect("must store");

        assert!(
            !store
                .list_secrets(BUYER_CONVERSATION_PREFIX)
                .contains(&junk),
            "the undecodable entry survived"
        );
        assert!(
            listed(&list_buyer_conversations(&store, STORE))
                .iter()
                .any(|c| c.buyer_public_key == oldest),
            "a real conversation was evicted while rubbish was kept"
        );
    }

    /// Everything this writes is under the exported prefix, so a delegate
    /// re-key carries it. Without that, a re-key destroys every buyer's
    /// ability to read a reply -- the same loss the whole mechanism exists to
    /// prevent, arriving by a different route.
    #[test]
    fn buyer_conversations_are_under_the_exported_prefix() {
        let mut store = MemSecrets::default();
        let opened = open(17);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);

        let everything = store.list_secrets(b"");
        assert!(!everything.is_empty(), "precondition");
        for key in everything {
            assert!(
                key.starts_with(b"harvest:"),
                "the delegate wrote {}, which no export would carry",
                String::from_utf8_lossy(&key)
            );
        }
    }
}
