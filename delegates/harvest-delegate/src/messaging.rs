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

use freenet_migrate::SecretStore;
use harvest_common::delegate::{ConversationKey, HarvestDelegateResponse, RequestId};
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
