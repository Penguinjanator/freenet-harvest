use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::MessageOrigin;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Sha256;

use harvest_common::delegate::{
    HarvestDelegateRequest, HarvestDelegateResponse, StoreRegistration, TransactionRecord,
};
use harvest_common::{from_cbor, to_cbor};

// Secret key prefixes for delegate storage
fn rsa_sk_key(fp: &str) -> Vec<u8> {
    format!("harvest:rsa_sk:{fp}").into_bytes()
}
fn rsa_pk_key(fp: &str) -> Vec<u8> {
    format!("harvest:rsa_pk:{fp}").into_bytes()
}
fn tx_key(tx_id: &str) -> Vec<u8> {
    format!("harvest:tx:{tx_id}").into_bytes()
}
fn stores_key(fp: &str) -> Vec<u8> {
    format!("harvest:stores:{fp}").into_bytes()
}
const TX_INDEX_KEY: &[u8] = b"harvest:tx_index";

/// Every shape of secret key this delegate writes, for a sample fingerprint
/// and transaction id.
///
/// Exists so `migration`'s tests can assert that all of them fall under the
/// prefix an export covers. A key builder that stopped starting with
/// `harvest:` would be silently omitted from every future migration -- no
/// error, no warning, just a secret that does not arrive -- and nothing else
/// connects the two.
///
/// Keep in step with the builders above and with `crate::bitcoin`'s two
/// constants.
#[cfg(test)]
pub(crate) fn all_secret_key_shapes(fp: &str, tx_id: &str) -> Vec<Vec<u8>> {
    vec![
        rsa_sk_key(fp),
        rsa_pk_key(fp),
        tx_key(tx_id),
        stores_key(fp),
        TX_INDEX_KEY.to_vec(),
        crate::bitcoin::BITCOIN_WATCHES_KEY.to_vec(),
        crate::bitcoin::BITCOIN_BRIDGE_KEY.to_vec(),
        crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY.to_vec(),
        crate::markers::marker_secret_key("v1.store.aa.bb"),
    ]
}

fn load_tx_index<S: SecretStore>(store: &S) -> Vec<String> {
    store
        .get_secret(TX_INDEX_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_tx_index<S: SecretStore>(store: &mut S, index: &[String]) {
    if let Ok(bytes) = to_cbor(&index) {
        store.set_secret(TX_INDEX_KEY, &bytes);
    }
}

/// Answer one Harvest request, for the Harvest web app only.
///
/// # Why every variant below is behind the gate, reads included
///
/// The writes are the obvious half. `InitReputationKeys` mints an RSA key the
/// store's whole reputation identity then rests on; `BeginTransaction` and
/// `RecordBlindSignature` write the transaction ledger; `RegisterStore` decides
/// which contracts the seller's UI will treat as their own stores;
/// `SetMigrationMarker` can seal a migration as done that never ran, which
/// loses data silently rather than loudly (see [`crate::markers`]).
/// `BlindSignFeedbackToken` is the sharpest of them: it signs caller-supplied
/// bytes with the seller's reputation key, so an ungated caller gets a signing
/// oracle for an identity that is not theirs.
///
/// The reads are gated for the same reason as `crate::bitcoin`'s: each hands
/// back something whose value is that it is private. `ListStores` and
/// `ListTransactions` are the seller's commercial history -- which stores are
/// theirs, who they have traded with -- and `GetRsaPublicKey` plus
/// `GetMigrationMarker` let a caller confirm which pseudonymous ghostkey
/// fingerprints and which store generations belong to this one user, which is
/// exactly the linkage a pseudonymous marketplace exists to avoid.
///
/// No caller outside the Harvest web app is broken by this, because none
/// exists: this delegate is Harvest's own, and nothing else is expected to
/// speak `HarvestDelegateRequest`.
pub fn handle<S: SecretStore>(
    store: &mut S,
    origin: Option<&MessageOrigin>,
    request: HarvestDelegateRequest,
) -> HarvestDelegateResponse {
    // A refusal is reported rather than swallowed: a caller that got a
    // plausible-looking empty answer would be indistinguishable, to whoever is
    // reading the node's log later, from one that legitimately had no data.
    if let Err(refusal) = crate::origin::authorize(origin) {
        return HarvestDelegateResponse::Error {
            message: match refusal {
                freenet_stdlib::prelude::DelegateError::Other(message) => message,
                other => format!("{other:?}"),
            },
        };
    }

    match request {
        HarvestDelegateRequest::InitReputationKeys {
            ghostkey_fingerprint,
        } => handle_init_reputation_keys(store, &ghostkey_fingerprint),

        HarvestDelegateRequest::GetRsaPublicKey {
            ghostkey_fingerprint,
        } => handle_get_rsa_public_key(store, &ghostkey_fingerprint),

        HarvestDelegateRequest::BlindSignFeedbackToken {
            request_id,
            ghostkey_fingerprint,
            blinded_token,
        } => handle_blind_sign(store, request_id, &ghostkey_fingerprint, &blinded_token),

        HarvestDelegateRequest::CreateListing { request_id, .. } => {
            // Listing creation requires calling the ghostkey delegate for signing.
            // For now, return an error -- this will be implemented when we add
            // inter-delegate communication support.
            HarvestDelegateResponse::ListingCreated {
                request_id,
                result: Err("listing creation via delegate not yet implemented -- sign listings from the UI via ghostkey delegate directly".into()),
            }
        }

        HarvestDelegateRequest::BeginTransaction {
            request_id,
            transaction_id,
            our_token,
            our_blinded_token,
        } => handle_begin_transaction(
            store,
            request_id,
            &transaction_id,
            our_token,
            our_blinded_token,
        ),

        HarvestDelegateRequest::RecordBlindSignature {
            request_id,
            transaction_id,
            blind_signature,
        } => handle_record_blind_signature(store, request_id, &transaction_id, blind_signature),

        HarvestDelegateRequest::ListTransactions => handle_list_transactions(store),

        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint,
            store_contract_id,
            reputation_contract_id,
            mailbox_contract_id,
        } => handle_register_store(
            store,
            &ghostkey_fingerprint,
            store_contract_id,
            reputation_contract_id,
            mailbox_contract_id,
        ),

        HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint,
        } => handle_list_stores(store, &ghostkey_fingerprint),

        // The migration repeat-gate. `markers` owns both the namespace and the
        // fail-safe direction; this is only the routing.
        HarvestDelegateRequest::GetMigrationMarker { marker } => {
            crate::markers::get_marker(store, &marker)
        }

        HarvestDelegateRequest::SetMigrationMarker { marker, note } => {
            crate::markers::set_marker(store, &marker, &note)
        }

        _ => HarvestDelegateResponse::Error {
            message: "unsupported request variant for this delegate version".into(),
        },
    }
}

fn handle_init_reputation_keys<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    // Check if keys already exist
    if store
        .get_secret(&rsa_pk_key(ghostkey_fingerprint))
        .is_some()
    {
        // Return existing public key
        return match store.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
            Some(pk_der) => HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
                rsa_public_key_der: pk_der,
            },
            None => HarvestDelegateResponse::Error {
                message: "RSA public key not found after existence check".into(),
            },
        };
    }

    // Generate a new RSA-2048 keypair for blind signing
    // Use getrandom for the RNG in WASM context
    let mut rng = rsa::rand_core::OsRng;
    let private_key = match rsa::RsaPrivateKey::new(&mut rng, 2048) {
        Ok(k) => k,
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("RSA key generation failed: {e}"),
            }
        }
    };

    let public_key = private_key.to_public_key();

    // Serialize keys to DER
    let sk_der = match private_key.to_pkcs1_der() {
        Ok(d) => d.as_bytes().to_vec(),
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("serialize RSA private key: {e}"),
            }
        }
    };

    let pk_der = match public_key.to_pkcs1_der() {
        Ok(d) => d.as_bytes().to_vec(),
        Err(e) => {
            return HarvestDelegateResponse::Error {
                message: format!("serialize RSA public key: {e}"),
            }
        }
    };

    // Store both keys
    store.set_secret(&rsa_sk_key(ghostkey_fingerprint), &sk_der);
    store.set_secret(&rsa_pk_key(ghostkey_fingerprint), &pk_der);

    HarvestDelegateResponse::ReputationKeysInitialized {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        rsa_public_key_der: pk_der,
    }
}

fn handle_get_rsa_public_key<S: SecretStore>(
    store: &S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    match store.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
        Some(pk_der) => HarvestDelegateResponse::RsaPublicKey {
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
            rsa_public_key_der: pk_der,
        },
        None => HarvestDelegateResponse::Error {
            message: format!(
                "no RSA keys for ghostkey {ghostkey_fingerprint} -- call InitReputationKeys first"
            ),
        },
    }
}

fn handle_blind_sign<S: SecretStore>(
    store: &S,
    request_id: u64,
    ghostkey_fingerprint: &str,
    blinded_token: &[u8],
) -> HarvestDelegateResponse {
    // Load RSA private key
    let sk_der = match store.get_secret(&rsa_sk_key(ghostkey_fingerprint)) {
        Some(b) => b,
        None => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("no RSA keys for ghostkey {ghostkey_fingerprint}")),
            }
        }
    };

    let private_key = match rsa::RsaPrivateKey::from_pkcs1_der(&sk_der) {
        Ok(k) => k,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("deserialize RSA private key: {e}")),
            }
        }
    };

    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);

    // Blind-sign the token
    let mut rng = rsa::rand_core::OsRng;
    let signature = match signing_key.try_sign_with_rng(&mut rng, blinded_token) {
        Ok(sig) => sig,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureResult {
                request_id,
                result: Err(format!("blind signing failed: {e}")),
            }
        }
    };

    HarvestDelegateResponse::BlindSignatureResult {
        request_id,
        result: Ok(signature.to_bytes().to_vec()),
    }
}

fn handle_begin_transaction<S: SecretStore>(
    store: &mut S,
    request_id: u64,
    transaction_id: &str,
    our_token: harvest_common::FeedbackToken,
    our_blinded_token: Vec<u8>,
) -> HarvestDelegateResponse {
    let record = TransactionRecord {
        transaction_id: transaction_id.to_string(),
        our_token,
        our_blinded_token,
        blind_signature: None,
        // A delegate MAY read the host clock -- unlike a contract, whose
        // verdict must be a pure function of its inputs. This uses the host's
        // clock via the runtime rather than chrono's `wasmbind` backend, which
        // would make the module unloadable.
        created_at: freenet_stdlib::time::now(),
    };

    let record_bytes = match to_cbor(&record) {
        Ok(b) => b,
        Err(e) => {
            return HarvestDelegateResponse::TransactionRecorded {
                request_id,
                result: Err(format!("serialize transaction: {e}")),
            }
        }
    };

    store.set_secret(&tx_key(transaction_id), &record_bytes);

    // Update index
    let mut index = load_tx_index(store);
    if !index.contains(&transaction_id.to_string()) {
        index.push(transaction_id.to_string());
        save_tx_index(store, &index);
    }

    HarvestDelegateResponse::TransactionRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_record_blind_signature<S: SecretStore>(
    store: &mut S,
    request_id: u64,
    transaction_id: &str,
    blind_signature: Vec<u8>,
) -> HarvestDelegateResponse {
    let record_bytes = match store.get_secret(&tx_key(transaction_id)) {
        Some(b) => b,
        None => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("transaction {transaction_id} not found")),
            }
        }
    };

    let mut record: TransactionRecord = match from_cbor(&record_bytes) {
        Ok(r) => r,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("deserialize transaction: {e}")),
            }
        }
    };

    record.blind_signature = Some(blind_signature);

    let updated_bytes = match to_cbor(&record) {
        Ok(b) => b,
        Err(e) => {
            return HarvestDelegateResponse::BlindSignatureRecorded {
                request_id,
                result: Err(format!("serialize updated transaction: {e}")),
            }
        }
    };

    store.set_secret(&tx_key(transaction_id), &updated_bytes);

    HarvestDelegateResponse::BlindSignatureRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_list_transactions<S: SecretStore>(store: &S) -> HarvestDelegateResponse {
    let index = load_tx_index(store);
    let mut transactions = Vec::new();

    for tx_id in &index {
        if let Some(bytes) = store.get_secret(&tx_key(tx_id)) {
            if let Ok(record) = from_cbor::<TransactionRecord>(&bytes) {
                transactions.push(record);
            }
        }
    }

    HarvestDelegateResponse::TransactionList { transactions }
}

fn load_stores<S: SecretStore>(store: &S, ghostkey_fingerprint: &str) -> Vec<StoreRegistration> {
    store
        .get_secret(&stores_key(ghostkey_fingerprint))
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_stores<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
    stores: &[StoreRegistration],
) {
    if let Ok(bytes) = to_cbor(&stores) {
        store.set_secret(&stores_key(ghostkey_fingerprint), &bytes);
    }
}

fn handle_register_store<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
    store_contract_id: Vec<u8>,
    reputation_contract_id: Vec<u8>,
    mailbox_contract_id: Vec<u8>,
) -> HarvestDelegateResponse {
    let mut stores = load_stores(store, ghostkey_fingerprint);

    // Check for duplicate (same store contract)
    if stores
        .iter()
        .any(|s| s.store_contract_id == store_contract_id)
    {
        return HarvestDelegateResponse::StoreRegistered {
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        };
    }

    stores.push(StoreRegistration {
        store_contract_id,
        reputation_contract_id,
        mailbox_contract_id,
        store_contract_key: None,
    });
    save_stores(store, ghostkey_fingerprint, &stores);

    HarvestDelegateResponse::StoreRegistered {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
    }
}

fn handle_list_stores<S: SecretStore>(
    store: &S,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    let stores = load_stores(store, ghostkey_fingerprint);
    HarvestDelegateResponse::StoreList {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        stores,
    }
}

// ---------------------------------------------------------------------------
// Origin gating.
//
// Driven through `handle` against a real in-memory store, so the assertions
// are about what is left in the store afterwards rather than merely about what
// was returned.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod origin_gating_tests {
    use super::*;
    use crate::origin::test_origins::{a_different_web_app, harvest};
    use crate::secrets::MemSecrets;

    const FINGERPRINT: &str = "fp1";

    /// The store the attacker would like registered under the seller's
    /// fingerprint, and the seller's own. They differ, so an assertion that
    /// only one of them is present can actually fail.
    const ATTACKERS_STORE: [u8; 4] = [0xaa, 0xaa, 0xaa, 0xaa];
    const SELLERS_STORE: [u8; 4] = [0xbb, 0xbb, 0xbb, 0xbb];

    fn register(store_contract_id: [u8; 4]) -> HarvestDelegateRequest {
        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            store_contract_id: store_contract_id.to_vec(),
            reputation_contract_id: vec![1],
            mailbox_contract_id: vec![2],
        }
    }

    fn refusal_message(response: &HarvestDelegateResponse) -> &str {
        match response {
            HarvestDelegateResponse::Error { message } => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The registry decides which contracts the seller's own UI will treat as
    /// their stores, so a foreign write here is a way to put an attacker's
    /// contract in front of the seller as if it were their own.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_register_a_store() {
        let mut store = MemSecrets::default();

        let response = handle(
            &mut store,
            Some(&a_different_web_app()),
            register(ATTACKERS_STORE),
        );
        assert!(
            refusal_message(&response).contains("Harvest web app"),
            "the refusal must say why: {}",
            refusal_message(&response)
        );
        assert!(
            store.is_empty(),
            "a foreign web app wrote to the delegate's secret store"
        );

        // The genuine caller still works, and registers a DIFFERENT store --
        // so this half would fail if the write had silently done nothing.
        match handle(&mut store, Some(&harvest()), register(SELLERS_STORE)) {
            HarvestDelegateResponse::StoreRegistered { .. } => {}
            other => panic!("the Harvest web app must be able to register: {other:?}"),
        }
        match handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::ListStores {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        ) {
            HarvestDelegateResponse::StoreList { stores, .. } => {
                let ids: Vec<Vec<u8>> =
                    stores.iter().map(|s| s.store_contract_id.clone()).collect();
                assert_eq!(ids, vec![SELLERS_STORE.to_vec()], "wrong registry contents");
            }
            other => panic!("expected a StoreList, got {other:?}"),
        }
    }

    /// An unattested caller is refused as well.
    #[test]
    fn an_unattested_caller_cannot_register_a_store() {
        let mut store = MemSecrets::default();
        let response = handle(&mut store, None, register(ATTACKERS_STORE));
        assert!(refusal_message(&response).contains("could not attest"));
        assert!(store.is_empty(), "an unattested caller wrote a secret");
    }

    /// Reads are gated too: which stores and which transactions are this
    /// user's is the linkage a pseudonymous marketplace exists to withhold.
    #[test]
    fn another_web_app_cannot_read_the_sellers_registry_or_ledger() {
        let mut store = MemSecrets::default();
        handle(&mut store, Some(&harvest()), register(SELLERS_STORE));

        for request in [
            HarvestDelegateRequest::ListStores {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
            HarvestDelegateRequest::ListTransactions,
            HarvestDelegateRequest::GetRsaPublicKey {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
            },
        ] {
            let response = handle(&mut store, Some(&a_different_web_app()), request);
            assert!(
                refusal_message(&response).contains("Harvest web app"),
                "a foreign web app read Harvest's private state"
            );
        }
    }

    /// A marker sealed by a foreign caller would report a migration as already
    /// done that never ran, which loses the seller's data silently.
    #[test]
    fn another_web_app_cannot_seal_a_migration_marker() {
        let mut store = MemSecrets::default();
        let marker = "v1.store.aabb.ccdd";

        handle(
            &mut store,
            Some(&a_different_web_app()),
            HarvestDelegateRequest::SetMigrationMarker {
                marker: marker.to_string(),
                note: "sealed by nobody".into(),
            },
        );
        assert!(store.is_empty(), "a foreign web app sealed a marker");

        // Sealing it for real does write, so the assertion above is not
        // passing because the request is inert.
        handle(
            &mut store,
            Some(&harvest()),
            HarvestDelegateRequest::SetMigrationMarker {
                marker: marker.to_string(),
                note: "recovered".into(),
            },
        );
        assert!(!store.is_empty(), "the seller could not seal their marker");
    }
}
