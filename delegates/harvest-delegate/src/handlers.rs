use freenet_stdlib::prelude::DelegateCtx;
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

fn load_tx_index(ctx: &DelegateCtx) -> Vec<String> {
    ctx.get_secret(TX_INDEX_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_tx_index(ctx: &mut DelegateCtx, index: &[String]) {
    if let Ok(bytes) = to_cbor(&index) {
        ctx.set_secret(TX_INDEX_KEY, &bytes);
    }
}

pub fn handle(ctx: &mut DelegateCtx, request: HarvestDelegateRequest) -> HarvestDelegateResponse {
    match request {
        HarvestDelegateRequest::InitReputationKeys {
            ghostkey_fingerprint,
        } => handle_init_reputation_keys(ctx, &ghostkey_fingerprint),

        HarvestDelegateRequest::GetRsaPublicKey {
            ghostkey_fingerprint,
        } => handle_get_rsa_public_key(ctx, &ghostkey_fingerprint),

        HarvestDelegateRequest::BlindSignFeedbackToken {
            request_id,
            ghostkey_fingerprint,
            blinded_token,
        } => handle_blind_sign(ctx, request_id, &ghostkey_fingerprint, &blinded_token),

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
            ctx,
            request_id,
            &transaction_id,
            our_token,
            our_blinded_token,
        ),

        HarvestDelegateRequest::RecordBlindSignature {
            request_id,
            transaction_id,
            blind_signature,
        } => handle_record_blind_signature(ctx, request_id, &transaction_id, blind_signature),

        HarvestDelegateRequest::ListTransactions => handle_list_transactions(ctx),

        HarvestDelegateRequest::RegisterStore {
            ghostkey_fingerprint,
            store_contract_id,
            reputation_contract_id,
            mailbox_contract_id,
        } => handle_register_store(
            ctx,
            &ghostkey_fingerprint,
            store_contract_id,
            reputation_contract_id,
            mailbox_contract_id,
        ),

        HarvestDelegateRequest::ListStores {
            ghostkey_fingerprint,
        } => handle_list_stores(ctx, &ghostkey_fingerprint),

        // The migration repeat-gate. `markers` owns both the namespace and the
        // fail-safe direction; this is only the routing.
        HarvestDelegateRequest::GetMigrationMarker { marker } => {
            crate::markers::get_marker(&crate::markers::CtxMarkers(ctx), &marker)
        }

        HarvestDelegateRequest::SetMigrationMarker { marker, note } => {
            crate::markers::set_marker(&mut crate::markers::CtxMarkers(ctx), &marker, &note)
        }

        _ => HarvestDelegateResponse::Error {
            message: "unsupported request variant for this delegate version".into(),
        },
    }
}

fn handle_init_reputation_keys(
    ctx: &mut DelegateCtx,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    // Check if keys already exist
    if ctx.get_secret(&rsa_pk_key(ghostkey_fingerprint)).is_some() {
        // Return existing public key
        return match ctx.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
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
    ctx.set_secret(&rsa_sk_key(ghostkey_fingerprint), &sk_der);
    ctx.set_secret(&rsa_pk_key(ghostkey_fingerprint), &pk_der);

    HarvestDelegateResponse::ReputationKeysInitialized {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        rsa_public_key_der: pk_der,
    }
}

fn handle_get_rsa_public_key(
    ctx: &DelegateCtx,
    ghostkey_fingerprint: &str,
) -> HarvestDelegateResponse {
    match ctx.get_secret(&rsa_pk_key(ghostkey_fingerprint)) {
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

fn handle_blind_sign(
    ctx: &DelegateCtx,
    request_id: u64,
    ghostkey_fingerprint: &str,
    blinded_token: &[u8],
) -> HarvestDelegateResponse {
    // Load RSA private key
    let sk_der = match ctx.get_secret(&rsa_sk_key(ghostkey_fingerprint)) {
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

fn handle_begin_transaction(
    ctx: &mut DelegateCtx,
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

    ctx.set_secret(&tx_key(transaction_id), &record_bytes);

    // Update index
    let mut index = load_tx_index(ctx);
    if !index.contains(&transaction_id.to_string()) {
        index.push(transaction_id.to_string());
        save_tx_index(ctx, &index);
    }

    HarvestDelegateResponse::TransactionRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_record_blind_signature(
    ctx: &mut DelegateCtx,
    request_id: u64,
    transaction_id: &str,
    blind_signature: Vec<u8>,
) -> HarvestDelegateResponse {
    let record_bytes = match ctx.get_secret(&tx_key(transaction_id)) {
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

    ctx.set_secret(&tx_key(transaction_id), &updated_bytes);

    HarvestDelegateResponse::BlindSignatureRecorded {
        request_id,
        result: Ok(()),
    }
}

fn handle_list_transactions(ctx: &DelegateCtx) -> HarvestDelegateResponse {
    let index = load_tx_index(ctx);
    let mut transactions = Vec::new();

    for tx_id in &index {
        if let Some(bytes) = ctx.get_secret(&tx_key(tx_id)) {
            if let Ok(record) = from_cbor::<TransactionRecord>(&bytes) {
                transactions.push(record);
            }
        }
    }

    HarvestDelegateResponse::TransactionList { transactions }
}

fn load_stores(ctx: &DelegateCtx, ghostkey_fingerprint: &str) -> Vec<StoreRegistration> {
    ctx.get_secret(&stores_key(ghostkey_fingerprint))
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_stores(ctx: &mut DelegateCtx, ghostkey_fingerprint: &str, stores: &[StoreRegistration]) {
    if let Ok(bytes) = to_cbor(&stores) {
        ctx.set_secret(&stores_key(ghostkey_fingerprint), &bytes);
    }
}

fn handle_register_store(
    ctx: &mut DelegateCtx,
    ghostkey_fingerprint: &str,
    store_contract_id: Vec<u8>,
    reputation_contract_id: Vec<u8>,
    mailbox_contract_id: Vec<u8>,
) -> HarvestDelegateResponse {
    let mut stores = load_stores(ctx, ghostkey_fingerprint);

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
    save_stores(ctx, ghostkey_fingerprint, &stores);

    HarvestDelegateResponse::StoreRegistered {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
    }
}

fn handle_list_stores(ctx: &DelegateCtx, ghostkey_fingerprint: &str) -> HarvestDelegateResponse {
    let stores = load_stores(ctx, ghostkey_fingerprint);
    HarvestDelegateResponse::StoreList {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        stores,
    }
}
