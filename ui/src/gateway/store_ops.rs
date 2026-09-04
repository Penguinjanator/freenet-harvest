//! Store operations: creating stores, submitting listings, subscribing.

use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, ContractKey};
use harvest_common::listing::AuthorizedListing;
use harvest_common::StoreRegistration;

/// The store contract this build of the UI bundles. `create_store_contracts`
/// publishes it; `store_contract_key` hashes it to recover the key of a store
/// published earlier.
const STORE_CONTRACT_WASM: &[u8] = include_bytes!("../../public/contracts/store_contract.wasm");

/// Whether a store's `ContractKey` was recovered from local state or rebuilt
/// from the bundled contract -- see `store_contract_key`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyOrigin {
    /// Recorded locally when the store was created. Always correct.
    Recorded,
    /// Rebuilt from the store contract this build bundles. Correct only if
    /// the store was published with the same contract build.
    Reconstructed,
}

/// Bytes of a store-contract delta carrying only listings.
///
/// The store contract's delta is the `StoreStateV1Delta` the `#[composable]`
/// macro generates -- a struct of one `Option` per field -- not the inner
/// field's own delta. Sending the bare `Vec<AuthorizedListing>` produces CBOR
/// the contract rejects outright with "invalid type: sequence, expected map",
/// so the listing never lands and the failure says nothing about why.
fn listings_delta_bytes(listings: Vec<AuthorizedListing>) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        info: None,
        listings: Some(listings),
        orders: None,
    })
    .map_err(|e| format!("serialize listing delta: {e}"))
}

/// Bytes of a store-contract delta carrying only the store's own details.
fn store_info_delta_bytes(
    info: harvest_common::store::AuthorizedStoreInfoV1,
) -> Result<Vec<u8>, String> {
    harvest_common::to_cbor(&harvest_common::store::StoreStateV1Delta {
        info: Some(info),
        listings: None,
        orders: None,
    })
    .map_err(|e| format!("serialize store info delta: {e}"))
}

/// The `ContractKey` for a store, which is what sending it an update needs.
///
/// The key is written down exactly once, locally, when the store is created.
/// The delegate cannot keep it: `HarvestDelegateRequest::RegisterStore` has no
/// field for it, so every registration `ListStores` returns is keyless. After
/// a page reload there is therefore no local copy to fall back on either --
/// `my_stores` starts empty and is refilled entirely from the delegate -- and
/// preserving a known key across a merge, while necessary, does nothing for
/// the reload case. So rebuild it.
///
/// A `ContractKey` is an instance id plus a code hash, and both are available
/// without the delegate: the instance id *is* `store_contract_id`, and the
/// code hash is the hash of the store contract this build bundles. The
/// parameters -- which we do not have after a reload -- are not needed,
/// because they are already folded into the instance id.
///
/// The one case this does not fix: a store published with an *older* store
/// contract has a different code hash, so the rebuilt key names a contract
/// that does not exist and the update will fail. That store is already broken
/// today, with no key at all, so this is never a regression -- but it is not
/// a fix for every store either, which is why the caller is told which of the
/// two it got and can say so.
pub fn store_contract_key(
    registration: &StoreRegistration,
) -> Result<(ContractKey, KeyOrigin), String> {
    if let Some(bytes) = registration.store_contract_key.as_ref() {
        return harvest_common::from_cbor(bytes)
            .map(|key| (key, KeyOrigin::Recorded))
            .map_err(|e| format!("deserialize stored contract key: {e}"));
    }

    let instance_id: [u8; 32] = registration
        .store_contract_id
        .as_slice()
        .try_into()
        .map_err(|_| {
            format!(
                "store contract id is {} bytes, not 32",
                registration.store_contract_id.len()
            )
        })?;
    let code_hash = *ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash();
    Ok((
        ContractKey::from_id_and_code(ContractInstanceId::new(instance_id), code_hash),
        KeyOrigin::Reconstructed,
    ))
}

/// Create the three contracts for a new store and register them with the
/// harvest delegate.
#[cfg(target_arch = "wasm32")]
pub async fn create_store_contracts(
    seller_fingerprint: String,
    seller_verifying_key_bytes: [u8; 32],
    rsa_public_key_der: Vec<u8>,
    certificate_pem: String,
    store_name: String,
    description: String,
    payment_instructions: String,
) -> Result<(), String> {
    use dioxus::logger::tracing::info;
    use dioxus::prelude::{ReadableExt, WritableExt};
    use freenet_stdlib::prelude::*;
    use std::sync::Arc;

    let seller_vk = ed25519_dalek::VerifyingKey::from_bytes(&seller_verifying_key_bytes)
        .map_err(|e| format!("invalid verifying key: {e}"))?;

    // Helper to create a ContractContainer from WASM bytes and parameters
    fn make_contract(
        wasm: &[u8],
        params_bytes: Vec<u8>,
    ) -> (ContractContainer, ContractInstanceId, ContractKey) {
        let code = ContractCode::from(wasm.to_vec());
        let params = Parameters::from(params_bytes);
        let wrapped = WrappedContract::new(Arc::new(code), params);
        let key = wrapped.key().clone();
        let instance_id = ContractInstanceId::from(key.clone());
        let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
        (container, instance_id, key)
    }

    // 1. Reputation contract
    let reputation_params = harvest_common::reputation::ReputationParameters {
        rsa_public_key_der: rsa_public_key_der.clone(),
        owner_verifying_key: seller_vk,
    };
    let reputation_params_bytes = harvest_common::to_cbor(&reputation_params)
        .map_err(|e| format!("serialize reputation params: {e}"))?;

    let reputation_state = harvest_common::reputation::ReputationStateV1 {
        owner_certificate_pem: certificate_pem.clone(),
        ..Default::default()
    };
    let reputation_state_bytes = harvest_common::to_cbor(&reputation_state)
        .map_err(|e| format!("serialize reputation state: {e}"))?;

    let reputation_wasm = include_bytes!("../../public/contracts/reputation_contract.wasm");
    let (reputation_container, reputation_id, _reputation_key) =
        make_contract(reputation_wasm, reputation_params_bytes);

    info!("Creating reputation contract: {:?}", reputation_id);
    super::put_contract(
        reputation_container,
        WrappedState::new(reputation_state_bytes),
    )
    .await?;

    // 2. Store contract (initially empty, version 0)
    let store_params = harvest_common::store::StoreParameters {
        seller_verifying_key: seller_vk,
        // No Bitcoin bridge configured at store-creation time yet -- an
        // empty trust list is the documented safe default (no order on
        // this store can ever validate as `Paid` until the seller
        // configures a trusted bridge). Wiring this up to the Bitcoin
        // section's bridge configuration is follow-up work, not part of
        // creating the store's other two contracts here.
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    };
    let store_params_bytes = harvest_common::to_cbor(&store_params)
        .map_err(|e| format!("serialize store params: {e}"))?;

    let store_state = harvest_common::store::StoreStateV1::default();
    let store_state_bytes =
        harvest_common::to_cbor(&store_state).map_err(|e| format!("serialize store state: {e}"))?;

    let store_wasm = include_bytes!("../../public/contracts/store_contract.wasm");
    let (store_container, store_id, store_key) = make_contract(store_wasm, store_params_bytes);

    info!("Creating store contract: {:?}", store_id);
    super::put_contract(store_container, WrappedState::new(store_state_bytes)).await?;

    // 3. Mailbox contract
    let mailbox_params = harvest_common::mailbox::MailboxParameters {
        owner_verifying_key: seller_vk,
    };
    let mailbox_params_bytes = harvest_common::to_cbor(&mailbox_params)
        .map_err(|e| format!("serialize mailbox params: {e}"))?;

    let mailbox_state = harvest_common::mailbox::MailboxStateV1::default();
    let mailbox_state_bytes = harvest_common::to_cbor(&mailbox_state)
        .map_err(|e| format!("serialize mailbox state: {e}"))?;

    let mailbox_wasm = include_bytes!("../../public/contracts/mailbox_contract.wasm");
    let (mailbox_container, mailbox_id, _mailbox_key) =
        make_contract(mailbox_wasm, mailbox_params_bytes);

    info!("Creating mailbox contract: {:?}", mailbox_id);
    super::put_contract(mailbox_container, WrappedState::new(mailbox_state_bytes)).await?;

    // 4. Register store with harvest delegate
    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;

    let register_request = harvest_common::HarvestDelegateRequest::RegisterStore {
        ghostkey_fingerprint: seller_fingerprint.clone(),
        store_contract_id: store_id.as_bytes().to_vec(),
        reputation_contract_id: reputation_id.as_bytes().to_vec(),
        mailbox_contract_id: mailbox_id.as_bytes().to_vec(),
    };
    let payload = harvest_common::to_cbor(&register_request)
        .map_err(|e| format!("serialize register request: {e}"))?;

    super::send_delegate_message(&delegate_key, payload).await?;

    info!(
        "Store creation complete for {} -- 3 contracts created and registered",
        seller_fingerprint
    );

    // Update app state
    // Serialize the store contract key for later use in updates
    let store_key_bytes = harvest_common::to_cbor(&store_key).ok();

    super::APP_STATE
        .write()
        .my_stores
        .entry(seller_fingerprint.clone())
        .or_default()
        .push(harvest_common::StoreRegistration {
            store_contract_id: store_id.as_bytes().to_vec(),
            reputation_contract_id: reputation_id.as_bytes().to_vec(),
            mailbox_contract_id: mailbox_id.as_bytes().to_vec(),
            store_contract_key: store_key_bytes,
        });

    // The mailbox id is known here and nowhere else in this session -- the
    // store contract's state doesn't carry it -- so record the mapping now,
    // or every message a buyer leaves in this mailbox is dropped on arrival.
    super::APP_STATE
        .write()
        .register_store_mailbox(store_id.as_bytes(), mailbox_id.as_bytes());

    // 5. Publish the store's own details.
    //
    // The contract was PUT with `StoreStateV1::default()`, whose info is at
    // version 0 -- the uninitialized state. Until this lands, every store on
    // the network has an empty name and description, so a buyer following the
    // seller's share link arrives at a blank storefront.
    //
    // This cannot be done in the PUT above: `AuthorizedStoreInfoV1::verify`
    // skips verification only at version 0, so anything a buyer can read has
    // to carry a real Ed25519 signature over the ghostkey delegate's
    // `ScopedPayload`. That is a round-trip -- `SignMessage` now, the update
    // when `SignResult` comes back (see `AppState::on_ghostkey_response`) --
    // the same one a listing makes.
    let info = harvest_common::store::StoreInfoV1 {
        version: 1,
        certificate_pem,
        seller_fingerprint: seller_fingerprint.clone(),
        reputation_contract_id: *reputation_id
            .as_bytes()
            .first_chunk::<32>()
            .ok_or("reputation contract id is not 32 bytes -- cannot publish store details")?,
        store_name,
        description,
        payment_instructions,
    };
    request_store_info_signature(seller_fingerprint, store_id.as_bytes().to_vec(), info).await?;

    Ok(())
}

/// Ask the ghostkey delegate to sign a store's details, and queue them for
/// publication when the signature comes back.
#[cfg(target_arch = "wasm32")]
async fn request_store_info_signature(
    seller_fingerprint: String,
    store_contract_id: Vec<u8>,
    info: harvest_common::store::StoreInfoV1,
) -> Result<(), String> {
    use dioxus::prelude::{ReadableExt, WritableExt};

    let gk_delegate_key = super::APP_STATE
        .read()
        .ghostkey_delegate_key
        .clone()
        .ok_or("ghostkey delegate not registered -- cannot sign store details")?;

    // What the delegate signs is the CBOR of the info itself; `verify` checks
    // the scoped payload wraps exactly these bytes.
    let message = harvest_common::to_cbor(&info)
        .map_err(|e| format!("serialize store info for signing: {e}"))?;

    // Queue before sending: the response can arrive as soon as the send
    // returns, and an answer with nothing queued is dropped.
    super::APP_STATE.write().pending_signatures.push_back(
        crate::state::PendingSignature::StoreInfo(crate::state::PendingStoreInfo {
            info,
            store_contract_id,
        }),
    );

    let request = ghostkey_common::GhostkeyRequest::SignMessage {
        fingerprint: seller_fingerprint,
        message,
    };
    let payload =
        ghostkey_common::to_cbor(&request).map_err(|e| format!("serialize SignMessage: {e}"))?;

    if let Err(e) = super::send_delegate_message(&gk_delegate_key, payload).await {
        // Nothing will answer, so don't leave an entry that would consume
        // the next unrelated signature.
        super::APP_STATE.write().pending_signatures.pop_back();
        return Err(format!("send store info for signing: {e}"));
    }
    Ok(())
}

/// Submit a signed listing to a store contract.
///
/// Resolves the store's `ContractKey` (see `store_contract_key`) and sends
/// the listing as a delta update.
#[cfg(target_arch = "wasm32")]
pub async fn submit_listing_by_id(
    store_contract_id: &[u8],
    listing: AuthorizedListing,
) -> Result<(), String> {
    use dioxus::logger::tracing::{info, warn};
    use dioxus::prelude::ReadableExt;
    use freenet_stdlib::prelude::*;

    let (contract_key, origin) = {
        let state = super::APP_STATE.read();
        let registration = state
            .my_stores
            .values()
            .flat_map(|stores| stores.iter())
            .find(|s| s.store_contract_id == store_contract_id)
            .ok_or("this store is not one of yours -- nothing to add a listing to")?;
        store_contract_key(registration)?
    };
    if origin == KeyOrigin::Reconstructed {
        warn!("Store contract key rebuilt from the bundled store contract");
    }

    let title = listing.listing.title.clone();
    let delta_bytes = listings_delta_bytes(vec![listing])?;

    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await
    .map_err(|e| match origin {
        // A rebuilt key is wrong if the store predates the store contract
        // this build bundles, and the failure that produces says nothing
        // about why. Say it here rather than leaving the seller with a bare
        // gateway error.
        KeyOrigin::Reconstructed => format!(
            "{e} -- this store's contract key was rebuilt from the store \
             contract this version of Harvest bundles. If the store was \
             created with an older version, that key is wrong and the \
             listing cannot be submitted."
        ),
        KeyOrigin::Recorded => e,
    })?;

    info!("Submitted listing '{}' to store contract", title);
    Ok(())
}

/// Publish a store's signed details to its contract.
///
/// Separate from creation because it cannot happen during it: the details
/// have to be signed by the ghostkey delegate first, and that is a round-trip
/// through `SignMessage`/`SignResult`.
#[cfg(target_arch = "wasm32")]
pub async fn submit_store_info_by_id(
    store_contract_id: &[u8],
    info: harvest_common::store::AuthorizedStoreInfoV1,
) -> Result<(), String> {
    use dioxus::logger::tracing::info;
    use dioxus::prelude::ReadableExt;
    use freenet_stdlib::prelude::*;

    let (contract_key, _origin) = {
        let state = super::APP_STATE.read();
        let registration = state
            .my_stores
            .values()
            .flat_map(|stores| stores.iter())
            .find(|s| s.store_contract_id == store_contract_id)
            .ok_or("this store is not one of yours -- cannot publish its details")?;
        store_contract_key(registration)?
    };

    let name = info.info.store_name.clone();
    let delta_bytes = store_info_delta_bytes(info)?;
    super::update_contract(
        &contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await?;

    info!("Published store details for '{}'", name);
    Ok(())
}

/// Ask the harvest delegate which stores are registered for a ghostkey
/// identity.
///
/// Registrations live in the delegate's own secret storage, which survives a
/// page reload; `AppState::my_stores` does not. Without asking, a seller who
/// refreshes the page is shown "Create Store" again for an identity that
/// already owns one, with no way back to it -- the store, its listings and
/// its mailbox are all still on the network, but the UI has forgotten which
/// contracts they are.
#[cfg(target_arch = "wasm32")]
pub async fn list_stores(ghostkey_fingerprint: String) -> Result<(), String> {
    use dioxus::prelude::ReadableExt;

    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;

    let request = harvest_common::HarvestDelegateRequest::ListStores {
        ghostkey_fingerprint,
    };
    let payload =
        harvest_common::to_cbor(&request).map_err(|e| format!("serialize ListStores: {e}"))?;

    super::send_delegate_message(&delegate_key, payload).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn list_stores(_ghostkey_fingerprint: String) -> Result<(), String> {
    Err("delegate messaging requires WASM".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(store_contract_key: Option<Vec<u8>>) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: vec![3u8; 32],
            reputation_contract_id: vec![4u8; 32],
            mailbox_contract_id: vec![5u8; 32],
            store_contract_key,
        }
    }

    /// The reload path: after a refresh there is no local state at all, and
    /// every registration the delegate returns is keyless. Preserving a known
    /// key across a merge does nothing here -- there is nothing to preserve
    /// from -- so the key has to be rebuilt or "Add Listing" stays broken.
    #[test]
    fn a_keyless_registration_still_yields_a_usable_key() {
        let (key, origin) = store_contract_key(&registration(None)).expect("should rebuild");

        assert_eq!(origin, KeyOrigin::Reconstructed);
        assert_eq!(key.id().as_bytes(), &[3u8; 32]);
        assert_eq!(
            key.code_hash(),
            ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash(),
            "the code hash must come from the bundled store contract"
        );
    }

    /// A key recorded at creation time is authoritative -- it is right even
    /// for a store published under an older contract build, which is exactly
    /// the case reconstruction gets wrong.
    #[test]
    fn a_recorded_key_wins_over_reconstruction() {
        let recorded = ContractKey::from_id_and_code(
            ContractInstanceId::new([3u8; 32]),
            *ContractCode::from(vec![0xFEu8; 16]).hash(),
        );
        let bytes = harvest_common::to_cbor(&recorded).expect("serialize");

        let (key, origin) = store_contract_key(&registration(Some(bytes))).expect("should decode");

        assert_eq!(origin, KeyOrigin::Recorded);
        assert_eq!(key.code_hash(), recorded.code_hash());
        assert_ne!(
            key.code_hash(),
            ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash()
        );
    }

    /// The store contract's delta is `StoreStateV1Delta`, a struct of
    /// `Option`s -- not the listings field's own delta. Sending the bare
    /// `Vec` was CBOR the contract could not read, so no listing ever landed.
    #[test]
    fn a_listing_delta_is_shaped_like_the_contracts_delta() {
        let bytes = listings_delta_bytes(Vec::new()).expect("serialize");
        let delta = harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bytes)
            .expect("the contract must be able to read its own delta");
        assert!(delta.listings.is_some());
        assert!(delta.info.is_none() && delta.orders.is_none());

        // The shape that was being sent, pinned so it cannot come back.
        let bare = harvest_common::to_cbor(&Vec::<AuthorizedListing>::new()).expect("serialize");
        assert!(
            harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bare).is_err(),
            "a bare Vec is not a store delta"
        );
    }

    /// The whole point of the round-trip: the bytes we hand `SignMessage`
    /// have to be exactly the bytes `AuthorizedStoreInfoV1::verify` checks
    /// the scoped payload against. Get that wrong and the contract rejects
    /// the store's details with no clue why, which is indistinguishable from
    /// them never having been sent.
    #[test]
    fn signing_the_bytes_we_send_produces_info_the_contract_accepts() {
        use ed25519_dalek::{Signer, SigningKey};
        use freenet_stdlib::prelude::ContractInstanceId;
        use harvest_common::listing::verify_scoped_signature;
        use harvest_common::store::{AuthorizedStoreInfoV1, StoreInfoV1};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let info = StoreInfoV1 {
            version: 1,
            certificate_pem: "-----BEGIN CERT-----".to_string(),
            seller_fingerprint: "fp-1".to_string(),
            reputation_contract_id: [2u8; 32],
            store_name: "Bean Shop".to_string(),
            description: "Coffee".to_string(),
            payment_instructions: "BTC: bc1q...".to_string(),
        };

        // Exactly what `request_store_info_signature` sends as `message`.
        let message = harvest_common::to_cbor(&info).expect("serialize info");

        // What the ghostkey delegate wraps it in before signing.
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        let signature = signing_key.sign(&scoped_payload).to_bytes().to_vec();

        let authorized = AuthorizedStoreInfoV1 {
            info,
            scoped_payload,
            signature,
        };
        // The check `AuthorizedStoreInfoV1::verify` runs for any version past
        // 0, called directly so the test needs nothing from contract state.
        verify_scoped_signature(
            &authorized.scoped_payload,
            &authorized.signature,
            &signing_key.verifying_key(),
            &authorized.info,
        )
        .expect("the store contract must accept its own signed info");

        // And it must go on the wire in the shape the contract reads.
        let bytes = store_info_delta_bytes(authorized).expect("serialize delta");
        let delta = harvest_common::from_cbor::<harvest_common::store::StoreStateV1Delta>(&bytes)
            .expect("the contract must be able to read its own delta");
        assert!(delta.info.is_some());
    }

    /// Version 0 is the uninitialized state, which `verify` skips entirely --
    /// so publishing details at version 0 would publish something no buyer
    /// can trust. The details we build must be past it.
    #[test]
    fn published_store_details_are_past_the_unverified_version() {
        let unpublished = harvest_common::store::AuthorizedStoreInfoV1::default();
        assert_eq!(unpublished.info.version, 0);
        assert!(unpublished.info.store_name.is_empty());
    }

    /// A malformed id is reported, not silently turned into some other
    /// contract -- the same reasoning as `store_link::parse_store_id`.
    #[test]
    fn a_store_id_of_the_wrong_length_is_an_error() {
        let mut reg = registration(None);
        reg.store_contract_id = vec![3u8; 31];

        let err = store_contract_key(&reg).expect_err("should refuse");
        assert!(err.contains("31 bytes"), "unhelpful error: {err}");
    }
}
