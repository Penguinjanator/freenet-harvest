//! Store operations: creating stores, submitting listings, subscribing.
//!
//! These are high-level operations that coordinate multiple gateway calls
//! (delegate messages + contract PUTs) into coherent user flows.

#[cfg(target_arch = "wasm32")]
use dioxus::logger::tracing::{error, info};
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::prelude::*;

use harvest_common::listing::AuthorizedListing;

/// Create the three contracts for a new store and register them with the
/// harvest delegate.
///
/// Requires:
/// - `seller_fingerprint`: the ghostkey identity to use
/// - `seller_verifying_key_bytes`: 32-byte Ed25519 verifying key
/// - `rsa_public_key_der`: RSA public key from InitReputationKeys
/// - `certificate_pem`: ghostkey certificate PEM
/// - `store_name`: human-readable store name
/// - `description`: store description
/// - `payment_instructions`: how buyers should pay
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
    let seller_vk = ed25519_dalek::VerifyingKey::from_bytes(&seller_verifying_key_bytes)
        .map_err(|e| format!("invalid verifying key: {e}"))?;

    // 1. Create and PUT the reputation contract
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

    let reputation_code = include_bytes!("../../public/contracts/reputation_contract.wasm");
    let reputation_contract_code = ContractCode::from(reputation_code.to_vec());
    let reputation_params_obj = Parameters::from(reputation_params_bytes.clone());
    let reputation_contract = Contract::from((&reputation_contract_code, &reputation_params_obj));
    let reputation_key = reputation_contract.key();
    let reputation_instance_id = ContractInstanceId::from(*reputation_key);
    let reputation_container = ContractContainer::Wasm(WasmAPIVersion::V1(reputation_contract));

    info!("Creating reputation contract: {:?}", reputation_instance_id);
    super::put_contract(
        reputation_container,
        WrappedState::new(reputation_state_bytes),
    )
    .await?;

    // 2. Create and PUT the store contract
    let store_params = harvest_common::store::StoreParameters {
        seller_verifying_key: seller_vk,
    };
    let store_params_bytes = harvest_common::to_cbor(&store_params)
        .map_err(|e| format!("serialize store params: {e}"))?;

    let store_info = harvest_common::store::StoreInfoV1 {
        version: 1,
        certificate_pem: certificate_pem.clone(),
        seller_fingerprint: seller_fingerprint.clone(),
        reputation_contract_id: *reputation_instance_id
            .as_bytes()
            .first_chunk::<32>()
            .ok_or("reputation contract ID not 32 bytes")?,
        store_name,
        description,
        payment_instructions,
    };

    // The store info needs to be signed, but we don't have the signing key
    // (it's in the ghostkey delegate). For the initial PUT, we create a
    // default (unsigned, version 0) state and update it with a signed version
    // after the ghostkey delegate signs it.
    let store_state = harvest_common::store::StoreStateV1::default();
    let store_state_bytes =
        harvest_common::to_cbor(&store_state).map_err(|e| format!("serialize store state: {e}"))?;

    let store_code = include_bytes!("../../public/contracts/store_contract.wasm");
    let store_contract_code = ContractCode::from(store_code.to_vec());
    let store_params_obj = Parameters::from(store_params_bytes.clone());
    let store_contract = Contract::from((&store_contract_code, &store_params_obj));
    let store_key = store_contract.key();
    let store_instance_id = ContractInstanceId::from(*store_key);
    let store_container = ContractContainer::Wasm(WasmAPIVersion::V1(store_contract));

    info!("Creating store contract: {:?}", store_instance_id);
    super::put_contract(store_container, WrappedState::new(store_state_bytes)).await?;

    // 3. Create and PUT the mailbox contract
    let mailbox_params = harvest_common::mailbox::MailboxParameters {
        owner_verifying_key: seller_vk,
    };
    let mailbox_params_bytes = harvest_common::to_cbor(&mailbox_params)
        .map_err(|e| format!("serialize mailbox params: {e}"))?;

    let mailbox_state = harvest_common::mailbox::MailboxStateV1::default();
    let mailbox_state_bytes = harvest_common::to_cbor(&mailbox_state)
        .map_err(|e| format!("serialize mailbox state: {e}"))?;

    let mailbox_code = include_bytes!("../../public/contracts/mailbox_contract.wasm");
    let mailbox_contract_code = ContractCode::from(mailbox_code.to_vec());
    let mailbox_params_obj = Parameters::from(mailbox_params_bytes.clone());
    let mailbox_contract = Contract::from((&mailbox_contract_code, &mailbox_params_obj));
    let mailbox_key = mailbox_contract.key();
    let mailbox_instance_id = ContractInstanceId::from(*mailbox_key);
    let mailbox_container = ContractContainer::Wasm(WasmAPIVersion::V1(mailbox_contract));

    info!("Creating mailbox contract: {:?}", mailbox_instance_id);
    super::put_contract(mailbox_container, WrappedState::new(mailbox_state_bytes)).await?;

    // 4. Register the store with the harvest delegate
    let app_state = super::APP_STATE.read();
    let delegate_key = app_state
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;
    drop(app_state);

    let register_request = harvest_common::HarvestDelegateRequest::RegisterStore {
        ghostkey_fingerprint: seller_fingerprint.clone(),
        store_contract_id: store_instance_id.as_bytes().to_vec(),
        reputation_contract_id: reputation_instance_id.as_bytes().to_vec(),
        mailbox_contract_id: mailbox_instance_id.as_bytes().to_vec(),
    };
    let payload = harvest_common::to_cbor(&register_request)
        .map_err(|e| format!("serialize register request: {e}"))?;

    super::send_delegate_message(&delegate_key, payload).await?;

    info!(
        "Store creation complete for {} -- 3 contracts created and registered",
        seller_fingerprint
    );

    // Store the info and contract IDs in app state so the UI updates
    {
        let mut app_state = super::APP_STATE.write();
        app_state
            .my_stores
            .entry(seller_fingerprint)
            .or_default()
            .push(harvest_common::StoreRegistration {
                store_contract_id: store_instance_id.as_bytes().to_vec(),
                reputation_contract_id: reputation_instance_id.as_bytes().to_vec(),
                mailbox_contract_id: mailbox_instance_id.as_bytes().to_vec(),
            });
    }

    Ok(())
}

/// Submit a signed listing as a delta update to a store contract.
#[cfg(target_arch = "wasm32")]
pub async fn submit_listing(
    store_contract_key: &ContractKey,
    listing: AuthorizedListing,
) -> Result<(), String> {
    let delta = vec![listing];
    let delta_bytes =
        harvest_common::to_cbor(&delta).map_err(|e| format!("serialize listing delta: {e}"))?;

    super::update_contract(
        store_contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await?;

    info!("Submitted listing to store contract");
    Ok(())
}
