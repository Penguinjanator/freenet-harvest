//! Store operations: creating stores, submitting listings, subscribing.

use harvest_common::listing::AuthorizedListing;

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
    ) -> (ContractContainer, ContractInstanceId) {
        let code = ContractCode::from(wasm.to_vec());
        let params = Parameters::from(params_bytes);
        let wrapped = WrappedContract::new(Arc::new(code), params);
        let key = wrapped.key().clone();
        let instance_id = ContractInstanceId::from(key);
        let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
        (container, instance_id)
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
    let (reputation_container, reputation_id) =
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
    };
    let store_params_bytes = harvest_common::to_cbor(&store_params)
        .map_err(|e| format!("serialize store params: {e}"))?;

    let store_state = harvest_common::store::StoreStateV1::default();
    let store_state_bytes =
        harvest_common::to_cbor(&store_state).map_err(|e| format!("serialize store state: {e}"))?;

    let store_wasm = include_bytes!("../../public/contracts/store_contract.wasm");
    let (store_container, store_id) = make_contract(store_wasm, store_params_bytes);

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
    let (mailbox_container, mailbox_id) = make_contract(mailbox_wasm, mailbox_params_bytes);

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
    super::APP_STATE
        .write()
        .my_stores
        .entry(seller_fingerprint)
        .or_default()
        .push(harvest_common::StoreRegistration {
            store_contract_id: store_id.as_bytes().to_vec(),
            reputation_contract_id: reputation_id.as_bytes().to_vec(),
            mailbox_contract_id: mailbox_id.as_bytes().to_vec(),
        });

    Ok(())
}

/// Submit a signed listing as a delta update to a store contract.
#[cfg(target_arch = "wasm32")]
pub async fn submit_listing(
    _store_contract_key: &freenet_stdlib::prelude::ContractKey,
    _listing: AuthorizedListing,
) -> Result<(), String> {
    use dioxus::logger::tracing::info;
    use freenet_stdlib::prelude::*;

    let delta = vec![_listing];
    let delta_bytes =
        harvest_common::to_cbor(&delta).map_err(|e| format!("serialize listing delta: {e}"))?;

    super::update_contract(
        _store_contract_key,
        UpdateData::Delta(StateDelta::from(delta_bytes)),
    )
    .await?;

    info!("Submitted listing to store contract");
    Ok(())
}
