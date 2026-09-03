//! Routes incoming HostResponse messages to appropriate handlers.
//!
//! The Freenet gateway sends responses for contract operations (GET, PUT,
//! Subscribe, Update) and delegate operations. This module deserializes
//! them and updates application state, and triggers follow-up operations
//! (e.g., subscribing to a store's reputation contract after receiving
//! the store state).

use dioxus::logger::tracing::{error, info, warn};
use freenet_stdlib::client_api::{ContractResponse, HostResponse};

use harvest_common::{from_cbor, HarvestDelegateResponse};

use super::APP_STATE;

/// Process a single host response from the Freenet gateway.
pub fn handle_response(response: Result<HostResponse, String>) {
    match response {
        Ok(HostResponse::ContractResponse(contract_response)) => {
            handle_contract_response(contract_response);
        }
        Ok(HostResponse::DelegateResponse { key, values }) => {
            handle_delegate_response(key, values);
        }
        Ok(HostResponse::QueryResponse(_)) => {
            // Node queries -- not used by Harvest yet
        }
        Ok(other) => {
            info!("Unhandled host response: {:?}", other);
        }
        Err(e) => {
            error!("Gateway error: {}", e);
        }
    }
}

fn handle_contract_response(response: ContractResponse) {
    match response {
        ContractResponse::GetResponse {
            key,
            contract: _,
            state,
        } => {
            let contract_id = key.as_bytes().to_vec();
            let state_bytes = state.as_ref().to_vec();

            info!("GET response for contract ({} bytes)", state_bytes.len());

            // Check if this is a store state -- if so, we need to follow
            // the reputation contract link
            let reputation_to_subscribe = check_for_reputation_link(&state_bytes);

            {
                let mut app = APP_STATE.write();
                app.on_contract_state(contract_id, state_bytes);
            }

            // Subscribe to the reputation contract if we found one
            if let Some(reputation_id) = reputation_to_subscribe {
                follow_reputation_link(reputation_id);
            }
        }

        ContractResponse::PutResponse { key } => {
            info!("PUT response for contract {:?}", key);
        }

        ContractResponse::UpdateResponse { key, summary: _ } => {
            info!("UPDATE response for contract {:?}", key);
        }

        ContractResponse::SubscribeResponse { key, subscribed } => {
            if subscribed {
                info!("Subscribed to contract {:?}", key);
            } else {
                warn!("Subscription failed for contract {:?}", key);
            }
        }

        ContractResponse::UpdateNotification { key, update: _ } => {
            info!("Update notification for contract {:?}", key);
            // Re-GET the authoritative full state rather than trying to
            // apply `update` in place. `update` is very often a genuine
            // delta -- for composable states (store, bitcoin tip/address)
            // that's a *different* wire shape from the full state (e.g.
            // `StoreStateV1Delta` has `orders: Option<Vec<AuthorizedOrder>>`
            // where `StoreStateV1` has `orders: OrdersV1`), so re-parsing
            // delta bytes as full state silently fails and the update gets
            // dropped -- exactly the bug that would have made "realtime"
            // updates invisible. Re-GET is more traffic but always correct;
            // proper client-side delta application would need each
            // contract's `ComposableState::apply_delta` (and its
            // `Parameters`) wired into the UI, which isn't done anywhere in
            // this codebase yet.
            request_full_state(key);
        }

        _ => {
            info!("Unhandled contract response");
        }
    }
}

/// If the state bytes deserialize as a StoreStateV1, extract the reputation
/// contract ID so we can subscribe to it automatically.
fn check_for_reputation_link(state_bytes: &[u8]) -> Option<Vec<u8>> {
    let store_state =
        harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(state_bytes).ok()?;
    let reputation_id = store_state.info.info.reputation_contract_id;
    // Don't follow if it's all zeros (uninitialized)
    if reputation_id == [0u8; 32] {
        return None;
    }
    Some(reputation_id.to_vec())
}

/// Re-GET a contract's full state (re-subscribing is a harmless no-op if we
/// already are). See the long comment at the `UpdateNotification` call site
/// for why this exists instead of applying `update` in place.
fn request_full_state(_key: freenet_stdlib::prelude::ContractKey) {
    #[cfg(target_arch = "wasm32")]
    {
        let instance_id = *_key.id();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = super::get_contract(&instance_id, true).await {
                error!("Failed to re-GET contract after update notification: {}", e);
            }
        });
    }
}

/// Subscribe to a reputation contract that a store links to.
fn follow_reputation_link(_reputation_id: Vec<u8>) {
    info!("Following reputation link -- subscribing to reputation contract");

    #[cfg(target_arch = "wasm32")]
    {
        let reputation_id = _reputation_id;
        wasm_bindgen_futures::spawn_local(async move {
            if reputation_id.len() != 32 {
                error!(
                    "Reputation contract ID is not 32 bytes: {}",
                    reputation_id.len()
                );
                return;
            }
            let mut id_bytes = [0u8; 32];
            id_bytes.copy_from_slice(&reputation_id);
            let contract_id = freenet_stdlib::prelude::ContractInstanceId::new(id_bytes);
            if let Err(e) = super::get_contract(&contract_id, true).await {
                error!("Failed to subscribe to reputation contract: {}", e);
            }
        });
    }
}

fn handle_delegate_response(
    key: freenet_stdlib::prelude::DelegateKey,
    values: Vec<freenet_stdlib::prelude::OutboundDelegateMsg>,
) {
    for value in values {
        match value {
            freenet_stdlib::prelude::OutboundDelegateMsg::ApplicationMessage(msg) => {
                // Try harvest delegate response first
                match from_cbor::<HarvestDelegateResponse>(&msg.payload) {
                    Ok(response) => {
                        info!("Harvest delegate response: {:?}", response);
                        let mut app = APP_STATE.write();
                        app.on_delegate_response(response);
                    }
                    Err(_) => {
                        // Try ghostkey delegate response
                        match from_cbor::<ghostkey_common::GhostkeyResponse>(&msg.payload) {
                            Ok(gk_response) => {
                                info!("Ghostkey response: {:?}", gk_response);
                                let mut app = APP_STATE.write();
                                app.on_ghostkey_response(gk_response);
                            }
                            Err(_) => {
                                // Try the harvest delegate's Bitcoin surface
                                match from_cbor::<harvest_common::BitcoinDelegateResponse>(
                                    &msg.payload,
                                ) {
                                    Ok(btc_response) => {
                                        info!("Bitcoin delegate response: {:?}", btc_response);
                                        let mut app = APP_STATE.write();
                                        app.on_bitcoin_delegate_response(btc_response);
                                    }
                                    Err(e) => {
                                        error!(
                                            "Unknown delegate response from {:?} (err: {e})",
                                            key
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            freenet_stdlib::prelude::OutboundDelegateMsg::RequestUserInput(req) => {
                info!("Delegate requesting user input: {:?}", req.message);
                // Permission prompts from the ghostkey delegate will arrive here.
                // The Freenet runtime handles displaying these to the user and
                // routing the response back to the delegate.
            }
            _ => {
                info!("Unhandled delegate outbound message");
            }
        }
    }
}
