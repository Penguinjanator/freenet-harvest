//! The bridge's public `/v1/status` HTTP endpoint -- a plain, unauthenticated
//! `fetch`, not a Freenet gateway call.
//!
//! # Why this bypasses the delegate entirely
//!
//! Everything else in `gateway::bitcoin_ops` talks to the harvest delegate,
//! which then (per `harvest_common::bitcoin_delegate`'s doc comments) is
//! meant to be the one that talks to a bridge. But delegates have zero
//! outbound-HTTP capability in `freenet-stdlib` -- there is no host function
//! for it -- so `ConfigureBridge`/`GetBridge` only ever hand the UI a
//! `BridgeEndpoint { url, .. }`; they cannot proxy a live HTTP status
//! request. The browser can make that call directly, and the bridge's
//! `/v1/status` route (see `freenet-bitcoin/bridge/src/service.rs::status`)
//! is deliberately public and unauthenticated for exactly this reason: it
//! needs no Ghost Key, no challenge, nothing.
//!
//! # Why this exists at all, given "no polling"
//!
//! This is a one-time discovery step, not the realtime path. Its only job
//! is to learn each network's `tip_contract_id` (and `address_code_hash`,
//! for later) so the UI can `subscribe_contract` to the real Freenet
//! contract -- from there on, live updates flow through the normal
//! `UpdateNotification` path with no further HTTP calls. See
//! `refresh_bridge_status` for where this feeds back into `AppState`.

use serde::Deserialize;

/// The bridge's self-reported status. Shape matches exactly what
/// `bridge/src/service.rs::status` serializes -- a hand-built JSON object,
/// not a direct serialization of `freenet_bitcoin_common::BridgeStatus`
/// (which has a slightly different field set), so this has its own type
/// rather than reusing that one.
#[derive(Deserialize, Debug)]
struct BridgeStatusResponse {
    #[allow(dead_code)]
    bridge_id: String,
    /// Hex-encoded BLAKE3 hash of the `BitcoinAddressContract` WASM this
    /// bridge's tip/address contracts were built against. Not yet consumed
    /// here -- needed once the UI computes per-watch address contract ids
    /// itself rather than relying on `WatchedPayment::contract_id` -- kept
    /// on this type now so that's a one-line change later, not a reparse.
    #[allow(dead_code)]
    address_code_hash: Option<String>,
    networks: Vec<BridgeNetworkStatus>,
}

#[derive(Deserialize, Debug)]
struct BridgeNetworkStatus {
    /// e.g. "signet" -- parses via `BitcoinNetwork::from_str`.
    network: String,
    #[allow(dead_code)]
    tip_height: u32,
    #[allow(dead_code)]
    initial_block_download: bool,
    #[allow(dead_code)]
    accepted_auth: Vec<String>,
    tip_contract_id: Option<String>,
}

/// Fetch `<base_url>/v1/status` and register every network's tip contract
/// (if any) it reports, so `AppState` starts subscribing to it. Errors are
/// logged, not propagated -- this runs fire-and-forget right after a
/// `GetBridge`/`ConfigureBridge` response, and a bridge that's briefly
/// unreachable shouldn't produce a user-facing failure for what is, from
/// the user's perspective, just background discovery.
#[cfg(target_arch = "wasm32")]
pub async fn refresh_bridge_status(base_url: String) {
    match fetch_status(&base_url).await {
        Ok(status) => {
            let mut app = super::APP_STATE.write();
            for net in status.networks {
                let Ok(network) = net
                    .network
                    .parse::<freenet_bitcoin_common::BitcoinNetwork>()
                else {
                    dioxus::logger::tracing::warn!(
                        "Bridge at {base_url} reported an unrecognized network: {}",
                        net.network
                    );
                    continue;
                };
                if let Some(contract_id) = net.tip_contract_id {
                    app.register_tip_contract_with_id(network, &contract_id);
                } else {
                    dioxus::logger::tracing::info!(
                        "Bridge at {base_url} has no tip contract for {} yet",
                        net.network
                    );
                }
            }
        }
        Err(e) => {
            dioxus::logger::tracing::warn!("Failed to fetch bridge status from {base_url}: {e}");
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn refresh_bridge_status(_base_url: String) {}

#[cfg(target_arch = "wasm32")]
async fn fetch_status(base_url: &str) -> Result<BridgeStatusResponse, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let url = format!("{}/v1/status", base_url.trim_end_matches('/'));
    let window = web_sys::window().ok_or("no window")?;
    let response_value = JsFuture::from(window.fetch_with_str(&url))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;
    let response: web_sys::Response = response_value
        .dyn_into()
        .map_err(|_| "fetch did not resolve to a Response".to_string())?;
    if !response.ok() {
        return Err(format!("bridge returned HTTP {}", response.status()));
    }
    let text_promise = response
        .text()
        .map_err(|e| format!("response.text() failed: {e:?}"))?;
    let text_value = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("reading response body failed: {e:?}"))?;
    let text = text_value
        .as_string()
        .ok_or("response body was not a string")?;
    serde_json::from_str(&text).map_err(|e| format!("parse bridge status JSON: {e}"))
}
