//! Well-known Bitcoin contract configuration.
//!
//! # Why this file exists and why it is empty today
//!
//! The first-run Bitcoin panel needs to subscribe to a network's
//! `BitcoinTipContract` before the user has watched anything or connected a
//! Ghost Key -- that is the whole point of showing live chain data with no
//! credential. Subscribing needs that contract's `ContractInstanceId`, which
//! is a hash over its WASM code plus its `BitcoinTipParameters` (network +
//! trusted bridge keys).
//!
//! A bridge now exists (`freenet-bitcoin/bridge`, deployed on nova against
//! signet), but its tip-contract id deliberately stays OUT of this file.
//!
//! A `BitcoinTipContract`'s id is a hash over its WASM plus its parameters,
//! and its parameters include `trusted_bridges`, which is per-deployment
//! rather than a fixed per-network constant. A compiled-in id would therefore
//! go stale on any re-key -- including a bare version bump -- and the failure
//! is silent: every read comes back looking like "this network has no data
//! yet". So the id is fetched at runtime from the bridge's unauthenticated
//! `GET /v1/status`, which reports it (see `bitcoin_bridge_http`).
//!
//! What CANNOT be discovered at runtime is which bridge to ask in the first
//! place, so that is the one thing defaulted here.

use freenet_bitcoin_common::BitcoinNetwork;

/// bs58 `ContractInstanceId` of the network-wide `BitcoinTipContract`, or
/// `None` if no deployment is known for that network yet.
pub fn well_known_tip_contract_id(network: BitcoinNetwork) -> Option<&'static str> {
    match network {
        BitcoinNetwork::Bitcoin => None,
        BitcoinNetwork::Testnet4 => None,
        // Signet is the network a demo bridge would most plausibly run
        // first (trivial difficulty, no real money at stake) -- still None
        // until one is actually deployed and this constant is filled in.
        BitcoinNetwork::Signet => None,
        BitcoinNetwork::Regtest => None,
    }
}

/// The network the first-run panel defaults to showing before the user has
/// picked one. Signet for the same reason as above: it's where a demo
/// deployment would live.
pub fn default_network() -> BitcoinNetwork {
    BitcoinNetwork::Signet
}

/// The bridge to ask before the user has configured one.
///
/// # Why localhost, and not a freenet.org URL
///
/// Defaulting to the user's own machine matches what the architecture actually
/// recommends: running your own bridge is the real answer to bridge-operator
/// correlation, because an operator necessarily learns which scripts it has
/// been asked to synchronize. A default that points everyone at one operator
/// would quietly make the privacy-worst option the path of least resistance.
///
/// It also fails honestly. If no local bridge is running the fetch simply
/// fails and the UI says no bridge is configured, rather than showing data
/// from a service the user never chose.
///
/// A hosted freenet.org bridge is a genuine product decision that has not been
/// made: it needs a published URL, a decision about who signs for it, and --
/// because it would be internet-facing rather than loopback -- the Ghost Key
/// authorization policy switched on and rate limiting configured. Until then,
/// pointing the default at a URL that does not exist would be worse than
/// pointing it at one that might.
pub fn default_bridge_url() -> &'static str {
    "http://127.0.0.1:8431"
}
