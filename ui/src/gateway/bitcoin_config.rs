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
//! There is no deployed bridge or published tip contract yet (as of this
//! writing `freenet-bitcoin/bridge/src/main.rs` is `fn main(){}`), so there
//! is nothing real to pin here. This module is the single place that will
//! need to change once one exists -- analogous to how
//! `harvest_common::HARVEST_WEBAPP_CONTRACT_ID` pins the webapp container id
//! from a checked-in file. Until then every lookup here returns `None` and
//! the UI shows an honest "bridge not configured yet" state rather than
//! fabricated data.
//!
//! TODO(bitcoin-bridge-deployment): once freenet.org (or any operator)
//! deploys a `BitcoinTipContract`, fill in its bs58 `ContractInstanceId`
//! below, one per network it serves. Per-address contract ids never belong
//! here -- those are learned per-watch from
//! `harvest_common::WatchedPayment::contract_id`, reported by the delegate
//! after a successful `Watch`.

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
