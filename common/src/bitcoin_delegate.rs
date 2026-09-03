//! The Harvest delegate's Bitcoin payment surface.
//!
//! # Why the watch list lives here and nowhere else
//!
//! Everything in this module is **private local state on the user's own
//! machine**. None of it is ever written to a Freenet contract.
//!
//! The tempting alternative is a `WatchRegistry` contract listing the scripts
//! people want synchronized, which would make the bridge's job trivial. It is
//! also the one thing this design refuses to build: Freenet contracts are
//! reachable by anyone who knows the key and are replicated indefinitely, so
//! such a registry would be a permanent, globally enumerable index of who
//! cares about which Bitcoin address. Merely *watching* an address must never
//! make that interest public.
//!
//! An order's payment destination IS public, in the Harvest store contract —
//! but for a different and legitimate reason: decentralized payment
//! verification is impossible unless everyone can see what was owed and where.
//! That is application semantics requiring publication. It is not the same as
//! publishing a user's arbitrary list of interests, and the two must not be
//! allowed to blur together.
//!
//! # What the bridge unavoidably learns
//!
//! To synchronize script X, the bridge has to be told about X. So the operator
//! of a bridge you use knows that *somebody it authorized* asked about X, and
//! — because a Ghost Key certificate is a stable identifier reused across
//! requests — can link a single user's requests to each other. That is real,
//! it is not fixed by anything in this file, and it is written up honestly in
//! `docs/privacy.md` along with the mitigations available to a user who cares.

use serde::{Deserialize, Serialize};

use freenet_bitcoin_common::{BitcoinNetwork, BridgeId};

use crate::payment::OrderId;

/// One script the user is privately watching.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WatchedPayment {
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey`. The identity; the address string is display.
    pub script_pubkey: Vec<u8>,
    /// Human-readable address, for display only.
    pub address: String,
    /// The user's private label. Never leaves this machine.
    pub label: Option<String>,
    /// Set when this watch exists because of a Harvest order rather than a
    /// manual request. Both kinds share the same machinery and the same
    /// privacy properties; this only drives how the UI groups them.
    pub order_id: Option<OrderId>,
    pub expected_amount_sats: Option<u64>,
    /// Freenet contract instance id (bs58) of the address contract, so the UI
    /// can subscribe without recomputing the key.
    pub contract_id: Option<String>,
    /// Milliseconds since the Unix epoch, taken from the UI at the moment of
    /// the request. Delegates may read a clock; contracts may not, and none of
    /// this value ever reaches one.
    pub added_at_ms: u64,
    /// Whether a bridge has confirmed it is synchronizing this script.
    pub bridge_synced: bool,
    /// Why the last bridge request failed, if it did. Surfaced so the UI can
    /// say "needs a Ghost Key" rather than silently showing nothing.
    pub last_error: Option<String>,
}

impl WatchedPayment {
    /// Stable key for this watch: network plus script.
    pub fn key(&self) -> String {
        format!(
            "{}:{}",
            self.network.as_str(),
            hex::encode(&self.script_pubkey)
        )
    }
}

/// How the delegate should authorize itself to a bridge.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BridgeAuthMode {
    /// The bridge serves anyone; send no credential.
    Open,
    /// Authorize with the user's Ghost Key.
    ///
    /// The delegate holds the credential; it is never handed to a Harvest
    /// contract, and never to the UI in a form the UI could replay elsewhere.
    GhostKey { fingerprint: String },
}

/// A bridge the user's delegate will talk to.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BridgeEndpoint {
    /// HTTPS base URL of the bridge service.
    pub url: String,
    /// The bridge's signing key, so observations can be verified.
    ///
    /// Separate from anything about authorization: this is "whose signature do
    /// I accept on Bitcoin facts", not "may I ask this bridge for work".
    pub bridge_id: BridgeId,
    pub network: BitcoinNetwork,
    pub auth: BridgeAuthMode,
}

/// Requests the UI sends the delegate about Bitcoin payments.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BitcoinDelegateRequest {
    /// Start watching a script. Purely local until the delegate asks a bridge
    /// to synchronize it.
    Watch {
        request_id: u64,
        watch: WatchedPayment,
    },
    /// Stop watching. Also asks the bridge to drop its interest, though the
    /// bridge may keep synchronizing for other users — and deliberately does
    /// not say whether it will, since that would leak whether anybody else
    /// is watching the same address.
    Unwatch {
        request_id: u64,
        network: BitcoinNetwork,
        script_pubkey: Vec<u8>,
    },
    /// The user's private watch list.
    ListWatched,
    /// Attach a watch to an order, so the UI can group it under Payments.
    AssociateOrder {
        request_id: u64,
        network: BitcoinNetwork,
        script_pubkey: Vec<u8>,
        order_id: OrderId,
        expected_amount_sats: u64,
    },
    /// Configure which bridge to use and how to authorize to it.
    ConfigureBridge {
        request_id: u64,
        endpoint: BridgeEndpoint,
    },
    /// The configured bridge, if any. The UI needs this to render the
    /// public status panel before the user has authenticated with anything.
    GetBridge,
}

#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum BitcoinDelegateResponse {
    Watched {
        request_id: u64,
        result: Result<WatchedPayment, String>,
    },
    Unwatched {
        request_id: u64,
        result: Result<(), String>,
    },
    WatchList {
        watches: Vec<WatchedPayment>,
    },
    OrderAssociated {
        request_id: u64,
        result: Result<(), String>,
    },
    BridgeConfigured {
        request_id: u64,
        result: Result<(), String>,
    },
    Bridge {
        endpoint: Option<BridgeEndpoint>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> WatchedPayment {
        WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xde, 0xad],
            address: "tb1qexample".into(),
            label: Some("rent".into()),
            order_id: None,
            expected_amount_sats: Some(50_000),
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    #[test]
    fn watch_key_separates_networks_for_one_script() {
        let mut a = watch();
        let mut b = watch();
        a.network = BitcoinNetwork::Bitcoin;
        b.network = BitcoinNetwork::Signet;
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn requests_roundtrip_through_cbor() {
        let req = BitcoinDelegateRequest::Watch {
            request_id: 7,
            watch: watch(),
        };
        let bytes = crate::to_cbor(&req).unwrap();
        assert_eq!(
            crate::from_cbor::<BitcoinDelegateRequest>(&bytes).unwrap(),
            req
        );
    }

    /// The private label must not be something the UI can accidentally leak
    /// into a bridge request: the bridge protocol has no field for it.
    #[test]
    fn the_bridge_watch_request_has_nowhere_to_put_a_private_label() {
        let w = watch();
        let req = freenet_bitcoin_common::WatchRequest {
            network: w.network,
            script_pubkey: w.script_pubkey.clone(),
            scan_from_height: None,
        };
        let encoded = crate::to_cbor(&req).unwrap();
        let haystack = String::from_utf8_lossy(&encoded).to_string();
        assert!(
            !haystack.contains("rent"),
            "a private label reached the bridge wire format"
        );
    }
}
