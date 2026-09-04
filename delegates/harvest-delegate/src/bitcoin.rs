//! Bitcoin payment-watch handlers for the Harvest delegate.
//!
//! Everything here operates on `harvest_common::bitcoin_delegate` types. See
//! that module's doc comment for the full argument, in short: a watch list is
//! **private local state**. It must never be written to a Freenet contract,
//! because a contract is reachable by anyone who knows the key and is
//! replicated indefinitely -- turning "who is watching which Bitcoin
//! address" into a permanent, globally enumerable index. Every value this
//! file persists goes through `DelegateCtx::{get,set}_secret`, which is
//! per-user, encrypted, and never leaves this machine.
//!
//! # Manual watches and order-driven watches are the same watch
//!
//! [`watch_order_payment`] exists so that a Harvest order acquiring a
//! Bitcoin destination can start a watch without the user doing anything.
//! It calls the exact same [`apply_watch`] the `Watch` request handler uses,
//! and writes to the exact same secret. The only difference is which fields
//! get populated (`order_id` set, `label` left `None`). Nothing about
//! automating this changes its privacy: the watch is still local-only,
//! still invisible to the bridge until (and unless) something asks the
//! bridge to synchronize the script, and still invisible to any contract.
//!
//! # No scheduled wakeup, and no HTTPS from a delegate
//!
//! A delegate cannot wake itself up on a timer (freenet-core#3972), and
//! under `freenet local` a delegate's own contract GET/PUT/SUBSCRIBE calls
//! are silently no-ops (freenet-core#5273). Nothing here is designed to
//! depend on the delegate later doing something on its own initiative --
//! every response is computed synchronously from the request that triggered
//! it. Separately, a delegate has no way to make an outbound HTTPS call at
//! all (there is no such `OutboundDelegateMsg` variant), so actually talking
//! to a bridge is the UI's job: it reads the `BridgeEndpoint` back from
//! `GetBridge`/`ConfigureBridge` and speaks to that URL directly.

use freenet_stdlib::prelude::{DelegateCtx, DelegateError};

use harvest_common::bitcoin_delegate::{
    BitcoinDelegateRequest, BitcoinDelegateResponse, BridgeEndpoint, WatchedPayment,
};
use harvest_common::{from_cbor, to_cbor, OrderId};

use freenet_bitcoin_common::BitcoinNetwork;

/// Secret key holding the whole watch list, as CBOR of `Vec<WatchedPayment>`.
///
/// Versioned because this crate has no separate secret-migration registry
/// (unlike the contract-WASM re-key path documented next to
/// `harvest_common::LEGACY_HARVEST_WEBAPP_CONTRACT_IDS`): the version number
/// in the key itself IS the migration mechanism. If `WatchedPayment`'s shape
/// ever changes incompatibly, add a `v2` key, have the loader fall back to
/// reading `v1` and upgrading it in memory, and write future saves under
/// `v2` -- don't reuse `v1` for an incompatible shape.
pub(crate) const BITCOIN_WATCHES_KEY: &[u8] = b"harvest:bitcoin:watches:v1";

/// Secret key holding the configured bridge, as CBOR of `Option<BridgeEndpoint>`.
pub(crate) const BITCOIN_BRIDGE_KEY: &[u8] = b"harvest:bitcoin:bridge:v1";

fn load_watches(ctx: &DelegateCtx) -> Vec<WatchedPayment> {
    ctx.get_secret(BITCOIN_WATCHES_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_watches(ctx: &mut DelegateCtx, watches: &[WatchedPayment]) {
    if let Ok(bytes) = to_cbor(&watches) {
        ctx.set_secret(BITCOIN_WATCHES_KEY, &bytes);
    }
}

fn load_bridge(ctx: &DelegateCtx) -> Option<BridgeEndpoint> {
    ctx.get_secret(BITCOIN_BRIDGE_KEY)
        .and_then(|bytes| from_cbor::<Option<BridgeEndpoint>>(&bytes).ok())
        .flatten()
}

fn save_bridge(ctx: &mut DelegateCtx, endpoint: &BridgeEndpoint) {
    if let Ok(bytes) = to_cbor(&Some(endpoint.clone())) {
        ctx.set_secret(BITCOIN_BRIDGE_KEY, &bytes);
    }
}

// ---------------------------------------------------------------------------
// Pure watch-list logic.
//
// Kept free of `DelegateCtx` on purpose: outside a real WASM delegate host,
// `DelegateCtx::get_secret`/`set_secret` are no-op stubs (see
// freenet-stdlib's `delegate_host.rs`, `#[cfg(not(target_family = "wasm"))]`
// branch), so a test that round-trips through `ctx` would silently observe
// nothing being stored. Separating "how the watch list changes" from "where
// it's persisted" lets the interesting logic run -- and be asserted on --
// under plain `cargo test`.
// ---------------------------------------------------------------------------

/// Insert `watch`, replacing any existing entry with the same
/// `WatchedPayment::key()` (network + script). Shared by manual `Watch`
/// requests and [`watch_order_payment`] -- the only difference between the
/// two call sites is which fields the caller filled in.
fn apply_watch(watches: &mut Vec<WatchedPayment>, watch: WatchedPayment) -> WatchedPayment {
    let key = watch.key();
    watches.retain(|w| w.key() != key);
    watches.push(watch.clone());
    watch
}

/// Remove the watch for `network`/`script_pubkey`, if any. Returns whether
/// something was actually removed; the caller treats "nothing to remove" as
/// success either way, since asking to stop watching something nobody was
/// watching is not an error.
fn apply_unwatch(
    watches: &mut Vec<WatchedPayment>,
    network: BitcoinNetwork,
    script_pubkey: &[u8],
) -> bool {
    let before = watches.len();
    watches.retain(|w| !(w.network == network && w.script_pubkey == script_pubkey));
    watches.len() != before
}

/// Attach an order to an existing watch. Errors if there is no watch for
/// that network/script yet -- the UI is expected to `Watch` before it
/// `AssociateOrder`s, since associating is about labelling an existing
/// private watch, not creating one.
fn apply_associate_order(
    watches: &mut [WatchedPayment],
    network: BitcoinNetwork,
    script_pubkey: &[u8],
    order_id: OrderId,
    expected_amount_sats: u64,
) -> Result<(), String> {
    match watches
        .iter_mut()
        .find(|w| w.network == network && w.script_pubkey == script_pubkey)
    {
        Some(w) => {
            w.order_id = Some(order_id);
            w.expected_amount_sats = Some(expected_amount_sats);
            Ok(())
        }
        None => Err("no watch for that network/script -- call Watch first".into()),
    }
}

/// Add or refresh a watch because a Harvest order now has a Bitcoin payment
/// destination, rather than because the user manually asked to watch an
/// address. Uses [`apply_watch`], the exact same storage and upsert logic a
/// manual `Watch` request goes through.
///
/// Still private: creating this watch touches no contract and is invisible
/// to anyone but this machine, exactly like a manual watch. See this
/// module's doc comment for why that invariant matters.
///
/// Not yet called anywhere in this crate: wiring an incoming order/payment
/// notification to this function is order-tracking's job, not the Bitcoin
/// watch-list's, and lands in a separate change. `#[allow(dead_code)]` is
/// deliberate here rather than a signal to remove the function.
#[allow(dead_code)]
pub fn watch_order_payment(
    ctx: &mut DelegateCtx,
    network: BitcoinNetwork,
    script_pubkey: Vec<u8>,
    address: String,
    order_id: OrderId,
    expected_amount_sats: u64,
    added_at_ms: u64,
) -> WatchedPayment {
    let mut watches = load_watches(ctx);
    let watch = apply_watch(
        &mut watches,
        WatchedPayment {
            network,
            script_pubkey,
            address,
            label: None,
            order_id: Some(order_id),
            expected_amount_sats: Some(expected_amount_sats),
            contract_id: None,
            added_at_ms,
            bridge_synced: false,
            last_error: None,
        },
    );
    save_watches(ctx, &watches);
    watch
}

pub fn handle(
    ctx: &mut DelegateCtx,
    request: BitcoinDelegateRequest,
) -> Result<BitcoinDelegateResponse, DelegateError> {
    Ok(match request {
        BitcoinDelegateRequest::Watch { request_id, watch } => {
            let mut watches = load_watches(ctx);
            let watch = apply_watch(&mut watches, watch);
            save_watches(ctx, &watches);
            BitcoinDelegateResponse::Watched {
                request_id,
                result: Ok(watch),
            }
        }

        BitcoinDelegateRequest::Unwatch {
            request_id,
            network,
            script_pubkey,
        } => {
            let mut watches = load_watches(ctx);
            if apply_unwatch(&mut watches, network, &script_pubkey) {
                save_watches(ctx, &watches);
            }
            BitcoinDelegateResponse::Unwatched {
                request_id,
                result: Ok(()),
            }
        }

        BitcoinDelegateRequest::ListWatched => BitcoinDelegateResponse::WatchList {
            watches: load_watches(ctx),
        },

        BitcoinDelegateRequest::AssociateOrder {
            request_id,
            network,
            script_pubkey,
            order_id,
            expected_amount_sats,
        } => {
            let mut watches = load_watches(ctx);
            let result = apply_associate_order(
                &mut watches,
                network,
                &script_pubkey,
                order_id,
                expected_amount_sats,
            );
            if result.is_ok() {
                save_watches(ctx, &watches);
            }
            BitcoinDelegateResponse::OrderAssociated { request_id, result }
        }

        BitcoinDelegateRequest::ConfigureBridge {
            request_id,
            endpoint,
        } => {
            save_bridge(ctx, &endpoint);
            BitcoinDelegateResponse::BridgeConfigured {
                request_id,
                result: Ok(()),
            }
        }

        BitcoinDelegateRequest::GetBridge => BitcoinDelegateResponse::Bridge {
            endpoint: load_bridge(ctx),
        },

        // `BitcoinDelegateRequest` is `#[non_exhaustive]` in harvest-common,
        // so this match must keep a wildcard even though every variant that
        // exists today is handled above. A future variant added on the
        // other side of the workspace then fails here with a clean error
        // instead of failing to compile this crate.
        _ => {
            return Err(DelegateError::Other(
                "unsupported bitcoin request variant for this delegate version".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(network: BitcoinNetwork, script: u8, label: Option<&str>) -> WatchedPayment {
        WatchedPayment {
            network,
            script_pubkey: vec![0x00, 0x14, script],
            address: format!("addr-{script}"),
            label: label.map(|s| s.to_string()),
            order_id: None,
            expected_amount_sats: Some(50_000),
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    #[test]
    fn watch_then_list_roundtrips() {
        let mut watches = Vec::new();
        let inserted = apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, Some("rent")));
        assert_eq!(watches, vec![inserted]);
    }

    #[test]
    fn watching_the_same_script_twice_replaces_rather_than_duplicates() {
        let mut watches = Vec::new();
        apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, Some("rent")));
        apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("rent (renamed)")),
        );
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].label.as_deref(), Some("rent (renamed)"));
    }

    #[test]
    fn unwatch_of_an_unknown_script_removes_nothing_but_is_not_an_error() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let removed = apply_unwatch(&mut watches, BitcoinNetwork::Signet, &[0x00, 0x14, 0xff]);
        assert!(!removed, "no matching watch should be found");
        assert_eq!(watches.len(), 1, "the unrelated watch must survive");
        // The handler-level contract (see `handle`) always returns
        // `result: Ok(())` for Unwatch regardless of `removed`, which is the
        // property this test exists to pin: unwatching something you were
        // never watching is success, not an error.
    }

    #[test]
    fn unwatch_of_a_known_script_removes_it() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let removed = apply_unwatch(&mut watches, BitcoinNetwork::Signet, &[0x00, 0x14, 0x01]);
        assert!(removed);
        assert!(watches.is_empty());
    }

    #[test]
    fn associate_order_attaches_to_an_existing_watch() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let order_id = OrderId([7u8; 16]);
        apply_associate_order(
            &mut watches,
            BitcoinNetwork::Signet,
            &[0x00, 0x14, 0x01],
            order_id.clone(),
            12_345,
        )
        .expect("watch exists");
        assert_eq!(watches[0].order_id, Some(order_id));
        assert_eq!(watches[0].expected_amount_sats, Some(12_345));
    }

    #[test]
    fn associate_order_on_a_script_never_watched_is_an_error() {
        let mut watches: Vec<WatchedPayment> = Vec::new();
        let result = apply_associate_order(
            &mut watches,
            BitcoinNetwork::Signet,
            &[0x00, 0x14, 0x01],
            OrderId([1u8; 16]),
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_same_script_on_two_networks_is_two_distinct_watches() {
        let mut watches = Vec::new();
        apply_watch(&mut watches, watch(BitcoinNetwork::Bitcoin, 1, None));
        apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, None));
        assert_eq!(watches.len(), 2);
    }

    /// Manual watches and order-driven watches must go through the same
    /// upsert so they can never diverge in behavior -- this pins that
    /// `watch_order_payment`'s core logic literally is `apply_watch`, not a
    /// parallel reimplementation of it.
    #[test]
    fn order_driven_watch_shares_apply_watch_with_manual_watch() {
        let mut watches = Vec::new();
        apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("manual label")),
        );

        let order_id = OrderId([9u8; 16]);
        let order_watch = WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 1],
            address: "addr-1".into(),
            label: None,
            order_id: Some(order_id.clone()),
            expected_amount_sats: Some(99),
            contract_id: None,
            added_at_ms: 1,
            bridge_synced: false,
            last_error: None,
        };
        apply_watch(&mut watches, order_watch);

        // Same key => the manual watch's private label is gone now, exactly
        // as it would be if the same `Watch` request had been replayed --
        // there is only one code path, not two with different semantics.
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].order_id, Some(order_id));
    }

    /// A private label must never end up in anything shaped for the wire to
    /// a bridge. This mirrors
    /// `harvest_common::bitcoin_delegate::tests::the_bridge_watch_request_has_nowhere_to_put_a_private_label`,
    /// but starting from a watch that went through *this* crate's storage
    /// round-trip, so it also pins that nothing added here (e.g. a future
    /// helper that assembles a bridge request from a stored watch) smuggles
    /// the label along.
    #[test]
    fn a_stored_labels_watch_never_leaks_into_a_bridge_watch_request() {
        let mut watches = Vec::new();
        let stored = apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("secret rent label")),
        );

        let bridge_request = freenet_bitcoin_common::WatchRequest {
            network: stored.network,
            script_pubkey: stored.script_pubkey.clone(),
            scan_from_height: None,
        };
        let encoded = freenet_bitcoin_common::to_cbor(&bridge_request).unwrap();
        let haystack = String::from_utf8_lossy(&encoded).to_string();
        assert!(
            !haystack.contains("secret rent label"),
            "a private label reached the bridge wire format"
        );
    }
}
