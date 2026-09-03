//! The Bitcoin/Payments section: live chain data, Harvest orders grouped by
//! payment status (payments-first -- this is Harvest's story, not a block
//! explorer), and the user's private watch list.
//!
//! # Realtime, end to end
//!
//! Nothing here polls. `crate::gateway::bitcoin_ops::subscribe_contract`
//! issues a GET with `subscribe: true` for a chain-tip or address contract;
//! `crate::gateway::response_handler` routes the resulting
//! `UpdateNotification`s back through `AppState::on_contract_state` (via a
//! re-GET -- see that module's long comment on why), which folds fresh
//! `BitcoinTipStateV1`/`BitcoinAddressStateV1` bytes into
//! `AppState.bitcoin.tips` / `.addresses`. Those are plain fields read here
//! through the `APP_STATE` global signal, so Dioxus re-renders this
//! component automatically whenever a block arrives or a watched address's
//! claims change -- no timer anywhere in this file.

use dioxus::prelude::*;

use freenet_bitcoin_common::BitcoinNetwork;
use harvest_common::payment::{AuthorizedOrder, OrderStatus};
use harvest_common::{BridgeEndpoint, WatchedPayment};

use crate::gateway::{bitcoin_address, bitcoin_config, bitcoin_ops, APP_STATE};
use crate::state::{friendly_bridge_error, AddressView, BitcoinState, TipView, TxRowStatus};

#[component]
pub fn BitcoinView() -> Element {
    let app_state = APP_STATE.read();
    let network = active_network(&app_state.bitcoin);
    let tip = app_state.bitcoin.tips.get(&network).cloned();
    let bridge_loaded = app_state.bitcoin.bridge_loaded;
    let bridge = app_state.bitcoin.bridge.clone();
    let orders = my_orders(&app_state);
    let watches = app_state.bitcoin.watches.clone();
    let watches_loaded = app_state.bitcoin.watches_loaded;
    let has_ghostkey = !app_state.ghostkeys.is_empty();

    // A brand-new user has neither -- that's the first-run case, and it
    // gets the expanded live-data panel instead of an empty table. Once
    // either appears, the compact status bar plus payments-first layout
    // takes over.
    let show_first_run = watches_loaded && watches.is_empty() && orders.is_empty();

    rsx! {
        div {
            h2 { "Payments" }

            div { class: "info-box",
                p {
                    "Harvest can prove a Bitcoin payment happened without trusting any one party: "
                    "a bridge attests what it saw on chain, and anyone can verify the signed evidence. "
                    "Orders here show real payment status as it confirms on chain."
                }
            }

            BridgeStatusBar { bridge_loaded, bridge: bridge.clone(), network, tip: tip.clone() }

            if show_first_run {
                FirstRunPanel { bridge_loaded, bridge, network, tip, has_ghostkey }
            } else {
                if !orders.is_empty() {
                    OrdersSection { orders, app_state_snapshot: app_state.bitcoin.clone() }
                }
                WatchListSection { watches, network, has_ghostkey }
            }
        }
    }
}

/// Which network the section currently shows: whatever the user is already
/// watching something on, else the configured bridge's network, else the
/// build's default demo network.
fn active_network(bitcoin: &BitcoinState) -> BitcoinNetwork {
    if let Some(w) = bitcoin.watches.first() {
        return w.network;
    }
    if let Some(b) = &bitcoin.bridge {
        return b.network;
    }
    bitcoin_config::default_network()
}

/// Every order, across every store we've loaded state for, where one of our
/// connected Ghost Keys is buyer or seller. Depends on having browsed (or
/// registered) the relevant store at least once -- same scoping `MyStore`
/// already uses for listings.
fn my_orders(app_state: &crate::state::AppState) -> Vec<AuthorizedOrder> {
    let my_fingerprints: std::collections::HashSet<&str> = app_state
        .ghostkeys
        .iter()
        .map(|k| k.fingerprint.as_str())
        .collect();
    let mut orders: Vec<AuthorizedOrder> = app_state
        .browsing_stores
        .values()
        .flat_map(|s| s.orders.iter())
        .filter(|o| {
            my_fingerprints.contains(o.order.buyer_fingerprint.as_str())
                || my_fingerprints.contains(o.order.seller_fingerprint.as_str())
        })
        .cloned()
        .collect();
    // Newest first.
    orders.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    orders
}

// ---------------------------------------------------------------------------
// Bridge / chain-tip status
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum BridgeHealth {
    /// `GetBridge` has answered and no bridge is configured. Real state of
    /// the world today: there is no canonical default bridge published
    /// anywhere yet (`freenet-bitcoin/deploy/` is empty), so this is
    /// expected, not an error -- say so plainly rather than looking broken.
    NotConfigured,
    /// A bridge is configured but we haven't yet learned its tip contract
    /// id (still waiting on `GetBridge`, or the `/v1/status` fetch is in
    /// flight or hasn't resolved), or we have the id but no data has
    /// arrived from the subscription yet.
    WaitingForData,
    Online,
    Stale,
}

fn bridge_health(
    bridge_loaded: bool,
    bridge: &Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: &Option<TipView>,
) -> BridgeHealth {
    if !bridge_loaded || bridge.is_none() {
        return if bridge_loaded {
            BridgeHealth::NotConfigured
        } else {
            BridgeHealth::WaitingForData
        };
    }
    let Some(tip) = tip else {
        return BridgeHealth::WaitingForData;
    };
    let Some(last_block_time) = tip.last_block_time else {
        return BridgeHealth::WaitingForData;
    };
    // Regtest blocks are manually mined and may be minutes or days apart --
    // recency says nothing about health there, so don't call it stale.
    if network == BitcoinNetwork::Regtest {
        return BridgeHealth::Online;
    }
    let age = (now_unix_seconds() - last_block_time as i64).max(0);
    // 6x the ~10-minute target interval: generous enough that ordinary
    // variance in block timing never falsely reads as "stale".
    if age < 60 * 60 {
        BridgeHealth::Online
    } else {
        BridgeHealth::Stale
    }
}

#[component]
fn BridgeStatusBar(
    bridge_loaded: bool,
    bridge: Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: Option<TipView>,
) -> Element {
    let health = bridge_health(bridge_loaded, &bridge, network, &tip);
    let (dot_class, label) = match health {
        BridgeHealth::NotConfigured => ("btc-dot unknown", "No Bitcoin bridge configured for this build yet".to_string()),
        BridgeHealth::WaitingForData => ("btc-dot unknown", "Connecting to the Bitcoin bridge…".to_string()),
        BridgeHealth::Online => ("btc-dot online", "Online".to_string()),
        BridgeHealth::Stale => ("btc-dot offline", "No recent blocks -- bridge may be behind".to_string()),
    };

    rsx! {
        div { class: "btc-status-bar",
            span { class: "{dot_class}" }
            span { class: "btc-status-text", "{label}" }
            span { class: "btc-status-network", "{network.as_str()}" }
            if let Some(t) = &tip {
                if let Some(height) = t.tip_height {
                    span { class: "btc-status-sep", "·" }
                    span { class: "btc-status-text", "Tip height {height}" }
                }
                if let Some(bt) = t.last_block_time {
                    span { class: "btc-status-sep", "·" }
                    span { class: "btc-status-text", "Last block {relative_time_ago(bt)}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// First-run panel
// ---------------------------------------------------------------------------

#[component]
fn FirstRunPanel(
    bridge_loaded: bool,
    bridge: Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: Option<TipView>,
    has_ghostkey: bool,
) -> Element {
    rsx! {
        div { class: "card",
            h3 { "Live on {network.as_str()}" }
            match &tip {
                Some(t) if !t.recent_blocks.is_empty() => rsx! {
                    RecentBlocksList { blocks: t.recent_blocks.clone() }
                },
                _ => rsx! {
                    p { class: "text-muted text-italic",
                        "No chain data yet. "
                        if !bridge_loaded {
                            "Connecting…"
                        } else if bridge.is_none() {
                            "This build has no Bitcoin bridge configured for {network.as_str()} yet."
                        } else {
                            "Waiting for the bridge to report the chain tip…"
                        }
                    }
                },
            }

            div { class: "info-box", style: "margin-top: 16px;",
                p {
                    "A curated demo address isn't configured for this build yet -- once a bridge is live, "
                    "this is where you'd see a public address's activity update in real time with no "
                    "credential at all."
                }
            }
        }

        WatchForm { network, has_ghostkey }
    }
}

#[component]
fn RecentBlocksList(blocks: Vec<crate::state::BlockRow>) -> Element {
    rsx! {
        div { class: "btc-block-list",
            for block in blocks {
                div { class: "btc-block-row", key: "{block.height}",
                    span { class: "btc-block-height", "#{block.height}" }
                    span { class: "btc-block-txcount", "{block.tx_count} tx" }
                    span { class: "btc-block-time text-muted", "{relative_time_ago(block.block_time)}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Orders (payments-first)
// ---------------------------------------------------------------------------

#[component]
fn OrdersSection(orders: Vec<AuthorizedOrder>, app_state_snapshot: BitcoinState) -> Element {
    let awaiting: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| o.status == OrderStatus::AwaitingPayment)
        .collect();
    let paid: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| matches!(o.status, OrderStatus::Paid | OrderStatus::Fulfilled))
        .collect();
    let other: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| matches!(o.status, OrderStatus::Cancelled | OrderStatus::PaymentReversed))
        .collect();

    rsx! {
        div {
            h3 { "Your orders" }
            if !awaiting.is_empty() {
                p { class: "section-count", "Awaiting payment" }
                for order in &awaiting {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
            if !paid.is_empty() {
                p { class: "section-count", "Paid" }
                for order in &paid {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
            if !other.is_empty() {
                p { class: "section-count", "Other" }
                for order in &other {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
        }
    }
}

/// If we happen to be watching this order's payment address, its live claim
/// data -- lets an `AwaitingPayment` order show "payment seen, unconfirmed"
/// the moment it hits the mempool, well before the store contract's own
/// `Paid` transition (which needs a fully-formed, sufficiently-confirmed
/// proof) lands.
fn live_address_for_order(
    bitcoin: &BitcoinState,
    order: &harvest_common::payment::Order,
) -> Option<AddressView> {
    let watch = bitcoin.watches.iter().find(|w| {
        w.network == order.network && w.script_pubkey == order.payment_script_pubkey
    })?;
    let contract_id_bs58 = watch.contract_id.as_deref()?;
    let bytes = bs58::decode(contract_id_bs58).into_vec().ok()?;
    bitcoin.addresses.get(&bytes).cloned()
}

#[component]
fn OrderCard(order: AuthorizedOrder, live: Option<AddressView>) -> Element {
    let o = &order.order;
    let (status_class, status_text) = match order.status {
        OrderStatus::AwaitingPayment => match &live {
            Some(l) if l.confirmed_sats > 0 => ("btc-pill paid", "Payment seen on chain".to_string()),
            Some(l) if l.pending_sats > 0 => ("btc-pill pending", "Payment seen, unconfirmed".to_string()),
            _ => ("btc-pill waiting", "Awaiting payment".to_string()),
        },
        OrderStatus::Paid => ("btc-pill paid", "Paid".to_string()),
        OrderStatus::Fulfilled => ("btc-pill paid", "Fulfilled".to_string()),
        OrderStatus::PaymentReversed => ("btc-pill reversed", "Payment reversed".to_string()),
        OrderStatus::Cancelled => ("btc-pill cancelled", "Cancelled".to_string()),
    };

    rsx! {
        div { class: "listing-card",
            div { class: "listing-header",
                span { class: "listing-price", "{format_sats(o.amount_sats)}" }
                span { class: "{status_class}", "{status_text}" }
            }
            p { class: "text-muted", "Order {o.id.short()} · {o.network.as_str()}" }
            p { class: "seller-id", "{o.payment_address}" }
        }
    }
}

// ---------------------------------------------------------------------------
// Watch list (secondary)
// ---------------------------------------------------------------------------

#[component]
fn WatchListSection(watches: Vec<WatchedPayment>, network: BitcoinNetwork, has_ghostkey: bool) -> Element {
    // Manual watches only -- ones tied to an order are already visible above
    // and would otherwise be shown twice.
    let manual: Vec<&WatchedPayment> = watches.iter().filter(|w| w.order_id.is_none()).collect();

    rsx! {
        div { style: "margin-top: 24px;",
            h3 { "Watched addresses" }
            if manual.is_empty() {
                p { class: "text-muted text-italic", "Not watching any addresses yet." }
            } else {
                for watch in &manual {
                    WatchRow { key: "{watch.key()}", watch: (*watch).clone() }
                }
            }
            WatchForm { network, has_ghostkey }
        }
    }
}

#[component]
fn WatchRow(watch: WatchedPayment) -> Element {
    let app_state = APP_STATE.read();
    let live = watch
        .contract_id
        .as_deref()
        .and_then(|id| bs58::decode(id).into_vec().ok())
        .and_then(|bytes| app_state.bitcoin.addresses.get(&bytes).cloned());
    drop(app_state);

    let mut unwatching = use_signal(|| false);
    let network = watch.network;
    let script_pubkey = watch.script_pubkey.clone();

    rsx! {
        div { class: "identity-card",
            div {
                p { class: "identity-name",
                    if let Some(label) = &watch.label { "{label}" } else { "{watch.address}" }
                }
                p { class: "seller-id", "{watch.address}" }
                if let Some(err) = &watch.last_error {
                    p { class: "text-warning", "{friendly_bridge_error(err)}" }
                } else if !watch.bridge_synced {
                    p { class: "text-muted text-italic", "Waiting for bridge to sync…" }
                }
                if let Some(l) = &live {
                    p { class: "text-muted",
                        if l.confirmed_sats > 0 { "{format_sats(l.confirmed_sats)} confirmed" }
                        if l.pending_sats > 0 { " · {format_sats(l.pending_sats)} pending" }
                        if l.confirmed_sats == 0 && l.pending_sats == 0 { "No activity yet" }
                    }
                    for tx in l.txs.iter().take(5) {
                        TxRowView { key: "{tx.txid_display}", tx: tx.clone() }
                    }
                }
            }
            button {
                class: "btn btn-outline btn-sm",
                disabled: *unwatching.read(),
                onclick: move |_| {
                    unwatching.set(true);
                    let network = network;
                    let script_pubkey = script_pubkey.clone();
                    spawn(async move {
                        if let Err(e) = bitcoin_ops::unwatch(network, script_pubkey).await {
                            APP_STATE
                                .write()
                                .notifications
                                .push(format!("Couldn't stop watching: {e}"));
                        }
                        unwatching.set(false);
                    });
                },
                if *unwatching.read() { "Stopping…" } else { "Unwatch" }
            }
        }
    }
}

#[component]
fn TxRowView(tx: crate::state::TxRow) -> Element {
    let status_text = match tx.status {
        TxRowStatus::Unconfirmed => "unconfirmed".to_string(),
        TxRowStatus::Confirmed { .. } => "confirmed".to_string(),
        TxRowStatus::Retracted => "reversed".to_string(),
    };
    rsx! {
        p { class: "btc-tx-row text-muted",
            span { class: "btc-tx-id", "{tx.txid_display}" }
            span { class: "btc-tx-amount", "{format_sats(tx.value_sats)}" }
            span { class: "btc-tx-status", "{status_text}" }
        }
    }
}

// ---------------------------------------------------------------------------
// Watch form + Ghost Key gate
// ---------------------------------------------------------------------------

#[component]
fn WatchForm(network: BitcoinNetwork, has_ghostkey: bool) -> Element {
    let mut address = use_signal(String::new);
    let mut label = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut show_gate = use_signal(|| false);
    let mut submitting = use_signal(|| false);

    rsx! {
        div { class: "card",
            h4 { "Watch a Bitcoin address" }
            div { class: "form-group",
                input {
                    class: "form-input",
                    placeholder: "Bitcoin address",
                    value: "{address}",
                    oninput: move |e| {
                        address.set(e.value());
                        error.set(None);
                    },
                }
            }
            div { class: "form-group",
                input {
                    class: "form-input",
                    placeholder: "Label (optional, never leaves this device)",
                    value: "{label}",
                    oninput: move |e| label.set(e.value()),
                }
            }
            if let Some(e) = error.read().clone() {
                p { class: "text-warning", "{e}" }
            }
            if *show_gate.read() {
                GhostKeyGate { on_dismiss: move |_| show_gate.set(false) }
            } else {
                button {
                    class: "btn btn-primary",
                    disabled: *submitting.read() || address.read().trim().is_empty(),
                    onclick: move |_| {
                        if !has_ghostkey {
                            show_gate.set(true);
                            return;
                        }
                        let raw_address = address.read().clone();
                        match bitcoin_address::address_to_script_pubkey(&raw_address, network) {
                            Ok(script_pubkey) => {
                                error.set(None);
                                submitting.set(true);
                                let label_value = {
                                    let l = label.read().clone();
                                    (!l.trim().is_empty()).then_some(l)
                                };
                                let watch = WatchedPayment {
                                    network,
                                    script_pubkey,
                                    address: raw_address,
                                    label: label_value,
                                    order_id: None,
                                    expected_amount_sats: None,
                                    contract_id: None,
                                    added_at_ms: now_unix_millis(),
                                    bridge_synced: false,
                                    last_error: None,
                                };
                                address.set(String::new());
                                label.set(String::new());
                                spawn(async move {
                                    if let Err(e) = bitcoin_ops::watch(watch).await {
                                        APP_STATE
                                            .write()
                                            .notifications
                                            .push(format!("Couldn't send watch request: {e}"));
                                    }
                                    submitting.set(false);
                                });
                            }
                            Err(e) => error.set(Some(e)),
                        }
                    },
                    if *submitting.read() { "Watching…" } else { "Watch address" }
                }
            }
        }
    }
}

/// Shown only when the user tries to start a NEW watch and has no Ghost Key
/// connected -- public/demo data above needs no credential at all, this
/// gate is specifically for adding a new watch backed by Freenet.org's
/// bridge.
#[component]
fn GhostKeyGate(on_dismiss: EventHandler<()>) -> Element {
    rsx! {
        div { class: "info-box",
            p {
                "Watching a new address through Freenet.org's bridge is available to Ghost Key holders. "
                "A Ghost Key just proves you've supported the network -- the bridge never learns anything else about you."
            }
            div { style: "margin-top: 12px; display: flex; gap: 8px; align-items: center;",
                button {
                    class: "btn btn-primary",
                    onclick: move |_| super::my_store::connect_ghostkey(),
                    "Use Ghost Key"
                }
                a {
                    class: "btn btn-outline",
                    href: "https://freenet.org/ghostkey/create/",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    "Learn more"
                }
                button {
                    class: "btn btn-outline btn-sm",
                    onclick: move |_| on_dismiss.call(()),
                    "Cancel"
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_sats(sats: u64) -> String {
    format!("{:.8} BTC", sats as f64 / 100_000_000.0)
}

#[cfg(target_arch = "wasm32")]
fn now_unix_millis() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_millis() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn now_unix_seconds() -> i64 {
    (now_unix_millis() / 1000) as i64
}

/// Browser-clock relative time, e.g. "3 minutes ago". `unix_secs` is a
/// Bitcoin block header timestamp -- Bitcoin's clock, never trusted as
/// authoritative on its own, only ever compared against the local clock for
/// display. See `freenet_bitcoin_common::tip_state`'s doc comment on why
/// contracts themselves may never read a host clock; this is the UI doing
/// exactly the comparison that comment says is fine.
fn relative_time_ago(unix_secs: u32) -> String {
    let delta = (now_unix_seconds() - unix_secs as i64).max(0);
    if delta < 60 {
        "just now".to_string()
    } else if delta < 3600 {
        let m = delta / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else if delta < 86_400 {
        let h = delta / 3600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let d = delta / 86_400;
        format!("{d} day{} ago", if d == 1 { "" } else { "s" })
    }
}
