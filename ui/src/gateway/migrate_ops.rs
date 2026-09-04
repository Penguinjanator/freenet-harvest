//! Driving the migration probe over the gateway's shared response handler.
//!
//! `crate::migrate` owns every decision -- what to ask next, what a silence
//! means, whether a result may be sealed. This module owns only the I/O: send
//! a GET, arm a deadline, route a response back, and PUT the recovered state
//! forward. That split is deliberate, because the decisions are the part that
//! loses data when it is wrong and this is the part that cannot be unit-tested
//! (it needs a browser and a node).
//!
//! # Why the probe is hand-pumped
//!
//! `WebApi` delivers every response to one app-registered handler, so a
//! request and its answer are not connected by anything the language can see:
//! there is no future to await. `ProbeDriver` is the migration crate's sans-IO
//! answer to exactly that shape. `PROBES` below is the correlation the
//! transport does not provide -- a candidate id maps to the probe waiting on
//! it, and an answer for anything else is ignored rather than guessed at.
//!
//! # Why a probe response must not reach `AppState`
//!
//! A probe GETs an OLD generation's instance. Its state is real, decodable
//! store/mailbox/reputation state, and feeding it to `on_contract_state` would
//! display a superseded generation as if it were the live store.
//! `handle_contract_response` therefore offers every GET response to
//! [`deliver_state`] first and returns if it is consumed.
//!
//! # Why the repeat gate is asynchronous
//!
//! The durable marker lives in the harvest delegate's secret store, so reading
//! it is a round trip and not a function call. It used to be a `localStorage`
//! read, which is synchronous and, in the deployed gateway, is not a read at
//! all: Freenet serves a webapp inside an iframe with no `allow-same-origin`,
//! so the frame has an opaque origin and `window.localStorage` throws. The
//! gate worked under `dx serve` and silently did nothing once published.
//!
//! So a probe is now built first and *held* in [`PENDING`] while the delegate
//! is asked. Exactly three things can release it, and two of them run it:
//! the delegate says `present` (dropped), the delegate says absent (run), or
//! nothing usable comes back within [`MARKER_QUERY_TIMEOUT_MS`] (run). The
//! send failing runs it immediately, for the same reason. Building the probe
//! before the answer arrives is what keeps that decision in one place --
//! `migrate::probe_gate` -- rather than spread across three callbacks.

#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::collections::HashMap;

use dioxus::logger::tracing::{info, warn};
use dioxus::prelude::{ReadableExt, WritableExt};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, WrappedContract, WrappedState,
};
use harvest_common::mailbox::MailboxStateV1;
use harvest_common::reputation::ReputationStateV1;
use harvest_common::store::StoreStateV1;

use crate::migrate::{self, Artifact, MailboxOps, ProbeSession, ReputationOps, Seal, StoreOps};

use super::store_ops::{MAILBOX_CONTRACT_WASM, REPUTATION_CONTRACT_WASM, STORE_CONTRACT_WASM};

/// One probe's state machine plus the context needed to act on its result.
struct Probe {
    artifact: Artifact,
    fingerprint: String,
    /// The durable marker this probe may write, and only if it earns it.
    marker: String,
    /// The current generation's instance id -- where a recovery is PUT.
    current: ContractInstanceId,
    params: Parameters<'static>,
    session: Session,
}

/// The three probe types behind one handle.
///
/// Boxed: the variants differ by ~400 bytes (a `StoreOps` carries the full
/// `StoreParameters`, a `MailboxOps` one verifying key), and every `Probe`
/// would otherwise be padded to the largest. There are at most three of these
/// alive at a time so the size hardly matters, but the enum is moved into and
/// out of the correlation table on every hop of every walk, and a boxed
/// variant makes each of those a pointer move.
enum Session {
    Store(Box<ProbeSession<StoreOps>>),
    Reputation(Box<ProbeSession<ReputationOps>>),
    Mailbox(Box<ProbeSession<MailboxOps>>),
}

/// The recovered state to PUT forward, already CBOR-encoded.
struct Forward {
    bytes: Vec<u8>,
    wasm: &'static [u8],
}

thread_local! {
    /// Probes that have an outstanding GET, keyed by the candidate they are
    /// waiting on.
    ///
    /// A `thread_local` rather than a dioxus signal: the browser is
    /// single-threaded, nothing renders from this, and keeping it out of
    /// `APP_STATE` removes any chance of holding two `RefCell` borrows at once
    /// -- the failure the delegate-response path already carries a comment
    /// about.
    ///
    /// The driver probes one candidate at a time, so a probe appears here
    /// under exactly one key, and the key changes as the walk advances.
    static PROBES: RefCell<HashMap<ContractInstanceId, Probe>> = RefCell::new(HashMap::new());

    /// Marker keys of probes that are running or finished in this session, so
    /// a second `GhostKeyList` (the vault sends one per connect) does not start
    /// a duplicate walk of the same lineage.
    ///
    /// In-memory only, and deliberately separate from the durable marker: this
    /// suppresses a concurrent duplicate, the durable one suppresses a repeat
    /// on a later load. Conflating them is how an in-flight probe becomes a
    /// permanent "already done".
    static IN_FLIGHT: RefCell<std::collections::HashSet<String>> =
        RefCell::new(std::collections::HashSet::new());

    /// Probes that are built and waiting on the delegate's answer about their
    /// durable marker, keyed by that marker.
    ///
    /// A probe sits here for one round trip and no longer. Whichever of the
    /// three releases arrives first takes it; the other two then find nothing
    /// and do nothing, which is what makes a late answer and a fired timeout
    /// harmless in either order.
    static PENDING: RefCell<HashMap<String, Probe>> = RefCell::new(HashMap::new());
}

/// How long to wait for one candidate before recording it as unresolved.
///
/// `freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS` is the crate's own advice.
/// Expiring the timer is [`ProbeSession::on_unknown`], never `on_absent`: a
/// deadline establishes nothing, and typing it as absence is what lets a
/// migration seal over live data.
const PROBE_TIMEOUT_MS: u32 = freenet_migrate::RECOMMENDED_PROBE_TIMEOUT_MS as u32;

/// How long to wait for the delegate's answer about a marker before running
/// the probe anyway.
///
/// Shorter than [`PROBE_TIMEOUT_MS`], because it is a different kind of wait:
/// a delegate call is node-local and answers in milliseconds, where a contract
/// GET crosses the network. Expiring costs one walk that may not have
/// been needed; never expiring would leave a migration that has not been
/// sealed permanently un-run, which is the failure this whole module exists to
/// prevent.
const MARKER_QUERY_TIMEOUT_MS: u32 = 8_000;

/// The BLAKE3 code hash of a bundled contract -- the current generation.
fn code_hash(wasm: &[u8]) -> [u8; 32] {
    let hash = *ContractCode::from(wasm.to_vec()).hash();
    let bytes: &[u8] = hash.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// Start the migrations that need nothing but the seller's ghostkey: their
/// store and their mailbox.
///
/// Called the moment a ghostkey identity becomes known. Both artifacts'
/// parameters are derivable from the verifying key alone, so this runs even
/// for a seller whose delegate secrets did not survive -- which is the whole
/// reason it does not wait for the delegate.
pub fn start_identity_migration(fingerprint: &str, verifying_key_bytes: &[u8]) {
    let Some(vk) = verifying_key(verifying_key_bytes) else {
        warn!("cannot migrate for {fingerprint}: ghostkey verifying key is not 32 valid bytes");
        return;
    };

    let store_params = migrate::store_params(&vk);
    // The store's predecessors are NOT addressed by these parameter bytes.
    // `StoreParameters` shed two fields when the Bitcoin bridge list moved
    // onto `Order`, so every already-published generation lives at an address
    // derived from the older, longer encoding, and `store_candidates` is what
    // derives each generation under the encoding it was published with. These
    // parameters still address the CURRENT instance, which is what `start`
    // needs them for.
    match (
        migrate::encode_params(&store_params),
        migrate::store_candidates(&vk),
    ) {
        (Ok(params), Ok(candidates)) => {
            start(
                Artifact::Store,
                fingerprint,
                params.clone(),
                STORE_CONTRACT_WASM,
                move |_p| {
                    Session::Store(Box::new(ProbeSession::start_with_candidates(
                        StoreOps {
                            params: store_params.clone(),
                        },
                        local_snapshot(),
                        candidates.clone(),
                        migrate::fold_all_policy(),
                    )))
                },
            );
        }
        (Err(e), _) | (_, Err(e)) => warn!("cannot migrate store for {fingerprint}: {e}"),
    }

    let mailbox_params = migrate::mailbox_params(&vk);
    match migrate::encode_params(&mailbox_params) {
        Ok(params) => start(
            Artifact::Mailbox,
            fingerprint,
            params,
            MAILBOX_CONTRACT_WASM,
            |p| {
                Session::Mailbox(Box::new(ProbeSession::start(
                    MailboxOps {
                        params: mailbox_params.clone(),
                    },
                    local_snapshot(),
                    p,
                    migrate::mailbox_lineage(),
                    migrate::fold_all_policy(),
                )))
            },
        ),
        Err(e) => warn!("cannot migrate mailbox for {fingerprint}: {e}"),
    }
}

/// Start the reputation migration, which cannot run until the delegate has
/// produced this identity's RSA public key.
///
/// **This is the ordering constraint, enforced.**
/// `ReputationParameters::rsa_public_key_der` is that key, so it is an input to
/// the reputation contract's address: without it there is no way to derive a
/// predecessor id at all, and no way to derive the CURRENT one either. Running
/// this before the key arrives would probe ids belonging to nobody, find
/// nothing, and could seal that verdict over a recoverable instance.
///
/// [`migrate::reputation_probe_inputs`] is what makes that structural rather
/// than remembered -- there is no way to call this without the key, and a
/// missing key returns without starting anything rather than substituting a
/// placeholder.
pub fn start_reputation_migration(fingerprint: &str, verifying_key_bytes: &[u8]) {
    let Some(vk) = verifying_key(verifying_key_bytes) else {
        return;
    };
    let der = super::APP_STATE
        .read()
        .rsa_public_keys
        .get(fingerprint)
        .cloned();
    let Some(inputs) = migrate::reputation_probe_inputs(der.as_ref(), &vk) else {
        // Not yet, never "nothing to migrate". The next delegate response for
        // this identity calls back in.
        info!("reputation migration for {fingerprint} waits on the delegate's RSA public key");
        return;
    };

    match migrate::encode_params(&inputs.params) {
        Ok(params) => start(
            Artifact::Reputation,
            fingerprint,
            params,
            REPUTATION_CONTRACT_WASM,
            |p| {
                Session::Reputation(Box::new(ProbeSession::start(
                    ReputationOps {
                        params: inputs.params.clone(),
                    },
                    local_snapshot(),
                    p,
                    migrate::reputation_lineage(),
                    migrate::fold_all_policy(),
                )))
            },
        ),
        Err(e) => warn!("cannot migrate reputation for {fingerprint}: {e}"),
    }
}

fn verifying_key(bytes: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// The client's own snapshot to seed a probe with.
///
/// It is `default()` for all three artifacts, and that is a statement about
/// Harvest rather than a shortcut. The probe is seeded from the client's
/// snapshot so a recovery can never drop local-only state -- state the device
/// holds that the network does not. Harvest has none: `AppState` keeps a
/// DECOMPOSED view (`BrowsingStore` holds an unsigned `StoreInfoV1`, a listing
/// list and an order list, not the contract state), so there is no faithful
/// snapshot to hand over in the first place, and every edit the seller makes
/// is sent to the contract as it is made rather than accumulating locally.
///
/// If a local-only write is ever introduced, this is the function that has to
/// learn about it, or that write is what a migration silently drops.
fn local_snapshot<S: Default>() -> S {
    S::default()
}

/// Build a probe and ask the delegate whether its lineage is already done.
///
/// The durable marker is consulted HERE and nowhere else, and it gates only
/// the repeat: a first run for this `(instance, current code hash)` is
/// unconditional. Nothing asks whether the successor is empty -- an emptiness
/// gate is satisfied by any write to the new key, including this app's own
/// `create_store_contracts` PUT of a default state, and would then suppress
/// the migration forever (freenet/river#621).
///
/// The probe is built before the answer arrives and parked in [`PENDING`].
/// That is not eagerness for its own sake: it means the marker's three
/// possible outcomes all reduce to "release this probe, or drop it", decided
/// by `migrate::probe_gate` rather than by three separate code paths.
fn start<F>(
    artifact: Artifact,
    fingerprint: &str,
    params: Parameters<'static>,
    wasm: &'static [u8],
    build: F,
) where
    F: FnOnce(&Parameters<'static>) -> Session,
{
    let current_hash = code_hash(wasm);
    let current = migrate::current_id(&current_hash, &params);
    let marker = migrate::marker_key(artifact, &current, &current_hash);

    // The in-memory guard comes first, and covers the marker query as well as
    // the walk. Without that, a second `GhostKeyList` arriving inside the
    // query's round trip would park a second probe under the same marker and
    // silently evict the first from `PENDING` -- a migration that never ran
    // and never reported anything.
    let fresh = IN_FLIGHT.with(|f| f.borrow_mut().insert(marker.clone()));
    if !fresh {
        return;
    }

    let probe = Probe {
        artifact,
        fingerprint: fingerprint.to_string(),
        marker: marker.clone(),
        current,
        params: params.clone(),
        session: build(&params),
    };
    PENDING.with(|p| p.borrow_mut().insert(marker.clone(), probe));

    // The deadline first, so a send that never produces a response cannot
    // strand the probe. An expiry that finds the probe already gone is a
    // no-op.
    {
        let marker = marker.clone();
        gloo_timers::callback::Timeout::new(MARKER_QUERY_TIMEOUT_MS, move || {
            // A `None` here is the normal case: the delegate already answered
            // and the probe is long gone. Saying so when it is NOT is what
            // matters -- a timeout firing on every load is the signal that
            // markers are not reaching the delegate at all.
            if release_pending(&marker).is_some() {
                warn!(
                    "migration: the delegate did not answer about marker {marker}; \
                     treating it as not migrated and probing"
                );
            }
        })
        .forget();
    }

    let query = migrate::marker_query(&marker);
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = send_harvest_request(&query).await {
            // Unavailable, so the probe runs. `probe_gate` is where that
            // choice is argued; this is only the path that reaches it.
            warn!("migration: could not ask the delegate about {marker}: {e}");
            release_pending(&marker);
        }
    });
}

/// Send one request to the harvest delegate.
async fn send_harvest_request(
    request: &harvest_common::HarvestDelegateRequest,
) -> Result<(), String> {
    let delegate_key = super::APP_STATE
        .read()
        .harvest_delegate_key
        .clone()
        .ok_or("harvest delegate not registered")?;
    let payload =
        harvest_common::to_cbor(request).map_err(|e| format!("serialize delegate request: {e}"))?;
    super::send_delegate_message(&delegate_key, payload).await
}

/// Release a parked probe and run it, returning it if this call is the one
/// that found it.
///
/// Idempotent by construction: the probe is removed from [`PENDING`] under one
/// borrow, so of a late delegate answer, an expired deadline and a failed send
/// exactly one does anything and the rest find nothing.
fn release_pending(marker: &str) -> Option<()> {
    let probe = PENDING.with(|p| p.borrow_mut().remove(marker))?;
    info!(
        "migration: probing {} predecessor generation(s) of the {} contract for {}",
        probe.artifact.lineage().len(),
        probe.artifact.as_str(),
        probe.fingerprint
    );
    pump(probe);
    Some(())
}

/// Drop a parked probe without running it: the delegate says this lineage was
/// already carried forward under this exact code hash.
fn drop_pending(marker: &str) {
    let dropped = PENDING.with(|p| p.borrow_mut().remove(marker));
    if let Some(probe) = dropped {
        info!(
            "migration: the {} contract for {} is already migrated at this generation",
            probe.artifact.as_str(),
            probe.fingerprint
        );
    }
    // The in-flight guard is what stops a later `GhostKeyList` re-asking the
    // delegate about a marker this session has already settled.
    IN_FLIGHT.with(|f| {
        f.borrow_mut().insert(marker.to_string());
    });
}

/// A delegate response arrived. Returns `true` if it belonged to the migration
/// and must not reach `AppState`.
///
/// Offered BEFORE the app-state write guard is taken, for the same reason
/// `deliver_state` is: releasing a probe can run all the way through to
/// `finish`, which writes `APP_STATE`, and `APP_STATE` is a `RefCell`
/// underneath -- taking the write guard twice panics.
pub fn deliver_delegate_response(response: &super::response_handler::DelegateResponse) -> bool {
    use harvest_common::HarvestDelegateResponse;
    let super::response_handler::DelegateResponse::Harvest(harvest) = response else {
        return false;
    };
    match harvest {
        HarvestDelegateResponse::MigrationMarker { marker, present } => {
            match migrate::probe_gate(if *present {
                migrate::MarkerLookup::Present
            } else {
                migrate::MarkerLookup::Absent
            }) {
                migrate::Gate::Skip => drop_pending(marker),
                migrate::Gate::Run => {
                    release_pending(marker);
                }
            }
            true
        }
        HarvestDelegateResponse::MigrationMarkerRecorded { marker, recorded } => {
            if !*recorded {
                warn!(
                    "migration: the delegate did not record marker {marker}; \
                     this lineage will be probed again on the next load"
                );
            }
            true
        }
        _ => false,
    }
}

/// Advance one probe: ask for the next candidate, or finish it.
///
/// Takes the probe by value and re-registers it under the candidate it is now
/// waiting on. That is what makes `PROBES` a correlation table rather than a
/// list to search: an arriving response either names a candidate some probe is
/// waiting on, or belongs to nobody.
fn pump(mut probe: Probe) {
    let next = match &mut probe.session {
        Session::Store(s) => s.next_get(),
        Session::Reputation(s) => s.next_get(),
        Session::Mailbox(s) => s.next_get(),
    };

    let Some(candidate) = next else {
        finish(probe);
        return;
    };

    // Register BEFORE sending. The response can arrive as soon as the send
    // returns, and an answer with nothing registered is dropped -- the same
    // ordering `request_store_info_signature` documents for signatures.
    PROBES.with(|p| p.borrow_mut().insert(candidate, probe));

    wasm_bindgen_futures::spawn_local(async move {
        // Never subscribe to a legacy key: the point is to read it once, not
        // to start receiving its updates forever.
        if let Err(e) = super::get_contract(&candidate, false).await {
            warn!("migration: GET for predecessor {candidate} could not be sent: {e}");
            deliver_unknown(candidate);
        }
    });

    // The deadline. An expired timer is `on_unknown`, never `on_absent`: a
    // deadline establishes nothing, and typing silence as absence is what lets
    // a migration seal over live data (freenet-migrate#19).
    gloo_timers::callback::Timeout::new(PROBE_TIMEOUT_MS, move || {
        deliver_unknown(candidate);
    })
    .forget();
}

/// Offer a GET response to the probes. Returns `true` if a probe consumed it,
/// in which case the caller must NOT treat the bytes as current app state:
/// they belong to a superseded generation.
pub fn deliver_state(id: &ContractInstanceId, bytes: &[u8]) -> bool {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(id)) else {
        return false;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_state(*id, bytes),
        Session::Reputation(s) => s.on_state(*id, bytes),
        Session::Mailbox(s) => s.on_state(*id, bytes),
    }
    pump(probe);
    true
}

/// Offer a positive `NotFound` to the probes.
///
/// Only ever called for `ContractResponse::NotFound` -- an answer the node
/// actually gave. Every other way a GET can fail to produce state routes to
/// [`deliver_unknown`].
pub fn deliver_absent(id: &ContractInstanceId) -> bool {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(id)) else {
        return false;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_absent(*id),
        Session::Reputation(s) => s.on_absent(*id),
        Session::Mailbox(s) => s.on_absent(*id),
    }
    pump(probe);
    true
}

/// Record that nothing came back for `id`. Harmless if the probe already
/// advanced past this candidate -- the entry is simply not there.
fn deliver_unknown(id: ContractInstanceId) {
    let Some(mut probe) = PROBES.with(|p| p.borrow_mut().remove(&id)) else {
        return;
    };
    match &mut probe.session {
        Session::Store(s) => s.on_unknown(id),
        Session::Reputation(s) => s.on_unknown(id),
        Session::Mailbox(s) => s.on_unknown(id),
    }
    pump(probe);
}

/// A probe reached the end of its lineage: adopt what it found, and seal only
/// if it earned that.
fn finish(mut probe: Probe) {
    let (note, seal, forward) = match &mut probe.session {
        Session::Store(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, STORE_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
        Session::Reputation(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, REPUTATION_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
        Session::Mailbox(s) => match s.take_result() {
            Some((outcome, seal)) => {
                let note = migrate::describe(&outcome);
                let forward = match outcome {
                    freenet_migrate::Outcome::Recovered { merged, .. } => {
                        encode_forward(&merged, MAILBOX_CONTRACT_WASM)
                    }
                    _ => None,
                };
                (note, seal, forward)
            }
            None => return,
        },
    };

    info!(
        "migration: {} contract for {}: {note}",
        probe.artifact.as_str(),
        probe.fingerprint
    );

    let recovered = forward.is_some();
    if let Some(forward) = forward {
        put_forward(probe.artifact, probe.params.clone(), forward);
        if probe.artifact == Artifact::Store {
            adopt_recovered_store(&probe.fingerprint, probe.current);
        }
        super::APP_STATE.write().notifications.push(format!(
            "Recovered your {} from an earlier version of Harvest.",
            probe.artifact.as_str()
        ));
    }

    // The seal comes from `migrate::seal_decision`, which is the only place
    // that decides it. Sealing is recorded AFTER the forward PUT is queued, so
    // a probe that could not even encode its result does not mark itself done.
    match seal {
        Seal::Seal if recovered => record_marker(&probe.marker, &note),
        // `Seal` without anything to forward cannot happen today (only
        // `Recovered` seals, and `Recovered` always yields state), but if a
        // future outcome made it possible, not sealing is the safe half.
        Seal::Seal | Seal::Retry => {}
    }

    IN_FLIGHT.with(|f| {
        f.borrow_mut().remove(&probe.marker);
    });
}

/// Ask the delegate to record a completed migration.
///
/// Fire-and-forget: the reply is only logged. A write the delegate refuses,
/// or a send that never arrives, leaves the marker unwritten, and an unwritten
/// marker means the walk runs again on the next load -- wasteful and correct,
/// which is the same direction every other uncertainty here resolves in.
fn record_marker(marker: &str, note: &str) {
    let request = migrate::marker_write(marker, note);
    let marker = marker.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = send_harvest_request(&request).await {
            warn!("migration: could not record marker {marker}: {e}");
        }
    });
}

fn encode_forward<T: serde::Serialize>(state: &T, wasm: &'static [u8]) -> Option<Forward> {
    match harvest_common::to_cbor(state) {
        Ok(bytes) => Some(Forward { bytes, wasm }),
        Err(e) => {
            warn!("migration: recovered state could not be re-encoded: {e}");
            None
        }
    }
}

/// PUT a recovered state under the CURRENT generation's key.
///
/// A PUT rather than an UPDATE because the current instance may not exist on
/// the network at all -- that is the normal case straight after a re-key, and
/// an UPDATE to a contract nobody holds has nothing to update. Where it does
/// exist the node merges rather than replaces (`update_state` merges for all
/// three contracts), so this is safe to repeat and safe when another client
/// has already written.
fn put_forward(artifact: Artifact, params: Parameters<'static>, forward: Forward) {
    let code = std::sync::Arc::new(ContractCode::from(forward.wasm.to_vec()));
    let wrapped = WrappedContract::new(code, params);
    let key: ContractKey = *wrapped.key();
    let container = ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped));
    let bytes = forward.bytes;

    wasm_bindgen_futures::spawn_local(async move {
        match super::put_contract(container, WrappedState::new(bytes)).await {
            Ok(()) => info!(
                "migration: PUT recovered {} state forward to {}",
                artifact.as_str(),
                key.id()
            ),
            Err(e) => warn!(
                "migration: could not PUT recovered {} state forward: {e}",
                artifact.as_str()
            ),
        }
    });
}

/// Point this session's `my_stores` entry at the generation that now holds the
/// seller's data.
///
/// Replaces the predecessor registration rather than adding to it: the
/// recovered store is the SAME store at a new address, and appending would
/// show the seller two.
///
/// The delegate's own registry is not rewritten here, and after a reload it
/// still names the predecessor. Repointing it needs a delegate request that
/// can REPLACE a registration -- `RegisterStore` only appends, and is a no-op
/// for a store id it already holds -- which is a separate change with its own
/// duplicate-handling to reason about. Until then the probe simply runs again
/// on the next load, which is exactly what the marker rules make safe.
fn adopt_recovered_store(fingerprint: &str, current: ContractInstanceId) {
    let current_bytes = current.as_bytes().to_vec();
    let mut app = super::APP_STATE.write();
    let Some(stores) = app.my_stores.get_mut(fingerprint) else {
        return;
    };
    if stores.iter().any(|s| s.store_contract_id == current_bytes) {
        return;
    }
    if let Some(existing) = stores.first_mut() {
        existing.store_contract_id = current_bytes;
        // The recorded key belonged to the predecessor's code hash and is now
        // wrong. Clearing it makes `store_contract_key` rebuild from the
        // bundled contract, which is the right answer for the current
        // generation.
        existing.store_contract_key = None;
    }
}
