//! Carrying a seller's data forward when Harvest's contracts re-key.
//!
//! # Why this exists
//!
//! A contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, so **the compiled
//! bytes are the address**. Every rebuild that changes codegen -- a source
//! edit, a direct or transitive dependency bump, a rustc upgrade, a `cargo fmt`
//! that moves a panic location -- moves every store, reputation and mailbox
//! instance to a new address. The new address is empty. The seller's listings,
//! feedback and messages are still sitting at the old one, and nothing anywhere
//! reports a problem.
//!
//! Freenet has no core mechanism to carry state across that, deliberately and
//! permanently (freenet-core#2776), so it is app-level work. `legacy/*.toml`
//! records every superseded code hash; this module walks them.
//!
//! # What makes Harvest's instance ids re-derivable
//!
//! A predecessor's instance id is `BLAKE3(old_code_hash || cbor(params))`, so
//! recovering an old generation needs the OLD hash (from the registry) and the
//! parameter bytes that generation was published under -- never the old WASM,
//! which is why the artifacts being stale and irreproducible (harvest#18) does
//! not block any of this.
//!
//! Harvest's parameters happen to be derivable from things the client already
//! knows:
//!
//! * **Store** -- the seller's ghostkey verifying key.
//! * **Mailbox** -- the owner's ghostkey verifying key.
//! * **Reputation** -- the seller's RSA public key AND their verifying key.
//!
//! The first two need nothing but the ghostkey, which is why a store is
//! recoverable even for a seller whose delegate secrets are gone. The third
//! does not, and that asymmetry is the ordering constraint below.
//!
//! ## When the PARAMETERS change, not just the code
//!
//! `freenet_migrate` derives every predecessor id from one set of parameter
//! bytes, which is right only while the parameter encoding is stable. The
//! store's is not: `StoreParameters` shed two fields when the Bitcoin bridge
//! list moved onto `Order`, so generations V1-V5 live at addresses no
//! encoding this build produces can reproduce. [`store_candidates`] derives
//! each generation under the encoding it was actually published with, and
//! [`LAST_LEGACY_STORE_PARAM_GENERATION`] is the boundary. Any future change
//! to a contract's parameters needs the same treatment, and its absence is
//! silent: the probe finds nothing at every address and reports success.
//!
//! # The ordering constraint
//!
//! `ReputationParameters::rsa_public_key_der` is exactly the value the harvest
//! delegate holds under `harvest:rsa_pk:{fingerprint}`. So a reputation
//! instance id -- for **any** generation, the current one included -- cannot be
//! derived until that secret has been carried forward. Probing reputation
//! first would not merely fail to find anything: it would probe ids derived
//! from the wrong key, get nothing, and could seal a "nothing there" marker
//! over a perfectly recoverable instance.
//!
//! Here the constraint is structural rather than a rule to remember:
//! [`reputation_probe_inputs`] cannot be constructed without the RSA key, and
//! the only source of that key is a delegate response. Store and mailbox have
//! no such dependency and run as soon as the ghostkey is known.
//!
//! # When the probe runs
//!
//! **Unconditionally, once per `(instance, current_code_hash)`, seeded from
//! whatever snapshot the client already holds.** Only the REPEAT is gated, on a
//! durable marker.
//!
//! The first run is deliberately *not* gated on the successor being empty. An
//! emptiness gate reads like a free optimisation and is the shape that lost
//! River's rooms (freenet/river#621): any write to the new key satisfies "not
//! empty" first, and the probe then never fires -- an optimistic PUT, a
//! placeholder seed, a cached snapshot pushed forward all qualify, and all of
//! them are silent. Harvest has exactly such a write:
//! `create_store_contracts` PUTs `StoreStateV1::default()` under the current
//! key. Under an emptiness gate that PUT would permanently disable the
//! migration for that seller.
//!
//! # What may seal a marker
//!
//! Only `Recovered` with no unresolved candidates and no truncated fold. That
//! is the one *positive* result: the data was found and the search is known to
//! have been complete.
//!
//! Never `SeedLocal`, however conclusive it looks. Absence on Freenet is
//! unauthenticated: with the placement migration disabled (freenet-core#4440),
//! present-but-unfindable dead-ends were measured at ~99.6% of all
//! `get_not_found` traffic, so an all-`Absent` walk is more likely reporting a
//! routing failure than an empty lineage. The crate's own 0.6.0 documentation
//! says outright that it cannot tell you sealing is safe.
//!
//! `Outcome` is `#[non_exhaustive]`, so the wildcard arm in [`seal_decision`]
//! falls through to *retry* -- for today's non-definitive variants and for
//! every variant added later. A wildcard defaulting to "done" would write a
//! permanent marker for a case nobody has seen yet.

use freenet_migrate::{
    contract_id_from_code_hash, ContractLineageEntry, DelegateLineageEntry, FoldAllAck, Outcome,
    ProbeStateOps, SelectionPolicy,
};
use freenet_stdlib::prelude::{ContractInstanceId, Parameters};
use harvest_common::mailbox::{MailboxParameters, MailboxStateV1};
use harvest_common::reputation::{ReputationParameters, ReputationStateV1};
use harvest_common::store::{StoreParameters, StoreStateV1};

// The codegen emits both a contract and a delegate const per file; only one of
// each pair is populated. Wrapping each in its own module keeps the names from
// colliding, and the `dead_code` allow covers the empty half rather than
// editing generated source.
#[allow(dead_code)]
mod store_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_store_contract.rs"));
}
#[allow(dead_code)]
mod reputation_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_reputation_contract.rs"));
}
#[allow(dead_code)]
mod mailbox_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_mailbox_contract.rs"));
}
#[allow(dead_code)]
mod delegate_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_harvest_delegate.rs"));
}

/// Superseded generations of the store contract, oldest first.
pub fn store_lineage() -> &'static [ContractLineageEntry] {
    store_gen::LEGACY_STORE_CONTRACT
}

/// Superseded generations of the reputation contract, oldest first.
pub fn reputation_lineage() -> &'static [ContractLineageEntry] {
    reputation_gen::LEGACY_REPUTATION_CONTRACT
}

/// Superseded generations of the mailbox contract, oldest first.
pub fn mailbox_lineage() -> &'static [ContractLineageEntry] {
    mailbox_gen::LEGACY_MAILBOX_CONTRACT
}

/// Superseded generations of the harvest delegate, oldest first.
///
/// Recorded and exercised by tests, but nothing recovers from them yet: the
/// export handshake needs the PREDECESSOR delegate to answer an export
/// request, and no generation before the current one has an export handler.
/// See `legacy/harvest_delegate.toml`.
pub fn delegate_lineage() -> &'static [DelegateLineageEntry] {
    delegate_gen::LEGACY_HARVEST_DELEGATE
}

/// Which artifact a probe is for. Used to key durable markers, so that a
/// store and a mailbox whose instance ids somehow coincided could not share
/// one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Artifact {
    Store,
    Reputation,
    Mailbox,
}

impl Artifact {
    pub fn as_str(self) -> &'static str {
        match self {
            Artifact::Store => "store",
            Artifact::Reputation => "reputation",
            Artifact::Mailbox => "mailbox",
        }
    }

    pub fn lineage(self) -> &'static [ContractLineageEntry] {
        match self {
            Artifact::Store => store_lineage(),
            Artifact::Reputation => reputation_lineage(),
            Artifact::Mailbox => mailbox_lineage(),
        }
    }
}

// --- parameters ---------------------------------------------------------

/// The store parameters a seller's store is published under.
///
/// These must match `create_store_contracts` exactly, or every id derived here
/// names a contract that does not exist. The seller's key is the only
/// parameter, which is what makes every generation's store instance derivable
/// from the seller's ghostkey alone -- the Bitcoin trust configuration used to
/// sit here too and is now per-order, so it can no longer re-key a store.
pub fn store_params(seller_verifying_key: &ed25519_dalek::VerifyingKey) -> StoreParameters {
    StoreParameters {
        seller_verifying_key: *seller_verifying_key,
    }
}

/// The last store generation published under the OLD `StoreParameters` shape.
///
/// # Why a generation split exists at all
///
/// A contract's address is `BLAKE3(code_hash || parameter_bytes)`, and
/// `freenet_migrate::ContractLineageEntry` carries only the code hash: the
/// crate derives every predecessor's id using the parameters the CURRENT build
/// encodes. That is right as long as the parameter *encoding* never changes,
/// and it silently stops being right the moment it does -- the probe walks a
/// list of addresses that never existed, finds nothing at every one, and
/// reports a clean "nothing to migrate".
///
/// `StoreParameters` used to carry `trusted_bitcoin_bridges` and
/// `bitcoin_address_code_hash` alongside the seller's key. Moving them onto
/// `Order` cut its CBOR from 109 bytes to 56, so every store ever published --
/// generations V1 through V5 -- lives at an address derived from the longer
/// encoding, and nothing this build encodes will ever reproduce it.
///
/// So this constant is the boundary: at or below it, derive with
/// [`legacy_store_params_cbor`]; above it, with today's encoding. It is a
/// fixed historical fact, not a thing to bump on the next re-key -- a
/// generation added later is published under the current shape.
pub const LAST_LEGACY_STORE_PARAM_GENERATION: u32 = 5;

/// The parameter bytes generations V1..=[`LAST_LEGACY_STORE_PARAM_GENERATION`]
/// were actually published under.
///
/// Mirrors the old `StoreParameters` exactly, including the values
/// `create_store_contracts` supplied for the two Bitcoin fields: an empty
/// bridge list and no code hash. This is a frozen record of bytes that already
/// exist on the network, so it is written out here rather than derived from
/// the live struct -- deriving it from a type that is still being edited is
/// how it would go quietly wrong again.
fn legacy_store_params_cbor(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Parameters<'static>, String> {
    #[derive(serde::Serialize)]
    struct LegacyStoreParameters {
        seller_verifying_key: ed25519_dalek::VerifyingKey,
        trusted_bitcoin_bridges: Vec<[u8; 32]>,
        bitcoin_address_code_hash: Option<[u8; 32]>,
    }
    encode_params(&LegacyStoreParameters {
        seller_verifying_key: *seller_verifying_key,
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    })
}

/// Every superseded store instance to probe, newest generation first, each id
/// derived under the parameter encoding ITS generation was published with.
///
/// This is what `freenet_migrate::NewestFirst::from_lineage` would do if the
/// encoding had never changed; it exists only because it did. See
/// [`LAST_LEGACY_STORE_PARAM_GENERATION`].
pub fn store_candidate_ids(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Vec<ContractInstanceId>, String> {
    let current = encode_params(&store_params(seller_verifying_key))?;
    let legacy = legacy_store_params_cbor(seller_verifying_key)?;

    let mut by_generation: Vec<(u32, ContractInstanceId)> = store_lineage()
        .iter()
        .map(|e| {
            let params = if e.generation <= LAST_LEGACY_STORE_PARAM_GENERATION {
                &legacy
            } else {
                &current
            };
            (
                e.generation,
                contract_id_from_code_hash(&e.code_hash, params),
            )
        })
        .collect();
    // Same ordering rule as `NewestFirst::from_lineage`: by the registry's
    // declared generation, never by slice order.
    by_generation.sort_by_key(|(generation, _)| core::cmp::Reverse(*generation));
    Ok(by_generation.into_iter().map(|(_, id)| id).collect())
}

/// [`store_candidate_ids`] as the ordering-proof type `ProbeSession` wants.
///
/// `assume_ordered` is safe here for the reason it asks for: the list is sorted
/// by the registry's declared `generation`, descending, immediately above.
pub fn store_candidates(
    seller_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<freenet_migrate::NewestFirst, String> {
    Ok(freenet_migrate::NewestFirst::assume_ordered(
        store_candidate_ids(seller_verifying_key)?,
    ))
}

pub fn mailbox_params(owner_verifying_key: &ed25519_dalek::VerifyingKey) -> MailboxParameters {
    MailboxParameters {
        owner_verifying_key: *owner_verifying_key,
    }
}

pub fn reputation_params(
    rsa_public_key_der: Vec<u8>,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> ReputationParameters {
    ReputationParameters {
        rsa_public_key_der,
        owner_verifying_key: *owner_verifying_key,
    }
}

/// The reputation probe's inputs, which cannot be assembled without the RSA
/// public key the harvest delegate holds.
///
/// This type exists to make the ordering constraint structural rather than
/// remembered: there is no way to start a reputation probe while the delegate
/// secret is still missing, because there is no way to build this.
pub struct ReputationProbeInputs {
    pub params: ReputationParameters,
}

/// Assemble the reputation probe's inputs, or `None` if the delegate has not
/// yet produced this identity's RSA public key.
///
/// `None` means **not yet**, never "nothing to migrate". The caller must not
/// substitute a placeholder key or fall back to probing without one: the ids
/// would be wrong, the walk would find nothing, and a seal on that would
/// strand a recoverable instance permanently.
pub fn reputation_probe_inputs(
    rsa_public_key_der: Option<&Vec<u8>>,
    owner_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Option<ReputationProbeInputs> {
    let der = rsa_public_key_der?;
    if der.is_empty() {
        return None;
    }
    Some(ReputationProbeInputs {
        params: reputation_params(der.clone(), owner_verifying_key),
    })
}

/// CBOR-encode parameters the way the contracts do.
pub fn encode_params<T: serde::Serialize>(params: &T) -> Result<Parameters<'static>, String> {
    harvest_common::to_cbor(params)
        .map(Parameters::from)
        .map_err(|e| format!("serialize contract parameters: {e}"))
}

/// The instance ids of every superseded generation, for these parameters.
///
/// The crate's own derivation, re-exported rather than reimplemented: this is
/// the function whose agreement with the node's addressing the whole scheme
/// rests on, and a second copy is a second thing to get wrong.
pub use freenet_migrate::predecessor_ids;

/// The instance id this build's WASM produces for these parameters.
pub fn current_id(code_hash: &[u8; 32], params: &Parameters<'_>) -> ContractInstanceId {
    contract_id_from_code_hash(code_hash, params)
}

// --- state semantics ----------------------------------------------------

/// Merge rules for a store's state.
///
/// The merge is the contract's own `ComposableState::merge`, reused rather
/// than reimplemented: folding a generation is then the same operation the
/// network performs between two peers, so its correctness does not have to be
/// argued separately from the contract's.
pub struct StoreOps {
    pub params: StoreParameters,
}

impl ProbeStateOps for StoreOps {
    type State = StoreStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        harvest_common::from_cbor(bytes).ok()
    }

    /// "Real" means the seller actually did something with this store.
    ///
    /// A store PUT at creation time holds `StoreStateV1::default()`: info at
    /// version 0 (the uninitialized version `verify` skips), no listings, no
    /// orders. Adopting one of those would report a hit while recovering
    /// nothing, and -- worse -- could satisfy a caller that stops at the first
    /// hit, so a genuinely populated older generation would never be reached.
    fn is_real(&self, state: &Self::State) -> bool {
        state.info.info.version > 0
            || !state.listings.listings.is_empty()
            || !state.orders.orders.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_store(recovered, local, &self.params)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_store(newer, &older, &self.params)
    }
}

fn merge_store(
    mut base: StoreStateV1,
    other: &StoreStateV1,
    params: &StoreParameters,
) -> StoreStateV1 {
    use freenet_scaffold::ComposableState;
    let snapshot = base.clone();
    // Keep the primary on a merge failure rather than losing it -- the
    // behaviour `ProbeStateOps` documents. A merge fails here when the other
    // side carries a listing whose signature does not verify against these
    // parameters, which is exactly a case where discarding the other side is
    // the right answer.
    if base.merge(&snapshot, params, other).is_err() {
        return snapshot;
    }
    base
}

/// Merge rules for a reputation contract's state.
pub struct ReputationOps {
    pub params: ReputationParameters,
}

impl ProbeStateOps for ReputationOps {
    type State = ReputationStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        harvest_common::from_cbor(bytes).ok()
    }

    /// Feedback is what a reputation contract is for. A state holding only a
    /// certificate is the shell created alongside a store and carries nothing
    /// to recover.
    fn is_real(&self, state: &Self::State) -> bool {
        !state.feedback.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_reputation(recovered, local, &self.params)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_reputation(newer, &older, &self.params)
    }
}

/// The reputation contract's own merge: take every feedback entry we do not
/// already hold, verifying each signature as it lands.
///
/// Mirrors `update_state`'s `UpdateData::State` arm in
/// `contracts/reputation-contract`, including the certificate back-fill.
fn merge_reputation(
    mut base: ReputationStateV1,
    other: &ReputationStateV1,
    params: &ReputationParameters,
) -> ReputationStateV1 {
    let snapshot = base.clone();
    let delta: Vec<_> = other
        .feedback
        .iter()
        .filter(|e| !base.used_nonces.contains(&e.token.nonce))
        .cloned()
        .collect();
    if !delta.is_empty() && base.apply_delta(params, &Some(delta)).is_err() {
        // One unverifiable entry rejects the whole delta, so keep the primary
        // rather than adopting a partially-applied state.
        return snapshot;
    }
    if base.owner_certificate_pem.is_empty() {
        base.owner_certificate_pem = other.owner_certificate_pem.clone();
    }
    base
}

/// Merge rules for a mailbox's state.
pub struct MailboxOps {
    pub params: MailboxParameters,
}

impl ProbeStateOps for MailboxOps {
    type State = MailboxStateV1;

    fn decode(&self, bytes: &[u8]) -> Option<Self::State> {
        harvest_common::from_cbor(bytes).ok()
    }

    fn is_real(&self, state: &Self::State) -> bool {
        !state.messages.is_empty()
    }

    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State {
        merge_mailbox(recovered, local)
    }

    fn merge_generations(&self, newer: Self::State, older: Self::State) -> Self::State {
        merge_mailbox(newer, &older)
    }
}

/// The mailbox contract's own merge: add messages we do not hold, then let
/// `apply_delta` re-run its deterministic TTL prune.
///
/// Folding an older generation can re-admit a message the successor had
/// already pruned. That is harmless and self-correcting: the prune is measured
/// against the newest timestamp present after the merge and is re-applied on
/// every `apply_delta`, so the fold result is pruned again by the same rule
/// every peer would apply to the same bytes.
fn merge_mailbox(mut base: MailboxStateV1, other: &MailboxStateV1) -> MailboxStateV1 {
    let snapshot = base.clone();
    let delta: Vec<_> = other
        .messages
        .iter()
        .filter(|m| !base.messages.iter().any(|held| held.nonce == m.nonce))
        .cloned()
        .collect();
    if base.apply_delta(&Some(delta)).is_err() {
        return snapshot;
    }
    base
}

// --- policy -------------------------------------------------------------

/// `FoldAll` for all three artifacts, and the acknowledgement is earned rather
/// than waved through.
///
/// Fold-all is only sound where deletions are EXPLICIT, because it resurrects
/// anything deleted by mere absence. For each of Harvest's three states:
///
/// * **Store** -- listings are grow-only and keyed by `ListingId`; the
///   contract has no removal path at all, so absence is never a deletion.
///   Orders are capacity-pruned by `enforce_order_cap`, which is deterministic
///   and re-run inside `apply_delta`, so a fold that re-admits a pruned order
///   is pruned again identically.
/// * **Reputation** -- a grow-only set keyed by nonce with no removal path
///   whatsoever. Nothing can be resurrected because nothing is ever deleted.
/// * **Mailbox** -- messages are keyed by nonce and pruned by a TTL measured
///   against the newest message present, re-applied on every `apply_delta`.
///   Same argument as the order cap.
///
/// Fold-all matters here rather than being a free upgrade: Harvest has re-keyed
/// four times, so a seller who used it across generations has listings at
/// several DIFFERENT instances, none of which was ever carried forward.
/// `NewestFirstWins` would stop at the newest populated one and leave the rest.
///
/// The preconditions are asserted on real states in this module's tests via
/// the crate's own `policy_check` helpers, which is the point of the ack being
/// a token rather than a comment.
pub fn fold_all_policy() -> SelectionPolicy {
    SelectionPolicy::FoldAll(FoldAllAck::i_understand_fold_all_resurrects_without_tombstones())
}

// --- sealing ------------------------------------------------------------

/// Whether a finished probe may record a durable "done" marker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seal {
    /// Positive evidence: the data was found and the search was complete.
    Seal,
    /// Anything else. Adopt what there is, seal nothing, probe again next run.
    Retry,
}

/// The sealing rule.
///
/// Exactly one shape may seal: `Recovered` with **no** unresolved candidates
/// and **no** truncated fold. Everything else retries, including the wildcard
/// -- `Outcome` is `#[non_exhaustive]`, so a variant added by a future release
/// lands there, and a wildcard that defaulted to `Seal` would write a
/// permanent marker for a case this code has never seen.
///
/// `SeedLocal` is called out separately below because it is the one that looks
/// safe. It means every candidate answered and none held state -- but a
/// `NotFound` on Freenet is unauthenticated and routinely wrong (~99.6% of
/// `get_not_found` traffic was present-but-unfindable when the placement
/// migration was disabled, freenet-core#4440), and an undecodable answer lands
/// here too. Sealing on it would mark a live predecessor permanently empty.
pub fn seal_decision<S>(outcome: &Outcome<S>) -> Seal {
    match outcome {
        Outcome::Recovered {
            truncated_fold: false,
            unresolved,
            ..
        } if unresolved.is_empty() => Seal::Seal,
        // A recovery that is missing generations is a partial answer. Adopt it
        // -- the merge only ever adds -- but leave the migration open.
        Outcome::Recovered { .. } => Seal::Retry,
        // Never. See this function's docs.
        Outcome::SeedLocal { .. } => Seal::Retry,
        Outcome::Indeterminate { .. } => Seal::Retry,
        // An empty lineage is not evidence of anything. It also cannot happen
        // here -- ui/build.rs fails the build on a registry with no rows --
        // but sealing on it would be wrong if it ever did.
        Outcome::NoLegacy { .. } => Seal::Retry,
        _ => Seal::Retry,
    }
}

/// A one-line description of an outcome, for the log and the notification bar.
pub fn describe<S>(outcome: &Outcome<S>) -> String {
    match outcome {
        Outcome::Recovered {
            source,
            truncated_fold,
            unresolved,
            ..
        } => {
            let mut s = format!("recovered state from predecessor {source}");
            if *truncated_fold {
                s.push_str("; the fold was cut short by the hop cap");
            }
            if !unresolved.is_empty() {
                s.push_str(&format!(
                    "; {} predecessor(s) never answered, so this is not the whole story",
                    unresolved.len()
                ));
            }
            s
        }
        Outcome::SeedLocal { .. } => {
            "every predecessor answered and none held state; keeping local, sealing nothing"
                .to_string()
        }
        Outcome::Indeterminate { unresolved, .. } => format!(
            "{} predecessor(s) did not answer; adopting nothing and retrying later",
            unresolved.len()
        ),
        Outcome::NoLegacy { .. } => "no predecessor generations recorded".to_string(),
        _ => "unrecognised migration outcome; treating as retry".to_string(),
    }
}

// --- durable markers ----------------------------------------------------

/// The id under which a completed migration is recorded.
///
/// Keyed by `(artifact, instance, current code hash)`. The code hash is part
/// of the key because a marker only ever means "this generation has finished
/// pulling its predecessors forward" -- the next re-key produces a new key and
/// the walk runs again, which is the whole point.
///
/// **Both ids are hex.** Raw bytes in a storage key alias: anything that puts
/// a key through a lossy UTF-8 conversion maps every invalid byte to U+FFFD,
/// so two distinct 32-byte ids collapse onto one marker slot and one of them
/// gets sealed having never been migrated. River hit exactly that.
///
/// The `v1.` prefix versions the id FORMAT. It is the client that mints these,
/// so a change of shape has to invalidate the old ones from here; the delegate
/// only prefixes its own namespace and cannot know the format moved.
///
/// This is an id, not a storage key: the harvest delegate concatenates it onto
/// `harvest:migrate:` itself, so nothing chosen here can name another secret.
pub fn marker_key(
    artifact: Artifact,
    instance: &ContractInstanceId,
    current_code_hash: &[u8; 32],
) -> String {
    format!(
        "v1.{}.{}.{}",
        artifact.as_str(),
        hex::encode(instance.as_bytes()),
        hex::encode(current_code_hash),
    )
}

/// What the delegate said about a marker -- or failed to say.
///
/// The third variant is the one that matters. A marker query can fail to
/// produce an answer in ways that are not "absent": the delegate may not be
/// registered yet, the send may fail, the reply may never arrive. Those are
/// silence, and silence has to be distinguishable from a definite `Absent` at
/// the type level so neither can be quietly read as the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MarkerLookup {
    /// The delegate answered: this migration is already recorded as done.
    Present,
    /// The delegate answered: nothing is recorded.
    Absent,
    /// No usable answer -- not registered, send failed, or nothing came back.
    Unavailable,
}

/// Whether a probe should run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate {
    /// The marker says this generation already finished. Skip.
    Skip,
    /// Run the walk.
    Run,
}

/// The repeat gate: **only a definite `Present` skips.**
///
/// # Why the direction is the whole design
///
/// This gate used to be a `localStorage` read, which in the deployed gateway
/// is not a gate at all: Freenet serves a webapp inside an iframe with no
/// `allow-same-origin`, so the frame has an opaque origin and
/// `window.localStorage` throws. The marker worked under `dx serve` and was a
/// silent no-op once published -- every seller re-swept every generation of
/// every artifact on every page load, forever. It cost performance and nothing
/// else, and the reason it cost nothing else is precisely this direction:
/// storage that cannot answer reads as "not migrated".
///
/// So the marker moved into the harvest delegate's secret store (which is
/// where River keeps its own, for the same reason), and the direction moved
/// with it. `Unavailable` runs the walk. A walk that did not need to run
/// merges what it finds into what is already there and adds nothing; a walk
/// that was skipped because a storage failure looked like "done" leaves the
/// seller's listings at an address nothing will ever visit again.
pub fn probe_gate(lookup: MarkerLookup) -> Gate {
    match lookup {
        MarkerLookup::Present => Gate::Skip,
        MarkerLookup::Absent => Gate::Run,
        // Never `Skip`. See this function's docs.
        MarkerLookup::Unavailable => Gate::Run,
    }
}

/// The delegate request that asks whether a marker is recorded.
///
/// Built here rather than at the call site so the wire shape is next to the
/// rules it serves, and so it is exercised by this module's native tests --
/// the call site is wasm-only.
pub fn marker_query(marker: &str) -> harvest_common::HarvestDelegateRequest {
    harvest_common::HarvestDelegateRequest::GetMigrationMarker {
        marker: marker.to_string(),
    }
}

/// The delegate request that records a completed migration.
///
/// Best effort by design: a write the delegate refuses means the probe
/// repeats, which is wasteful and correct.
pub fn marker_write(marker: &str, note: &str) -> harvest_common::HarvestDelegateRequest {
    harvest_common::HarvestDelegateRequest::SetMigrationMarker {
        marker: marker.to_string(),
        note: note.to_string(),
    }
}

// --- the probe, as a hand-pumped session -------------------------------

/// One probe of one artifact for one identity.
///
/// # Why hand-pumped rather than `migrate_contract`
///
/// `freenet_migrate::migrate_contract` wants an awaitable
/// request/response adapter. The browser does not have one: `WebApi` delivers
/// every response to a single app-registered handler, so correlation is the
/// app's job. `ProbeDriver` is the crate's sans-IO answer to exactly that
/// environment, and this is a thin wrapper over it -- the two make identical
/// decisions.
///
/// Wrapping rather than using `ProbeDriver` directly at the call site buys one
/// thing that matters: the sequencing lives in native-testable code. The
/// wasm-only part is reduced to sending a GET, arming a timer, and routing a
/// response, and everything with a decision in it -- what to ask next, what a
/// silence means, whether the result may be sealed -- is exercised by
/// `cargo test` on the host.
pub struct ProbeSession<O: ProbeStateOps> {
    driver: freenet_migrate::ProbeDriver<O>,
    /// The candidate a GET is outstanding for, if any. Held here as well as in
    /// the driver so a stale response or a fired timer can be recognised as
    /// stale by the caller before it reaches the driver.
    outstanding: Option<ContractInstanceId>,
    finished: Option<(Outcome<O::State>, Seal)>,
}

impl<O: ProbeStateOps> ProbeSession<O> {
    /// Start a probe over a lineage.
    ///
    /// Candidates are ordered by the registry's `generation` field, descending
    /// -- never by slice order, so a generation appended out of order (which is
    /// exactly what "append the outgoing hash" invites) is still probed in the
    /// right place.
    pub fn start(
        ops: O,
        local_snapshot: O::State,
        params: &Parameters<'_>,
        lineage: &[ContractLineageEntry],
        policy: SelectionPolicy,
    ) -> Self {
        Self::start_with_candidates(
            ops,
            local_snapshot,
            freenet_migrate::NewestFirst::from_lineage(params, lineage),
            policy,
        )
    }

    /// Start a probe over candidates the caller derived itself.
    ///
    /// Only for an artifact whose PARAMETER ENCODING changed at some point in
    /// its lineage, so one set of parameter bytes cannot address every
    /// generation -- see [`store_candidates`]. Everything else should use
    /// [`start`](Self::start), which cannot be handed a wrong order.
    pub fn start_with_candidates(
        ops: O,
        local_snapshot: O::State,
        candidates: freenet_migrate::NewestFirst,
        policy: SelectionPolicy,
    ) -> Self {
        Self {
            driver: freenet_migrate::ProbeDriver::new(ops, local_snapshot, candidates, policy),
            outstanding: None,
            finished: None,
        }
    }

    /// The next candidate to GET, or `None` when the probe is finished.
    ///
    /// Idempotent: asking again without an intervening event returns the same
    /// candidate rather than advancing.
    pub fn next_get(&mut self) -> Option<ContractInstanceId> {
        if self.finished.is_some() {
            return None;
        }
        match self.driver.next_action() {
            freenet_migrate::Step::Get(id) => {
                self.outstanding = Some(id);
                Some(id)
            }
            freenet_migrate::Step::Done => {
                self.outstanding = None;
                if let Some(outcome) = self.driver.take_outcome() {
                    let seal = seal_decision(&outcome);
                    self.finished = Some((outcome, seal));
                }
                None
            }
        }
    }

    /// The candidate a GET is currently outstanding for.
    pub fn outstanding(&self) -> Option<ContractInstanceId> {
        self.outstanding
    }

    /// A GET response arrived for `id`.
    pub fn on_state(&mut self, id: ContractInstanceId, bytes: &[u8]) {
        self.driver.on_response(id, bytes);
        self.clear_if(id);
    }

    /// The node answered, positively, that there is nothing at `id`
    /// (`ContractResponse::NotFound`).
    ///
    /// Only ever call this for an answer actually received. Routing a deadline
    /// here types silence as absence, which is the data-loss default
    /// freenet-migrate#19 exists to remove.
    pub fn on_absent(&mut self, id: ContractInstanceId) {
        self.driver.on_absent(id);
        self.clear_if(id);
    }

    /// Nothing came back for `id`: a timeout, a send failure, an unexpected
    /// response, an error the transport could not attribute.
    ///
    /// This establishes nothing, so the candidate is recorded as unresolved
    /// and the walk can never end in a sealable outcome because of it.
    pub fn on_unknown(&mut self, id: ContractInstanceId) {
        self.driver.on_unknown(id);
        self.clear_if(id);
    }

    fn clear_if(&mut self, id: ContractInstanceId) {
        if self.outstanding == Some(id) {
            self.outstanding = None;
        }
    }

    /// The terminal outcome and whether it may seal a durable marker, once the
    /// probe is done. `None` while it is still running.
    ///
    /// Taking it leaves the session finished; a second call returns `None`.
    pub fn take_result(&mut self) -> Option<(Outcome<O::State>, Seal)> {
        self.finished.take()
    }
}

#[cfg(test)]
mod tests;
