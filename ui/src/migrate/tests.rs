//! Tests for the migration registries and the probe's decisions.
//!
//! Two halves, and the second is the one that matters most.
//!
//! The **registry** tests pin what is recorded: that every lineage is
//! non-empty and ordered, that the recorded hashes are the ones derived from
//! git history, that each delegate key really derives from its code hash, and
//! that no CURRENT hash has crept into a registry of superseded ones.
//!
//! The **probe** tests drive a real `ProbeDriver` through the answers the
//! network actually gives -- state, a positive `NotFound`, and silence -- and
//! assert what may be sealed. Every failure in this area is silent, so the
//! only useful assertions are the ones that fail when a guard is removed. Each
//! test below was confirmed to go red by applying the mutation it describes.

use std::collections::HashSet;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_migrate::Outcome;
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId};
use harvest_common::listing::{AuthorizedListing, Listing, ListingId, ListingKind};
use harvest_common::mailbox::{EncryptedMessage, MailboxStateV1};
use harvest_common::reputation::{FeedbackEntry, ReputationStateV1};
use harvest_common::store::StoreStateV1;

use super::*;

// --- fixtures -----------------------------------------------------------

fn seller() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn seller_vk() -> VerifyingKey {
    seller().verifying_key()
}

fn store_bytes(state: &StoreStateV1) -> Vec<u8> {
    harvest_common::to_cbor(state).expect("serialize store state")
}

/// A listing signed the way the ghostkey delegate signs one, so
/// `AuthorizedListing::verify` -- which the store contract's `apply_delta`
/// runs on every merged listing -- accepts it.
fn signed_listing(id: u8, title: &str) -> AuthorizedListing {
    let listing = Listing {
        id: ListingId([id; 16]),
        title: title.to_string(),
        description: String::new(),
        kind: ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp"),
    };
    let payload = harvest_common::to_cbor(&listing).expect("serialize listing");
    let scoped = ghostkey_common::ScopedPayload {
        requestor: ghostkey_common::SignatureRequestor::WebApp(
            harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                .parse::<ContractInstanceId>()
                .expect("canonical webapp id"),
        ),
        payload,
    };
    let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped payload");
    let signature = seller().sign(&scoped_payload).to_bytes().to_vec();
    AuthorizedListing {
        listing,
        scoped_payload,
        signature,
        certificate_pem: String::new(),
    }
}

fn store_with(listings: &[AuthorizedListing]) -> StoreStateV1 {
    let mut state = StoreStateV1::default();
    state.listings.listings = listings.to_vec();
    state
}

fn message(nonce: u8, secs: i64) -> EncryptedMessage {
    EncryptedMessage {
        conversation_id: harvest_common::mailbox::ConversationId([nonce; 32]),
        sender_public_key: vec![nonce; 32],
        ciphertext: vec![nonce; 8],
        timestamp: chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp"),
        nonce: [nonce; 24],
    }
}

fn mailbox_with(messages: Vec<EncryptedMessage>) -> MailboxStateV1 {
    MailboxStateV1 { messages }
}

fn store_ops() -> StoreOps {
    StoreOps {
        params: store_params(&seller_vk()),
    }
}

fn store_params_encoded() -> freenet_stdlib::prelude::Parameters<'static> {
    encode_params(&store_params(&seller_vk())).expect("encode store params")
}

/// Drive a probe to completion, answering each candidate from `answers`.
///
/// `answers` maps a candidate id to what the network says about it; anything
/// not listed is silence (`on_unknown`), which is how a real run behaves when
/// a deadline expires.
enum Answer {
    State(Vec<u8>),
    Absent,
    Silence,
}

fn run<O: ProbeStateOps>(
    mut session: ProbeSession<O>,
    mut answer: impl FnMut(ContractInstanceId) -> Answer,
) -> (Outcome<O::State>, Seal) {
    // Bounded so a driver bug cannot hang the test suite.
    for _ in 0..64 {
        match session.next_get() {
            Some(id) => match answer(id) {
                Answer::State(bytes) => session.on_state(id, &bytes),
                Answer::Absent => session.on_absent(id),
                Answer::Silence => session.on_unknown(id),
            },
            None => {
                return session
                    .take_result()
                    .expect("probe finished without a result")
            }
        }
    }
    panic!("probe did not terminate");
}

fn store_session(local: StoreStateV1) -> ProbeSession<StoreOps> {
    ProbeSession::start(
        store_ops(),
        local,
        &store_params_encoded(),
        store_lineage(),
        fold_all_policy(),
    )
}

// --- registry: what is recorded -----------------------------------------

/// Every lineage has rows. An empty lineage probes nothing, finds nothing, and
/// reports success -- the failure mode this whole mechanism exists to avoid,
/// and the one that looks healthiest.
///
/// `ui/build.rs` already fails the build on a registry with no `[[entry]]`
/// rows, and that guard fires FIRST -- so emptying a registry cannot make this
/// test red, it makes the build red. This asserts the same property one layer
/// down, against the generated consts rather than the TOML text, and covers
/// what the build guard cannot: a codegen change, or an accessor here, that
/// produced an empty lineage from a populated file.
///
/// Mutated red by stubbing `store_lineage()` to return `&[]`.
#[test]
fn every_lineage_has_predecessors() {
    for (name, len) in [
        ("store", store_lineage().len()),
        ("reputation", reputation_lineage().len()),
        ("mailbox", mailbox_lineage().len()),
        ("delegate", delegate_lineage().len()),
    ] {
        assert!(
            len > 0,
            "the {name} lineage is empty: a probe over it would report a clean \
             migration having looked at nothing"
        );
    }
}

/// Generations are unique and strictly increasing.
///
/// The driver orders candidates by the `generation` FIELD, descending -- not
/// by slice order -- so the whole newest-first guarantee, and with it the
/// anti-rollback property, rests on these numbers being right. Two rows
/// sharing a generation makes the probe order between them arbitrary.
#[test]
fn generations_are_unique_and_ascending() {
    for (name, entries) in [
        ("store", store_lineage()),
        ("reputation", reputation_lineage()),
        ("mailbox", mailbox_lineage()),
    ] {
        let generations: Vec<u32> = entries.iter().map(|e| e.generation).collect();
        let unique: HashSet<u32> = generations.iter().copied().collect();
        assert_eq!(
            unique.len(),
            generations.len(),
            "{name}: duplicate generation numbers {generations:?}"
        );
        let mut sorted = generations.clone();
        sorted.sort_unstable();
        assert_eq!(generations, sorted, "{name}: generations are out of order");
    }
    let delegate_generations: Vec<u32> = delegate_lineage().iter().map(|e| e.generation).collect();
    let mut sorted = delegate_generations.clone();
    sorted.sort_unstable();
    assert_eq!(
        delegate_generations, sorted,
        "delegate generations disorder"
    );
}

/// The recorded hashes, pinned.
///
/// Each was produced by hashing the committed artifact out of git history --
/// `git show <commit>:ui/public/contracts/<a>.wasm | b3sum --no-names` -- which
/// is meaningful because the UI embeds those files with `include_bytes!`, so
/// the committed bytes at a commit ARE what was deployed from it. The method
/// was checked first by confirming that HEAD's committed bytes reproduce
/// exactly under `scripts/build-contract-wasm.sh`.
///
/// This test is what makes deleting a row loud. A generation quietly dropped
/// from a registry is a generation nothing ever probes again, and no other
/// check in the repo would notice.
#[test]
fn the_recorded_hashes_are_the_ones_derived_from_git_history() {
    let expected: &[(&str, &[&str])] = &[
        (
            "store",
            &[
                "4d7ad3c31238a4b7a45095ae8722df52f9931a5362568ed2c63b3f36a96c711d",
                "0227238dccae77ef9f49d06b685fa3fed95fe63b292d7d7a4fa9d6ad3f42caa8",
                "ccc61113e758c463ab03a55612ac28a480c4733e9a82eb961566cf6496205233",
                "df0e8dfbc12071b1ab80d1b5c05aa6a9265b9b4141669a740f04f96363118d4a",
                "186f7784628f0f773dd711c91a35d822e2f1111fe052328227f924977df2d2c0",
                // V6, from `git show 94a3fd1:ui/public/contracts/store_contract.wasm`.
                // Superseded by the per-order Bitcoin payment address.
                "9add809b5af3b735114e0683fac23a459a1d3dde447cf4f921ced9a0719611cf",
            ],
        ),
        (
            "reputation",
            &[
                "b8577fa15470f4721ede1dfb677d03e263d6f59e6b2661d922aa5eb8d66ce3f9",
                "2d274a944701a37166b09c2a41d987738cd7b29a5f5b8b0179e400dace9ce1f5",
                "7f345c69a800288fe2eb649319cf9b34587953f8161976cc412ab4d308ad35da",
                "c9a939f9a93648f1571193228ccd2fd8331a9970f7c3d934b5b0d646f8cae2ca",
                "5c4d0eec19bf023c32c1723fc6676e43ecc1638922e952ab06c572b407350750",
                // V6, from `git show 94a3fd1:ui/public/contracts/reputation_contract.wasm`.
                "fd91d10d8100cec85ce5719290b57b2c56908352c31f5038fe0e78168eca9f35",
            ],
        ),
        (
            "mailbox",
            &[
                "db0b1c286442209e76eb7f507d945803ae9ebf6582e9f1b2714d57d7b03703cc",
                "a2819d2967e92510d0e1b7a5ece5c2261fbd04f4ec8b4fbdabd6f58d2ff0ea9d",
                "99fc27fab5a87d274fb32a5772a4f670cad6821700a7e4c54eaec783c6aa1358",
                "61154e38ca91b5dbf0e4c1c3fa5ad36b4ed56f058dbc8418d20781213e613f4e",
                "a00fd23796d2d87c6652749ac2365a94bf060f27f5fbe5e70929cc6635c19433",
                // V6, from `git show 94a3fd1:ui/public/contracts/mailbox_contract.wasm`.
                "e49cb3038b321a895850adcf594e09b6a5a698b7ba469a991a529910493628dc",
            ],
        ),
    ];

    for ((name, hashes), entries) in
        expected
            .iter()
            .zip([store_lineage(), reputation_lineage(), mailbox_lineage()])
    {
        let recorded: Vec<String> = entries.iter().map(|e| hex::encode(e.code_hash)).collect();
        assert_eq!(
            recorded,
            hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "{name}: the recorded generations are not the ones derived from git history"
        );
    }

    let delegate: Vec<String> = delegate_lineage()
        .iter()
        .map(|e| hex::encode(e.code_hash))
        .collect();
    assert_eq!(
        delegate,
        vec![
            "1fa5776b332464a22a99ca80d0079cf82120cfc57b195023af8bd6ec8dfd0bfd".to_string(),
            "2f805880b45c83ab25271e0da1e9528ab6a3f7e96dae730e4b5465227654877d".to_string(),
            "ddcecc5b3f1abd49194f103fec424ce6ad38f0ac8359a4bad92d9125ae43085e".to_string(),
            "57b467532105613f28829c0fac8a4d72d0a146593d6d64430892f5ce7009027a".to_string(),
            "230c2b581c4fa44de16cd9705413d099dfc5bff0634130907c1b81e0cee05c42".to_string(),
            // V6, from `git show ea94a33:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by moving the migration marker into this delegate's
            // own secret store.
            "d6a387917599b8ae3746dd41f7ad45d2cc008adb7f4f98b26156ed66032e4aec".to_string(),
            // V7, from `git show 94a3fd1:ui/public/contracts/harvest_delegate.wasm`.
            // Superseded by the per-order Bitcoin payment address, which added
            // the BIP-84 derivation module and the payment-xpub secret.
            "f6d6543524d359f54379bd9b0d79f5106a72d1d205b44b04f6375db74fde7e91".to_string(),
            // V8, from `git show d9cddad:ui/public/contracts/harvest_delegate.wasm`.
            // The first build of the payment-address work, superseded by its
            // own review fixes before it left the branch.
            "f563abc42391938ad99ea47202177acbeddd1e41d517a1b92a49a6aa03a3a6eb".to_string(),
        ],
    );
}

/// Every recorded delegate key is `BLAKE3(code_hash || params)` with Harvest's
/// empty parameters.
///
/// `freenet-migrate-build` already cross-checks this at build time. Re-deriving
/// it here independently is the point: the build-time check is only as good as
/// the build crate's own derivation agreeing with what the node does, and this
/// asserts the same property from the app's side of that boundary.
#[test]
fn delegate_keys_derive_from_their_code_hashes() {
    for entry in delegate_lineage() {
        assert!(
            !entry.irregular_key,
            "generation {} claims a pre-standard key; Harvest has never had one",
            entry.generation
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry.code_hash);
        // The derivation is `blake3(code_hash || params)`, and reading it as
        // `blake3(code_hash)` is only accidentally right. Read the parameters
        // from the constant the app registers with rather than writing `&[]`
        // here: a hardcoded empty slice would keep this test passing after a
        // change that re-keyed the real delegate.
        hasher.update(harvest_common::delegate::DELEGATE_PARAMETERS);
        assert_eq!(
            *hasher.finalize().as_bytes(),
            entry.delegate_key,
            "generation {}'s recorded delegate key is not the one its code hash derives",
            entry.generation
        );
    }
}

/// The bundled artifacts' code hashes are NOT in the registries.
///
/// The registries list superseded generations only; the live one is derived
/// from the WASM the build ships. A current hash appearing in one means either
/// the entry was appended and the artifact never rebuilt, or the change that
/// moved it was reverted -- and in both cases the probe would walk to its own
/// instance, find its own state, and report a successful migration having
/// moved nothing.
///
/// `scripts/check-code-hashes.sh` asserts the same thing in CI against a fresh
/// build. This asserts it against the COMMITTED artifacts, which are what
/// `include_bytes!` actually ships, so the two cover different failures: CI's
/// catches a source change without a rebuild, this catches a committed file
/// that names a generation already retired.
///
/// Mutated red by appending the live store hash to `legacy/store_contract.toml`.
#[test]
fn no_bundled_artifact_is_recorded_as_superseded() {
    /// (artifact name, the bytes `include_bytes!` ships, its superseded hashes)
    type Bundled<'a> = (&'a str, &'a [u8], Vec<[u8; 32]>);

    let bundled: &[Bundled<'_>] = &[
        (
            "store",
            include_bytes!("../../public/contracts/store_contract.wasm"),
            store_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "reputation",
            include_bytes!("../../public/contracts/reputation_contract.wasm"),
            reputation_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "mailbox",
            include_bytes!("../../public/contracts/mailbox_contract.wasm"),
            mailbox_lineage().iter().map(|e| e.code_hash).collect(),
        ),
        (
            "delegate",
            include_bytes!("../../public/contracts/harvest_delegate.wasm"),
            delegate_lineage().iter().map(|e| e.code_hash).collect(),
        ),
    ];

    for (name, wasm, superseded) in bundled {
        let hash: [u8; 32] = *blake3::hash(wasm).as_bytes();
        assert!(
            !superseded.contains(&hash),
            "the bundled {name} artifact's code hash {} is recorded as SUPERSEDED. \
             Either it was never rebuilt after the entry was added, or the change \
             that moved it was reverted.",
            hex::encode(hash)
        );
    }
}

/// The contract code hash the migration derives ids from is the one the rest
/// of the app publishes under.
///
/// `store_ops` builds a `ContractCode` and takes its hash; the migration
/// hashes the same bytes with blake3 directly. If those two ever disagreed,
/// every id the probe derives would name a contract nobody else uses -- and
/// nothing else in the repo compares them.
#[test]
fn the_migrations_code_hash_matches_the_one_contracts_are_published_under() {
    for wasm in [
        include_bytes!("../../public/contracts/store_contract.wasm").as_slice(),
        include_bytes!("../../public/contracts/reputation_contract.wasm").as_slice(),
        include_bytes!("../../public/contracts/mailbox_contract.wasm").as_slice(),
    ] {
        let via_stdlib = *ContractCode::from(wasm.to_vec()).hash();
        let via_blake3: [u8; 32] = *blake3::hash(wasm).as_bytes();
        assert_eq!(
            AsRef::<[u8]>::as_ref(&via_stdlib),
            &via_blake3[..],
            "stdlib's contract code hash and blake3 of the same bytes disagree"
        );
    }
}

/// Each generation derives a DIFFERENT instance id, and none of them collides
/// with the current one.
///
/// This is the property that makes the whole exercise necessary: the same
/// seller, the same parameters, four addresses. It also catches a registry
/// with a duplicated hash, which would otherwise waste a probe hop on an id
/// already asked for.
#[test]
fn each_generation_is_a_different_instance() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "two generations derive the same id"
    );

    let current_hash: [u8; 32] =
        *blake3::hash(include_bytes!("../../public/contracts/store_contract.wasm")).as_bytes();
    let current = current_id(&current_hash, &params);
    assert!(
        !ids.contains(&current),
        "a predecessor derives the current instance id"
    );
}

// --- the ordering constraint --------------------------------------------

/// A reputation probe cannot be assembled without the delegate's RSA public
/// key.
///
/// `ReputationParameters::rsa_public_key_der` is an input to the reputation
/// contract's address, so a probe started before the delegate answered would
/// walk ids belonging to nobody, find nothing, and could seal that verdict
/// over a recoverable instance. Making the inputs unconstructible is what
/// turns that from a rule someone has to remember into something the compiler
/// enforces.
///
/// Mutated red by having `reputation_probe_inputs` substitute an empty key
/// instead of returning `None`.
#[test]
fn a_reputation_probe_needs_the_delegates_rsa_key_first() {
    assert!(
        reputation_probe_inputs(None, &seller_vk()).is_none(),
        "a missing RSA key must block the reputation probe, not default it"
    );
    assert!(
        reputation_probe_inputs(Some(&Vec::new()), &seller_vk()).is_none(),
        "an empty RSA key is a missing one; it must not be probed with"
    );
    assert!(
        reputation_probe_inputs(Some(&vec![1u8, 2, 3]), &seller_vk()).is_some(),
        "a present key must produce probe inputs"
    );
}

/// The RSA key is genuinely part of the address, not merely carried alongside
/// it. Two different keys for the same owner name two different contracts.
///
/// This is what the ordering constraint is FOR: probing with the wrong key is
/// not a degraded search, it is a search of the wrong place.
#[test]
fn the_rsa_key_changes_the_reputation_instance_id() {
    let a = reputation_probe_inputs(Some(&vec![1u8; 64]), &seller_vk()).expect("inputs");
    let b = reputation_probe_inputs(Some(&vec![2u8; 64]), &seller_vk()).expect("inputs");
    let hash = [9u8; 32];
    let id_a = current_id(&hash, &encode_params(&a.params).expect("encode"));
    let id_b = current_id(&hash, &encode_params(&b.params).expect("encode"));
    assert_ne!(
        id_a, id_b,
        "the RSA public key must be part of the reputation contract's address"
    );
}

// --- the store's parameter-encoding split -------------------------------

/// The bytes generations V1..=5 were published under, reconstructed here
/// independently of `migrate.rs` so the two have to agree.
fn legacy_store_param_bytes(vk: &VerifyingKey) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Old {
        seller_verifying_key: VerifyingKey,
        trusted_bitcoin_bridges: Vec<[u8; 32]>,
        bitcoin_address_code_hash: Option<[u8; 32]>,
    }
    harvest_common::to_cbor(&Old {
        seller_verifying_key: *vk,
        trusted_bitcoin_bridges: Vec::new(),
        bitcoin_address_code_hash: None,
    })
    .expect("encode legacy store parameters")
}

/// The premise: the two encodings really are different, so probing an old
/// generation with today's parameters is a search of the wrong address rather
/// than a harmless re-encoding.
///
/// Without this the test below could pass vacuously.
#[test]
fn the_store_parameter_encoding_actually_changed() {
    let current = encode_params(&store_params(&seller_vk())).expect("encode");
    assert_ne!(
        current.as_ref(),
        legacy_store_param_bytes(&seller_vk()).as_slice(),
        "if these matched there would be nothing to split on and \
         `store_candidates` would be dead weight"
    );
}

/// Every already-published store generation must be probed at the address it
/// actually has.
///
/// `freenet_migrate::ContractLineageEntry` carries only a code hash, so the
/// crate derives every predecessor id from the CURRENT parameters. That is
/// right until the parameter encoding changes, and then it fails silently:
/// the probe walks addresses that never existed, every one comes back
/// `NotFound`, and the sweep reports a clean "nothing to migrate" over a
/// seller's whole store.
///
/// Mutated red by deriving the lineage with `NewestFirst::from_lineage` and
/// today's parameters -- i.e. by not making the split at all, which is what
/// the code did before `store_candidates` existed.
#[test]
fn superseded_store_generations_are_probed_under_their_own_parameter_encoding() {
    let vk = seller_vk();
    let legacy = Parameters::from(legacy_store_param_bytes(&vk));
    let current = encode_params(&store_params(&vk)).expect("encode");

    let candidates = store_candidate_ids(&vk).expect("candidates");
    assert_eq!(
        candidates.len(),
        store_lineage().len(),
        "every recorded generation must be probed"
    );

    // Newest-first, each generation derived under the encoding IT was
    // published with. Which side each generation falls on is asserted against
    // the artifacts in
    // `each_store_generation_is_derived_under_the_encoding_it_shipped_with`;
    // this test is about the ordering and completeness of the walk, so it is
    // entitled to ask the predicate.
    let mut newest_first: Vec<_> = store_lineage().iter().collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.generation));

    let mut seen_legacy = false;
    let mut seen_current = false;
    for (entry, got) in newest_first.iter().zip(&candidates) {
        let legacy_side = published_under_legacy_store_params(entry.generation);
        let (expected, wrong) = if legacy_side {
            seen_legacy = true;
            (
                current_id(&entry.code_hash, &legacy),
                current_id(&entry.code_hash, &current),
            )
        } else {
            seen_current = true;
            (
                current_id(&entry.code_hash, &current),
                current_id(&entry.code_hash, &legacy),
            )
        };
        assert_ne!(expected, wrong);
        assert_eq!(
            *got,
            expected,
            "generation {} must be probed at its real address, not at one derived \
             from the {} parameter encoding -- which it was never published under",
            entry.generation,
            if legacy_side { "current" } else { "legacy" }
        );
    }

    // Both branches have to be exercised, or this test stops being about the
    // split at all: with generations on only one side of it, deriving every
    // id under one encoding would pass.
    assert!(
        seen_legacy && seen_current,
        "the lineage must span the parameter split for this test to mean anything \
         (legacy seen: {seen_legacy}, current seen: {seen_current})"
    );
}

/// Which encoding each store generation was ACTUALLY published under, taken
/// from the artifacts rather than from the code under test.
///
/// The store's parameter encoding did not change once, it changed twice and
/// came back:
///
/// | generation | built at  | `StoreParameters` | cbor |
/// |------------|-----------|-------------------|------|
/// | V1         | `ded0e3a` | 1 field           | 56 B |
/// | V2         | `78d1020` | 3 fields          | 109 B|
/// | V3         | `ca57d8f` | 3 fields          | 109 B|
/// | V4         | `47b67aa` | 3 fields          | 109 B|
/// | V5         | `9e3e1fb` | 3 fields          | 109 B|
/// | V6         | `ea94a33` | 1 field           | 56 B |
///
/// The two Bitcoin fields were added by `7c192d2` (first shipped in the V2
/// artifact) and removed again by `fc760ed` (first shipped in the V6
/// artifact). Each "built at" commit is the one whose committed
/// `ui/public/contracts/store_contract.wasm` hashes to that generation's
/// `code_hash` in `legacy/store_contract.toml`, so the mapping is checkable
/// with `git show <commit>:ui/public/contracts/store_contract.wasm | b3sum`.
///
/// Written out per generation on purpose. Deriving the expectation from
/// `published_under_legacy_store_params` -- as the test below this one does,
/// for the ordering property it is actually about -- cannot catch the
/// boundary being wrong, because it asks the code under test what the answer
/// is. V1 sat on the wrong side of that boundary for exactly that reason.
const PUBLISHED_UNDER_LEGACY_PARAMS: &[(u32, bool)] = &[
    (1, false),
    (2, true),
    (3, true),
    (4, true),
    (5, true),
    (6, false),
];

/// V1 is derived under TODAY's parameter encoding, not the legacy one.
///
/// V1 predates the Bitcoin payments work entirely: its `StoreParameters` had
/// one field, exactly as today's does. It is also the only generation ever
/// published to the network (`git show origin/main:ui/public/contracts/\
/// store_contract.wasm | b3sum` is `4d7ad3c3...`, the registry's first row),
/// so getting it wrong means the migration probe cannot find the one store
/// that exists -- and reports a clean "nothing to migrate" while doing it.
///
/// Mutated red by restoring the single threshold this replaced
/// (`generation <= LAST_LEGACY_STORE_PARAM_GENERATION`), which buckets V1 as
/// legacy because generations are 1-based.
#[test]
fn each_store_generation_is_derived_under_the_encoding_it_shipped_with() {
    let vk = seller_vk();
    let legacy = Parameters::from(legacy_store_param_bytes(&vk));
    let current = encode_params(&store_params(&vk)).expect("encode");

    // The sizes named in `legacy/store_contract.toml` and in
    // `harvest_common::address`. If either moves, the table above is about
    // something else.
    assert_eq!(legacy.as_ref().len(), 109, "legacy StoreParameters cbor");
    assert_eq!(current.as_ref().len(), 56, "current StoreParameters cbor");

    assert_eq!(
        PUBLISHED_UNDER_LEGACY_PARAMS.len(),
        store_lineage().len(),
        "the table must cover every recorded generation, and only those"
    );

    let candidates = store_candidate_ids(&vk).expect("candidates");
    let mut newest_first: Vec<_> = store_lineage().iter().collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.generation));

    for (entry, got) in newest_first.iter().zip(&candidates) {
        let (_, legacy_side) = PUBLISHED_UNDER_LEGACY_PARAMS
            .iter()
            .find(|(g, _)| *g == entry.generation)
            .unwrap_or_else(|| panic!("generation {} is not in the table", entry.generation));

        let expected = if *legacy_side {
            current_id(&entry.code_hash, &legacy)
        } else {
            current_id(&entry.code_hash, &current)
        };
        assert_eq!(
            *got,
            expected,
            "generation {} was published under the {} parameter encoding",
            entry.generation,
            if *legacy_side { "legacy" } else { "current" }
        );

        // And the predicate the derivation actually consults has to agree
        // with the table, so a future edit to one of them cannot drift from
        // the other unnoticed.
        assert_eq!(
            published_under_legacy_store_params(entry.generation),
            *legacy_side,
            "the generation band disagrees with the artifacts for V{}",
            entry.generation
        );
    }
}

/// A contract's parameters are derived in exactly ONE place.
///
/// # Why this is a source scrape and not a behavioural test
///
/// `gateway::store_ops::create_store_contracts` is `#[cfg(target_arch =
/// "wasm32")]`. Neither `cargo test --workspace` nor `cargo clippy
/// --workspace --all-targets` compiles it, so no host test can call it and
/// compare what it derives against what the probe derives. Scraping the
/// source is what is left, and it is enough for the property that matters:
/// that there is no SECOND derivation to drift.
///
/// # Why the property is worth a test at all
///
/// A contract's address is `BLAKE3(code_hash || cbor(parameters))`. Two
/// hand-maintained copies of a parameter struct means the PUT and the
/// migration probe can disagree about a store's address, and the disagreement
/// is silent in both directions: the probe walks addresses that were never
/// written, takes `NotFound` at each, and reports a clean "nothing to
/// migrate" over a seller's entire store.
///
/// That is not hypothetical. A parameter-derivation mismatch is exactly the
/// defect this branch opened with -- `StoreParameters` gained two fields and
/// lost them again, and the probe derived V1, the only generation ever
/// published, at an address it never had. Fixing that symptom left the
/// structural cause standing: `create_store_contracts` still built all three
/// parameter structs itself.
///
/// `include_str!` rather than a runtime read, so renaming the file fails the
/// build instead of silently skipping the check.
#[test]
fn store_ops_derives_no_contract_parameters_of_its_own() {
    const STORE_OPS: &str = include_str!("../gateway/store_ops.rs");

    // Every parameter type whose encoding is hashed into a contract address.
    // A literal construction of any of them outside `migrate` is a second
    // derivation, whatever it happens to contain today.
    for ty in [
        "StoreParameters {",
        "MailboxParameters {",
        "ReputationParameters {",
    ] {
        assert!(
            !STORE_OPS.contains(ty),
            "gateway/store_ops.rs constructs `{ty}` itself. Contract parameters are \
             derived in `migrate::{{store,mailbox,reputation}}_params` and nowhere else -- \
             call those instead. A second copy drifts silently and re-keys every \
             contract it addresses."
        );
    }

    // And the shared derivations are what it should be calling.
    for f in [
        "migrate::store_params",
        "migrate::mailbox_params",
        "migrate::reputation_params",
    ] {
        assert!(
            STORE_OPS.contains(f),
            "gateway/store_ops.rs should derive its parameters through `{f}`"
        );
    }
}

// --- sealing ------------------------------------------------------------

/// Only a complete recovery may seal.
///
/// Mutated red five ways: `Recovered`-with-truncation, `Recovered`-with-
/// unresolved, `SeedLocal`, `Indeterminate` and `NoLegacy` each turned into a
/// `Seal` in `seal_decision` and each caught here.
///
/// The wildcard arm is NOT among them, and cannot be: `Outcome` is
/// `#[non_exhaustive]`, so today every variant is named and the wildcard is
/// unreachable. Inverting it to `Seal::Seal` leaves this test green -- which
/// is exactly the defence-in-depth guard that nothing exercises, so
/// `the_wildcard_outcome_arm_retries` pins it by reading the source instead.
#[test]
fn only_a_complete_recovery_seals() {
    let src = ContractInstanceId::new([1u8; 32]);
    let other = ContractInstanceId::new([2u8; 32]);
    let local = StoreStateV1::default();

    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: false,
            unresolved: Vec::new(),
        }),
        Seal::Seal
    );

    // A fold cut short by the hop cap is missing the oldest generations.
    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: true,
            unresolved: Vec::new(),
        }),
        Seal::Retry
    );

    // A generation that never answered may hold anything.
    assert_eq!(
        seal_decision(&Outcome::Recovered {
            merged: local.clone(),
            source: src,
            truncated_fold: false,
            unresolved: vec![other],
        }),
        Seal::Retry
    );

    assert_eq!(
        seal_decision(&Outcome::SeedLocal {
            local: local.clone()
        }),
        Seal::Retry,
        "an all-absent walk must never seal: absence on Freenet is unauthenticated"
    );

    assert_eq!(
        seal_decision(&Outcome::Indeterminate {
            local: local.clone(),
            unresolved: vec![other],
        }),
        Seal::Retry
    );

    assert_eq!(seal_decision(&Outcome::NoLegacy { local }), Seal::Retry);
}

// --- the probe, end to end ----------------------------------------------

/// A populated newest generation is recovered, and that recovery seals.
///
/// The candidate answered from is the NEWEST, which is what the newest-first
/// ordering is for.
#[test]
fn a_populated_predecessor_is_recovered_and_seals() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("a lineage with rows");
    let populated = store_with(&[signed_listing(1, "Coffee")]);
    let bytes = store_bytes(&populated);

    let (outcome, seal) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(bytes.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, source, .. } => {
            assert_eq!(source, newest, "recovered from the wrong generation");
            assert_eq!(merged.listings.listings.len(), 1);
            assert_eq!(merged.listings.listings[0].listing.title, "Coffee");
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
    assert_eq!(seal, Seal::Seal);
}

/// Fold-all reaches past the newest populated generation.
///
/// Harvest re-keyed four times, so a seller's listings can be spread across
/// several instances, none of which was ever carried forward.
/// `NewestFirstWins` would stop at the first hit and leave the rest behind --
/// which is why the policy is `FoldAll` and why the ack is earned in
/// `fold_all_preconditions_hold` below.
///
/// Mutated red by switching `fold_all_policy` to `NewestFirstWins`: the
/// recovered store then holds one listing instead of two.
#[test]
fn fold_all_recovers_listings_spread_across_generations() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    assert!(ids.len() >= 2, "this test needs at least two generations");
    let newest = ids[ids.len() - 1];
    let older = ids[0];

    let from_newest = store_bytes(&store_with(&[signed_listing(2, "Beans")]));
    let from_older = store_bytes(&store_with(&[signed_listing(1, "Coffee")]));

    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(from_newest.clone())
        } else if id == older {
            Answer::State(from_older.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, .. } => {
            let titles: HashSet<&str> = merged
                .listings
                .listings
                .iter()
                .map(|l| l.listing.title.as_str())
                .collect();
            assert_eq!(
                titles,
                HashSet::from(["Coffee", "Beans"]),
                "fold-all must reach past the newest populated generation"
            );
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
}

/// A recovery seeded from a local snapshot keeps the local state too.
///
/// The probe is seeded from the client's own snapshot precisely so a recovery
/// can never drop local-only writes.
#[test]
fn a_recovery_never_drops_the_local_snapshot() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let recovered = store_bytes(&store_with(&[signed_listing(1, "Coffee")]));
    let local = store_with(&[signed_listing(9, "Local only")]);

    let (outcome, _) = run(store_session(local), |id| {
        if id == newest {
            Answer::State(recovered.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { merged, .. } => {
            let titles: HashSet<&str> = merged
                .listings
                .listings
                .iter()
                .map(|l| l.listing.title.as_str())
                .collect();
            assert!(
                titles.contains("Local only"),
                "the local snapshot was dropped by the merge"
            );
            assert!(titles.contains("Coffee"));
        }
        other => panic!("expected a recovery, got {}", describe(&other)),
    }
}

/// Every candidate answering `NotFound` produces `SeedLocal`, and `SeedLocal`
/// does not seal.
///
/// This is the single most important assertion in the file. An all-absent walk
/// is the case that LOOKS conclusive -- everyone was asked, nobody had
/// anything -- and sealing it is what marks a live predecessor permanently
/// empty. Absence on Freenet is unauthenticated, and a contract that exists
/// answers `NotFound` while it is momentarily unfindable.
///
/// Mutated red by making `seal_decision` seal on `SeedLocal`.
#[test]
fn an_all_absent_walk_does_not_seal() {
    let (outcome, seal) = run(store_session(StoreStateV1::default()), |_| Answer::Absent);
    assert!(
        matches!(outcome, Outcome::SeedLocal { .. }),
        "expected SeedLocal, got {}",
        describe(&outcome)
    );
    assert_eq!(
        seal,
        Seal::Retry,
        "an all-absent walk must be retried, never sealed"
    );
}

/// One candidate that never answers keeps the walk open, even when another
/// generation was recovered.
///
/// Under fold-all the probe continues past silence and reports the
/// unanswered candidates, so the recovery is real but partial -- the silent
/// generation may hold listings this fold is missing.
///
/// Mutated red by dropping the `unresolved.is_empty()` condition from
/// `seal_decision`.
#[test]
fn silence_anywhere_keeps_the_migration_open() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let silent = ids[0];
    let bytes = store_bytes(&store_with(&[signed_listing(1, "Coffee")]));

    let (outcome, seal) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(bytes.clone())
        } else if id == silent {
            Answer::Silence
        } else {
            Answer::Absent
        }
    });

    match &outcome {
        Outcome::Recovered { unresolved, .. } => {
            assert!(
                unresolved.contains(&silent),
                "the silent candidate must be reported as unresolved"
            );
        }
        other => panic!("expected a partial recovery, got {}", describe(other)),
    }
    assert_eq!(seal, Seal::Retry, "a partial recovery must not seal");
    assert!(
        describe(&outcome).contains("not the whole story"),
        "the description must say the result is incomplete: {}",
        describe(&outcome)
    );
}

/// A walk where nothing answers at all is indeterminate, and indeterminate
/// never seals.
#[test]
fn total_silence_is_indeterminate_and_never_seals() {
    let (outcome, seal) = run(store_session(StoreStateV1::default()), |_| Answer::Silence);
    match &outcome {
        Outcome::Indeterminate { unresolved, .. } => {
            assert_eq!(unresolved.len(), store_lineage().len());
        }
        other => panic!("expected Indeterminate, got {}", describe(other)),
    }
    assert_eq!(seal, Seal::Retry);
}

/// An empty predecessor is a miss, not a hit.
///
/// A store PUT at creation time holds `StoreStateV1::default()`. Adopting one
/// would report a successful migration having recovered nothing -- and under a
/// stop-at-first-hit policy would prevent an older, populated generation from
/// ever being reached.
///
/// Mutated red by making `StoreOps::is_real` return `true` unconditionally.
#[test]
fn an_empty_predecessor_is_a_miss() {
    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let empty = store_bytes(&StoreStateV1::default());
    let populated = store_bytes(&store_with(&[signed_listing(1, "Coffee")]));

    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(empty.clone())
        } else if id == ids[0] {
            Answer::State(populated.clone())
        } else {
            Answer::Absent
        }
    });

    match outcome {
        Outcome::Recovered { source, merged, .. } => {
            assert_eq!(source, ids[0], "the empty generation was adopted as a hit");
            assert_eq!(merged.listings.listings.len(), 1);
        }
        other => panic!(
            "expected the older generation to be recovered, got {}",
            describe(&other)
        ),
    }
}

/// Undecodable bytes are a miss, and never a panic.
///
/// A predecessor whose state cannot be parsed is skipped defensively; the walk
/// continues to older generations rather than aborting.
#[test]
fn undecodable_state_is_a_miss_not_a_crash() {
    let ops = store_ops();
    assert!(ops.decode(b"not cbor at all").is_none());
    assert!(ops
        .decode(&harvest_common::to_cbor(&"a string").expect("cbor"))
        .is_none());

    let params = store_params_encoded();
    let ids = predecessor_ids(&params, store_lineage());
    let newest = *ids.last().expect("rows");
    let populated = store_bytes(&store_with(&[signed_listing(1, "Coffee")]));
    let (outcome, _) = run(store_session(StoreStateV1::default()), |id| {
        if id == newest {
            Answer::State(b"garbage".to_vec())
        } else if id == ids[0] {
            Answer::State(populated.clone())
        } else {
            Answer::Absent
        }
    });
    assert!(matches!(outcome, Outcome::Recovered { .. }));
}

// --- fold-all preconditions ---------------------------------------------

/// The properties `FoldAllAck` asks a caller to establish BEFORE opting in,
/// asserted on real states rather than argued in prose. That is the whole
/// point of the ack being a token.
#[test]
fn fold_all_preconditions_hold_for_the_store_state() {
    let ops = store_ops();
    let samples = vec![
        store_with(&[signed_listing(10, "Alpha")]),
        store_with(&[signed_listing(11, "Beta")]),
        store_with(&[signed_listing(10, "Alpha"), signed_listing(12, "Gamma")]),
    ];
    let merge = |x: StoreStateV1, y: StoreStateV1| ops.merge_generations(x, y);
    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_merge_idempotent(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
}

/// Same, for the mailbox -- the one Harvest state with a real pruning rule.
///
/// Folding an older generation can re-admit a message the successor pruned.
/// That is sound only because the prune is deterministic and re-run on every
/// merge, so the fold result is pruned again identically. If it were not, the
/// order-invariance assertion here would fail.
#[test]
fn fold_all_preconditions_hold_for_the_mailbox_state() {
    let ops = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    let base = 1_700_000_000;
    let samples = vec![
        mailbox_with(vec![message(1, base)]),
        mailbox_with(vec![message(2, base + 10)]),
        mailbox_with(vec![message(1, base), message(3, base + 20)]),
    ];
    let merge = |x: MailboxStateV1, y: MailboxStateV1| ops.merge_generations(x, y);
    freenet_migrate::driver::policy_check::assert_merge_commutative(&samples, merge);
    freenet_migrate::driver::policy_check::assert_merge_idempotent(&samples, merge);
    freenet_migrate::driver::policy_check::assert_fold_order_invariant(&samples, merge);
}

/// An empty mailbox or reputation state is a miss.
#[test]
fn empty_states_are_not_real() {
    let mailbox = MailboxOps {
        params: mailbox_params(&seller_vk()),
    };
    assert!(!mailbox.is_real(&MailboxStateV1::default()));
    assert!(mailbox.is_real(&mailbox_with(vec![message(1, 1_700_000_000)])));

    let reputation = ReputationOps {
        params: reputation_params(vec![1u8; 32], &seller_vk()),
    };
    assert!(!reputation.is_real(&ReputationStateV1::default()));
    let mut with_feedback = ReputationStateV1::default();
    with_feedback.feedback.push(dummy_feedback());
    assert!(reputation.is_real(&with_feedback));
}

/// A feedback entry that exists but does not verify. Used only where the
/// signature is not the property under test.
fn dummy_feedback() -> FeedbackEntry {
    FeedbackEntry {
        token: harvest_common::feedback::FeedbackToken {
            target_reputation_contract: [5u8; 32],
            nonce: [4u8; 32],
        },
        signature: vec![0u8; 8],
        category: harvest_common::feedback::FeedbackCategory::NonDelivery,
        comment: String::new(),
        submitted_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
    }
}

/// A merge that cannot be applied keeps the primary rather than losing it.
///
/// `ReputationStateV1::apply_delta` rejects the whole delta if any entry's
/// RSA signature does not verify. The documented `ProbeStateOps` behaviour is
/// keep-primary, and getting that backwards would let one bad entry from an
/// old generation erase a good newer one.
#[test]
fn an_unverifiable_merge_keeps_the_primary() {
    let params = reputation_params(vec![1u8; 32], &seller_vk());
    let ops = ReputationOps {
        params: params.clone(),
    };
    let primary = ReputationStateV1 {
        owner_certificate_pem: "PRIMARY".to_string(),
        ..Default::default()
    };

    let mut bad = ReputationStateV1::default();
    bad.feedback.push(dummy_feedback());
    bad.used_nonces.insert([4u8; 32]);

    let merged = ops.merge_generations(primary.clone(), bad);
    assert_eq!(
        merged, primary,
        "an unverifiable delta must leave the primary untouched"
    );
}

// --- markers ------------------------------------------------------------

/// Marker keys are hex, and two distinct instances never share one.
///
/// Raw bytes in a storage key alias: anything that runs a key through a lossy
/// UTF-8 conversion maps every invalid byte to U+FFFD, so two distinct 32-byte
/// ids collapse onto one slot and one of them is sealed having never been
/// migrated. River hit exactly that.
///
/// Mutated red by encoding the ids with `String::from_utf8_lossy` instead of
/// hex: the two ids below then produce the same key.
#[test]
fn marker_keys_are_hex_and_do_not_alias() {
    // Two ids that differ only in bytes that are invalid UTF-8, so a lossy
    // conversion maps both to the same replacement character.
    let a = ContractInstanceId::new([0xF8u8; 32]);
    let b = ContractInstanceId::new([0xF9u8; 32]);
    let hash = [1u8; 32];

    let key_a = marker_key(Artifact::Store, &a, &hash);
    let key_b = marker_key(Artifact::Store, &b, &hash);
    assert_ne!(key_a, key_b, "two distinct instances share a marker slot");
    assert!(
        key_a.is_ascii(),
        "a marker key must be plain ASCII: {key_a}"
    );
    assert!(key_a.contains(&hex::encode(a.as_bytes())));
}

/// The marker is keyed by the CURRENT code hash, so the next re-key starts a
/// fresh walk rather than inheriting a "done" from the generation before.
///
/// Mutated red by dropping the code hash from `marker_key`.
#[test]
fn a_new_generation_gets_a_new_marker() {
    let id = ContractInstanceId::new([3u8; 32]);
    assert_ne!(
        marker_key(Artifact::Store, &id, &[1u8; 32]),
        marker_key(Artifact::Store, &id, &[2u8; 32]),
        "a re-key must not inherit the previous generation's completion marker"
    );
}

/// **The fail-safe direction, which is the whole reason the marker moved.**
///
/// The gate used to be a `localStorage` read. In the deployed gateway
/// `localStorage` throws -- Freenet's webapp iframe has no
/// `allow-same-origin`, so the frame's origin is opaque -- and the only reason
/// that was a performance bug rather than a data-loss one is that an
/// unreadable marker reads as "not migrated". The marker now lives in the
/// delegate, where the ways to get no usable answer are different (not
/// registered, send failed, no reply) and the direction has to be the same.
///
/// Mutated red by having `probe_gate` skip on `Unavailable`.
#[test]
fn an_unavailable_marker_runs_the_probe() {
    assert_eq!(probe_gate(MarkerLookup::Unavailable), Gate::Run);
}

/// Only a definite `Present` skips.
///
/// Mutated red by having `probe_gate` skip on `Absent`, which is the shape
/// that would suppress every first-run migration.
#[test]
fn only_a_recorded_marker_skips_the_probe() {
    assert_eq!(probe_gate(MarkerLookup::Present), Gate::Skip);
    assert_eq!(probe_gate(MarkerLookup::Absent), Gate::Run);
}

/// A marker id is something the harvest delegate will store.
///
/// The delegate refuses an empty or non-ASCII marker id (`markers::
/// is_valid_marker`), because a key that survives a lossy UTF-8 conversion is
/// a key that cannot alias with another. A minting side that produced one of
/// those would have every write silently refused and every walk repeat
/// forever, with nothing but a log line to say so.
///
/// Mutated red by having `marker_key` emit the raw id bytes rather than hex.
#[test]
fn a_marker_id_is_one_the_delegate_will_store() {
    let key = marker_key(
        Artifact::Mailbox,
        &ContractInstanceId::new([0xF8u8; 32]),
        &[0xF9u8; 32],
    );
    assert!(!key.is_empty());
    assert!(key.is_ascii(), "the delegate refuses a non-ASCII marker id");
}

/// The two delegate requests carry the marker id unchanged.
///
/// They are built in `migrate` rather than at the wasm-only call site so this
/// is assertable at all; a query that named a different marker than the write
/// would seal one slot and read another forever.
#[test]
fn the_delegate_requests_name_the_same_marker() {
    use harvest_common::HarvestDelegateRequest;

    let id = marker_key(
        Artifact::Store,
        &ContractInstanceId::new([3u8; 32]),
        &[1u8; 32],
    );

    match (marker_query(&id), marker_write(&id, "note")) {
        (
            HarvestDelegateRequest::GetMigrationMarker { marker: queried },
            HarvestDelegateRequest::SetMigrationMarker {
                marker: written,
                note,
            },
        ) => {
            assert_eq!(queried, id);
            assert_eq!(written, id);
            assert_eq!(note, "note");
        }
        (q, w) => panic!("wrong request variants: {q:?} / {w:?}"),
    }
}

/// Two artifacts never share a marker.
#[test]
fn artifacts_have_separate_markers() {
    let id = ContractInstanceId::new([3u8; 32]);
    let hash = [1u8; 32];
    let keys: HashSet<String> = [Artifact::Store, Artifact::Reputation, Artifact::Mailbox]
        .into_iter()
        .map(|a| marker_key(a, &id, &hash))
        .collect();
    assert_eq!(keys.len(), 3);
}

/// The wildcard arm of `seal_decision` retries.
///
/// A source scrape, which is an unusual thing to assert and is the right tool
/// here. `Outcome` is `#[non_exhaustive]`: every variant that exists today is
/// named explicitly, so the wildcard is unreachable and no behavioural test
/// can reach it. It exists for the variant a future `freenet-migrate` release
/// adds -- and if that arm said `Seal`, that variant would silently write a
/// permanent "this predecessor had nothing" marker the first time it occurred,
/// for a case this code has never seen.
///
/// The crate's own docs make the same point about `#[non_exhaustive]`: it
/// "protects exhaustive matches only", so it forces the arm to exist without
/// saying anything about what it does. This says what it must do.
///
/// Anchored on the `Seal::` values rather than on surrounding prose so
/// reformatting or re-commenting the function does not break it.
///
/// Mutated red by changing the arm to `_ => Seal::Seal`.
#[test]
fn the_wildcard_outcome_arm_retries() {
    let source = include_str!("../migrate.rs");
    let body = source
        .split("pub fn seal_decision")
        .nth(1)
        .expect("seal_decision must exist");
    let body = body.split("\n}\n").next().expect("a function body");

    assert!(
        body.contains("_ => Seal::Retry"),
        "seal_decision has no wildcard arm returning Retry; a future Outcome \
         variant would fall through to whatever is there instead"
    );
    assert!(
        !body.contains("_ => Seal::Seal"),
        "seal_decision's wildcard arm SEALS. A variant added by a future \
         freenet-migrate release would write a permanent marker for a case \
         this code has never seen."
    );
}
