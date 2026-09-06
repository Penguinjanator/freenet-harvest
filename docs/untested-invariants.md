# Untested invariants

Safety and correctness properties that the code asserts in a comment, are
**true as of the commit below**, and that **no test would catch becoming
false**.

Compiled 2026-09-05, against `feat/bitcoin-payments`, after a review that found
eleven comments asserting protections that either did not exist or described a
mechanism that had moved. In every one of those cases the comment read as
authoritative. This file exists because the reviewed fix for that is not more
comments.

Scope: `common/src/{store,payment,mailbox,reputation,listing,address}.rs`,
`contracts/*/src/lib.rs`, `ui/src/migrate.rs`, `ui/src/state.rs`. It did not
originally cover `delegates/` or `ui/src/gateway/`, which were held by other
people during the review and are collected separately -- but the messaging
section below does, because that change touched both and there is no reason to
leave a fresh gap for a later review to find.

A note on what CI does and does not compile, because it was got wrong twice
during this review in the pessimistic direction. `ui/src/gateway/` **is**
type-checked and linted on every PR, by the `clippy the UI for wasm32` step;
it is never EXECUTED, which is the real gap. `tests/rehearsal/` was reached by
nothing at all until 2026-09-05 and is now compile-checked; it still cannot be
run without a live node.

**This list is not a to-do list.** Most entries are cheap to leave uncovered.
The four that are not are named at the end, and that section is the point of
the document.

## How to read an entry

* **Claim** — what the comment asserts, not what the code does.
* **Caught?** — would any existing test fail if the claim stopped holding?
  "No" means the guard can be deleted, or the property broken, with
  `cargo test --workspace` still green.

Entries are recorded per claim, not per line: several claims below rest on one
guard, and that is noted where it happens.

## A test can be red-verified and still not observe its own claim

The failure this document exists for has a second form, found on 2026-09-05
and worth naming because it defeats the usual check. A test can be honestly
written, honestly red at the time, and still be unable to see the thing it
describes -- because the FIXTURE makes the mutation cancel itself out.

`re_storing_a_held_conversation_evicts_nothing` re-stored the OLDEST held
conversation. The oldest is also the eviction victim, so with the guard
deleted the eviction removed exactly the record about to be re-written: the
count was unchanged, the record was present, the test passed. Its own doc
comment described the failure it could not observe.

**So "I watched it fail" is necessary and not sufficient.** The additional
question is whether the fixture puts the guard's subject and the mutation's
effect in the same place. Ask it whenever a test fills a bounded structure and
then acts on a member of it: the member you choose decides whether the test
can see anything. Choose the one the code path is actually about -- here, the
thread the buyer is writing into, which is the newest.

---

## A doc comment outlives the design it described

`entry_digest`'s doc comment said, in the same commit that made the digest the
contract's identity, that identity is the writer's NONCE and that a colliding
substitute displaces the original -- the exact inverse of the security
property the commit established. Nothing was wrong when it was written. The
digest existed first as a client-side convenience for recognising your own
messages, and that paragraph described the world it lived in truthfully. When
the digest was PROMOTED to the contract's definition of identity, the code
moved and the comment did not, because the promotion touched `verify`,
`summarize`, `delta` and the dedup -- and not the function whose meaning had
changed underneath them all.

**The general shape: a symbol whose ROLE changes without its BODY changing is
the one whose documentation goes stale silently.** A rename or a signature
change drags the comment into the diff and a reviewer reads it. A promotion
does not: `entry_digest`'s body is byte-for-byte what it was, so the diff
offered nothing to read. Every reviewer looked at the call sites, which is
where the change was.

It is also the worst possible direction of staleness. A comment that merely
lags is a nuisance; this one asserted the *negation* of a property the code
now guarantees, in the doc comment of the function that guarantees it, which
is the first thing anyone touching identity would read. A later change could
have been justified by it in good faith.

The check that would have caught it costs one question, asked at the moment a
helper is promoted rather than at review: **"which comments described this
thing in its old role?"** Grep for the symbol before promoting it, not after.

---

## Attribution: the same error, got right and got wrong in one commit

The convergence comments in `common/src/mailbox.rs` are careful about
attribution -- they name both mechanisms, say that either alone suffices, and
say what fails when both go. In the same commit, the register row for the
AES-GCM nonce limitation credited the invariant to a test whose body referenced
no Harvest symbol at all, while the three tests that actually pin nonce
freshness went uncredited. One commit, the correct form in one place and the
error in the other.

**The difference was not care, it was the forcing function.** The convergence
claim came out of a mutation matrix: deleting each mechanism in turn produced
a table, and a table with two rows reading "passes" makes it impossible to
write "this one carries it" without noticing you cannot support that. The
register row had no such table. It was written from the belief that a test with
a matching name must be pinning the thing the row describes -- and the name
matched because the row and the test were written in the same sitting, for each
other.

**So the practice worth generalising is not "attribute carefully".** It is:
*run the mutation before writing the attribution, and let the result name the
mechanism.* Where that is too expensive, write the weaker claim the evidence
supports. Both rows now name the mutation that produced them.

---

## Three doc comments have attached to the wrong item, all by a missing blank line

`decode_probed_state`, `enforce_message_cap`, and
`known_limit_the_counterparty_can_write_in_either_direction`. In each case a
new doc block was inserted directly above an existing one with no blank line
between them; Rust merges consecutive `///` lines into a single doc comment, so
the compiler is content, `rustfmt` is content, and the combined block silently
documents whichever item comes last. The item that lost its documentation is
left bare.

Three instances on one branch is a mechanism, not bad luck, and the last one
cost the most: it stripped the doc from a test whose entire value is telling a
future reader that a red result means **inverting the assertion, not repairing
the code**. A bare `known_limit_*` test is one somebody fixes.

**Is there a cheap check? Yes, for the consequence rather than the cause.** The
cause is undetectable: a merged doc block is syntactically identical to a long
one, and no lint can know where you meant the boundary. `clippy` catches only
the neighbouring shape -- `empty_line_after_doc_comment`, which is what caught
the `enforce_message_cap` instance -- and that fires on a blank line where
there should be none, the opposite defect.

The consequence is detectable and is the same in all three cases: **an item
silently loses its documentation.** A source scrape asserting that every
`#[test] fn` (and every `pub fn`) is immediately preceded by a `///` line, or
by attributes that are themselves preceded by one, catches every instance of
this class, because the absorbed doc always leaves its owner bare. It is the
same shape as `no_production_code_compares_message_nonces_for_identity` and
would reuse its file walker. Filed, not built.

---

## A citation is a claim, and this file makes hundreds of them

Four rows in the tables below cited tests by names that did not exist:
`a_backup_is_filed_under_the_store_that_was_asked_about` (renamed when export
became per-conversation), `an_import_asks_for_the_restored_conversations`
(plural, the test is singular), `known_limit_a_nonce_collision_reuses_the_\
keystream` (asserted as a pin for a day before anyone wrote it), and the
handler `on_conversations_exported` (also singular). All four are fixed above;
the keystream one was fixed by writing the test, because the claim was worth
pinning and the pin was short.

The third is the one to learn from. That row was read as evidence in the
nonce-reuse analysis that led to the entry-digest change -- an argument
resting, in part, on a test nobody had written. **A "Yes -- `test_name`" in
this file is a load-bearing claim, and an unresolvable name is a claim that
was never checked.**

**A cheap way to make a dead citation fail the build, not yet built.** A
single `#[test]` in `harvest-common` that reads this file, extracts every
snake_case identifier appearing in a "Yes"/"Pinned" cell, greps the workspace
`.rs` sources for `fn <name>`, and asserts every one resolves. It is the same
shape as `no_production_code_compares_message_nonces_for_identity`, which
already reads sources from `CARGO_MANIFEST_DIR`, so the machinery exists. Two
details decide whether it is worth having: it must skip cells marked **No** or
**Partly** (which legitimately name things that do not exist), and it must
tolerate non-test identifiers like `skip_serializing_if` and `conversation_id`
-- most cheaply by requiring an explicit opt-out marker rather than by
guessing. Filed here rather than built, because the decision to spend a test
on documentation-integrity is the lead's.

## `common/src/store.rs`

| Line | Claim | Caught? |
|---|---|---|
| 470 | `OrdersV1::verify` rejects a state holding more than `MAX_ORDERS` entries. | **No.** `enforce_order_cap` is well tested, but nothing tests the `verify` guard. Delete it and the suite stays green. Contrast `common/src/mailbox.rs`, whose identical guard *is* tested by `an_over_cap_state_is_rejected`. |
| 476 | A record filed under a key that is not its own `order.id` is rejected. | **No.** No test constructs a mis-keyed state. `merge_order` always keys by `incoming.order.id`, so this is unreachable from any honest path and reachable only from a hand-built state — which is exactly what a hostile peer submits. |
| 439 | The summary is "capped at `MAX_ORDERS` entries", and so is bounded. | **No.** True only because line 470 rejects over-cap states. Inherits that gap; not independently covered. |
| 272 | The `to_cbor` here is "Infallible … cannot fail", justifying an `expect` inside contract code. | **No**, and not straightforwardly testable — it is a claim about the shape of the type, and a breach is a panic inside the contract rather than a wrong answer. |
| 388 | `enforce_order_cap`'s ranking is "a pure function of the *content* of `orders`, not of the sequence in which entries were inserted". | **Yes** — `pruning_is_order_independent`. Listed because three neighbouring claims cite it. |

`ListingsV1` has no cap and no `verify` guard of either kind, and claims none.
Orders are capped at 4096 and mailbox messages at 512, both with a `verify`
guard; listings are bounded only by the seller's own signature being required
on each one. That asymmetry is deliberate as far as the code shows, but it is
stated nowhere, so a reader who generalises from `MAX_ORDERS` will be wrong.

## `common/src/payment.rs`

| Line | Claim | Caught? |
|---|---|---|
| 526 | `verify_payment_proof` "must be a pure function of its arguments: no clock, no network, no ambient state". | **No.** True today. Nothing enforces it, and nothing would fail if a clock were added — the divergence it prevents only appears between peers. A source-scrape pin test is the only practical form. |
| 628 | — | Not a claim: `verify_on_chain_proof` carries **no doc comment at all**, while every claim about it lives in its callers' and its types' comments. The only undocumented private item in `common/`. |
| 306 | The claim-set completeness gap "cannot be fixed inside this function", in the merge, or via the related contract. | **Partly.** `a_withheld_retraction_is_not_currently_detected` and `a_withheld_reconfirmation_still_reads_as_a_reversal` pin the two *symptoms* as known gaps. Nothing pins the argument that they cannot be closed locally. |

## `common/src/mailbox.rs`

| Line | Claim | Caught? |
|---|---|---|
| 121 | `enforce_message_cap`'s ranking "has to be *total* and a pure function of message content", so two replicas holding the same messages keep the same subset. | **Yes** — `merging_is_order_independent`, `merging_is_batch_independent`. |
| 194 | `verify` must "be a pure function of its inputs or two peers evaluating identical bytes at different moments disagree and never converge". | **Partly.** `an_old_message_does_not_invalidate_the_whole_mailbox` and `age_alone_never_drops_a_message` cover the time-dependence that actually broke this once. Purity in general is not enforced. |
| 8 | The count cap "is the mailbox's only retention rule". | **Yes** — `age_alone_never_drops_a_message`, `a_mailbox_under_the_cap_keeps_everything`. |

This file is the best-covered in the review scope: 14 tests, including one
(`known_gap_a_funded_flood_still_evicts_every_honest_message`) that pins a
residual so closing it fails loudly. It is the model the other entries are
measured against.

## `common/src/reputation.rs`

| Line | Claim | Caught? |
|---|---|---|
| 34 | Feedback is "naturally commutative: adding feedback entries in any order produces the same final set". | **No.** Atomicity and intra-delta dedup are tested; ordering is not. Nothing applies two deltas in both orders and compares. |
| 40 | The feedback list is "append-only" — no removal path. | **No.** No test asserts absence of a removal path. Load-bearing for `ui/src/migrate.rs:620`, which selects `FoldAll` on the strength of it. |

## `common/src/listing.rs`

| Line | Claim | Caught? |
|---|---|---|
| 394 | A signature produced for "some other webapp must NOT verify, even though the signature itself is genuine". | **Yes** — `test_authorized_listing_wrong_requestor_fails`, `test_authorized_listing_delegate_requestor_fails`, `test_authorized_store_info_wrong_requestor_fails`. |

Nine tests, and the claims that matter are pinned. No gaps found.

## `common/src/address.rs`

| Line | Claim | Caught? |
|---|---|---|
| 116 | "The whole guard rests on this: the same source must encode to the same bytes." | **Yes** — `placeholders_are_deterministic`. |
| 156 | "Distinct structs must not collide, or a field moved from one to another would not register as a change." | **Yes** — `placeholders_differ_between_structs`. |
| 168 | `placeholder_verifying_key` is a real curve point, so the encoding is representative. | **Yes** — `placeholder_verifying_key_is_canonical`. |

This module is the parameter-drift guard that the V1/V2 encoding change should
have tripped. Its own claims are covered.

## `contracts/store-contract/src/lib.rs`

| Line | Claim | Caught? |
|---|---|---|
| 100 | The related-contract cross-check "is ADDITIVE ONLY … can NEVER make otherwise-valid state invalid, and every branch below is written so that no path through this section returns `Invalid`". | **Partly, and the untested half is the dangerous one.** `validates_once_related_state_resolves_even_if_it_came_back_empty` covers related state coming back *empty*. Nothing covers related state coming back **populated and contradicting** the embedded proof — the case where an implementation would most naturally return `Invalid`. |
| 118 | Divergence "is precisely what a Freenet contract must never produce". | **No.** This is the *reason* for line 100 and is not separately testable within one process; it needs two peers with different related-state views. |
| 150 | "Only an id that has NEVER been requested belongs in this call's (one and only) `RequestRelated`" — asking twice is disallowed. | **Yes** — `skips_related_request_when_code_hash_absent`, `requests_related_contract_for_a_paid_order_when_code_hash_known`, and the empty-resolve test above. |

## `contracts/mailbox-contract/src/lib.rs`, `contracts/reputation-contract/src/lib.rs`

| Line | Claim | Caught? |
|---|---|---|
| — | Neither file asserts a safety property in a comment. | **No tests at all.** 141 and 143 lines respectively, zero `#[test]`. The entry points marshal state in and out of `harvest-common`, which is itself well covered, so the untested surface is the marshalling — decode failure handling, delta application, and the `InvalidUpdate` paths. |

## `ui/src/migrate.rs`

| Line | Claim | Caught? |
|---|---|---|
| 190 | `store_params` is the one place a store's parameters are derived. | **Not a test — the compiler.** The parameter structs' fields are `pub(crate)`, so outside `harvest-common` the only way to build one is its `new`, and a second derivation does not compile whatever it is spelled. `contract_parameter_fields_stay_crate_private` guards the one step that would silently give that up (a field made `pub` again); it is a substring match and says so. |
| 615 | Listings are "grow-only … the contract has no removal path at all, so absence is never a deletion" — the soundness precondition for `FoldAll`. | **No.** True (verified by inspection: `ListingsV1::apply_delta` only pushes). Nothing asserts it, and `common/src/store.rs:152` asserted the opposite until 2026-09-05. |
| 620 | Reputation is "a grow-only set keyed by nonce with no removal path whatsoever" — same precondition. | **No.** Same shape as above. |
| 300 | Candidates are ordered "by the registry's declared generation, never by slice order". | **Yes** — `superseded_store_generations_are_probed_under_their_own_parameter_encoding`. |
| 231 | The legacy parameter band is `V2..=V5`, a middle band a threshold cannot express. | **Yes** — `each_store_generation_is_derived_under_the_encoding_it_shipped_with`, which takes its expectation from the artifacts rather than from the predicate under test. |

## `ui/src/state.rs`

Outside the list this review was asked for; included because it was covered and
belongs in the durable record.

| Line | Claim | Caught? |
|---|---|---|
| 1249 | `withdraw_pending_signature` matches on signed bytes, "so this cannot withdraw a different request that happens to sit at the same position". | **No.** The function is host-compilable, but both call sites are `#[cfg(target_arch = "wasm32")]` and no test calls it. The sibling claim about matching an *answer* is tested (`an_answer_goes_to_the_request_whose_bytes_it_carries`); withdrawal is not. |
| 834 | The migration map is kept flat, so "resolving is a single lookup and can never chase a cycle". | **Partly.** The single-hop case is tested. Chained hops (A→B then B→C) and the degenerate case (B→A) are not. |
| 881 | "never lose a locally-known registration" — the delegate's answer only adds. | **Yes** — `a_store_list_answer_never_drops_a_store_it_does_not_name`, `a_store_list_answer_keeps_a_locally_known_contract_key`. |

## Buyer-to-seller messaging (added on `feat/messaging`, 2026-09-05)

Recorded at the time the code was written rather than by a later review, which
is the only way this file stays a record rather than an archaeology exercise.

| Where | Claim | Caught? |
|---|---|---|
| `ui/src/gateway/mailbox_ops.rs::send_message` | A client GET primes the local node's store, so issuing one before the update gives the node the contract it is about to run. | **No, and it cannot be here.** Nothing in this repository can reach a node. The doc comment says so in those words rather than asserting the send works; the whole path is unexercised against a live node. |
| same | The GET-then-update race is tolerable. | **No.** Both calls resolve on WebSocket send, so the ordering at the node is not observable from here. The call site now records what is known, what is not, what the failure looks like when the race is lost (message stays permanently in `unconfirmed_sent`, seller never receives it, buyer is not told), and why a sleep or retry must not be added. Characterising it needs `tests/rehearsal/` and a node. |
| `ui/src/components/message_view.rs::send` | The buyer's subscription to the seller's mailbox actually delivers replies. | **No.** The subscribe is a wasm-gated `register_store_mailbox` and the delivery is the network's. What IS tested is everything either side of it: that a reply the buyer *receives* is read correctly (`a_seller_replies_into_their_own_mailbox_and_the_buyer_reads_it`, at both the `messaging` and `AppState` levels). |
| `ui/src/gateway/mailbox_ops.rs::reply_to_mailbox` | The seller's reply reaches the same mailbox the buyer is reading. | **Partly.** `the_two_ways_to_address_a_mailbox_agree` pins that the derived key and the rebuilt-from-id key are identical in instance AND code hash -- the second assertion added after the first version of that test survived the mutation, because `ContractKey`'s `PartialEq` ignores the code hash. What is untested is the send itself. |
| `harvest_common::mailbox::MessageDirection` | A copy of the buyer's own message cannot read as a reply from the seller. | **Yes** -- `a_copy_of_the_buyers_own_message_does_not_read_as_a_reply`, mutated red by deriving both keys under `BuyerToSeller`, which also turned two neighbouring tests red. Note the first version of that test mutated the WHOLE 24-byte nonce, so it passed because decryption failed for an unrelated reason; it now mutates only the dedup padding, which is the mutation an attacker would make. |
| `harvest_common::mailbox::message_aad` | Every field of a message except the ciphertext is authenticated, so it cannot be replayed, re-dated, re-tagged or re-labelled. | **Yes** -- `a_replayed_message_with_fresh_padding_does_not_authenticate` and `the_whole_envelope_is_authenticated`, both observed red before the associated data existed. The replay was verified working: bytes 12..24 of the nonce fed deduplication and nothing else. |
| `harvest_common::mailbox::MailboxStateV1::apply_delta` | It never produces a state `verify` rejects. | **Yes** -- five tests in `dedup_tests`, all observed red against the shipped snapshot-before-the-loop form. This is the claim `verify`'s own doc comment rested on and that nothing checked; the defect was live on `main`. |
| `harvest_common::mailbox::dedupe_identical_entries` | Two different messages sharing a nonce converge AND both survive. | **Yes** -- `two_different_messages_sharing_a_nonce_converge_and_both_survive` and `a_nonce_collision_inside_one_delta_converges_and_keeps_both`. Both were renamed on 2026-09-05 when identity moved to `entry_digest`: convergence alone had stopped being the whole claim, because two peers agreeing to DISCARD the same message converges perfectly and is exactly the retraction the change forbids. |
| `harvest_common::mailbox::apply_delta` | The merged state's byte order is deterministic when NEITHER cap binds. | **Yes, since 2026-09-05** -- `merging_converges_when_neither_cap_binds`. It was not before: all four earlier convergence tests use over-cap fixtures, so every one of them exercised `enforce_message_cap`'s ordering and none exercised the under-cap path. Deleting BOTH ordering mechanisms left those four green and only this one red. The row below is corrected accordingly. |
| `ui/src/state.rs::on_conversation_keys` | The delegate's answers are paired with the questions by echoed tag, not by position. | **Yes, since 2026-09-05** -- `a_short_answer_does_not_hand_one_buyers_key_to_another` and `a_reordered_answer_still_decrypts_both_buyers`. It was not before, and the gap has a shape worth naming: the delegate had a test proving it ECHOES the tag, whose comment called the positional case "the mutation that matters" -- but a test that proves a producer emits something cannot prove the consumer uses it, and the consumer is the only side that could correlate positionally. The guard was on the wrong side of the boundary from the thing it guarded. |
| `ui/src/state.rs::on_delegate_response` (`EncryptionKeyReady`) | The key is filed under the identity the delegate named. | **Yes, since 2026-09-05** -- `an_encryption_key_is_filed_under_the_identity_the_delegate_named`, found by applying the same producer/consumer question to the other messaging response. Worse than the `ConversationKeys` case if it went wrong: a misfiled encryption key is PUBLISHED in that identity's signed store details, so every buyer thereafter encrypts to a key the seller cannot read -- permanently, in a record they cannot retract. |
| `ui/src/state.rs::on_delegate_response` (`ReputationKeysInitialized`, `RsaPublicKey`, `StoreList`) | Each answer is filed under the identity the delegate named. | **Yes, since 2026-09-05** -- `delegate_correlation_tests`, four tests, each mutated red by filing under `pending_store_creation`'s fingerprint instead. Pre-existing sites, hardened after the same shape produced a real gap in `on_conversation_keys`. The RSA one is the sharpest: `ReputationParameters` carries the RSA key, so a contract's ADDRESS is derived from it, and a misfiled key points a signed store at a reputation contract nobody owns. |
| `ui/src/state.rs::conversation_keys_to_request` | A tag the delegate declined is never asked about again. | **Yes** -- `a_tag_the_delegate_declined_is_not_asked_about_again`. The previous behaviour re-asked forever, on the reasoning that a short answer might be transient; the delegate's omissions are deterministic, so one message with an unusable tag looped the tab for its lifetime. |
| `ui/src/messaging.rs::BuyerConversation::read` | A buyer sees their own conversation and nobody else's, and a flood tagged with their key does not hide it. | **Yes** -- `a_buyer_sees_only_their_own_conversation` and `a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread`. The COST of that flood is measured rather than asserted (see `docs/messaging-privacy.md`); no timing assertion was added, because a wall-clock bound in CI is a flaky test. |
| `harvest_common::mailbox::enforce_message_cap` | The mailbox is bounded in bytes, and two peers prune to byte-identical state. | **Yes for the bound**, `the_mailbox_is_bounded_in_bytes_and_not_only_in_count`, red against the count-only predecessor. **Partly for the convergence**, and the qualification matters: `merging_is_order_independent_across_the_byte_budget` is red against a rule that sorted only when the COUNT cap bound, but the batch-independence test is NOT -- chunks arrive in the same relative order, so the two do not bite equally. And all four convergence tests use over-cap fixtures, so what they pin is `enforce_message_cap`'s ordering rather than convergence in general; the under-cap path was untested until `merging_converges_when_neither_cap_binds`. |
| same | Pruning cannot empty a mailbox. | **Yes**, structurally and behaviourally: a `const _: () = assert!(...)` beside the constants makes the corner a BUILD failure, and `an_oversized_message_is_refused_rather_than_emptying_the_mailbox` drives it through `apply_delta` with a message dated past the honest traffic. |
| `harvest_common::mailbox::message_bytes` | The byte charge is a bound and not a proxy. | **Yes** -- `the_byte_charge_is_never_less_than_the_encoded_size`, checked against real CBOR across empty, small, top-bucket, long-timestamp and empty-tag shapes. |
| `harvest_common::mailbox::MailboxStateV1::verify` | It deliberately does NOT check the byte budget, so a mailbox that was legal when written is never stranded. | **Yes** -- `verify_accepts_an_over_budget_state_so_an_existing_mailbox_is_never_stranded`. Worth having as a test rather than a comment precisely because adding the check looks like an improvement. Residual: a peer may hold an over-budget state until its next merge; only the node's maximum state size bounds that. |
| `harvest_common::mailbox::MessageDirection` (second entry) | Direction separation defends against a third party and **NOT** against the counterparty. | **Pinned as a LIMITATION** -- `known_limit_the_counterparty_can_write_in_either_direction`. Both parties derive both keys from one symmetric secret, so either can encrypt in either direction; a buyer's message was verified appearing in a seller's inbox addressed as the seller's own. Not fixable at this layer: only a per-message signature distinguishes two holders of one secret. The UI therefore reports direction, and names only what this browser sent itself as authored. |
| `ui/src/messaging.rs::seal` | A message the compose box accepts is one a mailbox accepts. | **Yes** -- `a_message_too_large_for_a_mailbox_is_refused_at_the_compose_box`. Found by accident: a measurement fixture had every message silently dropped by `apply_delta`, which from the sender's side is indistinguishable from the write race and never resolves. |
| `ui/src/gateway/store_ops.rs::create_store_contracts` | The store is published carrying the seller's encryption key. | **No.** The function is `#[cfg(target_arch = "wasm32")]`, so `cargo test` never reaches it -- the same blind spot as entry 1 below, and the same reason: it is the counterparty of a derivation, not the derivation itself. What IS tested is that `PendingStoreEdit::store_info` carries the key on the *edit* path, which is the path a seller uses to repair a store. |
| `ui/src/state.rs::ask_for_conversation_keys` | The request actually reaches the delegate. | **No.** The decision half (`conversation_keys_to_request`) is host-tested to eight assertions; the send is a wasm-gated `spawn_local`. |
| `ui/src/components/message_view.rs` | Everything the component says on screen. | **No.** There are no component tests in this repository at all. This is the file whose *previous* version claimed "messages are end-to-end encrypted" beside a button that encrypted nothing, so it is worth being explicit: the claims were re-enabled on the strength of the crypto tests below, and nothing checks that the words on screen still match them. A future change that makes messaging conditional again will not fail any test by leaving the reassuring paragraph in place. |
| `common/src/mailbox.rs::conversation_key_from_dh` | Buyer and seller derive the same key. | **Yes**, three ways: a known-answer test against `b3sum` (`the_conversation_key_derivation_is_pinned`), the delegate's `the_seller_derives_the_key_the_buyer_derived`, and the UI's `a_sealed_message_is_readable_by_the_seller_who_holds_the_secret`, which reconstructs the seller from a bare X25519 secret rather than from the UI's own code. |
| `common/src/store.rs::StoreInfoV1::encryption_public_key` | `skip_serializing_if` keeps every pre-existing ghostkey signature verifying. | **Yes** -- `a_store_info_that_predates_the_encryption_key_re_encodes_unchanged`, observed red against the naive `#[serde(default)]`-only form. |
| `ui/src/ghostkey_cert.rs::store_verifying_key` | A stolen certificate yields no key, so a buyer cannot be routed to the victim's mailbox. | **Yes** -- `a_stolen_certificate_yields_no_key_to_derive_a_mailbox_from`, mutated red by trusting any certificate that parses and chains. |
| `ui/src/state.rs::BrowsingStore::seller_verifying_key` | A store the buyer is told is unverified is never one the compose box is offered for, because both come from one call. | **Yes** -- `an_unverified_store_yields_no_key_to_message_it_with`, mutated red by setting the key unconditionally. It pins the wiring; the check itself is the `ghostkey_cert` row above. |
| `delegates/harvest-delegate/src/messaging.rs` | Everything the delegate writes is under the exported prefix. | **Yes** -- `everything_this_module_writes_is_under_the_exported_prefix`, which drives the real writer. The pre-existing `every_secret_the_delegate_writes_is_under_the_exported_prefix` stayed GREEN under the same mutation, because it reads a hand-maintained list; that is the gap the new test closes. |

### Buyer conversation persistence (added 2026-09-05, same branch)

| Where | Claim | Caught? |
|---|---|---|
| `delegates/harvest-delegate/src/secrets.rs::RemovableSecrets` | The node genuinely deletes a removed secret -- blob, snapshots, index entry and enumeration-registry entry. | **No, and it cannot be here.** `DelegateCtx::remove_secret` is a `false`-returning stub off wasm32, like every other secret method, so the tests drive `MemSecrets`. The claim is read from freenet-core's own source (`wasm_runtime/secrets_store/store.rs::remove_secret`) and cited in the trait's doc comment; the doc comment also says, in those words, what the tests do and do not establish. Observing it needs `tests/rehearsal/` and a live node. What IS tested is that this crate asks for removal, re-reads the key, and reports a failure rather than an `Ok` when the key is still there (`a_refused_removal_is_not_reported_as_forgotten`). |
| `delegates/harvest-delegate/src/messaging.rs::forget_buyer_conversation` | Forgetting leaves nothing behind, not an emptied value. | **Yes** -- `a_forgotten_conversation_leaves_nothing_behind`, observed red against the emptied-value form, which left `harvest:buyer_conv:{store}:{tag}` in the store with the store id still in it. That red run is the reason the key is named rather than an opaque slot: the slot design existed only to work around a deletion the platform turned out to have. |
| `delegates/harvest-delegate/src/messaging.rs::MAX_BUYER_CONVERSATIONS` | The count cap is a byte bound, because both the key and the value are bounded. | **Yes for both halves.** The cap itself: `the_cap_bounds_the_store_and_evicts_the_oldest`, red with the cap deleted. The key half: `a_store_id_that_is_not_a_contract_id_is_refused` -- without that refusal the key is caller-sized and the cap bounds entries while bounding no bytes, which is this repository's own named trap. |
| same | An undecodable entry is evicted before a real conversation. | **Yes** -- `an_undecodable_entry_is_evicted_before_a_real_one`, red when the ordering sorts undecodable entries last. |
| `ui/src/state.rs::compose_to_seller` | Sending a message is what asks the node to keep the key. | **Yes** -- `sending_a_message_asks_the_node_to_keep_the_conversation`, red when the call is removed from the send path. Worth its own test because every other test around it calls `conversation_to_keep` directly and would have stayed green. |
| `ui/src/state.rs` / `delegates/.../messaging.rs` | The tag the delegate files a conversation under is the tag the mailbox carries. | **Yes, from both sides, which is the point.** The delegate derives the tag from the secret it is sent (`a_stored_conversation_comes_back_with_usable_keys` asserts the recalled tag and both keys against a seller derived independently); the UI asserts that what it SENDS has that same public half (`the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries`). The seam between the two crates is `harvest_common::mailbox::conversation_key_from_dh`, which both call and which is separately pinned by a known-answer test. The UI crate cannot depend on the delegate crate, so this pair is the strongest available statement. |
| `ui/src/state.rs::on_buyer_conversations` | A recalled conversation reads the reply that arrived while the tab was closed. | **Yes** -- `a_reply_is_readable_after_the_tab_that_asked_is_gone`, which builds the delegate's answer from the real crypto and drives a fresh `AppState`. Red when the recall handler is inert. |
| `ui/src/state.rs::conversation_thread` | Every conversation this node has had with the store is read, not just the active one. | **Yes** -- `every_conversation_with_a_store_is_read`, red when only the last is read. It drives the documented race (the buyer writes before the recall answers, so they hold two conversations with one store) and asserts the older thread still appears. |
| same | A non-empty recall re-subscribes to the seller's mailbox, and an empty one subscribes to nothing. | **Yes** -- `recalling_conversations_subscribes_to_the_sellers_mailbox` and `recalling_nothing_subscribes_to_nothing`. The second is the privacy half: a reader who never wrote to a seller must not advertise an interest in their mailbox. |
| `ui/src/state.rs::buyer_conversations_to_recall` | A store is not marked as asked before the delegate is registered. | **Yes** -- `a_store_is_not_marked_asked_before_the_delegate_is_registered` and `registering_the_delegate_asks_about_stores_already_on_screen`, both red with the guard removed. `components::app` opens a store link BEFORE registering the harvest delegate, so this ordering is the common one, not the exotic one. |
| `ui/src/state.rs::on_buyer_conversation_forgotten` | A conversation leaves the buyer's view only when the node says the record is gone. | **Yes** -- `a_conversation_is_dropped_only_when_the_node_says_it_is_gone`, which drives the refusal first and the success second, plus `an_unasked_forget_answer_drops_nothing`. |
| `harvest_common::delegate::ConversationSecret` | The buyer's secret does not print itself, in the `Debug`-deriving request it travels in. | **Yes** -- `a_conversation_secret_does_not_print_itself`, observed red against a derived `Debug`, which printed all 32 bytes. `a_conversation_secret_encodes_as_its_bytes` pins that the newtype is not a wire change. |
| `ui/src/components/message_view.rs::KeptConversations` | The buyer can reach the forget control at all, and the panel says what it does. | **No.** There are still no component tests in this repository -- the same gap as the row above about everything this component says on screen. The state transition behind the button is tested; the button is not. |
| `delegates/.../messaging.rs::decode_backup` | A truncated or foreign paste is refused rather than half-imported. | **Yes** -- `a_truncated_backup_is_refused` (base58check catches the lost tail) and `a_paste_that_is_not_a_backup_is_refused_by_name`, which drives four shapes of wrong paste including a next-version prefix. |
| same, `import_buyer_conversations` | Importing a conversation this node already holds keeps the HELD one, and never overwrites it. | **Yes** -- `importing_a_held_conversation_keeps_the_held_one`, which pastes both an honest backup and a hand-built one naming the same routing tag with a different `conversation_id`, and asserts the held record is what the node still reads its thread with. The one exception is pinned separately: `importing_over_an_undecodable_entry_restores_it`. |
| same | At the cap an import refuses and names what it refused, rather than evicting. | **Yes** -- `an_import_at_the_cap_refuses_rather_than_evicting`, which also asserts the oldest held conversation is still there. This inverts the eviction rule for storing, so the two tests are the record of a deliberate asymmetry rather than an inconsistency. |
| same, `mark_conversations_backed_up` | The backup marker is deleted with the conversation it describes. | **Yes** -- `forgetting_a_conversation_leaves_no_backup_marker_behind`, observed red against the ghostkey vault's own shape (a marker key of its own), which left `harvest:conv_backedup:...` behind naming the store. This is why the marker is a field of the record here and not a separate secret. |
| `delegates/.../handlers.rs` | A foreign web app can neither export a buyer's secrets NOR silence the warning that they exist in one place only. | **Yes** -- `another_web_app_cannot_export_or_silence_a_buyers_backup_warning`, red with the `authorize` call removed. The marker half is the one worth the test: it writes no secret and answers none, so it reads as harmless, and what it does is stop a warning about a conversation nobody has a copy of. |
| `harvest_common::ImportedConversations` / `ui/src/state.rs::on_conversations_imported` | A conversation that could not be restored is NAMED with its reason, not folded into a count. | **Yes** -- `a_refused_import_says_which_and_why`, which asserts both the reason and the shortened tag survive into what the buyer is told. |
| `ui/src/state.rs::on_conversations_marked_backed_up` / `on_conversations_imported` | The screen is refreshed by re-asking the delegate, not by assuming what it did. | **Yes** -- `marking_asks_the_delegate_again_rather_than_assuming`, `an_import_asks_for_the_restored_conversation`, and `a_recall_refreshes_whether_a_held_conversation_is_backed_up`, which drives the whole marking round trip and would fail if a recall only ADDED conversations instead of refreshing held ones. |
| `ui/src/state.rs::on_buyer_conversations` | An answer is filed under the store this browser ASKED about, and one nothing asked for is ignored. | **Yes, since the backup work** -- `conversations_are_filed_under_the_store_that_was_asked_about` and `a_recall_answer_nothing_asked_for_is_ignored`, both red against the obvious implementations (file by the echoed id; act on any answer). The recall carried no request id until this change, so neither guard could exist; the defect it would have caused is a buyer reading, and composing into, a thread against the wrong seller's mailbox. |
| `ui/src/state.rs::ConversationBackup` | A backup does not print itself. | **Yes** -- `a_backup_on_screen_does_not_print_itself`, red against a derived `Debug`. More at stake than the single secret it shares this guard's reasoning with: this one is a complete portable copy of every conversation with a store. |
| `ui/src/state.rs::authored_here` | "What this tab sent" is recognised by something the counterparty cannot reproduce. | **Yes, since the review** -- `a_substituted_message_is_not_shown_as_the_buyers_own` and `a_seller_is_not_credited_with_a_substituted_reply`, both red against the shipped nonce-matching. It was NOT true before: the nonce is public, the counterparty holds the key, and `dedupe_by_nonce` keeps whichever entry ranks highest under attacker-chosen fields -- so their words appeared under "You, from this tab" in both directions. The tests drive the REAL `MailboxStateV1::apply_delta`, so the displacement is the contract's own, not a fixture's. |
| `ui/src/state.rs::unconfirmed_sent` | "Landed" means THIS message is in the mailbox, not that its nonce is. | **Yes, since the final review** -- `a_message_absent_from_the_mailbox_is_unconfirmed_even_if_its_nonce_is_there`, red when landed-ness is decided by nonce. The neighbouring test could not see it: it puts both entries in the mailbox, so the nonce rule and the digest rule agree -- the same fixture shape that let the re-store guard go unpinned. `replaced_sent`, which this row used to cite, was DELETED when the contract fix made displacement impossible; see `docs/messaging-privacy.md`. |
| `harvest_common::mailbox::entry_digest` | Every field is covered, and a substitute sharing a nonce differs. | **Yes** -- four tests, two of them red under mutation (dropping the ciphertext; dropping the length prefixes). |
| `contracts/mailbox-contract` `UpdateData::State` arm, `ui/src/migrate.rs::merge_mailbox` | "Already held" is decided by the same identity `verify` enforces. | **Yes, since the final review** -- neither site decides it any more: both hand everything to `apply_delta`, which dedups by `entry_digest`. Pinned behaviourally by `a_state_merge_keeps_a_message_whose_nonce_something_else_shares` and `folding_keeps_a_message_whose_nonce_the_newer_generation_shares` (both red first), and structurally by `no_production_code_compares_message_nonces_for_identity`, a source scrape, which found the migration fold that review had not. **The scrape is a tripwire, not a proof, and for one round it was far weaker than this row said.** Review planted six rewrites of the identical defect at that same site and it caught one; separately, its `#[cfg(test)]` cut was a truncation at the FIRST occurrence, so an attribute on a helper 40 lines into `handlers.rs` hid the other 1,098 lines, and the control-form defect planted below it was invisible. Both are fixed (brace-matched stripping, widened patterns, waivered reputation sites, workspace-derived directory list) and all seven plants are now caught -- but it reads no types, so a comparison behind a helper or spread across lines still passes. The behavioural tests are what carry the property; every one of the seven plants was caught by those. |
| `ui/src/migrate.rs::merge_mailbox` | The fold is commutative, so `FoldAllAck`'s precondition holds. | **Yes, since 2026-09-05, and it did NOT hold before.** `apply_delta` refuses a message over `MAX_MESSAGE_BYTES` on the INCOMING side, and `merge_generations(newer, older)` puts the predecessor there -- so the same message survived from the successor and vanished from the predecessor, silently, during the one operation whose purpose is to preserve messages. `fold_all_preconditions_hold_for_the_mailbox_state` was green throughout because all three of its samples were small. Now pinned by `folding_is_commutative_across_the_message_size_bound` and `an_oversized_message_is_dropped_from_whichever_side_it_is_on` (both red first, the second via the crate's own `assert_merge_commutative`), and the refusal is applied to both sides with what it could not carry reported. |
| same | The mailbox merge is **normalising**, so strict `merge(a, a) == a` is false for un-normalised input. | **Yes, since 2026-09-05** -- `fold_all_preconditions_hold_for_a_mailbox_that_needs_normalising`. Found while fixing the row above and worth more than it: `policy_check::assert_merge_idempotent` asserts the strict form, and the mailbox merge has never satisfied it -- hand it 517 messages and `merge(a, a)` returns 512, because `enforce_message_cap` runs on every call. So the `FoldAllAck` token was minted against a sample set too small to meet ANY normalisation, not just the size bound. What fold-all actually needs is asserted instead: commutativity and order-invariance on raw samples, idempotence on the merge's own output, and absorption (`merge(merge(a, b), b) == merge(a, b)`), which nothing checked at all. |
| `contracts/mailbox-contract::validate_state` | A state the contract hands back is one it would accept. | **Yes, since 2026-09-05.** It was vacuous: stubbing `validate_state` to return `Valid` unconditionally failed ZERO tests across the workspace, and `a_merged_state_validates` was the only test of it anywhere. What it pinned was that `update_state`'s output CBOR-decodes. It now also asserts a rejection (`a_merged_state_validates_and_an_invalid_one_does_not`) and is killed by that mutation. |
| `contracts/mailbox-contract::summarize_state` | The summary reports what the state holds. | **Yes, since 2026-09-05** -- `a_summary_of_what_a_peer_holds_asks_only_for_what_it_lacks`, found by mutation while re-checking the tests added the same day: stubbing `summarize_state` to answer a non-empty state with an empty summary failed nothing, because the two empty-summary tests drive `get_state_delta` and take the summary as given. The producer/consumer split again -- the consumer was covered and the producer was not. |
| `common/src/reputation.rs::ReputationStateV1` | "Feedback is naturally commutative: adding entries in any order produces the same final set." | **NO -- and the claim is FALSE, which this row previously recorded only as untested.** The RSA signature covers `entry.token` alone while `category`, `comment` and `submitted_at` ride alongside it unsigned, and identity is `token.nonce`. So a published entry can be re-submitted with different words under the same token, and each peer keeps whichever it saw first. Demonstrated by execution in `known_gap_two_feedback_variants_sharing_a_token_do_not_converge`. Beyond convergence: a seller who reads negative feedback can push a neutered variant to peers that do not hold the original, and those peers then refuse the real one because its nonce is used. Same class as the mailbox's nonce identity; **deliberately not fixed on this branch** -- different contract, its own re-key, and for feedback the better repair is probably to sign the whole entry so the variant cannot exist at all. |
| `harvest_common::mailbox` convergence for a same-nonce pair | Which mechanism carries it. | **The JOINT property IS pinned; no SINGLE mutation observes it.** Both halves matter and the first is the one that gets lost: three tests fail when both mechanisms are removed, so the suite does defend convergence -- what it cannot do is tell you which mechanism to keep. Corrected after review, because the first version of this row stated a measurement that does not reproduce. The matrix: an order-dependent dedup alone passes (the final `(nonce, entry_digest)` sort re-normalises); removing the final sort's tiebreak alone passes (dedup already ordered them); doing BOTH fails three tests. `enforce_message_cap`'s digest tiebreak is a third mechanism and is redundant to both. The earlier inference -- "the tiebreaks survive their own mutation, so the property lives in the dedup sort" -- was invalid, since the dedup sort survives its own mutation too. Each comment now says it is one of two and that removing both is what breaks; two comments each truthfully saying "no test fails without me" would together authorise deleting both, which is the only real exposure here. |
| `harvest_common::mailbox` identity | The counterparty can delete a message you sent. | **FIXED on 2026-09-05, not a limitation any more.** Identity is `entry_digest` over the whole entry, computed by the contract, so there is no collision to resolve. Pinned by `a_message_cannot_be_retracted_by_submitting_another_under_its_nonce` and four neighbours, plus the contract's own `a_state_merge_keeps_a_message_whose_nonce_something_else_shares`. **What remains is narrower and is still a live gap:** a funded flood evicts it under the cap (`known_gap_a_funded_flood_still_evicts_every_honest_message`, and more cheaply `known_gap_the_byte_route_evicts_in_one_update_and_costs_fewer_entries` -- 64 entries via the byte budget rather than 512 via the count cap), so retraction is expensive and indiscriminate rather than impossible. It is NOT interruptible: `apply_delta` merges a whole delta, so either route is one update. This row previously told a reader that deletion was an accepted live limitation of the shipped contract, which was true when written and false by the end of the same day. |
| `ui/src/messaging.rs::encrypt_message` | The mailbox nonce is FRESH per message, so an honest client never collides. | **Yes** -- and credited here only after review pointed out this file named the wrong test. Three tests die when `encrypt_message` derives the nonce deterministically instead of drawing it from `getrandom`: `each_conversation_carries_a_fresh_tag`, `a_mailbox_is_read_with_the_keys_on_hand_and_says_so_when_it_cannot_be`, and `state::conversation_tests::a_second_message_continues_the_same_conversation`. Verified by that mutation. This is the invariant that makes the row below a limitation rather than a defect. |
| `ui/src/messaging.rs` (AES-GCM) | A deliberate nonce collision reuses the keystream, and Harvest's AAD does not prevent it. | **Pinned as a LIMITATION, since 2026-09-05** -- `known_limit_a_nonce_collision_reuses_the_keystream` asserts `C1 xor C2 == P1 xor P2`, red under a mutation that separates the two nonces. **What it establishes, precisely:** the xor assertion is a property of AES-GCM and holds for any key, so it is not evidence about Harvest's crypto specifically; the first version of this test used a bare key and bare `aes_gcm` call and would have passed with all of Harvest's construction deleted. It now derives the key with `conversation_key_from_dh`, pads with `pad_to_bucket` and binds `message_aad` exactly as `encrypt_message` does, so a change to any of those reaches the test -- and it makes the non-obvious Harvest claim explicit: the mailbox nonce IS bound into the AAD, and that authenticates without randomising, so it does nothing about keystream reuse. This row asserted the pin for a day before the test existed, and was cited in the nonce-reuse analysis that led to the entry-digest change -- an argument resting in part on a test nobody had written. |
| `delegates/.../messaging.rs::make_room` | A conversation that exists only on this node is the last thing evicted. | **Yes** -- `a_conversation_that_exists_only_here_outlives_an_imported_one`, red when the ranking ignores `backed_up`. The reproduction is the reviewer's: a pasted backup fills the store, and the next conversation the buyer opens destroys one of their own. |
| same | An eviction is reported. | **Yes** -- `an_eviction_is_reported` and `storing_without_evicting_reports_no_eviction` (so the report is evidence rather than noise), plus `a_conversation_discarded_to_make_room_is_reported` and `discarding_a_backed_up_conversation_says_it_can_be_restored` on the consumer side, all red under mutation. |
| same, `decode_backup` | An oversized paste is refused before it is decoded. | **Yes** -- `a_backup_string_longer_than_the_cap_is_refused_without_decoding_it`, which also asserts the refusal is fast. Found by measurement, not by reading: base58 is quadratic, and a 253-conversation round trip took 72 seconds in a debug build with nothing bounding the length. |
| same, `import_buyer_conversations` | A record whose keys cannot be derived is refused rather than silently occupying a slot. | **Yes, since the review** -- `a_record_whose_keys_cannot_be_derived_is_refused_and_stores_nothing`. It was one of the two guards the sweep section did not cover. |
| same, `store_buyer_conversation` | Re-storing a held conversation evicts nothing. | **Yes, since the review.** The test existed and could not observe its own claim: it re-stored the OLDEST held conversation, which is also the eviction victim, so with the guard deleted the eviction cancelled itself out and the suite stayed green. It now re-stores the NEWEST -- the thread the buyer is actually writing into, which is what the UI re-sends -- and is red under that mutation. |
| same, `mark_conversations_backed_up` | A refused write is reported rather than counted as "not marked". | **Yes, since the review** -- `marking_reports_a_failure_when_the_node_refuses_the_write`. The response could not express a failure before, which made the UI's error path dead code. |
| `ui/src/state.rs::on_conversation_exported` | A backup is filed under the CONVERSATION that was ASKED about, and one nothing asked for is ignored. | **Yes, since the review** -- `a_backup_is_filed_under_the_conversation_that_was_asked_about` and `a_backup_nothing_asked_for_does_not_reach_the_screen`. Both the handler and the test were named for the STORE until export became per-conversation; this row kept the old names for a day, which is the citation drift the note at the end of this file is about. This file states the principle for `BuyerConversationList` and did not follow it here; a backup on screen under the wrong heading invites the buyer to save it as that store's. |
| `ui/src/state.rs::on_buyer_conversations` (sort) | The NEWEST recalled conversation is the one a new message continues. | **Yes, since the review** -- `a_new_message_continues_the_newest_of_several_recalled_conversations`, red with the sort deleted. The two existing tests could not see it: one had a single recalled conversation, the other had two but only asserted both were readable. |
| `ui/src/state.rs::on_conversations_imported` | An imported conversation may become the active thread, and its secret may be known to whoever supplied the string. | **No, and it is a residual rather than a claim.** The notification says so; nothing tests the wording, and nothing prevents it -- a backup the buyer was handed is indistinguishable from one they made. Recorded here rather than left in the commit message. |
| `delegates/.../messaging.rs` (backup format) | One backup string covers ONE conversation. | **Yes** -- `a_backup_carries_one_conversation`, which holds two conversations with one store and a third with another, and asserts the restore brings back exactly the one that was asked for. The granularity is the whole point of the change: a store-wide string is silently incomplete the moment the next conversation is opened. |
| same, `mark_conversation_backed_up` | Marking clears the warning on that conversation and no other. | **Yes** -- `marking_a_conversation_clears_its_warning_and_no_others` and, on the request side, `marking_names_only_the_conversation_that_was_saved`. This is the "cannot silence a warning about a key it has no backup of" property at the granularity level rather than the permission level. |
| same, `make_room` | An imported conversation is evicted before one opened here, even when both are backed up. | **Yes** -- `an_imported_conversation_is_evicted_before_one_opened_here`, red when the import tier is dropped from the ranking. This is the half `backed_up` alone does not cover: once the buyer has saved their own conversations, both sit in one tier and the order falls to `created_at`, which travels inside the backup string. `imported` is set by the delegate from which call arrived, so no string can claim it. |
| same, `decode_backup` | A v1 (store-wide) string is refused rather than read as something it is not. | **Yes** -- `a_paste_that_is_not_a_backup_is_refused_by_name` drives `harvest-conv-backup-v1:` alongside a ghostkey PEM and a v3 string. No v1 artefact was ever produced outside tests, so there is deliberately no v1-reading path. |
| same | An honest backup is far inside the length cap. | **Yes** -- `an_honest_backup_is_far_inside_the_length_cap`, which asserts four times the real size still fits. Worth pinning because the cap was tightened from 64 KiB to 4 KiB when the format went from a store's worth to one conversation, and a cap that refused real backups would be worse than no cap. |
| `ui/src/state.rs::on_conversation_exported` | A backup is filed under the conversation that was ASKED about. | **Yes** -- `a_backup_is_filed_under_the_conversation_that_was_asked_about` and `an_exported_backup_reaches_the_screen_under_its_own_conversation`, both red when the answer's own tag is trusted. Stronger than the store-level version it replaces: one string covers one conversation, so showing it under the wrong one invites the buyer to save it as that conversation's. |
| `ui/src/components/message_view.rs::ConversationBackupControl` | Everything the backup panel says, and that "I have saved this" is a separate action from revealing the string. | **No.** Still no component tests. The state transitions behind both buttons are tested and the delegate refuses to be told a backup exists by anything but the Harvest app -- but nothing checks that the UI actually makes the buyer press the second button, which is the whole basis of the marker meaning anything. This is the most load-bearing untested claim added by the backup work. |
| `ui/src/state.rs::send_to_harvest_delegate` | Any of these requests actually reach the delegate. | **No.** The same wasm-gated `spawn_local` gap as `ask_for_conversation_keys`, which this now shares one implementation with. Every decision is host-tested; the send is not. |

### The guard sweep, 2026-09-05 — **scope: the messaging change only**

**This section covers the guards in `683feb0` and its neighbours, NOT the
buyer-conversation persistence or backup work in the tables above and below.**
It was written before either existed and sits after them by accident of
ordering, which a reviewer read — correctly — as a claim of completeness it
does not have. Two guards added by the persistence work were found unpinned by
exactly that misreading (the re-store guard and import's low-order refusal);
both are now pinned, and their rows say so.

Every guard the messaging change touched or added was deleted, one at a time,
and the suite re-run. A guard whose removal leaves the suite green is one a future
refactor removes silently, and this branch had already produced two of them
(the routing-tag filter, and a `ContractKey` comparison that ignored the code
hash because `PartialEq` does).

**Pinned (16):** the mailbox's oversize refusal, byte budget, `verify`
over-count guard and `verify` duplicate-nonce guard; `ListingsV1`'s delta
dedup and `reputation`'s intra-delta dedup; the buyer's `conversation_id`
check, low-order refusal and compose-time size check; the delegate's low-order
refusal; `compose_reply`'s ownership check; `conversation_keys_to_request`'s
ownership gate and in-flight dedup; `EncryptionKeyReady`'s length check; and
the two `mailbox_ops` key derivations.

**Unpinned (2):** both `OrdersV1::verify` guards, which entry 3 below already
named. The sweep did not find anything entry 3 had missed, which is the useful
result -- it says the document was accurate rather than optimistic.

**Newly pinned during the sweep (1):** the routing-tag filter, which no
assertion about output could catch, because correctness genuinely does not
depend on it. It is pinned by measuring the work instead
(`reading_a_thread_costs_the_thread_and_not_the_mailbox`): removing it takes a
buyer's read from 3 decryption attempts to 1023.

Three things follow that are worth saying plainly rather than leaving as a
pattern in the table. First, **every read path is fully host-tested and every
write path is not**, because a write ends at a node and a read ends in a pure
function. Second, **the component is the least-covered file in the change and
is the one that makes claims to users**, which is the exact shape of the
defect that produced this document. Third, **the sharpest limitation was not
in this table at all**, because it was not a claim that could become false: a
buyer's conversation keys died with the browser tab, so a reply arriving after
a reload was unreadable by anyone forever.

That third one was closed later the same day -- the delegate now keeps the
buyer's per-conversation secret, and the rows added below cover it. What
replaces it is narrower and is stated wherever it matters: the secret is in
ONE node's delegate, so a buyer who changes device still loses the
conversation, and the keyed record is a durable local note of which stores this
node contacted (removable, and the removal is a real deletion). See
`docs/buyer-conversation-persistence.md`.

---

## The four that matter

Ranked by what breaks if the claim turns out to be false, not by how easy the
test would be.

### 1. `ui/src/migrate.rs:190` — parameters are derived in one place — **CLOSED STRUCTURALLY 2026-09-05**

**Data survival.** Ranked first when this list was compiled, and fixed rather
than left listed. `create_store_contracts` held a second, hand-maintained copy
of all three parameter structs. If the copies drifted, every derived instance
id named a contract that was never published: the migration probe would walk
addresses that do not exist, take `NotFound` at each, and report a clean
"nothing to migrate" over a seller's entire store — listings, reputation and
mailbox. Silent at every layer: no error, no log, no failing test, green CI.

It ranked first because **it had already happened once in this exact shape** —
a parameter-derivation mismatch is the defect this whole review opened with,
and fixing that symptom had left the structural cause standing. It was also
the only entry whose counterparty is invisible to every automated check in the
repository, `create_store_contracts` being wasm-gated.

There is now one derivation *in the code as written*. The duplication was
worse than recorded: three production copies (store, mailbox, reputation), not
one, plus a fourth in that file's own test module which meant the test could
pass against parameters the real PUT would never produce.
`common/src/delegate.rs` was checked and is already a single shared const.

**This entry was marked CLOSED on 2026-09-05 and that was wrong.** A third
review round mutation-tested the scrape meant to hold the line and beat both
halves of it. Both mutations were reproduced before this correction was
written:

* **The negative half** matches the literal `"StoreParameters {"`. A type
  alias evades it entirely — `use harvest_common::store::StoreParameters as
  SP; let p = SP { seller_verifying_key: vk };` reintroduces the second
  derivation, passes the test, and passes `cargo fmt --check`. That is an
  ordinary refactor, not a contrived evasion.
* **The positive half** asserts the file contains `"migrate::store_params"`.
  It is satisfied by a COMMENT at `ui/src/gateway/store_ops.rs:176` and by the
  `#[cfg(test)]` module, so deleting the production call does not trip it.

One mutation beats both at once, which is how it should have been tested when
it was written. Writing a test to confirm a fix, rather than to attack it, is
the failure this whole document exists to record, and it happened here in the
document itself.

**A wrong "CLOSED" is worse than an open item**, because it stops the next
person looking. That is why this note is longer than the entry it corrects,
and why it stays here now that the entry really is closed.

**The repair, and why it counts as closed this time.** The fields are now
`pub(crate)` with a `new` on each struct, so the invariant is held by the
compiler rather than by a test: outside `harvest-common` a second derivation
does not compile. The aliased mutation that beat the scrape was re-run and
now fails with E0451. This was judged too large when the scrape was chosen —
it edits `harvest-common`, which re-keys every contract — but the committed
WASM is already stale by ten `common/` commits on this branch, so the re-key
and its `contract-rekey-acknowledged` label were pending regardless.

Residual, stated so it is not discovered later as a surprise: nothing stops
someone making a field `pub` again. `contract_parameter_fields_stay_crate_
private` is a substring scrape over three files and catches the ordinary
form of that change; a rename, unusual spacing, or a fourth parameter struct
added elsewhere slips past it. It is a guard on a review-visible change, not
the thing that makes the invariant true.

### 2. `contracts/store-contract/src/lib.rs:100` — the cross-check is additive only

**Convergence, and therefore money.** If any path through the related-contract
section can return `Invalid`, two peers holding byte-identical `StoreStateV1`
can disagree about its validity purely because one has fetched the Bitcoin
address contract and the other has not. Divergence in a payments contract means
peers disagreeing about whether an order is paid.

The tested half is the benign one — related state came back empty. The untested
half is related state that came back **populated and contradicting**, which is
exactly where a future edit would most naturally add a rejection, because at
that point the contract appears to hold evidence of a problem. The comment says
loudly not to, and a comment is currently the whole enforcement.

### 3. `common/src/store.rs:470` and `:476` — the `OrdersV1::verify` guards
### **CONFIRMED BY EXECUTION 2026-09-05, still open**

**Money, then resource exhaustion.** These two guards are the only thing
standing between a hostile peer's hand-built state and the rest of the order
machinery. The mis-keyed check (`:476`) is the sharper of the pair: every
honest path keys by `record.order.id`, so a mismatch can only arrive from a
constructed state, and downstream code looks orders up by map key while
verifying the record inside — so a record filed under someone else's id is
checked as itself but found as another order.

Both were deleted, one at a time, on 2026-09-05, and `cargo test -p
harvest-common` stayed green for each -- so this entry is now a measurement
rather than a reading. They were the ONLY two hits in a sweep of every guard
this branch touched or added; the sixteen others all failed at least one test
when removed. The sweep is summarised at the end of the messaging section
above. `MAX_ORDERS`
(`:470`) additionally carries the bound that three other comments cite as
established, so one deletion silently falsifies four claims. The equivalent
guard in `mailbox.rs` is tested; this is the same guard, in the state that
holds payment evidence rather than messages.

### 4. `ui/src/migrate.rs:615` and `:620` — no removal path, so `FoldAll` is sound

**Data survival, in the direction that looks like success.** `fold_all_policy`
selects `FoldAll`, which resurrects anything deleted by mere absence, and its
entire soundness argument is that neither listings nor feedback can be deleted.
Add a removal path — a plausible, well-motivated feature — without a tombstone,
and folding an older generation silently reinstates every listing a seller
removed and every retracted piece of feedback. There is no error state: the
migration reports success, and the resurrected data looks like recovered data.

This ranks fourth only because it requires someone to add a feature rather than
to make a mistake. It ranks *this high* because `common/src/store.rs:152`
asserted the opposite — "grow-only with removal by signed deletion", describing
a mechanism that never existed — until it was corrected on 2026-09-05. Someone
reading that line would have concluded a removal path already existed and that
`FoldAll` was already unsound. The two claims contradicted each other across
files for as long as both existed, and nothing brought them together.

### Not in the four, and why

`common/src/payment.rs:526` (purity of `verify_payment_proof`) is the most
severe claim in the file — a clock there diverges the network — but it is
comfortably the least likely to break by accident: the function takes no
capability that would let it, and adding one is a deliberate act. It wants a
source-scrape pin test, not a behavioural one, and it is cheap enough to be
worth doing anyway.

`common/src/store.rs:272` (`to_cbor` is infallible) is unfalsifiable by test
and would surface as a panic rather than a wrong answer.
