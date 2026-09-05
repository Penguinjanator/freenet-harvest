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
`contracts/*/src/lib.rs`, `ui/src/migrate.rs`, `ui/src/state.rs`. It does not
cover `delegates/` or `ui/src/gateway/`, which were held by other people during
the review and are collected separately.

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

---

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

**Money, then resource exhaustion.** These two guards are the only thing
standing between a hostile peer's hand-built state and the rest of the order
machinery. The mis-keyed check (`:476`) is the sharper of the pair: every
honest path keys by `record.order.id`, so a mismatch can only arrive from a
constructed state, and downstream code looks orders up by map key while
verifying the record inside — so a record filed under someone else's id is
checked as itself but found as another order.

Both can be deleted today with `cargo test --workspace` green. `MAX_ORDERS`
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
