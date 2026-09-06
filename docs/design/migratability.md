# Migratability is a requirement, not a nicety

**Status: a requirement and an unbuilt design. Written 2026-09-06 on
`feat/buy-flow`, immediately after that branch demonstrated the cost of not
having it. Nothing described under "The fix nobody has built" exists.**

## The requirement

**A new contract version must be migratable from every version that has ever
held user data.**

Ian, 2026-09-06: *migratability from old contract versions should be a
requirement for any new contract version once an app has actual users.*

A change to how a record's identity is derived is **a breaking change to
users' data**, not an internal refactor. It reads like one — it is a few lines
in one function, every test passes, and nothing in the type system moves — and
that is exactly why it needs writing down.

The threshold is "once an app has actual users". Harvest does not have them
yet, which is the only reason the loss described below was acceptable when it
happened. The requirement is for the next time, and the next time is whenever
somebody publishes a store they care about.

## What it cost, so the requirement is not abstract

On `feat/buy-flow`, `ListingId` and `OrderId` were changed to be derived from
a record's own terms. The change was right: without it a seller could sign two
listings with one id at different prices, and `ListingsV1::apply_delta` is
first-writer-wins, so two peers would keep different copies and **never**
reconcile — each one's summary already names the id, so neither can ever tell
the other.

The consequence nobody noticed until it was probed:

1. Every listing published by a previous generation carries an id derived the
   old way.
2. `AuthorizedListing::verify` refuses any listing whose id is not the one its
   terms give.
3. `ListingsV1::apply_delta` returns on the **first** refusal.
4. So `fold_or_keep_primary` discards the predecessor generation **in full** —
   the listings, the orders, and the store's own name, description and
   certificate with them.
5. It was reported by a `probe_warn`, which is a browser console line.
6. The migration then **seals**. There is no second attempt.

A seller upgrading lost their entire shop, and the only trace was a log nobody
reads. It passed `cargo fmt`, `cargo clippy` on both targets, the full test
suite, and a review round.

**Why no test saw it:** every fixture in this repository builds its records
with the *current* derivation. Not one of them could hold what a predecessor
generation produced. That is the general trap, and it is not specific to ids —
it applies to any change where the old bytes and the new code have to meet.

## The fix nobody has built: re-issue under the owner's key

**Where a derivation change makes old records unverifiable, the migration must
re-issue them rather than discard them.**

This is possible today and simply has not been done. The migration runs
**client-side, in the owner's own browser**, for the owner's own stores — it is
triggered by that identity's `GhostKeyList` — and their signing key is in the
ghostkey delegate, reachable by the same `SignMessage`/`SignResult` round trip
the app already uses to publish a listing.

So the client can:

1. accept the old-format record from the predecessor generation, as data;
2. recompute its id under the current rules (`ListingId::from_terms`);
3. ask the delegate to re-sign it, **as the same owner, over the same terms**;
4. publish that.

The contract only ever sees new-format records, so the hole the derivation
change closed stays closed, and the seller keeps their store. Nothing is
forged: the owner is re-signing their own data, and every record still carries
a signature by the key the store's parameters name.

### What it would take

`merge_store` is a pure function with no delegate access, and that is
deliberate — it is why the fold is testable at all. So the fold cannot do the
re-signing itself. The shape is:

* the fold surfaces the records it refused, as *needs re-issuing* rather than
  as *discarded*, alongside the ones it carried;
* the UI layer takes that list, asks the delegate to sign each, and publishes
  the re-issued generation.

That is a real piece of work, not a tweak. It also has to survive the seal:
today a fold that refuses everything still seals, so a re-issue that failed
half way would need to leave the migration unsealed rather than half-carried.

### Two complications worth knowing before starting

**An order's id changing breaks the buyer's pointer.** The buyer learns which
commitment is theirs from an `OrderAccepted` message naming an `OrderId`
(`ui/src/messaging.rs`). Re-issuing an order under a new id leaves that
pointer naming an order that no longer exists, and the buyer has no way to
find the replacement. Listings have no such problem. Either orders are exempt
— they expire after `MAX_ANCHOR_AGE_BLOCKS`, about eight hours, so a
predecessor generation's orders are unpayable anyway — or the re-issue has to
reach the buyer, which is a protocol question rather than a migration one.

**A payment proof survives an id change, which is not obvious.** An
`OnChainPaymentProof`'s claims bind to the `ScriptId` from
`Order::bitcoin_params()` — network, script, bridges, work floor — and not to
the order's id. So a re-issued `Paid` order keeps a valid proof. Worth knowing
so nobody assumes otherwise and exempts paid orders unnecessarily.

## Why accepting the old format in `verify` is NOT the answer

This is the obvious first idea. It is wrong, for two independent reasons, and
both are worth stating because the first one alone sounds surmountable.

**It reopens the hole the change closed.** The old `ListingId` covered
`(seller_fingerprint, created_at_ms, title)` and not the price. Accepting that
form means a seller can still mint two listings with one id at different
prices — and `apply_delta`'s first-writer-wins turns that into permanent,
unreconcilable divergence between peers. The whole point of the derivation
change was to make those two listings two listings.

**And it cannot be scoped to old data, because a contract has no history.**
The tempting patch is "accept the old form only for records that predate the
change". A contract validating state sees the state and its parameters, and
nothing else — no clock, no record of when anything was written, no
predecessor. It cannot distinguish a genuinely old record from a new one
shaped to look old. Any acceptance of the old form is acceptance for
everybody, forever.

A third, smaller reason: re-stamping inside the fold is also unavailable
without the owner's key, because the id is inside what the seller signed. That
is precisely why the fix above goes through the delegate.

## What is in place today

Not the fix — the disclosure, and the alarm.

* **The seller is told.** A discarded predecessor produces a notification
  naming the store, what specifically is gone, that this was **expected** as
  part of an upgrade, and that they need to republish
  (`migrate::describe_lost_store`). It drains in `migrate_ops::finish`
  *before* the nothing-was-recovered early return, which is the case it exists
  for. Pinned by `migrate::uncarried_tests`.
* **The next derivation change fails a test.**
  `listing::listing_identity_tests::the_listing_id_derivation_is_pinned` and
  `payment::order_identity_tests::the_order_id_derivation_is_pinned` are
  known-answer tests over each derivation's output. Their doc comments carry
  this argument and say that updating the constant is the last step, not the
  first.
* **A first attempt at that pin did not work**, and the failure is instructive:
  it built a record with a hard-coded *old* id, which is refused whatever the
  derivation is, so simulating a future change failed zero tests. A fixture
  that pins the old algorithm cannot detect a change to the current one. Only
  a fixture that depends on the current derivation's own output fires.

## The rule, for someone about to change a derivation

If the change makes previously-published records unverifiable:

1. It is a data-breaking change. Say so in the PR.
2. Either build the re-issue path above, or establish that no published
   generation holds data anyone would miss — and record who established it.
3. If the answer is "the data goes", the person who loses it must be told in
   the app, in language that says the loss was expected rather than that
   something broke.

Tonight the answer was (2), decided by Ian on 2026-09-06: no published store
held data worth preserving, sellers republish. That answer does not survive
Harvest having users.
