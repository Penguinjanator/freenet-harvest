# Bitcoin integration — status and known gaps

What works, and — more usefully — what does not, including two pre-existing
Harvest gaps that block the full buyer-side scenario and are unrelated to
Bitcoin.

## Working

- Orders in the store contract, with a monotonic status lattice and merge laws
  asserted on exact bytes.
- `AwaitingPayment → Paid` gated on bridge-signed Bitcoin evidence that any
  peer re-verifies (raw transaction, Merkle branch, block-header work), not on
  anyone's say-so.
- The store contract reaches a paid order's `BitcoinAddressContract` through
  Freenet's real related-contract mechanism, respecting the one-round limit —
  as a strictly additive cross-check that can never make valid state invalid.
- A private watch list in the delegate, never written to any contract.
- A Payments UI that subscribes to contracts and updates live.
- The bridge is deployed and observing real signet payments.

## Blocking gaps for the full end-to-end scenario

### 1. A buyer cannot open another seller's store

`AppState::begin_browsing()` exists but **is never called** — no call sites.
There is no URL/query-param parsing anywhere in the UI, so there is no way to
open a store from a shared link. `StoreView` only ever renders a store created
in the same session.

The consequence for the Bitcoin scenario: the seller half works (create an
order, watch the payment, see it confirm), but *"Alice opens Harvest and sees
the payment request"* cannot happen, because Alice has no way to reach Bob's
store. This is a **pre-existing Harvest gap**, not something the Bitcoin work
introduced, and closing it means building link-consumption: parse an incoming
store id, `get_contract(&id, true)`, and extend the existing
`follow_reputation_link` pattern to also subscribe the mailbox and the address
contracts named by the store's orders.

`mailbox_to_store` has the same shape of problem: it is read but nothing ever
inserts into it, so mailbox updates are never routed.

### 2. No migration registry — this change re-keys the store contract

Adding `OrdersV1` to `StoreStateV1` changes the store contract's WASM, which
changes its code hash, which changes every store's contract key. Harvest has
**no `legacy_*.toml` registry** and has not adopted `freenet-migrate`. The only
migration mechanism that exists is `LEGACY_HARVEST_WEBAPP_CONTRACT_IDS`, which
covers the *webapp container* id and nothing else.

So any store published under the previous contract WASM is orphaned by this
change. Harvest's README describes the project as early scaffolding, so the
practical blast radius is probably zero today — but the gap should be closed
**before** anyone publishes stores they care about, because the fix is
mechanical beforehand and a data-loss incident afterwards. See the
`freenet-app-migration` skill.

## Smaller things found and fixed along the way

- **The delegate WASM did not link at all.** `rsa`'s `OsRng` pulls in
  `getrandom`, whose `custom` feature was enabled workspace-wide with no
  backend ever registered, so `cargo build --target wasm32-unknown-unknown -p
  harvest-delegate` failed at link time with `undefined symbol:
  __getrandom_custom` — at HEAD, before any Bitcoin work. Fixed by registering
  a backend over `freenet_stdlib::rand::rand_bytes`.
- **Updates were never actually live.** `on_contract_update` parsed
  `UpdateNotification` delta bytes as though they were full state. For any
  composable state the delta is a different wire shape, so every delta silently
  failed to parse and was dropped. Fixed by re-GETting full state on
  notification. This affected store and listing updates too, not just Bitcoin.

## Not done

- The bridge is loopback-only with open authorization. Public exposure needs
  Ghost Key auth, rate limiting, and a TLS route first.
- No canonical bridge URL is published, so first run defaults to the user's own
  machine.
- `freenet-bitcoin` is referenced by a **local path dependency**, so this branch
  will not build on another machine until that becomes a git or crates.io
  dependency.
- `ui/assets/harvest.css` imports Google Fonts, which the gateway CSP blocks —
  so production Harvest has been falling back to default fonts app-wide. Real,
  pre-existing, and outside this change's scope.
