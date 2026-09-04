# Bitcoin integration — status and known gaps

What works, and — more usefully — what does not, including pre-existing
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
- A buyer can open a seller's store from a share link: `begin_browsing()` is
  called from `store_link::open_store_from_url`, which parses a store id out of
  the page's hash or query string, GETs the contract, and reports a failure
  rather than sitting on "Loading store…" forever.
- `mailbox_to_store` is populated, by `AppState::register_store_mailbox`. Only
  for the user's own stores: the mapping comes from the delegate's
  `StoreRegistration`, and `StoreInfoV1` names a store's reputation contract
  but not its mailbox, so it cannot be recovered from contract state for a
  store being browsed as a buyer.

## Blocking gaps for the full end-to-end scenario

### 1. Every store the UI creates refuses every payment, permanently

`gateway::store_ops::create_store_contracts` builds `StoreParameters` with
`trusted_bitcoin_bridges: Vec::new()`. An empty list means
`verify_payment_proof` rejects with `NoTrustedBridges`, so **no order on that
store can ever validate as `Paid`** — which is the right fail-closed default,
and is fatal as a permanent one.

It is permanent because `trusted_bitcoin_bridges` is a *parameter*, and a
contract's key is `BLAKE3(BLAKE3(wasm) || parameters)`. Changing the trusted
bridge list changes the address, so it is not a setting a seller can edit
later — it is chosen once, at creation, and the UI chooses "none" every time.
There is no path in the UI that ever supplies a bridge id here, and the
Payments section's bridge configuration is delegate-side state that never
reaches store creation.

So the Bitcoin payment path is complete and verified in the contract, and
unreachable from any store this app creates. Closing it means deciding which
bridge a new store trusts at the moment it is created (and accepting that
changing that decision later means a new store).

### 2. A watch is recorded and nothing is ever asked to synchronize it

`WatchForm` builds a `WatchedPayment`, the delegate persists it and answers
`Ok`, and that is the end of it. No bridge is sent a `WatchRequest`, so
`contract_id` stays `None`, no `BitcoinAddressContract` is subscribed, and no
transaction can appear for a manually watched address.

Both places the request could be made are closed:

- **The delegate cannot.** `OutboundDelegateMsg` has no HTTP variant — the
  whole set is application messages, user input, context, and contract
  GET/PUT/UPDATE/SUBSCRIBE. A delegate has no outbound HTTP capability at all.
- **The page cannot, once published.** A webapp is served with `connect-src`
  limited to its own gateway, so `fetch` to a bridge URL is refused. This is
  the same refusal that turned the tip-contract id into a build-time constant
  (see `gateway::bitcoin_config`'s module docs). It works under `dx serve`,
  where no CSP applies, which is why `bitcoin_bridge_http` exists at all.

The UI now says so rather than showing "Waiting for bridge to sync…"
indefinitely (`state::WatchSyncStatus`). Actually closing it needs a route
from a published webapp to a bridge — a contract-mediated request queue, or a
gateway-side proxy — not a smaller change to either side.

Note this does **not** affect order-driven payment watching end to end: the
tip contract and any address contract whose id is already known are subscribed
over the gateway like any other contract, and that path works.

### 3. Buyer-seller messaging is not implemented

`messaging::encrypt_message`/`decrypt_message` have no callers outside their
own tests, and nothing sends anything to a mailbox contract. The missing piece
is the seller's X25519 public key: `StoreInfoV1` publishes a certificate and a
reputation contract id and no encryption key, so a buyer has nothing to derive
a conversation key against.

`MessageView` used to claim "Messages are end-to-end encrypted" while
discarding whatever was typed; it now says messaging is unavailable. The
mailbox contract itself is real and stores messages — nothing in this app can
put one there or read one back.

### 4. No migration registry — this change re-keys the store contract

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
- **The committed contract WASM matched no build of this source.** All four
  artifacts under `ui/public/contracts/` differed from a fresh build and
  carried 45/63/24/43 absolute `/home/...` paths from the machine that made
  them. Since the UI embeds them with `include_bytes!`, the deployed contract
  was not the reviewed source. Rebuilt reproducibly, and `ci.yml`'s
  `wasm-staleness` job now compares the committed bytes against a fresh build
  on every PR.
- **A store edit published before its state arrived was silently discarded.**
  The next version was computed as `local.version + 1` with "no local state"
  answering 1, which is reachable on any reload — so a seller could retype
  details into an empty-looking form and have the update dropped as stale by
  last-writer-wins while the UI reported success.

## Not done

- The bridge is loopback-only with open authorization. Public exposure needs
  Ghost Key auth, rate limiting, and a TLS route first.
- No canonical bridge URL is published, so first run defaults to the user's own
  machine.
- `ui/assets/harvest.css` imports Google Fonts, which the gateway CSP blocks —
  so production Harvest has been falling back to default fonts app-wide. Real,
  pre-existing, and outside this change's scope.
