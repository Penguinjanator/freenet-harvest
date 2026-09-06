# How a buyer's conversation survives the tab

**Status: built.** Written as a proposal on 2026-09-05 at `ee0f41f`, and
rewritten on the same day to describe what was actually built, on
`feat/messaging`. Where the built thing differs from the proposal, the
difference is called out rather than quietly edited away.

## The problem, stated at its cost

A buyer's conversation keys lived in the browser tab and nowhere else. Close
the tab and they were gone; the ciphertext stayed in the seller's mailbox and
became unreadable by anyone, including the buyer who wrote it.

Today that costs a conversation. Once the seller's reply carries a pre-signed
statement — the buyer's only capability to complain against the seller's bond,
since on-chain payment proof is public and authorizes nothing by itself — it
costs the buyer **all recourse**, silently, and they do not find out until they
need it.

So the secret has to outlive the tab.

## Constraint 1: there is no browser-side storage at all

Verified in `freenet-core` rather than inherited. `crates/core/src/server/
path_handlers/assets/shell.html:11`:

```html
<iframe id="app" sandbox="allow-scripts allow-forms allow-popups
        allow-popups-to-escape-sandbox allow-downloads allow-modals" ...>
```

No `allow-same-origin`, so the app document has an **opaque origin**. Two
independent pieces of evidence that this throws rather than degrading:

* freenet-core says so in prose — `shell_bridge.js:82`, "opaque origin, so
  localStorage throws and the per-user token can't be read".
* freenet-core **acts on it**: every `localStorage` access in
  `shell_bridge.js` is wrapped in `try { ... } catch (e) {}` with an in-memory
  fallback (`contractHasConsent`, `setContractConsent`, and the token path).
  Code written to survive a throw is stronger evidence than a comment
  asserting one.

**The constraint is broader than "localStorage".** An opaque origin denies
`sessionStorage`, IndexedDB and cookies by the same rule. There is no
browser-side option to weigh, so this is not a trade-off between storage
mechanisms — the delegate is the only durable store this application has.

## Constraint 2: the buyer has no identity

No ghostkey, no fingerprint, no account. Their Bitcoin payment is their whole
commitment. Every other secret the harvest delegate holds is keyed by ghostkey
fingerprint, so this is a genuinely new shape for it.

## What was built

### The key

```
harvest:buyer_conv:{store_id_b58}:{buyer_public_key_b58}
```

Identity-free, and both halves are recoverable after a reload:

* **The store id** comes from the URL. `store_link::open_store_from_url()` is
  how a buyer reaches a store at all, so a buyer returning to a conversation is
  by definition returning to a link that carries it.
* **The routing tag** is the buyer's ephemeral public key, which every message
  in the conversation carries in the clear, in both directions. So a recovered
  secret can be matched against what is actually in the mailbox.

The `:` terminator is load-bearing: it is not in the base58 alphabet, so one
store's prefix cannot be a prefix of another store's keys and a recall cannot
return a neighbouring store's conversations. Pinned by
`conversations_are_scoped_to_their_store`.

Recovery: reopen the store link, ask the delegate to list secrets under
`harvest:buyer_conv:{store_id}:`, derive both direction keys from each stored
secret, read the mailbox. A stored conversation whose tag is absent from the
mailbox simply yields nothing.

**Why not the order id**, which was the other candidate: an order does not
exist when the first message is sent. The seller issues invoices
(`AppState::issue_invoice`), so at the moment the secret must be stored there
is nothing to key by.

**A 32-byte store id is required, and a wrong length is refused.** The id is
base58-encoded into the key, so a caller-sized id would be a caller-sized key
— and then the cap below would bound entries while bounding no bytes, which is
exactly the count-cap-over-variable-values trap this codebase has been bitten
by. Pinned by `a_store_id_that_is_not_a_contract_id_is_refused`.

### What is stored

The 32-byte X25519 secret, the 32-byte seller public key the conversation was
opened against, the 32-byte conversation id, and an 8-byte creation timestamp.
No variable-length field.

**The seller public key is a deviation from the proposal**, which stored only
the secret, the conversation id and the timestamp. It is stored because recall
derives with THAT key rather than with one a caller supplies: a recall path
that took the peer key as an argument would be a Diffie-Hellman oracle against
every secret the node holds, reachable by anything that got past the origin
gate.

**There is no `buyer_public_key` field, and that is deliberate.** The routing
tag is the public half of the stored secret, so the delegate derives it. A
stored copy would be a second source for one value, and the two could disagree
— filing a conversation under a tag no message in the mailbox carries, which
nothing downstream could detect. Pinned across the crate boundary by
`the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries` (UI
side) and `a_stored_conversation_comes_back_with_usable_keys` (delegate side).

**The timestamp comes from the browser, not the delegate.**
`freenet_stdlib::time::now()` is a `MaybeUninit` transmute off wasm32
(`time.rs:7`), so a delegate that called it could not be exercised by `cargo
test` without undefined behaviour. The value orders nothing but the caller's
own records, so a skewed clock costs the caller an eviction of their own
choosing.

`BuyerConversation::open` used to **discard** the ephemeral secret, and its
doc said that was deliberate — "keeping the secret would only widen what a
leak costs". That comment is now corrected in place rather than quietly
falsified: the reasoning traded a small leak surface for the silent, total
loss of the buyer's recourse.

### What bounds it

**256 records per node, across every store, evicting oldest-first by creation
time.**

The repository's count-cap-over-contract-controlled-values pattern does **not**
apply here, and the reason is the whole point of that pattern: it bites when a
count caps entries whose values are *contract-controlled and variable* — the
mailbox case, where `ciphertext` was attacker-supplied and unbounded. Here the
value is three 32-byte arrays and an `i64`, and the KEY is bounded by the
32-byte store-id refusal above. So the count IS a byte bound: roughly 60 KiB
at the cap.

A count cap is still required, because a page can open conversations in a
loop. Eviction rather than refusal: refusing would mean the conversation the
buyer is having *right now* is the one that cannot be saved.

Two details that only show up once it is built:

* **An entry whose value does not decode is evicted first.** It recalls
  nothing, so discarding it costs nothing — and it still occupies a key, so
  something has to reclaim it or the cap slowly fills with rubbish.
* **Re-storing a conversation the delegate already holds evicts nothing.** The
  UI re-sends the same conversation whenever the buyer writes into a thread it
  already has, so without this a full store would shed one real conversation
  per message sent.

### When one is discarded

Two triggers, and deliberately no third:

1. **Cap eviction**, oldest-first.
2. **The buyer explicitly forgetting a conversation.**

**No age-based expiry.** That would repeat the mailbox TTL mistake at a higher
cost: the thing it discards is precisely the capability the buyer needs later,
and the buyer has no way to know when they will need it.

The two failure directions are not symmetric:

* **Discarded too early** — the confession becomes unreadable and the buyer has
  no recourse, with no error at any layer. This is the expensive direction, so
  the cap is set well above plausible use (a buyer messaging 256 distinct
  stores) and eviction is oldest-first rather than anything cleverer.
* **Kept forever** — a bounded store of a few tens of KiB, plus the durable
  local record discussed below. This is the cheap direction, which is why the
  bound is generous.

## "Forget" genuinely deletes, and that took finding

The first design keyed the record by store and tag, and the first
implementation could only ever EMPTY the value, because
`freenet_migrate::SecretStore` is `list`/`get`/`has`/`set` with no removal. That
made the privacy control a lie: emptying the value stops the conversation
being readable while leaving a key that says, durably, that this node held a
conversation with that store.

The intermediate answer was to key by an opaque slot number so the key said
nothing. That was abandoned once the platform was actually checked:

* `DelegateCtx::remove_secret` exists (freenet-stdlib 0.8.5,
  `delegate_host.rs:424`), reaching `__frnt__delegate__remove_secret`.
* The node implements it as a real deletion (freenet-core
  `wasm_runtime/secrets_store/store.rs::remove_secret`): it removes the
  encrypted blob, removes its snapshot history, drops the key from the
  persistent index, and de-registers the raw key from the enumeration registry
  that backs `list_secrets`.
* The host function has been registered since freenet-core `c61a5ca8d`
  (2026-02-11), so calling it does not add an import a deployed node cannot
  resolve.

So the delegate deletes, through a small crate-local `RemovableSecrets` trait
that carries the one capability `SecretStore` lacks. It then **re-reads the key
and reports a failure if it is still there**, because a buyer stops being
careful on the strength of a control like this. The UI drops the conversation
from view only when the delegate says the record is gone; a refused removal
leaves the thread on screen and says so.

**What is NOT verified here:** that the node performs the deletion. Every
`DelegateCtx` secret method is a `false`-returning stub off wasm32, so the
tests drive an in-memory stand-in. What they state is that this crate asks for
removal and reports honestly on the answer. The node's own behaviour is read
from its source, cited above, and would need `tests/rehearsal/` and a live node
to observe.

## Cross-device recovery: NO

The secret is in one node's delegate. A buyer who messages from a laptop and
later opens the store on a phone has a different node, a different delegate,
and ciphertext nobody can read. **This is a hard limitation of storing the
secret node-side and it does not have a fix within this design.**

It is on screen rather than left to be discovered: the compose box, the
thread, the "kept on this device" panel and the seller's reply box all say that
the conversation does not follow the buyer to another device.

A **recovery string** — the 32-byte secret, base58, shown once for the buyer to
save — would close it, and is roughly forty lines. It is deliberately not part
of this change: it changes what a buyer is *asked to do*, which is a product
decision rather than an implementation one, and it introduces a secret the
buyer can paste into the wrong place.

## Two consequences that were weighed, and stand

**A durable local record of who this node messaged.** "This node has a
conversation with store X" now persists, where before it did not. It is on the
buyer's own node, in the delegate's secret store (encrypted at rest by the
node), reachable only by the Harvest webapp — but a buyer's pseudonymity gains
a local artefact, and a node inspected or seized reveals which stores its owner
contacted. The trade is worth making, because losing recourse is worse, and it
is why "forget this conversation" exists and why it had to be a real deletion.
Also recorded in `messaging-privacy.md`.

**The migration export grows.** These records sit under `harvest:`, so a
delegate re-key carries them — which is necessary, since otherwise a re-key
destroys every buyer's recourse. It means export size now scales with
conversations rather than being roughly constant. Pinned by
`buyer_conversations_are_under_the_exported_prefix`.

## The shape of the change, as built

Three request families on the harvest delegate, behind the same
`origin::authorize` gate every other family passes through:
`StoreBuyerConversation`, `ListBuyerConversations`, `ForgetBuyerConversation`.
The cap is **in the delegate**, not the UI: a cap enforced by the caller is not
a cap.

On the UI side:

* `BuyerConversation` keeps its ephemeral secret, and
  `AppState::compose_to_seller` asks the delegate to keep it on the path that
  opens the conversation — not left to a caller to remember.
* `BrowsingStore::conversations` is a list, oldest first. Every one of them is
  read, so a reply to a question asked last week is still readable; the LAST is
  the one a new message continues, so a returning buyer resumes their thread
  rather than forking a second one beside it.
* Recall is issued when a store's state arrives, once per store — and NOT
  before the harvest delegate is registered, because `components::app` opens a
  store link before registering it. A store marked as asked on a request that
  was never sent would be a buyer whose conversations are never recalled.
  `recall_conversations_for_known_stores`, called when the delegate registers,
  covers the other ordering.
* A non-empty recall **re-subscribes to the seller's mailbox**. Browsing a
  storefront deliberately does not, since a subscription advertises a standing
  interest; a non-empty recall is exactly the evidence that this node has
  already written to that seller, so it tells the network nothing new.

## What this does not do

* **It does not persist `authored_here`.** The nonces of messages this tab
  sent are the only authorship this browser can establish, and they are not
  kept. After a reload the buyer's own messages are described by direction
  ("Addressed to the seller") rather than as "You, from this tab". Both are
  truthful; the second is less specific. What is at stake in this change is the
  ability to READ the thread, which is unaffected.
* **It does not close the race** where a buyer sends a first message before the
  recall answer arrives. They get a second conversation with the same store;
  the older one is still recalled and still readable, and the thread view shows
  both in time order.
* **It does not survive the buyer's node being replaced**, for the same reason
  cross-device recovery is impossible.
