# Making a buyer's conversation survive the tab — PROPOSAL

**Status: proposal. Nothing here is implemented.** Written 2026-09-05 on
`feat/messaging`, at `ee0f41f`.

## The problem, stated at its cost

A buyer's conversation keys live in the browser tab and nowhere else. Close the
tab and they are gone; the ciphertext stays in the seller's mailbox and becomes
unreadable by anyone, including the buyer who wrote it.

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
commitment. Every secret the harvest delegate holds today is keyed by ghostkey
fingerprint, so this is a genuinely new shape for it.

## The proposal

### What the key is

```
harvest:buyer_conv:{store_id_b58}:{ephemeral_pub_b58}
```

Identity-free, and both halves are recoverable after a reload:

* **The store id** comes from the URL. `store_link::open_store_from_url()` is
  how a buyer reaches a store at all, so a buyer returning to a conversation is
  by definition returning to a link that carries it.
* **The ephemeral public key** is the conversation's routing tag, which is what
  every message in the conversation carries in the clear. So a recovered secret
  can be matched against what is actually in the mailbox.

Recovery: reopen the store link, ask the delegate to list secrets under
`harvest:buyer_conv:{store_id}:` (`SecretStore::list_secrets(prefix)` already
exists), derive both direction keys from each, read the mailbox. A stored
conversation whose tag is absent from the mailbox simply yields nothing.

**Why not the order id**, which was the other candidate: an order does not
exist when the first message is sent. The seller issues invoices
(`AppState::issue_invoice`), so at the moment the secret must be stored there
is nothing to key by. Order id becomes a useful SECONDARY index later, once
orders exist, for deciding which conversations are resolved — see discard,
below.

### What is stored

A fixed-size record: the 32-byte X25519 secret, the 32-byte conversation id,
an 8-byte creation timestamp. No variable-length field.

The secret rather than the two derived keys: half the bytes, and it is the
canonical value the keys come from.

This requires a change to existing code and its documentation.
`BuyerConversation::open` currently **discards** the ephemeral secret, and its
doc says that is deliberate — "keeping the secret would only widen what a leak
costs". Persistence requires keeping it, so that comment must be corrected
rather than quietly falsified.

### What bounds it

**256 records per node, evicting oldest-first by creation time.**

The repository's count-cap-over-contract-controlled-values pattern does **not**
apply here, and the reason is the whole point of that pattern: it bites when a
count caps entries whose values are *contract-controlled and variable* — the
mailbox case, where `ciphertext` was attacker-supplied and unbounded. Here
every field is fixed-width and client-generated, so a count cap **is** a byte
bound: 256 × ~72 bytes plus envelope, a few tens of KiB worst case.

A count cap is still required, because a page can open conversations in a
loop. Eviction rather than refusal: refusing would mean the conversation the
buyer is having *right now* is the one that cannot be saved.

### When one is discarded, and what going wrong in each direction costs

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

The natural refinement, once orders exist: evict oldest **among conversations
whose order is resolved**, falling back to plain oldest. Not proposed now,
because inventing a resolved-ness concept ahead of the orders work would be
guessing at its shape.

### Cross-device recovery: NO

The secret is in one node's delegate. A buyer who messages from a laptop and
later opens the store on a phone has a different node, a different delegate,
and ciphertext nobody can read. **This is a hard limitation of storing the
secret node-side and it does not have a fix within this design.**

It belongs in the documentation beside the write race, and it does not
disappear by being unwelcome: a buyer who changes device loses recourse exactly
as a buyer who closed a tab does today.

A **recovery string** — the 32-byte secret, base58, shown once for the buyer to
save — would close it, and is roughly forty lines. It is deliberately not part
of this proposal: it changes what a buyer is *asked to do*, which is a product
decision rather than an implementation one, and it introduces a secret the
buyer can paste into the wrong place.

## Two consequences to weigh before building

**A durable local record of who this node messaged.** "This node has a
conversation with store X" now persists, where before it did not. It is on the
buyer's own node, in the delegate's secret store, reachable only by the Harvest
webapp — but a buyer's pseudonymity gains a local artefact, and a node
inspected or seized reveals which stores its owner contacted. The trade is
worth making, because losing recourse is worse, but it is a trade and belongs
in `messaging-privacy.md` rather than being discovered later.

**The migration export grows.** These records sit under `harvest:`, so a
delegate re-key carries them — which is necessary, since otherwise a re-key
destroys every buyer's recourse. It means export size now scales with
conversations rather than being roughly constant.

## Shape of the change

Three request families on the harvest delegate, behind the same
`origin::authorize` gate every other family passes through:

* store a buyer conversation for a store,
* list the conversations stored for a store,
* forget one.

The cap belongs **in the delegate**, not in the UI. A cap enforced by the
caller is not a cap.

Plus, on the UI side: the recovery path on load, and `authored_here`'s local
record surviving alongside so that attribution still distinguishes what this
browser wrote (see `messaging::Addressing` for why that distinction is not
optional).
