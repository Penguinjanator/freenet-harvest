# What a watcher learns from Harvest messaging

Written 2026-09-05, alongside the reply path (`feat/messaging`). It records
what is **visible to anyone at all**, because the mailbox is a public contract
and nothing about reading it is privileged. It is not a threat model for the
marketplace as a whole; it covers the messaging mechanism only.

## The shape of the thing

One mailbox contract per store, addressed at
`BLAKE3(BLAKE3(mailbox_wasm) || cbor(MailboxParameters { owner_verifying_key }))`.
Open-write by necessity: a buyer must be able to reach a seller they have no
prior relationship with, so there is nobody to authenticate.

Each entry is `EncryptedMessage { conversation_id, sender_public_key,
ciphertext, timestamp, nonce }`. Only `ciphertext` is encrypted.
`conversation_id` is *inside* it and therefore not visible; everything else in
that struct is.

## Visible to anyone

* **That the store has a mailbox, and where.** Derived from the seller's
  ghostkey, which is published in the store's own details.
* **How many messages it holds**, up to `MAX_MESSAGES` (512).
* **When each arrived** — not from `timestamp`, which is unsigned and
  self-asserted, but from observing the contract change.
* **Each message's padded size**, one of 1 KiB / 4 KiB / 16 KiB / 64 KiB.
  Every message that lands has been padded to one of those; see the size-bound
  section below for why that is now true of all of them rather than only of
  those under 64 KiB.
* **The conversation tag** (`sender_public_key`): the buyer's ephemeral X25519
  public key, carried on every message of that conversation **in both
  directions**. So an observer can group a mailbox into conversations, count
  the messages in each, and see the order they arrived in.
* **That an entry was written by the same party that wrote another entry in
  the same conversation** — the tag is shared, but the direction is not
  visible. An observer cannot tell a reply from a question by inspection, only
  by inference from timing.

## Not forgeable, and it was

Every field of an entry except the ciphertext is authenticated as AES-GCM
associated data (`harvest_common::mailbox::message_aad`). Before that, only
the ciphertext was protected, and three things followed that a reader of this
document should know were once true:

* **Replay.** The mailbox dedupes on the full 24-byte nonce, but only the
  first 12 are the AES-GCM nonce. Randomising bytes 12..24 resubmitted the
  same ciphertext as a new message. Verified working.
* **Re-dating.** `timestamp` is the primary key of the eviction ranking, so a
  genuine message could be moved up or down the order that decides what
  survives a flood.
* **Re-tagging and re-labelling.** The routing tag and the cleartext
  conversation id could be edited freely.

None of these needed a key or any relationship with either party, because
anybody can read the mailbox and anybody can write to it.

## Authorship is NOT established by anything here

Direction separation stops a third party reflecting a copied message. It does
not, and cannot, stop the counterparty: both parties derive both direction
keys from the same symmetric Diffie-Hellman secret, because the buyer needs
the seller-to-buyer key in order to read replies at all. So either party can
encrypt in either direction, and a buyer can place a message in the seller's
mailbox that authenticates exactly as the seller's own reply would.

Only a per-message signature could distinguish two holders of one secret, and
that is a different mechanism from this one. **Anything whose authenticity
matters must carry its own signature and must not rest on which key decrypted
it.** The UI reports which direction a message was addressed, names only what
the current tab sent as authored, and says on screen that direction is not
proof of authorship.

## NOT visible

* **What was said.** AES-256-GCM under a key derived from an X25519 exchange
  the observer cannot perform.
* **Who the buyer is.** The tag is freshly random per conversation and is tied
  to no identity, no ghostkey, and no payment. Harvest gives a buyer no
  identity to leak.
* **Whether two conversations with the same store are the same buyer.** A
  fresh keypair per conversation is what buys this, and it is the property a
  reasonable-looking optimisation (one keypair per store, reused) would
  silently delete. Pinned by `each_conversation_carries_a_fresh_tag`.
* **Whether two conversations with *different* stores are the same buyer.**
  Same reason.

## The tag is a deliberate trade, and here is the other side of it

Echoing the buyer's key on the seller's replies is what lets a buyer find
their own thread cheaply. The alternative — a tag nobody can link — would hide
the thread structure but force the buyer to attempt decryption against every
entry in the mailbox.

Measured on this machine (x86-64, hardware AES, `--release`, 2026-09-05), a
buyer reading a mailbox filled to the enforced budget with entries all
carrying their tag:

| Mailbox | Per read |
|---|---|
| 512 entries at the 1 KiB bucket (632 KiB — the count cap binds) | **3.2 ms** |
| 63 entries at the top bucket (3.95 MiB — the byte budget binds) | **20.7 ms** |

Both are measured at the real cap, through the real pruning, rather than
extrapolated. The second figure was **193 ms** before `MAX_MAILBOX_BYTES`
existed, when 512 top-bucket entries were admissible; bounding the mailbox in
bytes bounds this too, which is the second reason the budget is worth having.

**Caveat on those numbers, stated because it is the half that could be wrong:**
they are native x86-64 with AES-NI. The UI runs on `wasm32-unknown-unknown`,
where the `aes` crate uses a constant-time software backend and no hardware
instruction. An attempt to force the software path with
`--cfg aes_force_soft` produced numbers within noise of the hardware ones,
which almost certainly means the flag did not take effect rather than that
the backends perform alike — so **the wasm cost is unmeasured**, and a 5-20x
multiple on the figures above would not be surprising. At that multiple 3.2 ms
stays comfortable and 20.7 ms becomes noticeable but not pathological; before
the byte budget, the same multiple on 193 ms would not have been survivable.

No timing assertion is committed anywhere. A wall-clock bound in CI is a flaky
test, and this repository treats a flaky test as a broken one.

## The flood, and what bounds it

The tag is in the clear, so **an attacker can read a buyer's tag out of the
mailbox and stamp it on entries of their own**. Those entries do not
authenticate — the AEAD is what decides, and the tag is only a fast path — but
they do force the buyer to attempt decryption. A full cap's worth is the worst
case, which is what the table above measures. `read` still returns the buyer's
real thread and nothing else; pinned by
`a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread`.

The same flood evicts the honest traffic, which is a pre-existing and
separately-pinned gap: see
`harvest_common::mailbox::known_gap_a_funded_flood_still_evicts_every_honest_message`.

## The size bound, and the shape of it

`MailboxStateV1::verify` bounds the mailbox by **message count** and nothing
else — a count cap over entries holding contract-controlled `ciphertext` and
`sender_public_key`, which reads like a memory bound and is not one. That was
found while writing this document and is now fixed, but the SHAPE of the fix
is the part worth recording.

**Pruning, not rejection.** `MAX_MAILBOX_BYTES` (4 MiB) is met by
`enforce_message_cap` dropping the lowest-ranked messages, exactly as the
count cap is. `verify` deliberately does **not** check it, and that is not an
oversight: mailboxes already on the network were produced by an honest
`apply_delta` under the old rules and may exceed the new budget, so a `verify`
that rejected them would make them permanently invalid — never convergeable
again, with no way back. This repository has already been bitten by exactly
that once, when a TTL check rejected a whole mailbox because one message had
aged out. Pruning can only ever produce a smaller valid state.

The count cap IS checked in `verify`, and the difference is worth stating: it
has been enforced since the mailbox existed, so no honest state was ever over
it. A cap added later has no such guarantee. Pinned by
`verify_accepts_an_over_budget_state_so_an_existing_mailbox_is_never_stranded`.

**One oversized message is refused on the way in.** Pruning keeps a prefix of
the ranking, so if the highest-ranked message did not fit, nothing behind it
would be reached and the mailbox would prune to nothing — and an attacker can
put their message at the top of that ranking for free, because timestamps are
unsigned. So `MAX_MESSAGE_BYTES` is set well below the total budget and
`apply_delta` drops anything over it. Refusing an incoming message is
recoverable; invalidating existing state is not.

**The residual:** between arriving and the next merge, a peer may hold an
over-budget state. Nothing here bounds that; the node's own maximum state size
does.

**And a cost this change also fixes:** `MAX_MESSAGE_BYTES` is exactly a full
top-bucket message, so a message built from data `pad_to_bucket` declined to
pad cannot fit. Every message a reader can see has therefore been padded, and
the size privacy the buckets claim now holds for everything rather than for
everything under 64 KiB.

## What the byte budget costs, honestly

It makes a flood **cheaper for the attacker** while bounding what the flood
costs everyone else. Filling the count cap took 512 contract updates; filling
the byte budget takes about 63. The eviction ranking is unchanged and still
grindable — `(timestamp, nonce)`, both sender-chosen — so the same total
eviction is now available for an eighth of the updates.

That is a deliberate trade rather than an oversight: unbounded state is the
worse of the two, and the flood was already affordable at 512 updates. It is
pinned by `known_gap_a_byte_budget_flood_evicts_with_far_fewer_messages` so
that closing it is understood to need admission control — payment,
proof-of-work, or a per-sender quota — rather than a retuned cap.

## The one that limits the mechanism rather than leaking from it

**A buyer's conversation does not survive a page reload.** The keys live in
the tab. There is no buyer delegate, and `localStorage` throws inside the
gateway's sandboxed iframe (no `allow-same-origin`), so there is nowhere
durable to put them. A buyer who reloads before the seller answers can never
read that reply: the ciphertext sits in the mailbox forever and the key is
gone.

This matters beyond convenience. If a seller's reply is later made to carry
something the buyer *needs* — an authorization, a receipt, a signed statement
— then losing the key loses that thing, silently, with the ciphertext still
visibly present. Any such use needs a durable buyer key first, and the options
(a recovery string the buyer saves, a passphrase-derived keypair, a buyer-side
delegate) are all design decisions this document does not make.
