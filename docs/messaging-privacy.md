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
* **Each message's padded size**, one of 1 KiB / 4 KiB / 16 KiB / 64 KiB (see
  the size note below, which is a real defect).
* **The conversation tag** (`sender_public_key`): the buyer's ephemeral X25519
  public key, carried on every message of that conversation **in both
  directions**. So an observer can group a mailbox into conversations, count
  the messages in each, and see the order they arrived in.
* **That an entry was written by the same party that wrote another entry in
  the same conversation** — the tag is shared, but the direction is not
  visible. An observer cannot tell a reply from a question by inspection, only
  by inference from timing.

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
buyer reading a mailbox of 512 entries all carrying their tag:

| Entry size | Per read |
|---|---|
| 1 KiB (a text message) | **3.4 ms** |
| 64 KiB (the largest padding bucket) | **193 ms** |

So the trial-decryption cost the tag saves is small in absolute terms, and the
tag is not buying much performance. What it *is* buying is that the common
case is bounded by the buyer's own conversation rather than by the mailbox —
which matters because the flood below is cheap to mount.

**Caveat on those numbers, stated because it is the half that could be wrong:**
they are native x86-64 with AES-NI. The UI runs on `wasm32-unknown-unknown`,
where the `aes` crate uses a constant-time software backend and no hardware
instruction. An attempt to force the software path with
`--cfg aes_force_soft` produced numbers within noise of the hardware ones,
which almost certainly means the flag did not take effect rather than that
the backends perform alike — so **the wasm cost is unmeasured**, and a 5-20x
multiple on the figures above would not be surprising. 3.4 ms is fine at any
plausible multiple; 193 ms is not obviously fine.

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

## A size bound that does not exist — found while writing this, NOT fixed here

`MailboxStateV1::verify` bounds the mailbox by **message count** and nothing
else. `pad_to_bucket` pads up to 64 KiB and then gives up:

```rust
.unwrap_or(len + 4) // if larger than all buckets, no padding
```

So a single message may be arbitrarily large, and 512 of them make the
mailbox's state arbitrarily large. Nothing in `harvest-common` caps it; the
only ceiling is the node's own maximum state size. This is the
"bounded by entry COUNT while holding contract-controlled values" shape that
freenet-core's own bug-prevention rules name, and the consequences are a
buyer's fetch cost, a seller's fetch cost, and the network's storage.

It is **not** fixed on this branch: adding a byte bound changes
`MailboxStateV1::verify`, which is contract behaviour, and a change that can
make an existing state invalid needs its own review and its own convergence
argument. Recorded here so it is a known open item rather than a discovery.

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
