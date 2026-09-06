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

"What the current tab sent" is recognised by a digest of the whole mailbox
entry, not by its nonce. The distinction is the subject of the next section
and it is not a detail: the nonce is public and the counterparty can put their
own words under it.

## The counterparty can DELETE a message you sent, and take its place

Found by review on 2026-09-05, demonstrated by execution, and **not fixed** —
what changed is that the client no longer mistakes the result for your own
words, and says out loud that it happened.

The mailbox keeps **one entry per nonce**: `MailboxStateV1::verify` rejects a
state holding a duplicate, and a summary is a set of nonces. The nonce is
public, the contract is open-write, and the counterparty holds the
conversation key. So they can take a message you sent, encrypt *different*
plaintext under the same key with the **same nonce**, date it one second
later, and submit it. `dedupe_by_nonce` keeps one of the two by a total order
over content, and every field in that order is theirs to choose.

Three things happen at once: your message is gone from a public contract, the
substitute reads as a normal message of the conversation, and — until this was
fixed — your own screen labelled it as something you wrote, because
`authored_here` matched on the nonce.

**Why no tiebreak fixes it.** The dedup rule must be a pure function of the
SET of messages, or two peers that saw them in different orders keep different
bytes forever. A function of the set has no notion of which arrived first, so
it cannot protect the incumbent. Ranking by content instead of timestamp only
changes the attacker's cost from "add one second" to "try a few ciphertexts
until one sorts first" — they choose the whole plaintext, so they win about
half of any comparison on the first attempt.

**What would actually close it.** The first answer written here was wrong and
is corrected rather than deleted, because the mistake is instructive: it said
to derive the nonce deterministically from the message (an SIV-style
construction), so that two different plaintexts could not share a nonce.

**That does not work, because nothing can enforce it.** The nonce is a field
the writer fills in, and the reader takes it from the entry
(`decrypt_message`, `ui/src/messaging.rs`). The contract cannot check a keyed
derivation — it has no key — and the reader checking it comes too late,
because the displacement already happened at the contract. An attacker who
holds the conversation key simply does not follow the derivation rule. A rule
only honest clients obey is not a defence against a dishonest one.

What WOULD close it is making the identity **the contract itself computes**:
key the summary, the delta, the duplicate check and the dedup on a hash of the
whole entry rather than on the writer's nonce. Two entries that differ in any
byte are then two entries; there is no collision to resolve, so there is
nothing to displace. It needs no key, so the contract can enforce it. It costs
a wire-format change to the summary and delta shape, and it is not attempted
here.

**What was done instead**, at the client, where first-hand knowledge lives:

* `authored_here` matches on `entry_digest` — every field of the entry — so a
  substitute is not credited to you. The counterparty cannot reproduce it
  without sending the identical message, which is not a substitution.
* `AppState::replaced_sent` reports a message whose **nonce is present with a
  different digest**: it arrived and was displaced. That is a different thing
  to tell someone than "not seen yet", and both are on screen. A nonce is 24
  random bytes, so this is never an accident.

It works in both directions. A buyer can put a confession in a seller's own
inbox under the seller's nonce; the seller's screen showed it as their own
words until this was fixed, and now shows their reply as replaced.

## A deliberate nonce collision is also AES-GCM nonce reuse

The same act reuses an AES-GCM (key, nonce) pair across two different
plaintexts, which is a cryptographic problem in its own right and not only a
UX one. Pinned as an executable fact by
`known_limit_a_nonce_collision_reuses_the_keystream`, which asserts
`C1 xor C2 == P1 xor P2`.

Who it exposes what to:

* **Not the counterparty.** They hold the conversation key, so they could
  already read and write everything in that conversation. The reuse gives them
  nothing new — which is why it is not a way *in*.
* **A third party watching the mailbox** sees both entries (the original is
  public until the substitute displaces it) and learns `P1 xor P2` **without
  any key**. The substitute's plaintext is attacker-chosen, so anyone who
  knows or guesses it recovers your original message. `pad_to_bucket` puts
  both in the same size bucket, so the xor typically covers the whole message.
* **A third party who obtains either plaintext** recovers the keystream for
  that nonce; the repeated-nonce pair additionally permits GHASH-subkey
  recovery, so they can forge further entries under that nonce without holding
  the key. They cannot decrypt anything under a different nonce.

**How much this actually matters, stated after a second look.** Every path
requires a key holder to create the collision deliberately — and a key holder
can already decrypt the buyer's message and publish the plaintext directly.
So the xor leak grants the counterparty nothing they lack; it is a more
deniable route to a disclosure they could make anyway. The one genuinely
additional capability is narrow: recovering the GHASH subkey lets them hand a
third party the ability to FORGE entries in that conversation without handing
over the ability to READ it. In a two-party conversation whose counterparty
can already forge anything, that is exotic.

An earlier version of this section stopped at "a third party learns `P1 xor
P2` without any key", which is true and, on its own, overstates the
consequence. It is recorded here in corrected form rather than quietly
rewritten.

**And it is not closable at this layer.** A deterministic nonce would stop
honest clients colliding, which they were never going to do with 24 random
bytes; it does nothing about a key holder who chooses to collide, for the same
reason it does nothing about displacement. Nothing short of removing the
counterparty's key removes this, and the counterparty must hold the key to
read replies at all.

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

## What the byte budget costs — corrected

An earlier version of this section said the budget "makes a flood **cheaper
for the attacker**", that filling the count cap "took 512 contract updates"
against about 63 for the byte budget, and that the same eviction was available
"for an eighth of the updates".

**All of that was wrong, and measurement is what showed it.**

* A `MailboxDelta` is a bare `Vec<EncryptedMessage>` and `apply_delta` merges
  the whole vector, so neither route is a *number of contract updates*. Both
  are **one**.
* In the currency that actually costs — bytes on the wire — the byte-budget
  route is far more expensive:

| Route | Messages | Wire bytes | Honest survivors |
|---|---|---|---|
| Fill the count cap with the smallest messages | 512 | **124,883** | 0 |
| Fill the byte budget with the largest | 64 | **4,207,018** | 0 |

The count cap still binds first for small messages, so **the cheapest total
eviction is unchanged by the byte budget** — it was one ~122 KiB update before
this change and it still is. The budget conceded a downside it does not have.

What it does buy is a bound on what a flood costs everyone else: without it,
512 top-bucket entries were admissible and the mailbox had no size limit at
all.

The eviction ranking is unchanged and still grindable — `(timestamp, nonce)`,
both sender-chosen. Closing that needs admission control (payment,
proof-of-work, or a per-sender quota) and not a retuned cap. Pinned by
`known_gap_the_byte_budget_did_not_make_a_flood_cheaper`, which now measures
both routes so the prose cannot drift from the fixture again — that drift is
exactly how the wrong claim survived, because the test measured message COUNT
while its comment drew a conclusion about COST.

**One flood is also permanent, not a recurring cost.** Far-future timestamps
rank above all honest traffic for as long as they sit there, so a single
paid-for flood holds the mailbox indefinitely with no further spend.

## The one that limits the mechanism rather than leaking from it

**A buyer's conversation used to die with the browser tab, and no longer
does.** That paragraph stood here until 2026-09-05, when the harvest delegate
started keeping the buyer's per-conversation secret; the full design is in
`buyer-conversation-persistence.md`. The limitation it described was real and
sharp: if a seller's reply is later made to carry something the buyer *needs*
— an authorization, a receipt, a signed statement — then losing the key loses
that thing, silently, with the ciphertext still visibly present.

Two limits replace it, and one of them is a new privacy cost rather than a
leftover.

### The new cost: a durable local record of who this node messaged

The delegate now holds, per conversation, a secret keyed by store id and
routing tag. So "this node has a conversation with store X" **persists**,
where before it did not. It is on the buyer's own node, in the delegate's
secret store (encrypted at rest by the node), and reachable only by the
Harvest webapp — but a buyer's pseudonymity gains a local artefact, and a node
inspected or seized reveals which stores its owner contacted.

Nothing about this leaks to the network. It is a trade between two things the
buyer cares about, and it was made in the direction of recourse: losing the
key loses the ability to complain about a seller they paid, and that is worse.

**The buyer can undo it, and the control does what it says.** "Forget this
conversation" DELETES the record rather than emptying it. That distinction is
the whole point: emptying the value would stop the conversation being readable
while leaving a key that still names the store, so the control would be a lie.
The delegate re-reads the key afterwards and reports a failure rather than a
success it cannot stand behind, and the UI keeps the thread on screen until
the node says the record is gone. Forgetting cannot be undone: the messages
stay in the seller's mailbox and become unreadable by everyone, including the
buyer.

What is NOT verified from this repository is that the node performs the
deletion. `DelegateCtx::remove_secret` is a stub off wasm32, so the tests
drive an in-memory store; the node's own implementation is read from
freenet-core's source (`wasm_runtime/secrets_store/store.rs::remove_secret`,
which removes the blob, its snapshots, the index entry and the enumeration
registry entry). See `docs/untested-invariants.md`.

### The new surface: a backup is a portable capability

A buyer can now export their conversations with a store as a single string and
paste it into Harvest on another machine. That string holds the X25519 secrets
themselves, which is what makes it work — and what makes it worth exactly as
much as the conversations it restores. **Anyone holding it can read them, and
once a seller's reply carries a pre-signed statement, can file the complaint
that statement authorizes, as though they were the buyer.**

It is not a password. There is nothing to rotate: the secret IS the
conversation, so a leaked backup cannot be revoked, only forgotten — and
forgetting it makes the conversation unreadable to the buyer too.

Three things follow, and all three are on screen rather than in a doc:

* the string is shown only when asked for, and hidden again on request;
* what holding it means is stated beside it, before the buyer copies it,
  because that is the basis on which a person decides where to put it;
* a conversation with no copy anywhere else is **warned about**, and only the
  buyer saying they have saved it clears the warning. Exporting is not saving.

The warning's marker is gated to the Harvest web app for its own reason,
separate from the export's: silencing a warning costs the silencer nothing and
costs the buyer everything. See `buyer-conversation-persistence.md`.

**The export is per conversation**, so one string covers exactly one thread
with one seller -- the smallest blast radius available, and the granularity at
which the "saved elsewhere" marker means something checkable rather than
"some snapshot was taken at some point".

### The remaining limit: a different device is a different node

The secret is in ONE node's delegate. A buyer who writes from a laptop and
later opens the same store on a phone has a different node and ciphertext
nobody can read — **unless they carried a backup across**, which is what the
section above is for. Nothing happens by itself, and a buyer who saved nothing
is in the same position as one who closed the tab used to be.

It is said on screen before the buyer sends rather than left to be discovered
when they need the answer.

Automatic sync between a user's own peers would remove the step. Whether that
belongs in freenet-core or in each delegate is unsettled and is not attempted
here.
