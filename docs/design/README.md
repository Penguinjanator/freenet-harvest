# Harvest design documents

## Reading order

**[incentive-mechanism.md](incentive-mechanism.md) is the current design.** It is
the most recent and most complete of these documents, and where the two below
disagree with it, it wins. Start there.

It answers one question: how do you make fraud unprofitable in a marketplace with
no operator, no arbitration, no reversible payments, and no way to observe whether
a parcel arrived? The answer is a seller's *standing* — cumulative money burned by
donating to Freenet, bound to their ghostkey — against which complaints act as
withdrawals rather than as evidence about character.

The other two are earlier, longer treatments the explainer condenses. They are kept
because each still contains material the explainer cut for length:

- **[transaction-walkthrough.html](transaction-walkthrough.html)** — the Alice-and-Bob
  purchase in full, step by step, with what each party sees at each point.
- **[privacy-analysis.html](privacy-analysis.html)** — what the design publishes to
  the world, and what that means for real people. The transparency is load-bearing:
  it is what makes the exit-scam protection work, so it cannot be optimised away
  without giving up the protection.

## Relationship to the older documents

`../design.md` describes Harvest's overall shape — stores, listings, reputation,
mailboxes — and remains accurate for those. Its account of the *incentive mechanism*
is superseded: it describes buyer-authored feedback tokens with blind signatures,
which `incentive-mechanism.md` Part 3 shows fails in three independent ways.

GitHub issue #8 has the same problem. It was filed as the v1 epic but records the
superseded design, not this one.

## Two things the explainer says that are now out of date

**Lightning is not required.** The explainer states that proof of payment needs a
Lightning preimage, because "an on-chain Bitcoin payment produces no such secret".
That was true when it was written. Since then `freenet-bitcoin` has grown a working
SPV implementation — a pure function verifying a Bitcoin payment from the raw
transaction, a Merkle branch, and block-header proof-of-work. Combined with the
unique per-order address each order already gets, an on-chain payment now yields a
proof with the property the design needs: it cannot exist unless the buyer paid.

What is genuinely lost is that a preimage is *secret* while an on-chain proof is
*public*, so Lightning additionally protects against a leaked confession. That is a
narrower risk than the latency and fee costs of requiring Lightning for every sale.

**Order commitments must be identity-level, not per-store.** The explainer says
commitments go into "Alice's public record", which is right. The implementation puts
them in the per-store contract, and one ghostkey may create unlimited stores — so a
buyer counting a seller's outstanding orders sees a fraction of what the bond backs,
which defeats the exposure cap entirely.

**The block anchor can be backdated.** The explainer argues that a commitment cannot
be made to look old, "because looking old requires having published early, which is
exactly the behaviour being forced". This is wrong, and it matters, because the
complaint window rests on it. A block hash proves a commitment was signed *no earlier*
than that block — a lower bound only — and every past block hash is public. So a
seller can anchor a fresh commitment to an old block, have readers close it
immediately, and read zero exposure while taking orders.

Two rules neutralise it. A buyer pays only if the anchor is within about six blocks of
the tip. And a *paid* order takes its clock from the payment's own block height, which
comes from the SPV proof and cannot be forged; the anchor then governs only unpaid
orders, where backdating merely closes a phantom nobody paid for.

See issue #8 for the full contract topology this implies.
