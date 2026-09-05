//! Bitcoin payment types for Harvest orders.
//!
//! # Where the trust boundaries fall
//!
//! An [`Order`] is **shared marketplace state**. It lives in the seller's
//! store contract and is public, because decentralized payment verification
//! requires everyone to agree on what was owed and where it was to be paid.
//! That is a very different thing from a user's private list of addresses they
//! happen to be interested in, which never appears in any contract at all —
//! see the Harvest delegate.
//!
//! # How an order becomes Paid
//!
//! Not by the seller's say-so, and not by the buyer's. The transition carries
//! an [`OrderPaymentProof`]: the actual bridge-signed Bitcoin observations,
//! plus a bridge-signed chain tip to measure confirmations against. Any peer
//! can verify it, so any peer can submit it — the buyer's own client normally
//! does.
//!
//! # What the proof is trusted for
//!
//! **The bridges named in the order are trusted for chain state.** They assert
//! which blocks are on Bitcoin, what height each is at, and where the tip is,
//! and nothing in this verification checks any of that against the network.
//! Confirmation depth is arithmetic over two of those assertions — the claim's
//! `anchor.height` and the signed tip's height. A holder of a trusted bridge
//! key can therefore settle an order that was never paid, which is why the
//! trusted-bridge list is part of what the seller signs and why the UI flags
//! bridges the build does not recognise.
//!
//! The SPV evidence inside each claim is still doing real work: it fixes the
//! amount and the destination out of the transaction the txid commits to, and
//! the claim is bound to this order's script and network. So a bridge cannot
//! misreport what a real transaction paid, or to whom, and cannot repoint
//! somebody else's payment at this order. That is defence in depth against a
//! lying bridge, not a substitute for trusting one — see
//! `freenet_bitcoin_common::spv` for the boundary in full.
//!
//! ## Why the proof is embedded rather than fetched
//!
//! Harvest *does* use Freenet's related-contract mechanism to reach the
//! `BitcoinAddressContract` (see the store contract's `validate_state`), but
//! the authoritative gate is the embedded proof, and that is deliberate.
//!
//! A contract's verdict has to be a pure function of its own inputs, or
//! replicas that evaluate it at different moments reach different answers and
//! never converge. Related state is not under this contract's control: a peer
//! whose copy of the Bitcoin contract has not caught up yet would judge a
//! perfectly good order invalid. Embedding the signed claims makes validity
//! self-contained and monotonic — once a proof verifies it verifies forever,
//! on every peer, regardless of replication timing.
//!
//! The related contract is therefore used for **discovery and
//! cross-checking**, never as the thing that can make existing state invalid.
//!
//! ### What embedding costs
//!
//! Self-containment cuts both ways: the evidence a verifier sees is the
//! evidence the *submitter chose to send*, and no check inside a pure function
//! can distinguish a complete claim set from a curated one. That is a real,
//! currently-open gap, written up on [`OnChainPaymentProof`] along with why it
//! cannot be closed here and what would close it.
//!
//! ## What happens if the payment is later reorged out
//!
//! Nothing retroactively invalidates the order, because that would mean state
//! flipping from valid to invalid and replicas disagreeing about which. The
//! reorg is instead expressed as a *further* transition, [`OrderStatus::PaymentReversed`],
//! carried by its own evidence at a higher chain height. Status only ever
//! moves forward, which is what keeps the merge monotonic.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::{
    fold_outpoint_status, BitcoinAddressParameters, BitcoinNetwork, BridgeId, Claim,
    OutpointStatus, SignedClaim, SignedTipEntry,
};
use serde::{Deserialize, Serialize};

use crate::listing::ListingId;

/// Unique order identifier: first 16 bytes of
/// `BLAKE3(seller_fingerprint || listing_id || created_at_ms || buyer_fingerprint)`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct OrderId(pub [u8; 16]);

impl OrderId {
    pub fn new(
        seller_fingerprint: &str,
        listing_id: &ListingId,
        created_at: &DateTime<Utc>,
        buyer_fingerprint: &str,
    ) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"harvest/order-id/v1");
        h.update(seller_fingerprint.as_bytes());
        h.update(&listing_id.0);
        h.update(&created_at.timestamp_millis().to_le_bytes());
        h.update(buyer_fingerprint.as_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&h.finalize().as_bytes()[..16]);
        Self(id)
    }

    /// Short, human-quotable form for the UI ("Order 3xK9…").
    pub fn short(&self) -> String {
        bs58::encode(&self.0[..4]).into_string()
    }
}

impl std::fmt::Display for OrderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

/// Where an order stands. Transitions only ever move forward.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum OrderStatus {
    /// Created; the buyer has not paid, or the payment is not yet visible.
    AwaitingPayment,
    /// A qualifying payment has been proven on chain.
    Paid,
    /// A previously-proven payment was reorged out of the chain.
    ///
    /// This exists so a reorg is a forward transition rather than a
    /// retroactive invalidation. Making the order *invalid* instead would mean
    /// a peer's verdict changing under it, which is precisely what stops
    /// replicas converging.
    PaymentReversed,
    /// Cancelled by the seller before payment.
    Cancelled,
}

impl OrderStatus {
    /// Rank used to keep status monotonic under merge. A merge takes the
    /// higher rank, so two peers that saw transitions in different orders
    /// still agree.
    ///
    /// # The invariant this ordering has to hold
    ///
    /// **No status a party can assert by signature may outrank one that is
    /// evidenced by Bitcoin.** Rank is permanent -- a merge never comes back
    /// down -- so whatever sits at the top is what the order says forever,
    /// and putting a self-signed status there hands one party a veto over the
    /// chain.
    ///
    /// There used to be a `Fulfilled` at rank 4, above `PaymentReversed`, and
    /// it was seller-signed. A seller could therefore bury a genuine reorg
    /// under a status they issued themselves, and a scammer could mark every
    /// order fulfilled and read as carrying no outstanding exposure at all --
    /// which is what the bond in `docs/design/incentive-mechanism.md` is
    /// measured against. It is deleted rather than demoted: below `Paid` it
    /// would be unreachable in practice, since it is only ever meaningful
    /// after payment, and a status that cannot survive its own merge is worse
    /// than no status.
    ///
    /// `Cancelled` is seller-signed too, but it outranks only
    /// `AwaitingPayment` and is beaten by `Paid`, so a payment always
    /// overrides a cancellation. That is the right direction.
    pub fn rank(self) -> u8 {
        match self {
            OrderStatus::AwaitingPayment => 0,
            OrderStatus::Cancelled => 1,
            OrderStatus::Paid => 2,
            OrderStatus::PaymentReversed => 3,
        }
    }
}

/// The immutable terms of an order, as agreed and published by the seller.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Order {
    pub id: OrderId,
    pub listing_id: ListingId,
    /// Ghostkey fingerprint of the buyer this invoice was issued to.
    pub buyer_fingerprint: String,
    pub seller_fingerprint: String,
    pub amount_sats: u64,
    pub network: BitcoinNetwork,
    /// Canonical `scriptPubKey` the payment must reach.
    ///
    /// Public, and necessarily so: without it no third party could verify the
    /// payment, which is the entire point. This is why it is not a privacy
    /// regression — it is application semantics requiring publication, not a
    /// watch list being leaked.
    pub payment_script_pubkey: Vec<u8>,
    /// Human-readable address form, carried for display only. Verification
    /// always uses `payment_script_pubkey`; several address encodings can
    /// denote the same script, and only the script appears on chain.
    pub payment_address: String,
    /// Confirmations required before this order counts as paid. On-chain only;
    /// a Lightning payment is final the moment the preimage exists.
    pub required_confirmations: u32,
    /// For a Lightning order, the invoice's payment hash.
    ///
    /// Public for the same reason a scriptPubKey is: without it nobody but the
    /// two parties could verify the payment, which defeats the purpose.
    /// `#[serde(default)]` so orders written before this field existed still
    /// decode.
    #[serde(default)]
    pub payment_hash: Option<[u8; 32]>,
    /// The Bitcoin bridges whose observations settle *this* invoice.
    ///
    /// # Why this is per-order and not a store parameter
    ///
    /// It used to be `StoreParameters::trusted_bitcoin_bridges`. A contract's
    /// parameters are hashed into its address, so that list was immutable for
    /// the store's whole life: a store created with an empty list could never
    /// accept an on-chain payment, ever, and a bridge that went away could
    /// never be replaced. Every store the UI creates was in exactly that
    /// state.
    ///
    /// Moving it to *mutable state* would have been worse. `OrdersV1::verify`
    /// re-checks every order against the list on every state validation, so
    /// rotating a mutable list would retroactively invalidate the entire
    /// historical order book — a peer's verdict changing under it, which is
    /// precisely what stops replicas converging.
    ///
    /// Per-order, both problems go away at once. An order is verified forever
    /// against the bridge set that was in force when the seller signed it, and
    /// a new order can name a new set. A bridge going dark costs the orders
    /// already open against it, not the store.
    ///
    /// # What authenticates it
    ///
    /// Nothing new. `AuthorizedOrder::verify_terms` checks a ghostkey-scoped
    /// seller signature over the CBOR of this whole struct, so the bridge set
    /// is signed by the same signature as the amount and the payment address.
    /// A buyer who accepts an invoice is accepting its bridges along with its
    /// price, which is why the UI shows them (see `OrderCard`).
    ///
    /// Empty means no payment can ever be proven — `verify_payment_proof`
    /// returns `NoTrustedBridges` outright — so an order that names no bridge
    /// fails closed rather than accepting an unattested claim.
    ///
    /// `#[serde(default)]` so orders written before this field existed still
    /// decode; they come back with no bridges, i.e. unpayable, which is the
    /// safe direction.
    #[serde(default)]
    pub trusted_bridges: Vec<BridgeId>,
    /// BLAKE3 hash of the `BitcoinAddressContract` WASM whose instance
    /// observes this order's payment address.
    ///
    /// Used only for the store contract's related-contract cross-check, which
    /// is additive-only (see that file's `validate_state`). The store contract
    /// never holds the Bitcoin contract's WASM, so it has to be told the hash;
    /// `None` simply skips the cross-check for this order and forfeits nothing
    /// else, since the embedded [`OrderPaymentProof`] stays authoritative
    /// either way.
    ///
    /// Per-order for the same reason as `trusted_bridges`: as a store
    /// parameter it was frozen at the store's address, so a rebuild of the
    /// Bitcoin contract could never be reflected.
    #[serde(default)]
    pub bitcoin_address_code_hash: Option<[u8; 32]>,
    pub created_at: DateTime<Utc>,
}

impl Order {
    /// Parameters of the `BitcoinAddressContract` that observes this order's
    /// payment destination.
    pub fn bitcoin_params(&self) -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: self.network,
            script_pubkey: self.payment_script_pubkey.clone(),
            trusted_bridges: self.trusted_bridges.clone(),
            // Derived from the network rather than carried in the order, so a
            // seller cannot weaken the work floor for their own invoices.
            pow_floor: self.network.default_pow_floor(),
        }
    }
}

/// Bridge-signed evidence that an order's payment reached the *chain*.
///
/// # KNOWN GAP: the claim set is chosen by whoever submits it
///
/// Everything below is checked: each claim carries a bridge signature over a
/// body naming this script and an `as_of` chain position, and the verifier
/// re-runs the same fold the address contract would. What is **not** checked,
/// and cannot be checked with the evidence this type carries, is whether the
/// set is *complete*.
///
/// A submitter who holds a bridge-signed confirmation from before a reorg and
/// the bridge-signed retraction that followed it can present the first and
/// omit the second. Every remaining check passes: the confirmation is
/// genuinely signed, genuinely about this script, and genuinely deep enough
/// against the supplied tip. The fold has nothing to fold it against, so the
/// order validates as `Paid` on a payment that is no longer on the chain.
///
/// The same omission runs in the other direction, and that one is worse
/// because `PaymentReversed` is permanent under merge. If a payment was
/// confirmed, reorged out, and then re-confirmed on the new chain, the bridge
/// has published three claims for that outpoint; a submitter can present the
/// first two and withhold the re-confirmation, and the fold then reads a live
/// payment as reversed. `verify_on_chain_proof` requires a reversal to show
/// confirmations covering the order that were themselves retracted, so this
/// is no longer reachable for an order that was never paid -- but for one
/// that WAS paid and survived a reorg, it still is. **That residual is real
/// and is not closed here**; see `verify_on_chain_proof` for exactly what the
/// precondition does and does not buy, and
/// `store::order_tests::a_withheld_reconfirmation_still_reads_as_a_reversal`
/// for the case pinned as a known gap.
///
/// ## Why it cannot be fixed inside this function
///
/// - **The contract may not consult the address contract as an authority.**
///   That is the convergence argument in this module's header, and it is not
///   negotiable: related state replicates on its own schedule, so gating on it
///   would let two peers holding byte-identical state disagree about whether
///   it is valid. The store contract does fetch it (`validate_state`), but
///   only ever to log a discrepancy.
/// - **It cannot be fixed in the merge either**, which is the tempting place,
///   since `merge_order` holds both records and could demand that a reversal's
///   claims be a superset of the `Paid` record's. That breaks convergence in
///   the other direction: a peer that already holds the `Paid` record would
///   reject what a peer holding only `AwaitingPayment` accepts, and the two
///   would never agree.
/// - **A freshness rule is unavailable.** A contract has no clock, so "this
///   tip is recent" is not a question it can ask.
///
/// ## The shape of the real fix
///
/// The missing ingredient is a bridge-signed **commitment to the complete
/// claim set**, which belongs upstream in `freenet-bitcoin` rather than here.
/// `Claim::ScannedTo` already means "I have published everything I found for
/// this script as of `as_of`" and carries no payload; giving it a root over
/// the digests of every claim the bridge holds for that script would make the
/// assertion checkable. Verification here would then require:
///
/// 1. a `ScannedTo` from a trusted bridge whose `as_of.height` is at least the
///    supplied tip's height -- so a current tip cannot be paired with a stale
///    claim set, which is precisely the split this attack relies on; and
/// 2. that recomputing the root over exactly the supplied claims reproduces
///    the signed one -- so omitting any claim is detectable.
///
/// That needs no change to this type's wire format, since `ScannedTo` travels
/// in `claims` like any other claim. It does not close everything: a submitter
/// can still present a matched stale pair (old tip AND old set), but then
/// depth is measured against the old tip, so a reorg shallower than
/// `required_confirmations` no longer suffices.
///
/// Until then, a party acting on `Paid` -- shipping goods, say -- should
/// cross-check the live `BitcoinAddressContract` in its own client rather than
/// trusting the embedded proof alone. That check is unavailable to the
/// contract but perfectly available to an application.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OnChainPaymentProof {
    /// The claims the submitter has chosen to present about the qualifying
    /// outpoints.
    ///
    /// The intent is the bridges' whole published history, not merely the
    /// favourable subset, because the verifier re-runs the same fold the
    /// address contract would and a fold given a curated subset reaches a more
    /// optimistic answer. But nothing here can tell a complete set from a
    /// curated one -- see this type's doc comment.
    ///
    /// Bounded on submission by [`MAX_PROOF_CLAIM_BYTES`] and, after
    /// deduplication, by [`MAX_PROOF_CLAIMS`]. Those bounds sit in tension
    /// with "whole published history": a payment script whose genuine history
    /// runs past 32 distinct claims has no representable proof, and the order
    /// against it cannot be settled. That is the intended trade -- a
    /// per-invoice script that busy is not a payment destination -- but it is
    /// a real edge, and it is the reason the cap is not tighter still.
    pub claims: Vec<SignedClaim>,
    /// A bridge-signed chain tip, so confirmation depth is itself attested
    /// rather than asserted by whoever submitted the proof.
    pub tip: SignedTipEntry,
}

/// Proof that an order was paid, by whichever rail carried the payment.
///
/// # Why this is an enum today rather than when Lightning arrives
///
/// A contract's state format is frozen at publish: changing it produces new
/// WASM, a new contract key, and orphaned state. Adding a second payment rail
/// later would therefore be a migration, not an edit. Shaping the type for it
/// now costs nothing and removes that migration from the future.
///
/// # The two rails verify very differently, and it is worth knowing how
///
/// **On-chain** payments are publicly observable, so proof is a set of
/// bridge-signed observations, each carrying SPV evidence a reader checks
/// against the transaction and the block headers. That check binds the amount
/// and destination to a real transaction; which blocks are on Bitcoin stays
/// the bridges' assertion.
///
/// **Lightning** payments are, by design, *not* publicly observable — there is
/// no on-chain record of a routed payment, so no bridge can watch for one and
/// the entire SPV apparatus has nothing to look at. What Lightning provides
/// instead is the **preimage**: the payer ends up holding `r` where
/// `SHA256(r) == payment_hash`. The order publishes the payment hash (exactly
/// where an on-chain order publishes its scriptPubKey) and the proof is `r`.
/// Verification is a single hash, with no bridge in the picture at all.
///
/// That makes the Lightning path *simpler* to verify, not harder, and it
/// sidesteps the watch-list privacy problem entirely since there is nothing to
/// watch. The genuinely hard part of Lightning is operational — a seller needs
/// an always-on node with inbound liquidity — and none of that difficulty
/// lives in this file.
///
/// ## What the preimage does and does not prove
///
/// It proves the invoice with that hash was settled. It does **not** identify
/// who paid, and the seller who issued the invoice knows `r` from the outset,
/// so a seller can always mark their own order paid. That asymmetry is
/// harmless here because it runs against the seller's own interest: the
/// dispute that actually matters is a seller falsely claiming they were *not*
/// paid, and the buyer refutes that by presenting `r`, which they could only
/// have obtained by settling the invoice.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum OrderPaymentProof {
    OnChain(OnChainPaymentProof),
    Lightning(LightningPaymentProof),
}

impl OrderPaymentProof {
    /// Convenience for the common on-chain case.
    pub fn on_chain(claims: Vec<SignedClaim>, tip: SignedTipEntry) -> Self {
        OrderPaymentProof::OnChain(OnChainPaymentProof { claims, tip })
    }
}

/// The preimage settling a Lightning invoice.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LightningPaymentProof {
    /// `r` such that `SHA256(r)` equals the order's `payment_hash`.
    pub preimage: [u8; 32],
}

/// Why a payment proof was rejected. Distinguished so the UI can say something
/// useful rather than "invalid".
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProofError {
    NoTrustedBridges,
    BadTip(String),
    BadClaim(String),
    /// The tip is for one network and the order for another.
    NetworkMismatch,
    /// The claims are about a script that is not this order's destination.
    WrongScript,
    /// Confirmed, but not deeply enough yet.
    InsufficientConfirmations {
        have: u32,
        need: u32,
    },
    /// Not enough value reached the script.
    InsufficientValue {
        have_sats: u64,
        need_sats: u64,
    },
    /// The most recent evidence says the payment is no longer on chain.
    Reversed,
    /// A Lightning proof was offered for an order that has no payment hash,
    /// or an on-chain proof for one that has no script.
    WrongRail,
    /// `SHA256(preimage)` does not equal the order's payment hash.
    PreimageMismatch,
    /// More distinct claims than [`MAX_PROOF_CLAIMS`], each of which would
    /// cost a signature verification.
    TooManyClaims {
        have: usize,
        cap: usize,
    },
    /// The submitted claims exceed [`MAX_PROOF_CLAIM_BYTES`].
    ClaimsTooLarge {
        have_bytes: usize,
        budget: usize,
    },
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::NoTrustedBridges => {
                write!(
                    f,
                    "this store trusts no Bitcoin bridge, so no payment can be proven"
                )
            }
            ProofError::BadTip(e) => write!(f, "chain tip evidence invalid: {e}"),
            ProofError::BadClaim(e) => write!(f, "payment evidence invalid: {e}"),
            ProofError::NetworkMismatch => write!(f, "evidence is for a different Bitcoin network"),
            ProofError::WrongScript => write!(f, "evidence is for a different payment address"),
            ProofError::InsufficientConfirmations { have, need } => {
                write!(f, "payment has {have} confirmations, needs {need}")
            }
            ProofError::InsufficientValue {
                have_sats,
                need_sats,
            } => {
                write!(
                    f,
                    "payment of {have_sats} sats is short of {need_sats} sats"
                )
            }
            ProofError::Reversed => write!(f, "the payment was reorganized off the chain"),
            ProofError::WrongRail => {
                write!(
                    f,
                    "the evidence is for a different payment method than the order"
                )
            }
            ProofError::PreimageMismatch => {
                write!(f, "the preimage does not settle this order's invoice")
            }
            ProofError::TooManyClaims { have, cap } => {
                write!(
                    f,
                    "payment evidence holds {have} distinct claims, cap is {cap}"
                )
            }
            ProofError::ClaimsTooLarge { have_bytes, budget } => {
                write!(
                    f,
                    "payment evidence is {have_bytes} bytes, budget is {budget}"
                )
            }
        }
    }
}

/// Verify that `proof` establishes payment of `order`.
///
/// This is the function the store contract runs, so it must be a pure function
/// of its arguments: no clock, no network, no ambient state. Everything it
/// needs is either in the order or in the proof — including which bridges to
/// believe, which the seller fixed when they signed the order.
pub fn verify_payment_proof(order: &Order, proof: &OrderPaymentProof) -> Result<u64, ProofError> {
    match proof {
        OrderPaymentProof::OnChain(p) => verify_on_chain_proof(order, p),
        OrderPaymentProof::Lightning(p) => verify_lightning_proof(order, p),
    }
}

/// Verify a Lightning payment: one hash, no bridge, no chain.
///
/// Note there is no confirmation depth to check. A settled Lightning payment
/// is final immediately; there is no reorg that can undo it, which is why
/// `required_confirmations` does not appear here.
pub fn verify_lightning_proof(
    order: &Order,
    proof: &LightningPaymentProof,
) -> Result<u64, ProofError> {
    let Some(expected) = order.payment_hash else {
        return Err(ProofError::WrongRail);
    };
    let got: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(proof.preimage);
        h.finalize().into()
    };
    if got != expected {
        return Err(ProofError::PreimageMismatch);
    }
    Ok(order.amount_sats)
}

/// Hard cap on the number of DISTINCT claims one payment proof may carry.
///
/// This is the bound on the expensive work: each distinct claim costs an
/// Ed25519 verification plus, for a `ConfirmedOutput`, full SPV verification
/// (SHA256d over a transaction of up to `MAX_RAW_TX` = 64 KB, a Merkle branch,
/// and up to 25 block headers). `OrdersV1::verify` re-runs every order's proof
/// on every state validation, and a store may hold `MAX_ORDERS` orders, so
/// this multiplies.
///
/// 32 is generous for what a legitimate proof needs. An order's payment script
/// is a destination for one invoice: it sees one payment, occasionally two,
/// plus whatever retraction/re-confirmation churn a reorg produces and one
/// `ScannedTo` per trusted bridge. The address contract's own set is capped at
/// `freenet_bitcoin_common::address_state::MAX_CLAIMS` = 512, but that cap is
/// sized for a REUSED address; a per-order script that needed 32 claims to
/// prove one payment is not a payment destination.
///
/// This counts distinct claims, not submitted ones, because it is the
/// signature verifications it exists to bound and duplicates never reach one.
/// `MAX_PROOF_CLAIM_BYTES` is what bounds the submitted vector.
pub const MAX_PROOF_CLAIMS: usize = 32;

/// Byte budget for a payment proof's claims, measured on their actual CBOR
/// encoding.
///
/// # Why a byte budget as well as a count
///
/// A count cap *reads* like a memory bound and is not one: claim size is set
/// by whoever made the Bitcoin transaction, not by us, and a single
/// `ConfirmedOutput` claim can carry a 64 KB raw transaction. The same
/// reasoning is written up at length on
/// `freenet_bitcoin_common::address_state::MAX_CLAIM_BYTES`, whose value this
/// matches deliberately: a proof is drawn from one address contract's claim
/// set, so it has no business being larger than that whole set.
///
/// It also does a job the count cap cannot. The count cap is applied to
/// *distinct* claims, so on its own it would let a submitter send an unbounded
/// vector of duplicates and pay only for the dedup. This budget bounds the
/// submitted vector, and therefore the dedup itself: at a floor of roughly 160
/// bytes for the smallest possible claim, it admits under ~1,700 submitted
/// claims, i.e. that many BLAKE3 hashes over small inputs, which is nothing
/// next to one signature verification.
pub const MAX_PROOF_CLAIM_BYTES: usize = 256 * 1024;

/// A claim's cost against [`MAX_PROOF_CLAIM_BYTES`], measured on the encoding
/// that actually travels rather than on the fields' logical sizes.
///
/// An unencodable claim is charged the maximum, so it is refused rather than
/// admitted for free.
fn claim_cost(claim: &SignedClaim) -> usize {
    crate::to_cbor(claim).map(|b| b.len()).unwrap_or(usize::MAX)
}

/// The distinct claims in `claims`, in submission order, keyed by
/// [`SignedClaim::digest`].
///
/// `digest` is a BLAKE3 over the bridge id, the signed body bytes and the
/// signature, so two claims share one only if they are byte-identical -- there
/// is no way to smuggle a differing claim past it.
fn distinct_claims(claims: &[SignedClaim]) -> Vec<&SignedClaim> {
    let mut seen = std::collections::BTreeSet::new();
    claims
        .iter()
        .filter(|c| seen.insert(c.digest()))
        .collect::<Vec<_>>()
}

fn verify_on_chain_proof(order: &Order, proof: &OnChainPaymentProof) -> Result<u64, ProofError> {
    if order.payment_script_pubkey.is_empty() {
        return Err(ProofError::WrongRail);
    }
    if order.trusted_bridges.is_empty() {
        return Err(ProofError::NoTrustedBridges);
    }

    // Bound the work BEFORE doing any crypto at all -- see
    // `MAX_PROOF_CLAIM_BYTES` and `MAX_PROOF_CLAIMS` for what each bounds and
    // why one of them is not enough on its own. The byte budget comes first
    // because everything after it, dedup included, is linear in the submitted
    // bytes.
    let mut submitted_bytes: usize = 0;
    for c in &proof.claims {
        submitted_bytes = submitted_bytes.saturating_add(claim_cost(c));
        if submitted_bytes > MAX_PROOF_CLAIM_BYTES {
            return Err(ProofError::ClaimsTooLarge {
                have_bytes: submitted_bytes,
                budget: MAX_PROOF_CLAIM_BYTES,
            });
        }
    }
    let distinct = distinct_claims(&proof.claims);
    if distinct.len() > MAX_PROOF_CLAIMS {
        return Err(ProofError::TooManyClaims {
            have: distinct.len(),
            cap: MAX_PROOF_CLAIMS,
        });
    }

    let tip_params = freenet_bitcoin_common::BitcoinTipParameters {
        network: order.network,
        trusted_bridges: order.trusted_bridges.clone(),
    };
    let tip = proof.tip.verify(&tip_params).map_err(ProofError::BadTip)?;
    if tip.network != order.network {
        return Err(ProofError::NetworkMismatch);
    }
    let tip_height = tip.anchor.height;

    let addr_params = order.bitcoin_params();
    let expected_script = addr_params.script_id();

    // Verify every DISTINCT claim's signature and that it is about THIS
    // script. A claim about some other address would otherwise let an
    // attacker prove payment with somebody else's transaction.
    //
    // Iterating `distinct_claims` rather than `proof.claims` is what keeps a
    // duplicate from ever reaching `SignedClaim::verify`: there is no path in
    // this function that verifies a claim outside this loop. A bridge's
    // claims are public, so anyone can harvest genuine ones and resubmit them
    // hundreds of times; each one costs an Ed25519 verify plus SHA256d over
    // up to 64 KB of transaction, and `OrdersV1::verify` re-runs the lot on
    // every single state validation, for up to `MAX_ORDERS` orders. Deduping
    // first makes a duplicate cost one BLAKE3 hash instead.
    let mut bodies = Vec::with_capacity(distinct.len());
    for c in distinct {
        let body = c.verify(&addr_params).map_err(ProofError::BadClaim)?;
        if body.script_id != expected_script {
            return Err(ProofError::WrongScript);
        }
        bodies.push(body);
    }

    // Re-run exactly the fold the address contract would: group by outpoint,
    // then defer to `fold_outpoint_status` itself rather than restating its
    // rule here. Broadly it is "highest `as_of` wins", but how it settles a
    // tie at equal height is upstream's to decide and has changed there, and a
    // second copy of the rule in this comment is a copy that goes stale
    // without anything failing.
    //
    // Note what this does and does not establish: given the full history it
    // reaches the address contract's own answer, but the history is whatever
    // the submitter supplied, and a withheld retraction is invisible here. See
    // `OnChainPaymentProof`'s doc comment.
    let mut by_outpoint: std::collections::BTreeMap<_, Vec<_>> = std::collections::BTreeMap::new();
    for b in &bodies {
        if let Some(op) = b.claim.outpoint() {
            by_outpoint.entry(op).or_default().push(b.clone());
        }
    }

    let mut confirmed_total: u64 = 0;
    let mut shallowest: Option<u32> = None;
    // Value this proof shows was confirmed at SOME point, whether or not it
    // still is. This is what distinguishes a reversal from an order that was
    // simply never paid: see the `Reversed` test below.
    let mut ever_confirmed_total: u64 = 0;
    // Whether any outpoint this proof shows as retracted was also shown
    // CONFIRMED by it. A retraction of something never confirmed -- a dust
    // sighting, an evicted mempool transaction -- reverses nothing.
    let mut retracted_a_confirmed_outpoint = false;

    for claims in by_outpoint.values() {
        // The value the proof attests this outpoint once held, if it holds a
        // confirmation for it at all. Taking the minimum across duplicates is
        // the conservative direction for a value that will be used to ADMIT a
        // reversal; in practice the choice is moot, because `SignedClaim::
        // verify` checks each `ConfirmedOutput` against an SPV proof binding
        // `value_sats` to that exact txid and vout, so two verified
        // confirmations of one outpoint cannot disagree about the value.
        let ever_confirmed: Option<u64> = claims
            .iter()
            .filter_map(|b| match &b.claim {
                Claim::ConfirmedOutput { value_sats, .. } => Some(*value_sats),
                _ => None,
            })
            .min();
        if let Some(v) = ever_confirmed {
            ever_confirmed_total = ever_confirmed_total.saturating_add(v);
        }

        match fold_outpoint_status(claims.iter()) {
            Some(OutpointStatus::Confirmed { value_sats, anchor }) => {
                let confs = freenet_bitcoin_common::confirmations(&anchor, tip_height);
                confirmed_total = confirmed_total.saturating_add(value_sats);
                shallowest = Some(shallowest.map_or(confs, |s: u32| s.min(confs)));
            }
            Some(OutpointStatus::Retracted) => {
                if ever_confirmed.is_some() {
                    retracted_a_confirmed_outpoint = true;
                }
            }
            // Mempool-only outputs never count toward a paid order.
            Some(OutpointStatus::Unconfirmed { .. }) | None => {}
        }
    }

    // A reversal is a reversal OF something, and all three of these have to
    // hold:
    //
    //   1. the proof shows this order was AT SOME POINT covered;
    //   2. a bridge has retracted one of the very outpoints that covered it;
    //   3. what is still confirmed no longer covers the order.
    //
    // (3) alone was the original test, and (3) alone is trivially true of
    // every order nobody has paid yet -- the current total is zero. Combined
    // with (2) in its weaker "any retraction at all" form, that made a
    // retraction of ANY output on this script sufficient evidence that a
    // payment which never happened had been undone. The order's payment
    // address is public in the store state, so an attacker could send dust to
    // it, or broadcast a low-fee transaction and let it be evicted, and
    // submit the resulting retraction. `PaymentReversed` outranks `Paid` and
    // merge is monotonic, so the order would then be poisoned permanently.
    //
    // (1) is measured over `ConfirmedOutput` claims only. A `MempoolOutput`
    // sighting is not a payment, and it is the cheap attacker-controlled
    // path: causing a confirmed output to be retracted needs a reorg, while
    // causing a mempool one to be retracted needs only a low fee.
    //
    // Testing (3) only for a total of zero was too narrow: an order paid
    // across two outpoints, one of which is later reorged out, is genuinely
    // reversed while the other outpoint's value is still confirmed -- and
    // that case used to surface as `InsufficientValue`. Which is precisely
    // why `AuthorizedOrder::verify` accepted `InsufficientValue` as evidence
    // of a reversal, and why an empty claim set (`InsufficientValue
    // { have: 0 }`, no bridge involved at all) could poison any order in the
    // store. Report the reversal here, so that arm can require the reversal
    // error itself.
    //
    // The `== 0` limb covers the degenerate zero-sats order. It no longer
    // admits a reversal on its own, because (1) and (2) still have to hold,
    // and (2) needs a genuine confirmed-then-retracted outpoint.
    let was_ever_covered = ever_confirmed_total >= order.amount_sats;
    let no_longer_covered = confirmed_total < order.amount_sats || confirmed_total == 0;
    if retracted_a_confirmed_outpoint && was_ever_covered && no_longer_covered {
        return Err(ProofError::Reversed);
    }
    if confirmed_total < order.amount_sats {
        return Err(ProofError::InsufficientValue {
            have_sats: confirmed_total,
            need_sats: order.amount_sats,
        });
    }
    let depth = shallowest.unwrap_or(0);
    if depth < order.required_confirmations {
        return Err(ProofError::InsufficientConfirmations {
            have: depth,
            need: order.required_confirmations,
        });
    }
    Ok(confirmed_total)
}

/// An order plus its current status, signed where a signature is meaningful.
///
/// The order *terms* are signed by the seller: only they may issue an invoice
/// against their own store. The `Paid` transition is not signed by anybody —
/// it is authorized by [`OrderPaymentProof`], which any peer can verify, so
/// neither party has to be taken at their word about payment.
///
/// The order's trusted bridges do have to be taken at their word about chain
/// state; see this module's docs.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedOrder {
    pub order: Order,
    /// CBOR `ScopedPayload` from the ghostkey delegate, over `order`.
    pub scoped_payload: Vec<u8>,
    /// Seller's Ed25519 signature over `scoped_payload`.
    pub signature: Vec<u8>,
    pub status: OrderStatus,
    /// Evidence for `Paid` / `PaymentReversed`. Absent while awaiting payment.
    pub payment_proof: Option<OrderPaymentProof>,
    /// Seller's signature over `(order.id, status)` for the transitions only
    /// the seller may make -- today just `Cancelled`.
    pub status_scoped_payload: Option<Vec<u8>>,
    pub status_signature: Option<Vec<u8>>,
}

impl AuthorizedOrder {
    /// Verify the order terms are genuinely the seller's.
    pub fn verify_terms(&self, seller_key: &VerifyingKey) -> Result<(), String> {
        crate::listing::verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            seller_key,
            &self.order,
        )
    }

    /// Which of the optional fields each status actually consults.
    ///
    /// # Do not give this match a wildcard arm
    ///
    /// It is exhaustive on purpose, and that is load-bearing rather than
    /// stylistic. A new status stops this compiling until somebody decides
    /// what it authorizes, and that decision is what
    /// [`Self::verify_unused_fields_absent`] enforces and what
    /// `store::merge_order`'s tie-break argument rests on: at an equal rank
    /// the only field an attacker may vary is one this table marks as used.
    ///
    /// This is only HALF the guard, and it is the half that fires on the less
    /// likely change. A struct grows a field more often than an enum grows a
    /// variant, and a new FIELD is caught by the `..`-free destructuring in
    /// [`Self::verify_unused_fields_absent`], not here. Neither half is
    /// sufficient alone; do not weaken either.
    ///
    /// A `_ => (false, false)` arm would compile, would silently pin the new
    /// status's own fields to absent, and would break the record it was added
    /// to describe. A `_ => (true, true)` arm would compile, would leave the
    /// new status's fields unchecked, and would hand the tie-break straight
    /// back to whoever wanted to win it -- see
    /// `store::order_tests::a_field_the_status_does_not_use_is_rejected` for
    /// what that costs. Both failures are silent; the compile error is the
    /// only thing that is not.
    fn fields_used(status: OrderStatus) -> (bool, bool) {
        match status {
            // Nothing is asserted yet, so nothing may be attached.
            OrderStatus::AwaitingPayment => (false, false),
            // The seller's signature over `(id, status)`, and nothing else.
            OrderStatus::Cancelled => (false, true),
            // Bitcoin evidence, and nothing else. `Cancelled` ranks BELOW
            // `Paid`, so a paid order never reaches `Cancelled` under merge
            // and a proof on one of these is not a record of anything.
            OrderStatus::Paid | OrderStatus::PaymentReversed => (true, false),
        }
    }

    /// Reject a record carrying evidence or authorization its status does not
    /// use.
    ///
    /// # Why an unchecked field is not harmless
    ///
    /// `verify`'s `Paid` arm never reads `status_scoped_payload` or
    /// `status_signature`, and its `AwaitingPayment` arm reads nothing at all.
    /// Left unchecked, those fields are bytes any third party may set on a
    /// record that still verifies — and `store::merge_order` breaks an
    /// equal-rank tie on the full CBOR encoding, keeping the smaller. In CBOR
    /// `None` is `0xf6` and *every* `Some(..)` here begins with an array
    /// header of `0x80..=0x9b`, so `Some(anything)` sorts BELOW `None`.
    ///
    /// A third party could therefore take a genuine `Paid` record, set
    /// `status_scoped_payload: Some(vec![])` — a field nothing reads — and
    /// permanently displace the honest record, because merge is a monotonic
    /// maximum. Nothing about the order changed; the attacker simply owns the
    /// copy every replica keeps.
    ///
    /// Pinning the unused fields to `None` closes that, and it is the reason
    /// `merge_order`'s soundness argument can talk about `payment_proof` as
    /// the only field an attacker may vary at an equal rank. Do not relax this
    /// without redoing that argument.
    ///
    /// Safe to add: both production constructors
    /// (`state::authorize_new_order` and the one in `gateway::store_ops`)
    /// already build `AwaitingPayment` with every optional field `None`, and
    /// `orders` did not exist in V1 — the only generation ever published — so
    /// no deployed state contains an order at all.
    fn verify_unused_fields_absent(&self) -> Result<(), String> {
        // Destructured WITHOUT `..`, and that is the point of writing it this
        // way. `fields_used` makes ADDING A STATUS a compile error; this makes
        // ADDING A FIELD one. Both are needed, and the second is the more
        // likely change: a struct grows a field far more often than an enum
        // grows a variant.
        //
        // Every binding below must be accounted for. `order`, `scoped_payload`
        // and `signature` are pinned by `verify_terms`, which has already run;
        // `status` selects the rules. The remaining three are the optional
        // ones this function exists to police. A new optional field arriving
        // here stops the crate compiling until somebody decides which statuses
        // consult it -- because if the answer is "none of them", it is an
        // unchecked field a third party may set on a record that still
        // verifies, and `store::merge_order` breaks an equal-rank tie on the
        // full CBOR encoding. That is not a hypothetical: it is exactly the
        // attack this function was added to close.
        //
        // Do NOT silence this with `..`. Doing so compiles, changes no
        // behaviour today, and quietly removes the only thing that will make
        // the next field's author think about it.
        let Self {
            order: _,
            scoped_payload: _,
            signature: _,
            status,
            payment_proof,
            status_scoped_payload,
            status_signature,
        } = self;

        let (uses_proof, uses_status_signature) = Self::fields_used(*status);
        if !uses_proof && payment_proof.is_some() {
            return Err(format!(
                "{status:?} carries payment evidence, which nothing checks for that status"
            ));
        }
        if !uses_status_signature && (status_scoped_payload.is_some() || status_signature.is_some())
        {
            return Err(format!(
                "{status:?} carries a status signature, which nothing checks for that status"
            ));
        }
        Ok(())
    }

    /// Verify the whole record: terms, and whatever authorizes the status.
    ///
    /// The bridges the payment evidence is judged against come from
    /// `self.order.trusted_bridges`, which `verify_terms` has just established
    /// is genuinely the seller's — so this needs no bridge argument and cannot
    /// be called with a set the seller did not sign for.
    pub fn verify(&self, seller_key: &VerifyingKey) -> Result<(), String> {
        self.verify_terms(seller_key)?;
        self.verify_unused_fields_absent()?;
        match self.status {
            OrderStatus::AwaitingPayment => Ok(()),
            OrderStatus::Paid => {
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "order marked Paid without payment evidence".to_string())?;
                verify_payment_proof(&self.order, proof)
                    .map(|_| ())
                    .map_err(|e| format!("payment proof rejected: {e}"))
            }
            OrderStatus::PaymentReversed => {
                // A reversal must be evidenced by a bridge-signed retraction,
                // and by nothing weaker.
                //
                // `PaymentReversed` outranks `Paid` and merge is a monotonic
                // maximum on rank, so this status is effectively permanent:
                // once a peer accepts it, no later proof of payment can ever
                // displace it. It is also, deliberately, unsigned -- evidenced
                // by Bitcoin rather than by authority -- so anyone who can read
                // the public order can submit one. Those two facts together
                // mean the evidence test here is the ONLY thing standing
                // between a public order and permanent poisoning.
                //
                // So it accepts `ProofError::Reversed` and nothing else.
                // Every other rejection means "this evidence does not
                // demonstrate payment", which is not the same claim as
                // "payment was demonstrated and then undone". An empty
                // `claims` vector fails with `InsufficientValue { have: 0 }`
                // and costs an attacker nothing to build; accepting that as a
                // reversal, as this once did, let anyone permanently poison
                // any order in any store. Absence of proof is not proof of
                // absence.
                //
                // `Reversed` requires the proof to show confirmations
                // covering the order that a trusted bridge has since
                // retracted -- see `verify_on_chain_proof`. A retraction on
                // its own is not enough, and neither is a retraction of dust
                // or of an evicted mempool sighting, because a reversal has
                // to be a reversal OF something.
                //
                // Residual, and it is NOT small -- tracked as the
                // selective-omission gap in the `OnChainPaymentProof` doc
                // comment. The submitter still picks which claims to show. So
                // for an order whose payment WAS confirmed, reorged out, and
                // re-confirmed on the new chain, a submitter can exhibit the
                // confirmation and the retraction while withholding the
                // re-confirmation; the precondition above is then satisfied
                // by genuine claims, and a live payment reads as reversed.
                // What the precondition removes is the case where no payment
                // ever happened at all, which needed no reorg and no
                // cooperation from anyone. Closing the rest needs a
                // bridge-signed commitment to the complete claim set, not a
                // change here.
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "reversal without evidence".to_string())?;
                match verify_payment_proof(&self.order, proof) {
                    Err(ProofError::Reversed) => Ok(()),
                    Ok(_) => Err("reversal claimed, but the evidence still proves payment".into()),
                    Err(e) => Err(format!("reversal evidence invalid: {e}")),
                }
            }
            OrderStatus::Cancelled => {
                let (sp, sig) = self
                    .status_scoped_payload
                    .as_ref()
                    .zip(self.status_signature.as_ref())
                    .ok_or_else(|| format!("{:?} requires the seller's signature", self.status))?;
                crate::listing::verify_scoped_signature(
                    sp,
                    sig,
                    seller_key,
                    &(self.order.id.clone(), self.status),
                )
            }
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    /// Who gets to assert a status.
    #[derive(PartialEq, Debug)]
    enum Authority {
        /// The order's initial state; nobody asserts it.
        Initial,
        /// A signature from the seller, and nothing else, makes it true.
        SellerSignature,
        /// Bridge-signed Bitcoin observations make it true, and any peer can
        /// check them.
        BitcoinEvidence,
    }

    /// The classification `AuthorizedOrder::verify` actually implements.
    ///
    /// Written as a `match` on purpose: adding a status to `OrderStatus`
    /// stops this compiling until somebody decides which side of the line it
    /// belongs on, which is the decision that was got wrong.
    fn authority(status: OrderStatus) -> Authority {
        match status {
            OrderStatus::AwaitingPayment => Authority::Initial,
            OrderStatus::Cancelled => Authority::SellerSignature,
            OrderStatus::Paid | OrderStatus::PaymentReversed => Authority::BitcoinEvidence,
        }
    }

    const ALL: [OrderStatus; 4] = [
        OrderStatus::AwaitingPayment,
        OrderStatus::Cancelled,
        OrderStatus::Paid,
        OrderStatus::PaymentReversed,
    ];

    /// Rank is a permanent, monotonic maximum under merge, so whichever
    /// status sits highest is what the order says forever. A status one party
    /// can assert with their own signature must therefore never outrank one
    /// evidenced by Bitcoin -- otherwise that party holds a veto over the
    /// chain.
    ///
    /// `Fulfilled` was seller-signed and sat at the very top, above
    /// `PaymentReversed`, so a seller could bury a genuine reorg under a
    /// status they issued themselves. It is deleted; this is what stops it
    /// (or anything like it) coming back.
    #[test]
    fn no_seller_signed_status_outranks_a_bitcoin_evidenced_one() {
        for signed in ALL
            .iter()
            .filter(|s| authority(**s) == Authority::SellerSignature)
        {
            for evidenced in ALL
                .iter()
                .filter(|s| authority(**s) == Authority::BitcoinEvidence)
            {
                assert!(
                    signed.rank() < evidenced.rank(),
                    "{signed:?} is asserted by the seller's own signature but outranks                      {evidenced:?}, which is evidenced by Bitcoin -- the seller can then                      bury the chain's verdict permanently"
                );
            }
        }
    }

    /// Ranks must be distinct, or merge's tie-break falls through to raw CBOR
    /// bytes between two statuses that mean different things.
    #[test]
    fn every_status_has_its_own_rank() {
        let mut ranks: Vec<u8> = ALL.iter().map(|s| s.rank()).collect();
        ranks.sort_unstable();
        let before = ranks.len();
        ranks.dedup();
        assert_eq!(ranks.len(), before, "two statuses share a rank");
    }

    /// Deleting a variant is a wire-format change, and the only safe way for
    /// it to fail is loudly.
    ///
    /// Ciborium encodes a fieldless variant as its NAME, not its index, so
    /// removing `Fulfilled` from the middle of the enum does not renumber
    /// `PaymentReversed` or `Cancelled` -- old bytes for those still mean
    /// what they always meant, and old bytes for `Fulfilled` fail to decode
    /// rather than silently becoming some other status. That distinction is
    /// the whole safety argument for the deletion, so it is pinned here.
    #[test]
    fn a_deleted_status_fails_to_decode_rather_than_becoming_another_one() {
        let fulfilled = crate::to_cbor(&"Fulfilled").unwrap();
        assert!(
            crate::from_cbor::<OrderStatus>(&fulfilled).is_err(),
            "an order written as Fulfilled must not decode as anything at all"
        );

        for status in ALL {
            let bytes = crate::to_cbor(&status).unwrap();
            assert_eq!(
                crate::from_cbor::<OrderStatus>(&bytes).unwrap(),
                status,
                "{status:?} must round-trip"
            );
            // The encoding is the variant's name. If this ever became an
            // index, deleting a variant would silently reinterpret every
            // status above it.
            assert_eq!(
                bytes,
                crate::to_cbor(&format!("{status:?}")).unwrap(),
                "{status:?} must encode as its own name"
            );
        }
    }
}

#[cfg(test)]
mod lightning_tests {
    use super::*;
    use freenet_bitcoin_common::BitcoinNetwork;

    fn sha256(b: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b);
        h.finalize().into()
    }

    fn lightning_order(payment_hash: Option<[u8; 32]>) -> Order {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let listing_id = ListingId::new("seller", &ts, "Widget");
        Order {
            id: OrderId::new("seller", &listing_id, &ts, "buyer"),
            listing_id,
            buyer_fingerprint: "buyer".into(),
            seller_fingerprint: "seller".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Bitcoin,
            // A Lightning order has no on-chain destination at all.
            payment_script_pubkey: Vec::new(),
            payment_address: String::new(),
            payment_hash,
            required_confirmations: 0,
            // Lightning needs no observer at all, which is exactly why these
            // tests pass an empty bridge set: a preimage settles the invoice
            // with no bridge in the picture.
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            created_at: ts,
        }
    }

    #[test]
    fn a_correct_preimage_settles_a_lightning_order() {
        let preimage = [42u8; 32];
        let order = lightning_order(Some(sha256(&preimage)));
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof { preimage });
        // No bridge is consulted: the trusted-bridge list is irrelevant here,
        // which is the point -- a Lightning payment needs no observer.
        assert_eq!(verify_payment_proof(&order, &proof).unwrap(), 50_000);
    }

    #[test]
    fn a_wrong_preimage_is_rejected() {
        let order = lightning_order(Some(sha256(&[42u8; 32])));
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [7u8; 32],
        });
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::PreimageMismatch)
        );
    }

    #[test]
    fn a_lightning_proof_cannot_settle_an_on_chain_order() {
        // Rails must not be interchangeable: presenting a preimage for an
        // order that expects an on-chain payment would otherwise be a way to
        // mark it paid with no payment at all.
        let mut order = lightning_order(None);
        order.payment_script_pubkey = vec![0x00, 0x14, 0xaa, 0xbb];
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [42u8; 32],
        });
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::WrongRail)
        );
    }

    #[test]
    fn an_on_chain_proof_cannot_settle_a_lightning_order() {
        let order = lightning_order(Some(sha256(&[1u8; 32])));
        let proof = OrderPaymentProof::on_chain(vec![], dummy_tip());
        assert_eq!(
            verify_payment_proof(&order, &proof),
            Err(ProofError::WrongRail)
        );
    }

    fn dummy_tip() -> SignedTipEntry {
        SignedTipEntry {
            body_cbor: Vec::new(),
            bridge: freenet_bitcoin_common::BridgeId([0u8; 32]),
            signature: Vec::new(),
        }
    }

    /// The wire format must be able to represent both rails, so that adding
    /// Lightning support later is a code change rather than a state migration.
    #[test]
    fn both_rails_round_trip_through_cbor() {
        let ln = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [9u8; 32],
        });
        let bytes = crate::to_cbor(&ln).unwrap();
        assert_eq!(crate::from_cbor::<OrderPaymentProof>(&bytes).unwrap(), ln);
    }

    /// An order written before `payment_hash` existed must still decode.
    #[test]
    fn orders_without_a_payment_hash_still_decode() {
        #[derive(serde::Serialize)]
        struct OldOrder {
            id: OrderId,
            listing_id: ListingId,
            buyer_fingerprint: String,
            seller_fingerprint: String,
            amount_sats: u64,
            network: BitcoinNetwork,
            payment_script_pubkey: Vec<u8>,
            payment_address: String,
            required_confirmations: u32,
            created_at: chrono::DateTime<chrono::Utc>,
        }
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let listing_id = ListingId::new("seller", &ts, "Widget");
        let old = OldOrder {
            id: OrderId::new("seller", &listing_id, &ts, "buyer"),
            listing_id,
            buyer_fingerprint: "buyer".into(),
            seller_fingerprint: "seller".into(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14],
            payment_address: "tb1q".into(),
            required_confirmations: 1,
            created_at: ts,
        };
        let bytes = crate::to_cbor(&old).unwrap();
        let decoded: Order = crate::from_cbor(&bytes).expect("old orders must still decode");
        assert_eq!(decoded.payment_hash, None);
    }
}
