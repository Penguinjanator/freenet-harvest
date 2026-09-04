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
//! Not by anybody's say-so. The transition carries an [`OrderPaymentProof`]:
//! the actual bridge-signed Bitcoin observations, plus a bridge-signed chain
//! tip to measure confirmations against. Any peer can verify it, so any peer
//! can submit it — the buyer's own client normally does.
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
    fold_outpoint_status, BitcoinAddressParameters, BitcoinNetwork, BridgeId, OutpointStatus,
    SignedClaim, SignedTipEntry,
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
    /// The seller has marked the order fulfilled.
    Fulfilled,
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
    pub fn rank(self) -> u8 {
        match self {
            OrderStatus::AwaitingPayment => 0,
            OrderStatus::Cancelled => 1,
            OrderStatus::Paid => 2,
            OrderStatus::PaymentReversed => 3,
            OrderStatus::Fulfilled => 4,
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
    pub created_at: DateTime<Utc>,
}

impl Order {
    /// Parameters of the `BitcoinAddressContract` that observes this order's
    /// payment destination.
    pub fn bitcoin_params(&self, trusted_bridges: Vec<BridgeId>) -> BitcoinAddressParameters {
        BitcoinAddressParameters {
            network: self.network,
            script_pubkey: self.payment_script_pubkey.clone(),
            trusted_bridges,
            // Derived from the network rather than carried in the order, so a
            // seller cannot weaken the work floor for their own invoices.
            pow_floor: self.network.default_pow_floor(),
        }
    }
}

/// Bridge-signed evidence that an order's payment reached the *chain*.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OnChainPaymentProof {
    /// Every claim the bridges have published about the qualifying outpoints,
    /// not merely the winning one.
    ///
    /// The whole history is required because a verifier re-runs the same fold
    /// the submitter did, and a fold given only the favourable subset would
    /// reach a different — and more optimistic — answer. Handing over just the
    /// confirmation while withholding a later retraction is exactly the attack
    /// this defends against.
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
/// against the transaction and the block headers.
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
        }
    }
}

/// Verify that `proof` establishes payment of `order`.
///
/// This is the function the store contract runs, so it must be a pure function
/// of its arguments: no clock, no network, no ambient state. Everything it
/// needs is either in the order, in the proof, or in the store's parameters.
pub fn verify_payment_proof(
    order: &Order,
    proof: &OrderPaymentProof,
    trusted_bridges: &[BridgeId],
) -> Result<u64, ProofError> {
    match proof {
        OrderPaymentProof::OnChain(p) => verify_on_chain_proof(order, p, trusted_bridges),
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

fn verify_on_chain_proof(
    order: &Order,
    proof: &OnChainPaymentProof,
    trusted_bridges: &[BridgeId],
) -> Result<u64, ProofError> {
    if order.payment_script_pubkey.is_empty() {
        return Err(ProofError::WrongRail);
    }
    if trusted_bridges.is_empty() {
        return Err(ProofError::NoTrustedBridges);
    }

    let tip_params = freenet_bitcoin_common::BitcoinTipParameters {
        network: order.network,
        trusted_bridges: trusted_bridges.to_vec(),
    };
    let tip = proof.tip.verify(&tip_params).map_err(ProofError::BadTip)?;
    if tip.network != order.network {
        return Err(ProofError::NetworkMismatch);
    }
    let tip_height = tip.anchor.height;

    let addr_params = order.bitcoin_params(trusted_bridges.to_vec());
    let expected_script = addr_params.script_id();

    // Verify every claim's signature and that it is about THIS script. A claim
    // about some other address would otherwise let an attacker prove payment
    // with somebody else's transaction.
    let mut bodies = Vec::with_capacity(proof.claims.len());
    for c in &proof.claims {
        let body = c.verify(&addr_params).map_err(ProofError::BadClaim)?;
        if body.script_id != expected_script {
            return Err(ProofError::WrongScript);
        }
        bodies.push(body);
    }

    // Re-run exactly the fold the address contract would: group by outpoint,
    // highest as_of wins. Feeding the full history in is what makes a
    // withheld retraction impossible to exploit.
    let mut by_outpoint: std::collections::BTreeMap<_, Vec<_>> = std::collections::BTreeMap::new();
    for b in &bodies {
        if let Some(op) = b.claim.outpoint() {
            by_outpoint.entry(op).or_default().push(b.clone());
        }
    }

    let mut confirmed_total: u64 = 0;
    let mut shallowest: Option<u32> = None;
    let mut saw_retraction = false;

    for claims in by_outpoint.values() {
        match fold_outpoint_status(claims.iter()) {
            Some(OutpointStatus::Confirmed { value_sats, anchor }) => {
                let confs = freenet_bitcoin_common::confirmations(&anchor, tip_height);
                confirmed_total = confirmed_total.saturating_add(value_sats);
                shallowest = Some(shallowest.map_or(confs, |s: u32| s.min(confs)));
            }
            Some(OutpointStatus::Retracted) => saw_retraction = true,
            // Mempool-only outputs never count toward a paid order.
            Some(OutpointStatus::Unconfirmed { .. }) | None => {}
        }
    }

    // What makes a reversal a reversal is a bridge-signed `Retracted` claim
    // PLUS a remaining total that no longer covers what the order is owed.
    //
    // Testing only for a total of zero was too narrow. An order paid across
    // two outpoints, one of which is later reorged out, is genuinely reversed
    // while the other outpoint's value is still confirmed -- and that case
    // used to surface as `InsufficientValue`. Which is precisely why
    // `AuthorizedOrder::verify` accepted `InsufficientValue` as evidence of a
    // reversal, and why an empty claim set (`InsufficientValue { have: 0 }`,
    // no bridge involved at all) could poison any order in the store. Report
    // the reversal here, so that arm can require the reversal error itself.
    //
    // The `== 0` limb only covers the degenerate zero-sats order, which
    // reached `Reversed` before this change and still does.
    if saw_retraction && (confirmed_total < order.amount_sats || confirmed_total == 0) {
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
/// nobody has to be trusted to report a payment honestly.
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
    /// the seller may make (`Fulfilled`, `Cancelled`).
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

    /// Verify the whole record: terms, and whatever authorizes the status.
    pub fn verify(
        &self,
        seller_key: &VerifyingKey,
        trusted_bridges: &[BridgeId],
    ) -> Result<(), String> {
        self.verify_terms(seller_key)?;
        match self.status {
            OrderStatus::AwaitingPayment => Ok(()),
            OrderStatus::Paid => {
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "order marked Paid without payment evidence".to_string())?;
                verify_payment_proof(&self.order, proof, trusted_bridges)
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
                // `Reversed` is reachable only via `fold_outpoint_status`
                // returning `Retracted` for an outpoint, which requires a
                // claim signed by one of this store's trusted bridges.
                //
                // Residual, tracked as the selective-omission gap in the
                // `OnChainPaymentProof` doc comment: the submitter still picks
                // which claims to show, so once a bridge has ever published a
                // retraction for this script, a submitter can exhibit that
                // claim while withholding a later re-confirmation. Closing
                // that needs a bridge-signed commitment to the complete claim
                // set, not a change here.
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "reversal without evidence".to_string())?;
                match verify_payment_proof(&self.order, proof, trusted_bridges) {
                    Err(ProofError::Reversed) => Ok(()),
                    Ok(_) => Err("reversal claimed, but the evidence still proves payment".into()),
                    Err(e) => Err(format!("reversal evidence invalid: {e}")),
                }
            }
            OrderStatus::Fulfilled | OrderStatus::Cancelled => {
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
        assert_eq!(verify_payment_proof(&order, &proof, &[]).unwrap(), 50_000);
    }

    #[test]
    fn a_wrong_preimage_is_rejected() {
        let order = lightning_order(Some(sha256(&[42u8; 32])));
        let proof = OrderPaymentProof::Lightning(LightningPaymentProof {
            preimage: [7u8; 32],
        });
        assert_eq!(
            verify_payment_proof(&order, &proof, &[]),
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
            verify_payment_proof(&order, &proof, &[]),
            Err(ProofError::WrongRail)
        );
    }

    #[test]
    fn an_on_chain_proof_cannot_settle_a_lightning_order() {
        let order = lightning_order(Some(sha256(&[1u8; 32])));
        let proof = OrderPaymentProof::on_chain(vec![], dummy_tip());
        assert_eq!(
            verify_payment_proof(&order, &proof, &[]),
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
