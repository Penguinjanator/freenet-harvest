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
    /// Confirmations required before this order counts as paid.
    pub required_confirmations: u32,
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

/// Bridge-signed evidence that an order's payment reached the chain.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OrderPaymentProof {
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
    InsufficientConfirmations { have: u32, need: u32 },
    /// Not enough value reached the script.
    InsufficientValue { have_sats: u64, need_sats: u64 },
    /// The most recent evidence says the payment is no longer on chain.
    Reversed,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::NoTrustedBridges => {
                write!(f, "this store trusts no Bitcoin bridge, so no payment can be proven")
            }
            ProofError::BadTip(e) => write!(f, "chain tip evidence invalid: {e}"),
            ProofError::BadClaim(e) => write!(f, "payment evidence invalid: {e}"),
            ProofError::NetworkMismatch => write!(f, "evidence is for a different Bitcoin network"),
            ProofError::WrongScript => write!(f, "evidence is for a different payment address"),
            ProofError::InsufficientConfirmations { have, need } => {
                write!(f, "payment has {have} confirmations, needs {need}")
            }
            ProofError::InsufficientValue { have_sats, need_sats } => {
                write!(f, "payment of {have_sats} sats is short of {need_sats} sats")
            }
            ProofError::Reversed => write!(f, "the payment was reorganized off the chain"),
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
    if trusted_bridges.is_empty() {
        return Err(ProofError::NoTrustedBridges);
    }

    let tip_params = freenet_bitcoin_common::BitcoinTipParameters {
        network: order.network,
        trusted_bridges: trusted_bridges.to_vec(),
    };
    let tip = proof
        .tip
        .verify(&tip_params)
        .map_err(ProofError::BadTip)?;
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

    for (_op, claims) in &by_outpoint {
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

    if confirmed_total == 0 && saw_retraction {
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
                // A reversal must also be evidenced, or anyone could declare a
                // paid order unpaid.
                let proof = self
                    .payment_proof
                    .as_ref()
                    .ok_or_else(|| "reversal without evidence".to_string())?;
                match verify_payment_proof(&self.order, proof, trusted_bridges) {
                    Err(ProofError::Reversed) => Ok(()),
                    Err(ProofError::InsufficientValue { .. }) => Ok(()),
                    Ok(_) => Err("reversal claimed, but the evidence still proves payment".into()),
                    Err(e) => Err(format!("reversal evidence invalid: {e}")),
                }
            }
            OrderStatus::Fulfilled | OrderStatus::Cancelled => {
                let (sp, sig) = self
                    .status_scoped_payload
                    .as_ref()
                    .zip(self.status_signature.as_ref())
                    .ok_or_else(|| {
                        format!("{:?} requires the seller's signature", self.status)
                    })?;
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
