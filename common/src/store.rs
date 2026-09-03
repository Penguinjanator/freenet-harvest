use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::BridgeId;
use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};

use crate::listing::{verify_scoped_signature, AuthorizedListing, ListingId};
use crate::payment::{AuthorizedOrder, OrderId, OrderStatus};

/// Immutable parameters for a store contract, set at creation time.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreParameters {
    /// The seller's Ed25519 verifying key (from their ghostkey certificate).
    pub seller_verifying_key: VerifyingKey,
    /// Bitcoin bridges this store trusts to attest order payments.
    ///
    /// Empty means no order can ever be proven `Paid` --
    /// `verify_payment_proof` rejects `NoTrustedBridges` outright -- so a
    /// store that hasn't been configured with a bridge yet fails closed
    /// rather than accepting an unattested payment claim.
    ///
    /// `#[serde(default)]` so stores serialized before orders existed still
    /// decode: they simply come back with no trusted bridges, i.e. no order
    /// on them can ever validate as `Paid`, which is the safe default.
    #[serde(default)]
    pub trusted_bitcoin_bridges: Vec<BridgeId>,
    /// BLAKE3 hash of the `BitcoinAddressContract` WASM whose instances this
    /// store's orders reference for the related-contract cross-check in the
    /// store contract's `validate_state` (see that file's doc comment for
    /// why the cross-check is additive-only).
    ///
    /// The store contract cannot know the Bitcoin contract's code hash on
    /// its own -- it never sees that WASM -- so it has to be told. `None`
    /// (the `#[serde(default)]` value, and also correct for stores created
    /// before this field existed) simply skips the related-contract request:
    /// the embedded [`crate::payment::OrderPaymentProof`] remains fully
    /// authoritative either way, so omitting this forfeits an optional
    /// cross-check and nothing else.
    #[serde(default)]
    pub bitcoin_address_code_hash: Option<[u8; 32]>,
}

/// Information about the store owner. Single-value, version-bumped on update.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreInfoV1 {
    /// Monotonically increasing version number for last-writer-wins.
    pub version: u32,
    /// Seller's ghostkey certificate PEM (for buyers to verify the trust chain).
    pub certificate_pem: String,
    /// Seller's ghostkey fingerprint (BLAKE3 of verifying key, bs58-encoded).
    pub seller_fingerprint: String,
    /// The seller's reputation contract ID bytes.
    pub reputation_contract_id: [u8; 32],
    /// Human-readable store name.
    pub store_name: String,
    /// Optional store description.
    pub description: String,
    /// Payment instructions (freeform, e.g. "BTC: bc1q...").
    pub payment_instructions: String,
}

/// Store info signed by the seller's ghostkey via the ghostkey delegate.
///
/// Uses the ScopedPayload format from the ghostkey delegate's SignResult:
/// the signature is over the CBOR-encoded ScopedPayload which wraps the
/// CBOR-encoded StoreInfoV1 as its payload.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedStoreInfoV1 {
    pub info: StoreInfoV1,
    /// CBOR-serialized ScopedPayload from the ghostkey delegate's SignResult.
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature over the scoped_payload bytes.
    pub signature: Vec<u8>,
}

impl Default for AuthorizedStoreInfoV1 {
    fn default() -> Self {
        Self {
            info: StoreInfoV1 {
                version: 0,
                certificate_pem: String::new(),
                seller_fingerprint: String::new(),
                reputation_contract_id: [0u8; 32],
                store_name: String::new(),
                description: String::new(),
                payment_instructions: String::new(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
        }
    }
}

impl freenet_scaffold::ComposableState for AuthorizedStoreInfoV1 {
    type ParentState = StoreStateV1;
    type Summary = u32; // version number
    type Delta = AuthorizedStoreInfoV1; // full replacement
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        // Version 0 is the default (empty/uninitialized) state -- skip verification
        if self.info.version == 0 {
            return Ok(());
        }
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            &parameters.seller_verifying_key,
            &self.info,
        )
        .map_err(|e| format!("store info signature invalid: {e}"))
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.info.version
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        if self.info.version > *old_state_summary {
            Some(self.clone())
        } else {
            None
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(new_info) = delta {
            if new_info.info.version <= self.info.version {
                return Ok(()); // stale update, ignore
            }
            verify_scoped_signature(
                &new_info.scoped_payload,
                &new_info.signature,
                &parameters.seller_verifying_key,
                &new_info.info,
            )
            .map_err(|e| format!("store info delta signature invalid: {e}"))?;
            *self = new_info.clone();
        }
        Ok(())
    }
}

/// The set of listings in a store. Grow-only with removal by signed deletion.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ListingsV1 {
    pub listings: Vec<AuthorizedListing>,
}

impl freenet_scaffold::ComposableState for ListingsV1 {
    type ParentState = StoreStateV1;
    type Summary = Vec<ListingId>;
    type Delta = Vec<AuthorizedListing>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        for authorized in &self.listings {
            authorized.verify(&parameters.seller_verifying_key)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.listings.iter().map(|l| l.listing.id.clone()).collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let new_listings: Vec<_> = self
            .listings
            .iter()
            .filter(|l| !old_state_summary.contains(&l.listing.id))
            .cloned()
            .collect();
        if new_listings.is_empty() {
            None
        } else {
            Some(new_listings)
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(new_listings) = delta {
            let existing_ids: std::collections::HashSet<ListingId> =
                self.listings.iter().map(|l| l.listing.id.clone()).collect();

            for listing in new_listings {
                if existing_ids.contains(&listing.listing.id) {
                    continue; // already have this listing
                }
                listing.verify(&parameters.seller_verifying_key)?;
                self.listings.push(listing.clone());
            }

            // Sort deterministically for CRDT convergence
            self.listings
                .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        }
        Ok(())
    }
}

/// How many orders one store contract will hold.
///
/// Unlike listings, orders carry payment evidence: a `Paid` order embeds an
/// [`crate::payment::OrderPaymentProof`], which is itself a set of bridge-signed
/// claims plus a signed chain tip -- easily hundreds of bytes to a few KB per
/// order. Without a cap a popular store's state (and, worse, its per-heartbeat
/// summary -- see `OrdersV1`'s `Summary`) would grow without bound. On
/// overflow the least-relevant orders are dropped first: see
/// `enforce_order_cap`.
pub const MAX_ORDERS: usize = 4096;

/// Small state-change fingerprint for one order, used only to let
/// [`OrdersV1::delta`] detect a same-rank content change (see that impl's
/// doc comment for why one can happen). This is deliberately NOT the
/// tie-break comparator used to decide which of two same-rank records wins
/// a merge -- that comparison is over the full CBOR bytes, in
/// `merge_order` -- it only has to be cheap enough to carry in every
/// summary entry and to change whenever the record's bytes do.
fn order_content_digest(record: &AuthorizedOrder) -> [u8; 8] {
    // Infallible: `AuthorizedOrder` and everything it contains derives
    // `Serialize` over plain data (no custom fallible encoding), so CBOR
    // serialization of an in-memory value here cannot fail.
    let bytes = crate::to_cbor(record).expect("AuthorizedOrder always serializes to CBOR");
    let hash = blake3::hash(&bytes);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

/// Merge one already-verified incoming order record into `orders`.
///
/// Keeps whichever of the existing and incoming record has the higher
/// [`OrderStatus::rank`]. On an exact rank tie -- which happens when two
/// peers each independently assemble a different, but individually valid,
/// proof for the same transition (e.g. two different sets of bridge claims
/// that both establish `Paid`) -- the tie is broken by comparing the CBOR
/// bytes of the two records and keeping the greater. Comparing bytes rather
/// than, say, "whichever arrived first" is what makes the choice a pure
/// function of content: every replica that ends up holding both candidate
/// records picks the same winner, regardless of which one it received
/// first or via which peer.
///
/// This is a `max` over the total order `(rank, cbor_bytes)`, so it is
/// associative, commutative and idempotent -- the three properties the
/// merge tests in this module pin directly on serialized bytes.
fn merge_order(orders: &mut BTreeMap<OrderId, AuthorizedOrder>, incoming: AuthorizedOrder) {
    let id = incoming.order.id.clone();
    let Some(existing) = orders.get(&id) else {
        orders.insert(id, incoming);
        return;
    };
    match incoming.status.rank().cmp(&existing.status.rank()) {
        std::cmp::Ordering::Greater => {
            orders.insert(id, incoming);
        }
        std::cmp::Ordering::Less => {
            // Stale: we already hold a later transition for this order.
        }
        std::cmp::Ordering::Equal => {
            let existing_bytes =
                crate::to_cbor(existing).expect("AuthorizedOrder always serializes to CBOR");
            let incoming_bytes =
                crate::to_cbor(&incoming).expect("AuthorizedOrder always serializes to CBOR");
            if incoming_bytes > existing_bytes {
                orders.insert(id, incoming);
            }
        }
    }
}

/// Drop the least-relevant orders if `orders` is over [`MAX_ORDERS`].
///
/// Priority for keeping an order is, from least to most important: first,
/// whether its status is terminal (`Fulfilled`, `Cancelled`,
/// `PaymentReversed` -- nothing further will ever happen to it); second,
/// how old it is (`Order::created_at`); third, its id, purely as a
/// tie-breaker so the ordering is total. Terminal orders are dropped before
/// any order still awaiting resolution, and within a tier the oldest goes
/// first.
///
/// This ranking is a pure function of the *content* of `orders`, not of the
/// sequence in which entries were inserted, so two replicas that converge
/// to the same set of orders always prune to the same subset -- which is
/// exactly what the associated test checks.
fn enforce_order_cap(orders: &mut BTreeMap<OrderId, AuthorizedOrder>) {
    if orders.len() <= MAX_ORDERS {
        return;
    }
    let mut ranked: Vec<(bool, i64, OrderId)> = orders
        .iter()
        .map(|(id, record)| {
            let terminal = matches!(
                record.status,
                OrderStatus::Fulfilled | OrderStatus::Cancelled | OrderStatus::PaymentReversed
            );
            // `!terminal` sorts terminal orders (false) ahead of active ones
            // (true), so they are the first candidates dropped below.
            (
                !terminal,
                record.order.created_at.timestamp_millis(),
                id.clone(),
            )
        })
        .collect();
    ranked.sort();
    let excess = orders.len() - MAX_ORDERS;
    for (_, _, id) in ranked.into_iter().take(excess) {
        orders.remove(&id);
    }
}

/// The set of orders placed against this store, keyed by [`OrderId`].
///
/// # Merge model
///
/// This is neither grow-only (like a claim set) nor last-writer-wins by an
/// explicit version counter (like [`AuthorizedStoreInfoV1`]). It is a
/// **per-key monotonic maximum on [`OrderStatus::rank`]**, the same shape as
/// `freenet_bitcoin_common::address_state::ClaimSetV1`'s per-bridge scan
/// watermark: merging two versions of the same order keeps whichever has
/// the higher rank. A maximum over a total order is always associative,
/// commutative and idempotent, which is what makes it safe to merge two
/// replicas' order sets in any order and reach the same result -- see
/// `merge_order` for the same-rank tie-break this needs on top.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct OrdersV1 {
    pub orders: BTreeMap<OrderId, AuthorizedOrder>,
}

impl freenet_scaffold::ComposableState for OrdersV1 {
    type ParentState = StoreStateV1;
    /// One `(id, status rank, content digest)` triple per order, capped at
    /// [`MAX_ORDERS`] entries.
    ///
    /// This does not use a fixed-size bucket digest the way
    /// `freenet_bitcoin_common::digest::BucketDigest` does for claim sets,
    /// because that trades away precision this state actually needs: a
    /// bucket digest can only say "something in this bucket changed", which
    /// is fine for a grow-only set (re-sending the whole bucket is a cheap
    /// no-op), but `OrdersV1` mutates a specific order's status in place, and
    /// a buyer's payment confirming needs to propagate as *that one order*,
    /// not as a resend of every order that happens to hash into the same
    /// bucket. Instead this is bounded the way `MAX_CLAIMS` bounds
    /// `ClaimSetV1`: capped at a fixed number of entries rather than a fixed
    /// number of bytes. At 25 bytes an entry (16-byte id, 1-byte rank,
    /// 8-byte digest) this is still tiny next to a single order's own
    /// encoded size once it carries an `OrderPaymentProof` -- an order can
    /// run into the hundreds of bytes to multiple KB; a summary entry never
    /// does.
    type Summary = Vec<(OrderId, u8, [u8; 8])>;
    /// Full replacement records for whichever orders are new, ahead in rank,
    /// or -- at an exact rank tie -- differ in content (see `delta`).
    type Delta = Vec<AuthorizedOrder>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        if self.orders.len() > MAX_ORDERS {
            return Err(format!(
                "order set holds {} entries, cap is {MAX_ORDERS}",
                self.orders.len()
            ));
        }
        for (id, record) in &self.orders {
            if record.order.id != *id {
                return Err("order filed under a key that is not its own id".to_string());
            }
            record
                .verify(
                    &parameters.seller_verifying_key,
                    &parameters.trusted_bitcoin_bridges,
                )
                .map_err(|e| format!("order {id} invalid: {e}"))?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.orders
            .iter()
            .map(|(id, record)| {
                (
                    id.clone(),
                    record.status.rank(),
                    order_content_digest(record),
                )
            })
            .collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let old: BTreeMap<&OrderId, (u8, [u8; 8])> = old_state_summary
            .iter()
            .map(|(id, rank, digest)| (id, (*rank, *digest)))
            .collect();

        // Send an order whenever the requester's summary can't already
        // account for it: it's missing outright, it's behind in rank, or --
        // at an equal rank -- its content digest differs. That last case is
        // what keeps two peers from disagreeing forever about which of two
        // equally-ranked, independently-assembled records is current: see
        // `OrdersV1`'s doc comment. Sending in that case is always safe even
        // when our own record would in fact lose `merge_order`'s tie-break,
        // because the receiver re-runs that same tie-break on the full
        // bytes and simply keeps what it already had.
        let changed: Vec<AuthorizedOrder> = self
            .orders
            .iter()
            .filter(|(id, record)| {
                let our_rank = record.status.rank();
                match old.get(id) {
                    None => true,
                    Some((their_rank, their_digest)) => {
                        our_rank > *their_rank
                            || (our_rank == *their_rank
                                && order_content_digest(record) != *their_digest)
                    }
                }
            })
            .map(|(_, record)| record.clone())
            .collect();

        if changed.is_empty() {
            None
        } else {
            Some(changed)
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(incoming) = delta else {
            return Ok(());
        };
        for record in incoming {
            record
                .verify(
                    &parameters.seller_verifying_key,
                    &parameters.trusted_bitcoin_bridges,
                )
                .map_err(|e| format!("order {} delta invalid: {e}", record.order.id))?;
            merge_order(&mut self.orders, record.clone());
        }
        enforce_order_cap(&mut self.orders);
        Ok(())
    }
}

/// Top-level composable store state.
#[composable]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct StoreStateV1 {
    pub info: AuthorizedStoreInfoV1,
    pub listings: ListingsV1,
    pub orders: OrdersV1,
}

#[cfg(test)]
mod order_tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::{
        spv::testing::payment_proof, BitcoinNetwork, BlockAnchor, BlockHash, Claim, ClaimBody,
        OutPoint, SignedClaim, SignedTipEntry, TipEntryBody,
    };

    use crate::payment::{Order, OrderPaymentProof};

    fn seller_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
    }

    fn params(seller: &SigningKey, bridge: &SigningKey) -> StoreParameters {
        StoreParameters {
            seller_verifying_key: seller.verifying_key(),
            trusted_bitcoin_bridges: vec![BridgeId(bridge.verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
        }
    }

    fn timestamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn make_order(buyer_fp: &str, created_at_secs: i64, script: &[u8]) -> Order {
        let seller_fp = "seller-fingerprint";
        let ts = timestamp(created_at_secs);
        let listing_id = ListingId::new(seller_fp, &ts, "Widget");
        Order {
            id: OrderId::new(seller_fp, &listing_id, &ts, buyer_fp),
            listing_id,
            buyer_fingerprint: buyer_fp.into(),
            seller_fingerprint: seller_fp.into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: script.to_vec(),
            payment_hash: None,
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            created_at: ts,
        }
    }

    /// 32-byte contract id that order-term / status signatures must carry
    /// under Harvest's pinned requestor, same convention as
    /// `listing::tests::harvest_requestor_bytes`.
    fn harvest_requestor_bytes() -> [u8; 32] {
        let v = bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .expect("HARVEST_WEBAPP_CONTRACT_ID must decode as base58");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// Sign `data` as a ghostkey-delegate `ScopedPayload` would, without
    /// pulling in `ghostkey-common` -- same technique as
    /// `listing::tests::make_authorized_listing_with_requestor`.
    fn sign_scoped<T: serde::Serialize>(signing_key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }

        let payload = crate::to_cbor(data).unwrap();
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
            payload,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes).to_bytes().to_vec();
        (scoped_bytes, signature)
    }

    /// Build a fully authorized order: seller-signed terms, and -- for
    /// `Fulfilled`/`Cancelled` -- a seller-signed status transition too.
    fn make_authorized_order(
        seller: &SigningKey,
        order: Order,
        status: OrderStatus,
        payment_proof: Option<OrderPaymentProof>,
    ) -> AuthorizedOrder {
        let (scoped_payload, signature) = sign_scoped(seller, &order);
        let (status_scoped_payload, status_signature) = match status {
            OrderStatus::Fulfilled | OrderStatus::Cancelled => {
                let (sp, sig) = sign_scoped(seller, &(order.id.clone(), status));
                (Some(sp), Some(sig))
            }
            _ => (None, None),
        };
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status,
            payment_proof,
            status_scoped_payload,
            status_signature,
        }
    }

    /// Build a genuine, independently-verifiable `OrderPaymentProof`
    /// establishing `order` as paid, signed by `bridge`. `prev_block_seed`
    /// varies the mined block (and therefore every byte downstream of it),
    /// which is how the equal-rank-tie-break test gets two distinct-but-both-
    /// valid proofs for the same order.
    fn make_payment_proof(
        order: &Order,
        bridge: &SigningKey,
        prev_block_seed: u8,
    ) -> OrderPaymentProof {
        let addr_params = order.bitcoin_params(vec![]); // only used for script_id() here
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [prev_block_seed; 32],
        );

        let confirm_height = 100;
        let claim_body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: confirm_height,
                hash: block_hash,
            },
            claim: Claim::ConfirmedOutput {
                outpoint: OutPoint { txid, vout: 0 },
                value_sats: order.amount_sats,
                anchor: BlockAnchor {
                    height: confirm_height,
                    hash: block_hash,
                },
                spv,
            },
        };
        let claim = SignedClaim::sign(bridge, &claim_body).unwrap();

        let tip_height = confirm_height + order.required_confirmations - 1;
        let tip_body = TipEntryBody {
            network: order.network,
            anchor: BlockAnchor {
                height: tip_height,
                hash: BlockHash([9u8; 32]),
            },
            prev_hash: BlockHash([8u8; 32]),
            block_time: 1_700_000_000,
            tx_count: 1,
            median_time: 1_700_000_000,
        };
        let tip = SignedTipEntry::sign(bridge, &tip_body).unwrap();

        OrderPaymentProof::on_chain(vec![claim], tip)
    }

    /// Reach into an on-chain proof to tamper with it in tests.
    fn on_chain_mut(p: &mut OrderPaymentProof) -> &mut crate::payment::OnChainPaymentProof {
        match p {
            OrderPaymentProof::OnChain(c) => c,
            other => panic!("expected an on-chain proof, got {other:?}"),
        }
    }

    fn orders_of(pairs: impl IntoIterator<Item = (OrderId, AuthorizedOrder)>) -> OrdersV1 {
        OrdersV1 {
            orders: pairs.into_iter().collect(),
        }
    }

    // -----------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------

    #[test]
    fn genuinely_paid_order_verifies() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_ok(),
            "a genuinely paid order, with a real bridge-signed proof, must verify"
        );
    }

    #[test]
    fn forged_proof_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let mut proof = make_payment_proof(&order, &bridge, 1);
        // Flip a byte in the bridge's claim signature: same claim body,
        // forged signature.
        let inner = on_chain_mut(&mut proof);
        let last = inner.claims[0].signature.len() - 1;
        inner.claims[0].signature[last] ^= 0xff;
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("a forged bridge signature must not verify");
        assert!(err.contains("invalid"), "got: {err}");
    }

    #[test]
    fn order_marked_paid_without_evidence_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, None);

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("Paid with no payment_proof must be rejected");
        assert!(err.contains("without payment evidence"), "got: {err}");
    }

    #[test]
    fn order_proof_for_a_different_script_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        // Genuine proof, but for a DIFFERENT script than the order's own.
        let wrong_script_order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0x99, 0x88]);
        let proof = make_payment_proof(&wrong_script_order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("a proof for a different script must not establish this order as paid");
        assert!(err.contains("payment proof rejected"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Merge properties
    // -----------------------------------------------------------------

    #[test]
    fn status_is_monotonic_under_merge() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        let awaiting =
            make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
        let proof = make_payment_proof(&order, &bridge, 1);
        let paid = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let mut a = orders_of([(order.id.clone(), awaiting.clone())]);
        let b = orders_of([(order.id.clone(), paid.clone())]);
        a.merge(&StoreStateV1::default(), &p, &b).unwrap();
        assert_eq!(
            a.orders[&order.id].status,
            OrderStatus::Paid,
            "merging in a higher-ranked status must adopt it"
        );

        // Merging the stale AwaitingPayment version back in must NOT
        // regress the status: rank only ever moves forward.
        let stale = orders_of([(order.id.clone(), awaiting)]);
        a.merge(&StoreStateV1::default(), &p, &stale).unwrap();
        assert_eq!(
            a.orders[&order.id].status,
            OrderStatus::Paid,
            "a stale, lower-ranked status must never overwrite a later one"
        );
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);

        let order_x = make_order("buyer-x", 1_700_000_000, &[0x00, 0x14, 0x01, 0x01]);
        let order_y = make_order("buyer-y", 1_700_000_100, &[0x00, 0x14, 0x02, 0x02]);
        let proof_x = make_payment_proof(&order_x, &bridge, 3);
        let proof_y = make_payment_proof(&order_y, &bridge, 4);

        // a: X awaiting, Y absent.
        let a = orders_of([(
            order_x.id.clone(),
            make_authorized_order(&seller, order_x.clone(), OrderStatus::AwaitingPayment, None),
        )]);
        // b: X paid (higher rank), Y awaiting.
        let b = orders_of([
            (
                order_x.id.clone(),
                make_authorized_order(
                    &seller,
                    order_x.clone(),
                    OrderStatus::Paid,
                    Some(proof_x.clone()),
                ),
            ),
            (
                order_y.id.clone(),
                make_authorized_order(&seller, order_y.clone(), OrderStatus::AwaitingPayment, None),
            ),
        ]);
        // c: X fulfilled (higher still), Y paid.
        let c = orders_of([
            (
                order_x.id.clone(),
                make_authorized_order(&seller, order_x.clone(), OrderStatus::Fulfilled, None),
            ),
            (
                order_y.id.clone(),
                make_authorized_order(
                    &seller,
                    order_y.clone(),
                    OrderStatus::Paid,
                    Some(proof_y.clone()),
                ),
            ),
        ]);

        let merge = |x: &OrdersV1, y: &OrdersV1| -> OrdersV1 {
            let mut m = x.clone();
            m.merge(&StoreStateV1::default(), &p, y).unwrap();
            m
        };

        let ab_c = merge(&merge(&a, &b), &c);
        let a_bc = merge(&a, &merge(&b, &c));
        let ba_c = merge(&merge(&b, &a), &c);
        let ac_b = merge(&merge(&a, &c), &b);

        let bytes = |s: &OrdersV1| crate::to_cbor(s).unwrap();
        assert_eq!(bytes(&ab_c), bytes(&a_bc), "merge must be associative");
        assert_eq!(bytes(&ab_c), bytes(&ba_c), "merge must be commutative");
        assert_eq!(bytes(&ab_c), bytes(&ac_b), "merge must be commutative (2)");

        let idempotent = merge(&ab_c, &ab_c);
        assert_eq!(bytes(&ab_c), bytes(&idempotent), "merge must be idempotent");

        // And the converged result actually reflects the higher-ranked
        // status for both orders.
        assert_eq!(ab_c.orders[&order_x.id].status, OrderStatus::Fulfilled);
        assert_eq!(ab_c.orders[&order_y.id].status, OrderStatus::Paid);
    }

    #[test]
    fn equal_rank_ties_are_broken_deterministically_and_commutatively() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // Two independently-assembled, EACH INDIVIDUALLY VALID proofs for
        // the same order and the same status: different mined blocks, so
        // different bytes end to end, but both establish Paid.
        let proof_1 = make_payment_proof(&order, &bridge, 5);
        let proof_2 = make_payment_proof(&order, &bridge, 6);
        assert_ne!(
            crate::to_cbor(&proof_1).unwrap(),
            crate::to_cbor(&proof_2).unwrap(),
            "the two proofs must actually differ for this test to mean anything"
        );

        let record_1 =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof_1));
        let record_2 =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof_2));

        let a = orders_of([(order.id.clone(), record_1.clone())]);
        let b = orders_of([(order.id.clone(), record_2.clone())]);

        let mut a_then_b = a.clone();
        a_then_b.merge(&StoreStateV1::default(), &p, &b).unwrap();
        let mut b_then_a = b.clone();
        b_then_a.merge(&StoreStateV1::default(), &p, &a).unwrap();

        assert_eq!(
            crate::to_cbor(&a_then_b).unwrap(),
            crate::to_cbor(&b_then_a).unwrap(),
            "the tie-break winner must not depend on merge order"
        );

        // The winner must be whichever record has the greater CBOR bytes.
        let expected_winner =
            if crate::to_cbor(&record_1).unwrap() > crate::to_cbor(&record_2).unwrap() {
                &record_1
            } else {
                &record_2
            };
        assert_eq!(
            crate::to_cbor(&a_then_b.orders[&order.id]).unwrap(),
            crate::to_cbor(expected_winner).unwrap(),
            "the tie-break must deterministically pick the greater CBOR encoding"
        );

        // Idempotent: merging the winner into itself changes nothing.
        let mut winner_twice = a_then_b.clone();
        winner_twice
            .merge(&StoreStateV1::default(), &p, &a_then_b)
            .unwrap();
        assert_eq!(
            crate::to_cbor(&a_then_b).unwrap(),
            crate::to_cbor(&winner_twice).unwrap()
        );
    }

    #[test]
    fn delta_returns_none_when_summary_already_matches() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller, &bridge);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));
        let state = orders_of([(order.id.clone(), record)]);

        let own_summary = state.summarize(&StoreStateV1::default(), &p);
        assert!(
            state
                .delta(&StoreStateV1::default(), &p, &own_summary)
                .is_none(),
            "a requester whose summary already matches ours must get no delta"
        );
    }

    // -----------------------------------------------------------------
    // Capacity pruning
    // -----------------------------------------------------------------

    /// Cheap synthetic fixture for pruning tests: no real signatures, since
    /// `enforce_order_cap` is a structural function that never calls
    /// `verify`. Building thousands of genuinely-signed-and-proved orders
    /// just to exercise pruning would be needlessly slow.
    fn synthetic_order(
        seed: u8,
        created_at_secs: i64,
        status: OrderStatus,
    ) -> (OrderId, AuthorizedOrder) {
        let ts = timestamp(created_at_secs);
        let listing_id = ListingId::new("seller", &ts, "Widget");
        let id = OrderId::new("seller", &listing_id, &ts, &format!("buyer-{seed}"));
        let order = Order {
            id: id.clone(),
            listing_id,
            buyer_fingerprint: format!("buyer-{seed}"),
            seller_fingerprint: "seller".into(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, seed],
            payment_address: "tb1qtest".into(),
            payment_hash: None,
            required_confirmations: 1,
            created_at: ts,
        };
        (
            id,
            AuthorizedOrder {
                order,
                scoped_payload: vec![],
                signature: vec![],
                status,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            },
        )
    }

    #[test]
    fn pruning_drops_terminal_orders_before_active_ones() {
        let mut orders: BTreeMap<OrderId, AuthorizedOrder> = BTreeMap::new();
        let (id_active, rec_active) = synthetic_order(1, 1_000, OrderStatus::AwaitingPayment);
        let (id_terminal, rec_terminal) = synthetic_order(2, 2_000, OrderStatus::Cancelled);
        orders.insert(id_active.clone(), rec_active);
        orders.insert(id_terminal.clone(), rec_terminal);

        // Force the cap down to 1 for this test by pruning a 2-entry map
        // down to `MAX_ORDERS - 1` worth of headroom is impractical to set
        // up directly (MAX_ORDERS is a real constant), so instead call the
        // pruning logic's underlying comparison directly by filling past
        // the real cap with cheap synthetic entries sharing the terminal
        // one's profile, then checking the terminal-tier one is gone and
        // the active one survives.
        for i in 3..(MAX_ORDERS as u16 + 3) {
            let (id, rec) =
                synthetic_order((i % 256) as u8, 3_000 + i as i64, OrderStatus::Cancelled);
            orders.insert(id, rec);
        }
        assert!(orders.len() > MAX_ORDERS);

        enforce_order_cap(&mut orders);
        assert_eq!(orders.len(), MAX_ORDERS);
        assert!(
            orders.contains_key(&id_active),
            "the only active (non-terminal) order must survive pruning"
        );
        assert!(
            !orders.contains_key(&id_terminal),
            "the oldest terminal order must be dropped before newer terminal ones"
        );
    }

    #[test]
    fn pruning_is_order_independent() {
        let mut entries = Vec::new();
        for i in 0..(MAX_ORDERS as u16 + 25) {
            let status = if i % 3 == 0 {
                OrderStatus::Cancelled
            } else {
                OrderStatus::AwaitingPayment
            };
            entries.push(synthetic_order((i % 256) as u8, 10_000 + i as i64, status));
        }

        let mut forward: BTreeMap<OrderId, AuthorizedOrder> = entries.iter().cloned().collect();
        let mut backward: BTreeMap<OrderId, AuthorizedOrder> =
            entries.iter().rev().cloned().collect();

        enforce_order_cap(&mut forward);
        enforce_order_cap(&mut backward);

        assert_eq!(forward.len(), MAX_ORDERS);
        assert_eq!(
            forward.keys().collect::<Vec<_>>(),
            backward.keys().collect::<Vec<_>>(),
            "pruning must depend only on content, not on insertion order"
        );
    }
}
