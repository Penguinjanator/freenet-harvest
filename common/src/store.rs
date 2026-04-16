use ed25519_dalek::{Signature, VerifyingKey};
use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};

use crate::listing::{AuthorizedListing, ListingId};

/// Immutable parameters for a store contract, set at creation time.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreParameters {
    /// The seller's Ed25519 verifying key (from their ghostkey certificate).
    pub seller_verifying_key: VerifyingKey,
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

/// Store info signed by the seller's ghostkey.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedStoreInfoV1 {
    pub info: StoreInfoV1,
    pub signature: Signature,
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
            signature: Signature::from_bytes(&[0u8; 64]),
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
        crate::util::verify_struct(&self.info, &self.signature, &parameters.seller_verifying_key)
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
            // Verify the new info's signature
            crate::util::verify_struct(
                &new_info.info,
                &new_info.signature,
                &parameters.seller_verifying_key,
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
            self.listings.sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        }
        Ok(())
    }
}

/// Top-level composable store state.
#[composable]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct StoreStateV1 {
    pub info: AuthorizedStoreInfoV1,
    pub listings: ListingsV1,
}
