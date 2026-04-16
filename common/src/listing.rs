use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// What kind of listing this is.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum ListingKind {
    Sale,
    Gift,
    Request,
}

/// Price information for a listing. Freeform text -- the marketplace is payment-agnostic.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PriceInfo {
    /// e.g. "0.005", "50.00"
    pub amount: String,
    /// e.g. "BTC", "USD", "XMR"
    pub currency: String,
}

/// Unique listing identifier: first 16 bytes of BLAKE3(fingerprint || timestamp_ms || title).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ListingId(pub [u8; 16]);

impl ListingId {
    pub fn new(seller_fingerprint: &str, created_at: &DateTime<Utc>, title: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seller_fingerprint.as_bytes());
        hasher.update(&created_at.timestamp_millis().to_le_bytes());
        hasher.update(title.as_bytes());
        let hash = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id)
    }
}

impl std::fmt::Display for ListingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl PartialOrd for ListingId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ListingId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// A product, service, gift, or request listing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Listing {
    pub id: ListingId,
    pub title: String,
    pub description: String,
    pub kind: ListingKind,
    pub price: Option<PriceInfo>,
    pub created_at: DateTime<Utc>,
}

/// A listing signed by the seller's ghostkey.
///
/// The signature covers the CBOR-encoded `Listing` bytes. Verification requires
/// the seller's Ed25519 verifying key (from the store parameters or ghostkey certificate).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedListing {
    pub listing: Listing,
    pub signature: Signature,
    /// The seller's ghostkey certificate PEM, so any verifier can check the trust chain.
    pub certificate_pem: String,
}

impl AuthorizedListing {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        crate::util::verify_struct(&self.listing, &self.signature, verifying_key)
            .map_err(|e| format!("listing signature invalid: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sign_struct;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_listing_id_deterministic() {
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let id1 = ListingId::new("abc123", &ts, "Widget");
        let id2 = ListingId::new("abc123", &ts, "Widget");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_listing_id_differs_by_input() {
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let id1 = ListingId::new("abc123", &ts, "Widget");
        let id2 = ListingId::new("abc123", &ts, "Gadget");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_authorized_listing_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();

        let listing = Listing {
            id: ListingId::new("abc123", &ts, "Widget"),
            title: "Widget".into(),
            description: "A nice widget".into(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.001".into(),
                currency: "BTC".into(),
            }),
            created_at: ts,
        };

        let signature = sign_struct(&listing, &signing_key);
        let authorized = AuthorizedListing {
            listing,
            signature,
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
        };

        assert!(authorized.verify(&verifying_key).is_ok());
    }
}
