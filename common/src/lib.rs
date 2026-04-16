//! Shared types for Harvest, the decentralized marketplace on Freenet.
//!
//! This crate defines the wire-format schemas used by the Harvest contracts,
//! delegate, and UI: store listings, feedback-token protocol messages, and
//! reputation contract state.

#![deny(unsafe_code)]

pub mod delegate;
pub mod feedback;
pub mod listing;
pub mod mailbox;
pub mod reputation;
pub mod store;
pub mod util;

// Re-exports for convenience
pub use delegate::{HarvestDelegateRequest, HarvestDelegateResponse, TransactionRecord};
pub use feedback::{FeedbackCategory, FeedbackToken, FeedbackTokenMsg};
pub use listing::{AuthorizedListing, Listing, ListingId, ListingKind, PriceInfo};
pub use mailbox::{ConversationId, EncryptedMessage, MailboxParameters, MailboxStateV1};
pub use reputation::{FeedbackEntry, ReputationParameters, ReputationStateV1};
pub use store::{StoreParameters, StoreStateV1};

/// Serialize a value to CBOR bytes.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| format!("CBOR serialize: {e}"))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes.
pub fn from_cbor<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR deserialize: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_roundtrip() {
        let original = "hello harvest";
        let bytes = to_cbor(&original).unwrap();
        let decoded: String = from_cbor(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}
