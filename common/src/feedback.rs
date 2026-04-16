use serde::{Deserialize, Serialize};

/// Category of negative feedback.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum FeedbackCategory {
    NonDelivery,
    Misrepresented,
    Counterfeit,
    Other(String),
}

/// A feedback token: the plaintext that gets blind-signed by the seller.
///
/// The buyer creates this, blinds it, sends the blinded version to the seller for
/// signing, then unblinds the signature. The unblinded token + signature can later
/// be submitted to the seller's reputation contract as negative feedback.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FeedbackToken {
    /// Which reputation contract this token targets (ContractInstanceId bytes).
    pub target_reputation_contract: [u8; 32],
    /// Unique nonce to prevent replay.
    pub nonce: [u8; 32],
}

/// Protocol messages for the feedback token exchange, sent via encrypted mailbox.
///
/// Flow:
/// 1. Buyer creates a `FeedbackToken`, blinds it, sends `Request` to seller
/// 2. Seller blind-signs it (can't see the actual token), sends `Response` back
/// 3. Buyer unblinds the signature -- now holds a valid signature the seller can't link
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum FeedbackTokenMsg {
    /// Buyer -> Seller: "Here's my blinded token for your reputation contract"
    Request {
        blinded_token: Vec<u8>,
        target_reputation_contract: [u8; 32],
    },
    /// Seller -> Buyer: "Here's my blind signature on your token"
    Response { blind_signature: Vec<u8> },
}
