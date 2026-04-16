use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::feedback::{FeedbackCategory, FeedbackToken};

/// Immutable parameters for a reputation contract, set at creation time.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReputationParameters {
    /// RSA public key in PKCS#1 DER format, for verifying blind-signed feedback tokens.
    pub rsa_public_key_der: Vec<u8>,
    /// Owner's Ed25519 verifying key (from ghostkey certificate), for identity linkage.
    pub owner_verifying_key: VerifyingKey,
}

/// A single piece of negative feedback submitted to a seller's reputation contract.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FeedbackEntry {
    /// The unblinded feedback token.
    pub token: FeedbackToken,
    /// RSA-PSS blind signature over the CBOR-encoded token (RFC 9474, unblinded).
    pub signature: Vec<u8>,
    /// What went wrong.
    pub category: FeedbackCategory,
    /// Optional freeform comment from the buyer.
    pub comment: String,
    /// When the feedback was submitted.
    pub submitted_at: DateTime<Utc>,
}

/// Per-seller reputation contract state. Append-only negative feedback.
///
/// This is naturally commutative: adding feedback entries in any order produces the
/// same final set (grow-only set with nonce-based deduplication).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReputationStateV1 {
    /// Owner's ghostkey certificate PEM (for verifiers to check identity chain).
    pub owner_certificate_pem: String,
    /// Append-only list of negative feedback entries.
    pub feedback: Vec<FeedbackEntry>,
    /// Used nonces for replay prevention (mirrors nonces from feedback entries).
    pub used_nonces: HashSet<[u8; 32]>,
}

/// Summary for delta computation: the set of known nonces.
pub type ReputationSummary = HashSet<[u8; 32]>;

/// Delta: new feedback entries to add.
pub type ReputationDelta = Vec<FeedbackEntry>;

impl ReputationStateV1 {
    /// Verify the entire state: all feedback entries have valid RSA signatures
    /// and consistent nonce tracking.
    pub fn verify(&self, parameters: &ReputationParameters) -> Result<(), String> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pss::{Signature, VerifyingKey as RsaVerifyingKey};
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(&parameters.rsa_public_key_der)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key);

        for entry in &self.feedback {
            // Verify the RSA-PSS signature over the CBOR-encoded token
            let token_bytes =
                crate::to_cbor(&entry.token).map_err(|e| format!("serialize token: {e}"))?;
            let signature = Signature::try_from(entry.signature.as_slice())
                .map_err(|e| format!("invalid RSA signature bytes: {e}"))?;
            verifying_key
                .verify(&token_bytes, &signature)
                .map_err(|e| format!("feedback signature invalid: {e}"))?;

            // Verify nonce is tracked
            if !self.used_nonces.contains(&entry.token.nonce) {
                return Err(format!(
                    "feedback entry nonce not in used_nonces set: {:?}",
                    entry.token.nonce
                ));
            }
        }

        // Verify no duplicate nonces
        if self.feedback.len() != self.used_nonces.len() {
            return Err("feedback count does not match used_nonces count".into());
        }

        Ok(())
    }

    /// Generate a summary (set of used nonces) for delta computation.
    pub fn summarize(&self) -> ReputationSummary {
        self.used_nonces.clone()
    }

    /// Compute delta: feedback entries whose nonces are not in the old summary.
    pub fn delta(&self, old_summary: &ReputationSummary) -> Option<ReputationDelta> {
        let new_entries: Vec<_> = self
            .feedback
            .iter()
            .filter(|e| !old_summary.contains(&e.token.nonce))
            .cloned()
            .collect();
        if new_entries.is_empty() {
            None
        } else {
            Some(new_entries)
        }
    }

    /// Apply a delta: add new feedback entries, verifying each signature.
    pub fn apply_delta(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
    ) -> Result<(), String> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pss::{Signature, VerifyingKey as RsaVerifyingKey};
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let Some(entries) = delta else {
            return Ok(());
        };

        let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(&parameters.rsa_public_key_der)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key);

        for entry in entries {
            // Reject duplicate nonces
            if self.used_nonces.contains(&entry.token.nonce) {
                continue;
            }

            // Verify the RSA-PSS signature
            let token_bytes =
                crate::to_cbor(&entry.token).map_err(|e| format!("serialize token: {e}"))?;
            let signature = Signature::try_from(entry.signature.as_slice())
                .map_err(|e| format!("invalid RSA signature bytes: {e}"))?;
            verifying_key
                .verify(&token_bytes, &signature)
                .map_err(|e| format!("feedback signature invalid: {e}"))?;

            self.used_nonces.insert(entry.token.nonce);
            self.feedback.push(entry.clone());
        }

        // Sort deterministically by nonce for CRDT convergence
        self.feedback.sort_by(|a, b| a.token.nonce.cmp(&b.token.nonce));

        Ok(())
    }
}
