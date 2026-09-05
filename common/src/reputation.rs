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

        // Verify the WHOLE delta before committing any of it. Verifying and
        // pushing in one pass left a delta of [valid, invalid] with the valid
        // entry -- and its nonce -- already in `self` when the error returned,
        // so a caller that keeps the state it passed in would take on entries
        // from a delta it had been told to reject. The burnt nonce is the
        // worse half: `used_nonces` is what suppresses a replay, so the
        // genuine entry could then never be added. Same defect, and the same
        // fix, as `store::OrdersV1::apply_delta`.
        let mut accepted: Vec<&FeedbackEntry> = Vec::new();
        // Nonces this delta has already accounted for, so a delta naming one
        // entry twice still stores it once. `self.used_nonces` used to be
        // mutated in the loop and did this job; it cannot now, because nothing
        // is committed until every entry has passed.
        let mut seen: HashSet<[u8; 32]> = HashSet::new();

        for entry in entries {
            // Reject duplicate nonces
            if self.used_nonces.contains(&entry.token.nonce) || !seen.insert(entry.token.nonce) {
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

            accepted.push(entry);
        }

        for entry in accepted {
            self.used_nonces.insert(entry.token.nonce);
            self.feedback.push(entry.clone());
        }

        // Sort deterministically by nonce for CRDT convergence
        self.feedback
            .sort_by(|a, b| a.token.nonce.cmp(&b.token.nonce));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pss::{BlindedSigningKey, VerifyingKey as RsaVerifyingKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    use crate::feedback::{FeedbackCategory, FeedbackToken};

    /// 1024 bits, not 2048: this is a signature-shape fixture, not a security
    /// claim, and key generation is the slowest thing in the test.
    fn key_pair() -> (RsaPrivateKey, ReputationParameters) {
        let mut rng = rsa::rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 1024).expect("generate RSA key");
        let der = RsaPublicKey::from(&private)
            .to_pkcs1_der()
            .expect("encode public key")
            .as_bytes()
            .to_vec();
        let params = ReputationParameters {
            rsa_public_key_der: der,
            owner_verifying_key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key(),
        };
        (private, params)
    }

    fn token(nonce: u8) -> FeedbackToken {
        FeedbackToken {
            target_reputation_contract: [5u8; 32],
            nonce: [nonce; 32],
        }
    }

    fn entry(signature: Vec<u8>, nonce: u8) -> FeedbackEntry {
        FeedbackEntry {
            token: token(nonce),
            signature,
            category: FeedbackCategory::NonDelivery,
            comment: String::new(),
            submitted_at: DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        }
    }

    /// A feedback entry whose RSA-PSS signature genuinely verifies.
    fn signed_entry(private: &RsaPrivateKey, nonce: u8) -> FeedbackEntry {
        let mut rng = rsa::rand_core::OsRng;
        let signing_key = BlindedSigningKey::<Sha256>::new(private.clone());
        let bytes = crate::to_cbor(&token(nonce)).expect("serialize token");
        let signature = signing_key.sign_with_rng(&mut rng, &bytes).to_vec();
        entry(signature, nonce)
    }

    /// The fixture has to be right, or the atomicity test below passes for the
    /// wrong reason: a "valid" entry that does not actually verify would leave
    /// nothing behind whether or not the delta is atomic.
    #[test]
    fn the_signed_fixture_actually_verifies() {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::signature::Verifier;

        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);

        let public = rsa::RsaPublicKey::from_pkcs1_der(&params.rsa_public_key_der).expect("decode");
        let verifying = RsaVerifyingKey::<Sha256>::new(public);
        let bytes = crate::to_cbor(&good.token).expect("serialize token");
        let signature =
            rsa::pss::Signature::try_from(good.signature.as_slice()).expect("signature");
        verifying
            .verify(&bytes, &signature)
            .expect("the fixture signature must verify");

        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good]))
            .expect("a genuinely signed entry must apply");
        assert_eq!(state.feedback.len(), 1);
    }

    /// A delta is all-or-nothing.
    ///
    /// The same defect as `OrdersV1::apply_delta` and `ListingsV1::apply_delta`
    /// in `store.rs`: this verified and committed in one pass, so a delta of
    /// `[valid, invalid]` pushed the valid entry -- and its nonce -- into
    /// `self` and only then returned `Err`. A caller that keeps the state it
    /// passed in would silently take on entries from a delta it had been told
    /// to reject, and the leaked nonce would then make the genuine entry
    /// undeliverable, because `used_nonces` is what suppresses a replay.
    #[test]
    fn a_delta_holding_one_invalid_entry_applies_none_of_it() {
        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);
        // Too short to even parse as a signature for this modulus, so it fails
        // before any RSA work. Any rejection would do.
        let bad = entry(vec![0u8; 8], 2);

        let mut state = ReputationStateV1::default();
        let err = state
            .apply_delta(&params, &Some(vec![good.clone(), bad.clone()]))
            .expect_err("a delta carrying an unverifiable entry must be rejected");
        assert!(err.contains("signature"), "got: {err}");
        assert!(
            state.feedback.is_empty(),
            "a rejected delta must leave no feedback behind"
        );
        assert!(
            state.used_nonces.is_empty(),
            "and must not burn the nonce of an entry it did not keep"
        );

        // Order within the delta must not matter either.
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![bad, good.clone()]))
            .expect_err("a delta carrying an unverifiable entry must be rejected");
        assert!(state.feedback.is_empty());
        assert!(state.used_nonces.is_empty());

        // And the good entry alone still applies, so the assertions above are
        // about atomicity rather than about `good` being unusable.
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good]))
            .expect("the valid entry alone must apply");
        assert_eq!(state.feedback.len(), 1);
        assert_eq!(state.used_nonces.len(), 1);
    }

    /// A delta naming one entry twice stores it once, and the second copy is
    /// not re-verified. Pins the dedup this file already had, so the
    /// two-pass restructuring cannot quietly drop it.
    #[test]
    fn a_delta_repeating_one_entry_stores_it_once() {
        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);

        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good.clone(), good]))
            .expect("a repeated valid entry is a duplicate, not an error");
        assert_eq!(state.feedback.len(), 1);
        assert_eq!(state.used_nonces.len(), 1);
    }
}
