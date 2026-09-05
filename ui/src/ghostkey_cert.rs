//! Does a published ghostkey certificate actually mean anything?
//!
//! Every store and every listing carries a `certificate_pem`, and until this
//! module existed nothing ever parsed one. A seller could put arbitrary text
//! there -- or, worse, somebody else's perfectly genuine certificate -- and
//! every part of Harvest would carry it around and display it unexamined.
//!
//! # What a certificate is for, and what it is not for
//!
//! Harvest already proves *this key signed this record*: the store contract
//! verifies every listing, order and store-info signature against
//! [`StoreParameters::seller_verifying_key`], which is frozen into the
//! store's address. That is authentication, and it works without any
//! certificate at all.
//!
//! What it does not establish is that the key means anything. A ghostkey is
//! minted by donating to Freenet, so it is *scarce* -- and scarcity is the
//! foundation the whole incentive design rests on (see
//! `docs/design/incentive-mechanism.md`, Part 2). A store whose key is just a
//! key somebody generated has no bond behind it. The certificate is the only
//! thing that separates the two, so a certificate nobody checks leaves the
//! design's own premise unenforced.
//!
//! # The check that matters most
//!
//! Certificates are **public**. Alice's certificate is handed to every buyer
//! who opens her store, so the easy attack is not forging one -- it is
//! copying hers. A scammer publishes their own store, signs everything with
//! their own throwaway key, and pastes Alice's certificate into
//! `certificate_pem`. Chain verification alone passes: the certificate really
//! is genuine, really does chain to Freenet's master key, and really does
//! attest a donation. It just is not *this seller's*.
//!
//! So verification here is two questions, and the second is the load-bearing
//! one:
//!
//! 1. Does the certificate chain to Freenet's master key?
//! 2. Is the key it certifies the key this store is addressed by?
//!
//! # How (2) is answered without the contract's parameters
//!
//! A Freenet contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, and a
//! store's only parameter is the seller's verifying key. The node's GET
//! response does carry the contract container, but Harvest discards it (see
//! `gateway::response_handler`), so the reader holds the instance id and
//! nothing else.
//!
//! That is enough, because the derivation runs forwards: take the key the
//! certificate certifies, encode it as `StoreParameters`, hash it against the
//! store contract this build bundles, and see whether the answer is the
//! contract id actually being read. A match proves three things at once --
//! the certified key *is* the parameter key, the parameters are what we think
//! they are, and the code at that address is the genuine Harvest store
//! contract rather than a permissive lookalike. Everything the contract
//! validated, it validated against the certified key.
//!
//! Superseded generations are included ([`crate::migrate`] derives them),
//! because a store published under an older contract build lives at a
//! different address and is not therefore fraudulent.
//!
//! # The limitation this approach has, and cannot fix
//!
//! Running the derivation forwards means enumerating the code hashes this
//! build knows about: today's, and every one in `legacy/store_contract.toml`.
//! A store published by a *newer* build of Harvest than the one reading it
//! lives at an address derived from a code hash this build has never heard
//! of, and is indistinguishable here from a certificate issued to somebody
//! else. Both are "no id matches".
//!
//! That is not hypothetical -- the store contract has already been through
//! several generations, and a rustc or stdlib bump is enough to move it. So
//! `CertificateStatus::Invalid` names the benign explanation alongside the
//! hostile one, and the storefront's wording declines to credit the seller
//! rather than accusing them, which is the right response either way: a
//! reader that cannot verify a bond should not act as though it had.
//!
//! Removing it means reading the contract's PARAMETERS instead of deriving
//! its address. The node's GET response carries them, and
//! `gateway::response_handler` currently discards the container; recovering
//! them would let the check be `certificate.verifying_key ==
//! parameters.seller_verifying_key` with no dependence on any code hash. The
//! cost is that it no longer establishes, in the same step, that the code at
//! that address is the real Harvest store contract -- that becomes a separate
//! check against the same list of known hashes, and so carries the same
//! staleness, but as a weaker and separately-reportable signal rather than as
//! a false accusation.
//!
//! # What is deliberately NOT read here
//!
//! The donation *amount*. `GhostkeyCertificateV1::verify` returns the notary
//! info string, which encodes the tier, and this module throws it away. The
//! amount is the seller's bond, and turning a bond into a number a buyer acts
//! on is the whole of the standing mechanism -- weighting, open orders,
//! complaint multipliers. None of that is designed yet, and a half-read tier
//! displayed next to a store would be acted on as if it were.
//!
//! [`StoreParameters::seller_verifying_key`]: harvest_common::store::StoreParameters::seller_verifying_key

use ed25519_dalek::VerifyingKey;
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId};
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;

use crate::gateway::store_ops::STORE_CONTRACT_WASM;

/// What a reader concluded about one published certificate.
///
/// Three outcomes rather than a `bool`, because "no certificate" and "a
/// certificate that does not verify" are different things to tell a buyer:
/// the first is an unfinished store, the second is a store actively claiming
/// a bond it does not have.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum CertificateStatus {
    /// Nothing was published. The seller has no verifiable identity here.
    #[default]
    Absent,
    /// Chains to Freenet's master key, and certifies this store's own key.
    Verified,
    /// Published, and does not hold up. The string says how, for display.
    Invalid(String),
}

impl CertificateStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, CertificateStatus::Verified)
    }

    /// The short line a reader sees.
    pub fn label(&self) -> &'static str {
        match self {
            CertificateStatus::Absent => "No ghostkey certificate",
            CertificateStatus::Verified => "Ghostkey verified",
            CertificateStatus::Invalid(_) => "Ghostkey certificate does not verify",
        }
    }

    /// The longer explanation, or `None` when the label says it all.
    pub fn detail(&self) -> Option<&str> {
        match self {
            CertificateStatus::Invalid(why) => Some(why.as_str()),
            _ => None,
        }
    }
}

/// The code hash of the store contract this build bundles.
///
/// Cached: it is a BLAKE3 over the whole contract WASM, and a store page
/// verifies one certificate per listing plus one for the store itself.
fn store_code_hash() -> [u8; 32] {
    static HASH: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        let hash = *ContractCode::from(STORE_CONTRACT_WASM.to_vec()).hash();
        let bytes: &[u8] = hash.as_ref();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[..32]);
        out
    });
    *HASH
}

/// Every store instance id the holder of `key` could have published at: this
/// build's, plus every superseded generation.
///
/// The legacy ids come from [`crate::migrate::store_candidate_ids`], which
/// already knows which generations were published under a *different*
/// `StoreParameters` encoding -- a middle BAND, V2..=V5, not everything below
/// a threshold: V1 predates the two Bitcoin fields and V6 onwards postdates
/// them, so both sit on the current encoding. See
/// `migrate::published_under_legacy_store_params`.
///
/// Re-deriving them here would be a second copy of that fact, and the first
/// one was got wrong once already -- twice, in fact. The comment this replaced
/// said "at or below `LAST_LEGACY_STORE_PARAM_GENERATION`", which was the
/// same off-by-one that made the probe derive V1 -- the only generation ever
/// published -- at an address it never had. Delegating rather than
/// re-deriving is what kept that bug out of this file.
fn store_instance_ids(key: &VerifyingKey) -> Result<Vec<ContractInstanceId>, String> {
    let params = crate::migrate::encode_params(&crate::migrate::store_params(key))?;
    let mut ids = vec![crate::migrate::current_id(&store_code_hash(), &params)];
    ids.extend(crate::migrate::store_candidate_ids(key)?);
    Ok(ids)
}

/// Parse a certificate and check its chain, returning the key it certifies.
///
/// `master` is `None` in every non-test caller, which means "Freenet's
/// published master key", the one compiled into `ghostkey_lib`. It is a
/// parameter only so the tests can mint a chain of their own; it is not
/// reachable from outside this module, because which authority a certificate
/// is checked against is not a caller's decision to make. The ghostkey
/// delegate removed exactly this knob from its own wire protocol for the same
/// reason (see `ghostkey_common::GhostkeyRequest::ImportGhostKey`).
fn certified_key(pem: &str, master: &Option<VerifyingKey>) -> Result<VerifyingKey, String> {
    let cert = GhostkeyCertificateV1::from_armored_string(pem)
        .map_err(|e| format!("not a readable ghostkey certificate: {e}"))?;
    // `verify` returns the notary info string, which encodes the donation
    // tier. Dropped on purpose -- see the module docs.
    cert.verify(master)
        .map_err(|e| format!("does not chain to Freenet's master key: {e}"))?;
    Ok(cert.verifying_key)
}

/// Verify a certificate published by, or inside, the store at
/// `store_contract_id`.
pub fn verify_store_certificate(pem: &str, store_contract_id: &[u8]) -> CertificateStatus {
    verify_store_certificate_against(pem, store_contract_id, &None)
}

fn verify_store_certificate_against(
    pem: &str,
    store_contract_id: &[u8],
    master: &Option<VerifyingKey>,
) -> CertificateStatus {
    if pem.trim().is_empty() {
        return CertificateStatus::Absent;
    }

    let key = match certified_key(pem, master) {
        Ok(key) => key,
        Err(why) => return CertificateStatus::Invalid(why),
    };

    let Ok(bytes) = <[u8; 32]>::try_from(store_contract_id) else {
        return CertificateStatus::Invalid(format!(
            "store contract id is {} bytes, not 32",
            store_contract_id.len()
        ));
    };
    let id = ContractInstanceId::new(bytes);

    match store_instance_ids(&key) {
        Ok(ids) if ids.contains(&id) => CertificateStatus::Verified,
        // The attack this whole module is for: a genuine certificate, issued
        // to somebody else, pasted onto this store. The other explanation is
        // benign and is named too -- see the module docs.
        Ok(_) => CertificateStatus::Invalid(
            "genuine, but not this store's identity; or this store was published by a \
             newer build of Harvest than yours"
                .to_string(),
        ),
        Err(e) => CertificateStatus::Invalid(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;

    /// One notary, minted once.
    ///
    /// `NotaryCertificateV1::new` generates a 2048-bit RSA keypair, which is
    /// seconds of work in a debug build. Every test below issues ghostkeys
    /// under the same notary rather than paying for that again.
    struct TestAuthority {
        master: SigningKey,
        notary: NotaryCertificateV1,
        notary_key: blind_rsa_signatures::SecretKey,
    }

    fn authority() -> &'static TestAuthority {
        static AUTHORITY: std::sync::LazyLock<TestAuthority> = std::sync::LazyLock::new(|| {
            // A fixed seed rather than an RNG: `SigningKey::generate` needs
            // ed25519-dalek's `rand_core` feature, which the workspace does
            // not enable, and a test authority gains nothing from being
            // unpredictable.
            let master = SigningKey::from_bytes(&[0x11; 32]);
            let (notary, notary_key) =
                NotaryCertificateV1::new(&master, &"Test Notary".to_string())
                    .expect("mint a notary certificate");
            TestAuthority {
                master,
                notary,
                notary_key,
            }
        });
        &AUTHORITY
    }

    /// A fresh ghostkey certificate under the shared test authority, and the
    /// PEM a seller would publish for it.
    fn issue_ghostkey() -> (VerifyingKey, String) {
        let a = authority();
        let (cert, _signing_key) = GhostkeyCertificateV1::new(&a.notary, &a.notary_key);
        let pem = cert.to_armored_string().expect("armor the certificate");
        (cert.verifying_key, pem)
    }

    fn test_master() -> Option<VerifyingKey> {
        Some(authority().master.verifying_key())
    }

    /// The store id a seller holding `key` would publish at with this build.
    fn store_id_for(key: &VerifyingKey) -> Vec<u8> {
        store_instance_ids(key).expect("derive store ids")[0]
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn a_genuine_certificate_verifies_for_its_own_store() {
        let (key, pem) = issue_ghostkey();
        assert_eq!(
            verify_store_certificate_against(&pem, &store_id_for(&key), &test_master()),
            CertificateStatus::Verified
        );
    }

    /// The attack the module exists for, and the one a chain-only check waves
    /// straight through. Certificates are public, so a scammer can always
    /// obtain a *genuine* one; what they cannot obtain is the private key
    /// behind it, and the store address is what ties the two together.
    ///
    /// Delete the `store_instance_ids` membership check in
    /// `verify_store_certificate_against` and this is the test that fails.
    #[test]
    fn a_valid_certificate_for_another_identity_does_not_authenticate_this_store() {
        let (victim_key, victim_pem) = issue_ghostkey();
        let (scammer_key, _scammer_pem) = issue_ghostkey();

        // The scammer's own store, carrying the victim's real certificate.
        let status = verify_store_certificate_against(
            &victim_pem,
            &store_id_for(&scammer_key),
            &test_master(),
        );

        assert!(
            matches!(status, CertificateStatus::Invalid(_)),
            "a certificate issued to somebody else must not authenticate this store, got {status:?}"
        );
        // And the certificate itself is genuine -- the rejection is about
        // identity, not about the chain.
        assert_eq!(
            verify_store_certificate_against(
                &victim_pem,
                &store_id_for(&victim_key),
                &test_master()
            ),
            CertificateStatus::Verified,
            "the same certificate must still verify for the store it belongs to"
        );
    }

    /// A store published under a superseded contract build lives at a
    /// different address, and is not thereby fraudulent.
    #[test]
    fn a_certificate_verifies_at_a_superseded_generation() {
        let (key, pem) = issue_ghostkey();
        let ids = store_instance_ids(&key).expect("derive store ids");
        assert!(
            ids.len() > 1,
            "the store lineage should carry at least one superseded generation; \
             without one this test proves nothing"
        );
        for id in ids.iter().skip(1) {
            assert_eq!(
                verify_store_certificate_against(&pem, id.as_bytes(), &test_master()),
                CertificateStatus::Verified,
                "a store at a superseded generation must still verify"
            );
        }
    }

    /// The known limitation, pinned so it stays visible. A store at an
    /// address this build cannot derive -- a future contract generation --
    /// reads exactly like a stolen certificate, because in both cases no
    /// known code hash produces the id. See the module docs for what fixing
    /// it would take.
    #[test]
    fn a_store_at_an_unknown_contract_generation_cannot_be_verified() {
        let (key, pem) = issue_ghostkey();
        let params = crate::migrate::encode_params(&crate::migrate::store_params(&key))
            .expect("encode store parameters");
        // The seller's own key, under a code hash this build knows nothing of.
        let future = crate::migrate::current_id(&[0xAB; 32], &params);

        assert!(
            matches!(
                verify_store_certificate_against(&pem, future.as_bytes(), &test_master()),
                CertificateStatus::Invalid(_)
            ),
            "a generation this build cannot derive cannot be verified either"
        );
    }

    #[test]
    fn a_certificate_from_another_authority_is_rejected() {
        let (key, pem) = issue_ghostkey();
        let stranger = SigningKey::from_bytes(&[0x22; 32]).verifying_key();

        let status = verify_store_certificate_against(&pem, &store_id_for(&key), &Some(stranger));
        assert!(
            matches!(status, CertificateStatus::Invalid(_)),
            "a chain to the wrong master key must not verify, got {status:?}"
        );
    }

    /// The production entry point uses Freenet's master key and nothing else.
    /// A locally minted chain is exactly what a forged one looks like, so it
    /// must fail here even though it passes with the test authority.
    #[test]
    fn the_production_check_uses_freenets_master_key() {
        let (key, pem) = issue_ghostkey();
        let id = store_id_for(&key);

        assert_eq!(
            verify_store_certificate_against(&pem, &id, &test_master()),
            CertificateStatus::Verified,
            "the fixture must be a valid chain under its own authority"
        );
        assert!(
            matches!(
                verify_store_certificate(&pem, &id),
                CertificateStatus::Invalid(_)
            ),
            "a certificate minted outside Freenet's PKI must not verify in production"
        );
    }

    #[test]
    fn text_that_is_not_a_certificate_is_rejected() {
        for pem in [
            "-----BEGIN CERT-----",
            "-----BEGIN GHOSTKEY CERTIFICATE-----rehearsal-----END-----",
            "not a certificate at all",
            "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nbm90IGNib3I=\n-----END GHOSTKEY_CERTIFICATE_V1-----\n",
        ] {
            assert!(
                matches!(
                    verify_store_certificate_against(pem, &[7u8; 32], &test_master()),
                    CertificateStatus::Invalid(_)
                ),
                "{pem:?} is not a certificate and must not verify"
            );
        }
    }

    /// An unpublished certificate is its own outcome. Folding it into
    /// `Invalid` would tell a buyer a store is claiming a bond it does not
    /// have, when it is claiming nothing at all.
    #[test]
    fn an_absent_certificate_is_absent_rather_than_invalid() {
        for pem in ["", "   \n "] {
            assert_eq!(
                verify_store_certificate_against(pem, &[7u8; 32], &test_master()),
                CertificateStatus::Absent
            );
        }
    }

    #[test]
    fn a_contract_id_of_the_wrong_length_does_not_verify() {
        let (_key, pem) = issue_ghostkey();
        assert!(matches!(
            verify_store_certificate_against(&pem, &[1u8; 31], &test_master()),
            CertificateStatus::Invalid(_)
        ));
    }
}
