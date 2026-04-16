use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;

/// Sign a serde-serializable struct by CBOR-encoding it, then Ed25519-signing the bytes.
pub fn sign_struct<T: Serialize>(message: &T, signing_key: &SigningKey) -> Signature {
    let mut data = Vec::new();
    ciborium::ser::into_writer(message, &mut data).expect("CBOR serialization should not fail");
    signing_key.sign(&data)
}

/// Verify an Ed25519 signature over the CBOR encoding of a struct.
pub fn verify_struct<T: Serialize>(
    message: &T,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), SignatureError> {
    let mut data = Vec::new();
    ciborium::ser::into_writer(message, &mut data).expect("CBOR serialization should not fail");
    verifying_key.verify(&data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_sign_verify_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let message = "hello harvest";
        let signature = sign_struct(&message, &signing_key);
        assert!(verify_struct(&message, &signature, &verifying_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]).verifying_key();

        let message = "hello harvest";
        let signature = sign_struct(&message, &signing_key);
        assert!(verify_struct(&message, &signature, &wrong_key).is_err());
    }
}
