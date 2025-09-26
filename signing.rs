//! PGP signing and signature verification functionality
use crate::keypair::KeyPair;
use pgp::composed::message::Message;
use pgp::{crypto, Deserializable};
use rand::prelude::*;
use std::io::Cursor;
use thiserror::Error as ThisError;

/// Errors that can occur during signing or verification operations
#[derive(ThisError, Debug)]
pub enum SigningError {
    #[error("Failed to sign data: {0}")]
    SigningFailed(String),
    #[error("Failed to verify signature: {0}")]
    VerificationFailed(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("No content in message")]
    NoContent,
    #[error("PGP error: {0}")]
    PgpError(#[from] pgp::errors::Error),
    #[error("Failed to convert bytes to string: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

/// Sign a message and create a signed message (data + signature combined)
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the secret key for signing
/// * `message` - The message string to be signed
///
/// # Returns
/// * `Ok(String)` - Armored signed message on success
/// * `Err(SigningError)` - Error if signing fails
pub fn sign_message(key_pair: &KeyPair, message: &str) -> Result<String, SigningError> {
    let mut rng = StdRng::from_entropy();
    let passwd_fn = || String::new();

    // Create a literal message
    let msg = Message::new_literal("", message);

    // Sign the message
    let signed_msg = msg
        .sign(
            &mut rng,
            key_pair.secret_key(),
            passwd_fn,
            crypto::hash::HashAlgorithm::SHA2_256,
        )
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    // Convert to armored string
    signed_msg
        .to_armored_string(pgp::ArmorOptions::default())
        .map_err(|e| SigningError::SigningFailed(e.to_string()))
}

/// Verify a signed message and extract the original data
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the public key for verification
/// * `signed_message_armored` - The armored signed message string
///
/// # Returns
/// * `Ok((String, bool))` - Tuple of (extracted_message, is_signature_valid)
/// * `Err(SigningError)` - Error during verification
pub fn verify_signed_message(
    key_pair: &KeyPair,
    signed_message_armored: &str,
) -> Result<(String, bool), SigningError> {
    // Parse the armored signed message
    let msg = Message::from_armor_single(Cursor::new(signed_message_armored))
        .map_err(|e| SigningError::InvalidSignatureFormat(e.to_string()))?
        .0;

    // First try to verify, following the pattern from decrypt.rs where verify returns a result
    let is_valid = match msg.verify(key_pair.public_key()) {
        Ok(_) => true,
        Err(_) => false,
    };

    // Extract content regardless of verification status
    let content = msg.get_content()?.ok_or_else(|| SigningError::NoContent)?;

    let message_str = String::from_utf8(content)?;

    Ok((message_str, is_valid))
}

/// Sign arbitrary data by wrapping it in a literal message
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the secret key for signing
/// * `data` - The data to be signed
///
/// # Returns
/// * `Ok(String)` - Armored signed message on success
/// * `Err(SigningError)` - Error if signing fails
pub fn sign_data(key_pair: &KeyPair, data: &[u8]) -> Result<String, SigningError> {
    // Convert bytes to string for literal message
    let data_str = String::from_utf8_lossy(data);
    sign_message(key_pair, &data_str)
}

/// Verify signed data and extract the original data
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the public key for verification
/// * `signed_data_armored` - The armored signed message string
///
/// # Returns
/// * `Ok((Vec<u8>, bool))` - Tuple of (extracted_data, is_signature_valid)
/// * `Err(SigningError)` - Error during verification
pub fn verify_signed_data(
    key_pair: &KeyPair,
    signed_data_armored: &str,
) -> Result<(Vec<u8>, bool), SigningError> {
    let (message_str, valid) = verify_signed_message(key_pair, signed_data_armored)?;
    Ok((message_str.into_bytes(), valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_message() {
        let key_pair = KeyPair::generate_key_pair("test@example.com");
        let test_message = "Hello, PGP signed message world!";

        // Sign the message
        let signed_message = sign_message(&key_pair, test_message).unwrap();
        assert!(!signed_message.is_empty());
        println!("Signed message:\n{}", signed_message);
        assert!(false);

        // Verify the signed message
        let (extracted_message, is_valid) =
            verify_signed_message(&key_pair, &signed_message).unwrap();
        assert!(is_valid);
        assert_eq!(extracted_message, test_message);
    }

    #[test]
    fn test_sign_and_verify_data() {
        let key_pair = KeyPair::generate_key_pair("test@example.com");
        let test_data = b"Hello, PGP signing world!";

        // Sign the data
        let signed_data = sign_data(&key_pair, test_data).unwrap();
        assert!(!signed_data.is_empty());

        // Verify the signed data
        let (extracted_data, is_valid) = verify_signed_data(&key_pair, &signed_data).unwrap();
        assert!(is_valid);
        assert_eq!(extracted_data, test_data);
    }

    #[test]
    fn test_cross_key_verification_fails() {
        let key_pair1 = KeyPair::generate_key_pair("test1@example.com");
        let key_pair2 = KeyPair::generate_key_pair("test2@example.com");
        let test_message = "Hello, cross-key test!";

        // Sign with key_pair1
        let signed_message = sign_message(&key_pair1, test_message).unwrap();

        // Try to verify with key_pair2 (should fail)
        let (extracted_message, is_valid) =
            verify_signed_message(&key_pair2, &signed_message).unwrap();
        assert!(!is_valid);
        assert_eq!(extracted_message, test_message); // Content should still be extractable
    }
}
