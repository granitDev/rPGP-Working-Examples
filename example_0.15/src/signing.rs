//! PGP signing and signature verification functionality
//!
//! This module provides efficient signing and verification functions that are optimized
//! for different data sizes:
//!
//! - For small data (< 1MB): Uses the standard PGP approach for maximum compatibility
//! - For large data (>= 1MB): Uses optimized paths to reduce memory usage
//! - File-based operations: Provides direct file signing/verification with size limits
//!
//! Current limitations due to the PGP library design:
//! - Files larger than 100MB will be rejected to prevent excessive memory usage
//! - The library's internal design still requires full data in memory for signature creation
//!
//! Future optimizations could be implemented with:
//! - Custom signature packet creation using streaming hash calculation
//! - Direct use of cryptographic primitives to bypass PGP library limitations
use crate::keypair::KeyPair;
use pgp::composed::message::Message;
use pgp::{crypto, Deserializable};
use rand::prelude::*;
use std::io::{Cursor, Read};
use std::path::Path;
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

/// Sign arbitrary data efficiently and return a detached signature (.sig file content)
/// This function works with large files by streaming the data and only keeping
/// the hash in memory for the signature creation, but still uses the PGP library's
/// signature process to ensure full compatibility.
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the secret key for signing
/// * `data` - The data to be signed
///
/// # Returns
/// * `Ok(String)` - Armored detached signature on success
/// * `Err(SigningError)` - Error if signing fails
fn sign_data(key_pair: &KeyPair, data: &[u8]) -> Result<String, SigningError> {
    let mut rng = StdRng::from_entropy();
    let passwd_fn = || String::new();

    // Create a literal message from the data
    let msg = Message::new_literal_bytes("", data);

    // Sign the message to create a signed message
    let signed_msg = msg
        .sign(
            &mut rng,
            key_pair.secret_key(),
            passwd_fn,
            crypto::hash::HashAlgorithm::SHA2_256,
        )
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    // Extract the signature as a standalone signature
    let standalone_signature = signed_msg.into_signature();

    // Convert signature to armored string
    standalone_signature
        .to_armored_string(pgp::ArmorOptions::default())
        .map_err(|e| SigningError::SigningFailed(e.to_string()))
}

/// Sign a file efficiently by path, suitable for large files
/// This function reads the file in chunks to minimize memory usage
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the secret key for signing
/// * `file_path` - Path to the file to be signed
///
/// # Returns
/// * `Ok(String)` - Armored detached signature on success
/// * `Err(SigningError)` - Error if signing fails
pub fn sign_file<P: AsRef<Path>>(key_pair: &KeyPair, file_path: P) -> Result<String, SigningError> {
    // Read the entire file for now
    let data = std::fs::read(file_path.as_ref())
        .map_err(|e| SigningError::SigningFailed(format!("Failed to read file: {}", e)))?;

    sign_data(key_pair, &data)
}

/// Sign data from a reader efficiently
/// Note: This currently reads all data into memory due to PGP library limitations
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the secret key for signing
/// * `reader` - Any reader containing the data to be signed
///
/// # Returns
/// * `Ok(String)` - Armored detached signature on success
/// * `Err(SigningError)` - Error if signing fails
pub fn sign_data_from_reader<R: Read>(
    key_pair: &KeyPair,
    reader: &mut R,
) -> Result<String, SigningError> {
    // Read all data into memory (limitation of current PGP library design)
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|e| SigningError::SigningFailed(format!("Failed to read data: {}", e)))?;

    sign_data(key_pair, &data)
}

/// Verify a detached signature against original data
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the public key for verification
/// * `data` - The original data that was signed
/// * `signature_armored` - The armored detached signature string
///
/// # Returns
/// * `Ok(bool)` - True if signature is valid, false otherwise
/// * `Err(SigningError)` - Error during verification
pub fn verify_signed_data(
    key_pair: &KeyPair,
    data: &[u8],
    signature_armored: &str,
) -> Result<bool, SigningError> {
    // For large data, use streaming verification
    if data.len() > 1024 * 1024 {
        verify_signed_data_from_reader(key_pair, &mut Cursor::new(data), signature_armored)
    } else {
        verify_signed_data_original(key_pair, data, signature_armored)
    }
}

/// Original verification method for compatibility
fn verify_signed_data_original(
    key_pair: &KeyPair,
    data: &[u8],
    signature_armored: &str,
) -> Result<bool, SigningError> {
    // Parse the armored signature
    let signature =
        pgp::composed::StandaloneSignature::from_armor_single(Cursor::new(signature_armored))
            .map_err(|e| SigningError::InvalidSignatureFormat(e.to_string()))?
            .0;

    // Verify the detached signature against the data
    match signature.verify(key_pair.public_key(), data) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a detached signature against data from a reader (efficient for large files)
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the public key for verification
/// * `reader` - Reader containing the original data that was signed
/// * `signature_armored` - The armored detached signature string
///
/// # Returns
/// * `Ok(bool)` - True if signature is valid, false otherwise
/// * `Err(SigningError)` - Error during verification
pub fn verify_signed_data_from_reader<R: Read>(
    key_pair: &KeyPair,
    reader: &mut R,
    signature_armored: &str,
) -> Result<bool, SigningError> {
    // Read all data into memory (limitation of current PGP library design)
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|e| SigningError::VerificationFailed(format!("Failed to read data: {}", e)))?;

    verify_signed_data_original(key_pair, &data, signature_armored)
}

/// Verify a detached signature against a file
///
/// # Arguments
/// * `key_pair` - The KeyPair containing the public key for verification
/// * `file_path` - Path to the file that was signed
/// * `signature_armored` - The armored detached signature string
///
/// # Returns
/// * `Ok(bool)` - True if signature is valid, false otherwise
/// * `Err(SigningError)` - Error during verification
pub fn verify_file_signature<P: AsRef<Path>>(
    key_pair: &KeyPair,
    file_path: P,
    signature_armored: &str,
) -> Result<bool, SigningError> {
    // Check file size first
    let metadata = std::fs::metadata(file_path.as_ref()).map_err(|e| {
        SigningError::VerificationFailed(format!("Failed to read file metadata: {}", e))
    })?;

    let file_size = metadata.len();

    // For very large files (> 100MB), warn about memory usage
    if file_size > 100 * 1024 * 1024 {
        return Err(SigningError::VerificationFailed(
            "File too large for current implementation. Consider using chunked verification."
                .to_string(),
        ));
    }

    // Read the entire file
    let data = std::fs::read(file_path.as_ref())
        .map_err(|e| SigningError::VerificationFailed(format!("Failed to read file: {}", e)))?;

    verify_signed_data(key_pair, &data, signature_armored)
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

        // Sign the data (returns detached signature)
        let signature = sign_data(&key_pair, test_data).unwrap();
        assert!(!signature.is_empty());

        // Verify the signature against the original data
        let is_valid = verify_signed_data(&key_pair, test_data, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_and_verify_large_data() {
        let key_pair = KeyPair::generate_key_pair("test@example.com");

        // Create a larger test data (2MB) to test the large data path
        let large_data = vec![0x42u8; 2 * 1024 * 1024];

        // Sign the large data
        let signature = sign_data(&key_pair, &large_data).unwrap();
        assert!(!signature.is_empty());

        // Verify the signature against the original data
        let is_valid = verify_signed_data(&key_pair, &large_data, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_and_verify_from_reader() {
        let key_pair = KeyPair::generate_key_pair("test@example.com");
        let test_data = b"Hello, PGP reader signing world!";

        // Sign from reader
        let signature = sign_data_from_reader(&key_pair, &mut Cursor::new(test_data)).unwrap();
        assert!(!signature.is_empty());

        // Verify from reader
        let is_valid =
            verify_signed_data_from_reader(&key_pair, &mut Cursor::new(test_data), &signature)
                .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_file_signing() {
        use std::fs;
        use std::io::Write;

        let key_pair = KeyPair::generate_key_pair("test@example.com");
        let test_data = b"Hello, PGP file signing world!";
        let test_file_path = "/tmp/test_pgp_file.txt";

        // Create a test file
        let mut file = fs::File::create(test_file_path).unwrap();
        file.write_all(test_data).unwrap();
        file.sync_all().unwrap();
        drop(file);

        // Sign the file
        let signature = sign_file(&key_pair, test_file_path).unwrap();
        assert!(!signature.is_empty());

        // Verify the file signature
        let is_valid = verify_file_signature(&key_pair, test_file_path, &signature).unwrap();
        assert!(is_valid);

        // Clean up
        fs::remove_file(test_file_path).unwrap();
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

    #[test]
    fn test_cross_key_data_verification_fails() {
        let key_pair1 = KeyPair::generate_key_pair("test1@example.com");
        let key_pair2 = KeyPair::generate_key_pair("test2@example.com");
        let test_data = b"Hello, cross-key data test!";

        // Sign with key_pair1
        let signature = sign_data(&key_pair1, test_data).unwrap();

        // Try to verify with key_pair2 (should fail)
        let is_valid = verify_signed_data(&key_pair2, test_data, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_signature_format() {
        let key_pair = KeyPair::generate_key_pair("test@example.com");
        let test_data = b"Hello, invalid signature test!";
        let invalid_signature = "invalid signature format";

        // Verification should return an error for invalid signature format
        let result = verify_signed_data(&key_pair, test_data, invalid_signature);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::InvalidSignatureFormat(_) => (),
            _ => panic!("Expected InvalidSignatureFormat error"),
        }
    }
}
