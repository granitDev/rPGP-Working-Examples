//! Create PGP Key Pairs for encryption and decryption
use os_path::OsPath;
use pgp::types::SecretKeyTrait;
use pgp::{composed, crypto, Deserializable};
use rand::prelude::*;
use smallvec::*;
use thiserror::Error as ThisError;

/// Errors that can occur when generating a key pair
#[derive(ThisError, Debug)]
pub enum KeyPairError {
    #[error("Failed to create KeyPair from armored strings: {0}")]
    FromStringError(String),
    #[error("Failed to load key pair: {file} | Error: {source}")]
    LoadError {
        file: OsPath,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to save key pair: {0}")]
    SaveError(String),
    #[error("Failed to convert key to armored string: {0}")]
    ToArmoredStringError(String),
    #[error("PGP error: {0}")]
    PgpError(#[from] pgp::errors::Error),
    #[error("IO error context: {0}")]
    IoError(#[from] std::io::Error),
}

/// A struct that contains a public and private key pair
#[derive(Debug)]
pub struct KeyPair {
    secret_key: pgp::SignedSecretKey,
    public_key: pgp::SignedPublicKey,
}

impl KeyPair {
    /// Creates a KeyPair from armored string representations of the secret and public keys
    pub fn from_armored_strings(secret_key: &str, public_key: &str) -> Result<Self, KeyPairError> {
        let (secret_key, _) = pgp::SignedSecretKey::from_string(secret_key)
            .map_err(|e| KeyPairError::FromStringError(e.to_string()))?;
        let (public_key, _) = pgp::SignedPublicKey::from_string(public_key)
            .map_err(|e| KeyPairError::FromStringError(e.to_string()))?;

        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }

    /// Creates a KeyPair by loading the secret and public keys from files
    pub fn from_files(
        secret_key_path: &OsPath,
        public_key_path: &OsPath,
    ) -> Result<Self, KeyPairError> {
        let secret_key =
            std::fs::read_to_string(&secret_key_path).map_err(|e| KeyPairError::LoadError {
                file: secret_key_path.clone(),
                source: e,
            })?;
        let public_key =
            std::fs::read_to_string(&public_key_path).map_err(|e| KeyPairError::LoadError {
                file: public_key_path.clone(),
                source: e,
            })?;
        Self::from_armored_strings(&secret_key, &public_key)
    }

    /// Generates a new KeyPair with default parameters
    /// # Arguments
    /// * `user_id` - The user ID to associate with the key pair, can be anything you want, typicall an email address
    #[allow(clippy::redundant_closure)]
    pub fn generate_key_pair(user_id: &str) -> Self {
        let mut key_params = composed::key::SecretKeyParamsBuilder::default();
        key_params
            .key_type(composed::KeyType::Rsa(2048))
            .can_certify(false)
            .can_sign(true)
            .primary_user_id(user_id.into())
            .preferred_symmetric_algorithms(smallvec![crypto::sym::SymmetricKeyAlgorithm::AES256]);

        let secret_key_params = key_params
            .build()
            .expect("Must be able to create secret key params");

        let rng = StdRng::from_entropy();
        let secret_key = secret_key_params
            .generate(rng)
            .expect("Failed to generate a plain key.");

        let rng = StdRng::from_entropy();
        let passwd_fn = || String::new();
        let signed_secret_key = secret_key
            .sign(rng, passwd_fn)
            .expect("Secret Key must be able to sign its own metadata");

        let rng = StdRng::from_entropy();
        let public_key = signed_secret_key.public_key();
        let signed_public_key = public_key
            .sign(rng, &signed_secret_key, passwd_fn)
            .expect("Public key must be able to sign its own metadata");

        KeyPair {
            secret_key: signed_secret_key,
            public_key: signed_public_key,
        }
    }

    /// Saves the KeyPair to the specified directory as "secret_key.asc" and "public_key.asc"
    pub fn save(&self, save_directory: &OsPath) -> Result<(), KeyPairError> {
        let ao = pgp::ArmorOptions {
            headers: None,
            ..Default::default()
        };
        std::fs::write(
            save_directory.join("secret_key.asc"),
            self.secret_key.to_armored_string(ao.clone())?,
        )?;
        std::fs::write(
            save_directory.join("public_key.asc"),
            self.public_key.to_armored_string(ao)?,
        )?;
        Ok(())
    }

    /// Accessor for the secret key
    pub fn secret_key(&self) -> &pgp::SignedSecretKey {
        &self.secret_key
    }

    /// Accessor for the public key
    pub fn public_key(&self) -> &pgp::SignedPublicKey {
        &self.public_key
    }

    /// Returns the armored string representation of the public key
    pub fn public_key_armored_string(&self) -> Result<String, KeyPairError> {
        let ao = pgp::ArmorOptions {
            headers: None,
            ..Default::default()
        };
        self.public_key
            .to_armored_string(ao)
            .map_err(|e| KeyPairError::ToArmoredStringError(e.to_string()))
    }

    /// Returns the armored string representation of the secret key
    pub fn secret_key_armored_string(&self) -> Result<String, KeyPairError> {
        let ao = pgp::ArmorOptions {
            headers: None,
            ..Default::default()
        };
        self.secret_key
            .to_armored_string(ao)
            .map_err(|e| KeyPairError::ToArmoredStringError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair() {
        let key_pair = KeyPair::generate_key_pair("foo bar baz");
        let pub_ascii = key_pair.public_key_armored_string().unwrap();
        let sec_ascii = key_pair.secret_key_armored_string().unwrap();
        assert!(!&pub_ascii.is_empty());
        assert!(!&sec_ascii.is_empty());

        let key_pair2 = KeyPair::from_armored_strings(&sec_ascii, &pub_ascii).unwrap();
        assert_eq!(key_pair.secret_key, key_pair2.secret_key);
        assert_eq!(key_pair.public_key, key_pair2.public_key);
    }
}
