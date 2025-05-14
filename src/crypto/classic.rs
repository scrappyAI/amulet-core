//!
//! Implementation of the `CryptoProvider` traits for the CLASSIC algorithm suite.
//! Uses BLAKE3-256 for hashing and Ed25519 for signatures.

use crate::types::{AlgSuite, CID, PublicKey, PrivateKeyPlaceholder, Signature};
use crate::error::{KernelError, CryptoError};
use super::{Hasher, Signer, Verifier, CryptoProvider}; // Super refers to crypto/mod.rs

// Import necessary items from chosen crypto libraries.
// These lines will cause errors until `blake3` and `ed25519-dalek` are added to Cargo.toml.
use blake3::Hasher as Blake3Hasher;
use ed25519_dalek::{
    Signer as Ed25519Signer,
    Verifier as Ed25519Verifier,
    Signature as Ed25519Signature,
    SigningKey as Ed25519SecretKey,
    VerifyingKey as Ed25519PublicKey,
    SECRET_KEY_LENGTH
};
use std::convert::TryInto; // Keep this for .try_into()

/// A `CryptoProvider` implementation for the CLASSIC suite (BLAKE3-256, Ed25519).
#[derive(Debug, Default, Clone, Copy)]
pub struct ClassicCryptoProvider;

impl Hasher for ClassicCryptoProvider {
    fn hash(data: &[u8], alg_suite: AlgSuite) -> Result<CID, CryptoError> {
        if alg_suite != AlgSuite::CLASSIC {
            tracing::warn!(
                "ClassicCryptoProvider hash called with unsupported AlgSuite: {:?}. Expected CLASSIC.",
                alg_suite
            );
            return Err(CryptoError::UnsupportedAlgSuite(alg_suite));
        }
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        Ok(*hasher.finalize().as_bytes()) // Returns [u8; 32]
    }
}

impl Signer for ClassicCryptoProvider {
    fn sign(data: &[u8], private_key_bytes: &PrivateKeyPlaceholder, alg_suite: AlgSuite) -> Result<Signature, KernelError> {
        if alg_suite != AlgSuite::CLASSIC {
            return Err(KernelError::Other(format!("ClassicCryptoProvider cannot sign for suite {:?}", alg_suite)));
        }

        let secret_key_bytes_slice = private_key_bytes.get(..SECRET_KEY_LENGTH)
            .ok_or_else(|| KernelError::Other("Invalid private key length for Ed25519".to_string()))?;
        
        let secret_key_array: [u8; SECRET_KEY_LENGTH] = secret_key_bytes_slice.try_into()
            .map_err(|_| KernelError::Other("Failed to convert private key slice to array for Ed25519".to_string()))?;
        
        let secret_key = Ed25519SecretKey::from_bytes(&secret_key_array); // from_bytes takes &[u8; 32]
        
        let signature: Ed25519Signature = secret_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verifier for ClassicCryptoProvider {
    fn verify(data: &[u8], signature_bytes: &Signature, public_key_bytes: &PublicKey, alg_suite: AlgSuite) -> Result<(), KernelError> {
        if alg_suite != AlgSuite::CLASSIC {
            return Err(KernelError::Other(format!("ClassicCryptoProvider cannot verify for suite {:?}", alg_suite)));
        }

        let signature_array: &[u8; ed25519_dalek::SIGNATURE_LENGTH] = signature_bytes.as_slice().try_into()
            .map_err(|_| KernelError::SignatureVerificationFailed)?;
        let signature = Ed25519Signature::from_bytes(signature_array);

        let public_key_array: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = public_key_bytes.as_slice().try_into()
            .map_err(|_| KernelError::SignatureVerificationFailed)?;
        let public_key = Ed25519PublicKey::from_bytes(public_key_array)
            .map_err(|e| KernelError::Other(format!("Invalid public key format for Ed25519: {}", e)))?;

        public_key.verify(data, &signature)
            .map_err(|_| KernelError::SignatureVerificationFailed)
    }
}

impl CryptoProvider for ClassicCryptoProvider {}


#[cfg(test)]
mod tests {
    use super::*; 
    use crate::types::PrivateKeyPlaceholder; 
    use ed25519_dalek::SigningKey; // Import SigningKey directly for tests
    use rand::rngs::OsRng;

    #[test]
    fn test_classic_hash() {
        let data = b"hello amulet";
        let cid = ClassicCryptoProvider::hash(data, AlgSuite::CLASSIC).unwrap();
        
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let expected_cid_bytes = *hasher.finalize().as_bytes();

        assert_eq!(cid, expected_cid_bytes);

        let res_fips = ClassicCryptoProvider::hash(data, AlgSuite::FIPS);
        assert!(matches!(res_fips, Err(CryptoError::UnsupportedAlgSuite(AlgSuite::FIPS))));
    }

    #[test]
    fn test_classic_sign_verify_roundtrip() {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng); // Now uses the imported SigningKey
        let secret_key_bytes: PrivateKeyPlaceholder = keypair.to_bytes().to_vec();
        let public_key_bytes: PublicKey = keypair.verifying_key().to_bytes().to_vec();

        let data = b"message to sign";

        let signature = ClassicCryptoProvider::sign(data, &secret_key_bytes, AlgSuite::CLASSIC).unwrap();
        assert_eq!(signature.len(), ed25519_dalek::SIGNATURE_LENGTH); // Use full path for clarity or import constant

        let verification_result = ClassicCryptoProvider::verify(data, &signature, &public_key_bytes, AlgSuite::CLASSIC);
        assert!(verification_result.is_ok());
    }

    #[test]
    fn test_classic_verify_tampered_data() {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        let secret_key_bytes: PrivateKeyPlaceholder = keypair.to_bytes().to_vec();
        let public_key_bytes: PublicKey = keypair.verifying_key().to_bytes().to_vec();

        let data = b"message to sign";
        let tampered_data = b"tampered message";

        let signature = ClassicCryptoProvider::sign(data, &secret_key_bytes, AlgSuite::CLASSIC).unwrap();

        let verification_result = ClassicCryptoProvider::verify(tampered_data, &signature, &public_key_bytes, AlgSuite::CLASSIC);
        assert!(verification_result.is_err());
        assert_eq!(verification_result.unwrap_err(), KernelError::SignatureVerificationFailed);
    }

    #[test]
    fn test_classic_verify_wrong_key() {
        let mut csprng = OsRng;
        let keypair1 = SigningKey::generate(&mut csprng);
        let secret_key1_bytes: PrivateKeyPlaceholder = keypair1.to_bytes().to_vec();
        
        let keypair2 = SigningKey::generate(&mut csprng);
        let public_key2_bytes: PublicKey = keypair2.verifying_key().to_bytes().to_vec();

        let data = b"message to sign";
        let signature = ClassicCryptoProvider::sign(data, &secret_key1_bytes, AlgSuite::CLASSIC).unwrap();

        let verification_result = ClassicCryptoProvider::verify(data, &signature, &public_key2_bytes, AlgSuite::CLASSIC);
        assert!(verification_result.is_err());
        assert_eq!(verification_result.unwrap_err(), KernelError::SignatureVerificationFailed);
    }

    #[test]
    fn test_unsupported_suite_sign() {
        let secret_key_bytes: PrivateKeyPlaceholder = vec![0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        let data = b"test";
        let result = ClassicCryptoProvider::sign(data, &secret_key_bytes, AlgSuite::FIPS);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_suite_verify() {
        let public_key_bytes: PublicKey = vec![0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        let signature: Signature = vec![0u8; ed25519_dalek::SIGNATURE_LENGTH];
        let data = b"test";
        let result = ClassicCryptoProvider::verify(data, &signature, &public_key_bytes, AlgSuite::PQC);
        assert!(result.is_err());
    }
} 