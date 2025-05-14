//!
//! Implementation of the `CryptoProvider` traits for the FIPS algorithm suite.
//! Uses SHA-3-256 for hashing and ECDSA with P-256 for signatures.

use crate::types::{AlgSuite, CID, PublicKey, PrivateKeyPlaceholder, Signature};
use crate::error::{KernelError, CryptoError};
use super::{Hasher, Signer, Verifier, CryptoProvider};

// Import necessary items from chosen crypto libraries.
// These lines will cause errors until `sha3`, `p256`, and `ecdsa` are added to Cargo.toml.
use sha3::{Digest, Sha3_256};
use p256::{
    ecdsa::{
        SigningKey as EcdsaP256SigningKey,
        VerifyingKey as EcdsaP256VerifyingKey,
        Signature as EcdsaP256Signature // This is `p256::ecdsa::Signature`
    },
    SecretKey as P256SecretKey // p256::SecretKey for key generation/conversion
};
// The `ecdsa` crate re-exports `Signature` type for interop, often used with specific curve crates.
// `p256::ecdsa::Signature` should be used for P-256 specific operations.
use ecdsa::signature::{
    Signer as EcdsaSigner,
    Verifier as EcdsaVerifier
};

/// A `CryptoProvider` implementation for the FIPS suite (SHA-3-256, ECDSA P-256).
#[derive(Debug, Default, Clone, Copy)]
pub struct FipsCryptoProvider;

impl Hasher for FipsCryptoProvider {
    fn hash(data: &[u8], alg_suite: AlgSuite) -> Result<CID, CryptoError> {
        if alg_suite != AlgSuite::FIPS {
            tracing::warn!(
                "FipsCryptoProvider hash called with unsupported AlgSuite: {:?}. Expected FIPS.",
                alg_suite
            );
            return Err(CryptoError::UnsupportedAlgSuite(alg_suite));
        }
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Ok(hasher.finalize().into()) // GenericArray<u8, N> converts to [u8; N]
    }
}

impl Signer for FipsCryptoProvider {
    fn sign(data: &[u8], private_key_bytes: &PrivateKeyPlaceholder, alg_suite: AlgSuite) -> Result<Signature, KernelError> {
        if alg_suite != AlgSuite::FIPS {
            return Err(KernelError::Other(format!("FipsCryptoProvider cannot sign for suite {:?}", alg_suite)));
        }

        // P256SecretKey from p256 crate can be created from raw bytes.
        // It expects a byte array of specific length (field size for P-256, which is 32 bytes).
        let secret_key = P256SecretKey::from_slice(private_key_bytes)
            .map_err(|e| KernelError::Other(format!("Invalid private key bytes for P-256: {}", e)))?;
        
        let signing_key: EcdsaP256SigningKey = EcdsaP256SigningKey::from(secret_key); // Convert p256::SecretKey to ecdsa::SigningKey

        let signature: EcdsaP256Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verifier for FipsCryptoProvider {
    fn verify(data: &[u8], signature_bytes: &Signature, public_key_bytes: &PublicKey, alg_suite: AlgSuite) -> Result<(), KernelError> {
        if alg_suite != AlgSuite::FIPS {
            return Err(KernelError::Other(format!("FipsCryptoProvider cannot verify for suite {:?}", alg_suite)));
        }

        let verifying_key = EcdsaP256VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| KernelError::Other(format!("Invalid public key bytes for P-256: {}", e)))?;
        
        let signature = EcdsaP256Signature::from_slice(signature_bytes)
            .map_err(|e| KernelError::Other(format!("Invalid signature format for P-256: {}",e)))?;

        verifying_key.verify(data, &signature)
            .map_err(|e| KernelError::Other(format!("P-256 ECDSA verification failed: {}", e))) // Map `ecdsa::Error` to `KernelError`
    }
}

impl CryptoProvider for FipsCryptoProvider {}

#[cfg(test)]
mod tests {
    use super::*; 
    use crate::types::{PrivateKeyPlaceholder, PublicKey};
    use p256::ecdsa::SigningKey as EcdsaP256SigningKey; // For key generation
    use rand::rngs::OsRng; // For a random number generator

    #[test]
    fn test_fips_hash() {
        let data = b"hello amulet fips";
        let cid = FipsCryptoProvider::hash(data, AlgSuite::FIPS).unwrap();
        
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let expected_cid_bytes: [u8; 32] = hasher.finalize().into();

        assert_eq!(cid, expected_cid_bytes);

        let res_classic = FipsCryptoProvider::hash(data, AlgSuite::CLASSIC);
        assert!(matches!(res_classic, Err(CryptoError::UnsupportedAlgSuite(AlgSuite::CLASSIC))));
    }

    #[test]
    fn test_fips_sign_verify_roundtrip() {
        // Generate a P256 key pair
        let secret_key = P256SecretKey::random(&mut OsRng);
        let signing_key = EcdsaP256SigningKey::from(&secret_key); // Correct way to get SigningKey
        let verifying_key = signing_key.verifying_key();

        let private_key_placeholder: PrivateKeyPlaceholder = secret_key.to_bytes().to_vec();
        let public_key_bytes: PublicKey = verifying_key.to_sec1_bytes().as_ref().to_vec(); // SEC1 encoded public key

        let data = b"message for FIPS signature";

        let signature = FipsCryptoProvider::sign(data, &private_key_placeholder, AlgSuite::FIPS).unwrap();
        
        let verification_result = FipsCryptoProvider::verify(data, &signature, &public_key_bytes, AlgSuite::FIPS);
        assert!(verification_result.is_ok(), "Verification failed: {:?}", verification_result.err());
    }

    #[test]
    fn test_fips_verify_tampered_data() {
        let secret_key = P256SecretKey::random(&mut OsRng);
        let signing_key = EcdsaP256SigningKey::from(&secret_key);
        let verifying_key = signing_key.verifying_key();

        let private_key_placeholder: PrivateKeyPlaceholder = secret_key.to_bytes().to_vec();
        let public_key_bytes: PublicKey = verifying_key.to_sec1_bytes().as_ref().to_vec();
        
        let data = b"message for FIPS signature";
        let tampered_data = b"tampered message for FIPS";

        let signature = FipsCryptoProvider::sign(data, &private_key_placeholder, AlgSuite::FIPS).unwrap();

        let verification_result = FipsCryptoProvider::verify(tampered_data, &signature, &public_key_bytes, AlgSuite::FIPS);
        assert!(verification_result.is_err());
    }

    #[test]
    fn test_fips_verify_wrong_key() {
        let secret_key1 = P256SecretKey::random(&mut OsRng);
        let _signing_key1 = EcdsaP256SigningKey::from(&secret_key1); // underscore to silence unused var warning
        let private_key1_placeholder: PrivateKeyPlaceholder = secret_key1.to_bytes().to_vec();

        let secret_key2 = P256SecretKey::random(&mut OsRng);
        let signing_key2 = EcdsaP256SigningKey::from(&secret_key2);
        let verifying_key2 = signing_key2.verifying_key(); // Verifying key from a DIFFERENT pair
        let public_key2_bytes: PublicKey = verifying_key2.to_sec1_bytes().as_ref().to_vec();

        let data = b"message for FIPS signature";
        let signature = FipsCryptoProvider::sign(data, &private_key1_placeholder, AlgSuite::FIPS).unwrap();

        let verification_result = FipsCryptoProvider::verify(data, &signature, &public_key2_bytes, AlgSuite::FIPS);
        assert!(verification_result.is_err());
    }
} 