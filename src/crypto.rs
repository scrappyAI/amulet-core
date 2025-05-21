use crate::primitives::{PublicKey, Signature};
use crate::types::AlgSuite;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("Signature verification failed: invalid signature")]
    InvalidSignature,
    #[error("Hashing operation failed: {0}")]
    HashingFailure(String),
    #[error("Unsupported or invalid algorithm suite tag: {0}")]
    UnsupportedAlgorithmSuite(u8),
    #[error("Crypto operation failed for an unknown reason: {0}")]
    Other(String),
}

/// Trait defining the cryptographic operations required by the Amulet kernel.
/// This trait is intended to be implemented by a dedicated crypto crate (e.g., Amulet-Crypto).
pub trait CryptoProvider: Send + Sync + std::fmt::Debug + Clone + Default {
    /// Hashes the given data using the specified algorithm suite.
    ///
    /// # Arguments
    /// * `data`: The data to hash.
    /// * `alg_suite`: The algorithm suite to use for hashing.
    ///
    /// # Returns
    /// A `Result` containing the 32-byte hash (CID) or a `CryptoError`.
    fn hash(&self, data: &[u8], alg_suite: AlgSuite) -> Result<[u8; 32], CryptoError>;

    /// Verifies a signature against the given data using the holder's public key and algorithm suite.
    ///
    /// # Arguments
    /// * `data_to_verify`: The data that was purportedly signed.
    /// * `signature`: The signature to verify.
    /// * `holder_public_key`: The public key of the entity that allegedly signed the data.
    /// * `alg_suite`: The algorithm suite used for the signature.
    ///
    /// # Returns
    /// An `Ok(())` if the signature is valid, or a `CryptoError` otherwise.
    fn verify(
        &self,
        data_to_verify: &[u8],
        signature: &Signature,
        holder_public_key: &PublicKey,
        alg_suite: AlgSuite,
    ) -> Result<(), CryptoError>;

    // Potentially other methods in the future, e.g., for key generation, encryption/decryption
    // if the kernel were to ever need those directly (unlikely for core Amulet).
}

// For now, we can provide a re-implementation of PlaceholderCryptoProvider here
// that conforms to the new trait, for use in tests and until a real provider is integrated.

#[derive(Debug, Clone, Default)]
pub struct PlaceholderCryptoProvider;

impl CryptoProvider for PlaceholderCryptoProvider {
    fn hash(&self, data: &[u8], alg_suite: AlgSuite) -> Result<[u8; 32], CryptoError> {
        // Extremely naive placeholder hash: just repeats the first byte of alg_suite tag.
        // DO NOT USE IN PRODUCTION.
        if data.is_empty() { // To prevent panic on data[0] for empty slices
            return Ok([alg_suite as u8; 32]);
        }
        Ok([data[0]; 32]) 
    }

    fn verify(
        &self,
        _data_to_verify: &[u8],
        _signature: &Signature,
        _holder_public_key: &PublicKey,
        _alg_suite: AlgSuite,
    ) -> Result<(), CryptoError> {
        // Placeholder always verifies successfully.
        // DO NOT USE IN PRODUCTION.
        Ok(())
    }
} 