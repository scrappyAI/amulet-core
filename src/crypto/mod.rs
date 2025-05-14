//!
//! Cryptographic Abstraction Layer for Amulet-Core.
//!
//! This module defines traits and structures for cryptographic operations like hashing,
//! signing, and verification. It allows the kernel to remain independent of specific
//! cryptographic library implementations.

use crate::types::{AlgSuite, CID, PublicKey, PrivateKeyPlaceholder, Signature};
use crate::error::{KernelError, CryptoError}; // For returning crypto-related errors

/// Trait for a provider of cryptographic hashing operations.
pub trait Hasher {
    /// Hashes the given data using the specified algorithm suite.
    /// Note: The `alg_suite` might determine which specific hash function to use (e.g., BLAKE3 for CLASSIC).
    fn hash(data: &[u8], alg_suite: AlgSuite) -> Result<CID, CryptoError>;
}

/// Trait for a provider of cryptographic signature generation operations.
pub trait Signer {
    /// Signs the given data using the specified private key and algorithm suite.
    fn sign(data: &[u8], private_key: &PrivateKeyPlaceholder, alg_suite: AlgSuite) -> Result<Signature, KernelError>;
}

/// Trait for a provider of cryptographic signature verification operations.
pub trait Verifier {
    /// Verifies a signature against the given data, public key, and algorithm suite.
    fn verify(data: &[u8], signature: &Signature, public_key: &PublicKey, alg_suite: AlgSuite) -> Result<(), KernelError>;
}

/// A combined trait for a full suite of cryptographic operations.
/// Implementors would provide concrete crypto logic.
pub trait CryptoProvider: Hasher + Signer + Verifier {}

// Module for the CLASSIC Algorithm Suite (BLAKE3-256, Ed25519)
pub mod classic;

// Re-export the concrete provider for easier access
pub use classic::ClassicCryptoProvider;

// Module for the FIPS Algorithm Suite (SHA-3-256, ECDSA P-256)
pub mod fips;

// Re-export the concrete provider for easier access
pub use fips::FipsCryptoProvider;

// Placeholder implementation - In a real scenario, this would use actual crypto libraries.
// This struct would be part of a concrete implementation, not the abstraction module itself usually.
// For now, keeping it here to allow the Kernel to compile with a crypto provider.

#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderCryptoProvider;

impl Hasher for PlaceholderCryptoProvider {
    fn hash(data: &[u8], alg_suite: AlgSuite) -> Result<CID, CryptoError> {
        tracing::debug!(
            "PlaceholderCryptoProvider hash called for data (len: {}) with AlgSuite: {:?}",
            data.len(),
            alg_suite
        );
        // Using BLAKE3 for the placeholder as it's simple and already a dependency.
        use blake3::Hasher as B3;
        let mut hasher = B3::new();
        hasher.update(data);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl Signer for PlaceholderCryptoProvider {
    fn sign(_data: &[u8], _private_key: &PrivateKeyPlaceholder, _alg_suite: AlgSuite) -> Result<Signature, KernelError> {
        tracing::debug!("[PlaceholderCryptoProvider] Signing data.");
        Ok(Vec::new()) // Placeholder: empty signature
    }
}

impl Verifier for PlaceholderCryptoProvider {
    fn verify(_data: &[u8], _signature: &Signature, _public_key: &PublicKey, _alg_suite: AlgSuite) -> Result<(), KernelError> {
        tracing::debug!("[PlaceholderCryptoProvider] Verifying signature. Assuming OK.");
        // In a real implementation, this would return Err(KernelError::SignatureVerificationFailed)
        // if verification fails.
        Ok(())
    }
}

impl CryptoProvider for PlaceholderCryptoProvider {} 