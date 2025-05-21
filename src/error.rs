//!
//! Defines error types for the Amulet kernel.

// use crate::types::AlgSuite; // Removed as unused
// use crate::crypto_placeholder::CryptoError as PlaceholderCryptoError; // Will be removed
// Removed unused import: use crate::crypto::CryptoError;

/// Represents errors that can occur during kernel operations, such as command validation or application.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    /// The specified Capability ID was not found in the current state.
    #[error("Capability not found in state")]
    CapabilityNotFound,
    /// The `alg_suite` in the Command does not match the `alg_suite` of the referenced Capability.
    #[error("Command AlgSuite mismatch with Capability AlgSuite")]
    AlgorithmSuiteMismatch,
    /// Cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    /// The referenced Capability does not grant sufficient rights for the Command's payload.
    #[error("Capability does not grant sufficient rights")]
    InsufficientRights,
    /// The Command's proposed `lclock` is invalid (e.g., too old).
    #[error("Command lclock is invalid")]
    InvalidCommandLClock,
    /// The `expiry_lc` of a Capability has been reached or surpassed.
    #[error("Capability has expired")]
    CapabilityExpired,
    /// An invariant was violated during processing (e.g., by the delta from runtime).
    #[error("Kernel invariant violation: {0}")]
    InvariantViolation(String),
    /// An error occurred during the execution of the command-specific runtime logic.
    #[error("Runtime error: {0}")]
    RuntimeError(String),
    /// A general or otherwise unspecified error.
    #[error("Kernel error: {0}")]
    Other(String),
}

/* Removed old CryptoError definition
/// Error type for cryptographic operations.
/// This is now defined in `crypto.rs`.
*/