//!
//! Defines error types for the Amulet kernel.

use crate::types::AlgSuite;

/// Represents errors that can occur during kernel operations, such as command validation or application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// The specified Capability ID was not found in the current state.
    CapabilityNotFound,
    /// The `alg_suite` in the Command does not match the `alg_suite` of the referenced Capability.
    AlgorithmSuiteMismatch,
    /// The Command's signature failed to verify.
    SignatureVerificationFailed,
    /// The referenced Capability does not grant sufficient rights for the Command's payload.
    InsufficientRights,
    /// The Command's proposed `lclock` is invalid (e.g., too old).
    InvalidCommandLClock,
    /// The `expiry_lc` of a Capability has been reached or surpassed.
    CapabilityExpired,
    /// An invariant was violated during processing (e.g., by the delta from runtime).
    InvariantViolation(String),
    /// An error occurred during the execution of the command-specific runtime logic.
    RuntimeError(String),
    /// An error related to cryptographic operations.
    CryptoError(CryptoError),
    /// A general or otherwise unspecified error.
    Other(String),
}

// Implement standard error traits for better interoperability
impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelError::CapabilityNotFound => write!(f, "Capability not found in state"),
            KernelError::AlgorithmSuiteMismatch => write!(f, "Command AlgSuite mismatch with Capability AlgSuite"),
            KernelError::SignatureVerificationFailed => write!(f, "Command signature verification failed"),
            KernelError::InsufficientRights => write!(f, "Capability does not grant sufficient rights"),
            KernelError::InvalidCommandLClock => write!(f, "Command lclock is invalid"),
            KernelError::CapabilityExpired => write!(f, "Capability has expired"),
            KernelError::InvariantViolation(details) => write!(f, "Invariant violation: {}", details),
            KernelError::RuntimeError(details) => write!(f, "Runtime error: {}", details),
            KernelError::CryptoError(error) => write!(f, "Crypto error: {}", error),
            KernelError::Other(details) => write!(f, "Kernel error: {}", details),
        }
    }
}

impl std::error::Error for KernelError {}

/// Represents errors specific to cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided algorithm suite is not supported by the current crypto provider for the requested operation.
    UnsupportedAlgSuite(AlgSuite),
    /// Signature generation failed.
    SigningFailed(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Hashing failed (though less common to be explicitly distinct from CID generation issues).
    HashingFailed(String),
    /// Other crypto-related error.
    Other(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::UnsupportedAlgSuite(alg) => write!(f, "Unsupported AlgSuite: {:?}", alg),
            CryptoError::SigningFailed(details) => write!(f, "Signing failed: {}", details),
            CryptoError::VerificationFailed(details) => write!(f, "Verification failed: {}", details),
            CryptoError::KeyGenerationFailed(details) => write!(f, "Key generation failed: {}", details),
            CryptoError::HashingFailed(details) => write!(f, "Hashing failed: {}", details),
            CryptoError::Other(details) => write!(f, "Crypto error: {}", details),
        }
    }
}

impl std::error::Error for CryptoError {} 