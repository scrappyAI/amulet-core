// use std::collections::HashMap; // This import is unused

// It's good practice to import Uuid if you are using it directly.
// For now, to avoid an immediate build error if the crate isn't added yet,
// this line is commented out. You'll need to uncomment it and add `uuid` to Cargo.toml.
// use uuid::Uuid;

// Core types like CID, ReplicaID, VClock (which replaces the old VectorClock Option),
// PublicKey, and Signature are now defined in `src/primitives.rs`.
// This file (`types.rs`) is intended for shared types that are not part of the
// direct structure of those core primitives, or for types that have broader use across
// modules like `crypto` or `rights`.

/// Algorithm Suite for cryptographic operations.
/// Defines profiles for hashing and signature algorithms (e.g., CLASSIC, FIPS, PQC, HYBRID).
/// This enum is the source of truth for algorithm suite variants.
/// The `alg_suite: u8` field in primitive structs (e.g., Command, Event, Capability)
/// in `primitives.rs` is a tag corresponding to these variants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AlgSuite {
    /// Best-effort security profile (e.g., BLAKE3-256, Ed25519).
    CLASSIC = 0,
    /// FIPS-140-3 compliant profile (e.g., SHA-3-256, ECDSA-P-256).
    FIPS = 1,
    /// Post-Quantum Cryptography profile (e.g., SHAKE-256, Dilithium-L3).
    PQC = 2,
    /// Hybrid profile for transitioning to PQC (e.g., SHA-3-256 & SHAKE-256, Ed25519 & Dilithium-L3).
    HYBRID = 3,
}

impl TryFrom<u8> for AlgSuite {
    type Error = String; // Using String for a simple error message

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AlgSuite::CLASSIC),
            1 => Ok(AlgSuite::FIPS),
            2 => Ok(AlgSuite::PQC),
            3 => Ok(AlgSuite::HYBRID),
            _ => Err(format!("Invalid AlgSuite tag: {}", value)),
        }
    }
}

/// RightsMask, a 32-bit field, as defined in `kernel_spec.md` §6 and `SpecPlan` §2.
/// The interpretation of its bits is:
/// - Bits 0-4: Core kernel rights (READ, WRITE, DELEGATE, ISSUE, REVOKE) - Frozen.
/// - Bits 5-15: Reserved for future kernel-level needs.
/// - Bits 16-31: Available for domain-specific overlays (e.g., finance, logistics).
pub type RightsMask = u32;

/// Placeholder for a private key.
/// The actual structure will depend on the chosen cryptographic algorithm suite(s).
/// This type is a placeholder to signify where private key data might be handled
/// (e.g., in `kms` or transiently in signing operations) but should generally
/// not be stored directly within core kernel state structures like Entities or Events.
/// It is explicitly kept out of `primitives.rs` for this reason.
pub type PrivateKeyPlaceholder = Vec<u8>;

// Ensure that PublicKey and Signature are NOT defined here.
// Their canonical definitions are:
// pub type PublicKey = [u8; 32]; // in primitives.rs
// pub type Signature = [u8; 64]; // in primitives.rs

// Any other general types that don't belong directly in primitives.rs can be added here. 