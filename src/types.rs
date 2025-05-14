use std::collections::HashMap;

// It's good practice to import Uuid if you are using it directly.
// For now, to avoid an immediate build error if the crate isn't added yet,
// this line is commented out. You'll need to uncomment it and add `uuid` to Cargo.toml.
// use uuid::Uuid;

/// Content Identifier: a 32-byte content address (hash of bytes).
/// This is typically the output of a cryptographic hash function like BLAKE3-256 or SHA-3-256.
pub type CID = [u8; 32];

/// Replica Identifier: a 128-bit UUID representing a collision-free domain for a replica.
/// Ensures that operations from different replicas can be uniquely identified.
// pub type ReplicaID = Uuid; // Uncomment this line after adding `uuid` crate to Cargo.toml
pub type ReplicaID = [u8; 16]; // Placeholder until `uuid` crate is confirmed to be added.


/// Algorithm Suite for cryptographic operations.
/// Defines profiles for hashing and signature algorithms (e.g., CLASSIC, FIPS, PQC, HYBRID).
#[repr(u8)] // Added repr(u8) for simple serialization in to_signed_bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Added Hash for use in HashMap keys if needed
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

/// Placeholder for RightsMask, a 32-bit field.
/// Bits 0-15 are core (READ, WRITE, DELEGATE, ISSUE, REVOKE).
/// The full algebra will live in `rights.md`.
pub type RightsMask = u32;

// Note: VectorClock is defined in the kernel spec as Option<HashMap<ReplicaID, u64>>
// This type alias can be useful if used in multiple places.
pub type VectorClock = Option<HashMap<ReplicaID, u64>>;

/// Placeholder for a public key.
/// The actual structure will depend on the chosen cryptographic algorithm suite.
pub type PublicKey = Vec<u8>;

/// Placeholder for a cryptographic signature.
/// The actual structure will depend on the chosen cryptographic algorithm suite.
pub type Signature = Vec<u8>;

/// Placeholder for a private key.
/// The actual structure will depend on the chosen cryptographic algorithm suite.
/// This should be handled with extreme care and typically not stored directly in kernel state.
pub type PrivateKeyPlaceholder = Vec<u8>; 