#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(deprecated)]

//!
//! Amulet-Core is a deterministic micro-kernel for economic state.
//! 
//! This crate provides the core data structures, types, and logic
//! as specified in the Amulet-Core Kernel Specification v0.5 (incorporating SpecPlan changes).
//! It aims to be a minimal and formal substrate upon which complex
//! economic behavior can safely and predictably emerge.

// Module for common, shared data types (like AlgSuite, RightsMask).
pub mod types;

// Module for core primitive data structures (Entity, Capability, Command, Event, VClock, etc.).
pub mod primitives;

// Re-export all core primitives for easier access at the crate root.
pub use primitives::*;

// Module for Rights Algebra logic.
pub mod rights;

// Module for Cryptographic Abstractions.
pub mod crypto;

// Module for Key Management Service.
// pub mod kms;

// Module for Kernel error types.
pub mod error;

// Module for Kernel logic.
pub mod kernel;

// Removed old module declarations as their contents are merged into primitives.rs:
// pub mod events;
// pub mod access;
// pub mod domain;

// TODO: Review if `types` module contents (AlgSuite, RightsMask) should also move to `primitives`
// or a more specific shared types module (e.g., `shared_enums`) if `crypto` becomes a separate crate.
// For now, `AlgSuite` from `types.rs` is the enum definition for `alg_suite: u8` tags in `primitives.rs`.

// TODO: Implement top-level kernel logic and state transition functions here or in a dedicated `kernel` module.
// TODO: Define and export primary error types for the crate.

// Example of how you might re-export important types for easier use by consumers of this crate:
// pub use types::{CID, ReplicaID, AlgSuite, RightsMask, VectorClock};
// pub use primitives::{Entity, EntityHeader, EncodedState /*, Capability, Command */ };
// pub use events::{Event /* ... other event related structs ... */ };

// The original content was:
// // This is the main library entry point.
// // Export modules from here.

pub mod command_traits;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}