#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(deprecated)]

//!
//! Amulet-Core is a deterministic micro-kernel for economic state.
//! 
//! This crate provides the core data structures, types, and logic
//! as specified in the Amulet-Core Kernel Specification v0.4.
//! It aims to be a minimal and formal substrate upon which complex
//! economic behavior can safely and predictably emerge.

// Module for common, core data types used throughout the kernel.
pub mod types;

// Module for core primitives: Entity, Capability, Command.
#[cfg(feature = "compat-primitives")]
#[allow(deprecated)]
pub mod primitives; // Deprecated shim to ease downstream migration

// Module for Event structures and related logic.
// This module already existed in the provided directory structure.
pub mod events;

// Module for Rights Algebra logic.
pub mod rights;

// New logical namespaces introduced during the May-2025 refactor.
pub mod access;
pub mod domain;
pub mod time;

// Module for Cryptographic Abstractions.
pub mod crypto;

// Module for Kernel error types.
pub mod error;

// Module for Kernel logic.
pub mod kernel;

// TODO: Implement top-level kernel logic and state transition functions here or in a dedicated `kernel` module.
// TODO: Define and export primary error types for the crate.

// Example of how you might re-export important types for easier use by consumers of this crate:
// pub use types::{CID, ReplicaID, AlgSuite, RightsMask, VectorClock};
// pub use primitives::{Entity, EntityHeader, EncodedState /*, Capability, Command */ };
// pub use events::{Event /* ... other event related structs ... */ };

// The original content was:
// // This is the main library entry point.
// // Export modules from here.