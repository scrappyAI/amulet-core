//! Access-control related modules (capabilities, rights, authentication).
//!
//! For now this is a façade re-exporting existing items.  Future PRs will
//! physically move `capability.rs` and related logic here.

// Re-export current location so downstream `use crate::primitives::Capability` continues to compile.
pub mod capability;

pub use capability::*;
// Also expose the rights algebra under a shorter path.
pub use crate::rights as rights; 