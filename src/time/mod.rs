//! Logical-time utilities (Lamport, Vector clocks).
//!
//! The legacy `crate::clock` namespace has been deprecated; new code should
//! use `crate::time`.  Vector-clock utilities now live in `time::vector`.

pub mod vector;

// Re-export for convenience
pub use vector::*; 