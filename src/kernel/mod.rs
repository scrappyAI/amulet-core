pub mod core;
pub mod runtime;

// TODO: Potentially move error definitions specific to kernel operations here?
// For now, top-level `error.rs` is used.
mod tests; // Added to include the new test module

// Re-export the primary types so existing `crate::kernel::*` paths continue to work.
pub use core::{Kernel, StateDelta, SystemState};
pub use runtime::{Runtime, DefaultRuntime}; 