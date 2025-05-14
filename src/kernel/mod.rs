pub mod core;
pub mod runtime;
 
// Re-export the primary types so existing `crate::kernel::*` paths continue to work.
pub use core::{Kernel, StateDelta, SystemState};
pub use runtime::{Runtime, DefaultRuntime}; 