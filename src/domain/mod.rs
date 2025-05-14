//! Domain-level primitives: Entity, Command, Event.
//!
//! Types are now defined in this namespace.  Re-exports remain for backward compatibility.

pub mod entity;
pub mod command;

pub use entity::*;
pub use command::*;

// Events still live under `crate::events` – re-export for convenience.
pub use crate::events::*; 