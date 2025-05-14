//!
//! Defines Event-related structures for the Amulet kernel.
//!
//! Events are the outcome of successful command processing and represent committed state changes.

// Declare the event module, making its contents accessible via `crate::events::event::...`
pub mod event;

// Re-export items from the event module for easier access, e.g., `crate::events::Event`.
pub use event::Event; 