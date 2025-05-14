//! Kernel runtime abstraction.
//!
//! A `Runtime` is the component responsible for executing a `Command` against the
//! current `SystemState` to produce a `StateDelta`.  This separation allows the
//! deterministic state-machine (clocks, validation, append, etc.) to remain
//! completely generic over domain-specific business logic.
//!
//! At present we provide a `DefaultRuntime` that performs no state mutation –
//! suitable for unit tests and as a template for real runtimes added in Phase-2.

use crate::domain::{Command, EncodedCmd};
use crate::kernel::core::StateDelta;
use crate::kernel::core::SystemState;
use crate::crypto::CryptoProvider;
use crate::error::KernelError;

/// Trait implemented by pluggable runtimes.
///
/// The `execute` function MUST be deterministic and free of side-effects except
/// through its returned `StateDelta`, as required by `kernel_spec.md §5`.
pub trait Runtime<CP: CryptoProvider>: Send + Sync + 'static {
    fn execute<C: EncodedCmd>(
        &self,
        state: &SystemState,
        cmd: &Command<C>,
    ) -> Result<StateDelta, KernelError>;
}

/// Trivial runtime that always returns an empty `StateDelta`.
#[derive(Default, Debug, Clone)]
pub struct DefaultRuntime;

impl<CP: CryptoProvider> Runtime<CP> for DefaultRuntime {
    fn execute<C: EncodedCmd>(
        &self,
        _state: &SystemState,
        _cmd: &Command<C>,
    ) -> Result<StateDelta, KernelError> {
        Ok(StateDelta { new_entities: Vec::new(), updated_entities: Vec::new() })
    }
} 