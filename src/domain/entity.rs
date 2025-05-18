use crate::types::CID;
use std::fmt::Debug;

/// Trait for types that can be used as the serialisable body of an `Entity`.
/// See `kernel_spec.md §2.1` for invariants relating to entities.
pub trait EncodedState: Sized + Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
    type DecodeError: Debug + std::error::Error + Send + Sync + 'static;

    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Result<Self, Self::DecodeError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Blanket / example implementations
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct VecU8DecodeError(String);
impl std::fmt::Display for VecU8DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VecU8DecodeError: {}", self.0)
    }
}
impl std::error::Error for VecU8DecodeError {}

impl EncodedState for Vec<u8> {
    type DecodeError = VecU8DecodeError;
    fn encode(&self) -> Vec<u8> { self.clone() }
    fn decode(data: &[u8]) -> Result<Self, Self::DecodeError> { Ok(data.to_vec()) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entity header & container
// ─────────────────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityHeader {
    pub id: CID,
    pub version: u64,
    pub lclock: u64,
    pub parent: Option<CID>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity<E: EncodedState> {
    pub header: EntityHeader,
    pub body: E,
} 