//! Defines traits related to command encoding and processing for Amulet-Core.

use crate::primitives::{CID, ReplicaID}; // Removed Signature, PublicKey might also not be needed directly
use crate::types::AlgSuite; // AlgSuite for cryptographic context

/// Error type for command encoding/decoding operations.
#[derive(Debug)]
pub enum CommandTraitError {
    Encoding(String),
    Decoding(String),
    Signing(String), // If to_signed_bytes can fail for other reasons than crypto
    Other(String),
}

impl std::fmt::Display for CommandTraitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandTraitError::Encoding(s) => write!(f, "CommandEncodingError: {}", s),
            CommandTraitError::Decoding(s) => write!(f, "CommandDecodingError: {}", s),
            CommandTraitError::Signing(s) => write!(f, "CommandSigningError: {}", s),
            CommandTraitError::Other(s) => write!(f, "CommandTraitError: {}", s),
        }
    }
}

impl std::error::Error for CommandTraitError {}

/// Trait for command payloads that can be encoded, decoded, and provide necessary metadata.
/// This allows the kernel to be generic over the actual command payloads.
pub trait EncodedCmd: Sized + Send + Sync + 'static + Clone + std::fmt::Debug + PartialEq + Eq {
    /// The error type that can occur during encoding, decoding, or signing byte retrieval.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encodes the command payload into a byte vector for storage or transmission.
    fn encode(&self) -> Vec<u8>;

    /// Decodes a command payload from a byte slice.
    fn decode(bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Returns the rights mask required to execute this command.
    fn required_rights(&self) -> u32; // Corresponds to RightsMask

    /// Produces a deterministic byte vector representing the command details that need to be signed.
    /// This typically includes the command ID, algorithm suite, replica ID, capability CID,
    /// Lamport clock, and the encoded payload itself.
    ///
    /// # Arguments
    /// * `command_id` - The unique ID of the command.
    /// * `alg_suite` - The algorithm suite used for this command.
    /// * `replica` - The ID of the replica that originated the command.
    /// * `capability` - The CID of the capability authorizing this command.
    /// * `lclock` - The Lamport clock associated with this command.
    fn to_signed_bytes(
        &self,
        command_id: &CID,
        alg_suite: AlgSuite,
        replica: &ReplicaID,
        capability: &CID,
        lclock: u64,
    ) -> Result<Vec<u8>, Self::Error>;
} 