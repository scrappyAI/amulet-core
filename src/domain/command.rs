use crate::types::{AlgSuite, CID, ReplicaID, Signature, RightsMask};
use std::fmt::Debug;

/// Encoded command payload trait as per `kernel_spec.md §2.3`.
pub trait EncodedCmd: Sized + Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
    type Error: Debug + std::error::Error + Send + Sync + 'static;

    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Result<Self, Self::Error>;
    fn required_rights(&self) -> RightsMask;

    fn to_signed_bytes(
        &self,
        command_id: &CID,
        command_alg_suite: AlgSuite,
        command_replica_id: &ReplicaID,
        command_capability_cid: &CID,
        command_lclock: u64,
    ) -> Result<Vec<u8>, Self::Error>;
}

// Example Vec<u8> implementation
#[derive(Debug)]
pub struct VecCmdError(String);
impl std::fmt::Display for VecCmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VecCmdError: {}", self.0)
    }
}
impl std::error::Error for VecCmdError {}

impl EncodedCmd for Vec<u8> {
    type Error = VecCmdError;
    fn encode(&self) -> Vec<u8> { self.clone() }
    fn decode(data: &[u8]) -> Result<Self, Self::Error> { Ok(data.to_vec()) }
    fn required_rights(&self) -> RightsMask { 0 }

    fn to_signed_bytes(
        &self,
        command_id: &CID,
        command_alg_suite: AlgSuite,
        command_replica_id: &ReplicaID,
        command_capability_cid: &CID,
        command_lclock: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(command_id);
        bytes.push(command_alg_suite as u8);
        bytes.extend_from_slice(command_replica_id);
        bytes.extend_from_slice(command_capability_cid);
        bytes.extend_from_slice(&command_lclock.to_le_bytes());
        bytes.extend_from_slice(self);
        Ok(bytes)
    }
}

/// A signed Command envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command<C: EncodedCmd> {
    pub id: CID,
    pub alg_suite: AlgSuite,
    pub replica: ReplicaID,
    pub capability: CID,
    pub lclock: u64,
    pub payload: C,
    pub signature: Signature,
} 