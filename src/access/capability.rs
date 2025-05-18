use crate::types::{AlgSuite, CID, PublicKey, RightsMask, Signature};

/// Grants a `holder` specific rights over a `target_entity`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: CID,
    pub alg_suite: AlgSuite,
    pub holder: PublicKey,
    pub target_entity: CID,
    pub rights: RightsMask,
    pub nonce: u64,
    pub expiry_lc: Option<u64>,
    pub signature: Signature,
} 