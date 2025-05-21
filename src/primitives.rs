use std::collections::HashMap;

// --- Universal identifiers --------------------------------------------------
// kernel_spec.md §1
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)] // To serialize as the inner type directly
pub struct CidBytes(#[serde(with = "serde_bytes")] pub [u8; 32]);
pub type CID = CidBytes; // Keep CID as the primary type alias if preferred, or switch to CidBytes

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ReplicaIdBytes(#[serde(with = "serde_bytes")] pub [u8; 16]);
pub type ReplicaID = ReplicaIdBytes; // kernel_spec.md §1 & §2.4

// --- Cryptographic Primitives (Tags/Placeholders) ---------------------------
// Actual crypto operations and key storage live in a sibling crate (e.g., amulet-crypto).
// The kernel core only deals with tags or opaque byte arrays for signatures/keys.

// Placeholder for PublicKey, replace with actual type from crypto crate if available
// For now, using a common size for a public key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct PublicKeyBytes(#[serde(with = "serde_bytes")] pub [u8; 32]);
pub type PublicKey = PublicKeyBytes; // Example size, adjust as needed

// Placeholder for Signature, replace with actual type from crypto crate
// For now, using a common size for a signature.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(#[serde(with = "serde_bytes")] pub [u8; 64]);
pub type Signature = SignatureBytes; // Example size, adjust as needed

// --- Lamport & Vector Clock -------------------------------------------------
// kernel_spec.md §7 & SpecPlan §1

/// Vector Clock: A map from ReplicaID to its Lamport timestamp.
/// Now mandatory as per SpecPlan §1.
#[derive(Clone, Default, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VClock(pub HashMap<ReplicaID, u64>);

impl VClock {
    /// Merges another VClock into this one according to vector clock merge rules.
    /// For each (replica_id, l_time) in `other.0`:
    ///   `self.0[replica_id] = max(self.0.get(replica_id).cloned().unwrap_or(0), l_time)`.
    /// Entries in `self.0` not in `other.0` are retained.
    pub fn merge_into(&mut self, other: &VClock) {
        for (replica_id, other_ltime) in &other.0 {
            let self_ltime = self.0.entry(*replica_id).or_insert(0);
            *self_ltime = std::cmp::max(*self_ltime, *other_ltime);
        }
    }
}

// --- Entities ---------------------------------------------------------------
// kernel_spec.md §2.1 & SpecPlan §1

/// Header for an Entity, containing metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EntityHeader {
    pub id: CID,           // Stable across versions
    pub version: u64,      // Monotonic per Entity
    pub lclock: u64,       // Lamport time at creation/update
    pub parent: Option<CID>, // Optional parent Entity
}

/// Generic Entity structure, holding a header and a body of type E.
/// E would typically be a domain-specific state object that implements
/// serialization/deserialization traits defined elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entity<E> {
    pub header: EntityHeader,
    pub body: E,
}

// --- Capabilities -----------------------------------------------------------
// kernel_spec.md §2.2 & SpecPlan §1

/// Represents a capability, granting a holder specific rights.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    pub id: CID,
    pub alg_suite: u8,          // Tag only; impl lives in amulet-crypto (SpecPlan §1)
    pub holder: PublicKey,      // Public key of the capability holder
    pub target_entity: CID,   // The entity this capability targets
    pub rights: u32,            // RightsMask: lower 5 bits frozen, 5-15 kernel, 16-31 domain (SpecPlan §1, §2)
    pub nonce: u64,             // Nonce to prevent replay attacks
    pub expiry_lc: Option<u64>, // Optional Lamport clock expiry
    pub kind: u16,              // Reserved for overlay semantics (SpecPlan §1, §3)
    pub signature: Signature,   // Signature by capability.holder
}

// --- Command / Operation ----------------------------------------------------
// kernel_spec.md §2.3 & SpecPlan §1

/// Represents a command to be processed by the kernel.
/// P is the generic type for the command payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Command<P> {
    pub id: CID,                // Unique ID of the command
    pub alg_suite: u8,          // Algorithm suite tag
    pub replica: ReplicaID,     // ID of the replica submitting the command
    pub capability: CID,        // CID of the capability authorizing this command
    pub lclock: u64,            // Proposed Lamport time by the replica
    pub vclock: Option<VClock>, // Optional vector clock from the submitting replica
    pub payload: P,             // Command-specific payload
    pub signature: Signature,   // Signature by capability.holder over the command details + payload
}

// --- Event ------------------------------------------------------------------
// kernel_spec.md §2.4 & SpecPlan §1

/// Represents an event, the result of a successfully processed Command.
/// Events are the append-only log of the system.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub id: CID,                // Unique ID of the event
    pub alg_suite: u8,          // Algorithm suite tag, usually from the command
    pub replica: ReplicaID,     // ID of the replica that generated/validated this event
    pub caused_by: CID,         // Command.id that led to this event
    pub lclock: u64,            // Lamport timestamp assigned by the kernel
    pub vclock: VClock,         // Vector clock, now always present (SpecPlan §0, §1, §3)
    pub new_entities: Vec<CID>, // CIDs of entities created by this event
    pub updated_entities: Vec<CID>, // CIDs of entities updated by this event
    pub reserved: Vec<u8>,      // For unknown future fields, must be preserved bit-exact (kernel_spec.md §2.4, SpecPlan §1)
}

// Note: The original `event.rs` had `additional_fields: Option<BTreeMap<String, Vec<u8>>>`.
// This has been replaced by `reserved: Vec<u8>` as per SpecPlan §1 `Event` struct,
// implying a raw byte buffer for preserving unknown fields. The exact mechanism for
// handling this during serialization/deserialization (e.g., if specific field names
// need to be preserved alongside their byte values, or if it's an opaque blob)
// would depend on the chosen serialization library and strategy.
// The kernel_spec.md §2.4 states: "Unknown future fields MUST be preserved bit-exact when relayed."
// and SpecPlan §1 `Event` states: "reserved: Vec<u8>,       // unknown fields, bit-exact"
// This implementation assumes `reserved` is that opaque blob.

// Note on RightsMask (kernel_spec.md §6 & SpecPlan §1, §2)
// RightsMask is u32.
// Bits 0-4: Core (READ, WRITE, DELEGATE, ISSUE, REVOKE) - Frozen
// Bits 5-15: Reserved by kernel
// Bits 16-31: Domain overlays (e.g., finance, logistics)

// The `EncodedCmd` and `EncodedState` traits previously in `command.rs` and `entity.rs`
// respectively, are not included here. The SpecPlan suggests:
// "Mini "opcode" set Defer to runtime layer. Kernel only cares about the opaque payload: C."
// This implies that the generic `P` in `Command<P>` and `E` in `Entity<E>` will be
// handled by higher layers or specific runtime implementations, which will define
// how they are encoded/decoded and what rights they require. 

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (primitives)
    use proptest::prelude::*;
    use std::collections::HashMap;

    // Strategy for generating a ReplicaID
    fn arb_replica_id() -> impl Strategy<Value = ReplicaID> {
        prop::array::uniform16(any::<u8>()).prop_map(ReplicaIdBytes)
    }

    // Strategy for generating a VClock
    // Generates a HashMap with 0 to 10 entries.
    // Keys are generated by arb_replica_id(), values are u64.
    fn arb_vclock() -> impl Strategy<Value = VClock> {
        prop::collection::hash_map(arb_replica_id(), any::<u64>(), 0..10)
            .prop_map(VClock)
    }

    proptest! {
        #[test]
        fn property_vclock_merge_correctness(
            mut vc1 in arb_vclock(), 
            vc2 in arb_vclock()
        ) {
            let original_vc1 = vc1.clone();
            let original_vc2 = vc2.clone(); // vc2 is not mutated by merge_into

            vc1.merge_into(&vc2);

            // Check that all keys from both original vclocks are present in the merged vc1
            // And that their values are the maximum of the values from original_vc1 and original_vc2.
            let mut all_keys = HashMap::new();
            for (r, l) in original_vc1.0.iter() {
                all_keys.insert(*r, *l);
            }
            for (r, l_vc2) in original_vc2.0.iter() {
                let current_max = all_keys.entry(*r).or_insert(0);
                *current_max = std::cmp::max(*current_max, *l_vc2);
            }
            
            // Assert that vc1 now contains all keys from all_keys with the correct max values
            prop_assert_eq!(vc1.0.len(), all_keys.len(), "Merged VClock should have the union of keys");

            for (r_merged, l_merged) in vc1.0.iter() {
                 match all_keys.get(r_merged) {
                    Some(expected_l) => prop_assert_eq!(*l_merged, *expected_l, "Lamport time for replica {:?} is incorrect after merge", r_merged),
                    None => prop_assert!(false, "Merged VClock contains unexpected replica ID {:?}", r_merged), // Should not happen if len check passed
                 }
            }
             // Double check: all_keys should now be a subset of or equal to vc1.0
            for (r_expected, l_expected) in all_keys.iter() {
                match vc1.0.get(r_expected) {
                    Some(actual_l) => prop_assert_eq!(*actual_l, *l_expected, "Expected Lamport time for replica {:?} not found or incorrect in merged VClock", r_expected),
                    None => prop_assert!(false, "Expected replica ID {:?} not found in merged VClock", r_expected),
                }
            }
        }

        #[test]
        fn property_vclock_merge_idempotency(mut vc in arb_vclock()) {
            let original_vc = vc.clone();
            let vc_clone_for_merge = vc.clone();
            
            vc.merge_into(&vc_clone_for_merge); // Merge with a clone of itself

            // The VClock should be unchanged
            prop_assert_eq!(vc, original_vc, "Merging VClock with itself changed its value");
        }
        
        #[test]
        fn property_vclock_merge_commutativity(vc1_start in arb_vclock(), vc2_start in arb_vclock()) {
            let mut merged1 = vc1_start.clone();
            merged1.merge_into(&vc2_start);

            let mut merged2 = vc2_start.clone();
            merged2.merge_into(&vc1_start);

            // The two resulting VClocks should be identical
            prop_assert_eq!(merged1, merged2, "VClock merge result is not commutative");
        }
    }
} 