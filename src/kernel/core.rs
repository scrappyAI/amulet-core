//!
//! Core kernel logic for Amulet-Core, including state transition and command processing.
//!
//! This file was mechanically moved from `src/kernel.rs` to `src/kernel/core.rs`
//! as part of the repository re-organisation (see PROJECT_ROADMAP.md Phase Refactor).

// Primitive types from crate::primitives
use crate::primitives::{VClock, CID, ReplicaID, Event, Entity, Capability, Command, CidBytes};

// Shared types from crate::types
use crate::types::AlgSuite; // RightsMask is not directly used here but good for context

// Traits and specific types from new modules
use crate::command_traits::EncodedCmd;
use crate::crypto::{CryptoProvider}; // Removed CryptoError import

use crate::error::KernelError;
use std::collections::{HashMap}; // For SystemState and additional_fields in Event
use crate::rights; // Rights algebra module - uses RightsMask from types
// use crate::time::vector as vector_clock; // No longer needed
use crate::kernel::runtime::{Runtime, DefaultRuntime};

/// Represents the changes to the system state resulting from a command.
/// This is the `delta` referred to in the kernel specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDelta {
    /// New entities created by the command, with bodies in serialized form.
    pub new_entities: Vec<Entity<Vec<u8>>>,
    /// Entities updated by the command, with bodies in serialized form.
    pub updated_entities: Vec<Entity<Vec<u8>>>,
}

/// Represents the authoritative state (Σ) of the Amulet kernel.
/// This includes the append-only event log and materialised views of entities and capabilities.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SystemState {
    /// Materialised view of capabilities, mapping CID → Capability.
    pub capabilities: HashMap<CID, Capability>,
    /// Entities are stored with their bodies in serialized Vec<u8> form.
    /// Deserialization happens on-demand within `runtime` or other accessors.
    pub entities: HashMap<CID, Entity<Vec<u8>>>,
    /// Append-only log of events.
    pub event_log: Vec<Event>,
    // Potentially other materialised views or state components.
}

/// The Amulet kernel, responsible for managing state and processing commands.
#[derive(Debug, Clone)]
pub struct Kernel<CP: CryptoProvider + Clone, R: Runtime<CP> + Clone + std::fmt::Debug> {
    /// The kernel's current local Lamport clock.
    pub local_lc: u64,
    /// The kernel's current local Vector clock. Now mandatory.
    pub local_vc: VClock,
    /// The authoritative state of the system.
    pub state: SystemState,
    /// The ReplicaID of this kernel instance.
    pub replica_id: ReplicaID,
    pub(crate) runtime: R, // Made pub(crate) for test access
    crypto_provider: CP, // Store the actual crypto provider instance
}

impl<CP, R> Kernel<CP, R>
where
    CP: CryptoProvider + Clone,
    R: Runtime<CP> + Clone + std::fmt::Debug,
{
    /// Creates a new Kernel instance. Vector clocks are now mandatory.
    pub fn new(replica_id: ReplicaID, runtime: R, crypto_provider: CP) -> Self {
        Kernel {
            local_lc: 0,
            local_vc: VClock::default(),
            state: SystemState::default(),
            replica_id,
            runtime,
            crypto_provider, // Store it
        }
    }

    /// Generates a Content ID (CID) for the given data using the kernel's crypto provider.
    fn generate_cid(&self, data: &[u8], alg_suite_tag: u8) -> Result<CID, KernelError> {
        let crypto_alg_suite = AlgSuite::try_from(alg_suite_tag)
            .map_err(|e| KernelError::Other(format!("Invalid AlgSuite tag: {}", e)))?;
        self.crypto_provider.hash(data, crypto_alg_suite) // Use self.crypto_provider
            .map_err(KernelError::Crypto) 
            .map(CidBytes) 
    }

    /// Appends the identity fields of an event to a byte vector for digest calculation.
    /// These fields include the command that caused the event, the event's Lamport clock,
    /// the ID of the replica that generated the event, and the algorithm suite used.
    #[doc(hidden)] // Internal helper, not part of public direct-call API
    fn append_event_identity_for_digest(
        bytes: &mut Vec<u8>,
        caused_by_command_id: &CID,
        event_lclock: u64,
        event_replica_id: &ReplicaID,
        event_alg_suite_tag: u8, // Changed from AlgSuite to u8
    ) {
        bytes.extend_from_slice(&caused_by_command_id.0); // Use .0 to access inner array
        bytes.extend_from_slice(&event_lclock.to_le_bytes());
        bytes.extend_from_slice(&event_replica_id.0); // Use .0
        bytes.push(event_alg_suite_tag); // Use the u8 tag directly
    }

    /// Appends a slice of CIDs to a byte vector in a deterministic (sorted) manner for digest calculation.
    /// This is used for lists of new or updated entities.
    #[doc(hidden)] // Internal helper
    fn append_cids_for_digest(bytes: &mut Vec<u8>, cids: &[CID]) {
        let mut sorted_cids = cids.to_vec();
        sorted_cids.sort_unstable(); // Sort for deterministic output
        for cid in sorted_cids {
            bytes.extend_from_slice(&cid.0); // Use .0
        }
    }

    /// Appends a VectorClock to a byte vector in a deterministic manner for digest calculation.
    /// The VectorClock is now mandatory. Its entries are sorted by ReplicaID.
    #[doc(hidden)] // Internal helper
    fn append_vector_clock_for_digest(bytes: &mut Vec<u8>, vclock: &VClock) {
        // Since VectorClock is mandatory, we always serialize it.
        // We'll keep a '1' prefix to indicate that the vector clock data follows.
        bytes.push(1); // Indicate presence of VectorClock data
        let mut vc_entries: Vec<(&ReplicaID, &u64)> = vclock.0.iter().collect();
        // Sort entries by ReplicaID for deterministic output
        vc_entries.sort_unstable_by_key(|(k, _)| *k);
        for (replica_id, lclock_val) in vc_entries {
            bytes.extend_from_slice(&replica_id.0); // Use .0
            bytes.extend_from_slice(&lclock_val.to_le_bytes());
        }
    }

    /// Helper to deterministically serialise event fields for CID generation.
    /// This function now orchestrates calls to more specific append helpers.
    fn get_event_hash_input(
        &self, // Remains to potentially access self.crypto_provider if needed, though not currently used here
        caused_by_command_id: &CID,
        event_lclock: u64,
        event_replica_id: &ReplicaID,
        event_alg_suite_tag: u8, // Changed from AlgSuite to u8
        new_entities_cids: &[CID],
        updated_entities_cids: &[CID],
        vector_clock: &VClock,
        reserved_bytes: &[u8], // Changed from additional_fields to reserved_bytes
    ) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Append event identity fields
        Self::append_event_identity_for_digest(
            &mut bytes, 
            caused_by_command_id, 
            event_lclock, 
            event_replica_id, 
            event_alg_suite_tag // Pass the u8 tag
        );

        // Append CIDs for new entities (sorted)
        Self::append_cids_for_digest(&mut bytes, new_entities_cids);

        // Append CIDs for updated entities (sorted)
        Self::append_cids_for_digest(&mut bytes, updated_entities_cids);

        // Append VectorClock (sorted entries, mandatory)
        Self::append_vector_clock_for_digest(&mut bytes, vector_clock);

        // Append reserved bytes directly
        // As per kernel_spec.md §2.4, unknown fields (now `reserved: Vec<u8>`)
        // must be preserved bit-exact. So, we append the raw bytes.
        // We'll prefix with length to allow distinction from subsequent fields if any were added later.
        // For now, it's the last field.
        bytes.extend_from_slice(&(reserved_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(reserved_bytes);
        
        bytes
    }

    /// Append the `delta` into Σ, checking basic invariants.
    pub fn append_delta(&mut self, delta: &StateDelta, lclock_new: u64) -> Result<(), KernelError> {
        // 1. CID uniqueness for new entities.
        for ent in &delta.new_entities {
            if self.state.entities.contains_key(&ent.header.id) {
                return Err(KernelError::InvariantViolation(
                    "New entity CID already exists in state".into(),
                ));
            }
        }

        // 2. Updated entities must exist and version++.
        for upd in &delta.updated_entities {
            match self.state.entities.get(&upd.header.id) {
                Some(prev) if upd.header.version == prev.header.version + 1 => {}
                Some(_) => {
                    return Err(KernelError::InvariantViolation(format!(
                        "Entity version monotonicity violated for CID {:?}",
                        upd.header.id
                    )));
                }
                None => {
                    return Err(KernelError::InvariantViolation(format!(
                        "Updated entity with CID {:?} not found in state",
                        upd.header.id
                    )));
                }
            }
        }

        // 3. lclock consistency across entities.
        for ent in delta.new_entities.iter().chain(delta.updated_entities.iter()) {
            if ent.header.lclock != lclock_new {
                return Err(KernelError::InvariantViolation(
                    "Entity lclock must equal event lclock".into(),
                ));
            }
        }

        // 4. Materialise into state.
        for ent in &delta.new_entities {
            self.state.entities.insert(ent.header.id, ent.clone());
        }
        for ent in &delta.updated_entities {
            self.state.entities.insert(ent.header.id, ent.clone());
        }
        Ok(())
    }

    /// Create an Event object from the committed `delta`.
    fn materialise_event<C: EncodedCmd>(
        &self,
        command: &Command<C>,
        delta: &StateDelta,
        lclock_new: u64,
        vc_new: VClock,
    ) -> Result<Event, KernelError> {
        let new_cids: Vec<CID> = delta.new_entities.iter().map(|e| e.header.id).collect();
        let updated_cids: Vec<CID> = delta.updated_entities.iter().map(|e| e.header.id).collect();

        // For a newly materialised event, additional_fields is None as it's not carrying
        // unknown fields from another source yet.
        // Event.reserved is initialized as empty for new events.
        let reserved_for_new_event: Vec<u8> = Vec::new();

        let input = self.get_event_hash_input(
            &command.id,
            lclock_new,
            &self.replica_id,
            command.alg_suite, // This is u8, as required by get_event_hash_input
            &new_cids,
            &updated_cids,
            &vc_new,
            &reserved_for_new_event, // Pass empty reserved bytes
        );
        let event_id = self.generate_cid(&input, command.alg_suite)?; // command.alg_suite is u8

        Ok(Event {
            id: event_id,
            alg_suite: command.alg_suite, // This is u8, matches Event struct
            replica: self.replica_id,
            caused_by: command.id,
            lclock: lclock_new,
            new_entities: new_cids,
            updated_entities: updated_cids,
            vclock: vc_new,
            reserved: reserved_for_new_event, // Initialize with empty Vec<u8>
        })
    }

    /// Verify the command's signature using the capability holder's pub-key.
    fn verify_signature<C: EncodedCmd>(&self, command: &Command<C>) -> Result<(), KernelError> {
        let crypto_alg_suite = AlgSuite::try_from(command.alg_suite)
            .map_err(|e| KernelError::Other(format!("Invalid AlgSuite tag in command: {}", e)))?;

        let signed_bytes = command
            .payload
            .to_signed_bytes(
                &command.id,
                crypto_alg_suite, // Use converted AlgSuite enum for payload signing
                &command.replica,
                &command.capability,
                command.lclock,
            )
            .map_err(|e| {
                KernelError::Other(format!(
                    "Failed to get signed bytes from command payload: {:?}",
                    e
                ))
            })?;

        // Capability lookup to obtain public key.
        let cap = self
            .state
            .capabilities
            .get(&command.capability)
            .ok_or(KernelError::CapabilityNotFound)?;

        self.crypto_provider.verify(&signed_bytes, &command.signature, &cap.holder, crypto_alg_suite) // Use self.crypto_provider
            .map_err(KernelError::Crypto) 
    }

    fn rights_sufficient<T: EncodedCmd>(
        &self,
        capability: &Capability,
        cmd_payload: &T,
    ) -> Result<(), KernelError> {
        if rights::sufficient(capability.rights, cmd_payload.required_rights()) {
            Ok(())
        } else {
            Err(KernelError::InsufficientRights)
        }
    }

    pub fn validate_command<C: EncodedCmd + 'static>(
        &self,
        command: &Command<C>,
        current_lc: u64,
    ) -> Result<(), KernelError> {
        let cap = self
            .state
            .capabilities
            .get(&command.capability)
            .ok_or(KernelError::CapabilityNotFound)?;

        // Convert u8 tags to AlgSuite enums for comparison and use
        let cmd_alg_suite_tag = command.alg_suite;
        let cap_alg_suite_tag = cap.alg_suite;

        if cmd_alg_suite_tag != cap_alg_suite_tag { // Compare tags directly is fine here
            return Err(KernelError::AlgorithmSuiteMismatch);
        }
        // No need to convert to AlgSuite enum *just* for equality comparison of tags.
        // Conversion to AlgSuite enum is needed when calling crypto functions or 
        // when needing the enum type itself.

        if let Some(expiry) = cap.expiry_lc {
            if current_lc >= expiry {
                return Err(KernelError::CapabilityExpired);
            }
        }
        self.verify_signature(command)?; // verify_signature now handles AlgSuite conversion
        self.rights_sufficient(cap, &command.payload)?;
        if command.lclock < current_lc { // Spec: relaxed to >=. Code has <. This needs review against spec §2.3.
            // For now, keeping existing logic: KernelError::InvalidCommandLClock for cmd.lclock < current_lc
            // Spec §2.3 Validation: assert cmd.lclock >= local_lc
            // Spec §7.1.2 Validation: Kernel accepts cmd.lclock >= local_lc.
            // The current code `command.lclock < current_lc` is equivalent to `!(command.lclock >= current_lc)`
            // This seems correct as per spec. Error if it's *less than* current.
            return Err(KernelError::InvalidCommandLClock);
        }
        Ok(())
    }

    /// apply(cmd) → Event    (Kernel Spec §3)
    pub fn apply<C: EncodedCmd + Clone + std::fmt::Debug + PartialEq + Eq + Send + Sync + 'static>(
        &mut self,
        command: &Command<C>,
    ) -> Result<Event, KernelError> {
        // Lamport overflow guard (§7.1.5).
        if self.local_lc == u64::MAX {
            return Err(KernelError::Other(
                "Replica has reached maximum Lamport clock value and cannot process further commands.".into(),
            ));
        }

        // 1. validate(cmd) (Kernel Spec §2.3)
        self.validate_command(command, self.local_lc)?;

        // 2. lclock_new = max(cmd.lclock, local_lc + 1) (Kernel Spec §3, §7.1.3)
        let lclock_new = command.lclock.max(self.local_lc + 1);

        // 3. delta ← runtime(cmd) (Kernel Spec §3, §5)
        let mut delta = self.runtime.execute(&self.state, command)?;

        // --- KERNEL RESPONSIBILITY: SET ENTITY LCLOCKS ---
        // The runtime produces a delta based on the command and current state.
        // The kernel is responsible for assigning the event's lclock (lclock_new) 
        // to all entities within this delta before they are validated by append_delta.
        for entity in delta.new_entities.iter_mut() {
            entity.header.lclock = lclock_new;
        }
        for entity in delta.updated_entities.iter_mut() {
            entity.header.lclock = lclock_new;
        }
        // --- END LCLOCK ASSIGNMENT ---

        // 4. Σ.append(delta, lclock_new) (Kernel Spec §3) 
        //    (includes invariant checks: delta.respects_invariants() is implicitly checked by append_delta)
        //    The lclock check in append_delta will now pass due to the step above.
        self.append_delta(&delta, lclock_new)?;

        // 5. local_lc = lclock_new (Kernel Spec §3)
        self.local_lc = lclock_new;

        // 6. Update vector clock for the new event.
        //    Start with the kernel's current local_vc.
        //    Merge the command's vclock if present.
        //    Then, set the event's vclock for this replica to the new event lclock.
        //    (Kernel Spec §3: "vc = merge_vector_clock(local_vc, cmd.vclock_if_present)")
        //    (Kernel Spec §7.4 Increment: "On Event creation by replica R with Lamport time L: event.vclock[R] = L.
        //                                Other entries are merged from the causal command or previous local state.")
        
        let mut vc_for_event = self.local_vc.clone(); // Start with kernel's current VC

        if let Some(cmd_vc) = &command.vclock {
            vc_for_event.merge_into(cmd_vc); // Merge command's VC if it exists
        }

        // Regardless of command's VC, this replica's entry in the event's VC is set to the new event lclock.
        vc_for_event.0.insert(self.replica_id, lclock_new);
        
        // The kernel's local_vc is also updated to this newly computed vc_for_event, 
        // as it represents the most up-to-date causal knowledge *after* this event.
        self.local_vc = vc_for_event.clone();

        // 7. materialise_event (Kernel Spec §3)
        let event = self.materialise_event(command, &delta, lclock_new, vc_for_event)?;

        // Log the event locally (persisting to Σ.event_log).
        self.state.event_log.push(event.clone());

        Ok(event)
    }

    /// Merge an incoming event's clocks into the local replica.
    pub fn process_incoming_event(&mut self, evt: &Event) -> Result<(), KernelError> {
        // Lamport merge (§7.1.4)
        self.local_lc = self.local_lc.max(evt.lclock);

        // Vector-clock merge (§7.4.2) - now mandatory, using VClock::merge_into
        self.local_vc.merge_into(&evt.vclock);

        Ok(())
    }
}

// Test helper method moved from tests.rs
#[cfg(test)]
impl<CP: CryptoProvider + Clone, R: Runtime<CP> + Clone + std::fmt::Debug>
    Kernel<CP, R> 
{
    pub fn get_event_hash_input_for_test(
        &self,
        caused_by_command_id: &CID,
        event_lclock: u64,
        event_replica_id: &ReplicaID,
        event_alg_suite_tag: u8, // Corrected: Was event_alg_suite: AlgSuite, now u8 tag
        new_entities_cids: &[CID],
        updated_entities_cids: &[CID],
        vector_clock: &VClock,
        reserved_bytes: &[u8], // Corrected: Was additional_fields, now reserved_bytes
    ) -> Vec<u8> {
        // Now calling the private method from within the same impl block scope (conditionally compiled)
        self.get_event_hash_input(
            caused_by_command_id, 
            event_lclock, 
            event_replica_id, 
            event_alg_suite_tag, // Pass the u8 tag
            new_entities_cids, 
            updated_entities_cids, 
            vector_clock, 
            reserved_bytes // Pass reserved_bytes
        )
    }
}

impl Kernel<crate::crypto::PlaceholderCryptoProvider, DefaultRuntime> {
    /// Convenience constructor used heavily in tests.
    /// Vector clocks are now mandatory, so enable_vector_clocks parameter is removed.
    pub fn new_with_default_crypto(replica_id: ReplicaID) -> Self {
        Self::new(replica_id, DefaultRuntime::default(), crate::crypto::PlaceholderCryptoProvider::default())
    }
} 