//!
//! Core kernel logic for Amulet-Core, including state transition and command processing.
//!
//! This file was mechanically moved from `src/kernel.rs` to `src/kernel/core.rs`
//! as part of the repository re-organisation (see PROJECT_ROADMAP.md Phase Refactor).

use crate::types::{AlgSuite, CID, ReplicaID, VectorClock};
use crate::domain::{Command, EncodedCmd, Entity};
use crate::access::Capability;
use crate::events::Event;
use crate::error::KernelError;
use std::collections::HashMap; // For SystemState and VectorClock
use crate::rights; // Rights algebra module
use crate::time::vector as vector_clock; // Vector-clock utilities
use crate::crypto::{CryptoProvider, Hasher, Verifier, PlaceholderCryptoProvider}; // Crypto traits & placeholder provider
use std::marker::PhantomData; // Marker type for CP
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
#[derive(Debug, Clone, Default)]
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
pub struct Kernel<CP: CryptoProvider, R: Runtime<CP> = DefaultRuntime> {
    /// The kernel's current local Lamport clock.
    pub local_lc: u64,
    /// The kernel's current local Vector clock (if enabled).
    pub local_vc: VectorClock,
    /// The authoritative state of the system.
    pub state: SystemState,
    /// The ReplicaID of this kernel instance.
    pub replica_id: ReplicaID,
    runtime: R,
    _crypto_provider: PhantomData<CP>, // Marker for the crypto provider type
}

impl<CP, R> Kernel<CP, R>
where
    CP: CryptoProvider + Hasher + Verifier + Default + Clone,
    R: Runtime<CP> + Clone + std::fmt::Debug,
{
    /// Creates a new Kernel instance.
    pub fn new(replica_id: ReplicaID, runtime: R, _crypto_provider_param: CP) -> Self {
        Kernel {
            local_lc: 0,
            local_vc: if true { Some(HashMap::new()) } else { None },
            state: SystemState::default(),
            replica_id,
            runtime,
            _crypto_provider: PhantomData,
        }
    }

    /// Generates a Content ID (CID) for the given data using the kernel's crypto provider.
    fn generate_cid(&self, data: &[u8], alg_suite: AlgSuite) -> Result<CID, KernelError> {
        CP::hash(data, alg_suite).map_err(KernelError::CryptoError)
    }

    /// Helper to deterministically serialise event fields for CID generation.
    fn get_event_hash_input(
        &self,
        caused_by_command_id: &CID,
        event_lclock: u64,
        event_replica_id: &ReplicaID,
        event_alg_suite: AlgSuite,
        new_entities_cids: &[CID],
        updated_entities_cids: &[CID],
        vector_clock: &VectorClock,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(caused_by_command_id);
        bytes.extend_from_slice(&event_lclock.to_le_bytes());
        bytes.extend_from_slice(event_replica_id);
        bytes.push(event_alg_suite as u8);

        // Serialise CIDs deterministically (sorted).
        let mut sorted_new = new_entities_cids.to_vec();
        sorted_new.sort_unstable();
        for cid in sorted_new {
            bytes.extend_from_slice(&cid);
        }
        let mut sorted_updated = updated_entities_cids.to_vec();
        sorted_updated.sort_unstable();
        for cid in sorted_updated {
            bytes.extend_from_slice(&cid);
        }

        // Serialise VectorClock deterministically.
        if let Some(vc_map) = vector_clock {
            bytes.push(1);
            let mut vc_entries: Vec<(&ReplicaID, &u64)> = vc_map.iter().collect();
            vc_entries.sort_unstable_by_key(|(k, _)| *k);
            for (replica_id, lclock_val) in vc_entries {
                bytes.extend_from_slice(replica_id);
                bytes.extend_from_slice(&lclock_val.to_le_bytes());
            }
        } else {
            bytes.push(0);
        }
        bytes
    }

    /// Append the `delta` into Σ, checking basic invariants.
    fn append_delta(&mut self, delta: &StateDelta, lclock_new: u64) -> Result<(), KernelError> {
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
    fn materialise_event<C: EncodedCmd>(\n        &self,\n        command: &Command<C>,\n        delta: &StateDelta,\n        lclock_new: u64,\n        vc_new: VectorClock,\n    ) -> Result<Event, KernelError> {
        let new_cids: Vec<CID> = delta.new_entities.iter().map(|e| e.header.id).collect();
        let updated_cids: Vec<CID> = delta.updated_entities.iter().map(|e| e.header.id).collect();

        let input = self.get_event_hash_input(
            &command.id,
            lclock_new,
            &self.replica_id,
            command.alg_suite,
            &new_cids,
            &updated_cids,
            &vc_new,
        );
        let event_id = self.generate_cid(&input, command.alg_suite)?;

        Ok(Event {
            id: event_id,
            alg_suite: command.alg_suite,
            replica: self.replica_id,
            caused_by: command.id,
            lclock: lclock_new,
            new_entities: new_cids,
            updated_entities: updated_cids,
            vector_clock: vc_new,
        })
    }

    /// Verify the command's signature using the capability holder's pub-key.
    fn verify_signature<C: EncodedCmd>(&self, command: &Command<C>) -> Result<(), KernelError> {
        let signed_bytes = command
            .payload
            .to_signed_bytes(
                &command.id,
                command.alg_suite,
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

        CP::verify(&signed_bytes, &command.signature, &cap.holder, command.alg_suite)
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

        if command.alg_suite != cap.alg_suite {
            return Err(KernelError::AlgorithmSuiteMismatch);
        }
        if let Some(expiry) = cap.expiry_lc {
            if current_lc >= expiry {
                return Err(KernelError::CapabilityExpired);
            }
        }
        self.verify_signature(command)?;
        self.rights_sufficient(cap, &command.payload)?;
        if command.lclock < current_lc {
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

        // 1. validate(cmd)
        self.validate_command(command, self.local_lc)?;

        // 2. lclock_new = max(cmd.lclock, local_lc + 1)
        let lclock_new = command.lclock.max(self.local_lc + 1);

        // 3. delta ← runtime(cmd)
        let delta = self.runtime.execute(&self.state, command)?;

        // 5. Σ.append(delta, lclock_new)
        self.append_delta(&delta, lclock_new)?;

        // 6. local_lc = lclock_new
        self.local_lc = lclock_new;

        // 7. vc = merge_vector_clock(cmd)  (simplified: always Some(vc) if feature enabled)
        let mut final_vc: HashMap<ReplicaID, u64> = self
            .local_vc
            .clone()
            .unwrap_or_else(HashMap::new);
        if self.local_vc.is_some() {
            final_vc.insert(self.replica_id, lclock_new);
            self.local_vc = Some(final_vc.clone());
        }
        let vc_for_event = if self.local_vc.is_some() {
            Some(final_vc)
        } else {
            None
        };

        // 8. materialise_event
        let event = self.materialise_event(command, &delta, lclock_new, vc_for_event)?;

        // Log the event locally.
        self.state.event_log.push(event.clone());

        Ok(event)
    }

    /// Merge an incoming event's clocks into the local replica.
    pub fn process_incoming_event(&mut self, evt: &Event) -> Result<(), KernelError> {
        // Lamport merge (§7.1.4)
        self.local_lc = self.local_lc.max(evt.lclock);

        // Vector-clock merge (§7.4.2)
        if let (Some(local), Some(incoming)) = (&mut self.local_vc, &evt.vector_clock) {
            vector_clock::merge_into(local, incoming);
        }
        Ok(())
    }
}

impl Kernel<PlaceholderCryptoProvider, DefaultRuntime> {
    /// Convenience constructor used heavily in tests.
    pub fn new_with_default_crypto(replica_id: ReplicaID) -> Self {
        Self::new(replica_id, DefaultRuntime::default(), PlaceholderCryptoProvider::default())
    }
} 