#![cfg(test)]

use amulet_core::kernel::{Kernel, Runtime};
use amulet_core::error::KernelError;
use amulet_core::primitives::{ReplicaIdBytes, ReplicaID, VClock, Command, CidBytes, SignatureBytes, Entity, Capability, PublicKeyBytes};
use amulet_core::types::AlgSuite;
use amulet_core::command_traits::{EncodedCmd, CommandTraitError};
use amulet_core::kernel::core::{StateDelta, SystemState};
use amulet_core::crypto::PlaceholderCryptoProvider;
use std::collections::HashMap;
use std::fmt::Debug;

// --- Mock Command Payload for Tests ---
#[derive(Clone, Debug, PartialEq, Eq)]
struct MockCmdPayload(Vec<u8>);

impl EncodedCmd for MockCmdPayload {
    type Error = CommandTraitError;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(MockCmdPayload(bytes.to_vec()))
    }

    fn required_rights(&self) -> u32 {
        0 // For conformance tests, assume no specific rights are required by default
    }

    fn to_signed_bytes(
        &self,
        command_id: &CidBytes,
        alg_suite: AlgSuite,
        replica: &ReplicaID,
        capability: &CidBytes,
        lclock: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&command_id.0);
        bytes.extend_from_slice(&(alg_suite as u8).to_le_bytes());
        bytes.extend_from_slice(&replica.0);
        bytes.extend_from_slice(&capability.0);
        bytes.extend_from_slice(&lclock.to_le_bytes());
        bytes.extend_from_slice(&self.0);
        Ok(bytes)
    }
}
// --- End Mock Command Payload ---

// Helper function to create a placeholder Capability
fn create_placeholder_capability() -> Capability {
    Capability {
        id: CidBytes([1u8; 32]), // This CID must match the one used in commands
        alg_suite: AlgSuite::CLASSIC as u8,
        holder: PublicKeyBytes([0u8; 32]), // Placeholder public key
        target_entity: CidBytes([0u8; 32]), // Placeholder target entity
        rights: u32::MAX, // Grant all rights for simplicity in these tests
        nonce: 0,
        expiry_lc: None, // No expiry for simplicity
        kind: 0,
        signature: SignatureBytes([0u8; 64]), // Placeholder signature
    }
}

// Minimal Mock Runtime
#[derive(Clone, Debug)]
struct MockRuntime;

impl<CP: amulet_core::crypto::CryptoProvider + Clone> Runtime<CP> for MockRuntime {
    fn execute<CmdP: EncodedCmd>(
        &self,
        _state: &SystemState,
        _command: &Command<CmdP>
    ) -> Result<StateDelta, KernelError> {
        Ok(StateDelta {
            new_entities: Vec::new(),
            updated_entities: Vec::new(),
        })
    }
}

// Helper function to create a Kernel instance with a specific replica ID
fn create_kernel_for_test(replica_id: ReplicaID) -> Kernel<PlaceholderCryptoProvider, MockRuntime> {
    let crypto_provider = PlaceholderCryptoProvider::default();
    let runtime = MockRuntime;
    Kernel::new(replica_id, runtime, crypto_provider)
}

// Helper function to create a simple command
fn create_test_command_for_conformance(
    payload_bytes: Vec<u8>,
    vclock_opt: Option<VClock>,
    replica_id: ReplicaID,
    lclock: u64
) -> Command<MockCmdPayload> {
    Command {
        id: CidBytes([0u8; 32]),
        alg_suite: AlgSuite::CLASSIC as u8,
        replica: replica_id,
        capability: CidBytes([1u8; 32]),
        lclock: lclock,
        vclock: vclock_opt,
        payload: MockCmdPayload(payload_bytes),
        signature: SignatureBytes([0u8; 64]),
    }
}

#[test]
fn test_vclock_increment_local_component() {
    let replica_id_bytes = [1u8; 16];
    let replica_id = ReplicaIdBytes(replica_id_bytes);
    let mut kernel = create_kernel_for_test(replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    let initial_lc = kernel.local_vc.0.get(&replica_id).unwrap_or(&0).clone();

    let command = create_test_command_for_conformance(vec![1, 2, 3], None, replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    let new_lc = event.vclock.0.get(&replica_id).expect("Local replica ID should be in VClock");
    assert_eq!(*new_lc, initial_lc + 1, "Local component of VClock should increment by 1.");
}

#[test]
fn test_vclock_increment_other_components_unchanged() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);

    let other_replica_id_bytes = [2u8; 16];
    let other_replica_id = ReplicaIdBytes(other_replica_id_bytes);
    let other_replica_initial_lc = 5;

    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    // Initialize the kernel's VClock to include another replica's clock
    kernel.local_vc.0.insert(other_replica_id.clone(), other_replica_initial_lc);

    let command = create_test_command_for_conformance(vec![4, 5, 6], None, local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    let other_lc_after_event = event.vclock.0.get(&other_replica_id).expect("Other replica ID should be in VClock");
    assert_eq!(*other_lc_after_event, other_replica_initial_lc, "Other components of VClock should remain unchanged.");

    let local_lc_after_event = event.vclock.0.get(&local_replica_id).expect("Local replica ID should be in VClock");
    assert_eq!(*local_lc_after_event, 1, "Local component should increment even with other components present.");
}

// More tests for VClock merge logic will be added here.

// Helper function to create a VClock from a vector of (ReplicaID, u64) tuples
fn create_vclock_from_map(map: Vec<(ReplicaID, u64)>) -> VClock {
    VClock(map.into_iter().collect())
}

#[test]
fn test_vclock_merge_command_vclock_none() {
    let replica_id_bytes = [1u8; 16];
    let replica_id = ReplicaIdBytes(replica_id_bytes);
    let mut kernel = create_kernel_for_test(replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap.clone()); // clone since it's used twice for cmd1 & cmd2

    // Event 1: establish initial clock for replica_id
    let cmd1 = create_test_command_for_conformance(vec![1], None, replica_id.clone(), 1);
    let event1_result = kernel.apply(&cmd1);
    assert!(event1_result.is_ok(), "apply command failed: {:?}", event1_result.err());
    let event1 = event1_result.unwrap();
    assert_eq!(*event1.vclock.0.get(&replica_id).unwrap(), 1);

    // Event 2: command has no vclock, event vclock should be kernel's incremented vclock
    let cmd2 = create_test_command_for_conformance(vec![2], None, replica_id.clone(), 2);
    let event2_result = kernel.apply(&cmd2);
    assert!(event2_result.is_ok(), "apply command failed: {:?}", event2_result.err());
    let event2 = event2_result.unwrap();
    assert_eq!(*event2.vclock.0.get(&replica_id).unwrap(), 2);
    assert_eq!(event2.vclock.0.len(), 1, "VClock should only contain the local replica ID");
}

#[test]
fn test_vclock_merge_command_vclock_present_no_overlap() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);
    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    let cmd_replica_id_bytes = [2u8; 16];
    let cmd_replica_id = ReplicaIdBytes(cmd_replica_id_bytes);

    let mut cmd_vclock_map = HashMap::new();
    cmd_vclock_map.insert(cmd_replica_id.clone(), 5);
    let cmd_vclock = VClock(cmd_vclock_map);

    let command = create_test_command_for_conformance(vec![1,2,3], Some(cmd_vclock), local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    // Local component increments
    assert_eq!(*event.vclock.0.get(&local_replica_id).unwrap(), 1, "Local component should increment.");
    // Command's component is merged
    assert_eq!(*event.vclock.0.get(&cmd_replica_id).unwrap(), 5, "Command's VClock component should be merged.");
    assert_eq!(event.vclock.0.len(), 2, "Event VClock should have two entries.");
}

#[test]
fn test_vclock_merge_command_vclock_present_kernel_ahead() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);
    let shared_replica_id_bytes = [3u8; 16];
    let shared_replica_id = ReplicaIdBytes(shared_replica_id_bytes);

    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    kernel.local_vc.0.insert(shared_replica_id.clone(), 10);

    let mut cmd_vclock_map = HashMap::new();
    cmd_vclock_map.insert(shared_replica_id.clone(), 5);
    let cmd_vclock = VClock(cmd_vclock_map);

    let command = create_test_command_for_conformance(vec![1], Some(cmd_vclock), local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    assert_eq!(*event.vclock.0.get(&local_replica_id).unwrap(), 1, "Local component increments.");
    assert_eq!(*event.vclock.0.get(&shared_replica_id).unwrap(), 10, "Kernel's higher value for shared ID should be kept.");
    assert_eq!(event.vclock.0.len(), 2);
}

#[test]
fn test_vclock_merge_command_vclock_present_command_ahead() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);
    let shared_replica_id_bytes = [3u8; 16];
    let shared_replica_id = ReplicaIdBytes(shared_replica_id_bytes);

    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    kernel.local_vc.0.insert(shared_replica_id.clone(), 5);

    let mut cmd_vclock_map = HashMap::new();
    cmd_vclock_map.insert(shared_replica_id.clone(), 10);
    let cmd_vclock = VClock(cmd_vclock_map);

    let command = create_test_command_for_conformance(vec![1], Some(cmd_vclock), local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    assert_eq!(*event.vclock.0.get(&local_replica_id).unwrap(), 1, "Local component increments.");
    assert_eq!(*event.vclock.0.get(&shared_replica_id).unwrap(), 10, "Command's higher value for shared ID should be taken.");
    assert_eq!(event.vclock.0.len(), 2);
}

#[test]
fn test_vclock_merge_command_vclock_present_mixed_ahead() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);
    let replica_a_bytes = [10u8; 16];
    let replica_a = ReplicaIdBytes(replica_a_bytes);
    let replica_b_bytes = [11u8; 16];
    let replica_b = ReplicaIdBytes(replica_b_bytes);

    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    kernel.local_vc.0.insert(replica_a.clone(), 20);
    kernel.local_vc.0.insert(replica_b.clone(), 20);

    let mut cmd_vclock_map = HashMap::new();
    cmd_vclock_map.insert(replica_a.clone(), 15);
    cmd_vclock_map.insert(replica_b.clone(), 25);
    let cmd_vclock = VClock(cmd_vclock_map);

    let command = create_test_command_for_conformance(vec![1], Some(cmd_vclock), local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let event = event_result.unwrap();

    assert_eq!(*event.vclock.0.get(&local_replica_id).unwrap(), 1, "Local component increments.");
    assert_eq!(*event.vclock.0.get(&replica_a).unwrap(), 20, "Kernel's higher value for replica_a should be kept.");
    assert_eq!(*event.vclock.0.get(&replica_b).unwrap(), 25, "Command's higher value for replica_b should be taken.");
    assert_eq!(event.vclock.0.len(), 3);
}

#[test]
fn test_vclock_merge_updates_kernel_local_vc() {
    let local_replica_id_bytes = [1u8; 16];
    let local_replica_id = ReplicaIdBytes(local_replica_id_bytes);
    let cmd_replica_id_bytes = [2u8; 16];
    let cmd_replica_id = ReplicaIdBytes(cmd_replica_id_bytes);

    let mut kernel = create_kernel_for_test(local_replica_id.clone());

    // Insert placeholder capability
    let placeholder_cap = create_placeholder_capability();
    kernel.state.capabilities.insert(placeholder_cap.id, placeholder_cap);

    let mut cmd_vclock_map = HashMap::new();
    cmd_vclock_map.insert(cmd_replica_id.clone(), 5);
    cmd_vclock_map.insert(local_replica_id.clone(), 0);
    let cmd_vclock = VClock(cmd_vclock_map);

    let command = create_test_command_for_conformance(vec![1], Some(cmd_vclock), local_replica_id.clone(), 1);
    let event_result = kernel.apply(&command);
    assert!(event_result.is_ok(), "apply command failed: {:?}", event_result.err());
    let _event = event_result.unwrap();

    // Check kernel's internal VClock state
    let kernel_vc = &kernel.local_vc.0;
    assert_eq!(*kernel_vc.get(&local_replica_id).unwrap(), 1, "Kernel's local_vc: Local component should be incremented.");
    assert_eq!(*kernel_vc.get(&cmd_replica_id).unwrap(), 5, "Kernel's local_vc: Command's component should be merged.");
    assert_eq!(kernel_vc.len(), 2, "Kernel's local_vc should have two entries.");
} 