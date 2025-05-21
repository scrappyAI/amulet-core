#![cfg(test)]

use std::collections::{HashMap};
use crate::kernel::core::{Kernel, SystemState, StateDelta};
use crate::primitives::{VClock, CID, ReplicaID, Event, Entity, EntityHeader, Capability, Command, CidBytes, ReplicaIdBytes, SignatureBytes, PublicKeyBytes};
use crate::types::AlgSuite;
use crate::command_traits::{EncodedCmd, CommandTraitError};
use crate::crypto::{PlaceholderCryptoProvider, CryptoProvider};
use crate::kernel::runtime::{DefaultRuntime, Runtime};
use crate::error::KernelError;

// --- Test Utilities ---

const TEST_REPLICA_ID_1: ReplicaID = ReplicaIdBytes([1u8; 16]);
const TEST_REPLICA_ID_2: ReplicaID = ReplicaIdBytes([2u8; 16]);
const TEST_REPLICA_ID_3: ReplicaID = ReplicaIdBytes([3u8; 16]);

fn generate_test_cid(id_byte: u8) -> CID {
    CidBytes([id_byte; 32])
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MockEncodedCmd {
    payload_data: String,
    required_rights_value: u32,
}

impl MockEncodedCmd {
    fn new(payload_data: &str, required_rights_value: u32) -> Self {
        MockEncodedCmd {
            payload_data: payload_data.to_string(),
            required_rights_value,
        }
    }
}

#[derive(Debug)]
struct MockCmdError(String); // Minimal error type for the mock command

impl From<CommandTraitError> for MockCmdError { // Helper to convert if EncodedCmd returns CommandTraitError
    fn from(err: CommandTraitError) -> Self {
        MockCmdError(err.to_string())
    }
}

impl std::fmt::Display for MockCmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockCmdError: {}", self.0)
    }
}
impl std::error::Error for MockCmdError {}

impl EncodedCmd for MockEncodedCmd {
    type Error = MockCmdError;

    fn encode(&self) -> Vec<u8> {
        self.payload_data.as_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(MockEncodedCmd {
            payload_data: String::from_utf8(bytes.to_vec()).map_err(|e| MockCmdError(e.to_string()))?,
            required_rights_value: 0, // Default for this mock
        })
    }

    fn required_rights(&self) -> u32 {
        self.required_rights_value
    }

    fn to_signed_bytes(
        &self,
        command_id: &CID,
        alg_suite: AlgSuite,
        replica: &ReplicaID,
        capability: &CID,
        lclock: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&command_id.0);
        bytes.push(alg_suite as u8);
        bytes.extend_from_slice(&replica.0);
        bytes.extend_from_slice(&capability.0);
        bytes.extend_from_slice(&lclock.to_le_bytes());
        bytes.extend_from_slice(self.payload_data.as_bytes());
        Ok(bytes)
    }
}

fn create_test_kernel(replica_id: ReplicaID) -> Kernel<PlaceholderCryptoProvider, DefaultRuntime> {
    Kernel::new_with_default_crypto(replica_id)
}

fn create_test_command(
    payload: MockEncodedCmd,
    lclock: u64,
    replica_id: ReplicaID,
    capability_cid: CID,
    // Simulate CID generation for the command itself for more realism
    command_id_byte: u8, 
    vclock: Option<VClock>,
) -> Command<MockEncodedCmd> {
    let cmd_id = generate_test_cid(command_id_byte); 
    Command {
        id: cmd_id,
        alg_suite: AlgSuite::CLASSIC as u8,
        replica: replica_id,
        capability: capability_cid,
        lclock,
        vclock,
        payload,
        signature: SignatureBytes([0u8; 64]), // Placeholder signature
    }
}

fn create_test_capability(
    id: CID,
    holder_pk: [u8; 32], // PublicKey is [u8; 32] in primitives.rs
    target_entity: CID,
    rights: u32,
    expiry_lc: Option<u64>,
    alg_suite: AlgSuite,
) -> Capability {
    Capability {
        id,
        alg_suite: alg_suite as u8,
        holder: PublicKeyBytes(holder_pk),
        target_entity,
        rights,
        nonce: 0,
        expiry_lc,
        kind: 0,
        signature: SignatureBytes([0u8; 64]), // Placeholder signature
    }
}

fn create_test_entity(id_byte: u8, version: u64, lclock: u64, parent_cid_byte: Option<u8>) -> Entity<Vec<u8>> {
    Entity {
        header: EntityHeader {
            id: generate_test_cid(id_byte),
            version,
            lclock,
            parent: parent_cid_byte.map(generate_test_cid),
        },
        body: vec![id_byte], // Simple body
    }
}

// --- Test Cases ---

#[test]
fn test_kernel_new() {
    let kernel = create_test_kernel(TEST_REPLICA_ID_1);
    assert_eq!(kernel.local_lc, 0, "Initial Lamport clock should be 0");
    assert_eq!(kernel.local_vc, VClock::default(), "Initial Vector clock should be empty");
    assert!(kernel.state.entities.is_empty(), "Initial entities should be empty");
    assert!(kernel.state.capabilities.is_empty(), "Initial capabilities should be empty");
    assert!(kernel.state.event_log.is_empty(), "Initial event log should be empty");
    assert_eq!(kernel.replica_id, TEST_REPLICA_ID_1, "Replica ID should be set correctly");
}

#[test]
fn test_lamport_clock_on_apply() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let cap_id = generate_test_cid(100);
    let capability = create_test_capability(cap_id, [1u8;32], generate_test_cid(0), 0, None, AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, capability);

    // Case 1: cmd.lclock < kernel.local_lc + 1
    // kernel.local_lc = 0
    let cmd1_payload = MockEncodedCmd::new("cmd1", 0);
    let cmd1 = create_test_command(cmd1_payload, 0, TEST_REPLICA_ID_1, cap_id, 1, None); // cmd.lclock = 0
    let event1 = kernel.apply(&cmd1).expect("Apply command 1 failed");
    assert_eq!(event1.lclock, 1, "Event lclock should be kernel.local_lc + 1");
    assert_eq!(kernel.local_lc, 1, "Kernel lclock should be updated to event lclock");

    // Case 2: cmd.lclock == kernel.local_lc + 1
    // kernel.local_lc = 1
    let cmd2_payload = MockEncodedCmd::new("cmd2", 0);
    let cmd2 = create_test_command(cmd2_payload, 2, TEST_REPLICA_ID_1, cap_id, 2, None); // cmd.lclock = 2
    let event2 = kernel.apply(&cmd2).expect("Apply command 2 failed");
    assert_eq!(event2.lclock, 2, "Event lclock should be cmd.lclock");
    assert_eq!(kernel.local_lc, 2, "Kernel lclock should be updated");

    // Case 3: cmd.lclock > kernel.local_lc + 1
    // kernel.local_lc = 2
    let cmd3_payload = MockEncodedCmd::new("cmd3", 0);
    let cmd3 = create_test_command(cmd3_payload, 5, TEST_REPLICA_ID_1, cap_id, 3, None); // cmd.lclock = 5
    let event3 = kernel.apply(&cmd3).expect("Apply command 3 failed");
    assert_eq!(event3.lclock, 5, "Event lclock should be cmd.lclock");
    assert_eq!(kernel.local_lc, 5, "Kernel lclock should be updated");
}

#[test]
fn test_lamport_clock_on_process_incoming_event() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    kernel.local_lc = 5; // Set initial lc

    let mut incoming_event = Event {
        id: generate_test_cid(10),
        alg_suite: AlgSuite::CLASSIC as u8,
        replica: TEST_REPLICA_ID_2,
        caused_by: generate_test_cid(11),
        lclock: 3, // Lower than kernel.local_lc
        new_entities: Vec::new(),
        updated_entities: Vec::new(),
        vclock: VClock::default(),
        reserved: Vec::new(),
    };

    // Case 1: evt.lclock < kernel.local_lc
    kernel.process_incoming_event(&incoming_event).expect("Process event failed");
    assert_eq!(kernel.local_lc, 5, "Kernel lclock should remain unchanged");

    // Case 2: evt.lclock == kernel.local_lc
    incoming_event.lclock = 5;
    kernel.process_incoming_event(&incoming_event).expect("Process event failed");
    assert_eq!(kernel.local_lc, 5, "Kernel lclock should remain unchanged");
    
    // Case 3: evt.lclock > kernel.local_lc
    incoming_event.lclock = 10;
    kernel.process_incoming_event(&incoming_event).expect("Process event failed");
    assert_eq!(kernel.local_lc, 10, "Kernel lclock should be updated to event lclock");
}

#[test]
fn test_lamport_clock_overflow() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let cap_id = generate_test_cid(100);
    let capability = create_test_capability(cap_id, [1u8;32], generate_test_cid(0), 0, None, AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, capability);

    kernel.local_lc = u64::MAX -1; // One step before overflow

    let cmd_payload_ok = MockEncodedCmd::new("cmd_ok", 0);
    let cmd_ok = create_test_command(cmd_payload_ok.clone(), kernel.local_lc +1 , TEST_REPLICA_ID_1, cap_id, 200, None);
    
    match kernel.apply(&cmd_ok) {
        Ok(event) => {
            assert_eq!(event.lclock, u64::MAX, "Event lclock should be u64::MAX");
            assert_eq!(kernel.local_lc, u64::MAX, "Kernel lclock should be u64::MAX");
        }
        Err(e) => panic!("Apply before overflow should succeed, but got {:?}", e),
    }
    
    // Next apply should overflow
    let cmd_payload_overflow = MockEncodedCmd::new("cmd_overflow", 0);
    // cmd.lclock doesn't matter as much as kernel.local_lc being MAX
    let cmd_overflow = create_test_command(cmd_payload_overflow, kernel.local_lc , TEST_REPLICA_ID_1, cap_id, 201, None); 
    
    match kernel.apply(&cmd_overflow) {
        Err(KernelError::Other(msg)) => {
            assert!(msg.contains("Replica has reached maximum Lamport clock value"), "Error message mismatch for overflow");
        }
        Ok(_) => panic!("Apply should fail due to Lamport clock overflow"),
        Err(e) => panic!("Unexpected error type for Lamport overflow: {:?}", e),
    }
}

#[test]
fn test_vector_clock_on_apply() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let cap_id = generate_test_cid(100);
    let capability = create_test_capability(cap_id, [1u8;32], generate_test_cid(0), 0, None, AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, capability.clone());

    // Initial apply
    let cmd1_payload = MockEncodedCmd::new("cmd_vc1", 0);
    let cmd1 = create_test_command(cmd1_payload, 1, TEST_REPLICA_ID_1, cap_id, 10, None);
    let event1 = kernel.apply(&cmd1).expect("Apply command VC1 failed");

    assert_eq!(event1.vclock.0.len(), 1, "Event VC should have one entry");
    assert_eq!(event1.vclock.0.get(&TEST_REPLICA_ID_1), Some(&event1.lclock), "Event VC for own replica incorrect");
    assert_eq!(kernel.local_vc, event1.vclock, "Kernel VC should be updated to event VC");

    // Simulate some existing state in kernel.local_vc from another replica
    kernel.local_vc.0.insert(TEST_REPLICA_ID_2, 5);
    let mut expected_vc_before_apply2 = kernel.local_vc.clone(); // R1:ev1.lclock, R2:5

    let cmd2_payload = MockEncodedCmd::new("cmd_vc2", 0);
    let cmd2 = create_test_command(cmd2_payload, kernel.local_lc + 1, TEST_REPLICA_ID_1, cap_id, 11, None);
    let event2 = kernel.apply(&cmd2).expect("Apply command VC2 failed");
    
    expected_vc_before_apply2.0.insert(TEST_REPLICA_ID_1, event2.lclock);

    assert_eq!(event2.vclock.0.len(), 2, "Event VC should have two entries after prior state");
    assert_eq!(event2.vclock.0.get(&TEST_REPLICA_ID_1), Some(&event2.lclock), "Event VC for R1 (event2) incorrect");
    assert_eq!(event2.vclock.0.get(&TEST_REPLICA_ID_2), Some(&5), "Event VC for R2 (event2) should be preserved");
    assert_eq!(kernel.local_vc, event2.vclock, "Kernel VC should be updated to event2 VC");
    assert_eq!(kernel.local_vc, expected_vc_before_apply2, "Kernel VC should match expected VC");
}

#[test]
fn test_vector_clock_on_process_incoming_event() {
    let mut kernel_r1 = create_test_kernel(TEST_REPLICA_ID_1);
    kernel_r1.local_lc = 1;
    kernel_r1.local_vc.0.insert(TEST_REPLICA_ID_1, 1);

    // Event from R2, only knows about R2
    let mut vc_r2_event = VClock::default();
    vc_r2_event.0.insert(TEST_REPLICA_ID_2, 2);
    let event_from_r2 = Event {
        id: generate_test_cid(20),
        alg_suite: AlgSuite::CLASSIC as u8,
        replica: TEST_REPLICA_ID_2,
        caused_by: generate_test_cid(21),
        lclock: 2, 
        new_entities: Vec::new(),
        updated_entities: Vec::new(),
        vclock: vc_r2_event,
        reserved: Vec::new(),
    };

    kernel_r1.process_incoming_event(&event_from_r2).expect("Process R2 event failed");
    assert_eq!(kernel_r1.local_lc, 2, "R1 LC should update to R2 event LC");
    assert_eq!(kernel_r1.local_vc.0.len(), 2, "R1 VC should have 2 entries");
    assert_eq!(kernel_r1.local_vc.0.get(&TEST_REPLICA_ID_1), Some(&1), "R1 VC for R1 should be unchanged");
    assert_eq!(kernel_r1.local_vc.0.get(&TEST_REPLICA_ID_2), Some(&2), "R1 VC for R2 should be from event");

    // Event from R3, knows about R2 and R3, R1 has different clock for R2
    kernel_r1.local_vc.0.insert(TEST_REPLICA_ID_2, 3); // R1's knowledge of R2 advances
    kernel_r1.local_lc = 3;

    let mut vc_r3_event = VClock::default();
    vc_r3_event.0.insert(TEST_REPLICA_ID_2, 2); // R3 has older view of R2
    vc_r3_event.0.insert(TEST_REPLICA_ID_3, 4); // R3 is at 4
    let event_from_r3 = Event {
        id: generate_test_cid(30),
        alg_suite: AlgSuite::CLASSIC as u8,
        replica: TEST_REPLICA_ID_3,
        caused_by: generate_test_cid(31),
        lclock: 4, 
        new_entities: Vec::new(),
        updated_entities: Vec::new(),
        vclock: vc_r3_event,
        reserved: Vec::new(),
    };
    kernel_r1.process_incoming_event(&event_from_r3).expect("Process R3 event failed");
    assert_eq!(kernel_r1.local_lc, 4, "R1 LC should update to R3 event LC");
    assert_eq!(kernel_r1.local_vc.0.len(), 3, "R1 VC should have 3 entries");
    assert_eq!(kernel_r1.local_vc.0.get(&TEST_REPLICA_ID_1), Some(&1), "R1 VC for R1 unchanged");
    assert_eq!(kernel_r1.local_vc.0.get(&TEST_REPLICA_ID_2), Some(&3), "R1 VC for R2 should be max (3)");
    assert_eq!(kernel_r1.local_vc.0.get(&TEST_REPLICA_ID_3), Some(&4), "R1 VC for R3 should be from event");
}

// Mock Runtime for testing deltas
#[derive(Default, Debug, Clone)]
struct MockRuntimeWithDelta {
    delta_to_produce: Option<StateDelta>
}

impl<CP: CryptoProvider> Runtime<CP> for MockRuntimeWithDelta {
    fn execute<C: EncodedCmd>(
        &self,
        _state: &SystemState,
        _cmd: &Command<C>,
    ) -> Result<StateDelta, KernelError> {
        match &self.delta_to_produce {
            Some(delta) => Ok(delta.clone()),
            None => Ok(StateDelta { new_entities: Vec::new(), updated_entities: Vec::new() })
        }
    }
}

#[test]
fn test_materialise_event_content() {
    let replica_id = TEST_REPLICA_ID_1;
    let runtime = MockRuntimeWithDelta::default(); // No delta for this specific test part
    let mut kernel = Kernel::new(replica_id, runtime, PlaceholderCryptoProvider::default());
    
    let cap_id = generate_test_cid(100);
    let capability = create_test_capability(cap_id, [1u8;32], generate_test_cid(0), 0, None, AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, capability.clone());

    let new_entity_cid = generate_test_cid(50);
    let updated_entity_cid = generate_test_cid(51);

    // Add initial version of the entity that will be updated
    let initial_updated_entity = create_test_entity(51, 1, kernel.local_lc, None); // version 1, current lc
    kernel.state.entities.insert(updated_entity_cid, initial_updated_entity.clone());
    
    let mock_delta = StateDelta {
        new_entities: vec![create_test_entity(50, 1, 0, None)], // lclock will be set by kernel
        updated_entities: vec![create_test_entity(51, initial_updated_entity.header.version + 1, 0, None)], // lclock will be set by kernel, ensure version increments correctly
    };

    kernel.runtime = MockRuntimeWithDelta { delta_to_produce: Some(mock_delta) }; // Inject mock delta

    let cmd_payload = MockEncodedCmd::new("mat_event_cmd", 0);
    let cmd_lclock = kernel.local_lc + 1;
    let command = create_test_command(cmd_payload, cmd_lclock, replica_id, cap_id, 30, None);
    
    let event = kernel.apply(&command).expect("Apply for materialise_event failed");

    assert_ne!(event.id, CidBytes([0u8;32]), "Event ID should be generated");
    assert_eq!(event.alg_suite, command.alg_suite as u8, "Event alg_suite mismatch");
    assert_eq!(event.replica, replica_id, "Event replica mismatch");
    assert_eq!(event.caused_by, command.id, "Event caused_by mismatch");
    assert_eq!(event.lclock, cmd_lclock, "Event lclock mismatch"); // Kernel sets it based on cmd and local_lc
    
    assert!(event.vclock.0.contains_key(&replica_id), "Event VC missing own replica");
    assert_eq!(event.vclock.0.get(&replica_id), Some(&event.lclock), "Event VC for own replica has wrong lclock");

    assert_eq!(event.new_entities.len(), 1, "Incorrect number of new entities in event");
    assert_eq!(event.new_entities[0], new_entity_cid, "Incorrect new_entity CID");
    assert_eq!(event.updated_entities.len(), 1, "Incorrect number of updated entities in event");
    assert_eq!(event.updated_entities[0], updated_entity_cid, "Incorrect updated_entity CID");
    assert!(event.reserved.is_empty(), "Reserved field should be empty for new event");
}


#[test]
fn test_append_delta_invariants() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let event_lclock = kernel.local_lc + 1;

    // 1. New Entity CID Uniqueness
    let existing_entity_cid = generate_test_cid(1);
    kernel.state.entities.insert(existing_entity_cid, create_test_entity(1, 1, 0, None));
    let delta_conflict = StateDelta {
        new_entities: vec![create_test_entity(1, 1, event_lclock, None)], // Conflicting CID
        updated_entities: Vec::new(),
    };
    match kernel.append_delta(&delta_conflict, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("New entity CID already exists"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to new entity CID conflict"),
    }

    // 2. Updated Entity Existence & Version
    let _non_existent_cid = generate_test_cid(2);
    let delta_update_non_existent = StateDelta {
        new_entities: Vec::new(),
        updated_entities: vec![create_test_entity(2, 1, event_lclock, None)], // Non-existent CID
    };
    match kernel.append_delta(&delta_update_non_existent, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("Updated entity with CID"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to update non-existent entity"),
    }

    let entity_v1_cid = generate_test_cid(3);
    kernel.state.entities.insert(entity_v1_cid, create_test_entity(3, 1, 0, None));
    
    let delta_update_version_same = StateDelta {
        new_entities: Vec::new(),
        updated_entities: vec![create_test_entity(3, 1, event_lclock, None)], // Version not incremented
    };
    match kernel.append_delta(&delta_update_version_same, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("Entity version monotonicity violated"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to version not incremented"),
    }

    let delta_update_version_skip = StateDelta {
        new_entities: Vec::new(),
        updated_entities: vec![create_test_entity(3, 3, event_lclock, None)], // Version incremented by >1
    };
    match kernel.append_delta(&delta_update_version_skip, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("Entity version monotonicity violated"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to version skipped"),
    }

    // 3. Entity lclock Consistency
    let delta_new_entity_wrong_lclock = StateDelta {
        new_entities: vec![create_test_entity(4, 1, event_lclock + 1, None)], // Wrong lclock
        updated_entities: Vec::new(),
    };
    match kernel.append_delta(&delta_new_entity_wrong_lclock, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("Entity lclock must equal event lclock"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to new entity wrong lclock"),
    }
    
    let entity_for_update_cid = generate_test_cid(5);
    kernel.state.entities.insert(entity_for_update_cid, create_test_entity(5,1,0,None));
    let delta_updated_entity_wrong_lclock = StateDelta {
        new_entities: Vec::new(),
        updated_entities: vec![create_test_entity(5, 2, event_lclock + 1, None)], // Wrong lclock
    };
    match kernel.append_delta(&delta_updated_entity_wrong_lclock, event_lclock) {
        Err(KernelError::InvariantViolation(msg)) => 
            assert!(msg.contains("Entity lclock must equal event lclock"), "Wrong invariant msg: {}", msg),
        _ => panic!("Should fail due to updated entity wrong lclock"),
    }

    // 4. Successful Append
    let new_ok_cid = generate_test_cid(6);
    let update_ok_cid = generate_test_cid(7);
    kernel.state.entities.insert(update_ok_cid, create_test_entity(7,1,0,None));
    let delta_ok = StateDelta {
        new_entities: vec![create_test_entity(6, 1, event_lclock, None)],
        updated_entities: vec![create_test_entity(7, 2, event_lclock, None)],
    };
    kernel.append_delta(&delta_ok, event_lclock).expect("Successful append_delta failed");
    assert!(kernel.state.entities.contains_key(&new_ok_cid));
    assert_eq!(kernel.state.entities.get(&update_ok_cid).unwrap().header.version, 2);
}

#[test]
fn test_validate_command() {
    let mut kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let current_lc = kernel.local_lc;

    let cap_id = generate_test_cid(100);
    let holder_pk = [1u8; 32];
    let target_entity_cid = generate_test_cid(1);

    let valid_capability = create_test_capability(cap_id, holder_pk, target_entity_cid, 0, Some(current_lc + 10), AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, valid_capability.clone());

    let payload = MockEncodedCmd::new("valid_cmd", 0);
    let cmd_lclock = current_lc;

    // Case 1: Capability Not Found
    let cmd_no_cap = create_test_command(payload.clone(), cmd_lclock, TEST_REPLICA_ID_1, generate_test_cid(101), 40, None);
    match kernel.validate_command(&cmd_no_cap, current_lc) {
        Err(KernelError::CapabilityNotFound) => {}, // Expected
        _ => panic!("Should fail: CapabilityNotFound"),
    }

    // Case 2: Algorithm Suite Mismatch
    let mut cap_wrong_suite = valid_capability.clone();
    cap_wrong_suite.alg_suite = AlgSuite::FIPS as u8;
    kernel.state.capabilities.insert(cap_wrong_suite.id, cap_wrong_suite.clone()); // Use same ID to overwrite
    let cmd_algo_mismatch = create_test_command(payload.clone(), cmd_lclock, TEST_REPLICA_ID_1, cap_id, 41, None);
    // Command uses CLASSIC by default from helper
    match kernel.validate_command(&cmd_algo_mismatch, current_lc) {
        Err(KernelError::AlgorithmSuiteMismatch) => {},
        res => panic!("Should fail: AlgorithmSuiteMismatch, got {:?}", res),
    }
    kernel.state.capabilities.insert(cap_id, valid_capability.clone()); // Reset to valid capability

    // Case 3: Capability Expired
    let mut cap_expired = valid_capability.clone();
    cap_expired.expiry_lc = Some(current_lc); // expiry_lc is 0 if current_lc is 0
    kernel.state.capabilities.insert(cap_expired.id, cap_expired.clone());
    let cmd_cap_expired = create_test_command(payload.clone(), cmd_lclock, TEST_REPLICA_ID_1, cap_id, 42, None);
    match kernel.validate_command(&cmd_cap_expired, current_lc) {
        Err(KernelError::CapabilityExpired) => {},
        res => panic!("Should fail: CapabilityExpired (expiry == current), got {:?}", res),
    }
    
    // Test for capability expired in the tick before current_lc
    if current_lc > 0 { // Only run this sub-case if current_lc allows subtraction
        let mut cap_expired_just = valid_capability.clone();
        cap_expired_just.expiry_lc = Some(current_lc - 1); 
        kernel.state.capabilities.insert(cap_expired_just.id, cap_expired_just.clone());
        // cmd_cap_expired still uses cap_id which now points to cap_expired_just
        match kernel.validate_command(&cmd_cap_expired, current_lc) {
             Err(KernelError::CapabilityExpired) => {},
             res => panic!("Should fail: CapabilityExpired (expiry < current), got {:?}", res),
        }
    }
    kernel.state.capabilities.insert(cap_id, valid_capability.clone()); // Reset

    // Case 4: Invalid Command lclock (cmd.lclock < current_lc)
    if current_lc > 0 { // Only test if current_lc allows for a smaller cmd_lclock
        let cmd_invalid_lclock = create_test_command(payload.clone(), current_lc - 1, TEST_REPLICA_ID_1, cap_id, 43, None);
        match kernel.validate_command(&cmd_invalid_lclock, current_lc) {
            Err(KernelError::InvalidCommandLClock) => {},
            res => panic!("Should fail: InvalidCommandLClock, got {:?}", res),
        }
    }

    // Case 5: Valid Command
    let cmd_valid = create_test_command(payload.clone(), current_lc, TEST_REPLICA_ID_1, cap_id, 44, None);
    assert!(kernel.validate_command(&cmd_valid, current_lc).is_ok(), "Valid command should pass validation");
    
    let cmd_valid_future_lclock = create_test_command(payload.clone(), current_lc + 5, TEST_REPLICA_ID_1, cap_id, 45, None);
    assert!(kernel.validate_command(&cmd_valid_future_lclock, current_lc).is_ok(), "Valid command with future lclock should pass");
}

#[test]
fn test_apply_full_workflow() {
    let replica_id = TEST_REPLICA_ID_1;
    let cap_id = generate_test_cid(120);
    let entity_to_update_cid = generate_test_cid(121);
    let new_entity_cid = generate_test_cid(122); // This is the ID the mock runtime will assign *in the delta*

    // Setup kernel with initial state
    let mut kernel = Kernel::new(
        replica_id,
        MockRuntimeWithDelta::default(), // Will set specific delta later
        PlaceholderCryptoProvider::default()
    );
    
    let capability = create_test_capability(cap_id, [1u8;32], generate_test_cid(0), 0xFF, Some(kernel.local_lc + 100), AlgSuite::CLASSIC);
    kernel.state.capabilities.insert(cap_id, capability.clone());
    
    let initial_entity_lclock = kernel.local_lc; // or some earlier clock
    let entity_to_update = create_test_entity(121, 1, initial_entity_lclock, None);
    kernel.state.entities.insert(entity_to_update_cid, entity_to_update.clone());

    // Configure mock runtime to produce a delta
    let event_lclock_expected = kernel.local_lc + 1; // Command lclock will be kernel.local_lc
    
    let delta_new_entity_header = EntityHeader {
        id: new_entity_cid, // The CID for the new entity
        version: 1, 
        lclock: event_lclock_expected, // Kernel will set this based on event lclock
        parent: None,
    };
    let delta_new_entity_body = vec![122u8];
    let delta_new_entity = Entity { header: delta_new_entity_header, body: delta_new_entity_body.clone() };

    let delta_updated_entity_header = EntityHeader {
        id: entity_to_update_cid, 
        version: entity_to_update.header.version + 1,
        lclock: event_lclock_expected, // Kernel will set this
        parent: entity_to_update.header.parent,
    };
    let delta_updated_entity_body = vec![121u8, 1u8]; // Updated body
    let delta_updated_entity = Entity { header: delta_updated_entity_header, body: delta_updated_entity_body.clone() };

    let mock_delta = StateDelta {
        new_entities: vec![delta_new_entity],
        updated_entities: vec![delta_updated_entity],
    };
    kernel.runtime = MockRuntimeWithDelta { delta_to_produce: Some(mock_delta.clone()) };

    // Create and apply command
    let cmd_payload = MockEncodedCmd::new("full_workflow_cmd", 0);
    let cmd_lclock = kernel.local_lc; // Command proposes current kernel lclock
    let command = create_test_command(cmd_payload, cmd_lclock, replica_id, cap_id, 50, None);

    let initial_kernel_lc = kernel.local_lc;
    let initial_kernel_vc = kernel.local_vc.clone();

    match kernel.apply(&command) {
        Ok(event) => {
            // Verify Lamport clock update
            assert_eq!(kernel.local_lc, initial_kernel_lc + 1, "Kernel LC should increment");
            assert_eq!(event.lclock, kernel.local_lc, "Event LC should match new kernel LC");

            // Verify Vector clock update
            let mut expected_vc = initial_kernel_vc;
            expected_vc.0.insert(replica_id, kernel.local_lc);
            assert_eq!(kernel.local_vc, expected_vc, "Kernel VC incorrect");
            assert_eq!(event.vclock, expected_vc, "Event VC incorrect");

            // Verify state entities updated
            assert_eq!(kernel.state.entities.len(), 2, "Should be two entities in state");
            
            let new_e = kernel.state.entities.get(&new_entity_cid).expect("New entity not found in state");
            assert_eq!(new_e.header.id, new_entity_cid);
            assert_eq!(new_e.header.version, 1);
            assert_eq!(new_e.header.lclock, event.lclock, "New entity lclock mismatch");
            assert_eq!(new_e.body, vec![122u8]);

            let updated_e = kernel.state.entities.get(&entity_to_update_cid).expect("Updated entity not found");
            assert_eq!(updated_e.header.id, entity_to_update_cid);
            assert_eq!(updated_e.header.version, entity_to_update.header.version + 1);
            assert_eq!(updated_e.header.lclock, event.lclock, "Updated entity lclock mismatch");
            assert_eq!(updated_e.body, vec![121u8, 1u8]);

            // Verify event log
            assert_eq!(kernel.state.event_log.len(), 1, "Event log should have one event");
            assert_eq!(kernel.state.event_log[0].id, event.id, "Logged event ID mismatch");

            // Verify returned event details
            assert_eq!(event.caused_by, command.id);
            assert_eq!(event.new_entities, vec![new_entity_cid]);
            assert_eq!(event.updated_entities, vec![entity_to_update_cid]);
        }
        Err(e) => panic!("Apply full workflow failed: {:?}", e),
    }
}

#[test]
fn test_event_hash_input_deterministic() {
    let kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let cmd_id = generate_test_cid(1);
    let event_lc = 10;
    let alg_suite_tag = AlgSuite::CLASSIC as u8; // Correct: use u8 tag

    let cids1 = [generate_test_cid(2), generate_test_cid(3)];
    let cids2 = [generate_test_cid(3), generate_test_cid(2)]; // Reversed order

    let mut vc_map1 = HashMap::new();
    vc_map1.insert(TEST_REPLICA_ID_1, 10u64);
    vc_map1.insert(TEST_REPLICA_ID_2, 5u64);
    let vclock1 = VClock(vc_map1);

    let mut vc_map2 = HashMap::new();
    vc_map2.insert(TEST_REPLICA_ID_2, 5u64); // Reversed order of insertion
    vc_map2.insert(TEST_REPLICA_ID_1, 10u64);
    let vclock2 = VClock(vc_map2);
    
    let reserved_empty: Vec<u8> = Vec::new(); // Define reserved_empty for this test

    // Test with new_entities varying order
    let input1_new = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids1, &[], &vclock1, &reserved_empty);
    let input2_new = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids2, &[], &vclock1, &reserved_empty);
    assert_eq!(input1_new, input2_new, "Event hash input should be deterministic for new_entities order");

    // Test with updated_entities varying order
    let input1_updated = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &[], &cids1, &vclock1, &reserved_empty);
    let input2_updated = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &[], &cids2, &vclock1, &reserved_empty);
    assert_eq!(input1_updated, input2_updated, "Event hash input should be deterministic for updated_entities order");

    // Test with vector_clock entries varying order (VClock wrapper handles HashMap iteration order internally if sorted for digest)
    // The append_vector_clock_for_digest sorts by ReplicaID, so this should be deterministic.
    let input1_vc = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids1, &cids1, &vclock1, &reserved_empty);
    let input2_vc = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids1, &cids1, &vclock2, &reserved_empty);
    assert_eq!(input1_vc, input2_vc, "Event hash input should be deterministic for vector_clock entry order");
}

#[test]
fn test_event_hash_input_reserved_bytes_deterministic() {
    let kernel = create_test_kernel(TEST_REPLICA_ID_1);
    let cmd_id = generate_test_cid(1);
    let event_lc = 10;
    let alg_suite_tag = AlgSuite::CLASSIC as u8; // Use u8 tag
    let cids = [generate_test_cid(2)];
    let vclock = VClock::default();

    // Test with different Vec<u8> for reserved_bytes.
    let reserved_bytes1: Vec<u8> = vec![1, 2, 3];
    let reserved_bytes2: Vec<u8> = vec![1, 2, 3]; // Same as 1
    let reserved_bytes3: Vec<u8> = vec![4, 5, 6]; // Different from 1
    let reserved_empty: Vec<u8> = Vec::new();


    let input_empty_reserved = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids, &cids, &vclock, &reserved_empty);
    let input_reserved1 = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids, &cids, &vclock, &reserved_bytes1);
    let input_reserved2 = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids, &cids, &vclock, &reserved_bytes2);
    let input_reserved3 = kernel.get_event_hash_input_for_test(&cmd_id, event_lc, &TEST_REPLICA_ID_1, alg_suite_tag, &cids, &cids, &vclock, &reserved_bytes3);

    assert_ne!(input_empty_reserved, input_reserved1, "Input with empty reserved_bytes should differ from non-empty");
    assert_eq!(input_reserved1, input_reserved2, "Input should be deterministic for identical reserved_bytes");
    assert_ne!(input_reserved1, input_reserved3, "Input should differ for different reserved_bytes content");
} 