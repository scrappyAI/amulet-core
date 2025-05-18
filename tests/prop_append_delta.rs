use proptest::prelude::*;
use amulet_core::{
    kernel::{Kernel, StateDelta},
    types::CID,
    domain::{Entity, EntityHeader},
    crypto::PlaceholderCryptoProvider,
    error::KernelError,
};

// Helper to create a default kernel instance for tests
fn create_test_kernel() -> Kernel<PlaceholderCryptoProvider> {
    Kernel::new_with_default_crypto([0u8; 16], false) // Vector clocks disabled
}

// Helper to create a dummy entity with a specific CID, version, and lclock
fn create_dummy_entity(id: CID, version: u64, lclock: u64) -> Entity<Vec<u8>> {
    Entity {
        header: EntityHeader {
            id,
            version,
            lclock,
            parent: None,
        },
        body: vec![0u8;10], // Dummy body
    }
}

// Arbitrary strategies for proptest
fn arb_cid() -> impl Strategy<Value = CID> {
    prop::array::uniform32(any::<u8>())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Test Invariant: New entity CIDs must not already exist in state.
    /// append_delta should fail if a new_entity.header.id is already in kernel.state.entities.
    #[test]
    fn prop_append_delta_new_entity_cid_already_exists(
        existing_cid in arb_cid(),
        existing_version in 0u64..u64::MAX-1, // Avoid overflow issues for versioning
        lclock_new in any::<u64>()
    ) {
        let mut kernel = create_test_kernel();

        // Pre-populate state with an entity
        let existing_entity = create_dummy_entity(existing_cid, existing_version, lclock_new -1); // ensure different lclock if needed
        kernel.state.entities.insert(existing_cid, existing_entity.clone());

        // Delta tries to add an entity with the *same* CID as the existing one
        let conflicting_new_entity = create_dummy_entity(existing_cid, 0, lclock_new); // version 0, correct lclock_new

        let delta = StateDelta {
            new_entities: vec![conflicting_new_entity],
            updated_entities: Vec::new(),
        };

        let result = kernel.append_delta(&delta, lclock_new);

        prop_assert!(matches!(result, Err(KernelError::InvariantViolation(_))),
            "Expected InvariantViolation due to duplicate new entity CID. Got: {:?}", result);
        
        // Also ensure state wasn't mutated
        prop_assert_eq!(kernel.state.entities.len(), 1, "State should not have been mutated on error");
        prop_assert_eq!(kernel.state.entities.get(&existing_cid), Some(&existing_entity), "Existing entity should be unchanged");
    }

    /// Test Invariant: Updated entities must already exist in state.
    /// append_delta should fail if an updated_entity.header.id is not found.
    #[test]
    fn prop_append_delta_updated_entity_not_found(
        missing_cid in arb_cid(),
        update_version in 1u64.., // Updated version should be > 0
        lclock_new in any::<u64>()
    ) {
        let mut kernel = create_test_kernel();
        // kernel.state.entities is initially empty

        let entity_to_update = create_dummy_entity(missing_cid, update_version, lclock_new);

        let delta = StateDelta {
            new_entities: Vec::new(),
            updated_entities: vec![entity_to_update],
        };

        let result = kernel.append_delta(&delta, lclock_new);
        prop_assert!(matches!(result, Err(KernelError::InvariantViolation(_))),
            "Expected InvariantViolation due to updated entity not found. Got: {:?}", result);
        
        prop_assert!(kernel.state.entities.is_empty(), "State should not have been mutated on error");
    }

    /// Test Invariant: Updated entity version must be prev_version + 1.
    #[test]
    fn prop_append_delta_updated_entity_version_monotonicity(
        existing_cid in arb_cid(),
        initial_version in 0u64..u64::MAX-2, // ensure space for +1 and +offset
        version_offset in -5i64..=5, // Test around the correct version
        lclock_new in any::<u64>()
    ) {
        let mut kernel = create_test_kernel();

        let initial_entity = create_dummy_entity(existing_cid, initial_version, lclock_new -1); // lclock can be different
        kernel.state.entities.insert(existing_cid, initial_entity.clone());

        let attempted_update_version = if version_offset < 0 {
            initial_version.saturating_add(1).saturating_sub(version_offset.abs() as u64)
        } else {
            initial_version.saturating_add(1).saturating_add(version_offset.abs() as u64)
        };
        
        // Ensure we don't accidentally make it correct if offset is 0 but we wanted to test bad cases
        // Or if saturating_sub made it initial_version + 1 accidentally
        let final_update_version = if version_offset != 0 && attempted_update_version == initial_version + 1 {
            attempted_update_version + 1 // make it definitely wrong if offset was non-zero but math landed on correct
        } else if version_offset == 0 {
             initial_version + 1 // for the correct case
        } else {
            attempted_update_version
        };


        let entity_to_update = create_dummy_entity(existing_cid, final_update_version, lclock_new);
        let delta = StateDelta {
            new_entities: Vec::new(),
            updated_entities: vec![entity_to_update.clone()],
        };
        
        let result = kernel.append_delta(&delta, lclock_new);

        if final_update_version == initial_version + 1 {
            prop_assert!(result.is_ok(),
                "Expected Ok for correct version update. Got: {:?}, (initial_v: {}, update_v: {})", result, initial_version, final_update_version);
            // Check state updated
            prop_assert_eq!(kernel.state.entities.get(&existing_cid).map(|e| e.header.version), Some(final_update_version));
        } else {
            prop_assert!(matches!(result, Err(KernelError::InvariantViolation(_))),
                "Expected InvariantViolation for incorrect version. Got: {:?}, (initial_v: {}, update_v: {})", result, initial_version, final_update_version);
            // Check state not mutated from original
             prop_assert_eq!(kernel.state.entities.get(&existing_cid).map(|e| e.header.version), Some(initial_version));
        }
    }

    /// Test Invariant: All entities in delta must have lclock == lclock_new.
    #[test]
    fn prop_append_delta_entity_lclock_mismatch(
        cid1 in arb_cid(),
        cid2 in arb_cid(),
        lclock_new in 1u64.., // Ensure lclock_new is not 0
        new_entity_lclock_matches in any::<bool>(),
        updated_entity_lclock_matches in any::<bool>(),
        initial_updated_entity_version in 0u64..u64::MAX-1
    ) {
        // Ensure cids are different for independent new/updated entities
        prop_assume!(cid1 != cid2);

        let mut kernel = create_test_kernel();

        // Setup an existing entity to be updated
        let existing_entity_to_update = create_dummy_entity(cid2, initial_updated_entity_version, lclock_new -1 );
        kernel.state.entities.insert(cid2, existing_entity_to_update.clone());
        
        let new_entity_lclock = if new_entity_lclock_matches { lclock_new } else { lclock_new.wrapping_add(1) };
        let updated_entity_lclock = if updated_entity_lclock_matches { lclock_new } else { lclock_new.wrapping_sub(1) };

        let new_e = create_dummy_entity(cid1, 0, new_entity_lclock);
        let upd_e = create_dummy_entity(cid2, initial_updated_entity_version + 1, updated_entity_lclock);

        let delta = StateDelta {
            new_entities: vec![new_e.clone()],
            updated_entities: vec![upd_e.clone()],
        };

        let result = kernel.append_delta(&delta, lclock_new);

        if new_entity_lclock_matches && updated_entity_lclock_matches {
            prop_assert!(result.is_ok(), "Expected Ok when all lclocks match. New LClock: {}, Updated LClock: {}, lclock_new: {}. Got: {:?}",
                new_e.header.lclock, upd_e.header.lclock, lclock_new, result);
            prop_assert_eq!(kernel.state.entities.get(&cid1).map(|e| &e.header), Some(&new_e.header));
            prop_assert_eq!(kernel.state.entities.get(&cid2).map(|e| &e.header), Some(&upd_e.header));
        } else {
            prop_assert!(matches!(result, Err(KernelError::InvariantViolation(_))),
                "Expected InvariantViolation due to lclock mismatch. New LClock: {}, Updated LClock: {}, lclock_new: {}. Got: {:?}",
                new_e.header.lclock, upd_e.header.lclock, lclock_new, result);
            // Check state not mutated beyond initial setup
            prop_assert!(kernel.state.entities.get(&cid1).is_none());
            prop_assert_eq!(kernel.state.entities.get(&cid2).map(|e| &e.header), Some(&existing_entity_to_update.header));
        }
    }

    // Test Success Case: Valid delta is applied correctly.
    #[test]
    fn prop_append_delta_success_case(
        new_cid in arb_cid(),
        existing_cid in arb_cid(),
        initial_version in 0u64..u64::MAX-1,
        lclock_new in any::<u64>()
    ) {
        prop_assume!(new_cid != existing_cid); // Ensure CIDs are distinct

        let mut kernel = create_test_kernel();

        // Pre-populate state with an entity to be updated
        let initial_existing_entity = create_dummy_entity(existing_cid, initial_version, lclock_new -1 ); // lclock can be anything before
        kernel.state.entities.insert(existing_cid, initial_existing_entity.clone());

        // New entity for the delta
        let new_entity = create_dummy_entity(new_cid, 0, lclock_new); // Version 0, correct lclock

        // Updated entity for the delta
        let updated_entity = create_dummy_entity(existing_cid, initial_version + 1, lclock_new); // Correct version increment, correct lclock

        let delta = StateDelta {
            new_entities: vec![new_entity.clone()],
            updated_entities: vec![updated_entity.clone()],
        };

        let result = kernel.append_delta(&delta, lclock_new);
        prop_assert!(result.is_ok(), "Expected Ok for a valid delta. Got: {:?}", result);

        // Verify state
        prop_assert_eq!(kernel.state.entities.len(), 2, "Expected two entities in state after successful append");
        prop_assert_eq!(kernel.state.entities.get(&new_cid), Some(&new_entity), "New entity not found or incorrect after append");
        prop_assert_eq!(kernel.state.entities.get(&existing_cid), Some(&updated_entity), "Updated entity not found or incorrect after append");
    }
} 