use proptest::prelude::*;
use amulet_core::{
    kernel::Kernel,
    domain::{Command, EncodedCmd},
    access::Capability,
    types::{AlgSuite, CID, ReplicaID, Signature, RightsMask, PublicKey},
    crypto::PlaceholderCryptoProvider,
    error::KernelError,
};

// --- Helper: Dummy Command Payload ---
#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyCmdPayload(RightsMask);

#[derive(Debug)]
struct DummyCmdError(String);
impl std::fmt::Display for DummyCmdError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) } }
impl std::error::Error for DummyCmdError {}

impl EncodedCmd for DummyCmdPayload {
    type Error = DummyCmdError;
    fn encode(&self) -> Vec<u8> { self.0.to_le_bytes().to_vec() }
    fn decode(data: &[u8]) -> Result<Self, Self::Error> { 
        if data.len() < 4 {
            return Err(DummyCmdError("Data too short to decode RightsMask".to_string()));
        }
        Ok(Self(u32::from_le_bytes(data[0..4].try_into().unwrap())))
    }
    fn required_rights(&self) -> RightsMask {
        self.0
    }
    fn to_signed_bytes(&self, id: &CID, alg: AlgSuite, rep: &ReplicaID, cap: &CID, lck: u64) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(id);
        bytes.push(alg as u8);
        bytes.extend_from_slice(rep);
        bytes.extend_from_slice(cap);
        bytes.extend_from_slice(&lck.to_le_bytes());
        bytes.extend_from_slice(&self.0.to_le_bytes());
        Ok(bytes)
    }
}
// --- End Helper ---

fn create_test_kernel() -> Kernel<PlaceholderCryptoProvider> {
    let replica_id: ReplicaID = [0u8; 16];
    Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto(replica_id, false)
}

fn create_dummy_capability(id: CID, alg_suite: AlgSuite, rights: RightsMask, expiry_lc: Option<u64>) -> Capability {
    Capability {
        id,
        alg_suite,
        holder: PublicKey::new(),
        target_entity: [1u8; 32],
        rights,
        nonce: 0,
        expiry_lc,
        signature: Signature::new(),
    }
}

fn create_dummy_command(payload: DummyCmdPayload, capability_cid: CID, alg_suite: AlgSuite, lclock: u64) -> Command<DummyCmdPayload> {
    Command {
        id: [2u8; 32],
        alg_suite,
        replica: [3u8; 16],
        capability: capability_cid,
        lclock,
        payload,
        signature: Signature::new(),
    }
}

fn different_alg_suite(alg: AlgSuite) -> AlgSuite {
    match alg {
        AlgSuite::CLASSIC => AlgSuite::FIPS,
        AlgSuite::FIPS => AlgSuite::PQC,
        AlgSuite::PQC => AlgSuite::HYBRID,
        AlgSuite::HYBRID => AlgSuite::CLASSIC,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Test capability expiry: command should be invalid if capability.expiry_lc <= kernel.local_lc
    #[test]
    fn prop_validate_command_capability_expiry(
        kernel_lc in 0u64..u64::MAX-1, // Kernel's current time
        cap_expiry_offset in -5i64..5 // Offset for capability expiry from kernel_lc
    ) {
        let mut kernel = create_test_kernel();
        kernel.local_lc = kernel_lc;

        let cap_cid: CID = [10u8; 32];
        let cap_expiry_lc = if cap_expiry_offset < 0 {
            kernel_lc.saturating_sub(cap_expiry_offset.abs() as u64)
        } else {
            kernel_lc.saturating_add(cap_expiry_offset.abs() as u64)
        };
        
        let capability = create_dummy_capability(cap_cid, AlgSuite::CLASSIC, u32::MAX, Some(cap_expiry_lc));
        kernel.state.capabilities.insert(cap_cid, capability.clone());

        let cmd_lclock = kernel_lc; // Command lclock can be same as kernel_lc for this test
        let cmd = create_dummy_command(DummyCmdPayload(0), cap_cid, AlgSuite::CLASSIC, cmd_lclock);

        let validation_result = kernel.validate_command(&cmd, kernel.local_lc);

        if let Some(expiry) = capability.expiry_lc {
            if kernel.local_lc >= expiry {
                prop_assert!(matches!(validation_result, Err(KernelError::CapabilityExpired)),
                    "Expected CapabilityExpired for kernel_lc: {}, cap_expiry_lc: {}", kernel_lc, expiry);
            } else {
                // Might still fail for other reasons (like invalid lclock if cmd_lclock < kernel_lc),
                // but should not be CapabilityExpired.
                // If it passes, great. If it fails for *another* reason, that's a different test's concern.
                match validation_result {
                    Err(KernelError::CapabilityExpired) => {
                        prop_assert!(false, "Unexpected CapabilityExpired for kernel_lc: {}, cap_expiry_lc: {}", kernel_lc, expiry);
                    }
                    _ => {}
                }
            }
        } else {
            // No expiry, should not fail with CapabilityExpired
             match validation_result {
                Err(KernelError::CapabilityExpired) => {
                    prop_assert!(false, "Unexpected CapabilityExpired when no expiry set");
                }
                _ => {}
            }
        }
    }

    /// Test command lclock: command should be invalid if command.lclock < kernel.local_lc
    #[test]
    fn prop_validate_command_lclock(
        kernel_lc in 0u64..u64::MAX / 2, // Avoid overflow when adding offset
        cmd_lclock_offset in -5i64..5
    ) {
        let mut kernel = create_test_kernel();
        kernel.local_lc = kernel_lc;

        let cap_cid: CID = [11u8; 32];
        let capability = create_dummy_capability(cap_cid, AlgSuite::CLASSIC, u32::MAX, None); // No expiry for this test
        kernel.state.capabilities.insert(cap_cid, capability);
        
        let cmd_lclock = if cmd_lclock_offset < 0 {
            kernel_lc.saturating_sub(cmd_lclock_offset.abs() as u64)
        } else {
            kernel_lc.saturating_add(cmd_lclock_offset.abs() as u64)
        };

        let cmd = create_dummy_command(DummyCmdPayload(0), cap_cid, AlgSuite::CLASSIC, cmd_lclock);
        let validation_result = kernel.validate_command(&cmd, kernel.local_lc);

        if cmd.lclock < kernel.local_lc {
            prop_assert!(matches!(validation_result, Err(KernelError::InvalidCommandLClock)),
                "Expected InvalidCommandLClock for kernel_lc: {}, cmd_lclock: {}", kernel_lc, cmd_lclock);
        } else {
            match validation_result {
                Err(KernelError::InvalidCommandLClock) => {
                    prop_assert!(false, "Unexpected InvalidCommandLClock for kernel_lc: {}, cmd_lclock: {}", kernel_lc, cmd_lclock);
                }
                _ => {} // Ok if it passes or fails for other reasons
            }
        }
    }

    /// Test AlgSuite mismatch: command should be invalid if cmd.alg_suite != capability.alg_suite
    #[test]
    fn prop_validate_command_alg_suite_mismatch(
        cap_alg_suite_u8 in 0u8..4, // To generate AlgSuite from u8
        cmd_should_match_cap_alg_suite in prop::bool::ANY
    ) {
        let mut kernel = create_test_kernel();
        let cap_cid: CID = [12u8; 32];

        // Convert u8 to AlgSuite, defaulting to CLASSIC if out of range.
        // This ensures we cover all AlgSuite variants.
        let cap_alg_suite = match cap_alg_suite_u8 {
            0 => AlgSuite::CLASSIC,
            1 => AlgSuite::FIPS,
            2 => AlgSuite::PQC,
            3 => AlgSuite::HYBRID,
            _ => AlgSuite::CLASSIC, // Should not happen with 0..4 range
        };
        
        let capability = create_dummy_capability(cap_cid, cap_alg_suite, u32::MAX, None);
        kernel.state.capabilities.insert(cap_cid, capability.clone());

        let cmd_alg_suite = if cmd_should_match_cap_alg_suite {
            cap_alg_suite
        } else {
            different_alg_suite(cap_alg_suite)
        };
        
        let cmd = create_dummy_command(DummyCmdPayload(0), cap_cid, cmd_alg_suite, kernel.local_lc);
        let validation_result = kernel.validate_command(&cmd, kernel.local_lc);

        if cmd_alg_suite != cap_alg_suite {
            prop_assert!(matches!(validation_result, Err(KernelError::AlgorithmSuiteMismatch)),
                "Expected AlgorithmSuiteMismatch for cap_suite: {:?}, cmd_suite: {:?}", cap_alg_suite, cmd_alg_suite);
        } else {
            match validation_result {
                Err(KernelError::AlgorithmSuiteMismatch) => {
                    prop_assert!(false, "Unexpected AlgorithmSuiteMismatch for cap_suite: {:?}, cmd_suite: {:?}", cap_alg_suite, cmd_alg_suite);
                }
                _ => {} // Ok if it passes or fails for other reasons
            }
        }
    }

    /// Test insufficient rights: command should be invalid if capability.rights are not sufficient for cmd.payload.required_rights
    #[test]
    fn prop_validate_command_insufficient_rights(
        capability_rights in any::<RightsMask>(),
        required_rights_val in 0u8..=31 // Representing a single bit for required rights, or 0 for no rights
                                        // Or a small arbitrary u8 for simplicity. Payload uses first byte for rights.
    ) {
        let mut kernel = create_test_kernel();
        let cap_cid: CID = [13u8; 32];

        let capability = create_dummy_capability(cap_cid, AlgSuite::CLASSIC, capability_rights, None);
        kernel.state.capabilities.insert(cap_cid, capability.clone());

        // Use the required_rights_val to form the first byte of the payload,
        // which DummyCmdPayload uses to determine required_rights().
        // We'll test cases where one specific right is required.
        let required_rights_mask = if required_rights_val == 0 { 0 } else { 1u32 << (required_rights_val -1) };
        let cmd_payload = DummyCmdPayload(required_rights_mask);

        let cmd = create_dummy_command(cmd_payload, cap_cid, AlgSuite::CLASSIC, kernel.local_lc);
        let validation_result = kernel.validate_command(&cmd, kernel.local_lc);
        
        // Using amulet_core::rights::sufficient to check the condition
        let expected_sufficient = amulet_core::rights::sufficient(capability_rights, required_rights_mask);

        if !expected_sufficient {
            prop_assert!(matches!(validation_result, Err(KernelError::InsufficientRights)),
                "Expected InsufficientRights for cap_rights: {:#b}, req_rights: {:#b}", capability_rights, required_rights_mask);
        } else {
             match validation_result {
                Err(KernelError::InsufficientRights) => {
                    prop_assert!(false, "Unexpected InsufficientRights for cap_rights: {:#b}, req_rights: {:#b}", capability_rights, required_rights_mask);
                }
                _ => {} // Ok if it passes or fails for other reasons
            }
        }
    }

    /// Test CapabilityNotFound: command should be invalid if cmd.capability CID is not in kernel.state.capabilities
    #[test]
    fn prop_validate_command_capability_not_found(
        // Generate a CID for the command to reference. This CID will *not* be added to the kernel state.
        missing_cap_cid in prop::array::uniform32(prop::num::u8::ANY),
        cmd_lclock_offset in -5i64..5 // To vary command lclock relative to kernel lclock
    ) {
        let mut kernel = create_test_kernel();
        // Ensure kernel.local_lc is not 0 to make cmd_lclock calculation more robust
        kernel.local_lc = 10;

        // NO capability is added to kernel.state.capabilities for missing_cap_cid

        let cmd_lclock = if cmd_lclock_offset < 0 {
            kernel.local_lc.saturating_sub(cmd_lclock_offset.abs() as u64)
        } else {
            kernel.local_lc.saturating_add(cmd_lclock_offset.abs() as u64)
        };
        // Ensure cmd_lclock is at least kernel.local_lc to isolate CapabilityNotFound error
        let valid_cmd_lclock = cmd_lclock.max(kernel.local_lc);

        let cmd = create_dummy_command(DummyCmdPayload(0), missing_cap_cid, AlgSuite::CLASSIC, valid_cmd_lclock);
        let validation_result = kernel.validate_command(&cmd, kernel.local_lc);

        prop_assert!(matches!(validation_result, Err(KernelError::CapabilityNotFound)),
            "Expected CapabilityNotFound for CID: {:?}, validation_result: {:?}", missing_cap_cid, validation_result);
    }
} 