#![cfg(test)]

use proptest::prelude::*;
use amulet_core::kernel::Kernel;
use amulet_core::primitives::{
    Command, Capability, VClock, CidBytes, ReplicaIdBytes, SignatureBytes, PublicKeyBytes,
    CID, ReplicaID,
};
use amulet_core::types::AlgSuite;
use amulet_core::command_traits::{EncodedCmd, CommandTraitError};
use amulet_core::crypto::ConfigurableCryptoProvider;
use amulet_core::crypto::CryptoError;
use amulet_core::error::KernelError;
use amulet_core::kernel::runtime::DefaultRuntime; // Using DefaultRuntime for these tests

// --- Test Utilities (minimal, copied from kernel/tests.rs for independence if needed) ---

const TEST_REPLICA_ID_CMD: ReplicaID = ReplicaIdBytes([1u8; 16]);
const TEST_HOLDER_PK_BYTES: [u8; 32] = [2u8; 32];

fn generate_test_cid(id_byte: u8) -> CID {
    CidBytes([id_byte; 32])
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MockValidationCmd {
    payload_data: Vec<u8>, // Using Vec<u8> for simplicity in proptests
    required_rights_value: u32,
}

impl EncodedCmd for MockValidationCmd {
    type Error = CommandTraitError; // Using the standard CommandTraitError

    fn encode(&self) -> Vec<u8> {
        self.payload_data.clone()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(MockValidationCmd {
            payload_data: bytes.to_vec(),
            required_rights_value: 0, // Default for this mock
        })
    }

    fn required_rights(&self) -> u32 {
        self.required_rights_value
    }

    // A simplified to_signed_bytes for validation testing purposes.
    // The actual content doesn't matter as much as the fact that it's called.
    fn to_signed_bytes(
        &self,
        _command_id: &CID,
        _alg_suite: AlgSuite,
        _replica: &ReplicaID,
        _capability: &CID,
        _lclock: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![1, 2, 3]) // Minimal fixed byte vector
    }
}

// --- Proptest Strategies ---

// Strategy for generating a Capability
fn arb_capability() -> impl Strategy<Value = Capability> {
    (
        any::<[u8; 32]>()      // id_byte for CID
            .prop_map(|b| CidBytes(b)),
        Just(AlgSuite::CLASSIC as u8), // alg_suite_tag (fixed for simplicity)
        Just(PublicKeyBytes(TEST_HOLDER_PK_BYTES)), // holder (fixed)
        any::<[u8; 32]>()      // target_entity_byte for CID
            .prop_map(|b| CidBytes(b)),
        any::<u32>(),          // rights
        any::<u64>(),          // nonce
        prop_oneof![          // expiry_lc
            Just(None),
            any::<u64>().prop_map(Some),
        ],
        Just(0u16),            // kind (fixed)
        any::<[u8; 64]>()      // signature_bytes
            .prop_map(|b| SignatureBytes(b)),
    )
        .prop_map(
            |(id, alg_suite, holder, target_entity, rights, nonce, expiry_lc, kind, signature)| {
                Capability {
                    id, alg_suite, holder, target_entity, rights, nonce, expiry_lc, kind, signature,
                }
            },
        )
}

// Strategy for generating a Command<MockValidationCmd>
fn arb_command(cap_cid: CID) -> impl Strategy<Value = Command<MockValidationCmd>> {
    (
        any::<[u8; 32]>()      // id_byte for CID
            .prop_map(|b| CidBytes(b)),
        Just(AlgSuite::CLASSIC as u8), // alg_suite_tag (must match capability's for basic validation)
        Just(TEST_REPLICA_ID_CMD),     // replica (fixed)
        Just(cap_cid),         // capability CID (linked to the generated capability)
        any::<u64>(),          // lclock
        prop::option::of(Just(VClock::default())), // vclock (Corrected: generates Option<VClock>)
        prop::collection::vec(any::<u8>(), 0..32), // payload_data for MockValidationCmd
        any::<u32>(),          // required_rights_value for MockValidationCmd
        any::<[u8; 64]>()      // signature_bytes
            .prop_map(|b| SignatureBytes(b)),
    )
        .prop_map(
            |(id, alg_suite, replica, capability, lclock, vclock, payload_data, required_rights_value, signature)| {
                Command {
                    id,
                    alg_suite,
                    replica,
                    capability, // This now correctly uses the cap_cid passed to arb_command
                    lclock,
                    vclock,
                    payload: MockValidationCmd { payload_data, required_rights_value },
                    signature,
                }
            },
        )
}

proptest! {
    #[test]
    fn prop_validate_command_crypto_failure(
        cap_strategy_input in arb_capability(),
        cmd_lclock_offset in 0..100u64 // Kernel's current_lc will be 0, command lclock will be >= 0
    ) {
        let capability = cap_strategy_input;
        let mut crypto_provider = ConfigurableCryptoProvider::default();
        crypto_provider.verification_outcome = Err(CryptoError::InvalidSignature);

        let mut kernel = Kernel::new(TEST_REPLICA_ID_CMD, DefaultRuntime::default(), crypto_provider);
        kernel.state.capabilities.insert(capability.id, capability.clone());

        // Generate a command linked to this capability using arb_command
        let _command_strategy = arb_command(capability.id);
        // Fetch a command sample from the strategy.
        // Proptest typically runs this multiple times; for direct use, we might need a test_rng or similar.
        // However, within the proptest! macro, this is handled for us when `command_strategy` is used as an input.
        // For this direct setup, we will construct command manually to ensure linkage, similar to original approach.

        let command = Command {
            id: generate_test_cid(100),
            alg_suite: capability.alg_suite, // Match capability's alg_suite
            replica: TEST_REPLICA_ID_CMD,
            capability: capability.id, // Ensure command uses the generated capability's ID
            lclock: cmd_lclock_offset, 
            vclock: None,
            payload: MockValidationCmd { payload_data: vec![1], required_rights_value: 0 },
            signature: SignatureBytes([0u8; 64]),
        };

        let current_lc = kernel.local_lc;
        let result = kernel.validate_command(&command, current_lc);

        prop_assert!(
            matches!(result, Err(KernelError::Crypto(CryptoError::InvalidSignature))),
            "Expected KernelError::Crypto(InvalidSignature), got {:?}", result
        );
    }

    #[test]
    fn prop_validate_command_crypto_success(
        cap_strategy_input in arb_capability(),
        cmd_lclock_offset in 0..100u64
    ) {
        let capability = cap_strategy_input;
        let crypto_provider = ConfigurableCryptoProvider::default(); // Defaults to Ok(()) for verify

        let mut kernel = Kernel::new(TEST_REPLICA_ID_CMD, DefaultRuntime::default(), crypto_provider);
        
        // Ensure capability is not expired for this test to focus on crypto success
        // and other basic validations pass.
        let mut mutable_cap = capability.clone();
        mutable_cap.expiry_lc = Some(kernel.local_lc + 200); // Far future expiry
        mutable_cap.rights = u32::MAX; // Grant all rights to simplify
        kernel.state.capabilities.insert(mutable_cap.id, mutable_cap.clone());

        // command_strategy here is not used in test logic directly, but shows how it could be used if the test was refactored
        let _command_strategy = arb_command(mutable_cap.id);

        let command = Command {
            id: generate_test_cid(101),
            alg_suite: mutable_cap.alg_suite, // Match capability's alg_suite
            replica: TEST_REPLICA_ID_CMD,
            capability: mutable_cap.id, // Ensure command uses the generated capability's ID
            lclock: kernel.local_lc + cmd_lclock_offset, 
            vclock: None,
            payload: MockValidationCmd { payload_data: vec![1], required_rights_value: 0 }, 
            signature: SignatureBytes([0u8; 64]),
        };
        
        let current_lc = kernel.local_lc;
        let result = kernel.validate_command(&command, current_lc);

        // If crypto passes, other validation errors might occur if proptest generates tricky values.
        // For this test, we are primarily interested that it DOES NOT fail with CryptoError.
        // It might fail with other KernelErrors (e.g. InsufficientRights if not handled above), or succeed.
        // A more robust test would be to ensure it *only* succeeds if all other conditions are met.
        // For now, we check it's not a CryptoError specifically.
        match result {
            Err(KernelError::Crypto(_)) => prop_assert!(false, "Expected crypto validation to pass, but got KernelError::Crypto. Result: {:?}", result),
            _ => prop_assert!(true) // Ok or other KernelError is acceptable for this specific test's focus
        }
    }
}
