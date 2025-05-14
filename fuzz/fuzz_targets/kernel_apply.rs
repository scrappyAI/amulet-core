#![no_main]

use libfuzzer_sys::fuzz_target;
use amulet_core::kernel::Kernel;
use amulet_core::domain::{Command, EncodedCmd};
use amulet_core::crypto::PlaceholderCryptoProvider; // Using placeholder for now
use amulet_core::types::{AlgSuite, CID, ReplicaID, Signature};
use amulet_core::access::Capability;

// A simple struct to represent the raw parts of a command for fuzzing.
// libfuzzer-sys works well with arbitrary byte slices, so we need a way
// to structure those bytes into something meaningful for our Command.
#[derive(Debug, Clone, arbitrary::Arbitrary)] // Using arbitrary crate for structured fuzzing
struct FuzzCommandInput {
    id: [u8; 32],
    // alg_suite: u8, // To derive AlgSuite, requires careful handling of valid enum values
    replica: [u8; 16],
    capability_cid: [u8; 32],
    lclock: u64,
    payload_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    // We'll fix alg_suite to CLASSIC for simplicity in this stub.
}

fuzz_target!(|data: FuzzCommandInput| {
    // Create a kernel instance (it's cheap).
    let replica_id_kernel: ReplicaID = [0u8; 16];
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto(replica_id_kernel);

    // For the command to be somewhat valid, the capability it refers to should exist.
    // We'll insert a dummy one.
    let dummy_cap_cid: CID = data.capability_cid;
    let dummy_cap = Capability {
        id: dummy_cap_cid,
        alg_suite: AlgSuite::CLASSIC, // Match command
        holder: vec![],
        target_entity: [0u8; 32],
        rights: u32::MAX, // Grant all rights for this dummy cap for fuzzing apply logic
        nonce: 0,
        expiry_lc: None,
        signature: vec![],
    };
    kernel.state.capabilities.insert(dummy_cap_cid, dummy_cap);
    
    // Construct the Command from fuzzed data.
    // AlgSuite is hardcoded to CLASSIC to avoid complexities of fuzzing enum variants directly
    // from raw bytes without more sophisticated Arbitrary impls.
    let command_to_fuzz = Command {
        id: data.id,
        alg_suite: AlgSuite::CLASSIC, 
        replica: data.replica,
        capability: data.capability_cid,
        lclock: data.lclock,
        payload: data.payload_bytes, // Vec<u8> implements EncodedCmd
        signature: data.signature_bytes,
    };

    // Call the function we want to fuzz.
    // We don't particularly care about the result for this stub, just that it doesn't panic
    // in unexpected ways (libFuzzer will catch panics, hangs, memory safety issues).
    let _ = kernel.apply(&command_to_fuzz);
});

// To make this work, you'll need to add `libfuzzer-sys` and `arbitrary`
// to the Cargo.toml in the `fuzz` directory created by `cargo fuzz init`:
//
// ```toml
// # In fuzz/Cargo.toml
// [dependencies]
// libfuzzer-sys = "0.4"
// arbitrary = { version = "1", features = ["derive"] }
// amulet-core = { path = ".." }
// ``` 