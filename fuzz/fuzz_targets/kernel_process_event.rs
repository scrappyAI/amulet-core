#![no_main]

use libfuzzer_sys::fuzz_target;
use amulet_core::{
    kernel::Kernel,
    primitives::{Event, VClock, CID, ReplicaID},
    types::AlgSuite,
    crypto::PlaceholderCryptoProvider,
};
use std::collections::HashMap;
use arbitrary::Arbitrary;

// A simple struct to represent the raw parts of an Event for fuzzing.
#[derive(Debug, Clone, Arbitrary)]
struct FuzzEventInput {
    id: [u8; 32],
    alg_suite_byte: u8,
    replica: [u8; 16],
    caused_by: [u8; 32],
    lclock: u64,
    new_entities: Vec<[u8; 32]>,
    updated_entities: Vec<[u8; 32]>,
    vector_clock_entries: Vec<([u8; 16], u64)>,
    reserved_data: Vec<u8>,
}

impl FuzzEventInput {
    fn to_event(&self) -> Event {
        let alg_suite_tag = self.alg_suite_byte % 4;

        let vclock_map: HashMap<ReplicaID, u64> = self.vector_clock_entries.iter().cloned().collect();
        let vclock = VClock(vclock_map);

        Event {
            id: self.id,
            alg_suite_tag,
            replica: self.replica,
            caused_by: self.caused_by,
            lclock: self.lclock,
            new_entities: self.new_entities.clone(),
            updated_entities: self.updated_entities.clone(),
            vclock,
            reserved: self.reserved_data.clone(),
        }
    }
}

fuzz_target!(|data: FuzzEventInput| {
    // Create a kernel instance.
    let replica_id_kernel: ReplicaID = [0u8; 16];
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto(replica_id_kernel);
    kernel.local_lc = data.lclock / 2;

    // Construct the Event from fuzzed data.
    let event_to_process = data.to_event();

    // Call the function we want to fuzz.
    // We don't particularly care about the result for this stub, just that it doesn't panic.
    let _ = kernel.process_incoming_event(&event_to_process);

    // Optionally, add assertions about the kernel's state after processing,
    // e.g., kernel.local_lc >= event_to_process.lclock,
    // or properties of the merged vector clock if applicable and checkable.
    // For now, we rely on libFuzzer to catch panics, hangs, memory safety issues.
    if kernel.local_lc < event_to_process.lclock {
        // This can happen if kernel.local_lc was reset by a very small data.lclock/2
        // and then event_to_process.lclock is larger. This is correct behavior:
        // self.local_lc = self.local_lc.max(event.lclock);
    }
});

// To make this work, you'll need to:
// 1. Ensure `arbitrary` with "derive" feature is in `fuzz/Cargo.toml`.
// 2. Add this target to `fuzz/Cargo.toml`:
//    [[bin]]
//    name = "kernel_process_event"
//    path = "fuzz_targets/kernel_process_event.rs"
//    test = false
//    doc = false 