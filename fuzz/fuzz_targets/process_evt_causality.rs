#![no_main]

// Harness: process_evt_causality – invariant I-03 (causal bounds) & VC merge.
// Sanitizer: ASAN, runtime budget 3s.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use amulet_core::{
    kernel::Kernel,
    events::Event,
    crypto::PlaceholderCryptoProvider,
    types::{AlgSuite, ReplicaID, VectorClock},
};

#[derive(Arbitrary, Debug, Clone)]
struct VCEntry([u8; 16], u64);

#[derive(Arbitrary, Debug, Clone)]
struct EventFrame {
    id: [u8; 32],
    parent: [u8; 32],
    lclock: u64,
    vc_entries: Vec<VCEntry>,
}

fuzz_target!(|frame: EventFrame| {
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto([0u8; 16]);

    // Construct vector clock map
    let vc_map: VectorClock = if frame.vc_entries.is_empty() {
        None
    } else {
        Some(frame.vc_entries.iter().cloned().map(|e| (e.0, e.1)).collect::<HashMap<ReplicaID, u64>>())
    };

    let ev = Event {
        id: frame.id,
        alg_suite: AlgSuite::CLASSIC,
        replica: [0; 16],
        caused_by: frame.parent,
        lclock: frame.lclock,
        new_entities: vec![],
        updated_entities: vec![],
        vector_clock: vc_map,
    };

    let _ = kernel.process_incoming_event(&ev);
}); 