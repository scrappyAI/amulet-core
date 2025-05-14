#![no_main]

// Harness: kernel_apply_sig
// Invariant I-06 – Hybrid signature rule length ↔ suite ↔ dual-verify.
// Payload focuses on combination of alg_suite and signature length.
// Sanitizer: ASAN, runtime budget 1s (CI enforced).

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use amulet_core::{
    kernel::Kernel,
    domain::Command,
    access::Capability,
    crypto::PlaceholderCryptoProvider,
    types::{AlgSuite, CID, ReplicaID},
};

#[derive(Arbitrary, Debug, Clone)]
struct SigFrame {
    id: [u8; 32],
    suite_choice: u8,      // maps to AlgSuite variant
    sig_bytes: Vec<u8>,    // variable length signature
}

fn suite_from_byte(b: u8) -> AlgSuite {
    match b % 4 {
        0 => AlgSuite::CLASSIC,
        1 => AlgSuite::FIPS,
        2 => AlgSuite::PQC,
        _ => AlgSuite::HYBRID,
    }
}

fuzz_target!(|frame: SigFrame| {
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto([0u8; 16]);

    // Provide capability
    let cap_cid: CID = [0xBB; 32];
    let dummy_cap = Capability {
        id: cap_cid,
        alg_suite: suite_from_byte(frame.suite_choice),
        holder: vec![],
        target_entity: [0u8; 32],
        rights: u32::MAX,
        nonce: 0,
        expiry_lc: None,
        signature: vec![],
    };
    kernel.state.capabilities.insert(cap_cid, dummy_cap);

    let command = Command {
        id: frame.id,
        alg_suite: suite_from_byte(frame.suite_choice),
        replica: [0u8; 16],
        capability: cap_cid,
        lclock: 1, // keep low to isolate signature paths
        payload: vec![],
        signature: frame.sig_bytes.clone(),
    };

    let _ = kernel.apply(&command);
}); 