#![no_main]

// Harness: kernel_apply_entities – invariant I-10 (CID duplication) & entity delta logic.
// Sanitizer: ASAN, runtime budget 2s.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use amulet_core::{
    kernel::Kernel,
    domain::Command,
    access::Capability,
    crypto::PlaceholderCryptoProvider,
    types::{AlgSuite, CID},
};

#[derive(Arbitrary, Debug, Clone)]
struct EntityFrame {
    id: [u8; 32],
    new_cid: [u8; 32],
    existing_cid: Option<[u8; 32]>,
}

fuzz_target!(|frame: EntityFrame| {
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto([0u8; 16]);

    // Optionally pre-create an entity to drive duplication logic
    if let Some(cid) = frame.existing_cid {
        kernel.state.entities.insert(cid, vec![]); // placeholder entity
    }

    // Capability to create/update entity
    let cap_cid: CID = [0xDD; 32];
    let cap = Capability {
        id: cap_cid,
        alg_suite: AlgSuite::CLASSIC,
        holder: vec![],
        target_entity: frame.new_cid,
        rights: u32::MAX,
        nonce: 0,
        expiry_lc: None,
        signature: vec![],
    };
    kernel.state.capabilities.insert(cap_cid, cap);

    // Minimal command whose payload is the CID we want to create
    let command = Command {
        id: frame.id,
        alg_suite: AlgSuite::CLASSIC,
        replica: [0u8; 16],
        capability: cap_cid,
        lclock: 1,
        payload: frame.new_cid.to_vec(),
        signature: vec![],
    };

    let _ = kernel.apply(&command);
}); 