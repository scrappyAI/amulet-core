#![no_main]

// Harness: kernel_apply_authz – invariants I-04 & I-08
// Focus: Capability expiry (lclock versus expiry_lc) + rights mask enforcement.
// Sanitizer: ASAN, runtime 1s.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use amulet_core::{
    kernel::Kernel,
    crypto::PlaceholderCryptoProvider,
    types::{AlgSuite, CID},
    access::Capability,
    domain::Command,
};

#[derive(Arbitrary, Debug, Clone)]
struct AuthzFrame {
    cmd_id: [u8; 32],
    rights: u32,
    opcode: u8,  // Raw opcode byte stored directly in payload
    expiry_delta: i64, // expiry_lc = cmd.lc + delta; may be negative
    lclock: u64,
}

fuzz_target!(|frame: AuthzFrame| {
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto([0u8; 16]);

    // Capability setup
    let cap_cid: CID = [0xCC; 32];
    let expiry = if frame.expiry_delta.is_negative() {
        frame.lclock.saturating_sub(frame.expiry_delta.unsigned_abs())
    } else {
        frame.lclock.saturating_add(frame.expiry_delta as u64)
    };

    let cap = Capability {
        id: cap_cid,
        alg_suite: AlgSuite::CLASSIC,
        holder: vec![],
        target_entity: [0u8; 32],
        rights: frame.rights,
        nonce: 0,
        expiry_lc: Some(expiry),
        signature: vec![],
    };
    kernel.state.capabilities.insert(cap_cid, cap);

    let command = Command {
        id: frame.cmd_id,
        alg_suite: AlgSuite::CLASSIC,
        replica: [0u8; 16],
        capability: cap_cid,
        lclock: frame.lclock,
        payload: vec![frame.opcode],
        signature: vec![],
    };

    let _ = kernel.apply(&command);
}); 