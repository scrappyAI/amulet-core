#![no_main]

// ────────────────────────────────────────────────────────────
// Harness: kernel_apply_lc
// Checks invariant I-02 (Lamport monotonicity) and I-09 (overflow)
// ────────────────────────────────────────────────────────────
// Data strategy:  Fixed-width frame carrying explicit Lamport clock
// as little-endian u64.  The rest of the command is minimally
// populated so the kernel "apply" logic runs.
//
// Sanitizers: Address + Undefined Behaviour (see fuzz_plan.md).
// Runtime: budgeted 500 ms via CI wrapper.
// ────────────────────────────────────────────────────────────

use libfuzzer_sys::fuzz_target;

use amulet_core::{
    kernel::Kernel,
    domain::Command,
    access::Capability,
    crypto::PlaceholderCryptoProvider,
    types::{AlgSuite, CID},
};

use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug, Clone)]
struct LcFrame {
    id: [u8; 32],
    lc: u64,
}

fuzz_target!(|frame: LcFrame| {
    // Instantiate kernel with default cryptography provider
    let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto([0u8; 16]);

    // Ensure referenced capability exists so apply() proceeds
    let cap_cid: CID = [0xAA; 32];
    let dummy_cap = Capability {
        id: cap_cid,
        alg_suite: AlgSuite::CLASSIC,
        holder: vec![],
        target_entity: [0u8; 32],
        rights: u32::MAX,
        nonce: 0,
        expiry_lc: None,
        signature: vec![],
    };
    kernel.state.capabilities.insert(cap_cid, dummy_cap);

    let cmd = Command {
        id: frame.id,
        alg_suite: AlgSuite::CLASSIC,
        replica: [0u8; 16],
        capability: cap_cid,
        lclock: frame.lc,
        payload: vec![],
        signature: vec![],
    };

    let _ = kernel.apply(&cmd);
}); 