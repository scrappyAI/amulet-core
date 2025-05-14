use proptest::prelude::*;
use amulet_core::kernel::Kernel;
use amulet_core::access::Capability;
use amulet_core::domain::Command;
use amulet_core::types::{AlgSuite, CID, ReplicaID};
use amulet_core::crypto::PlaceholderCryptoProvider;
use amulet_core::error::KernelError;

// Helper to build a dummy capability and insert into kernel state
fn insert_dummy_cap(kernel: &mut Kernel<PlaceholderCryptoProvider>, cap_cid: CID) {
    let cap = Capability {
        id: cap_cid,
        alg_suite: AlgSuite::CLASSIC,
        holder: Vec::new(),
        target_entity: [0u8; 32],
        rights: 0u32, // no rights required for Vec<u8> payload
        nonce: 0,
        expiry_lc: None,
        signature: Vec::new(),
    };
    kernel.state.capabilities.insert(cap_cid, cap);
}

// Helper to craft a minimal command that requires no rights and signs empty payload.
fn build_command(cap_cid: CID, lclock: u64) -> Command<Vec<u8>> {
    Command {
        id: [1u8; 32],
        alg_suite: AlgSuite::CLASSIC,
        replica: [2u8; 16],
        capability: cap_cid,
        lclock,
        payload: Vec::new(),
        signature: Vec::new(),
    }
}

proptest! {
    /// If the replica's local Lamport clock is `u64::MAX`, it must refuse all further commands.
    #[test]
    fn prop_refuse_when_local_lc_max(command_lc in any::<u64>()) {
        let replica_id: ReplicaID = [9u8; 16];
        let mut kernel = Kernel::<PlaceholderCryptoProvider>::new_with_default_crypto(replica_id);
        kernel.local_lc = u64::MAX; // Simulate overflow state

        let cap_cid: CID = [3u8; 32];
        insert_dummy_cap(&mut kernel, cap_cid);

        // Build command with arbitrary (but >= current) lclock
        let cmd_lclock = command_lc.max(u64::MAX);
        let cmd = build_command(cap_cid, cmd_lclock);

        let result = kernel.apply(&cmd);
        prop_assert!(matches!(result, Err(KernelError::Other(_))));
    }
} 