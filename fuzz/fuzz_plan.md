/*───────────────────────────────────────────────
  Amulet-Core  ▸  Deterministic Fuzz Blueprint
────────────────────────────────────────────────*/

/* PLAN ─────────────────────────────────────────
│ P | Invariant focus                | Harness                 | ms | Sanitizers │
│ 0 | Lamport monotone + overflow    | kernel_apply_lc         | 500| ASAN UBSAN │
│ 1 | Hybrid signature rule          | kernel_apply_sig        |1000| ASAN       │
│ 2 | Capability-expiry & rights     | kernel_apply_authz      |1000| ASAN       │
│ 3 | CID dup / entity delta         | kernel_apply_entities   |2000| ASAN       │
│ 4 | Unknown-field preservation     | roundtrip_frame         |2000| ASAN       │
│ 5 | Parent causal-bound + VClock   | process_evt_causality   |3000| ASAN       │
└──────────────────────────────────────────────────────────────*/

/* SEED CORPUS ─ ready for  fuzz/seeds/  (78-126 B each)
┌────┬─────────────hex_blob─────────────┬ target(s)          ┬ exp. ┬ invariants ─────────┬ note
│S1  │ 0111…11                          │ [kernel_apply]     │ ok   │ I-02                │ minimal create @lc=1
│S2  │ 0122…22                          │ [kernel_apply]     │ ok   │ I-06                │ valid HYBRID (80 B sig)
│S3  │ 0133…33                          │ [kernel_apply]     │ rej  │ I-06                │ HYBRID flag, 32 B sig
│S4  │ 0144…44                          │ [kernel_apply]     │ ok   │ I-09                │ lc = 2⁶⁴-2
│S5  │ 0155…55                          │ [kernel_apply]     │ ok   │ I-09                │ lc = 2⁶⁴-1 (caps future cmds)
│S6  │ 0166…66                          │ [kernel_apply]     │ rej  │ I-04                │ expiry == current lc
│S7  │ 0177…77 FF…                      │ [kernel_apply]     │ ok   │ I-07                │ unknown-tail preserved
│S8  │ 0201…11                          │ [kernel_apply]     │ rej  │ I-10                │ CID collision w/ S1
│S9  │ 0388…88                          │ [kernel_apply]     │ rej  │ I-08                │ rights mask insufficient
│S10 │ 0199…99                          │ [kernel_apply]     │ rej  │ I-06, I-05          │ PQC suite but 32 B sig
│S11 │ 0444…AB                          │ [process_event]    │ rej  │ I-03                │ parent lclock > incoming
│S12 │ 01BC…BC                          │ [kernel_apply]     │ ok   │ I-02                │ monotone advance to 10
└──────────────────────────────────────────────────────────────────────────────────────────*/

/* FEEDBACK LOOP ────────────────────────────────
1. crash → `cargo-fuzz tmin` → auto-tag JSON (invariant enum)
2. convert to `proptest` regression in tests/invariant_props.rs
3. replay trace in TLA+ (TLC) – spec gap if TLC accepts
4. weekly `cargo-fuzz cmin` → de-dupe seeds, commit new uniques
*/

/* CLI HINTS ────────────────────────────────────
RUSTFLAGS="-Zsanitizer=address" \
cargo fuzz run kernel_apply_lc \
  -- -rss_limit_mb=512 -seed=0xA11CE5 seeds/S1
*/

/* NEXT STEPS ───────────────────────────────────
☑ land six harnesses & CI gate "no crash ≤ 60 s"
☑ hook corpus + proptest into GH Actions
☑ write TLA+ skeleton (clocks, caps, entity map)
☑ close spec gaps surfaced by early rejects
☑ after 1 wk green ⇒ lift caps, add libAFL dictionary
*/ 