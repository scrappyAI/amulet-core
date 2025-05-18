# Amulet-Core Project Roadmap & Tech Stack

This document outlines the development roadmap and technology stack for the Amulet-Core project, derived from the `kernel_spec.MD` and `README.MD`. It will be updated as the project progresses.

## Project Roadmap

### Phase 0: Refactoring & Core Abstractions (Completed as part of initial Phase 1 work)

*   **0.1. Simplify State Handling:**
    *   Refactored `StateDelta` and `SystemState` to use `Entity<Vec<u8>>` for serialized entity bodies, removing `EncodedStateForDelta`.
    *   Updated `EncodedState` trait in `primitives/entity.rs` for explicit `encode`/`decode` methods.
    *   Adjusted `kernel.rs` (`runtime`, `materialise_event`) accordingly.
*   **0.2. Introduce Crypto Abstraction Layer:**
    *   Created `crypto` module with `Hasher`, `Signer`, `Verifier`, and `CryptoProvider` traits.
    *   Added `PlaceholderCryptoProvider` for initial compilation and testing.
    *   Made `Kernel` generic over `CryptoProvider` (`Kernel<CP: CryptoProvider>`).
    *   Updated `verify_signature` and CID generation (`generate_cid`, in `materialise_event`) in `kernel.rs` to use the crypto provider abstraction.

### Phase 1: Core Kernel Implementation (Rust) — Feature-Complete & Hardening

*   **1.1. Core Data Structures:** (Completed)
    *   Implement `Entity` struct and its invariants (defined, `EncodedState` updated).
    *   Implement `Capability` struct and its invariants (defined).
    *   Implement `Command` struct and its validation logic (defined, `EncodedCmd` updated).
    *   Implement `Event` struct, ensuring append-only nature and bit-exact preservation of unknown fields (Mechanism for unknown field preservation via `Event::additional_fields` implemented; full relay/re-serialization tests pending for Phase 2.4).
*   **1.2. State-Transition Semantics:** (Core Implemented, `runtime` is placeholder)
    *   Implemented the `apply(cmd) → Event` function in `kernel.rs`, including core validation, lclock management, delta application, and event materialization flow.
    *   Implemented `validate(cmd)` logic in `kernel.rs` with checks for capability, alg_suite, expiry, signature (via placeholder), rights, and command lclock.
    *   Implemented `append_delta` for robust state mutation based on `StateDelta`, with its internal invariant checks now extensively covered by property-based tests (see §1.7).
    *   The `kernel_spec.md §3` requirement `assert delta.respects_invariants()` is fulfilled by the detailed invariant checks within `append_delta`.
    *   Lamport clock overflow condition in `apply` is now correctly handled.
*   **1.3. Cryptographic Suites:** (CLASSIC ✅, FIPS ✅  — PQC & HYBRID pending)
    *   `AlgSuite` enum defined.
    *   Crypto abstraction layer (`crypto` module with traits) implemented.
    *   **CLASSIC Suite (BLAKE3-256 · Ed25519)** — complete & unit-tested.
    *   **FIPS Suite (SHA-3-256 · ECDSA-P-256)** — complete & unit-tested.
    *   **PQC Suite (SHAKE-256 · Dilithium-L3)** — design in progress.
    *   **HYBRID Suite (SHA-3-256 · SHAKE-256 · Ed25519 · Dilithium-L3)** — blocked on PQC provider.
    *   **Next (Phase-1 Hardening):**
        *   Add `PQC` provider (Dilithium-L3 via `pqcrypto`/`pqc` bindings).
        *   Add `HYBRID` provider & enforce dual-signature rule (§4, kernel_spec.md).
        *   Hook providers into compliance profile selection.
*   **1.4. Runtime Purity & Determinism** — principle established; concrete runtimes pending.
*   **1.5. Rights Algebra:** (Completed)
    *   Implemented `RightsMask` and core right constants in `rights.rs`.
    *   Implemented `canonicalise` and `sufficient` functions.
    *   Updated `EncodedCmd` trait with `required_rights()`.
    *   Integrated into `kernel.rs::rights_sufficient`.
    *   Created `rights.md`.
*   **1.6. Time Model:** (Largely Completed)
    *   **Lamport Clock Rules:** Rules 1-5 addressed in `kernel.rs` (`validate_command`, `apply`, `process_incoming_event`). Overflow check in `apply`.
    *   **Vector-Clock Extension (Optional Feature):**
        *   Logic for `vc[replica] = event.lclock` on event creation in `apply`.
        *   Merge logic (`vector_clock::merge_into`) and `process_incoming_event` integration complete.
        *   Compare logic (`vector_clock::compare`) implemented.
        *   Kernel support for enabling/disabling Vector Clocks at instantiation is now implemented (`enable_vector_clocks` flag).
*   **1.7. Hardening Actions**
    *   **✅** Forbid `unsafe_code` at crate root and enabled strict Clippy linting locally.
    *   **✅** Added property-based tests (`proptest`) for Rights Algebra.
    *   **✅** Added Criterion benchmark harness for hash functions (opt-in via `cargo bench --features bench`).
    *   **✅** Lamport overflow condition in `apply` fixed and covered by a new property-based test in `prop_lamport.rs`.
    *   **✅** Created initial fuzz target stub for `Kernel::apply` in `fuzz/fuzz_targets/kernel_apply.rs` (requires `cargo fuzz init` and manual `fuzz/Cargo.toml` setup by user).
    *   **✅** Added property-based tests for `validate_command` (capability expiry and command lclock) in `tests/prop_kernel_validate.rs`.
    *   **✅** Added comprehensive property-based tests for `Kernel::append_delta` invariants (`prop_append_delta.rs`).
    *   **🟡** CI integration (clippy, rustfmt, cargo-audit) scaffold to be added in tooling phase.
    *   **✅** Expanded fuzz harness with a new target for `Kernel::process_incoming_event`.
    *   **✅** Expanded command-validation proptests for `AlgSuiteMismatch`, `InsufficientRights`, and `CapabilityNotFound`.
    *   **🟡** Expand fuzz harness capabilities (e.g., more structured inputs, stateful fuzzing if appropriate) and targets (e.g., `Kernel::apply` with more diverse `EncodedCmd` types once defined, `Kernel::new`, specific crypto provider operations).
    *   **🟡** Further expand command-validation proptests to cover signature verification failures (when mock/faulty crypto-providers allow) and other edge cases, aiming for >90% coverage of `validate_command` logic.
    *   **🟡** Expand test coverage: Established infrastructure for a conformance test-vector suite (`conformance_tests.rs`) with initial vectors for Lamport clock rules and overflow. This complements property-based tests and unit tests for spec-driven scenarios. Further test vectors to be added (see §2.1).

### Phase 2: Formal Verification & Rigorous Testing

*   **2.1. Test-Vector Suite:** (Infrastructure established)
    *   Develop an official test-vector suite covering:
        *   Lamport clock rules and interactions. (Initial vectors implemented)
        *   Overflow behavior of Lamport clocks. (Initial vectors implemented)
        *   Hybrid signature verification rules (dual and single).
        *   Rights algebra logic (once fully defined).
    *   Core infrastructure (`conformance_tests.rs`, test runner, basic structures) for defining and running test vectors is in place.
*   **2.2. Formal Modeling (TLA+):**
    *   Create a machine-checked TLA+ model of the kernel.
    *   Prove Safety and Liveness properties against defined invariants (e.g., C-1 to C-8 from `kernel_spec.MD`, though these specific invariant labels need to be identified or defined).
*   **2.3. Property-Based Testing:**
    *   Implement property-based fuzz tests (e.g., using `proptest` crate in Rust).
    *   Derive test properties from traces of the TLA+ model.
*   **2.4. Conformance Gate: Unknown Field Preservation:**
    *   Verify that unknown Event fields are preserved bit-exact when relaying or re-serializing events. (Mechanism for preservation via `Event::additional_fields` implemented in Phase 1.1; dedicated conformance tests for relay/re-serialization during event exchange are pending).

### Phase 3: Documentation & Userland Guidance

*   **3.1. Rights Algebra Specification:**
    *   Create and complete `rights.md` detailing the full Rights Algebra.
*   **3.2. Core System Documentation:**
    *   Document core data structures (`Entity`, `Capability`, `Command`, `Event`) in detail.
    *   Document the kernel message lifecycle and state transition flow.
*   **3.3. Userland Layer Design:**
    *   Provide architectural guidance and best practices for designing and implementing userland layers on top of Amulet-Core.

### Phase 4: Compliance Profiles & Deployment Readiness

*   **4.1. Compliance Profiles:**
    *   Define, implement, and test the following compliance profiles:
        *   **Dev / PoC:** CLASSIC suite, Lamport time.
        *   **Fed-Moderate:** FIPS suite, Lamport time.
        *   **Hybrid-2025:** HYBRID suite, Vector time.
        *   **Archive:** PQC suite, Lamport time.
*   **4.2. Deployment Preparation:**
    *   Finalize build processes and release candidates.
    *   Prepare materials for community engagement and early adopters.

## Technology Stack

*   **Primary Programming Language:** Rust
    *   *Rationale:* Performance, memory safety, strong type system, and suitability for systems-level programming. Aligns with the project's security and long-term principles.
*   **Formal Verification:** TLA+
    *   *Rationale:* Specified in `kernel_spec.MD` for proving safety and liveness properties. Industry standard for formal specification and verification of concurrent and distributed systems.
*   **Property-Based Testing:** Rust crates such as `proptest`.
    *   *Rationale:* Recommended in `kernel_spec.MD` (e.g., QuickCheck) for generating a wide range of test cases from abstract properties, complementing TLA+ and example-based tests.
*   **Cryptographic Libraries:**
    *   `blake3 = "1.5"` (or latest) - Integrated for CLASSIC suite.
    *   `ed25519-dalek = { version = "2.1", features = ["rand_core"] }` (or latest) - Integrated for CLASSIC suite.
    *   `rand = "0.8"` (or latest) - Used for test key generation.
    *   `sha3 = "0.10"` (or latest) - Integrated for FIPS suite.
    *   `p256 = { version = "0.13", features = ["ecdsa"] }` (or latest) - Integrated for FIPS suite.
    *   `ecdsa = { version = "0.16", features = ["der"] }` (or latest) - Integrated for FIPS suite.
    *   (To be selected for PQC, HYBRID: RustCrypto, PQClean bindings like `liboqs` etc.)
*   **Data Serialization (for external representations):** (To be decided - e.g., `serde` with `bincode`/`prost`/`flatbuffers` or custom)
    *   Internal entity bodies are currently handled as `Vec<u8>` after `EncodedState::encode()`.
*   **Unique Identifiers (ReplicaID):** `uuid` crate (dependency noted).
*   **Build System & CI/CD:** Cargo, GitHub Actions or similar.
    *   *Rationale:* Standard tooling for Rust projects, enabling automated builds, tests, and checks.

This document will be revisited and updated at the end of each major phase or as significant design decisions are made. 