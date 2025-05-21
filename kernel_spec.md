Amulet-Core • Kernel Specification • v0.5 (2025-05-21)

Status: Draft — v0.5 changes integrating SpecPlan recommendations (2025-05-21). Key changes: Vector clocks mandatory, crypto suites moved to companion spec, Capability.kind added, Rights bits policy updated.

⸻

Changelog

Ver	Date	Highlights
0.5	2025-05-21	• Vector clocks mandatory (field no longer Option).
			• Command remains canonical; Operation is alias.
			• Crypto suites moved to companion spec "Amulet-Crypto".
			• Capability.kind (u16) reserved for overlay use.
			• Rights bits 0-4 frozen; expansion policy documented.
0.4	2025-05-10	• Relaxed Lamport monotonicity rule (≥).
• Defined overflow behaviour.		
• Added normative rights algebra stub.		
• Specified runtime purity.		
• Formalised hybrid signature rule.		
• Provided vector-clock merge algorithm.		
• Added ReplicaID type, field preservation rule, conformance gates.		
0.3	2025-05-09	Logical-time model (Lamport, optional vector clocks).
0.2	2025-05-09	Algorithm-suite agility (CLASSIC, FIPS, PQC, HYBRID).
0.1	2025-05-07	Initial public draft.


⸻

0 Executive Summary

Amulet-Core is a deterministic micro-kernel for economic state. v0.5 makes vector clocks mandatory, moves detailed cryptographic suite definitions to a companion specification ("Amulet-Crypto"), introduces `Capability.kind` for overlay semantics, and formalizes the rights bit allocation policy. These changes enhance clarity and focus the kernel on its core task of ordered event emission, while maintaining wire compatibility where possible (vector_clock field is now non-optional).

⸻

1 Notation
	•	→  pure function.
	•	Σ   authoritative state (append-only Event log + materialised views).
	•	CID 32-byte content address (hash(bytes)).
	•	lclock Lamport logical counter (u64).
	•	VClock Vector Clock (HashMap<ReplicaID, u64>).
	•	ReplicaID 128-bit UUID (collision-free domain).
	•	alg_suite_tag `u8` tag referencing an algorithm profile defined in "Amulet-Crypto" spec (§4).

⸻

2 Core Data Types

2.1 Entity

struct EntityHeader {
    id: CID,           // stable across versions
    version: u64,      // monotonic per Entity
    lclock: u64,       // Lamport time at creation/update
    parent: Option<CID>,
}
struct Entity<E> { header: EntityHeader, body: E } // E is an opaque, runtime-defined state type

Invariants
	1.	Version monotonicity — versionₙ₊₁ = versionₙ + 1 within an Entity.
	2.	Replica-local monotonicity — lclock strictly increases per update per replica.
	3.	Parent causal bound — When parent Event is observed, parent.lclock ≤ child.lclock holds; replicas MAY create children concurrently (vector-clock reconciliation §7.4).

⸻

2.2 Capability

struct Capability {
    id: CID,
    alg_suite_tag: u8,     // Tag for crypto suite (defined in Amulet-Crypto spec)
    holder: PublicKey,
    target_entity: CID,
    rights: RightsMask,        // see §6
    nonce: u64,
    expiry_lc: Option<u64>,
    kind: u16,               // Reserved for overlay semantics (e.g., capability type)
    signature: Signature,
}

Invariants
	1.	If expiry_lc set ⇒ current_lc < expiry_lc.
	2.	signature verifies under the algorithm suite indicated by `alg_suite_tag` (see §4).

⸻

2.3 Command

struct Command<P> { // P is an opaque, runtime-defined payload type
    id: CID,
    alg_suite_tag: u8,     // Tag for crypto suite
    replica: ReplicaID,
    capability: CID,
    lclock: u64,            // proposed Lamport time
    payload: P,
    signature: Signature,   // by capability.holder
}
// `Operation<P>` is a common alias for `Command<P>` in higher-level code.

Validation

validate(cmd) → Result
    assert Σ.contains(cmd.capability)
    cap ← Σ[cmd.capability]
    assert cmd.alg_suite_tag == cap.alg_suite_tag // Ensure command and capability use same suite context
    assert verify(cmd.signature, cmd.payload, cmd.alg_suite_tag) // Verification uses the tag
    assert rights_sufficient(cmd)          // §6
    assert cmd.lclock >= local_lc          // relaxed to ≥


⸻

2.4 Event

struct Event {
    id: CID,
    alg_suite_tag: u8,     // Tag for crypto suite, from Command
    replica: ReplicaID,
    caused_by: CID,      // Command.id
    lclock: u64,         // assigned by kernel
    vclock: VClock,      // MANDATORY: Vector clock (HashMap<ReplicaID, u64>)
    new_entities: Vec<CID>,
    updated_entities: Vec<CID>,
    reserved: Vec<u8>,   // Unknown future fields MUST be preserved bit-exact when relayed.
}

Events are append-only.

⸻

3 State-Transition Semantics

apply(cmd) → Event
    validate(cmd)                         // §2.3
    lclock_new = max(cmd.lclock, local_lc + 1)
    delta ← runtime(cmd)                  // §5
    assert delta.respects_invariants()
    Σ.append(delta, lclock_new)
    local_lc = lclock_new
    vc = merge_vector_clock(local_vc, cmd.vclock_if_present) // Or however command contributes to VC merge
                                          // Kernel ensures event.vclock is updated (§7.4)
    return materialise_event(delta, lclock_new, vc) // vc is the new, authoritative VClock for the event


⸻

4 Cryptographic Suites

(Note: Full cryptographic suite definitions, including specific algorithms for hashing and signatures for each suite, are now detailed in the companion "Amulet-Crypto" specification. The `alg_suite_tag: u8` field in core data structures (Event, Command, Capability) is a tag that refers to these externally defined suites.)

Primary `alg_suite_tag` values (examples, see Amulet-Crypto spec for normative list):
	•	`0`: CLASSIC (e.g., BLAKE3-256, Ed25519)
	•	`1`: FIPS (e.g., SHA-3-256, ECDSA-P-256)
	•	`2`: PQC (e.g., SHAKE-256, Dilithium-L3)
	•	`3`: HYBRID (e.g., SHA-3-256 + SHAKE-256, Ed25519 + Dilithium-L3)

Hybrid verification rule — (Moved to Amulet-Crypto spec) Until 2031-12-31, for HYBRID suite, both constituent signatures MUST verify; afterwards the PQC signature alone suffices. Implementations SHOULD emit dual signatures until that date.

¹ BLAKE3 is not FIPS approved; use FIPS/PQC suites for regulated environments.

⸻

5 Runtime Purity & Determinism

runtime(cmd) MUST be referentially transparent:
	•	NO wall-time, randomness, or external I/O.
	•	Deterministic with respect to (Σ, cmd) only.
Violations are a conformance failure.

⸻

6 Rights Algebra (normative stub)

RightsMask is a 32-bit field.
	•	Bits 0-4 are core kernel rights (READ, WRITE, DELEGATE, ISSUE, REVOKE). These are frozen.
	•	Bits 5-15 are reserved for future kernel-level needs (e.g., audit, seal, proof generation).
	•	Bits 16-31 are available for domain-specific overlays (e.g., finance, logistics specific rights).

rights_sufficient(cmd) evaluates (cap.rights & required_bits(cmd.payload)) == required_bits(cmd.payload).
The function `required_bits(cmd.payload)` is defined by the runtime layer interpreting the opaque payload `P`.
Full algebra lives in rights.md (forthcoming).

⸻

7 Time Model

7.1 Lamport Clock Rules
	1.	Increment — On Command creation: lclock = local_lc + 1; update local_lc.
	2.	Validation — Kernel accepts cmd.lclock ≥ local_lc.
	3.	Commit — Kernel sets event.lclock = max(cmd.lclock, local_lc + 1).
	4.	Merge — On receiving Event: local_lc = max(local_lc, event.lclock).
	5.	Overflow — If local_lc == 2⁶⁴-1, replica MUST refuse further Commands and request state compaction / new replica.

7.2 External Wall-Time

May be stored as metadata; MUST NOT influence ordering.

7.3 Logical Expiry

expiry_lc is compared against receiver's local_lc after merge; thus unaffected by clock skew.

7.4 Vector Clock (Mandatory)
	•	Structure — `Event.vclock` is a `VClock` (HashMap<ReplicaID, u64>).
	•	Increment — On Event creation by replica `R` with Lamport time `L`: `event.vclock[R] = L`. If `R` is not in its own clock, it's added. Other entries are merged from the causal command or previous local state.
	•	Merge — On receiving an Event `E`, the local vector clock `local_vc` is updated: for each `(replica_id, l_time)` in `E.vclock`, `local_vc[replica_id] = max(local_vc.get(replica_id), l_time)`. Also, for any entry in `local_vc` not in `E.vclock`, it is retained.
	•	Compare — Standard partial-order: `vc1 ≤ vc2` iff `∀r vc1.get(r).unwrap_or(0) ≤ vc2.get(r).unwrap_or(0)`. Concurrency exists when neither `vc1 ≤ vc2` nor `vc2 ≤ vc1` holds.
Vector clocks are mandatory for robust conflict detection and causal ordering across replicas.

⸻

8 Formal Verification & Conformance

An implementation claims compliance when it:
	1.	Passes the official test-vector suite (Lamport logic, mandatory vector clocks, overflow behavior, hybrid signature rules from Amulet-Crypto, rights algebra stubs).
	2.	Ships a machine-checked TLA+ model proving Safety & Liveness against invariants C-1…C-8 (updated for v0.5 semantics).
	3.	Includes property-based fuzz tests (e.g., QuickCheck) derived from traces of the TLA+ model, covering mandatory vector clock scenarios.
	4.	Preserves unknown Event fields (via `Event.reserved`) bit-exact when relaying or re-serialising.

⸻

Appendix A — Compliance Profiles

Profile	Suite (Tag)	Time Model	Notes
Dev / PoC	CLASSIC	Lamport + Vector	Fastest builds, full causal history
Fed-Moderate	FIPS	Lamport + Vector	Today's US federal needs, full causal history
Hybrid-2025	HYBRID	Lamport + Vector	PQ-transition w/ concurrency detection
Archive	PQC	Lamport + Vector	100-year durability, full causal history


⸻

End of Specification