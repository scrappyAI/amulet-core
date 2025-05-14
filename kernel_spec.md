Amulet-Core • Kernel Specification • v0.4 (2025-05-10)

Status: Draft — integrates peer review (2025-05-09). Major fixes: clock monotonicity under network re-ordering, overflow behaviour, vector-clock merge rules, hybrid-signature semantics, and clarified conformance gates.

⸻

Changelog

Ver	Date	Highlights
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

Amulet-Core is a deterministic micro-kernel for economic state. v0.4 tightens logical-time semantics and compliance surfaces while keeping wire compatibility with v0.3.

⸻

1 Notation
	•	→  pure function.
	•	Σ   authoritative state (append-only Event log + materialised views).
	•	CID 32-byte content address (hash(bytes)).
	•	lclock Lamport logical counter (u64).
	•	ReplicaID 128-bit UUID (collision-free domain).
	•	alg_suite algorithm profile (§4).

⸻

2 Core Data Types

2.1 Entity

struct EntityHeader {
    id: CID,           // stable across versions
    version: u64,      // monotonic per Entity
    lclock: u64,       // Lamport time at creation/update
    parent: Option<CID>,
}
struct Entity<E: EncodedState> { header: EntityHeader, body: E }

Invariants
	1.	Version monotonicity — versionₙ₊₁ = versionₙ + 1 within an Entity.
	2.	Replica-local monotonicity — lclock strictly increases per update per replica.
	3.	Parent causal bound — When parent Event is observed, parent.lclock ≤ child.lclock holds; replicas MAY create children concurrently (vector-clock reconciliation §7.4).

⸻

2.2 Capability

struct Capability {
    id: CID,
    alg_suite: AlgSuite,
    holder: PublicKey,
    target_entity: CID,
    rights: RightsMask,        // see §6
    nonce: u64,
    expiry_lc: Option<u64>,
    signature: Signature,
}

Invariants
	1.	If expiry_lc set ⇒ current_lc < expiry_lc.
	2.	signature verifies under alg_suite.

⸻

2.3 Command

struct Command<C: EncodedCmd> {
    id: CID,
    alg_suite: AlgSuite,
    replica: ReplicaID,
    capability: CID,
    lclock: u64,            // proposed Lamport time
    payload: C,
    signature: Signature,   // by capability.holder
}

Validation

validate(cmd) → Result
    assert Σ.contains(cmd.capability)
    assert cmd.alg_suite == Σ[cmd.capability].alg_suite
    assert verify(cmd.signature, cmd.payload, cmd.alg_suite)
    assert rights_sufficient(cmd)          // §6
    assert cmd.lclock >= local_lc          // relaxed to ≥


⸻

2.4 Event

struct Event {
    id: CID,
    alg_suite: AlgSuite,
    replica: ReplicaID,
    caused_by: CID,      // Command.id
    lclock: u64,         // assigned by kernel
    new_entities: Vec<CID>,
    updated_entities: Vec<CID>,
    vector_clock: Option<HashMap<ReplicaID, u64>>,  // if enabled
    // Unknown future fields MUST be preserved bit-exact when relayed.
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
    vc = merge_vector_clock(cmd)          // if §7.4 enabled
    return materialise_event(delta, lclock_new, vc)


⸻

4 Cryptographic Suites

enum AlgSuite { CLASSIC, FIPS, PQC, HYBRID }

Suite	Hash→CID	Signature(s)	Compliance
CLASSIC	BLAKE3-256¹	Ed25519	Best-effort
FIPS	SHA-3-256	ECDSA-P-256	FIPS-140-3
PQC	SHAKE-256	Dilithium-L3	CNSA 2.0
HYBRID	SHA-3-256 · SHAKE-256	Ed25519 · Dilithium-L3	Transition

¹ BLAKE3 is not FIPS approved; deploy FIPS/PQC suites for regulated environments.

Hybrid verification rule — Until 2031-12-31, both signatures MUST verify; afterwards Dilithium alone suffices. Implementations SHOULD emit dual signatures until that date.

⸻

5 Runtime Purity & Determinism

runtime(cmd) MUST be referentially transparent:
	•	NO wall-time, randomness, or external I/O.
	•	Deterministic with respect to (Σ, cmd) only.
Violations are a conformance failure.

⸻

6 Rights Algebra (normative stub)

RightsMask is a 32-bit field; bits 0-15 are core (READ, WRITE, DELEGATE, ISSUE, REVOKE).
rights_sufficient(cmd) evaluates (cap.rights & required_bits(cmd.payload)) == required_bits(cmd.payload).
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

expiry_lc is compared against receiver’s local_lc after merge; thus unaffected by clock skew.

7.4 Vector-Clock Extension (optional)
	•	Increment — On Event creation, set vc[replica] = event.lclock.
	•	Merge — On receipt, local_vc[r] = max(local_vc.get(r), incoming_vc[r]) for each entry.
	•	Compare — Standard partial-order: vc1 ≤ vc2 iff ∀r  vc1[r] ≤ vc2[r]. Concurrency when neither ≤ holds.
Vector clocks allow conflict detection but are not required for core safety.

⸻

8 Formal Verification & Conformance

An implementation claims compliance when it:
	1.	Passes the official test-vector suite (Lamport, overflow, hybrid sigs, rights algebra).
	2.	Ships a machine-checked TLA+ model proving Safety & Liveness against invariants C-1…C-8.
	3.	Includes property-based fuzz tests (e.g., QuickCheck) derived from traces of the TLA+ model.
	4.	Preserves unknown Event fields bit-exact when relaying or re-serialising.

⸻

Appendix A — Compliance Profiles

Profile	Suite	Time Ext	Notes
Dev / PoC	CLASSIC	Lamport	Fastest builds
Fed-Moderate	FIPS	Lamport	Today’s US federal needs
Hybrid-2025	HYBRID	Vector	PQ-transition w/ concurrency detection
Archive	PQC	Lamport	100-year durability


⸻

End of Specification