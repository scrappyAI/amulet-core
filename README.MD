# Amulet-Core

**A Foundational Library and Deterministic Kernel for Verifiable State**

---

## ✨ Mission

**Amulet-Core** is a lean, secure, foundational library providing a deterministic kernel. It's designed to serve as a "Layer-0" for systems requiring verifiable, auditable state transitions. While initially inspired by challenges in finance, its primitives aim to model the fundamental interactions of **who** can do **what**, **when**, and **under what authority** (optionally, **why** for autonomous agents or richer contextual information).

It provides a minimal and formal substrate upon which complex behaviors in domains like finance, law, and governance – or systems at their intersection (collectively, "lawful systems") – can safely and predictably emerge. Our goal is to model such systems from first principles using only essential primitives, fostering maximal composability, audit-friendliness, and trust.

---

## 📊 Core Primitives

At the heart of Amulet-Core lies a strict, irreducible set of **three** system primitives. These primitives are designed to comprehensively model interactions by capturing **who** (Entities, Capability holders) can perform **what** actions (Commands representing defined operations) on **what** resources (Entities), **when** (as Commands are processed and resulting Events are timestamped with logical clocks), and **under what authority** (Capabilities). They form the ontology for interacting with and evolving state:

### 1. `Entity`

A self-contained, persistent object with isolated state.

*   Represents the "who" (if an active agent) or "what" (if a passive resource or data).
*   Examples: accounts, contracts, legal documents, digital assets, user identities, autonomous agents.
*   Entities are versioned immutably; changes result in new versions.

### 2. `Capability`

The core enforcement mechanism of authority and permission.

*   Represents "under what authority" an action can be performed.
*   Capabilities determine what operations an entity (identified by its public key or other holder identifier) can perform on other entities or the system itself.
*   Capability-based security ensures **no ambient authority**; only explicit rights.
*   Capabilities can be granted or revoked and are enforced at the kernel level during command processing.

### 3. `Command`

The atomic instruction for state transition.

*   Represents the "what" (the specific operation to be performed) and implies the "when" (the logical time of intent).
*   `Command`s are cryptographically signed inputs that specify an intended operation (e.g., create entity, update entity, transfer capability, invoke an entity method).
*   They encapsulate the caller's intent, the necessary authority (`Capability` CID), and the operation payload. Optionally, payload can include metadata for "why".
*   The kernel processes `Command`s. If valid and authorized, a `Command` leads to changes in system state, which are then recorded as one or more `Event`s.
*   `Event`s are the immutable, auditable output of the kernel, representing committed state changes and definitively recording "what" happened and "when" (via logical clocks).

> No state-altering operation may occur without a valid `Command`. No `Command` is processed without a valid `Capability` granting sufficient rights.

---

## 🏛️ Architectural Principles

Amulet-Core is guided by a tight set of engineering values. All design decisions must align with these principles:

*   ❌ **Security First**

    *   The kernel must default to denial. Nothing happens without explicit capabilities.
    *   Isolation and immutability are assumed; mutation is modeled as versioned replacement.
*   ✅ **Simplicity > Complexity**

    *   If something can be expressed in terms of core primitives, it should be.
    *   No hidden behaviors, no magic state, no special cases.
*   ⏱️ **Long-Term First**

    *   Code and concepts must age gracefully. Trends and temporary hacks are rejected.
    *   Design for composability, not convenience.
*   ⛔ **Zero External Dependencies (for core logic)**

    *   The core kernel logic and state transition mechanisms must not depend on external libraries or frameworks unless **absolutely necessary** (e.g., fundamental crypto primitives).
    *   The kernel should be able to run in deterministic isolation. (Tooling like `tracing` is used for observability but can be compiled out or no-op for core execution).

---

## 🔧 What Amulet-Core Is *Not*

*   It is not a specific smart contract language (though one could be built on top).
*   It is not an application framework.
*   It is not a business logic engine out-of-the-box.
*   It is not tied to any specific blockchain, database, or ledger (though it can be integrated with them).

Instead, **Amulet-Core** is a formal substrate: the minimal, verifiable mechanism upon which entire "lawful systems" in various domains can be built, reasoned about, and trusted.

---

## 🌐 Vision

We envision a world where complex systems – be they in finance, law, governance, or their intersections forming "lawful systems" – are no longer black boxes. With Amulet-Core:

*   You can trace every state transition through immutable `Event`s, understanding precisely **what** changed and **when**.
*   You can validate **who** had the authority to act and **under what authority** via `Capability` verification for every `Command`.
*   You can reason about system behavior from first principles.
*   You can build and scale systems with verifiable integrity and confidence.

This is not software for today. It is software for the century.

---

## ✨ Inspired by

*   seL4, Erlang, and microkernel philosophy
*   Capability-based security systems (e.g., EROS, Coyotos)
*   Formal methods and verifiable computation
*   Functional programming and immutable data models
*   Ledger-level auditability, not UI-level abstraction

---

## 🔄 Next Steps

If you're reading this, you're likely building something serious. Start by:

*   Exploring the core data structures (`Entity`, `Command`, `Capability`, `Event`) and how they model "who, what, when, and authority".
*   Reviewing the command processing and event emission lifecycle within the `Kernel`.
*   Designing your own userland layer, application, or domain-specific logic on top of Amulet-Core's primitives.

Stay minimal. Stay precise. Stay true to the core principles.

---

⚡ **Amulet-Core: Build from first principles. Deploy with confidence.**
