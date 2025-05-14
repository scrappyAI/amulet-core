# Amulet-Core

**A Deterministic Kernel for Economic State**

---

## ✨ Mission

**Amulet-Core** is a lean, secure, deterministic kernel designed to serve as a "Layer-0" foundation for the financial world. It is not a financial application. It is a minimal and formal substrate upon which complex economic behavior can safely and predictably emerge.

Our goal is to model financial systems from first principles using only essential primitives. Amulet-Core is engineered to be maximally composable, audit-friendly, and trustable without sacrificing mechanical determinism.

---

## 📊 Core Primitives

At the heart of Amulet-Core lies a strict, irreducible set of **three** system primitives. These form the kernel's ontology:

### 1. `Entity`

A self-contained, persistent object with isolated state.

* Examples: accounts, businesses, contracts, obligations, agents.
* May represent both passive data (e.g., balance sheets) and active agents (e.g., AI actors).
* Entities can be versioned immutably.

### 2. `Capability`

The core enforcement mechanism of authority and permission.

* Capabilities determine what operations an entity can perform.
* Capability-based security ensures **no ambient authority**; only explicit rights.
* Capabilities can be granted or revoked and are enforced at the kernel level.

### 3. `Message`

The atomic communication unit for state transition and signaling.

* Inside the kernel, messages represent **operations** (e.g., spawn, transfer, update).
* Outside the kernel, committed messages become **events** (e.g., audit logs, state emissions).
* Every state change is initiated by a message and results in an event.

> No operation may occur without a message. No message is processed without a valid capability.

---

## 🏛️ Architectural Principles

Amulet-Core is guided by a tight set of engineering values. All design decisions must align with these principles:

* ❌ **Security First**

  * The kernel must default to denial. Nothing happens without explicit capabilities.
  * Isolation and immutability are assumed; mutation is modeled as versioned replacement.

* ✅ **Simplicity > Complexity**

  * If something can be expressed in terms of core primitives, it should be.
  * No hidden behaviors, no magic state, no special cases.

* ⏱️ **Long-Term First**

  * Code and concepts must age gracefully. Trends and temporary hacks are rejected.
  * Design for composability, not convenience.

* ⛔ **Zero External Dependencies**

  * The core must not depend on external libraries or frameworks unless **absolutely necessary**.
  * The kernel should be able to run in deterministic isolation.

---

## 🔧 What Amulet-Core Is *Not*

* It is not a smart contract language.
* It is not an app framework.
* It is not a business logic engine.
* It is not tied to any specific blockchain, database, or ledger.

Instead, **Amulet-Core** is a formal substrate: the minimal mechanism upon which entire financial systems can be built, reasoned about, and trusted.

---

## 🌐 Vision

We envision a world where financial systems are no longer black boxes. With Amulet-Core:

* You can trace every state transition.
* You can validate who had authority to act.
* You can reason about system behavior from first principles.
* You can scale economic systems with confidence.

This is not software for today. It is software for the century.

---

## ✨ Inspired by

* seL4, Erlang, and microkernel philosophy
* Capability-based security systems
* Functional programming and immutable data models
* Ledger-level auditability, not UI-level abstraction

---

## 🔄 Next Steps

If you're reading this, you're likely building something serious. Start by:

* Exploring the core data structures.
* Reviewing the kernel message lifecycle.
* Designing your own userland layer on top of Amulet-Core.

Stay minimal. Stay precise. Stay true to the kernel.

---

⚡ **Amulet-Core: Build from first principles. Deploy with confidence.**
