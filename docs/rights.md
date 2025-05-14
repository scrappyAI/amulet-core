# Amulet-Core Rights Algebra Specification

This document details the Rights Algebra used within Amulet-Core for managing permissions and capabilities.

## 1. Conceptual Goals

The Amulet-Core Rights Algebra is designed with the following principles:

*   **Bitwise Representation**: Every permission is represented as a single bit within a 32-bit unsigned integer (`RightsMask = u32`). This allows for efficient storage and manipulation.
*   **Fast Validation**: Kernel-level validation of rights is optimized for speed, typically reducing to a bitwise AND operation and a comparison.
*   **Extensibility**: Bits 5-15 are reserved for future core rights, and bits 16-31 are available for application-specific or user-defined rights. This design ensures forward compatibility, allowing new rights to be added without breaking existing acks.
*   **Implied Rights & Canonicalization**: The algebra supports the concept of implied rights (e.g., `WRITE` implies `READ`). A canonicalization step ensures that rights masks are consistently interpreted. Older replicas processing a capability with a right they don't understand (but which implies a right they do) can remain conservative yet safe.
*   **Delegation**: A specific `DELEGATE` bit allows a capability holder to create new (child) capabilities. The rights granted by a delegated capability must be a subset of the delegator's rights.
*   **Lifecycle Management**: `ISSUE` and `REVOKE` bits are provided for managing the lifecycle of other capabilities.

## 2. Bit Layout

The `RightsMask` is a `u32` value. Bits are assigned as follows (LSB = bit 0):

| Bit | Name       | Description                                                     |
|-----|------------|-----------------------------------------------------------------|
| 0   | `READ`     | Observe entity state.                                           |
| 1   | `WRITE`    | Mutate entity state (implies `READ`).                           |
| 2   | `DELEGATE` | Create a child capability with rights ⊆ own rights.             |
| 3   | `ISSUE`    | Create an **independent** capability (e.g., mint a new asset).   |
| 4   | `REVOKE`   | Revoke an issued or delegated capability.                       |
| --- | ---        | ---                                                             |
| 5-15| *Reserved* | Reserved for future core Amulet-Core rights. Must be zero for now. |
| 16-31| *Extension*| Available for application-specific or user-defined rights. Ignored by the core kernel for its checks but must be preserved. |

## 3. Kernel Validation Rule

The core validation rule, as specified in §6 of the Kernel Specification, is:

`rights_sufficient(command) ⇔ (capability.rights & required_bits(command.payload)) == required_bits(command.payload)`

Where:
*   `capability.rights` is the `RightsMask` from the capability presented with the command.
*   `required_bits(command.payload)` is the `RightsMask` indicating the permissions necessary to execute the specific operation defined in the command's payload. This value is determined by the command payload itself.

The kernel performs a canonicalization step on `capability.rights` before the check to ensure all implied rights are considered.

## 4. Delegation and Revocation Semantics (Future Elaboration)

*   **Delegation (`DELEGATE` right):**
    *   When a holder of a capability with the `DELEGATE` bit set attempts to create a new (child) capability, the kernel must verify:
        1.  The parent capability indeed has the `DELEGATE` bit set.
        2.  The rights mask of the new child capability (`child.rights`) is a subset of the canonicalized rights mask of the parent capability (`canonicalise(parent.rights)`). That is, `(canonicalise(parent.rights) & child.rights) == child.rights`.
*   **Issuance (`ISSUE` right):**
    *   The `ISSUE` right allows a capability holder to mint a brand-new, independent capability. This is distinct from delegation as there is no parent-child relationship in terms of rights derivation from an existing capability held by the issuer.
    *   The conditions under which `ISSUE` can be used (e.g., what types of capabilities can be issued, any associated costs or prerequisites) are typically defined by the runtime logic of specific "issuer" entities or commands.
*   **Revocation (`REVOKE` right):**
    *   The `REVOKE` right allows a capability holder to invalidate another capability.
    *   The kernel must maintain a state (e.g., a list of revoked capability CIDs) to check against when capabilities are presented.
    *   The exact mechanism of how a capability targets another for revocation (e.g., by CID) and the scope of `REVOKE` (e.g., can only revoke capabilities one issued/delegated, or broader authority) will be detailed by specific command types that implement revocation.

The implementation of these flows primarily resides within the runtime logic of specific command types, but the Rights Algebra provides the fundamental bitmask checks required to authorize these actions. 