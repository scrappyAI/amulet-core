//!
//! Rights Algebra for Amulet-Core.
//! Defines core bit flags for permissions and helper functions for their manipulation
//! and validation, conforming to the specifications in `rights.md` and `kernel_spec.MD` §6.

use crate::types::RightsMask; // RightsMask is u32

/// Core rights bit flags (bits 0-4 defined, 5-15 reserved).
/// These are fundamental permissions recognized by the kernel.
pub mod core {
    use super::RightsMask;

    /// Permission to observe an entity's state.
    pub const READ: RightsMask = 1 << 0; // 0b00001
    /// Permission to mutate an entity's state. Implies `READ`.
    pub const WRITE: RightsMask = 1 << 1; // 0b00010
    /// Permission to create a child capability with rights that are a subset of the current capability's rights.
    pub const DELEGATE: RightsMask = 1 << 2; // 0b00100
    /// Permission to create an independent capability (e.g., minting new assets or other capabilities).
    pub const ISSUE: RightsMask = 1 << 3; // 0b01000
    /// Permission to revoke an issued or delegated capability.
    pub const REVOKE: RightsMask = 1 << 4; // 0b10000

    // Bits 5-15 are reserved for future core rights and must be zero for now.
    // Bits 16-31 are for application/user-defined extensions; ignored by core kernel checks but preserved.
}

/// Canonicalizes a rights mask by adding any implied rights.
///
/// For example, `WRITE` permission implies `READ` permission. This function ensures that
/// if the `WRITE` bit is set, the `READ` bit is also set in the returned mask.
///
/// # Arguments
/// * `mask` - The `RightsMask` to canonicalize.
///
/// # Returns
/// The canonicalized `RightsMask` with all implied rights included.
#[inline]
pub fn canonicalise(mask: RightsMask) -> RightsMask {
    let mut m = mask;
    if (m & core::WRITE) == core::WRITE { // Check if WRITE bit is set
        m |= core::READ; // If WRITE is set, ensure READ is also set
    }
    // Add other implication rules here if they are defined in the future.
    // e.g., if core::SUPER_WRITE implied core::WRITE, you'd add:
    // if (m & core::SUPER_WRITE) == core::SUPER_WRITE {
    //     m |= core::WRITE;
    // }
    m
}

/// Checks if a given `RightsMask` (`have`) satisfies a required `RightsMask` (`need`).
///
/// This function first canonicalizes the `have` mask to include all implied rights.
/// It then checks if all bits set in the `need` mask are also set in the canonicalized `have` mask.
/// This corresponds to the rule: `(canonicalise(have) & need) == need`.
///
/// # Arguments
/// * `have` - The `RightsMask` representing the permissions currently possessed.
/// * `need` - The `RightsMask` representing the permissions required for an operation.
///
/// # Returns
/// `true` if the `have` mask satisfies the `need` mask, `false` otherwise.
#[inline]
pub fn sufficient(have: RightsMask, need: RightsMask) -> bool {
    // First, ensure the 'have' mask includes all implied rights.
    let canonical_have = canonicalise(have);
    // Then, check if all bits required by 'need' are present in 'canonical_have'.
    (canonical_have & need) == need
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalise_write_implies_read() {
        assert_eq!(canonicalise(core::WRITE), core::WRITE | core::READ);
        assert_eq!(canonicalise(core::READ), core::READ);
        assert_eq!(canonicalise(core::WRITE | core::DELEGATE), core::WRITE | core::READ | core::DELEGATE);
        assert_eq!(canonicalise(0), 0);
    }

    #[test]
    fn test_sufficient_basic() {
        assert!(sufficient(core::READ, core::READ));
        assert!(!sufficient(0, core::READ));
        assert!(sufficient(core::WRITE | core::READ, core::READ));
        assert!(sufficient(core::WRITE | core::READ, core::WRITE));
    }

    #[test]
    fn test_sufficient_with_canonicalisation() {
        // `have` only has WRITE, but WRITE implies READ, so it should be sufficient for READ.
        assert!(sufficient(core::WRITE, core::READ)); 
        // `have` has WRITE (implies READ), needs WRITE AND READ.
        assert!(sufficient(core::WRITE, core::WRITE | core::READ));
        // `have` only READ, needs WRITE. Not sufficient.
        assert!(!sufficient(core::READ, core::WRITE));
    }

    #[test]
    fn test_sufficient_multiple_rights() {
        let have = core::WRITE | core::DELEGATE; // Implies READ
        let need_ok = core::READ | core::DELEGATE;
        let need_fail = core::READ | core::ISSUE;
        assert!(sufficient(have, need_ok));
        assert!(!sufficient(have, need_fail));
        assert!(sufficient(have, core::WRITE));
    }

    #[test]
    fn test_extension_bits_ignored_by_sufficient_logic_if_not_in_need() {
        let extension_bit_16 = 1 << 16;
        let have_core = core::WRITE;
        let have_with_extension = core::WRITE | extension_bit_16;
        
        // If `need` only asks for core rights, extension bits in `have` don't break sufficiency.
        assert!(sufficient(have_with_extension, core::READ)); // WRITE implies READ
        assert!(sufficient(have_with_extension, core::WRITE));
        
        // If `need` asks for an extension bit, `have` must also have it.
        assert!(sufficient(have_with_extension, core::READ | extension_bit_16));
        assert!(!sufficient(have_core, core::READ | extension_bit_16));
    }
} 