use proptest::prelude::*;
use amulet_core::rights::{self, core};

proptest! {
    /// For any mask, canonicalise(mask) should be a superset of mask (bitwise).
    #[test]
    fn prop_canonicalise_superset(mask in any::<u32>()) {
        let canon = rights::canonicalise(mask);
        // All bits set in `mask` must also be set in `canon`.
        prop_assert_eq!(mask & canon, mask);
    }

    /// WRITE implies READ after canonicalisation.
    #[test]
    fn prop_write_implies_read(mask in any::<u32>()) {
        let canon = rights::canonicalise(mask | core::WRITE);
        prop_assert!((canon & core::READ) != 0);
    }

    /// Sufficient should be equivalent when `have` is first canonicalised.
    #[test]
    fn prop_sufficient_equivalence(have in any::<u32>(), need in any::<u32>()) {
        let s1 = rights::sufficient(have, need);
        let canon_have = rights::canonicalise(have);
        let s2 = rights::sufficient(canon_have, need);
        prop_assert_eq!(s1, s2);
    }
} 