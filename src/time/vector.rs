//! Vector Clock implementation for Amulet-Core (moved from `clock::vector_clock`).
//!
//! This module duplicates the prior implementation verbatim so that callers no
//! longer depend on the deprecated `crate::clock` namespace.

use crate::types::ReplicaID;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PartialOrder {
    LessThan,
    GreaterThan,
    Equal,
    Concurrent,
}

pub fn merge_into(local_vc_map: &mut HashMap<ReplicaID, u64>, incoming_vc_map: &HashMap<ReplicaID, u64>) {
    for (replica_id, incoming_lclock) in incoming_vc_map {
        let local_lclock = local_vc_map.entry(*replica_id).or_insert(0);
        *local_lclock = (*local_lclock).max(*incoming_lclock);
    }
}

pub fn compare(vc1_map: &HashMap<ReplicaID, u64>, vc2_map: &HashMap<ReplicaID, u64>) -> PartialOrder {
    let mut vc1_le_vc2 = true;
    let mut vc2_le_vc1 = true;

    let mut all_keys = vc1_map.keys().collect::<std::collections::HashSet<_>>();
    all_keys.extend(vc2_map.keys());

    for key in all_keys {
        let val1 = vc1_map.get(key).copied().unwrap_or(0);
        let val2 = vc2_map.get(key).copied().unwrap_or(0);

        if val1 > val2 { vc1_le_vc2 = false; }
        if val1 < val2 { vc2_le_vc1 = false; }
    }
    if vc1_le_vc2 && vc2_le_vc1 {
        PartialOrder::Equal
    } else if vc1_le_vc2 {
        PartialOrder::LessThan
    } else if vc2_le_vc1 {
        PartialOrder::GreaterThan
    } else {
        PartialOrder::Concurrent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ReplicaID; // Assuming ReplicaID is [u8; 16]

    fn rid(id: u8) -> ReplicaID { [id; 16] }

    #[test]
    fn test_merge_into_basic() {
        let mut local = HashMap::from([(rid(1), 5), (rid(2), 3)]);
        let incoming = HashMap::from([(rid(1), 7), (rid(3), 4)]);
        merge_into(&mut local, &incoming);
        assert_eq!(local.get(&rid(1)), Some(&7));
        assert_eq!(local.get(&rid(2)), Some(&3));
        assert_eq!(local.get(&rid(3)), Some(&4));
    }

    #[test]
    fn test_merge_into_empty_local() {
        let mut local = HashMap::new();
        let incoming = HashMap::from([(rid(1), 7), (rid(3), 4)]);
        merge_into(&mut local, &incoming);
        assert_eq!(local, incoming);
    }

    #[test]
    fn test_merge_into_empty_incoming() {
        let mut local = HashMap::from([(rid(1), 5), (rid(2), 3)]);
        let original_local = local.clone();
        let incoming = HashMap::new();
        merge_into(&mut local, &incoming);
        assert_eq!(local, original_local);
    }

    #[test]
    fn test_compare_equal() {
        let vc1 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        let vc2 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        assert_eq!(compare(&vc1, &vc2), PartialOrder::Equal);
    }

    #[test]
    fn test_compare_less_than() {
        let vc1 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        let vc2 = HashMap::from([(rid(1), 1), (rid(2), 2)]);
        assert_eq!(compare(&vc1, &vc2), PartialOrder::LessThan);

        let vc3 = HashMap::from([(rid(1), 1)]);
        let vc4 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        assert_eq!(compare(&vc3, &vc4), PartialOrder::LessThan);
    }

    #[test]
    fn test_compare_greater_than() {
        let vc1 = HashMap::from([(rid(1), 1), (rid(2), 2)]);
        let vc2 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        assert_eq!(compare(&vc1, &vc2), PartialOrder::GreaterThan);

        let vc3 = HashMap::from([(rid(1), 1), (rid(2), 1)]);
        let vc4 = HashMap::from([(rid(1), 1)]);
        assert_eq!(compare(&vc3, &vc4), PartialOrder::GreaterThan);
    }

    #[test]
    fn test_compare_concurrent() {
        let vc1 = HashMap::from([(rid(1), 1), (rid(2), 2)]);
        let vc2 = HashMap::from([(rid(1), 2), (rid(2), 1)]);
        assert_eq!(compare(&vc1, &vc2), PartialOrder::Concurrent);

        let vc3 = HashMap::from([(rid(1), 1)]);
        let vc4 = HashMap::from([(rid(2), 1)]);
        assert_eq!(compare(&vc3, &vc4), PartialOrder::Concurrent);
    }

    #[test]
    fn test_compare_with_missing_entries() {
        // vc1: {rA:1}, vc2: {rA:1, rB:1}  => vc1 < vc2
        let vc1 = HashMap::from([(rid(1),1)]);
        let vc2 = HashMap::from([(rid(1),1), (rid(2),1)]);
        assert_eq!(compare(&vc1, &vc2), PartialOrder::LessThan);

        // vc1: {rA:1, rB:1}, vc2: {rA:1} => vc1 > vc2
        assert_eq!(compare(&vc2, &vc1), PartialOrder::GreaterThan);

        // vc1: {rA:2}, vc2: {rA:1, rB:1} => concurrent
        let vc3 = HashMap::from([(rid(1),2)]);
        assert_eq!(compare(&vc3, &vc2), PartialOrder::Concurrent);
    }
} 