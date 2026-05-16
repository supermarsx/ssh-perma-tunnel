//! Object identifier value type.
//!
//! `ObjectIdentifier` wraps a `Vec<u32>` of sub-arcs. It supports
//! lexicographic comparison (used by GetNext/GetBulk walks), parsing
//! from `"1.3.6.1.2.1.1.1.0"` strings, and `Display` formatting.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Result};

/// IANA enterprise OID prefix.
pub const ENTERPRISES_PREFIX: [u32; 6] = [1, 3, 6, 1, 4, 1];

/// RFC documentation enterprise subtree as a dotted OID string.
///
/// This is for tests and examples only. Production deployments must use
/// [`enterprise_oid`] with their registered IANA Private Enterprise Number.
pub const DOCUMENTATION_ENTERPRISE_OID: &str = "1.3.6.1.4.1.32473";

/// Builds `1.3.6.1.4.1.<pen>` for the supplied enterprise number.
#[must_use]
pub fn enterprise_oid(pen: u32) -> ObjectIdentifier {
    let mut arcs = ENTERPRISES_PREFIX.to_vec();
    arcs.push(pen);
    ObjectIdentifier::new(arcs)
}

/// Builds the RFC documentation enterprise subtree.
#[must_use]
pub fn documentation_enterprise_oid() -> ObjectIdentifier {
    enterprise_oid(crate::agent::DOCUMENTATION_ENTERPRISE_PEN)
}

/// An ASN.1 OBJECT IDENTIFIER. Internally a `Vec<u32>` of sub-arcs.
///
/// # Examples
///
/// ```
/// use spt_snmp::ObjectIdentifier;
///
/// let a: ObjectIdentifier = "1.3.6.1.2.1.1.1.0".parse().unwrap();
/// let b = ObjectIdentifier::new([1u32, 3, 6, 1, 2, 1, 1, 1, 0]);
/// assert_eq!(a, b);
/// assert_eq!(a.to_string(), "1.3.6.1.2.1.1.1.0");
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ObjectIdentifier {
    arcs: Vec<u32>,
}

impl ObjectIdentifier {
    /// Constructs an OID from any iterable of `u32` arcs.
    pub fn new<I: IntoIterator<Item = u32>>(arcs: I) -> Self {
        Self {
            arcs: arcs.into_iter().collect(),
        }
    }

    /// Returns the OID's sub-arcs as a slice.
    #[must_use]
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Returns the number of sub-arcs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.arcs.len()
    }

    /// Returns `true` if the OID has no sub-arcs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.arcs.is_empty()
    }

    /// Appends a single sub-arc.
    pub fn push(&mut self, arc: u32) {
        self.arcs.push(arc);
    }

    /// Returns a new OID extended by one sub-arc.
    #[must_use]
    pub fn with_suffix(&self, arc: u32) -> Self {
        let mut o = self.clone();
        o.push(arc);
        o
    }

    /// Returns `true` if `self` starts with `prefix`.
    #[must_use]
    pub fn starts_with(&self, prefix: &ObjectIdentifier) -> bool {
        self.arcs.starts_with(&prefix.arcs)
    }
}

impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OID({self})")
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for a in &self.arcs {
            if !first {
                f.write_str(".")?;
            }
            first = false;
            write!(f, "{a}")?;
        }
        Ok(())
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim_start_matches('.');
        let mut arcs = Vec::new();
        for part in s.split('.') {
            let v: u32 = part
                .parse()
                .map_err(|_| Error::Ber(format!("invalid OID arc {part:?}")))?;
            arcs.push(v);
        }
        if arcs.len() < 2 {
            return Err(Error::Ber("OID must have at least 2 arcs".into()));
        }
        Ok(Self { arcs })
    }
}

impl PartialOrd for ObjectIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lexicographic over the sub-arcs (RFC 1905 §4.2.2 walk semantics).
        self.arcs.cmp(&other.arcs)
    }
}

impl From<Vec<u32>> for ObjectIdentifier {
    fn from(v: Vec<u32>) -> Self {
        Self { arcs: v }
    }
}

impl<const N: usize> From<[u32; N]> for ObjectIdentifier {
    fn from(v: [u32; N]) -> Self {
        Self { arcs: v.to_vec() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let a: ObjectIdentifier = "1.3.6.1.2.1".parse().unwrap();
        assert_eq!(a.to_string(), "1.3.6.1.2.1");
        assert_eq!(a.arcs(), &[1, 3, 6, 1, 2, 1]);
    }

    #[test]
    fn lexicographic() {
        let a: ObjectIdentifier = "1.3.6.1.2".parse().unwrap();
        let b: ObjectIdentifier = "1.3.6.1.2.1".parse().unwrap();
        assert!(a < b);
        let c: ObjectIdentifier = "1.3.6.1.3".parse().unwrap();
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn rejects_short() {
        assert!("1".parse::<ObjectIdentifier>().is_err());
        assert!("".parse::<ObjectIdentifier>().is_err());
    }

    #[test]
    fn rejects_invalid_arc() {
        assert!("1.x.3".parse::<ObjectIdentifier>().is_err());
        assert!("1.-2".parse::<ObjectIdentifier>().is_err());
        assert!("1.3..5".parse::<ObjectIdentifier>().is_err());
    }

    #[test]
    fn leading_dot_is_tolerated() {
        let a: ObjectIdentifier = ".1.3.6".parse().unwrap();
        assert_eq!(a.arcs(), &[1, 3, 6]);
    }

    #[test]
    fn push_and_with_suffix() {
        let mut a: ObjectIdentifier = "1.3.6.1".parse().unwrap();
        let b = a.with_suffix(99);
        a.push(99);
        assert_eq!(a, b);
        assert_eq!(a.arcs().last(), Some(&99));
        assert_eq!(a.len(), 5);
    }

    #[test]
    fn is_empty_and_len() {
        let empty = ObjectIdentifier::new(Vec::<u32>::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let two = ObjectIdentifier::new([1u32, 3]);
        assert!(!two.is_empty());
        assert_eq!(two.len(), 2);
    }

    #[test]
    fn starts_with_prefix_and_self() {
        let parent: ObjectIdentifier = "1.3.6.1".parse().unwrap();
        let child: ObjectIdentifier = "1.3.6.1.4.1".parse().unwrap();
        assert!(child.starts_with(&parent));
        assert!(parent.starts_with(&parent));
        assert!(!parent.starts_with(&child));
        let unrelated: ObjectIdentifier = "1.4".parse().unwrap();
        assert!(!child.starts_with(&unrelated));
    }

    #[test]
    fn display_and_debug() {
        let oid: ObjectIdentifier = "1.3.6.1.4.1.32473".parse().unwrap();
        assert_eq!(format!("{oid}"), "1.3.6.1.4.1.32473");
        let dbg = format!("{oid:?}");
        assert!(dbg.starts_with("OID("));
        assert!(dbg.contains("1.3.6.1.4.1.32473"));
    }

    #[test]
    fn from_vec_and_array() {
        let from_vec = ObjectIdentifier::from(vec![1u32, 3, 6]);
        let from_arr: ObjectIdentifier = ObjectIdentifier::from([1u32, 3, 6]);
        assert_eq!(from_vec, from_arr);
    }

    #[test]
    fn enterprise_oid_helpers() {
        let e = enterprise_oid(99);
        assert_eq!(e.arcs(), &[1, 3, 6, 1, 4, 1, 99]);
        let doc = documentation_enterprise_oid();
        assert!(doc.starts_with(&enterprise_oid(crate::agent::DOCUMENTATION_ENTERPRISE_PEN)));
    }

    #[test]
    fn partial_cmp_matches_cmp() {
        let a: ObjectIdentifier = "1.3.6.1".parse().unwrap();
        let b: ObjectIdentifier = "1.3.6.2".parse().unwrap();
        assert_eq!(a.partial_cmp(&b), Some(core::cmp::Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(core::cmp::Ordering::Greater));
        assert_eq!(a.partial_cmp(&a.clone()), Some(core::cmp::Ordering::Equal));
    }

    #[test]
    fn hash_eq_consistency() {
        use std::collections::HashSet;
        let mut s = HashSet::new();
        s.insert(ObjectIdentifier::new([1u32, 3, 6]));
        assert!(s.contains(&ObjectIdentifier::from(vec![1u32, 3, 6])));
    }
}
