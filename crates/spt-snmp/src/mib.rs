//! MIB binding registry: OID → handler dispatch.
//!
//! - [`Handler`] handles a single scalar OID (Get/Set).
//! - [`TableHandler`] supports tables with lexicographic GetNext/GetBulk
//!   walks via a [`TableHandler::next`] cursor.
//!
//! The registry is shared between the `Get`/`Set` and `GetNext`/`GetBulk`
//! agent code paths; it owns the OID-keyed mapping in a `BTreeMap` so the
//! GetNext walk operates in O(log n).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::oid::ObjectIdentifier;
use crate::pdu::ErrorStatus;
use crate::value::Value;

/// Outcome of a `Set` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOutcome {
    /// Set succeeded; the new value is now live.
    Ok,
    /// The target is read-only.
    NotWritable,
    /// The supplied value is not acceptable for this object.
    WrongValue,
    /// Some other error occurred.
    GenErr,
}

impl SetOutcome {
    /// Maps to a PDU `error-status`.
    #[must_use]
    pub fn to_error_status(self) -> ErrorStatus {
        match self {
            Self::Ok => ErrorStatus::NoError,
            Self::NotWritable => ErrorStatus::NotWritable,
            Self::WrongValue => ErrorStatus::WrongValue,
            Self::GenErr => ErrorStatus::GenErr,
        }
    }
}

/// Handler for a scalar (`.0`-suffixed) MIB object.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// Returns the current value of the object.
    async fn get(&self) -> Result<Value>;

    /// Sets the object. Default: not writable.
    async fn set(&self, _value: Value) -> SetOutcome {
        SetOutcome::NotWritable
    }
}

/// Trait for tables (and other walkable subtrees).
///
/// Implementors are expected to know their full subtree and answer the
/// `next(after)` query in lexicographic order. `after` is `None` on the
/// first GetNext into the table.
#[async_trait]
pub trait TableHandler: Send + Sync + 'static {
    /// Given an OID strictly greater than `after` (or the first OID in the
    /// table when `after` is `None`), returns it together with its value.
    /// Returns `None` once the walk reaches the end of the table.
    async fn next(
        &self,
        after: Option<&ObjectIdentifier>,
    ) -> Result<Option<(ObjectIdentifier, Value)>>;

    /// Performs an exact-instance Get. Default: walk to find a match.
    async fn get(&self, oid: &ObjectIdentifier) -> Result<Option<Value>> {
        // Default O(n) implementation using `next`.
        let mut cur: Option<ObjectIdentifier> = None;
        loop {
            match self.next(cur.as_ref()).await? {
                None => return Ok(None),
                Some((found, v)) => {
                    if found == *oid {
                        return Ok(Some(v));
                    }
                    if found > *oid {
                        return Ok(None);
                    }
                    cur = Some(found);
                }
            }
        }
    }
}

/// A read-only scalar that always returns the same value.
///
/// # Examples
///
/// ```
/// # use spt_snmp::{ConstScalar, Value, ObjectIdentifier, MibRegistry};
/// let reg = MibRegistry::new();
/// // ... configure scalars ...
/// # let _ = ConstScalar::new(Value::Integer(42));
/// # let _ = reg;
/// # let _: ObjectIdentifier = "1.3.6.1.4.1.32473.1".parse().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ConstScalar {
    value: Value,
}

impl ConstScalar {
    /// Creates a new constant scalar.
    #[must_use]
    pub fn new(value: Value) -> Self {
        Self { value }
    }
}

#[async_trait]
impl Handler for ConstScalar {
    async fn get(&self) -> Result<Value> {
        Ok(self.value.clone())
    }
}

/// MIB registry: OID-keyed lookup of scalar and table handlers.
#[derive(Default)]
pub struct MibRegistry {
    scalars: BTreeMap<ObjectIdentifier, Arc<dyn Handler>>,
    tables: BTreeMap<ObjectIdentifier, Arc<dyn TableHandler>>,
}

impl std::fmt::Debug for MibRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MibRegistry")
            .field("scalar_count", &self.scalars.len())
            .field("table_count", &self.tables.len())
            .finish()
    }
}

impl MibRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a scalar handler at the exact OID (must include the trailing
    /// `.0` per SNMP convention).
    pub fn add_scalar<H: Handler>(&mut self, oid: ObjectIdentifier, handler: H) {
        self.scalars.insert(oid, Arc::new(handler));
    }

    /// Registers a table handler rooted at the given OID prefix.
    pub fn add_table<H: TableHandler>(&mut self, oid: ObjectIdentifier, handler: H) {
        self.tables.insert(oid, Arc::new(handler));
    }

    /// Returns the scalar handler at exactly `oid`, if any.
    #[must_use]
    pub fn scalar(&self, oid: &ObjectIdentifier) -> Option<Arc<dyn Handler>> {
        self.scalars.get(oid).cloned()
    }

    /// Looks up the table prefix that *contains* `oid`, if any.
    #[must_use]
    pub fn table_for(
        &self,
        oid: &ObjectIdentifier,
    ) -> Option<(ObjectIdentifier, Arc<dyn TableHandler>)> {
        for (prefix, handler) in &self.tables {
            if oid.starts_with(prefix) {
                return Some((prefix.clone(), handler.clone()));
            }
        }
        None
    }

    /// Performs a Get for `oid`, consulting scalars first then tables.
    pub async fn get(&self, oid: &ObjectIdentifier) -> Result<Option<Value>> {
        if let Some(h) = self.scalar(oid) {
            return Ok(Some(h.get().await?));
        }
        if let Some((_, table)) = self.table_for(oid) {
            return table.get(oid).await;
        }
        Ok(None)
    }

    /// Computes the lexicographic successor of `after` for a GetNext / GetBulk
    /// walk. Returns `None` if `after` is at or beyond the last managed OID.
    pub async fn next(
        &self,
        after: &ObjectIdentifier,
    ) -> Result<Option<(ObjectIdentifier, Value)>> {
        // Strict-greater scalar successor.
        let scalar_next = self
            .scalars
            .range(after.clone()..)
            .find(|(k, _)| *k > after)
            .map(|(k, h)| (k.clone(), h.clone()));

        // Strict-greater table successor: ask each table for `next(after)`.
        let mut best: Option<(ObjectIdentifier, Value)> = None;
        for (prefix, table) in &self.tables {
            // Skip tables whose entire range is below `after`.
            // (We pass `after` directly; tables are responsible for returning
            //  an OID strictly greater than `after`.)
            let cursor: Option<&ObjectIdentifier> = if after.starts_with(prefix) || prefix > after {
                if prefix > after {
                    // We want anything from this table — pass `None`.
                    None
                } else {
                    Some(after)
                }
            } else {
                continue;
            };
            if let Some((oid, v)) = table.next(cursor).await? {
                if oid > *after {
                    match &best {
                        None => best = Some((oid, v)),
                        Some((b, _)) if oid < *b => best = Some((oid, v)),
                        _ => {}
                    }
                }
            }
        }

        // Combine scalar and table results, take the smallest strictly-greater.
        let scalar_resolved = match scalar_next {
            Some((oid, h)) => Some((oid, h.get().await?)),
            None => None,
        };
        Ok(match (scalar_resolved, best) {
            (Some((so, sv)), Some((to, tv))) => {
                if so <= to {
                    Some((so, sv))
                } else {
                    Some((to, tv))
                }
            }
            (Some(s), None) => Some(s),
            (None, Some(t)) => Some(t),
            (None, None) => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(s: &str) -> ObjectIdentifier {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn scalar_get() {
        let mut reg = MibRegistry::new();
        reg.add_scalar(
            oid("1.3.6.1.4.1.32473.1.0"),
            ConstScalar::new(Value::Integer(7)),
        );
        let v = reg.get(&oid("1.3.6.1.4.1.32473.1.0")).await.unwrap();
        assert_eq!(v, Some(Value::Integer(7)));
        let v = reg.get(&oid("1.3.6.1.4.1.32473.2.0")).await.unwrap();
        assert_eq!(v, None);
    }

    #[tokio::test]
    async fn lexicographic_next_scalars() {
        let mut reg = MibRegistry::new();
        reg.add_scalar(
            oid("1.3.6.1.4.1.32473.1.0"),
            ConstScalar::new(Value::Integer(1)),
        );
        reg.add_scalar(
            oid("1.3.6.1.4.1.32473.2.0"),
            ConstScalar::new(Value::Integer(2)),
        );
        reg.add_scalar(
            oid("1.3.6.1.4.1.32473.3.0"),
            ConstScalar::new(Value::Integer(3)),
        );

        let n = reg
            .next(&oid("1.3.6.1.4.1.32473.1.0"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n.0, oid("1.3.6.1.4.1.32473.2.0"));

        let n = reg.next(&oid("1.3.6.1.4.1.32473.3.0")).await.unwrap();
        assert!(n.is_none());

        // First in the tree
        let n = reg.next(&oid("1.3.6.1.4.1.32472")).await.unwrap().unwrap();
        assert_eq!(n.0, oid("1.3.6.1.4.1.32473.1.0"));
    }
}
