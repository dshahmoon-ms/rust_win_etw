//! Public configuration types for [`crate::TracelogSubscriber`]: keyword
//! rules, field aliases, and global fields. Plus the internal
//! [`GlobalsBlob`] cache built from a `&[GlobalField]`.

use bytes::BufMut;
use win_etw_metadata::{InFlag, OutFlag};

/// Set of `tracing` levels at which a [`KeywordRule`] applies. Combine variants with `|`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LevelSet(u8);

impl LevelSet {
    pub const ERROR: LevelSet = LevelSet(1 << 0);
    pub const WARN: LevelSet = LevelSet(1 << 1);
    pub const INFO: LevelSet = LevelSet(1 << 2);
    pub const DEBUG: LevelSet = LevelSet(1 << 3);
    pub const TRACE: LevelSet = LevelSet(1 << 4);
    pub const ALL: LevelSet = LevelSet(0b0001_1111);

    pub const fn empty() -> Self {
        LevelSet(0)
    }

    pub const fn contains(self, other: LevelSet) -> bool {
        (self.0 & other.0) == other.0
    }

    pub(crate) fn from_level(level: tracing::Level) -> Self {
        match level {
            tracing::Level::ERROR => Self::ERROR,
            tracing::Level::WARN => Self::WARN,
            tracing::Level::INFO => Self::INFO,
            tracing::Level::DEBUG => Self::DEBUG,
            tracing::Level::TRACE => Self::TRACE,
        }
    }
}

impl std::ops::BitOr for LevelSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        LevelSet(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for LevelSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A keyword OR'd into the ETW event keyword whenever the event's level is
/// in [`KeywordRule::levels`]. Multiple rules accumulate.
///
/// # Examples
/// ```ignore
/// // Always-on classification:
/// subscriber.add_keyword(KeywordRule { keyword: 0x1, levels: LevelSet::ALL });
///
/// // ETW collapses DEBUG and TRACE to VERBOSE; this keeps them distinguishable:
/// subscriber.add_keyword(KeywordRule { keyword: 0x10, levels: LevelSet::TRACE });
/// ```
#[derive(Debug, Clone, Copy)]
pub struct KeywordRule {
    pub keyword: u64,
    pub levels: LevelSet,
}

/// Renames an ETW field at write time. Any field that would have been emitted
/// under `from` is emitted under `to` instead. The value is unchanged.
///
/// Aliases apply to user-supplied fields, the implicit `message` field, and
/// the auto-emitted `target` field. They do **not** apply to global fields
/// (those are written verbatim).
#[derive(Debug, Clone)]
pub struct FieldAlias {
    pub from: String,
    pub to: String,
}

impl FieldAlias {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

/// A constant key/value field included in every event emitted by the subscriber.
#[derive(Debug, Clone)]
pub struct GlobalField {
    pub name: String,
    pub value: String,
}

impl GlobalField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Pre-rendered metadata + data bytes for the global fields. Built once per
/// `set_global_fields` call and concatenated as-is into every event.
#[derive(Default, Clone)]
pub(crate) struct GlobalsBlob {
    pub(crate) metadata: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

impl GlobalsBlob {
    pub(crate) fn from_fields(fields: &[GlobalField]) -> Self {
        let mut blob = Self::default();
        for f in fields {
            blob.metadata.put_slice(f.name.as_bytes());
            blob.metadata.put_u8(0); // null terminator
            blob.metadata
                .put_u8((InFlag::ANSI_STRING | InFlag::CHAIN_FLAG).bits());
            blob.metadata.put_u8(OutFlag::UTF8.bits());
            blob.data.extend_from_slice(f.value.as_bytes());
            blob.data.put_u8(0); // null terminator
        }
        blob
    }
}