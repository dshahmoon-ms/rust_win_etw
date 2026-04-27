//! Keyword vocabulary: which `tracing` levels contribute which keyword bits.

/// Set of `tracing` levels at which a [`KeywordRule`] applies. Combine
/// variants with `|`.
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
