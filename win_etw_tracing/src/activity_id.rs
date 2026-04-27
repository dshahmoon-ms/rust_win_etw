//! ETW activity ID handling: extraction from `tracing` span attributes and
//! fallback to the current thread's ETW activity ID.

use core::fmt;
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use win_etw_provider::{Error, GUID};

/// Wraps an ETW activity ID `GUID`. Stored in the `tracing` span extensions
/// so descendant spans/events can pick it up as their related activity ID.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActivityId(pub(crate) GUID);

impl ActivityId {
    pub(crate) fn from_current_thread() -> Result<Self, Error> {
        Ok(Self(win_etw_provider::get_current_thread_activity_id()?))
    }
}

/// Visitor that pulls an `activity_id` field out of span attributes, parsing
/// its `Debug` representation as a GUID.
struct ActivityIdVisitor {
    value: Option<GUID>,
}

impl Visit for ActivityIdVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "activity_id" {
            let debug_str = format!("{:?}", value);
            self.value = GUID::try_from(debug_str.as_str()).ok();
        }
    }
}

/// Returns the GUID supplied via an `activity_id = ...` field on a span, if
/// present and parseable.
pub(crate) fn extract_activity_id_attr(attrs: &Attributes<'_>) -> Option<GUID> {
    let mut visitor = ActivityIdVisitor { value: None };
    attrs.record(&mut visitor);
    visitor.value
}
