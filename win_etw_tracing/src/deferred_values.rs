//! Defers `Span::record` values until the span closes.
//!
//! Ideally we would emit each `record` as another event and the analysis
//! tools would aggregate them, but WPA and friends don't.

use core::fmt;
use tracing::field::{Field, Visit};

#[derive(Default)]
pub(crate) struct DeferredValues {
    values: Vec<(Field, DeferredValue)>,
}

impl DeferredValues {
    fn update(&mut self, field: &Field, value: DeferredValue) {
        for (f, v) in &mut self.values {
            if f == field {
                *v = value;
                return;
            }
        }
        self.values.push((field.clone(), value));
    }

    pub(crate) fn record(&self, visit: &mut dyn Visit) {
        for (field, v) in &self.values {
            match v {
                DeferredValue::Unsigned(v) => visit.record_u64(field, *v),
                DeferredValue::Signed(v) => visit.record_i64(field, *v),
                DeferredValue::Boolean(v) => visit.record_bool(field, *v),
                DeferredValue::String(v) => visit.record_str(field, v),
            }
        }
    }
}

impl Visit for DeferredValues {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.update(field, DeferredValue::String(format!("{value:?}")));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.update(field, DeferredValue::Signed(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.update(field, DeferredValue::Unsigned(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.update(field, DeferredValue::Boolean(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.update(field, DeferredValue::String(value.to_string()));
    }
}

enum DeferredValue {
    Unsigned(u64),
    Signed(i64),
    Boolean(bool),
    String(String),
}
