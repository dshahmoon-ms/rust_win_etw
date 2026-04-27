//! Per-event payload builder and constant global-field blob.

use bytes::BufMut;
use core::fmt;
use std::io::Write;
use tracing::field::{Field, Visit};
use win_etw_metadata::{InFlag, OutFlag};

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

/// A constant key/value field included in every event emitted by the
/// subscriber.
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

/// Per-event payload builder. Borrows the alias slice from the subscriber so
/// no per-event cloning is required.
pub(crate) struct EventData<'a> {
    pub(crate) metadata: Vec<u8>,
    pub(crate) data: Vec<u8>,
    aliases: &'a [FieldAlias],
}

impl<'a> EventData<'a> {
    pub(crate) fn new(aliases: &'a [FieldAlias]) -> Self {
        Self {
            metadata: Vec::new(),
            data: Vec::new(),
            aliases,
        }
    }

    /// Resolves a field name through the alias table. Returns the renamed
    /// name if `name` is aliased, or `name` unchanged otherwise.
    pub(crate) fn resolve(&self, name: &'a str) -> &'a str {
        for a in self.aliases {
            if a.from == name {
                return a.to.as_str();
            }
        }
        name
    }

    /// Writes the resolved field name + null terminator. Returns `false` if
    /// the field should be skipped (only used for the `tracing-log`
    /// passthrough fields).
    fn write_name(&mut self, name: &str) -> bool {
        if cfg!(feature = "tracing-log") && name.starts_with("log.") {
            return false;
        }
        // Split-borrow: resolve via `&self.aliases`, write via `&mut self.metadata`.
        let aliases = self.aliases;
        let metadata = &mut self.metadata;
        let resolved: &str = aliases
            .iter()
            .find(|a| a.from == name)
            .map(|a| a.to.as_str())
            .unwrap_or(name);
        metadata.put_slice(resolved.as_bytes());
        metadata.put_u8(0);
        true
    }
}

impl<'a> Visit for EventData<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.write_name(field.name()) {
            self.metadata
                .put_u8((InFlag::ANSI_STRING | InFlag::CHAIN_FLAG).bits());
            self.metadata.put_u8(OutFlag::UTF8.bits());
            let _ = write!(&mut self.data, "{value:?}\0");
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if self.write_name(field.name()) {
            self.metadata.put_u8(InFlag::INT64.bits());
            self.data.put_i64_le(value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if self.write_name(field.name()) {
            self.metadata
                .put_u8((InFlag::UINT64 | InFlag::CHAIN_FLAG).bits());
            self.metadata.put_u8(OutFlag::HEX.bits());
            self.data.put_u64_le(value);
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if self.write_name(field.name()) {
            self.metadata.put_u8(InFlag::UINT8.bits());
            self.metadata.put_u8(OutFlag::BOOLEAN.bits());
            self.data.put_u8(value.into());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if self.write_name(field.name()) {
            self.metadata
                .put_u8((InFlag::ANSI_STRING | InFlag::CHAIN_FLAG).bits());
            self.metadata.put_u8(OutFlag::UTF8.bits());
            self.data.extend_from_slice(value.as_bytes());
            self.data.put_u8(0);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if self.write_name(field.name()) {
            self.metadata
                .put_u8((InFlag::ANSI_STRING | InFlag::CHAIN_FLAG).bits());
            self.metadata.put_u8(OutFlag::UTF8.bits());
            let _ = write!(&mut self.data, "{value}");
            let mut source = value.source();
            while let Some(v) = source.take() {
                let _ = write!(&mut self.data, ": {v}");
                source = v.source();
            }
            self.data.put_u8(0);
        }
    }
}
