// Copyright (C) Microsoft Corporation. All rights reserved.

//! Subscriber for tracing events that emits Windows ETW tracelogging events.
#![cfg(windows)]
#![forbid(unsafe_code)]

use bytes::BufMut;
use core::fmt;
use std::io::Write;
use std::sync::Arc;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::span::Attributes;
use tracing::span::Record;
use tracing::Event;
use tracing::Id;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use win_etw_metadata::InFlag;
use win_etw_metadata::OutFlag;
use win_etw_provider::Error;
use win_etw_provider::EtwProvider;
use win_etw_provider::EventDataDescriptor;
use win_etw_provider::EventDescriptor;
use win_etw_provider::EventOptions;
use win_etw_provider::Provider;
use win_etw_provider::GUID;

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

    fn from_level(level: tracing::Level) -> Self {
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
struct GlobalsBlob {
    metadata: Vec<u8>,
    data: Vec<u8>,
}

impl GlobalsBlob {
    fn from_fields(fields: &[GlobalField]) -> Self {
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

/// An implementation for [`tracing_subscriber::Layer`] that emits tracelogging
/// events.
pub struct TracelogSubscriber {
    provider: EtwProvider,
    /// Provider metadata bytes. Registered once with ETW (so xperf, TDH,
    /// etc. can discover the provider schema) and emitted as the first data
    /// descriptor on every event.
    provider_metadata: Vec<u8>,
    keyword_mask: u64,
    keyword_rules: Vec<KeywordRule>,
    global_fields: GlobalsBlob,
    /// Held as `Arc<[FieldAlias]>` so the per-event hot path
    /// avoids allocating; `set_field_alias` rebuilds the Arc (cold path).
    field_aliases: Arc<[FieldAlias]>,
}

impl TracelogSubscriber {
    /// Creates a new subscriber with provider ID `id` and provider name `name`.
    pub fn new(id: impl Into<GUID>, name: &str) -> Result<Self, Error> {
        let mut provider_metadata = Vec::new();
        provider_metadata.put_u16_le(
            (2 + name.len() + 1)
                .try_into()
                .expect("provider name too long"),
        );
        provider_metadata.put_slice(name.as_bytes());
        provider_metadata.put_u8(0);

        let mut provider = EtwProvider::new(&id.into())?;
        provider.register_provider_metadata(provider_metadata.as_slice())?;
        Ok(Self {
            provider,
            provider_metadata,
            keyword_mask: !0_u64,
            keyword_rules: Vec::new(),
            global_fields: GlobalsBlob::default(),
            field_aliases: Arc::from(Vec::<FieldAlias>::new()),
        })
    }

    // If some events are by default marked with telemetry keywords, this allows an opt out.
    pub fn enable_telemetry_events(&mut self, enabled: bool) {
        self.keyword_mask = if enabled {
            !0_u64
        } else {
            !(win_etw_metadata::MICROSOFT_KEYWORD_CRITICAL_DATA
                | win_etw_metadata::MICROSOFT_KEYWORD_MEASURES
                | win_etw_metadata::MICROSOFT_KEYWORD_TELEMETRY)
        };
    }

    /// Adds a [`KeywordRule`]. Multiple rules accumulate (their keywords are
    /// OR'd together for any event whose level is in the rule's level set).
    pub fn add_keyword(&mut self, rule: KeywordRule) {
        self.keyword_rules.push(rule);
    }

    /// Global fields are automatically included in all events emitted by this
    /// layer. They can be set at the time of layer creation, or by using
    /// [`tracing_subscriber::reload`] to dynamically reconfigure a registered
    /// layer. Note that if the subscriber is registered as the [global
    /// default](tracing::dispatcher#setting-the-default-subscriber), thesee
    /// fields will be global to the entire process.
    ///
    /// # Example
    /// ```
    /// # use win_etw_tracing::{TracelogSubscriber, GlobalField};
    /// # use win_etw_provider::GUID;
    /// # let provider_guid = GUID {
    /// #     data1: 0xe1c71d95,
    /// #     data2: 0x7bbc,
    /// #     data3: 0x5f48,
    /// #     data4: [0xa9, 0x2b, 0x8a, 0xaa, 0x0b, 0x52, 0x91, 0x58],
    /// # };
    /// let mut layer = TracelogSubscriber::new(provider_guid, "provider_name").unwrap();
    /// let globals = vec![GlobalField::new("field name", "my value")];
    /// layer.set_global_fields(&globals);
    /// ```
    pub fn set_global_fields(&mut self, fields: &[GlobalField]) {
        self.global_fields = GlobalsBlob::from_fields(fields);
    }

    /// Adds (or replaces) a field rename. See [`FieldAlias`].
    pub fn set_field_alias(&mut self, alias: FieldAlias) {
        let mut aliases: Vec<FieldAlias> = self.field_aliases.iter().cloned().collect();
        if let Some(slot) = aliases.iter_mut().find(|a| a.from == alias.from) {
            slot.to = alias.to;
        } else {
            aliases.push(alias);
        }
        self.field_aliases = Arc::from(aliases);
    }

    fn resolve_keyword(&self, level: tracing::Level) -> u64 {
        let bit = LevelSet::from_level(level);
        let mut k = 0u64;
        for r in &self.keyword_rules {
            if r.levels.contains(bit) {
                k |= r.keyword;
            }
        }
        k & self.keyword_mask
    }
}

impl TracelogSubscriber {
    fn write_event(
        &self,
        opcode: u8,
        options: &EventOptions,
        write_target: bool,
        meta: &Metadata<'_>,
        write_name: impl FnOnce(&mut Vec<u8>),
        record: impl FnOnce(&mut EventData<'_>),
    ) {
        let level = match *meta.level() {
            tracing::Level::ERROR => win_etw_metadata::Level::ERROR,
            tracing::Level::WARN => win_etw_metadata::Level::WARN,
            tracing::Level::INFO => win_etw_metadata::Level::INFO,
            tracing::Level::DEBUG | tracing::Level::TRACE => win_etw_metadata::Level::VERBOSE,
        };

        let event_descriptor = EventDescriptor {
            id: 0,
            version: 0,
            channel: 11, // this value tells older versions of ETW that this is a tracelogging event
            level,
            opcode,
            task: 0,
            keyword: self.resolve_keyword(*meta.level()),
        };

        if !self.provider.is_event_enabled(&event_descriptor) {
            return;
        }

        let mut event_data = EventData::new(&self.field_aliases);
        event_data.metadata.put_u16_le(0); // reserve space for the size
        event_data.metadata.put_u8(0); // no extensions
        write_name(&mut event_data.metadata);
        event_data.metadata.put_u8(0); // null terminator

        let target_len = if write_target {
            let target_name = event_data.resolve("target");
            event_data.metadata.put_slice(target_name.as_bytes());
            event_data.metadata.put_u8(0); // null terminator
            event_data
                .metadata
                .put_u8((InFlag::COUNTED_ANSI_STRING | InFlag::CHAIN_FLAG).bits());
            event_data.metadata.put_u8(OutFlag::UTF8.bits());
            meta.target().len() as u16
        } else {
            0
        };

        event_data
            .metadata
            .put_slice(self.global_fields.metadata.as_slice());
        event_data
            .data
            .put_slice(self.global_fields.data.as_slice());
        record(&mut event_data);

        // Update the length.
        let event_metadata_len = event_data.metadata.len() as u16;
        (&mut event_data.metadata[0..2]).put_u16_le(event_metadata_len);

        // TraceLogging events require both the provider-metadata and
        // per-event-metadata data descriptors at the head of the payload
        let (data_descriptors_with_target, data_descriptors_without_target);
        let data_descriptors = if write_target {
            data_descriptors_with_target = [
                EventDataDescriptor::for_provider_metadata(self.provider_metadata.as_slice()),
                EventDataDescriptor::for_event_metadata(event_data.metadata.as_slice()),
                EventDataDescriptor::from(&target_len),
                EventDataDescriptor::from(meta.target()),
                EventDataDescriptor::for_bytes(&event_data.data),
            ];
            &data_descriptors_with_target[..]
        } else {
            data_descriptors_without_target = [
                EventDataDescriptor::for_provider_metadata(self.provider_metadata.as_slice()),
                EventDataDescriptor::for_event_metadata(event_data.metadata.as_slice()),
                EventDataDescriptor::for_bytes(&event_data.data),
            ];
            &data_descriptors_without_target[..]
        };
        self.provider
            .write(Some(options), &event_descriptor, data_descriptors);
    }
}

#[derive(Debug, Clone, Default)]
struct ActivityId(GUID);

impl ActivityId {
    #[allow(dead_code)]
    fn new() -> Result<Self, Error> {
        Ok(Self(win_etw_provider::new_activity_id()?))
    }

    fn from_current_thread() -> Result<Self, Error> {
        Ok(Self(win_etw_provider::get_current_thread_activity_id()?))
    }
}

struct ActivityIdVisitor {
    value: Option<GUID>,
}

impl Visit for ActivityIdVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "activity_id" {
            // Parse the GUID debug string
            let debug_str = format!("{:?}", value);
            self.value = GUID::try_from(debug_str.as_str()).ok();
        }
    }
}

/// Extracts the "activity_id" field from span attributes.
/// Returns None if the field is missing.
fn extract_activity_id_attr(attrs: &Attributes<'_>) -> Option<GUID> {
    let mut visitor = ActivityIdVisitor { value: None };
    attrs.record(&mut visitor);
    visitor.value
}

const WINEVENT_OPCODE_INFO: u8 = 0;
const WINEVENT_OPCODE_START: u8 = 1;
const WINEVENT_OPCODE_STOP: u8 = 2;

impl<S: Subscriber> Layer<S> for TracelogSubscriber
where
    S: for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        // Extract "activity_id" from attributes
        let activity_id = extract_activity_id_attr(attrs)
            .map(ActivityId)
            .unwrap_or_else(|| {
                // If not provided, get the current thread's activity ID
                ActivityId::from_current_thread().unwrap_or_default()
            });

        let related_activity_id = {
            if attrs.is_contextual() {
                ctx.current_span().id().cloned()
            } else {
                attrs.parent().cloned()
            }
            .and_then(|id| {
                ctx.span(&id)
                    .unwrap()
                    .extensions()
                    .get::<ActivityId>()
                    .cloned()
            })
            .map(|x| x.0)
        };

        // Store the activity ID on the span to look up later.
        ctx.span(id)
            .unwrap()
            .extensions_mut()
            .insert(activity_id.clone());

        let name = attrs.metadata().name();
        self.write_event(
            WINEVENT_OPCODE_START,
            &EventOptions {
                activity_id: Some(activity_id.0),
                related_activity_id,
                ..Default::default()
            },
            true,
            attrs.metadata(),
            |metadata| metadata.extend_from_slice(name.as_bytes()),
            |event_data| attrs.record(event_data as &mut dyn Visit),
        );
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        // Defer the recorded value until on_close is called. Ideally we would
        // just log the additional data as another event and the data would be
        // aggregated with the rest of the activity's data, but WPA and other
        // analysis tools don't actually handle this.
        let span = ctx.span(id).unwrap();
        let mut extensions = span.extensions_mut();
        let deferred = if let Some(deferred) = extensions.get_mut::<DeferredValues>() {
            deferred
        } else {
            extensions.insert(DeferredValues::default());
            extensions.get_mut().unwrap()
        };
        values.record(deferred);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        #[cfg(feature = "tracing-log")]
        let normalized_meta = tracing_log::NormalizeEvent::normalized_metadata(event);
        #[cfg(feature = "tracing-log")]
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());
        #[cfg(not(feature = "tracing-log"))]
        let meta = event.metadata();

        let activity_id = ctx
            .event_span(event)
            .and_then(|span| span.extensions().get::<ActivityId>().cloned().map(|x| x.0));

        let event_name = meta.name();

        self.write_event(
            WINEVENT_OPCODE_INFO,
            &EventOptions {
                activity_id,
                ..Default::default()
            },
            true,
            meta,
            |metadata| metadata.extend_from_slice(event_name.as_bytes()),
            |event_data| {
                event.record(event_data as &mut dyn Visit);
            },
        );
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).unwrap();
        let extensions = span.extensions();
        let ActivityId(activity_id) = extensions.get::<ActivityId>().cloned().unwrap();
        let values = extensions.get::<DeferredValues>();
        let name = span.metadata().name();
        self.write_event(
            WINEVENT_OPCODE_STOP,
            &EventOptions {
                activity_id: Some(activity_id),
                ..Default::default()
            },
            false,
            span.metadata(),
            |metadata| metadata.extend_from_slice(name.as_bytes()),
            |event_data| {
                if let Some(values) = values {
                    values.record(event_data as &mut dyn Visit)
                };
            },
        );
    }
}

/// Collection of deferred values to log when the span is closed.
#[derive(Default)]
struct DeferredValues {
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

    fn record(&self, visit: &mut dyn Visit) {
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

/// Per-event payload builder. Borrows the alias slice from the subscriber so
/// no per-event cloning is required.
struct EventData<'a> {
    metadata: Vec<u8>,
    data: Vec<u8>,
    aliases: &'a [FieldAlias],
}

impl<'a> EventData<'a> {
    fn new(aliases: &'a [FieldAlias]) -> Self {
        Self {
            metadata: Vec::new(),
            data: Vec::new(),
            aliases,
        }
    }

    /// Resolves a field name through the alias table. Returns the renamed
    /// name if `name` is aliased, or `name` unchanged otherwise.
    fn resolve(&self, name: &'a str) -> &'a str {
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
            self.data.extend(value.as_bytes());
            self.data.put_u8(0); // null terminator
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
            self.data.put_u8(0); // null terminator
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::reload;
    use tracing_subscriber::Registry;

    static PROVIDER_GUID: GUID = GUID {
        data1: 0xe1c71d95,
        data2: 0x7bbc,
        data3: 0x5f48,
        data4: [0xa9, 0x2b, 0x8a, 0xaa, 0x0b, 0x52, 0x91, 0x58],
    };

    static PROVIDER_NAME: &str = "rust-test-provider";

    #[test]
    fn basic() {
        let layer = TracelogSubscriber::new(PROVIDER_GUID.clone(), PROVIDER_NAME).unwrap();
        let _x = Registry::default().with(layer).set_default();
        tracing::info!(foo = 123, bar = 456, "hi {baz}", baz = "what");
        tracing::error!(foo = true, bar = ?PROVIDER_GUID);
        let err = anyhow::anyhow!("failed")
            .context("really failed")
            .context("this thing failed");
        tracing::error!(error = &*err as &dyn std::error::Error, "disaster");
    }

    #[test]
    fn span() {
        let layer = TracelogSubscriber::new(PROVIDER_GUID.clone(), PROVIDER_NAME).unwrap();
        let _x = Registry::default().with(layer).set_default();
        tracing::info_span!("geo", bar = 456).in_scope(|| {
            let span = tracing::info_span!("dude", baz = 789, later = tracing::field::Empty);
            span.in_scope(|| {
                tracing::info!("test");
                span.record("later", true);
                span.record("later", "wait no it's a string now");
            });
        });
    }

    #[test]
    fn global() {
        let (layer, reload_handle) = reload::Layer::new(
            TracelogSubscriber::new(PROVIDER_GUID.clone(), PROVIDER_NAME).unwrap(),
        );
        let _x = Registry::default().with(layer).set_default();
        tracing::info!(a_field = 123, "test globals");
        let global = vec![GlobalField::new("global", "some value")];
        reload_handle
            .modify(|layer| layer.set_global_fields(&global))
            .unwrap();
        tracing::info!(a_field = 456, "test globals modify");
        let _s = tracing::info_span!("span with globals", span_field = "abc").entered();
        let global = vec![
            GlobalField::new("global", "new value"),
            GlobalField::new("global2", "value"),
        ];
        reload_handle
            .modify(|layer| layer.set_global_fields(&global))
            .unwrap();
        tracing::info!(a_field = 789, "test globals modify again");
    }

    #[test]
    fn aliases() {
        let mut layer = TracelogSubscriber::new(PROVIDER_GUID.clone(), PROVIDER_NAME).unwrap();
        layer.set_field_alias(FieldAlias::new("target", "TaskName"));
        layer.set_field_alias(FieldAlias::new("message", "msg"));
        let _x = Registry::default().with(layer).set_default();
        tracing::info!(foo = 1, "hello world");
    }

    #[test]
    fn keyword_rules() {
        let mut layer = TracelogSubscriber::new(PROVIDER_GUID.clone(), PROVIDER_NAME).unwrap();
        layer.add_keyword(KeywordRule {
            keyword: 0x1,
            levels: LevelSet::ALL,
        });
        layer.add_keyword(KeywordRule {
            keyword: 0x10,
            levels: LevelSet::TRACE | LevelSet::DEBUG,
        });
        assert_eq!(layer.resolve_keyword(tracing::Level::INFO), 0x1);
        assert_eq!(layer.resolve_keyword(tracing::Level::TRACE), 0x11);
        assert_eq!(layer.resolve_keyword(tracing::Level::DEBUG), 0x11);
    }
}