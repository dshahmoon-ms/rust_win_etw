//! `TracelogSubscriber` and its `tracing_subscriber::Layer` implementation.

use bytes::BufMut;
use std::sync::Arc;
use tracing::field::Visit;
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use win_etw_metadata::{InFlag, OutFlag};
use win_etw_provider::{
    Error, EtwProvider, EventDataDescriptor, EventDescriptor, EventOptions, Provider, GUID,
};

use crate::activity_id::{extract_activity_id_attr, ActivityId};
use crate::deferred_values::DeferredValues;
use crate::event_writer::{EventData, FieldAlias, GlobalField, GlobalsBlob};
use crate::keyword::{KeywordRule, LevelSet};

/// `tracing_subscriber::Layer` that emits real ETW TraceLogging events.
pub struct TracelogSubscriber {
    provider: EtwProvider,
    /// Provider metadata bytes. Registered once with ETW (so xperf, TDH,
    /// etc. can discover the provider schema) and emitted as the first data
    /// descriptor on every event.
    provider_metadata: Vec<u8>,
    keyword_mask: u64,
    /// Per-level keyword contributions. OR'd together for every event whose
    /// level is in the rule's level set.
    keyword_rules: Vec<KeywordRule>,

    /// Pre-rendered metadata + data blob for the constant global fields.
    global_fields: GlobalsBlob,

    /// Field renames. Held as `Arc<[FieldAlias]>` so the per-event hot path
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

    /// If some events are by default marked with telemetry keywords, this allows an opt out.
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
            channel: 11, // tells older versions of ETW that this is a tracelogging event
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
            // Auto-emitted `target` field, with alias applied so consumers
            // can rename it (e.g. to `TaskName`).
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
        // per-event-metadata data descriptors at the head of the payload so
        // that TDH can decode them. The codegen in `win_etw_macros` does the
        // same.
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

const WINEVENT_OPCODE_INFO: u8 = 0;
const WINEVENT_OPCODE_START: u8 = 1;
const WINEVENT_OPCODE_STOP: u8 = 2;

impl<S: Subscriber> Layer<S> for TracelogSubscriber
where
    S: for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let activity_id = extract_activity_id_attr(attrs)
            .map(ActivityId)
            .unwrap_or_else(|| ActivityId::from_current_thread().unwrap_or_default());

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
