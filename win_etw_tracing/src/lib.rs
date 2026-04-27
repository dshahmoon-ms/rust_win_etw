// Copyright (C) Microsoft Corporation. All rights reserved.

//! Subscriber for tracing events that emits Windows ETW TraceLogging events.
#![cfg(windows)]
#![forbid(unsafe_code)]

mod activity_id;
mod deferred_values;
mod event_writer;
mod keyword;
mod subscriber;

pub use event_writer::{FieldAlias, GlobalField};
pub use keyword::{KeywordRule, LevelSet};
pub use subscriber::TracelogSubscriber;
