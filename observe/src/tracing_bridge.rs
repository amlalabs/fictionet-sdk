use fictionet::events::{Interest, Level, Observation, Observer, Stamp};
use fictionet::stdlib::codec::Wire;

/// Forwards events through an integrator's explicit tracing dispatch.
/// Info maps to INFO, Notice to WARN, and Alarm to ERROR.
pub struct Tracing {
    dispatch: tracing::Dispatch,
}

impl Tracing {
    /// Uses this dispatch only during each event delivery.
    pub fn new(dispatch: tracing::Dispatch) -> Self {
        Self { dispatch }
    }
}

impl Observer for Tracing {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(..))
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation else {
            return;
        };
        let fields = event
            .fields
            .to_json()
            .to_bytes()
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| "null".into());
        tracing::dispatcher::with_default(&self.dispatch, || {
            macro_rules! emit {
                ($level:expr) => {
                    tracing::event!(target: "fictionet", $level, source = event.source, kind = event.kind,
                        seq = stamp.seq, at = stamp.at.since_start().as_secs_f64(), summary = event.summary.as_str(), fields = fields.as_str())
                };
            }
            match event.level {
                Level::Info => emit!(tracing::Level::INFO),
                Level::Notice => emit!(tracing::Level::WARN),
                Level::Alarm => emit!(tracing::Level::ERROR),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use fictionet::events::{ConnInfo, Event, Metadata, Stream, TopologyKind};
    use fictionet::time::{Instant, ms};
    use tracing::{
        Event as TraceEvent, Metadata as TraceMetadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
    };

    use super::*;

    type Entries = Arc<Mutex<Vec<(tracing::Level, String, BTreeMap<String, String>)>>>;
    struct Sink(Entries);
    impl Subscriber for Sink {
        fn enabled(&self, _: &TraceMetadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
        fn event(&self, event: &TraceEvent<'_>) {
            struct Fields(BTreeMap<String, String>);
            impl Visit for Fields {
                fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                    self.0.insert(field.name().into(), format!("{value:?}"));
                }
                fn record_str(&mut self, field: &Field, value: &str) {
                    self.0.insert(field.name().into(), value.into());
                }
            }
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push((
                *event.metadata().level(),
                event.metadata().target().into(),
                fields.0,
            ));
        }
    }

    #[test]
    fn dispatch_is_scoped_and_fields_are_stable() {
        let outer = Entries::default();
        let inner = Entries::default();
        let observer = Tracing::new(tracing::Dispatch::new(Sink(inner.clone())));
        assert!(observer.enabled(Interest::Event(
            Metadata {
                source: "shop",
                kind: "order"
            },
            &ConnInfo::default()
        )));
        assert!(!observer.enabled(Interest::Topology(TopologyKind::Link)));
        let was_set = tracing::dispatcher::get_default(|dispatch| {
            dispatch.is::<tracing::subscriber::NoSubscriber>()
        });
        tracing::dispatcher::with_default(&tracing::Dispatch::new(Sink(outer.clone())), || {
            tracing::info!("before");
            for (index, level) in [Level::Info, Level::Notice, Level::Alarm]
                .into_iter()
                .enumerate()
            {
                let mut event = Event::new("shop", "order")
                    .summary("ready")
                    .field("count", 3u32);
                event.level = level;
                observer.observe(
                    Stamp {
                        stream: Stream::Events,
                        seq: index as u64 + 1,
                        at: Instant::ZERO + ms(250),
                    },
                    Observation::Event(&event),
                );
            }
            tracing::info!("after");
        });
        assert!(was_set);
        assert!(tracing::dispatcher::get_default(|dispatch| {
            dispatch.is::<tracing::subscriber::NoSubscriber>()
        }));
        assert_eq!(outer.lock().unwrap().len(), 2);
        let entries = inner.lock().unwrap();
        assert_eq!(entries.len(), 3);
        for (index, level) in [
            tracing::Level::INFO,
            tracing::Level::WARN,
            tracing::Level::ERROR,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(entries[index].0, level);
            assert_eq!(entries[index].1, "fictionet");
            assert_eq!(
                entries[index].2,
                BTreeMap::from([
                    ("source".into(), "shop".into()),
                    ("kind".into(), "order".into()),
                    ("seq".into(), (index + 1).to_string()),
                    ("at".into(), "0.25".into()),
                    ("summary".into(), "ready".into()),
                    ("fields".into(), "{\"count\":3}".into()),
                ])
            );
        }
    }
}
