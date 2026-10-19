//! TLS key recording shared by protocol producers and observation consumers.

#[cfg(feature = "observe")]
use crate::sync::{Mutex, MutexGuard};
#[cfg(feature = "observe")]
use std::collections::VecDeque;

/// One line of an `SSLKEYLOGFILE`: a TLS secret and the client random it
/// belongs to.
#[derive(Clone, Debug)]
pub struct KeyLine {
    /// SSLKEYLOGFILE label, such as CLIENT_TRAFFIC_SECRET_0.
    pub label: String,
    /// ClientHello random identifying the session.
    pub client_random: Vec<u8>,
    /// Traffic secret bytes.
    pub secret: Vec<u8>,
}

/// How many TLS secrets a world keeps, about 4,000 sessions. Past that,
/// the oldest are forgotten.
#[cfg(feature = "observe")]
pub(crate) const MAX_KEYS: usize = 20_000;

/// A run's bounded key log. A producer holds only this recording handle.
#[cfg(feature = "observe")]
#[derive(Default)]
pub(crate) struct KeyRecorder {
    state: Mutex<KeyState>,
}

#[cfg(feature = "observe")]
#[derive(Default)]
pub(crate) struct KeyState {
    pub(crate) keys: VecDeque<KeyLine>,
    /// How many keys have ever been added, so watches can take new ones
    /// after old ones are forgotten.
    pub(crate) keys_added: u64,
}

#[cfg(feature = "observe")]
impl KeyRecorder {
    pub(crate) fn state(&self) -> MutexGuard<'_, KeyState> {
        self.state.lock()
    }

    pub(crate) fn key(&self, line: KeyLine) {
        let mut s = self.state();
        if s.keys.len() >= MAX_KEYS {
            s.keys.pop_front();
        }
        s.keys.push_back(line);
        s.keys_added += 1;
    }
}

#[cfg(feature = "observe")]
impl std::fmt::Debug for KeyRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecorder").finish_non_exhaustive()
    }
}

#[cfg(feature = "observe")]
impl rustls::KeyLog for KeyRecorder {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.key(KeyLine {
            label: label.to_owned(),
            client_random: client_random.to_vec(),
            secret: secret.to_vec(),
        });
    }
}

/// Rustls delivery scoped to a connection, without retaining its run.
pub(crate) struct KeyLog {
    dispatch: std::sync::Weak<crate::events::Dispatch>,
    connection: Option<crate::events::ConnInfo>,
    #[cfg(feature = "observe")]
    old: Option<std::sync::Arc<KeyRecorder>>,
}

impl KeyLog {
    pub(crate) fn for_cx(
        cx: &crate::Cx,
        connection: Option<&crate::events::ConnInfo>,
    ) -> Option<std::sync::Arc<dyn rustls::KeyLog>> {
        use crate::events::{Interest, KeyMeta};
        let wanted = [
            "CLIENT_RANDOM",
            "CLIENT_EARLY_TRAFFIC_SECRET",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
            "EARLY_EXPORTER_SECRET",
        ]
        .iter()
        .any(|label| {
            cx.run
                .observer
                .enabled(Interest::TlsKey(KeyMeta { label, connection }))
        });
        #[cfg(feature = "observe")]
        let old = cx.observed().then(|| cx.run.keys.clone());
        #[cfg(feature = "observe")]
        let retained = old.is_some();
        #[cfg(not(feature = "observe"))]
        let retained = false;
        (wanted || retained).then(|| {
            std::sync::Arc::new(Self {
                connection: if wanted { connection.cloned() } else { None },
                dispatch: if wanted {
                    std::sync::Arc::downgrade(cx.run.observer.shared().unwrap())
                } else {
                    std::sync::Weak::new()
                },
                #[cfg(feature = "observe")]
                old,
            }) as std::sync::Arc<dyn rustls::KeyLog>
        })
    }
}

impl std::fmt::Debug for KeyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyLog").finish_non_exhaustive()
    }
}

impl rustls::KeyLog for KeyLog {
    fn will_log(&self, label: &str) -> bool {
        #[cfg(feature = "observe")]
        if self.old.is_some() {
            return true;
        }
        self.dispatch.upgrade().is_some_and(|dispatch| {
            dispatch.enabled(crate::events::Interest::TlsKey(crate::events::KeyMeta {
                label,
                connection: self.connection.as_ref(),
            }))
        })
    }

    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Some(dispatch) = self.dispatch.upgrade() {
            dispatch.key(crate::events::KeyRef {
                label,
                client_random,
                secret,
                connection: self.connection.as_ref(),
            });
        }
        #[cfg(feature = "observe")]
        if let Some(old) = &self.old {
            old.log(label, client_random, secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Seed, block_on, lab};

    #[test]
    fn no_recorder_without_an_observer() {
        block_on(lab(
            fictionet::RunOptions::new(Seed::from_u64(7)),
            |fcx| async move {
                assert!(fcx.tls_key_log(None).is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn an_event_observer_does_not_create_a_key_adapter() {
        let memory = std::sync::Arc::new(crate::events::Memory::default());
        block_on(lab(
            crate::RunOptions::new(Seed::from_u64(7)).observer(memory),
            |cx| async move {
                assert!(cx.tls_key_log(None).is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn key_interest_and_delivery_include_connection_context() {
        use crate::events::{ConnInfo, Interest, Observation, Observer, Stamp};
        struct Sink;
        impl Observer for Sink {
            fn enabled(&self, interest: Interest<'_>) -> bool {
                matches!(interest, Interest::TlsKey(key) if key.label == "CLIENT_RANDOM" && key.connection.is_some_and(|info| info.id == Some(17)))
            }
            fn observe(&self, _: Stamp, item: Observation<'_>) {
                let Observation::TlsKey(key) = item else {
                    panic!("unexpected stream")
                };
                assert_eq!(key.connection.unwrap().id, Some(17));
                assert_eq!(key.secret(), &[1, 2, 3]);
            }
        }
        block_on(lab(
            crate::RunOptions::new(Seed::from_u64(7)).observer(std::sync::Arc::new(Sink)),
            |cx| async move {
                assert!(cx.tls_key_log(None).is_none());
                let info = ConnInfo {
                    id: Some(17),
                    ..ConnInfo::default()
                };
                let logger = cx.tls_key_log(Some(&info)).unwrap();
                assert!(logger.will_log("CLIENT_RANDOM"));
                assert!(!logger.will_log("SERVER_TRAFFIC_SECRET_0"));
                logger.log("CLIENT_RANDOM", &[0; 32], &[1, 2, 3]);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[cfg(feature = "observe")]
    #[test]
    fn recorder_keeps_only_keys_after_observers_and_the_run_leave() {
        use crate::sync::Mutex;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let kept = Arc::new(Mutex::new(None));
        let keep = kept.clone();
        block_on(lab(
            fictionet::RunOptions::new(Seed::from_u64(7)),
            move |fcx| async move {
                let graph = fcx.graph();
                graph.viewers.store(1, Ordering::Relaxed);
                let recorder = fcx.tls_key_log(None).unwrap();
                graph.viewers.store(0, Ordering::Relaxed);
                assert!(fcx.tls_key_log(None).is_none());
                recorder.log("CLIENT_RANDOM", &[0, 255, 7], &[128, 0, 42]);
                {
                    let s = graph.keys.state();
                    assert_eq!(s.keys_added, 1);
                    assert_eq!(s.keys.len(), 1);
                    assert_eq!(s.keys[0].label, "CLIENT_RANDOM");
                    assert_eq!(s.keys[0].client_random, [0, 255, 7]);
                    assert_eq!(s.keys[0].secret, [128, 0, 42]);
                }
                *keep.lock() = Some((
                    recorder,
                    Arc::downgrade(&fcx.run),
                    Arc::downgrade(graph),
                    Arc::downgrade(&graph.keys),
                ));
                Ok(())
            },
        ))
        .unwrap();
        let (recorder, run, graph, keys) = kept.lock().take().unwrap();
        assert!(run.upgrade().is_none());
        assert!(graph.upgrade().is_none());
        recorder.log("SERVER_TRAFFIC_SECRET_0", &[1, 2], &[3, 4]);
        {
            let keys = keys.upgrade().unwrap();
            let s = keys.state();
            assert_eq!(s.keys_added, 2);
            assert_eq!(s.keys[1].label, "SERVER_TRAFFIC_SECRET_0");
            assert_eq!(s.keys[1].client_random, [1, 2]);
            assert_eq!(s.keys[1].secret, [3, 4]);
        }
        drop(recorder);
        assert!(keys.upgrade().is_none());
    }
}
