//! Rustls key emission for the run observer.

/// Rustls delivery scoped to a connection, without retaining its run.
pub(crate) struct KeyLog {
    dispatch: std::sync::Weak<crate::events::Dispatch>,
    connection: Option<crate::events::ConnInfo>,
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
        wanted.then(|| {
            std::sync::Arc::new(Self {
                connection: connection.cloned(),
                dispatch: std::sync::Arc::downgrade(cx.run.observer.shared().unwrap()),
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
}
