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

#[cfg(test)]
mod tests {
    use crate::{Seed, block_on, lab};

    #[test]
    fn no_recorder_without_an_observer() {
        block_on(lab(Seed::from_u64(7), |fcx| async move {
            assert!(fcx.tls_key_log().is_none());
            Ok(())
        }))
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
        block_on(lab(Seed::from_u64(7), move |fcx| async move {
            let graph = fcx.graph();
            graph.viewers.store(1, Ordering::Relaxed);
            let recorder = fcx.tls_key_log().unwrap();
            graph.viewers.store(0, Ordering::Relaxed);
            assert!(fcx.tls_key_log().is_none());
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
        }))
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
