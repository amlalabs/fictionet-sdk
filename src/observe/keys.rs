//! TLS session keys for observers, so that watched links can be decrypted.
//!
//! While a world is observed, the stdlib's TLS server gives rustls a key
//! log that keeps each session's secrets with what the run tracks for
//! observers, as `SSLKEYLOGFILE` lines. With no observer, configs are used as
//! they are and nothing is recorded.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::Cx;
use crate::watch::{Graph, KeyLine};

/// Keeps secrets with what a run tracks for observers.
struct Recorder {
    graph: Arc<Graph>,
    /// The name the client asked for, for the note.
    sni: Option<String>,
    task: u64,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").field("sni", &self.sni).finish()
    }
}

impl rustls::KeyLog for Recorder {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let first = !self.graph.state().keys.iter().any(|k| k.client_random == client_random);
        self.graph.key(KeyLine { label: label.to_owned(), client_random: client_random.to_vec(), secret: secret.to_vec() });
        if first {
            let name = self.sni.as_deref().unwrap_or("a connection with no name");
            let text = format!("session keys for {name}, client random {}…", super::packets::hex(&client_random[..4]));
            let _task = crate::watch::Polling::enter(self.task);
            self.graph.note("tls_keys", text, None);
        }
    }
}

/// `config`, logging its session keys while `cx`'s world is observed.
pub(crate) fn observed_config(cx: &Cx, config: Arc<ServerConfig>, sni: Option<&str>) -> Arc<ServerConfig> {
    if !cx.observed() {
        return config;
    }
    let mut logged = (*config).clone();
    logged.key_log =
        Arc::new(Recorder { graph: cx.graph().clone(), sni: sni.map(str::to_owned), task: crate::watch::current_task() });
    Arc::new(logged)
}
