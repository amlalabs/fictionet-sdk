//! TLS session keys for observers, so that watched links can be decrypted.
//!
//! While a world is observed, the stdlib's TLS server gives rustls a key
//! log that keeps each session's secrets with what the run tracks for
//! observers, as `SSLKEYLOGFILE` lines, and records a `tls.keys` event for
//! each session. With no observer, configs are used as they are and no keys
//! are kept.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::Cx;
use crate::events::Event;
use crate::watch::KeyLine;

/// Keeps secrets with what a run tracks for observers.
struct Recorder {
    fcx: Cx,
    /// The name the client asked for, for the event.
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
        let graph = self.fcx.graph();
        let first = !graph.state().keys.iter().any(|k| k.client_random == client_random);
        graph.key(KeyLine { label: label.to_owned(), client_random: client_random.to_vec(), secret: secret.to_vec() });
        if first {
            let name = self.sni.as_deref().unwrap_or("a connection with no name");
            let random = super::packets::hex(&client_random[..4]);
            let summary = format!("session keys for {name}, client random {random}…");
            let _task = crate::watch::Polling::enter(self.task);
            self.fcx.record(Event::new("tls", "keys").summary(summary).field("sni", crate::events::opt(self.sni.as_deref())).field("client_random", random));
        }
    }
}

/// `config`, logging its session keys while `fcx`'s world is observed.
pub(crate) fn observed_config(fcx: &Cx, config: Arc<ServerConfig>, sni: Option<&str>) -> Arc<ServerConfig> {
    if !fcx.observed() {
        return config;
    }
    let mut logged = (*config).clone();
    logged.key_log =
        Arc::new(Recorder { fcx: fcx.clone(), sni: sni.map(str::to_owned), task: crate::watch::current_task() });
    Arc::new(logged)
}
