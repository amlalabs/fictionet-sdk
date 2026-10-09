//! TLS session keys for observers, so that watched links can be decrypted.
//!
//! While a world is observed, the stdlib's TLS server gives rustls a key
//! log that keeps each session's secrets with what the run tracks for
//! observers, as `SSLKEYLOGFILE` lines. With no observer, configs are used
//! as they are and no keys are kept.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::Cx;
use crate::watch::KeyLine;

/// Keeps secrets with what a run tracks for observers.
struct Recorder {
    fcx: Cx,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").finish_non_exhaustive()
    }
}

impl rustls::KeyLog for Recorder {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let graph = self.fcx.graph();
        graph.key(KeyLine {
            label: label.to_owned(),
            client_random: client_random.to_vec(),
            secret: secret.to_vec(),
        });
    }
}

/// Applies TLS observation to `config` for `fcx`'s run.
///
/// Returns `config` unchanged when the run is not observed. Otherwise,
/// clones it and replaces its key logger with one that records session
/// secrets for packet decryption.
pub fn observed_config(fcx: &Cx, config: Arc<ServerConfig>) -> Arc<ServerConfig> {
    if !fcx.observed() {
        return config;
    }
    let mut logged = (*config).clone();
    logged.key_log = Arc::new(Recorder { fcx: fcx.clone() });
    Arc::new(logged)
}

#[cfg(test)]
mod tests;
