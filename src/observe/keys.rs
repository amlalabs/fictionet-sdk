//! TLS session keys for observers, so that watched links can be decrypted.
//!
//! While a world is observed, the stdlib's TLS server gives rustls a key
//! log that keeps each session's secrets with what the run tracks for
//! observers, as `SSLKEYLOGFILE` lines. With no observer, configs are used
//! as they are and no keys are kept.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::Cx;

/// Applies TLS observation to `config` for `fcx`'s run.
///
/// Returns `config` unchanged when the run is not observed. Otherwise,
/// clones it and replaces its key logger with one that records session
/// secrets for packet decryption.
pub fn observed_config(fcx: &Cx, config: Arc<ServerConfig>) -> Arc<ServerConfig> {
    match fcx.tls_key_log(None) {
        Some(key_log) => {
            let mut logged = (*config).clone();
            logged.key_log = key_log;
            Arc::new(logged)
        }
        None => config,
    }
}

#[cfg(all(test, feature = "observe"))]
mod tests;
