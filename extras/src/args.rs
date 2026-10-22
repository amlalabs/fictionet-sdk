//! The command line the Docker example worlds share: where a world listens
//! for attachments and its observer, and where it writes its CA, state and
//! ready file. Each world starts from its own defaults and may take flags of
//! its own.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// The world's command line.
pub struct Args {
    /// Unix socket for guest attachments.
    pub socket: String,
    /// Optional observation server socket.
    pub observation: Option<PathBuf>,
    /// Directory for certificates trusted by guests.
    pub ca_dir: PathBuf,
    /// Directory for durable world state and logs.
    pub state_dir: PathBuf,
    /// File written when the world accepts attachments.
    pub ready: PathBuf,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            socket: "/run/fictionet/sock/world.sock".into(),
            observation: None,
            ca_dir: "/app/ca".into(),
            state_dir: "/var/lib/fictionet".into(),
            ready: "/run/fictionet/ready".into(),
        }
    }
}

impl Args {
    /// Reads `flags`, the command line after the program name, over these
    /// defaults. Another flag goes to `other` with its value; [`unknown`]
    /// refuses every one.
    pub fn read(
        mut self,
        flags: impl IntoIterator<Item = String>,
        mut other: impl FnMut(&str, String) -> Result<(), String>,
    ) -> Result<Self, String> {
        let mut it = flags.into_iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--socket" => self.socket = value,
                "--observation" => self.observation = Some(value.into()),
                "--ca-dir" => self.ca_dir = value.into(),
                "--state-dir" => self.state_dir = value.into(),
                "--ready" => self.ready = value.into(),
                _ => other(&flag, value)?,
            }
        }
        Ok(self)
    }
}

/// Refuses a flag the world does not take.
pub fn unknown(flag: &str, _value: String) -> Result<(), String> {
    Err(format!("unknown flag {flag}"))
}

/// Reads the command line with the default paths and no flags of the
/// world's own.
pub fn args() -> Result<Args, String> {
    Args::default().read(std::env::args().skip(1), unknown)
}

/// Reads one positional JSON configuration before the shared path arguments.
pub fn configuration<T: serde::de::DeserializeOwned>(
    args: &mut impl Iterator<Item = String>,
) -> Result<T, String> {
    let value = args.next().ok_or("a JSON configuration is required")?;
    serde_json::from_str(&value).map_err(|error| format!("configuration: {error}"))
}

/// Seconds since the epoch.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_keeps_path_arguments_separate() {
        let mut argv = [
            r#"{"variant":"normal","seed":"a value with spaces"}"#,
            "--socket",
            "/run/service.sock",
        ]
        .map(str::to_owned)
        .into_iter();
        let config: serde_json::Value = configuration(&mut argv).unwrap();
        assert_eq!(config["variant"], "normal");
        assert_eq!(config["seed"], "a value with spaces");
        assert_eq!(
            Args::default().read(argv, unknown).unwrap().socket,
            "/run/service.sock"
        );
        for input in ["--variant", "{", ""] {
            assert!(
                configuration::<serde_json::Value>(&mut [input.to_owned()].into_iter()).is_err()
            );
        }
    }
}
