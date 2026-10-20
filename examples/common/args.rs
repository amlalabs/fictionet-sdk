//! The command line the Docker example worlds share.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// The world's command line.
pub struct Args {
    pub socket: String,
    pub observation: Option<PathBuf>,
    pub ca_dir: PathBuf,
    pub state_dir: PathBuf,
    pub ready: PathBuf,
}

/// Reads the command line.
pub fn args() -> Result<Args, String> {
    let mut a = Args {
        observation: None,
        socket: "/run/fictionet/sock/world.sock".into(),
        ca_dir: "/app/ca".into(),
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--observation" => a.observation = Some(value.into()),
            "--ca-dir" => a.ca_dir = value.into(),
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

/// Seconds since the epoch.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
