//! Command line and Python backend startup.

use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The world's command line.
pub struct Args {
    pub socket: String,
    pub ca_dir: PathBuf,
    pub backend: PathBuf,
    pub backend_port: u16,
    pub state_dir: PathBuf,
    pub ready: PathBuf,
}

/// Reads the command line.
pub fn args() -> Result<Args, String> {
    let mut a = Args {
        socket: "/run/fictionet/sock/world.sock".into(),
        ca_dir: "/app/ca".into(),
        backend: "/app/backend".into(),
        backend_port: 8080,
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--ca-dir" => a.ca_dir = value.into(),
            "--backend" => a.backend = value.into(),
            "--backend-port" => {
                a.backend_port = value.parse().map_err(|e| format!("--backend-port: {e}"))?
            }
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

/// Starts backend.py and waits for its first line. Returns that line and
/// the running backend. [`watch_backend`] makes the world exit with it.
pub fn start_backend(args: &Args) -> fictionet::Result<(Value, std::process::Child)> {
    let mut child = Command::new("python3")
        .arg("backend.py")
        .arg(args.backend_port.to_string())
        .current_dir(&args.backend)
        .env("PYTHONUNBUFFERED", "1")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| fictionet::Error::msg(format!("cannot start backend.py: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fictionet::Error::msg("no backend stdout"))?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    if line.trim().is_empty() {
        let status = child.wait()?;
        return Err(fictionet::Error::msg(format!(
            "backend.py exited before it was ready ({status})"
        )));
    }
    Ok((serde_json::from_str(&line)?, child))
}

/// If the backend exits, the world exits too, so the container stops
/// instead of serving errors.
pub fn watch_backend(mut child: std::process::Child, world: &'static str) {
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("{world}: backend.py exited ({status:?}); stopping");
        std::process::exit(1);
    });
}
