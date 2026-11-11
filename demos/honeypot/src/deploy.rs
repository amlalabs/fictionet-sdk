//! Executable options and protected persistent sensor state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use honeypot_world::Args;
use honeypot_world::config::{Flag, SshAuth};
use serde_json::{Value, json};

pub const HELP: &str = "honeypot run [OPTIONS]\n\
  --state-dir PATH        Protected persistent identity, key, and run evidence\n\
  --address IPV4 [--address-v6 IPV6]   The server's addresses on the link\n\
  --gateway IPV4 [--gateway-v6 IPV6]   The link's gateways\n\
  --ssh PORT [--http PORT] [--http-profile caddy|nginx]\n\
  --mcp PORT --a2a PORT --fleet PORT   Northbank simulated company services\n\
  --ssh-auth accept|reject|password:VALUE\n\
  --metrics IP:PORT       Explicit management Prometheus listener\n\
  --queue-bytes N --max-record-bytes N --rotate-bytes N --retain-files N\n\
  --restricted-evidence  Retain exact decrypted SSH bytes in protected files\n\
  --version              Build version\n\
This build has no packet path: run checks its options, then refuses to start.\n";

pub struct Options {
    pub args: Args,
    pub state_dir: PathBuf,
    pub metrics: Option<SocketAddr>,
    pub restricted_evidence: bool,
    pub queue_bytes: usize,
    pub max_record_bytes: usize,
    pub rotate_bytes: u64,
    pub retain_files: usize,
}

impl Options {
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> fictionet::Result<Self> {
        let mut args: Vec<_> = arguments.into_iter().collect();
        if args.first().is_some_and(|v| v == "run") {
            args.remove(0);
        }
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let key = flag.strip_prefix("--").ok_or_else(|| {
                fictionet::Error::msg(format!("expected an option, got {flag:?}"))
            })?;
            let value = if key == "restricted-evidence" {
                "true".into()
            } else {
                it.next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| fictionet::Error::msg(format!("{flag} needs a value")))?
            };
            let entries = values.entry(key.to_owned()).or_default();
            if !entries.is_empty()
                && !matches!(key, "ssh" | "http" | "mcp" | "a2a" | "fleet" | "internet")
            {
                return Err(fictionet::Error::msg(format!("duplicate option {flag}")));
            }
            entries.push(value);
        }
        Self::resolve(values)
    }

    fn resolve(mut values: BTreeMap<String, Vec<String>>) -> fictionet::Result<Self> {
        let state_dir = take(&mut values, "state-dir")
            .unwrap_or_else(|| "honeypot-state".into())
            .into();
        let metrics: Option<SocketAddr> = take(&mut values, "metrics")
            .map(|v| v.parse())
            .transpose()?;
        if metrics.is_some_and(|address| address.port() == 0) {
            return Err(fictionet::Error::msg(
                "metrics requires an explicit nonzero port",
            ));
        }
        let restricted_evidence = boolean(&mut values, "restricted-evidence")?;
        let queue_bytes = number(&mut values, "queue-bytes", 8 * 1024 * 1024)?;
        let max_record_bytes = number(&mut values, "max-record-bytes", 1024 * 1024)?;
        let rotate_bytes = number(&mut values, "rotate-bytes", 64 * 1024 * 1024)?;
        let retain_files = number(&mut values, "retain-files", 32)?;
        if max_record_bytes > queue_bytes
            || queue_bytes > 1024 * 1024 * 1024
            || rotate_bytes < max_record_bytes
            || retain_files < 3
        {
            return Err(fictionet::Error::msg(
                "require record <= queue <= 1 GiB, rotation >= record and retention >= 3 files",
            ));
        }
        let mut persona = Vec::new();
        for (key, entries) in values {
            let flag = format!("--{key}");
            if Flag::parse(&flag).is_none() {
                return Err(fictionet::Error::msg(format!("unknown option {flag}")));
            }
            for value in entries {
                persona.extend([flag.clone(), value]);
            }
        }
        let args = Args::parse(persona)?;
        let mut ports = std::collections::HashSet::new();
        for port in &args.config.ports {
            if port.number == 0 || !ports.insert(port.number) {
                return Err(fictionet::Error::msg(
                    "listener ports must be distinct and nonzero; port zero remains closed",
                ));
            }
        }
        let company: Vec<_> = args
            .config
            .ports
            .iter()
            .filter_map(|p| honeypot_world::company_host(p.service))
            .collect();
        if !company.is_empty()
            && (ports.contains(&53) || company.iter().any(|(_, ip)| *ip == args.config.address))
        {
            return Err(fictionet::Error::msg(
                "Company services reserve DNS port 53 and separate private host addresses",
            ));
        }
        Ok(Self {
            args,
            state_dir,
            metrics,
            restricted_evidence,
            queue_bytes,
            max_record_bytes,
            rotate_bytes: rotate_bytes as u64,
            retain_files,
        })
    }

    pub fn summary(&self) -> Value {
        json!({
            "event": "configuration", "build": env!("CARGO_PKG_VERSION"),
            "address": self.args.config.address, "address_v6": self.args.config.address_v6,
            "persona": "Ubuntu 24.04 / Linux 6.8", "http_profile": format!("{:?}", self.args.config.http_profile),
            "listeners": self.args.config.ports.iter().map(|port| json!({"port": port.number, "service": format!("{:?}", port.service).to_lowercase()})).collect::<Vec<_>>(),
            "company_hosts": self.args.config.ports.iter().filter_map(|p|honeypot_world::company_host(p.service)).map(|(name,address)|json!({"name":name,"address":address,"http":80,"https":443})).collect::<Vec<_>>(),
            "ssh_auth": match self.args.config.ssh_auth { SshAuth::Reject => "reject", SshAuth::AnyCredentials => "accept", SshAuth::PasswordOrPublicKey(_) => "configured_password_or_signed_public_key" },
            "internet_ipv4": self.args.config.internet.ipv4.to_string(), "internet_ipv6": self.args.config.internet.ipv6.to_string(),
            "burst_window_ms": self.args.config.burst.window.as_millis(), "burst_syns": self.args.config.burst.syns,
            "gateway": self.args.config.gateway, "gateway_v6": format!("{:?}", self.args.config.gateway_v6),
            "observations": ["mptcp", "ipv4_options", "ssh", "port_zero", "trap", "tcp_wire", "dns_wire", "tls_client_hello"],
            "state_dir": self.state_dir, "metrics": self.metrics, "restricted_evidence": self.restricted_evidence,
            "queue_bytes": self.queue_bytes, "max_record_bytes": self.max_record_bytes,
            "rotate_bytes": self.rotate_bytes, "retain_files_per_stream": self.retain_files, "observation_state_limit_per_map": honeypot_world::observe::STATE_LIMIT,
            "connection_limit": honeypot_world::CONNECTION_LIMIT,
            "public_reachability": "not_tested",
        })
    }
}

fn take(values: &mut BTreeMap<String, Vec<String>>, key: &str) -> Option<String> {
    values.remove(key).map(|mut v| v.remove(0))
}
fn boolean(values: &mut BTreeMap<String, Vec<String>>, key: &str) -> fictionet::Result<bool> {
    take(values, key)
        .map(|v| v.parse::<bool>().map_err(fictionet::Error::from))
        .unwrap_or(Ok(false))
}
fn number(
    values: &mut BTreeMap<String, Vec<String>>,
    key: &str,
    default: usize,
) -> fictionet::Result<usize> {
    let value = take(values, key)
        .map(|v| v.parse::<usize>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(fictionet::Error::msg(format!("{key} must be positive")));
    }
    Ok(value)
}

fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid takes no pointers and cannot invalidate Rust storage.
    unsafe { libc::geteuid() }
}

pub struct State {
    _lock: File,
    pub sensor_id: String,
    pub host_key: [u8; 32],
}

impl State {
    pub fn open(path: &Path) -> io::Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.uid() != effective_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "state directory must be owned by this user and have mode 0700",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.join("lock"))?;
        lock.try_lock().map_err(io::Error::other)?;
        let identity = secret(&path.join("sensor-id"), 16)?;
        let sensor_id = identity.iter().map(|b| format!("{b:02x}")).collect();
        let host_key = secret(&path.join("ssh-host-key"), 32)?.try_into().unwrap();
        Ok(Self {
            _lock: lock,
            sensor_id,
            host_key,
        })
    }
}

fn secret(path: &Path, size: usize) -> io::Result<Vec<u8>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.len() != size as u64
                || metadata.uid() != effective_uid()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sensor identity and key must be intact private files owned by this user",
                ));
            }
            let mut bytes = Vec::with_capacity(size);
            file.take(size as u64).read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut bytes = vec![0; size];
            File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            File::open(path.parent().unwrap())?.sync_all()?;
            Ok(bytes)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(line: &str) -> fictionet::Result<Options> {
        Options::parse(line.split_whitespace().map(String::from))
    }

    #[test]
    fn rejects_conflicting_and_unknown_options() {
        assert!(options("run --ssh 22 --gateway 192.0.2.1").is_ok());
        for line in [
            "--ssh 0",
            "--ssh 22 --http 22",
            "--queue-bytes 1",
            "--metrics 127.0.0.1:0",
            "--state-dir a --state-dir b",
            "--ssh 53 --mcp 8081",
            "--address 10.44.0.11 --mcp 8081",
            "--unknown 1",
        ] {
            assert!(options(line).is_err(), "{line}");
        }
    }

    #[test]
    fn summary_leaves_out_the_ssh_password_and_parsing_writes_nothing() {
        let state = std::env::temp_dir().join(format!(
            "honeypot-options-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let options = Options::parse([
            "run".into(),
            "--state-dir".into(),
            state.to_str().unwrap().into(),
            "--ssh-auth".into(),
            "password:private-value".into(),
        ])
        .unwrap();
        assert!(!options.summary().to_string().contains("private-value"));
        assert!(!state.exists());
    }

    #[test]
    fn state_persists_identity_key_and_prevents_concurrent_use() {
        let directory = std::env::temp_dir().join(format!(
            "honeypot-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = State::open(&directory).unwrap();
        let key = first.host_key;
        let identity = first.sensor_id.clone();
        assert!(State::open(&directory).is_err());
        drop(first);
        let second = State::open(&directory).unwrap();
        assert_eq!(second.host_key, key);
        assert_eq!(second.sensor_id, identity);
        drop(second);
        fs::set_permissions(
            directory.join("ssh-host-key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(State::open(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
