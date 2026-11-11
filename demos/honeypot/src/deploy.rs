//! Executable options and protected persistent sensor state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fictionet_host::xdp::InterfaceName;
use honeypot_world::Args;
use honeypot_world::config::{Flag, SshAuth};
use honeypot_world::record::{CompanyHost, Configuration, Listener, Reachability, SshAuthPolicy};

pub const HELP: &str = "honeypot run --interface NAME [OPTIONS]\n\
  --interface NAME        The data ENA the honeypot takes over with native XDP\n\
  --state-dir PATH        Protected persistent identity, key, and run evidence\n\
  --address IPV4 [--address-v6 IPV6]   The server's addresses on the link\n\
  --gateway IPV4 [--gateway-v6 IPV6]   The link's gateways\n\
  --public-address IPV4   The public address mapped to --address, recorded only\n\
  --ssh PORT [--http PORT] [--http-profile caddy|nginx]\n\
  --mcp PORT --a2a PORT --fleet PORT   Northbank simulated company services\n\
  --ssh-auth accept|reject|password:VALUE\n\
  --queue-bytes N --max-record-bytes N --rotate-bytes N --retain-files N\n\
  --restricted-evidence  Retain exact decrypted SSH bytes in protected files\n\
  --version              Build version\n\
run refuses an interface that has an address or a route, carries a connection,\n\
is not an ENA, or does not read back MTU 1500 and one queue after it sets them.\n";

pub struct Options {
    pub args: Args,
    pub interface: InterfaceName,
    pub public_address: Option<Ipv4Addr>,
    pub state_dir: PathBuf,
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
        let interface: InterfaceName = take(&mut values, "interface")
            .ok_or_else(|| fictionet::Error::msg("run needs --interface NAME"))?
            .parse()?;
        let public_address: Option<Ipv4Addr> = take(&mut values, "public-address")
            .map(|v| v.parse())
            .transpose()?;
        let state_dir = take(&mut values, "state-dir")
            .unwrap_or_else(|| "honeypot-state".into())
            .into();
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
            interface,
            public_address,
            state_dir,
            restricted_evidence,
            queue_bytes,
            max_record_bytes,
            rotate_bytes: rotate_bytes as u64,
            retain_files,
        })
    }

    /// This run's configuration, as the log records it, without the SSH password.
    pub fn configuration(&self) -> Configuration {
        let config = &self.args.config;
        Configuration {
            build: env!("CARGO_PKG_VERSION").into(),
            interface: self.interface.as_str().into(),
            public_address: self.public_address,
            address: config.address,
            address_v6: config.address_v6,
            persona: "Ubuntu 24.04 / Linux 6.8".into(),
            http_profile: config.http_profile,
            listeners: config
                .ports
                .iter()
                .map(|port| Listener {
                    port: port.number,
                    service: port.service,
                })
                .collect(),
            company_hosts: config
                .ports
                .iter()
                .filter_map(|port| honeypot_world::company_host(port.service))
                .map(|(name, address)| CompanyHost {
                    name: name.into(),
                    address,
                    http: 80,
                    https: 443,
                })
                .collect(),
            ssh_auth: match config.ssh_auth {
                SshAuth::Reject => SshAuthPolicy::Reject,
                SshAuth::AnyCredentials => SshAuthPolicy::Accept,
                SshAuth::PasswordOrPublicKey(_) => {
                    SshAuthPolicy::ConfiguredPasswordOrSignedPublicKey
                }
            },
            internet_ipv4: config.internet.ipv4,
            internet_ipv6: config.internet.ipv6,
            burst_window_ms: config.burst.window.as_millis() as u64,
            burst_syns: config.burst.syns,
            gateway: config.gateway,
            gateway_v6: config.gateway_v6.into(),
            observations: [
                "mptcp",
                "ipv4_options",
                "ssh",
                "port_zero",
                "trap",
                "tcp_wire",
                "dns_wire",
                "tls_client_hello",
            ]
            .map(String::from)
            .to_vec(),
            state_dir: self.state_dir.clone(),
            restricted_evidence: self.restricted_evidence,
            queue_bytes: self.queue_bytes,
            max_record_bytes: self.max_record_bytes,
            rotate_bytes: self.rotate_bytes,
            retain_files_per_stream: self.retain_files,
            observation_state_limit_per_map: honeypot_world::observe::STATE_LIMIT,
            connection_limit: honeypot_world::CONNECTION_LIMIT,
            public_reachability: Reachability::NotTested,
        }
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
        let parsed = options("run --interface ens6 --ssh 22 --gateway 192.0.2.1").unwrap();
        assert_eq!(parsed.interface.as_str(), "ens6");
        assert_eq!(parsed.public_address, None);
        for line in [
            "--ssh 22",
            "--interface ens6/x",
            "--interface ens6 --interface ens7",
            "--interface ens6 --public-address 2001:db8::1",
            "--interface ens6 --ssh 0",
            "--interface ens6 --ssh 22 --http 22",
            "--interface ens6 --queue-bytes 1",
            "--interface ens6 --state-dir a --state-dir b",
            "--interface ens6 --ssh 53 --mcp 8081",
            "--interface ens6 --address 10.44.0.11 --mcp 8081",
            "--interface ens6 --unknown 1",
        ] {
            assert!(options(line).is_err(), "{line}");
        }
    }

    #[test]
    fn the_public_address_is_recorded_and_not_used_as_the_server_address() {
        let parsed =
            options("run --interface ens6 --address 10.0.2.20 --public-address 203.0.113.9")
                .unwrap();
        let configuration = parsed.configuration();
        assert_eq!(configuration.address, Ipv4Addr::new(10, 0, 2, 20));
        assert_eq!(
            configuration.public_address,
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(configuration.interface, "ens6");
    }

    #[test]
    fn configuration_leaves_out_the_ssh_password_and_parsing_writes_nothing() {
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
            "--interface".into(),
            "ens6".into(),
            "--state-dir".into(),
            state.to_str().unwrap().into(),
            "--ssh-auth".into(),
            "password:private-value".into(),
        ])
        .unwrap();
        let configuration = serde_json::to_string(&options.configuration()).unwrap();
        assert!(!configuration.contains("private-value"));
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
