//! Executable configuration and protected persistent sensor state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use honeypot_world::Args;
use honeypot_world::config::{Flag, SshAuth};
use serde_json::{Value, json};

pub const HELP: &str = "honeypot run [--config FILE] [--dry-run] --backend world|tun|vfio\n\
  --state-dir PATH        Protected persistent identity, key, and run evidence\n\
  --world unix:PATH       World socket (world backend only)\n\
  --tun NAME             TUN interface (tun backend only)\n\
  --tun-mode existing|create   Existing persistent TUN by default\n\
  --device PCI           Prepared virtio-net PCI address (vfio backend only)\n\
  --address IPV4 [--address-v6 IPV6]   Address delivered inside the guest\n\
  --gateway IPV4 [--gateway-v6 IPV6]   VFIO gateways\n\
  --ssh PORT [--http PORT] [--http-profile caddy|nginx]\n\
  --ssh-auth accept|reject|password:VALUE\n\
  --metrics IP:PORT       Explicit management Prometheus listener\n\
  --queue-bytes N --max-record-bytes N --rotate-bytes N --retain-files N\n\
  --restricted-evidence  Retain exact decrypted SSH bytes in protected files\n\
  --version              Build and compiled backends\n\
Configuration is a JSON object with the same option names, without --.\n\
Repeated service and internet options use arrays. CLI options replace file options.\n\
XDP, AF_XDP and direct ENA ownership are not implemented.\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    World,
    Tun { name: String, create: bool },
    Vfio { device: String },
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Self::World => "world",
            Self::Tun { .. } => "tun",
            Self::Vfio { .. } => "vfio",
        }
    }
}

pub struct Options {
    pub backend: Backend,
    pub args: Args,
    pub state_dir: PathBuf,
    pub metrics: Option<SocketAddr>,
    pub dry_run: bool,
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
        let mut cli: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let key = flag.strip_prefix("--").ok_or_else(|| {
                fictionet::Error::msg(format!("expected an option, got {flag:?}"))
            })?;
            let value = if matches!(key, "dry-run" | "restricted-evidence") {
                "true".into()
            } else {
                it.next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| fictionet::Error::msg(format!("{flag} needs a value")))?
            };
            let values = cli.entry(key.to_owned()).or_default();
            if !values.is_empty() && !matches!(key, "ssh" | "http" | "internet") {
                return Err(fictionet::Error::msg(format!("duplicate option {flag}")));
            }
            values.push(value);
        }
        let mut values = BTreeMap::new();
        if let Some(config) = cli.remove("config") {
            let file = File::open(&config[0])?;
            let object: BTreeMap<String, Value> = serde_json::from_reader(file)?;
            for (key, value) in object {
                let items = match value {
                    Value::Array(items) => items,
                    other => vec![other],
                };
                if items.is_empty()
                    || (items.len() > 1 && !matches!(key.as_str(), "ssh" | "http" | "internet"))
                {
                    return Err(fictionet::Error::msg(format!(
                        "invalid configuration value for {key}"
                    )));
                }
                let items = items
                    .into_iter()
                    .map(|item| match item {
                        Value::String(v) => Ok(v),
                        Value::Number(v) => Ok(v.to_string()),
                        Value::Bool(v) => Ok(v.to_string()),
                        _ => Err(fictionet::Error::msg(format!(
                            "invalid configuration value for {key}"
                        ))),
                    })
                    .collect::<fictionet::Result<Vec<_>>>()?;
                values.insert(key, items);
            }
        }
        values.extend(cli);
        Self::resolve(values)
    }

    fn resolve(mut values: BTreeMap<String, Vec<String>>) -> fictionet::Result<Self> {
        let backend = take(&mut values, "backend").unwrap_or_else(|| "world".into());
        let tun = take(&mut values, "tun");
        let tun_mode = take(&mut values, "tun-mode");
        let device = take(&mut values, "device");
        let invalid_backend_flags = match backend.as_str() {
            "world" => {
                tun.is_some()
                    || tun_mode.is_some()
                    || device.is_some()
                    || values.contains_key("gateway")
                    || values.contains_key("gateway-v6")
            }
            "tun" => {
                device.is_some()
                    || values.contains_key("world")
                    || values.contains_key("gateway")
                    || values.contains_key("gateway-v6")
            }
            "vfio" => tun.is_some() || tun_mode.is_some() || values.contains_key("world"),
            "xdp" | "af-xdp" | "ena" => {
                return Err(fictionet::Error::msg(
                    "XDP, AF_XDP and direct ENA ownership are not implemented; no backend was attached",
                ));
            }
            _ => return Err(fictionet::Error::msg("backend must be world, tun or vfio")),
        };
        if invalid_backend_flags {
            return Err(fictionet::Error::msg(
                "options from different packet backends cannot be combined",
            ));
        }
        let backend = match backend.as_str() {
            "world" => Backend::World,
            "tun" => {
                if !cfg!(target_os = "linux") {
                    return Err(fictionet::Error::msg("TUN requires Linux"));
                }
                let name =
                    tun.ok_or_else(|| fictionet::Error::msg("tun backend requires --tun NAME"))?;
                if name.is_empty()
                    || name.len() >= 16
                    || name
                        .bytes()
                        .any(|b| !(b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
                {
                    return Err(fictionet::Error::msg("invalid TUN interface name"));
                }
                let create = match tun_mode.as_deref().unwrap_or("existing") {
                    "existing" => false,
                    "create" => true,
                    _ => return Err(fictionet::Error::msg("tun-mode must be existing or create")),
                };
                Backend::Tun { name, create }
            }
            "vfio" => {
                if !cfg!(all(target_os = "linux", feature = "raw-virtio")) {
                    return Err(fictionet::Error::msg(
                        "VFIO virtio-net is unavailable in this build",
                    ));
                }
                let device = device
                    .ok_or_else(|| fictionet::Error::msg("vfio backend requires --device PCI"))?;
                #[cfg(all(target_os = "linux", feature = "raw-virtio"))]
                let _: fictionet_host::PciAddress = device.parse()?;
                Backend::Vfio { device }
            }
            _ => unreachable!(),
        };
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
        let dry_run = boolean(&mut values, "dry-run")?;
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
            if matches!(key.as_str(), "log" | "pcap") || Flag::parse(&flag).is_none() {
                return Err(fictionet::Error::msg(format!(
                    "unsupported option {flag}; evidence files belong to --state-dir"
                )));
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
        Ok(Self {
            backend,
            args,
            state_dir,
            metrics,
            dry_run,
            restricted_evidence,
            queue_bytes,
            max_record_bytes,
            rotate_bytes: rotate_bytes as u64,
            retain_files,
        })
    }

    pub fn summary(&self) -> Value {
        json!({
            "event": "configuration", "backend": self.backend.name(), "build": env!("CARGO_PKG_VERSION"),
            "address": self.args.config.address, "address_v6": self.args.config.address_v6,
            "persona": "Ubuntu 24.04 / Linux 6.8", "http_profile": format!("{:?}", self.args.config.http_profile),
            "listeners": self.args.config.ports.iter().map(|port| json!({"port": port.number, "service": format!("{:?}", port.service).to_lowercase()})).collect::<Vec<_>>(),
            "ssh_auth": match self.args.config.ssh_auth { SshAuth::Reject => "reject", SshAuth::AnyCredentials => "accept", SshAuth::PasswordOrPublicKey(_) => "configured_password_or_signed_public_key" },
            "internet_ipv4": self.args.config.internet.ipv4.to_string(), "internet_ipv6": self.args.config.internet.ipv6.to_string(),
            "burst_window_ms": self.args.config.burst.window.as_millis(), "burst_syns": self.args.config.burst.syns,
            "capture_boundary": if matches!(self.backend, Backend::Vfio { .. }) { "ethernet_and_derived_ip" } else { "ip" },
            "observations": ["mptcp", "ipv4_options", "ssh", "port_zero"],
            "state_dir": self.state_dir, "metrics": self.metrics, "restricted_evidence": self.restricted_evidence,
            "queue_bytes": self.queue_bytes, "max_record_bytes": self.max_record_bytes,
            "rotate_bytes": self.rotate_bytes, "retain_files_per_stream": self.retain_files, "observation_state_limit_per_map": honeypot_world::observe::STATE_LIMIT,
            "connection_limit": honeypot_world::CONNECTION_LIMIT,
            "public_reachability": "not_tested", "dry_run": self.dry_run,
            "attachment": match &self.backend {
                Backend::World => json!({"world": self.args.world.to_string()}),
                Backend::Tun {name, create} => json!({"tun": name, "mode": if *create {"create"} else {"existing"}, "mtu": 1500}),
                Backend::Vfio {device} => json!({"device": device, "gateway": self.args.config.gateway, "gateway_v6": format!("{:?}", self.args.config.gateway_v6)}),
            },
            "prerequisites": match self.backend {
                Backend::World => "Writable parent directory for the world socket; clients attach separately",
                Backend::Tun {create: false, ..} => "Prepared Linux guest; persistent, up, single-queue TUN with MTU 1500 and no packet-info or virtio headers; accessible sysfs; current network namespace; owner permissions; forwarding and decoy destination routes provisioned externally",
                Backend::Tun {create: true, ..} => "Prepared Linux guest; /dev/net/tun, CAP_NET_ADMIN, and writable per-interface IPv6 addr_gen_mode/autoconf/accept_ra sysctls under /proc/sys/net/ipv6/conf; unused name; kernel address autoconfiguration is suppressed before this ephemeral interface is brought up; forwarding and decoy destination routes provisioned externally",
                Backend::Vfio {..} => "Prepared QEMU guest with fictionet.rawnic=1, real IOMMU, isolated VFIO group and dedicated modern virtio-net device already bound to vfio-pci; separate management interface",
            }
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
        // SAFETY: geteuid takes no arguments and has no side effects.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
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
            // SAFETY: geteuid takes no arguments and has no side effects.
            if !metadata.is_file()
                || metadata.len() != size as u64
                || metadata.uid() != unsafe { libc::geteuid() }
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
    fn validates_backend_ownership_without_opening_devices() {
        assert!(
            options("run --backend tun --tun hp0 --dry-run")
                .unwrap()
                .dry_run
        );
        for line in [
            "--backend tun",
            "--backend tun --tun hp0 --world unix:/tmp/world",
            "--backend world --device 0000:00:03.0",
            "--backend world --gateway 1.2.3.4",
            "--backend tun --tun hp0 --tun-mode auto",
            "--backend xdp",
            "--backend ena",
            "--ssh 0",
            "--ssh 22 --http 22",
            "--queue-bytes 1",
            "--backend world --backend tun",
        ] {
            assert!(options(line).is_err(), "{line}");
        }
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

    #[test]
    fn file_configuration_and_cli_share_validation() {
        let directory = std::env::temp_dir().join(format!(
            "honeypot-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let file = directory.join("sensor.json");
        let state = directory.join("state");
        fs::write(
            &file,
            serde_json::to_vec(&json!({
                "backend": "tun", "tun": "hp0", "ssh": [22, 2222],
                "state-dir": state, "ssh-auth": "password:private-value",
            }))
            .unwrap(),
        )
        .unwrap();
        let options = Options::parse([
            "run".into(),
            "--config".into(),
            file.to_str().unwrap().into(),
            "--ssh".into(),
            "2223".into(),
            "--dry-run".into(),
        ])
        .unwrap();
        assert_eq!(
            options.backend,
            Backend::Tun {
                name: "hp0".into(),
                create: false
            }
        );
        assert_eq!(options.args.config.ports.len(), 1);
        assert_eq!(options.args.config.ports[0].number, 2223);
        assert!(options.dry_run);
        assert!(!options.summary().to_string().contains("private-value"));
        assert!(!state.exists());
        fs::write(&file, r#"{"backend":"world","tun":"hp0"}"#).unwrap();
        assert!(Options::parse(["--config".into(), file.to_str().unwrap().into()]).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
