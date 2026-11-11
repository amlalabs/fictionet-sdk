//! What the instance runs, built from typed settings: the first-boot user
//! data that keeps Linux off the data interface, and the honeypot's unit.

use std::net::Ipv4Addr;

use super::aws::MacAddress;

pub const BINARY: &str = "/usr/local/bin/honeypot";
pub const COMMIT_FILE: &str = "/usr/local/share/honeypot/commit";
pub const UNIT: &str = "/etc/systemd/system/honeypot.service";
pub const USER: &str = "honeypot";
pub const STATE_DIR: &str = "/var/lib/honeypot";

/// One file the first boot writes.
pub struct File {
    pub path: &'static str,
    pub mode: u32,
    pub content: String,
}

/// The first boot's work: Linux leaves the data interface (found by its MAC
/// address) unconfigured, with IPv6 off before the link is ever up, and the
/// service account and its state directory exist.
pub struct FirstBoot {
    pub data_mac: MacAddress,
}

impl FirstBoot {
    pub fn files(&self) -> Vec<File> {
        let mac = &self.data_mac;
        vec![
            // Sorts before the 70- files amazon-ec2-net-utils writes per
            // interface, so systemd-networkd matches this one first.
            File {
                path: "/etc/systemd/network/10-honeypot-data.network",
                mode: 0o644,
                content: format!("[Match]\nMACAddress={mac}\n\n[Link]\nUnmanaged=yes\n"),
            },
            // Runs when the interface appears, after udev has renamed it and
            // before anything brings it up.
            File {
                path: "/etc/udev/rules.d/90-honeypot-data.rules",
                mode: 0o644,
                content: format!(
                    "ACTION==\"add\", SUBSYSTEM==\"net\", ATTR{{address}}==\"{mac}\", \
                     RUN+=\"/usr/sbin/sysctl -q -w net.ipv6.conf.$name.accept_ra=0 \
                     net.ipv6.conf.$name.addr_gen_mode=1 net.ipv6.conf.$name.disable_ipv6=1\"\n"
                ),
            },
            File {
                path: "/etc/sysctl.d/90-honeypot.conf",
                mode: 0o644,
                content: "net.ipv4.ip_forward = 0\n".into(),
            },
        ]
    }

    pub fn commands(&self) -> Vec<Vec<String>> {
        let command = |words: &[&str]| words.iter().map(|w| w.to_string()).collect();
        vec![
            command(&[
                "useradd",
                "--system",
                "--no-create-home",
                "--shell",
                "/sbin/nologin",
                USER,
            ]),
            command(&[
                "install", "-d", "-m", "0700", "-o", USER, "-g", USER, STATE_DIR,
            ]),
            command(&["sysctl", "--system"]),
            command(&["udevadm", "control", "--reload"]),
            command(&["networkctl", "reload"]),
        ]
    }

    /// The cloud-init document. Every value is quoted as JSON, which YAML
    /// reads as the same string.
    pub fn user_data(&self) -> String {
        let quote = |text: &str| serde_json::Value::from(text).to_string();
        let mut out = String::from("#cloud-config\nwrite_files:\n");
        for file in self.files() {
            out += &format!(
                "  - path: {}\n    permissions: {}\n    content: {}\n",
                quote(file.path),
                quote(&format!("0{:o}", file.mode)),
                quote(&file.content),
            );
        }
        out += "runcmd:\n";
        for command in self.commands() {
            let words: Vec<_> = command.iter().map(|w| quote(w)).collect();
            out += &format!("  - [{}]\n", words.join(", "));
        }
        out
    }
}

/// The honeypot service as systemd runs it.
pub struct Service {
    /// The data interface's private address, which the world answers on.
    pub address: Ipv4Addr,
    /// The subnet's VPC router.
    pub gateway: Ipv4Addr,
    pub memory_max_mib: u32,
}

impl Service {
    /// The command line, one argument per element.
    pub fn command(&self) -> Vec<String> {
        [
            BINARY,
            "run",
            "--state-dir",
            STATE_DIR,
            "--address",
            &self.address.to_string(),
            "--gateway",
            &self.gateway.to_string(),
        ]
        .map(String::from)
        .to_vec()
    }

    pub fn unit(&self) -> String {
        let command = self.command();
        // Arguments are paths, fixed words and addresses, so none needs
        // quoting on the ExecStart line.
        debug_assert!(
            command
                .iter()
                .all(|word| !word.contains(char::is_whitespace))
        );
        format!(
            "[Unit]\n\
             Description=Fictionet honeypot\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             StartLimitIntervalSec=0\n\
             \n\
             [Service]\n\
             User={USER}\n\
             Group={USER}\n\
             ExecStart={exec}\n\
             Restart=always\n\
             RestartSec=5\n\
             MemoryMax={memory}M\n\
             MemorySwapMax=0\n\
             AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF\n\
             CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF\n\
             NoNewPrivileges=yes\n\
             ProtectSystem=strict\n\
             ProtectHome=yes\n\
             PrivateTmp=yes\n\
             ReadWritePaths={STATE_DIR}\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            exec = command.join(" "),
            memory = self.memory_max_mib,
        )
    }
}

/// The compiler arguments `zig cc` gets when it stands in for a musl C
/// compiler. cc-rs adds Rust's `--target=` triple, which zig does not parse;
/// zig gets its own. zig enables UBSan in unoptimized C, which aws-lc uses
/// for one file, and Rust's link has no UBSan runtime, so it is turned off.
pub fn musl_cc_arguments(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> =
        ["cc", "-target", "x86_64-linux-musl", "-fno-sanitize=all"]
            .map(Into::into)
            .to_vec();
    out.extend(
        args.into_iter()
            .filter(|arg| !arg.to_string_lossy().starts_with("--target=")),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_boot() -> FirstBoot {
        FirstBoot {
            data_mac: MacAddress::try_from("0a:1b:2c:3d:4e:5f".to_owned()).unwrap(),
        }
    }

    /// The fields of one `write_files` entry in the generated document.
    fn written(user_data: &str) -> Vec<(String, String, String)> {
        let lines: Vec<_> = user_data.lines().collect();
        let value = |line: &str, key: &str| -> String {
            let json = line
                .trim_start()
                .trim_start_matches("- ")
                .strip_prefix(key)
                .unwrap();
            serde_json::from_str(json).unwrap()
        };
        lines
            .windows(3)
            .filter(|w| w[0].starts_with("  - path: "))
            .map(|w| {
                (
                    value(w[0], "path: "),
                    value(w[1], "permissions: "),
                    value(w[2], "content: "),
                )
            })
            .collect()
    }

    #[test]
    fn user_data_writes_every_file_whole() {
        let boot = first_boot();
        let user_data = boot.user_data();
        assert!(user_data.starts_with("#cloud-config\n"));
        let files = boot.files();
        let entries = written(&user_data);
        assert_eq!(entries.len(), files.len());
        for (file, (path, mode, content)) in files.iter().zip(entries) {
            assert_eq!(path, file.path);
            assert_eq!(u32::from_str_radix(&mode, 8).unwrap(), file.mode);
            assert_eq!(content, file.content);
        }
    }

    #[test]
    fn user_data_runs_every_command_word_for_word() {
        let boot = first_boot();
        let user_data = boot.user_data();
        let run: Vec<Vec<String>> = user_data
            .split("runcmd:\n")
            .nth(1)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line.strip_prefix("  - ").unwrap()).unwrap())
            .collect();
        assert_eq!(run, boot.commands());
    }

    #[test]
    fn the_data_interface_is_matched_by_its_mac_and_left_unmanaged() {
        let boot = first_boot();
        let files = boot.files();
        let network = files.iter().find(|f| f.path.ends_with(".network")).unwrap();
        assert!(
            network
                .content
                .lines()
                .any(|l| l == "MACAddress=0a:1b:2c:3d:4e:5f")
        );
        assert!(network.content.lines().any(|l| l == "Unmanaged=yes"));
        let rule = files.iter().find(|f| f.path.ends_with(".rules")).unwrap();
        assert!(
            rule.content
                .contains("ATTR{address}==\"0a:1b:2c:3d:4e:5f\"")
        );
        for setting in ["disable_ipv6=1", "accept_ra=0", "addr_gen_mode=1"] {
            assert!(
                rule.content
                    .contains(&format!("net.ipv6.conf.$name.{setting}"))
            );
        }
    }

    fn service() -> Service {
        Service {
            address: Ipv4Addr::new(172, 31, 20, 7),
            gateway: Ipv4Addr::new(172, 31, 16, 1),
            memory_max_mib: 4096,
        }
    }

    /// `key=value` lines of one unit section.
    fn section(unit: &str, name: &str) -> Vec<(String, String)> {
        unit.split(&format!("[{name}]\n"))
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|line| !line.starts_with('['))
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn the_unit_runs_the_typed_command_and_restarts_within_a_memory_limit() {
        let service = service();
        let unit = service.unit();
        let settings = section(&unit, "Service");
        let get = |key: &str| {
            settings
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{key} missing"))
        };
        let exec: Vec<String> = get("ExecStart").split(' ').map(String::from).collect();
        assert_eq!(exec, service.command());
        let address = exec.iter().position(|a| a == "--address").unwrap();
        assert_eq!(exec[address + 1], service.address.to_string());
        let gateway = exec.iter().position(|a| a == "--gateway").unwrap();
        assert_eq!(exec[gateway + 1], service.gateway.to_string());
        assert_eq!(get("Restart"), "always");
        assert_eq!(get("MemoryMax"), format!("{}M", service.memory_max_mib));
        assert_eq!(get("User"), USER);
        assert_eq!(get("ReadWritePaths"), STATE_DIR);
        assert_eq!(
            get("AmbientCapabilities"),
            get("CapabilityBoundingSet"),
            "the service holds no capability beyond the ones it is given"
        );
        assert!(section(&unit, "Unit").contains(&("StartLimitIntervalSec".into(), "0".into())));
    }

    #[test]
    fn zig_gets_its_own_target_in_place_of_rusts() {
        let args = musl_cc_arguments(
            ["--target=x86_64-unknown-linux-musl", "-O2", "-c", "a.c"].map(Into::into),
        );
        let args: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a.starts_with("--target=")));
        let target = args.iter().position(|a| a == "-target").unwrap();
        assert_eq!(args[target + 1], "x86_64-linux-musl");
        assert!(args.ends_with(&["-O2".into(), "-c".into(), "a.c".into()]));
    }
}
