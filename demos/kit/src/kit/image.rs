//! Prepared workstations and their per-run settings disk.

use super::{Guest, desktop, seed::Provision, ssh};
use std::io::{self, Cursor, Write};

/// The reusable disk built by `cargo xtask search-image`.
pub const WORKSTATION: &str = "search-workstation.qcow2";
pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
pub const START: &str = "https://www.google.com/";

const READY: &str = "env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && pgrep -x xfwm4 >/dev/null && env DISPLAY=:1 xdotool search --onlyvisible --class firefox >/dev/null";
const TERMINAL: &str = "env DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus tmux new-session -A -s main";

/// Runtime identity and consoles; all software is supplied by the image.
pub fn workstation() -> Guest {
    let mut guest = terminal_settings(Guest::prepared(HOST, USER, WORKSTATION))
        .resources(4, 4096)
        .desktop(desktop::VNC_PORT, READY)
        .terminal(TERMINAL);
    guest.features = super::Features {
        claude_code: true,
        codex: true,
        firefox: true,
    };
    guest
}

fn terminal_settings(guest: Guest) -> Guest {
    guest.file(
        &format!("/home/{USER}/.tmux.conf"),
        0o644,
        "set -g status off\n",
    )
}

/// Builds a settings disk without any package installation or network commands.
pub(super) fn seed(provision: &Provision<'_>) -> io::Result<Vec<u8>> {
    provision.guest.validate()?;
    let guest = provision.guest;
    if !guest.packages.is_empty() || !guest.steps.is_empty() {
        return Err(io::Error::other(
            "a prepared guest cannot install software at boot",
        ));
    }
    let mut script = String::from("set -eu\n");
    script.push_str(&format!("hostname {}\n", ssh::quote(&guest.hostname)));
    write_file(
        &mut script,
        &format!("/home/{}/.ssh/authorized_keys", guest.user),
        0o600,
        provision.authorized_key,
    );
    if let Some((name, pem)) = provision.ca {
        write_file(
            &mut script,
            &format!("/usr/local/share/ca-certificates/{name}.crt"),
            0o644,
            pem,
        );
        script.push_str("update-ca-certificates >/dev/null\n");
    }
    for file in &guest.files {
        write_file(&mut script, &file.path, file.mode, &file.content);
    }
    script.push_str(&format!(
        "chown -R {0}:{0} /home/{0}\nssh-keygen -A\n",
        guest.user
    ));
    disk("settings", "apply.sh", &script)
}

/// A FAT disk used by image construction and by per-run provisioning.
pub fn disk(label: &str, name: &str, content: &str) -> io::Result<Vec<u8>> {
    let mut volume_label = [b' '; 11];
    if label.len() > volume_label.len() {
        return Err(io::Error::other("disk label too long"));
    }
    volume_label[..label.len()].copy_from_slice(label.as_bytes());
    let mut cursor = Cursor::new(vec![0u8; 4 << 20]);
    fatfs::format_volume(
        &mut cursor,
        fatfs::FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat16)
            .volume_label(volume_label),
    )?;
    {
        let fs = fatfs::FileSystem::new(&mut cursor, fatfs::FsOptions::new())?;
        fs.root_dir()
            .create_file(name)?
            .write_all(content.as_bytes())?;
    }
    Ok(cursor.into_inner())
}

fn write_file(script: &mut String, path: &str, mode: u32, content: &str) {
    let parent = std::path::Path::new(path)
        .parent()
        .unwrap()
        .to_str()
        .unwrap();
    let encoded = fictionet::stdlib::codec::base64::encode(content.as_bytes());
    script.push_str(&format!(
        "mkdir -p {}\nprintf %s {} | base64 -d > {}\nchmod {mode:o} {}\n",
        ssh::quote(parent),
        ssh::quote(&encoded),
        ssh::quote(path),
        ssh::quote(path)
    ));
}

fn definition() -> Guest {
    terminal_settings(desktop::codex(desktop::claude_code(
        desktop::browser_image(HOST, USER, START),
    )))
    .packages(&[
        "xclip",
        "nmap",
        "tmux",
        "python3",
        "python3-pip",
        "python3-venv",
    ])
}

/// Image construction has no access to host credentials or per-run trust roots.
pub fn installation() -> io::Result<String> {
    let guest = definition();
    guest.validate()?;
    let mut script = format!(
        "set -eux\ntouch /etc/cloud/cloud-init.disabled\ngrowpart /dev/vda 1\nresize2fs /dev/vda1\nhostname {HOST}\nuseradd -m -s /bin/bash {USER}\nusermod -aG sudo {USER}\n"
    );
    write_file(
        &mut script,
        "/etc/sudoers.d/analyst",
        0o440,
        "analyst ALL=(ALL) NOPASSWD:ALL\n",
    );
    for file in &guest.files {
        write_file(&mut script, &file.path, file.mode, &file.content);
    }
    write_file(
        &mut script,
        "/etc/systemd/network/05-eth0.network",
        0o644,
        "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n",
    );
    write_file(
        &mut script,
        "/etc/profile.d/trust.sh",
        0o644,
        "export NODE_USE_SYSTEM_CA=1\nexport REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nexport SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n",
    );
    write_file(
        &mut script,
        "/etc/environment",
        0o644,
        "NODE_USE_SYSTEM_CA=1\nREQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nSSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n",
    );
    write_file(
        &mut script,
        "/etc/systemd/system.conf.d/trust.conf",
        0o644,
        "[Manager]\nDefaultEnvironment=NODE_USE_SYSTEM_CA=1 REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n",
    );
    script.push_str("apt-get update\nDEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl ");
    script.push_str(
        &guest
            .packages
            .iter()
            .map(|s| ssh::quote(s))
            .collect::<Vec<_>>()
            .join(" "),
    );
    script.push('\n');
    for step in &guest.steps {
        script.push_str(step);
        script.push('\n');
    }
    write_file(
        &mut script,
        "/etc/systemd/system/workstation-settings.service",
        0o644,
        "[Unit]\nDescription=Workstation settings\nDefaultDependencies=no\nRequires=dev-vdb.device\nAfter=local-fs.target dev-vdb.device\nBefore=ssh.service ssh.socket vnc.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/bash -euc 'mkdir -p /run/settings; mount -o ro /dev/disk/by-label/settings /run/settings; /bin/bash /run/settings/apply.sh; umount /run/settings'\n[Install]\nWantedBy=multi-user.target\n",
    );
    for unit in ["ssh.service", "ssh.socket", "vnc.service"] {
        write_file(
            &mut script,
            &format!("/etc/systemd/system/{unit}.d/settings.conf"),
            0o644,
            "[Unit]\nRequires=workstation-settings.service\nAfter=workstation-settings.service\n",
        );
    }
    script.push_str("systemctl enable workstation-settings.service systemd-networkd.service\n");
    script.push_str("systemctl mask systemd-networkd-wait-online.service pollinate.service\n");
    script.push_str("rm -f /opt/install-claude.sh /opt/install-codex.sh /opt/setup-desktop.sh\nrm -rf /var/lib/cloud /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/* /var/tmp/* /home/analyst/.cache\nsystemctl stop systemd-random-seed.service\nrm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed /var/lib/dbus/machine-id\ntruncate -s 0 /etc/machine-id\nrm -rf /mnt/build\nfind /var/log -type f -exec truncate -s 0 {} +\nclaude --version\ncodex --version\npython3 --version\nsync\n");
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn image_installs_the_complete_quiet_workstation() {
        let guest = definition();
        guest.validate().unwrap();
        for package in [
            "firefox",
            "python3",
            "python3-pip",
            "python3-venv",
            "dbus-user-session",
            "xdotool",
            "xclip",
            "nmap",
            "tmux",
            "tigervnc-standalone-server",
            "xfce4",
        ] {
            assert!(guest.packages.iter().any(|p| p == package), "{package}");
        }
        let file = |path: &str| {
            &guest
                .files
                .iter()
                .find(|file| file.path == path)
                .unwrap()
                .content
        };
        assert_eq!(file("/etc/apt/apt.conf.d/20apt-esm-hook.conf"), "");
        assert!(file("/opt/start-desktop.sh").contains(&format!(
            "firefox --profile \"$HOME/.mozilla/firefox/default\" '{START}'"
        )));
        assert!(
            file("/etc/firefox/policies/policies.json")
                .contains("firefox.settings.services.mozilla.com")
        );
        assert!(file("/etc/apt/apt.conf.d/99periodic").contains("APT::Periodic::Enable \"0\""));
        assert!(file("/etc/default/motd-news").contains("ENABLED=0"));
        file("/etc/systemd/timesyncd.conf");
        file("/etc/systemd/system/apt-daily.timer.d/quiet.conf");
        file("/etc/claude-code/managed-settings.json");
        assert_eq!(file("/home/analyst/.tmux.conf"), "set -g status off\n");
        assert!(
            guest
                .steps
                .iter()
                .any(|step| step.contains("then systemctl stop apt-daily.timer; fi"))
        );
        assert!(
            !guest
                .steps
                .iter()
                .any(|step| step.contains("systemctl start vnc"))
        );
        assert!(!file("/opt/setup-desktop.sh").contains("enable --now"));
        assert!(!installation().unwrap().contains("date -u -s"));
    }

    #[test]
    fn prepared_settings_are_per_run_and_never_install_packages() {
        let guest = workstation().file("/home/analyst/.claude/settings.json", 0o600, "placeholder");
        let data = seed(&Provision {
            guest: &guest,
            authorized_key: "fresh-key",
            ca: Some(("office", "fresh-ca")),
        })
        .unwrap();
        let fs = fatfs::FileSystem::new(Cursor::new(data), fatfs::FsOptions::new()).unwrap();
        let mut script = String::new();
        fs.root_dir()
            .open_file("apply.sh")
            .unwrap()
            .read_to_string(&mut script)
            .unwrap();
        for value in ["fresh-key", "fresh-ca", "placeholder"] {
            assert!(script.contains(&fictionet::stdlib::codec::base64::encode(value.as_bytes())));
            assert!(!installation().unwrap().contains(value));
        }
        assert!(script.contains(&fictionet::stdlib::codec::base64::encode(
            b"set -g status off\n"
        )));
        assert!(script.contains(" > '/home/analyst/.tmux.conf'"));
        assert!(!script.contains("apt-get"));
        assert!(!script.contains("curl"));
        assert!(
            seed(&Provision {
                guest: &guest.packages(&["curl"]),
                authorized_key: "key",
                ca: None
            })
            .is_err()
        );
    }
}
