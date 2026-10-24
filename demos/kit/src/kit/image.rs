//! Prepared workstations and their per-run settings disk.

use super::{Software, seed::Provision, ssh};
use std::io::{self, Cursor, Write};

/// A software recipe, separate from the identity used to boot an existing image.
pub struct Recipe {
    pub(super) hostname: String,
    pub(super) user: String,
    pub(super) files: Vec<super::File>,
    pub(super) packages: Vec<Package>,
    pub(super) steps: Vec<String>,
}

pub(super) enum Package {
    Repository(String),
    Archive {
        name: String,
        url: String,
        checksum: String,
    },
}

impl Recipe {
    /// Replaces a repository package with a checksum-verified Debian archive.
    pub fn archive(mut self, name: &str, url: &str, checksum: &str) -> io::Result<Self> {
        let package = self
            .packages
            .iter_mut()
            .find(|package| matches!(package, Package::Repository(value) if value == name))
            .ok_or_else(|| io::Error::other("archive must replace an existing package"))?;
        *package = Package::Archive {
            name: name.into(),
            url: url.into(),
            checksum: checksum.into(),
        };
        Ok(self)
    }
}

/// Builds a settings disk without any package installation or network commands.
pub(super) fn seed<P: Software>(provision: &Provision<'_, P>) -> io::Result<Vec<u8>> {
    let guest = provision.guest;
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

/// Image construction has no access to host credentials or per-run trust roots.
pub fn installation(recipe: &Recipe) -> String {
    let Recipe {
        hostname,
        user,
        files,
        packages,
        steps,
    } = recipe;
    let mut script = format!(
        "set -euxo pipefail\ntouch /etc/cloud/cloud-init.disabled\ngrowpart /dev/vda 1\nresize2fs /dev/vda1\nhostname {hostname}\nuseradd -m -s /bin/bash {user}\nusermod -aG sudo {user}\n"
    );
    write_file(
        &mut script,
        &format!("/etc/sudoers.d/{user}"),
        0o440,
        &format!("{user} ALL=(ALL) NOPASSWD:ALL\n"),
    );
    for file in files {
        write_file(&mut script, &file.path, file.mode, &file.content);
    }
    for (path, content) in super::seed::trust_files() {
        write_file(&mut script, path, 0o644, &content);
    }
    let environment: String = super::seed::TRUST_ENV
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect();
    write_file(&mut script, "/etc/environment", 0o644, &environment);
    let mut arguments = Vec::new();
    for package in packages {
        match package {
            Package::Repository(name) => arguments.push(ssh::quote(name)),
            Package::Archive {
                name,
                url,
                checksum,
            } => {
                let path = format!("/var/tmp/{name}.deb");
                script.push_str(&format!(
                    "curl -fsSL -o {} {}\necho {} | sha256sum -c -\n",
                    ssh::quote(&path),
                    ssh::quote(url),
                    ssh::quote(&format!("{checksum}  {path}"))
                ));
                arguments.push(ssh::quote(&path));
            }
        }
    }
    script.push_str("apt-get update\nDEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl ");
    script.push_str(&arguments.join(" "));
    script.push('\n');
    for step in steps {
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
    let cache = ssh::quote(&format!("/home/{user}/.cache"));
    script.push_str(&format!(
        "rm -f /opt/install-claude.sh /opt/install-codex.sh /opt/setup-desktop.sh\nrm -rf /var/lib/cloud /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/* /var/tmp/* {cache}\nsystemctl stop systemd-random-seed.service\nrm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed /var/lib/dbus/machine-id\ntruncate -s 0 /etc/machine-id\nrm -rf /mnt/build\nfind /var/log -type f -exec truncate -s 0 {{}} +\nclaude --version\ncodex --version\npython3 --version\nsync\n"
    ));
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::Guest;
    use std::io::Read;

    #[test]
    fn prepared_settings_are_per_run_and_never_install_packages() {
        let guest = Guest::prepared("station", "analyst", "desktop.qcow2")
            .file("/home/analyst/.tmux.conf", 0o644, "set -g status off\n")
            .file("/home/analyst/.claude/settings.json", 0o600, "placeholder");
        let data = super::super::seed::build(&Provision {
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
        for value in [
            "fresh-key",
            "fresh-ca",
            "placeholder",
            "set -g status off\n",
        ] {
            assert!(script.contains(&fictionet::stdlib::codec::base64::encode(value.as_bytes())));
        }
        assert!(script.contains(" > '/home/analyst/.tmux.conf'"));
        assert!(!script.contains("apt-get"));
        assert!(!script.contains("curl"));
    }
}
