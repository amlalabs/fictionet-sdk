//! Prepared workstations: the installation recipe and the files its build
//! leaves beside the image.

use super::ssh;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};

/// A software recipe, separate from the identity used to boot an existing image.
pub struct Recipe {
    pub(super) hostname: String,
    pub(super) user: String,
    pub(super) admin_key: String,
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

/// A prepared image in the downloads folder, and the files its build
/// leaves beside it, each readable only by its owner.
pub struct Baked {
    image: PathBuf,
}

impl Baked {
    /// The image file `image` in `downloads`.
    pub fn new(downloads: &Path, image: &str) -> Self {
        Self {
            image: downloads.join(image),
        }
    }
    /// The image itself.
    pub fn image(&self) -> &Path {
        &self.image
    }
    /// The private half of the key the image's admin account accepts.
    pub fn admin_key(&self) -> PathBuf {
        self.beside("key")
    }
    /// The key material of the certificate authority whose root the image trusts.
    pub fn trust_root(&self) -> PathBuf {
        self.beside("ca.pem")
    }
    /// The placeholder the image carries in place of a model credential.
    pub fn placeholder(&self) -> PathBuf {
        self.beside("token")
    }
    fn beside(&self, suffix: &str) -> PathBuf {
        let stem = self.image.file_stem().unwrap_or_default().to_string_lossy();
        self.image.with_file_name(format!("{stem}.{suffix}"))
    }
}

/// Writes `content` to `path`, readable only by its owner, replacing any
/// earlier file whole.
pub fn write_private(path: &Path, content: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut partial = path.as_os_str().to_owned();
    partial.push(".part");
    let partial = PathBuf::from(partial);
    let _ = std::fs::remove_file(&partial);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(partial, path)
}

/// A FAT disk used by image construction.
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

/// The image's installation script: the user, the admin account the host
/// logs in as, the recipe's files, packages and steps, then cleanup.
pub fn installation(recipe: &Recipe) -> String {
    let Recipe {
        hostname,
        user,
        admin_key,
        files,
        packages,
        steps,
    } = recipe;
    let admin = super::ADMIN;
    let mut script = format!(
        "set -euxo pipefail\ntouch /etc/cloud/cloud-init.disabled\ngrowpart /dev/vda 1\nresize2fs /dev/vda1\nhostname {hostname}\necho {hostname} > /etc/hostname\necho '127.0.1.1 {hostname}' >> /etc/hosts\nuseradd -m -s /bin/bash {user}\nusermod -aG sudo {user}\nuseradd -m -s /bin/bash {admin}\n"
    );
    for account in [user.as_str(), admin] {
        write_file(
            &mut script,
            &format!("/etc/sudoers.d/{account}"),
            0o440,
            &format!("{account} ALL=(ALL) NOPASSWD:ALL\n"),
        );
    }
    write_file(
        &mut script,
        &format!("/home/{admin}/.ssh/authorized_keys"),
        0o600,
        admin_key,
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
    script.push_str(&format!(
        "chown -R {user}:{user} /home/{user}\nchown -R {admin}:{admin} /home/{admin}\nssh-keygen -A\n"
    ));
    script.push_str("systemctl enable systemd-networkd.service\n");
    script.push_str("systemctl mask systemd-networkd-wait-online.service pollinate.service\n");
    let cache = ssh::quote(&format!("/home/{user}/.cache"));
    script.push_str(&format!(
        "rm -f /opt/install-claude.sh /opt/install-codex.sh /opt/setup-desktop.sh\nrm -rf /var/lib/cloud /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/* /var/tmp/* {cache}\nsystemctl stop systemd-random-seed.service\nrm -f /var/lib/systemd/random-seed /var/lib/dbus/machine-id\ntruncate -s 0 /etc/machine-id\nrm -rf /mnt/build\nfind /var/log -type f -exec truncate -s 0 {{}} +\nclaude --version\ncodex --version\npython3 --version\nsync\n"
    ));
    script
}
