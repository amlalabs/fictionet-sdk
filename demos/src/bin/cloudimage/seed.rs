//! The cloud-init NoCloud seed: a small FAT image labelled `cidata`,
//! written in Rust, carrying `meta-data` and a `#cloud-config` user-data.
//!
//! The user-data provisions the guest at boot with nothing baked into the
//! image: a neutral hostname, a sudo user holding this run's SSH public key,
//! the world's CA installed the distro way (`update-ca-certificates`), and a
//! systemd socket unit that runs sshd on vsock port 22 with no listener on
//! any network interface.

use std::io::{Cursor, Write};

use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};

/// What the guest is provisioned with.
pub struct Provision<'a> {
    /// A neutral hostname, nothing that names an eval.
    pub hostname: &'a str,
    /// The login the control plane uses.
    pub user: &'a str,
    /// This run's SSH public key, as one `authorized_keys` line.
    pub authorized_key: &'a str,
    /// The world's CA root, in PEM, installed as `zscaler.crt`.
    pub ca_pem: &'a str,
    /// Whether to wait for the network at boot. Off until the world's NIC is
    /// attached, so cloud-init does not stall on `networkd-wait-online`.
    pub wait_online: bool,
}

/// Builds the `cidata` FAT image bytes for `provision`.
pub fn build(provision: &Provision) -> std::io::Result<Vec<u8>> {
    let user_data = user_data(provision);
    let meta_data = format!(
        "instance-id: iid-{0}\nlocal-hostname: {0}\n",
        provision.hostname
    );

    // A couple of mebibytes is ample for two small files and keeps FAT12.
    let mut cursor = Cursor::new(vec![0u8; 4 << 20]);
    fatfs::format_volume(
        &mut cursor,
        FormatVolumeOptions::new()
            .fat_type(FatType::Fat12)
            .volume_label(*b"cidata     "),
    )
    .map_err(std::io::Error::other)?;
    {
        let fs = FileSystem::new(&mut cursor, FsOptions::new()).map_err(std::io::Error::other)?;
        let root = fs.root_dir();
        for (name, body) in [
            ("meta-data", meta_data.as_str()),
            ("user-data", user_data.as_str()),
            ("vendor-data", ""),
        ] {
            let mut file = root.create_file(name).map_err(std::io::Error::other)?;
            file.truncate().map_err(std::io::Error::other)?;
            file.write_all(body.as_bytes())?;
        }
    }
    Ok(cursor.into_inner())
}

/// The `#cloud-config` document.
fn user_data(p: &Provision) -> String {
    // The CA, indented under a YAML block scalar.
    let ca_indented: String = p
        .ca_pem
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect();
    // sshd on vsock port 22: a socket unit accepting connections and a
    // per-connection template that runs sshd in inetd mode. No network
    // listener is opened.
    let mask_wait_online = if p.wait_online {
        ""
    } else {
        "  - systemctl mask systemd-networkd-wait-online.service\n"
    };
    format!(
        "#cloud-config\n\
         hostname: {hostname}\n\
         fqdn: {hostname}\n\
         preserve_hostname: false\n\
         users:\n\
         \x20 - name: {user}\n\
         \x20   sudo: 'ALL=(ALL) NOPASSWD:ALL'\n\
         \x20   shell: /bin/bash\n\
         \x20   lock_passwd: true\n\
         \x20   ssh_authorized_keys:\n\
         \x20     - {key}\n\
         write_files:\n\
         \x20 - path: /usr/local/share/ca-certificates/zscaler.crt\n\
         \x20   permissions: '0644'\n\
         \x20   content: |\n\
         {ca_indented}\
         \x20 - path: /etc/systemd/system/sshd-vsock.socket\n\
         \x20   content: |\n\
         \x20     [Unit]\n\
         \x20     Description=sshd over vsock\n\
         \x20     [Socket]\n\
         \x20     ListenStream=vsock::22\n\
         \x20     Accept=yes\n\
         \x20     [Install]\n\
         \x20     WantedBy=sockets.target\n\
         \x20 - path: /etc/systemd/system/sshd-vsock@.service\n\
         \x20   content: |\n\
         \x20     [Unit]\n\
         \x20     Description=sshd for one vsock connection\n\
         \x20     [Service]\n\
         \x20     ExecStart=-/usr/sbin/sshd -i\n\
         \x20     StandardInput=socket\n\
         runcmd:\n\
         \x20 - update-ca-certificates\n\
         \x20 - ssh-keygen -A\n\
         \x20 - systemctl daemon-reload\n\
         \x20 - systemctl enable --now sshd-vsock.socket\n\
         {mask_wait_online}",
        hostname = p.hostname,
        user = p.user,
        key = p.authorized_key,
    )
}
