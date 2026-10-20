//! NoCloud provisioning for an unmodified Ubuntu cloud image.
use super::{Guest, base64};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use std::io::{Cursor, Write};

/// The guest configuration and credentials for one seed.
pub struct Provision<'a> {
    /// The guest identity and provisioning steps.
    pub guest: &'a Guest,
    /// The public SSH key allowed to log in.
    pub authorized_key: &'a str,
    /// An optional root certificate name and PEM content.
    pub ca: Option<(&'a str, &'a str)>,
}

/// Builds the `cidata` FAT image bytes for `provision`.
pub fn build(provision: &Provision) -> std::io::Result<Vec<u8>> {
    provision.guest.validate()?;
    if provision
        .ca
        .is_some_and(|(name, _)| !super::valid_name(name))
    {
        return Err(std::io::Error::other("invalid root certificate name"));
    }
    let user_data = user_data(provision);
    let meta_data = format!(
        "instance-id: iid-{0}\nlocal-hostname: {0}\n",
        provision.guest.hostname
    );
    // DHCP the one NIC from the world; the world leases by MAC.
    let network_config = "version: 2\n\
         ethernets:\n\
         \x20 eth0:\n\
         \x20   match:\n\
         \x20     name: eth0\n\
         \x20   dhcp4: true\n\
         \x20   dhcp-identifier: mac\n";

    // 32 MiB holds the user-data (the embedded files, base64) with room.
    let mut cursor = Cursor::new(vec![0u8; 32 << 20]);
    fatfs::format_volume(
        &mut cursor,
        FormatVolumeOptions::new()
            .fat_type(FatType::Fat16)
            .volume_label(*b"cidata     "),
    )
    .map_err(std::io::Error::other)?;
    {
        let fs = FileSystem::new(&mut cursor, FsOptions::new()).map_err(std::io::Error::other)?;
        let root = fs.root_dir();
        for (name, body) in [
            ("meta-data", meta_data.as_str()),
            ("user-data", user_data.as_str()),
            ("network-config", network_config),
            ("vendor-data", ""),
        ] {
            let mut file = root.create_file(name).map_err(std::io::Error::other)?;
            file.truncate().map_err(std::io::Error::other)?;
            file.write_all(body.as_bytes())?;
        }
    }
    Ok(cursor.into_inner())
}

/// Builds cloud-init's user data, including the shared trust store.
pub fn user_data(p: &Provision) -> String {
    let g = p.guest;
    let quote = |s: &str| serde_json::to_string(s).expect("a string");
    let mut out = format!(
        concat!(
            "#cloud-config\nhostname: {}\npreserve_hostname: false\nusers:\n",
            "  - name: {}\n    sudo: 'ALL=(ALL) NOPASSWD:ALL'\n    shell: /bin/bash\n",
            "    lock_passwd: true\n    ssh_authorized_keys:\n      - {}\nwrite_files:\n",
        ),
        quote(&g.hostname),
        quote(&g.user),
        quote(p.authorized_key)
    );
    let shared = [
        (
            "/etc/systemd/network/05-eth0.network",
            "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n",
        ),
        (
            "/etc/systemd/system.conf.d/trust.conf",
            "[Manager]\nDefaultEnvironment=NODE_USE_SYSTEM_CA=1 \
                REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
                SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n",
        ),
        (
            "/etc/profile.d/trust.sh",
            "export NODE_USE_SYSTEM_CA=1\n\
             export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\n\
             export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n",
        ),
    ];
    let root =
        p.ca.map(|(name, pem)| (format!("/usr/local/share/ca-certificates/{name}.crt"), pem));
    for (path, mode, content) in root
        .iter()
        .map(|(path, pem)| (path.as_str(), 0o644, *pem))
        .chain(shared.iter().map(|(p, c)| (*p, 0o644, *c)))
        .chain(
            g.files
                .iter()
                .map(|f| (f.path.as_str(), f.mode, f.content.as_str())),
        )
    {
        out.push_str(&format!(
            "  - path: {}\n    permissions: '{mode:04o}'\n    encoding: b64\n    content: {}\n",
            quote(path),
            base64(content.as_bytes())
        ));
        if path.starts_with(&format!("/home/{}/", g.user)) {
            out.push_str(&format!(
                "    owner: {}:{}\n    defer: true\n",
                g.user, g.user
            ));
        }
    }
    out.push_str("runcmd:\n");
    let mut commands = vec![
        "apt-get update".to_string(),
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            ca-certificates"
            .into(),
        "update-ca-certificates".into(),
        "printf '%s\\n' NODE_USE_SYSTEM_CA=1 \
            REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
            SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt >> /etc/environment"
            .into(),
        "systemctl daemon-reexec".into(),
    ];
    if !g.packages.is_empty() {
        commands.push("apt-get update".into());
        commands.push(format!(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {}",
            g.packages
                .iter()
                .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    commands.extend(g.steps.iter().cloned());
    // One shell stops provisioning on the first failed command.
    out.push_str(&format!(
        "  - [bash, -euc, {}]\n",
        quote(&commands.join("\n"))
    ));
    out
}
