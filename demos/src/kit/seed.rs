//! NoCloud provisioning for an unmodified Ubuntu cloud image.
use super::Guest;
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use fictionet::stdlib::codec::base64;
use std::collections::BTreeMap;
use std::io::{Cursor, Write};

/// The variables that point TLS clients at the system trust store: Node,
/// Python's requests, and OpenSSL's users.
const TRUST_ENV: &[(&str, &str)] = &[
    ("NODE_USE_SYSTEM_CA", "1"),
    ("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"),
    ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
];

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
    let audit = example_common::guest_content::Audit::default();
    for (path, content) in files(&user_data)? {
        audit.installed(&path, content.as_bytes());
    }
    audit.inspect(
        "device manufacturer",
        provision.guest.manufacturer.as_bytes(),
    );
    audit.inspect("device product", provision.guest.product.as_bytes());
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
            audit.installed(name, body.as_bytes());
            let mut file = root.create_file(name).map_err(std::io::Error::other)?;
            file.truncate().map_err(std::io::Error::other)?;
            file.write_all(body.as_bytes())?;
        }
    }
    audit.check().map_err(std::io::Error::other)?;
    Ok(cursor.into_inner())
}

/// Reads back the files a rendered [`user_data`] writes, by path. Tests use
/// it to check a seed as the guest receives it.
pub fn files(user_data: &str) -> std::io::Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    let mut path = None;
    for line in user_data.lines() {
        if let Some(quoted) = line.strip_prefix("  - path: ") {
            path = Some(serde_json::from_str::<String>(quoted)?);
        } else if let Some(encoded) = line.strip_prefix("    content: ") {
            let path = path
                .take()
                .ok_or_else(|| std::io::Error::other("file content without a path"))?;
            let encoded: String = serde_json::from_str(encoded)?;
            let bytes = base64::decode(encoded.as_bytes(), base64::Padding::Required)
                .ok_or_else(|| std::io::Error::other(format!("{path}: invalid base64")))?;
            files.insert(
                path,
                String::from_utf8(bytes).map_err(std::io::Error::other)?,
            );
        }
    }
    Ok(files)
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
    let assignments: Vec<_> = TRUST_ENV.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let systemd = format!("[Manager]\nDefaultEnvironment={}\n", assignments.join(" "));
    let profile: String = assignments
        .iter()
        .map(|a| format!("export {a}\n"))
        .collect();
    let shared = [
        (
            "/etc/systemd/network/05-eth0.network",
            "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n",
        ),
        ("/etc/systemd/system.conf.d/trust.conf", systemd.as_str()),
        ("/etc/profile.d/trust.sh", profile.as_str()),
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
            quote(&base64::encode(content.as_bytes()))
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
        format!(
            "printf '%s\\n' {} >> /etc/environment",
            assignments.join(" ")
        ),
        "systemctl daemon-reexec".into(),
    ];
    if !g.packages.is_empty() {
        commands.push("apt-get update".into());
        commands.push(format!(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {}",
            g.packages
                .iter()
                .map(|s| super::ssh::quote(s))
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
