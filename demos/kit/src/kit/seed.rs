//! NoCloud provisioning for an unmodified Ubuntu cloud image.
use super::{Guest, Installation, Software};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use fictionet::stdlib::codec::base64;
use fictionet::stdlib::protocols::dns::dnssec::TrustAnchor;
use std::collections::BTreeMap;
use std::io::{Cursor, Write};

/// The variables that point TLS clients at the system trust store: Node,
/// Python's requests, and OpenSSL's users.
pub(super) const TRUST_ENV: &[(&str, &str)] = &[
    ("NODE_USE_SYSTEM_CA", "1"),
    ("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"),
    ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
];

/// Shared TLS settings for cloud provisioning and prepared images.
pub(super) fn trust_files() -> Vec<(&'static str, String)> {
    let assignments: Vec<_> = TRUST_ENV.iter().map(|(k, v)| format!("{k}={v}")).collect();
    vec![
        (
            "/etc/systemd/network/05-eth0.network",
            "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n".into(),
        ),
        (
            "/etc/systemd/system.conf.d/trust.conf",
            format!("[Manager]\nDefaultEnvironment={}\n", assignments.join(" ")),
        ),
        (
            "/etc/profile.d/trust.sh",
            assignments
                .iter()
                .map(|a| format!("export {a}\n"))
                .collect(),
        ),
    ]
}

/// The directory systemd-resolved reads trust anchors from when it starts
/// (dnssec-trust-anchors.d(5)).
const RESOLVED_ANCHORS: &str = "/etc/dnssec-trust-anchors.d";

/// The files a guest's resolvers read a root trust anchor from, for a
/// world that serves and signs a root zone of its own:
/// systemd-resolved's positive anchor, which replaces its built-in root
/// anchor; the dns-root-data copy that Unbound's packaging installs from;
/// and BIND's `bind.keys`, which `delv` reads. A world adds each with
/// [`Guest::file`](super::Guest::file), and a guest that installs Unbound
/// adds [`unbound_root_anchor`] too. A cloud guest restarts
/// systemd-resolved once the files are written, before it installs
/// packages; a prepared image reads them when it boots.
pub fn root_anchor_files(anchor: &TrustAnchor) -> [(&'static str, String); 3] {
    [
        (
            "/etc/dnssec-trust-anchors.d/root.positive",
            anchor.resolved_positive(),
        ),
        ("/usr/share/dns/root.key", anchor.root_key()),
        ("/etc/bind/bind.keys", anchor.bind_keys()),
    ]
}

/// Unbound's own root trust anchor file, which it reads and keeps up to
/// date, for a guest that installs Unbound.
pub fn unbound_root_anchor(anchor: &TrustAnchor) -> (&'static str, String) {
    ("/var/lib/unbound/root.key", anchor.root_key())
}

/// The guest configuration and credentials for one seed.
pub struct Provision<'a, P = Installation> {
    /// The guest identity and provisioning steps.
    pub guest: &'a Guest<P>,
    /// The public SSH key allowed to log in.
    pub authorized_key: &'a str,
    /// An optional root certificate name and PEM content.
    pub ca: Option<(&'a str, &'a str)>,
}

/// A cloud guest's clock comes from the host, so network time, which would
/// request a name the world does not serve, stays off.
const HOST_CLOCK: &[(&str, &str)] = &[
    (
        "/etc/systemd/timesyncd.conf",
        "[Time]\nNTP=\nFallbackNTP=\n",
    ),
    (
        "/etc/systemd/system/systemd-timesyncd.service.d/quiet.conf",
        "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n",
    ),
];

/// Builds the `cidata` FAT image bytes for `provision`. A prepared image
/// takes no seed: everything it needs is in the image.
pub fn build<P: Software>(provision: &Provision<P>) -> std::io::Result<Vec<u8>> {
    provision.guest.validate()?;
    if provision
        .ca
        .is_some_and(|(name, _)| !super::valid_name(name))
    {
        return Err(std::io::Error::other("invalid root certificate name"));
    }
    let Some(installation) = provision.guest.software.installation() else {
        return Err(std::io::Error::other("a prepared image takes no seed"));
    };
    let user_data = cloud_data(provision, installation);
    let audit = fictionet_extras::guest_content::Audit::default();
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
pub fn user_data(p: &Provision<'_>) -> String {
    cloud_data(p, &p.guest.software)
}

fn cloud_data<P: Software>(p: &Provision<P>, installation: &Installation) -> String {
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
    let shared = trust_files();
    let root =
        p.ca.map(|(name, pem)| (format!("/usr/local/share/ca-certificates/{name}.crt"), pem));
    for (path, mode, content) in root
        .iter()
        .map(|(path, pem)| (path.as_str(), 0o644, *pem))
        .chain(shared.iter().map(|(p, c)| (*p, 0o644, c.as_str())))
        .chain(HOST_CLOCK.iter().map(|(p, c)| (*p, 0o644, *c)))
        .chain(
            installation
                .files
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
    // The Ubuntu image already has the updater; trust the world before apt uses HTTPS.
    let assignments: Vec<_> = TRUST_ENV.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut commands = vec![
        "update-ca-certificates".into(),
        format!(
            "printf '%s\\n' {} >> /etc/environment",
            assignments.join(" ")
        ),
        "systemctl daemon-reexec".into(),
    ];
    // systemd-resolved started before the files were written, and reads
    // trust anchors only when it starts.
    if installation
        .files
        .iter()
        .any(|f| std::path::Path::new(&f.path).starts_with(RESOLVED_ANCHORS))
    {
        commands.push("systemctl try-restart systemd-resolved.service".into());
    }
    commands.extend([
        "apt-get update".into(),
        format!(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates {}",
            installation
                .packages
                .iter()
                .map(|s| super::ssh::quote(s))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        "if systemctl is-active --quiet systemd-timesyncd.service; then systemctl stop systemd-timesyncd.service; fi".into(),
    ]);
    commands.extend(installation.steps.iter().cloned());
    // One shell stops provisioning on the first failed command.
    out.push_str(&format!(
        "  - [bash, -euc, {}]\n",
        quote(&commands.join("\n"))
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::dns::dnssec::{Algorithm, KeyFlags, KeySet, ZoneKey};
    use fictionet::stdlib::protocols::dns::rr::Name;
    use fictionet::{Seed, SeededEntropy};
    use std::sync::Arc;

    fn anchor() -> TrustAnchor {
        let entropy = SeededEntropy::new(Seed::from_u64(1));
        let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
        KeySet {
            keys: vec![Arc::new(key)],
        }
        .anchor(&Name::root())
    }

    fn user_data(guest: &Guest<Installation>) -> String {
        super::user_data(&Provision {
            guest,
            authorized_key: "ssh-ed25519 key",
            ca: None,
        })
    }

    #[test]
    fn a_root_anchor_reaches_every_resolver_and_restarts_resolved_before_apt() {
        let anchor = anchor();
        let mut guest = Guest::ubuntu("station", "analyst").packages(&["unbound"]);
        for (path, content) in root_anchor_files(&anchor) {
            guest = guest.file(path, 0o644, content);
        }
        let (path, content) = unbound_root_anchor(&anchor);
        let data = user_data(&guest.file(path, 0o644, content));
        let files = files(&data).unwrap();
        let ds = anchor.resolved_positive();
        assert!(ds.starts_with(". IN DS "));
        assert_eq!(files["/etc/dnssec-trust-anchors.d/root.positive"], ds);
        assert_eq!(files["/usr/share/dns/root.key"], ds);
        assert_eq!(files["/var/lib/unbound/root.key"], ds);
        assert_eq!(files["/etc/bind/bind.keys"], anchor.bind_keys());
        let restart = data
            .find("systemctl try-restart systemd-resolved.service")
            .unwrap();
        assert!(data.find("daemon-reexec").unwrap() < restart);
        assert!(restart < data.find("apt-get update").unwrap());
        assert_eq!(data.matches("systemd-resolved").count(), 1);
    }

    #[test]
    fn a_guest_without_an_anchor_does_not_restart_resolved() {
        let data = user_data(&Guest::ubuntu("station", "analyst"));
        assert!(!data.contains("systemd-resolved"));
        assert!(
            !files(&data)
                .unwrap()
                .keys()
                .any(|path| path.contains("dnssec"))
        );
    }
}
