//! The cloud-init NoCloud seed: a small FAT image labelled `cidata`,
//! written in Rust, carrying `meta-data`, a `network-config`, and a
//! `#cloud-config` user-data that provisions the whole guest at boot with
//! nothing baked into the image.
//!
//! The user-data installs an Xfce desktop from the world's apt mirror
//! (Firefox from Mozilla's repository, not the snap), one system-wide trust
//! store pointing every TLS client at the world's CA, and Xvnc with an Xfce
//! session on the loopback. The admin reaches the guest with Ubuntu's own
//! sshd on port 22, as the image ships it, with this run's key, and tunnels
//! VNC through it. The config files go in as base64 `write_files`, and a
//! setup script does the install and wiring.

use std::io::{Cursor, Write};

use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};

/// Mozilla's apt signing key, armored (public; checked against its sha256).
const MOZILLA_KEY: &str = include_str!("packages.mozilla.org.asc");

/// What the guest is provisioned with.
pub struct Provision<'a> {
    /// A neutral hostname, nothing that names an eval.
    pub hostname: &'a str,
    /// The admin's login, and the desktop's user.
    pub user: &'a str,
    /// This run's SSH public key, as one `authorized_keys` line.
    pub authorized_key: &'a str,
    /// The world's CA root, in PEM, installed as `zscaler.crt`.
    pub ca_pem: &'a str,
    /// The HTTPS site Firefox opens.
    pub site: &'a str,
}

/// Builds the `cidata` FAT image bytes for `provision`.
pub fn build(provision: &Provision) -> std::io::Result<Vec<u8>> {
    let user_data = user_data(provision);
    let meta_data = format!(
        "instance-id: iid-{0}\nlocal-hostname: {0}\n",
        provision.hostname
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

/// The `#cloud-config` document.
fn user_data(p: &Provision) -> String {
    let mut files: Vec<(&str, &str, String)> = Vec::new();
    // (path, permissions, content)
    let site = p.site;
    let mozilla_sources = "Types: deb\n\
         URIs: https://packages.mozilla.org/apt\n\
         Suites: mozilla\n\
         Components: main\n\
         Signed-By: /etc/apt/keyrings/packages.mozilla.org.asc\n"
        .to_string();
    let mozilla_pref = "Package: *\n\
         Pin: origin packages.mozilla.org\n\
         Pin-Priority: 1000\n";
    // Firefox trusts the system store through p11-kit and opens the world's
    // site; no first-run pages.
    let policies = format!(
        "{{\"policies\":{{\
           \"OverrideFirstRunPage\":\"\",\"OverridePostUpdatePage\":\"\",\
           \"DisableAppUpdate\":true,\"DontCheckDefaultBrowser\":true,\
           \"DNSOverHTTPS\":{{\"Enabled\":false,\"Locked\":true}},\
           \"Homepage\":{{\"URL\":\"https://{site}/\",\"StartPage\":\"homepage\"}},\
           \"SecurityDevices\":{{\"Add\":{{\"p11-kit-trust\":\"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so\"}}}},\
           \"UserMessaging\":{{\"SkipOnboarding\":true,\"WhatsNew\":false}},\
           \"Preferences\":{{\
             \"browser.preonboarding.enabled\":{{\"Value\":false,\"Status\":\"locked\"}},\
             \"datareporting.policy.dataSubmissionPolicyBypassNotification\":{{\"Value\":true,\"Status\":\"locked\"}}\
           }}\
         }}}}"
    );
    // Xvnc on :1 (5901), loopback only, no auth: reached only through an SSH
    // tunnel. An Xfce session and Firefox for the user.
    let start_desktop = format!(
        "#!/bin/bash\n\
         set -x\n\
         export HOME=/home/{user} DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/$(id -u {user})\n\
         /usr/bin/Xvnc :1 -localhost -SecurityTypes None -AlwaysShared -nolisten tcp -geometry 1280x800 -depth 24 >/tmp/xvnc.log 2>&1 &\n\
         for _ in $(seq 1 150); do xdpyinfo -display :1 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         eval \"$(dbus-launch --sh-syntax)\"\n\
         # The Xfce session, then the window manager, then Firefox: launched\n\
         # here (not via Xfce autostart, which did not run reliably) so its\n\
         # start is ordered and its output is captured.\n\
         startxfce4 >/tmp/xfce.log 2>&1 &\n\
         for _ in $(seq 1 150); do pgrep -x xfwm4 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         sleep 2\n\
         # Create the profile root so Firefox never hits \"profile missing\".\n\
         mkdir -p \"$HOME/.mozilla/firefox\"\n\
         firefox --no-remote https://{site}/ >/tmp/firefox.log 2>&1 &\n\
         wait\n",
        user = p.user,
        site = p.site,
    );
    let vnc_service = format!(
        "[Unit]\n\
         Description=Xvnc with an Xfce session\n\
         After=systemd-user-sessions.service\n\
         [Service]\n\
         User={user}\n\
         PAMName=login\n\
         ExecStart=/opt/start-desktop.sh\n\
         Restart=on-failure\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = p.user,
    );
    // The trust store for every service started by systemd (the desktop
    // session included); /etc/environment covers login shells.
    let trust_conf = "[Manager]\n\
         DefaultEnvironment=NODE_USE_SYSTEM_CA=1 REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n";
    let setup = setup_script(p.user);

    files.push((
        "/usr/local/share/ca-certificates/zscaler.crt",
        "0644",
        p.ca_pem.to_string(),
    ));
    files.push((
        "/etc/apt/keyrings/packages.mozilla.org.asc",
        "0644",
        MOZILLA_KEY.to_string(),
    ));
    files.push((
        "/etc/apt/sources.list.d/mozilla.sources",
        "0644",
        mozilla_sources,
    ));
    files.push((
        "/etc/apt/preferences.d/mozilla",
        "0644",
        mozilla_pref.into(),
    ));
    files.push(("/etc/firefox/policies/policies.json", "0644", policies));
    files.push((
        "/etc/systemd/network/05-eth0.network",
        "0644",
        "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n".into(),
    ));
    files.push(("/opt/start-desktop.sh", "0755", start_desktop));
    files.push(("/etc/systemd/system/vnc.service", "0644", vnc_service));
    files.push((
        "/etc/systemd/system.conf.d/trust.conf",
        "0644",
        trust_conf.into(),
    ));
    // Login shells read the same trust store (/etc/environment is for
    // pam_env; this covers plain shells too).
    files.push((
        "/etc/profile.d/trust.sh",
        "0644",
        "export NODE_USE_SYSTEM_CA=1\n\
         export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\n\
         export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n"
            .into(),
    ));
    files.push(("/opt/setup-desktop.sh", "0755", setup));

    let mut out = String::from(
        "#cloud-config\n\
         hostname: ",
    );
    out.push_str(p.hostname);
    out.push('\n');
    out.push_str("preserve_hostname: false\n");
    out.push_str(&format!(
        "users:\n\
         \x20 - name: {user}\n\
         \x20   sudo: 'ALL=(ALL) NOPASSWD:ALL'\n\
         \x20   shell: /bin/bash\n\
         \x20   lock_passwd: true\n\
         \x20   ssh_authorized_keys:\n\
         \x20     - {key}\n",
        user = p.user,
        key = p.authorized_key,
    ));
    out.push_str("write_files:\n");
    for (path, perms, content) in &files {
        out.push_str(&format!(
            "\x20 - path: {path}\n\
             \x20   permissions: '{perms}'\n\
             \x20   encoding: b64\n\
             \x20   content: {}\n",
            base64(content.as_bytes()),
        ));
    }
    out.push_str("runcmd:\n");
    out.push_str("\x20 - [ bash, /opt/setup-desktop.sh ]\n");
    out
}

/// The install-and-wire script run from `runcmd`.
fn setup_script(user: &str) -> String {
    format!(
        "#!/bin/bash\n\
         set -euo pipefail\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         # The world's CA first, so HTTPS apt sources work.\n\
         apt-get update\n\
         apt-get install -y --no-install-recommends ca-certificates\n\
         update-ca-certificates\n\
         # Install the desktop from the world's mirror; fail on any apt error.\n\
         apt-get update\n\
         apt-get install -y --no-install-recommends \
           xfce4 xfce4-terminal tigervnc-standalone-server dbus-x11 xdotool \
           firefox p11-kit p11-kit-modules libnss3 \
           fonts-dejavu-core fonts-liberation adwaita-icon-theme x11-utils scrot\n\
         # Mozilla's Firefox, not Ubuntu's snap shim.\n\
         test -x /usr/lib/firefox/firefox\n\
         # One trust store: NSS's builtin roots module becomes p11-kit's.\n\
         mkdir -p /usr/lib/x86_64-linux-gnu/nss\n\
         dpkg-divert --add --rename \
           --divert /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so \
           /usr/lib/x86_64-linux-gnu/libnssckbi.so\n\
         ln -sf pkcs11/p11-kit-trust.so /usr/lib/x86_64-linux-gnu/libnssckbi.so\n\
         # Trust env for login shells.\n\
         printf '%s\\n' NODE_USE_SYSTEM_CA=1 \
           REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
           SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt >> /etc/environment\n\
         # Xfce's default panel for {user}, so no first-run dialog.\n\
         install -d -o {user} -g {user} /home/{user}/.config/xfce4/xfconf/xfce-perchannel-xml\n\
         install -o {user} -g {user} -m0644 /etc/xdg/xfce4/panel/default.xml \
           /home/{user}/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml\n\
         chown -R {user}:{user} /home/{user}/.config\n\
         # Apply the DefaultEnvironment drop-in, then bring the desktop up.\n\
         systemctl daemon-reexec\n\
         systemctl daemon-reload\n\
         systemctl enable --now vnc.service\n",
    )
}

/// Standard base64, for cloud-init `write_files` content.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
