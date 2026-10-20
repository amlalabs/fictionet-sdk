use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
pub const START: &str = "https://www.google.com/";

pub fn guest() -> Guest {
    // The kit's browser keeps Firefox quiet; background requests would create
    // pages and spend the generation budget, so the system stays quiet too.
    let mut guest = kit::desktop::browser(HOST, USER, START)
        // The Pro apt hook contacts the contract service during package setup.
        .file("/etc/apt/apt.conf.d/20apt-esm-hook.conf", 0o644, "")
        // Pro apt news fetches a remote news feed during package setup.
        .file(
            "/etc/ubuntu-advantage/uaclient.conf",
            0o644,
            "ua_config:\n  apt_news: false\n",
        )
        // Release checks fetch the upgrade list even when no upgrade is wanted.
        .file(
            "/etc/update-manager/release-upgrades",
            0o644,
            "[DEFAULT]\nPrompt=never\n",
        )
        // The clock comes from the host; network time would request another name.
        .file(
            "/etc/systemd/timesyncd.conf",
            0o644,
            "[Time]\nNTP=\nFallbackNTP=\n",
        )
        // Stop unattended apt work after cloud-init's explicit package setup.
        .file(
            "/etc/apt/apt.conf.d/99periodic",
            0o644,
            "APT::Periodic::Enable \"0\";\n",
        )
        // MOTD must not fetch news when the scripted searcher logs in.
        .file("/etc/default/motd-news", 0o644, "ENABLED=0\n");
    // Prevent later refresh starts when desktop setup reloads systemd.
    for unit in [
        "systemd-timesyncd.service",
        "snapd.socket",
        "snapd.service",
        "snapd.seeded.service",
        "motd-news.service",
        "motd-news.timer",
        "ua-timer.timer",
        "ua-timer.service",
        "ubuntu-advantage.service",
        "fwupd-refresh.service",
        "fwupd-refresh.timer",
        "apt-daily.timer",
        "apt-daily.service",
        "apt-daily-upgrade.timer",
        "apt-daily-upgrade.service",
    ] {
        guest = guest
            .file(
                &format!("/etc/systemd/system/{unit}.d/quiet.conf"),
                0o644,
                "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n",
            )
            // Stop any refresh job that was already active before provisioning.
            .run(format!(
                "if systemctl is-active --quiet {unit}; then systemctl stop {unit}; fi"
            ));
    }
    guest
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::{b64_decode, seed};

    #[test]
    fn desktop_is_quiet_and_uses_neutral_names() {
        let guest = guest();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        for package in ["firefox", "xdotool", "tigervnc-standalone-server", "xfce4"] {
            assert!(data.contains(package), "{package}");
        }
        let mut files = Vec::new();
        for line in data.lines() {
            if let Some(encoded) = line.strip_prefix("    content: ") {
                files.push(String::from_utf8(b64_decode(encoded).unwrap()).unwrap());
            }
        }
        assert!(
            files
                .iter()
                .any(|s| s.contains(&format!("firefox --no-remote '{START}'")))
        );
        assert!(
            files
                .iter()
                .any(|s| s.contains("firefox.settings.services.mozilla.com"))
        );
        assert!(
            files
                .iter()
                .any(|s| s.contains("APT::Periodic::Enable \"0\""))
        );
        assert!(files.iter().any(|s| s.contains("ENABLED=0")));
        for forbidden in [
            "fictionet",
            "adaptive",
            "stub",
            "sandbox",
            "search-demo",
            "world",
        ] {
            assert!(!data.contains(forbidden));
            assert!(files.iter().all(|s| !s.contains(forbidden)), "{forbidden}");
        }
    }
}
