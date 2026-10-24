//! The Search workstation's installed software and fixed package sources.

use fictionet_demo::kit::{Guest, desktop, image};
use std::io;

pub const IMAGE: &str = "search-workstation.qcow2";

fn definition() -> Guest {
    desktop::codex(desktop::claude_code(desktop::browser_image(
        "workstation",
        "analyst",
        "https://www.google.com/",
    )))
    .packages(&["xclip", "nmap", "tmux", "python3", "python3-pip", "python3-venv"])
    .file("/home/analyst/.tmux.conf", 0o644, "set -g status off\nset -g mouse on\n")
    .file("/home/analyst/.hushlogin", 0o644, "")
    .file("/etc/apt/sources.list.d/mozilla.sources", 0o644, "")
    .file("/etc/apt/sources.list.d/ubuntu.sources", 0o644,
        "Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/\nSuites: noble noble-updates noble-security noble-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nCheck-Valid-Until: no\n")
}

pub fn recipe() -> io::Result<image::Recipe> {
    definition().into_recipe()?
    .archive("firefox", "https://packages.mozilla.org/apt/pool/mozilla/firefox_158.0.1~build1_amd64_563b50f128d7d58759d99e57779c0cb7.deb",
        "18dbb71cbbd8ecca54b2523ec01104457cd48cf5a0ad30943d2b05da6ec6b6a8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    #[test]
    fn image_installs_the_complete_quiet_workstation() {
        let guest = definition();
        guest.validate().unwrap();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        let files = seed::files(&data).unwrap();
        let command = data
            .lines()
            .last()
            .unwrap()
            .strip_prefix("  - [bash, -euc, ")
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        let command: String = serde_json::from_str(command).unwrap();
        let packages = command
            .lines()
            .find(|line| line.contains("apt-get install"))
            .unwrap();
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
            assert!(
                packages
                    .split_whitespace()
                    .any(|word| word == format!("'{package}'")),
                "{package}"
            );
        }
        let file = |path: &str| files[path].as_str();
        assert_eq!(file("/etc/apt/apt.conf.d/20apt-esm-hook.conf"), "");
        assert!(file("/opt/start-desktop.sh").contains(
            "firefox --profile \"$HOME/.mozilla/firefox/default\" 'https://www.google.com/'"
        ));
        assert!(
            file("/etc/firefox/policies/policies.json")
                .contains("firefox.settings.services.mozilla.com")
        );
        assert!(file("/etc/apt/apt.conf.d/99periodic").contains("APT::Periodic::Enable \"0\""));
        assert!(file("/etc/default/motd-news").contains("ENABLED=0"));
        file("/etc/systemd/timesyncd.conf");
        file("/etc/systemd/system/apt-daily.timer.d/quiet.conf");
        file("/etc/claude-code/managed-settings.json");
        assert_eq!(
            file("/home/analyst/.tmux.conf"),
            "set -g status off\nset -g mouse on\n"
        );
        assert!(file("/home/analyst/.hushlogin").is_empty());
        assert!(command.contains("then systemctl stop apt-daily.timer; fi"));
        assert!(!command.contains("systemctl start vnc"));
        assert!(!file("/opt/setup-desktop.sh").contains("enable --now"));
        assert!(file("/etc/apt/sources.list.d/mozilla.sources").is_empty());
        assert!(
            file("/etc/apt/sources.list.d/ubuntu.sources")
                .contains("https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/")
        );
        assert!(!image::installation(&recipe().unwrap()).contains("date -u -s"));
    }
}
