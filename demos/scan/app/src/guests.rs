//! The two guests. Both boot Ubuntu's 24.04 cloud image unmodified and
//! install their packages at boot through the world's mirror.
//!
//! The workstation is the scanner, with nmap. Its screen is the kit's
//! terminal desktop: one full-screen interactive shell. Reports can be
//! saved in `~/notes`.
//!
//! The office server runs nginx and OpenSSH at 10.0.0.50. Its login shell
//! follows sshd's journal and nginx's access log, so the page's terminal
//! shows nmap's probes reaching a real server.
use fictionet::stdlib::network::ethernet::Family;
use fictionet_demo::kit::{Guest, desktop};

pub const WORKSTATION: &str = "workstation";
pub const SERVER: &str = "office";
pub const USER: &str = "analyst";

// The screen is wide and short because its tile is: with two hosts stacked
// in the workspace, a tile's console measures 817x344 at 1440x900 and
// 724x294 at 1280x800, about 2.4 times as wide as tall, so a screen of that
// shape fills it. At 15 px, DejaVu Sans Mono's characters are 9 px wide, so
// 960 px holds 106 columns and nmap's widest service line (82 characters)
// fits on one line. The page scales the screen by 0.85 at 1440x900 and 0.74
// at 1280x800, so the text shows at 11 to 13 px.
const SCREEN: (u16, u16) = (960, 400);
const FONT_SIZE: u8 = 15;

pub fn workstation() -> Guest {
    desktop::terminal(WORKSTATION, USER, "Office inventory", SCREEN, FONT_SIZE)
        .forbid(&["scan"])
        .attachment(scan_world::SCANNER)
        .resources(2, 1024)
        .card(Family::FromWorld)
        .packages(&["nmap"])
        .run(format!("sudo -u {USER} mkdir -p /home/{USER}/notes"))
}

pub fn server() -> Guest {
    Guest::ubuntu(SERVER, "sysadmin")
        .forbid(&["scan"])
        .attachment(scan_world::SERVER)
        .resources(1, 512)
        .card(Family::Serve(scan_world::SERVER_LEASE))
        .packages(&["nginx", "openssh-server"])
        // The page's terminal can log in before cloud-init has installed
        // nginx. tail -F waits for the access log to appear; its notes about
        // the missing file go to /dev/null so the terminal shows only logs.
        .file(
            "/etc/profile.d/office-logs.sh",
            0o644,
            r#"if [ -n "$PS1" ]; then
    sudo journalctl -f -u ssh.service -u ssh.socket --no-pager &
    journal_pid=$!
    sudo tail -n 20 -F /var/log/nginx/access.log 2>/dev/null &
    access_pid=$!
    trap 'kill "$journal_pid" "$access_pid" 2>/dev/null' EXIT
fi
"#,
        )
        // The cloud image socket-activates OpenSSH already, and the kit reaches
        // the guest through it. Restarting ssh.service here would put systemd's
        // left-over process warnings in the journal the terminal follows.
        .run("systemctl enable --now nginx.service")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    fn data(guest: &Guest) -> String {
        seed::user_data(&seed::Provision {
            guest,
            authorized_key: "key",
            ca: None,
        })
    }

    #[test]
    fn guest_users_do_not_conflict_with_system_accounts() {
        // A base-passwd user or group prevents cloud-init from creating the guest user.
        let reserved = [
            "root", "daemon", "bin", "sys", "adm", "tty", "disk", "lp", "mail", "news", "uucp",
            "man", "proxy", "kmem", "dialout", "fax", "voice", "cdrom", "floppy", "tape", "sudo",
            "audio", "dip", "www-data", "backup", "operator", "list", "irc", "src", "shadow",
            "utmp", "video", "sasl", "plugdev", "staff", "games", "users", "nogroup", "nobody",
        ];
        for guest in [workstation(), server()] {
            let text = data(&guest);
            let user: String = serde_json::from_str(
                text.lines()
                    .find_map(|line| line.strip_prefix("  - name: "))
                    .unwrap(),
            )
            .unwrap();
            assert!(
                !reserved.contains(&user.as_str()),
                "reserved guest user: {user}"
            );
        }
    }

    #[test]
    fn guests_install_their_services() {
        let station = workstation();
        let office = server();
        for guest in [&station, &office] {
            guest.validate().unwrap();
            assert!(data(guest).contains("NOPASSWD:ALL"));
        }
        let text = data(&station);
        for package in ["nmap", "openbox", "xterm"] {
            assert!(text.contains(&format!("'{package}'")));
        }
        assert!(text.contains("sudo -u analyst mkdir -p /home/analyst/notes"));
        let start = &seed::files(&text).unwrap()["/opt/start-desktop.sh"];
        assert!(start.contains("-geometry 960x400 ") && start.contains("-fs 15 "));
        let text = data(&office);
        assert!(text.contains("'nginx' 'openssh-server'"));
        // The login shell follows the access log without printing tail's
        // notes while nginx is not installed yet.
        assert!(
            seed::files(&text)
                .unwrap()
                .values()
                .any(|s| s.contains("tail -n 20 -F /var/log/nginx/access.log 2>/dev/null &"))
        );
        // nginx is enabled; OpenSSH stays socket-activated as the image ships it.
        let runcmd = text
            .lines()
            .find(|line| line.starts_with("  - [bash, -euc, "))
            .unwrap();
        assert!(runcmd.contains("systemctl enable --now nginx.service"));
        assert!(!runcmd.contains("ssh.service") && !runcmd.contains("ssh.socket"));
        assert!(!text.contains("vnc"));
    }
}
