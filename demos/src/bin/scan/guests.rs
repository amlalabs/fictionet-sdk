//! The two guests. Both boot Ubuntu's 24.04 cloud image unmodified and
//! install their packages at boot through the world's mirror.
//!
//! The workstation is the scanner, with nmap. Its screen is Xvnc with
//! openbox and one full-screen xterm. The xterm runs a small runner that
//! reads one command at a time from a named pipe, types it out, runs it and
//! writes back its exit status. The demo sends the story's nmap commands
//! through that pipe over SSH.
//!
//! The office server runs nginx and OpenSSH at 10.0.0.50. Its login shell
//! follows sshd's journal and nginx's access log, so the page's terminal
//! shows nmap's probes reaching a real server.
use fictionet::stdlib::network::ethernet::Family;
use fictionet_demo::kit::{Guest, desktop::VNC_PORT};

pub const WORKSTATION: &str = "workstation";
pub const SERVER: &str = "office";
pub const USER: &str = "analyst";

pub fn workstation() -> Guest {
    terminal_desktop(WORKSTATION, USER)
        .attachment(scan_world::SCANNER)
        .resources(2, 1024)
        .card(Family::FromWorld)
        .packages(&["nmap"])
}

pub fn server() -> Guest {
    Guest::ubuntu(SERVER, "sysadmin")
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

fn terminal_desktop(hostname: &str, user: &str) -> Guest {
    Guest::ubuntu(hostname, user)
        .packages(&[
            "tigervnc-standalone-server",
            "openbox",
            "xterm",
            "x11-utils",
            "fonts-dejavu-core",
        ])
        .desktop(VNC_PORT, DESKTOP_READY)
        .file("/opt/assistant", 0o755, RUNNER)
        .file("/opt/session", 0o755, session(user))
        .file("/etc/systemd/system/vnc.service", 0o644, service(user))
        .run("systemctl daemon-reload; systemctl enable --now vnc.service")
}

const DESKTOP_READY: &str = "env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 \
    && pgrep -x xterm >/dev/null && test -p ~/notes/requests";

fn session(user: &str) -> String {
    format!(
        r#"#!/bin/bash
set -euo pipefail
export HOME=/home/{user} DISPLAY=:1
mkdir -p "$HOME/notes"
for fifo in "$HOME/notes/requests" "$HOME/notes/results"; do
    if [ ! -p "$fifo" ]; then mkfifo "$fifo"; fi
done
Xvnc :1 -localhost -SecurityTypes None -AlwaysShared -nolisten tcp -geometry {GEOMETRY} -depth 24 &
xpid=$!
trap 'kill "$xpid"' EXIT
# Wait for the X server before opening the terminal.
for ((attempt=0; attempt<150; attempt++)); do
    if xdpyinfo >/dev/null 2>&1; then break; fi
    sleep 0.2
done
xdpyinfo >/dev/null
openbox &
exec xterm -fa 'DejaVu Sans Mono' -fs {FONT_SIZE} -fullscreen -bg '#101820' -fg '#e7edf4' \
    -title 'Office work' -e /opt/assistant
"#
    )
}

// The screen is wide and short because its tile is: with two hosts stacked
// in the workspace, a tile's console measures 817x344 at 1440x900 and
// 724x294 at 1280x800, about 2.4 times as wide as tall, so a screen of that
// shape fills it. At 15 px, DejaVu Sans Mono's characters are 9 px wide, so
// 960 px holds 106 columns and nmap's widest service line (82 characters)
// fits on one line. The page scales the screen by 0.85 at 1440x900 and 0.74
// at 1280x800, so the text shows at 11 to 13 px.
const GEOMETRY: &str = "960x400";
const FONT_SIZE: u8 = 15;

fn service(user: &str) -> String {
    format!(
        "[Unit]\n\
         Description=Office desktop\n\
         After=systemd-user-sessions.service\n\
         [Service]\n\
         User={user}\n\
         PAMName=login\n\
         ExecStart=/opt/session\n\
         KillMode=control-group\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

const RUNNER: &str = r#"#!/bin/bash
set -uo pipefail
cd "$HOME"
printf 'Scripted assistant · Office inventory\n\n'
while IFS= read -r command < notes/requests; do
    printf '%s@%s:~$ ' "$USER" "$(hostname)"
    for ((i=0; i<${#command}; i++)); do
        printf '%s' "${command:i:1}"
        sleep 0.02
    done
    printf '\n'
    timeout 300 bash -c "$command" 2>&1 | tee notes/output
    result=${PIPESTATUS[0]}
    printf '\nExit status: %s\n\n' "$result"
    printf '%s\n' "$result" > notes/results
done
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::base64;
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
    fn guests_install_their_services_and_keep_neutral_names() {
        let station = workstation();
        let office = server();
        for guest in [&station, &office] {
            seed::build(&seed::Provision {
                guest,
                authorized_key: "key",
                ca: None,
            })
            .unwrap();
            let text = data(guest);
            for line in text.lines().filter(|l| !l.contains("content:")) {
                for word in ["fictionet", "eval", "sandbox", "world", "scan", "demo"] {
                    assert!(!line.to_lowercase().contains(word), "{line}");
                }
            }
            for encoded in text
                .lines()
                .filter_map(|line| line.strip_prefix("    content: "))
            {
                let file = String::from_utf8(
                    base64::decode(encoded.as_bytes(), base64::Padding::Required).unwrap(),
                )
                .unwrap();
                for word in ["fictionet", "eval", "sandbox", "world", "scan", "demo"] {
                    assert!(
                        !file.to_lowercase().contains(word),
                        "guest file contains {word}"
                    );
                }
            }
            assert!(text.contains("NOPASSWD:ALL"));
        }
        let text = data(&station);
        for package in ["nmap", "tigervnc-standalone-server", "openbox", "xterm"] {
            assert!(text.contains(&format!("'{package}'")));
        }
        let files: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix("    content: "))
            .map(|s| {
                String::from_utf8(base64::decode(s.as_bytes(), base64::Padding::Required).unwrap())
                    .unwrap()
            })
            .collect();
        assert!(
            files
                .iter()
                .any(|s| s.contains("Xvnc :1 -localhost") && s.contains("exec xterm"))
        );
        assert!(
            files
                .iter()
                .any(|s| s.contains("timeout 300 bash") && s.contains("PIPESTATUS[0]"))
        );
        assert!(text.contains("enable --now vnc.service"));
        assert!(
            files
                .iter()
                .any(|s| s.contains("-geometry 960x400 ") && s.contains("-fs 15 "))
        );
        let text = data(&office);
        assert!(text.contains("'nginx' 'openssh-server'"));
        // The login shell follows the access log without printing tail's
        // notes while nginx is not installed yet.
        assert!(
            text.lines()
                .filter_map(|line| line.strip_prefix("    content: "))
                .map(|s| String::from_utf8(
                    base64::decode(s.as_bytes(), base64::Padding::Required).unwrap()
                )
                .unwrap())
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
