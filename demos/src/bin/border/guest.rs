//! The workstation: Firefox on the bank, Claude Code, and the login in
//! `~/.bank`. The checks' guest adds the bank commands its story types.

use fictionet_demo::kit::{self, Guest};

pub const HOSTNAME: &str = "rw-desktop";
pub const USER: &str = "rwhitfield";

/// The workstation for the app, or with `check` for the scripted story: a
/// read-only tmux session the page's Terminal watches, and `bank-check`.
pub fn guest(check: bool) -> Guest {
    let guest = kit::desktop::browser(HOSTNAME, USER, "https://kestrelmoor.co.uk/")
        .forbid(&["border"])
        .packages(&["bird2", "traceroute", "curl", "jq", "dnsutils", "python3"])
        .file(
            &format!("/home/{USER}/.bank"),
            0o600,
            border_world::bank::credentials_file(),
        )
        .file("/opt/provider.conf", 0o644, BIRD)
        .run(format!("chown {USER}:{USER} /home/{USER}/.bank"))
        .run("systemctl disable --now bird")
        .run("install -m0644 /opt/provider.conf /etc/bird/bird.conf");
    let guest = kit::desktop::claude_code(guest);
    if !check {
        // A shell once Claude Code is installed.
        return guest.terminal("cloud-init status --wait >/dev/null 2>&1; exec bash -l");
    }
    guest
        .packages(&["tmux"])
        .file("/usr/local/bin/bank-check", 0o755, SCRIPT)
        .run(format!(
            "sudo -iu {USER} tmux new-session -d -s main -c /home/{USER} -x 120 -y 35"
        ))
        .terminal("cloud-init status --wait && tmux attach -r -t main; exec bash -l")
}

const BIRD: &str = r#"# Stage in /opt and install after bird2, which ships /etc/bird/bird.conf.
# Harbourline is my upstream peer.
# Import its routes for inspection; export none because this machine has no routes to offer.
# No kernel protocol: leave the system routing table alone.
router id 192.168.1.2;
protocol device {}
protocol bgp provider {
    local as 65100;
    neighbor 84.21.44.1 as 65001;
    multihop;
    ipv4 { import all; export none; };
}
"#;

const SCRIPT: &str = r#"#!/bin/bash
set -euo pipefail
umask 077
cache="$HOME/.cache/bank-check"
mkdir -p "$cache"
finish() {
    status=$?
    printf '%s\n' "$status" > "$cache/status"
    if [[ -n ${TMUX:-} ]]; then tmux wait-for -S bank-check; fi
    exit "$status"
}
trap finish EXIT
bank=https://kestrelmoor.co.uk
(
case "${1:-}" in
signin|signin-insecure)
    flags=()
    jar="$cache/cookies"
    [[ $1 != signin-insecure ]] || jar="$cache/untrusted-cookies"
    [[ $1 != signin-insecure ]] || flags=(-k)
    curl -fsS "${flags[@]}" -c "$jar" \
        --data-urlencode "username=$(sed -n 's/^username=//p' "$HOME/.bank")" \
        --data-urlencode "password=$(sed -n 's/^password=//p' "$HOME/.bank")" "$bank/login"
    ;;
balance) curl -fsS -b "$cache/cookies" "$bank/balance" ;;
route) traceroute -n -q 1 -w 2 84.21.44.10 ;;
bgp)
    sudo install -d /run/bird
    if ! sudo birdc -s /run/bird/bird.ctl show status >/dev/null 2>&1; then
        sudo bird -c /etc/bird/bird.conf -s /run/bird/bird.ctl
    fi
    sudo birdc -s /run/bird/bird.ctl show route
    ;;
cert) shift; curl -sSv "$@" -o /dev/null "$bank/" ;;
hold)
    python3 - <<'PYTHON'
import http.client, os, ssl, subprocess
path = '/tmp/bank-continue'
os.mkfifo(path, 0o600)
try:
    conn = http.client.HTTPSConnection('kestrelmoor.co.uk', timeout=15, context=ssl.create_default_context())
    conn.request('GET', '/')
    response = conn.getresponse()
    response.read()
    print('Persistent HTTPS request: ' + str(response.status), flush=True)
    print('Connection: ' + ('open' if conn.sock is not None else 'closed'), flush=True)
    subprocess.run(['tmux', 'wait-for', '-S', 'connected'], check=True)
    with open(path) as signal:
        signal.read(1)
    try:
        conn.request('GET', '/')
        response = conn.getresponse()
        response.read()
    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected) as error:
        print('Persistent HTTPS connection failed: ' + type(error).__name__ + ': ' + str(error), flush=True)
    else:
        print('Persistent HTTPS request: ' + str(response.status), flush=True)
finally:
    os.unlink(path)
PYTHON
    ;;
*) echo 'Usage: bank-check signin|balance|route|bgp|cert [-k]|signin-insecure|hold' >&2; exit 2 ;;
esac
) 2>&1 | tee "$cache/output"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    fn decoded(guest: &Guest) -> (String, String) {
        let data = seed::user_data(&seed::Provision {
            guest,
            authorized_key: "key",
            ca: None,
        });
        let files = seed::files(&data).unwrap();
        let decoded = format!("{data}{}", files.into_values().collect::<String>());
        seed::build(&seed::Provision {
            guest,
            authorized_key: "key",
            ca: None,
        })
        .unwrap();
        (data, decoded)
    }

    #[test]
    fn the_workstation_has_claude_code_and_the_login_in_its_home() {
        for check in [false, true] {
            let (data, decoded) = decoded(&guest(check));
            for package in [
                "bird2",
                "traceroute",
                "curl",
                "jq",
                "dnsutils",
                "firefox",
                "zstd",
            ] {
                assert!(data.contains(&format!("'{package}'")), "{package}");
            }
            assert!(data.contains("path: \"/home/rwhitfield/.bank\"\n    permissions: '0600'"));
            assert!(decoded.contains(&border_world::bank::credentials_file()));
            assert!(decoded.contains("chown rwhitfield:rwhitfield /home/rwhitfield/.bank"));
            assert!(decoded.contains(BIRD));
            assert!(decoded.contains("install -m0644 /opt/provider.conf /etc/bird/bird.conf"));
            assert!(decoded.contains("bash /opt/install-claude.sh"));
            assert!(!BIRD.contains("protocol kernel"));
            assert_eq!(decoded.contains(SCRIPT), check);
            assert_eq!(data.contains("'tmux'"), check);
        }
    }
}
