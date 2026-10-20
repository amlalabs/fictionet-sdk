//! The workstation and its bank commands.

use fictionet_demo::kit::{self, Guest};

pub const HOSTNAME: &str = "rw-desktop";
pub const USER: &str = "rwhitfield";

pub fn guest() -> Guest {
    kit::desktop::browser(HOSTNAME, USER, "https://kestrelmoor.co.uk/")
        .packages(&[
            "bird2",
            "traceroute",
            "curl",
            "jq",
            "dnsutils",
            "tmux",
            "python3",
        ])
        .file(
            "/home/rwhitfield/.config/bank/credentials",
            0o600,
            border_world::bank::credentials_file(),
        )
        .file("/opt/provider.conf", 0o644, BIRD)
        .file("/usr/local/bin/bank-check", 0o755, SCRIPT)
        .run("chown -R rwhitfield:rwhitfield /home/rwhitfield/.config/bank")
        .run("systemctl disable --now bird")
        .run("install -m0644 /opt/provider.conf /etc/bird/bird.conf")
        .run("sudo -iu rwhitfield tmux new-session -d -s main -c /home/rwhitfield -x 120 -y 35")
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
    jar="$HOME/.config/bank/cookies"
    [[ $1 != signin-insecure ]] || jar="$HOME/.config/bank/untrusted-cookies"
    [[ $1 != signin-insecure ]] || flags=(-k)
    curl -fsS "${flags[@]}" -c "$jar" \
        --data-urlencode "username=$(sed -n 's/^username=//p' "$HOME/.config/bank/credentials")" \
        --data-urlencode "password=$(sed -n 's/^password=//p' "$HOME/.config/bank/credentials")" "$bank/login"
    ;;
balance) curl -fsS -b "$HOME/.config/bank/cookies" "$bank/balance" ;;
route) traceroute -n -q 1 -w 2 84.21.44.10 ;;
bgp)
    expected=${2:?supply the expected route count}
    sudo install -d /run/bird
    if ! sudo birdc -s /run/bird/bird.ctl show status >/dev/null 2>&1; then
        sudo bird -c /etc/bird/bird.conf -s /run/bird/bird.ctl
    fi
    deadline=$((SECONDS + 30))
    until sudo birdc -s /run/bird/bird.ctl show route count | grep -q "^$expected of $expected routes .* table master4"; do
        if (( SECONDS >= deadline )); then echo 'BIRD did not import the expected routes' >&2; exit 1; fi
        sleep 0.2
    done
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
    if response.status != 200 or conn.sock is None:
        raise RuntimeError('the bank did not keep the connection open')
    print('Persistent HTTPS request: 200', flush=True)
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
        raise RuntimeError('the existing connection survived the route change')
finally:
    os.unlink(path)
PYTHON
    ;;
*) echo 'Usage: bank-check signin|balance|route|bgp COUNT|cert [-k]|signin-insecure|hold' >&2; exit 2 ;;
esac
) 2>&1 | tee "$cache/output"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::{b64_decode, seed};

    #[test]
    fn seed_installs_the_workstation_and_private_credentials() {
        let guest = guest();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        let mut decoded = data.clone();
        for line in data
            .lines()
            .filter_map(|line| line.strip_prefix("    content: "))
        {
            decoded.push_str(&String::from_utf8(b64_decode(line).unwrap()).unwrap());
        }
        for forbidden in ["fictionet", "eval", "sandbox", "world", "border", "demo"] {
            assert!(
                !decoded.to_lowercase().contains(forbidden),
                "guest contains {forbidden}"
            );
        }
        for package in [
            "bird2",
            "traceroute",
            "curl",
            "jq",
            "dnsutils",
            "tmux",
            "firefox",
        ] {
            assert!(data.contains(&format!("'{package}'")));
        }
        assert!(data.contains(
            "path: \"/home/rwhitfield/.config/bank/credentials\"\n    permissions: '0600'"
        ));
        assert!(decoded.contains(&border_world::bank::credentials_file()));
        assert!(decoded.contains("chown -R rwhitfield:rwhitfield /home/rwhitfield/.config/bank"));
        assert!(decoded.contains(BIRD));
        assert!(decoded.contains("install -m0644 /opt/provider.conf /etc/bird/bird.conf"));
        assert!(decoded.contains(SCRIPT));
        assert!(!BIRD.contains("protocol kernel"));
        seed::build(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        })
        .unwrap();
    }
}
