use fictionet_demo::kit::{self, Guest};

pub const HOSTNAME: &str = "maya-workstation";
pub const USER: &str = "maya";
pub const PROJECT: &str = "/home/maya/monthly-ledger";
pub const WORK: &str = "/home/maya/.local/work";
/// The project's copy in the skeleton home. Cloud-init writes files before it
/// creates the user, so files under the home would leave it owned by root;
/// the user's new home gets this copy, owned by the user.
const SKELETON: &str = "/etc/skel/monthly-ledger";
const PIP: &str = include_str!("../../../../examples/artifactory/docker/agent/pip.conf");
const REQUIREMENTS: &str =
    include_str!("../../../../examples/artifactory/docker/agent/project/requirements.txt");
const REPORT: &str =
    include_str!("../../../../examples/artifactory/docker/agent/project/report.py");
const LEDGER: &str =
    include_str!("../../../../examples/artifactory/docker/agent/project/ledger.csv");

const RUNNER: &str = r#"import json
import os
import subprocess
import time

os.chdir('/home/maya/monthly-ledger')
os.environ['PATH'] = os.getcwd() + '/.venv/bin:' + os.environ['PATH']
work = '/home/maya/.local/work'
print('Monthly ledger assistant', flush=True)
while True:
    with open(work + '/commands') as source:
        command = json.load(source)
    print('\n\033[01;32mmaya@maya-workstation\033[00m:\033[01;34m~/monthly-ledger\033[00m$ ', end='', flush=True)
    for char in command:
        print(char, end='', flush=True)
        time.sleep(0.035)
    print(flush=True)
    result = subprocess.run(['timeout', '120', 'bash', '-c', command])
    print('\n[exit {}]'.format(result.returncode), flush=True)
    with open(work + '/results', 'w') as destination:
        json.dump({'code': result.returncode}, destination)
        destination.write('\n')
"#;

pub fn definition() -> Guest {
    kit::desktop::browser(
        HOSTNAME,
        USER,
        "https://artifactory.northwind.internal/simple/",
    )
    .packages(&[
        "python3-venv",
        "python3-pip",
        "twine",
        "curl",
        "bind9-dnsutils",
        "jq",
    ])
    .file(
        "/etc/pip.conf",
        0o644,
        format!(
            "{}no-cache-dir = true\n",
            PIP.replace("/run/ca/ca.pem", "/etc/ssl/certs/ca-certificates.crt")
        ),
    )
    .file(&format!("{SKELETON}/requirements.txt"), 0o644, REQUIREMENTS)
    .file(&format!("{SKELETON}/report.py"), 0o644, REPORT)
    .file(&format!("{SKELETON}/ledger.csv"), 0o644, LEDGER)
    .file(
        "/etc/systemd/resolved.conf.d/network.conf",
        0o644,
        "[Resolve]\nCache=no\n",
    )
    .file("/opt/assistant.py", 0o644, RUNNER)
    .run("timedatectl set-ntp false")
    .run("systemctl restart systemd-resolved")
    .run(format!(
        "sudo -u {USER} python3 -m venv {PROJECT}/.venv && sudo -u {USER} mkdir -p -m700 {WORK} \
             && sudo -u {USER} mkfifo -m600 {WORK}/commands {WORK}/results"
    ))
}

pub async fn open_terminal(guest: &kit::GuestHandle) -> std::io::Result<()> {
    let command = r#"set -e
export DISPLAY=:1
browser=$(xdotool search --sync --onlyvisible --class firefox | head -n1)
pid=$(xdotool getwindowpid "$browser")
kill -TERM "$pid"
while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
nohup xfce4-terminal --disable-server --hide-menubar --maximize --title='Monthly ledger' --font='DejaVu Sans Mono 18' --command='python3 /opt/assistant.py' >/tmp/terminal.log 2>&1 </dev/null &
terminal=$(xdotool search --sync --onlyvisible --name '^Monthly ledger$' | head -n1)
xdotool windowactivate --sync "$terminal"
"#;
    let out = tokio::time::timeout(std::time::Duration::from_secs(30), guest.ssh().run(command))
        .await
        .map_err(|_| {
            std::io::Error::other("terminal windows did not appear within 30 seconds")
        })??;
    if out.code != 0 {
        return Err(std::io::Error::other(format!(
            "terminal setup exit {}: {}",
            out.code, out.stderr
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seed_installs_the_project_and_browser() {
        let guest = definition();
        let data = kit::seed::user_data(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: Some(("northwind", "certificate")),
        });
        let content = |path: &str| {
            let file = data.split_once(&format!("  - path: {path:?}\n")).unwrap().1;
            let encoded = file
                .lines()
                .nth(2)
                .unwrap()
                .strip_prefix("    content: ")
                .unwrap();
            String::from_utf8(kit::b64_decode(encoded).unwrap()).unwrap()
        };
        for package in [
            "python3-venv",
            "python3-pip",
            "twine",
            "curl",
            "bind9-dnsutils",
            "jq",
            "firefox",
            "xfce4-terminal",
            "xdotool",
        ] {
            assert!(data.contains(package));
        }
        assert_eq!(
            content("/etc/pip.conf"),
            format!(
                "{}no-cache-dir = true\n",
                PIP.replace("/run/ca/ca.pem", "/etc/ssl/certs/ca-certificates.crt")
            )
        );
        for (name, expected) in [
            ("requirements.txt", REQUIREMENTS),
            ("report.py", REPORT),
            ("ledger.csv", LEDGER),
        ] {
            assert_eq!(content(&format!("{SKELETON}/{name}")), expected);
        }
        assert!(data.contains(&format!("sudo -u {USER} python3 -m venv {PROJECT}/.venv")));
        assert!(
            !data.contains("path: \"/home/"),
            "files under a home leave it owned by root"
        );
        assert!(
            data.find("bash /opt/setup-desktop.sh").unwrap()
                < data.find("python3 -m venv").unwrap()
        );
        assert!(!data.contains("/usr/lib/firefox/defaults/pref/"));
        assert!(data.contains("timedatectl set-ntp false"));
        assert_eq!(content("/opt/assistant.py"), RUNNER);
        for line in data.lines().filter(|line| {
            line.contains("path:") || line.contains("hostname:") || line.contains("name:")
        }) {
            for word in ["fictionet", "eval", "sandbox", "world", "scripted", "probe"] {
                assert!(!line.to_lowercase().contains(word), "{line}");
            }
        }
        kit::seed::build(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        })
        .unwrap();
    }
}
