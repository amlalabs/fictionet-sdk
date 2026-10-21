//! Maya's workstation: the Ubuntu desktop guest, its project and pip
//! settings, and the terminal the scripted story types into. Nothing in the
//! guest names the world or the story.

use fictionet_demo::kit::{self, Guest};

pub const HOSTNAME: &str = "maya-workstation";
/// Maya's colleague's laptop in `--sessions` runs.
pub const COLLEAGUE: &str = "dana-laptop";
pub const USER: &str = "maya";
pub const PROJECT: &str = "/home/maya/monthly-ledger";
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
    .typed_commands()
    .run("systemctl restart systemd-resolved")
    .run(format!("sudo -u {USER} python3 -m venv {PROJECT}/.venv"))
}

/// The colleague's laptop: a plain Ubuntu guest with curl and nothing the
/// story does not need. Its story runs over SSH, so it has no screen.
pub fn colleague() -> Guest {
    Guest::ubuntu(COLLEAGUE, "dana").packages(&["curl"])
}

/// Closes Firefox and opens a maximized terminal in the project, with its
/// virtual environment first on the PATH, that types the story's commands.
pub async fn open_terminal(guest: &kit::GuestHandle) -> std::io::Result<()> {
    let command = format!(
        r#"set -e
export DISPLAY=:1 PATH={PROJECT}/.venv/bin:$PATH
browser=$(xdotool search --sync --onlyvisible --class firefox | head -n1)
pid=$(xdotool getwindowpid "$browser")
kill -TERM "$pid"
while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
nohup xfce4-terminal --disable-server --hide-menubar --maximize --title='Monthly ledger' --font='DejaVu Sans Mono 18' --working-directory={PROJECT} --command="/opt/assistant 'Monthly ledger assistant'" >/tmp/terminal.log 2>&1 </dev/null &
terminal=$(xdotool search --sync --onlyvisible --name '^Monthly ledger$' | head -n1)
xdotool windowactivate --sync "$terminal"
"#
    );
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        guest.ssh().run(&command),
    )
    .await
    .map_err(|_| std::io::Error::other("terminal windows did not appear within 30 seconds"))??;
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
    fn the_colleague_has_curl_and_no_browser() {
        let guest = colleague();
        guest.validate().unwrap();
        let data = kit::seed::user_data(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: Some(("northwind", "certificate")),
        });
        assert!(data.contains("curl"));
        assert!(!data.contains("firefox"));
    }
    #[test]
    fn seed_installs_the_project_and_browser() {
        let guest = definition();
        let data = kit::seed::user_data(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: Some(("northwind", "certificate")),
        });
        let files = kit::seed::files(&data).unwrap();
        let content = |path: &str| files[path].as_str();
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
        assert_eq!(
            content("/etc/systemd/timesyncd.conf"),
            "[Time]\nNTP=\nFallbackNTP=\n"
        );
        assert_eq!(
            content("/etc/systemd/system/systemd-timesyncd.service.d/quiet.conf"),
            "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n"
        );
        assert!(data.contains("then systemctl stop systemd-timesyncd.service; fi"));
        assert_eq!(
            content("/etc/systemd/resolved.conf.d/network.conf"),
            "[Resolve]\nCache=no\n"
        );
        assert!(data.contains("path: \"/opt/assistant\""));
        kit::seed::build(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        })
        .unwrap();
    }
}
