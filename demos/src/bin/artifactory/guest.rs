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
    print('\n maya@maya-workstation:~/monthly-ledger $ ', end='', flush=True)
    for char in command:
        print(char, end='', flush=True)
        time.sleep(0.015)
    print(flush=True)
    result = subprocess.run(['timeout', '120', 'bash', '-c', command])
    print('\n[exit {}]'.format(result.returncode), flush=True)
    with open(work + '/results', 'w') as destination:
        json.dump({'code': result.returncode}, destination)
        destination.write('\n')
"#;

const PREFERENCES: &str = r#"pref("network.captive-portal-service.enabled", false);
pref("network.connectivity-service.enabled", false);
pref("toolkit.telemetry.enabled", false);
pref("toolkit.telemetry.unified", false);
pref("toolkit.telemetry.server", "");
pref("datareporting.healthreport.uploadEnabled", false);
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("app.shield.optoutstudies.enabled", false);
pref("app.normandy.enabled", false);
pref("app.normandy.api_url", "");
pref("services.settings.server", "");
pref("dom.push.enabled", false);
pref("browser.safebrowsing.malware.enabled", false);
pref("browser.safebrowsing.phishing.enabled", false);
pref("browser.safebrowsing.downloads.enabled", false);
pref("browser.safebrowsing.downloads.remote.enabled", false);
pref("browser.safebrowsing.provider.google.updateURL", "");
pref("browser.safebrowsing.provider.google4.updateURL", "");
pref("browser.safebrowsing.provider.mozilla.updateURL", "");
pref("extensions.update.enabled", false);
pref("extensions.getAddons.cache.enabled", false);
pref("extensions.systemAddon.update.enabled", false);
pref("extensions.systemAddon.update.url", "");
pref("browser.region.network.url", "");
pref("browser.region.update.enabled", false);
pref("browser.search.geoip.url", "");
pref("browser.search.update", false);
pref("network.dns.disablePrefetch", true);
pref("network.prefetch-next", false);
pref("network.predictor.enabled", false);
pref("network.http.speculative-parallel-limit", 0);
pref("browser.urlbar.speculativeConnect.enabled", false);
pref("browser.urlbar.suggest.searches", false);
pref("browser.search.suggest.enabled", false);
pref("media.gmp-provider.enabled", false);
pref("media.gmp-manager.updateEnabled", false);
pref("media.gmp-manager.url", "");
pref("media.gmp-gmpopenh264.enabled", false);
pref("browser.newtabpage.enabled", false);
pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
pref("browser.newtabpage.activity-stream.telemetry", false);
pref("browser.newtabpage.activity-stream.showSponsored", false);
pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
pref("browser.newtabpage.activity-stream.asrouter.providers.cfr", "");
pref("browser.discovery.enabled", false);
pref("browser.ping-centre.telemetry", false);
pref("browser.topsites.contile.enabled", false);
pref("extensions.pocket.enabled", false);
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
    .file(
        "/usr/lib/firefox/defaults/pref/network.js",
        0o644,
        PREFERENCES,
    )
    .run("systemctl restart systemd-resolved")
    .run(format!(
        "sudo -u {USER} python3 -m venv {PROJECT}/.venv && sudo -u {USER} mkdir -p -m700 {WORK} \
             && sudo -u {USER} mkfifo -m600 {WORK}/commands {WORK}/results"
    ))
}

pub async fn open_terminal(guest: &kit::GuestHandle) -> std::io::Result<()> {
    let command = r#"export DISPLAY=:1
nohup xfce4-terminal --disable-server --hide-menubar --title='Monthly ledger' --font='DejaVu Sans Mono 13' --command='python3 /opt/assistant.py' >/tmp/terminal.log 2>&1 </dev/null &
set -e
browser=$(xdotool search --sync --onlyvisible --class firefox | head -n1)
terminal=$(xdotool search --sync --onlyvisible --name '^Monthly ledger$' | head -n1)
xdotool windowmove "$browser" 0 40 windowsize "$browser" 460 740
xdotool windowmove "$terminal" 460 40 windowsize "$terminal" 820 740 windowactivate "$terminal"
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
        assert_eq!(
            content("/usr/lib/firefox/defaults/pref/network.js"),
            PREFERENCES
        );
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
