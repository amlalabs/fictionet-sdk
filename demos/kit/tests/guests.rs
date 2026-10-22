use fictionet_demo::kit::{Guest, desktop, seed};
use std::io::Read;

#[path = "../../artifactory/app/src/guest.rs"]
mod artifactory;
#[path = "../../border/app/src/guest.rs"]
mod border;
#[path = "../../fakewiki/app/src/guest.rs"]
mod fakewiki;
#[path = "../../scan/app/src/guests.rs"]
mod scan;
#[path = "../../search/app/src/guest.rs"]
mod search;
#[path = "../../desktop/app/src/guest.rs"]
mod workstation;

const HOST: &str = "workstation";
const URL: &str = "https://en.wikipedia.org/wiki/Stream_ripping";

#[test]
fn every_guest_seed_carries_quieting_and_no_forbidden_words() {
    for (guest, browser, claude) in [
        (Guest::ubuntu("station", "analyst"), false, false),
        (search::guest("2026-10-07"), true, true),
        (border::guest(), true, true),
        (fakewiki::workstation(), true, false),
        (scan::workstation(), false, false),
        (scan::server(), false, false),
        (artifactory::definition(), true, false),
        (artifactory::colleague(), false, false),
        (
            workstation::workstation(HOST, "analyst", "intranet.northwind.internal"),
            true,
            true,
        ),
    ] {
        check_seed(&guest, browser, claude);
    }
}

fn check_seed(guest: &Guest, browser: bool, claude: bool) {
    guest.validate().unwrap();
    let provision = seed::Provision {
        guest,
        authorized_key: "key",
        ca: Some(("office", "root")),
    };
    let data = seed::user_data(&provision);
    let files = seed::files(&data).unwrap();
    for (path, expected) in [
        ("/etc/apt/apt.conf.d/20apt-esm-hook.conf", ""),
        (
            "/etc/ubuntu-advantage/uaclient.conf",
            "ua_config:\n  apt_news: false\n",
        ),
        (
            "/etc/update-manager/release-upgrades",
            "[DEFAULT]\nPrompt=never\n",
        ),
        (
            "/etc/systemd/timesyncd.conf",
            "[Time]\nNTP=\nFallbackNTP=\n",
        ),
        (
            "/etc/apt/apt.conf.d/99periodic",
            "APT::Periodic::Enable \"0\";\n",
        ),
        ("/etc/default/motd-news", "ENABLED=0\n"),
    ] {
        assert_eq!(files[path], expected, "{path}");
    }
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
        assert_eq!(
            files[&format!("/etc/systemd/system/{unit}.d/quiet.conf")],
            "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n"
        );
        assert!(data.contains(&format!(
            "if systemctl is-active --quiet {unit}; then systemctl stop {unit}; fi"
        )));
    }
    assert_eq!(
        files.contains_key("/etc/firefox/policies/policies.json"),
        browser
    );
    if browser {
        let policy: serde_json::Value =
            serde_json::from_str(&files["/etc/firefox/policies/policies.json"]).unwrap();
        assert_eq!(policy["policies"]["DisableTelemetry"], true);
        assert_eq!(
            policy["policies"]["Preferences"]["browser.preonboarding.enabled"]["Value"],
            false
        );
        assert_eq!(
            files["/opt/desktop/firefox/default/chrome/userChrome.css"],
            "#TabsToolbar { visibility: collapse }\n"
        );
        let base = "/opt/desktop/xfce4/xfconf/xfce-perchannel-xml";
        assert!(files[&format!("{base}/xfwm4.xml")].contains("titleless_maximize"));
        assert!(
            files[&format!("{base}/xfce4-panel.xml")]
                .contains("<property name=\"panels\" type=\"array\"/>")
        );
        assert!(
            files[&format!("{base}/xfce4-desktop.xml")]
                .contains("<property name=\"style\" type=\"int\" value=\"0\"/>")
        );
    }
    assert_eq!(
        files.contains_key("/etc/claude-code/managed-settings.json"),
        claude
    );
    if claude {
        assert_eq!(
            files["/etc/claude-code/managed-settings.json"],
            desktop::CLAUDE_SETTINGS
        );
    }
    let image = seed::build(&provision).unwrap();
    let fs = fatfs::FileSystem::new(std::io::Cursor::new(image), fatfs::FsOptions::new()).unwrap();
    for entry in fs.root_dir().iter() {
        let entry = entry.unwrap();
        let mut text = String::new();
        entry.to_file().read_to_string(&mut text).unwrap();
        let decoded = seed::files(&text).unwrap();
        for line in text
            .lines()
            .filter(|line| !line.starts_with("    content: "))
            .chain(decoded.values().flat_map(|content| content.lines()))
        {
            assert_eq!(guest.reveals(line), None, "{}: {line}", entry.file_name());
        }
    }
}
