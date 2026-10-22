use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
pub const START: &str = "https://www.google.com/";

/// The workstation, with its clock on `date` (YYYY-MM-DD), the day the
/// web it searches is on.
pub fn guest(date: &str) -> Guest {
    let guest = kit::desktop::browser(HOST, USER, START)
        .resources(4, 4096)
        // The searcher reads the address back before submitting it.
        .packages(&["xclip", "nmap", "tmux"])
        .terminal("tmux new-session -A -s main");
    let date = date
        .bytes()
        .all(|c| c.is_ascii_digit() || c == b'-')
        .then_some(date)
        .expect("a YYYY-MM-DD date");
    kit::desktop::codex(kit::desktop::claude_code(guest))
        // Once the packages are in, and before the desktop starts, the clock
        // moves to the web's day, at the same time of day.
        .run_first(format!("date -u -s {date}T$(date -u +%T)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    #[test]
    fn desktop_installs_the_searcher_and_stays_quiet() {
        let guest = guest("2026-10-07");
        guest.validate().unwrap();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        for package in [
            "firefox",
            "xdotool",
            "xclip",
            "nmap",
            "tigervnc-standalone-server",
            "xfce4",
        ] {
            assert!(data.contains(&format!("'{package}'")), "{package}");
        }
        let files = seed::files(&data).unwrap();
        assert_eq!(files["/etc/apt/apt.conf.d/20apt-esm-hook.conf"], "");
        assert!(data.contains("    content: \"\"\n"));
        assert!(files["/opt/start-desktop.sh"].contains(&format!(
            "firefox --no-remote --profile \"$HOME/.mozilla/firefox/default\" '{START}'"
        )));
        assert!(
            files["/etc/firefox/policies/policies.json"]
                .contains("firefox.settings.services.mozilla.com")
        );
        assert!(files["/etc/apt/apt.conf.d/99periodic"].contains("APT::Periodic::Enable \"0\""));
        assert!(files["/etc/default/motd-news"].contains("ENABLED=0"));
        for path in [
            "/etc/systemd/timesyncd.conf",
            "/etc/systemd/system/apt-daily.timer.d/quiet.conf",
        ] {
            assert!(files.contains_key(path), "{path}");
        }
        assert!(data.contains("then systemctl stop apt-daily.timer; fi"));
        assert!(files.contains_key("/etc/claude-code/managed-settings.json"));
        assert!(
            data.find("date -u -s").unwrap() < data.find("bash /opt/setup-desktop.sh").unwrap()
        );
        assert!(data.contains("date -u -s 2026-10-07T$(date -u +%T)"));
    }
}
