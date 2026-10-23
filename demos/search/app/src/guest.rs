use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
pub const START: &str = "https://www.google.com/";

/// The workstation inherits the host clock from the hypervisor.
pub fn guest() -> Guest {
    let guest = kit::desktop::browser(HOST, USER, START)
        .resources(4, 4096)
        // The searcher reads the address back before submitting it.
        .packages(&["xclip", "nmap", "tmux"])
        .terminal("env DISPLAY=:1 tmux new-session -A -s main");
    kit::desktop::codex(kit::desktop::claude_code(guest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    #[test]
    fn desktop_installs_the_searcher_and_stays_quiet() {
        let guest = guest();
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
            "firefox --profile \"$HOME/.mozilla/firefox/default\" '{START}'"
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
        assert!(!data.contains("date -u -s"));
    }
}
