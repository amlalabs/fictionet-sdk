use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";

/// The workstation inherits the host clock from the hypervisor.
pub fn guest(token: Option<&str>) -> Guest<kit::PreparedImage> {
    let mut guest = Guest::prepared(HOST, USER, "search-workstation.qcow2")
        .resources(4, 4096)
        .desktop(kit::desktop::VNC_PORT, kit::desktop::BROWSER_READY)
        .terminal("env DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus tmux new-session -A -s main");
    guest.features = kit::Features {
        claude_code: true,
        codex: true,
        firefox: true,
    };
    if let Some(token) = token {
        let mut settings: serde_json::Value =
            serde_json::from_str(kit::desktop::CLAUDE_SETTINGS).expect("managed settings");
        settings["env"]["CLAUDE_CODE_OAUTH_TOKEN"] = token.into();
        guest = guest
            .file(
                &format!("/home/{USER}/.claude/settings.json"),
                0o600,
                settings.to_string(),
            )
            .file(
                &format!("/home/{USER}/.claude.json"),
                0o600,
                serde_json::json!({
                    "hasCompletedOnboarding": true,
                    "theme": "dark",
                    "projects": {
                        format!("/home/{USER}"): {"hasTrustDialogAccepted": true}
                    }
                })
                .to_string(),
            );
    }
    guest
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn prepared_desktop_receives_only_the_placeholder() {
        let guest = guest(Some("sk-ant-oat01-guest-placeholder"));
        guest.validate().unwrap();
        let image = kit::seed::build(&kit::seed::Provision {
            guest: &guest,
            authorized_key: "fresh-key",
            ca: Some(("office", "fresh-ca")),
        })
        .unwrap();
        let fs =
            fatfs::FileSystem::new(std::io::Cursor::new(image), fatfs::FsOptions::new()).unwrap();
        assert_eq!(fs.volume_label().trim(), "settings");
        let mut script = String::new();
        fs.root_dir()
            .open_file("apply.sh")
            .unwrap()
            .read_to_string(&mut script)
            .unwrap();
        let read_json = |path: &str| -> serde_json::Value {
            let line = script
                .lines()
                .find(|line| {
                    line.starts_with("printf %s ") && line.ends_with(&format!(" > '{path}'"))
                })
                .unwrap();
            let encoded = line.split_whitespace().nth(2).unwrap().trim_matches('\'');
            let bytes = fictionet::stdlib::codec::base64::decode(
                encoded.as_bytes(),
                fictionet::stdlib::codec::base64::Padding::Required,
            )
            .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        let settings = read_json("/home/analyst/.claude/settings.json");
        assert_eq!(
            settings["env"]["CLAUDE_CODE_OAUTH_TOKEN"],
            "sk-ant-oat01-guest-placeholder"
        );
        let state = read_json("/home/analyst/.claude.json");
        assert_eq!(state["hasCompletedOnboarding"], true);
        assert_eq!(
            state["projects"]["/home/analyst"]["hasTrustDialogAccepted"],
            true
        );
        assert!(script.contains("chmod 600 '/home/analyst/.claude/settings.json'"));
        for value in ["fresh-key", "fresh-ca"] {
            assert!(script.contains(&fictionet::stdlib::codec::base64::encode(value.as_bytes())));
        }
        assert!(!script.contains("curl"));
        assert!(!script.contains("apt-get"));
        assert!(!script.contains("date -u -s"));
    }
}
