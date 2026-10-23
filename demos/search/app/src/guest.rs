use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = kit::image::HOST;
pub const USER: &str = kit::image::USER;

/// The workstation inherits the host clock from the hypervisor.
pub fn guest(token: Option<&str>) -> Guest {
    let mut guest = kit::image::workstation();
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
            ca: None,
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
        assert!(!script.contains("apt-get"));
        assert!(!script.contains("date -u -s"));
    }
}
