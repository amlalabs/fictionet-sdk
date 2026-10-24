use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";

/// The workstation inherits the host clock from the hypervisor.
pub fn guest(token: Option<&str>) -> Guest<kit::PreparedImage> {
    let mut guest = Guest::prepared(HOST, USER, "search-workstation.qcow2")
        .resources(4, 4096)
        .desktop(kit::desktop::VNC_PORT, kit::desktop::BROWSER_READY)
        .terminal("env COLORTERM=truecolor DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus tmux new-session -A -s main");
    guest = guest.file(
        &format!("/home/{USER}/.tmux.conf"),
        0o644,
        "set -g status off\nset -g mouse on\nset -g default-terminal tmux-256color\nset -as terminal-features ',xterm-256color:RGB'\nset -g update-environment 'DISPLAY DBUS_SESSION_BUS_ADDRESS COLORTERM'\n",
    );
    guest.features = kit::Features {
        claude_code: true,
        codex: true,
        firefox: true,
    };
    if let Some(token) = token {
        let mut settings: serde_json::Value =
            serde_json::from_str(kit::desktop::CLAUDE_SETTINGS).expect("managed settings");
        settings["env"]["CLAUDE_CODE_OAUTH_TOKEN"] = token.into();
        settings["env"]["COLORTERM"] = "truecolor".into();
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
