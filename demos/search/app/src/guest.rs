use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";

/// The workstation is ready once Firefox shows its start page: its window
/// title names a page, not only the browser.
fn browser_shows_page() -> String {
    format!(
        "{} && env DISPLAY=:1 xdotool search --onlyvisible --class firefox getwindowname | grep -qv '^Mozilla Firefox$'",
        kit::desktop::BROWSER_READY
    )
}

/// The workstation inherits the host clock from the hypervisor.
pub fn guest(token: Option<&str>) -> Guest<kit::PreparedImage> {
    let mut guest = Guest::prepared(HOST, USER, "search-workstation.qcow2")
        .resources(4, 4096)
        .desktop(kit::desktop::VNC_PORT, browser_shows_page())
        .terminal("env COLORTERM=truecolor DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus tmux new-session -A -s main");
    guest = guest.file(
        &format!("/home/{USER}/.tmux.conf"),
        0o644,
        "set -g status off\nset -g mouse on\nset -g default-terminal tmux-256color\nset -as terminal-features ',xterm-256color:RGB'\nset -g update-environment 'DISPLAY DBUS_SESSION_BUS_ADDRESS COLORTERM'\n",
    );
    // Firefox is a phone browser: sites see a mobile browser and lay out for
    // the portrait screen the page gives it. Links opened from the terminal
    // become tabs of its one window, which fills the screen.
    guest = guest.file(
        &format!("/home/{USER}/.mozilla/firefox/default/user.js"),
        0o644,
        "user_pref(\"general.useragent.override\", \"Mozilla/5.0 (Android 15; Mobile; rv:158.0) Gecko/158.0 Firefox/158.0\");\n\
         user_pref(\"dom.meta-viewport.enabled\", true);\n\
         user_pref(\"browser.link.open_newwindow.override.external\", 3);\n\
         user_pref(\"widget.gtk.overlay-scrollbars.enabled\", true);\n",
    );
    // A phone browser's toolbar: back, reload, the address and the menu, and
    // no desktop minimum width, so the window fits the portrait screen.
    guest = guest.file(
        &format!("/home/{USER}/.mozilla/firefox/default/chrome/userChrome.css"),
        0o644,
        "#TabsToolbar { visibility: collapse }\n\
         :root, #nav-bar, #urlbar-container, #urlbar { min-width: 0 !important }\n\
         #sidebar-button, #forward-button, #home-button, #unified-extensions-button,\n\
         #star-button-box, #reader-mode-button, #picture-in-picture-button { display: none !important }\n",
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
