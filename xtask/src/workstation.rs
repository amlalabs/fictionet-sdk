//! The Search workstation's installed software, settings and fixed package sources.

use fictionet_demo::kit::{Guest, desktop, image, ssh};
use std::io;

pub const IMAGE: &str = "search-workstation.qcow2";
const USER: &str = "analyst";

/// The workstation with the root certificate it trusts and the Claude
/// credential placeholder it carries.
fn definition(root_pem: &str, placeholder: &str) -> io::Result<Guest> {
    let mut settings: serde_json::Value =
        serde_json::from_str(desktop::CLAUDE_SETTINGS).expect("managed settings");
    settings["env"]["CLAUDE_CODE_OAUTH_TOKEN"] = placeholder.into();
    settings["env"]["COLORTERM"] = "truecolor".into();
    let claude_state = serde_json::json!({
        "hasCompletedOnboarding": true,
        "theme": "dark",
        "projects": {
            format!("/home/{USER}"): {"hasTrustDialogAccepted": true}
        }
    });
    desktop::claude_code(desktop::browser_image(
        "workstation",
        USER,
        "https://www.google.com/",
    ))
    .packages(&["xclip", "nmap", "tmux", "python3", "python3-pip", "python3-venv"])
    // Pages and search results in Chinese, Japanese or Korean, and emoji,
    // show their glyphs instead of empty boxes.
    .packages(&["fonts-noto-cjk", "fonts-noto-color-emoji"])
    // An attach copies nothing from the attaching client into the session.
    .file(&format!("/home/{USER}/.tmux.conf"), 0o644,
        "set -g status off\nset -g mouse on\nset -g default-terminal tmux-256color\nset -as terminal-features ',xterm-256color:RGB'\nset -g update-environment \"\"\n")
    // The user's terminal session starts at boot on the desktop's display,
    // and again whenever its last shell exits.
    .file(&format!("/home/{USER}/.config/systemd/user/tmux.service"), 0o644,
        "[Unit]\nDescription=Terminal session\n[Service]\nType=forking\nEnvironment=DISPLAY=:1 COLORTERM=truecolor DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus\nWorkingDirectory=%h\nExecStart=/usr/bin/tmux new-session -d -s main\nRestart=always\n[Install]\nWantedBy=default.target\n")
    .run(format!("mkdir -p /home/{USER}/.config/systemd/user/default.target.wants && ln -sf ../tmux.service /home/{USER}/.config/systemd/user/default.target.wants/tmux.service"))
    .run(format!("mkdir -p /var/lib/systemd/linger && touch /var/lib/systemd/linger/{USER}"))
    // The desktop opens once network time has set the clock.
    .file("/etc/systemd/system/vnc.service.d/time.conf", 0o644,
        "[Unit]\nWants=time-sync.target\nAfter=time-sync.target\n")
    .run("systemctl enable systemd-time-wait-sync.service")
    // timesyncd starts before the resolver, so its first lookup fails; by
    // default it then waits 30 s before asking again.
    .file("/etc/systemd/timesyncd.conf.d/retry.conf", 0o644,
        "[Time]\nConnectionRetrySec=2\n")
    .file(&format!("/home/{USER}/.hushlogin"), 0o644, "")
    // Firefox is a phone browser: sites see a mobile browser and lay out for
    // the portrait screen the page gives it. Links opened from the terminal
    // become tabs of its one window, which fills the screen.
    .file("/opt/desktop/firefox/default/user.js", 0o644,
        "user_pref(\"general.useragent.override\", \"Mozilla/5.0 (Android 15; Mobile; rv:158.0) Gecko/158.0 Firefox/158.0\");\n\
         user_pref(\"dom.meta-viewport.enabled\", true);\n\
         user_pref(\"browser.link.open_newwindow.override.external\", 3);\n\
         user_pref(\"widget.gtk.overlay-scrollbars.enabled\", true);\n")
    // A phone browser's toolbar: back, reload, the address and the menu, and
    // no desktop minimum width, so the window fits the portrait screen.
    .file("/opt/desktop/firefox/default/chrome/userChrome.css", 0o644,
        "#TabsToolbar { visibility: collapse }\n\
         :root, #nav-bar, #urlbar-container, #urlbar { min-width: 0 !important }\n\
         #sidebar-button, #forward-button, #home-button, #unified-extensions-button,\n\
         #star-button-box, #reader-mode-button, #picture-in-picture-button { display: none !important }\n")
    .file(&format!("/home/{USER}/.claude/settings.json"), 0o600, settings.to_string())
    .file(&format!("/home/{USER}/.claude.json"), 0o600, claude_state.to_string())
    .file("/etc/apt/sources.list.d/mozilla.sources", 0o644, "")
    .file("/etc/apt/sources.list.d/ubuntu.sources", 0o644,
        "Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/\nSuites: noble noble-updates noble-security noble-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nCheck-Valid-Until: no\n")
    .trust("office", root_pem)
}

pub fn recipe(
    admin: &ssh::Identity,
    root_pem: &str,
    placeholder: &str,
) -> io::Result<image::Recipe> {
    definition(root_pem, placeholder)?.into_recipe(admin)?
    .archive("firefox", "https://packages.mozilla.org/apt/pool/mozilla/firefox_158.0.1~build1_amd64_563b50f128d7d58759d99e57779c0cb7.deb",
        "18dbb71cbbd8ecca54b2523ec01104457cd48cf5a0ad30943d2b05da6ec6b6a8")
}
