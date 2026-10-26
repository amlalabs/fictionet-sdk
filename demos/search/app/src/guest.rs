use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
/// The workstation image, built with `cargo xtask search-image`, which also
/// leaves its admin key, trust root and credential placeholder beside it.
pub const IMAGE: &str = "search-workstation.qcow2";

/// The workstation is ready once Firefox shows its start page: its window
/// title names a page, not only the browser.
fn browser_shows_page() -> String {
    format!(
        "{} && env DISPLAY=:1 xdotool search --onlyvisible --class firefox getwindowname | grep -qv '^Mozilla Firefox$'",
        kit::desktop::BROWSER_READY
    )
}

/// The workstation: its settings, its trust root and the user's terminal
/// session, started at boot, are all in its image. The page terminal joins
/// that session.
pub fn guest() -> Guest<kit::PreparedImage> {
    let mut guest = Guest::prepared(HOST, USER, IMAGE)
        .resources(4, 4096)
        .desktop(kit::desktop::VNC_PORT, browser_shows_page())
        .terminal("tmux attach -t main");
    guest.features = kit::Features {
        claude_code: true,
        codex: true,
        firefox: true,
    };
    guest
}
