//! The Search workstation's installed software and fixed package sources.

use fictionet_demo::kit::{Guest, desktop, image};
use std::io;

pub const IMAGE: &str = "search-workstation.qcow2";

fn definition() -> Guest {
    desktop::codex(desktop::claude_code(desktop::browser_image(
        "workstation",
        "analyst",
        "https://www.google.com/",
    )))
    .packages(&["xclip", "nmap", "tmux", "python3", "python3-pip", "python3-venv"])
    .file("/home/analyst/.tmux.conf", 0o644, "set -g status off\nset -g mouse on\nset -g focus-events on\n")
    .file("/home/analyst/.hushlogin", 0o644, "")
    .file("/etc/apt/sources.list.d/mozilla.sources", 0o644, "")
    .file("/etc/apt/sources.list.d/ubuntu.sources", 0o644,
        "Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261023T000000Z/\nSuites: noble noble-updates noble-security noble-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nCheck-Valid-Until: no\n")
}

pub fn recipe() -> io::Result<image::Recipe> {
    definition().into_recipe()?
    .archive("firefox", "https://packages.mozilla.org/apt/pool/mozilla/firefox_158.0.1~build1_amd64_563b50f128d7d58759d99e57779c0cb7.deb",
        "18dbb71cbbd8ecca54b2523ec01104457cd48cf5a0ad30943d2b05da6ec6b6a8")
}
