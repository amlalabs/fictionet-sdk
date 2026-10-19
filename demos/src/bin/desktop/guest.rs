//! The workstation desktop and pinned coding agents.

use fictionet_demo::kit::Guest;

/// Mozilla's apt signing key, armored (public; checked against its sha256).
const MOZILLA_KEY: &str = include_str!("packages.mozilla.org.asc");

/// Claude Code's native build, on Anthropic's stable channel. The guest
/// fetches the zstd file as Anthropic's installer does, and checks it and
/// the binary it unpacks to against the sha256s in the release's
/// `manifest.zst.json` and `manifest.json`, both signed with Anthropic's
/// release key.
pub const CLAUDE_VERSION: &str = "2.1.292";
const CLAUDE_ZST_SHA256: &str = "28509427a53a5c15bd94d022d39013cc4b867a8e6305497f48162dcf91576326";
const CLAUDE_SHA256: &str = "a967e7b1d8b4e47ee421d5433027880347952b0c0857abf880e2c942a4ec93b3";
/// Codex's standalone package for x86-64 Linux (musl), the one OpenAI's
/// installer unpacks: the CLI with its ripgrep and bubblewrap. Its sha256 is
/// the digest the release lists on GitHub and on releases.openai.com.
pub const CODEX_VERSION: &str = "0.163.0";
const CODEX_SHA256: &str = "df22dac1f24b7927e817e8b113067fbe1caa586aba7554247fabd49464cf9c96";

pub fn workstation(hostname: &str, user: &str, site: &str) -> Guest {
    let mozilla_sources = "Types: deb\n\
         URIs: https://packages.mozilla.org/apt\n\
         Suites: mozilla\n\
         Components: main\n\
         Signed-By: /etc/apt/keyrings/packages.mozilla.org.asc\n"
        .to_string();
    let mozilla_pref = "Package: *\n\
         Pin: origin packages.mozilla.org\n\
         Pin-Priority: 1000\n";
    // Firefox trusts the system store through p11-kit and opens the world's
    // site; no first-run pages.
    let policies = format!(
        "{{\"policies\":{{\
           \"OverrideFirstRunPage\":\"\",\"OverridePostUpdatePage\":\"\",\
           \"DisableAppUpdate\":true,\"DontCheckDefaultBrowser\":true,\
           \"DNSOverHTTPS\":{{\"Enabled\":false,\"Locked\":true}},\
           \"Homepage\":{{\"URL\":\"https://{site}/\",\"StartPage\":\"homepage\"}},\
           \"SecurityDevices\":{{\"Add\":{{\"p11-kit-trust\":\
             \"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so\"}}}},\
           \"UserMessaging\":{{\"SkipOnboarding\":true,\"WhatsNew\":false}},\
           \"Preferences\":{{\
             \"browser.preonboarding.enabled\":{{\"Value\":false,\"Status\":\"locked\"}},\
             \"datareporting.policy.dataSubmissionPolicyBypassNotification\":{{\
               \"Value\":true,\"Status\":\"locked\"}}\
           }}\
         }}}}"
    );
    // Xvnc on :1 (5901), loopback only, no auth: reached only through an SSH
    // tunnel. An Xfce session and Firefox for the user.
    let start_desktop = format!(
        "#!/bin/bash\n\
         set -x\n\
         export HOME=/home/{user} DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/$(id -u {user})\n\
         /usr/bin/Xvnc :1 -localhost -SecurityTypes None -AlwaysShared -nolisten tcp \
           -geometry 1280x800 -depth 24 >/tmp/xvnc.log 2>&1 &\n\
         for _ in $(seq 1 150); do xdpyinfo -display :1 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         eval \"$(dbus-launch --sh-syntax)\"\n\
         # The Xfce session, then the window manager, then Firefox: launched\n\
         # here (not via Xfce autostart, which did not run reliably) so its\n\
         # start is ordered and its output is captured.\n\
         startxfce4 >/tmp/xfce.log 2>&1 &\n\
         for _ in $(seq 1 150); do pgrep -x xfwm4 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         sleep 2\n\
         # Create the profile root so Firefox never hits \"profile missing\".\n\
         mkdir -p \"$HOME/.mozilla/firefox\"\n\
         firefox --no-remote https://{site}/ >/tmp/firefox.log 2>&1 &\n\
         wait\n",
        user = user,
        site = site,
    );
    let vnc_service = format!(
        "[Unit]\n\
         Description=Xvnc with an Xfce session\n\
         After=systemd-user-sessions.service\n\
         [Service]\n\
         User={user}\n\
         PAMName=login\n\
         ExecStart=/opt/start-desktop.sh\n\
         Restart=on-failure\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = user,
    );
    let setup = setup_script(user);

    Guest::ubuntu(hostname, user)
        .resources(4, 4096)
        .dmi("LENOVO", "20UES000-WS")
        .packages(&[
            "xfce4",
            "xfce4-terminal",
            "tigervnc-standalone-server",
            "dbus-x11",
            "xdotool",
            "firefox",
            "p11-kit",
            "p11-kit-modules",
            "libnss3",
            "fonts-dejavu-core",
            "fonts-liberation",
            "adwaita-icon-theme",
            "x11-utils",
            "scrot",
        ])
        .file(
            "/etc/apt/keyrings/packages.mozilla.org.asc",
            0o644,
            MOZILLA_KEY,
        )
        .file(
            "/etc/apt/sources.list.d/mozilla.sources",
            0o644,
            mozilla_sources,
        )
        .file("/etc/apt/preferences.d/mozilla", 0o644, mozilla_pref)
        .file("/etc/firefox/policies/policies.json", 0o644, policies)
        .file("/opt/start-desktop.sh", 0o755, start_desktop)
        .file("/etc/systemd/system/vnc.service", 0o644, vnc_service)
        .file(
            "/etc/claude-code/managed-settings.json",
            0o644,
            "{\"env\":{\"DISABLE_UPDATES\":\"1\"}}\n",
        )
        .file("/opt/setup-desktop.sh", 0o755, setup)
        .run("bash /opt/setup-desktop.sh")
}

/// The install-and-wire script run from `runcmd`.
fn setup_script(user: &str) -> String {
    format!(
        "#!/bin/bash\n\
         set -euo pipefail\n\
         # Mozilla's Firefox, not Ubuntu's snap shim.\n\
         test -x /usr/lib/firefox/firefox\n\
         # One trust store: NSS's builtin roots module becomes p11-kit's.\n\
         mkdir -p /usr/lib/x86_64-linux-gnu/nss\n\
         dpkg-divert --add --rename \
           --divert /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so \
           /usr/lib/x86_64-linux-gnu/libnssckbi.so\n\
         ln -sf pkcs11/p11-kit-trust.so /usr/lib/x86_64-linux-gnu/libnssckbi.so\n\
         # Xfce's default panel for {user}, so no first-run dialog.\n\
         install -d -o {user} -g {user} /home/{user}/.config/xfce4/xfconf/xfce-perchannel-xml\n\
         install -o {user} -g {user} -m0644 /etc/xdg/xfce4/panel/default.xml \
           /home/{user}/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml\n\
         chown -R {user}:{user} /home/{user}/.config\n\
         # Bring the desktop up.\n\
         systemctl daemon-reload\n\
         systemctl enable --now vnc.service\n\
         # The coding agents, from their vendors' release servers, each checked\n\
         # against its pinned sha256; sha256sum -c stops the script on a mismatch.\n\
         # Both go in /usr/local/bin, on PATH in every shell and session.\n\
         started=$SECONDS\n\
         work=$(mktemp -d)\n\
         curl -fsSLo \"$work/claude.zst\" \
           https://downloads.claude.ai/claude-code-releases/{CLAUDE_VERSION}/linux-x64/claude.zst\n\
         echo \"{CLAUDE_ZST_SHA256}  $work/claude.zst\" | sha256sum -c -\n\
         zstd -dq \"$work/claude.zst\" -o \"$work/claude\"\n\
         echo \"{CLAUDE_SHA256}  $work/claude\" | sha256sum -c -\n\
         install -m0755 \"$work/claude\" /usr/local/bin/claude\n\
         curl -fsSLo \"$work/codex.tar.zst\" \
           https://releases.openai.com/codex/releases/{CODEX_VERSION}/\
             codex-package-x86_64-unknown-linux-musl.tar.zst\n\
         echo \"{CODEX_SHA256}  $work/codex.tar.zst\" | sha256sum -c -\n\
         install -d /opt/codex\n\
         tar --zstd -xf \"$work/codex.tar.zst\" --no-same-owner -C /opt/codex\n\
         ln -sf /opt/codex/bin/codex /usr/local/bin/codex\n\
         echo \"coding agents: $(cat \"$work/claude.zst\" \"$work/codex.tar.zst\" | wc -c) \
           bytes in $((SECONDS - started)) s\"\n\
         rm -rf \"$work\"\n",
    )
}
