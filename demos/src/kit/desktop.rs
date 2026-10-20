//! An Ubuntu browser desktop reached through the admin SSH session.

use super::Guest;

/// Xvnc's display port on the guest's loopback.
pub const VNC_PORT: u16 = 5901;
/// HTTPS hosts used at boot. Serve these through World::mirror with TLS
/// certificates from the CA passed to World::trust.
pub const HOSTS: &[&str] = &["packages.mozilla.org"];

const MOZILLA_KEY: &str = include_str!("desktop/packages.mozilla.org.asc");

/// An Ubuntu guest with Xfce on Xvnc and Mozilla's Firefox at start_url.
/// Panics if the URL is not neutral HTTP or HTTPS or contains shell quoting
/// or expansion characters. Desktop setup precedes caller-added run steps.
pub fn browser(hostname: &str, user: &str, start_url: &str) -> Guest {
    let rest = start_url
        .strip_prefix("https://")
        .or_else(|| start_url.strip_prefix("http://"));
    assert!(
        rest.is_some_and(|s| !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~:/?#[]@!&()*+,;=%".contains(&c)))
            && super::neutral(start_url),
        "invalid start URL {start_url:?}; use a neutral http:// or https:// URL with URL characters and no whitespace, quotes, backslashes, dollar signs or backticks"
    );
    let mozilla_sources = "Types: deb\n\
         URIs: https://packages.mozilla.org/apt\n\
         Suites: mozilla\n\
         Components: main\n\
         Signed-By: /etc/apt/keyrings/packages.mozilla.org.asc\n"
        .to_string();
    let mozilla_pref = "Package: *\n\
         Pin: origin packages.mozilla.org\n\
         Pin-Priority: 1000\n";
    let policies = serde_json::json!({"policies": {
        "OverrideFirstRunPage": "", "OverridePostUpdatePage": "",
        "DisableAppUpdate": true, "DontCheckDefaultBrowser": true,
        "DNSOverHTTPS": {"Enabled": false, "Locked": true},
        "Homepage": {"URL": start_url, "StartPage": "homepage"},
        "SecurityDevices": {"Add": {"p11-kit-trust": "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so"}},
        "UserMessaging": {"SkipOnboarding": true, "WhatsNew": false},
        "Preferences": {
            "browser.preonboarding.enabled": {"Value": false, "Status": "locked"},
            "datareporting.policy.dataSubmissionPolicyBypassNotification": {"Value": true, "Status": "locked"}
        }
    }}).to_string();
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
         firefox --no-remote '{start_url}' >/tmp/firefox.log 2>&1 &\n\
         wait\n",
        user = user,
        start_url = start_url,
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
        .desktop(
            VNC_PORT,
            "env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && pgrep -x xfwm4 >/dev/null",
        )
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
",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::{b64_decode, seed};

    #[test]
    fn browser_seed_has_the_desktop_and_firefox_policy() {
        let url = "https://example.test/start?a=1&b=two#section";
        let guest = browser("workstation", "analyst", url).run("echo caller");
        guest.validate().unwrap();
        let (port, ready) = guest.desktop.as_ref().unwrap();
        assert_eq!(*port, VNC_PORT);
        assert!(ready.contains("DISPLAY=:1 xdpyinfo"));
        assert!(ready.contains("pgrep -x xfwm4"));
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        let content = |path: &str| {
            let file = data.split_once(&format!("  - path: {path:?}\n")).unwrap().1;
            let encoded = file
                .lines()
                .nth(2)
                .unwrap()
                .strip_prefix("    content: ")
                .unwrap();
            String::from_utf8(b64_decode(encoded).unwrap()).unwrap()
        };
        assert_eq!(
            content("/etc/apt/keyrings/packages.mozilla.org.asc"),
            MOZILLA_KEY
        );
        assert!(
            content("/etc/apt/sources.list.d/mozilla.sources")
                .contains("https://packages.mozilla.org/apt")
        );
        assert!(content("/etc/apt/preferences.d/mozilla").contains("Pin-Priority: 1000"));
        let policy: serde_json::Value =
            serde_json::from_str(&content("/etc/firefox/policies/policies.json")).unwrap();
        let policy = &policy["policies"];
        assert_eq!(policy["Homepage"]["URL"], url);
        assert_eq!(
            policy["SecurityDevices"]["Add"]["p11-kit-trust"],
            "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so"
        );
        assert_eq!(policy["OverrideFirstRunPage"], "");
        assert_eq!(policy["OverridePostUpdatePage"], "");
        assert_eq!(policy["UserMessaging"]["SkipOnboarding"], true);
        assert_eq!(policy["UserMessaging"]["WhatsNew"], false);
        assert_eq!(policy["DontCheckDefaultBrowser"], true);
        assert_eq!(policy["DisableAppUpdate"], true);
        assert_eq!(policy["DNSOverHTTPS"]["Enabled"], false);
        assert_eq!(
            policy["Preferences"]["browser.preonboarding.enabled"]["Value"],
            false
        );
        let start = content("/opt/start-desktop.sh");
        assert!(start.contains("Xvnc :1 -localhost"));
        assert!(start.contains(&format!("firefox --no-remote '{url}'")));
        assert!(
            content("/etc/systemd/system/vnc.service").contains("ExecStart=/opt/start-desktop.sh")
        );
        let setup = content("/opt/setup-desktop.sh");
        assert!(setup.contains("ln -sf pkcs11/p11-kit-trust.so"));
        assert!(setup.contains("/etc/xdg/xfce4/panel/default.xml"));
        assert!(
            data.find("bash /opt/setup-desktop.sh").unwrap() < data.find("echo caller").unwrap()
        );
    }

    #[test]
    fn invalid_urls_name_the_url_and_rule() {
        for url in [
            "file:///tmp/page",
            "https://",
            "https://host/\"",
            "https://host/'",
            "https://host/\\",
            "https://host/$HOME",
            "https://host/`id`",
            "https://host/a b",
            "https://host/\n",
            "https://world.test/",
            "https://host/<script>",
        ] {
            let panic = std::panic::catch_unwind(|| browser("workstation", "analyst", url))
                .err()
                .unwrap();
            let message = panic.downcast_ref::<String>().unwrap();
            assert!(message.contains(&format!("{url:?}")), "{message}");
            assert!(
                message.contains("neutral http:// or https:// URL"),
                "{message}"
            );
        }
    }
}
