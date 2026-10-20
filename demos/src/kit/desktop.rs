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
        "DisableAppUpdate": true, "AppAutoUpdate": false,
        "DontCheckDefaultBrowser": true,
        "DNSOverHTTPS": {"Enabled": false, "Locked": true},
        "Homepage": {"URL": start_url, "StartPage": "homepage"},
        "SecurityDevices": {"Add": {"p11-kit-trust": "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so"}},
        "UserMessaging": {
            "SkipOnboarding": true, "WhatsNew": false, "ExtensionRecommendations": false,
            "FeatureRecommendations": false, "UrlbarInterventions": false,
            "MoreFromMozilla": false, "Locked": true
        },
        // Each of these turns off requests that no page asked for.
        "DisableTelemetry": true,
        "DisableFirefoxStudies": true,
        "DisablePocket": true,
        "DisableFirefoxAccounts": true,
        "DisableSystemAddonUpdate": true,
        "ExtensionUpdate": false,
        "CaptivePortal": false,
        "NetworkPrediction": false,
        "SearchSuggestEnabled": false,
        "TranslateEnabled": false,
        "NewTabPage": false,
        "EncryptedMediaExtensions": {"Enabled": false, "Locked": true},
        "FirefoxHome": {
            "Search": false, "TopSites": false, "SponsoredTopSites": false, "Highlights": false,
            "Pocket": false, "SponsoredPocket": false, "Locked": true
        },
        "FirefoxSuggest": {
            "WebSuggestions": false, "SponsoredSuggestions": false, "ImproveSuggest": false,
            "Locked": true
        },
        "Preferences": quiet_preferences(),
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
         while IFS= read -r entry; do export \"$entry\"; done < <(dbus-launch)\n\
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

/// Locked preferences that keep Firefox from making requests no page asked
/// for, in the form the enterprise `Preferences` policy takes. Release
/// Firefox ignores `services.settings.server`, and the policy cannot set
/// `app.normandy.enabled`, so the remote settings and studies hosts resolve
/// to the guest's own loopback instead.
fn quiet_preferences() -> serde_json::Value {
    let preferences: &[(&str, serde_json::Value)] = &[
        ("browser.preonboarding.enabled", false.into()),
        (
            "datareporting.policy.dataSubmissionPolicyBypassNotification",
            true.into(),
        ),
        ("datareporting.policy.dataSubmissionEnabled", false.into()),
        // A typed address stays an address after a search.
        ("browser.urlbar.showSearchTerms.enabled", false.into()),
        ("browser.urlbar.showSearchTerms.featureGate", false.into()),
        // Suggestions send a request for every address bar keystroke.
        ("browser.search.suggest.enabled", false.into()),
        ("browser.urlbar.suggest.searches", false.into()),
        ("browser.urlbar.quicksuggest.enabled", false.into()),
        // Speculation and prefetch request pages before anyone opens them.
        ("network.http.speculative-parallel-limit", 0.into()),
        ("network.dns.disablePrefetch", true.into()),
        ("network.prefetch-next", false.into()),
        ("network.predictor.enabled", false.into()),
        ("browser.urlbar.speculativeConnect.enabled", false.into()),
        ("browser.places.speculativeConnect.enabled", false.into()),
        // Connectivity checks.
        ("network.captive-portal-service.enabled", false.into()),
        ("network.connectivity-service.enabled", false.into()),
        // New tab feeds, sponsored content and recommendations.
        ("browser.newtabpage.enabled", false.into()),
        (
            "browser.newtabpage.activity-stream.feeds.telemetry",
            false.into(),
        ),
        ("browser.newtabpage.activity-stream.telemetry", false.into()),
        (
            "browser.newtabpage.activity-stream.feeds.section.topstories",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.showSponsored",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.showSponsoredTopSites",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.useRemoteL10n",
            false.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.providers.cfr",
            r#"{"id":"cfr","enabled":false}"#.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.providers.message-groups",
            r#"{"id":"message-groups","enabled":false}"#.into(),
        ),
        (
            "browser.newtabpage.activity-stream.asrouter.providers.messaging-experiments",
            r#"{"id":"messaging-experiments","enabled":false}"#.into(),
        ),
        // Threat list downloads.
        ("browser.safebrowsing.phishing.enabled", false.into()),
        ("browser.safebrowsing.malware.enabled", false.into()),
        ("browser.safebrowsing.downloads.enabled", false.into()),
        (
            "browser.safebrowsing.downloads.remote.enabled",
            false.into(),
        ),
        ("browser.safebrowsing.provider.google.updateURL", "".into()),
        ("browser.safebrowsing.provider.google4.updateURL", "".into()),
        ("browser.safebrowsing.provider.mozilla.updateURL", "".into()),
        // Update, add-on and recommendation checks.
        ("app.update.auto", false.into()),
        ("extensions.update.enabled", false.into()),
        ("extensions.getAddons.cache.enabled", false.into()),
        ("extensions.systemAddon.update.enabled", false.into()),
        ("extensions.systemAddon.update.url", "".into()),
        ("browser.discovery.enabled", false.into()),
        ("browser.search.update", false.into()),
        ("browser.translations.enable", false.into()),
        (
            "browser.contentblocking.report.monitor.enabled",
            false.into(),
        ),
        // Push keeps a connection open with no page asking for it.
        ("dom.push.enabled", false.into()),
        ("dom.push.connection.enabled", false.into()),
        // Media plugin downloads and their update checks.
        ("media.gmp-manager.updateEnabled", false.into()),
        ("media.gmp-gmpopenh264.enabled", false.into()),
        ("media.gmp-gmpopenh264.autoupdate", false.into()),
        ("media.gmp-widevinecdm.enabled", false.into()),
        ("media.gmp-widevinecdm.autoupdate", false.into()),
        ("media.eme.enabled", false.into()),
        // Region lookup at startup.
        ("browser.region.network.url", "".into()),
        ("browser.region.update.enabled", false.into()),
        // Lookups go to the guest's own resolver, never over HTTPS.
        ("network.trr.mode", 5.into()),
        // Remote settings and studies fetch from these hosts at startup.
        (
            "network.dns.localDomains",
            "firefox.settings.services.mozilla.com,normandy.cdn.mozilla.net".into(),
        ),
    ];
    preferences
        .iter()
        .map(|(name, value)| {
            let locked = serde_json::json!({"Value": value, "Status": "locked"});
            (name.to_string(), locked)
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
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
        // Release Firefox ignores services.settings.server, and the policy
        // cannot turn studies off, so their hosts resolve to the loopback.
        let local = &policy["Preferences"]["network.dns.localDomains"];
        assert_eq!(
            local["Value"],
            "firefox.settings.services.mozilla.com,normandy.cdn.mozilla.net"
        );
        assert_eq!(local["Status"], "locked");
        for (name, value) in [
            ("browser.search.suggest.enabled", serde_json::json!(false)),
            ("network.captive-portal-service.enabled", false.into()),
            ("dom.push.connection.enabled", false.into()),
            ("browser.safebrowsing.provider.google4.updateURL", "".into()),
            ("network.trr.mode", 5.into()),
        ] {
            assert_eq!(policy["Preferences"][name]["Value"], value, "{name}");
            assert_eq!(policy["Preferences"][name]["Status"], "locked", "{name}");
        }
        // The Preferences policy sets only these branches; others need their own policy.
        for name in policy["Preferences"].as_object().unwrap().keys() {
            assert!(
                [
                    "browser.",
                    "network.",
                    "dom.",
                    "media.",
                    "extensions.",
                    "app.update.",
                    "datareporting.policy."
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
                "{name}"
            );
        }
        for name in ["DisableTelemetry", "DisableFirefoxStudies", "DisablePocket"] {
            assert_eq!(policy[name], true, "{name}");
        }
        for name in ["CaptivePortal", "NetworkPrediction", "SearchSuggestEnabled"] {
            assert_eq!(policy[name], false, "{name}");
        }
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
