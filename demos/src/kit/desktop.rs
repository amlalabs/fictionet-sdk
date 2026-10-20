//! Ubuntu desktops on Xvnc, reached through the admin SSH session: a
//! browser with Xfce and Firefox, or one full-screen terminal that types
//! the commands [`GuestHandle::type_command`] sends.

use std::io;
use std::time::Duration;

use fictionet::stdlib::codec::base64;

use super::{Guest, GuestHandle, ssh};

/// Xvnc's display port on the guest's loopback.
pub const VNC_PORT: u16 = 5901;
/// HTTPS hosts used at boot. Serve these through World::mirror with TLS
/// certificates from the CA passed to World::trust.
pub const HOSTS: &[&str] = &["packages.mozilla.org"];

const MOZILLA_KEY: &str = include_str!("desktop/packages.mozilla.org.asc");

/// Where the typed-command program reads commands and writes results, in
/// the user's home.
const WORK: &str = ".local/work";
/// The typed-command program. It waits on its pipe for a line holding a time
/// limit in seconds and a command. It shows a prompt and types the command
/// out, runs it for at most that limit, and writes back its exit status. Its
/// arguments are a heading it shows first.
const ASSISTANT: &str = r#"#!/bin/bash
work=$HOME/.local/work
[ $# -eq 0 ] || printf '%s\n\n' "$*"
while read -r limit command < "$work/commands"; do
    : > "$work/output"
    printf '\033[01;32m%s@%s\033[00m:\033[01;34m%s\033[00m$ ' "$USER" "$(hostname)" "${PWD/#$HOME/\~}"
    for ((i = 0; i < ${#command}; i++)); do
        printf '%s' "${command:i:1}"
        sleep 0.03
    done
    printf '\n'
    timeout "$limit" bash -c "$command" 2>&1 | tee "$work/output"
    status=${PIPESTATUS[0]}
    printf '\n[exit %s]\n\n' "$status"
    printf '%s\n' "$status" > "$work/results"
done
"#;
/// Prints the title of the first visible Firefox window on the guest's
/// display, or nothing when none shows.
pub(crate) const FIREFOX_TITLE: &str = "env DISPLAY=:1 sh -c 'xdotool search --onlyvisible \
    --class firefox | head -n1 | xargs -r xdotool getwindowname'";

/// Returns the title of the first visible Firefox window on the guest's
/// screen, or an empty string when none shows. It takes at most 10 s.
pub async fn firefox_title(ssh: &ssh::Session) -> io::Result<String> {
    let out = tokio::time::timeout(Duration::from_secs(10), ssh.run(FIREFOX_TITLE))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the Firefox title query hung"))??;
    if out.code != 0 {
        return Err(io::Error::other(format!(
            "the Firefox title query exited {}: {}",
            out.code, out.stderr
        )));
    }
    Ok(out.stdout.trim().to_owned())
}

/// How much longer than a command's limit [`GuestHandle::type_command`]
/// waits, for the typing.
const TYPING: Duration = Duration::from_secs(30);
/// The most of a typed command's output [`GuestHandle::type_command`] reads
/// back: its last 1 MiB.
const OUTPUT_LIMIT: usize = 1 << 20;

impl Guest {
    /// Installs `/opt/assistant`, the program a terminal window runs to
    /// type and run the commands [`GuestHandle::type_command`] sends, and
    /// the pipes it reads them from. [`terminal`] includes it.
    pub fn typed_commands(self) -> Self {
        let (user, work) = (self.user.clone(), WORK);
        self.file("/opt/assistant", 0o755, ASSISTANT).run(format!(
            "sudo -u {user} mkdir -p -m700 /home/{user}/{work} \
             && sudo -u {user} mkfifo -m600 /home/{user}/{work}/commands /home/{user}/{work}/results"
        ))
    }
}

/// What a command typed with [`GuestHandle::type_command`] did.
pub struct Typed {
    /// The command's exit status; 124 when it ran out of time.
    pub code: i32,
    /// Its output and error output together: the last 1 MiB when it printed
    /// more.
    pub output: String,
}

impl GuestHandle {
    /// Types `command` in the terminal window that runs `/opt/assistant`
    /// (see [`Guest::typed_commands`]) and runs it for at most `limit`,
    /// whole seconds and at least one. The command is one line. When the
    /// terminal does not report back, the error carries the output so far.
    pub async fn type_command(&self, command: &str, limit: Duration) -> io::Result<Typed> {
        if command.contains(['\n', '\r', '\0']) {
            return Err(io::Error::other("a typed command must be one line"));
        }
        let wait = limit + TYPING;
        let send = send_typed(command, limit);
        let sent = self.ssh().run_bounded(&send, OUTPUT_LIMIT + 64);
        let error = match tokio::time::timeout(wait, sent).await {
            Err(_) => format!("it did not finish in {wait:?}"),
            Ok(Err(error)) => error.to_string(),
            Ok(Ok(out)) => match out.stdout.split_once('\n') {
                Some((status, output)) if out.code == 0 => match status.trim().parse() {
                    Ok(code) => {
                        return Ok(Typed {
                            code,
                            output: output.to_owned(),
                        });
                    }
                    Err(_) => format!("its status line was {status:?}"),
                },
                _ => format!("exit {}; {}", out.code, out.stderr),
            },
        };
        let read = format!("tail -c {OUTPUT_LIMIT} ~/{WORK}/output");
        let output =
            match tokio::time::timeout(TYPING, self.ssh().run_bounded(&read, OUTPUT_LIMIT)).await {
                Ok(Ok(out)) => out.stdout,
                Ok(Err(error)) => format!("(unreadable: {error})"),
                Err(_) => "(reading it timed out)".into(),
            };
        Err(io::Error::other(format!(
            "{}: the terminal did not run {command:?}: {error}\nits output so far:\n{output}",
            self.name()
        )))
    }
}

/// The shell command that hands `command` and its time limit to
/// `/opt/assistant` and prints its exit status on one line, then the last
/// [`OUTPUT_LIMIT`] bytes of its output.
fn send_typed(command: &str, limit: Duration) -> String {
    let line = format!("{} {command}\n", limit.as_secs().max(1));
    format!(
        "printf %s {} | base64 -d > ~/{WORK}/commands && head -n1 ~/{WORK}/results \
         && tail -c {OUTPUT_LIMIT} ~/{WORK}/output",
        ssh::quote(&base64::encode(line.as_bytes()))
    )
}

/// An Ubuntu guest whose screen is Xvnc on display :1, `width` by `height`
/// pixels, on the guest's loopback with no password: only the admin SSH
/// tunnel reaches it. Once the X server answers, `session` runs as `user`,
/// and `ready` exits zero once the desktop is up. The caller enables
/// `vnc.service` after its own setup.
fn xvnc(
    hostname: &str,
    user: &str,
    (width, height): (u16, u16),
    session: &str,
    ready: &str,
) -> Guest {
    // The guest's clipboard stays in the guest: noVNC watching in view-only
    // mode loses its place in the stream when a clipboard update arrives,
    // and the screen drops.
    let start = format!(
        "#!/bin/bash\n\
         export HOME=/home/{user} DISPLAY=:1 XDG_RUNTIME_DIR=/run/user/$(id -u {user})\n\
         /usr/bin/Xvnc :1 -localhost -SecurityTypes None -AlwaysShared -SendCutText=0 -nolisten tcp \
           -geometry {width}x{height} -depth 24 >/tmp/xvnc.log 2>&1 &\n\
         for _ in $(seq 1 150); do xdpyinfo -display :1 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         xdpyinfo -display :1 >/dev/null 2>&1 || exit 1\n\
         {session}"
    );
    let service = format!(
        "[Unit]\n\
         Description=Desktop session\n\
         After=systemd-user-sessions.service\n\
         [Service]\n\
         User={user}\n\
         PAMName=login\n\
         ExecStart=/opt/start-desktop.sh\n\
         Restart=on-failure\n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    Guest::ubuntu(hostname, user)
        .desktop(VNC_PORT, ready)
        .packages(&[
            "tigervnc-standalone-server",
            "x11-utils",
            "fonts-dejavu-core",
        ])
        .file("/opt/start-desktop.sh", 0o755, start)
        .file("/etc/systemd/system/vnc.service", 0o644, service)
}

/// An Ubuntu guest whose screen is one full-screen terminal at `size`
/// pixels with `font_size` text. It runs `/opt/assistant` in the user's
/// home, headed by `title`, so it types each command
/// [`GuestHandle::type_command`] sends.
pub fn terminal(hostname: &str, user: &str, title: &str, size: (u16, u16), font_size: u8) -> Guest {
    let title = ssh::quote(title);
    let session = format!(
        "openbox &\n\
         cd \"$HOME\"\n\
         exec xterm -fa 'DejaVu Sans Mono' -fs {font_size} -fullscreen -bg '#101820' -fg '#e7edf4' \
           -title {title} -e /opt/assistant {title}\n"
    );
    xvnc(
        hostname,
        user,
        size,
        &session,
        "env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && pgrep -x xterm >/dev/null",
    )
    .packages(&["openbox", "xterm"])
    .typed_commands()
    .run("systemctl daemon-reload && systemctl enable --now vnc.service")
}

/// An Ubuntu guest with Xfce on Xvnc at 1280x800 and Mozilla's Firefox at
/// start_url. Panics if the URL is not neutral HTTP or HTTPS or contains
/// shell quoting or expansion characters. Desktop setup precedes
/// caller-added run steps.
pub fn browser(hostname: &str, user: &str, start_url: &str) -> Guest {
    let rest = start_url
        .strip_prefix("https://")
        .or_else(|| start_url.strip_prefix("http://"));
    assert!(
        rest.is_some_and(|s| !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~:/?#[]@!&()*+,;=%".contains(&c)))
            && super::forbidden_in(start_url, &[]).is_none(),
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
    // The Xfce session, then its window manager, then Firefox, in order.
    // Firefox starts once its profile root exists.
    let session = format!(
        "while IFS= read -r entry; do export \"$entry\"; done < <(dbus-launch)\n\
         startxfce4 >/tmp/xfce.log 2>&1 &\n\
         for _ in $(seq 1 150); do pgrep -x xfwm4 >/dev/null 2>&1 && break; sleep 0.2; done\n\
         sleep 2\n\
         mkdir -p \"$HOME/.mozilla/firefox\"\n\
         firefox --no-remote '{start_url}' >/tmp/firefox.log 2>&1 &\n\
         wait\n"
    );
    xvnc(
        hostname,
        user,
        (1280, 800),
        &session,
        "env DISPLAY=:1 xdpyinfo >/dev/null 2>&1 && pgrep -x xfwm4 >/dev/null",
    )
    .packages(&[
        "xfce4",
        "xfce4-terminal",
        "dbus-x11",
        "xdotool",
        "firefox",
        "p11-kit",
        "p11-kit-modules",
        "libnss3",
        "fonts-liberation",
        "adwaita-icon-theme",
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
    .file("/opt/setup-desktop.sh", 0o755, setup_script(user))
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
    use crate::kit::seed;
    use std::collections::BTreeMap;

    /// The guest's seed as the guest receives it, and the files it writes.
    fn seed(guest: &Guest) -> (String, BTreeMap<String, String>) {
        let data = seed::user_data(&seed::Provision {
            guest,
            authorized_key: "key",
            ca: None,
        });
        let files = seed::files(&data).unwrap();
        (data, files)
    }

    #[test]
    fn browser_seed_has_the_desktop_and_firefox_policy() {
        let url = "https://example.test/start?a=1&b=two#section";
        let guest = browser("workstation", "analyst", url).run("echo caller");
        guest.validate().unwrap();
        let (port, ready) = guest.desktop.as_ref().unwrap();
        assert_eq!(*port, VNC_PORT);
        assert!(ready.contains("DISPLAY=:1 xdpyinfo"));
        assert!(ready.contains("pgrep -x xfwm4"));
        let (data, files) = seed(&guest);
        let content = |path: &str| files[path].clone();
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
        assert!(start.contains(" -SendCutText=0 "));
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
    fn terminal_runs_the_assistant_full_screen_on_the_shared_session() {
        let guest = terminal("workstation", "analyst", "Office inventory", (960, 400), 15);
        guest.validate().unwrap();
        let content = |guest: &Guest, path: &str| seed(guest).1[path].clone();
        let start = content(&guest, "/opt/start-desktop.sh");
        assert!(start.contains("Xvnc :1 -localhost -SecurityTypes None"));
        assert!(start.contains(" -SendCutText=0 "));
        assert!(start.contains("-geometry 960x400 "));
        assert!(start.contains(
            "exec xterm -fa 'DejaVu Sans Mono' -fs 15 -fullscreen -bg '#101820' -fg '#e7edf4' \
             -title 'Office inventory' -e /opt/assistant 'Office inventory'"
        ));
        assert_eq!(content(&guest, "/opt/assistant"), ASSISTANT);
        let browser = browser("workstation", "analyst", "https://example.test/");
        assert_eq!(
            content(&guest, "/etc/systemd/system/vnc.service"),
            content(&browser, "/etc/systemd/system/vnc.service")
        );
        let (_, ready) = guest.desktop.as_ref().unwrap();
        assert!(ready.contains("pgrep -x xterm"));
        let fifos = guest
            .steps
            .iter()
            .position(|s| s.contains("mkfifo"))
            .unwrap();
        let enable = guest
            .steps
            .iter()
            .position(|s| s.contains("enable --now vnc"))
            .unwrap();
        assert!(fifos < enable, "the pipes exist before the terminal starts");
    }

    #[test]
    fn the_assistant_types_runs_and_reports_each_command() {
        let home = crate::kit::util::RunDir::new(&std::env::temp_dir(), "assistant").unwrap();
        let home = home.path();
        let work = home.join(WORK);
        std::fs::create_dir_all(&work).unwrap();
        let mkfifo = std::process::Command::new("mkfifo")
            .arg(work.join("commands"))
            .arg(work.join("results"))
            .status()
            .unwrap();
        assert!(mkfifo.success());
        std::fs::write(home.join("assistant"), ASSISTANT).unwrap();
        /// Stops the program when the test ends, passing or not.
        struct Running(std::process::Child);
        impl Drop for Running {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = std::process::Command::new("bash")
            .arg(home.join("assistant"))
            .arg("Office inventory")
            .env("HOME", home)
            .env("USER", "analyst")
            .current_dir(home)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let assistant = Running(child);
        // The screen is read as the program writes it, so a long output
        // never fills the pipe.
        let screen = std::thread::spawn(move || {
            let mut screen = String::new();
            std::io::Read::read_to_string(&mut stdout, &mut screen).unwrap();
            screen
        });
        let typed = |command: &str, limit: u64| {
            let out = std::process::Command::new("bash")
                .args(["-c", &send_typed(command, Duration::from_secs(limit))])
                .env("HOME", home)
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(typed("echo \"it's here\"; exit 3", 10), "3\nit's here\n");
        assert_eq!(typed("printf 'one\\ntwo\\n'", 10), "0\none\ntwo\n");
        assert_eq!(typed("echo started; sleep 5", 1), "124\nstarted\n");
        let long = typed("head -c 1100000 /dev/zero | tr '\\0' x", 10);
        assert_eq!(long, format!("0\n{}", "x".repeat(OUTPUT_LIMIT)));
        drop(assistant);
        let screen = screen.join().unwrap();
        assert!(screen.starts_with("Office inventory\n\n"), "{screen}");
        assert!(
            screen.contains("echo \"it's here\"; exit 3\nit's here\n\n[exit 3]\n"),
            "{screen}"
        );
        assert!(
            screen.contains("printf 'one\\ntwo\\n'\none\ntwo\n\n[exit 0]\n"),
            "{screen}"
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
