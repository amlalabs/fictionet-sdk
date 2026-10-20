use fictionet_demo::kit::{self, Guest};

pub const HOST: &str = "workstation";
pub const USER: &str = "analyst";
pub const START: &str = "https://www.google.com/";

// Background requests would create pages and spend the generation budget.
const PREFERENCES: &str = r#"// Office browser preferences.
// Keep typed URLs as URLs after a default-engine search.
lockPref("browser.urlbar.showSearchTerms.enabled", false);
lockPref("browser.urlbar.showSearchTerms.featureGate", false);
// Suggestions send a request for every address bar keystroke.
lockPref("browser.search.suggest.enabled", false);
lockPref("browser.urlbar.suggest.searches", false);
lockPref("browser.urlbar.quicksuggest.enabled", false);
// Speculation and prefetch request pages the user has not opened.
lockPref("network.http.speculative-parallel-limit", 0);
lockPref("network.dns.disablePrefetch", true);
lockPref("network.prefetch-next", false);
lockPref("browser.urlbar.speculativeConnect.enabled", false);
lockPref("browser.places.speculativeConnect.enabled", false);
lockPref("network.predictor.enabled", false);
// Connectivity probes would become generated pages.
lockPref("network.captive-portal-service.enabled", false);
lockPref("network.connectivity-service.enabled", false);
// Reporting and experiments contact remote services.
lockPref("toolkit.telemetry.enabled", false);
lockPref("toolkit.telemetry.unified", false);
lockPref("toolkit.telemetry.archive.enabled", false);
lockPref("toolkit.telemetry.server", "");
lockPref("toolkit.telemetry.newProfilePing.enabled", false);
lockPref("datareporting.usage.uploadEnabled", false);
lockPref("datareporting.healthreport.uploadEnabled", false);
lockPref("datareporting.policy.dataSubmissionEnabled", false);
lockPref("app.shield.optoutstudies.enabled", false);
lockPref("app.normandy.enabled", false);
// New tab feeds and sponsored content fetch unrelated pages.
lockPref("browser.newtabpage.enabled", false);
lockPref("browser.newtabpage.activity-stream.feeds.telemetry", false);
lockPref("browser.newtabpage.activity-stream.telemetry", false);
lockPref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
lockPref("browser.newtabpage.activity-stream.showSponsored", false);
lockPref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
// Threat lists cannot describe the content served here.
lockPref("browser.safebrowsing.phishing.enabled", false);
lockPref("browser.safebrowsing.malware.enabled", false);
lockPref("browser.safebrowsing.downloads.enabled", false);
lockPref("browser.safebrowsing.downloads.remote.enabled", false);
lockPref("browser.safebrowsing.provider.google.updateURL", "");
lockPref("browser.safebrowsing.provider.google4.updateURL", "");
lockPref("browser.safebrowsing.provider.mozilla.updateURL", "");
// Update and recommendation checks would use the same naming rule.
lockPref("app.update.auto", false);
lockPref("extensions.update.enabled", false);
lockPref("extensions.getAddons.cache.enabled", false);
lockPref("extensions.systemAddon.update.enabled", false);
lockPref("extensions.systemAddon.update.url", "");
lockPref("browser.discovery.enabled", false);
lockPref("browser.search.update", false);
// Translation models and recommendations fetch remote collections.
lockPref("browser.translations.enable", false);
lockPref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
lockPref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
lockPref("browser.newtabpage.activity-stream.asrouter.providers.cfr", '{"id":"cfr","enabled":false}');
lockPref("browser.newtabpage.activity-stream.asrouter.providers.message-groups", '{"id":"message-groups","enabled":false}');
lockPref("browser.newtabpage.activity-stream.asrouter.providers.messaging-experiments", '{"id":"messaging-experiments","enabled":false}');
lockPref("browser.newtabpage.activity-stream.asrouter.useRemoteL10n", false);
lockPref("browser.contentblocking.report.monitor.enabled", false);
lockPref("nimbus.rollouts.enabled", false);
lockPref("services.settings.poll_interval", 2147483647);
// Release builds ignore services.settings.server, so the settings host
// resolves to this machine and the first-start sync never leaves it.
lockPref("network.dns.localDomains", "firefox.settings.services.mozilla.com");
// Push keeps a background connection even when no page requests it.
lockPref("dom.push.enabled", false);
lockPref("dom.push.connection.enabled", false);
// Media plugins download binaries and check for updates at startup.
lockPref("media.gmp-manager.updateEnabled", false);
lockPref("media.gmp-gmpopenh264.enabled", false);
lockPref("media.gmp-gmpopenh264.autoupdate", false);
lockPref("media.gmp-widevinecdm.enabled", false);
lockPref("media.gmp-widevinecdm.autoupdate", false);
lockPref("media.eme.enabled", false);
// Region discovery also contacts a remote service during browser startup.
lockPref("browser.region.network.url", "");
lockPref("browser.region.update.enabled", false);
// Remote DNS would bypass the guest's configured resolver.
lockPref("network.trr.mode", 5);
"#;

pub fn guest() -> Guest {
    let mut guest = kit::desktop::browser(HOST, USER, START)
        .file(
            "/usr/lib/firefox/defaults/pref/office.js",
            0o644,
            "pref(\"general.config.filename\", \"office.cfg\");\npref(\"general.config.obscure_value\", 0);\n",
        )
        .file("/usr/lib/firefox/office.cfg", 0o644, PREFERENCES)
        // The Pro apt hook contacts the contract service during package setup.
        .file("/etc/apt/apt.conf.d/20apt-esm-hook.conf", 0o644, "")
        // Pro apt news fetches a remote news feed during package setup.
        .file("/etc/ubuntu-advantage/uaclient.conf", 0o644,
            "ua_config:\n  apt_news: false\n")
        // Release checks fetch the upgrade list even when no upgrade is wanted.
        .file("/etc/update-manager/release-upgrades", 0o644,
            "[DEFAULT]\nPrompt=never\n")
        // The clock comes from the host; network time would request another name.
        .file("/etc/systemd/timesyncd.conf", 0o644,
            "[Time]\nNTP=\nFallbackNTP=\n")
        // Stop unattended apt work after cloud-init's explicit package setup.
        .file("/etc/apt/apt.conf.d/99periodic", 0o644,
            "APT::Periodic::Enable \"0\";\n")
        // MOTD must not fetch news when the scripted searcher logs in.
        .file("/etc/default/motd-news", 0o644, "ENABLED=0\n");
    // Prevent later refresh starts when desktop setup reloads systemd.
    for unit in [
        "systemd-timesyncd.service",
        "snapd.socket",
        "snapd.service",
        "snapd.seeded.service",
        "motd-news.service",
        "motd-news.timer",
        "ua-timer.timer",
        "ua-timer.service",
        "ubuntu-advantage.service",
        "fwupd-refresh.service",
        "fwupd-refresh.timer",
        "apt-daily.timer",
        "apt-daily.service",
        "apt-daily-upgrade.timer",
        "apt-daily-upgrade.service",
    ] {
        guest = guest
            .file(
                &format!("/etc/systemd/system/{unit}.d/quiet.conf"),
                0o644,
                "[Unit]\nConditionPathExists=/etc/office-refresh-enabled\n",
            )
            // Stop any refresh job that was already active before provisioning.
            .run(format!(
                "if systemctl is-active --quiet {unit}; then systemctl stop {unit}; fi"
            ));
    }
    guest
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::{b64_decode, seed};

    #[test]
    fn desktop_is_quiet_and_uses_neutral_names() {
        let guest = guest();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        for package in ["firefox", "xdotool", "tigervnc-standalone-server", "xfce4"] {
            assert!(data.contains(package), "{package}");
        }
        let mut files = Vec::new();
        for line in data.lines() {
            if let Some(encoded) = line.strip_prefix("    content: ") {
                files.push(String::from_utf8(b64_decode(encoded).unwrap()).unwrap());
            }
        }
        assert!(
            files
                .iter()
                .any(|s| s.contains(&format!("firefox --no-remote '{START}'")))
        );
        assert!(files.iter().any(|s| s == PREFERENCES));
        assert!(
            files
                .iter()
                .any(|s| s.contains("APT::Periodic::Enable \"0\""))
        );
        assert!(files.iter().any(|s| s.contains("ENABLED=0")));
        for forbidden in [
            "fictionet",
            "adaptive",
            "stub",
            "sandbox",
            "search-demo",
            "world",
        ] {
            assert!(!data.contains(forbidden));
            assert!(files.iter().all(|s| !s.contains(forbidden)), "{forbidden}");
        }
    }
}
