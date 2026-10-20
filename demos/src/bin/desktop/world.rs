//! The desktop sites and Firefox request observer.
use example_common::web_world::{SHARED, app};
use example_common::zscaler::{DEFAULT_CLOUD, zscaler};
use fictionet::events::{Event, Observation, Observer, Stamp};
use fictionet::stdlib::web;
use fictionet::{Cx, Result};
use fictionet_demo::kit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Watches the world's `http.request` events for Firefox's GET of the site.
/// The coding agents' checks fetch the site too, so the request must carry
/// Firefox's User-Agent.
pub struct SiteLoaded {
    pub host: String,
    pub loaded: Arc<AtomicBool>,
}

impl Observer for SiteLoaded {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(metadata, _connection) = interest else {
            return false;
        };
        metadata.source == "http" && metadata.kind == "request"
    }

    fn observe(&self, _stamp: Stamp, observation: Observation<'_>) {
        if let Observation::Event(event) = observation
            && event.str("host") == Some(self.host.as_str())
            && event.str("method") == Some("GET")
            && event.str("path") == Some("/")
            && event.get("status").and_then(|v| v.as_u64()) == Some(200)
            && event.get("complete").and_then(|v| v.as_bool()) == Some(true)
            && user_agent(event).is_some_and(|agent| agent.contains("Firefox/"))
        {
            self.loaded.store(true, Ordering::SeqCst);
        }
    }
}

/// The `User-Agent` of an `http.request` event, from its header pairs.
fn user_agent(event: &Event) -> Option<&str> {
    event.get("headers")?.as_array()?.iter().find_map(|pair| {
        let [name, value] = pair.as_array()? else {
            return None;
        };
        (name.as_str()? == "user-agent")
            .then(|| value.as_str())
            .flatten()
    })
}

pub async fn start(fcx: Cx, mut world: kit::World, site: String) -> Result {
    let now_unix = world.now_unix();
    let now_sys = SystemTime::UNIX_EPOCH + Duration::from_secs(now_unix as u64);
    let z = zscaler(&fcx, DEFAULT_CLOUD, now_unix)?;
    let www = format!("www.{site}");
    let site_cfg = z.server_config(&fcx, &[site.as_str(), www.as_str()], now_sys)?;
    // The Zscaler leaves the world presents for the HTTPS download hosts:
    // Mozilla's apt repository, and the release servers the guest
    // installs Claude Code and Codex from.
    let mozilla_cfg = z.server_config(&fcx, &["packages.mozilla.org"], now_sys)?;
    let claude_cfg = z.server_config(&fcx, &["downloads.claude.ai"], now_sys)?;
    let openai_cfg = z.server_config(&fcx, &["releases.openai.com"], now_sys)?;
    world.trust("zscaler", z.root_pem())?;
    // The mirror: the world forwards these names to the real servers over
    // the host's network, so the guest installs the desktop and the
    // coding agents at boot. apt's signatures verify the packages, and
    // the guest checks each agent download against its pinned sha256.
    let mirror = world.mirror(&fcx)?;
    web::Sites::new(move |host: &str| match host {
        h if h == site || h == www => Some(web::Site::new(app()).at(SHARED).tls(site_cfg.clone())),
        "archive.ubuntu.com" | "security.ubuntu.com" | "ports.ubuntu.com" => {
            Some(web::Site::new(mirror.clone()))
        }
        "packages.mozilla.org" => Some(web::Site::new(mirror.clone()).tls(mozilla_cfg.clone())),
        "downloads.claude.ai" => Some(web::Site::new(mirror.clone()).tls(claude_cfg.clone())),
        "releases.openai.com" => Some(web::Site::new(mirror.clone()).tls(openai_cfg.clone())),
        _ => None,
    })
    .date(now_sys)
    .into_net()
    .route(kit::JUMP, kit::jump_prefix())
    .start(&fcx, world.into_attachments())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::events::{Fields, Stream};

    #[test]
    fn only_a_complete_firefox_page_read_marks_the_site_loaded() {
        let loaded = Arc::new(AtomicBool::new(false));
        let observer = SiteLoaded {
            host: "example.test".into(),
            loaded: loaded.clone(),
        };
        for (method, path, status, complete, agent, passes) in [
            ("GET", "/", 200, true, "Firefox/140", true),
            ("POST", "/", 200, true, "Firefox/140", false),
            ("GET", "/favicon.ico", 200, true, "Firefox/140", false),
            ("GET", "/", 404, true, "Firefox/140", false),
            ("GET", "/", 200, false, "Firefox/140", false),
            ("GET", "/", 200, true, "curl", false),
        ] {
            loaded.store(false, Ordering::SeqCst);
            let event = Event::new("http", "request").fields(
                Fields::new()
                    .with("host", "example.test")
                    .with("method", method)
                    .with("path", path)
                    .with("status", status)
                    .with("complete", complete)
                    .with(
                        "headers",
                        vec![fictionet::stdlib::protocols::json::Value::Array(vec![
                            "user-agent".into(),
                            agent.into(),
                        ])],
                    ),
            );
            observer.observe(
                Stamp {
                    stream: Stream::Events,
                    seq: 1,
                    at: fictionet::time::Instant::ZERO,
                },
                Observation::Event(&event),
            );
            assert_eq!(loaded.load(Ordering::SeqCst), passes);
        }
    }
}
