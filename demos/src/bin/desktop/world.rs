//! The desktop sites and Firefox request observer.
use example_common::web_world::SHARED;
use example_common::zscaler::{DEFAULT_CLOUD, zscaler};
use fictionet::events::{Event, Observation, Observer, Stamp};
use fictionet::stdlib::web;
use fictionet::{Cx, Result};
use fictionet_demo::kit;
use fictionet_extras::models;
use fictionet_observe::page::{CommandPort, Rejected};
use serde::Deserialize;
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Pause,
    Resume,
    Calls(u64),
    Budget(models::Budget),
}

pub async fn start(
    fcx: Cx,
    mut world: kit::World,
    site: String,
    commands: CommandPort<Command, bool>,
) -> Result {
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
    let seed = adaptive_web_world::pages::Seed::builtin("halvard-cve")?;
    let addresses = Arc::new(adaptive_web_world::Addresses::new(
        seed.fixed_addresses(),
        None,
    )?);
    let pages = Arc::new(adaptive_web_world::pages::Pages::new(seed));
    let handler = adaptive_web_world::handler::Handler::new(&fcx, pages.clone());
    let codex_pages = pages.clone();
    let model_cfg = z.server_config(&fcx, &["api.anthropic.com"], now_sys)?;
    let store = std::path::Path::new(".ax/credentials.redb");
    let store = if store.exists() {
        Some(models::oauth::Store::open(store)?)
    } else {
        None
    };
    let oauth = if let Some(store) = store.as_ref()
        && store.has_login(models::oauth::Login::Claude)?
    {
        Some(models::oauth::OAuth::new(
            &fcx,
            models::oauth::Login::Claude,
            store.clone(),
        )?)
    } else {
        None
    };
    let token_cfg = z.server_config(&fcx, &[models::oauth::Login::Claude.host()], now_sys)?;
    let (model, name) = if let Some(oauth) = &oauth {
        let model = models::Model::oauth(&fcx, oauth.clone()).await?;
        world.seed_home_files(oauth.guest_files()?)?;
        (Some(model), "claude-haiku-4-5-20251001")
    } else if std::env::var_os("ANTHROPIC_API_KEY").is_some() {
        (Some(models::anthropic(&fcx)?), "claude-haiku-4-5-20251001")
    } else if std::env::var_os("OPENROUTER_API_KEY").is_some() {
        (
            Some(models::anthropic_via_openrouter(&fcx)?),
            "anthropic/claude-haiku-4.5",
        )
    } else {
        (None, "claude-haiku-4-5-20251001")
    };
    let model = model.map(|model| {
        model
            .search(pages)
            .prices(name, models::Prices::haiku_4_5())
            .budget(models::Budget::new().calls(12))
    });
    if let Some(model) = &model {
        world.seed_env(model.guest_env())?;
        world.seed_home_files([(
            ".claude/settings.json",
            serde_json::json!({"model":name}).to_string(),
        )])?;
    }
    // Codex: a ChatGPT login from the store, or an API key, set up in the
    // guest the way `codex login` leaves a laptop.
    let codex_oauth = if let Some(store) = store.as_ref()
        && store.has_login(models::oauth::Login::Codex)?
    {
        Some(models::oauth::OAuth::new(
            &fcx,
            models::oauth::Login::Codex,
            store.clone(),
        )?)
    } else {
        None
    };
    let codex_api_cfg = z.server_config(&fcx, &["api.openai.com"], now_sys)?;
    let chatgpt_cfg = z.server_config(&fcx, &["chatgpt.com"], now_sys)?;
    let codex_token_cfg = z.server_config(&fcx, &[models::oauth::Login::Codex.host()], now_sys)?;
    let (codex, codex_name) = if let Some(oauth) = &codex_oauth {
        let model = models::Model::oauth(&fcx, oauth.clone()).await?;
        world.seed_home_files(oauth.guest_files()?)?;
        (Some(model), "gpt-5.4")
    } else if std::env::var_os("OPENAI_API_KEY").is_some() {
        (Some(models::openai(&fcx)?), "gpt-5.4-mini")
    } else if std::env::var_os("OPENROUTER_API_KEY").is_some() {
        (
            Some(models::openai_via_openrouter(&fcx)?),
            "openai/gpt-5.4-mini",
        )
    } else {
        (None, "gpt-5.4-mini")
    };
    let codex = codex.map(|model| {
        model
            .search(codex_pages)
            .budget(models::Budget::new().calls(8))
    });
    if let Some(codex) = &codex {
        let env = codex.guest_env();
        if let Some((_, key)) = env.first() {
            let login = serde_json::json!({"auth_mode": "apikey", "OPENAI_API_KEY": key});
            world.seed_home_files([(".codex/auth.json", serde_json::to_string_pretty(&login)?)])?;
        }
        world.seed_env(env)?;
        world.seed_home_files([(
            ".codex/config.toml",
            format!(
                "model = {codex_name:?}\nmodel_reasoning_effort = \"low\"\n\
                 web_search = \"live\"\ncli_auth_credentials_store = \"file\"\n"
            ),
        )])?;
    }
    let controlled: Vec<_> = model.clone().into_iter().chain(codex.clone()).collect();
    fcx.spawn(move |cx| async move {
        kit::serve_commands(&cx, &commands, |command| {
            if controlled.is_empty() {
                return Ok(Err(Rejected::Invalid {
                    message: "No model credential is configured".into(),
                }));
            }
            for model in &controlled {
                match command {
                    Command::Pause => model.pause(true),
                    Command::Resume => model.pause(false),
                    Command::Budget(budget) => model.set_budget(*budget),
                    Command::Calls(limit) => model.set_budget(models::Budget::new().calls(*limit)),
                }
            }
            Ok(Ok(true))
        })
        .await
    });
    // The mirror: the world forwards these names to the real servers over
    // the host's network, so the guest installs the desktop and the
    // coding agents at boot. apt's signatures verify the packages, and
    // the guest checks each agent download against its pinned sha256.
    let mirror = world.mirror(&fcx)?;
    let operations = fictionet::stdlib::web::httpd::Router::new().get("/", |_, _| {
        http::Response::new(bytes::Bytes::from_static(
            b"Northwind Operations\nService desk: available\nPackage repository: online\nMaintenance: Sunday 02:00 UTC\n",
        ))
    });
    let world_cx = fcx.clone();
    web::Sites::new(move |host: &str| match host {
        h if h == site || h == www => Some(
            web::Site::handler(operations.clone())
                .at(SHARED)
                .tls(site_cfg.clone()),
        ),
        "archive.ubuntu.com" | "security.ubuntu.com" | "ports.ubuntu.com" => {
            Some(web::Site::new(mirror.clone()))
        }
        "api.anthropic.com" => model
            .clone()
            .map(|model| web::Site::new(model).tls(model_cfg.clone())),
        "api.openai.com" if codex_oauth.is_none() => codex
            .clone()
            .map(|model| web::Site::new(model).tls(codex_api_cfg.clone())),
        "chatgpt.com" if codex_oauth.is_some() => codex
            .clone()
            .map(|model| web::Site::new(model).tls(chatgpt_cfg.clone())),
        "auth.openai.com" => codex_oauth
            .clone()
            .map(|oauth| web::Site::new(oauth).tls(codex_token_cfg.clone())),
        "platform.claude.com" => oauth
            .clone()
            .map(|oauth| web::Site::new(oauth).tls(token_cfg.clone())),
        "packages.mozilla.org" => Some(web::Site::new(mirror.clone()).tls(mozilla_cfg.clone())),
        "downloads.claude.ai" => Some(web::Site::new(mirror.clone()).tls(claude_cfg.clone())),
        "releases.openai.com" => Some(web::Site::new(mirror.clone()).tls(openai_cfg.clone())),
        _ => {
            if adaptive_web_world::admit(host).is_err() {
                return None;
            }
            let (address, _) = addresses.assign(host).ok()??;
            let tls = z.server_config(&world_cx, &[host], now_sys).ok()?;
            Some(web::Site::new(handler.clone()).at(address).tls(tls))
        }
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
            host: "intranet.northwind.internal".into(),
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
                    .with("host", "intranet.northwind.internal")
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
