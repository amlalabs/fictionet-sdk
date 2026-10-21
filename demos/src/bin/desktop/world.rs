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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Login {
    Subscription,
    ApiKey,
    OpenRouter,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Logins {
    pub claude: Login,
    pub codex: Login,
}

impl Logins {
    pub fn choose(
        store: Option<&models::oauth::Store>,
        has_key: impl Fn(&str) -> bool,
    ) -> Result<Self> {
        let choose = |login, key| -> Result<Login> {
            let subscribed = store
                .map(|store| store.has_login(login))
                .transpose()?
                .unwrap_or(false);
            Ok(if subscribed {
                Login::Subscription
            } else if has_key(key) {
                Login::ApiKey
            } else if has_key("OPENROUTER_API_KEY") {
                Login::OpenRouter
            } else {
                Login::None
            })
        };
        Ok(Self {
            claude: choose(models::oauth::Login::Claude, "ANTHROPIC_API_KEY")?,
            codex: choose(models::oauth::Login::Codex, "OPENAI_API_KEY")?,
        })
    }

    pub fn load() -> Result<(Self, Option<Arc<models::oauth::Store>>)> {
        let path = std::path::Path::new(".ax/credentials.redb");
        let store = if path.exists() {
            Some(models::oauth::Store::open(path)?)
        } else {
            None
        };
        let logins = Self::choose(store.as_deref(), |key| std::env::var_os(key).is_some())?;
        Ok((logins, store))
    }

    pub fn stop_messages(self) -> [Option<&'static str>; 2] {
        [
            match self.claude {
                // @anthropic-ai/claude-code-linux-x64 2.1.292, package/claude:
                // embedded JavaScript mwe.five_hour, _Dn and Ck format this prefix.
                Login::Subscription => Some("You've hit your session limit"),
                Login::ApiKey | Login::OpenRouter => {
                    Some("You have reached your specified workspace API usage limits")
                }
                Login::None => None,
            },
            match self.codex {
                // github.com/openai/codex, rust-v0.163.0:
                // codex-rs/protocol/src/error.rs, UsageLimitReachedError::fmt.
                Login::Subscription => Some("You’ve hit your usage limit."),
                Login::ApiKey | Login::OpenRouter => {
                    Some("Quota exceeded. Check your plan and billing details.")
                }
                Login::None => None,
            },
        ]
    }

    pub fn provider_hosts(self) -> [&'static str; 2] {
        [
            "api.anthropic.com",
            if self.codex == Login::Subscription {
                "chatgpt.com"
            } else {
                "api.openai.com"
            },
        ]
    }
}

fn chatgpt_model(
    codex: &models::Model,
    subscription: bool,
    catalog: Option<(String, bytes::Bytes)>,
) -> Result<models::Model> {
    if subscription {
        Ok(codex.clone())
    } else {
        codex.codex_catalog("https://chatgpt.com".parse()?, catalog)
    }
}

async fn bundled_catalog(cx: &Cx) -> Result<(String, bytes::Bytes)> {
    use http_body_util::BodyExt;
    use tower_service::Service;
    let version = super::guest::CODEX_VERSION;
    let origin = "https://raw.githubusercontent.com";
    let mut forward = web::forward(cx, origin.parse()?, Arc::new(fictionet_host::Client::new()))?;
    let request = http::Request::get(format!(
        "/openai/codex/rust-v{version}/codex-rs/models-manager/models.json"
    ))
    .header("host", "raw.githubusercontent.com")
    .body(web::Body::empty())?;
    let fetch = async {
        let response = forward.call(request).await?;
        if !response.status().is_success() {
            return Err(fictionet::Error::msg(format!(
                "GitHub returned {}",
                response.status()
            )));
        }
        let body = response.into_body().collect().await?.to_bytes();
        let decoded: serde_json::Value = serde_json::from_slice(&body)?;
        if !decoded["models"].is_array() {
            return Err(fictionet::Error::msg("catalog has no models array"));
        }
        Ok((origin.to_owned(), body))
    };
    fetch.await.map_err(|error: fictionet::Error| {
        fictionet::Error::msg(format!(
            "Could not load Codex {version} bundled model catalog from GitHub: {error}"
        ))
    })
}

pub async fn start(
    fcx: Cx,
    mut world: kit::World,
    site: String,
    commands: CommandPort<Command, bool>,
    logins: Logins,
    store: Option<Arc<models::oauth::Store>>,
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
    let seed = web_world::pages::Seed::builtin("web")?;
    let addresses = Arc::new(web_world::Addresses::new(
        seed.fixed_addresses(),
        None,
    )?);
    let pages = Arc::new(web_world::pages::Pages::new(seed));
    let handler = web_world::handler::Handler::new(&fcx, pages.clone());
    let codex_pages = pages.clone();
    let model_cfg = z.server_config(&fcx, &["api.anthropic.com"], now_sys)?;
    let oauth = if logins.claude == Login::Subscription {
        Some(models::oauth::OAuth::new(
            &fcx,
            models::oauth::Login::Claude,
            store.as_ref().expect("selected subscription store").clone(),
        )?)
    } else {
        None
    };
    let token_cfg = z.server_config(&fcx, &[models::oauth::Login::Claude.host()], now_sys)?;
    let (model, name) = if let Some(oauth) = &oauth {
        let model = models::Model::oauth(&fcx, oauth.clone()).await?;
        world.seed_home_files(oauth.guest_files()?)?;
        (Some(model), "claude-haiku-4-5-20251001")
    } else if logins.claude == Login::ApiKey {
        (Some(models::anthropic(&fcx)?), "claude-haiku-4-5-20251001")
    } else if logins.claude == Login::OpenRouter {
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
        let env = model.guest_env();
        let key = env.first().map(|(_, value)| value.as_str()).unwrap_or("");
        world.seed_home_files(fictionet_demo::kit::desktop::claude_files(
            super::USER,
            key,
            name,
        ))?;
        world.seed_env(env)?;
    }
    // Codex: a ChatGPT login from the store, or an API key, set up in the
    // guest the way `codex login` leaves a laptop.
    let codex_oauth = if logins.codex == Login::Subscription {
        Some(models::oauth::OAuth::new(
            &fcx,
            models::oauth::Login::Codex,
            store.as_ref().expect("selected subscription store").clone(),
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
    } else if logins.codex == Login::ApiKey {
        (Some(models::openai(&fcx)?), "gpt-5.4-mini")
    } else if logins.codex == Login::OpenRouter {
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
    let catalog = if logins.codex == Login::OpenRouter {
        Some(bundled_catalog(&fcx).await?)
    } else {
        None
    };
    let chatgpt = codex
        .as_ref()
        .map(|model| chatgpt_model(model, codex_oauth.is_some(), catalog))
        .transpose()?;
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
            .map(|model| web::Site::handler(model).tls(model_cfg.clone())),
        "api.openai.com" => codex
            .clone()
            .filter(|_| codex_oauth.is_none())
            .map(|model| web::Site::handler(model).tls(codex_api_cfg.clone())),
        "chatgpt.com" => chatgpt
            .clone()
            .map(|model| web::Site::handler(model).tls(chatgpt_cfg.clone())),
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
            if web_world::admit(host).is_err() {
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

    fn login_store() -> (std::path::PathBuf, Arc<models::oauth::Store>) {
        let mut random = [0; 8];
        fictionet::random_bytes(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "desktop-logins-{}.redb",
            u64::from_le_bytes(random)
        ));
        let store = models::oauth::Store::open(&path).unwrap();
        (path, store)
    }

    #[test]
    fn login_choices_and_stop_messages_follow_each_agent() {
        let (path, store) = login_store();
        let keys = |key: &str| matches!(key, "ANTHROPIC_API_KEY" | "OPENAI_API_KEY");
        let api = Logins::choose(Some(&store), keys).unwrap();
        assert_eq!(
            api,
            Logins {
                claude: Login::ApiKey,
                codex: Login::ApiKey
            }
        );
        assert_eq!(
            api.stop_messages(),
            [
                Some("You have reached your specified workspace API usage limits"),
                Some("Quota exceeded. Check your plan and billing details."),
            ]
        );
        for login in [models::oauth::Login::Claude, models::oauth::Login::Codex] {
            store
                .put(
                    login,
                    models::oauth::Tokens::new(
                        models::Secret::new("access", "access".into()).unwrap(),
                        models::Secret::new("refresh", "refresh".into()).unwrap(),
                        u64::MAX,
                    ),
                )
                .unwrap();
            let selected = Logins::choose(Some(&store), keys).unwrap();
            assert_eq!(selected.claude, Login::Subscription);
            assert_eq!(
                selected.stop_messages()[0],
                Some("You've hit your session limit")
            );
            if login == models::oauth::Login::Claude {
                assert_eq!(selected.codex, Login::ApiKey);
                assert_eq!(selected.stop_messages()[1], api.stop_messages()[1]);
            } else {
                assert_eq!(selected.codex, Login::Subscription);
                assert_eq!(
                    selected.stop_messages()[1],
                    Some("You’ve hit your usage limit.")
                );
            }
        }
        assert_eq!(
            Logins::choose(None, |_| false).unwrap().stop_messages(),
            [None, None]
        );
        let router = Logins::choose(None, |key| key == "OPENROUTER_API_KEY").unwrap();
        assert_eq!(
            router,
            Logins {
                claude: Login::OpenRouter,
                codex: Login::OpenRouter
            }
        );
        assert_eq!(router.stop_messages(), api.stop_messages());
        assert_eq!(
            api.provider_hosts(),
            ["api.anthropic.com", "api.openai.com"]
        );
        assert_eq!(
            Logins::choose(Some(&store), keys).unwrap().provider_hosts(),
            ["api.anthropic.com", "chatgpt.com"]
        );
        for logins in [api, router, Logins::choose(Some(&store), keys).unwrap()] {
            for message in logins.stop_messages().into_iter().flatten() {
                assert!(super::super::stopped(1, message, message));
                assert!(!super::super::stopped(0, message, message));
                assert!(!super::super::stopped(124, "connection failed", message));
            }
            for provider in logins.provider_hosts() {
                let event = serde_json::json!({"source":"model", "kind":"refused", "fields":{"provider":provider,"reason":"budget"}});
                assert!(super::super::budget_refusal(&event, provider));
                assert!(!super::super::budget_refusal(&event, "unrelated.example"));
                for (field, value) in [("reason", "credential"), ("reason", "handshake")] {
                    let mut wrong = event.clone();
                    wrong["fields"][field] = value.into();
                    assert!(!super::super::budget_refusal(&wrong, provider));
                }
                let mut call = event;
                call["kind"] = "call".into();
                assert!(!super::super::budget_refusal(&call, provider));
            }
        }
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn api_key_chatgpt_site_serves_the_model_catalog() {
        use http_body_util::BodyExt;
        use web::httpd::{Handler, Reply};
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(4)),
            |cx| async move {
                let credential = models::Credential::api_key(
                    &cx,
                    models::Secret::new("OPENAI_API_KEY", "sk-host-key".into())?,
                );
                let bearer = format!("Bearer {}", credential.placeholder());
                let model = models::Model::at(
                    &cx,
                    models::Provider::OpenAi,
                    credential,
                    "http://127.0.0.1:1".parse()?,
                )?;
                let catalog = bytes::Bytes::from_static(br#"{"models":[]}"#);
                let site = chatgpt_model(
                    &model,
                    false,
                    Some(("https://raw.githubusercontent.com".into(), catalog)),
                )
                .expect("chatgpt.com must resolve for API-key catalog reads");
                let conn = fictionet::events::ConnInfo::default();
                let mut exchange = web::httpd::Exchange::new(cx.now(), &cx, &conn);
                let reply = site.call(
                    http::Request::get("/backend-api/codex/models?client_version=0.163.0")
                        .header("authorization", bearer)
                        .body(web::Body::empty())?,
                    &mut exchange,
                );
                let response = match reply {
                    Reply::Now(response) => response,
                    Reply::Later(work) => work(cx).await?,
                    Reply::Handoff(_) => panic!("catalog read upgraded"),
                };
                assert_eq!(response.status(), 200);
                #[derive(Deserialize)]
                struct Catalog {
                    models: Vec<serde_json::Value>,
                }
                let body = response.into_body().collect().await?.to_bytes();
                let decoded: Catalog = serde_json::from_slice(&body)?;
                assert!(decoded.models.is_empty());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn chatgpt_catalog_audit_preserves_first_party_checks() {
        use example_common::guest_content::Audit;
        use fictionet::stdlib::network::ConnectionExt;
        use fictionet::stdlib::protocols::dns::rr::RecordType;
        use fictionet::stdlib::world::sandbox;
        use std::net::{Ipv4Addr, SocketAddr};
        for path in [
            "/backend-api/codex/responses",
            "/backend-api/wham/usage",
            "/backend-api/codex/models?client_version=0.163.0",
        ] {
            let audit = Arc::new(Audit::default());
            fictionet::block_on(fictionet::run(
                fictionet::RunOptions::new(fictionet::Seed::from_u64(5))
                    .observer(audit.clone()),
                |cx| async move {
                    let credential = models::Credential::api_key(
                        &cx,
                        models::Secret::new("OPENAI_API_KEY", "sk-host-key".into())?,
                    );
                    let bearer = format!("Bearer {}", credential.placeholder());
                    let model = models::Model::at(
                        &cx,
                        models::Provider::OpenAi,
                        credential,
                        "http://127.0.0.1:1".parse()?,
                    )?;
                    let catalog = bytes::Bytes::from_static(
                        br#"{"models":[{"instructions":"test and evaluation"}]}"#,
                    );
                    let site = chatgpt_model(&model, false, Some(("https://raw.githubusercontent.com".into(), catalog.clone())))?;
                    let first_party = web::httpd::Router::new()
                        .post("/backend-api/codex/responses", |_, _| {
                            http::Response::new(bytes::Bytes::from_static(b"test and evaluation"))
                        })
                        .get("/backend-api/wham/usage", |_, _| {
                            http::Response::builder()
                                .extension(Fields::new().with("forwarded", "https://chatgpt.com"))
                                .body(bytes::Bytes::from_static(b"test and evaluation"))
                                .unwrap()
                        });
                    let is_catalog = path.starts_with("/backend-api/codex/models");
                    let (attacher, attachments) = fictionet::attachments();
                    web::Sites::new(move |host: &str| {
                        (host == "chatgpt.com").then(|| {
                            if is_catalog {
                                web::Site::handler(site.clone()).at(SHARED)
                            } else {
                                web::Site::handler(first_party.clone()).at(SHARED)
                            }
                        })
                    })
                    .into_net()
                    .start(&cx, attachments)?;
                    let end = attacher.attach("client")?;
                    let machine = sandbox::machine(&cx, end, Ipv4Addr::new(10, 0, 0, 2));
                    let answer = machine.lookup(
                        &cx, Ipv4Addr::new(10, 0, 0, 1).into(), "chatgpt.com", RecordType::A,
                    ).await?;
                    assert!(!answer.answers.is_empty());
                    let mut conn = machine.tcp
                        .connect(&cx, SocketAddr::new(SHARED.into(), 80))
                        .await?;
                    let method = if path.ends_with("/responses") { "POST" } else { "GET" };
                    conn.write_all(&cx, format!(
                        "{method} {path} HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ).as_bytes()).await?;
                    let mut response = Vec::new();
                    loop {
                        let mut buf = [0; 4096];
                        let n = conn.read(&cx, &mut buf).await?;
                        if n == 0 { break; }
                        response.extend_from_slice(&buf[..n]);
                    }
                    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
                    if is_catalog {
                        assert!(response.ends_with(&catalog), "{response:?}");
                    } else {
                        assert!(response.ends_with(b"test and evaluation"), "{response:?}");
                    }
                    cx.cancel();
                    Ok(())
                },
            )).unwrap();
            let result = audit.check();
            if path.starts_with("/backend-api/codex/models") {
                assert!(result.is_ok(), "{result:?}");
            } else {
                let error = result.unwrap_err();
                assert!(error.contains("guest content contains \"test\""), "{error}");
                assert!(
                    error.contains("guest content contains \"evaluation\""),
                    "{error}"
                );
            }
        }
    }

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
