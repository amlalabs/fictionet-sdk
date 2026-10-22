//! The desktop sites and Firefox request observer.
use fictionet::stdlib::web;
use fictionet::{Cx, Result};
use fictionet_demo::kit;
use fictionet_extras::models;
use fictionet_extras::web_world::SHARED;
use fictionet_extras::zscaler::{DEFAULT_CLOUD, zscaler};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
    let seed = web_world::pages::Seed::builtin("web")?;
    let addresses = Arc::new(web_world::Addresses::new(seed.fixed_addresses(), None)?);
    let pages = Arc::new(web_world::pages::Pages::new(seed));
    let handler = web_world::handler::Handler::new(&fcx, pages.clone());
    let model = models::Model::guest(&fcx, models::Provider::Anthropic)?.search(pages.clone());
    let codex = models::Model::guest(&fcx, models::Provider::OpenAi)?.search(pages);
    let chatgpt = codex.codex_catalog("https://chatgpt.com".parse()?, None)?;
    let model_cfg = z.server_config(&fcx, &["api.anthropic.com"], now_sys)?;
    let codex_api_cfg = z.server_config(&fcx, &["api.openai.com"], now_sys)?;
    let chatgpt_cfg = z.server_config(&fcx, &["chatgpt.com"], now_sys)?;
    // The mirror: the world forwards these names to the real servers over
    // the host's network, so the guest installs the desktop and the
    // coding agents at boot. apt's signatures verify the packages, and
    // the guest checks each agent download against its pinned sha256.
    let mirror = world.mirror(&fcx)?;
    let operations_cx = fcx.clone();
    let operations = fictionet::stdlib::web::httpd::Router::new().get("/", move |exchange, request| {
        operations_cx.emitter(exchange.conn()).emit("adaptive", "request", |event| {
            event.field("path", request.uri().path())
        });
        http::Response::new(bytes::Bytes::from_static(
            b"Northwind Operations\nService desk: available\nPackage repository: online\nMaintenance: Sunday 02:00 UTC\n",
        ))
    });
    let world_cx = fcx.clone();
    let mut net = web::Sites::new(move |host: &str| match host {
        h if h == site || h == www => Some(
            web::Site::handler(operations.clone())
                .at(SHARED)
                .tls(site_cfg.clone()),
        ),
        "archive.ubuntu.com" | "security.ubuntu.com" | "ports.ubuntu.com" => {
            Some(web::Site::new(mirror.clone()))
        }
        "api.anthropic.com" => Some(web::Site::handler(model.clone()).tls(model_cfg.clone())),
        "api.openai.com" => Some(web::Site::handler(codex.clone()).tls(codex_api_cfg.clone())),
        "chatgpt.com" => Some(web::Site::handler(chatgpt.clone()).tls(chatgpt_cfg.clone())),
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
    .route(kit::JUMP, kit::jump_prefix());
    for host in fictionet_extras::models::signin::HOSTS {
        net = net.host(host, |node| {
            node.dns_name(host).port_server(
                443,
                fictionet_extras::models::signin::Relay(format!("{host}:443")),
            )
        });
    }
    net.start(&fcx, world.into_attachments())
}
