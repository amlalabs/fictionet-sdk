//! Join model gateways, provider sign-in and the package mirror to the web.

use fictionet::Cx;
use http_body::Body as _;
use std::sync::Arc;

/// The names the world forwards to the real internet, and why: the guest's
/// packages and coding agents, installed at boot.
pub const FORWARDED: &[(&str, &str)] = &[
    ("archive.ubuntu.com", "Ubuntu packages installed at boot"),
    (
        "security.ubuntu.com",
        "Ubuntu security packages installed at boot",
    ),
    ("packages.mozilla.org", "Firefox installed at boot"),
    (
        fictionet_demo::kit::desktop::CLAUDE_HOST,
        "Claude Code installed at boot",
    ),
    ("releases.openai.com", "Codex installed at boot"),
];

/// The world's network for the guest run and the preview: the web,
/// with package downloads mirrored, sign-in relayed over raw TLS, and model
/// search and fetch answered by the world using the guest’s own credentials.
pub fn build(
    world: &web_world::World,
    cx: &Cx,
    log: Arc<fictionet_extras::log::Log>,
    mirror: fictionet_demo::kit::mirror::Cache<fictionet::stdlib::web::Proxy>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    use fictionet::stdlib::web::Site;
    let mozilla = world
        .ca
        .config(cx, fictionet_demo::kit::desktop::HOSTS[0])?
        .0;
    let claude = world
        .ca
        .config(cx, fictionet_demo::kit::desktop::CLAUDE_HOST)?
        .0;
    let openai = world.ca.config(cx, "releases.openai.com")?.0;
    use fictionet_extras::models::{Model, Provider};
    let models = [Provider::Anthropic, Provider::OpenAi, Provider::ChatGpt]
        .into_iter()
        .map(|provider| {
            Ok((
                provider.host(),
                (
                    Gateway {
                        model: Model::guest(cx, provider)?,
                        pages: world.pages.clone(),
                        host: provider.host().into(),
                    },
                    world.ca.config(cx, provider.host())?.0,
                ),
            ))
        })
        .collect::<fictionet::Result<Vec<_>>>()?;
    Ok(world.net(cx, log, move |host| {
        if let Some((_, (model, tls))) = models.iter().find(|(name, _)| *name == host) {
            return Some(
                Site::handler(model.clone())
                    .tls(tls.clone())
                    .into_host(host),
            );
        }
        if fictionet_extras::models::signin::HOSTS.contains(&host) {
            return Some(
                fictionet::stdlib::world::net::Host::new(host)
                    .dns_name(host)
                    .port_server(
                        443,
                        fictionet_extras::models::signin::Relay(format!("{host}:443")),
                    ),
            );
        }
        FORWARDED.iter().any(|(name, _)| *name == host).then(|| {
            let site = Site::new(mirror.clone());
            if fictionet_demo::kit::desktop::HOSTS.contains(&host) {
                site.tls(mozilla.clone())
            } else if host == fictionet_demo::kit::desktop::CLAUDE_HOST {
                site.tls(claude.clone())
            } else if host == "releases.openai.com" {
                site.tls(openai.clone())
            } else {
                site
            }
            .into_host(host)
        })
    }))
}

/// Starts Search's network with its own DNS and refusal reader on guest links.
pub fn start(
    cx: &Cx,
    net: fictionet::stdlib::world::net::Net,
    mut attachments: fictionet::Attachments,
    pages: Arc<web_world::pages::Pages>,
) -> fictionet::Result {
    use fictionet::{Interface, InterfaceExt};
    let (attacher, observed) = fictionet::attachments();
    cx.spawn(move |cx| async move {
        while let Ok(attachment) = attachments.next(&cx).await {
            let name = attachment.name().to_owned();
            let mut destination = attacher.attach(&name)?;
            let pages = pages.clone();
            cx.spawn(move |cx| async move {
                let mut link = web_world::observation::Link { inner: attachment, cx:cx.clone(), pages };
                loop {
                    tokio::select! {
                        packet = link.recv(&cx) => match packet { Ok(packet) => destination.send(packet), Err(_) => break },
                        packet = destination.recv(&cx) => match packet { Ok(packet) => link.send(packet), Err(_) => break },
                    }
                }
                Ok(())
            });
        }
        Ok(())
    });
    net.start(cx, observed)
}

use fictionet::stdlib::web::{Body, httpd};
use web_world::observation::{CallPhase, Hit, SearchObs, Tool};

#[derive(Clone)]
struct Gateway {
    model: fictionet_extras::models::Model,
    pages: Arc<web_world::pages::Pages>,
    host: String,
}
impl httpd::Handler for Gateway {
    fn call(
        &self,
        request: http::Request<Body>,
        exchange: &mut httpd::Exchange<'_>,
    ) -> httpd::Reply {
        let call = exchange.random_u64();
        let path = request.uri().path().to_owned();
        let method = request.method().to_string();
        let pages = self.pages.clone();
        let host = self.host.clone();
        let model = self.model.clone().search(Arc::new(Tools {
            pages: pages.clone(),
            call,
        }));
        let reply = model.call(request, exchange);
        httpd::Reply::Later(Box::new(move |cx| {
            Box::pin(async move {
                pages.report(
                    &cx,
                    SearchObs::ModelCall {
                        call,
                        host: host.clone(),
                        path: path.clone(),
                        status: None,
                        method: method.clone(),
                        phase: CallPhase::Connecting,
                    },
                );
                let response = match reply {
                    httpd::Reply::Now(response) => Ok(response),
                    httpd::Reply::Later(work) => work(cx.clone()).await,
                };
                match response {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let streaming = response
                            .headers()
                            .get(http::header::CONTENT_TYPE)
                            .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
                        pages.report(
                            &cx,
                            SearchObs::ModelCall {
                                call,
                                host: host.clone(),
                                path: path.clone(),
                                status: Some(status),
                                method: method.clone(),
                                phase: if streaming {
                                    CallPhase::Streaming
                                } else {
                                    CallPhase::Receiving
                                },
                            },
                        );
                        Ok(response.map(|inner| {
                            Body::new(CallBody {
                                inner,
                                cx,
                                pages,
                                call,
                                host,
                                path,
                                status,
                                method,
                                done: false,
                            })
                        }))
                    }
                    Err(error) => {
                        pages.report(
                            &cx,
                            SearchObs::ModelCall {
                                call,
                                host,
                                path,
                                status: Some(502),
                                method,
                                phase: CallPhase::Complete,
                            },
                        );
                        Err(error)
                    }
                }
            })
        }))
    }
}

struct Tools {
    pages: Arc<web_world::pages::Pages>,
    call: u64,
}
impl fictionet_extras::models::Engine for Tools {
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
        source: &'static str,
        settings: serde_json::Value,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            let result = self
                .pages
                .clone()
                .search(cx.clone(), query.clone(), source, settings)
                .await;
            let hits = result
                .as_ref()
                .map(|hits| {
                    hits.iter()
                        .map(|hit| Hit {
                            url: hit.url.clone(),
                            title: hit.title.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.pages.report(
                &cx,
                SearchObs::Tool {
                    call: self.call,
                    tool: Tool::WebSearch,
                    target: query,
                    results: hits,
                    error: result
                        .as_ref()
                        .err()
                        .map(|_| "Search is unavailable".into()),
                },
            );
            result
        })
    }
    fn fetch(
        self: Arc<Self>,
        cx: Cx,
        url: String,
    ) -> fictionet_extras::models::tools::Answer<fictionet_extras::models::tools::Page> {
        Box::pin(async move {
            let result = self.pages.clone().fetch(cx.clone(), url.clone()).await;
            self.pages.report(
                &cx,
                SearchObs::Tool {
                    call: self.call,
                    tool: Tool::Fetch,
                    target: url,
                    results: Vec::new(),
                    error: result.as_ref().err().map(|_| "Page is unavailable".into()),
                },
            );
            result
        })
    }
    fn serves(&self, host: &str) -> bool {
        web_world::admit(host).is_ok()
    }
}

struct CallBody {
    inner: Body,
    cx: Cx,
    pages: Arc<web_world::pages::Pages>,
    call: u64,
    host: String,
    path: String,
    status: u16,
    method: String,
    done: bool,
}
impl http_body::Body for CallBody {
    type Data = bytes::Bytes;
    type Error = fictionet::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, fictionet::Error>>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_frame(task);
        match &result {
            std::task::Poll::Ready(None) => self.finish(CallPhase::Complete),
            std::task::Poll::Ready(Some(Err(_))) => self.finish(CallPhase::Interrupted),
            _ => {}
        }
        result
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
impl CallBody {
    fn finish(&mut self, phase: CallPhase) {
        if !self.done {
            self.done = true;
            self.pages.report(
                &self.cx,
                SearchObs::ModelCall {
                    call: self.call,
                    host: self.host.clone(),
                    path: self.path.clone(),
                    status: Some(self.status),
                    method: self.method.clone(),
                    phase,
                },
            );
        }
    }
}
impl Drop for CallBody {
    fn drop(&mut self) {
        self.finish(if self.inner.is_end_stream() {
            CallPhase::Complete
        } else {
            CallPhase::Interrupted
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use httpd::Handler;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn dropping_an_unread_model_body_reports_interruption() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| async move {
                let pages = Arc::new(web_world::pages::Pages::new(
                    web_world::pages::Seed::builtin("web")?,
                ));
                let (sender, mut observations) = tokio::sync::mpsc::unbounded_channel();
                pages.observe(sender);
                drop(CallBody {
                    inner: Body::from("unread"),
                    cx: cx.clone(),
                    pages,
                    call: 1,
                    host: "api.anthropic.com".into(),
                    path: "/v1/messages".into(),
                    method: "POST".into(),
                    status: 200,
                    done: false,
                });
                let observation = observations.try_recv().unwrap();
                assert!(matches!(
                    observation.fact,
                    SearchObs::ModelCall {
                        phase: CallPhase::Interrupted,
                        ..
                    }
                ));
                assert!(observations.try_recv().is_err());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gateway_calls_keep_their_tool_results_and_finish_without_recording_credentials() {
        let turns = Arc::new(AtomicUsize::new(0));
        let turn = turns.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let upstream=axum::Router::new().route("/v1/messages",axum::routing::post(move |axum::Json(body):axum::Json<Value>| {
            let turn=turn.clone();
            async move {
                let turn=turn.fetch_add(1,Ordering::SeqCst);
                let content=match turn {
                    0=>json!([{"type":"tool_use","id":"search","name":"web_search","input":{"query":"black hole"}}]),
                    1=>{assert!(body["messages"].to_string().contains("https://sky.org/black-hole"));json!([{"type":"tool_use","id":"fetch","name":"web_fetch","input":{"url":"https://sky.org/black-hole"}}])},
                    _=>{assert!(body["messages"].to_string().contains("bends spacetime"));json!([{"type":"text","text":"Black holes bend spacetime."}])},
                };
                axum::Json(json!({"id":"message","type":"message","role":"assistant","model":"claude-mythos","content":content,"stop_reason":if turn<2 {"tool_use"} else {"end_turn"},"stop_sequence":null,"usage":{"input_tokens":30,"output_tokens":20}}))
            }
        }));
        let upstream = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let pages = Arc::new(
            web_world::pages::Pages::copied(
                web_world::pages::Seed::builtin("web").unwrap(),
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../extras/tests/fixtures"),
                &["https://sky.org/".into()],
                None,
            )
            .unwrap(),
        );
        let (page, (mut observations, _)) = crate::page::Page::new(&pages, false);
        fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
            move |cx| async move {
                let gateway = Gateway {
                    model: fictionet_extras::models::Model::guest_at(
                        &cx,
                        fictionet_extras::models::Provider::Anthropic,
                        origin,
                    )?,
                    pages,
                    host: "api.anthropic.com".into(),
                };
                let request = http::Request::post("/v1/messages")
                    .header("x-api-key", "local-only")
                    .header("anthropic-version", "2023-06-01")
                    .header("anthropic-beta", "web-fetch-2025-09-10")
                    .body(Body::from(include_str!(
                        "../../world/tests/anthropic-search.json"
                    )))?;
                let reply = gateway.call(
                    request,
                    &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
                );
                let httpd::Reply::Later(work) = reply else {
                    panic!("gateway work is deferred")
                };
                let response = work(cx.clone()).await?;
                assert_eq!(response.status(), 200);
                let bytes = response.into_body().collect().await?.to_bytes();
                let body: Value = serde_json::from_slice(&bytes)?;
                assert_eq!(body["stop_reason"], "end_turn");
                while let Ok(row) = observations.try_recv() {
                    page.publish(row);
                }
                let view = page.snapshots.borrow();
                assert_eq!(view.calls.len(), 1);
                let call = &view.calls[0];
                assert_eq!(call.status, Some(200));
                assert_eq!(call.phase, CallPhase::Complete);
                assert_eq!(call.tools.len(), 2);
                assert_eq!(call.tools[0].target, "black hole");
                assert_eq!(call.tools[0].results[0].url, "https://sky.org/black-hole");
                assert!(matches!(call.tools[1].tool, Tool::Fetch));
                assert!(!serde_json::to_string(&*view)?.contains("local-only"));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(turns.load(Ordering::SeqCst), 3);
        upstream.abort();
    }
}
