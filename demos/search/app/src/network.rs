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
/// with package downloads mirrored, sign-in inspected during setup, and model
/// search and fetch answered by the world using the guest’s own credentials.
pub fn build(
    world: &web_world::World,
    cx: &Cx,
    log: Arc<fictionet_extras::log::Log>,
    mirror: fictionet_demo::kit::mirror::Mirror<fictionet::stdlib::web::Proxy>,
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
    use fictionet_extras::models::{Model, Provider, signin};
    let signin = signin::Session::default();
    report_signin(&world.pages, cx, true);
    let signins = signin::HOSTS
        .iter()
        .map(|host| {
            Ok((
                *host,
                (
                    SignIn {
                        session: signin.clone(),
                        pages: world.pages.clone(),
                        host: host.parse()?,
                        forward: fictionet::stdlib::web::forward(
                            cx,
                            format!("https://{host}").parse()?,
                            Arc::new(fictionet_host::Client::new()),
                        )?,
                    },
                    world.ca.config(cx, host)?.0,
                ),
            ))
        })
        .collect::<fictionet::Result<Vec<_>>>()?;
    let models = [Provider::Anthropic, Provider::OpenAi, Provider::ChatGpt]
        .into_iter()
        .map(|provider| {
            Ok((
                provider.host(),
                (
                    Gateway {
                        model: Model::guest(cx, provider)?,
                        pages: world.pages.clone(),
                        host: provider.host().parse()?,
                        signin: signin.clone(),
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
        if let Some((_, (signin, tls))) = signins.iter().find(|(name, _)| *name == host) {
            return Some(
                Site::handler(signin.clone())
                    .tls(tls.clone())
                    .into_host(host),
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

use fictionet::stdlib::web::{Body, httpd};
use web_world::observation::{CallPhase, Hit, SearchObs, Tool};

#[derive(Clone)]
struct Gateway {
    model: fictionet_extras::models::Model,
    pages: Arc<web_world::pages::Pages>,
    host: web_world::observation::HostName,
    signin: fictionet_extras::models::signin::Session,
}
impl httpd::Handler for Gateway {
    fn call(
        &self,
        request: http::Request<Body>,
        exchange: &mut httpd::Exchange<'_>,
    ) -> httpd::Reply {
        if self.signin.closed() && request.uri().path() == "/api/oauth/cli/create_api_key" {
            return httpd::Reply::Now(
                http::Response::builder()
                    .status(403)
                    .body(Body::empty())
                    .unwrap(),
            );
        }
        let call = exchange.random_u64();
        let path = request
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
        let method = request.method().clone();
        let pages = self.pages.clone();
        let host = self.host.clone();
        let model = self.model.clone().search(Arc::new(Tools {
            pages: pages.clone(),
            call,
        }));
        let egress_pages = pages.clone();
        let egress_host = host.clone();
        let signin = self.signin.clone();
        let model = model.observe_upstream(Arc::new(move |cx, method, path, status| {
            egress_pages.report(
                cx,
                SearchObs::Egress {
                    host: egress_host.clone(),
                    method: method.to_string(),
                    path: path.path().into(),
                    purpose: if path.path().contains("oauth") {
                        "account"
                    } else {
                        "model"
                    }
                    .into(),
                    phase: if status.is_some() {
                        "response"
                    } else {
                        "attempt"
                    }
                    .into(),
                    status: status.map(|s| s.as_u16()),
                },
            );
            if method == http::Method::POST
                && matches!(
                    path.path(),
                    "/v1/messages"
                        | "/v1/responses"
                        | "/v1/chat/completions"
                        | "/backend-api/codex/responses"
                )
                && status.is_some_and(|s| s.is_success())
                && signin.close()
            {
                report_signin(&egress_pages, cx, false);
            }
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
                        let status = response.status();
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
                                status: Some(http::StatusCode::BAD_GATEWAY),
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
    host: web_world::observation::HostName,
    path: http::uri::PathAndQuery,
    status: http::StatusCode,
    method: http::Method,
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
            fictionet::Seed::from_u64(1),
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
                    host: "api.anthropic.com".parse().unwrap(),
                    path: http::uri::PathAndQuery::from_static("/v1/messages"),
                    method: http::Method::POST,
                    status: http::StatusCode::OK,
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
        fictionet::run(fictionet::Seed::from_u64(7), move |cx| async move {
            let signin = fictionet_extras::models::signin::Session::default();
            let gateway = Gateway {
                model: fictionet_extras::models::Model::guest_at(
                    &cx,
                    fictionet_extras::models::Provider::Anthropic,
                    origin,
                )?,
                pages,
                host: "api.anthropic.com".parse().unwrap(),
                signin: signin.clone(),
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
            assert!(signin.closed());
            while let Ok(row) = observations.try_recv() {
                page.publish(row);
            }
            let view = page.snapshots.borrow();
            assert_eq!(view.calls.len(), 1);
            assert_eq!(view.activity.iter().filter(|row| matches!(row.fact, SearchObs::Egress { ref phase, .. } if phase == "attempt")).count(), 3);
            assert_eq!(view.activity.iter().filter(|row| matches!(row.fact, SearchObs::Signin { open: false, .. })).count(), 1);
            let call = &view.calls[0];
            assert_eq!(call.status, Some(200));
            assert_eq!(call.phase, CallPhase::Complete);
            assert_eq!(call.tools.len(), 2);
            assert_eq!(call.tools[0].target, "black hole");
            assert_eq!(call.tools[0].results[0].url, "https://sky.org/black-hole");
            assert!(matches!(call.tools[1].tool, Tool::Fetch));
            assert!(!serde_json::to_string(&*view)?.contains("local-only"));
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(turns.load(Ordering::SeqCst), 3);
        upstream.abort();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_in_requests_close_on_existing_handlers_and_refresh_remains_observed() {
        let count = Arc::new(AtomicUsize::new(0));
        let received = count.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let upstream = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let received = received.clone();
            async move {
                let n = received.fetch_add(1, Ordering::SeqCst);
                if n == 1 {
                    assert_eq!(request.uri().path(), "/v1/oauth/token");
                    let body = axum::body::to_bytes(request.into_body(), 65536)
                        .await
                        .unwrap();
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["grant_type"], "refresh_token");
                    assert_eq!(body["refresh_token"], "private-refresh");
                }
                http::StatusCode::OK
            }
        });
        let upstream = tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        fictionet::run(fictionet::Seed::from_u64(3), |cx| async move {
            let pages = Arc::new(web_world::pages::Pages::new(web_world::pages::Seed::builtin("web")?));
            let (sender, mut observations) = tokio::sync::mpsc::unbounded_channel();
            pages.observe(sender);
            let session = fictionet_extras::models::signin::Session::default();
            let handler = SignIn { session: session.clone(), pages, host: "platform.claude.com".parse()?, forward: fictionet::stdlib::web::forward(&cx, origin, Arc::new(fictionet_host::Client::new()))? };
            let send = |request| {
                let reply = handler.call(request, &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()));
                let httpd::Reply::Later(work) = reply else { panic!("deferred sign-in") };
                work(cx.clone())
            };
            assert_eq!(send(http::Request::get("/oauth/authorize?code=private-code").body(Body::empty())?).await?.status(), 200);
            session.close();
            assert_eq!(send(http::Request::get("/v1/oauth/hello").body(Body::empty())?).await?.status(), 200);
            assert_eq!(send(http::Request::get("/oauth/authorize").body(Body::empty())?).await?.status(), 403);
            assert_eq!(send(http::Request::post("/v1/oauth/token").body(Body::from(r#"{"grant_type":"authorization_code"}"#))?).await?.status(), 403);
            let refresh = "grant_type=authorization_code&grant_type=refresh_token&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e&refresh_token=private-refresh";
            assert_eq!(send(http::Request::post("/v1/oauth/token").header("content-type", "application/x-www-form-urlencoded").body(Body::from(refresh))?).await?.status(), 200);
            let mut facts = Vec::new();
            while let Ok(row) = observations.try_recv() { facts.push(row); }
            assert_eq!(facts.iter().filter(|r| matches!(r.fact, SearchObs::Egress { ref phase, .. } if phase == "attempt")).count(), 2);
            assert_eq!(facts.iter().filter(|r| matches!(r.fact, SearchObs::Egress { ref phase, .. } if phase == "denied")).count(), 2);
            let recorded = serde_json::to_string(&facts)?;
            assert!(!recorded.contains("private-code"));
            assert!(!recorded.contains("private-refresh"));
            Ok(())
        }).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        upstream.abort();
    }
}

fn report_signin(pages: &web_world::pages::Pages, cx: &Cx, open: bool) {
    pages.report(cx, SearchObs::Signin { open, exceptions: if open {
        fictionet_extras::models::signin::HOSTS.iter().map(|host| format!("https://{host}:443 during sign-in")).collect()
    } else {
        vec!["POST platform.claude.com/v1/oauth/token with a refresh grant".into(), "POST auth.openai.com/oauth/token with a refresh grant".into(),
             "GET api.anthropic.com/api/oauth/profile and /api/oauth/roles".into(), "GET api.anthropic.com/api/claude_code/policy_limits".into(),
             "GET chatgpt.com/backend-api/codex/models, /backend-api/wham/accounts/check and /backend-api/wham/usage".into()]
    }});
}

#[derive(Clone)]
struct SignIn {
    session: fictionet_extras::models::signin::Session,
    pages: Arc<web_world::pages::Pages>,
    host: web_world::observation::HostName,
    forward: fictionet::stdlib::web::Forward,
}
impl httpd::Handler for SignIn {
    fn call(&self, request: http::Request<Body>, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        use http_body_util::BodyExt;
        let this = self.clone();
        httpd::Reply::Later(Box::new(move |cx| {
            Box::pin(async move {
                if this.session.closed()
                    && this.host.to_ascii().trim_end_matches('.') == "platform.claude.com"
                    && matches!(*request.method(), http::Method::GET | http::Method::HEAD)
                    && request.uri().path() == "/v1/oauth/hello"
                {
                    this.pages.report(
                        &cx,
                        SearchObs::Egress {
                            host: this.host,
                            method: request.method().to_string(),
                            path: request.uri().path().into(),
                            purpose: "startup".into(),
                            phase: "local".into(),
                            status: Some(200),
                        },
                    );
                    return Ok(http::Response::new(Body::empty()));
                }
                let (parts, body) = request.into_parts();
                let body = match http_body_util::Limited::new(body, 64 * 1024)
                    .collect()
                    .await
                {
                    Ok(body) => body.to_bytes(),
                    Err(_) => {
                        return Ok(http::Response::builder().status(413).body(Body::empty())?);
                    }
                };
                let host = this.host.to_ascii();
                let parsed = if parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|v| {
                        v.as_bytes()
                            .starts_with(b"application/x-www-form-urlencoded")
                    }) {
                    serde_json::Value::Object(
                        url::form_urlencoded::parse(&body)
                            .map(|(k, v)| {
                                (k.into_owned(), serde_json::Value::String(v.into_owned()))
                            })
                            .collect(),
                    )
                } else {
                    serde_json::from_slice(&body).unwrap_or_default()
                };
                let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
                let access = this.session.authorize(
                    host.trim_end_matches('.'),
                    &parts.method,
                    path,
                    &parsed,
                );
                let Some(access) = access else {
                    this.pages.report(
                        &cx,
                        SearchObs::Egress {
                            host: this.host,
                            method: parts.method.to_string(),
                            path: "/[sign-in path omitted]".into(),
                            purpose: "sign-in".into(),
                            phase: "denied".into(),
                            status: Some(403),
                        },
                    );
                    return Ok(http::Response::builder().status(403).body(Body::empty())?);
                };
                let path = if access == fictionet_extras::models::signin::Access::Refresh {
                    parts.uri.path()
                } else {
                    "/[sign-in path omitted]"
                };
                let report = |phase: &str, status| {
                    this.pages.report(
                        &cx,
                        SearchObs::Egress {
                            host: this.host.clone(),
                            method: parts.method.to_string(),
                            path: path.into(),
                            purpose: if access == fictionet_extras::models::signin::Access::Refresh
                            {
                                "token refresh"
                            } else {
                                "sign-in"
                            }
                            .into(),
                            phase: phase.into(),
                            status,
                        },
                    )
                };
                report("attempt", None);
                // Query strings, bodies and headers can contain credentials and are never recorded.
                let mut forward = this.forward.clone();
                let refresh = access == fictionet_extras::models::signin::Access::Refresh;
                let body = if refresh {
                    bytes::Bytes::from(parsed.to_string())
                } else {
                    body
                };
                let mut request = http::Request::from_parts(parts.clone(), Body::from(body));
                if refresh {
                    request.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/json"),
                    );
                    request.headers_mut().remove(http::header::CONTENT_LENGTH);
                }
                request
                    .headers_mut()
                    .insert(http::header::HOST, host.trim_end_matches('.').parse()?);
                let result = tower_service::Service::call(&mut forward, request).await;
                report(
                    if result.is_ok() { "response" } else { "failed" },
                    result.as_ref().ok().map(|r| r.status().as_u16()),
                );
                result
            })
        }))
    }
}
