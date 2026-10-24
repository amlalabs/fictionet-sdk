//! Operational model gateways and local startup responses.

use fictionet::Cx;
use std::sync::Arc;

/// The operational guest network: inspected model calls, with search and fetch
/// answered by the world. Software is supplied by the prepared image.
pub fn build(
    world: &web_world::World,
    cx: &Cx,
    log: Arc<fictionet_extras::log::Log>,
    claude_token: Option<fictionet_extras::models::Credential>,
) -> fictionet::Result<fictionet::stdlib::world::net::Net> {
    use fictionet::stdlib::web::Site;
    world.pages.report(
        cx,
        SearchObs::RunStarted {
            started_at_ms: world
                .start
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64
                - cx.now().since_start().as_millis() as u64,
        },
    );
    use fictionet_extras::models::{Model, Provider};
    world.pages.report(
        cx,
        SearchObs::Signin {
            open: false,
            exceptions: if claude_token.is_some() {
                vec![SigninException::CodexAccount]
            } else {
                vec![
                    SigninException::ClaudeAccount,
                    SigninException::CodexAccount,
                ]
            },
        },
    );
    let models = [Provider::Anthropic, Provider::OpenAi, Provider::ChatGpt]
        .into_iter()
        .map(|provider| {
            Ok((
                provider.host(),
                (
                    Gateway {
                        model: if provider == Provider::Anthropic {
                            if let Some(credential) = &claude_token {
                                Model::at(
                                    cx,
                                    provider,
                                    credential.clone(),
                                    "https://api.anthropic.com".parse()?,
                                )?
                            } else {
                                Model::guest(cx, provider)?
                            }
                        } else {
                            Model::guest(cx, provider)?
                        },
                        pages: world.pages.clone(),
                        host: provider.host().parse()?,
                    },
                    world.ca.config(cx, provider.host())?.0,
                ),
            ))
        })
        .collect::<fictionet::Result<Vec<_>>>()?;
    let world_ca = world.ca.clone();
    let world_cx = cx.clone();
    Ok(world.net(cx, log, move |host| {
        if let Some((_, (model, tls))) = models.iter().find(|(name, _)| *name == host) {
            return Some(
                Site::handler(model.clone())
                    .tls(tls.clone())
                    .into_host(host),
            );
        }
        if host == "platform.claude.com" {
            let tls = world_ca.config(&world_cx, host).ok()?.0;
            return Some(Site::handler(Startup).tls(tls).into_host(host));
        }
        None
    }))
}

use fictionet::stdlib::web::{Body, httpd};
use fictionet_extras::models::CallPhase as ModelPhase;
use web_world::observation::{CallPhase, EgressPurpose, Hit, SearchObs, SigninException, Tool};

#[derive(Clone)]
struct Gateway {
    model: fictionet_extras::models::Model,
    pages: Arc<web_world::pages::Pages>,
    host: web_world::observation::HostName,
}
impl httpd::Handler for Gateway {
    fn call(
        &self,
        request: http::Request<Body>,
        exchange: &mut httpd::Exchange<'_>,
    ) -> httpd::Reply {
        if request.uri().path() == "/api/oauth/cli/create_api_key" {
            return httpd::Reply::Now(
                http::Response::builder()
                    .status(403)
                    .body(Body::empty())
                    .expect("static response"),
            );
        }
        let pages = self.pages.clone();
        let host = self.host.clone();
        let model = self
            .model
            .clone()
            .observe_calls(Arc::new(move |cx, method, path| {
                let call = cx.random_u64();
                let engine = Arc::new(Tools {
                    pages: pages.clone(),
                    call,
                });
                let pages = pages.clone();
                let host = host.clone();
                let cx = cx.clone();
                let method = method.clone();
                let path = path.clone();
                fictionet_extras::models::Call {
                    engine,
                    observe: Arc::new(move |phase, status| {
                        pages.report(
                            &cx,
                            SearchObs::ModelCall {
                                call,
                                host: host.clone(),
                                method: method.clone(),
                                path: path.clone(),
                                status,
                                phase: match phase {
                                    ModelPhase::Connecting => CallPhase::Connecting,
                                    ModelPhase::Receiving => CallPhase::Receiving,
                                    ModelPhase::Streaming => CallPhase::Streaming,
                                    ModelPhase::Complete => CallPhase::Complete,
                                    ModelPhase::Interrupted => CallPhase::Interrupted,
                                },
                            },
                        );
                    }),
                }
            }));
        let pages = self.pages.clone();
        let host = self.host.clone();
        model
            .observe_upstream(Arc::new(move |cx, event| {
                pages.report(
                    cx,
                    SearchObs::Egress {
                        attempt: event.attempt,
                        host: host.clone().into(),
                        method: event.method.to_string(),
                        path: event.path.path().into(),
                        purpose: if event.path.path().contains("oauth")
                            || event.method == http::Method::GET
                        {
                            EgressPurpose::Account
                        } else {
                            EgressPurpose::Model
                        },
                        phase: event.phase,
                        status: event.status.map(|s| s.as_u16()),
                    },
                );
            }))
            .call(request, exchange)
    }
}

#[derive(Clone)]
struct Startup;
impl httpd::Handler for Startup {
    fn call(&self, request: http::Request<Body>, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let status = if matches!(*request.method(), http::Method::GET | http::Method::HEAD)
            && request.uri().path() == "/v1/oauth/hello"
            && request.uri().query().is_none()
        {
            200
        } else {
            403
        };
        httpd::Reply::Now(
            http::Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("static response"),
        )
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
        fictionet_extras::models::Engine::serves(self.pages.as_ref(), host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_extras::models::UpstreamPhase;
    use http_body_util::BodyExt;
    use httpd::Handler;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            let gateway = Gateway {
                model: fictionet_extras::models::Model::guest_at(
                    &cx,
                    fictionet_extras::models::Provider::Anthropic,
                    origin,
                )?,
                pages,
                host: "api.anthropic.com".parse().unwrap(),
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
            assert_eq!(
                view.activity
                    .iter()
                    .filter(|row| matches!(
                        row.fact,
                        SearchObs::Egress {
                            phase: UpstreamPhase::Attempt,
                            ..
                        }
                    ))
                    .count(),
                3
            );
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
    #[test]
    fn domain_checks_delegate_to_the_copied_corpus() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(8),
            |cx| async move {
                let pages = Arc::new(
                    web_world::pages::Pages::copied(
                        web_world::pages::Seed::builtin("web")?,
                        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../../../extras/tests/fixtures"),
                        &["https://sky.org/".into()],
                        None,
                    )
                    .map_err(fictionet::Error::msg)?,
                );
                let gateway = Gateway {
                    model: fictionet_extras::models::Model::guest(
                        &cx,
                        fictionet_extras::models::Provider::Anthropic,
                    )?,
                    pages,
                    host: "api.anthropic.com".parse()?,
                };
                for (host, allowed) in [("sky.org", true), ("uncaptured.org", false)] {
                    let request = http::Request::get(format!("/api/web/domain_info?domain={host}"))
                        .body(Body::empty())?;
                    let httpd::Reply::Later(work) = gateway.call(
                        request,
                        &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
                    ) else {
                        panic!("gateway work")
                    };
                    let response = work(cx.clone()).await?;
                    let body = response.into_body().collect().await?.to_bytes();
                    let body: Value = serde_json::from_slice(&body)?;
                    assert_eq!(body["can_fetch"], allowed);
                }
                let request =
                    http::Request::post("/api/oauth/cli/create_api_key").body(Body::empty())?;
                let httpd::Reply::Now(response) = gateway.call(
                    request,
                    &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
                ) else {
                    panic!("setup denied locally")
                };
                assert_eq!(response.status(), 403);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn account_setup_is_not_exposed_to_the_agent_network() {
        use httpd::Handler;
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(3),
            |cx| async move {
                for (method, path, expected) in [
                    (http::Method::GET, "/v1/oauth/hello", 200),
                    (http::Method::HEAD, "/v1/oauth/hello", 200),
                    (http::Method::GET, "/v1/oauth/hello?code=private-value", 403),
                    (
                        http::Method::GET,
                        "/oauth/authorize?code=private-value",
                        403,
                    ),
                    (http::Method::POST, "/v1/oauth/token", 403),
                    (http::Method::GET, "/unrelated", 403),
                ] {
                    let request = http::Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())?;
                    let httpd::Reply::Now(response) = Startup.call(
                        request,
                        &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
                    ) else {
                        panic!("local response")
                    };
                    assert_eq!(response.status(), expected);
                }
                Ok(())
            },
        ))
        .unwrap();
    }
}
