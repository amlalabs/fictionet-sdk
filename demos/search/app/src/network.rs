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
            exceptions: vec![],
        },
    );
    let models = [Provider::Anthropic]
        .into_iter()
        .map(|provider| {
            Ok((
                provider.host(),
                (
                    Gateway {
                        model: if let Some(credential) = &claude_token {
                            Model::at(
                                cx,
                                provider,
                                credential.clone(),
                                "https://api.anthropic.com".parse()?,
                            )?
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
use web_world::observation::{CallPhase, EgressPurpose, Hit, SearchObs, Tool};

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
                        page: None,
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
        settings: fictionet_extras::models::tools::Domains,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            let result = self.pages.tool_search(&cx, &query, &settings).await;
            let (hits, edits) = match &result {
                Ok(found) => (
                    found
                        .results
                        .iter()
                        .map(|hit| Hit {
                            url: hit.url.clone(),
                            title: hit.title.clone(),
                        })
                        .collect(),
                    found.edits.clone(),
                ),
                Err(_) => (Vec::new(), Vec::new()),
            };
            self.pages.report(
                &cx,
                SearchObs::Tool {
                    call: self.call,
                    tool: Tool::WebSearch,
                    target: query,
                    results: hits,
                    edits,
                    error: result
                        .as_ref()
                        .err()
                        .map(|_| "Search is unavailable".into()),
                    source: self.pages.page_source(),
                },
            );
            result
                .map(|found| found.results)
                .map_err(|_| fictionet::Error::msg("Search is unavailable"))
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
                    edits: Vec::new(),
                    error: result.as_ref().err().map(|_| "Page is unavailable".into()),
                    source: self.pages.page_source(),
                },
            );
            result
        })
    }
    fn serves(&self, host: &str) -> bool {
        fictionet_extras::models::Engine::serves(self.pages.as_ref(), host)
    }
}
