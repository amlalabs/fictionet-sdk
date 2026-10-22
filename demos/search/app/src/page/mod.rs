//! Search owns its map, details, rewind and world controls.

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use fictionet_demo::kit::page::{self as pieces, Console, HostStatus};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};
use web_world::{
    observation::{CallPhase, Hit, Observation, PageSource, SearchObs, Tool},
    pages::{NewPages, Pages},
};

const HISTORY: usize = 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Site {
    pub host: String,
    pub address: Option<std::net::IpAddr>,
    pub at_ms: u64,
    pub requests: Vec<Request>,
    pub searches: Vec<Search>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Request {
    pub at_ms: u64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bytes: usize,
    pub content_type: String,
    pub source: PageSource,
    pub elapsed_ms: u64,
    pub headers: Vec<(String, String)>,
    pub has_preview: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Search {
    pub at_ms: u64,
    pub engine: web_world::observation::Engine,
    pub query: String,
    pub results: Vec<Hit>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Call {
    pub call: u64,
    pub at_ms: u64,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub method: String,
    pub phase: CallPhase,
    pub tools: Vec<ToolUse>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ToolUse {
    pub at_ms: u64,
    pub tool: Tool,
    pub target: String,
    pub results: Vec<Hit>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub at_ms: u64,
    pub oldest_ms: u64,
    pub sites: Vec<Site>,
    pub calls: Vec<Call>,
    pub activity: Vec<Observation>,
}

#[derive(Default)]
pub struct Views {
    observations: VecDeque<Observation>,
    oldest_ms: u64,
}
impl Views {
    pub fn push(&mut self, observation: Observation) {
        if self.observations.len() == HISTORY {
            self.observations.pop_front();
            self.oldest_ms = self.observations.front().map_or(0, |row| row.at_ms);
        }
        self.observations.push_back(observation);
    }
    pub fn at(&self, at_ms: u64) -> View {
        let mut view = View {
            at_ms,
            oldest_ms: self.oldest_ms,
            sites: Vec::new(),
            calls: Vec::new(),
            activity: Vec::new(),
        };
        for observation in self.observations.iter().filter(|row| row.at_ms <= at_ms) {
            match &observation.fact {
                SearchObs::Resolved { name, address } => {
                    if address.is_some() {
                        site(&mut view.sites, name, observation.at_ms).address = *address;
                    }
                }
                SearchObs::Request {
                    host,
                    method,
                    path,
                    status,
                    bytes,
                    content_type,
                    source,
                    elapsed_ms,
                    headers,
                    preview,
                } => {
                    site(&mut view.sites, host, observation.at_ms)
                        .requests
                        .push(Request {
                            at_ms: observation.at_ms,
                            method: method.clone(),
                            path: path.clone(),
                            status: *status,
                            bytes: *bytes,
                            content_type: content_type.clone(),
                            source: source.clone(),
                            elapsed_ms: *elapsed_ms,
                            headers: headers.clone(),
                            has_preview: preview.is_some(),
                        });
                }
                SearchObs::Search {
                    engine,
                    query,
                    results,
                } => {
                    let host = match engine {
                        web_world::observation::Engine::Google => "www.google.com",
                        web_world::observation::Engine::Bing => "www.bing.com",
                        web_world::observation::Engine::DuckDuckGo => "html.duckduckgo.com",
                        web_world::observation::Engine::YouTube => "www.youtube.com",
                        web_world::observation::Engine::WebSearch => "World search",
                    };
                    site(&mut view.sites, host, observation.at_ms)
                        .searches
                        .push(Search {
                            at_ms: observation.at_ms,
                            engine: *engine,
                            query: query.clone(),
                            results: results.clone(),
                        });
                }
                SearchObs::ModelCall {
                    call,
                    host,
                    path,
                    status,
                    method,
                    phase,
                } => {
                    if let Some(row) = view.calls.iter_mut().find(|row| row.call == *call) {
                        row.status = *status;
                        row.phase = *phase;
                    } else {
                        view.calls.push(Call {
                            call: *call,
                            at_ms: observation.at_ms,
                            host: host.clone(),
                            path: path.clone(),
                            status: *status,
                            method: method.clone(),
                            phase: *phase,
                            tools: Vec::new(),
                        });
                    }
                }
                SearchObs::Tool {
                    call,
                    tool,
                    target,
                    results,
                    error,
                } => {
                    if let Some(row) = view.calls.iter_mut().find(|row| row.call == *call) {
                        row.tools.push(ToolUse {
                            at_ms: observation.at_ms,
                            tool: *tool,
                            target: target.clone(),
                            results: results.clone(),
                            error: error.clone(),
                        });
                    }
                }
                SearchObs::NoRoute { .. } => {}
            }
            view.activity.push(observation.clone());
        }
        view
    }
    pub fn preview(&self, host: &str, path: &str, at_ms: u64) -> Option<Arc<str>> {
        self.observations
            .iter()
            .rev()
            .filter(|row| row.at_ms <= at_ms)
            .find_map(|row| match &row.fact {
                SearchObs::Request {
                    host: site,
                    path: target,
                    preview,
                    ..
                } if site == host && target == path => preview.clone(),
                _ => None,
            })
    }
    pub fn current(&self) -> View {
        self.at(self.observations.back().map_or(0, |row| row.at_ms))
    }
}
fn site<'a>(sites: &'a mut Vec<Site>, host: &str, at_ms: u64) -> &'a mut Site {
    let index = sites
        .iter()
        .position(|site| site.host == host)
        .unwrap_or_else(|| {
            sites.push(Site {
                host: host.into(),
                address: None,
                at_ms,
                requests: Vec::new(),
                searches: Vec::new(),
            });
            sites.len() - 1
        });
    sites[index].at_ms = at_ms;
    &mut sites[index]
}

#[derive(Clone, Debug, Serialize)]
pub struct WorldState {
    pub source: PageSource,
    pub copied: bool,
    pub model_written: bool,
    pub live: bool,
    pub date: String,
    pub instructions: String,
    pub preview: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    Source { source: Source },
    Restart,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Copied,
    ModelWritten,
    Live,
}

type Control = (Command, tokio::sync::oneshot::Sender<Result<(), String>>);
type Receivers = (
    mpsc::UnboundedReceiver<Observation>,
    mpsc::UnboundedReceiver<Control>,
);

#[derive(Clone)]
pub struct Page {
    pub views: Arc<Mutex<Views>>,
    pub snapshots: watch::Sender<View>,
    pub console: Arc<Mutex<Option<Arc<dyn Console>>>>,
    pub host: watch::Sender<HostStatus>,
    world: watch::Sender<WorldState>,
    commands: mpsc::UnboundedSender<Control>,
}
impl Page {
    pub fn new(pages: &Pages, preview: bool) -> (Self, Receivers) {
        let views = Views::default();
        let (snapshots, _) = watch::channel(views.current());
        let (observations, receive) = mpsc::unbounded_channel();
        pages.observe(observations);
        let (commands, control) = mpsc::unbounded_channel();
        let world = world_state(pages, preview);
        (
            Self {
                views: Arc::new(Mutex::new(views)),
                snapshots,
                console: Arc::default(),
                host: watch::channel(HostStatus::default()).0,
                world: watch::channel(world).0,
                commands,
            },
            (receive, control),
        )
    }
    pub fn publish(&self, observation: Observation) {
        let mut views = self.views.lock().unwrap();
        views.push(observation);
        self.snapshots.send_replace(views.current());
    }
    pub async fn observe(&self, mut observations: mpsc::UnboundedReceiver<Observation>) {
        while let Some(observation) = observations.recv().await {
            self.publish(observation);
        }
    }
    pub fn run_commands(
        &self,
        cx: &fictionet::Cx,
        pages: Arc<Pages>,
        mut control: mpsc::UnboundedReceiver<(
            Command,
            tokio::sync::oneshot::Sender<Result<(), String>>,
        )>,
    ) {
        let page = self.clone();
        cx.spawn(move |cx| async move {
            while let Ok(Some((command, reply))) = cx.race(None, control.recv()).await {
                let restart = matches!(command, Command::Restart);
                let expected_revision = pages.generation().revision;
                let command = match command {
                    Command::Source { source } => web_world::pages::Command::SetNewPages {
                        new_pages: match source {
                            Source::Copied => NewPages::Copied,
                            Source::ModelWritten => NewPages::ModelWritten,
                            Source::Live => NewPages::LiveSearch,
                        },
                        expected_revision,
                    },
                    Command::Restart => web_world::pages::Command::Restart { expected_revision },
                };
                let result = pages
                    .apply(&cx, command)
                    .map(|_| {
                        if restart {
                            let mut views = page.views.lock().unwrap();
                            *views = Views::default();
                            page.snapshots.send_replace(views.current());
                        }
                        let preview = page.world.borrow().preview;
                        page.world.send_replace(world_state(&pages, preview));
                    })
                    .map_err(|error| match error {
                        web_world::pages::Rejected::Invalid { message } => message,
                        web_world::pages::Rejected::Stale { .. } => {
                            "The source changed; try again".into()
                        }
                    });
                let _ = reply.send(result);
            }
            Ok(())
        });
    }
    pub fn router(&self) -> Router {
        let shared = self.clone();
        let preview = self.clone();
        let console = self.console.clone();
        let screen = console.clone();
        Router::new()
            .route(
                "/favicon.ico",
                get(|| async { http::StatusCode::NO_CONTENT }),
            )
            .route("/", get(|| async { Html(include_str!("index.html")) }))
            .route(
                "/search.mjs",
                get(|| async {
                    (
                        [(http::header::CONTENT_TYPE, "text/javascript")],
                        include_str!("search.mjs"),
                    )
                }),
            )
            .route(
                "/style.css",
                get(|| async {
                    (
                        [(http::header::CONTENT_TYPE, "text/css")],
                        include_str!("style.css"),
                    )
                }),
            )
            .route(
                "/terminal.mjs",
                get(|| async {
                    (
                        [(http::header::CONTENT_TYPE, "text/javascript")],
                        include_str!("terminal.mjs"),
                    )
                }),
            )
            .route(
                "/screen.mjs",
                get(|| async {
                    (
                        [(http::header::CONTENT_TYPE, "text/javascript")],
                        include_str!("screen.mjs"),
                    )
                }),
            )
            .route(
                "/view",
                get(move |Query(query): Query<Rewind>| {
                    let page = shared.clone();
                    async move { Json(page.views.lock().unwrap().at(query.at_ms)) }
                }),
            )
            .route(
                "/preview",
                get(move |Query(query): Query<Preview>| {
                    let page = preview.clone();
                    async move {
                        match page.views.lock().unwrap().preview(
                            &query.host,
                            &query.path,
                            query.at_ms,
                        ) {
                            Some(markup) => (
                                http::StatusCode::OK,
                                [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                                markup.to_string(),
                            )
                                .into_response(),
                            None => (
                                http::StatusCode::NOT_FOUND,
                                "No recorded page at this point in the run",
                            )
                                .into_response(),
                        }
                    }
                }),
            )
            .route(
                "/world",
                get({
                    let world = self.world.clone();
                    move || {
                        let world = world.clone();
                        async move { Json(world.borrow().clone()) }
                    }
                }),
            )
            .route("/command", post(command))
            .route(
                "/terminal",
                get(move |upgrade: axum::extract::ws::WebSocketUpgrade| {
                    let console = console.lock().unwrap().clone();
                    async move { open_console(upgrade, console, false).await }
                }),
            )
            .route(
                "/screen",
                get(move |upgrade: axum::extract::ws::WebSocketUpgrade| {
                    let console = screen.lock().unwrap().clone();
                    async move { open_console(upgrade, console, true).await }
                }),
            )
            .with_state(self.clone())
            .merge(fictionet::stdlib::page::state(self.snapshots.subscribe()))
            .nest(
                "/host",
                fictionet::stdlib::page::state(self.host.subscribe()),
            )
            .merge(pieces::libraries())
    }
}
#[derive(Deserialize)]
struct Preview {
    host: String,
    path: String,
    at_ms: u64,
}
#[derive(Deserialize)]
struct Rewind {
    at_ms: u64,
}
async fn command(
    State(page): State<Page>,
    Json(command): Json<Command>,
) -> axum::response::Response {
    let (reply, receive) = tokio::sync::oneshot::channel();
    if page.commands.send((command, reply)).is_err() {
        return (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "The world has stopped",
        )
            .into_response();
    }
    match receive.await {
        Ok(Ok(())) => http::StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => (http::StatusCode::BAD_REQUEST, error).into_response(),
        Err(_) => (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "The world has stopped",
        )
            .into_response(),
    }
}
async fn open_console(
    upgrade: axum::extract::ws::WebSocketUpgrade,
    console: Option<Arc<dyn Console>>,
    screen: bool,
) -> axum::response::Response {
    let Some(console) = console else {
        return (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "The workstation is booting",
        )
            .into_response();
    };
    pieces::upgrade(upgrade, console, screen).await
}
fn world_state(pages: &Pages, preview: bool) -> WorldState {
    WorldState {
        source: pages.source(),
        copied: pages.has_copied(),
        model_written: matches!(
            pages.generator_kind(),
            web_world::pages::GeneratorKind::Model(_)
        ),
        live: pages.live_available(),
        date: pages.seed().date.clone(),
        instructions: pages.seed().instructions.clone(),
        preview,
    }
}

/// Binds the app to loopback and requires the run token for reads and writes.
pub async fn serve(router: Router, port: u16) -> std::io::Result<Server> {
    let listener = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await
    {
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && port != 0 => {
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?
        }
        result => result?,
    };
    let address = listener.local_addr()?;
    let token = fictionet_demo::kit::random_uuid();
    let expected = token.clone();
    let origin = format!("http://{address}");
    let router = router.layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let token = expected.clone();
            let origin = origin.clone();
            async move {
                let authenticated = request
                    .headers()
                    .get(http::header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|cookies| {
                        cookies
                            .split(';')
                            .any(|cookie| cookie.trim() == format!("search={token}"))
                    });
                let bootstrap = request.uri().path() == "/"
                    && request.uri().query() == Some(format!("token={token}").as_str());
                let same_origin = request
                    .headers()
                    .get(http::header::ORIGIN)
                    .is_none_or(|value| value.as_bytes() == origin.as_bytes());
                if (!authenticated && !bootstrap) || !same_origin {
                    return http::StatusCode::FORBIDDEN.into_response();
                }
                let mut response = next.run(request).await;
                if bootstrap {
                    response.headers_mut().insert(
                        http::header::SET_COOKIE,
                        format!("search={token}; HttpOnly; SameSite=Strict; Path=/")
                            .parse()
                            .unwrap(),
                    );
                }
                response
                    .headers_mut()
                    .insert("referrer-policy", "no-referrer".parse().unwrap());
                response
                    .headers_mut()
                    .insert("x-content-type-options", "nosniff".parse().unwrap());
                response
                    .headers_mut()
                    .insert(http::header::CACHE_CONTROL, "no-store".parse().unwrap());
                response
            }
        },
    ));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    Ok(Server {
        url: format!("http://{address}/?token={token}"),
        stop: Some(stop),
        task,
    })
}
pub struct Server {
    pub url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Server {
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
