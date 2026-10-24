//! Search owns its map, details and world controls.

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use fictionet_demo::kit::page::{self as pieces, Console, HostStatus};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};
use web_world::{
    observation::{CallPhase, EgressPurpose, Fetch, Hit, Observation, PageSource, SearchObs, Tool},
    pages::{NewPages, Pages},
};

fn wall_start() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("current date")
        .as_millis() as u64
}

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
    pub url: String,
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
    pub fetch: Fetch,
    pub referrer: Option<String>,
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
pub struct Connection {
    pub host: String,
    pub purpose: EgressPurpose,
    pub at_ms: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub started_at_ms: u64,
    pub at_ms: u64,
    pub sites: Vec<Site>,
    pub calls: Vec<Call>,
    pub activity: Vec<Observation>,
    pub connections: Vec<Connection>,
    pub egress: Vec<Observation>,
    pub signin: Option<Observation>,
}

pub struct Views {
    view: View,
    previews: HashMap<String, (web_world::pages::PageBody, PageSource)>,
}
impl Default for Views {
    fn default() -> Self {
        Self {
            view: View {
                started_at_ms: wall_start(),
                at_ms: 0,
                sites: Vec::new(),
                calls: Vec::new(),
                activity: Vec::new(),
                connections: Vec::new(),
                egress: Vec::new(),
                signin: None,
            },
            previews: HashMap::new(),
        }
    }
}
impl Views {
    pub fn push(&mut self, mut observation: Observation) {
        let view = &mut self.view;
        view.at_ms = observation.at_ms;
        if let SearchObs::RunStarted { started_at_ms } = observation.fact {
            view.started_at_ms = started_at_ms;
        }
        match &observation.fact {
            SearchObs::Resolved { name, address } => {
                if address.is_some() {
                    site(&mut view.sites, &name.to_ascii(), observation.at_ms).address = *address;
                }
            }
            SearchObs::Request {
                scheme,
                host,
                method,
                path,
                status,
                bytes,
                content_type,
                source,
                elapsed_ms,
                headers,
                fetch,
                referrer,
                title: _,
                preview,
            } => {
                let url = format!("{scheme}://{host}{path}");
                if let Some(body) = preview {
                    self.previews
                        .insert(url.clone(), (body.clone(), source.clone()));
                } else {
                    self.previews.remove(&url);
                }
                site(&mut view.sites, &host.to_ascii(), observation.at_ms)
                    .requests
                    .push(Request {
                        url,
                        at_ms: observation.at_ms,
                        method: method.to_string(),
                        path: path.to_string(),
                        status: status.as_u16(),
                        bytes: *bytes,
                        content_type: content_type.clone(),
                        source: source.clone(),
                        elapsed_ms: *elapsed_ms,
                        headers: headers
                            .iter()
                            .filter(|(_, value)| value.as_bytes() != b"[redacted]")
                            .map(|(name, value)| {
                                (
                                    name.to_string(),
                                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                )
                            })
                            .collect(),
                        has_preview: preview.is_some(),
                        fetch: *fetch,
                        referrer: referrer.clone(),
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
                    row.status = status.map(|status| status.as_u16());
                    row.phase = *phase;
                } else {
                    view.calls.push(Call {
                        call: *call,
                        at_ms: observation.at_ms,
                        host: host.to_ascii(),
                        path: path.to_string(),
                        status: status.map(|status| status.as_u16()),
                        method: method.to_string(),
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
            SearchObs::Egress {
                host,
                purpose,
                attempt,
                ..
            } => {
                let host = host.to_ascii();
                if !view
                    .connections
                    .iter()
                    .any(|connection| connection.host == host && connection.purpose == *purpose)
                {
                    view.connections.push(Connection {
                        host,
                        purpose: *purpose,
                        at_ms: observation.at_ms,
                    });
                }
                if let Some(previous) = view.egress.iter_mut().find(
                    |row| matches!(row.fact, SearchObs::Egress { attempt: id, .. } if id == *attempt),
                ) {
                    *previous = observation.clone();
                } else {
                    view.egress.push(observation.clone());
                }
            }
            SearchObs::Signin { .. } => view.signin = Some(observation.clone()),
            SearchObs::NoRoute { .. }
            | SearchObs::PageRevision { .. }
            | SearchObs::RunStarted { .. } => {}
        }
        if let SearchObs::Request { preview, .. } = &mut observation.fact {
            *preview = None;
        }
        if let SearchObs::ModelCall { call, .. } = observation.fact
            && let Some(previous) = view
                .activity
                .iter_mut()
                .find(|row| matches!(row.fact, SearchObs::ModelCall { call: id, .. } if id == call))
        {
            previous.fact = observation.fact;
        } else if let SearchObs::Egress { attempt, .. } = observation.fact
            && let Some(previous) = view.activity.iter_mut().find(
                |row| matches!(row.fact, SearchObs::Egress { attempt: id, .. } if id == attempt),
            )
        {
            *previous = observation;
        } else {
            view.activity.push(observation);
        }
    }
    pub fn preview(&self, url: &url::Url) -> Option<(web_world::pages::PageBody, PageSource)> {
        self.previews.get(url.as_str()).cloned()
    }
    pub fn current(&self) -> View {
        self.view.clone()
    }
    fn restart(&mut self) {
        self.view.sites.clear();
        self.view.calls.clear();
        self.view.activity.clear();
        self.view.egress.clear();
        self.previews.clear();
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
    pub copied: Availability,
    pub model_written: Availability,
    pub live: Availability,
    pub date: String,
    pub instructions: String,
    pub preview: bool,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable { reason: UnavailableReason },
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    NoCaptures,
    NoPageWriter,
    NoSearchKey,
}
impl Availability {
    fn new(available: bool, reason: UnavailableReason) -> Self {
        if available {
            Self::Available
        } else {
            Self::Unavailable { reason }
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    SetSource { source: Source },
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
    /// The world, while it runs; the page must not keep it (and its
    /// observation stream) alive.
    pages: std::sync::Weak<Pages>,
}
impl Page {
    pub fn new(pages: Arc<Pages>, preview: bool) -> (Self, Receivers) {
        let views = Views::default();
        let (snapshots, _) = watch::channel(views.current());
        let (observations, receive) = mpsc::unbounded_channel();
        pages.observe(observations);
        let (commands, control) = mpsc::unbounded_channel();
        let world = world_state(&pages, preview);
        (
            Self {
                views: Arc::new(Mutex::new(views)),
                snapshots,
                console: Arc::default(),
                host: watch::channel(HostStatus::default()).0,
                world: watch::channel(world).0,
                commands,
                pages: Arc::downgrade(&pages),
            },
            (receive, control),
        )
    }
    pub fn publish(&self, observation: Observation) {
        let mut views = self.views.lock().unwrap();
        views.push(observation);
        self.snapshots.send_replace(views.current());
    }
    /// Writes a separate, private record for this launch before publishing each fact.
    pub async fn record(
        &self,
        mut observations: mpsc::UnboundedReceiver<Observation>,
        directory: &std::path::Path,
    ) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(directory)?;
        let path = directory.join(format!("run-{}.jsonl", fictionet_demo::kit::random_uuid()));
        let mut file = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?,
        );
        println!("Run record: {}", path.display());
        let mut started_at_ms = self.views.lock().unwrap().view.started_at_ms;
        while let Some(observation) = observations.recv().await {
            if let SearchObs::RunStarted {
                started_at_ms: start,
            } = observation.fact
            {
                started_at_ms = start;
            }
            #[derive(Serialize)]
            struct Entry<'a> {
                timestamp: String,
                #[serde(flatten)]
                observation: &'a Observation,
            }
            let timestamp = time::OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(started_at_ms + observation.at_ms) * 1_000_000,
            )
            .map_err(std::io::Error::other)?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(std::io::Error::other)?;
            serde_json::to_writer(
                &mut file,
                &Entry {
                    timestamp,
                    observation: &observation,
                },
            )?;
            writeln!(file)?;
            file.flush()?;
            self.publish(observation);
        }
        Ok(())
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
                    Command::SetSource { source } => web_world::pages::Command::SetNewPages {
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
                            views.restart();
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
                "/fonts/terminal.woff2",
                get(|| async {
                    (
                        [(http::header::CONTENT_TYPE, "font/woff2")],
                        include_bytes!("fonts/JetBrainsMono-Regular.woff2").as_slice(),
                    )
                }),
            )
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
                "/preview",
                get(move |Query(query): Query<Preview>| {
                    let page = preview.clone();
                    async move {
                        let Ok(url) = url::Url::parse(&format!(
                            "{}://{}{}",
                            query.scheme.as_deref().unwrap_or("https"),
                            query.host,
                            query.path
                        )) else {
                            return http::StatusCode::BAD_REQUEST.into_response();
                        };
                        let body = page.views.lock().unwrap().preview(&url);
                        match body {
                            Some((body, _)) => {
                                match tokio::task::spawn_blocking(move || body.text()).await {
                                    Ok(Ok(markup)) => (
                                        http::StatusCode::OK,
                                        [(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                                        markup.to_string(),
                                    )
                                        .into_response(),
                                    _ => (
                                        http::StatusCode::INTERNAL_SERVER_ERROR,
                                        "Recorded page could not be read",
                                    )
                                        .into_response(),
                                }
                            }
                            None => {
                                (http::StatusCode::NOT_FOUND, "No recorded page").into_response()
                            }
                        }
                    }
                }),
            )
            .route("/thumbnail", get(thumbnail))
            .route("/held", get(held))
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
    scheme: Option<String>,
    host: String,
    path: String,
}
/// A page the world served, by its address.
#[derive(Deserialize)]
struct Served {
    url: url::Url,
}
/// A dependency of a served page, read from the source that served it.
#[derive(Deserialize)]
struct Dependency {
    page: url::Url,
    url: url::Url,
}
/// What a still picture of a served page may load: only what the world holds.
const PICTURE_POLICY: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; base-uri 'none'; form-action 'none'";
fn held_address(page: &url::Url) -> impl Fn(&url::Url) -> String + '_ {
    move |url| {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("page", page.as_str())
            .append_pair("url", url.as_str())
            .finish();
        format!("/held?{query}")
    }
}
/// The page as the world served it, with its own stylesheets and images.
async fn thumbnail(
    State(page): State<Page>,
    Query(Served { url }): Query<Served>,
) -> axum::response::Response {
    let Some((body, _)) = page.views.lock().unwrap().preview(&url) else {
        return (http::StatusCode::NOT_FOUND, "No served page").into_response();
    };
    let picture = tokio::task::spawn_blocking(move || {
        body.text()
            .map(|html| web_world::pages::snapshot::page(&url, &html, &held_address(&url)))
    })
    .await;
    match picture {
        Ok(Ok(html)) => (
            [
                (http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (http::header::CONTENT_SECURITY_POLICY, PICTURE_POLICY),
            ],
            html,
        )
            .into_response(),
        _ => (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "The served page could not be read",
        )
            .into_response(),
    }
}
async fn held(
    State(page): State<Page>,
    Query(Dependency { page: owner, url }): Query<Dependency>,
) -> axum::response::Response {
    let Some((_, source)) = page.views.lock().unwrap().preview(&owner) else {
        return http::StatusCode::NOT_FOUND.into_response();
    };
    let Some(pages) = page.pages.upgrade() else {
        return http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let held = tokio::task::spawn_blocking(move || {
        let mut held = pages.held_resource(&source, url.as_str())?;
        if held.content_type.starts_with("text/css") {
            held.body = web_world::pages::snapshot::stylesheet(
                &url,
                &String::from_utf8_lossy(&held.body),
                &held_address(&owner),
            )
            .into_bytes();
        }
        Some(held)
    })
    .await;
    match held {
        Ok(Some(held)) => (
            [
                (http::header::CONTENT_TYPE, held.content_type),
                (
                    http::header::CONTENT_SECURITY_POLICY,
                    PICTURE_POLICY.to_owned(),
                ),
            ],
            held.body,
        )
            .into_response(),
        _ => http::StatusCode::NOT_FOUND.into_response(),
    }
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
        copied: Availability::new(pages.has_copied(), UnavailableReason::NoCaptures),
        model_written: Availability::new(
            matches!(
                pages.generator_kind(),
                web_world::pages::GeneratorKind::Model(_)
            ),
            UnavailableReason::NoPageWriter,
        ),
        live: Availability::new(pages.live_available(), UnavailableReason::NoSearchKey),
        date: pages.seed().date.clone(),
        instructions: pages.seed().instructions.clone(),
        preview,
    }
}

/// Binds the app to loopback.
pub async fn serve(router: Router, port: u16) -> std::io::Result<Server> {
    let listener = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await
    {
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && port != 0 => {
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?
        }
        result => result?,
    };
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    Ok(Server {
        url: format!("http://{address}/"),
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
