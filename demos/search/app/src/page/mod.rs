//! Search owns its map, details and world controls.

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
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
    pages::{Edit, Pages, Scenario, Source},
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
    pub edits: Vec<Edit>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Search {
    pub at_ms: u64,
    pub engine: web_world::observation::Engine,
    pub query: String,
    pub results: Vec<Hit>,
    pub edits: Vec<Edit>,
    pub source: PageSource,
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
    pub edits: Vec<Edit>,
    pub error: Option<String>,
    pub source: PageSource,
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
    /// How many addresses Live-Depth allows, once it allows any.
    pub allowed: Option<u64>,
}

pub struct Views {
    view: View,
    previews: HashMap<String, (web_world::pages::PageBody, PageSource)>,
    boot: Boot,
}

/// The workstation's own start-up: its browser opening its start page.
/// The run record keeps it; the page shows what happens after it.
#[derive(Default)]
struct Boot {
    /// When the workstation became ready, in wall-clock milliseconds.
    ended_at_ms: Option<u64>,
    /// Addresses the start-up loaded; their own requests are start-up too.
    pages: std::collections::HashSet<String>,
}
impl Boot {
    /// Whether this fact belongs to start-up; remembers the pages it loaded.
    fn claims(&mut self, wall_ms: u64, fact: &SearchObs) -> bool {
        let booting = self.ended_at_ms.is_none_or(|ended| wall_ms < ended);
        match fact {
            SearchObs::RunStarted { .. } | SearchObs::Signin { .. } => false,
            SearchObs::Request {
                scheme,
                host,
                path,
                fetch,
                referrer,
                ..
            } => {
                let url = format!("{scheme}://{host}{path}");
                let owned = *fetch == Fetch::Subresource
                    && referrer
                        .as_ref()
                        .is_some_and(|page| self.pages.contains(page));
                if booting || owned {
                    self.pages.insert(url);
                    true
                } else {
                    // A later visit to the start page is the agent's own.
                    self.pages.remove(&url);
                    false
                }
            }
            SearchObs::Egress { page, .. } => {
                booting || page.as_ref().is_some_and(|page| self.pages.contains(page))
            }
            _ => booting,
        }
    }
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
                allowed: None,
            },
            previews: HashMap::new(),
            boot: Boot::default(),
        }
    }
}
impl Views {
    /// Adds `observation` to what the page shows; `false` when the page
    /// shows nothing new.
    pub fn push(&mut self, mut observation: Observation) -> bool {
        // Each session is a new run: the page shows only its own.
        if let SearchObs::RunStarted { started_at_ms } = observation.fact {
            *self = Self::default();
            self.view.started_at_ms = started_at_ms;
        }
        let view = &mut self.view;
        view.at_ms = observation.at_ms;
        if self
            .boot
            .claims(view.started_at_ms + observation.at_ms, &observation.fact)
        {
            return false;
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
                error: _,
                unlisted: _,
                depth: _,
                edits,
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
                            .0
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
                        edits: edits.clone(),
                    });
            }
            SearchObs::Search {
                engine,
                query,
                results,
                edits,
                source,
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
                        edits: edits.clone(),
                        source: source.clone(),
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
                edits,
                error,
                source,
            } => {
                if let Some(row) = view.calls.iter_mut().find(|row| row.call == *call) {
                    row.tools.push(ToolUse {
                        at_ms: observation.at_ms,
                        tool: *tool,
                        target: target.clone(),
                        results: results.clone(),
                        edits: edits.clone(),
                        error: error.clone(),
                        source: source.clone(),
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
            SearchObs::Allowlist { links } => {
                view.allowed = Some(*links);
                return true;
            }
            SearchObs::Signin { .. } => view.signin = Some(observation.clone()),
            SearchObs::NoRoute { .. }
            | SearchObs::Certificate { .. }
            | SearchObs::Abandoned { .. }
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
        true
    }
    /// The workstation is ready: what happens from now on is shown.
    pub fn end_boot(&mut self) {
        self.boot.ended_at_ms.get_or_insert_with(wall_start);
    }
    pub fn preview(&self, url: &url::Url) -> Option<(web_world::pages::PageBody, PageSource)> {
        self.previews.get(url.as_str()).cloned()
    }
    pub fn current(&self) -> View {
        self.view.clone()
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
    /// The mode of the session running or starting.
    pub source: Source,
    pub session: Session,
    pub copied: Availability,
    pub live: Availability,
    pub live_depth: Availability,
    pub edited: Availability,
    pub date: String,
    /// What Edited changes on real pages.
    pub scenario: Option<Scenario>,
    pub preview: bool,
}
/// Where the session is: each mode chosen starts a new one, with a
/// workstation booted afresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Session {
    /// The workstation is booting for the session.
    Starting,
    /// The workstation's terminal and screen are the session's.
    Running,
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
    NoSearchKey,
    NoModelKey,
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
    /// Start a new session in this mode.
    SetSource {
        source: Source,
    },
    SetScenario {
        scenario: String,
    },
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
    /// The running session's world, for copies the page asks for and
    /// scenarios it sets.
    cx: Arc<Mutex<Option<fictionet::Cx>>>,
    /// Shows the session's workstation status on the page.
    following: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}
impl Page {
    /// The world's settings as the page shows them, as they change.
    pub fn world(&self) -> watch::Receiver<WorldState> {
        self.world.subscribe()
    }

    pub fn new(pages: Arc<Pages>, preview: bool) -> (Self, Receivers) {
        let views = Views::default();
        let (snapshots, _) = watch::channel(views.current());
        let (observations, receive) = mpsc::unbounded_channel();
        pages.observe(observations);
        let (commands, control) = mpsc::unbounded_channel();
        let world = world_state(&pages, preview, pages.source(), Session::Starting);
        (
            Self {
                views: Arc::new(Mutex::new(views)),
                snapshots,
                console: Arc::default(),
                host: watch::channel(HostStatus::default()).0,
                world: watch::channel(world).0,
                commands,
                pages: Arc::downgrade(&pages),
                cx: Arc::default(),
                following: Arc::default(),
            },
            (receive, control),
        )
    }
    /// Ends the workstation's start-up on the page.
    pub fn end_boot(&self) {
        let mut views = self.views.lock().unwrap();
        views.end_boot();
        self.snapshots.send_replace(views.current());
    }
    pub fn publish(&self, observation: Observation) {
        let mut views = self.views.lock().unwrap();
        if views.push(observation) {
            self.snapshots.send_replace(views.current());
        }
    }
    /// Shows the world's settings again, for the session in `source`.
    fn refresh(&self, pages: &Pages, source: Source, session: Session) {
        let preview = self.world.borrow().preview;
        self.world
            .send_replace(world_state(pages, preview, source, session));
    }
    /// A session in `source` is starting: the previous workstation's
    /// console and status leave the page.
    pub fn begin_session(&self, pages: &Pages, source: Source) {
        if let Some(following) = self.following.lock().unwrap().take() {
            following.abort();
        }
        self.console.lock().unwrap().take();
        self.cx.lock().unwrap().take();
        self.host.send_modify(|status| {
            status.state = fictionet_demo::kit::page::HostState::Booting;
            status.addresses.clear();
            status.screen = false;
            status.terminal = false;
        });
        self.refresh(pages, source, Session::Starting);
    }
    /// The session's world runs in `cx`: the scenario's readiness reaches
    /// the page as it changes.
    pub fn attach_world(&self, cx: &fictionet::Cx, pages: Arc<Pages>) {
        *self.cx.lock().unwrap() = Some(cx.clone());
        if let Some(mut changes) = pages.scenario_changes() {
            let page = self.clone();
            cx.spawn(move |cx| async move {
                while let Ok(Ok(())) = cx.race(None, changes.changed()).await {
                    let (source, session) = {
                        let world = page.world.borrow();
                        (world.source, world.session)
                    };
                    page.refresh(&pages, source, session);
                }
                Ok(())
            });
        }
    }
    /// The session's workstation is ready for its terminal and screen.
    pub fn attach_console(&self, pages: &Pages, console: fictionet_demo::kit::page::GuestConsole) {
        let mut status = console.status.subscribe();
        *self.console.lock().unwrap() = Some(Arc::new(console));
        let destination = self.host.clone();
        destination.send_replace(status.borrow().clone());
        *self.following.lock().unwrap() = Some(tokio::spawn(async move {
            while status.changed().await.is_ok() {
                destination.send_replace(status.borrow().clone());
            }
        }));
        let source = self.world.borrow().source;
        self.refresh(pages, source, Session::Running);
    }
    /// Writes a separate, private record of each session, a run of its
    /// own, before publishing each fact.
    pub async fn record(
        &self,
        mut observations: mpsc::UnboundedReceiver<Observation>,
        directory: &std::path::Path,
    ) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(directory)?;
        let open = || -> std::io::Result<_> {
            let path = directory.join(format!("run-{}.jsonl", fictionet_demo::kit::random_uuid()));
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
            println!("Run record: {}", path.display());
            Ok(std::io::BufWriter::new(file))
        };
        let mut file = None;
        let mut started_at_ms = self.views.lock().unwrap().view.started_at_ms;
        while let Some(observation) = observations.recv().await {
            if let SearchObs::RunStarted {
                started_at_ms: start,
            } = observation.fact
            {
                started_at_ms = start;
                file = None;
            }
            let file = match &mut file {
                Some(file) => file,
                None => file.insert(open()?),
            };
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
                &mut *file,
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
    /// Answers the page's commands: a mode chosen goes to `sessions`,
    /// which starts a session in it; a scenario applies to the running
    /// session's world.
    pub fn serve_commands(
        &self,
        pages: Arc<Pages>,
        mut control: mpsc::UnboundedReceiver<Control>,
        sessions: watch::Sender<Source>,
    ) {
        let page = self.clone();
        tokio::spawn(async move {
            while let Some((command, reply)) = control.recv().await {
                let result = match command {
                    Command::SetSource { source } => match pages.unavailable(source) {
                        Some(message) => Err(message.to_owned()),
                        None => {
                            page.refresh(&pages, source, Session::Starting);
                            sessions.send_replace(source);
                            Ok(())
                        }
                    },
                    Command::SetScenario { scenario } => {
                        let cx = page.cx.lock().unwrap().clone();
                        match cx {
                            None => Err("The workstation is starting; try again".into()),
                            Some(cx) => pages
                                .apply(
                                    &cx,
                                    web_world::pages::Command::SetScenario {
                                        scenario,
                                        expected_revision: pages.revision(),
                                    },
                                )
                                .map(|_| {
                                    let (source, session) = {
                                        let world = page.world.borrow();
                                        (world.source, world.session)
                                    };
                                    page.refresh(&pages, source, session);
                                })
                                .map_err(|error| match error {
                                    web_world::pages::Rejected::Invalid { message } => message,
                                    web_world::pages::Rejected::Stale { .. } => {
                                        "The settings changed; try again".into()
                                    }
                                }),
                        }
                    }
                };
                let _ = reply.send(result);
            }
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
            .route("/updates", get(updates))
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
    picture: Picture,
}
/// A dependency of a served page, read from the source that served it.
#[derive(Deserialize)]
struct Dependency {
    page: url::Url,
    url: url::Url,
    picture: Picture,
}
/// Where a picture of a served page is shown, which decides whether it may
/// copy what the world does not hold yet.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Picture {
    /// A small picture in the feed: drawn from what the world holds, so a
    /// feed of many pages sends no requests to their sites.
    Feed,
    /// The page opened to read: its images are copied as they come into
    /// view, as a browser loads them.
    Reading,
}
/// What a still picture of a served page may load: only what the world holds.
const PICTURE_POLICY: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; base-uri 'none'; form-action 'none'";
fn held_address(page: &url::Url, picture: Picture) -> impl Fn(&url::Url) -> String + '_ {
    move |url| {
        let picture = match picture {
            Picture::Feed => "feed",
            Picture::Reading => "reading",
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("page", page.as_str())
            .append_pair("url", url.as_str())
            .append_pair("picture", picture)
            .finish();
        format!("/held?{query}")
    }
}
/// The page as the world served it, with its own stylesheets and images.
async fn thumbnail(
    State(page): State<Page>,
    Query(Served { url, picture }): Query<Served>,
) -> axum::response::Response {
    let Some((body, _)) = page.views.lock().unwrap().preview(&url) else {
        return (http::StatusCode::NOT_FOUND, "No served page").into_response();
    };
    let picture = tokio::task::spawn_blocking(move || {
        body.text()
            .map(|html| web_world::pages::snapshot::page(&url, &html, &held_address(&url, picture)))
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
    Query(Dependency {
        page: owner,
        url,
        picture,
    }): Query<Dependency>,
) -> axum::response::Response {
    let Some((_, source)) = page.views.lock().unwrap().preview(&owner) else {
        return http::StatusCode::NOT_FOUND.into_response();
    };
    let Some(pages) = page.pages.upgrade() else {
        return http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    pages.settled(&source, url.as_str()).await;
    // An image is copied when the page opened to read first shows it.
    let holds = {
        let (pages, source, url) = (pages.clone(), source.clone(), url.clone());
        tokio::task::spawn_blocking(move || pages.held_resource(&source, url.as_str()).is_some())
    };
    let cx = page.cx.lock().unwrap().clone();
    if matches!(picture, Picture::Reading)
        && !holds.await.unwrap_or(false)
        && let Some(cx) = cx
    {
        pages
            .copy_for_picture(&cx, &source, &owner, url.as_str())
            .await;
    }
    let held = tokio::task::spawn_blocking(move || {
        let mut held = pages.held_resource(&source, url.as_str())?;
        if held.content_type.starts_with("text/css") {
            held.body = web_world::pages::snapshot::stylesheet(
                &url,
                &String::from_utf8_lossy(&held.body),
                &held_address(&owner, picture),
            )
            .into_bytes();
        }
        Some(held)
    })
    .await;
    match held {
        // The picture is a sandboxed frame with no origin of its own; its
        // fonts load only when the reply allows any origin.
        Ok(Some(held)) => (
            [
                (http::header::CONTENT_TYPE, held.content_type),
                (
                    http::header::CONTENT_SECURITY_POLICY,
                    PICTURE_POLICY.to_owned(),
                ),
                (http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".to_owned()),
            ],
            held.body,
        )
            .into_response(),
        _ => http::StatusCode::NOT_FOUND.into_response(),
    }
}
/// What the page's socket sends: each stream's latest state as it changes,
/// and the reply to each command the page sent on it.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Update {
    View { state: Box<View> },
    World { state: WorldState },
    Host { state: HostStatus },
    Reply { id: u64, error: Option<String> },
}
/// A command the page sends on its socket, numbered for its reply.
#[derive(Deserialize)]
struct Asked {
    id: u64,
    command: Command,
}
/// The page's one socket: its states and its commands share it, so they
/// never wait behind the page's pictures for one of the few connections a
/// browser opens to a host, however many tabs show the page.
async fn updates(
    State(page): State<Page>,
    upgrade: axum::extract::ws::WebSocketUpgrade,
) -> axum::response::Response {
    upgrade.on_upgrade(move |socket| page.serve_updates(socket))
}
impl Page {
    async fn serve_updates(self, mut socket: axum::extract::ws::WebSocket) {
        use axum::extract::ws::Message;
        let mut view = self.snapshots.subscribe();
        let mut world = self.world.subscribe();
        let mut host = self.host.subscribe();
        view.mark_changed();
        world.mark_changed();
        host.mark_changed();
        let (replied, mut replies) = mpsc::unbounded_channel::<Update>();
        loop {
            // States go before replies, so a reply finds the page showing
            // what its command changed.
            let update = tokio::select! {
                biased;
                Ok(()) = world.changed() => Update::World { state: world.borrow_and_update().clone() },
                Ok(()) = host.changed() => Update::Host { state: host.borrow_and_update().clone() },
                Ok(()) = view.changed() => Update::View { state: Box::new(view.borrow_and_update().clone()) },
                Some(reply) = replies.recv() => reply,
                message = socket.recv() => match message {
                    Some(Ok(Message::Text(text))) => {
                        let Ok(Asked { id, command }) = serde_json::from_str(&text) else {
                            break;
                        };
                        let (reply, receive) = tokio::sync::oneshot::channel();
                        if self.commands.send((command, reply)).is_err() {
                            let error = Some("The world has stopped".to_owned());
                            let _ = replied.send(Update::Reply { id, error });
                            continue;
                        }
                        let replied = replied.clone();
                        tokio::spawn(async move {
                            let error = match receive.await {
                                Ok(result) => result.err(),
                                Err(_) => Some("The world has stopped".to_owned()),
                            };
                            let _ = replied.send(Update::Reply { id, error });
                        });
                        continue;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                },
            };
            let Ok(text) = serde_json::to_string(&update) else {
                break;
            };
            if socket.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
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
fn world_state(pages: &Pages, preview: bool, source: Source, session: Session) -> WorldState {
    let live = Availability::new(pages.live_available(), UnavailableReason::NoSearchKey);
    // A Copied session's day is the day its pages were copied.
    let lag = pages
        .copied_lag()
        .filter(|_| source == Source::Copied)
        .unwrap_or_default();
    WorldState {
        source,
        session,
        copied: Availability::new(pages.has_copied(), UnavailableReason::NoCaptures),
        live,
        live_depth: live,
        edited: if !pages.live_available() {
            Availability::Unavailable {
                reason: UnavailableReason::NoSearchKey,
            }
        } else {
            Availability::new(pages.edited_available(), UnavailableReason::NoModelKey)
        },
        date: (time::OffsetDateTime::now_utc() - lag).date().to_string(),
        scenario: pages.scenario(),
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
