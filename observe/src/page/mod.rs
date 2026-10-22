//! A loopback page over an in-process dashboard.
//!
//! The public page at `GET /`, styles at `GET /page.css` and module at
//! `GET /page.mjs` contain no world data. Each tab signs in with the URL the run printed ([`Server::url`]). The page removes its fragment,
//! posts to `/api/bootstrap` with `Authorization: Bearer <token>`, and stores
//! that token in session storage. Bootstrap returns 204 with no body for each
//! valid bearer with an empty query. All API routes require the bearer header.
//! Query parameters and cookies never authenticate. Errors are
//! `{"error":"description"}` with an HTTP error status.
//!
//! Every request needs exactly one Host, `127.0.0.1:PORT` or `localhost:PORT`.
//! POST, DELETE and upgrades require Origin `http://127.0.0.1:PORT` or
//! `http://localhost:PORT`. Present origins must always match one of these.
//! Sec-Fetch-Site may only be `same-origin` or `none`. Duplicate security
//! headers and transfer encoding are rejected. Request heads are bounded to
//! 16 KiB, bodies to 64 KiB; POST and DELETE require Content-Length, even for
//! an empty body. Connections close after one request. At most 64 connections
//! are served at once. Reads and writes have a ten-second deadline.
//!
//! `GET /api/page` returns [`PageDescription`]. Its hosts and panels are arrays.
//! A table panel is `{id,title,area,kind:"table",state,columns}`. A control is
//! `{id,title,area,kind:"control",command,actions,state}`; `state` is null when no
//! topic is linked. `state` and `command` are same-origin absolute paths.
//! A column is `{label,pointer,format}`, with a JSON pointer and a format of
//! `text`, `number`, `bytes`, `time` or `status`. An action is `{label,command}`.
//! Values and labels are rendered as text. Browser modules live in `dashboard/`.
//! Pinned libraries are embedded at `/vendor/<name>/<path>` after running
//! `cargo xtask demo libraries`. `/vendor/licenses` lists their versions and licenses.
//! The page response uses a fresh nonce for its inline import map.
//!
//! # Observation
//!
//! `GET /api/<op>` accepts the dashboard operations `world`, `graph`,
//! `counters`, `events`, `link`, `keylog`, `watch`, `packets`, `packet`, `pcap`.
//! Query arguments become flat request fields: nonempty decimal values
//! shorter than 16 bytes become integers; other values remain strings.
//! The route determines `op`. Reply JSON and observer event data use the
//! [crate's observation interface](crate). In particular, `events` accepts
//! `after` and `max`; packet operations accept `link`, `packets` accepts
//! `after`, and `packet` requires `seq`. Open a `packets` stream for a link
//! before requesting its `packet` details. `pcap` exports retained copies
//! directly from the collector, without a watch. Ordinary observer refusals return
//! HTTP 404 with `{error}`. Unknown routes also return 404.
//!
//! `keylog` downloads text with an attachment filename; `pcap` downloads
//! pcapng as `application/vnd.tcpdump.pcap`. Downloads and SSE require bearer
//! authenticated fetches, including when opening them from the browser.
//! Use fetch streams rather than EventSource, which cannot set that header.
//!
//! `watch` and `packets` return `text/event-stream`, with `event: NAME` and
//! one `data: JSON` line per JSON line. Comment heartbeats have no data.
//! `watch` events are `waiting`, `snapshot`, `group`, `node`, `edge`,
//! `edge_end`, `node_end`, `group_end`, `host`, `host_end`, `status`,
//! `counters`, `event`, `ended` and `end`. Their data is the unchanged
//! [watch data documented by the crate](crate#watch).
//! Packet events are `link`, `packet`, `gap` and `end`, with the
//! [crate's packet data](crate#packet-values). `world_error` carries `{error}`
//! and terminates a refused stream. `end` carries `{reason}` and is terminal.
//! There are at most 32 active SSE streams, shared with state streams;
//! capacity returns 503 before starting a subscription. A stream ends as soon
//! as its client closes the connection, which frees its place.
//! [`Server::shutdown`] stops accepting connections and drains available stream
//! data, including `ended` when the run has ended, before the terminal `end`.
//! State streams also end with `end`; the server reason is `the page server stopped`.
//! Console WebSockets close with code 1001. Connections that exceed the supplied
//! timeout are aborted. Dropping a server without shutdown aborts immediately.
//!
//! `packets?link=e3,e7` merges up to 32 links. Each event's data object gets
//! `link`; a link's `end` becomes `link_end`, a refusal becomes `link_error`
//! with `{link,error}`, and other links continue. The final `end` reason is
//! `every link closed`, or `every link finished` if any failed.
//! `pcap?link=e3,e7` concatenates pcapng sections in query order. If any link
//! is unavailable, it returns 404 with
//! `{error:"no capture for e3, e7",links:[{link,error},...]}` instead of a
//! partial download. The in-process session does all packet decoding.
//!
//! # Authoritative state
//!
//! `GET /api/state/<id>` returns
//! `{revision,at,value,status:{too_large}}`. `at` is run time in seconds.
//! Before publication, revision and time are zero and value is null.
//! A successful publish advances the revision once. An oversized snapshot
//! keeps the previous revision and value and permanently sets
//! `status.too_large`. Snapshot values are serialized once at publication,
//! and each is bounded by `StateLimits.max_bytes`.
//!
//! `GET /api/states/stream?topics=a,b&after=a:3,b:7` is one SSE stream for
//! up to 64 topics. A browser allows six HTTP/1.1 connections to one origin,
//! so a page streams all of its state on one connection. `topics` lists topic
//! ids; `after` is optional and gives a revision per listed topic. An unknown
//! topic returns 404 naming it; a malformed or repeated list returns 400.
//! Each event is `snapshot`, with the GET shape plus `topic`. A topic gets
//! one when the stream opens, unless its cursor is current, and one after
//! each change; a reader that falls behind gets only the latest. Status
//! changes send a snapshot even when the revision has not changed.
//!
//! A page holds at most three long-lived streams: `watch`, the state stream
//! and `packets`. Everything else is a short request. The browser components
//! share one of each.
//!
//! # Commands
//!
//! `POST /api/command/<id>` accepts [`CommandRequest`]:
//! `{request_id,command}`. The ID must contain one to 128 UTF-8 bytes. The
//! command is deserialized to the author's concrete type; invalid fields
//! return 400 with a field path in `{error}`. Access to a declared port is
//! the capability, granted by the page bearer. Declared actions describe UI
//! affordances; the world must validate every decoded command.
//!
//! [`CommandReply`] has these JSON forms and HTTP statuses:
//!
//! | Status | Body |
//! |---|---|
//! | 200 | `{status:"applied",request_id,reply}` |
//! | 409 | `{status:"rejected",request_id,rejection}` |
//! | 202 | `{status:"pending",request_id}` |
//! | 504 | `{status:"timeout",request_id,error}` |
//!
//! A rejection is `{reason:"stale_revision",current}`,
//! `{reason:"invalid",message}` or `{reason:"unavailable"}`. Full mailboxes
//! or caches containing only pending IDs return 503 with `{error}` at once.
//! The 504 error is `the command may still apply; read the state before
//! retrying`. It does not cancel the command. Browsers must never retry
//! commands automatically. Deduplication is per port and panel: duplicates
//! return the first reply, or pending, even if their command differs.
//! Only completed IDs can be evicted, oldest first. After eviction the ID
//! may execute again, so callers should use fresh IDs for new inputs.
//!
//! The optional control state URL tells the browser to put the snapshot value's
//! `revision` in `command.expected_revision`, falling back to the snapshot's
//! revision when the value has none. The world checks it when applying.
//! `Command::reply` and `Command::reject` emit source `page`, kind
//! `command`, with fields `{panel,request_id,command,outcome}` through the
//! world's own `Cx`, then release the HTTP reply. Observer event retention
//! and event truncation bounds still apply. Dropping an unanswered command
//! returns unavailable; it does not record an accepted input.
//!
//! ```
//! use fictionet_observe::page::{Command, CommandLimits, CommandPort, Rejected};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Deserialize)]
//! struct SetRoute { mode: String, expected_revision: u64 }
//! #[derive(Serialize)]
//! struct Applied { revision: u64, at: f64 }
//!
//! fn apply(cx: &fictionet::Cx, input: Command<SetRoute, Applied>,
//!          mode: &mut String, revision: &mut u64) {
//!     if input.command.expected_revision != *revision {
//!         input.reject(cx, Rejected::StaleRevision { current: *revision });
//!         return;
//!     }
//!     *mode = input.command.mode.clone();
//!     *revision += 1;
//!     input.reply(cx, Applied {
//!         revision: *revision, at: cx.now().since_start().as_secs_f64(),
//!     });
//! }
//! let port = CommandPort::<SetRoute, Applied>::new(CommandLimits::default());
//! // Pass a clone to Page::control; receive from this port in a world task.
//! ```

//! # Composition and embedded files
//!
//! Every panel has `{id,title,area,kind,...}`. IDs are slugged titles and
//! are unique across all panel kinds. `area` is `workspace` or `inspector`.
//! `standard_panels()` adds Packets, Events, Map, Left the box, Containment,
//! and Labels and export, in that order before world panels,
//! plus `<host-slug>-screen` and `<host-slug>-terminal` in the workspace for
//! each offered console. Their kinds are `packets`, `events`, `map`, `left_the_box`,
//! `screen` or `terminal`; console panels also have `host`.
//! `workspace(title)` places that custom panel in the workspace and moves
//! the consoles to the inspector. Add `workspace_consoles()` to keep their
//! tiles beside the custom panel. `inspector_first(title)` puts that
//! inspector panel first and opens the inspector on it, with the page's other
//! own panels after it; `/api/page` gives its id as `inspector_first`, which
//! is null without the call. `app()` shows the page as an app: the first
//! host's Screen and Terminal as tabs beside the workspace panel, a World
//! menu the panel fills, and no inspector; `/api/page` gives `app: true`.
//! `command(name, port)` registers a mailbox
//! at `/api/command/<name>` without a control panel. Names, columns, actions, paths and
//! composition conflicts are checked before the listener binds.
//!
//! `GET /api/egress` returns the dashboard's bounded
//! [`crate::egress::EgressSnapshot`], including startup observations, pending
//! connections and persistent loss counts. It requires a bearer and an empty
//! query. Host selection filters the snapshot by sandbox in the browser; the
//! loss counts cover the whole run.
//!
//! `containment(topic)` connects a [`StateTopic<Containment>`]. The guest kit
//! publishes probe commands, guest results, proxy facts and world answers.
//! Without a topic, the panel says no checks have been published.
//!
//! `labels(Labels::default())` enables typed event, connection and packet-flow
//! labels. Keep a clone and run [`Labels::run`] in a world task, or receive
//! from [`Labels::commands`] and call [`Labels::apply`] at a scheduling point.
//! Labels are limited to 256 entries of 80 UTF-8 bytes each. Changes publish
//! [`Labels::topic`] and emit `page.label` with the input, assigned identity
//! and revision. Without this builder call, the panel offers exports and
//! explains that labeling has not been enabled.
//!
//! `GET /api/export/events` streams a JSONL snapshot of retained events,
//! ending at the last sequence held when the download began. `host=<name>`
//! scopes events to that page host; omit it for the whole run. The first
//! line describes the scope, end sequence and label snapshot. Event lines
//! carry their event and connection labels. `type: loss` lines report lost
//! event counts for the run, including for a host-scoped export. Truncated
//! event markers remain in the event data. Loss totals come from the same
//! snapshot; sequence gaps alone are not treated as loss.
//! `GET /api/export/packets` accepts the same scope and streams the captured
//! guest links as pcapng sections, with retained TLS keys. Capture limits
//! apply. Both exports require the bearer;
//! browser download links contain only local blob URLs.
//!
//! Each host is `{name,sandbox,status,screen,terminal,claude_code}`. `status` is
//! `/api/state/host-<name>`; `screen` and `terminal` are panel IDs or null.
//! `claude_code` reports whether Claude Code is installed.
//! Capabilities are stable declarations; current availability comes from
//! the status topic's value `{state,addresses,screen,terminal}`. `state` is
//! `booting`, `network_up`, `ssh_up`, `desktop_up` or `stopped`, addresses
//! are strings and availability flags are booleans. Hosts without a supplied
//! status topic have a null snapshot value until publication. Host names
//! are one to 128 ASCII letters, digits, `-` and `_` and must be unique.
//!
//! `GET /api/host/<name>/links` returns `{links:["e1",...]}` from the
//! dashboard collector's current topology, selecting links whose sandbox
//! matches the host's declared sandbox. It returns an empty array before
//! that sandbox appears and 404 for an unknown page host.
//!
//! Event table panels are `{id,title,area,kind:"event_table",events,columns}`.
//! `GET /api/event-table/<id>?after=N` returns `{rows,next,dropped}`.
//! Rows are unchanged dashboard events; columns use JSON pointers over
//! each whole event. The source, kind, field equality and host filters are
//! combined with AND. `field` names a member of the event's `fields` object;
//! `host` maps the page host to the event's `sandbox.name`. Missing fields
//! do not match, including when the expected value is null. Omitted filters
//! match everything. Each call reads the retained events after the cursor in
//! batches of 1,000, until they run out or 1,000 rows match; `next` advances
//! over exactly the examined events, even when rows is empty, so it never
//! skips an event. `dropped` has the session's loss semantics. Pass next
//! as after on the next request. Only after is accepted as a query field.
//!
//! `moment(title, EventFilter)` names a story moment. `/api/page` includes
//! `moments: [{id,title,events}]`. Each events URL uses the event-table
//! projection above, including its cursor and loss behavior. A moment is
//! not a panel and has no columns. Its first matching world event supplies
//! the banner's run time and selection. A newer moment replaces the banner.
//! IDs must be unique across panels and moments; validation happens at bind.
//!
//! Custom panels are `{id,title,area,kind:"custom",module,state}`.
//! `GET /panels/<id>.mjs` serves the declared module as JavaScript.
//! It exports `mount(root, services, options)` returning a dispose function.
//! `GET /assets/<path>` serves an embedded asset with its declared media
//! type. These files, like the page, are public static resources: never
//! embed world secrets in them. Paths are relative, slash-separated ASCII
//! letters, digits, `-`, `_`, and `.`, with no empty, dot or parent segments.
//! Content types accept type/subtype and optional token parameters such as
//! `; charset=utf-8`. Duplicate paths and invalid types fail at bind. Browser code
//! reads world state only through authenticated API requests.
//!
//! ```no_run
//! use fictionet_observe::{DashboardObserver, DashboardOptions};
//! use fictionet_observe::page::{
//!     Action, Column, CommandLimits, CommandPort, EventFilter, Host,
//!     HostStatus, Page, StateLimits, StateTopic,
//! };
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize)]
//! struct Package { name: String }
//! #[derive(Deserialize)]
//! struct SetRoute { mode: String, expected_revision: u64 }
//! #[derive(Serialize)]
//! struct Applied { revision: u64, at: f64 }
//!
//! # async fn build() -> std::io::Result<()> {
//! let dashboard = DashboardObserver::new(DashboardOptions {
//!     collector: fictionet_observe::Options::default(),
//!     ..Default::default()
//! });
//! let status = StateTopic::<HostStatus>::new(StateLimits::default());
//! let inventory = StateTopic::<Vec<Package>>::new(StateLimits::default());
//! let routing = StateTopic::<String>::new(StateLimits::default());
//! let commands = CommandPort::<SetRoute, Applied>::new(CommandLimits::default());
//! let server = Page::new("Desktop", dashboard.handle())
//!     .host(Host::new("workstation").sandbox("workstation").status(status))
//!     .standard_panels()
//!     .table("Packages", inventory, vec![Column::new("Name", "/name")])
//!     .event_table("Requests", EventFilter {
//!         source: Some("http".into()), kind: Some("request".into()),
//!         ..EventFilter::default()
//!     }, vec![Column::new("Summary", "/summary")])
//!     .moment("Ready", EventFilter { kind: Some("ready".into()), ..EventFilter::default() })
//!     .custom("Plant", "export function mount() { return () => {}; }", routing.clone())
//!     .asset("plant/data.json", "application/json", b"{}".to_vec())
//!     .workspace("Plant")
//!     .control("Routing", commands, vec![Action {
//!         label: "Bank".into(), command: serde_json::json!({"mode":"bank","expected_revision":0}),
//!     }])
//!     .control_state(routing)
//!     .bind_loopback(0).await?;
//! println!("{}", server.url());
//! # Ok(())
//! # }
//! ```
//!
//! # Console tickets and WebSockets
//!
//! `POST /api/ticket` takes `{host,capability}`, where capability is `screen`
//! or `terminal`, with the bearer and Origin headers. It returns
//! `{ticket,session,expires_in:30}`. Ticket and session are independent random
//! 32-byte values encoded as lowercase hex. Tickets are single use, bound to
//! the named host and capability, and expire after 30 seconds. At most 64
//! unconsumed, unexpired tickets can exist; capacity returns 503. An unknown
//! host or capability unavailable on that host returns 404; invalid JSON or
//! capability names return 400. Time is elapsed monotonic server time.
//! Expiration includes the exact deadline.
//!
//! `GET /ws/screen/<host>?ticket=...` and
//! `GET /ws/terminal/<host>?ticket=...` upgrade using the SDK's WebSocket
//! codec. Exactly one ticket query field is required. Host and Origin checks
//! apply before ticket consumption. A mismatched, expired or reused ticket
//! returns 401. A presented ticket is consumed even on a host or capability
//! mismatch or capacity refusal. At most four screens and four terminals
//! can be open per host, also subject to the 64-connection page limit.
//! Capacity returns 503. No console open is polled before these checks.
//! After HTTP 101, an open error closes with code 1008 and the error's reason
//! (truncated to 123 UTF-8 bytes). Normal termination closes with code 1000.
//! Ping gets Pong, Pong is accepted, and malformed frames close the socket.
//! All HTTP responses, including upgrades, carry the page security headers.
//!
//! Screen frames are binary RFB bytes in both directions. Text frames close
//! the socket. A client message is bounded to 1 MiB plus the eight-byte
//! clipboard header. RFB messages may span frames or share one frame. Only
//! client versions 3.7 and 3.8 and security type None are accepted. ClientInit
//! is rewritten to shared. SetPixelFormat, SetEncodings (at most 64),
//! FramebufferUpdateRequest, EnableContinuousUpdates and Fence (at most 64
//! payload bytes) always pass. KeyEvent, PointerEvent, ClientCutText, XVP,
//! SetDesktopSize and QEMU extended key events pass only for the lease holder;
//! otherwise the whole message is dropped. Extended clipboard lengths are
//! signed and their absolute payload is bounded to 1 MiB. The extended
//! pointer byte is accepted only after encoding -316 was declared and when
//! the button mask has bit 7 set. Unknown types or QEMU subtypes close.
//! Server-to-browser RFB bytes pass unchanged. Watching never requires a lease.
//!
//! Terminals start at 80 columns by 24 rows. Binary frames carry PTY bytes
//! both ways; client messages are bounded to 64 KiB. Text frames are either
//! `{"type":"resize","cols":100,"rows":40}` (positive u16 dimensions) or
//! `{"type":"ack","bytes":4096}` (bytes the browser has consumed).
//! Acknowledging more than the outstanding bytes closes the socket.
//! Above 128 KiB unacknowledged output, the server stops reading the PTY;
//! it resumes only below 32 KiB. Reads take one chunk at a time and writes
//! have a ten-second deadline. Output is framed in chunks of at most 64 KiB.
//! The PTY is closed on disconnect; dropping an implementation must also
//! close its channel, including when the page server is dropped. `Pty::read`
//! must be cancellation safe. Terminal input does not use the screen lease.
//!
//! # Input leases
//!
//! `POST /api/lease` takes `{host,session}` or `{host,session,take:true}`.
//! Session is the ticket reply's session ID and must name an open screen
//! for that host; terminals take no lease. The first form acquires a free lease or retains its own;
//! it returns 409 when another session holds the lease. The take form
//! transfers it. `DELETE /api/lease` takes `{host,session}` and releases only
//! that session's lease. Both return `{holder}` (session ID or null).
//! Invalid sessions return 400. Closing the holding WebSocket also releases
//! the lease. These mutations require bearer and Origin headers.
//!
//! `leases` is a built-in state topic: `GET /api/state/leases` and the state
//! stream with `topics=leases` use the regular shapes. Value is a map
//! `{"alpha":{"holder":null},"beta":{"holder":"session id"}}`.
//! This built-in topic publishes replacement snapshots, with at measured on
//! the injected server clock. Compare holder to the ticket's session ID to
//! detect loss of control. Ownership is checked for each complete RFB input
//! message, so takeover blocks the previous session's next input immediately.
//! Taking control never pauses the agent; it claims browser input only.

mod assets;
mod auth;
mod builder;
mod command;
mod console;
mod containment;
mod export;
mod host;
mod http;
mod labels;
mod observation;
mod panel;
mod rfb;
mod state;

pub use builder::EventFilter;
pub use command::{
    Action, Command, CommandLimits, CommandPort, CommandReply, CommandRequest, Rejected,
};
pub use containment::{Containment, ProbeOutcome, ProbeResult, ProxySetting};
pub use host::{BoxFuture, Console, Duplex, Host, HostDescription, HostState, HostStatus, Pty};
pub use labels::{Label, LabelCommand, LabelTarget, Labels};
pub use panel::{Area, Column, Format, PanelContent, PanelDescription};
pub use state::{PublishError, Snapshot, StateLimits, StateStatus, StateTopic};

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::DashboardHandle;
use builder::invalid;

/// An HTTP error body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorReply {
    /// Human-readable reason.
    pub error: String,
}

/// 32 random bytes as lowercase hex: tokens, tickets, sessions and nonces.
fn random_hex() -> io::Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(crate::hex(&bytes))
}

/// Looks up an embedded browser library by its path under `/vendor/`.
/// Returns `None` when the file was not downloaded before building.
pub fn vendored(path: &str) -> Option<&'static [u8]> {
    assets::vendored(path)
}

/// A service in the world's architecture, selected by observation metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchitectureService {
    /// Short display label.
    pub title: String,
    /// Observation source declared by the world.
    pub source: String,
    /// Event kinds belonging to this service; empty includes every kind.
    pub kinds: Vec<String>,
    /// JSON field printed on each event line.
    pub detail: String,
    /// Whether these events represent traffic leaving the world.
    pub outside: bool,
}

/// Page composition returned by `/api/page`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PageDescription {
    /// Page title.
    pub title: String,
    /// Hosts on this page.
    pub hosts: Vec<HostDescription>,
    /// Declared panels.
    pub panels: Vec<PanelDescription>,
    /// Named event projections shown in the top bar.
    pub moments: Vec<MomentDescription>,
    /// The inspector panel shown first and opened first, or null for Packets.
    pub inspector_first: Option<String>,
    /// The page is an app: the first host's screen and terminal beside the
    /// workspace panel, with no inspector (see [`Page::app`]).
    #[serde(default)]
    pub app: bool,
    /// Services declared by the world for its architecture view.
    #[serde(default)]
    pub architecture: Vec<ArchitectureService>,
}

/// A named moment marked by world events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MomentDescription {
    /// Identifier shared with its event projection.
    pub id: String,
    /// Banner title.
    pub title: String,
    /// Server-filtered event endpoint.
    pub events: String,
}

/// An embedded page served from the loopback interface.
pub struct Page {
    title: String,
    dashboard: DashboardHandle,
    panels: Vec<PanelDescription>,
    moments: Vec<MomentDescription>,
    topics: Vec<(String, state::Topic)>,
    commands: Vec<(String, Box<dyn command::Dispatch>)>,
    errors: Vec<String>,
    hosts: Vec<Host>,
    standard: bool,
    labels: Option<Labels>,
    workspace: Option<String>,
    workspace_consoles: bool,
    inspector_first: Option<String>,
    app: bool,
    architecture: Vec<ArchitectureService>,
    modules: Vec<(String, String)>,
    assets: Vec<(String, String, Vec<u8>)>,
    filters: Vec<(String, EventFilter)>,
    clock: Arc<dyn Fn() -> std::time::Duration + Send + Sync>,
}

impl Page {
    /// Declares the services whose observed events drive the architecture view.
    pub fn architecture(mut self, services: Vec<ArchitectureService>) -> Self {
        self.architecture = services;
        self
    }

    /// Starts an explicit page composition.
    pub fn new(title: impl Into<String>, dashboard: DashboardHandle) -> Self {
        Self {
            title: title.into(),
            dashboard,
            panels: vec![],
            moments: vec![],
            topics: vec![],
            commands: vec![],
            errors: vec![],
            hosts: vec![],
            standard: false,
            labels: None,
            workspace: None,
            workspace_consoles: false,
            inspector_first: None,
            app: false,
            architecture: vec![],
            modules: vec![],
            assets: vec![],
            filters: vec![],
            clock: {
                let start = std::time::Instant::now();
                Arc::new(move || start.elapsed())
            },
        }
    }

    /// Registers a typed command endpoint without adding a control panel.
    pub fn command<C: serde::de::DeserializeOwned + Send + 'static, R: Serialize + 'static>(
        mut self,
        name: impl Into<String>,
        port: CommandPort<C, R>,
    ) -> Self {
        self.commands.push((name.into(), Box::new(port)));
        self
    }

    /// Adds a table over an authoritative state topic.
    pub fn table<T: Serialize>(
        mut self,
        title: impl Into<String>,
        topic: StateTopic<Vec<T>>,
        columns: Vec<Column>,
    ) -> Self {
        let title = title.into();
        let id = panel::slug(&title);
        self.topics.push((id.clone(), topic.topic));
        self.panels.push(PanelDescription::inspector(
            id.clone(),
            title,
            PanelContent::Table {
                state: format!("/api/state/{id}"),
                columns,
            },
        ));
        self
    }

    /// Adds declared actions backed by a typed world mailbox.
    pub fn control<C: serde::de::DeserializeOwned + Send + 'static, R: Serialize + 'static>(
        mut self,
        title: impl Into<String>,
        port: CommandPort<C, R>,
        actions: Vec<Action>,
    ) -> Self {
        let title = title.into();
        let id = panel::slug(&title);
        self.commands.push((id.clone(), Box::new(port)));
        self.panels.push(PanelDescription::inspector(
            id.clone(),
            title,
            PanelContent::Control {
                command: format!("/api/command/{id}"),
                actions,
                state: None,
            },
        ));
        self
    }

    /// Links the last control to authoritative state. The browser copies its
    /// value's revision (or the envelope revision when absent) into
    /// `expected_revision`; the world must check it when applying.
    pub fn control_state<T: Serialize>(mut self, topic: StateTopic<T>) -> Self {
        if let Some(PanelDescription {
            id,
            content: PanelContent::Control { state, .. },
            ..
        }) = self.panels.last_mut()
        {
            if state.is_some() {
                self.errors.push(
                    "control_state was called twice for one control; link one topic per control"
                        .into(),
                );
                return self;
            }
            *state = Some(format!("/api/state/{id}"));
            self.topics.push((id.clone(), topic.topic));
        } else {
            self.errors.push(
                "control_state must immediately follow control; move the call after control".into(),
            );
        }
        self
    }

    /// Validates the composition and binds `port` on IPv4 loopback. Zero, or
    /// a port another listener holds, binds a free port; [`Server::url`]
    /// names the port bound.
    pub async fn bind_loopback(mut self, port: u16) -> io::Result<Server> {
        self.prepare()?;
        if self.title.trim().is_empty() {
            return Err(invalid("Page::new title is empty; give the page a title"));
        }
        if let Some(error) = self.errors.first() {
            return Err(invalid(error.clone()));
        }
        let mut commands = std::collections::BTreeSet::new();
        for (name, port) in &self.commands {
            if !builder::valid_name(name) || !commands.insert(name) {
                return Err(invalid(
                    "command needs a unique name of at most 128 ASCII letters, digits, hyphens or underscores",
                ));
            }
            port.validate(&[], false).map_err(invalid)?;
        }
        let mut ids = std::collections::BTreeMap::new();
        for panel in &self.panels {
            if panel.id.is_empty() || ids.contains_key(&panel.id) {
                return Err(invalid(format!(
                    "{}({:?}) has an empty id or conflicts with {}; choose distinct titles with ASCII letters or digits",
                    panel.content.call(),
                    panel.title,
                    ids.get(&panel.id)
                        .unwrap_or(&String::from("an empty title"))
                )));
            }
            ids.insert(
                &panel.id,
                format!("{}({:?})", panel.content.call(), panel.title),
            );
            if let PanelContent::Control { actions, state, .. } = &panel.content {
                let (_, port) = self
                    .commands
                    .iter()
                    .find(|(id, _)| id == &panel.id)
                    .unwrap();
                port.validate(actions, state.is_some())
                    .map_err(|error| invalid(format!("control {:?}: {error}", panel.title)))?;
            }
            let (PanelContent::Table { columns, .. } | PanelContent::EventTable { columns, .. }) =
                &panel.content
            else {
                continue;
            };
            for column in columns {
                if column.label.trim().is_empty() || !panel::valid_pointer(&column.pointer) {
                    return Err(invalid(format!(
                        "{}({:?}) column {:?} has an empty label or invalid JSON pointer {:?}; use a label and a pointer starting with /",
                        panel.content.call(),
                        panel.title,
                        column.label,
                        column.pointer
                    )));
                }
            }
        }
        for moment in &self.moments {
            if moment.id.is_empty() || moment.id.len() > 128 || ids.contains_key(&moment.id) {
                return Err(invalid(format!(
                    "moment({:?}) has an invalid or duplicate id; choose a distinct title with at most 128 ASCII letters, digits or separators",
                    moment.title
                )));
            }
            ids.insert(&moment.id, format!("moment({:?})", moment.title));
        }
        let mut topics = std::collections::BTreeSet::from(["leases"]);
        for (id, _) in &self.topics {
            if !topics.insert(id) {
                return Err(invalid(format!(
                    "state topic {id:?} conflicts with a host status or built-in topic; rename the panel or host"
                )));
            }
        }
        let consoles = console::Sessions::new(&self.hosts);
        self.topics
            .push(("leases".into(), consoles.topic.topic.clone()));
        let auth = auth::Auth::new()?;
        let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Err(error) if port != 0 && error.kind() == io::ErrorKind::AddrInUse => {
                TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?
            }
            bound => bound?,
        };
        let port = listener.local_addr()?.port();
        let url = format!("http://127.0.0.1:{port}/#token={}", auth.token);
        let (stop, mut stopping) = watch::channel(false);
        let shared = Arc::new(Shared {
            page: self,
            auth,
            port,
            streams: Semaphore::new(32),
            consoles,
            stopping: stopping.clone(),
        });
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(64));
            let mut connections = JoinSet::new();
            loop {
                while connections.try_join_next().is_some() {}
                let accepted = tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut conn, _)) = accepted else {
                    break;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                let shared = shared.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = serve(&mut conn, &shared).await;
                });
            }
            drop(listener);
            while connections.join_next().await.is_some() {}
        });
        Ok(Server { url, task, stop })
    }
}

struct Shared {
    page: Page,
    auth: auth::Auth,
    port: u16,
    streams: Semaphore,
    consoles: console::Sessions,
    stopping: watch::Receiver<bool>,
}

/// A running page. Dropping it closes the listener and active connections.
pub struct Server {
    url: String,
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Server {
    /// Drains stream data and closes connections, aborting any left after `timeout`.
    pub async fn shutdown(mut self, timeout: Duration) {
        self.stop.send_replace(true);
        if tokio::time::timeout(timeout, &mut self.task).await.is_err() {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
    }

    /// The loopback URL, with the per-run bearer token in its fragment.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(conn: &mut TcpStream, shared: &Shared) -> io::Result<()> {
    let Some(req) = http::read_request(conn, http::IO_TIMEOUT).await? else {
        return http::error(conn, 400, "invalid or oversized request").await;
    };
    if !http::allowed(&req, shared.port) {
        return http::error(conn, 403, "Host, Origin or Sec-Fetch-Site is not allowed").await;
    }
    if req.path.starts_with("/api/") && !shared.auth.allows(&req) {
        return http::error(conn, 401, "bearer token required").await;
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => http::page(conn).await,
        ("GET", "/vendor/licenses") => {
            http::respond(
                conn,
                200,
                "text/html; charset=utf-8",
                assets::licenses().as_bytes(),
            )
            .await
        }
        ("GET", path) if assets::lookup(path).is_some() => {
            let (kind, bytes) = assets::lookup(path).expect("matched asset");
            http::respond(conn, 200, kind, bytes).await
        }
        ("POST", "/api/bootstrap") => {
            if !shared.auth.bootstrap(&req) {
                return http::error(conn, 409, "bootstrap requires an empty query").await;
            }
            http::respond(conn, 204, "text/plain", b"").await
        }
        ("POST", "/api/ticket") => console::ticket(conn, shared, &req).await,
        ("POST" | "DELETE", "/api/lease") => console::lease(conn, shared, &req).await,
        ("GET", path) if path.starts_with("/ws/") => console::upgrade(conn, shared, &req).await,
        ("GET", path) if path.starts_with("/assets/") || path.starts_with("/panels/") => {
            builder::asset(conn, shared, path).await
        }
        ("GET", path)
            if path.starts_with("/api/host/") || path.starts_with("/api/event-table/") =>
        {
            builder::projection(conn, shared, &req).await
        }
        ("GET", "/api/export/events" | "/api/export/packets") => {
            export::route(conn, shared, &req).await
        }
        ("GET", "/api/egress") => {
            if !req.query.is_empty() {
                return http::error(conn, 400, "egress takes no query parameters").await;
            }
            http::json(conn, 200, &shared.page.dashboard.egress()).await
        }
        ("GET", "/api/page") => {
            http::json(
                conn,
                200,
                &PageDescription {
                    title: shared.page.title.clone(),
                    hosts: shared.page.hosts.iter().map(Host::description).collect(),
                    panels: shared.page.panels.clone(),
                    moments: shared.page.moments.clone(),
                    inspector_first: shared.page.inspector_first.clone(),
                    app: shared.page.app,
                    architecture: shared.page.architecture.clone(),
                },
            )
            .await
        }
        ("GET", "/api/states/stream") => {
            let topics = match state_stream_topics(&shared.page.topics, &req.query) {
                Ok(topics) => topics,
                Err((status, error)) => return http::error(conn, status, &error).await,
            };
            let Ok(_permit) = shared.streams.try_acquire() else {
                return http::error(conn, 503, "too many streams").await;
            };
            state::stream(conn, &topics, shared.stopping.clone()).await
        }
        ("GET", path) if path.starts_with("/api/state/") => {
            let id = &path[11..];
            let Some((_, topic)) = shared.page.topics.iter().find(|(name, _)| name == id) else {
                return http::error(conn, 404, "no such state topic").await;
            };
            http::respond(conn, 200, "application/json", topic.snapshot().as_bytes()).await
        }
        ("POST", path) if path.starts_with("/api/command/") => {
            let Some((id, port)) = shared
                .page
                .commands
                .iter()
                .find(|(id, _)| id == &path[13..])
            else {
                return http::error(conn, 404, "no such command port").await;
            };
            let request = match serde_json::from_slice(&req.body) {
                Ok(request) => request,
                Err(error) => return http::error(conn, 400, &error.to_string()).await,
            };
            match port.submit(id, request).await {
                Ok((status, reply)) => http::json(conn, status, &reply).await,
                Err((status, error)) => http::error(conn, status, &error).await,
            }
        }
        ("GET", path)
            if path
                .strip_prefix("/api/")
                .is_some_and(|op| observation::OPS.contains(&op)) =>
        {
            observation::route(conn, shared, &path[5..], &req.query).await
        }
        _ => http::error(conn, 404, "no such route").await,
    }
}

type StreamTopics<'a> = Vec<(&'a str, &'a state::Topic, Option<u64>)>;

/// Reads `topics=a,b&after=a:3` into the topics a state stream carries.
fn state_stream_topics<'a>(
    declared: &'a [(String, state::Topic)],
    query: &[(String, String)],
) -> Result<StreamTopics<'a>, (u16, String)> {
    let bad = |error: &str| Err((400, error.to_owned()));
    let (mut names, mut after) = (None, None);
    for (key, value) in query {
        let slot = match key.as_str() {
            "topics" => &mut names,
            "after" => &mut after,
            _ => return bad("state streams accept only topics and after"),
        };
        if slot.replace(value.as_str()).is_some() {
            return Err((400, format!("{key} appears more than once")));
        }
    }
    let Some(names) = names else {
        return bad("name the topics, as topics=a,b");
    };
    if names.split(',').count() > state::MAX_STREAM_TOPICS {
        return Err((
            400,
            format!(
                "a stream carries at most {} topics",
                state::MAX_STREAM_TOPICS
            ),
        ));
    }
    let mut topics: StreamTopics<'a> = Vec::new();
    for name in names.split(',') {
        if name.is_empty() {
            return bad("topics is a comma-separated list of topic ids");
        }
        if topics.iter().any(|(id, _, _)| *id == name) {
            return Err((400, format!("topic {name:?} appears more than once")));
        }
        let Some((id, topic)) = declared.iter().find(|(id, _)| id == name) else {
            return Err((404, format!("no such state topic: {name:?}")));
        };
        topics.push((id, topic, None));
    }
    for cursor in after.into_iter().flat_map(|after| after.split(',')) {
        let Some((name, revision)) = cursor.split_once(':') else {
            return bad("after is a list of topic:revision");
        };
        let Some(entry) = topics.iter_mut().find(|(id, _, _)| *id == name) else {
            return Err((400, format!("after names {name:?}, which is not in topics")));
        };
        let Ok(revision) = revision.parse() else {
            return bad("after must give unsigned revisions");
        };
        if entry.2.replace(revision).is_some() {
            return Err((400, format!("after names {name:?} more than once")));
        }
    }
    Ok(topics)
}

#[cfg(test)]
mod tests;
