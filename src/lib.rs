//! Fictionet: a simulated internet for AI agent evals and RL environments.
//!
//! Fictionet lets you decide what an AI agent sees when it uses the network.
//! You write a *world*: an ordinary Rust program that decides what every
//! name resolves to, which sites exist, what they serve over TLS under the
//! world's own certificate authority, and how packets are routed, delayed
//! and dropped. Then you attach the agent's sandbox to it. From inside the
//! sandbox, the agent's own tools (`curl`, `dig`, `ping`, a browser) see the
//! world as the whole network.
//!
//! Use it to build evals, RL environments and tests where the network is part
//! of the task: a tampered website, a slow or lossy link, a hijacked route, an
//! impostor service.
//!
//! A world's time and randomness come from its [`Cx`]. Randomness starts
//! from a seed. With real sandboxes it runs on real time ([`run`]).
//! In a test it runs on simulated time ([`lab`]), where the same seed and
//! ordered inputs, interests and limits give the same observations and stamps.
//! [Repeatable runs](guide::running#repeatable-runs) lists the requirements and
//! runtime boundaries. [`running`](guide::running) is the guide;
//! [`run`], [`lab`] and [`Cx`] document runtime operations.
//!
//! Core produces four typed streams: events, packets, TLS keys and topology.
//! The integrator installs one observer in [`RunOptions`]. [`events`] defines
//! the contract, including
//! [what observation skips without an observer](events#interest-identity-and-order).
//! [Fictionet Observe](../fictionet_observe/index.html) consumes
//! these streams: `Memory` and `Aggregate` for grading, `Jsonl` for files,
//! `Collector` for bounded collection, and `DashboardObserver` for clients.
//! `run.start` emits the seed to interested observers. Core retains no
//! observation history.
//!
//! # How a sandbox connects to a world
//!
//! The world runs as its own process and listens on a Unix socket, such as
//! `/run/fictionet/world.sock`. Next to each sandbox, you run
//! `fictionet attach`. In the most common setup, attach makes a network
//! device, `tun0`, inside the sandbox's network namespace, and routes the
//! sandbox's traffic through it. Every packet the sandbox sends through
//! `tun0` goes to the world, and every packet the world sends back comes
//! out of `tun0`. The agent needs no proxy settings and no special
//! software.
//!
//! Attach adds `tun0` and its routes, and leaves the rest of the namespace
//! as it was. So `tun0` is the sandbox's only way out when the namespace
//! has no other interface, such as a new one from `ip netns add`. In a
//! namespace that already has one, such as a Kubernetes pod's `eth0`,
//! attach can take that interface down first (`--down-link`).
//!
//! <style>.fn-attach > svg {display:block;width:100%;max-width:696px;min-width:480px;height:auto}</style>
//! <div class="fn-attach" style="overflow-x:auto;margin:1.25em 0">
#![doc = include_str!("../docs/diagrams/attach.svg")]
//! </div>
//!
//! This command, run as root on the host, attaches the network namespace
//! `/run/netns/agent` as a sandbox named `agent`. `--world` names the
//! world's socket, `--name` the sandbox, and `attach tun` asks for a
//! `tun0` device. `--netns` is the namespace to put it in. The last six
//! flags give the sandbox an address, a gateway and a DNS server inside
//! the world, for both IPv4 and IPv6, because attach runs no DHCP for
//! `tun`:
//!
//! ```text
//! fictionet attach tun --world unix:/run/fictionet/world.sock --name agent \
//!     --netns /run/netns/agent \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! ```
//!
//! Sandboxes can attach and detach at any time while the world runs. Each one
//! has a name, and the world receives it as an [`Attachment`]. A virtual
//! machine attaches through its network card instead (`attach tap`). A sandbox
//! that cannot have a network device, because it has no privileges at all, can
//! attach through a proxy (`attach http-proxy` or `attach socks5`). Whatever
//! the type, the world receives IP packets: [`lowering`](guide::lowering) shows
//! how each type turns what its sandbox sends into them.
//!
//! # A world in code
//!
//! A world is an async function. It receives a context ([`Cx`], described
//! below) and the sandboxes that attach to it ([`Attachments`]). Here is
//! the start of one:
//!
//! ```
//! use fictionet::{Attachments, Cx, Result, stdlib, time::ms};
//!
//! async fn world(fcx: Cx, mut attachments: Attachments) -> Result {
//!     let agent = attachments.get(&fcx, "agent").await?;
//!     let link = stdlib::network::delay(&fcx, ms(50), agent);
//!     let (v4, v6, _) = stdlib::network::ip::split_versions(&fcx, link);
//!     // route v4 and v6 with stdlib::network::route::router(&fcx, ...)
//!     Ok(())
//! }
//! ```
//!
//! The first line waits for the sandbox named `agent` to attach. The next
//! line puts a 50 ms delay in front of it, and the one after splits its
//! traffic into IPv4 and IPv6. A complete world would go on to connect `v4`
//! and `v6` to more stdlib code, such as a router and the machines behind
//! it. The `delay` and `split_versions` calls each start one background
//! task, return immediately, and hand back new interfaces for the next call
//! to use:
//!
#![doc = include_str!("../docs/diagrams/world.svg")]
//!
//! A few types do all the work in that example:
//!
//! - An [`Interface`] is anything that carries IP packets: you send packets
//!   into it and receive packets from it. Every piece of a world talks to
//!   the next piece through an `Interface`.
//! - [`pair`] makes two connected interfaces. A packet sent into one comes
//!   out of the other. It is how you join two pieces of a world by hand.
//! - An [`Attachment`] is one attached sandbox, as seen by the world. It is
//!   an `Interface` like any other, so stdlib functions take it directly.
//!   [`Attachments`] hands them to the world by name or in arrival order.
//! - A [`Cx`] is the context that world code runs in. World code reads
//!   Fictionet's clock, waits, draws random numbers and starts background
//!   tasks through it.
//!   Background tasks belong to a [region](Cx#regions), a group of tasks
//!   that are cancelled together. Cancelling the region stops all of its
//!   tasks, and a region ends only after all of its tasks have ended. So a
//!   task can outlive the function that started it, but never its region.
//!   [What ends what](guide::running#what-ends-what) lists every case.
//! - [`Packet`] holds the raw bytes of one IP packet.
//!
//! These types, at the crate root, are the core of Fictionet. The core
//! moves packets but never parses them. Addresses, ports, names, routing,
//! TCP, TLS and HTTP are all in [`stdlib`], built on these types. For a
//! whole network of websites in a few lines, see [`stdlib::web`]. The core
//! also assumes no async runtime: its futures use only
//! [`std::task::Waker`], so a world runs on tokio or on Fictionet's own
//! [`block_on`].
//!
//! # Running a world
//!
//! Fictionet does not own `main` or the executor. A world runs inside an
//! ordinary program, and this is the whole of `main`:
//!
//! ```no_run
//! # use fictionet::{Attachments, Cx, Result};
//! # async fn world(_fcx: Cx, _attachments: Attachments) -> Result { Ok(()) }
//! fn main() -> fictionet::Result {
//!     let (attacher, attachments) = fictionet::attachments();
//!     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
//!     let _listening = fictionet::listen(socket, attacher)?;
//!     fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::random()), |fcx| world(fcx, attachments)))
//! }
//! ```
//!
//! [`attachments`] makes the channel that sandboxes arrive through. [`listen`]
//! opens the world socket that the [`WorldSocket`] names, so that each
//! `fictionet attach` that connects arrives in that channel. [`run`] turns the
//! world function into one future, and [`block_on`] polls it until the world
//! ends. Each world is its own process, with no central daemon. It has the
//! host's real network, so world code can also reach the internet or a
//! database. [`running`](guide::running) explains each step, how a world stops,
//! and how to run one in a test with no socket at all.
//!
//! # Services on a network
//!
//! Most worlds are a network of hosts, each answering some protocols. Three
//! stdlib modules make one in a few lines:
//!
//! - [`stdlib::services::serve`]: a [`Service`](stdlib::services::serve::Service)
//!   is the server side of one protocol for one connection, with no I/O: it
//!   gets decoded items, appends reply bytes, and records facts. One driver
//!   runs any service over any connection, with timers, TLS, a transcript and
//!   fault plans.
//! - [`stdlib::world::net`]: a [`Net`](stdlib::world::net::Net) builds the
//!   network around the [`Host`](stdlib::world::net::Host)s it is given: the
//!   sandboxes' subnet with DHCP, DNS for every host's names, a router, one
//!   machine per address, and each host's services on their ports.
//! - [`events`]: structured facts emitted lazily to the run's observer.
//!   The companion's `Memory`, `Aggregate` and `Jsonl` retain, summarize
//!   and export them. See [Fictionet Observe](../fictionet_observe/index.html).
//!
//! HTTP is a service too ([`stdlib::web::httpd`]): a router whose handlers get
//! byte bodies, or any tower service such as an axum `Router`. Here a web
//! server and a line-echo service run on two hosts; installed observers can
//! retain their events:
//!
//! ```
//! # {
//! use std::sync::Arc;
//! use fictionet::{Attachments, Cx, Result};
//! use fictionet::stdlib::codec::{Ending, LineError, Lines};
//! use fictionet::stdlib::web::httpd::{Router, Server};
//! use fictionet::events::Event;
//! use fictionet::stdlib::world::net::Net;
//! use fictionet::stdlib::services::serve::{Flow, Driver, Service};
//!
//! /// Echoes each line back.
//! struct Echo;
//!
//! impl Service for Echo {
//!     type Decoder = Lines;
//!     type State = ();
//!     type Error = std::convert::Infallible;
//!     fn decoder(&self) -> Lines {
//!         Lines::new(1024, Ending::LfOrCrlf)
//!     }
//!     fn on_item(&mut self, line: std::result::Result<Vec<u8>, LineError>, _: &(), driver: &mut Driver<'_, Self::Decoder>) -> std::result::Result<Flow, Self::Error> {
//!         let line = line.unwrap_or_default();
//!         driver.emit("echo", "line", |event| event.field("bytes", line.len() as u64));
//!         driver.reply().extend_from_slice(&line);
//!         driver.reply().push(b'\n');
//!         Ok(Flow::Continue)
//!     }
//! }
//!
//! async fn world(fcx: Cx, attachments: Attachments) -> Result {
//!     let site = Router::new().get("/", |_, _| http::Response::new("hello\n".into()));
//!     Net::new()
//!         .host("www", |h| h.dns_name("www.example.test").port_server(80, Server::new(site)))
//!         .host("echo", |h| h.dns_name("echo.example.test").tcp(7, Arc::new(()), || Echo))
//!         .start(&fcx, attachments)
//! }
//! # }
//! ```
//!
//! [`stdlib::web::Sites`] is a preset on `Net` for a world of websites. The
//! guide in `docs/services.md` walks through services, `Net`, and events
//! step by step.
//!
//! # Protocols
//!
//! The stdlib provides codecs (no I/O) for about a hundred protocols and
//! data formats, listed in the [module table](stdlib#modules). Their message
//! types parse and write bytes ([`Wire`](stdlib::codec::Wire)), and their
//! decoders cut items out of input ([`Decode`](stdlib::codec::Decode)).
//! HTTP has a ready server, [`stdlib::world::net::Net`] serves DNS and DHCP, and
//! TLS is built in. For other protocols, a world writes a
//! [`Service`](stdlib::services::serve::Service) around the module's decoder.
//! The codecs also work in unit tests and fuzz targets. The companion's
//! `Present` adapters use them to decode captured traffic for the dashboard.
//! See [Changing a protocol by copying it](stdlib#changing-a-protocol-by-copying-it).
//!
//! # Watching a world
//!
//! Install `fictionet_observe::DashboardObserver` in [`RunOptions`] before
//! execution. It consumes all four streams and owns their bounded retention.
//! A world shows its own page with `fictionet_observe::page::Page`, and serves
//! the handle on a private observation socket for `fictionet observe`, using
//! `--observation unix:PATH`. The attachment socket carries sandbox traffic.
//! Late clients see retained history.
//!
//! The page draws tasks and groups with host context from topology and
//! decodes captured packets. It can decrypt TLS 1.3 when instrumented endpoints
//! emit the needed keys. `fictionet observe` prints JSON replies and streams,
//! or exports packets and keys. The [companion crate](../fictionet_observe/index.html)
//! covers installation, sign-in, capture limits and the observation protocol.
//!
//! # Where to go next
//!
//! 1. [`getting_started`](guide::getting_started): from `cargo build` to an
//!    HTTPS request from a sandbox, with every command and its output.
//! 2. [`running`](guide::running): the program around a world, and worlds in tests.
//! 3. [`lowering`](guide::lowering): how each attach type turns what its
//!    sandbox sends into IP packets, and what the world sees from each.
//! 4. [`stdlib`], then [`stdlib::world::net`] and [`stdlib::services::serve`]: the
//!    networking pieces a world is built from, and a network of hosts and
//!    services in a few lines. [`stdlib::web`] does the same for websites.
//! 5. [Fictionet Observe](../fictionet_observe/index.html): collection, grading,
//!    files, the dashboard and the observation protocol. [`events`] covers
//!    producing observations from world code.
//! 6. [`proto`](guide::proto): the protocol between attach and a world, if you
//!    want to write your own attach.
//! 7. [`roadmap`](guide::roadmap): what is planned, such as attaching remote
//!    sandboxes.
//!
//! # Features and dependencies
//!
//! | Feature | What it gates | Implies | Default |
//! |---|---|---|---|
//! | `tokio` | Tokio adapters and axum upgrades | — | No |
//! | `web-proxy` | `web::proxy` and `web::forward`, with an injected `Upstream` transport | — | No |
//!
//! Fictionet always uses the Rust standard library and its mutexes
//! ([`sync::Mutex`]). Real clocks, OS entropy, HTTP servers and native world
//! sockets are available without features. The default build has no tokio,
//! hyper or h2 dependency. File export belongs to the companion's `native` feature.
//!
//! # In a browser
//!
//! The library also builds for `wasm32-unknown-unknown`, with
//! no features needed for HTTP/1.1 and HTTP/2. A world
//! then runs inside a page: [`run`],
//! [`Cx`] and its timers, [`block_on`], [`pair`], [`attachments`], the
//! [`stdlib`] with smoltcp, DNS, `web::Sites` and TLS (rustls with the
//! run-aware provider and ring, whose C code needs a clang with the wasm32
//! target). All four observation streams are available, and the companion's
//! base collectors build for wasm too. The page plays the sandboxes through [`Attacher::attach`],
//! whose [`End`] carries raw IP packets.
//!
//! What needs an operating system is left out of that build: [`listen`],
//! [`WorldSocket`]. The clocks come from `performance.now()` and
//! `Date.now()`, random bytes from `crypto.getRandomValues`, and timers
//! from `setTimeout`. In a page, hand [`run`] to the event loop with
//! `wasm_bindgen_futures`. [`block_on`] also works, but spins between
//! timers. Opt-in axum upgrades still use hyper, whose internal clock is
//! unavailable on this target. [`httpd`](stdlib::web::httpd) says how the
//! native HTTP/2 server keeps time.

#![warn(missing_docs)]
#![cfg_attr(
    not(all(feature = "tokio", feature = "web-proxy")),
    allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Protocol files use the same imports here and when copied into a user crate.
extern crate self as fictionet;

mod attach;
mod block_on;
mod cable;
mod cx;
mod entropy;
mod environment;
mod error;
pub mod events;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
pub mod guide;
mod interface;
#[cfg(not(target_arch = "wasm32"))]
mod listen;
mod packet_queue;
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub mod relay;
pub use entropy::{Entropy, Seed, SeededEntropy};
mod group;
mod link;
mod run;
pub mod stdlib;
pub mod sync;
mod sys;
pub mod time;
mod timer;
mod tls_keys;
#[cfg(feature = "tokio")]
pub mod tokio;

/// The extension traits. Import this to call methods such as
/// [`recv`](InterfaceExt::recv) and [`read`](stdlib::network::ConnectionExt::read).
///
/// ```
/// use fictionet::prelude::*;
/// ```
pub mod prelude {
    pub use crate::InterfaceExt;
    pub use crate::stdlib::network::ConnectionExt;
    #[cfg(feature = "tokio")]
    pub use crate::tokio::ConnectionTokioExt;
}

pub use attach::{AttachError, Attacher, Attachment, Attachments, attachments};
pub use block_on::block_on;
pub use cable::{End, PACKET_COST, pair, pair_with_limit};
pub use clock::RunMode;
pub use cx::{CancelWait, Cancelled, Cx, JoinError, RaceError, Task, Timer};
pub use error::{Error, ErrorChain};
pub use interface::{Interface, InterfaceExt, LinkHandle, Packet, Recv, RecvError};
#[cfg(not(target_arch = "wasm32"))]
pub use listen::{Listening, ParseWorldSocketError, WorldSocket, listen};
pub use run::run;
pub use run::{RunOptions, lab};
mod clock;
pub use sys::random_bytes;

/// The result type of a world, and of most Fictionet functions that can
/// fail. Any error type that implements [`std::error::Error`], `Send` and
/// `Sync` converts into [`Error`] with `?`.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

#[cfg(doctest)]
#[doc(hidden)]
#[doc = include_str!("../README.md")]
mod readme {}

/// Includes tokens when the SDK's `tokio` feature is enabled.
///
/// An optional `else` block supplies the tokens for builds without the
/// feature. Prefix the branches with `items` to select item definitions.
#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! cfg_tokio {
    (items { $($enabled:tt)* } else { $($disabled:tt)* }) => { $($enabled)* };
    ({ $($enabled:tt)* } else { $($disabled:tt)* }) => {{ $($enabled)* }};
    ($($enabled:tt)*) => { $($enabled)* };
}

/// Includes tokens selected by the SDK's `tokio` feature.
#[cfg(not(feature = "tokio"))]
#[macro_export]
macro_rules! cfg_tokio {
    (items { $($enabled:tt)* } else { $($disabled:tt)* }) => { $($disabled)* };
    ({ $($enabled:tt)* } else { $($disabled:tt)* }) => {{ $($disabled)* }};
    ($($enabled:tt)*) => {};
}

/// Includes the standard library branch. Fictionet always uses `std`.
#[macro_export]
macro_rules! cfg_std {
    (items { $($enabled:tt)* } else { $($disabled:tt)* }) => { $($enabled)* };
    ({ $($enabled:tt)* } else { $($disabled:tt)* }) => {{ $($enabled)* }};
    ($($enabled:tt)*) => { $($enabled)* };
}

/// Includes tokens when the SDK's `web-proxy` feature is enabled.
///
/// An optional `else` block supplies the tokens for builds without the
/// feature. Prefix the branches with `items` to select item definitions.
#[cfg(feature = "web-proxy")]
#[macro_export]
macro_rules! cfg_web_proxy {
    (items { $($enabled:tt)* } else { $($disabled:tt)* }) => { $($enabled)* };
    ({ $($enabled:tt)* } else { $($disabled:tt)* }) => {{ $($enabled)* }};
    ($($enabled:tt)*) => { $($enabled)* };
}

/// Includes tokens selected by the SDK's `web-proxy` feature.
#[cfg(not(feature = "web-proxy"))]
#[macro_export]
macro_rules! cfg_web_proxy {
    (items { $($enabled:tt)* } else { $($disabled:tt)* }) => { $($disabled)* };
    ({ $($enabled:tt)* } else { $($disabled:tt)* }) => {{ $($disabled)* }};
    ($($enabled:tt)*) => {};
}
