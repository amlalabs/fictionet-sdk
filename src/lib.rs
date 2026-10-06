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
//! Use it to build evals, RL environments and tests where the network is part of
//! the task: a tampered website, a slow or lossy link, a hijacked route, an
//! impostor service. The repository's examples include an eval that serves
//! agents tampered Wikipedia, gov.uk and BBC pages, and one with a BGP
//! hijack and an impostor bank. [`recipes`] shows the pieces they are
//! built from, with commands to run: a delayed website, a slow or lossy
//! link, a packet capture and a route that changes mid-run.
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
//! attach can take that interface down first: [How `tun`
//! works](attaching#how-tun-works) explains this.
//!
#![doc = include_str!("../docs/diagrams/attach.svg")]
//!
//! This command, run as root on the host, attaches the network namespace
//! `/run/netns/agent` as a sandbox named `agent`. `--world` names the
//! world's socket, `--name` the sandbox, and `--type tun` asks for a
//! `tun0` device. `--netns` is the namespace to put it in. The last six
//! flags give the sandbox an address, a gateway and a DNS server inside
//! the world, for both IPv4 and IPv6, because attach runs no DHCP for
//! `tun`:
//!
//! ```text
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
//!     --netns /run/netns/agent \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! ```
//!
//! Sandboxes can attach and detach at any time while the world runs. Each
//! one has a name, and the world receives it as an [`Attachment`]. A
//! virtual machine attaches through its network card instead
//! (`--type tap`). A sandbox that cannot have a network device, because it
//! has no privileges at all, can attach through a proxy (`--type
//! https_proxy` or `--type socks5`). [`attaching`] covers every setup: a
//! namespace on the host, Docker Compose, Kubernetes, hosted sandboxes, the
//! proxy and VMs. Whatever the type, the world receives IP packets:
//! [`lowering`] shows how each type turns what its sandbox sends into
//! them.
//!
//! # A world in code
//!
//! A world is an async function. It receives a context ([`Cx`], described
//! below), the sandboxes that attach to it ([`Attachments`]), and its
//! command-line arguments. Here is the start of one:
//!
//! ```
//! use fictionet::{Attachments, Cx, Result, stdlib, time::ms};
//!
//! async fn world(cx: Cx, mut attachments: Attachments, args: Vec<String>) -> Result {
//!     let agent = attachments.get(&cx, "agent").await?;
//!     let link = stdlib::delay(&cx, ms(50), agent);
//!     let (v4, v6, _) = stdlib::ip::split_versions(&cx, link);
//!     // route v4 and v6 with stdlib::route::router(&cx, ...)
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
//!   [What ends what](running#what-ends-what) lists every case.
//! - [`Packet`] holds the raw bytes of one IP packet.
//!
//! These types, at the crate root, are the core of Fictionet. The core
//! moves packets but never parses them. Addresses, ports, names, routing,
//! TCP, TLS and HTTP are all in [`stdlib`], built on these types. For a
//! whole network of websites in a few lines, see [`stdlib::web`]. The core
//! also assumes no async runtime:
//! its futures use only [`std::task::Waker`], so a world runs on tokio or
//! on Fictionet's own [`block_on`].
//!
//! # Running a world
//!
//! Fictionet does not own `main` or the executor. A world runs inside an
//! ordinary program, and this is the whole of `main`:
//!
//! ```no_run
//! # use fictionet::{Attachments, Cx, Result};
//! # async fn world(_cx: Cx, _attachments: Attachments, _args: Vec<String>) -> Result { Ok(()) }
//! fn main() -> fictionet::Result {
//!     let (attacher, attachments) = fictionet::attachments();
//!     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
//!     let _listening = fictionet::listen(socket, attacher)?;
//!     let args = std::env::args().skip(1).collect();
//!     fictionet::block_on(fictionet::run(|cx| world(cx, attachments, args)))
//! }
//! ```
//!
//! [`attachments`] makes the channel that sandboxes arrive through.
//! [`listen`] opens the world socket that the [`WorldSocket`] names, so
//! that each `fictionet attach` that connects arrives in that channel.
//! [`run`] turns the world function into one future, and [`block_on`]
//! polls it until the world ends. Each world is
//! its own process, with no central daemon. It has the host's real network,
//! so world code can also reach the internet or a database.
//! [`running`] explains each step, how a world stops, and how to run one in
//! a test with no socket at all.
//!
//! # Where to go next
//!
//! 1. [`getting_started`]: from `cargo build` to an HTTPS request from a
//!    sandbox, with every command and its output.
//! 2. [`running`]: the program around a world, and worlds in tests.
//! 3. [`attaching`]: every way to attach a sandbox, its addresses and DNS,
//!    and how to check that it works.
//! 4. [`lowering`]: how each attach type turns what its sandbox sends
//!    into IP packets, and what the world sees from each.
//! 5. [`stdlib`], and then [`stdlib::web`]: the networking pieces a world
//!    is built from, and a whole network of websites in a few lines.
//! 6. [`recipes`]: a delayed website, a slow or lossy link, a packet
//!    capture, and a route that changes mid-run.
//! 7. [`observe`]: watching a running world, in the dashboard or from a
//!    shell, and sending your own events from world code.
//! 8. [`proto`]: the protocol between attach and a world, if you want to
//!    write your own attach.
//! 9. [`roadmap`]: what is planned, such as attaching remote sandboxes.
//!
//! # Features and dependencies
//!
//! The crate has one Cargo feature, and it is on by default:
//!
//! | Feature | What it adds | Dependencies it adds |
//! |---|---|---|
//! | `tokio` (default) | `fictionet::tokio`, which hands stdlib connections to tokio-based libraries such as hyper and axum, and `web::proxy()`, which passes requests through to the real site | `hyper-util`, `hyper-rustls` with `webpki-roots`, and hyper's client |
//!
//! The `tokio` runtime crate itself is always a dependency, because hyper
//! and h2 run on it, and so are `rustls` (with the `ring` provider), `hyper`
//! (server side), `h2`, `smoltcp` and `hickory-proto`. A world that needs
//! neither `fictionet::tokio` nor `web::proxy` can leave the feature out
//! with `default-features = false`.

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Protocol files use the same imports here and when copied into a user crate.
extern crate self as fictionet;

mod attach;
pub mod attaching;
mod cable;
mod cx;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
pub mod observe;
pub mod getting_started;
mod listen;
pub mod lowering;
#[doc(hidden)]
pub mod relay;
mod run;
pub mod running;
mod timer;
mod watch;
pub mod proto;
pub mod recipes;
pub mod roadmap;
pub mod stdlib;
pub mod time;
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio;

/// The extension traits. Import this to call methods such as
/// [`recv`](InterfaceExt::recv) and [`read`](stdlib::ConnectionExt::read).
///
/// ```
/// use fictionet::prelude::*;
/// ```
pub mod prelude {
    pub use crate::InterfaceExt;
    pub use crate::stdlib::ConnectionExt;
    #[cfg(feature = "tokio")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub use crate::tokio::ConnectionTokioExt;
}

pub use attach::{AttachError, Attachment, Attacher, Attachments, attachments};
pub use cable::{End, pair};
pub use cx::{Cancelled, Cx, Task};
pub use listen::{Listening, ParseWorldSocketError, WorldSocket, block_on, listen};
pub use run::run;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The result type of a world, and of most Fictionet functions that can
/// fail. Any error type that implements [`std::error::Error`], `Send` and
/// `Sync` converts into [`Error`] with `?`.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Any error a world returns: a boxed [`std::error::Error`].
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// One IPv4 or IPv6 packet, exactly the bytes on the wire.
///
/// The core never parses a packet, so a program can send a broken one on
/// purpose. Parsing lives in [`stdlib`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet(pub Vec<u8>);

/// Why [`recv`](InterfaceExt::recv) returned no packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// The other end is gone, and every packet it sent has been received.
    Closed,
    /// The [region](Cx#regions) of the `Cx` passed to `recv` was cancelled.
    Cancelled,
}

/// Something that sends and receives packets: one end of a two-way
/// packet link.
///
/// Whatever is sent into one end comes out of the other. An interface is
/// the one shape every part of a world shares. A sandbox reaches the world
/// as an [`Attachment`], which is an interface. [`pair`] makes two
/// connected interfaces inside the world. Every stdlib function that moves
/// packets takes interfaces and returns new ones, so the pieces of a
/// network plug into each other.
///
/// Dropping one end closes the link. The other end then receives every
/// packet that was already sent to it, and after that
/// [`recv`](InterfaceExt::recv) returns [`RecvError::Closed`]. That
/// holds for one interface. A chain of them, such as a sandbox behind a
/// [`stdlib::delay`], may lose packets on the way: each stdlib task stops
/// when its region is cancelled, and on `Closed` by its own rule. A
/// `delay` stops as soon as either side closes, and drops what it still
/// holds. [Three kinds of functions](stdlib#three-kinds-of-functions)
/// lists the rule of each.
///
/// An interface holds no borrowed references (it is `'static`), because
/// most interfaces end up inside background tasks. Such a task can outlive
/// the function that started it, but not its owning [region](Cx#regions)
/// (see [What ends what](running#what-ends-what)).
///
/// An interface is `Send`: it can move to another thread, for example into
/// a tokio task.
///
/// # Using an interface
///
/// Call [`recv`](InterfaceExt::recv) and `.await` it, after
/// `use fictionet::prelude::*`. Call [`send`](Interface::send) directly.
/// The trait itself holds only the two methods a new kind of interface must
/// implement. Everything built on them is in [`InterfaceExt`].
///
/// Interfaces of different types can share one list as
/// `Box<dyn Interface>`, which is itself an `Interface`.
pub trait Interface: Send + 'static {
    /// Polls for the next packet from the other end.
    ///
    /// Returns `Poll::Pending` and arranges for `task` to be woken when a
    /// packet arrives, the other end closes, or `cx`'s region is cancelled.
    ///
    /// Callers use [`recv`](InterfaceExt::recv) instead. It is a polling
    /// method, not an `async fn`, so that `Box<dyn Interface>` works without
    /// allocating per packet. `std::future::Future` is built the same way.
    fn poll_recv(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<Packet, RecvError>>;

    /// Sends a packet to the other end.
    ///
    /// This never waits, so it takes no context and cannot be cancelled. If
    /// the other end is gone, the packet is lost, as on an unplugged network
    /// link.
    ///
    /// An interface from [`pair`] has no size limit, so its `send` never
    /// drops a packet while the other end exists. To model a link whose
    /// queue fills up and drops packets, add one on purpose with
    /// [`stdlib::bottleneck`].
    ///
    /// An [`Attachment`] is different, because its packets leave the
    /// process. When the connection to `fictionet attach` is full, the packet
    /// waits in a queue inside the world, and the queue is written out in
    /// order as attach makes room. The queue has a budget of 32 MiB. Each
    /// waiting packet counts its own length plus 64 bytes. A packet that
    /// would take the queue past that budget is dropped. See [`listen`].
    fn send(&mut self, packet: Packet);

    /// The link this interface is one end of, for the
    /// [dashboard](crate::dashboard). Only [`End`] and [`Attachment`] have
    /// one.
    #[doc(hidden)]
    fn observe_link(&self) -> Option<observe::LinkHandle> {
        None
    }
}

impl Interface for Box<dyn Interface> {
    fn poll_recv(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        (**self).poll_recv(cx, task)
    }

    fn send(&mut self, packet: Packet) {
        (**self).send(packet)
    }

    fn observe_link(&self) -> Option<observe::LinkHandle> {
        (**self).observe_link()
    }
}

/// What every [`Interface`] can do, built on its two methods.
///
/// Implemented for every interface. Imported by [`prelude`].
pub trait InterfaceExt: Interface {
    /// Waits for the next packet from the other end.
    ///
    /// Returns [`RecvError::Closed`] once the other end is gone and every
    /// packet it sent has been received. Returns early with
    /// [`RecvError::Cancelled`] if `cx`'s [region](Cx#regions) is cancelled.
    /// So a loop that waits on `recv` stops on its own when its region is
    /// cancelled, with no extra code.
    fn recv<'a>(&'a mut self, cx: &'a Cx) -> Recv<'a, Self> {
        Recv { interface: self, cx }
    }
}

impl<I: Interface + ?Sized> InterfaceExt for I {}

/// The future returned by [`recv`](InterfaceExt::recv).
pub struct Recv<'a, I: ?Sized> {
    interface: &'a mut I,
    cx: &'a Cx,
}

impl<I: Interface + ?Sized> Future for Recv<'_, I> {
    type Output = Result<Packet, RecvError>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.interface.poll_recv(this.cx, task)
    }
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvError::Closed => f.write_str("the other end of the interface is gone"),
            RecvError::Cancelled => f.write_str("the region was cancelled"),
        }
    }
}

impl std::error::Error for RecvError {}

/// The README's example, `docs/readme/sites.rs`, compiled as a doctest.
/// `tests/readme.rs` checks that the README shows exactly that file.
#[cfg(doctest)]
#[doc = concat!(
    "```\n",
    "# use std::net::Ipv4Addr;\n",
    "# use std::sync::Arc;\n",
    "# use fictionet::{Attachments, Cx, Result, stdlib::web};\n",
    "# use rustls::ServerConfig;\n",
    "# struct Certs { wikipedia: Arc<ServerConfig>, stripe: Arc<ServerConfig> }\n",
    "# async fn world(cx: Cx, attachments: Attachments, wiki: axum::Router, fake_stripe: axum::Router, certs: Certs) -> Result {\n",
    include_str!("../docs/readme/sites.rs"),
    "# Ok(())\n",
    "# }\n",
    "```\n",
)]
pub struct ReadmeExample;
