//! Watching a running world: the dashboard, the `fictionet observe`
//! command, and the API they both use.
//!
//! Every world can be watched while it runs. You can see its tasks, the
//! links between them, how many packets cross each link, and the packets
//! themselves, decoded, with HTTPS decrypted. There is nothing to turn on
//! in world code. An observer connects to the world socket, the same socket
//! that [`fictionet attach`](crate::attaching) uses, and asks.
//!
//! # The dashboard
//!
//! With a world running on `/run/fictionet/world.sock`, start the dashboard
//! next to it with a private token file:
//!
//! ```text
//! $ (umask 077; openssl rand -hex 32 > /run/fictionet/dashboard-token)
//! $ fictionet dashboard --world unix:/run/fictionet/world.sock --token-file /run/fictionet/dashboard-token
//! fictionet dashboard: serving the world at /run/fictionet/world.sock on http://127.0.0.1:7878/
//! ```
//!
//! Open `http://127.0.0.1:7878/login?token=<token>` with the file's token.
//! Percent-encode the token if it contains URL punctuation. This URL works
//! once per dashboard process and sets an HttpOnly, SameSite=Strict cookie.
//! The browser then uses that cookie for the app, streams and downloads.
//! Restart the dashboard to sign in again. Scripts can send
//! `Authorization: Bearer <token>` instead. All requests, including
//! `/api/keylog` from loopback, require authentication.
//!
//! This is the `web_world` example with one sandbox, `agent`, fetching
//! pages with `curl`:
//!
#![doc = include_str!("../docs/diagrams/dashboard.svg")]
//!
//! The sandbox is on the left. Each box to its right is a task, placed by
//! how many links it is from the sandbox. Each line is a link, and it grows
//! thicker as more packets cross it. Dots move along it, one color for each
//! direction, while packets flow. A router's links carry the prefix that
//! routes to them, so you can read the network's addresses off the
//! drawing. Hover over a box or a line for its counts.
//!
//! Boxes with a stack of cards behind them are [groups](#groups): parts of
//! the world drawn as one box until you open them. Drag any box, or an
//! open group by its name, to move it. It stays where you drop it, the
//! lines follow, and the rest of the drawing keeps out of its way. The
//! dashboard remembers where you put things, and which groups you opened,
//! for each world, in your browser. Double-click the background, or press
//! the round arrow in the corner, to lay the drawing out again.
//!
//! Click a task to see where it was spawned, its links and its events.
//! Click a link to watch its packets. A list fills as packets cross,
//! with each packet's source, destination, protocol and a one-line
//! summary, as in Wireshark. Select one to see its layers, and its bytes
//! with the selected field marked. **Capture for Wireshark** downloads the
//! packets shown as a pcapng file.
//!
//! The dashboard is a separate program from the world. `fictionet
//! dashboard` serves a web page, built into the binary, and carries the
//! page's requests to the world as an observer:
//!
#![doc = include_str!("../docs/diagrams/observe.svg")]
//!
//! The dashboard shows everything the world carries, including the
//! decrypted contents of HTTPS. It listens on 127.0.0.1, where only
//! programs on the same machine can reach it. `--listen <ip:port>` picks
//! another address. HTTP carries the token in plaintext, so use loopback
//! or a trusted TLS tunnel. Keep the token and the world socket outside
//! the sandbox. Containers in one Kubernetes pod share loopback; binding
//! there does not keep the agent out.
//!
//! # From a shell
//!
//! `fictionet observe` makes one request and prints each value of the reply
//! as one line of JSON, for scripts and harnesses. (`pcap` and `keylog`
//! replies are binary, and are written out as they are.) The request follows the
//! flags: `world` reports whether the world runs, and `watch` prints the
//! graph of tasks and links, then every change to it. With no request,
//! `fictionet observe` prints the graph once:
//!
//! ```text
//! $ fictionet observe --world unix:/run/fictionet/world.sock world
//! {"observe":1,"fictionet":"0.1.0","running":true,"ended":false,"started":1790989827708,"t":123.285394}
//! $ fictionet observe --world unix:/run/fictionet/world.sock watch
//! {"event":"snapshot","data":{"t":123.288818,"started":1790989827708,"ended":false,"nodes":[{"id":"s7","kind":"sandbox","name":"agent"},...
//! {"event":"counters","data":{"t":123.538718,"edges":{"e2":[1642,110577,1642,117625],...}}}
//! {"event":"event","data":{"seq":527,"at":123.324772,"source":"dns","kind":"query",...,"fields":{"name":"example.test","qtype":1,...},"node":"t7",...}}
//! ```
//!
//! `watch` runs until you stop it. `fictionet observe --help` lists every
//! request. Links have ids such as `e7`, which the graph lists. To save a
//! link's packets, first watch it with `fictionet observe ... packets e7`
//! while traffic crosses it. Then, in another shell, while that command
//! still runs, `fictionet observe ... pcap e7 > agent.pcapng` saves what
//! it copied. A link that is not being watched has no packets to save.
//!
//! # What the graph shows
//!
//! **Each task is a node.** That is the world function, everything started
//! with [`Cx::spawn`](crate::Cx::spawn), and each stdlib function that runs
//! in the background, such as [`delay`](crate::stdlib::delay) or a
//! [`router`](crate::stdlib::route::router). A node shows a name and the
//! file and line that started it. A stdlib function shows its own name,
//! and the line in your code that called it, so `delay` called at
//! `world.rs:5` appears as `delay` at `world.rs:5`. Other tasks are named
//! after the function their future comes from.
//!
//! **Each sandbox is a node too**, with one link: its
//! [`Attachment`](crate::Attachment).
//!
//! **Each link is an edge.** A link is the two ends of a
//! [`pair`](crate::pair), or an `Attachment`. Fictionet implements both
//! ends, so it knows which task reads from each end, and counts the packets
//! and bytes each end sends. This works for any world, even one that only
//! moves raw packets.
//!
//! A task with no links, such as one per HTTP connection, is not drawn. The
//! side panel lists every task, grouped by where it was started, with how
//! many are running.
//!
//! # Groups
//!
//! A real network has parts: an office LAN, a data center, a host with a
//! dozen services. World code says which tasks make up one part with
//! [`Cx::group`](crate::Cx::group), which returns a `Cx` whose tasks belong
//! to a named group. Every task started with that `Cx` is in the group,
//! and so is every task those tasks start, the stdlib's own tasks
//! included. Groups nest. A sandbox belongs to the group of the task that
//! reads its [`Attachment`](crate::Attachment). This puts each simulated
//! machine of the `scan` example in a group of its own, inside a group for
//! all of them:
//!
//! ```
//! # use fictionet::{Cx, End, Result};
//! # use fictionet::stdlib::{ip, tcp};
//! fn machine(fcx: &Cx, side: End, name: &str, addr: std::net::IpAddr) -> Result {
//!     let host = fcx.group(format!("{name} {addr}"));
//!     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&host, side);
//!     let _ssh = tcp::endpoint(&host, tcp, addr).listen(22)?;
//!     Ok(())
//! }
//! # fn wire(fcx: Cx, sides: Vec<End>) -> Result {
//! let hosts = fcx.group("simulated hosts");
//! for (side, n) in sides.into_iter().zip(10u8..) {
//!     machine(&hosts, side, "www", std::net::Ipv4Addr::new(10, 0, 0, n).into())?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`web::Sites`](crate::stdlib::web::Sites) groups its own parts. One
//! group, `web::Sites`, holds its router and the rest. Inside it, the
//! gateway with its DNS server is a group, and so is each machine, named
//! after the first site placed at its address. Each sandbox's filter stays
//! outside, with its sandbox.
//!
//! The dashboard draws a closed group as one box. Its lines are the links
//! that cross the group's edge: links from one box to the same other box
//! are drawn as one line, with their packet and byte counts added up, and
//! links between two tasks inside the group are not drawn. Clicking such a
//! line opens a packet list with the packets of all of its links, merged
//! in time order, and **Capture for Wireshark** downloads them all, one
//! pcapng section per link.
//!
//! Double-click a closed group, or press its **+**, to open it where it
//! is. An open group is a frame around what it holds, with its name on
//! top: double-click the name, or press its **−**, to close it again.
//! Groups at the outermost level start open, unless they hold more than
//! 40 boxes. Groups inside them start closed. So `web_world` starts as its
//! sandbox and a few big boxes, and you open the one you want to look
//! into. When something inside a group is selected, a breadcrumb over the
//! drawing shows the groups around it, from the world down.
//!
//! Groups change nothing about how the world runs: a grouped `Cx` stays in
//! the same [region](crate::Cx#regions). [`Cx::group`](crate::Cx::group)
//! says what a group costs.
//!
//! # Events
//!
//! Every run keeps its [events](crate::events): what the stdlib's
//! services and network pieces saw, and what world code records with
//! [`Cx::record`](crate::Cx::record). The log keeps them whether or not
//! anyone watches, so an observer that connects late first sees what the
//! log still holds, then each new event as it comes. The dashboard lists
//! them under **Events**, each with the task that recorded it and the time
//! on the world's clock, and a click shows the task. The `web_world`
//! example's sites record one event per DNS query, TLS handshake and HTTP
//! request.
//!
//! ```
//! # use fictionet::Cx;
//! use fictionet::events::Event;
//! fn sold(fcx: &Cx, item: &str, count: u32) {
//!     fcx.record(Event::new("shop", "order").summary(format!("{count} × {item}")).field("item", item).field("count", count));
//! }
//! ```
//!
//! The core records events of its own. Packet drops are
//! [repeats](crate::events#repeats): the first of a run is recorded, the
//! rest counted in its `count` field.
//!
//! - [`bottleneck`](crate::stdlib::bottleneck) records the packets its
//!   full queue drops (`bottleneck.drop`), and the dashboard counts them on
//!   its node.
//! - A [router](crate::stdlib::route::router) records a route it removes
//!   because the route's interface closed (`router.route_removed`), and
//!   the packets it drops because their TTL or hop limit ran out
//!   (`router.drop`).
//! - A [LAN](crate::stdlib::route::lan) records the packets it drops
//!   (`lan.drop`) and each member replaced or gone (`lan.member_replaced`,
//!   `lan.member_removed`).
//!
//! # Packets, decoding and decryption
//!
//! Packets are copied only from a link that someone is watching, and only
//! while they watch. Each link copies the first 64 packets of every 100 ms.
//! Past that it copies one packet in two, then one in four, and so on, so a
//! busy link costs at most about 130 copies every 100 ms, or 1,300 a
//! second, however many packets cross it. The dashboard marks where
//! packets were skipped. A watched link keeps its
//! latest 4,096 decoded packets, up to 32 MiB, and keeps them for a minute
//! after the last observer stops watching it, for the detail pane and the
//! capture download.
//!
//! Each copy is decoded the way Wireshark decodes it. Packets on a link are
//! IPv4 or IPv6 with no Ethernet header. The decoder reads IP, TCP, UDP and
//! ICMP, then DNS, DHCP, HTTP/1.1, and HTTP/2 with its headers. HTTP/2 uses
//! [`http2::Capture`] through the public registry.
//! Recognized gRPC calls add message layers from DATA under a shared budget. TCP
//! connections are followed in order, so a message spread over several
//! packets is shown whole on the packet that completes it. An HTTP/2 header
//! that names a table entry the decoder could not follow, for example
//! because the packets that set it were not copied, is shown as not known.
//!
//! While an observer is following the world, the stdlib's TLS server keeps
//! the secrets of each new session. The world keeps its latest 20,000
//! secrets, about 4,000 sessions, and forgets older ones. The decoder uses them to decrypt TLS
//! 1.3 on watched links, so a link that carries HTTPS shows the HTTP inside
//! it. A session that started before anyone was following cannot be
//! decrypted. TLS 1.2 is shown encrypted. The capture download carries the
//! keys in the file itself, so Wireshark decrypts both versions with no
//! setting.
//!
//! # User protocols
//!
//! Implement [`Present`] on any [`Decode`](crate::stdlib::codec::Decode)
//! type, including a protocol copied into your crate. Its fields use ranges
//! relative to the item's raw bytes. [`Observed`] drives it through a
//! bounded stream; [`Placement`] maps those ranges through exact spans to
//! packet bytes, or keeps a separate buffer for a reassembled item.
//!
//! Add it to [`Registry`] with a matcher for ports or first bytes, or select
//! its name explicitly with [`Registry::choose`]. Built-ins register through
//! the same API. [`Dissector::with_registry`] decodes raw IP packets from a
//! pcap reader or live capture. [`Cx::observe_protocols`](crate::Cx::observe_protocols)
//! installs the registry for newly watched links, including the dashboard
//! and `fictionet observe` JSON output. Existing watches keep their state.
//!
//! # Who can observe
//!
//! Anyone who can open the world socket can observe the world, just as
//! anyone who can open it can attach a sandbox. The socket's file
//! permissions decide who that is. The agent cannot reach it over the
//! network: the sandbox's network leads only into the world, and the
//! socket is a file, not an address. Keep the socket out of the agent's
//! file system too, as the examples do. In the Docker Compose example in
//! [`attaching`](crate::attaching#in-docker-compose), the agent's container
//! mounts the world's CA certificate, and not the socket's directory.
//!
//! An observer sees everything the world carries, and its TLS keys, so give
//! access only to people and programs you would trust with that.
//!
//! An observer only reads. No request changes the world.
//!
//! # What it costs
//!
//! Each link counts its packets, as plain numbers under a lock that sending
//! already takes. Copying is one check of a flag per packet while no one
//! watches the link. On a benchmark that moves packets through a chain of
//! pairs, the difference is within the noise between runs: a median of
//! 31.9 ns per packet per hop, against 31.6 ns before the dashboard
//! existed.
//!
//! A 16 MiB HTTPS download from a sandbox through the web test's world
//! (`tests/web_fixture`) ran at a median of 442 MB/s with no observer,
//! 430 MB/s with one following the graph, and 468 MB/s with one watching
//! the sandbox's link.
//! Before the dashboard existed it ran at 461 MB/s. Runs varied more than
//! that, from about 300 to 600 MB/s.
//!
//! Each task's start and end, and each task's first use of a link end, take
//! one lock. A task that does nothing but read one end of a pair costs
//! about 165 ns more to spawn and end: a median of 586 ns, against 420 ns.
//! TLS keys and packet copies cost nothing until someone observes. Events
//! are recorded either way; [`events`](crate::events#what-it-costs) says
//! what that costs.
//!
//! Watching links is not free once traffic is heavy. Each watched packet
//! takes two locks, and the packets kept are decoded and turned into JSON
//! on the observer's thread. The `observe` group of the performance suite
//! (`cargo bench --bench perf -- observe`, see `CONTRIBUTING.md`) measures
//! this with ten sandboxes sending HTTPS requests, unwatched, with the graph
//! watched, and with all ten sandbox links watched.
//!
//! # The API
//!
//! Every observer speaks the same API. An observer connects to the world
//! socket and sends a `hello` with the type `observe`. The world accepts it
//! without taking a sandbox name. Then the observer sends requests, and the
//! world answers each with one or more values. The
//! [relay protocol](crate::proto#observer-sessions) describes the messages
//! that carry them. This section describes what they say.
//!
//! A request is a JSON object with an `op`, such as `{"op":"graph"}`. A
//! value is JSON, except where the table says binary. A request that fails
//! gets one value, `{"error":"..."}`, and nothing more.
//!
//! | `op` | Fields | Reply |
//! |---|---|---|
//! | `world` | | `{"observe":1,"fictionet":"0.1.0","running":true,"ended":false,"started":1790989827708,"t":123.28}` |
//! | `graph` | | the [graph](#the-graph) as it is now |
//! | `watch` | `after`: an event number, optional | a stream: the graph, then [what changes](#changes) |
//! | `counters` | | `{"t":..,"edges":{"e7":[p,b,p,b],..}}` for every link |
//! | `events` | `after`: an event number; `max`: at most this many, default 1,000 | `{"events":[..]}`, the [events](#events-1) after that one |
//! | `link` | `link`: such as `"e7"` | one edge, with its `counters` |
//! | `packets` | `link`, `after`: a packet number | a stream: `link`, then each [packet](#packets) |
//! | `packet` | `link`, `seq` | one packet's [layers and bytes](#packets) |
//! | `pcap` | `link` | binary: a pcapng file of the link's kept packets |
//! | `keylog` | | binary: the world's TLS keys, as an `SSLKEYLOGFILE` |
//! | `cancel` | `id`: a request id | `{"ok":true}`, and that stream ends |
//!
//! A stream is a series of values, each an object
//! `{"event":"<name>","data":<data>}`. It ends with
//! `{"event":"end","data":{"reason":"..."}}` when its link closes, the
//! world ends (a `watch` sends `ended` first), or it is cancelled.
//!
//! An observer finds the world's run the first time the world asks its
//! [`Attachments`](crate::Attachments) for a sandbox, with
//! [`next`](crate::Attachments::next) or [`get`](crate::Attachments::get).
//! Until then, `world` reports `"running":false`, and a `watch` sends
//! `{"event":"waiting","data":{}}`, then the graph once the world asks. A
//! world that does a long setup before it asks is not seen during that
//! setup.
//!
//! `packet` and `pcap` read the decoded packets of a link that is watched,
//! or was watched in the last minute. Send `packets` first. A packet's
//! `seq` numbers the packets of one watch, from 1.
//!
//! ## The graph
//!
//! `graph`, and the `snapshot` event that starts `watch`:
//!
//! ```text
//! {"t":12.5,"started":1790989827708,"ended":false,
//!  "nodes":[{"id":"t11","kind":"task","name":"net::filter","file":"src/stdlib/net.rs",
//!            "line":243,"parent":"t10","started":0.113998},
//!           {"id":"s7","kind":"sandbox","name":"agent"}],
//!  "edges":[{"id":"e7","a":"t11","b":"s7","label":null}],
//!  "counters":{"e7":[95987,136344354,56916,2816859]},
//!  "events":[...]}
//! ```
//!
//! - `t` is seconds since the world started, on its clock. `started` is
//!   when it started, in milliseconds since the Unix epoch.
//! - A node's `kind` is `world` (the world function), `task` or `sandbox`.
//!   A task has `name`, `file`, `line`, `parent` (the task that spawned it,
//!   or `null`), `group` and `started`. A sandbox has its `name` and
//!   `group`. `group` is the id of the [group](#groups) the node belongs
//!   to, or `null`.
//! - `groups` lists every group that holds a node, directly or in a group
//!   inside it, each with its `id`, `name` and `parent` (the group it is
//!   inside, or `null`). Follow `parent` from a node's group to get its
//!   path:
//!
//!   ```text
//!   "groups":[{"id":"g1","name":"simulated hosts","parent":null},
//!             {"id":"g2","name":"www 10.0.0.10","parent":"g1"},...],
//!   "nodes":[{"id":"t3","kind":"task","name":"split_protocols","file":"examples/scan/main.rs",
//!             "line":132,"parent":"t1","group":"g2","started":0.000015},
//!            {"id":"s21","kind":"sandbox","name":"scanner","group":"g6"},...]
//!   ```
//! - An edge joins nodes `a` and `b`. When one end is a sandbox, it is `b`.
//!   `label` is the prefix a router sends to that link, or `null`.
//! - `counters` gives each edge four numbers: packets and bytes sent by
//!   `a`, then packets and bytes sent by `b`.
//! - Ids are strings: `t` and a number for a task, `s` for a sandbox, `e`
//!   for a link, `g` for a group. A task's or group's id is never used
//!   again in one run.
//!
//! ## Changes
//!
//! After the snapshot, `watch` sends what changed, four times a second:
//!
//! - `node` and `edge`: one that is new, or changed (an edge whose end
//!   moved to another task), in the snapshot's form.
//! - `edge_end` and `node_end`: `{"id":".."}` for one that is gone. Edges
//!   go before the nodes they joined.
//! - `group` and `group_end`: a group that is new, in the snapshot's form,
//!   and `{"id":".."}` for one that no longer holds any node. A new group
//!   comes before the nodes in it, and `group_end` after them.
//! - `counters`: `{"t":..,"edges":{..}}`, only the links whose counts
//!   changed. Counts only grow, so a rate is the difference over the time.
//! - `event`: one new [event](#events-1). With `after`, `watch` first
//!   sends every event the log holds after that number, a thousand every
//!   quarter second, then each new one: `"after":0` replays the whole log.
//! - `ended`: `{"t":..}`, once the world has ended.
//!
//! Clients should ignore events and fields they do not know.
//!
//! ## Events
//!
//! An event, in the `events` reply, the snapshot and the `event` messages
//! of `watch`, is [`Event::to_json`](crate::events::Event::to_json):
//!
//! ```text
//! {"seq":527,"at":123.32,"source":"dns","kind":"query","level":"info",
//!  "summary":"example.test A: 203.0.113.10","sandbox":{"id":1,"name":"agent",
//!  "addr":"10.0.0.2","addr_v6":null},"conn":null,"local":null,"peer":"10.0.0.2:47583",
//!  "transport":"tcp","tls":false,"sni":null,"alpn":null,
//!  "fields":{"name":"example.test","qtype":1,...},
//!  "node":"t7","task":"net::serve_dns","file":"src/stdlib/net.rs","line":1750,"parent":"t1"}
//! ```
//!
//! `seq` numbers the run's events from 1, with no gaps, and `at` is when it
//! happened, in seconds on the world's clock. `tls` says whether the
//! connection was TLS, and `sni` and `alpn` are what its handshake named
//! and agreed. `node` is the task that
//! recorded it, and `task`, `file`, `line` and `parent` describe that task,
//! since a short task may have ended before anyone reads the event. The
//! world keeps its latest 50,000 events, up to 16 MiB of them, and apart
//! from them its latest 5,000 [repeats](crate::events#repeats). Where a
//! reader asks for events the log no longer holds, an `events.dropped`
//! event stands in their place, whose `count` field says how many it
//! missed.
//!
//! ## Packets
//!
//! Each `packet` event of a `packets` stream is one line of the list:
//!
//! ```text
//! {"seq":12401,"t":95.838490,"side":0,"len":85,"skipped":0,"src":"10.0.0.1:53",
//!  "dst":"10.0.0.2:47583","proto":"DNS",
//!  "info":"Standard query response 0x8d89 A example.test A 203.0.113.10","tags":[]}
//! ```
//!
//! `side` is 0 for a packet sent by the edge's `a`, 1 for one sent by `b`.
//! `skipped` counts the packets before this one that were not copied.
//! `tags` can hold `decrypted`, `retransmission`, `reset`, `fragment`,
//! `gap`, `malformed` and `dns-error`.
//!
//! `packet` gives one packet's `layers` and `buffers`. Each layer has a
//! `name`, a `summary`, and `fields`, each with a `name` and `value`. A
//! layer's `range`, and a field's, if it has one, is `[start, end)` in the
//! buffer numbered `buf`. Buffer 0 is the packet itself. Others hold
//! decrypted TLS, or a message put together from several packets, each with
//! a `name` and its bytes as `hex`. One packet's layers and buffers hold
//! about 1 MiB at most. A packet that completes more than that, such as one
//! that fills a gap many held packets waited on, ends with a layer named
//! `Not shown` that counts what was left out.
//!
//! ## Versions
//!
//! This is version 1 of the API, as `world` reports in `observe`. Version 1
//! may gain requests, fields and events. It will not lose or change them.
//! A version that does will be offered under a new `hello` type that starts
//! with `observe`, such as `observe2`. A world refuses a type that starts
//! with `observe` and that it does not know, with its reason.
//!
//! Groups are part of version 1: the `groups` list, the `group` field of
//! each node, and the `group` and `group_end` events. A client that
//! ignores them, as clients should ignore what they do not know, draws
//! every task on its own.

mod conversation;
/// Copyable HTTP/2 and gRPC presentation.
#[cfg(feature = "observe")]
pub mod http2;
/// Copyable capture decoders and presenters for the built-in protocols.
#[cfg(feature = "observe")]
pub mod protocols;
/// Copyable TLS record presentation, handshake state, and decryption.
#[cfg(feature = "observe")]
pub mod tls;

pub use conversation::Conversation;
#[cfg(feature = "observe")]
pub use packets::hex;
mod present;
mod registry;

pub use crate::watch::KeyLine;
pub use decode::{Decoded, Dissector, Field, Layer};
pub use present::{Observed, Place, Placement, Present};
pub use registry::{Match, Protocol, Registry, Selection};

#[cfg(feature = "observe")]
mod app;
mod decode;
mod json;
mod keys;
#[cfg(feature = "observe")]
mod packets;
#[cfg(feature = "observe")]
mod pcap;
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
mod session;
#[cfg(feature = "observe")]
mod view;

#[cfg(feature = "observe")]
use fictionet::sync::Mutex;
use std::sync::Arc;
#[cfg(feature = "observe")]
use std::time::Duration;

use crate::Cx;
#[cfg(feature = "observe")]
use crate::watch::Graph;
pub use keys::observed_config;
#[cfg(feature = "observe")]
pub(crate) use packets::LinkWatch;

/// How long a link's decoded packets are kept after the last observer
/// stopped asking for them.
#[cfg(feature = "observe")]
const WATCH_LINGER: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(60)
};
/// How often the reaper looks for watches to forget.
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
const REAP_EVERY: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(5)
};

/// Serves one observer session on `fd`, which has been accepted on the
/// world socket of `attacher`.
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
pub(crate) fn serve_session(attacher: crate::Attacher, fd: std::os::fd::OwnedFd) {
    session::start(attacher, fd);
}

/// Forgets the watches that have had no subscriber for a minute.
#[cfg(feature = "observe")]
pub(crate) fn reap(graph: &Graph) {
    graph
        .watches
        .lock()
        .retain(|_, w| !w.idle_for(WATCH_LINGER));
}

/// The worlds with watches that may need forgetting, and whether the
/// reaper thread runs.
///
/// Locks are taken in this order: this, then a graph's `watches`, then a
/// watch's own. So nothing calls [`reap_later`] while it holds either of
/// the others.
#[cfg(feature = "observe")]
static REAPER: Mutex<(Vec<std::sync::Weak<Graph>>, bool)> = Mutex::new((Vec::new(), false));

/// Makes sure `graph`'s watches are forgotten once idle for a minute, even
/// if no observer asks anything more. Called when the last subscriber of a
/// watch leaves.
#[cfg(feature = "observe")]
pub(crate) fn reap_later(graph: &Arc<Graph>) -> std::io::Result<()> {
    graph.environment.require_real_io()?;
    let mut reaper = REAPER.lock();
    if !reaper
        .0
        .iter()
        .any(|g| std::ptr::eq(g.as_ptr(), Arc::as_ptr(graph)))
    {
        reaper.0.push(Arc::downgrade(graph));
    }
    if !reaper.1 {
        reaper.1 = start_reaper();
    }
    Ok(())
}

/// Starts the thread that reaps the worlds in [`REAPER`]. Returns whether
/// it runs.
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
fn start_reaper() -> bool {
    std::thread::Builder::new()
        .name("fictionet-reaper".into())
        .spawn(|| {
            loop {
                std::thread::sleep(REAP_EVERY);
                let mut reaper = REAPER.lock();
                // A world that ended, or has no watches left, needs no more.
                reaper.0.retain(|g| {
                    g.upgrade().is_some_and(|g| {
                        reap(&g);
                        !g.watches.lock().is_empty()
                    })
                });
                if reaper.0.is_empty() {
                    reaper.1 = false;
                    return;
                }
            }
        })
        .is_ok()
}

/// A browser has no thread for the reaper. Idle watches there are
/// forgotten when the next watch starts.
#[cfg(all(feature = "observe", target_arch = "wasm32"))]
fn start_reaper() -> bool {
    false
}

/// The watch of link `id` in `graph`, made if needed, and a subscription
/// to it. Both are taken under the lock the reaper takes, so the reaper
/// cannot forget the watch between them.
#[cfg(feature = "observe")]
pub(crate) fn watch(
    graph: &Arc<Graph>,
    id: u64,
) -> Option<(Arc<LinkWatch>, packets::Subscription)> {
    reap(graph);
    let mut watches = graph.watches.lock();
    let w = match watches.get(&id) {
        Some(w) => w.clone(),
        None => {
            let w = Arc::new(LinkWatch::start(graph, id)?);
            watches.insert(id, w.clone());
            w
        }
    };
    let subscription = w.subscribe();
    Some((w, subscription))
}

/// The watch of link `id`, if one is kept.
#[cfg(feature = "observe")]
pub(crate) fn existing_watch(graph: &Graph, id: u64) -> Option<Arc<LinkWatch>> {
    graph.watches.lock().get(&id).cloned()
}

/// An opaque link an [`Interface`](crate::Interface) belongs to.
/// Use [`LinkHandle::label`] to name it for observers.
#[derive(Clone)]
pub struct LinkHandle(Arc<crate::watch::Meter>);

impl LinkHandle {
    pub(crate) fn new(meter: Arc<crate::watch::Meter>) -> Self {
        Self(meter)
    }

    /// Names this link in `fcx`'s observation graph.
    /// Replaces any label already set for this link in that run.
    pub fn label(&self, fcx: &Cx, label: String) {
        fcx.graph().label(&self.0, label);
    }
}

impl std::fmt::Debug for LinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LinkHandle").field(&self.0.id).finish()
    }
}

#[cfg(all(test, feature = "observe"))]
mod tests {
    use super::*;

    #[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
    #[test]
    fn lab_refuses_the_observer_reaper() {
        crate::block_on(crate::lab(
            crate::Seed::from_u64(0),
            move |fcx| async move {
                assert!(
                    reap_later(fcx.graph())
                        .unwrap_err()
                        .to_string()
                        .contains("lab")
                );
                assert!(
                    !REAPER
                        .lock()
                        .0
                        .iter()
                        .any(|g| std::ptr::eq(g.as_ptr(), Arc::as_ptr(fcx.graph())))
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A link is copied only while a `packets` stream subscribes, and a
    /// kept watch does not keep its world alive.
    #[test]
    fn watches_copy_only_while_subscribed() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        graph.task_started(1, "world".into(), std::panic::Location::caller(), None);
        let (w, sub) = watch(&graph, meter.id).unwrap();
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        w.pump();
        assert_eq!(w.rows_after(0, 10).len(), 1);
        drop(sub);
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        w.pump();
        assert_eq!(
            w.rows_after(0, 10).len(),
            1,
            "nothing is copied with no subscriber"
        );
        // The decoded rows stay for a while, for `packet` and `pcap`.
        assert!(existing_watch(&graph, meter.id).is_some());
        drop(w);
        let weak = Arc::downgrade(&graph);
        drop(graph);
        assert!(
            weak.upgrade().is_none(),
            "the kept watch held its world alive"
        );
    }

    #[test]
    fn a_world_registry_reaches_watch_json_without_a_socket() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let watched = graph.clone();
        crate::block_on(crate::run::run_with(graph, move |fcx| async move {
            let mut registry = Registry::new();
            registry.register(
                "custom",
                |s| {
                    if s.ports.0 == 9000 || s.ports.1 == 9000 {
                        Match::Yes
                    } else {
                        Match::No
                    }
                },
                |_| [protocols::Modbus::new(true), protocols::Modbus::new(false)],
            );
            fcx.observe_protocols(registry);
            let meter = Meter::new();
            watched.owns(&meter, 0, 1);
            let (watch, _subscription) = watch(&watched, meter.id).unwrap();
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&52u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
            packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
            packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
            packet[22..24].copy_from_slice(&9000u16.to_be_bytes());
            packet[32] = 0x50;
            packet[33] = 0x18;
            packet.extend_from_slice(&[0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1]);
            meter.sent(0, &crate::Packet(packet));
            watch.pump();
            let rows = watch.rows_after(0, 10);
            assert_eq!(rows.len(), 1);
            assert!(rows[0].1.contains(r#""proto":"Modbus/TCP""#));
            let detail = watch.detail(rows[0].0).unwrap();
            assert!(detail.contains(r#""buf":0,"range":[40,52]"#), "{detail}");
            assert!(detail.contains("address 2, quantity 1"), "{detail}");
            Ok(())
        }))
        .unwrap();
    }

    /// A watch with no subscriber is forgotten after the linger time,
    /// even when no observer asks anything more.
    #[test]
    fn idle_watches_are_forgotten_without_more_requests() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        drop(watch(&graph, meter.id).unwrap());
        assert!(existing_watch(&graph, meter.id).is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while existing_watch(&graph, meter.id).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the idle watch was kept"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // A watch taken again is subscribed to as it is found, so the
        // reaper keeps the one the stream follows.
        let (w, _sub) = watch(&graph, meter.id).unwrap();
        std::thread::sleep(WATCH_LINGER * 2);
        assert!(Arc::ptr_eq(&existing_watch(&graph, meter.id).unwrap(), &w));
    }

    /// `filter` shows as `filter`, at the line that called it.
    #[test]
    fn filter_reports_its_caller() {
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            let (a, _b) = crate::pair();
            let line = line!() + 1;
            let _f = crate::stdlib::filter(&fcx, a, |_, _, _| true);
            let tasks: Vec<_> = fcx.graph().state().tasks.values().cloned().collect();
            assert!(
                tasks
                    .iter()
                    .any(|t| t.name == "filter" && t.file == file!() && t.line == line),
                "{tasks:?}"
            );
            Ok(())
        }))
        .unwrap();
    }

    /// A router records a route it removes, with no observer.
    #[test]
    fn routers_record_routes_they_remove() {
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            let (a, b) = crate::pair();
            let (c, d) = crate::pair();
            let router =
                crate::stdlib::route::router(&fcx, vec![("10.0.0.0/24".parse().unwrap(), a)]);
            router.add("10.0.1.0/24".parse().unwrap(), c);
            assert!(!fcx.observed());
            drop(b);
            fcx.sleep(Duration::from_millis(10)).await?;
            let removed = fcx.events().of("router", "route_removed");
            assert_eq!(removed.len(), 1);
            assert_eq!(removed[0].str("prefix"), Some("10.0.0.0/24"));
            drop(d);
            Ok(())
        }))
        .unwrap();
    }
}
