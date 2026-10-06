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
//! next to it and open the address it prints:
//!
//! ```text
//! $ fictionet dashboard --world unix:/run/fictionet/world.sock
//! fictionet dashboard: serving the world at /run/fictionet/world.sock on http://127.0.0.1:7878/
//! ```
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
//! another address. Give it one on a network you trust.
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
//! {"observe":1,"fictionet":"0.0.0","running":true,"ended":false,"started":1790989827708,"t":123.285394}
//! $ fictionet observe --world unix:/run/fictionet/world.sock watch
//! {"event":"snapshot","data":{"t":123.288818,"started":1790989827708,"ended":false,"nodes":[{"id":"s7","kind":"sandbox","name":"agent"},...
//! {"event":"counters","data":{"t":123.538718,"edges":{"e2":[1642,110577,1642,117625],...}}}
//! {"event":"note","data":{"seq":527,"t":123.324772,"node":"t7","kind":"event","task":"names::serve_udp",...,"name":"dns_query","data":{"sandbox":"agent","name":"example.test","answer":"203.0.113.10"}}}
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
//! fn machine(cx: &Cx, side: End, name: &str, addr: std::net::IpAddr) -> Result {
//!     let host = cx.group(format!("{name} {addr}"));
//!     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&host, side);
//!     let _ssh = tcp::endpoint(&host, tcp, addr).listen(22)?;
//!     Ok(())
//! }
//! # fn wire(cx: Cx, sides: Vec<End>) -> Result {
//! let hosts = cx.group("simulated hosts");
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
//! # Custom events
//!
//! World code can send events of its own. Observers see each one with the
//! task that sent it and the time on the world's clock. The dashboard lists
//! them under **Events**, and a click shows the task. The `web_world`
//! example sends one per HTTP request:
//!
//! ```
//! # use fictionet::Cx;
//! # use fictionet::stdlib::web;
//! fn observed(cx: &Cx, event: &web::Event) {
//!     if let web::Event::Http(h) = event {
//!         cx.event("http_request")
//!             .str("method", h.method.as_str())
//!             .str("path", h.uri.path())
//!             .int("status", h.status.map_or(0, |s| s.as_u16()))
//!             .emit();
//!     }
//! }
//! ```
//!
//! [`Cx::event`](crate::Cx::event) builds a flat JSON object field by
//! field. [`Cx::emit`](crate::Cx::emit) takes any JSON text, such as the
//! output of `serde_json`. Both cost almost nothing while no observer is
//! following the world: the event is never made, and nothing is kept.
//! [`Cx::observed`](crate::Cx::observed) tells you whether an observer is
//! following, so you can skip expensive work too.
//!
//! The stdlib sends events of its own:
//!
//! - [`bottleneck`](crate::stdlib::bottleneck) reports each packet its full
//!   queue drops, and the dashboard counts them on its node.
//! - A [router](crate::stdlib::route::router) reports a route it removes
//!   because the route's interface closed.
//! - The [TLS](crate::stdlib::tls) server reports each session whose keys
//!   it kept (see below).
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
//! ICMP, then DNS, DHCP, HTTP/1.1, and HTTP/2 with its headers. TCP
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
//! A 16 MiB HTTPS download from a sandbox through the `web_world` example
//! ran at a median of 442 MB/s with no observer, 430 MB/s with one
//! following the graph, and 468 MB/s with one watching the sandbox's link.
//! Before the dashboard existed it ran at 461 MB/s. Runs varied more than
//! that, from about 300 to 600 MB/s.
//!
//! Each task's start and end, and each task's first use of a link end, take
//! one lock. A task that does nothing but read one end of a pair costs
//! about 165 ns more to spawn and end: a median of 586 ns, against 420 ns.
//! Events, TLS keys and packet copies cost nothing until someone observes.
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
//! | `world` | | `{"observe":1,"fictionet":"0.0.0","running":true,"ended":false,"started":1790989827708,"t":123.28}` |
//! | `graph` | | the [graph](#the-graph) as it is now |
//! | `watch` | | a stream: the graph, then [what changes](#changes) |
//! | `counters` | | `{"t":..,"edges":{"e7":[p,b,p,b],..}}` for every link |
//! | `notes` | `after`: a note number | `{"notes":[..]}`, the [notes](#notes) after that one |
//! | `link` | `link`: such as `"e7"` | one edge, with its `counters` |
//! | `packets` | `link`, `after`: a packet number | a stream: `link`, then each [packet](#packets) |
//! | `packet` | `link`, `seq` | one packet's [layers and bytes](#packets) |
//! | `pcap` | `link` | binary: a pcapng file of the link's kept packets |
//! | `keylog` | | binary: the world's TLS keys, as an `SSLKEYLOGFILE` |
//! | `cancel` | `id`: a request id | `{"ok":true}`, and that stream ends |
//!
//! A stream is a series of values, each an object
//! `{"event":"<name>","data":<data>}`. It ends with
//! `{"event":"end","data":{"reason":"..."}}` when its link closes or it is
//! cancelled.
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
//!  "nodes":[{"id":"t11","kind":"task","name":"net::filter","file":"src/stdlib/web/net.rs",
//!            "line":243,"parent":"t10","started":0.113998},
//!           {"id":"s7","kind":"sandbox","name":"agent"}],
//!  "edges":[{"id":"e7","a":"t11","b":"s7","label":null}],
//!  "counters":{"e7":[95987,136344354,56916,2816859]},
//!  "notes":[...]}
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
//! - `note`: one new [note](#notes).
//! - `ended`: `{"t":..}`, once the world has ended.
//!
//! Clients should ignore events and fields they do not know.
//!
//! ## Notes
//!
//! A note is an event from the stdlib or from world code:
//!
//! ```text
//! {"seq":527,"t":123.32,"node":"t7","kind":"event","task":"names::serve_udp",
//!  "file":"src/stdlib/web/net.rs","line":442,"parent":"t1",
//!  "name":"dns_query","data":{"sandbox":"agent","name":"example.test","answer":"203.0.113.10"}}
//! ```
//!
//! `seq` numbers notes from 1. `node` is the task that sent it, and `task`,
//! `file`, `line` and `parent` describe that task, since a short task may
//! have ended before anyone reads the note. `kind` is `event` for world
//! code's events, with `name` and `data`. The stdlib's are `drop`,
//! `route_removed` and `tls_keys`, with a `text`, and `packet`, whether the
//! note kept the packet it is about. The world keeps its latest 5,000
//! notes.
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

mod app;
mod decode;
mod json;
mod keys;
mod packets;
mod hpack;
mod pcap;
#[cfg(not(target_arch = "wasm32"))]
mod session;
mod stream;
mod view;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::watch::Graph;
use crate::Cx;
pub(crate) use keys::observed_config;
pub(crate) use packets::LinkWatch;

/// How long a link's decoded packets are kept after the last observer
/// stopped asking for them.
const WATCH_LINGER: Duration = if cfg!(test) { Duration::from_millis(200) } else { Duration::from_secs(60) };
/// How often the reaper looks for watches to forget.
#[cfg(not(target_arch = "wasm32"))]
const REAP_EVERY: Duration = if cfg!(test) { Duration::from_millis(50) } else { Duration::from_secs(5) };

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serves one observer session on `fd`, which has been accepted on the
/// world socket of `attacher`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn serve_session(attacher: crate::Attacher, fd: std::os::fd::OwnedFd) {
    session::start(attacher, fd);
}

/// Forgets the watches that have had no subscriber for a minute.
pub(crate) fn reap(graph: &Graph) {
    lock(&graph.watches).retain(|_, w| !w.idle_for(WATCH_LINGER));
}

/// The worlds with watches that may need forgetting, and whether the
/// reaper thread runs.
///
/// Locks are taken in this order: this, then a graph's `watches`, then a
/// watch's own. So nothing calls [`reap_later`] while it holds either of
/// the others.
static REAPER: Mutex<(Vec<std::sync::Weak<Graph>>, bool)> = Mutex::new((Vec::new(), false));

/// Makes sure `graph`'s watches are forgotten once idle for a minute, even
/// if no observer asks anything more. Called when the last subscriber of a
/// watch leaves.
pub(crate) fn reap_later(graph: &Arc<Graph>) {
    let mut reaper = lock(&REAPER);
    if !reaper.0.iter().any(|g| std::ptr::eq(g.as_ptr(), Arc::as_ptr(graph))) {
        reaper.0.push(Arc::downgrade(graph));
    }
    if reaper.1 {
        return;
    }
    reaper.1 = start_reaper();
}

/// Starts the thread that reaps the worlds in [`REAPER`]. Returns whether
/// it runs.
#[cfg(not(target_arch = "wasm32"))]
fn start_reaper() -> bool {
    std::thread::Builder::new()
        .name("fictionet-reaper".into())
        .spawn(|| {
            loop {
                std::thread::sleep(REAP_EVERY);
                let mut reaper = lock(&REAPER);
                // A world that ended, or has no watches left, needs no more.
                reaper.0.retain(|g| {
                    g.upgrade().is_some_and(|g| {
                        reap(&g);
                        !lock(&g.watches).is_empty()
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
#[cfg(target_arch = "wasm32")]
fn start_reaper() -> bool {
    false
}

/// The watch of link `id` in `graph`, made if needed, and a subscription
/// to it. Both are taken under the lock the reaper takes, so the reaper
/// cannot forget the watch between them.
pub(crate) fn watch(graph: &Arc<Graph>, id: u64) -> Option<(Arc<LinkWatch>, packets::Subscription)> {
    reap(graph);
    let mut watches = lock(&graph.watches);
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
pub(crate) fn existing_watch(graph: &Graph, id: u64) -> Option<Arc<LinkWatch>> {
    lock(&graph.watches).get(&id).cloned()
}

/// A custom event, built field by field, from [`Cx::event`].
///
/// While no observer is subscribed, the builder holds nothing and every
/// method returns immediately, so building an event costs almost nothing.
#[must_use = "an event is sent by calling emit"]
pub struct Event<'a> {
    cx: &'a Cx,
    /// The name and the JSON object so far, only while observed.
    building: Option<(String, json::Object)>,
}

impl<'a> Event<'a> {
    pub(crate) fn new(cx: &'a Cx, name: &str) -> Event<'a> {
        let building = cx.graph().observed().then(|| (name.to_owned(), json::Object::new()));
        Event { cx, building }
    }

    fn with(mut self, f: impl FnOnce(json::Object) -> json::Object) -> Event<'a> {
        if let Some((name, object)) = self.building.take() {
            self.building = Some((name, f(object)));
        }
        self
    }

    /// Adds a text field.
    pub fn str(self, key: &str, value: &str) -> Event<'a> {
        self.with(|o| o.str(key, value))
    }

    /// Adds a number field. Numbers that are not finite become `null`.
    pub fn num(self, key: &str, value: impl Into<f64>) -> Event<'a> {
        let v: f64 = value.into();
        self.with(|o| if v.is_finite() { o.num(key, v) } else { o.raw(key, "null") })
    }

    /// Adds a whole-number field.
    pub fn int(self, key: &str, value: impl Into<i64>) -> Event<'a> {
        let v: i64 = value.into();
        self.with(|o| o.num(key, v))
    }

    /// Adds a true or false field.
    pub fn bool(self, key: &str, value: bool) -> Event<'a> {
        self.with(|o| o.bool(key, value))
    }

    /// Sends the event to the observers.
    pub fn emit(self) {
        if let Some((name, object)) = self.building {
            self.cx.graph().event(self.cx.now().since_start(), name, object.done());
        }
    }
}

impl std::fmt::Debug for Event<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event").field("observed", &self.building.is_some()).finish()
    }
}

/// Why [`Cx::emit`] refused an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotJson;

impl std::fmt::Display for NotJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the event's payload is not one JSON value")
    }
}

impl std::error::Error for NotJson {}

/// Sends a custom event whose payload is JSON text already.
pub(crate) fn emit(cx: &Cx, name: &str, payload: &str) -> Result<(), NotJson> {
    let graph = cx.graph();
    if !graph.observed() {
        return Ok(());
    }
    if !json::is_value(payload) {
        return Err(NotJson);
    }
    // One line, so it can go in a server-sent event or a line of output.
    graph.event(cx.now().since_start(), name.to_owned(), json::compact(payload));
    Ok(())
}

/// Tells observers that a queue dropped `packet` with `waiting` packets
/// ahead of it.
pub(crate) fn note_drop(cx: &Cx, packet: &crate::Packet, waiting: usize) {
    // Only the headers: this runs on the world's own thread.
    let d = decode::Dissector::headers_only().decode(&packet.0, &[]);
    let text = format!("{} → {} {} ({} bytes): the queue was full, {waiting} packets waiting", d.src, d.dst, d.proto, packet.0.len());
    cx.graph().note("drop", text, Some(&packet.0));
}

/// A link an [`Interface`](crate::Interface) belongs to, so the stdlib can
/// tell observers about it. Not for world code.
#[doc(hidden)]
#[derive(Clone)]
pub struct LinkHandle(pub(crate) Arc<crate::watch::Meter>);

impl std::fmt::Debug for LinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LinkHandle").field(&self.0.id).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// A link is copied only while a `packets` stream subscribes, and a
    /// kept watch does not keep its world alive.
    #[test]
    fn watches_copy_only_while_subscribed() {
        use crate::watch::Meter;
        let graph = Graph::new();
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
        assert_eq!(w.rows_after(0, 10).len(), 1, "nothing is copied with no subscriber");
        // The decoded rows stay for a while, for `packet` and `pcap`.
        assert!(existing_watch(&graph, meter.id).is_some());
        drop(w);
        let weak = Arc::downgrade(&graph);
        drop(graph);
        assert!(weak.upgrade().is_none(), "the kept watch held its world alive");
    }

    /// A watch with no subscriber is forgotten after the linger time,
    /// even when no observer asks anything more.
    #[test]
    fn idle_watches_are_forgotten_without_more_requests() {
        use crate::watch::Meter;
        let graph = Graph::new();
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        drop(watch(&graph, meter.id).unwrap());
        assert!(existing_watch(&graph, meter.id).is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while existing_watch(&graph, meter.id).is_some() {
            assert!(std::time::Instant::now() < deadline, "the idle watch was kept");
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
        crate::block_on(crate::run(|cx| async move {
            let (a, _b) = crate::pair();
            let line = line!() + 1;
            let _f = crate::stdlib::filter(&cx, a, |_, _, _| true);
            let tasks: Vec<_> = cx.graph().state().tasks.values().cloned().collect();
            assert!(tasks.iter().any(|t| t.name == "filter" && t.file == file!() && t.line == line), "{tasks:?}");
            Ok(())
        }))
        .unwrap();
    }

    /// A router keeps a note of a route it removes only while observed.
    #[test]
    fn route_notes_are_kept_only_while_observed() {
        crate::block_on(crate::run(|cx| async move {
            let (a, b) = crate::pair();
            let (c, d) = crate::pair();
            let router = crate::stdlib::route::router(&cx, vec![("10.0.0.0/24".parse().unwrap(), Box::new(a))]);
            router.add("10.0.1.0/24".parse().unwrap(), Box::new(c));
            drop(b);
            cx.sleep(Duration::from_millis(10)).await?;
            assert!(cx.graph().state().notes.is_empty());
            cx.graph().viewers.fetch_add(1, Ordering::Relaxed);
            drop(d);
            cx.sleep(Duration::from_millis(10)).await?;
            let notes: Vec<_> = cx.graph().state().notes.iter().map(|n| n.kind).collect();
            assert_eq!(notes, ["route_removed"]);
            Ok(())
        }))
        .unwrap();
    }

    /// With no observer, events are not built and nothing is kept. With
    /// one, each event is kept with its task and time.
    #[test]
    fn events_are_kept_only_while_observed() {
        crate::block_on(crate::run(|cx| async move {
            assert!(!cx.observed());
            cx.event("request").str("host", "example.test").int("status", 200).emit();
            assert_eq!(cx.emit("raw", "not json"), Ok(()), "unobserved payloads are not read");
            assert!(cx.graph().state().notes.is_empty());

            cx.graph().viewers.fetch_add(1, Ordering::Relaxed);
            assert!(cx.observed());
            cx.event("request").str("host", "example.test").int("status", 200).bool("tls", true).num("ms", 1.5).emit();
            assert_eq!(cx.emit("raw", r#" {"a":[1,2]} "#), Ok(()));
            assert_eq!(cx.emit("bad", "{"), Err(NotJson));
            let notes: Vec<_> = cx.graph().state().notes.iter().cloned().collect();
            assert_eq!(notes.len(), 2);
            let (name, data) = notes[0].event.clone().unwrap();
            assert_eq!(name, "request");
            assert_eq!(data, r#"{"host":"example.test","status":200,"tls":true,"ms":1.5}"#);
            assert_eq!(notes[1].event.clone().unwrap().1, r#"{"a":[1,2]}"#);
            // The world function is the first task.
            assert_eq!(notes[0].task, 1);
            assert!(notes[0].at <= notes[1].at && notes[1].at <= cx.now().since_start());
            Ok(())
        }))
        .unwrap();
    }
}
