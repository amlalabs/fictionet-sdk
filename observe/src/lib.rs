#![doc = include_str!("../README.md")]
//!
//! # The dashboard walkthrough
//!
//! The integrator installs a [`DashboardObserver`] before starting the run.
//! It owns a [`Collector`] and gives callers a [`DashboardHandle`]. The handle
//! works before, during and after the run. For external clients, [`serve`]
//! exposes it on an observation socket. The world socket serves attachments.
//!
//! With the observation socket at `/run/fictionet/observe.sock`, start the
//! browser server with a private token file:
//!
//! ```sh
//! (umask 077; openssl rand -hex 32 > /run/fictionet/dashboard-token)
//! fictionet dashboard --observation unix:/run/fictionet/observe.sock --token-file /run/fictionet/dashboard-token
//! ```
//!
//! Open `http://127.0.0.1:7878/#token=<token>` with the file's token.
//! Percent-encode URL punctuation. The page removes the fragment immediately.
//! It calls `/api/bootstrap` with `Authorization: Bearer <token>`.
//! Bootstrap succeeds once per dashboard process and sets no cookie.
//! The browser stores the token in `sessionStorage`, scoped to this origin
//! and tab. Reloading keeps it. Opening the bootstrap URL in the same tab
//! also keeps the session if the stored token matches.
//!
//! Log out or close the tab to clear the stored token. Restart the dashboard
//! to reuse a consumed bootstrap URL. Logout cancels requests and streams.
//! It does not revoke the file token for scripts or other signed-in tabs.
//! An authorization failure stops requests, clears the stored token and
//! closes the packet drawer. After signing in again, reopen the drawer.
//!
//! The static app shell is public and contains no world data. It expires
//! the `fictionet_token` cookie. Every API call, stream and download requires
//! the bearer header, including `/api/keylog` from loopback. Cookies and query
//! tokens do not authenticate. The browser uses fetch, omits cookies and
//! refuses redirects. It sends credentials only to fixed API paths at its
//! own origin. A service on another port receives no dashboard credential.
//! Scripts can send the same bearer header directly.
//!
//! The dashboard serves one HTTP/1.0 or HTTP/1.1 GET request per connection.
//! The target must start with `/`. The head is limited to 16 KiB, including
//! the first `\r\n\r\n`. Bytes after it cannot supply headers or another
//! request. Invalid request lines and headers close the connection.
//! Repeated `Host`, `Authorization`, `Cookie`, `Origin` or `Sec-Fetch-Site`
//! fields are rejected. `Transfer-Encoding` is rejected. `Content-Length`
//! may occur only once and must be zero.
//!
//! `Host` must name `localhost`, a loopback IP or the bound IP. A wildcard
//! bind accepts any IP literal. Other hostnames are rejected. If supplied,
//! `Sec-Fetch-Site` must be `same-origin` or `none`. An `Origin` must have the
//! same authority as `Host`. Scripts may omit both origin headers.
//! Responses disable caching and MIME sniffing, set `Referrer-Policy: no-referrer`,
//! and use a content security policy that restricts assets to the app's origin
//! and prevents framing.
//!
//! The dashboard embeds its web assets in the CLI binary. It forwards requests
//! to the observation socket and streams results to the browser:
//!
//! <style>.fn-observe > svg {display:block;width:100%;max-width:840px;min-width:560px;height:auto}</style>
//! <div class="fn-observe" style="overflow-x:auto;margin:1.25em 0">
#![doc = include_str!("../../docs/diagrams/observe.svg")]
//! </div>
//!
//! # From a shell
//!
//! `fictionet observe` sends one request and writes each JSON value followed
//! by a newline. It writes binary `pcap` and `keylog` replies as received.
//! With no request it prints the graph once. `watch` follows graph changes
//! and events. `fictionet observe --help` lists the requests.
//!
//! To try `web_world` without root, build both programs from the workspace
//! root. Use the target directory set for your build:
//!
//! ```sh
//! cargo build --locked -p fictionet --example web_world -p fictionet-cli --bin fictionet
//! bin="${CARGO_TARGET_DIR:-target}/debug"
//! work=$(mktemp -d /tmp/fictionet-observe.XXXXXX)
//! (umask 077; openssl rand -hex 32 > "$work/proxy-token")
//! "$bin/examples/web_world" "$work/world.sock" "$work/ca.pem" "$work/observe.sock" > "$work/world.log" 2>&1 &
//! world_pid=$!
//! ```
//!
//! Check that the socket and CA file exist. Run `ss -ltn` and choose a free
//! loopback port; these commands use 18781. Start the proxy and check its
//! ready file before sending traffic:
//!
//! ```sh
//! "$bin/fictionet" attach --world "unix:$work/world.sock" --name agent \
//!     --type http_proxy --listen 127.0.0.1:18781 --token-file "$work/proxy-token" \
//!     --ip-addr 10.0.0.2 --dns 10.0.0.1 --ready-file "$work/ready" > "$work/attach.log" 2>&1 &
//! attach_pid=$!
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" graph
//! ```
//!
//! Find the edge whose `b` node is the `agent` sandbox. In this run it was
//! `e13`. Start its packet stream before making requests: `web_world` uses
//! [`DashboardOptions::default()`], which captures links on demand.
//!
//! ```sh
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" packets e13 > "$work/packets.jsonl" &
//! packets_pid=$!
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" watch > "$work/watch.jsonl" &
//! watch_pid=$!
//! ```
//!
//! Once the packet stream has printed its `link` event, fetch a few pages.
//! The proxy accepts the token as a password; it does not check the username.
//! `--noproxy ''` keeps local proxy exclusions from bypassing the proxy.
//!
//! ```sh
//! curl --cacert "$work/ca.pem" --proxy http://127.0.0.1:18781 \
//!     --proxy-user "relay:$(cat "$work/proxy-token")" --noproxy '' \
//!     https://example.test/ https://example.test/count https://example.test/
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" world
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" events
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" packet e13 1
//! "$bin/fictionet" observe --observation "unix:$work/observe.sock" pcap e13 > "$work/agent.pcapng"
//! ```
//!
//! The [proxy guide](fictionet::guide::attaching#behind-a-proxy-http_proxy-and-socks5)
//! describes authentication and client settings. Stop only the processes
//! started in this shell, using their saved PIDs:
//!
//! ```sh
//! kill "$watch_pid" "$packets_pid" "$attach_pid" "$world_pid"
//! wait "$watch_pid" "$packets_pid" "$attach_pid" "$world_pid"
//! ```
//!
//! These replies came from that setup. Times, IDs and addresses can differ
//! between runs. `...` marks omitted output in the long examples below.
//!
//! ```text
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" world
//! {"observe":2,"fictionet":"0.1.0","running":true,"ended":false,"started":1792421987400,"t":25.654109}
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" graph
//! {"t":2.320307,"started":1792421987400,"revision":65,"hosts":[{"id":"h1","name":"gateway","group":"g2","sandbox":null},{"id":"h2","name":"agent","group":null,"sandbox":"agent"}],"status":{"incomplete":false,"refused":0,"missing":0,"truncated_bytes":0,"losses":[],"untracked":[]},"ended":false,"groups":[{"id":"g1","name":"web::Sites","parent":null},{"id":"g2","name":"gateway","parent":"g1"}],"nodes":[{"id":"s13","kind":"sandbox","name":"agent","group":null,"host":"h2"},...],...}
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" watch > "$work/watch.jsonl" &
//! $ cat "$work/watch.jsonl"
//! {"event":"snapshot","data":{"t":12.729358,"started":1792421987400,"revision":65,"hosts":[{"id":"h1","name":"gateway","group":"g2","sandbox":null},{"id":"h2","name":"agent","group":null,"sandbox":"agent"}],"status":{"incomplete":false,"refused":0,"missing":0,"truncated_bytes":0,"losses":[],"untracked":[]},"ended":false,"groups":[{"id":"g1","name":"web::Sites","parent":null},{"id":"g2","name":"gateway","parent":"g1"}],"nodes":[{"id":"s13","kind":"sandbox","name":"agent","group":null,"host":"h2"},...],...}}
//! {"event":"host","data":{"id":"h3","name":"example.test (203.0.113.10)","group":"g3","sandbox":null}}
//! {"event":"status","data":{"revision":121,"status":{"incomplete":false,"refused":0,"missing":0,"truncated_bytes":0,"losses":[],"untracked":[]}}}
//! ```
//!
//! # What the drawing shows
//!
//! This drawing shows `web_world` with one sandbox, `agent`, fetching pages:
//!
#![doc = include_str!("../../docs/diagrams/dashboard.svg")]
//!
//! Each task is a node: the world function, tasks started with
//! [`Cx::spawn`](fictionet::Cx::spawn), and background stdlib functions such as
//! [`delay`](fictionet::stdlib::network::delay) and
//! [`router`](fictionet::stdlib::network::route::router).
//! A node shows its name and the file and line that started it. A stdlib
//! function shows its own name and the line in your code that called it.
//! Other tasks use the name of the function their future comes from.
//! Each sandbox is also a node, with one [`Attachment`](fictionet::Attachment).
//!
//! A link is the two ends of a [`pair`](fictionet::pair), or an attachment.
//! Its edge joins the tasks that use the ends. If an end has no live owner,
//! the graph uses the live creating task. Edges without two distinct visible
//! ends are omitted. Counters track packets and bytes sent in each direction.
//! A task without links stays in the side panel's task list, grouped by its
//! spawn location, with the number running.
//!
//! The sandbox is on the left. Tasks are placed by their distance from it.
//! Lines thicken with traffic. Moving dots show direction in two colors.
//! Router links carry their route prefixes. Hover over a box or line for
//! counts. Click a task for its spawn location, links and events.
//! Click a link for packets, with source, destination, protocol and summary.
//! Select a packet for its layers and bytes. Selecting a field marks its bytes.
//! **Capture for Wireshark** downloads the kept packets as pcapng.
//!
//! Drag a box, or an open group's name, to move it. The lines follow and
//! other boxes keep out of its way. The browser remembers positions and open
//! groups for each world. Double-click the background or press the round arrow
//! to lay out the drawing again.
//!
//! # Groups
//!
//! [`Cx::group`](fictionet::Cx::group) returns a context whose tasks belong
//! to a named group. Their child tasks inherit it, including stdlib tasks.
//! Groups nest. A sandbox belongs to the group of the task reading its
//! attachment. A grouped context stays in the same execution region.
//!
//! ```rust
//! # use fictionet::{Cx, End, Result};
//! # use fictionet::stdlib::network::{ip, tcp};
//! fn machine(fcx: &Cx, side: End, name: &str, addr: std::net::IpAddr) -> Result {
//!     let host = fcx.host(format!("{name} {addr}"));
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
//! [`web::Sites`](fictionet::stdlib::web::Sites) groups its router and services.
//! Its gateway and each simulated machine have their own groups. A machine's
//! name comes from the first site at its address. Each sandbox's filter stays
//! outside, beside its sandbox.
//!
//! A closed group is one box with a stack of cards behind it. Internal links
//! are hidden. Links to the same outer box become one line with summed counts.
//! Clicking it opens packets from its links in time order. The drawer chooses
//! at most the 32 busiest links and labels that choice. Its capture download
//! contains one pcapng section per selected link.
//!
//! Double-click a closed group or press **+** to open it in place.
//! Double-click an open group's name or press **−** to close it.
//! Outermost groups start open unless they hold more than 40 visible boxes.
//! Inner groups start closed. A breadcrumb shows the groups around a selection.
//! See [`Cx::group`](fictionet::Cx::group) for allocation costs.
//!
//! # Hosts
//!
//! A host is an explicit topology entity with a run-scoped
//! [`HostId`](fictionet::events::HostId). It is distinct from a group.
//! [`Cx::host`](fictionet::Cx::host) creates a simulated host and its group.
//! Attachments also identify sandbox hosts. The graph's `hosts` array lists
//! each host's name, group and sandbox name, where present. Task nodes name
//! their nearest enclosing host; sandbox nodes name their attachment's host.
//! The drawing uses task and group boxes rather than a separate host box.
//!
//! [`Cx::connection_opened`](fictionet::Cx::connection_opened) binds a service
//! connection to its task and host; [`Cx::connection_closed`](fictionet::Cx::connection_closed)
//! removes that binding. [`Collector::topology`] exposes these connections.
//! The graph JSON exposes hosts and node-to-host links, not connection bindings.
//!
//! # Events
//!
//! Services and world code emit events lazily through
//! [`Cx::emit`](fictionet::Cx::emit). The integrator installs observers in
//! [`RunOptions`](fictionet::RunOptions). The collector inside
//! [`DashboardObserver`] uses [`Memory`] for retention. A late client sees
//! kept events, followed by later events. A separate grader can use its own
//! [`Memory`] through [`Fanout`](fictionet::events::Fanout).
//!
//! ```rust
//! # use fictionet::Cx;
//! fn sold(fcx: &Cx, item: &str, count: u32) {
//!     fcx.emit("shop", "order", |event| {
//!         event.summary(format!("{count} × {item}")).field("item", item).field("count", count)
//!     });
//! }
//! ```
//!
//! The dashboard lists events under **Events**, with the emitting task and
//! run-clock time. Network events include `bottleneck.drop`, `router.drop`,
//! `router.route_removed`, `lan.drop`, `lan.member_replaced` and
//! `lan.member_removed`. The dashboard counts bottleneck drops on its node.
//! [`Aggregate`] combines repeated facts into summaries with `count`,
//! `first_seq`, `last_seq` and ranges for numeric detail. Its first occurrence
//! passes through immediately. Reads do not flush aggregation.
//!
//! The default aggregate window is one second of run time, with at most
//! 1,024 pending facts and 2 MiB. Matching source, kind, level, connection,
//! task, summary and identifying fields share a window. A fact without
//! `count` represents one occurrence. Ordinary events, the next emission
//! after window expiry, capacity pressure and run end flush pending summaries
//! in sequence order. Distinct traffic can still overflow the destination.
//!
//! [`fictionet::stdlib::network::ip::emit_drop`] checks interest before
//! parsing packet details and emits each packet drop as a repeatable fact.
//! [`Layer::from_event`] turns an event into a display layer with its summary
//! and fields as notes. A non-string field that cannot be serialized becomes
//! an `unserializable: <error>` note. Packet parsing and presentation stay
//! outside core event construction.
//!
//! An event uses [`Event::to_json`](fictionet::events::Event::to_json).
//! This DNS event was captured by the shell run:
//!
//! ```json
//! {"seq":4,"at":13.893185483,"source":"dns","kind":"query","level":"info","summary":"example.test 1: 203.0.113.10","sandbox":{"id":1,"name":"agent","addr":"10.0.0.2","addr_v6":null},"conn":null,"local":"10.0.0.1:53","peer":"10.0.0.2:58747","transport":"udp","tls":false,"sni":null,"alpn":null,"fields":{"tcp":false,"name":"example.test","qtype":1,"answer":"addr","addr":"203.0.113.10","rcode":null},"node":"t8","task":"dns::dns_udp","file":"src/stdlib/world/net/dns.rs","line":49,"parent":"t1"}
//! ```
//!
//! `seq` numbers emitted events from 1; filtering and aggregation can leave
//! gaps. `at` is seconds on the run's clock. `source`, `kind`, `level` and
//! `summary` describe the event. `fields` holds its structured details.
//! `sandbox` identifies the originating sandbox, if known. `conn`, `local`,
//! `peer` and `transport` describe the connection. `tls`, `sni` and `alpn`
//! describe TLS and its negotiated protocol. Absent values are `null`.
//! `node`, `task`, `file`, `line` and `parent` preserve task context even
//! when that task has ended. Outside a task of the same run, task metadata
//! is absent.
//!
//! An `events` reply contains `events`, `last` and `dropped`. `last` is the
//! last delivered event sequence, not necessarily the last event in this
//! batch. Page with the last returned event's `seq`. `dropped` is the total
//! lost from retention. A watch emits `events.dropped` with a `count` field
//! when it reports loss. Sequence gaps alone do not establish loss.
//! [`Memory::checked_of`] and [`Memory::checked_all`] reject incomplete
//! histories for grading, even if loss affected another event kind.
//!
//! ```text
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" events
//! {"events":[{"seq":1,"at":0,"source":"run","kind":"start","level":"info","summary":"the run started","sandbox":null,"conn":null,"local":null,"peer":null,"transport":"tcp","tls":false,"sni":null,"alpn":null,"fields":{"wall":1792421987.400384,"seed":"0cac0fb52a890a0edb4c72345fd587a5c096814e73c73e35eb68ffc2ea2ae0ac","rng":"chacha20-v1"},"node":"t1","task":"world","file":"src/run.rs","line":236,"parent":null},...],"last":8,"dropped":0}
//! ```
//!
//! If JSON exceeds the writer's size, depth or value-count limit, the request
//! service sends a replacement at the same sequence. It keeps event, connection
//! and task metadata. Its summary is `unserializable: <error>`, and its only
//! field is `{"unserializable":"<error>"}`. Text metadata longer than 1,024
//! bytes is shortened at a UTF-8 boundary and ends in `…`. Cursors advance
//! past the replacement. [`Jsonl`] counts unserializable events as lost;
//! [`Jsonl::finish`] drains its worker and reports lost output or writer errors.
//! Call it outside observer callbacks. Its queue has explicit count and byte
//! bounds. Full queues report loss without blocking the world. `end` seals
//! input; [`Jsonl::lost`] counts rejected or unwritten events. Discard samples
//! with incomplete output. Worker scheduling can affect overflow, so use
//! synchronous [`Memory`] for repeatable lab grading. Browser and sans-I/O
//! consumers can use [`Memory`] or their own observer without a writer worker.
//!
//! # Packets
//!
//! The collector exists before clients connect. A late client can read retained
//! events, current topology, kept packet copies and TLS keys. Capture policy
//! decides which links have copies. [`DashboardOptions::default()`] captures
//! all links on demand. [`DashboardOptions::demo()`] captures sandbox links
//! from startup and other links on demand. Both retain TLS keys from startup.
//! The base [`Options::default()`] uses the demo capture policy.
//!
//! A `packets` subscriber holds capture demand for its link. Dropping the last
//! demand handle stops demand capture. Startup capture continues without
//! subscribers. [`CapturePolicy::Off`] declines capture. Packets that were
//! not captured cannot be recovered later. Watching the graph alone does not
//! start demand capture.
//!
//! Topology can arrive after packets produced during a task poll. If either
//! startup policy is enabled, the collector provisionally captures unknown
//! links within its limits. Link registration applies the policy and discards
//! provisional copies for links that should not retain them. Removed links
//! keep copies within the same budgets. Under pressure those captures are
//! evicted first, in removal order.
//!
//! Sampling uses run time. Each link keeps the first 64 packets in each
//! 100 ms window, then one in two, one in four, and so on. Each [`PacketCopy`]
//! keeps its stream stamp, original length and preceding sampling count.
//! A separate copy cursor distinguishes eviction from sampling gaps.
//!
//! A watch decodes kept copies in order. All subscribers to a link share its
//! decoder and rows. The drawer shows sampling, capture eviction and subscriber
//! overruns separately. Its totals count reports in the loaded history;
//! evicted rows may have carried other reports. Pausing and browser queue
//! trimming do not clear those totals.
//!
//! Selecting a packet clears the preceding layers and bytes while it loads.
//! Only that selection can fill them. Closing or reopening the drawer, or
//! reconnecting its stream, cancels pending detail requests. If a detail request
//! fails, both views clear. Select the packet again to retry.
//! A reconnect clears rows, queued packets, loss totals and selected detail,
//! then replays kept history. A paused view stays paused and holds that replay.
//! Dropped browser connections show a reconnect notice. A subscription refusal
//! or broken frame shows its reason and stops that stream. In a merged view,
//! a refusal names its link; the other links keep streaming.
//!
//! A merged capture download fails as a whole if any link has no capture.
//! The HTTP 404 JSON has an `error` naming all failed links, and a `links`
//! array with each failed `link` and its `error`. It returns no partial capture.
//!
//! # Decoding and decryption
//!
//! Packets are raw IPv4 or IPv6, with no Ethernet header. The decoder reads
//! IP, TCP, UDP and ICMP, then the selected application protocol. The built-in
//! [`Registry`] registers `http1`, `http2`, `tls`, `modbus`, `dhcp` and `dns`.
//! TCP reassembly presents a message on the packet that completes it.
//! HTTP/2 includes headers and recognized gRPC message layers under shared
//! bounds. An unavailable HPACK table entry is shown as unknown.
//!
//! Decoding and serialization run on the caller's thread when a session polls
//! or requests data. They do not run in an observer callback. Sampling and
//! capture eviction reset the link's connections, so no decoder joins bytes
//! across a capture gap.
//!
//! TLS 1.3 can be decrypted when instrumented endpoints emit keys through
//! [`fictionet::events`]. The stdlib TLS server uses this contract. Arbitrary
//! guest-to-internet TLS does not supply these keys. TLS 1.2 stays encrypted
//! in the dashboard; a capture with suitable keys can be opened in Wireshark.
//!
//! A late watch can decrypt a TLS 1.3 session if its required handshake and
//! packet bytes and keys are still available. Keeping keys does not recover
//! uncaptured packets. Without the captured ClientHello and ServerHello,
//! the decoder lacks the random and cipher needed to select keys. A capture
//! gap resets that state. Remaining bytes may stay encrypted or undecoded;
//! a missing message cannot be reconstructed from keys.
//!
//! Keys are bounded independently of packets. Each watch also caches keys
//! within the collector's configured key count and byte bounds. If the required
//! handshake or application secrets were evicted from both caches before the
//! decoder derived its keys, that direction cannot be decrypted even if its
//! packets remain. A decoder that already derived keys can continue while its
//! connection state survives. Retained decoded details keep their plaintext.
//!
//! A pcapng download includes deduplicated keys from the watch cache and the
//! collector. Wireshark can use them without a separate key file. The `keylog`
//! operation returns only the collector's retained keys as SSLKEYLOGFILE text.
//! Key debug output hides secrets.
//!
//! # User protocols
//!
//! Implement [`Present`] on a [`Decode`](fictionet::stdlib::codec::Decode)
//! type, including a protocol copied into your crate. Field ranges are relative
//! to the item's raw bytes. [`Observed`] drives bounded input. [`Placement`]
//! maps exact spans to packet bytes or uses a separate reassembly buffer.
//!
//! Add the presenter to [`Registry`] with a port or prefix matcher, or select
//! its name with [`Registry::choose`]. Built-ins use the same API.
//! [`Dissector::with_registry`] decodes raw IP from a pcap reader or live source.
//! Set [`DashboardOptions::protocols`] before constructing the observer to use
//! the registry in its watches. See the
//! [protocol guide](https://github.com/amlalabs/fictionet-sdk/blob/main/docs/observe-protocols.md)
//! for adapters and selection rules.
//!
//! # Who can observe
//!
//! The integrator chooses whether to expose a [`DashboardHandle`]. On Unix,
//! [`serve`] creates the socket in a temporary directory with mode `0700`,
//! sets the socket to `0600`, then publishes it at the requested path.
//! File permissions control access. Keep the observation socket and dashboard
//! token outside the sandbox. The sandbox's simulated network does not reach
//! this Unix socket, but sharing its filesystem can expose it.
//!
//! The world socket carries attachments only. An attach-protocol hello with
//! type `observe` is refused as an unknown attach type. Observation clients
//! connect only to the observation socket, with no world-socket fallback.
//! An observer can read retained traffic and TLS secrets. Grant access only
//! to people and programs trusted with those contents. Requests can change
//! capture demand, but do not command the world.
//!
//! The dashboard binds to `127.0.0.1:7878` by default. `--listen <ip:port>`
//! chooses another address. HTTP carries the token in plaintext; use loopback
//! or a trusted TLS tunnel. Containers in a Kubernetes pod share loopback,
//! so a loopback bind does not isolate the dashboard from an agent in that pod.
//!
//! # What it costs
//!
//! Without an observer, core does no observation allocation, clock read,
//! sequence increment or registration. Interest is checked before work.
//! Callbacks are synchronous and must return promptly; a slow custom observer
//! can delay execution. The collector copies and updates bounded state on the
//! producer's thread. Sessions decode and serialize on their caller's thread.
//! See [`fictionet::events`] for delivery and lock rules.
//!
//! `cargo bench --locked --bench network -- sched` uses Divan.
//! On one machine, three samples measured `sched::packet_round_trips`, which
//! moves 500,000 round trips over one pair: 1,000,000 crossings. The medians
//! were 116.2–116.6 ms without an observer, 119.3–119.7 ms with an event-only
//! observer that declines packets, and 169.6–170.3 ms with an observer that
//! receives every crossing and counts its bytes. That is about 57 ns per
//! published crossing.
//!
//! `cargo bench --locked --bench runtime -- observe` measures dashboard cost.
//! `observe::links` uses ten sandboxes sending HTTPS requests with no watch,
//! with the graph watched, and with all sandbox links watched.
//! `observe::graph` uses one sandbox and a large site graph, with and without
//! a graph watch. See
//! [CONTRIBUTING.md](https://github.com/amlalabs/fictionet-sdk/blob/main/CONTRIBUTING.md)
//! for the performance suite. These workloads include collection, transport,
//! decoding and presentation work that the packet-counting observer omits.
//!
//! # Resource limits
//!
//! Set [`DashboardOptions::collector`] before constructing the observer.
//! [`Options`] supplies these retention defaults:
//!
//! | Budget | Default | What it charges |
//! |---|---|---|
//! | `events` | 50,000 events, 16 MiB | Ordinary events, sized by [`Event::size`](fictionet::events::Event::size). `None` declines event retention. |
//! | `noise` | 5,000 events, 2 MiB | Separate storage for facts marked with [`Event::repeat`](fictionet::events::Event::repeat). |
//! | `packets` | 4,096 copies, 8 MiB per link | Packet payload bytes. |
//! | `packet_bytes` | 64 MiB | Packet payload bytes across all links. |
//! | `snap_len` | 65,535 bytes | Maximum copied bytes per packet; excess bytes count as truncation. |
//! | `keys` | 20,000 keys, 8 MiB | Key entries, labels, randoms, secrets and owned connection text. `None` declines keys. |
//! | `loss_streams` | 4,099 streams | Detailed loss totals by stream and reason. |
//!
//! [`TopologyLimits`] defaults to 16,384 tasks, 4,096 groups, 4,096 hosts,
//! 4,096 links including capture state, and 20,000 active connections.
//! Names and connection text fields allow 1,024 bytes each; link labels allow
//! 1,024 bytes. The aggregate topology budget is 16 MiB for entries and owned
//! text. Bounds can refuse entries or shorten text at UTF-8 boundaries.
//! Missing references and loss mark topology incomplete.
//!
//! Loss totals persist by stream and cause. After `loss_streams` fills,
//! additional streams contribute to [`LossStatus::untracked`] by cause without
//! stream identity. A refreshed snapshot cannot repair collector loss.
//! Zero count or byte bounds refuse retention. Event byte accounting includes
//! owned capacities, task names and shared connection metadata charged in full
//! per copy, plus estimated allocation overhead. It excludes spare collection
//! capacity and copies held by readers. Each event budget evicts its oldest
//! entries first.
//!
//! Each observation endpoint admits 64 sessions by default, including idle
//! clients and pending hellos. A full endpoint refuses with
//! `too many observation sessions`. Admission reserves a slot before acceptance;
//! disconnect or failed thread creation frees it. [`Endpoint::set_session_limit`]
//! changes admission for that endpoint and preserves connected sessions.
//! Zero refuses further sessions. The dashboard has its own 64-connection cap.
//! Attached sandboxes use separate resources.
//!
//! Each [`Session`] may hold 64 subscriptions and capture downloads combined.
//! [`DashboardOptions::watches`] defaults to 64 links, shared by all clients.
//! At capacity, another link evicts the longest-idle watch, with the lowest
//! link ID breaking ties. If every watch has a subscriber, `packets` returns
//! `{"error":"this world has too many watched links"}`. Unknown links return
//! `{"error":"no such link"}` even at capacity. Existing streams keep working.
//! Zero watch capacity refuses a watch for another link.
//!
//! Each watch retains at most 4,096 decoded rows and 32 MiB. Rows charge packet
//! bytes, summary JSON and detail JSON. [`DashboardOptions::watch_bytes`] adds
//! a 256 MiB aggregate row budget. Pressure forgets idle watches first,
//! longest idle first, then evicts the oldest decoded rows across watches.
//! Idle history lasts up to one minute by the caller's supplied time; pressure
//! can evict it sooner. Losing a watch loses its row numbers and details.
//! Watching that link again starts row numbers at 1 and decodes kept copies.
//! `packet` and `pcap` return `{"error":"nothing is watching that link"}`
//! when no watch remains. Removed links can still be watched while their
//! captures remain.
//!
//! These are retention and admission budgets, not a process-memory bound.
//! Packet payload budgets exclude fixed copy metadata, which is count bounded.
//! Snapshots, copies and exports held by readers are outside retention budgets.
//! Thread stacks, socket buffers, allocation overhead, temporary replies and
//! exports, decoder and reassembly state, and custom protocol state are separate.
//! Watch key caches have their own count and byte bounds. Reads in progress
//! and streams draining an ended run can keep holds until they finish.
//! Separate endpoints and runs have separate budgets. Pcapng output streams
//! in chunks rather than building a second full capture buffer.
//!
//! # Observation protocol reference
//!
//! The same request service backs [`Session`] in process and the Unix endpoint.
//! An in-process caller gives [`Session::request`] a request ID, flat JSON,
//! monotonic time and optional wall time since the Unix epoch. Call
//! [`Session::poll`] at [`Session::next_poll`] to drive streams and downloads.
//! Lab time comes from observations. Neither the collector nor the handle
//! reads a clock.
//!
//! ## Handshake and framing
//!
//! [`Client::connect`] connects to the observation socket and sends hello with
//! protocol name `fictionet-observe` and version 2. The server accepts that
//! exact pair. Other names or versions receive a refusal reason, such as
//! `expected fictionet-observe version 2; received fictionet-observe version 1`.
//! There is no fallback to the world socket. `world` reports `"observe":2`.
//! Clients should ignore fields and events they do not recognize.
//!
//! The transport is a Unix stream socket. Each message has a four-byte
//! big-endian body length, from 1 through 65,536. The body starts with a tag:
//!
//! | Tag | Body after the tag |
//! |---|---|
//! | 1, hello | Four-byte big-endian version, then UTF-8 protocol name. |
//! | 2, accept | Empty. |
//! | 3, refuse | UTF-8 reason. |
//! | 4, request | Four-byte big-endian request ID, then UTF-8 JSON. |
//! | 5, reply | Four-byte big-endian request ID, one flag byte, then payload. |
//!
//! Reply flags are `MORE` (1), `END` (2) and `BINARY` (4). `MORE` continues
//! one value in another chunk. Only its final chunk may carry `END`, which
//! ends the request. A stream contains several values before `END`.
//! A pcapng download also contains several binary values; concatenate them.
//! [`Client::request`] assigns an ID. [`Client::next_value`] joins chunks into
//! [`Value`] without rewriting payload bytes. Keep IDs unique while requests
//! are active. Request JSON can occupy at most 65,531 bytes.
//!
//! Server handshakes and sends time out after ten seconds. The client allows
//! eleven seconds for hello and its answer, then clears its read timeout.
//! A silent endpoint yields a handshake-timeout error. Accepted clients wait
//! for replies until their optional read timeout expires.
//! Dropping [`Endpoint`] disconnects clients, joins threads and removes its
//! socket. It does not end the run.
//!
//! ## Requests
//!
//! Requests are flat JSON objects, such as `{"op":"graph"}`. A failure is
//! one terminal value, `{"error":"..."}`. Except for the binary operations,
//! values are JSON.
//!
//! | `op` | Fields | Reply |
//! |---|---|---|
//! | `world` | None | `observe`, `fictionet`, `running`, `ended`, `started`, `t`. |
//! | `graph` | None | The graph snapshot described below. |
//! | `watch` | Optional `after`, an event sequence | Snapshot, then changes and events. |
//! | `counters` | None | `t` and `edges`, with four absolute counters per edge. |
//! | `events` | `after`, default 0; `max`, default and ceiling 1,000 | `events`, `last`, `dropped`. |
//! | `link` | `link`, such as `"e13"` | One edge with `counters`. |
//! | `packets` | `link`; `after`, a decoded row number, default 0 | `link`, then `packet` and `packet_gap` events. |
//! | `packet` | `link`, `seq` | One kept row's layers and buffers. |
//! | `pcap` | `link` | Binary pcapng of that watch's kept rows and keys. |
//! | `keylog` | None | Binary SSLKEYLOGFILE text from the collector. |
//! | `cancel` | `id`, a subscription's request ID | That stream ends; this request gets `{"ok":true}`. |
//!
//! Link arguments accept an `e`-prefixed string, a numeric string or a number.
//! The CLI accepts request names or a literal JSON object. `packet` and `pcap`
//! need a kept watch: send `packets` first. `cancel` targets a subscription,
//! not a capture download. An absent subscription returns `no such subscription`.
//! Malformed JSON, missing `op`, duplicate active request IDs and unknown
//! operations also return explicit errors. A missing row returns
//! `that packet is not kept`.
//!
//! Before its first observation or end callback, `world` reports
//! `running:false`, `ended:false`, `started:null`, `t:null`. `watch` emits
//! `{"event":"waiting","data":{}}` once, then a snapshot when observation
//! begins. Other data requests return `no world is running yet`. Observation
//! starts with the run; it does not wait for an attachment. After the run ends,
//! `running` is false, `ended` is true and `t` is the end time. Retained data
//! stays readable while the handle exists.
//!
//! ## Graph fields
//!
//! `graph` returns a snapshot. `watch` wraps it in
//! `{"event":"snapshot","data":...}`. Its fields are:
//!
//! - `t`: seconds on the run's clock. For a live real run, the caller's wall
//!   time can advance it beyond the last observation.
//! - `started`: Unix epoch milliseconds for a real run, or `null` for a lab.
//! - `revision`: topology revision, increased by state or completeness changes.
//! - `ended`: whether observation delivery has ended.
//! - `groups`: `id`, `name`, `parent` for every retained group. `parent` is
//!   another group ID or `null`.
//! - `hosts`: `id`, `name`, `group`, `sandbox` for each retained host. The
//!   last two fields are a group ID and sandbox name, or `null`.
//! - `nodes`: task and sandbox nodes. Task kinds are `world` or `task`, with
//!   `id`, `name`, `file`, `line`, `parent`, `group`, `started` and `host`.
//!   Node `started` is seconds on the run's clock. Sandbox nodes have
//!   `id`, `kind:"sandbox"`, `name`, `group` and `host`.
//! - `edges`: `id`, `a`, `b`, `label`. Ends name nodes; a sandbox end is `b`.
//!   An absent label is `null`.
//! - `counters`: edge IDs mapped to four numbers: packets and bytes sent by
//!   `a`, then packets and bytes sent by `b`.
//! - `events`: up to the latest 200 retained events, plus a loss notice when
//!   needed. A watch with `after` gets its replay in subsequent `event` values.
//! - `status`: topology completeness and persistent losses, as described below.
//!
//! IDs are strings: `t` for tasks, `g` for groups, `h` for hosts and `e` for
//! links, followed by a run-scoped number. Sandbox node IDs use `s` followed
//! by their link number. IDs are not reused within a run. Node `parent`,
//! `group` and `host` can be `null`. A task's host comes from its nearest
//! ancestor group with a host.
//!
//! This status came from the shell run:
//!
//! ```json
//! {"incomplete":false,"refused":0,"missing":0,"truncated_bytes":0,"losses":[],"untracked":[]}
//! ```
//!
//! `incomplete` means topology input was refused, shortened or lost. `refused`
//! counts changes refused by entry or byte bounds. `missing` counts changes
//! ignored because a referenced entity was missing. `truncated_bytes` counts
//! text bytes cut at UTF-8 boundaries.
//!
//! Each `losses` entry has `stream`, `reason`, `count` and `bytes`. Stream is
//! `events`, `keys`, `topology` or a link ID such as `e13`. Reasons include
//! `staging`, `sampling`, `truncation`, `eviction` and `overflow`. `count`
//! counts affected observations; `bytes` is their byte total or `null` when
//! unknown. `untracked` entries have `reason`, `count` and `bytes`, with known
//! bytes summed, for streams outside the detail budget. They have no stream
//! identity. Totals persist even after retained data is gone.
//!
//! ## Watch changes
//!
//! A stream value has `event` and `data`. After the snapshot, `watch` checks
//! graph changes every 250 ms:
//!
//! | Event | `data` |
//! |---|---|
//! | `group` | An added or changed group, in snapshot form. |
//! | `node` | An added or changed task or sandbox node, in snapshot form. |
//! | `edge` | An added or changed edge, including owner or label changes. |
//! | `edge_end` | `{"id":"e13"}` for a removed edge. |
//! | `node_end` | `{"id":"t18"}` for a removed node. |
//! | `group_end` | `{"id":"g3"}` for a removed group. |
//! | `host` | An added or changed host, in snapshot form. |
//! | `host_end` | `{"id":"h3"}` for a removed host. |
//! | `status` | `revision` and `status`, when either changes. |
//! | `counters` | `t` and `edges`, containing only changed counters. |
//! | `event` | One event in the [event JSON form](#events), including loss notices. |
//! | `ended` | `t`, when a followed run ends. |
//! | `end` | `reason`, after the retained event backlog drains or cancellation. |
//!
//! Removed edges precede node removals. Groups precede their member nodes;
//! group removals follow node removals. Group parents can arrive in either
//! order. Host updates follow node and group changes. Counters are absolute;
//! their difference over elapsed time gives a rate.
//! With `after`, the watch replays retained events after that sequence in
//! batches of up to 1,000. Full batches schedule another poll immediately.
//! `after:0` replays all retained events. A snapshot of an ended run already
//! has `ended:true`; the stream can end without a separate `ended` event.
//!
//! ## Packet values
//!
//! The shell run produced this packet stream:
//!
//! ```text
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" packets e13 > "$work/packets.jsonl" &
//! $ cat "$work/packets.jsonl"
//! {"event":"link","data":{"id":"e13","a":"t18","b":"s13","label":null}}
//! {"event":"packet","data":{"seq":1,"t":13.892643,"side":1,"len":58,"skipped":0,"evicted":0,"src":"10.0.0.2:58747","dst":"10.0.0.1:53","proto":"DNS","info":"Standard query 0x2257 A example.test","tags":[]}}
//! {"event":"packet","data":{"seq":2,"t":13.893495,"side":0,"len":74,"skipped":0,"evicted":0,"src":"10.0.0.1:53","dst":"10.0.0.2:58747","proto":"DNS","info":"Standard query response 0x2257 A example.test A 203.0.113.10","tags":[]}}
//! $ "$bin/fictionet" observe --observation "unix:$work/observe.sock" packet e13 1
//! {"seq":1,"t":13.892643,"side":1,"len":58,"layers":[{"name":"Internet Protocol Version 4","summary":"Src: 10.0.0.2, Dst: 10.0.0.1","buf":0,"range":[0,20],"fields":[{"name":"Version","value":"4","range":[0,1]},...]},...],"buffers":[{"name":"Packet","hex":"4500003a191b400040110d960a0000020a000001e57b00350026ab10225701000001000000000000076578616d706c6504746573740000010001"}]}
//! ```
//!
//! The initial `link` event describes the edge. Its `a`, `b` and `label` can
//! be `null` if the link is absent from the graph, including a removed link
//! whose capture remains. Each `packet` event has `seq`, `t`, `side`, `len`,
//! `skipped`, `evicted`, `src`, `dst`, `proto`, `info` and `tags`.
//! `seq` numbers decoded rows from 1 within a watch. It is separate from the
//! core packet stream sequence and the collector's copy cursor. `t` is run
//! time in seconds. `len` is the original length before snap truncation.
//! `side` is 0 for end `a`, 1 for end `b`.
//!
//! `skipped` counts sampling omissions since the preceding copy. `evicted`
//! counts copies lost before decoding since the preceding row. If every copy
//! is evicted, the next decoded row carries that loss. Sampling counts carried
//! by evicted copies are unavailable. Capture loss does not leave holes in
//! row numbers. Tags include `decrypted`, `retransmission`, `reset`, `fragment`,
//! `gap`, `malformed` and `dns-error`.
//!
//! A subscriber whose cursor predates retained rows receives a gap first:
//!
//! ```json
//! {"event":"packet_gap","data":{"after":7,"next":12,"missed":4}}
//! ```
//!
//! Here rows 8 through 11 are missing. `next` is the first retained row, or
//! the next row number to be assigned if none remain. The cursor advances
//! past the gap so it is reported once. This applies to `after:0` too.
//! It counts decoded rows, not copies or sampling omissions. Merged dashboard
//! streams add `link` to packet and gap data. Pcapng contains retained packet
//! bytes and keys; these JSON loss counts are not written into that file.
//!
//! Packet detail has `seq`, `t`, `side`, `len`, `layers` and `buffers`.
//! A layer has `name`, `summary`, `buf`, `range` and `fields`. Fields have
//! `name`, `value` and an optional `range`. Ranges are half-open `[start,end)`
//! byte offsets in the layer's buffer. Buffer 0 is the packet. Other buffers
//! hold decrypted or reassembled bytes. Each buffer has `name` and `hex`.
//! Details are bounded to about 1 MiB; a final `Not shown` layer counts omitted
//! content when one packet completes too much data.
//!
//! `packets` polls every 100 ms, sends up to 500 rows per poll, and schedules
//! another poll immediately while behind. It drains kept copies and rows
//! before `end`, whose reason is `the link closed`, `the world ended` or
//! `cancelled`.
//!
//! ## Errors and stream transport
//!
//! [`Value::envelope`] recognizes event and error JSON by fields, regardless
//! of whitespace, key order or string escapes. Recognition has no size,
//! element-count or nesting-depth limit. Invalid JSON, duplicate envelope
//! fields, mixed event/error objects, and missing or wrongly typed fields
//! are not recognized. Binary values are not inspected.
//! The CLI preserves original bytes. The dashboard forwards original JSON
//! data as server-sent events, with one `data:` line per JSON line. Event
//! names with line breaks or the reserved browser name `error` become errors.
//!
//! A boundary close differs from a partial value. The CLI accepts a boundary
//! close after `ended`; a partial value exits with status 1 even after `ended`.
//! Other request failures also exit with status 1; bad CLI arguments use 2.
//! The dashboard emits `end` with `the world closed` for a boundary close.
//! Framing errors and single-stream refusals emit `world_error` with `error`.
//! Merged refusals emit `link_error` with `link` and `error`; other links
//! continue until the merged stream ends. The browser displays terminal
//! reasons without retrying. Transient connection drops reconnect.
//! Non-stream framing errors return HTTP 502 with JSON.
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// The copyable decoders name this crate as their users do.
extern crate self as fictionet_observe;

mod aggregate;
mod capture;
mod keys;
mod loss;
mod memory;
mod topology;

#[cfg(feature = "page")]
pub mod page;

#[cfg(feature = "decode")]
mod dashboard;
#[cfg(feature = "decode")]
mod decode;
#[cfg(feature = "decode")]
mod json;
#[cfg(feature = "decode")]
mod value;
#[cfg(feature = "decode")]
mod view;
#[cfg(feature = "decode")]
mod watch;
#[cfg(feature = "decode")]
pub use dashboard::{DashboardHandle, DashboardObserver, DashboardOptions, Session};
#[cfg(feature = "decode")]
pub use decode::{
    Conversation, Decoded, Dissector, Field, KeyLine, Layer, Match, Observed, Place, Placement,
    Present, Protocol, Registry, Selection, hex, http2, protocols, tls,
};
#[cfg(feature = "decode")]
pub use value::{Envelope, Value};
#[cfg(all(feature = "native", unix))]
mod endpoint;
#[cfg(all(feature = "native", unix))]
pub use endpoint::{Client, Endpoint, serve};

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod jsonl;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use jsonl::Jsonl;
#[cfg(feature = "tracing")]
mod tracing_bridge;
#[cfg(feature = "tracing")]
pub use tracing_bridge::Tracing;

pub use aggregate::Aggregate;
pub use memory::{DisplayBatch, Incomplete, Limits, Memory};

/// Default number of ordinary events retained by [`Memory`], separate from noise.
pub const MAX_EVENTS: usize = 50_000;
/// Default ordinary event bytes, as counted by [`fictionet::events::Event::size`], separate from noise.
pub const MAX_EVENT_BYTES: usize = 16 << 20;

pub use capture::{CaptureDemand, CapturePolicy, PacketBatch, PacketCopy};
pub use keys::{Key, keylog};
pub use loss::{LossStatus, LossTotal};
pub use topology::{Connection, Group, Host, Link, Task, Topology, TopologyLimits};

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fictionet::events::{
    Counts, Interest, LinkId, Loss, LossReason, Observation, Observer, Stamp, Stream, TopologyRef,
};
use fictionet::sync::Mutex;
use fictionet::time::Instant;

use capture::{CaptureFlag, Captures};
use keys::Keys;

/// Count and byte bounds. Zero refuses retention.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Maximum retained items.
    pub count: usize,
    /// Maximum retained bytes.
    pub bytes: usize,
}

/// All collector limits and capture policies.
#[derive(Clone, Debug)]
pub struct Options {
    /// Ordinary event retention; none declines events.
    pub events: Option<Limits>,
    /// Separate retention for repeating network events.
    pub noise: Limits,
    /// Topology count and text limits.
    pub topology: TopologyLimits,
    /// Capture policy for sandbox links.
    pub sandbox_capture: CapturePolicy,
    /// Capture policy for other links.
    pub capture: CapturePolicy,
    /// Maximum bytes copied from each packet.
    pub snap_len: usize,
    /// Per-link packet count and payload byte limits.
    pub packets: Bounds,
    /// Aggregate packet payload byte budget across links.
    pub packet_bytes: usize,
    /// TLS key retention; none declines keys.
    pub keys: Option<Bounds>,
    /// Maximum streams with detailed loss totals. Further loss remains in
    /// `LossStatus::untracked`, grouped by cause without stream identity.
    pub loss_streams: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            events: Some(Limits::default()),
            noise: Limits::new(5000, 2 << 20),
            topology: TopologyLimits::default(),
            sandbox_capture: CapturePolicy::Startup,
            capture: CapturePolicy::Demand,
            snap_len: 65_535,
            packets: Bounds {
                count: 4096,
                bytes: 8 << 20,
            },
            packet_bytes: 64 << 20,
            keys: Some(Bounds {
                count: 20_000,
                bytes: 8 << 20,
            }),
            loss_streams: 4099,
        }
    }
}

/// A bounded collector for one run. Callbacks copy and update state on the
/// caller's thread. Readers own their snapshots and copies.
pub struct Collector {
    options: Options,
    events: Memory,
    flags: ArcSwap<BTreeMap<LinkId, Arc<CaptureFlag>>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    topology: Topology,
    captures: Captures,
    keys: Keys,
    losses: LossStatus,
    ended: Option<Instant>,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl Collector {
    /// Creates a collector before installing it on a run.
    pub fn new(options: Options) -> Self {
        Self {
            events: Memory::with_noise_limits(
                options.events.unwrap_or(Limits::new(0, 0)),
                options.noise,
            ),
            options,
            flags: ArcSwap::from_pointee(BTreeMap::new()),
            state: Mutex::new(State::default()),
        }
    }

    /// The retained event observer, including its grading and cursor methods.
    pub fn events(&self) -> &Memory {
        &self.events
    }
    /// A revisioned, bounded snapshot of current entities.
    pub fn topology(&self) -> Topology {
        self.state.lock().topology.clone()
    }
    /// Live absolute counters for every retained link.
    pub fn counters(&self) -> BTreeMap<LinkId, [Counts; 2]> {
        self.topology().counters()
    }
    /// Retained copies after a copy cursor and the number evicted before them.
    pub fn packets(&self, link: LinkId, after: u64, max: usize) -> PacketBatch {
        self.state
            .lock()
            .captures
            .links
            .get(&link)
            .map_or_else(PacketBatch::default, |c| c.since(after, max))
    }
    /// Retained TLS keys, ordered by stream sequence.
    pub fn keys(&self) -> Vec<Key> {
        self.state.lock().keys.items.iter().cloned().collect()
    }
    /// Retained TLS keys in SSLKEYLOGFILE format.
    pub fn keylog(&self) -> String {
        keylog(&self.keys())
    }
    /// Persistent loss totals, including producer loss.
    pub fn losses(&self) -> LossStatus {
        self.state.lock().losses.clone()
    }
    /// Run end time, when delivery has ended.
    pub fn ended(&self) -> Option<Instant> {
        self.state.lock().ended
    }
    /// Starts or joins demand capture. Off and unknown links return none.
    pub fn capture_demand(&self, link: LinkId) -> Option<CaptureDemand> {
        self.flags.load().get(&link)?.demand()
    }
    /// Retained TLS keys after stream sequence `after`.
    #[cfg(feature = "decode")]
    pub(crate) fn keys_after(&self, after: u64) -> Vec<Key> {
        let state = self.state.lock();
        let items = &state.keys.items;
        let start = items.partition_point(|k| k.stamp.seq <= after);
        items.range(start..).cloned().collect()
    }
    /// The link numbered `number`, if it is current or its capture is kept.
    #[cfg(feature = "decode")]
    pub(crate) fn find_link(&self, number: u64) -> Option<LinkId> {
        let state = self.state.lock();
        let topology = state.topology.links.keys();
        let captured = state.captures.links.keys();
        topology
            .chain(captured)
            .find(|id| id.get() == number)
            .copied()
    }
    /// Whether `link` is current: registered and not removed.
    #[cfg(feature = "decode")]
    pub(crate) fn live(&self, link: LinkId) -> bool {
        self.state.lock().topology.links.contains_key(&link)
    }
}

impl Observer for Collector {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        match interest {
            Interest::Event(..) => self.options.events.is_some(),
            Interest::Topology(_) => true,
            Interest::TlsKey(_) => self.options.keys.is_some(),
            Interest::Packet(packet) => {
                let flags = self.flags.load();
                flags.get(&packet.link).map_or(
                    self.options.capture == CapturePolicy::Startup
                        || self.options.sandbox_capture == CapturePolicy::Startup,
                    |flag| flag.enabled(),
                )
            }
        }
    }

    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        if let Observation::Event(event) = item {
            if self.options.events.is_none() || self.state.lock().ended.is_some() {
                return;
            }
            let before = self.events.dropped();
            self.events.observe(stamp, Observation::Event(event));
            let dropped = self.events.dropped().saturating_sub(before);
            let mut state = self.state.lock();
            let losses = &mut state.losses;
            if dropped > 0 {
                let retained = self
                    .events
                    .after(stamp.seq.saturating_sub(1), 1)
                    .first()
                    .is_some_and(|e| e.seq == stamp.seq);
                let reason = if retained {
                    LossReason::Eviction
                } else {
                    LossReason::Overflow
                };
                losses.event_loss(self.options.loss_streams, reason, dropped);
            }
            if event.is_truncated() {
                losses.record(self.options.loss_streams, stamp, LossReason::Truncation, 0);
            }
            return;
        }
        let mut state = self.state.lock();
        if state.ended.is_some() {
            return;
        }
        let State {
            topology,
            captures,
            keys,
            losses,
            ..
        } = &mut *state;
        match item {
            Observation::TlsKey(key) => {
                if let Some(bounds) = self.options.keys {
                    keys.push(stamp, key, bounds, losses, self.options.loss_streams);
                }
            }
            Observation::Packet(packet) => {
                if self.enabled(Interest::Packet(fictionet::events::PacketMeta {
                    link: packet.link,
                    side: packet.side,
                    len: packet.len,
                    link_type: packet.link_type,
                })) {
                    captures.push(stamp, packet, &self.options, losses);
                }
            }
            Observation::Topology(item) => {
                let link = match &item {
                    TopologyRef::LinkAdded { link, sandbox, .. } => Some((
                        *link,
                        Some(if sandbox.is_some() {
                            self.options.sandbox_capture
                        } else {
                            self.options.capture
                        }),
                    )),
                    TopologyRef::LinkRemoved { link, .. } => {
                        captures.retired(*link);
                        Some((*link, None))
                    }
                    _ => None,
                };
                topology.apply(
                    stamp,
                    item,
                    self.options.topology,
                    losses,
                    self.options.loss_streams,
                );
                if let Some((id, policy)) = link {
                    let mut flags = (**self.flags.load()).clone();
                    if let Some(policy) = policy.filter(|_| topology.links.contains_key(&id)) {
                        flags.insert(id, Arc::new(CaptureFlag::new(policy)));
                        if policy != CapturePolicy::Startup {
                            captures.remove(id, losses, self.options.loss_streams);
                        }
                    } else {
                        flags.remove(&id);
                        if policy.is_some() {
                            captures.remove(id, losses, self.options.loss_streams);
                        }
                    }
                    self.flags.store(Arc::new(flags));
                }
            }
            _ => {}
        }
    }

    fn lost(&self, loss: Loss) {
        let mut state = self.state.lock();
        if state.ended.is_some() {
            return;
        }
        if loss.stream == Stream::Topology && loss.count > 0 {
            state.topology.incomplete = true;
            state.topology.revision = state.topology.revision.saturating_add(1);
        }
        state.losses.add(self.options.loss_streams, loss.clone());
        drop(state);
        if loss.stream == Stream::Events {
            self.events.lost(loss);
        }
    }

    fn end(&self, at: Instant) {
        let mut state = self.state.lock();
        if state.ended.is_none() {
            state.ended = Some(at);
            drop(state);
            self.events.end(at);
        }
    }
}

#[cfg(test)]
mod tests;
