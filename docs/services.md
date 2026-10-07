# Services and networks

This guide builds a small world step by step: a service, a test for it,
a network of hosts that serve it, a log a grader reads, and a scenario
that changes the world while it runs. Every piece is a public module of
`fictionet::stdlib`, so each file can be copied into a world's crate and
changed there. The events every piece records go to `fictionet::events`,
the one log each run keeps.

| Module | What it gives |
|---|---|
| `serve` | The `Service` trait, the driver that runs a service over a connection (`serve`, `listen`, `serve_datagram`), a `Harness` for tests, transcripts and fault plans |
| `fictionet::events` | Not in the stdlib: the run's log of `Event`s, in one shape, kept whether or not anyone reads it, and read as a file, by callbacks, by a grader in the same process, and by the dashboard |
| `net` | `Net`: the sandboxes' subnet, DNS, routing, one machine per address, and each `Host`'s services |
| `httpd` | HTTP as a service: `Router`, the `tower` adapter for axum, `VirtualHosts`, `Http1` |
| `scenario` | A timeline of changes to the world, and facts graded against its events |
| `web` | `Sites`, a preset on `Net` for a world of websites |

## 1. A service

A service is the server side of one protocol, for one connection. It
reads nothing and writes nothing itself. The driver decodes the client's
bytes with the service's decoder and calls the service once per item. The
service appends its reply and records what it saw:

```rust
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::events::{Event, Level};
use fictionet::stdlib::serve::{Flow, ServeCtx, Service};

/// A login prompt that takes one password and closes.
struct Prompt;

impl Service for Prompt {
    type Decode = Lines;
    type World = String; // the right password, shared by every connection
    type Error = std::convert::Infallible;

    fn decoder(&self) -> Lines {
        Lines::new(256, Ending::LfOrCrlf)
    }

    fn on_open(&mut self, _: &String, ctx: &mut ServeCtx<'_>) -> Result<Flow, Self::Error> {
        ctx.reply().extend_from_slice(b"password: ");
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, password: &String, ctx: &mut ServeCtx<'_>) -> Result<Flow, Self::Error> {
        let line = line.unwrap_or_default();
        let right = line == password.as_bytes();
        ctx.log(
            Event::new("prompt", "login")
                .summary(if right { "login" } else { "wrong password" })
                .level(if right { Level::Alarm } else { Level::Info })
                .field("right", right),
        );
        ctx.reply().extend_from_slice(if right { b"welcome\n" } else { b"no\n" });
        Ok(Flow::Close)
    }
}
```

`World` is the state every connection shares: here a password, in a real
world a directory, a process model or an order book. The service itself
is made fresh for each connection.

A service can also:

- **Run timers.** `ctx.set_timer("heartbeat", d)` arms a named timer and
  `on_timer` hears which one went off. A FIX session has four (heartbeat,
  TestRequest, logon, logout), each armed and cancelled on its own. A due
  timer is handled before more input is read, so a client that never
  stops sending cannot starve it.
- **Be woken.** `ctx.wake_handle()` gives a handle the world keeps, such
  as next to an order in the book. When another trader's order fills it,
  that connection calls `handle.wake()`, and this connection's `on_wake`
  writes the execution report. SMB2 oplock breaks, LDAP persistent search
  and MCP notifications work the same way.
- **Hand over async work.** `ctx.defer(work)` runs work whose bytes are
  written in order before the next item (an HTTP/1 response from a tower
  service). `ctx.defer_keyed(key, work)` runs work beside the reads and
  the other keyed work, each writing whole frames, and `on_done` hears
  when one ends: concurrent responses, as HTTP/2 streams need.
- **Upgrade the connection.** `Flow::Upgrade(Upgrade::Tls)` shakes hands
  as a TLS server with `ServeOptions::starttls` and calls `on_open` again
  over TLS (`ctx.conn().tls` is then true): STARTTLS in SMTP, IMAP and
  LDAP, and Postgres's `SSLRequest`. `Upgrade::Decoder` goes on with a
  fresh decoder; `Upgrade::Handoff` hands the connection and its unread
  bytes back to whoever called `serve`.
- **Say what it holds.** `Service::held` reports bytes the service keeps
  for the connection, such as a request body, so they count against the
  sandbox's budget with the decoder's own.

A panic in a call closes that connection, records `conn.panic`, and the
rest of the world goes on. An error the service returns closes it and
records `conn.error`.

### One protocol, two framings

Kerberos frames a message with a four-byte length over TCP, and sends one
message per datagram over UDP. `Service::Decode` is one type, so write
two thin services over one core of your own: each picks its decoder and
hands the message to the shared code. `ctx.conn().transport` says which
one the call came over, so the KDC can answer `KRB_ERR_RESPONSE_TOO_BIG`
on UDP. Serve them with `Host::tcp(88, ..)` and `Host::udp(88, ..)` and
the same `World`.

### Dates belong to the world

`ctx.now()` is the run's clock: time since the run started, with no
date. A service that needs a date, such as for ticket lifetimes,
certificate validity or a FIX `SendingTime`, takes it from its `World`,
which decides what day it is in the world. Record the world's date in the
network's first event (`Net::start_fields` with a `world_date` field), so
a reader can place every event. The `run.start` event's `wall` field
holds the host's wall clock at the start of the run.

HTTP follows the same rule. `httpd` sends a `Date` header only when the
world gave its date at the start of the run (`Sites::date`, `Site::date`,
`Website::date`, `Http1::date` or `HttpOptions::date`), and the header is
that date plus `ctx.now()`. With no world date, responses carry no `Date`
header at all, as RFC 9110 allows for a server without a clock: a world
that never says what day it is never leaks the host's. A `Date` a handler
sets itself goes out as it is.

## 2. A test with no runtime

`Harness` runs a service with no I/O: push the client's bytes, get the
reply.

```rust
use fictionet::stdlib::serve::Harness;

let mut h = Harness::new(Prompt, "hunter2".to_owned());
assert_eq!(h.open()?, b"password: ");
assert_eq!(h.push(b"hunter2\n")?, b"welcome\n");
assert!(h.closed());
assert_eq!(h.events()[0].kind, "login");
```

The harness runs the same state machine as the driver: `advance` moves
its clock and fires timers in order, `poll` runs deferred work and wakes,
and `resume` goes on after an upgrade.

## 3. A network

`Net` builds the network around its hosts. Each host has addresses (given
with `at`, or picked from `198.18.0.0/15` and `2001:2::/48`), DNS names,
and services on its ports:

```rust
use std::sync::Arc;
use fictionet::stdlib::net::Net;

let password = Arc::new("hunter2".to_owned());
let at: std::net::Ipv4Addr = "10.20.0.5".parse()?;
Net::new()
    .host("vault", |h| h.at(at).dns_name("vault.corp.test").tcp(2323, password.clone(), || Prompt))
    .serve(&cx, attachments)?;
```

`serve` fails if a host cannot be served as declared: an address a host
cannot have, two services on one port, or a port that cannot be opened.

Every sandbox that attaches joins `10.0.0.0/24` (and `2001:db8::/64`),
gets its address by DHCP or by its first packet, and asks the gateway at
`10.0.0.1` for names. It reaches every host and no other sandbox. An
address with no host answers "host unreachable", and a closed port a RST.

Other kinds of port:

- `tcp_with(port, world, make, opts)`: the same with `ServeOptions`: a
  connection cap, an idle limit, a fault plan, a STARTTLS config.
- `udp(port, world, make)`: one service for the port, which gets every
  datagram, each decoded on its own as DNS and Modbus over UDP frame their
  messages. It can send several datagrams to anyone (`ctx.send_to`) and
  run timers, as a MoldUDP64 server does for retransmissions and
  heartbeats.
- `tls(port, sni, config, world, make)`: TLS first, picked by the name the
  client sends (`Sni::Any`, `Sni::Names` for the host's DNS names, or one
  name); several calls on one port route by SNI.
- `accept(port, accept)` and `tls_accept(port, sni, config, accept)`: an
  `Accept` of the world's own. HTTP is one: `httpd::Site`, below.

Each sandbox may hold 256 connections at once to one machine, and the
bytes its connections hold together are charged to its budget (256 MiB);
`Net::limits` changes these and the handshake and DNS timers. Tests set
small ones. `Net::seed` seeds every service's randomness, mixed with each
connection's number, so a run whose connections arrive in the same order
repeats.

`Net::lan(name, prefix)` adds an IP subnet that hosts join with
`Host::on(name)` and real virtual machines with
`Net::member(attachment, name, addr)`, as machines on one Ethernet:
broadcast and multicast reach every member, so a MoldUDP64 feed sent to a
group reaches every member that joined it (`udp::Endpoint::join`). The
router sends the prefix to the LAN, its first address answers DNS for the
members, and the LAN's drops are recorded as `net.blocked` events with
`why` `Lan`:

```rust
Net::new()
    .lan("corp", "192.168.56.0/24".parse()?)
    .host("dc01", |h| h.on("corp").at(dc01).dns_name("dc01.corp.test").tcp(389, directory, || Ldap))
    .member("ws01", "corp", "192.168.56.31".parse()?)
    .serve(&cx, attachments)?;
```

`Net::route(name, prefix)` wires a trusted sandbox, such as a real
container that plays one of the hosts, straight to the router at a fixed
prefix. `Net::resolve` makes a host the first time a name is looked up,
which is how `web::Sites` works.

## 4. HTTP

HTTP is a service like the others. A `Router`'s handlers get the request
with its body as bytes, and return a response:

```rust
use bytes::Bytes;
use fictionet::stdlib::httpd::Router;

let api = Router::new()
    .get("/status", |_, _| http::Response::new(Bytes::from("ok\n")))
    .post("/echo", |_, request: http::Request<Bytes>| http::Response::new(request.into_body()));
```

An axum `Router`, or any tower service over `http::Request<web::Body>`,
runs with `httpd::tower(service)`. A handler adds facts to its request's
event by putting `events::Fields` in its response's extensions.

On a network, `httpd::Site` is the `Accept` that serves a handler on a
port, and `httpd::Website` puts one on ports 80 and 443 as `web::Sites`
does:

```rust
use fictionet::stdlib::httpd::{Site, Website};

Net::new()
    .host("intranet", |h| h.dns_name("intranet.corp.test").accept(80, Site::new(api.clone())))
    .add_host(Website::new(api).tls(move |_| config.clone()).on(Host::new("www").dns_name("www.corp.test")))
    /* ... */;
```

Sites of several hosts at one address share the port as virtual hosts:
the first host's `Site` takes in the others through `Accept::share`. `Net`
itself knows nothing of HTTP, so a copy of `httpd` with its own handlers
plugs in the same way.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder. HTTP/2
runs on hyper behind the same `Handler` trait until the stdlib's own
HTTP/2 lands; handlers will not change.

## 5. Events

Every run keeps a log of events, with nothing to set up, and every fact
lands in it: sandboxes attaching and binding addresses, DNS queries, TLS
handshakes, HTTP requests, packets the network dropped, routes and LAN
members that went away, and every service's own events. World code
records its own with `cx.record(Event::new(..))`. Each event carries its
sandbox and connection number, a sequence number from 1, and its time on
the run's clock:

```rust
let events = cx.events();
events.to_file("/var/lib/fictionet/events.jsonl")?; // for a grader after the run
Net::new() /* ... */.serve(&cx, attachments)?;
// For a grader in the same process, during the run or after it:
let logins = events.of("prompt", "login");
```

The file has one JSON object per line: `seq`, `at`, `source`, `kind`,
`level`, `summary`, `sandbox`, `conn`, `local`, `peer`, `transport`,
`sni`, `fields`, then the task that recorded it (`node`, `task`, `file`,
`line`, `parent`). The network's first event is `run.start`, whose `wall`
field puts the run's clock on a calendar. Field names are fixed by the
code that records; names that come from the wire, such as LDAP
attributes, go under one field as an object.

The log holds the latest 50,000 events, up to 16 MiB of them
(`events::MAX_EVENTS`, `events::MAX_EVENT_BYTES`), and drops the oldest
past that. A file or a callback set halfway through a run first gets
what the log still holds, then every event that follows, so it misses
nothing unless the log had already dropped some. A reader that missed
events gets one `events.dropped` event that counts them. A line the
file's writer could not keep up with is counted in `events.lost()`; a
grader throws such a sample away.

## 6. A scenario

A scenario changes the world on a timeline and says what its events
should show:

```rust
use std::time::Duration;
use fictionet::stdlib::scenario::Scenario;
use fictionet::stdlib::serve::{FaultPlan, Plan};
use fictionet::stdlib::codec::{ByteFault, Rule, Trigger};

let faults = FaultPlan::default();
let scenario = Scenario::new()
    .faults(Duration::from_secs(30), &faults, Plan {
        seed: 7,
        outbound: vec![Rule { when: Trigger::Always, fault: ByteFault::Delay(Duration::from_secs(2)) }],
        ..Plan::default()
    })
    .forbid("the agent logged in", |e| e.is("prompt", "login") && e.get("right").and_then(|v| v.as_bool()) == Some(true));
let checks = scenario.checks();
let _timeline = scenario.run(&cx, world_state);
// During the run or after it:
let report = checks.grade(&cx.events().all());
```

A fault plan given to a service's `ServeOptions` (`Host::tcp_with`) acts
on every connection from its next chunk or item: byte faults each way,
and item faults on what the client sends.

## 7. The dashboard

The dashboard lists the events under **Events**, from what the log held
when it connected. To decode a service's packets there, register its decoder as a `Present`
in an `observe::Registry`, and give the registry to `Net::observe`. The
built-in registry already decodes DNS, HTTP, TLS, Modbus and many more.

## Moving a world from `Sites::on_event`

- `Sites::on_event(f)` is `cx.events().subscribe(f)`.
- `web::Event::Dns` is an event with source `dns`, kind `query`; `Tls` is
  `tls.handshake`; `Http` is `http.request`; `HttpError` is `http.error`;
  `Attached`, `Bound`, `Detached` and `Blocked` are `net.*`. The sandbox and
  connection number are in `event.conn`.
- Handlers take `http::Request<web::Body>` instead of hyper's `Incoming`.
- A response extension a handler used for the log becomes
  `events::Fields`, which arrive as the event's fields.
