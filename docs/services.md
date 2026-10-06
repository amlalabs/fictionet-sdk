# Services and networks

This guide builds a small world step by step: a service, a test for it,
a network of hosts that serve it, a log a grader reads, and a scenario
that changes the world while it runs. Every piece is a public module of
`fictionet::stdlib`, so each file can be copied into a world's crate and
changed there.

| Module | What it gives |
|---|---|
| `serve` | The `Service` trait, the driver that runs a service over a connection (`serve`, `listen`, `serve_datagram`), a `Harness` for tests, transcripts and fault plans |
| `journal` | One log for the whole world: `Event`s in one shape, sent to a file, callbacks, a list in memory, and the dashboard |
| `net` | `Net`: the sandboxes' subnet, DNS, routing, one machine per address, and each `Host`'s services |
| `httpd` | HTTP as a service: `Router`, the `tower` adapter for axum, `VirtualHosts`, `Http1` |
| `scenario` | A timeline of changes to the world, and facts graded against the journal |
| `web` | `Sites`, a preset on `Net` for a world of websites |

## 1. A service

A service is the server side of one protocol, for one connection. It
reads nothing and writes nothing itself. The driver decodes the client's
bytes with the service's decoder and calls the service once per item. The
service appends its reply and records what it saw:

```rust
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::journal::{Event, Level};
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

A service can also ask for a timer (`ctx.wake_in`, then `on_tick`), hand
over async work (`ctx.defer`, which the tower adapter uses), and hand the
connection back with its unread bytes (`Flow::Upgrade`, for STARTTLS).

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

## 3. A network

`Net` builds the network around its hosts. Each host has addresses (given
with `at`, or picked from `198.18.0.0/15` and `2001:2::/48`), DNS names,
and services on its ports:

```rust
use std::sync::Arc;
use fictionet::stdlib::net::Net;

let password = Arc::new("hunter2".to_owned());
Net::new()
    .host("vault")
        .at("10.20.0.5".parse::<std::net::Ipv4Addr>()?)
        .dns_name("vault.corp.test")
        .tcp(2323, password.clone(), || Prompt)
        .done()
    .serve(&cx, attachments)?;
```

Every sandbox that attaches joins `10.0.0.0/24` (and `2001:db8::/64`),
gets its address by DHCP or by its first packet, and asks the gateway at
`10.0.0.1` for names. It reaches every host and no other sandbox. An
address with no host answers "host unreachable", and a closed port a RST.

Other kinds of port:

- `udp(port, world, make)`: one datagram at a time, as DNS and Modbus over
  UDP frame their messages.
- `tls(port, sni, config, world, make)`: TLS first, picked by the name the
  client sends; several calls on one port route by SNI.
- `http(port, handler)` and `https(port, config, handler)`: HTTP sites.
  Hosts at one address share the port, and each request goes to the host
  it names.
- `web(site)`: a website on ports 80 and 443, as `web::Sites` serves one.
- `accept(port, accept)`: a connection handler of the world's own.

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
journal entry by putting `journal::Fields` in its response's extensions.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder. HTTP/2
runs on hyper behind the same `Handler` trait until the stdlib's own
HTTP/2 lands; handlers will not change.

## 5. The journal

Give the network a journal, and every fact lands in it: sandboxes
attaching and binding addresses, DNS queries, TLS handshakes, HTTP
requests, packets the network dropped, and every service's own events.
Each entry carries its sandbox and connection number:

```rust
use fictionet::stdlib::journal::Journal;

let journal = Journal::new().to_file("/var/lib/fictionet/journal.jsonl")?;
let kept = journal.keep(10_000); // for a grader in the same process
Net::new().journal(journal.clone()) /* ... */;
```

The file has one JSON object per line: `seq`, `at`, `service`, `kind`,
`level`, `summary`, `sandbox`, `conn`, `local`, `peer`, `sni`, `fields`.
An entry the file's writer could not keep up with is counted in
`journal.lost()`; a grader throws such a sample away.

## 6. A scenario

A scenario changes the world on a timeline and says what the journal
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
// After the run:
let report = checks.grade(&kept.entries());
```

A fault plan given to a service's `ServeOptions` (`Host::tcp_with`) acts
on every connection from its next chunk or item: byte faults each way,
and item faults on what the client sends.

## 7. The dashboard

Each entry also shows on the dashboard as an event named `service.kind`.
To decode a service's packets there, register its decoder as a `Present`
in an `observe::Registry`, and give the registry to `Net::observe`. The
built-in registry already decodes DNS, HTTP, TLS, Modbus and many more.

## Moving a world from `Sites::on_event`

- `Sites::on_event(f)` is `Sites::journal(journal)`, with `journal.subscribe(f)`.
- `web::Event::Dns` is an entry with service `dns`, kind `query`; `Tls` is
  `tls.handshake`; `Http` is `http.request`; `HttpError` is `http.error`;
  `Attached`, `Bound`, `Detached` and `Blocked` are `net.*`. The sandbox and
  connection number are in `entry.conn`.
- Handlers take `http::Request<web::Body>` instead of hyper's `Incoming`.
- A response extension a handler used for the log becomes
  `journal::Fields`, which arrive as the entry's fields.
