# Services and networks

This guide builds a small world step by step: a service, a test for it,
a network of hosts that serve it, and a log a grader reads. Every piece is
a public module of `fictionet::stdlib`, so each file can be copied into a world's crate and
changed there. The events every piece records go to `fictionet::events`,
the one log each run keeps.

| Module | What it gives |
|---|---|
| `serve` | The `Service` trait, the driver that runs a service over a connection (`connection`, `listen`, `datagram`), a `Harness` for tests, transcripts and fault plans |
| `fictionet::events` | Not in the stdlib: the run's log of `Event`s, in one shape, kept whether or not anyone reads it, and read as a file, by callbacks, by a grader in the same process, and by the dashboard |
| `net` | `Net`: the sandboxes' subnet, DNS, routing, one machine per address, and each `Host`'s services |
| `httpd` | HTTP as a service: `Router`, the `tower` adapter for axum, `VirtualHosts`, `Http1` |
| `web` | `Sites`, a preset on `Net` for a world of websites |

## 1. A service

A service is the server side of one protocol, for one connection. It
reads nothing and writes nothing itself. The driver decodes the client's
bytes with the service's decoder and calls the service once per item. The
service appends its reply and records what it saw:

```rust
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::events::{Event, Level};
use fictionet::stdlib::serve::{Flow, Driver, Service};

/// A login prompt that takes one password and closes.
struct Prompt;

impl Service for Prompt {
    type Decoder = Lines;
    type State = String; // the right password, shared by every connection
    type Error = std::convert::Infallible;

    fn decoder(&self) -> Lines {
        Lines::new(256, Ending::LfOrCrlf)
    }

    fn on_open(&mut self, _: &String, driver: &mut Driver<'_, Self::Decoder>) -> Result<Flow, Self::Error> {
        driver.reply().extend_from_slice(b"password: ");
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, line: Result<Vec<u8>, LineError>, password: &String, driver: &mut Driver<'_, Self::Decoder>) -> Result<Flow, Self::Error> {
        let line = line.unwrap_or_default();
        let right = line == password.as_bytes();
        driver.record(
            Event::new("prompt", "login")
                .summary(if right { "login" } else { "wrong password" })
                .level(if right { Level::Alarm } else { Level::Info })
                .field("right", right),
        );
        driver.reply().extend_from_slice(if right { b"welcome\n" } else { b"no\n" });
        Ok(Flow::Close)
    }
}
```

`State` is what every connection shares: here a password, in a real
world a directory, a process model or an order book. The service itself
is made fresh for each connection.

A service can also:

- **Run timers.** `driver.set_timer("heartbeat", d)` arms a named timer and
  `on_timer` hears which one went off. A FIX session has four (heartbeat,
  TestRequest, logon, logout), each armed and cancelled on its own. A due
  timer is handled before more input is read, so a client that never
  stops sending cannot starve it.
- **Be woken.** `driver.wake_handle()` gives a handle the world keeps, such
  as next to an order in the book. When another trader's order fills it,
  that connection calls `handle.wake()`, and this connection's `on_wake`
  writes the execution report. SMB2 oplock breaks, LDAP persistent search
  and MCP notifications work the same way.
- **Hand over async work.** `driver.defer(work)` runs work whose bytes are
  written in order before the next item (an HTTP/1 response from a tower
  service). `driver.defer_keyed(key, work)` runs work beside the reads and
  the other keyed work, each writing whole frames, and `on_done` hears
  when one ends: concurrent responses, as HTTP/2 streams need.
- **Upgrade the connection.** `Flow::Upgrade(Upgrade::Tls)` shakes hands
  as a TLS server with `ServeOptions::starttls` and calls `on_open` again
  over TLS (`driver.conn().tls` is then true): STARTTLS in SMTP, IMAP and
  LDAP, and Postgres's `SSLRequest`. `Upgrade::Decoder` goes on with a
  fresh decoder. `Upgrade::Handoff` hands the connection and its unread
  bytes back to whoever called `serve::connection`. A port served with `Host::tcp`
  or `tcp_with` closes such a connection. To go on with it, serve the port
  with a `PortServer` of your own, as `httpd::Server` does.
- **Say what it holds.** `Service::held` reports bytes the service keeps
  for the connection, such as a request body, and `Pending::held` what
  deferred work keeps, such as a response body not yet written. They
  count against the sandbox's budget with the decoder's own and the reply
  bytes waiting to be written.

An error the service returns closes its connection and records
`conn.error`. A panic is a bug in the world, and Fictionet does not catch
it: it ends the run, wherever in the world it happens. As it unwinds,
the driver names the service and the connection on standard error after
the panic's own message, so the failed run says where to look.

When the world stops, `on_end` hears `Ended::Cancelled`, and `serve::connection`
returns `Err(ServeError::Cancelled)`, also when the stop comes during the
TLS handshake, before the service started. `datagram` returns
`Err(Cancelled)`. A stop is never reported as a closed or broken
connection. `listen` and `Net` serve each connection in a task of its
own; a connection's failure is that connection's, recorded as
`conn.error`, and does not end the world.

A write that takes no bytes for `ServeOptions::write_timeout` (10
seconds) ends the connection: a client that stops reading cannot hold a
reply, or a service's timers, for ever. A client that resets the
connection ends it at once, also while a write waits.

### One protocol, two framings

Kerberos frames a message with a four-byte length over TCP, and sends one
message per datagram over UDP. `Service::Decoder` is one type, so write
two thin services over one core of your own: each picks its decoder and
hands the message to the shared code. `driver.conn().transport` says which
one the call came over, so the KDC can answer `KRB_ERR_RESPONSE_TOO_BIG`
on UDP. Serve them with `Host::tcp(88, ..)` and `Host::udp(88, ..)` and
the same `State`.

### Dates belong to the world

`driver.now()` is the run's clock: time since the run started, with no
date. A service that needs a date, such as for ticket lifetimes,
certificate validity or a FIX `SendingTime`, takes it from its `State`,
which decides what day it is in the world. Record the world's date in the
network's first event (`Net::start_fields` with a `world_date` field), so
a reader can place every event. The `run.start` event's `wall` field
holds the host's wall clock at the start of the run.

HTTP follows the same rule. `httpd` sends a `Date` header only when the
world gave its date at the start of the run (`Sites::date`, `Server::date`,
`Website::date`, `Http1::date` or `HttpOptions::date`), and the header is
that date plus `driver.now()`. With no world date, responses carry no `Date`
header at all, as RFC 9110 allows for a server without a clock: a world
that never says what day it is never leaks the host's. A `Date` a handler
sets itself goes out as it is.

## 2. A test with no runtime

`Harness` runs a service with no I/O: push the client's bytes, get the
reply.

```rust
use fictionet::stdlib::serve::Harness;

let mut h = Harness::new(fictionet::Seed::from_u64(0), Prompt, "hunter2".to_owned());
assert_eq!(h.open()?, b"password: ");
assert_eq!(h.push(b"hunter2\n")?, b"welcome\n");
assert!(h.closed());
assert_eq!(h.events()[0].kind, "login");
```

The harness runs the same state machine as the driver: `advance` moves
its clock and fires timers in order, `poll` runs deferred work and wakes,
and `resume` goes on after an upgrade. Its standalone entropy stream starts
from the supplied `Seed`. Calling `with_fcx` before opening it binds both
its clock and randomness to that run; use the run's sleeps and `poll` then,
because manual `advance` is only available to standalone harnesses.

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
    .start(&fcx, attachments)?;
```

`start` fails if a host cannot be served as declared: an address a host
cannot have, two services on one port, or a port that cannot be opened.

Every sandbox that attaches joins `10.0.0.0/24` (and `2001:db8::/64`),
gets its address by DHCP or by its first packet, and asks the gateway at
`10.0.0.1` for names. It reaches every host and no other sandbox. An
address with no host answers "host unreachable", and a closed port a RST.

Other kinds of port:

- `tcp_with(port, world, make, opts)`: the same, with `ServeOptions` for
  a connection cap, an idle limit, a fault plan or a STARTTLS config.
  Setting `opts.connection_events` to false turns the `conn.open` and
  `conn.close` events off.
- `udp(port, world, make)`: one service for the port, which gets every
  datagram, each decoded on its own as DNS and Modbus over UDP frame their
  messages. It can send several datagrams to anyone (`driver.send_to`) and
  run timers, as a MoldUDP64 server does for retransmissions and
  heartbeats.
- `tls(port, sni, config, world, make)`: TLS first, picked by the name the
  client sends (`Sni::Any`, `Sni::Names` for the host's DNS names, or one
  name); several calls on one port route by SNI.
- `port_server(port, server)` and `tls_accept(port, sni, config, server)`: a
  `PortServer` of the world's own. HTTP is one: `httpd::Server`, below.

Each sandbox may hold 256 connections at once to one machine. What its
connections hold is charged to one budget per sandbox, 256 MiB by default.
The driver counts each connection's read buffer or its decoder's capacity,
whichever is larger, the input its decoder has not used yet, queued
replies, and what the service and its deferred work report holding.
Memory outside those counts, such as hyper's own buffers, is not charged.
`Net::limits` changes these limits and the TLS handshake and DNS timers.
Its handshake timer also applies to STARTTLS. Tests set small ones.
`fictionet::run(seed, world)` gives TCP, UDP, services, HTTP exchanges and
fault decisions one ChaCha20 byte stream through `Cx`. The same seed and
ordered draws produce the same numbers. HTTP/2 handlers also draw from
this run stream, so their execution order matters.

`Net::lan(name, prefix)` adds an IP subnet that hosts join with
`Host::on(name)` and real virtual machines with
`Net::member(attachment, name, addr)`, as machines on one Ethernet:
broadcast and multicast reach every member, so a MoldUDP64 feed sent to a
group reaches every member that joined it (`udp::Endpoint::join`). The
router sends the prefix to the LAN, its first address answers DNS for the
members, and the LAN's drops are recorded as `net.blocked` repeats with
`why` `Lan` (see Events below):

```rust
Net::new()
    .lan("corp", "192.168.56.0/24".parse()?)
    .host("dc01", |h| h.on("corp").at(dc01).dns_name("dc01.corp.test").tcp(389, directory, || Ldap))
    .member("ws01", "corp", "192.168.56.31".parse()?)
    .start(&fcx, attachments)?;
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

On a network, `httpd::Server` is the `PortServer` that serves a handler on a
port, and `httpd::Website` puts one on ports 80 and 443 as `web::Sites`
does:

```rust
use fictionet::stdlib::httpd::{Server, Website};

Net::new()
    .host("intranet", |h| h.dns_name("intranet.corp.test").port_server(80, Server::new(api.clone())))
    .add_host(Website::new(api).tls(move |_| config.clone()).served_by(Host::new("www").dns_name("www.corp.test")))
    /* ... */;
```

Sites of several hosts at one address share the port as virtual hosts:
the first host's `Server` takes in the others through `Accept::share`. `Net`
itself knows nothing of HTTP, so a copy of `httpd` with its own handlers
plugs in the same way.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder. HTTP/2
runs on hyper, behind the same `Handler` trait. The stdlib's `http2`
module reads and writes HTTP/2 frames and tracks a session's state, but it
does not serve. Both versions share one set of `httpd::Limits`: body size,
body and write timers, and 100 streams at once on an HTTP/2 connection.
Both charge the request and response bodies they hold to the sandbox's
budget, and both draw a handler's randomness from the run's stream.

Each request is one `http.request` event. Its `sent` field counts the
body bytes the connection took, and `complete` says whether it took all
of them. Over HTTP/1 a byte counts once it is written to the connection,
and the event is made after the last one is: a client that stops reading
or resets the connection mid-body leaves `complete: false` and the bytes
it got. Over HTTP/2 a byte counts once hyper takes it for the stream.

## 5. Events

Every run keeps a log of events, with nothing to set up, and every fact
lands in it: sandboxes attaching and binding addresses, DNS queries, TLS
handshakes, HTTP requests, packets the network dropped, routes and LAN
members that went away, and every service's own events. World code
records its own with `fcx.record(Event::new(..))`. Each event carries its
sandbox and connection number, a sequence number from 1, and its time on
the run's clock:

```rust
let events = fcx.events();
events.to_file("/var/lib/fictionet/events.jsonl")?; // for a grader after the run
Net::new() /* ... */.start(&fcx, attachments)?;
// For a grader in the same process, during the run or after it:
let logins = events.of("prompt", "login");
```

The file has one JSON object per line: `seq`, `at`, `source`, `kind`,
`level`, `summary`, `sandbox`, `conn`, `local`, `peer`, `transport`,
`tls`, `sni`, `alpn`, `fields`, then the task that recorded it (`node`,
`task`, `file`, `line`, `parent`). The network's first event is
`run.start`, whose `wall` field puts the run's clock on a calendar and whose
`seed` field contains the 32-byte run seed as 64 lowercase hexadecimal digits.
The `rng` field is `chacha20-v1`: ChaCha20 with contiguous byte consumption,
little-endian integers and the high 53 bits for fractions. Field
names are fixed by the code that records; names that come from the wire,
such as LDAP attributes, go under one field as an object.

Events that come once per packet, such as `net.blocked` for a packet the
network refused and `drop` from a LAN, a router or a bottleneck, are
repeats (`fcx.record_repeat`). An agent decides how many of them there
are, so the log counts them: the first of a run of alike repeats is
recorded with `count` 1, and the rest of the next second are counted
into one more event with their `count`, and with `[low, high]` for each
number that changed, such as `dst_port`. The sum of `count` is how many
packets there were. A port scan of 65,535 ports to one machine costs a
couple of events a second.

The log holds the latest 50,000 events, up to 16 MiB of them
(`events::MAX_EVENTS`, `events::MAX_EVENT_BYTES`), and drops the oldest
past that. Repeats have bounds of their own beside those: the latest
5,000, up to 2 MiB (`events::MAX_REPEATS`, `events::MAX_REPEAT_BYTES`).
A flood of repeats pushes out only older repeats, never a service's
event, an HTTP request, a DNS query, a TLS handshake or a connection's
open and close.

A file or a callback set halfway through a run first gets what the log
still holds, then every event that follows, so it misses nothing unless
the log had already dropped some. Where a reader missed events, an
`events.dropped` event counts them. The run's end records the counts
still open and waits for file writers to write every line. A line a
file's writer could not keep up with, or could not write, is counted in
`events.lost()`; a grader throws such a sample away.

## 6. The dashboard

The dashboard lists the events under **Events**, from what the log held
when it connected. To decode a service's packets there, register its decoder as a `Present`
in an `observe::Registry`, and give the registry to `Net::observe`. The
built-in registry has six decoders: `http1`, `http2`, `tls`, `modbus`, `dhcp`
and `dns`.

## Changing framing between items

A service can use a protocol module's decoder directly. `Driver::decoder()` returns the active decoder, so a mode change applies before the next item, including bytes already buffered from the same read. For SMTP, accept `DATA`, send `354`, and call `start_data()`:

```rust
use fictionet::stdlib::{smtp, serve::{Driver, Flow, Service}};

#[derive(Default)]
struct Mailbox {
    messages: Vec<Vec<u8>>,
}

impl Service for Mailbox {
    type Decoder = smtp::Inputs;
    type State = ();
    type Error = smtp::Error;

    fn decoder(&self) -> Self::Decoder {
        smtp::Inputs::new()
    }

    fn on_item(
        &mut self,
        item: Result<smtp::Input, smtp::Error>,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        match item? {
            smtp::Input::Command(command) if command.verb == "DATA" => {
                driver.decoder().start_data().map_err(smtp::Error::Framing)?;
                driver.reply().extend_from_slice(b"354 Send data\r\n");
            }
            smtp::Input::Message(bytes) => {
                self.messages.push(bytes);
                driver.reply().extend_from_slice(b"250 Queued\r\n");
            }
            _ => driver.reply().extend_from_slice(b"250 OK\r\n"),
        }
        Ok(Flow::Continue)
    }
}
```

Install it with `host.tcp(smtp::PORT, Arc::new(()), Mailbox::default)`. The SMTP decoder removes transparency dots and returns to commands after the DATA terminator. The same access lets an IMAP service refuse a literal or a Postgres service resume startup after replying `N` to an SSL request.

Accessing the decoder or upgrading the connection stops item faults and emits the `conn.faults` event with a `stopped` field. Byte faults continue. Over UDP, decoder access applies to the current datagram; each new datagram starts with a fresh decoder.
