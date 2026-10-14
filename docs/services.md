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

UDP sockets and Net's DHCP server read only the declared UDP datagram.
A length below eight bytes or beyond the IP payload is dropped. Trailing
IP payload bytes do not enter delivery or checksum validation. Net uses
the same boundary when recording closed-port replies. A zero checksum is
accepted only over IPv4.

For raw packets, `udp::Datagram::parse` borrows that boundary without
checking the checksum; `checksum_ok` checks it separately. TAP uses the
same parser for complete datagrams and leaves checksums to the recipient.
It classifies first fragments by port without parsing a complete datagram.
`udp::encode` writes into a caller-owned buffer, sized with `encoded_len`.
It checks address families and IP size limits and always writes a checksum.
Allocation, MTU limits, fragments and IP header fields stay with the caller.

TDS response decoding has two separate ceilings: 4 MiB of wire bytes and
1,048,576 decoded units per reader or written token stream. These are codec
limits, not a process-memory bound; see the [`tds` module docs](../src/stdlib/tds.rs)
for the accounting rules and exclusions.

`codec::reserve_bytes` reserves space for additional bytes under a caller's
exact total limit. It leaves the vector's length and contents unchanged.
`ReserveError::TooLong` reports length overflow or a total above the limit;
`ReserveError::Allocation` reports storage refusal. Copied protocol modules
can use this public helper and map each reason to their own error.
`codec::append_bounded` keeps its separate `Buffer::MAX_LIMIT` clamp.

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

TCP disappearance watches wake when either side resets the connection or
the endpoint stops, even while a handler keeps the connection without
reading it. A local reset makes retained handles report `ConnError::Reset`;
an endpoint stop makes them report `ConnError::Closed`. The reset socket
stays until its RST can be sent, even when packet output is full.

After a graceful close, a dropped TCP connection releases its
`hold_until_gone` items, including connection counts, when it reaches
TIME-WAIT. Its `GoneWatch` becomes ready, and resetting it does nothing.
Only transport recovery state stays: the socket, tuple, buffers and outgoing
port remain until smoltcp's ten-second transport timer expires. Retransmitted
FINs get ACKs and restart that timer without holding connection counts.
Each endpoint retains at most 1,024 dropped TIME-WAIT sockets. If more
accumulate, housekeeping forgets them in the order it first saw them as
TIME-WAIT orphans; later packets for those tuples may get RSTs. This cap
does not evict sockets with live handles or sockets still closing. At the
default buffer size the cap retains up to 512 MiB of buffer address space.
On native builds, empty buffer pages can be released while the mappings
stay; browser buffers use the heap. Larger configured buffers increase
this bound.

TCP takes the peer's initial sequence number only from an accepted handshake.
Invalid or unsolicited SYN-ACKs cannot move the connection's receive window
or keep its buffer pages resident.

A pending TCP connect fails with `ConnError::Unreachable(code)` when an
ICMPv4 destination-unreachable message quotes its local and remote addresses,
ports, and current SYN sequence number. The code is the ICMP code, such as
1 for host unreachable. Code 4 (fragmentation needed) is ignored; TCP does
no path MTU discovery. A quote needs the IP header and at least eight TCP
bytes. Malformed, unrelated, and stale quotes are ignored. Other pending
connects and established connections are unaffected. Attach uses this TCP
result for its HTTP and SOCKS error replies.

### One protocol, two framings

Kerberos frames a message with a four-byte length over TCP, and sends one
message per datagram over UDP. `Service::Decoder` is one type, so write
two thin services over one core of your own: each picks its decoder and
hands the message to the shared code. `driver.conn().transport` says which
one the call came over, so the KDC can answer `KRB_ERR_RESPONSE_TOO_BIG`
on UDP. Serve them with `Host::tcp(88, ..)` and `Host::udp(88, ..)` and
the same `State`.

### COTP packet bounds

`cotp::Tpdu::parse` and its `Wire::parse` implementation read one complete
TPDU of at most `cotp::MAX_TPDU` bytes, including its header. This is the
largest payload a TPKT packet can carry: 65531 bytes. Larger inputs return
`cotp::Error::TpduTooLong` before header checks or allocation. Standalone
parsing previously accepted oversized connection, disconnect and data TPDUs;
it now uses the same limit as `Wire`. Inputs within the limit keep the same
grammar and errors. There is no unbounded parser.

`cotp::over_tpkt::tpdu` applies this limit even to a hand-built
`tpkt::Packet`. Packets read by the TPKT decoder already fit it. RDP keeps
its own limits and errors: `read_data` reports `Error::Limit("TPKT payload")`
before checking the data header, and `Connection::from_packet` checks its
smaller connection-header limit before parsing COTP.

### Writable STUN frames

STUN stream framing uses `codec::Frames<stun::Frame>`. It yields
`stun::Frame` values, not `Vec<u8>`; read a frame's bytes through `.0`.
The frame implements `Wire`, so it can pass directly through
`codec::Interceptor::next` and `codec::Faults::next`, including replacement
writing. Framing still checks only the header and length. Reading and
writing a frame preserves the original attributes and nonzero padding.
Use `stun::Message::parse(&frame.0)` to interpret attributes. Writing that
message uses zero padding and recomputes FINGERPRINT.

### Owning recursive protocol values

AMQP `FieldValue`, Thrift `Value`, and protobuf `Value` release nested
containers with an explicit work list. A hand-built tree can be dropped
normally even after a writer refuses it for exceeding the depth limit.
Parser and writer limits, errors, and wire bytes are unchanged. `Clone`,
`Debug`, and equality still recurse; they are not safe for arbitrarily
deep hand-built trees.

These enums now implement `Drop`. This is a source compatibility change:
consuming patterns cannot move their non-`Copy` fields out. Match a
reference to inspect a value. To extract owned data, match a mutable
reference and use `core::mem::take` on the child vector, table, or message.
For a Thrift list or map, take its `items` or `entries` vector. The protocol
module docs show extraction examples. Public module paths are unchanged.

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
`Http1::date` or `HttpOptions::date`), and the header is
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

DHCP checks the UDP length and checksum before reading a request. It drops
lengths below eight bytes or beyond the IP payload, and incorrect nonzero
checksums. IPv4 requests may use a zero checksum. Dropped requests do not
reserve or bind an address and get no reply.

With `fictionet attach --type http_proxy` or `--type socks5`, attach looks
names up in the world's DNS. It follows at most 16 CNAME aliases from the
queried name and uses an A record for the final name. It ignores unrelated
answers and rejects cycles or longer chains. The cache keeps the address
for the shortest TTL among those aliases and the A record, at most 60
seconds. A zero TTL expires immediately.

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

Each peer address may hold 256 connections at once across all machines
and gateway DNS listeners in the network. Bytes held by the service layer
are charged to one budget per sandbox, 256 MiB by default. TCP socket
buffers and TLS handshakes are outside this budget.
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

Lab clients can use `sandbox::TlsClient` over a simulated connection. Its
writes report plaintext taken only after the connection underneath has taken
the ciphertext. A blocked write stays pending, and downstream errors reach
the caller. Dropping a pending write may still send its bytes. A later write
starting with those bytes counts as a retry, even with more bytes appended.
A write with different starting bytes reports only its own bytes.

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

`Router` calls byte callbacks only with bodies held in full. An incomplete
body gets `400 Bad Request` before routing, so it never reaches a route or
the fallback, and never gets the usual `404` or `405`. A valid empty body
still reaches the callback. On native HTTP/1, a custom `httpd::Handler` or tower service
can read a cut-off body frame by frame: it gets the bytes received, then
an error. HTTP/2 and hyper's HTTP/1 upgrade path reject body collection
errors before calling any handler.

An axum `Router`, or any tower service over `http::Request<web::Body>`,
runs with `httpd::tower(service)`. A handler adds facts to its request's
event by putting `events::Fields` in its response's extensions.

HTTP/1.1 responses with unknown-length bodies use chunked encoding. Pending
polls and empty data frames do not end the response. The zero-size chunk is
sent only at body EOF, so the next response can use the same connection.

On a network, `httpd::Server` is the `PortServer` that serves a handler on a
port, and `httpd::Server::served_by` puts one on ports 80 and 443 as `web::Sites`
does:

```rust
use fictionet::stdlib::httpd::Server;

Net::new()
    .host("intranet", |h| h.dns_name("intranet.corp.test").port_server(80, Server::new(api.clone())))
    .add_host(Server::new(api).tls_with(move |_| config.clone()).served_by(Host::new("www").dns_name("www.corp.test")))
    /* ... */;
```

Sites of several hosts at one address share the port as virtual hosts:
the first host's `Server` takes in the others through
[`PortServer::prepare_share`](../src/stdlib/net.rs). It receives the local
`SocketAddr`, the host's DNS names and the other server. It returns `None`
to decline sharing, or a `PreparedShare` token. Preparation must not change
either server. The token captures an infallible commit; dropping it leaves
the servers unchanged. `Net` prepares all the host's ports at all its
addresses before committing any sharing, in address and declaration order.
A token must still work after earlier tokens commit. The default shares
only with the same server. On TLS, a declined host serves its own SNI
names, and later hosts are still offered to the first server.

HTTP names and defaults belong to each local address and port. Sharing an
IPv4 address does not add a site's names or default to another IPv6 address,
or the reverse. The first default at each endpoint keeps the role. Names
are matched without case or a trailing dot. `Net` itself knows nothing of
HTTP, so a copy of `httpd` with its own handlers plugs in the same way.

Each routed request carries an `httpd::Target`. Its `routing` field is
`Routing::Exact` when the requested host matches a registered name, or
`Routing::Fallback` when a default site answers. The `host` field keeps
the requested name in both cases.

With `web-proxy`, `web::Proxy` forwards only exact matches. A fallback
request gets `421 Misdirected Request` before any upstream I/O, even if
the proxy's site has `default_host()`. Its request event carries
`answer: misdirected`. For catch-all forwarding, use
`web::forward(&fcx, upstream)?`: it always connects to that fixed origin and
preserves the requested `Host`. Both `web::proxy` and `web::forward` require
a real run's context and return an error in a lab before constructing a
client. `Proxy`'s tower service returns
`httpd::Body`, so it can answer with a local rejection as well as a
streamed upstream response.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder. HTTP/2
runs on hyper, behind the same `Handler` trait. The stdlib's `http2`
module reads and writes HTTP/2 frames and tracks a session's state, but it
does not serve. Both versions share one set of `httpd::Limits`: body size,
body and write timers, and 100 streams at once on an HTTP/2 connection.
Both charge retained request heads, request events and bodies to the sandbox's
budget. A pending handler keeps its request charge. The copied event metadata
stays charged until the event is recorded, including while the response streams.
Heads count method, URI and header bytes and header slots. Events use
`Event::size()`. Hidden capacities in `http` types, request extensions,
third-party allocation overhead and transport buffers are outside these counts.
Hyper rejects a request whose metadata does not fit before calling its handler.
It records `answer: budget` without a status and ends that stream. Both versions
draw a handler's randomness from the run's stream.

In `http2::Session`, HPACK reductions wait for the corresponding SETTINGS
ACK. A decrease followed by an unacknowledged rebound leaves the earlier
allowance in place. ACKs apply in announcement order. Later pending
increases stay allowed, but do not cancel required minimum-size updates
at the next header block.

See [`httpd`'s event contract](../src/stdlib/httpd.rs) for `sent` and
`complete`, including when HTTP/1 and HTTP/2 count bytes.

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

`EventLog::wait` checks a snapshot of the held events, oldest first, with
the log unlocked. Its predicate may read or record events in the same log.
Events recorded by the predicate are considered on the next check.
It checks every 10 ms on the run's clock, shortening the last sleep to
the remaining time limit. At the deadline it returns the matches so far.
A limit that overflows the clock's range has no deadline. Cancellation
returns `Cancelled` before inspecting events and before returning matches,
even when enough events are already held, `n` is zero, or the deadline
has arrived.

Task identities belong to one run. An event recorded through a `Cx` from
another run has no task metadata. The same applies outside any world task.
A nested lab starts its own world root with no parent. Tasks spawned
through another run's `Cx` also have no parent in their run's graph.
Link owners and creators name only tasks from the graph's own run.

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

The [event log](../src/events.rs) documents retention, repeat aggregation,
late subscribers and dropped-event reporting. Sum `count` when grading
packet repeats; a port scan of 65,535 ports to one machine costs a couple of
events a second while its repeat windows fit.

Each subscription receives replay and live events in sequence order, one
callback at a time, outside the log and delivery locks. A callback may read,
record, or subscribe to the same log. Reentrant or concurrent recording queues
events for the caller already draining that subscription. Recording or
subscribing may return before those callbacks finish. A callback can run in a
different task or thread from the one that recorded its event, and must return
quickly without blocking. A callback panic propagates to the caller draining it.
If the run ends during a callback, its caller still drains the queued events.

History holds up to 50,000 ordinary events within 16 MiB and 5,000 repeats
within 2 MiB. An event larger than its history's byte limit is numbered but
not kept. It does not evict other events. Readers see an `events.dropped`
gap in its place; live callbacks still receive it. Open repeat windows have
a separate 2 MiB budget and a limit of 1,024 windows. The oldest counts
close early to make room, including when numeric detail ranges grow. A
repeat too large for a window is recorded individually with `count` 1.

Byte accounting includes owned capacities, task names, and the full shared
connection metadata for each retained copy, plus estimated allocation
overhead. It excludes spare capacity in history queues and window indexes,
static strings, temporary allocations while recording or reading, and
copies held by readers, callbacks, or pending subscription deliveries. These
fixed retention limits do not bound total process memory.

Native real runs use writer threads and wait for them at shutdown. In
browsers, labs and builds without `std`, event sinks write and flush each line
synchronously in the subscription's drainer, in sequence order. Browser runs
can use an in-memory sink with `EventLog::to_writer`. Native writer queues
have their own limit of 100,000 events or 16 MiB of event data; oversized
events are lost there too.
Discard a sample if
[`EventLog::lost`](../src/events.rs) is nonzero.

## 6. The dashboard

Selecting a packet clears the previous layers and bytes while it loads.
Only the current selection can fill them. Closing or reopening the drawer,
or reconnecting its stream, cancels pending detail requests. If a packet is
unavailable or its request fails, both views clear. Select it again to retry.

When a packet stream reconnects, the dashboard reloads retained history and
shows a reload notice. It clears old rows, pending and paused packets,
sampling totals and the selected detail before replay. A paused view stays
paused until resumed. This also applies to merged links and captures whose
packet numbering restarts.

The dashboard serves one HTTP/1.0 or HTTP/1.1 GET request per connection.
The target must be a path starting with `/`. The head may be at most 16 KiB,
including the first `\r\n\r\n`. Bytes after it cannot supply headers or another
request. Invalid request lines and headers close the connection. Repeated
`Host`, `Authorization`, `Cookie`, `Origin`, or `Sec-Fetch-Site` fields are
rejected. Request bodies are unsupported: `Transfer-Encoding` is rejected,
and `Content-Length` may occur only once and must be zero.

The dashboard and `fictionet observe` use a temporary 11-second timeout
when sending hello to the world and waiting for its answer. A silent world
causes a handshake-timeout error. After acceptance, these greeting timeouts
are cleared; callers control how long to wait for subscription replies.

Both commands inspect observer event and error envelopes as JSON. Field
order, whitespace and string escapes do not affect recognition. Inspection
uses `relay::observer::Value::envelope`. Recognition does not depend on size,
element count or nesting depth.
Invalid JSON, missing or wrongly typed fields, duplicate envelope fields,
and mixed event/error objects are not recognized. Binary values are never
inspected. Raw reply bytes and flags stay intact. The CLI writes the original
bytes; the dashboard forwards the original JSON data in SSE, with one `data:`
line per line of JSON. Event names with line breaks are sent as errors instead.

Each world listener admits 64 observer sessions by default, including idle
clients and direct API users. A full listener refuses the greeting with
`this listener has too many observer sessions`. Disconnecting frees a slot.
`Listening::set_observer_limit` changes this ceiling for one listener.
Each session can hold 64 subscriptions. Each run retains at most 64 link
watches by default, shared by all subscribers to each link.
`Cx::set_observe_watch_limit` changes that ceiling. The defaults fit the
dashboard's 64-connection cap and a session watching 64 distinct links.

When a new link needs a slot, idle watches are evicted longest-idle first,
with the lowest link id breaking ties.
If all watches are active, `packets` returns
`{"error":"this world has too many watched links"}` and ends that request.
Unknown links return `{"error":"no such link"}` even at capacity.
Existing streams and subscriptions to retained links keep working.
Idle history lasts up to a minute, but admission can evict it sooner.
Eviction removes packet details and capture history; a later watch starts
numbering packets at 1. Lowering a ceiling preserves active users until
they leave. Zero refuses new sessions or new links.

The default retained-row budget totals at most 2 GiB (64 times 32 MiB).
This is not a process-memory bound. Packet taps, event retention, TLS keys,
decoder state, graph views, thread stacks, socket buffers, temporary replies
and exports, and allocation overhead are separate costs. Reads in progress
and streams draining an ended run can keep their own watch holds until they
finish. Multiple listeners and runs have separate budgets.
Pending handshakes and attached sandboxes are outside these observer limits.

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
