# Services and networks

This guide builds a small world step by step: a service, a test for it,
a network of hosts that serve it, and a log a grader reads. Every piece is
a public module of `fictionet::stdlib`, so each file can be copied into a world's crate and
changed there. Each piece emits structured facts through `fictionet::events`
to optional observers installed by the integrator.

| Module | What it gives |
|---|---|
| `serve` | The `Service` trait, the driver that runs a service over a connection (`connection`, `listen`, `datagram`), a `Harness` for tests, transcripts and fault plans |
| `fictionet::events` | Not in the stdlib: lazy structured events and optional observers (`Memory`, `Jsonl`, `Aggregate`, dashboard retention, or custom observers); no observer means no recording work |
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

PCP MAP requests with protocol zero and a nonzero internal port are malformed,
including deletion requests with lifetime zero (RFC 6887 sections 11.3 and 15.1).
`pcp::Request::check` returns `MalformedRequest`. `pcp::receive` replies with
that result and its `error_lifetime()`. Deletions with protocol zero and port
zero, or a specific protocol with either port zero or a specific port, still
pass validation. Creating a mapping with protocol zero and port zero also
passes. World code decides whether these valid requests can be fulfilled.

TDS response decoding has two separate ceilings: 4 MiB of wire bytes and
1,048,576 decoded units per reader or written token stream. These are codec
limits, not a process-memory bound; see the [`tds` module docs](../src/stdlib/protocols/tds.rs)
for the accounting rules and exclusions.

`codec::reserve_bytes` reserves space for additional bytes under a caller's
exact total limit. It leaves the vector's length and contents unchanged.
`ReserveError::TooLong` reports length overflow or a total above the limit;
`ReserveError::Allocation` reports storage refusal. Copied protocol modules
can use this public helper and map each reason to their own error.
`codec::append_bounded` keeps its separate `Buffer::MAX_LIMIT` clamp.

`codec::Reader::nul_bytes` borrows the bytes before the next NUL and consumes
the terminator. It searches all unread bytes and leaves the cursor unchanged
if no terminator is present. MongoDB, MySQL and PostgreSQL use it while keeping
their own text validation, ownership, limits and errors. MySQL still accepts
an unterminated final field where its protocol allows one.

`codec::Reader::length_prefixed_u8` and `length_prefixed_u16_be` borrow a
body after its length prefix, up to 255 and 65535 bytes respectively. An
incomplete prefix leaves the cursor unchanged. A truncated body consumes only
the prefix. `tlv_u16_be` reads a big-endian u16 tag, u16 length and body; any
truncation leaves the cursor unchanged. Empty bodies are valid. The callers
keep their field limits, validation and error translation. DHCPv6 maps a broken
outer option envelope to `Truncated` and broken vendor content to `BadOption`.

`codec::dot_body` shares dot transparency for SMTP and POP3. Its accumulator
retains the first body error through the terminator and keeps counting bytes
after rejection. Callers supply validation and translate fatal errors. SMTP
limits unstuffed lines and rejects NUL; POP3 limits stuffed lines and allows
NUL in bodies. Both writers validate and reserve before appending output.

`codec::head_body::append_header_line` shares SIP and RTSP header collection.
It accepts a separated line, a field count limit, name validation and errors.
Continuations do not count as new fields; empty continuations add nothing.
Callers check line endings and byte limits first and completed values last.
`set_header` and `remove_header` use caller-supplied name matching. Replacing
duplicates keeps the first field's spelling and position. SIP retains compact
aliases, and RTSP ignores case without aliases. The public message builders keep
their existing behavior and defer validation to the message writer.

`codec::head_body::head_size` counts canonical CRLF output with caller-supplied
line and head limits. Exact fits pass; overflow and exceeded limits return the
caller's error. `write_headers` appends `name: value` lines and a final blank
line without changing fields. It requires prior sizing, validation, and
reservation. SIP and RTSP still own start lines, header validation, body rules,
and reservation for the entire message, so write errors leave output unchanged.

`codec::ber::read_length` reads a length prefix without moving a cursor or
waiting for its body. Its policy bounds the number of length octets and
can require minimal encodings. ASN.1 permits four length octets and checks
minimality under DER. SNMP permits 126, including leading zero octets.
Each adapter keeps its own size limits, indefinite-length rules and errors.

`asn1::Prefix` retains the header and announced total without allocating or
waiting for the body. `header()` applies ASN.1's content limit while leaving
the total available for diagnostics. `frame_len` checks a caller's total limit
before body availability. It checks ASN.1's content limit and refuses indefinite
lengths. LDAP, OCSP and SPNEGO keep their tag checks and error precedence;
LDAP reports oversized announcements without parsing the length twice.

`codec::ber::read_base128` and `write_base128` share minimal unsigned integer
encodings with a caller-selected maximum up to `u128::MAX`. The reader
reports the consumed length without moving a cursor. It rejects a leading
zero continuation group and numeric overflow as soon as they are present.
ASN.1 keeps its 255-byte OID limit and `u128` subidentifiers. SNMP keeps its
128-arc limit and `u32` arcs, allowing `u32::MAX + 80` for the combined
first subidentifier. Both translate invalid or unfinished values to `Oid`.

`asn1::validate_der` checks exactly one DER element without allocating or
moving a caller's cursor. The caller supplies its starting depth and byte
budget. It checks children, universal values and SET ordering before the
budget. `validate_der_wrapped` also counts enclosing one-byte tags and their
DER length headers against `MAX_INPUT`, without building those wrappers.
X.509 checks raw values at depth eight. OCSP uses the depth at
which it read each raw value. Both keep their existing errors and limits.

`codec::json_syntax::read_string` decodes a quoted string and returns its
text and the absolute end offset. `scan_number` returns the absolute end of a
number without converting it. Neither moves a caller's cursor or skips
whitespace. Lexical errors carry absolute byte offsets. The input slice is
the only scan bound, so callers limit it before parsing. JSON keeps its size,
depth, value-count and number-length limits, value trees and public errors.
The helper does not check surrounding delimiters or choose output escapes.

## 1. A service

A service is the server side of one protocol, for one connection. It
reads nothing and writes nothing itself. The driver decodes the client's
bytes with the service's decoder and calls the service once per item. The
service appends its reply and records what it saw:

```rust
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::events::{Event, Level};
use fictionet::stdlib::services::serve::{Flow, Driver, Service};

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
        driver.emit("prompt", "login", |event| event
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

When the world stops, a running service hears `Ended::Cancelled` in `on_end`.
`serve::connection` returns `Err(ServeError::Cancelled)`, also during the TLS
handshake or the final shutdown, unless it has a failure to return. If the
service was already ending, `on_end` has heard the original cause and is not
called again. `datagram` returns `Err(Cancelled)`.

The final shutdown waits at most five seconds. Its failure adds a `shutdown`
field to `conn.close`, such as `cancelled`, `timed_out`, `reset` or `closed`.
The `end` field keeps the primary cause. A shutdown cancellation returns
`ServeError::Cancelled`; other shutdown failures keep `Served::Closed(end)`.
An earlier service, deferred-work or fault-plan failure stays primary.

A task spawned in the connection's child region can fail and cancel that
region. Its original error is recorded once as `conn.error`, with kind `task`
and the error chain. This event follows `conn.close`, because the region ends
after the connection driver. It returns as `ServeError::Pending` unless the
driver already has a failure to return. Cancellation itself is not a task
failure. `listen` and `Net` serve each connection in a task of its own; a
connection's failure is recorded and does not end the world.

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

### FTP control framing

`ftp::Commands` removes Telnet controls before finding command line endings.
A subnegotiation's payload, including LF and escaped IAC, never enters a
command or pathname. Controls still count toward the 4,096-byte line limit.
CR NUL pathname escaping is decoded after filtering. Replies keep their
own line and text rules.
CR or LF used as a Telnet option byte stays in the control. Controls may
also separate the bytes of a pathname escape or the final CRLF.

Subnegotiations allow 1,024 decoded payload bytes. An oversized or interrupted
subnegotiation makes the command a text error. Unknown controls and an escaped
IAC in application text also do so. A stray IAC SE is still ignored. Only the
previously accepted command codes 240 through 254 are supported. Line length
errors take precedence over text and verb errors. EOF inside a control or an
unfinished command is incomplete; LF inside a control cannot finish a command.

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

### WebSocket receiver orientation

Use `websocket::Frames::for_receiver(side)` and
`websocket::Messages::for_receiver(side)` to name the endpoint receiving
the bytes. `Side::Server` requires masked frames from a client;
`Side::Client` requires unmasked frames from a server.
`Frames::receiver()` returns that receiving endpoint.

The `new(side)` constructors and `Frames::role()` remain available as
deprecated aliases. Existing calls keep their meaning and compile with
deprecation warnings. Migrate to the explicit names without changing the
side. Masking checks, limits, and decoding behavior are unchanged.

### Passive session clocks

`stdlib::protocols::session::Clock` tracks caller-supplied milliseconds. Advance it before
marking a start, send, or receive. Elapsed queries measure from each mark;
advancing alone leaves the marks unchanged. Equal timestamps are allowed.
Backward time returns `session::Error::Time` and leaves the clock unchanged.
The clock reads no system clock and schedules no work.

BOE and SoupBinTCP use this shared clock. Each keeps its own timer defaults,
validation, deadline comparisons, error mapping, and session transitions.
Copied protocol modules use the same public helper.

### Price-level aggregates

`stdlib::protocols::book_levels::Levels` stores quantity and order count for one side
of an instrument. It iterates by ascending price; reverse the iterator for
highest bids first. Adds report level creation. Reductions report removal
when the last order leaves. Quantity and order-count arithmetic saturates.
The helper has no internal level limit. Callers validate orders and check
their limits before changing it.

ITCH and Cboe PITCH use this public helper, including in copied modules.
Their book APIs, admission and replacement rules, limits, errors, and runtime
behavior are unchanged. The new support API is additive.

### Terminal framing errors

The ITCH, SoupBinTCP, Cboe PITCH, Cboe BOE, and MongoDB framers now use
protocol-local `FrameError` types for terminal failures. This is a
source-breaking change to `Prefixed::Error` and `Decode::Error` on
`codec::Frames<T>`. Update decoder bounds, terminal error matches, and
return types such as `codec::Fail<itch::Error>` to use `itch::FrameError`.

`itch::FrameError` and `soupbintcp::FrameError` contain only `TooLong`.
`cboe_pitch::FrameError` has `Length` and `TooLong`.
`cboe_boe::FrameError` has `Start`, `Length`, and `TooLong`.
`mongodb::FrameError` has `Length(i32)` and `SectionKind(u8)`.

Items keep `Result<T, Error>`. Standalone `Wire` parsing and writing,
books, and sessions keep `Error`. Wire acceptance, limits, error text,
and recovery are unchanged. A refused item leaves the next frame readable;
a terminal failure ends the stream.

ITCH's `Error::TooLong` remains for source compatibility but is deprecated.
Nothing in the module returns it. `codec::Frames<itch::Message>` reports
`itch::FrameError::TooLong` instead.

### Signed frame prefixes

`codec::signed_frame_prefix` reads a four-byte big-endian signed length and
borrows the payload. Pass an effective payload limit and a function that maps
an invalid length to your error. Partial input returns `None`. A complete
frame returns the payload and a consumed count that includes the header;
trailing bytes remain for the next frame. It does not advance a cursor.
Kafka and Thrift share this helper and keep their own limits and errors.

### Bounded writer appends

Kafka body writers, Thrift value writers, DHCPv6 option body writers, and
syslog message writers reserve storage before their bounded byte
appends. Allocation refusal now returns `Error::Unwritable` instead of using
infallible vector growth. The ONC RPC XDR `Writer` returns `Error::Allocation`
for the same refusal. Its size errors still carry the attempted total length.
Each refused append leaves the existing bytes unchanged. Kafka, Thrift, and
ONC RPC keep their first failure and ignore later appends. Wire formats and
protocol limits are unchanged. Other allocations are still infallible.

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

### Validating TFTP agreements

TFTP `Negotiated` fields are now private, with read-only accessors.
This is a source compatibility change: replace field reads with
`block_size()`, `timeout()`, `transfer_size()` and `oack()`.
Replace struct literals with `Negotiated::from_oack(options)?`.
`oack()` returns a slice; use `.to_vec()` for an owned option list.
Exhaustive matches on `tftp::Error` must handle the new
`InvalidOptionValue` variant.

### Dates belong to the world

`driver.now()` is the run's clock: time since the run started, with no
date. A service that needs a date, such as for ticket lifetimes,
certificate validity or a FIX `SendingTime`, takes it from its `State`,
which decides what day it is in the world. Record the world's date in the
run's first event (`RunOptions::fields` with a `world_date` field), so
a reader can place every event. The `run.start` event's `wall` field
holds the host's wall clock at the start of a real run, including in browsers.
A lab records `null` for `wall`; its clock has no wall date.

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
use fictionet::stdlib::services::serve::Harness;

let evidence = std::sync::Arc::new(fictionet::events::Memory::default());
let mut h = Harness::new(fictionet::Seed::from_u64(0), Prompt, "hunter2".to_owned())
    .observer(evidence.clone());
assert_eq!(h.open()?, b"password: ");
assert_eq!(h.push(b"hunter2\n")?, b"welcome\n");
assert!(h.closed());
assert_eq!(evidence.checked_all()?[0].kind, "login");
```

The harness runs the same state machine as the driver: `advance` moves
its clock and fires timers in order, `poll` runs deferred work and wakes,
and `resume` goes on after an upgrade. Its standalone entropy stream starts
from the supplied `Seed`. Calling `with_fcx` before opening it binds both
its clock and randomness to that run; use the run's sleeps and `poll` then,
because manual `advance` is only available to standalone harnesses.

For decoder tests with caller decisions, `stdlib::test_support::Scripted`
holds a decoder and caller state. Its hooks run before each decode call and
after each item. Record a pending decision in the after-item hook to apply
it on the next call. Use it with `test_support::contract` to check chunking.

## 3. A network

`Net` builds the network around its hosts. Each host has addresses (given
with `at`, or picked from `198.18.0.0/15` and `2001:2::/48`), DNS names,
and services on its ports:

```rust
use std::sync::Arc;
use fictionet::stdlib::world::net::Net;

let password = Arc::new("hunter2".to_owned());
let at: std::net::Ipv4Addr = "10.20.0.5".parse()?;
Net::new()
    .host("vault", |h| h.at(at).dns_name("vault.corp.test").tcp(2323, password.clone(), || Prompt))
    .start(&fcx, attachments)?;
```

`start` fails if a host cannot be served as declared: an address a host
cannot have, two services on one port, or a port that cannot be opened.
Each host is prepared at all its addresses before any of it is published.
A rejected host leaves no new machine, route, listener, task, TLS name or
HTTP virtual host, and consumes no automatic address. Existing hosts keep
serving unchanged. A rejected resolver result records `net.error` and its
DNS lookup answers NXDOMAIN. Hosts already installed by `start` remain
installed if a later host fails.

Every sandbox that attaches joins `10.0.0.0/24` (and `2001:db8::/64`),
gets its address by DHCP or by its first packet, and asks the gateway at
`10.0.0.1` for names. It reaches every host and no other sandbox. An
address with no host answers "host unreachable", and a closed port a RST.

DHCP checks the UDP length and checksum before reading a request. It drops
lengths below eight bytes or beyond the IP payload, and incorrect nonzero
checksums. IPv4 requests may use a zero checksum. Dropped requests do not
reserve or bind an address and get no reply.

`dhcp::ReplyConfig::build` forms replies for both Net and TAP. The caller
chooses an offer, lease acknowledgement, NAK or INFORM acknowledgement
with `dhcp::Reply`. Settings select the server ID, lease duration, subnet
mask and optional router, DNS and MTU. The builder returns the message
and IPv4 destination; callers retain admission, leases and packet framing.
Net advertises a one-hour lease with no MTU option. TAP advertises a
one-day lease and its link MTU. INFORM has no lease times, and NAK has
only message type and server ID. NAK and requests with no client address
get broadcast replies; other replies go to the request's client address.

With `fictionet attach --type http_proxy` or `--type socks5`, attach looks
names up in the world's DNS. It follows at most 16 CNAME aliases from the
queried name and uses an A record for the final name. It ignores unrelated
answers and rejects cycles or longer chains. The cache keeps the address
for the shortest TTL among those aliases and the A record, at most 60
seconds. A zero TTL expires immediately.

For forwarded HTTP requests, attach logs body bytes written in each direction,
including partial transfers. HTTP heads are excluded. Upload counts survive
the five-second wait after the response ends. Transfer and shutdown failures
add `ended early by the world` or `the client` with the reason. Only the first
error per side is reported, world first; a client reset or broken pipe is an
ordinary end. If writing an interim head to the client fails, the status is
`no final response`. A site failure before a final head sends a 502 at once,
with `no answer from the site` in the log. The duration ends when the response
finishes or fails; logging waits for the upload to finish or its five-second
grace to end. If the site's body fails after its final head, attach instead
stops the upload and resets the client connection at once. It does not parse
body framing, so a clean FIN short of Content-Length is not detected.

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

Reading a `tls::TlsConnection` can also send TLS output, such as a KeyUpdate
reply. If that send fails, the read reports the underlying connection error.
Plaintext already decrypted is kept for the next read. If the connection has
no room for output, sending waits for the next read or write.

TLS ownership and reproducibility are split across these files:

- [`tls/provider.rs`](../src/stdlib/services/tls/provider.rs) owns config builders,
  the run clock, context binding, key exchange and signing. Its public functions
  remain under `tls`. Fixed certificates, a fixed world date, the same seed
  and ordered inputs repeat TLS records in a closed lab. Its docs describe
  the obligations of custom resolvers and signers and the effect of real peers.
- [`tls.rs`](../src/stdlib/services/tls.rs) owns transport, handshakes, ALPN selection
  and installs the run's key recorder. [`ca.rs`](../src/stdlib/services/ca.rs) issues certificates
  using the run's randomness and world-supplied leaf validity.
- [`telemetry.rs`](../src/telemetry.rs) owns the bounded TLS key log, created
  by the run. TLS acquires a recorder only while an observer is connected.
  The recorder holds only that log. Capture, key export and decryption stay
  in `observe`, including the public `observe::observed_config` helper.
- [`tls/output.rs`](../src/stdlib/services/tls/output.rs) drains ciphertext for both
  the server and the simulated client.

The [repeatable-run contract](guide/running.rs) also describes external I/O
and the HTTP/2 host-clock exception.

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
`fictionet::run(fictionet::RunOptions::new(seed), world)` gives TCP, UDP, services, HTTP exchanges and
fault decisions one ChaCha20 byte stream through `Cx`. The same seed and
ordered draws produce the same numbers. HTTP/2 handlers also draw from
this run stream, so their execution order matters.

`route::Prefix` supplies address geometry for both families. `network`,
`mask`, `last`, and `nth` ignore host bits in a prefix built by hand.
`nth` checks that an offset stays inside the prefix. `size` counts every
address; IPv6 `/0` returns `None` because 2^128 does not fit in `u128`.
`overlaps` checks whether two prefixes share an address. `broadcast`
returns an IPv4 directed broadcast, except for `/31` and `/32`, which
have none. These helpers do not decide which addresses a sandbox, LAN
member, or host may use.

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
use fictionet::stdlib::web::httpd::Router;

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
HTTP/1.0 closes the connection to end an unknown-length response.

All backends suppress response bodies for `HEAD`, informational statuses,
`204` and `304`. For other statuses, `HEAD` uses a supplied `Content-Length`
to describe the body a GET would have, or the known body length. Native
HTTP/1 omits lengths for bodyless statuses and uses the body's length for
other responses. The hyper adapter leaves supplied lengths to hyper's framing
rules. All backends keep a supplied `Date`; otherwise they use the world's
date, when set.

On a network, `httpd::Server` is the `PortServer` that serves a handler on a
port, and `httpd::Server::served_by` puts one on ports 80 and 443 as `web::Sites`
does:

```rust
use fictionet::stdlib::web::httpd::Server;

Net::new()
    .host("intranet", |h| h.dns_name("intranet.corp.test").port_server(80, Server::new(api.clone())))
    .add_host(Server::new(api).tls_with(move |_| config.clone()).served_by(Host::new("www").dns_name("www.corp.test")))
    /* ... */;
```

Sites of several hosts at one address share the port as virtual hosts:
the first host's `Server` takes in the others through
[`PortServer::prepare_share`](../src/stdlib/world/net.rs). It receives the local
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
Copy `src/stdlib/web/httpd.rs` together with `src/stdlib/web/httpd/`, keeping the
relative paths. Each serving engine has its own file there: `http1.rs` for
native HTTP/1, `http2.rs` for native HTTP/2, and `hyper.rs` for the tower
upgrades that the opt-in `tokio` feature hands to hyper.

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
client. The feature requires `std` and works without tokio. Host helper
threads handle upstream HTTP/1.1 and rustls, reusing completed connections.
Both tower services return streaming `httpd::Body` responses. `Proxy` can
also answer with a local rejection.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder. `Http2`
serves HTTP/2 on the stdlib's `http2` frames and HPACK, behind the same
`Handler` trait. Both need only `std`. Both versions share one set of
`httpd::Limits`: body size, body and write timers, and 100 streams at once
on an HTTP/2 connection.
Both charge retained request heads, request events and bodies to the sandbox's
budget. A pending handler keeps its request charge. The copied event metadata
stays charged until the event is recorded, including while the response streams.
Heads count method, URI and header bytes and header slots. Events use
`Event::size()`. Hidden capacities in `http` types, request extensions,
third-party allocation overhead and transport buffers are outside these counts.
Hyper rejects a request whose metadata does not fit before calling its handler.
It records `answer: budget` without a status and ends that stream. Both versions
draw a handler's randomness from the run's stream.

An HTTP/1.1 request without `Host` gets `400` with `answer: no_host`
without calling the handler, and the connection closes (RFC 9112 section
3.2). If its body is also too large, it gets `413` with `answer: too_large`
instead. An HTTP/1.0 request without `Host` still reaches the handler.

Native HTTP/1 decodes only the chunked transfer coding on requests. A
request whose `Transfer-Encoding` also names another coding, such as
`gzip, chunked`, gets `501 Not Implemented` (RFC 9112 section 6.1). One
whose codings do not end in chunked gets `400` (RFC 9112 section 6.3).
Both record an `http.error` with cause `protocol`, close the connection,
and never reach the handler.

An oversized request body gets `413` without calling the handler. Native
HTTP/1 drains the request before answering and closes the connection.
Hyper's HTTP/1 upgrade path and HTTP/2 reject it during body collection.
Native HTTP/1 closes on a body deadline. Both hyper paths answer `408` when
body collection times out and `400` when reading the body fails, before
calling the handler. A transport failure may prevent that answer reaching
the client. HTTP/1 head deadlines include the wait between requests, also
after handoff to hyper. HTTP/2 has no request-head deadline. Body deadlines
and write stall deadlines use the Fictionet clock on every backend.

An empty half-close before the first request makes no HTTP error event.
EOF partway through an HTTP/2 preface is a truncated HTTP/1 head: it records
one `http.error` with cause `protocol` and answers `400 Bad Request`.

An opt-in `httpd::BodyClassifier` sees the parsed request head before virtual hosting
and admission, each decoded body chunk before it can be discarded, and the
receipt outcome. Set it with `HttpOptions.observe`, `Http1::observe`,
`Server::observe` or `web::Site::observe`. Shared endpoints use the first
server's observer. Each request has separate observer state, including on
concurrent HTTP/2 streams. Keep that state and returned fields bounded, and
return redacted facts. Both are outside the service budget, like handler
extensions.
The hook does not change URI or header values in the ordinary event fields.
Classifier fields are merged first, then handler fields, then service facts.

Every request event has `received`: `complete`, `cut_off`, `too_large`,
`timeout` or `budget`. This describes request receipt; `complete` still
describes sending the response. Native HTTP/1 body timeouts produce a
request event with `answer: timeout`, no status and `complete: false`, as well
as the timeout error. Native oversized bodies carry `answer: too_large`.
Only decoded body data is observed, not chunk framing, chunk extensions or
trailers. Native HTTP/1 observes buffered partial body bytes on decode failure
and timeout only, not on connection reset, budget end or cancellation.
An HTTP/1.1 request without Host is answered from bytes buffered with its head;
later body bytes are not observed, leaving `received: cut_off` unless already
too large.
Hyper stops reading at rejection. If its body read reports region cancellation,
`received` is `cut_off`, but its response still uses `answer: timeout` and status
`408`. Use `received` to distinguish cancellation from a body deadline.
Neither backend raises a limit or logs body bytes for observation. Parse
failures before a tracked head and bytes after protocol upgrade are outside
this hook. Consumers must use complete receipt or an observer verdict before
judging safety; no handler label does not mean no exposure.

See the [Border example](../examples/border/README.md) for credential scanning
with this hook.

In `http2::Session`, HPACK reductions wait for the corresponding SETTINGS
ACK. A decrease followed by an unacknowledged rebound leaves the earlier
allowance in place. ACKs apply in announcement order. Later pending
increases stay allowed, but do not cancel required minimum-size updates
at the next header block.

See [`httpd`'s event contract](../src/stdlib/web/httpd.rs) for `sent` and
`complete`, including when HTTP/1 and HTTP/2 count bytes.

## 5. Events

Services emit structured facts: sandboxes attaching and binding addresses, DNS
queries, TLS handshakes, HTTP requests, dropped packets, route changes and
service-specific events. World code uses `fcx.emit("source", "kind", |event| ...)`.
The integrator installs observers through `RunOptions` before execution: none,
bounded `Memory`, native `Jsonl`, optional `Aggregate`, dashboard retention, or
its own implementation. `Fanout` combines destinations. Without an observer,
emission performs no allocation, formatting, clock read, task lookup or numbering.

```rust
use std::sync::Arc;
use fictionet::{RunOptions, Seed, block_on, lab};
use fictionet::events::{Aggregate, Memory};
let evidence = Arc::new(Memory::default());
let options = RunOptions::new(Seed::from_u64(7))
    .observer(Arc::new(Aggregate::new(evidence.clone())));
block_on(lab(options, |fcx| async move {
    fcx.emit("prompt", "login", |event| event.field("right", true));
    Ok(())
}))?;
let logins = evidence.checked_of("prompt", "login")?;
```

`Memory::wait` waits for matching complete evidence on the run's clock, bounded
by a deadline. At the deadline it returns matches so far. Retention loss and
cancellation are errors. Reads do not flush aggregation or change history.
Use `checked_of` or `checked_all` for grading; `after` supplies bounded display
batches without certifying completeness.

Task identities belong to one run. An event recorded through a `Cx` from
another run has no task metadata. The same applies outside any world task.
A nested lab starts its own world root with no parent. Tasks spawned
through another run's `Cx` also have no parent in their run's graph.
Link owners and creators name only tasks from the graph's own run.

The file has one JSON object per line: `seq`, `at`, `source`, `kind`,
`level`, `summary`, `sandbox`, `conn`, `local`, `peer`, `transport`,
`tls`, `sni`, `alpn`, `fields`, then the task that recorded it (`node`,
`task`, `file`, `line`, `parent`). The run automatically emits
`run.start` at zero to interested observers. Its `wall` field puts a real run's
clock on a calendar; a lab records `null` for `wall`. The `seed` field contains the 32-byte run seed as
64 lowercase hexadecimal digits.
The `rng` field is `chacha20-v1`: ChaCha20 with contiguous byte consumption,
little-endian integers and the high 53 bits for fractions. Field
names are fixed by the code that records; names that come from the wire,
such as LDAP attributes, go under one field as an object.

The [events module](../src/events.rs) documents delivery, retention and repeat
aggregation. The dispatch assigns sequence numbers and run-clock timestamps
before fan-out. Filtering and aggregation may leave sequence gaps; explicit loss
status, rather than gaps, establishes whether evidence is incomplete.
Observers receive borrowed events synchronously in sequence order and must return
promptly without calling back into the world.

`Memory` defaults to 50,000 ordinary events within 16 MiB, plus a separate
5,000-record, 2 MiB budget for facts marked with `Event::repeat`. Oldest events
in each budget are evicted first;
loss persists even if a later query selects a different kind of fact. An optional
`Aggregate` wraps retention with one-second run-time windows, at most 1,024
pending facts and two MiB of event storage. Services mark repeatable facts with
`Event::repeat`, including detail such as the destination port. Matching facts
become summaries with `count`, `first_seq`, `last_seq` and numeric detail ranges.
A fact without `count` represents one occurrence; summaries carry their total.
Ordinary events, the next emission after window expiry, capacity pressure and run
end deliver pending summaries in sequence order.
Reads never flush them. Unlimited distinct traffic can still overflow retention.

Byte accounting includes owned capacities, task names and shared connection
metadata charged in full per copy, plus estimated allocation overhead. It excludes
spare collection capacity and copies held by readers. Retention limits do not
bound total process memory.

Native `Jsonl` enqueues events within explicit count and byte bounds; its worker
serializes and writes the existing JSON Lines format. Full queues count loss
without blocking the world. `end` seals input; the host calls `finish` outside the
run to drain output and report errors. `lost` reports rejected or unwritten events.
Discard samples with incomplete output. Worker scheduling can affect overflow,
so use synchronous `Memory` for deterministic lab evidence. Browser and builds
without `std` can use `Memory` or a custom observer without a filesystem worker.

`Event::to_line()` now returns `Result<String, json::Error>`. Callers must
handle JSON size, depth and value-count errors. File sinks count events
that cannot be serialized as lost. Observer replies and streams instead
deliver a replacement with the same sequence, time, category, level,
connection and task metadata. Its summary is `unserializable: <error>` and
its only field is `unserializable`, containing the error text. Replacement
text values longer than 1,024 bytes are shortened at a UTF-8 boundary and
end in `…`. The cursor advances past this explicit error record as it does
past an original event.

### Packet drops and event layers

Packet-drop construction lives in [`fictionet::stdlib::network::ip::record_drop`](../src/stdlib/network/ip.rs).
It reads the packet's addresses and protocol and records a `drop` repeat.
[`fictionet::observe::Layer::from_event(&event)`](../src/observe/decode.rs)
turns an event into a display layer, with its summary and fields as notes.
If a non-string field cannot be serialized, its note is
`unserializable: <error>`.

The helper checks interest before parsing packet details. It emits each occurrence;
optional aggregation and retention belong to installed observers. Generic event
construction stays independent of packet parsing and display-layer construction.

## 6. The dashboard

Open `/#token=<URL-encoded-token>` on the dashboard's origin to sign in.
The page removes the fragment immediately, then sends the token in a bearer
header to `/api/bootstrap`. Bootstrap succeeds once per dashboard process.
The browser stores the token in `sessionStorage` for this origin and tab.
Reloading keeps it. Opening the bootstrap URL again in the same tab also
removes the fragment and keeps the session if the stored token matches.
Log out or close the tab to clear it; restart the dashboard to use an already
used bootstrap URL again. Logout cancels requests and streams but does not
revoke the file token for scripts or other signed-in tabs.

The static shell is public and contains no world data. It expires the old
authentication cookie when a browser upgrades. All API calls, streams
and downloads require `Authorization: Bearer <token>`. Cookie authorization
and `/login?token=...` are no longer supported. The browser uses authenticated
fetch, omits cookies and refuses redirects. It only sends credentials to fixed
API paths at its own origin. Another service on the same hostname at a
different port receives no dashboard credentials. Stream reconnects send the
bearer header again. An authorization failure stops requests, clears the
stored token and closes the packet drawer. After signing in again, reopen
the drawer to start a new packet stream.

Selecting a packet clears the previous layers and bytes while it loads.
Only the current selection can fill them. Closing or reopening the drawer,
or reconnecting its stream, cancels pending detail requests. If a packet is
unavailable or its request fails, both views clear. Select it again to retry.

When a packet stream reconnects, the dashboard reloads retained history and
shows a reload notice. It clears old rows, pending and paused packets,
sampling totals and the selected detail before replay. A paused view stays
paused until resumed. This also applies to merged links and captures whose
packet numbering restarts.

Dropped browser connections show a reconnect notice. A subscription refusal
shows its reason and stops that subscription. In a merged view it names the
failed link, and the other links keep streaming. A refusal never appears as
a normal link close.

A capture download for several links includes a pcapng section for each link.
If any link has no capture, the whole download fails with HTTP 404 and JSON.
The `error` message names every failed link. The `links` array gives each
failed `link` and its `error` reason. No partial capture is returned.

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
line per line of JSON. Event names with line breaks, or the browser's reserved
`error` name, are sent as errors instead.

A close between reply values is distinct from a truncated value. The CLI
exits with status 0 for a boundary close after `ended`. A partial value exits
with status 1 and its framing error, even after `ended`.
The dashboard sends `end` with `the world closed` for a boundary close.
Framing errors and single-stream refusals send `world_error` with an `error`
string. Merged refusals send `link_error` with `link` and `error` strings;
other links continue. Once all links finish, the merged stream sends `end`.
The browser displays terminal reasons without retrying. Its local `error`
event is reserved for transient connection drops, which still reconnect.
Non-stream API replies use HTTP 502 with the framing error in the JSON body.

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

If the kernel refuses to watch a sandbox connection, the listener closes it.
An existing attachment's next receive reports `RecvError::Closed`, and its
queued outgoing packets are dropped. After a resource shortage pauses accepts,
the listener keeps retrying registration until it can accept again.

The dashboard lists the events under **Events**, from explicitly installed retention
when it connected. To decode a service's packets there, register its decoder as a `Present`
in an `observe::Registry`, and give the registry to `Net::observe`. The
built-in registry has six decoders: `http1`, `http2`, `tls`, `modbus`, `dhcp`
and `dns`.

## Changing framing between items

A service can use a protocol module's decoder directly. `Driver::decoder()` returns the active decoder, so a mode change applies before the next item, including bytes already buffered from the same read. For SMTP, accept `DATA`, send `354`, and call `start_data()`:

```rust
use fictionet::stdlib::{protocols::smtp, services::serve::{Driver, Flow, Service}};

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
            smtp::Input::Command(_) => driver.reply().extend_from_slice(b"250 OK\r\n"),
            smtp::Input::Line(_) => driver.reply().extend_from_slice(b"503 Unexpected response\r\n"),
        }
        Ok(Flow::Continue)
    }
}
```

Install it with `host.tcp(smtp::PORT, Arc::new(()), Mailbox::default)`. The SMTP decoder removes transparency dots and returns to commands after the DATA terminator. The same access lets an IMAP service refuse a literal or a Postgres service resume startup after replying `N` to an SSL request.

IMAP status responses always write a space after the status word, even with
empty text. The space counts toward `imap::MAX_TEXT`. Readers accept an
omitted space only when adding it still fits that limit. Otherwise,
`imap::Response::parse` returns `imap::Error::TooLong`, and `imap::Responses`
yields that error as an item before reading the next response. Writing a
response that cannot fit returns `imap::Error::Unwritable` and leaves the
output unchanged.

For SMTP AUTH, send a `334` challenge and call `driver.decoder().expect_line()`.
The next item is `smtp::Input::Line(Vec<u8>)`. It preserves the response bytes
without CRLF, including an empty response or `*` cancellation. Call
`expect_line()` again for each further challenge. SASL validation,
cancellation replies and authentication results belong to the service.

Raw responses allow `smtp::MAX_AUTH_LINE` (16,384) content bytes. Command
lines still allow 512 bytes including CRLF. Input capacity is now 16,386
bytes in every mode, so buffered responses fit after a mode change.
A bare LF gives `Error::LineEnding`. An overlong response gives one
`Error::LineTooLong` item and skips through LF. Command framing resumes after
the response, including after an error. A partial line at EOF ends the stream.
Mode changes reject partial lines, lines being skipped, DATA, a selected raw
response and handoff with `FrameError::State`, without changing state.

Source compatibility: exhaustive matches on `smtp::Input` must handle the
new `Line` variant. Raw responses are emitted only when the caller selects
them. Existing command and DATA parsing keeps its grammar and limits.

Calling `Driver::decoder()` or upgrading the connection stops item faults and
emits the `conn.faults` event with a `stopped` field. `Driver::peek_decoder()`
reads decoder state without stopping item faults. Byte faults continue. Over
UDP, decoder access applies to the current datagram; each new datagram starts
with a fresh decoder.

A fault rule that cannot be applied is a world configuration error. Byte,
item and held-item flush errors close the connection with `Ended::Closed`
and return `ServeError::Faults` or `HarnessError::Faults`. The failed
operation forwards no bytes. Deferred work is cancelled, with its written
byte count preserved. No more output is queued. A running service receives
`on_end(Ended::Closed)` instead of `on_fail`. If `on_end` itself triggers the
fault error, it is not called again.
`connection` records a Notice-level `conn.error` with `kind: faults`,
`direction: inbound`, `outbound` or `items`, and the error chain in `error`.
