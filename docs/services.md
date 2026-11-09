# Services and networks

This guide builds a small world step by step: a server stack, a test for
it, a network of hosts that serve it, and a log a grader reads. Every piece is
a public module of `fictionet::stdlib`, so each file can be copied into a world's crate and
changed there. Every world defines its own typed observations and decides
where to send them.

| Module | What it gives |
|---|---|
| `layer` | The `Layer` trait: one protocol between the carrier below it and what it offers above, stacked with `Chain`, `Switch` and `Children`, and a `Harness` for tests |
| `services::stack` | The runners that run a stack over a connection (`stream`) or a UDP socket (`datagrams`), and `Polling` to do a stack's work in a harness |
| `net` | `Net`: the sandboxes' subnet, a resolver at the gateway, routing, one machine per address, and each `Host`'s stacks on its ports |
| `httpd` | HTTP as a stack: `Handler`, the `tower` adapter for axum, `VirtualHosts`, `Http1`, `Http2` |
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

## 1. A server stack

A protocol is a layer: it sits between the carrier below it, such as a
byte stream, and what it offers above, and it reads nothing and writes
nothing itself. Events come up from below and commands come down, all
synchronously, with the time, the entropy and the budget in an `Env`. A
server is a stack with nothing above it (`Top`). Here a login prompt reads
lines with a codec stream it owns, answers one password and closes:

```rust
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use fictionet::stdlib::codec::{Ending, Lines, Stream};
use fictionet::stdlib::layer::{Admit, ByteStream, Chunk, Env, Layer, StreamCommand, StreamEvent, Top};

/// A login prompt that takes one password and closes.
struct Prompt {
    password: Arc<str>, // the right password, shared by every connection
    lines: Stream<Lines>,
    out: VecDeque<StreamCommand>,
    asked: bool,
    done: bool,
}

impl Prompt {
    fn new(password: Arc<str>) -> Prompt {
        let lines = Stream::new(Lines::new(256, Ending::LfOrCrlf));
        Prompt { password, lines, out: VecDeque::new(), asked: false, done: false }
    }
}

impl Layer for Prompt {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(&mut self, _: &mut Env<'_, Infallible>, event: StreamEvent) -> Result<Admit<StreamEvent>, Infallible> {
        match event {
            StreamEvent::Written(_) => Ok(Admit::Taken),
            event if self.done => Ok(Admit::Closed(event)),
            StreamEvent::Data(mut bytes) => {
                // Take what the line buffer has room for, and hand back the rest.
                let took = self.lines.push(&bytes);
                if took == bytes.len() {
                    return Ok(Admit::Taken);
                }
                bytes.advance(took);
                let rest = StreamEvent::Data(bytes);
                Ok(if took == 0 { Admit::Blocked(rest) } else { Admit::Partial(rest) })
            }
            StreamEvent::Ended | StreamEvent::Reset => {
                self.done = true;
                self.out.push_back(StreamCommand::End);
                Ok(Admit::Taken)
            }
        }
    }

    fn advance(&mut self, _: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        if !self.asked {
            self.asked = true;
            self.out.push_back(StreamCommand::Write(Chunk::new(b"password: ".to_vec())));
            return Ok(true);
        }
        if self.done {
            return Ok(false);
        }
        let Some(Ok(line)) = self.lines.next() else {
            return Ok(false);
        };
        let right = line.unwrap_or_default() == self.password.as_bytes();
        let answer: &[u8] = if right { b"welcome\n" } else { b"no\n" };
        self.out.push_back(StreamCommand::Write(Chunk::new(answer.to_vec())));
        self.out.push_back(StreamCommand::End);
        self.done = true;
        Ok(true)
    }

    fn is_terminal(&self) -> bool {
        self.done
    }

    fn on_command(&mut self, _: &mut Env<'_, Infallible>, command: Infallible) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.out.pop_front()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}
```

What every connection shares, here a password and in a real world a
directory, a process model or an order book, goes into the layer when it
is made, fresh for each connection. A layer refuses what it cannot take
yet, and the caller keeps it: the rules every layer keeps are in the
`layer` module docs.

Layers compose by type. `Chain<A, B>` puts `B` on `A` when `B`'s lower port
is `A`'s upper port, so TLS (`tls::TlsLayer`) goes under HTTP or under the
prompt above, `layer::Framed` turns a byte stream into whole frames with a
codec for a protocol that never handles bytes, and `Children` gives each
stream of a multiplexed connection, such as an HTTP/2 stream or an SSH
channel, a layer of its own. A layer can also:

- **Run timers.** It keeps them in a `layer::Timers` and answers
  `deadline` with the next; `on_timer` hears which one went off. A FIX
  session has four (heartbeat, TestRequest, logon, logout), each armed and
  cancelled on its own. A due timer is handled before more input is
  offered, so a client that never stops sending cannot starve it.
- **Hand over async work.** `take_work` gives the runner work that is a
  `services::stack::Job`, such as an HTTP handler's answer, the next frame
  of a streamed body, or a wait for something another connection sends,
  and `on_done` hears what it brought back. Work runs beside the reads, so
  concurrent responses interleave as HTTP/2 streams need. When another
  trader's order fills, that connection sends the fill to this one's work
  over a channel, and the layer writes the execution report. SMB2 oplock
  breaks, LDAP persistent search and MCP notifications work the same way.
- **Change protocol.** `layer::Switch<A, B>` runs `A` until it reaches a
  protocol boundary, then the `B` it negotiated, with the input `A` read
  past the boundary. STARTTLS (SMTP, IMAP, LDAP, Postgres's `SSLRequest`)
  is a plaintext layer whose `layer::Handoff` names a `tls::Secure` as what
  comes next, served with `Host::tcp_stack`. The plaintext layer hands over
  once its go-ahead is written. Plaintext the client pipelined after its
  request never reaches TLS: `B` is a `layer::Successor`, which says which
  of the input from before the switch it reads, and TLS reads none of it,
  however the plaintext layer handed it over. `services::stack::Tunnel`
  hands the rest of a stream to async code written against a connection,
  as what runs after a CONNECT or a WebSocket upgrade does.
- **Charge what it holds.** Each layer charges its own storage, such as a
  line buffer or a reply not yet written, to the connection's budget before
  it grows, and a `Chunk` carries its charge down the stack with the bytes.
  The runner charges its read buffer and the bytes the stack has not taken.

A stack error ends its connection. A panic is a bug in the world, and
Fictionet does not catch it: it ends the run, wherever in the world it
happens. As it unwinds, the runner names the stack and the connection on
standard error after the panic's own message, so the failed run says where
to look.

`services::stack::stream` runs a stack over a connection until the stack
has ended its direction with every byte written and no work left, and the
input has ended or the stack is terminal. When the world stops, or the
run's region is otherwise cancelled, it returns
`Err(StackError::Cancelled)`, unless the stack itself gave up. A task of
the stack's work that fails ends that work and cancels the run, never the
caller's region. `services::stack::datagrams` runs a stack over a UDP
socket the same way, one conversation for the socket's whole life.

The runner ends the input of a connection that sends nothing for
`StreamLimits::idle` (10 seconds) while it waits with nothing to write and
no work running: the stack hears it as an end of input. A write that takes
no bytes for `StreamLimits::write_timeout` (10 seconds) ends the
connection: a client that stops reading cannot hold a reply, or a stack's
timers, for ever. A client that resets the connection ends it at once,
also while a write waits.

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
message per datagram over UDP. Write a thin layer over a byte stream for
TCP and a thin layer over datagrams for UDP around one core of your own:
each picks its framing and hands the message to the shared code, and the
UDP side can answer `KRB_ERR_RESPONSE_TOO_BIG`. Serve them with
`Host::tcp_stack(88, ..)` and `Host::udp_stack(88, ..)`, each made with
the same shared state. The `ConnInfo` each factory gets says which.

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
The frame implements `Wire`, so a caller can write it directly. Framing still checks only the header and length. Reading and
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

`codec::Frames<itch::Message>` reports `itch::FrameError::TooLong`.

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

`Env::now` is the run's clock: time since the run started, with no
date. A layer that needs a date, such as for ticket lifetimes,
certificate validity or a FIX `SendingTime`, takes it from the shared
state it is made with, which decides what day it is in the world. Include that date in the world's
own typed state when readers need to place its observations on a calendar.

HTTP follows the same rule. `httpd` sends a `Date` header only when the
world gave its date at the start of the run (`Sites::date`, `Server::date`,
`Http1::date` or `HttpOptions::date`), and the header is
that date plus `Env::now`. With no world date, responses carry no `Date`
header at all, as RFC 9110 allows for a server without a clock: a world
that never says what day it is never leaks the host's. A `Date` a handler
sets itself goes out as it is.

## 2. A test with no runtime

`layer::Harness` runs a stack with no I/O: push the client's bytes, take
the reply.

```rust
use fictionet::stdlib::layer::Harness;

let mut h = Harness::new(fictionet::Seed::from_u64(0), Prompt::new("hunter2".into()));
h.settle()?;
assert_eq!(h.take_output(), b"password: ");
h.push(b"hunter2\n")?;
assert_eq!(h.take_output(), b"welcome\n");
assert!(h.ended());
```

The harness plays the peer and the transport, and takes the stack's output
only as fast as the test allows (`withhold`, `allow`, `allow_all`), so
backpressure can be tested. `advance` moves its clock and fires timers in
order. The stack's work waits for the test (`work`, `complete`) unless the
harness has a worker: `with_worker(services::stack::Polling::new())` polls
it as the live runners do. Its standalone entropy stream starts from the
supplied `Seed`. `Polling::in_world(fcx)` binds both its clock and
randomness to that run; use the run's sleeps then, because manual
`advance` is only available to standalone harnesses.

For decoder tests with caller decisions, `stdlib::test_support::Scripted`
holds a decoder and caller state. Its hooks run before each decode call and
after each item. Record a pending decision in the after-item hook to apply
it on the next call. Drive it with `test_support::decode_chunks` to check chunking.

## 3. A network

`Net` builds the network around its hosts. Each host has addresses (given
with `at`, or picked from the `Pools` the world passes to `Net::new`), DNS
names, and services on its ports. `fictionet_extras::network::cdn_pools`
gives public CDN space; `Pools::NONE` gives no automatic addresses, so every
host needs `at`. `tcp_stack(port, make)` serves a TCP port with a stack made
for each connection from its `ConnInfo`, which numbers it and names its
sandbox:

```rust
use std::sync::Arc;
use fictionet::stdlib::world::net::{Net, Pools};

let password: Arc<str> = "hunter2".into();
let at: std::net::Ipv4Addr = "10.20.0.5".parse()?;
Net::new(Pools::NONE)
    .host("vault", |h| h.at(at).dns_name("vault.corp.test").tcp_stack(2323, move |_| Prompt::new(password.clone())))
    .start(&fcx, attachments)?;
```

`start` fails if a host cannot be served as declared: an address a host
cannot have, two services on one port, or a port that cannot be opened.
Each host is prepared at all its addresses before any of it is published.
A rejected host leaves no new machine, route, listener, task, TLS name or
HTTP virtual host, and consumes no automatic address. Existing hosts keep
serving unchanged. Hosts already installed by `start` remain installed if
a later host fails. `NetHandle::add_host`, from `Net::handle`, places a
host while the network runs by the same rules, and returns the error.

Every sandbox that attaches joins `10.0.0.0/24` (and `2001:db8::/64`),
gets its address by DHCP or by its first packet, and asks the gateway at
`10.0.0.1` for names. It reaches every host and no other sandbox. An
address with no host answers "host unreachable", and a closed port a RST.

The gateway runs a recursive resolver with no route to the internet
(`net::dns::Recursive` over `resolver::Config::new()` with no root
hints). It answers the names hosts declare with their addresses, with RA
set and a one-hour TTL. Another name under a top-level
domain a declared name uses gets NXDOMAIN with an SOA, and a name under
any other top-level domain gets SERVFAIL with Extended DNS Error 22, No
Reachable Authority. `Net::gateway` runs something else there: a resolver
with root hints that iterates through authoritative servers on the
world's hosts (`net::dns::Authoritative`), or any program and services.
DNS programs run on any host with `Host::program`. A resolver's questions
to other servers leave its machine as real packets, so they reach the
world's hosts and any real server routed into the world. An authoritative
server's own questions, such as a learned zone's lookups of the zone's
real servers, go to a `net::dns::Upstream`, with `Only` around it to keep
them to the world's policy, and what comes back is filed as records the
server answers from. A `net::dns::Namespace` starts a new session in all
of them at once.

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

With `fictionet attach http-proxy` or `attach socks5`, attach looks
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

- `tcp_stack_with(port, limits, max_conns, make)`: the same, with
  `StreamLimits` for the idle and write limits, and a cap on the
  connections served at once (`tcp_stack` uses `DEFAULT_MAX_CONNS`, 64).
- `udp_stack(port, budget, make)`: one stack for the port, a layer over
  `Datagrams`, which gets every datagram whole with its sender's address
  and sends each datagram it gives to the address it names, so it can
  send to anyone and run timers, as a MoldUDP64 server does for
  retransmissions and heartbeats. It is one conversation for the socket's
  whole life, and its factory gets the socket's address. What it retains
  is charged to `budget`.
- `tls_stack(port, sni, certificate, make)`: TLS first, picked by the name the
  client sends (`Sni::Any`, `Sni::Names` for the host's DNS names, or one
  name), then a stack over the decrypted stream; several calls on one port
  route by SNI.
- `port_server(port, server)` and `tls_accept(port, sni, certificate, server)`: a
  `PortServer` of the world's own. HTTP is one: `httpd::Server`, below.

TLS certificate callbacks return `Arc<tls::CertifiedKey>`, containing the standard
DER certificate chain and private key. `ca::Leaf::certified_key()` constructs one
from an issued leaf. A replacement TLS factory receives this material and the
selected application's ALPN list; it does not need to inspect a rustls config.
The default factory constructs rustls configs and retains up to 64 recent ones
for resumption, isolated by run, certificate identity and ALPN. Reuse the
certificate's `Arc` across handshakes to keep its session state; cache eviction
can require a full handshake. Its configuration callback runs only when a new
configuration is built. Configure engine settings such as key logging through `tls::Factory::rustls`. Pass a
configured `httpd::Server` to `web::Site::from_server` to use replacement TLS
or negotiated applications inside `web::Sites`.

A `PortServer` constructs an application through `stack(fcx, opening)` on either
a plain stream or negotiated TLS. `opening.info.tls` identifies the carrier.
Its `PortStack` result supplies a layer, refuses the connection, or selects the
asynchronous `serve_connection` adapter. Refusal closes the transport child
without constructing an application.

Reading a `tls::TlsConnection` can also send TLS output, such as a KeyUpdate
reply. If that send fails, the read reports the underlying connection error.
Plaintext already decrypted is kept for the next read. If the connection has
no room for output, sending waits for the next read or write.

TLS ownership and reproducibility are split across these files:

- [`tls/provider.rs`](../src/stdlib/services/tls/provider.rs) owns config builders,
  the run clock, explicit entropy, key exchange and signing. Its public functions
  remain under `tls`. Fixed certificates, a fixed world date, the same seed
  and ordered inputs repeat TLS records in a closed lab. Its docs describe
  the obligations of custom resolvers and signers and the effect of real peers.
- [`tls/layer.rs`](../src/stdlib/services/tls/layer.rs) processes TLS records and
  accounts for ciphertext delivery and plaintext credit.
  [`stack/open.rs`](../src/stdlib/services/stack/open.rs) drives the layer through
  `Live` and handles connection reads, writes and cancellation.
- [`tls/factory.rs`](../src/stdlib/services/tls/factory.rs) defines replaceable TLS
  construction and negotiation. [`tls/secure.rs`](../src/stdlib/services/tls/secure.rs)
  selects the application after the handshake.
- [`tls.rs`](../src/stdlib/services/tls.rs) provides convenience handshakes and
  connections backed by the layer. [`ca.rs`](../src/stdlib/services/ca.rs) issues
  certificates using the run's randomness and world-supplied leaf validity.
- Supply a world-owned `rustls::KeyLog` to a TLS config when keys are needed.
  Capture, key retention, export and decryption belong to
  `fictionet::stdlib::dissect`.

[Repeatable runs](../src/guide/running.rs) describes external I/O and clock
limits. [`httpd.rs`](../src/stdlib/web/httpd.rs) says how the native HTTP/2
server keeps time.

Each peer address may hold 256 connections at once across all machines
and gateway DNS listeners in the network. Bytes held by the stacks are
charged to one budget per sandbox, 256 MiB by default. TCP socket
buffers and TLS handshakes are outside this budget. The runner counts
each connection's read buffer and the input the stack has not taken yet,
and each layer counts what it holds, such as a framer's buffer and the
replies not yet written. Memory outside those counts, such as hyper's
own buffers, is not charged.
`Net::limits` changes these limits and the TLS handshake and DNS timers.
Tests set small ones.
`fictionet::run(seed, world)` gives TCP, UDP, services, HTTP exchanges one ChaCha20 byte stream through `Cx`. The same seed and
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
Net::new(Pools::NONE)
    .lan("corp", "192.168.56.0/24".parse()?)
    .host("dc01", |h| h.on("corp").at(dc01).dns_name("dc01.corp.test").tcp_stack(389, move |_| Ldap::new(directory.clone())))
    .member("ws01", "corp", "192.168.56.31".parse()?)
    .start(&fcx, attachments)?;
```

`Net::route(name, prefix)` wires a trusted sandbox, such as a real
container that plays one of the hosts, straight to the router at a fixed
prefix. `net::dns::placing` is a root zone for the gateway's resolver that
places a host the first time a name is looked up, which is how `web::Sites`
works.

Lab clients can use `sandbox::TlsClient` over a simulated connection. A
write returns once rustls took its plaintext, and waits until the connection
underneath took the ciphertext of the write before. A flush, or `write_all`,
returns once it took all of it. A pending write took nothing, and downstream
errors reach the caller.

## 4. HTTP

HTTP is a stack like the others. Implement `httpd::Handler` for a
custom handler, or use axum through the tower adapter:

```rust
use fictionet::stdlib::web::httpd;
let api = httpd::tower(axum::Router::new()
    .route("/status", axum::routing::get(|| async { "ok\n" })));
```

On native HTTP/1, a handler can read a cut-off body frame by frame:
it gets the bytes received, then an error. HTTP/2 rejects body collection
errors before calling a handler. Protocol upgrades use a `101` response
with an `httpd::UpgradeHandler` extension, which receives the connection
and its unread bytes after the response is written.

An axum `Router`, or any tower service over `http::Request<web::Body>`,
runs with `httpd::tower(service)`. A handler reports typed facts directly
through state supplied by its world.

HTTP/1.1 responses with unknown-length bodies use chunked encoding. Pending
polls and empty data frames do not end the response. The zero-size chunk is
sent only at body EOF, so the next response can use the same connection.
HTTP/1.0 closes the connection to end an unknown-length response.

All backends suppress response bodies for `HEAD`, informational statuses,
`204` and `304`. For other statuses, `HEAD` uses a supplied `Content-Length`
to describe the body a GET would have, or the known body length. Native
HTTP/1 omits lengths for bodyless statuses and uses the body's length for
other responses. Both versions keep a supplied `Date`; otherwise they use the world's
date, when set.

On a network, `httpd::Server` is the `PortServer` that serves a handler on a
port, and `httpd::Server::served_by` puts one on ports 80 and 443 as `web::Sites`
does:

```rust
use fictionet::stdlib::web::httpd::Server;
use fictionet_extras::network::cdn_pools;

Net::new(cdn_pools())
    .host("intranet", |h| h.dns_name("intranet.corp.test").port_server(80, Server::new(api.clone())))
    .add_host(Server::new(api).tls_with(move |_| certificate.clone()).served_by(Host::new("www").dns_name("www.corp.test")))
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
relative paths. Each version has its own file there: `native.rs` for
HTTP/1, and `http2.rs` with the `http2/` directory for HTTP/2.

Each routed request carries an `httpd::Target`. Its `routing` field is
`Routing::Exact` when the requested host matches a registered name, or
`Routing::Fallback` when a default site answers. The `host` field keeps
the requested name in both cases.

With `web-proxy`, `web::Proxy` forwards only exact matches. A fallback
request gets `421 Misdirected Request` before any upstream I/O, even if
the proxy's site has `default_host()`. For catch-all forwarding, use
`web::forward(&fcx, upstream, client)?`: the injected `Upstream` transport connects to that fixed origin and
preserves the requested `Host`. Both `web::proxy` and `web::forward` work in real and lab runs. The feature
works without tokio. Host helper
threads handle upstream HTTP/1.1 and rustls, reusing completed connections.
Both tower services return streaming `httpd::Body` responses. `Proxy` can
also answer with a local rejection.

`Http1` speaks HTTP/1.0 and 1.1 on the stdlib's `http1` decoder, as a
`layer::Layer` over a byte stream: test it with `layer::Harness`, and
`serve_connection` runs it with `services::stack::stream`. On a host's TLS
port it runs in the same stack as TLS, `Chain<TlsLayer, Http1>`. `Http2`
is the HTTP/2 connection as a layer, on the stdlib's `http2` frames and
HPACK: a byte stream below, and one `HttpExchange` child per stream above,
opened with the request's head. `Respond` answers an exchange with the same
`Handler` trait, and `Responder::http2` composes the server,
`Chain<Http2, Children<Respond, Top, Opening>>`. `Grpc` serves gRPC calls
on an exchange instead, each call its own child. On a host's TLS port,
HTTP/2 runs in the same stack as TLS when ALPN chose `h2`. Without TLS,
`serve_connection` tells HTTP/2's preface from HTTP/1 by reading no more of
the first bytes than that takes, and HTTP/1 hands the connection to HTTP/2
after answering `Upgrade: h2c` with `101`. Neither version needs tokio.
Both share one set of `httpd::Limits`: body size, body and write timers,
and 100 streams at once on an HTTP/2 connection.
Both charge retained request heads and bodies to the sandbox's budget. A pending
handler keeps its request charge. Heads count method, URI and header bytes and
header slots. Hidden capacities in `http` types, request extensions, third-party
allocation overhead and transport buffers are outside these counts. A request
whose metadata does not fit is rejected before calling its handler. Both
versions draw a handler's randomness from the run's stream.

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
HTTP/2 rejects it during body collection.
Native HTTP/1 closes on a body deadline. HTTP/2 answers `408` when
body collection times out and `400` when reading the body fails, before
calling the handler. A transport failure may prevent that answer reaching
the client. HTTP/1 head deadlines include the wait between requests.
HTTP/2 has no request-head deadline. Body deadlines
and write stall deadlines use the Fictionet clock on every backend.

An empty half-close before the first request closes cleanly. EOF partway through
an HTTP/2 preface is a truncated HTTP/1 head and answers `400 Bad Request`.

In `http2::Session`, HPACK reductions wait for the corresponding SETTINGS
ACK. A decrease followed by an unacknowledged rebound leaves the earlier
allowance in place. ACKs apply in announcement order. Later pending
increases stay allowed, but do not cancel required minimum-size updates
at the next header block.

## 5. Observation

A stack reports facts through the typed state it was made with, and an HTTP handler can
report directly when it answers a request. Nothing is emitted by default.
The optional `network::tap` copies packets to a caller-owned bounded channel.
`Net::on_unreachable` supplies typed source and destination addresses when a
packet has no route.

Worlds own storage and views. Packet inspection is an independent function in
[`stdlib::dissect`](../src/stdlib/dissect/mod.rs); packets and TLS keys are
supplied by its caller. [`stdlib::pcap`](../src/stdlib/pcap.rs) writes those
packets to pcapng without retention or subscriptions.

## 6. A world's page

Each world writes its own page. With the `page` feature,
[`stdlib::page`](../src/stdlib/page.rs) streams one concrete state type from a
watch channel at `/state`. Compose that axum route with the world's HTML,
commands, assets, and access rules. The terminal and screen modules accept
caller-supplied sockets and browser libraries.

## Changing framing between items

A layer over a byte stream can own a protocol module's decoder in a
`codec::Stream`, as the prompt above owns its line reader. `Stream::decoder`
returns the active decoder, so a mode change applies before the next item,
including bytes already buffered from the same read. For SMTP, accept
`DATA`, send `354`, and call `start_data()`. The part of a mail layer that
answers what it has read:

```rust
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::layer::{Chunk, StreamCommand};
use fictionet::stdlib::protocols::smtp;

struct Mailbox {
    input: Stream<smtp::Inputs>,
    out: std::collections::VecDeque<StreamCommand>,
    messages: Vec<Vec<u8>>,
}

impl Mailbox {
    /// Answers every item the stream holds; the layer's `advance` calls it.
    fn answer(&mut self) -> Result<(), smtp::Error> {
        while let Some(item) = self.input.next() {
            // A stream cut short inside a command, or whose framing failed.
            let Ok(item) = item else {
                return Err(smtp::Error::Incomplete);
            };
            let reply: &[u8] = match item? {
                smtp::Input::Command(command) if command.verb == "DATA" => {
                    self.input.decoder().start_data().map_err(smtp::Error::Framing)?;
                    b"354 Send data\r\n"
                }
                smtp::Input::Message(bytes) => {
                    self.messages.push(bytes);
                    b"250 Queued\r\n"
                }
                smtp::Input::Command(_) => b"250 OK\r\n",
                smtp::Input::Line(_) => b"503 Unexpected response\r\n",
            };
            self.out.push_back(StreamCommand::Write(Chunk::new(reply.to_vec())));
        }
        Ok(())
    }
}
```

Serve it with `host.tcp_stack(smtp::PORT, |_| Mailbox::new())`. The SMTP
decoder removes transparency dots and returns to commands after the DATA
terminator. The same access lets an IMAP layer refuse a literal or a
Postgres layer resume startup after replying `N` to an SSL request.

IMAP status responses always write a space after the status word, even with
empty text. The space counts toward `imap::MAX_TEXT`. Readers accept an
omitted space only when adding it still fits that limit. Otherwise,
`imap::Response::parse` returns `imap::Error::TooLong`, and `imap::Responses`
yields that error as an item before reading the next response. Writing a
response that cannot fit returns `imap::Error::Unwritable` and leaves the
output unchanged.

For SMTP AUTH, send a `334` challenge and call `stream.decoder().expect_line()`.
The next item is `smtp::Input::Line(Vec<u8>)`. It preserves the response bytes
without CRLF, including an empty response or `*` cancellation. Call
`expect_line()` again for each further challenge. SASL validation,
cancellation replies and authentication results belong to the mail layer.

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

`Stream::decoder()` changes the active decoder between items. A layer
over datagrams reads each datagram with a stream of its own, so each new
datagram starts with a fresh decoder.

## SSH sessions

`stdlib::services::ssh::Ssh` is the SSH connection as a layer: a byte stream
below, and one child per channel above, each opened with its typed request.
Authentication and connection requests stay with the parent, and
`Ssh::sessions` puts a session layer on every channel. `ssh::Server` is the
`PortServer` that runs it with `services::stack::stream`.
Its `Handler` chooses each authentication result and creates a `Session` for a
shell, exec command or subsystem. `SessionRequest` carries the authenticated
user, accepted environment and optional terminal settings. The session receives
raw input bytes and typed resize, signal, EOF and close events. `Output` queues
stdout, stderr and exit status under a fixed bound; the server drains it under
the peer's channel window and maximum packet size. Applications must handle a
full output queue. A per-connection channel limit and authentication deadline
bound retained state.

The transport and message codecs contain protocol standards. World code owns
credentials, account policy, host keys and application behavior. The optional
`fictionet_extras::ssh` module provides a sourced Ubuntu OpenSSH profile,
`honeypot::Observed` to record typed activity without changing policy, and a
separate terminal line editor. The honeypot demo combines them with a fake
shell and a read-only SFTP directory; it never executes client commands.
