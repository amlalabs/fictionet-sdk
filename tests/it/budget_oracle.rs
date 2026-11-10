//! The allocation oracle: each stack runs on one thread under a tight
//! budget, and after every step the heap it holds is checked against what
//! its budget is charged. The test binary's allocator counts every
//! allocation made on this thread, which the charged types cannot see:
//! storage a stack keeps outside any budget shows up here as heap its
//! budget does not cover. This is the one place ambient state is used, and
//! only in this test binary.
//!
//! Only the stack's own steps are counted ([`Oracle::step`]); the test's
//! peer (a TLS or SSH client, and the bytes it builds) runs outside them.
//! After every step the oracle checks
//!
//! ```text
//! held - outside <= budget.used() + fixed + SLACK
//! ```
//!
//! where `held` is what the steps left allocated, `outside` is the peer's
//! bytes the harness still holds for the stack to take, and `fixed` is
//! what the stack held beyond its charge once it was built and settled:
//! its layer state, the harness and the driver, measured once and printed.
//! [`SLACK`] is the stated allowance for what the budget does not count by
//! design: the shared header around each chunk's bytes, one handler call's
//! request and response values in flight, and the part of the harness's
//! front input piece the stack has already copied.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, Driver, Harness, Layer, MessageCommand, MuxCommand, MuxEvent,
    PacketCommand, PacketEvent, StreamCommand, StreamEvent,
};
use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};
use fictionet::stdlib::network::packet::{CheckedIpPacket, Origin};
use fictionet::stdlib::network::transport::TcpControl;
use fictionet::stdlib::network::{ConnInfo, tcp};
use fictionet::stdlib::protocols::{hpack, http2};
use fictionet::stdlib::services::ca::Ca;
use fictionet::stdlib::services::stack::Polling;
use fictionet::stdlib::services::tls;
use fictionet::stdlib::web::httpd::{Http1, Responder};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy, block_on, lab};

use crate::common::alloc::{left_allocated, unmeasured};

/// What the budget does not count by design, in bytes: see the module
/// comment.
const SLACK: i128 = 8 << 10;

#[test]
fn complete_headers_need_no_assembly_copy() {
    use crate::common::alloc::allocations;
    let limits = http2::Limits::default();
    let mut encoded = Vec::new();
    hpack::Encoder::new(0)
        .encode_block(&[hpack::Field::new(":method", "GET")], &mut encoded)
        .unwrap();
    let frame = http2::Frame::Headers(http2::Headers {
        stream: 1,
        flags: 4,
        fragment: encoded,
        priority: None,
        padding: None,
    });
    let http2::Frame::Headers(head) = &frame else {
        unreachable!()
    };
    let mut model = hpack::Table::new(4096);
    let mut blocks = http2::HeaderBlocks::with_limits(limits);
    let (expected, direct) = allocations(|| {
        model
            .decode_block(&head.fragment, limits.header_list)
            .unwrap()
    });
    let (actual, assembled) = allocations(|| blocks.read_frame(&frame).unwrap().block.unwrap());
    assert_eq!(actual, expected);
    assert!(
        assembled <= direct,
        "{assembled} allocations versus {direct} for decoding"
    );
}

/// One stack's heap, counted step by step, and the budget it is checked
/// against.
struct Oracle {
    stack: &'static str,
    budget: Budget,
    /// What the stack's steps left allocated.
    held: i128,
    /// What the stack held beyond its charge once it settled.
    fixed: i128,
    /// The most the stack held past its charge and `fixed`.
    worst: i128,
    most_used: usize,
    checks: usize,
}

impl Oracle {
    fn new(stack: &'static str, budget: &Budget) -> Oracle {
        Oracle {
            stack,
            budget: budget.clone(),
            held: 0,
            fixed: 0,
            worst: i128::MIN,
            most_used: 0,
            checks: 0,
        }
    }

    /// Runs one step of the stack, counting what it leaves allocated.
    fn step<T>(&mut self, f: impl FnOnce() -> T) -> T {
        let (value, left) = left_allocated(f);
        self.held += left;
        value
    }

    /// The stack is built and has settled: what it holds now beyond its
    /// charge is its fixed state.
    fn settled(&mut self) {
        self.fixed = (self.held - self.used()).max(0);
    }

    /// Checks the heap the stack holds now, less `outside` bytes of the
    /// peer's that the harness still holds.
    fn check(&mut self, outside: usize) {
        let used = self.used();
        let over = self.held - outside as i128 - used - self.fixed;
        self.worst = self.worst.max(over);
        self.most_used = self.most_used.max(self.budget.used());
        self.checks += 1;
        assert!(
            over <= SLACK,
            "{}: the heap holds {} bytes, {over} past the budget's {used}, the fixed {} \
             and the slack {SLACK}",
            self.stack,
            self.held - outside as i128,
            self.fixed,
        );
    }

    /// The stack is gone: its budget is back at zero and its heap with it.
    fn finish(self) {
        assert_eq!(
            self.budget.used(),
            0,
            "{}: charges outlived the stack",
            self.stack
        );
        eprintln!(
            "{}: {} checks, fixed {} bytes, worst {} bytes past budget plus fixed \
             (slack {SLACK}), most used {} of {}, left after drop {}",
            self.stack,
            self.checks,
            self.fixed,
            self.worst,
            self.most_used,
            self.budget.limit(),
            self.held,
        );
        assert!(
            self.held <= SLACK,
            "{}: {} bytes stayed allocated after the stack was dropped",
            self.stack,
            self.held
        );
    }

    fn used(&self) -> i128 {
        self.budget.used() as i128
    }
}

/// Takes what the stack wrote, handing the peer a copy made outside the
/// count.
fn written<L: Layer<Lower = fictionet::stdlib::layer::ByteStream>>(h: &mut Harness<L>) -> Vec<u8> {
    let out = h.take_output();
    unmeasured(|| out.clone())
}

/// A header value of `n` bytes that lives for the whole test, made before
/// any count begins.
fn large_value(n: usize) -> &'static str {
    Box::leak("x".repeat(n).into_boxed_str())
}

#[test]
fn http1_holds_no_heap_its_budget_does_not_cover() {
    const REQUESTS: usize = 48;
    const BODY: usize = 12_000;
    let large = large_value(6000);
    let handler = fictionet_test_support::handler(move |_, request| {
        assert_eq!(request.body().len(), BODY);
        let mut response = http::Response::new(Bytes::from_static(b"done"));
        response
            .headers_mut()
            .insert("x-large", http::HeaderValue::from_static(large));
        response
    });
    let mut input = Vec::new();
    for i in 0..REQUESTS {
        input.extend_from_slice(
            format!(
                "POST /{i} HTTP/1.1\r\nHost: a.test\r\nX-Large: {large}\r\n\
                 Content-Length: {BODY}\r\n\r\n"
            )
            .as_bytes(),
        );
        input.extend(std::iter::repeat_n(b'b', BODY));
    }
    let budget = Budget::new(512 << 10);
    let mut oracle = Oracle::new("HTTP/1", &budget);
    let mut h = oracle.step(|| {
        let mut h = Harness::with_budget(Seed::from_u64(1), Http1::new(handler), budget.clone())
            .with_worker(Polling::new());
        h.settle().unwrap();
        h
    });
    oracle.settled();
    let mut answered = 0;
    for piece in input.chunks(1000) {
        answered += oracle.step(|| {
            h.push(piece).unwrap();
            let out = h.take_output();
            out.windows(12).filter(|w| w == b"HTTP/1.1 200").count()
        });
        oracle.check(h.unread());
    }
    while h.unread() > 0 || h.jobs() > 0 {
        answered += oracle.step(|| {
            h.settle().unwrap();
            let out = h.take_output();
            out.windows(12).filter(|w| w == b"HTTP/1.1 200").count()
        });
        oracle.check(h.unread());
    }
    assert_eq!(answered, REQUESTS);
    oracle.step(|| drop(h));
    oracle.finish();
}

/// A HEADERS frame for a POST on `stream`, carrying `large` as a header,
/// split into a HEADERS and a CONTINUATION frame when `split`.
fn h2_request(stream: u32, large: &str, split: bool) -> Vec<u8> {
    let mut fragment = Vec::new();
    for (name, value) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", "/upload"),
        ("x-large", large),
    ] {
        hpack::Field::new(name, value).write(&mut fragment).unwrap();
    }
    let mut bytes = Vec::new();
    let at = if split {
        fragment.len() / 2
    } else {
        fragment.len()
    };
    let rest = fragment.split_off(at);
    http2::Headers {
        stream,
        flags: if split { 0 } else { 4 },
        fragment,
        priority: None,
        padding: None,
    }
    .write(&mut bytes)
    .unwrap();
    if split {
        http2::Continuation {
            stream,
            flags: 4,
            fragment: rest,
        }
        .write(&mut bytes)
        .unwrap();
    }
    bytes
}

fn h2_preface() -> Vec<u8> {
    let mut bytes = http2::PREFACE.to_vec();
    for flags in [0, 1] {
        http2::Settings {
            flags,
            entries: Vec::new(),
        }
        .write(&mut bytes)
        .unwrap();
    }
    bytes
}

#[test]
fn http2_holds_no_heap_its_budget_does_not_cover() {
    const STREAMS: u32 = 24;
    const FRAMES: usize = 256;
    const FRAME: usize = 8;
    let large = large_value(9000);
    let handler = fictionet_test_support::handler(move |_, request| {
        assert_eq!(request.body().len(), FRAMES * FRAME);
        let mut response = http::Response::new(Bytes::from_static(b"done"));
        response
            .headers_mut()
            .insert("x-large", http::HeaderValue::from_static(large));
        response
    });
    let mut input = h2_preface();
    for i in 0..STREAMS {
        let stream = 2 * i + 1;
        input.extend(h2_request(stream, large, i % 2 == 1));
        for frame in 0..FRAMES {
            http2::Data {
                stream,
                flags: u8::from(frame + 1 == FRAMES),
                data: vec![b'd'; FRAME],
                padding: None,
            }
            .write(&mut input)
            .unwrap();
        }
    }
    let budget = Budget::new(192 << 10);
    let mut oracle = Oracle::new("HTTP/2", &budget);
    let mut h = oracle.step(|| {
        let mut h = Harness::with_budget(
            Seed::from_u64(1),
            Responder::new(handler).http2(),
            budget.clone(),
        )
        .with_worker(Polling::new());
        h.settle().unwrap();
        h
    });
    let mut output = Vec::new();
    let mut pieces = input.chunks(1000);
    let first = pieces.next().unwrap();
    output.extend(oracle.step(|| {
        h.push(first).unwrap();
        written(&mut h)
    }));
    oracle.settled();
    oracle.check(h.unread());
    for piece in pieces {
        output.extend(oracle.step(|| {
            h.push(piece).unwrap();
            written(&mut h)
        }));
        oracle.check(h.unread());
    }
    while h.unread() > 0 || h.jobs() > 0 {
        output.extend(oracle.step(|| {
            h.settle().unwrap();
            written(&mut h)
        }));
        oracle.check(h.unread());
    }
    let mut answered = 0;
    let mut rest = &output[..];
    while !rest.is_empty() {
        let header = http2::FrameHeader::parse(&rest[..9]).unwrap();
        if let http2::Frame::Headers(headers) =
            http2::Frame::parse(&rest[..9 + header.length]).unwrap()
        {
            answered += usize::from(headers.stream % 2 == 1);
        }
        rest = &rest[9 + header.length..];
    }
    assert_eq!(answered, STREAMS as usize, "every stream answered");
    oracle.step(|| drop(h));
    oracle.finish();
}

#[test]
fn tls_bulk_holds_no_heap_its_budget_does_not_cover() {
    use std::io::{Read, Write};
    const TOTAL: usize = 1 << 20;
    block_on(lab(Seed::from_u64(12), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = crate::tls::server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = crate::tls::client_config(&fcx, &ca, &[b"http/1.1"]);
        let mut client = rustls::ClientConnection::new(
            client_config,
            rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        )?;
        let client_output = |client: &mut rustls::ClientConnection| {
            let mut bytes = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut bytes).unwrap();
            }
            bytes
        };
        let receive = |client: &mut rustls::ClientConnection, bytes: &[u8]| {
            let mut rest = bytes;
            while !rest.is_empty() {
                assert!(client.read_tls(&mut rest).unwrap() > 0);
                client.process_new_packets().unwrap();
            }
        };
        let budget = Budget::new(256 << 10);
        // rustls's own buffers are charged to the same budget: nothing
        // the connection holds is allowed for.
        let mut oracle = Oracle::new("TLS", &budget);
        let mut h = oracle.step(|| {
            Harness::with_budget(
                Seed::from_u64(12),
                tls::TlsLayer::new(config.clone()),
                budget.clone(),
            )
        });
        let hello = client_output(&mut client);
        oracle.step(|| {
            h.push(&hello).unwrap();
            let selection = h.work().unwrap();
            drop(selection);
            h.complete(Some(config.clone())).unwrap();
        });
        for _ in 0..32 {
            let out = oracle.step(|| written(&mut h));
            receive(&mut client, &out);
            let next = client_output(&mut client);
            oracle.step(|| h.push(&next).unwrap());
            if !client.is_handshaking() && !h.layer().is_handshaking() {
                break;
            }
        }
        assert!(!h.layer().is_handshaking());
        let out = oracle.step(|| written(&mut h));
        receive(&mut client, &out);
        oracle.settled();
        oracle.check(h.unread());

        // The client sends a mebibyte; the server echoes each piece back.
        let message = vec![b'p'; 16 << 10];
        let mut sent = 0;
        let mut echoed = Vec::new();
        while sent < TOTAL || echoed.len() < TOTAL {
            if sent < TOTAL {
                client.writer().write_all(&message)?;
                sent += message.len();
            }
            let wire = client_output(&mut client);
            let out = oracle.step(|| {
                h.push(&wire).unwrap();
                let mut events = Vec::new();
                h.driver().send_above(|event| {
                    events.push(event);
                    Admit::Taken
                });
                for event in events {
                    if let StreamEvent::Data(chunk) = event {
                        assert!(matches!(
                            h.driver().command(StreamCommand::Write(chunk)),
                            Ok(Admit::Taken)
                        ));
                    }
                }
                h.settle().unwrap();
                written(&mut h)
            });
            oracle.check(h.unread());
            receive(&mut client, &out);
            let mut plain = [0; 16 << 10];
            loop {
                match client.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(n) => echoed.extend_from_slice(&plain[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
            assert!(echoed.len() <= sent);
        }
        assert_eq!(echoed.len(), TOTAL);
        oracle.step(|| drop(h));
        oracle.finish();
        Ok(())
    }))
    .unwrap();
}

const PEER: &str = "10.0.0.1";
const SERVER: &str = "10.0.0.2";
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

/// A segment from the peer's port `sport` to the server's port 80.
fn tcp_segment(
    sport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> PacketEvent<CheckedIpPacket> {
    let (src, dst) = (PEER.parse().unwrap(), SERVER.parse().unwrap());
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&80u16.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    let sum = transport_checksum(src, dst, 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    let packet = packet_with(src, dst, 6, Fields::default(), &t);
    PacketEvent::Packet(CheckedIpPacket::checked(Chunk::unpaid(packet.0), Origin::Arrived).unwrap())
}

#[test]
fn tcp_holds_no_heap_its_budget_does_not_cover() {
    const CONNS: u16 = 16;
    const ROUNDS: u32 = 48;
    const SEGMENT: usize = 1000;
    let payload = vec![b't'; SEGMENT];
    let budget = Budget::new(4 << 20);
    let mut oracle = Oracle::new("TCP", &budget);
    let mut stack = oracle.step(|| {
        let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(1)));
        let tcp = tcp::TcpLayer::new(
            SERVER.parse().unwrap(),
            tcp::Options::default(),
            &*entropy,
            Instant::ZERO,
        );
        let mut stack = Driver::new(tcp, entropy, budget.clone(), Instant::ZERO);
        for control in [
            TcpControl::Listen {
                port: 80,
                backlog: None,
                answer: None,
            },
            TcpControl::Accept {
                port: 80,
                count: usize::from(CONNS),
            },
        ] {
            assert!(matches!(
                stack.command(MuxCommand::control(MessageCommand::Send(control))),
                Ok(Admit::Taken)
            ));
        }
        stack.run().unwrap();
        stack
    });
    oracle.settled();
    oracle.check(0);
    let mut peers = Vec::new();
    let mut children = Vec::new();
    for port in 1000..1000 + CONNS {
        let ack = oracle.step(|| {
            assert!(matches!(
                stack.deliver(tcp_segment(port, 100, 0, SYN, &[])),
                Ok(Admit::Taken)
            ));
            stack.run().unwrap();
            let mut ack = None;
            stack.send_below(|command| {
                if let PacketCommand::Send(bytes) = command {
                    let ihl = usize::from(bytes[0] & 15) * 4;
                    let seq = u32::from_be_bytes(bytes[ihl + 4..ihl + 8].try_into().unwrap());
                    ack = Some(seq.wrapping_add(1));
                }
                Admit::Taken
            });
            // A connection the budget has no room for is not answered.
            let ack = ack?;
            assert!(matches!(
                stack.deliver(tcp_segment(port, 101, ack, ACK, &[])),
                Ok(Admit::Taken)
            ));
            stack.run().unwrap();
            stack.send_above(|event| {
                if let MuxEvent::Opened(child, _, _) = event {
                    children.push(child);
                }
                Admit::Taken
            });
            Some(ack)
        });
        oracle.check(0);
        if let Some(ack) = ack {
            peers.push((port, ack));
        }
    }
    assert_eq!(children.len(), peers.len());
    assert!(!peers.is_empty(), "the budget takes a connection");
    let mut received = 0;
    for round in 0..ROUNDS {
        // The first half of the rounds nothing is read, so the data waits
        // in the stack; after that every child is given credit to read.
        let reading = round >= ROUNDS / 2;
        for (i, &(port, ack)) in peers.iter().enumerate() {
            let seq = 101 + round * SEGMENT as u32;
            received += oracle.step(|| {
                let _ = stack.deliver(tcp_segment(port, seq, ack, ACK, &payload));
                if reading {
                    let _ = stack.command(children[i].grant(1 << 20));
                }
                stack.run().unwrap();
                stack.send_below(|_| Admit::Taken);
                let mut received = 0;
                if reading {
                    stack.send_above(|event| {
                        if let MuxEvent::Child(_, StreamEvent::Data(chunk)) = event {
                            received += chunk.len();
                        }
                        Admit::Taken
                    });
                }
                received
            });
            oracle.check(0);
        }
    }
    assert!(received > 0, "the children read data");
    oracle.step(|| {
        drop(children);
        drop(stack);
    });
    oracle.finish();
}

struct Echo;
impl fictionet::stdlib::services::ssh::Handler for Echo {
    type Session = Self;
    fn authenticate(
        &self,
        _: &fictionet::stdlib::services::ssh::Context<'_>,
        _: &fictionet::stdlib::services::ssh::AuthAttempt<'_>,
    ) -> fictionet::stdlib::services::ssh::AuthDecision {
        fictionet::stdlib::services::ssh::AuthDecision::Accept
    }
    fn open(
        &self,
        _: &fictionet::stdlib::services::ssh::Context<'_>,
        _: &fictionet::stdlib::services::ssh::SessionRequest,
        _: &mut fictionet::stdlib::services::ssh::Output,
    ) -> Option<Self> {
        Some(Self)
    }
}
impl fictionet::stdlib::services::ssh::Session for Echo {
    fn input(
        &mut self,
        _: &fictionet::stdlib::services::ssh::Context<'_>,
        bytes: &[u8],
        out: &mut fictionet::stdlib::services::ssh::Output,
    ) {
        out.write(bytes).unwrap();
    }
    fn event(
        &mut self,
        _: &fictionet::stdlib::services::ssh::Context<'_>,
        event: &fictionet::stdlib::services::ssh::SessionEvent,
        out: &mut fictionet::stdlib::services::ssh::Output,
    ) {
        if matches!(event, fictionet::stdlib::services::ssh::SessionEvent::Eof) {
            out.exit(0);
        }
    }
}

struct SshClient;
impl russh::client::Handler for SshClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn ssh_channels_hold_no_heap_their_budget_does_not_cover() {
    use fictionet::stdlib::protocols::ssh as wire;
    use fictionet::stdlib::services::ssh;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const CHANNELS: usize = 4;
    // The server's whole receive window.
    const PER_CHANNEL: usize = 64 << 10;
    tokio::time::timeout(Duration::from_secs(60), async {
        let (client_side, mut server) = tokio::io::duplex(1 << 20);
        // Near the most the connection holds, about 1.42 MiB with four
        // channels open, each in turn sending a full window. Storage the
        // budget refuses waits for memory, or refuses a channel; none of
        // it fails the connection.
        let budget = Budget::new(3 << 19);
        let server_budget = budget.clone();
        // Set once the client is authenticated: the server's state from
        // then on is its fixed state.
        let authenticated = Arc::new(AtomicBool::new(false));
        let signed_in = authenticated.clone();
        let task = tokio::spawn(async move {
            let budget = server_budget;
            let mut oracle = Oracle::new("SSH", &budget);
            let mut h = oracle.step(|| {
                let config = Arc::new(ssh::Config::new(
                    Arc::new(wire::transport::HostKey::ed25519_from_seed([7; 32]).unwrap()),
                    wire::Identification::new("2.0", "test", None).unwrap(),
                ));
                let layer =
                    ssh::Ssh::new(config, Arc::new(Echo), Arc::new(ConnInfo::default())).sessions();
                let mut h = Harness::with_budget(Seed::from_u64(19), layer, budget.clone());
                h.settle().unwrap();
                h
            });
            let out = oracle.step(|| written(&mut h));
            server.write_all(&out).await.unwrap();
            let mut input = vec![0; 8192];
            let mut settled = false;
            loop {
                let n = server.read(&mut input).await.unwrap();
                if n == 0 {
                    break;
                }
                let out = oracle.step(|| {
                    h.push(&input[..n]).unwrap();
                    written(&mut h)
                });
                if !settled && signed_in.load(Ordering::Acquire) {
                    oracle.settled();
                    settled = true;
                }
                if settled {
                    oracle.check(h.unread());
                }
                server.write_all(&out).await.unwrap();
                if h.ended() {
                    break;
                }
            }
            assert!(settled, "the connection was established");
            oracle.step(|| drop(h));
            oracle.finish();
        });
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_side,
            SshClient,
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_password("guest", "secret")
                .await
                .unwrap()
                .success()
        );
        authenticated.store(true, Ordering::Release);
        let block = vec![b's'; 1024];
        let mut channels = Vec::new();
        for _ in 0..CHANNELS {
            let channel = client.channel_open_session().await.unwrap();
            channel.exec(true, b"echo".to_vec()).await.unwrap();
            channels.push(channel);
        }
        // Every channel stays open while each in turn sends its bytes and
        // reads them back.
        for channel in &mut channels {
            for _ in 0..PER_CHANNEL / block.len() {
                channel.data(&block[..]).await.unwrap();
            }
            channel.eof().await.unwrap();
            let mut received = 0;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => received += data.len(),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(received, PER_CHANNEL);
        }
        client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        drop(client);
        task.await.unwrap();
    })
    .await
    .unwrap();
}
