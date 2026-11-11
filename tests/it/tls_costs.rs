//! The TLS layer's costed replays (verification/README.md, "Resource
//! properties"): each step of a session is run under the counting
//! allocator and held to two bounds stated before it runs, with
//! verification/resources/cost.rs. The bounds and their constants are in
//! verification/tls/README.md, "Resource properties".
//!
//! The charge. A step's bytes live at once, counted from the session's
//! start, stay within the room its budget had when the session started,
//! plus what the budget does not count by design ([`HEADERS`]). Every
//! buffer the layer and rustls hold is paid from that budget before it
//! grows, so this fails on storage nothing paid for, such as a hello
//! parsed before the room for it was charged. A session starts after the
//! connection is made, so rustls's own state for the connection (keys, the
//! handshake's state) is outside it, except in the hello sessions, whose
//! step is the hello itself.
//!
//! The input. The chunks a step delivers are made before it, as the
//! transport below makes them, and handed to the layer through its driver.

use std::io::Write;

use fictionet::stdlib::layer::{Admit, Budget, Chunk, Harness, StreamEvent};
use fictionet::stdlib::services::tls::HandshakeError;
use rustls::ClientConnection;

use super::*;
use crate::common::alloc::unmeasured;
use crate::common::cost::{Charged, Costs, Linear};

type Server = Harness<tls::TlsLayer>;

/// A record's header: its type, version and length.
const HEADER: usize = 5;
/// The most a record's body may be (RFC 5246 section 6.2.3): a record
/// arriving is given a buffer this large once its header says so.
const BODY: usize = (1 << 14) + 2048;
/// The most input the layer holds while a handshake message is joined
/// (`JOINED` in layer.rs, rustls's `MAX_HANDSHAKE_SIZE`).
const JOINED: usize = 0xffff;
/// What the budget does not count by design: the shared backing around
/// the bytes of a chunk (its vector, what pays for it, what it holds and
/// its pool, behind two reference counts), for the at most two chunks the
/// layer holds each way and the one being delivered, 128 bytes at most
/// each; and rustls's spans of the handshake message it joins, at most
/// four of a version, an optional size and a range, 48 bytes at most
/// each.
const HEADERS: usize = 5 * 128 + 4 * 48;

/// Records arriving in chunks cut anywhere. Records whole in a chunk are
/// decrypted where they lie and go up as slices of it, and a record that
/// arrives across chunks is gathered into one buffer of its size, paid for
/// first: at most one such buffer a chunk, whatever its length.
const CHUNKS: Linear = Linear {
    num: 0,
    den: 1,
    fixed: HEADER + BODY + HEADERS,
};

/// A handshake message joined from many records, one step for all of
/// them. The buffer the layer joins it in grows to at least twice what it
/// held, so all its growths together are at most twice the last, which is
/// at most twice what it held, every byte of which was delivered (4). The
/// record arriving is sized to its header before its body arrives, and a
/// growth may start from it (twice a record).
const JOINING: Linear = Linear {
    num: 4,
    den: 1,
    fixed: 2 * (HEADER + BODY) + HEADERS,
};

/// A hello read from records into the acceptor and taken, in halves of a
/// byte for each byte of it:
///
/// - rustls's read buffer, which doubles as it joins (8);
/// - parsing: an element takes at most a vector and its one byte (25
///   bytes) for two on the wire, and a vector that grows by doubling asks
///   for at most twice its last capacity, which is at most twice its
///   elements (100);
/// - the layer's [`Hello`](tls::Hello), which copies the server name and
///   each protocol, a vector and its bytes, at most 25 for two (25).
///
/// Fixed: a record's buffer before its body arrives and a growth from it,
/// what the budget does not count, each list's first four elements and
/// the boxed extensions ([`PARSE_FIXED`]), and the `Hello`'s own fields
/// ([`HELLO_FIXED`]).
const ACCEPTING: Linear = Linear {
    num: 8 + 100 + 25,
    den: 2,
    fixed: 2 * (HEADER + BODY) + HEADERS + PARSE_FIXED + HELLO_FIXED,
};

/// The fixed part of rustls's `parse_room`: sixteen lists of four key
/// shares (40 bytes at most each) and the hello's boxed extensions (2 KiB
/// at most).
const PARSE_FIXED: usize = 16 * 4 * 40 + (2 << 10);

/// The layer's `Hello` beside the bytes it copies, and the harness and
/// layer the hello step makes: their fields, and the vector of protocols'
/// first allocation, 4 KiB at most.
const HELLO_FIXED: usize = 4 << 10;

/// What the client has to send.
fn from(client: &mut ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    bytes
}

/// Gives the client what the server wrote.
fn to(client: &mut ClientConnection, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        assert!(client.read_tls(&mut rest).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
}

/// The plaintext the layer hands up, dropped: what it held up is the
/// application's.
fn take_up(server: &mut Server) -> usize {
    let mut up = 0;
    server.driver().send_above(|event| {
        if let StreamEvent::Data(chunk) = event {
            up += chunk.len();
        }
        Admit::Taken
    });
    up
}

/// Hands `chunk` to the layer, as the transport below does, taking the
/// plaintext it hands up so that it takes the rest. Returns the plaintext
/// bytes that came up.
fn deliver(server: &mut Server, mut chunk: Chunk) -> Result<usize, HandshakeError> {
    let mut up = 0;
    loop {
        let admit = server.driver().deliver(StreamEvent::Data(chunk))?;
        up += take_up(server);
        server.settle()?;
        up += take_up(server);
        match admit {
            Admit::Taken => return Ok(up),
            Admit::Partial(StreamEvent::Data(rest)) | Admit::Blocked(StreamEvent::Data(rest)) => {
                chunk = rest
            }
            other => panic!("the layer answered a chunk with {other:?}"),
        }
    }
}

/// Bytes the transport below delivers, made outside the count.
fn chunk(bytes: &[u8]) -> Chunk {
    unmeasured(|| Chunk::unpaid(bytes.to_vec()))
}

/// A server on `budget` and `client`, done with their handshake.
fn connected(
    config: Arc<ServerConfig>,
    mut client: ClientConnection,
    budget: &Budget,
) -> (Server, ClientConnection) {
    let mut server = Harness::with_budget(
        Seed::from_u64(31),
        tls::TlsLayer::new(config.clone()),
        budget.clone(),
    );
    server.push(&from(&mut client)).unwrap();
    drop(server.work());
    server.complete(Some(config)).unwrap();
    for _ in 0..32 {
        to(&mut client, &server.take_output());
        server.push(&from(&mut client)).unwrap();
        if !client.is_handshaking() && !server.layer().is_handshaking() {
            to(&mut client, &server.take_output());
            return (server, client);
        }
    }
    panic!("the handshake did not finish");
}

/// The room `budget` has: what a session's steps may hold at once.
fn room(budget: &Budget) -> usize {
    budget.limit() - budget.used()
}

/// A client of `version` that trusts `ca`.
fn client_of(
    fcx: &Cx,
    ca: &Ca,
    version: &'static rustls::SupportedProtocolVersion,
) -> ClientConnection {
    let mut config = ClientConfig::builder_with_details(
        Arc::new(tls::crypto_provider(Arc::new(fcx.clone()))),
        Arc::new(FixedTime(date(2030, 1, 1))),
    )
    .with_protocol_versions(&[version])
    .unwrap()
    .with_root_certificates(roots(ca))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("example.test").unwrap(),
    )
    .unwrap()
}

/// Application data of seeded sizes, up to three records each, in chunks
/// cut at seeded places, each chunk a step: within the budget's room, and
/// asking for no more than one record's buffer.
#[test]
fn records_in_seeded_chunks_cost_at_most_a_record() {
    block_on(lab(Seed::from_u64(31), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let mut all = Costs::new("records in seeded chunks");
        for (version, seed) in [(&rustls::version::TLS13, 1), (&rustls::version::TLS12, 2)] {
            let budget = Budget::new(256 << 10);
            let (mut server, mut client) =
                connected(config.clone(), client_of(&fcx, &ca, version), &budget);
            let charge = room(&budget) + HEADERS;
            let rng = fictionet::SeededEntropy::new(Seed::from_u64(seed));
            use fictionet::Entropy;
            let mut costs = Costs::new(format!("{version:?}"));
            let (mut sent, mut got) = (0, 0);
            for _ in 0..24 {
                let len = 1 + rng.random_below(3 << 14) as usize;
                client.writer().write_all(&vec![7; len])?;
                let wire = from(&mut client);
                sent += len;
                let mut at = 0;
                while at < wire.len() {
                    let end = (at + 1 + rng.random_below(2000) as usize).min(wire.len());
                    let bytes = chunk(&wire[at..end]);
                    got += costs.step(end - at, charge, CHUNKS, || {
                        Charged::new(deliver(&mut server, bytes).unwrap(), 0)
                    });
                    at = end;
                }
            }
            assert_eq!(got, sent, "{version:?}: the plaintext did not all come up");
            costs.print();
            all.absorb(&costs);
        }
        all.print();
        Ok(())
    }))
    .unwrap();
}

/// One record's step while a message is joined: it may move what is held
/// to a larger buffer, at most twice the most held, and size the record
/// arriving to its header.
const JOINING_STEP: Linear = Linear {
    num: 0,
    den: 1,
    fixed: 2 * JOINED + HEADER + BODY + HEADERS,
};

/// A server that took a TLS 1.2 client's hello and sent its flight, on
/// `budget`, and the records of a client_key_exchange that says it is
/// 60,000 bytes long, a byte a record, in plaintext records as the client's
/// flight is in TLS 1.2: as many as the layer joins without failing, so
/// that what it holds, the headers included, stays within the most it
/// joins.
fn joining(fcx: &Cx, budget: &Budget) -> (Server, Vec<Chunk>) {
    let ca = Ca::new(fcx, "Test CA").unwrap();
    let config = server_config(fcx, &ca, "example.test", &[b"http/1.1"]);
    let mut client = client_of(fcx, &ca, &rustls::version::TLS12);
    let mut server = Harness::with_budget(
        Seed::from_u64(32),
        tls::TlsLayer::new(config.clone()),
        budget.clone(),
    );
    server.push(&from(&mut client)).unwrap();
    drop(server.work());
    server.complete(Some(config)).unwrap();
    drop(server.take_output());
    let size: u32 = 60_000;
    let records = [16]
        .into_iter()
        .chain(size.to_be_bytes()[1..].iter().copied())
        .chain(std::iter::repeat(7))
        .take(JOINED / 6 - 1)
        .map(|byte| chunk(&[22, 3, 3, 0, 1, byte]))
        .collect();
    (server, records)
}

/// A handshake message sent a byte a record, each record in a chunk of
/// its own, joined by the layer up to the most a message may be joined
/// in: the security review's attack (security-review-tls-20261110,
/// finding 2). Two sessions. In one, each record is a step, held to the
/// budget's room. In the other, all the records are one step, moved to a
/// larger buffer a few times, not once a record: the bytes asked for stay
/// linear in the bytes delivered. (A step frees the chunks it is handed,
/// made before it, which lowers the live bytes it is charged with; one
/// step for all of them would hide what it holds behind them.)
#[test]
fn a_message_joined_from_one_byte_records_is_moved_a_few_times() {
    block_on(lab(Seed::from_u64(32), |fcx| async move {
        let budget = Budget::new(1 << 20);
        let (mut server, records) = joining(&fcx, &budget);
        let mut each = Costs::new("a message a byte a record, a step a record");
        let charge = room(&budget) + HEADERS;
        for record in records {
            each.step(6, charge, JOINING_STEP, || {
                Charged::new(deliver(&mut server, record).unwrap(), 0)
            });
        }
        assert!(server.layer().failure().is_none());
        each.print();

        let budget = Budget::new(1 << 20);
        let (mut server, records) = joining(&fcx, &budget);
        let mut whole = Costs::new("a message a byte a record, one step");
        let charge = room(&budget) + HEADERS;
        let input = 6 * records.len();
        whole.step(input, charge, JOINING, || {
            for record in records {
                deliver(&mut server, record).unwrap();
            }
            Charged::new((), 0)
        });
        assert!(server.layer().failure().is_none());
        assert!(server.layer().is_handshaking());
        whole.print();
        Ok(())
    }))
    .unwrap();
}

/// A TLS 1.3 ClientHello naming `example.test`, with `big`, an extension
/// (its type, then its body), after the ones every hello needs, in records
/// of at most 2^14 bytes.
fn hello(big: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    // server_name: example.test.
    let name = b"example.test";
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&u16::try_from(name.len() + 5).unwrap().to_be_bytes());
    ext.extend_from_slice(&u16::try_from(name.len() + 3).unwrap().to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(name);
    // supported_versions: TLS 1.3.
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    // supported_groups: x25519.
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    // signature_algorithms: ecdsa_secp256r1_sha256.
    ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]);
    ext.extend_from_slice(&big[..2]);
    ext.extend_from_slice(&u16::try_from(big.len() - 2).unwrap().to_be_bytes());
    ext.extend_from_slice(&big[2..]);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&ext);
    let mut message = vec![1u8];
    message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    let mut wire = Vec::new();
    for part in message.chunks(1 << 14) {
        wire.extend_from_slice(&[22, 3, 1]);
        wire.extend_from_slice(&u16::try_from(part.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(part);
    }
    wire
}

/// ALPN of 30,000 one-byte protocol names: the elements largest in memory
/// for their bytes on the wire, a 24-byte vector and its byte for two.
fn many_protocols() -> Vec<u8> {
    let list: Vec<u8> = (0..30_000u32).flat_map(|i| [1, i as u8]).collect();
    let mut ext = vec![0x00, 0x10];
    ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// A hello near 64 KiB that parses into many times its size, in one step
/// on a budget too small to parse it and on one large enough: on the
/// first it waits, parsed by nothing; on the second it is taken, and the
/// layer reads what the client asked for. Both within the budget's room.
#[test]
fn a_hello_is_parsed_only_with_room_for_what_parsing_holds() {
    block_on(lab(Seed::from_u64(33), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let wire = hello(&many_protocols());
        let mut all = Costs::new("a large hello");
        for (limit, parsed) in [(256 << 10, false), (4 << 20, true)] {
            let budget = Budget::new(limit);
            let mut costs = Costs::new(format!("a large hello, budget {limit}"));
            let charge = room(&budget) + HEADERS;
            let bytes = chunk(&wire);
            let server = costs.step(wire.len(), charge, ACCEPTING, || {
                let mut server = Harness::with_budget(
                    Seed::from_u64(33),
                    tls::TlsLayer::new(config.clone()),
                    budget.clone(),
                );
                deliver(&mut server, bytes).unwrap();
                Charged::new(server, 0)
            });
            assert_eq!(server.layer().hello().is_some(), parsed, "budget {limit}");
            assert!(server.layer().failure().is_none(), "budget {limit}");
            costs.print();
            all.absorb(&costs);
            unmeasured(|| drop(server));
        }
        all.print();
        Ok(())
    }))
    .unwrap();
}
