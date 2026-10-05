//! SOCKS4, SOCKS4a and SOCKS5 handshakes and UDP headers, as a world
//! playing a proxy or a client reads them.
#![no_main]

use fictionet::stdlib::socks::{
    Address, AuthReply, AuthRequest, ClientDecoder, ClientMessage, Command, Error, Greeting, MAX_BUFFERED,
    MAX_DATAGRAM, MAX_METHODS, Method, Reply, Request, Selection, ServerDecoder, ServerMessage, Socks4Command,
    Socks4Destination, Socks4Reply, Socks4Request, UdpHeader,
};
use fictionet::stdlib::{
    codec::{Decode, Step, contract},
    socks::{ClientMessages, ServerMessages},
};
use libfuzzer_sys::fuzz_target;

/// Takes messages out of a proxy's decoder, choosing a method and judging
/// logins the same way every time. A broken stream gives its error once.
fn drain_server(d: &mut ServerDecoder, out: &mut Vec<Result<ClientMessage, Error>>) {
    if matches!(out.last(), Some(Err(_))) {
        return;
    }
    while let Some(m) = d.next_message() {
        let stop = m.is_err();
        if let Ok(ClientMessage::Greeting(g)) = &m {
            let method = if g.methods.contains(&Method::UsernamePassword) {
                Method::UsernamePassword
            } else if g.methods.contains(&Method::NoAuth) {
                Method::NoAuth
            } else {
                Method::NoAcceptable
            };
            assert!(d.select(method));
        }
        if let Ok(ClientMessage::Auth(a)) = &m {
            d.verified(a.username != b"bad");
        }
        out.push(m);
        if stop {
            break;
        }
    }
}

/// Takes messages out of a client's decoder.
fn drain_client(d: &mut ClientDecoder, out: &mut Vec<Result<ServerMessage, Error>>) {
    if matches!(out.last(), Some(Err(_))) {
        return;
    }
    while let Some(m) = d.next_message() {
        let stop = m.is_err();
        out.push(m);
        if stop {
            break;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(ClientMessages::new, data);
    contract::check_decode(|| ClientMessages::with_limit(16), data);
    for method in [Method::NoAuth, Method::UsernamePassword] {
        contract::check_decode(
            || {
                let mut d = ClientMessages::with_limit(16);
                assert!(matches!(
                    d.decode(&[5, 1, method.code()], false),
                    Ok(Step::Item(_, 3))
                ));
                assert!(d.select(method));
                d
            },
            data,
        );
    }
    contract::check_decode(|| ServerMessages::socks5(Command::Connect), data);
    contract::check_decode(|| ServerMessages::with_limit(Command::Bind, 16), data);
    contract::check_decode(|| ServerMessages::socks4(Socks4Command::Bind), data);
    contract::check_wire::<Greeting>(data);
    contract::check_wire::<Selection>(data);
    contract::check_wire::<AuthRequest>(data);
    contract::check_wire::<AuthReply>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Reply>(data);
    contract::check_wire::<Socks4Request>(data);
    contract::check_wire::<Socks4Reply>(data);
    contract::check_wire_value(&AuthRequest { username: data.iter().take(256).copied().collect(), password: vec![] });
    // Past this, the two ways of feeding drop different bytes.
    if data.len() > MAX_BUFFERED {
        return;
    }

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = ServerDecoder::new();
    whole.feed(data);
    let mut messages = Vec::new();
    drain_server(&mut whole, &mut messages);
    let mut bytewise = ServerDecoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        drain_server(&mut bytewise, &mut again);
    }
    assert_eq!(messages, again);
    assert_eq!(whole.stage(), bytewise.stage());
    assert_eq!(whole.take_data(), bytewise.take_data());

    for make in [
        || ClientDecoder::socks5(Command::Connect),
        || ClientDecoder::socks5(Command::Bind),
        || ClientDecoder::socks4(Socks4Command::Bind),
    ] {
        let mut whole = make();
        whole.feed(data);
        let mut replies = Vec::new();
        drain_client(&mut whole, &mut replies);
        let mut bytewise = make();
        let mut again = Vec::new();
        for b in data {
            bytewise.feed(std::slice::from_ref(b));
            drain_client(&mut bytewise, &mut again);
        }
        assert_eq!(replies, again);
        assert_eq!(whole.stage(), bytewise.stage());
        assert_eq!(whole.take_data(), bytewise.take_data());
    }

    // A message read can be written, and reads back the same.
    if let Ok(Some((m, n))) = Greeting::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, n))) = Selection::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, n))) = AuthRequest::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, n))) = AuthReply::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, n))) = Request::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, n))) = Reply::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    if let Ok(Some((m, _))) = Socks4Request::parse(data) {
        // The 4a marker address and the end are rewritten, so compare
        // what reads back.
        let bytes = m.to_bytes();
        assert_eq!(Socks4Request::parse(&bytes), Ok(Some((m, bytes.len()))));
    }
    if let Ok(Some((m, n))) = Socks4Reply::parse(data) {
        assert_eq!(m.to_bytes(), data[..n]);
    }
    // Values built from the bytes, including ones no reader returns
    // (oversized fields, zero bytes in SOCKS4 fields, `Other` holding a
    // named code): every writer's output reads back whole.
    let first = data.first().copied().unwrap_or(0);
    let half = data.len() / 2;
    let (left, right) = data.split_at(half);
    let methods: Vec<Method> = data.iter().map(|&c| Method::Other(c)).collect();
    let bytes = Greeting { methods }.to_bytes();
    assert_eq!(Greeting::parse(&bytes).map(|m| m.map(|(_, n)| n)), Ok(Some(bytes.len())));
    let bytes = AuthRequest { username: left.to_vec(), password: right.to_vec() }.to_bytes();
    assert_eq!(AuthRequest::parse(&bytes).map(|m| m.map(|(_, n)| n)), Ok(Some(bytes.len())));
    let bytes = Request { command: Command::Connect, address: Address::Domain(left.to_vec()), port: 1 }.to_bytes();
    assert_eq!(Request::parse(&bytes).map(|m| m.map(|(_, n)| n)), Ok(Some(bytes.len())));
    let ip = std::net::Ipv4Addr::new(0, 0, 0, first);
    for destination in [Socks4Destination::Ip(ip), Socks4Destination::Domain(right.to_vec())] {
        let req = Socks4Request { command: Socks4Command::Connect, port: 1, destination, user_id: left.to_vec() };
        let bytes = req.to_bytes();
        assert_eq!(Socks4Request::parse(&bytes).map(|m| m.map(|(_, n)| n)), Ok(Some(bytes.len())));
    }
    let header = UdpHeader { fragment: first, address: Address::Domain(right.to_vec()), port: 1 };
    let bytes = header.datagram(data);
    assert!(bytes.len() <= MAX_DATAGRAM);
    assert!(UdpHeader::parse(&bytes).is_ok());

    // A selection a client did not offer fails a decoder that knows the
    // offer, and a proxy's decoder acts on the code a selection writes.
    let offered: Vec<Method> = right.iter().map(|&c| Method::from_code(c)).collect();
    let chosen = Method::Other(first);
    let mut client = ClientDecoder::socks5_offering(Command::Connect, &offered);
    client.feed(&Selection { method: chosen }.to_bytes());
    // A greeting carries only the first MAX_METHODS, so only those count.
    let allowed = first == 0xff || right[..right.len().min(MAX_METHODS)].contains(&first);
    match client.next_message() {
        Some(Ok(ServerMessage::Selection(s))) => assert!(allowed && s.method.code() == first),
        Some(Err(Error::Method(c))) => assert!(!allowed && c == first),
        other => panic!("{other:?}"),
    }
    let mut server = ServerDecoder::new();
    server.feed(&Greeting { methods: offered }.to_bytes());
    assert!(matches!(server.next_message(), Some(Ok(ClientMessage::Greeting(_)))));
    assert_eq!(server.select(chosen), allowed);
    let mut named = ServerDecoder::new();
    named.feed(&Greeting { methods: right.iter().map(|&c| Method::from_code(c)).collect() }.to_bytes());
    named.next_message();
    named.select(Method::from_code(first));
    assert_eq!(server.stage(), named.stage());

    // The bytes as a UDP datagram.
    if let Ok((header, payload)) = UdpHeader::parse(data) {
        if data.len() <= MAX_DATAGRAM {
            assert_eq!(header.datagram(payload), data);
        }
    }
});
