//! SOCKS4, SOCKS4a and SOCKS5 handshakes and UDP headers, as a world
//! playing a proxy or a client reads them.
#![no_main]

use fictionet::stdlib::socks::{
    AuthReply, AuthRequest, ClientDecoder, ClientMessage, Command, Error, Greeting, MAX_BUFFERED, MAX_DATAGRAM, Method,
    Reply, Request, Selection, ServerDecoder, ServerMessage, Socks4Command, Socks4Reply, Socks4Request, UdpHeader,
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
            let method =
                if g.methods.contains(&Method::UsernamePassword) { Method::UsernamePassword } else { Method::NoAuth };
            d.select(method);
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
    // The bytes as a UDP datagram.
    if let Ok((header, payload)) = UdpHeader::parse(data) {
        if data.len() <= MAX_DATAGRAM {
            assert_eq!(header.datagram(payload), data);
        }
    }
});
