//! Session modes and byte-preserving handoffs through the shared driver.

use core::{convert::Infallible, fmt::Debug};
use fictionet::stdlib::{
    codec::{self, Decode, Fail, Step, Stream, Wire, contract, test_support::chunks},
    proxy_protocol as proxy, rfb, socks,
};
use std::net::Ipv4Addr;

const PAYLOAD: &[u8] = b"\x00\xffpayload\r\nPROXY \x05\x01\x00RFB 003.008\n";
const LIMIT: usize = 4096;

struct Bytes;
impl Decode for Bytes {
    type Item = u8;
    type Error = Infallible;
    const NAME: &'static str = "handoff payload";
    fn capacity(&self) -> usize {
        1
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
        Ok(input.first().map_or(Step::Need, |&b| Step::Item(b, 1)))
    }
}

// Check read-ahead, unaccepted input, shrinking swap capacity, provenance,
// and EOF preservation. No input is pushed to a completed decoder.
fn handoff<D>(make: impl Fn() -> D, units: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let wire = [units, PAYLOAD].concat();
    contract::check_stack(&make, &wire);
    for pattern in [&[][..], &[1], &[3, 1, 7, 2, 64], &[units.len().saturating_sub(1), 64]] {
        let mut stream = Stream::with_buffer(make(), wire.len());
        let mut accepted = 0;
        let mut items = Vec::new();
        let mut at = 0u64;
        'input: for chunk in chunks(&wire, pattern) {
            let mut part = chunk;
            while !part.is_empty() {
                let n = stream.push(part);
                accepted += n;
                part = &part[n..];
                while let Some(result) = stream.with_next(|item, raw, range| {
                    assert_eq!(range.start, at);
                    assert_eq!(raw, &wire[range.start as usize..range.end as usize]);
                    at = range.end;
                    item
                }) {
                    items.push(result.unwrap());
                }
                if stream.is_done() {
                    break 'input;
                }
                assert!(n > 0);
            }
        }
        assert!(stream.is_done());
        assert!(stream.failed().is_none());
        assert_eq!(items, expected);
        assert_eq!(stream.offset(), units.len() as u64);
        let unread = stream.unread().to_vec();
        assert_eq!(unread, &PAYLOAD[..unread.len()]);
        assert_eq!([unread.as_slice(), &wire[accepted..]].concat(), PAYLOAD);

        // A one-byte decoder still receives the entire read-ahead suffix.
        let mut next = stream.swap(Bytes);
        let mut payload = Vec::new();
        while let Some(byte) = next.next() {
            payload.push(byte.unwrap());
        }
        assert_eq!(codec::pump(&mut next, &wire[accepted..], |b| payload.push(b)), Ok(wire.len() - accepted));
        codec::finish(&mut next, |b| payload.push(b)).unwrap();
        assert_eq!(payload, PAYLOAD);
        assert_eq!(next.offset(), wire.len() as u64);
    }

    let mut stream = Stream::with_buffer(make(), wire.len());
    assert_eq!(stream.push(&wire), wire.len());
    stream.end();
    while let Some(item) = stream.next() {
        item.unwrap();
    }
    assert!(stream.is_done());
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.unread(), PAYLOAD);
    assert_eq!(buffer.offset(), units.len() as u64);

    let mut stream = Stream::with_buffer(make(), wire.len());
    assert_eq!(stream.push(&wire), wire.len());
    stream.end();
    while let Some(item) = stream.next() {
        item.unwrap();
    }
    let mut next = stream.swap(Bytes);
    let mut payload = Vec::new();
    while let Some(byte) = next.next() {
        payload.push(byte.unwrap());
    }
    assert!(next.is_done(), "swap preserves EOF");
    assert_eq!(payload, PAYLOAD);
}

fn terminal<D>(make: impl Fn() -> D, bytes: &[u8], failure: Fail<D::Error>)
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, bytes);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(stream.next(), Some(Err(failure.clone())));
    assert!(stream.is_done());
    assert_eq!(stream.next(), None);
    assert_eq!(stream.failed(), Some(&failure));
    assert_eq!(stream.into_parts().0.unread(), bytes);
}

fn truncated<D>(make: impl Fn() -> D, bytes: &[u8])
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, bytes);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(stream.next(), None);
    stream.end();
    assert_eq!(stream.next(), Some(Err(Fail::Truncated { unread: bytes.len() })));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.into_parts().0.unread(), bytes);
}

#[test]
fn proxy_v1_v2_round_trip_and_handoff() {
    let mut headers = vec![
        proxy::Header::V1(proxy::V1::Tcp4 {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(198, 51, 100, 2),
            src_port: 4321,
            dst_port: 443,
        }),
        proxy::Header::V1(proxy::V1::Unknown(b" extra".to_vec())),
        proxy::Header::V2(proxy::V2 {
            command: proxy::Command::Proxy,
            addresses: proxy::Addresses::Unspec,
            tlvs: vec![proxy::Tlv::Authority(b"example.test".to_vec())],
        }),
        proxy::Header::V2(proxy::V2 {
            command: proxy::Command::Local,
            addresses: proxy::Addresses::Unspec,
            tlvs: vec![],
        }),
    ];
    let checksummed = proxy::Header::V2(proxy::V2 {
        command: proxy::Command::Proxy,
        addresses: proxy::Addresses::Unspec,
        tlvs: vec![proxy::Tlv::Crc32c(0)],
    })
    .to_bytes();
    headers.push(<proxy::Header as Wire>::parse(&checksummed).unwrap());
    for header in headers {
        let bytes = Wire::to_bytes(&header).unwrap();
        contract::check_wire::<proxy::Header>(&bytes);
        contract::check_wire_value(&header);
        handoff(proxy::Headers::new, &bytes, &[Ok(header)]);
    }
}

#[test]
fn proxy_header_limits_truncation_and_terminal_errors() {
    let mut over = proxy::V2_SIGNATURE.to_vec();
    over.extend_from_slice(&[0x21, 0, 0, 17]);
    terminal(|| proxy::Headers::with_limit(32), &over, Fail::Protocol(proxy::HeaderError::TooLong));
    let mut invalid = proxy::V2_SIGNATURE.to_vec();
    invalid.push(0x31);
    terminal(proxy::Headers::new, &invalid, Fail::Protocol(proxy::HeaderError::Protocol(proxy::Error::Version(3))));
    truncated(proxy::Headers::new, b"PROXY TCP4 192.");
    truncated(proxy::Headers::new, &over);
    let overline = [b"PROXY ".as_slice(), &[b'x'; proxy::V1_MAX_LEN - 6]].concat();
    terminal(proxy::Headers::new, &overline, Fail::Protocol(proxy::HeaderError::TooLong));
}

#[test]
fn proxy_not_proxy_retains_all_bytes_and_can_swap() {
    let bytes = b"GET / HTTP/1.1\r\n\x00\xff";
    terminal(proxy::Headers::new, bytes, Fail::Protocol(proxy::HeaderError::Protocol(proxy::Error::NotProxy)));
    for prefix in 1..=bytes.len() {
        let mut stream = Stream::new(proxy::Headers::new());
        assert_eq!(stream.push(&bytes[..prefix]), prefix);
        assert!(matches!(
            stream.next(),
            Some(Err(Fail::Protocol(proxy::HeaderError::Protocol(proxy::Error::NotProxy))))
        ));
        let mut stream = stream.swap(Bytes);
        let mut got = Vec::new();
        while let Some(v) = stream.next() {
            got.push(v.unwrap());
        }
        codec::pump(&mut stream, &bytes[prefix..], |b| got.push(b)).unwrap();
        assert_eq!(got, bytes);
    }
}

#[test]
fn proxy_bad_complete_body_is_an_item_before_end() {
    let mut bytes = proxy::V2_SIGNATURE.to_vec();
    bytes.extend_from_slice(&[0x21, 0, 0, 3, proxy::tlv_type::CRC32C, 0, 0]);
    handoff(proxy::Headers::new, &bytes, &[Err(proxy::Error::TlvLength(proxy::tlv_type::CRC32C))]);
    handoff(proxy::Headers::new, b"PROXY invalid\r\n", &[Err(proxy::Error::V1Syntax)]);
}

struct SocksHandshake(socks::ClientMessages);
impl Decode for SocksHandshake {
    type Item = Result<socks::ClientMessage, socks::Error>;
    type Error = socks::DecodeError;
    const NAME: &'static str = "SOCKS test session";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, b: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(b, eof)?;
        match &step {
            Step::Item(Ok(socks::ClientMessage::Greeting(g)), _) => {
                let method = if g.methods.contains(&socks::Method::UsernamePassword) {
                    socks::Method::UsernamePassword
                } else if g.methods.contains(&socks::Method::NoAuth) {
                    socks::Method::NoAuth
                } else {
                    socks::Method::NoAcceptable
                };
                assert!(self.0.select(method));
            }
            Step::Item(Ok(socks::ClientMessage::Auth(_)), _) => self.0.verified(true),
            _ => {}
        }
        Ok(step)
    }
}
fn socks5_request() -> socks::Request {
    socks::Request {
        command: socks::Command::Connect,
        address: socks::Address::Domain(b"example.test".to_vec()),
        port: 443,
    }
}

#[test]
fn socks5_greeting_auth_request_round_trip_and_handoff() {
    for auth in [false, true] {
        let greeting = socks::Greeting {
            methods: vec![if auth { socks::Method::UsernamePassword } else { socks::Method::NoAuth }],
        };
        let login = socks::AuthRequest { username: b"user".to_vec(), password: b"password".to_vec() };
        let request = socks5_request();
        let mut bytes = Wire::to_bytes(&greeting).unwrap();
        let mut expected = vec![Ok(socks::ClientMessage::Greeting(greeting))];
        if auth {
            Wire::write(&login, &mut bytes).unwrap();
            expected.push(Ok(socks::ClientMessage::Auth(login)));
        }
        Wire::write(&request, &mut bytes).unwrap();
        expected.push(Ok(socks::ClientMessage::Request(request)));
        handoff(|| SocksHandshake(socks::ClientMessages::new()), &bytes, &expected);
    }
}

#[test]
fn socks4_and_4a_round_trip_and_handoff() {
    for destination in [
        socks::Socks4Destination::Ip(Ipv4Addr::new(1, 2, 3, 4)),
        socks::Socks4Destination::Domain(b"example.test".to_vec()),
    ] {
        let request = socks::Socks4Request {
            command: socks::Socks4Command::Connect,
            destination,
            port: 80,
            user_id: b"user".to_vec(),
        };
        let bytes = Wire::to_bytes(&request).unwrap();
        contract::check_wire::<socks::Socks4Request>(&bytes);
        handoff(socks::ClientMessages::new, &bytes, &[Ok(socks::ClientMessage::Socks4(request))]);
    }
}

#[test]
fn socks_reply_bind_and_refusal_handoffs() {
    let selection = socks::Selection { method: socks::Method::NoAuth };
    let reply = socks::Reply {
        code: socks::ReplyCode::Succeeded,
        address: socks::Address::Ipv4(Ipv4Addr::LOCALHOST),
        port: 80,
    };
    let mut bytes = Wire::to_bytes(&selection).unwrap();
    Wire::write(&reply, &mut bytes).unwrap();
    Wire::write(&reply, &mut bytes).unwrap();
    handoff(
        || socks::ServerMessages::socks5(socks::Command::Bind),
        &bytes,
        &[
            Ok(socks::ServerMessage::Selection(selection)),
            Ok(socks::ServerMessage::Reply(reply.clone())),
            Ok(socks::ServerMessage::Reply(reply)),
        ],
    );
    let selection = socks::Selection { method: socks::Method::NoAcceptable };
    handoff(
        || socks::ServerMessages::socks5(socks::Command::Connect),
        &Wire::to_bytes(&selection).unwrap(),
        &[Ok(socks::ServerMessage::Selection(selection))],
    );
    let reply = socks::Socks4Reply { code: socks::Socks4Code::Granted, ip: Ipv4Addr::LOCALHOST, port: 80 };
    let mut bytes = Wire::to_bytes(&reply).unwrap();
    Wire::write(&reply, &mut bytes).unwrap();
    handoff(
        || socks::ServerMessages::socks4(socks::Socks4Command::Bind),
        &bytes,
        &[Ok(socks::ServerMessage::Socks4(reply)), Ok(socks::ServerMessage::Socks4(reply))],
    );
}

#[test]
fn socks_limits_truncation_and_framing_errors() {
    terminal(|| socks::ClientMessages::with_limit(8), &[5, 20], Fail::Protocol(socks::DecodeError::TooLong));
    terminal(socks::ClientMessages::new, &[3], Fail::Protocol(socks::DecodeError::Protocol(socks::Error::Version(3))));
    truncated(socks::ClientMessages::new, &[5, 2, 0]);
    truncated(socks::ClientMessages::new, &[4, 1, 0, 80, 1, 2, 3, 4, b'u']);
    let make = || {
        let mut d = socks::ClientMessages::with_limit(8);
        assert!(matches!(d.decode(&[5, 1, 0], false), Ok(Step::Item(_, 3))));
        assert!(d.select(socks::Method::NoAuth));
        d
    };
    terminal(make, &[5, 1, 0, 3, 30], Fail::Protocol(socks::DecodeError::TooLong));
    terminal(make, &[5, 1, 0, 99], Fail::Protocol(socks::DecodeError::Protocol(socks::Error::AddressType(99))));
    let make_auth = || {
        let mut d = socks::ClientMessages::with_limit(8);
        d.decode(&[5, 1, 2], false).unwrap();
        assert!(d.select(socks::Method::UsernamePassword));
        d
    };
    terminal(make_auth, &[1, 20], Fail::Protocol(socks::DecodeError::TooLong));
    truncated(make_auth, &[1, 1, b'u', 2, b'p']);
}

#[test]
fn socks_modes_and_complete_request_errors() {
    let mut stream = Stream::new(socks::ClientMessages::new());
    let mut bytes = vec![5, 1, 0];
    let mut request = Wire::to_bytes(&socks5_request()).unwrap();
    request[1] = 99;
    bytes.extend_from_slice(&request);
    bytes.extend_from_slice(PAYLOAD);
    assert_eq!(stream.push(&bytes), bytes.len());
    assert!(matches!(stream.next(), Some(Ok(Ok(socks::ClientMessage::Greeting(_))))));
    assert_eq!(stream.unread(), [&request[..], PAYLOAD].concat());
    assert!(!stream.decoder().select(socks::Method::UsernamePassword));
    assert!(stream.decoder().select(socks::Method::NoAuth));
    assert_eq!(stream.next(), Some(Ok(Err(socks::Error::Command(99)))));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.into_parts().0.unread(), PAYLOAD);
    contract::check_decode(socks::ClientMessages::new, &bytes); // Missing decision is terminal.
}

fn format() -> rfb::PixelFormat {
    rfb::PixelFormat::TRUE_COLOR_32
}
fn init() -> rfb::ServerInit {
    rfb::ServerInit { width: 8, height: 8, format: format(), name: b"desktop".to_vec() }
}
fn server_decoder(phase: rfb::Phase, limit: usize) -> rfb::ServerMessages {
    let mut d = rfb::ServerMessages::with_limit(limit);
    d.set_mode(phase, rfb::Dialect::V3_8, format()).unwrap();
    d
}
fn client_decoder(phase: rfb::Phase, limit: usize) -> rfb::ClientMessages {
    let mut d = rfb::ClientMessages::with_limit(limit);
    d.set_phase(phase).unwrap();
    d
}

struct RfbServerHandshake(rfb::ServerMessages);
impl Decode for RfbServerHandshake {
    type Item = Result<rfb::ServerMessage, rfb::Error>;
    type Error = rfb::Error;
    const NAME: &'static str = "RFB server transcript";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, b: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(b, eof)?;
        if let Step::Item(Ok(m), _) = &step {
            let phase = match m {
                rfb::ServerMessage::Version(_) => rfb::Phase::SecurityOffer,
                rfb::ServerMessage::SecurityTypes(_) => rfb::Phase::VncChallenge,
                rfb::ServerMessage::VncChallenge(_) => rfb::Phase::SecurityResult,
                rfb::ServerMessage::SecurityOk => rfb::Phase::ServerInit,
                rfb::ServerMessage::ServerInit(_) | rfb::ServerMessage::FramebufferUpdate(_) => rfb::Phase::Normal,
                _ => rfb::Phase::Closed,
            };
            self.0.set_mode(phase, rfb::Dialect::V3_8, format())?;
        }
        Ok(step)
    }
}
struct RfbClientHandshake(rfb::ClientMessages);
impl Decode for RfbClientHandshake {
    type Item = Result<rfb::ClientMessage, rfb::Error>;
    type Error = rfb::Error;
    const NAME: &'static str = "RFB client transcript";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, b: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(b, eof)?;
        if let Step::Item(Ok(m), _) = &step {
            self.0.set_phase(match m {
                rfb::ClientMessage::Version(_) => rfb::Phase::SecurityChoice,
                rfb::ClientMessage::SecurityType(_) => rfb::Phase::VncResponse,
                rfb::ClientMessage::VncResponse(_) => rfb::Phase::ClientInit,
                rfb::ClientMessage::ClientInit { .. } => rfb::Phase::Normal,
                _ => rfb::Phase::Closed,
            })?;
        }
        Ok(step)
    }
}

#[test]
fn rfb_whole_handshake_into_messages_and_handoff() {
    let update = rfb::ServerMessage::FramebufferUpdate(vec![
        rfb::Rectangle { x: 0, y: 0, width: 2, height: 2, contents: rfb::Contents::Raw(vec![7; 16]) },
        rfb::Rectangle { x: 2, y: 2, width: 1, height: 1, contents: rfb::Contents::CopyRect { src_x: 0, src_y: 0 } },
        rfb::Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: rfb::Contents::Cursor { pixels: vec![2; 4], mask: vec![128] },
        },
        rfb::Rectangle { x: 0, y: 0, width: 16, height: 16, contents: rfb::Contents::DesktopSize },
    ]);
    let messages = vec![
        rfb::ServerMessage::Version(rfb::Version::V3_8),
        rfb::ServerMessage::SecurityTypes(vec![1, 2]),
        rfb::ServerMessage::VncChallenge([7; 16]),
        rfb::ServerMessage::SecurityOk,
        rfb::ServerMessage::ServerInit(init()),
        update,
        rfb::ServerMessage::Bell,
    ];
    let mut bytes = Vec::new();
    for m in &messages {
        match m {
            rfb::ServerMessage::Version(v) => Wire::write(v, &mut bytes).unwrap(),
            rfb::ServerMessage::ServerInit(i) => Wire::write(i, &mut bytes).unwrap(),
            _ => m.write(rfb::Dialect::V3_8, &format(), &mut bytes).unwrap(),
        }
    }
    handoff(
        || RfbServerHandshake(rfb::ServerMessages::with_limit(LIMIT)),
        &bytes,
        &messages.into_iter().map(Ok).collect::<Vec<_>>(),
    );

    let messages = vec![
        rfb::ClientMessage::Version(rfb::Version::V3_8),
        rfb::ClientMessage::SecurityType(2),
        rfb::ClientMessage::VncResponse([9; 16]),
        rfb::ClientMessage::ClientInit { shared: true },
        rfb::ClientMessage::KeyEvent { down: true, key: 65 },
    ];
    let mut bytes = Vec::new();
    for m in &messages {
        if let rfb::ClientMessage::Version(v) = m {
            Wire::write(v, &mut bytes).unwrap();
        } else if m.is_handshake() {
            bytes.extend(m.to_bytes().unwrap());
        } else {
            Wire::write(m, &mut bytes).unwrap();
        }
    }
    handoff(
        || RfbClientHandshake(rfb::ClientMessages::with_limit(LIMIT)),
        &bytes,
        &messages.into_iter().map(Ok).collect::<Vec<_>>(),
    );
}

#[test]
fn rfb_limits_truncation_and_framing_errors() {
    let make = || server_decoder(rfb::Phase::ServerInit, 32);
    let bytes = Wire::to_bytes(&init()).unwrap();
    let mut over = bytes[..24].to_vec();
    over[20..24].copy_from_slice(&100u32.to_be_bytes());
    terminal(make, &over, Fail::Protocol(rfb::Error::TooLong));
    truncated(make, &bytes[..25]);
    truncated(rfb::ClientMessages::new, b"RFB 003.");
    truncated(|| server_decoder(rfb::Phase::SecurityResult, LIMIT), &[0, 0, 0]);
    terminal(rfb::ServerMessages::new, b"BAD", Fail::Protocol(rfb::Error::Version));
    terminal(|| server_decoder(rfb::Phase::Normal, LIMIT), &[99], Fail::Protocol(rfb::Error::MessageType(99)));
    terminal(
        || client_decoder(rfb::Phase::Normal, 32),
        &[6, 0, 0, 0, 0, 0, 0, 100],
        Fail::Protocol(rfb::Error::TooLong),
    );
    let rectangle = [0, 0, 0, 1, 0, 0, 0, 0, 0, 8, 0, 8, 0, 0, 0, 0];
    terminal(|| server_decoder(rfb::Phase::Normal, 32), &rectangle, Fail::Protocol(rfb::Error::TooLong));
    let mut unknown = rectangle;
    unknown[12..].copy_from_slice(&42i32.to_be_bytes());
    terminal(|| server_decoder(rfb::Phase::Normal, LIMIT), &unknown, Fail::Protocol(rfb::Error::Encoding(42)));
    truncated(|| server_decoder(rfb::Phase::Normal, LIMIT), &rectangle);
}

#[test]
fn rfb_body_errors_are_items_and_mode_changes_require_boundaries() {
    let mut stream = Stream::new(client_decoder(rfb::Phase::Normal, LIMIT));
    let bad_format = [0; 20];
    let good = rfb::ClientMessage::KeyEvent { down: false, key: 65 };
    let mut bytes = bad_format.to_vec();
    Wire::write(&good, &mut bytes).unwrap();
    assert_eq!(stream.push(&bytes[..2]), 2);
    assert_eq!(stream.next(), None);
    assert!(stream.decoder().set_phase(rfb::Phase::Closed).is_err());
    assert_eq!(stream.push(&bytes[2..]), bytes.len() - 2);
    assert_eq!(stream.next(), Some(Ok(Err(rfb::Error::PixelFormat))));
    assert_eq!(stream.next(), Some(Ok(Ok(good))));
    assert!(stream.decoder().set_phase(rfb::Phase::Closed).is_ok());
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    contract::check_decode(|| client_decoder(rfb::Phase::Normal, LIMIT), &bytes);
}

#[test]
fn strict_wire_writers_refuse_changes_transactionally() {
    contract::check_wire_value(&proxy::Header::V1(proxy::V1::Unknown(b"bad".to_vec())));
    contract::check_wire_value(&proxy::Header::V2(proxy::V2 {
        command: proxy::Command::Proxy,
        addresses: proxy::Addresses::Unspec,
        tlvs: vec![proxy::Tlv::Crc32c(0)],
    }));
    contract::check_wire_value(&socks::Greeting { methods: vec![socks::Method::Other(0)] });
    contract::check_wire_value(&socks::AuthRequest { username: vec![0; 256], password: vec![] });
    contract::check_wire_value(&socks::Socks4Request {
        command: socks::Socks4Command::Connect,
        destination: socks::Socks4Destination::Ip(Ipv4Addr::new(0, 0, 0, 1)),
        port: 80,
        user_id: b"a\0b".to_vec(),
    });
    contract::check_wire_value(&rfb::Version { major: 1000, minor: 8 });
    contract::check_wire_value(&rfb::ClientMessage::SecurityType(1));
    contract::check_wire_value(&format());
    contract::check_wire_value(&init());
    contract::check_wire::<rfb::Version>(&Wire::to_bytes(&rfb::Version::V3_8).unwrap());
    contract::check_wire::<rfb::ServerInit>(&Wire::to_bytes(&init()).unwrap());
    for bytes in [Wire::to_bytes(&rfb::Version::V3_8).unwrap(), Wire::to_bytes(&init()).unwrap()] {
        let mut trailing = bytes;
        trailing.push(0);
        if trailing.len() == rfb::VERSION_LEN + 1 {
            assert_eq!(<rfb::Version as Wire>::parse(&trailing), Err(rfb::ParseError::Trailing));
        } else {
            assert_eq!(<rfb::ServerInit as Wire>::parse(&trailing), Err(rfb::ParseError::Trailing));
        }
    }
    let mut out = vec![1, 2, 3];
    assert!(rfb::ServerMessage::SecurityTypes(vec![]).write(rfb::Dialect::V3_8, &format(), &mut out).is_err());
    assert_eq!(out, [1, 2, 3]);
}

#[test]
fn rfb_stream_sessions_negotiate_all_existing_dialects() {
    for version in [rfb::Version::V3_3, rfb::Version::V3_7, rfb::Version::V3_8] {
        for vnc in [false, true] {
            for chunk_size in [1, 7, 1024] {
                let mut server = rfb::Server::with_limit(LIMIT);
                let mut client = rfb::Client::with_limit(LIMIT);
                for _ in 0..16 {
                    assert_eq!(server.phase(), client.phase());
                    if server.phase() == rfb::Phase::Normal {
                        break;
                    }
                    if server.phase().server_turn() {
                        let message = match server.phase() {
                            rfb::Phase::ServerVersion => rfb::ServerMessage::Version(rfb::Version::V3_8),
                            rfb::Phase::SecurityOffer if server.dialect() == rfb::Dialect::V3_3 => {
                                rfb::ServerMessage::SecurityType(if vnc { 2 } else { 1 })
                            }
                            rfb::Phase::SecurityOffer => rfb::ServerMessage::SecurityTypes(vec![1, 2]),
                            rfb::Phase::VncChallenge => rfb::ServerMessage::VncChallenge([7; 16]),
                            rfb::Phase::SecurityResult => rfb::ServerMessage::SecurityOk,
                            rfb::Phase::ServerInit => rfb::ServerMessage::ServerInit(init()),
                            phase => panic!("unexpected server phase {phase:?}"),
                        };
                        let bytes = server.send(&message).unwrap();
                        let mut got = Vec::new();
                        for chunk in bytes.chunks(chunk_size) {
                            assert_eq!(client.push(chunk), chunk.len());
                            while let Some(item) = client.next_message() {
                                got.push(item.unwrap().unwrap());
                            }
                        }
                        assert_eq!(got, [message]);
                    } else {
                        let message = match client.phase() {
                            rfb::Phase::ClientVersion => rfb::ClientMessage::Version(version),
                            rfb::Phase::SecurityChoice => rfb::ClientMessage::SecurityType(if vnc { 2 } else { 1 }),
                            rfb::Phase::VncResponse => rfb::ClientMessage::VncResponse([9; 16]),
                            rfb::Phase::ClientInit => rfb::ClientMessage::ClientInit { shared: true },
                            phase => panic!("unexpected client phase {phase:?}"),
                        };
                        let bytes = client.send(&message).unwrap();
                        let mut got = Vec::new();
                        for chunk in bytes.chunks(chunk_size) {
                            assert_eq!(server.push(chunk), chunk.len());
                            while let Some(item) = server.next_message() {
                                got.push(item.unwrap().unwrap());
                            }
                        }
                        assert_eq!(got, [message]);
                    }
                }
                assert_eq!(server.phase(), rfb::Phase::Normal);
                assert_eq!(client.phase(), rfb::Phase::Normal);
                assert_eq!(server.dialect(), version.dialect());
                assert_eq!(client.dialect(), version.dialect());
                assert_eq!(client.pixel_format(), format());
                let req = rfb::ClientMessage::FramebufferUpdateRequest {
                    incremental: false,
                    x: 0,
                    y: 0,
                    width: 8,
                    height: 8,
                };
                let bytes = client.send(&req).unwrap();
                assert_eq!(server.push(&bytes), bytes.len());
                assert_eq!(server.next_message(), Some(Ok(Ok(req))));
                assert_eq!(client.send(&rfb::ClientMessage::SetPixelFormat(format())), Err(rfb::Error::Outstanding));
                let update = rfb::ServerMessage::FramebufferUpdate(vec![rfb::Rectangle {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                    contents: rfb::Contents::Raw(vec![0; 4]),
                }]);
                let bytes = server.send(&update).unwrap();
                assert_eq!(client.push(&bytes[..4]), 4);
                assert_eq!(client.next_message(), None);
                // A normal send must not reset a partially scanned update.
                client.send(&rfb::ClientMessage::PointerEvent { buttons: 0, x: 0, y: 0 }).unwrap();
                assert_eq!(client.push(&bytes[4..]), bytes.len() - 4);
                assert_eq!(client.next_message(), Some(Ok(Ok(update))));
                assert!(client.send(&rfb::ClientMessage::SetPixelFormat(format())).is_ok());
                client.end();
                assert_eq!(client.next_message(), None);
                assert!(client.is_done());
            }
        }
    }
}

#[test]
fn rfb_sessions_handoff_unsupported_security_and_refusal() {
    let mut server = rfb::Server::new();
    server.send(&rfb::ServerMessage::Version(rfb::Version::V3_8)).unwrap();
    let bytes = Wire::to_bytes(&rfb::Version::V3_8).unwrap();
    assert_eq!(server.push(&bytes), bytes.len());
    assert!(matches!(server.next_message(), Some(Ok(Ok(rfb::ClientMessage::Version(_))))));
    server.send(&rfb::ServerMessage::SecurityTypes(vec![42])).unwrap();
    let bytes = [&[42][..], PAYLOAD].concat();
    assert_eq!(server.push(&bytes), bytes.len());
    assert_eq!(server.next_message(), Some(Ok(Ok(rfb::ClientMessage::SecurityType(42)))));
    assert_eq!(server.phase(), rfb::Phase::Unsupported(42));
    assert_eq!(server.next_message(), None);
    assert!(server.is_done());
    assert_eq!(server.into_stream().into_parts().0.unread(), PAYLOAD);

    let mut client = rfb::Client::new();
    let bytes = Wire::to_bytes(&rfb::Version::V3_8).unwrap();
    assert_eq!(client.push(&bytes), bytes.len());
    assert!(matches!(client.next_message(), Some(Ok(Ok(rfb::ServerMessage::Version(_))))));
    client.send(&rfb::ClientMessage::Version(rfb::Version::V3_8)).unwrap();
    let refusal = rfb::ServerMessage::SecurityFailure(b"no access".to_vec());
    let mut bytes = refusal.to_bytes(rfb::Dialect::V3_8, &format()).unwrap();
    bytes.extend_from_slice(PAYLOAD);
    assert_eq!(client.push(&bytes), bytes.len());
    assert_eq!(client.next_message(), Some(Ok(Ok(refusal))));
    assert_eq!(client.next_message(), None);
    assert!(client.is_done());
    assert_eq!(client.into_stream().into_parts().0.unread(), PAYLOAD);
}

#[test]
fn contract_checks_small_arbitrary_inputs_and_wire_values() {
    let mut random = codec::test_support::Lcg::new(0x1234_5678);
    for len in 0..80 {
        let bytes: Vec<_> = (0..len).map(|_| random.next() as u8).collect();
        contract::check_decode(|| proxy::Headers::with_limit(32), &bytes);
        contract::check_decode(|| SocksHandshake(socks::ClientMessages::with_limit(16)), &bytes);
        contract::check_decode(|| socks::ServerMessages::socks5(socks::Command::Bind), &bytes);
        contract::check_decode(|| server_decoder(rfb::Phase::Normal, LIMIT), &bytes);
        contract::check_decode(|| client_decoder(rfb::Phase::Normal, LIMIT), &bytes);
        contract::check_wire::<proxy::Header>(&bytes);
        contract::check_wire::<socks::Greeting>(&bytes);
        contract::check_wire::<socks::AuthRequest>(&bytes);
        contract::check_wire::<socks::Request>(&bytes);
        contract::check_wire::<rfb::Version>(&bytes);
        contract::check_wire::<rfb::PixelFormat>(&bytes);
        contract::check_wire::<rfb::ServerInit>(&bytes);
        contract::check_wire::<rfb::ClientMessage>(&bytes);
    }
}
