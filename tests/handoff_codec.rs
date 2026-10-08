//! Session modes and byte-preserving handoffs through the shared driver.

use core::{convert::Infallible, fmt::Debug};
use fictionet::stdlib::{
    codec::{self, Decode, Fail, Step, Stream, Wire},
    test_support::contract, test_support::chunks,
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
    let (items, failure) = contract::check_decode(&make, &wire);
    assert_eq!(items, expected);
    assert_eq!(failure, None);
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
    assert_eq!(
        contract::check_decode_with_alloc_limit(&make, bytes, make().capacity().saturating_mul(2)),
        (vec![], Some(failure))
    );
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(bytes), bytes.len());
    stream.next().unwrap().unwrap_err();
    assert_eq!(stream.into_parts().0.unread(), bytes);
}

fn truncated<D>(make: impl Fn() -> D, bytes: &[u8])
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    assert_eq!(
        contract::check_decode_with_alloc_limit(&make, bytes, make().capacity().saturating_mul(2)),
        (vec![], Some(Fail::Truncated { unread: bytes.len() }))
    );
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(stream.next(), None);
    stream.end();
    stream.next().unwrap().unwrap_err();
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
    headers.push(proxy::Header::V2(proxy::V2 {
        command: proxy::Command::Proxy,
        addresses: proxy::Addresses::Unspec,
        tlvs: vec![],
    }.with_checksum().unwrap()));
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
    terminal(|| proxy::Headers::with_limit(32), &over, Fail::Protocol(proxy::FrameError::TooLong));
    let mut invalid = proxy::V2_SIGNATURE.to_vec();
    invalid.push(0x31);
    terminal(proxy::Headers::new, &invalid, Fail::Protocol(proxy::FrameError::Protocol(proxy::Error::Version(3))));
    truncated(proxy::Headers::new, b"PROXY TCP4 192.");
    truncated(proxy::Headers::new, &over);
    let overline = [b"PROXY ".as_slice(), &[b'x'; proxy::V1_MAX_LEN - 6]].concat();
    terminal(
        proxy::Headers::new,
        &overline,
        Fail::Protocol(proxy::FrameError::Protocol(proxy::Error::V1TooLong)),
    );
}

#[test]
fn proxy_not_proxy_retains_all_bytes_and_can_swap() {
    let bytes = b"GET / HTTP/1.1\r\n\x00\xff";
    terminal(proxy::Headers::new, bytes, Fail::Protocol(proxy::FrameError::Protocol(proxy::Error::NotProxy)));
    for prefix in 1..=bytes.len() {
        let mut stream = Stream::new(proxy::Headers::new());
        assert_eq!(stream.push(&bytes[..prefix]), prefix);
        assert!(matches!(
            stream.next(),
            Some(Err(Fail::Protocol(proxy::FrameError::Protocol(proxy::Error::NotProxy))))
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
    type Error = socks::FrameError;
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
    terminal(|| socks::ClientMessages::with_limit(8), &[5, 20], Fail::Protocol(socks::FrameError::TooLong));
    terminal(socks::ClientMessages::new, &[3], Fail::Protocol(socks::FrameError::Version(3)));
    truncated(socks::ClientMessages::new, &[5, 2, 0]);
    truncated(socks::ClientMessages::new, &[4, 1, 0, 80, 1, 2, 3, 4, b'u']);
    let make = || {
        let mut d = socks::ClientMessages::with_limit(8);
        assert!(matches!(d.decode(&[5, 1, 0], false), Ok(Step::Item(_, 3))));
        assert!(d.select(socks::Method::NoAuth));
        d
    };
    terminal(make, &[5, 1, 0, 3, 30], Fail::Protocol(socks::FrameError::TooLong));
    terminal(make, &[5, 1, 0, 99], Fail::Protocol(socks::FrameError::AddressType(99)));
    let make_auth = || {
        let mut d = socks::ClientMessages::with_limit(8);
        d.decode(&[5, 1, 2], false).unwrap();
        assert!(d.select(socks::Method::UsernamePassword));
        d
    };
    terminal(make_auth, &[1, 20], Fail::Protocol(socks::FrameError::TooLong));
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
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Failed);
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.into_parts().0.unread(), PAYLOAD);
    contract::check_decode_with_alloc_limit(socks::ClientMessages::new, &bytes, 2 * socks::MAX_MESSAGE); // Pending decisions preserve bytes below capacity.
}

#[test]
fn socks_client_item_error_is_failed() {
    let mut stream = Stream::new(socks::ClientMessages::new());
    assert_eq!(stream.push(&[5, 1, 0]), 3);
    assert!(matches!(
        stream.next(),
        Some(Ok(Ok(socks::ClientMessage::Greeting(_))))
    ));
    assert!(stream.decoder().select(socks::Method::NoAuth));
    let bytes = [5, 9, 0, 1, 1, 2, 3, 4, 0, 80, b'x'];
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(Err(socks::Error::Command(9)))));
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Failed);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), b"x");
}

#[test]
fn socks_client_terminal_error_is_failed() {
    let mut stream = Stream::new(socks::ClientMessages::new());
    let bytes = [7, 1, 0];
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(socks::FrameError::Version(7))))
    );
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Failed);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), bytes);
}

#[test]
fn socks_server_item_error_is_failed() {
    let mut stream = Stream::new(socks::ServerMessages::socks5(socks::Command::Connect));
    assert_eq!(stream.push(&[5, 0]), 2);
    assert!(matches!(
        stream.next(),
        Some(Ok(Ok(socks::ServerMessage::Selection(_))))
    ));
    let bytes = [5, 0, 9, 1, 1, 2, 3, 4, 0, 80, b'x'];
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(Err(socks::Error::Reserved(9)))));
    assert_eq!(stream.decoder().phase(), socks::ClientPhase::Failed);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), b"x");
}

#[test]
fn socks_server_terminal_error_is_failed() {
    let mut stream = Stream::new(socks::ServerMessages::socks5(socks::Command::Connect));
    let bytes = [7, 1, 0];
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(socks::FrameError::Version(7))))
    );
    assert_eq!(stream.decoder().phase(), socks::ClientPhase::Failed);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), bytes);
}

#[test]
fn socks_pumps_pause_for_world_decisions() {
    let mut stream = Stream::new(socks::ClientMessages::new());
    let mut items = Vec::new();
    assert_eq!(
        codec::pump(&mut stream, &[5, 1, 2], |m| items.push(m)),
        Ok(3)
    );
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Selecting);
    assert!(!stream.is_done());
    assert!(stream.decoder().select(socks::Method::UsernamePassword));
    assert_eq!(
        codec::try_pump(&mut stream, &[1, 1, b'u', 1, b'p'], |m| {
            items.push(m);
            Ok::<_, Infallible>(())
        }),
        Ok(5)
    );
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Verifying);
    assert!(!stream.is_done());
    assert_eq!(items.len(), 2);
    stream.decoder().verified(true);
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Request);
    let request = socks5_request();
    let bytes = Wire::to_bytes(&request).unwrap();
    assert_eq!(
        codec::pump(&mut stream, &bytes, |m| items.push(m)),
        Ok(bytes.len())
    );
    assert_eq!(
        items.last(),
        Some(&Ok(socks::ClientMessage::Request(request)))
    );
    assert_eq!(stream.decoder().phase(), socks::ServerPhase::Done);
}

#[test]
fn socks_decisions_fail_only_at_capacity_without_consuming() {
    for phase in [socks::ServerPhase::Selecting, socks::ServerPhase::Verifying] {
        let mut stream = Stream::new(socks::ClientMessages::with_limit(8));
        assert_eq!(stream.push(&[5, 1, 2]), 3);
        stream.next().unwrap().unwrap().unwrap();
        if phase == socks::ServerPhase::Verifying {
            assert!(stream.decoder().select(socks::Method::UsernamePassword));
            assert_eq!(stream.push(&[1, 1, b'u', 1, b'p']), 5);
            stream.next().unwrap().unwrap().unwrap();
        }
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().phase(), phase);
        assert_eq!(stream.push(&[0; 9]), 9);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().phase(), phase);
        assert_eq!(stream.unread(), [0; 9]);
        assert_eq!(stream.push(&[0]), 1);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(socks::FrameError::DecisionRequired(phase))))
        );
        assert_eq!(stream.decoder().phase(), socks::ServerPhase::Failed);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.into_parts().0.unread(), [0; 10]);
    }
}

#[test]
fn socks4_limit_is_independent_of_chunking_with_a_larger_buffer() {
    let mut bytes = vec![4, 1, 0, 80, 1, 2, 3, 4];
    bytes.extend_from_slice(&[b'a'; 300]);
    for chunk_size in [bytes.len(), 1, 7, 16] {
        let mut stream = Stream::with_buffer(socks::ClientMessages::with_limit(16), 4096);
        let mut result = None;
        for chunk in chunks(&bytes, &[chunk_size]) {
            assert_eq!(stream.push(chunk), chunk.len());
            result = stream.next();
            if result.is_some() {
                break;
            }
        }
        assert_eq!(
            result,
            Some(Err(Fail::Protocol(socks::FrameError::TooLong)))
        );
        assert_eq!(stream.decoder().phase(), socks::ServerPhase::Failed);
        assert_eq!(stream.offset(), 0);
        assert_eq!(stream.unread(), &bytes[..stream.buffered()]);
    }
}

#[test]
fn socks_reply_limit_and_unoffered_method_leave_failed() {
    let mut stream = Stream::new(socks::ServerMessages::with_limit(socks::Command::Bind, 8));
    assert_eq!(stream.decoder().limit(), 10);
    assert_eq!(stream.push(&[5, 0]), 2);
    stream.next().unwrap().unwrap().unwrap();
    assert_eq!(stream.push(&[5, 0, 0, 3, 30]), 5);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(socks::FrameError::TooLong)))
    );
    assert_eq!(stream.decoder().phase(), socks::ClientPhase::Failed);

    let mut stream = Stream::new(socks::ServerMessages::socks5_offering(
        socks::Command::Connect,
        &[socks::Method::NoAuth],
    ));
    assert_eq!(stream.push(&[5, 2]), 2);
    assert_eq!(stream.next(), Some(Ok(Err(socks::Error::Method(2)))));
    assert_eq!(stream.decoder().phase(), socks::ClientPhase::Failed);
}

#[test]
fn socks_minimum_limits_accept_requests_and_replies() {
    for limit in [0, 8, 10] {
        let mut client = Stream::new(socks::ClientMessages::with_limit(limit));
        assert_eq!(client.decoder().capacity(), 10);
        assert_eq!(client.push(&[5, 1, 0]), 3);
        client.next().unwrap().unwrap().unwrap();
        assert!(client.decoder().select(socks::Method::NoAuth));
        assert_eq!(client.push(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]), 10);
        assert!(matches!(
            client.next(),
            Some(Ok(Ok(socks::ClientMessage::Request(_))))
        ));

        let mut server = Stream::new(socks::ServerMessages::with_limit(
            socks::Command::Connect,
            limit,
        ));
        assert_eq!(server.decoder().capacity(), 10);
        assert_eq!(server.push(&[5, 0]), 2);
        server.next().unwrap().unwrap().unwrap();
        assert_eq!(server.push(&[5, 0, 0, 1, 1, 2, 3, 4, 0, 80]), 10);
        assert!(matches!(
            server.next(),
            Some(Ok(Ok(socks::ServerMessage::Reply(_))))
        ));

        let mut client = Stream::new(socks::ClientMessages::with_limit(limit));
        assert_eq!(client.push(&[4, 1, 0, 80, 1, 2, 3, 4, 0]), 9);
        assert!(matches!(
            client.next(),
            Some(Ok(Ok(socks::ClientMessage::Socks4(_))))
        ));

        let mut server = Stream::new(socks::ServerMessages::socks4_with_limit(
            socks::Socks4Command::Bind,
            limit,
        ));
        assert_eq!(server.decoder().capacity(), limit.max(8));
        for _ in 0..2 {
            assert_eq!(server.push(&[0, 90, 0, 80, 1, 2, 3, 4]), 8);
            assert!(matches!(
                server.next(),
                Some(Ok(Ok(socks::ServerMessage::Socks4(_))))
            ));
        }
        assert_eq!(server.next(), None);
        assert!(server.is_done());
    }
}

fn format() -> rfb::PixelFormat {
    rfb::PixelFormat::TRUE_COLOR_32
}
fn init() -> rfb::ServerInit {
    rfb::ServerInit { width: 8, height: 8, format: format(), name: b"desktop".to_vec() }
}
fn server_decoder(phase: rfb::Phase, limit: usize) -> rfb::ServerMessages {
    let mut d = rfb::ServerMessages::with_limit(limit);
    d.set_phase(phase, rfb::Dialect::V3_8, format()).unwrap();
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
    type Error = rfb::FrameError;
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
            self.0
                .set_phase(phase, rfb::Dialect::V3_8, format())
                .unwrap();
        }
        Ok(step)
    }
}
struct RfbClientHandshake(rfb::ClientMessages);
impl Decode for RfbClientHandshake {
    type Item = Result<rfb::ClientMessage, rfb::Error>;
    type Error = rfb::FrameError;
    const NAME: &'static str = "RFB client transcript";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, b: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(b, eof)?;
        if let Step::Item(Ok(m), _) = &step {
            self.0
                .set_phase(match m {
                    rfb::ClientMessage::Version(_) => rfb::Phase::SecurityChoice,
                    rfb::ClientMessage::SecurityType(_) => rfb::Phase::VncResponse,
                    rfb::ClientMessage::VncResponse(_) => rfb::Phase::ClientInit,
                    rfb::ClientMessage::ClientInit { .. } => rfb::Phase::Normal,
                    _ => rfb::Phase::Closed,
                })
                .unwrap();
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
        match m {
            rfb::ClientMessage::Version(v) => v.write(&mut bytes).unwrap(),
            rfb::ClientMessage::SecurityType(t) => rfb::SecurityChoice(*t).write(&mut bytes).unwrap(),
            rfb::ClientMessage::VncResponse(r) => rfb::VncResponse(*r).write(&mut bytes).unwrap(),
            rfb::ClientMessage::ClientInit { shared } => rfb::ClientInit { shared: *shared }.write(&mut bytes).unwrap(),
            _ => m.write(&mut bytes).unwrap(),
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
    terminal(make, &over, Fail::Protocol(rfb::FrameError::TooLong));
    truncated(make, &bytes[..25]);
    truncated(rfb::ClientMessages::new, b"RFB 003.");
    truncated(|| server_decoder(rfb::Phase::SecurityResult, LIMIT), &[0, 0, 0]);
    terminal(rfb::ServerMessages::new, b"BAD", Fail::Protocol(rfb::FrameError::Version));
    terminal(|| server_decoder(rfb::Phase::Normal, LIMIT), &[99], Fail::Protocol(rfb::FrameError::MessageType(99)));
    terminal(
        || client_decoder(rfb::Phase::Normal, 32),
        &[6, 0, 0, 0, 0, 0, 0, 100],
        Fail::Protocol(rfb::FrameError::TooLong),
    );
    let rectangle = [0, 0, 0, 1, 0, 0, 0, 0, 0, 8, 0, 8, 0, 0, 0, 0];
    terminal(|| server_decoder(rfb::Phase::Normal, 32), &rectangle, Fail::Protocol(rfb::FrameError::TooLong));
    let mut unknown = rectangle;
    unknown[12..].copy_from_slice(&42i32.to_be_bytes());
    terminal(|| server_decoder(rfb::Phase::Normal, LIMIT), &unknown, Fail::Protocol(rfb::FrameError::Encoding(42)));
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
    assert_eq!(
        stream.decoder().set_phase(rfb::Phase::Closed),
        Err(rfb::Error::PartialUnit)
    );
    assert_eq!(stream.push(&bytes[2..]), bytes.len() - 2);
    assert_eq!(
        stream.next(),
        Some(Ok(Err(rfb::Error::PixelFormat)))
    );
    assert_eq!(stream.next(), Some(Ok(Ok(good))));
    assert!(stream.decoder().set_phase(rfb::Phase::Closed).is_ok());
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    contract::check_decode_with_alloc_limit(|| client_decoder(rfb::Phase::Normal, LIMIT), &bytes, 2 * LIMIT);
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
            assert_eq!(<rfb::Version as Wire>::parse(&trailing), Err(rfb::Error::Trailing));
        } else {
            assert_eq!(<rfb::ServerInit as Wire>::parse(&trailing), Err(rfb::Error::Trailing));
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
                        for chunk in chunks(&bytes, &[chunk_size]) {
                            assert_eq!(client.push(chunk), chunk.len());
                            while let Some(item) = client.next() {
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
                        for chunk in chunks(&bytes, &[chunk_size]) {
                            assert_eq!(server.push(chunk), chunk.len());
                            while let Some(item) = server.next() {
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
                // Normal-phase refusals leave both sessions able to read the next unit.
                let good = rfb::ClientMessage::KeyEvent {
                    down: false,
                    key: 65,
                };
                let mut bytes = vec![0; 20];
                Wire::write(&good, &mut bytes).unwrap();
                assert_eq!(server.push(&bytes), bytes.len());
                assert_eq!(
                    server.next(),
                    Some(Ok(Err(rfb::Error::PixelFormat)))
                );
                assert_eq!(server.phase(), rfb::Phase::Normal);
                assert_eq!(server.next(), Some(Ok(Ok(good))));
                let bad = rfb::ServerMessage::FramebufferUpdate(vec![rfb::Rectangle {
                    x: 8,
                    y: 0,
                    width: 1,
                    height: 1,
                    contents: rfb::Contents::Raw(vec![0; 4]),
                }]);
                let mut bytes = server_bytes(&bad, server.dialect(), &format()).unwrap();
                rfb::ServerMessage::Bell
                    .write(server.dialect(), &format(), &mut bytes)
                    .unwrap();
                assert_eq!(client.push(&bytes), bytes.len());
                assert_eq!(
                    client.next(),
                    Some(Ok(Err(rfb::Error::Rectangle)))
                );
                assert_eq!(client.phase(), rfb::Phase::Normal);
                assert_eq!(
                    client.next(),
                    Some(Ok(Ok(rfb::ServerMessage::Bell)))
                );
                let req = rfb::ClientMessage::FramebufferUpdateRequest {
                    incremental: false,
                    x: 0,
                    y: 0,
                    width: 8,
                    height: 8,
                };
                let bytes = client.send(&req).unwrap();
                assert_eq!(server.push(&bytes), bytes.len());
                assert_eq!(server.next(), Some(Ok(Ok(req))));
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
                assert_eq!(client.next(), None);
                // A normal send must not reset a partially scanned update.
                client.send(&rfb::ClientMessage::PointerEvent { buttons: 0, x: 0, y: 0 }).unwrap();
                assert_eq!(client.push(&bytes[4..]), bytes.len() - 4);
                assert_eq!(client.next(), Some(Ok(Ok(update))));
                assert!(client.send(&rfb::ClientMessage::SetPixelFormat(format())).is_ok());
                client.end();
                assert_eq!(client.next(), None);
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
    assert!(matches!(server.next(), Some(Ok(Ok(rfb::ClientMessage::Version(_))))));
    server.send(&rfb::ServerMessage::SecurityTypes(vec![42])).unwrap();
    let bytes = [&[42][..], PAYLOAD].concat();
    assert_eq!(server.push(&bytes), bytes.len());
    assert_eq!(server.next(), Some(Ok(Ok(rfb::ClientMessage::SecurityType(42)))));
    assert_eq!(server.phase(), rfb::Phase::Unsupported(42));
    assert_eq!(server.next(), None);
    assert!(server.is_done());
    assert_eq!(server.into_stream().into_parts().0.unread(), PAYLOAD);

    let mut client = rfb::Client::new();
    let bytes = Wire::to_bytes(&rfb::Version::V3_8).unwrap();
    assert_eq!(client.push(&bytes), bytes.len());
    assert!(matches!(client.next(), Some(Ok(Ok(rfb::ServerMessage::Version(_))))));
    client.send(&rfb::ClientMessage::Version(rfb::Version::V3_8)).unwrap();
    let refusal = rfb::ServerMessage::SecurityFailure(b"no access".to_vec());
    let mut bytes = server_bytes(&refusal, rfb::Dialect::V3_8, &format()).unwrap();
    bytes.extend_from_slice(PAYLOAD);
    assert_eq!(client.push(&bytes), bytes.len());
    assert_eq!(client.next(), Some(Ok(Ok(refusal))));
    assert_eq!(client.next(), None);
    assert!(client.is_done());
    assert_eq!(client.into_stream().into_parts().0.unread(), PAYLOAD);
}

#[test]
fn rfb_unoffered_security_closes_without_reading_another_choice() {
    for choice in [0, 2] {
        let mut server = rfb::Server::new();
        server
            .send(&rfb::ServerMessage::Version(rfb::Version::V3_8))
            .unwrap();
        assert_eq!(server.push(b"RFB 003.008\n"), rfb::VERSION_LEN);
        server.next().unwrap().unwrap().unwrap();
        server
            .send(&rfb::ServerMessage::SecurityTypes(vec![1]))
            .unwrap();
        assert_eq!(server.push(&[choice, 1]), 2);
        assert_eq!(
            server.next(),
            Some(Ok(Err(rfb::Error::NotOffered(choice))))
        );
        assert_eq!(server.phase(), rfb::Phase::Closed);
        assert_eq!(server.next(), None);
        assert!(server.is_done());
        assert_eq!(server.into_stream().into_parts().0.unread(), [1]);
    }
}

#[test]
fn rfb_pending_input_is_bounded_and_error_survives_handoff() {
    let bytes = vec![0; rfb::MAX_PENDING + 1];
    for chunk_size in [1, 1024, bytes.len()] {
        let mut server = rfb::Server::new();
        let mut accepted = 0;
        for chunk in chunks(&bytes, &[chunk_size]) {
            accepted += server.push(chunk);
            assert!(server.buffered() <= rfb::MAX_PENDING);
        }
        assert_eq!(accepted, rfb::MAX_PENDING);
        assert_eq!(server.phase(), rfb::Phase::Closed);
        assert_eq!(server.push(&[1]), 0);
        assert_eq!(
            server.next(),
            Some(Err(Fail::Protocol(rfb::FrameError::OutOfTurn)))
        );
        assert_eq!(server.next(), None);
        assert!(server.is_done());
        let stream = server.into_stream();
        assert_eq!(
            stream.failed(),
            Some(&Fail::Protocol(rfb::FrameError::OutOfTurn))
        );
        assert_eq!(stream.unread(), &bytes[..accepted]);
    }

    let mut client = rfb::Client::new();
    assert_eq!(client.push(b"RFB 003.008\n"), rfb::VERSION_LEN);
    client.next().unwrap().unwrap().unwrap();
    assert_eq!(client.phase(), rfb::Phase::ClientVersion);
    assert_eq!(client.push(&bytes), rfb::MAX_PENDING);
    assert_eq!(client.phase(), rfb::Phase::Closed);
    // Extracting the stream before draining must preserve the pending failure.
    let mut stream = client.into_stream();
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(rfb::FrameError::OutOfTurn)))
    );
    assert_eq!(stream.next(), None);
    assert_eq!(stream.unread(), &bytes[..rfb::MAX_PENDING]);

    // The boundary itself is allowed while the server has yet to speak.
    let mut server = rfb::Server::new();
    assert_eq!(server.push(&bytes[..rfb::MAX_PENDING]), rfb::MAX_PENDING);
    assert_eq!(server.next(), None);
    assert_eq!(server.phase(), rfb::Phase::ServerVersion);
    assert!(!server.is_done());
}

#[test]
fn rfb_client_capacity_fits_the_largest_client_unit() {
    assert_eq!(rfb::ClientMessages::new().capacity(), 8 + rfb::MAX_TEXT);
    let message = rfb::ClientMessage::ClientCutText(vec![7; rfb::MAX_TEXT]);
    let bytes = Wire::to_bytes(&message).unwrap();
    let mut stream = Stream::new(client_decoder(rfb::Phase::Normal, rfb::MAX_CLIENT_MESSAGE));
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(Ok(message))));
    assert!(stream.unread().is_empty());
}

#[test]
fn rfb_mode_errors_name_the_refused_phase_or_partial_unit() {
    let mut client = rfb::ClientMessages::new();
    assert_eq!(
        client.set_phase(rfb::Phase::ServerInit),
        Err(rfb::Error::Phase(rfb::Phase::ServerInit))
    );
    assert_eq!(client.phase(), rfb::Phase::ClientVersion);
    assert_eq!(client.decode(b"RFB 003.", false), Ok(Step::Need));
    assert_eq!(
        client.set_phase(rfb::Phase::Closed),
        Err(rfb::Error::PartialUnit)
    );
    assert!(matches!(
        client.decode(b"RFB 003.008\n", false),
        Ok(Step::Item(Ok(_), 12))
    ));
    assert_eq!(client.set_phase(rfb::Phase::Closed), Ok(()));

    let mut server = rfb::ServerMessages::new();
    assert_eq!(
        server.set_phase(rfb::Phase::ClientInit, rfb::Dialect::V3_8, format()),
        Err(rfb::Error::Phase(rfb::Phase::ClientInit))
    );
    assert_eq!(server.phase(), rfb::Phase::ServerVersion);
    assert_eq!(server.decode(b"RFB 003.", false), Ok(Step::Need));
    assert_eq!(
        server.set_phase(rfb::Phase::Closed, rfb::Dialect::V3_8, format()),
        Err(rfb::Error::PartialUnit)
    );
    assert!(matches!(
        server.decode(b"RFB 003.008\n", false),
        Ok(Step::Item(Ok(_), 12))
    ));
    assert_eq!(
        server.set_phase(rfb::Phase::Closed, rfb::Dialect::V3_8, format()),
        Ok(())
    );
}

#[test]
fn rfb_frame_scan_accepts_raw_and_cursor_at_each_pixel_width() {
    for bits in [8, 16, 32] {
        let format = rfb::PixelFormat {
            bits_per_pixel: bits,
            depth: bits,
            true_color: false,
            ..format()
        };
        let pixel_bytes = usize::from(bits / 8);
        let message = rfb::ServerMessage::FramebufferUpdate(vec![
            rfb::Rectangle {
                x: 0,
                y: 0,
                width: 2,
                height: 1,
                contents: rfb::Contents::Raw(vec![1; 2 * pixel_bytes]),
            },
            rfb::Rectangle {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                contents: rfb::Contents::Cursor {
                    pixels: vec![2; pixel_bytes],
                    mask: vec![128],
                },
            },
        ]);
        let bytes = server_bytes(&message, rfb::Dialect::V3_8, &format).unwrap();
        let make = || {
            let mut d = rfb::ServerMessages::with_limit(LIMIT);
            d.set_phase(rfb::Phase::Normal, rfb::Dialect::V3_8, format)
                .unwrap();
            d
        };
        contract::check_decode_with_alloc_limit(make, &bytes, 2 * LIMIT);
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(Ok(message))));
        assert!(stream.unread().is_empty());
    }
}

#[test]
fn contract_checks_small_arbitrary_inputs_and_wire_values() {
    let mut random = codec::Lcg::new(0x1234_5678);
    for len in 0..80 {
        let bytes = random.bytes(len);
        contract::check_decode_with_alloc_limit(|| proxy::Headers::with_limit(32), &bytes, 2 * 32);
        contract::check_decode_with_alloc_limit(|| SocksHandshake(socks::ClientMessages::with_limit(16)), &bytes, 2 * 16);
        contract::check_decode_with_alloc_limit(|| socks::ServerMessages::socks5(socks::Command::Bind), &bytes, 2 * socks::MAX_MESSAGE);
        contract::check_decode_with_alloc_limit(|| server_decoder(rfb::Phase::Normal, LIMIT), &bytes, 2 * LIMIT);
        contract::check_decode_with_alloc_limit(|| client_decoder(rfb::Phase::Normal, LIMIT), &bytes, 2 * LIMIT);
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

#[test]
fn socks_pipelined_greeting_and_request_pause_in_pump() {
    for auth in [false, true] {
        let method = if auth {
            socks::Method::UsernamePassword
        } else {
            socks::Method::NoAuth
        };
        let mut bytes = vec![5, 1, method.code()];
        if auth {
            bytes.extend_from_slice(&[1, 1, b'u', 1, b'p']);
        }
        let request = [5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        bytes.extend_from_slice(&request);
        let mut stream = Stream::new(socks::ClientMessages::new());
        let mut items = Vec::new();
        assert_eq!(
            codec::pump(&mut stream, &bytes, |item| items.push(item)),
            Ok(bytes.len())
        );
        assert_eq!(
            items,
            [Ok(socks::ClientMessage::Greeting(socks::Greeting {
                methods: vec![method]
            }))]
        );
        assert_eq!(stream.decoder().phase(), socks::ServerPhase::Selecting);
        assert_eq!(stream.unread(), &bytes[3..]);
        assert!(stream.decoder().select(method));
        if auth {
            items.clear();
            assert_eq!(
                codec::pump(&mut stream, &[], |item| items.push(item)),
                Ok(0)
            );
            assert_eq!(
                items,
                [Ok(socks::ClientMessage::Auth(socks::AuthRequest {
                    username: b"u".to_vec(),
                    password: b"p".to_vec(),
                }))]
            );
            assert_eq!(stream.decoder().phase(), socks::ServerPhase::Verifying);
            assert_eq!(stream.unread(), request);
            stream.decoder().verified(true);
        }
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(socks::ClientMessage::Request(socks::Request {
                command: socks::Command::Connect,
                address: socks::Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
                port: 80,
            }))))
        );
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
    }
}

#[test]
fn rfb_client_refused_server_init_closes_before_retry() {
    let mut client = rfb::Client::new();
    assert_eq!(client.push(b"RFB 003.008\n"), rfb::VERSION_LEN);
    client.next().unwrap().unwrap().unwrap();
    client
        .send(&rfb::ClientMessage::Version(rfb::Version::V3_8))
        .unwrap();
    assert_eq!(client.push(&[1, 1]), 2);
    client.next().unwrap().unwrap().unwrap();
    client.send(&rfb::ClientMessage::SecurityType(1)).unwrap();
    assert_eq!(client.push(&[0; 4]), 4);
    client.next().unwrap().unwrap().unwrap();
    client
        .send(&rfb::ClientMessage::ClientInit { shared: true })
        .unwrap();
    assert_eq!(client.phase(), rfb::Phase::ServerInit);
    let good = Wire::to_bytes(&init()).unwrap();
    let mut bytes = good.clone();
    bytes[4] = 24;
    bytes.extend_from_slice(&good);
    assert_eq!(client.push(&bytes), bytes.len());
    assert_eq!(
        client.next(),
        Some(Ok(Err(rfb::Error::PixelFormat)))
    );
    assert_eq!(client.phase(), rfb::Phase::Closed);
    assert_eq!(client.next(), None);
    assert!(client.is_done());
    assert_eq!(client.into_stream().unread(), good);
}

#[test]
fn rfb_server_push_then_drain_finishes_after_out_of_turn() {
    for limit in [rfb::MAX_CLIENT_MESSAGE, 24] {
        let mut server = rfb::Server::with_limit(limit);
        let bytes = vec![0; rfb::MAX_PENDING + 10];
        let mut rest = bytes.as_slice();
        let mut errors = 0;
        for _ in 0..5 {
            if rest.is_empty() {
                break;
            }
            rest = &rest[server.push(rest)..];
            while let Some(item) = server.next() {
                assert_eq!(item, Err(Fail::Protocol(rfb::FrameError::OutOfTurn)));
                errors += 1;
            }
        }
        assert!(
            rest.is_empty(),
            "push stopped with {} bytes left at limit {limit}",
            rest.len()
        );
        assert_eq!(errors, 1);
        assert!(server.is_done());
        assert_eq!(server.buffered(), rfb::MAX_PENDING.min(limit));
        assert_eq!(server.push(b"discard"), 7);
    }
}

#[test]
fn rfb_client_push_then_drain_finishes_after_out_of_turn() {
    for limit in [rfb::MAX_MESSAGE, 24] {
        let mut client = rfb::Client::with_limit(limit);
        assert_eq!(client.push(b"RFB 003.008\n"), rfb::VERSION_LEN);
        client.next().unwrap().unwrap().unwrap();
        let bytes = vec![0; rfb::MAX_PENDING + 10];
        let mut rest = bytes.as_slice();
        let mut errors = 0;
        for _ in 0..5 {
            if rest.is_empty() {
                break;
            }
            rest = &rest[client.push(rest)..];
            while let Some(item) = client.next() {
                assert_eq!(item, Err(Fail::Protocol(rfb::FrameError::OutOfTurn)));
                errors += 1;
            }
        }
        assert!(
            rest.is_empty(),
            "push stopped with {} bytes left at limit {limit}",
            rest.len()
        );
        assert_eq!(errors, 1);
        assert!(client.is_done());
        assert_eq!(client.buffered(), rfb::MAX_PENDING.min(limit));
        assert_eq!(client.push(b"discard"), 7);
    }
}

#[test]
fn rfb_server_limits_pending_input_after_turn_change() {
    let mut server = rfb::Server::new();
    server
        .send(&rfb::ServerMessage::Version(rfb::Version::V3_8))
        .unwrap();
    let mut bytes = b"RFB 003.008\n".to_vec();
    bytes.resize(bytes.len() + 200_000, 0);
    assert_eq!(server.push(&bytes), bytes.len());
    assert_eq!(
        server.next(),
        Some(Ok(Ok(rfb::ClientMessage::Version(rfb::Version::V3_8))))
    );
    assert_eq!(
        server.next(),
        Some(Err(Fail::Protocol(rfb::FrameError::OutOfTurn)))
    );
    assert_eq!(server.phase(), rfb::Phase::Closed);
    assert_eq!(server.next(), None);
    assert!(server.is_done());
    assert_eq!(server.buffered(), 200_000);
    assert_eq!(server.push(b"discard"), 7);
}

#[test]
fn rfb_client_limits_pending_input_after_turn_change() {
    let mut client = rfb::Client::new();
    let mut bytes = b"RFB 003.008\n".to_vec();
    bytes.resize(bytes.len() + 200_000, 0);
    assert_eq!(client.push(&bytes), bytes.len());
    assert_eq!(
        client.next(),
        Some(Ok(Ok(rfb::ServerMessage::Version(rfb::Version::V3_8))))
    );
    assert_eq!(
        client.next(),
        Some(Err(Fail::Protocol(rfb::FrameError::OutOfTurn)))
    );
    assert_eq!(client.phase(), rfb::Phase::Closed);
    assert_eq!(client.next(), None);
    assert!(client.is_done());
    assert_eq!(client.buffered(), 200_000);
    assert_eq!(client.push(b"discard"), 7);
}

fn server_bytes(message: &rfb::ServerMessage, dialect: rfb::Dialect, format: &rfb::PixelFormat) -> Result<Vec<u8>, rfb::Error> {
    let mut out = Vec::new();
    message.write(dialect, format, &mut out)?;
    Ok(out)
}
