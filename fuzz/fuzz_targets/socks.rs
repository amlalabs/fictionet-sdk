//! SOCKS handshake units, method decisions, UDP datagrams and strict writers.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::{
    codec::{Decode, Step},
    protocols::socks::*,
};
use libfuzzer_sys::fuzz_target;

struct Handshake(ClientMessages);
impl Decode for Handshake {
    type Item = Result<ClientMessage, Error>;
    type Error = FrameError;
    const NAME: &'static str = "SOCKS scripted handshake";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(bytes, eof)?;
        match &step {
            Step::Item(Ok(ClientMessage::Greeting(g)), _) => {
                let method = if g.methods.contains(&Method::UsernamePassword) {
                    Method::UsernamePassword
                } else if g.methods.contains(&Method::NoAuth) {
                    Method::NoAuth
                } else {
                    Method::NoAcceptable
                };
                assert!(self.0.select(method));
            }
            Step::Item(Ok(ClientMessage::Auth(a)), _) => self.0.verified(a.username != b"bad"),
            _ => {}
        }
        Ok(step)
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ClientMessages::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE);
            }
        ),
        decode_all(ClientMessages::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Handshake(ClientMessages::new())),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE);
            }
        ),
        decode_all(|| Handshake(ClientMessages::new()), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ClientMessages::with_limit(16)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 32);
            }
        ),
        decode_all(|| ClientMessages::with_limit(16), data),
    );
    for method in [Method::NoAuth, Method::UsernamePassword] {
        let selected = || {
            let mut d = ClientMessages::with_limit(16);
            d.decode(&[5, 1, method.code()], false).unwrap();
            assert!(d.select(method));
            d
        };
        assert_eq!(
            decode_chunks(
                &mut Stream::new(selected()),
                chunks(data, &[1, 7, 64]),
                |s| {
                    assert!(s.allocated() <= 32);
                }
            ),
            decode_all(selected, data),
        );
    }
    for make in [
        || ServerMessages::socks5(Command::Connect),
        || ServerMessages::socks5(Command::Bind),
        || ServerMessages::socks4(Socks4Command::Bind),
    ] {
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE);
            }),
            decode_all(make, data),
        );
    }
    macro_rules! wires {
        ($($ty:ty),+) => {$(
            if let Ok(value) = <$ty as Wire>::parse(data) {
                let _ = assert_write(&value);
            }
        )+};
    }
    wires!(
        Greeting,
        Selection,
        AuthRequest,
        AuthReply,
        Request,
        Reply,
        Socks4Request,
        Socks4Reply,
        Endpoint,
        UdpHeader,
        UdpDatagram
    );
    let bounded = &data[..data.len().min(MAX_DATAGRAM + 1)];
    let (left, right) = bounded.split_at(bounded.len() / 2);
    let first = data.first().copied().unwrap_or(0);
    let _ = assert_write(&Greeting {
        methods: data
            .iter()
            .take(MAX_METHODS + 1)
            .map(|&c| Method::Other(c))
            .collect(),
    });
    let _ = assert_write(&AuthRequest {
        username: left.to_vec(),
        password: right.to_vec(),
    });
    let _ = assert_write(&Request {
        command: Command::Connect,
        address: Address::Domain(left.to_vec()),
        port: 1,
    });
    let _ = assert_write(&Reply {
        code: ReplyCode::Other(first),
        address: Address::Domain(left.to_vec()),
        port: 1,
    });
    let _ = assert_write(&Socks4Reply {
        code: Socks4Code::Other(first),
        port: 1,
        ip: std::net::Ipv4Addr::LOCALHOST,
    });
    for destination in [
        Socks4Destination::Ip(std::net::Ipv4Addr::new(0, 0, 0, first)),
        Socks4Destination::Domain(right.to_vec()),
    ] {
        let _ = assert_write(&Socks4Request {
            command: Socks4Command::Connect,
            port: 1,
            destination,
            user_id: left.to_vec(),
        });
    }
    let _ = assert_write(
        &UdpHeader {
            fragment: first,
            address: Address::Domain(right.to_vec()),
            port: 1,
        }
        .datagram(left.to_vec()),
    );
    let offered: Vec<Method> = right
        .iter()
        .take(MAX_METHODS + 1)
        .map(|&c| Method::from_code(c))
        .collect();
    let allowed = first == 0xff || right[..right.len().min(MAX_METHODS)].contains(&first);
    let mut d = ServerMessages::socks5_offering(Command::Connect, &offered);
    match d.decode(&[5, first], false) {
        Ok(Step::Item(Ok(ServerMessage::Selection(s)), 2)) => {
            assert!(allowed && s.method.code() == first)
        }
        Ok(Step::Item(Err(Error::Method(c)), 2)) => assert!(!allowed && c == first),
        other => panic!("{other:?}"),
    }
});
