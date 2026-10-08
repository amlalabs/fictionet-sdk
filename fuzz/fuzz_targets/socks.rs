//! SOCKS handshake units, method decisions, UDP datagrams and strict writers.
#![no_main]

use fictionet::stdlib::{
    codec::{Decode, Step},
    socks::*,
    test_support::contract,
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
    contract::check_decode_with_alloc_limit(ClientMessages::new, data, 2 * MAX_MESSAGE);
    contract::check_decode_with_alloc_limit(
        || Handshake(ClientMessages::new()),
        data,
        2 * MAX_MESSAGE,
    );
    contract::check_decode_with_alloc_limit(|| ClientMessages::with_limit(16), data, 32);
    for method in [Method::NoAuth, Method::UsernamePassword] {
        contract::check_decode_with_alloc_limit(
            || {
                let mut d = ClientMessages::with_limit(16);
                d.decode(&[5, 1, method.code()], false).unwrap();
                assert!(d.select(method));
                d
            },
            data,
            32,
        );
    }
    for make in [
        || ServerMessages::socks5(Command::Connect),
        || ServerMessages::socks5(Command::Bind),
        || ServerMessages::socks4(Socks4Command::Bind),
    ] {
        contract::check_decode_with_alloc_limit(make, data, 2 * MAX_MESSAGE);
    }
    macro_rules! wires { ($($ty:ty),+) => {$(contract::check_wire::<$ty>(data);)+}; }
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
    contract::check_wire_value(&Greeting {
        methods: data
            .iter()
            .take(MAX_METHODS + 1)
            .map(|&c| Method::Other(c))
            .collect(),
    });
    contract::check_wire_value(&AuthRequest {
        username: left.to_vec(),
        password: right.to_vec(),
    });
    contract::check_wire_value(&Request {
        command: Command::Connect,
        address: Address::Domain(left.to_vec()),
        port: 1,
    });
    contract::check_wire_value(&Reply {
        code: ReplyCode::Other(first),
        address: Address::Domain(left.to_vec()),
        port: 1,
    });
    contract::check_wire_value(&Socks4Reply {
        code: Socks4Code::Other(first),
        port: 1,
        ip: std::net::Ipv4Addr::LOCALHOST,
    });
    for destination in [
        Socks4Destination::Ip(std::net::Ipv4Addr::new(0, 0, 0, first)),
        Socks4Destination::Domain(right.to_vec()),
    ] {
        contract::check_wire_value(&Socks4Request {
            command: Socks4Command::Connect,
            port: 1,
            destination,
            user_id: left.to_vec(),
        });
    }
    contract::check_wire_value(
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
