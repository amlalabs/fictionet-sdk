//! SoupBinTCP packets as a framer reads them from a connection, and the
//! client and server sessions driven by whatever frames come out.
#![no_main]

use fictionet::stdlib::session::Action;
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{
    Wire,
};
use fictionet::stdlib::test_support::contract::{check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::soupbintcp::{Alpha, Client, Login, MAX_PACKET, Packet, Server, Timers};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const SMALL_LIMIT: usize = 64;

fn check_actions(actions: &[Action<Packet, fictionet::stdlib::soupbintcp::Event>]) {
    assert!(actions.len() <= 2);
    for action in actions {
        if let Action::Send(packet) = action {
            check_wire_value(packet);
            assert!(packet.to_bytes().is_ok());
        }
    }
}

fn login() -> Login {
    Login {
        username: Alpha::right_padded("ALICE").unwrap(),
        password: Alpha::right_padded("SECRET").unwrap(),
        session: Alpha::blank(),
        sequence: 1,
    }
}

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Packet>(data);
    if let Ok(packet) = Packet::parse_body(data) {
        check_wire_value(&packet);
    }
    check_decode(Frames::<Packet>::default, data);
    check_decode_with_alloc_limit(
        || Frames::<Packet>::with_limit(SMALL_LIMIT),
        data,
        2 * (SMALL_LIMIT + 3),
    );
    let (frames, _) = decode_all(Frames::<Packet>::default, data);

    // A logged-in client and server each read every frame, with time
    // taken from the frame bytes.
    let mut client = Client::new(login(), Timers::default(), 0).unwrap();
    let mut server = Server::new(Timers::default(), 0).unwrap();
    client.start(0).unwrap();
    server.receive(&Packet::LoginRequest(login()), 0).unwrap();
    let session = Alpha::left_padded("FUZZ").unwrap();
    for action in server.accept(session, 1, 0).unwrap() {
        if let Action::Send(packet) = action {
            client.receive(&packet, 0).unwrap();
        }
    }
    let mut now = 0u64;
    for frame in &frames {
        if let Ok(packet) = frame {
            check_wire_value(packet);
            assert!(packet.to_bytes().unwrap().len() <= MAX_PACKET);
        }
        now += frame.as_ref().map_or(0, |p| u64::from(p.kind()) * 50);
        let before = client.next_sequence();
        if let Ok(actions) = client.receive_frame(frame, now) {
            check_actions(&actions);
            assert!(client.next_sequence() - before <= 1);
        }
        if let Ok(actions) = server.receive_frame(frame, now) {
            check_actions(&actions);
        }
        check_actions(&client.tick(now).unwrap());
        check_actions(&server.tick(now).unwrap());
        if let Ok(packet) = server.send(&data[..data.len().min(16)], now) {
            check_wire_value(&packet);
        }
        if let Ok(packet) = client.send(&data[..data.len().min(16)], now) {
            check_wire_value(&packet);
        }
    }

    // A fresh server reads the frames as a client would send them.
    let mut fresh = Server::new(Timers::default(), 0).unwrap();
    for frame in &frames {
        if let Ok(actions) = fresh.receive_frame(frame, 1) {
            check_actions(&actions);
        }
    }
});
