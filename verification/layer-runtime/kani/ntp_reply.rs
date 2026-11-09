//! Kani harness over `ntp::server_reply` (src/stdlib/protocols/ntp.rs:
//! 544-593), the decision the Search time server answers by.
//!
//! Included from `src/stdlib/protocols/ntp.rs` under `cfg(kani)`. The
//! harnesses over `TimeServer` itself (`kani/ntp.rs`) cover the requests it
//! answers and the datagrams `Packet::parse` refuses; for a packet that
//! parses and is not a request, driving `TimeServer` did not fit in
//! 10 GiB, so this proves the refusal here, on the function `TimeServer`
//! calls, and `TimeServer` sends nothing when it refuses
//! (`demos/search/world/src/ntp.rs:104-111`: no reply without `Some`).

use super::*;

#[kani::proof]
fn a_reply_comes_only_for_a_request_and_carries_its_transmit_time() {
    let mode = match kani::any::<u8>() {
        1 => Mode::SymmetricActive,
        2 => Mode::SymmetricPassive,
        3 => Mode::Client,
        4 => Mode::Server,
        _ => Mode::Broadcast,
    };
    let version: u8 = kani::any();
    kani::assume(version <= 7);
    let transmit = Timestamp::from_bits(kani::any());
    let request = Packet {
        leap: Leap::None,
        version,
        mode,
        stratum: kani::any(),
        poll: kani::any(),
        precision: kani::any(),
        root_delay: kani::any(),
        root_dispersion: kani::any(),
        reference_id: kani::any(),
        reference: Timestamp::from_bits(kani::any()),
        origin: Timestamp::from_bits(kani::any()),
        receive: Timestamp::from_bits(kani::any()),
        transmit,
        trailer: Vec::new(),
    };
    let server = ServerInfo {
        leap: Leap::None,
        stratum: 2,
        precision: -24,
        root_delay: 0xa4,
        root_dispersion: 0x49,
        reference_id: [194, 58, 204, 148],
        reference: Timestamp::from_bits(kani::any()),
    };
    let now = Timestamp::from_bits(kani::any());
    let is_request =
        matches!(mode, Mode::Client | Mode::SymmetricActive) && (1..=4).contains(&version);
    match server_reply(&request, &server, now, now) {
        Ok(reply) => {
            assert!(is_request, "only a request is answered");
            assert!(
                reply.origin == transmit,
                "the origin is the request's transmit time"
            );
            assert!(reply.version == version);
            assert!(matches!(
                (mode, reply.mode),
                (Mode::Client, Mode::Server) | (Mode::SymmetricActive, Mode::SymmetricPassive)
            ));
        }
        Err(_) => assert!(!is_request, "every request is answered"),
    }
}

/// A header whose mode bits are 0, 6 or 7 does not parse, whatever its
/// other bytes; `TimeServer` answers nothing it cannot parse
/// (`demos/search/world/src/ntp.rs:50`).
#[kani::proof]
#[kani::unwind(50)]
fn a_header_of_mode_0_6_or_7_does_not_parse() {
    let bytes: [u8; 48] = kani::any();
    kani::assume(matches!(bytes[0] & 7, 0 | 6 | 7));
    assert!(Packet::parse(&bytes).is_err());
}
