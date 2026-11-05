//! NTP packets, as a world's time server reads them, and the replies it
//! builds from them.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::ntp::{
    KissCode, Leap, Mode, Packet, ServerInfo, Timestamp, kiss_reply, server_reply,
};
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Timestamp as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <KissCode as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    if let Ok(p) = Packet::parse(data) {
        // Every field is kept, so what was read writes back the same bytes.
        assert_eq!(p.to_bytes().unwrap(), data);
        let _ = p.kiss_code().map(|k| k.to_string());
        // Only requests of versions 1 to 4 are answered: a client gets
        // mode 4, and a symmetric active peer mode 2, in its own version.
        let answer = match p.mode {
            Mode::Client if p.version <= 4 => Some(Mode::Server),
            Mode::SymmetricActive if p.version <= 4 => Some(Mode::SymmetricPassive),
            _ => None,
        };
        let server = ServerInfo {
            leap: Leap::None,
            stratum: 1,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: *b"GPS\0",
            reference: p.reference,
        };
        let r = server_reply(&p, &server, p.receive, p.transmit);
        assert_eq!(
            r.as_ref().ok().map(|r| (r.mode, r.version)),
            answer.map(|m| (m, p.version))
        );
        if let Ok(r) = r {
            let _ = assert_write(&r);
            assert!(r.to_bytes().is_ok());
            assert_eq!(Packet::parse(&r.to_bytes().unwrap()).as_ref(), Ok(&r));
        }
        let r = kiss_reply(&p, KissCode::from_bytes(p.reference_id));
        assert_eq!(
            r.as_ref().ok().map(|r| (r.mode, r.version)),
            answer.map(|m| (m, p.version))
        );
        if let Ok(r) = r {
            let _ = assert_write(&r);
            assert!(r.to_bytes().is_ok());
            assert_eq!(Packet::parse(&r.to_bytes().unwrap()).as_ref(), Ok(&r));
        }
        // A timestamp read as Unix time comes back within a few units,
        // measured round the era: the last fraction of an era rounds up to
        // the next era's second 0.
        let (secs, nanos) = p.transmit.to_unix();
        assert!(nanos < 1_000_000_000);
        let (a, b) = (
            Timestamp::from_unix(secs, nanos).to_bits(),
            p.transmit.to_bits(),
        );
        assert!(a.wrapping_sub(b).min(b.wrapping_sub(a)) <= 3);
        // A request never carries a kiss code.
        if p.mode == Mode::Client {
            assert_eq!(p.kiss_code(), None);
        }
    }
    // Any Unix time survives a trip through a timestamp near itself.
    if let Some(b) = data.get(..12) {
        let secs = i64::from_be_bytes(b[..8].try_into().unwrap());
        let nanos = u32::from_be_bytes(b[8..].try_into().unwrap()) % 1_000_000_000;
        assert_eq!(
            Timestamp::from_unix(secs, nanos).to_unix_near(secs),
            (secs, nanos)
        );
    }
});
