//! QUIC datagrams, packets and frames, as a world playing a QUIC server
//! reads them once protection is removed.
#![no_main]

use fictionet::stdlib::quic::{Frame, Packet, Reassembler, parse_frames, split_datagram, write_datagram, write_frames};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte picks the short header's connection ID length, up to
    // 21 so the limit is tried too. The rest is one datagram.
    let Some((&pick, datagram)) = data.split_first() else { return };
    let dcid_len = usize::from(pick % 22);

    // Packets read can be written, and the datagram reads back the same.
    let (packets, _) = split_datagram(datagram, dcid_len);
    if !packets.is_empty() {
        let bytes = write_datagram(&packets).unwrap();
        assert_eq!(split_datagram(&bytes, dcid_len), (packets.clone(), None));
    }
    for p in &packets {
        let bytes = p.to_bytes().unwrap();
        let (back, used) = Packet::parse(&bytes, dcid_len).unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
        if let Some(payload) = p.payload() {
            check_frames(payload);
        }
    }

    // Any bytes as a payload on their own, and as a single frame.
    check_frames(datagram);
    if let Ok((f, used)) = Frame::parse(datagram) {
        assert!(used > 0 && used <= datagram.len());
        assert_eq!(parse_frames(&f.to_bytes().unwrap()).unwrap(), [f]);
    }

    // The bytes as stream data, fed to a reassembler all at once, and a
    // byte at a time from the last byte back. Both give the same stream.
    let mut whole = Reassembler::new();
    let mut bytewise = Reassembler::new();
    if whole.insert(0, datagram).is_ok() {
        for (i, b) in datagram.iter().enumerate().rev() {
            bytewise.insert(i as u64, std::slice::from_ref(b)).unwrap();
        }
        assert_eq!(whole.read(), bytewise.read());
    }
});

/// Frames read can be written, read back the same, and take no more
/// bytes than they did.
fn check_frames(payload: &[u8]) {
    if let Ok(frames) = parse_frames(payload) {
        let bytes = write_frames(&frames).unwrap();
        assert!(bytes.len() <= payload.len());
        assert_eq!(parse_frames(&bytes).unwrap(), frames);
    }
}
