//! SMB2 frames, compound chains and bodies, as a world playing a file
//! server on port 445 reads them.
#![no_main]

use fictionet::stdlib::smb2::{
    Decoder, FrameError, HEADER_LEN, MAX_BUFFERED, MAX_MESSAGE, Packet, Request, Response, frame, parse_frame,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` whole or a byte at a time, taking payloads out after each
/// feed, as a world does. Every payload, then the error that broke the
/// stream, if one did.
fn split(data: &[u8], bytewise: bool) -> (Vec<Vec<u8>>, Option<FrameError>) {
    let mut decoder = Decoder::new();
    let mut payloads = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_frame() {
                match r {
                    Ok(p) => payloads.push(p),
                    Err(e) => return (payloads, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a payload or an error.
            assert!(progress);
        }
    }
    (payloads, None)
}

/// Whether a body written back is no longer than the one read, or no
/// longer than its own StructureSize. Then a message read whole always fits
/// MAX_MESSAGE when written back.
fn no_longer(new: &[u8], old: &[u8]) -> bool {
    new.len() <= old.len() || new.get(..2).is_some_and(|s| new.len() <= usize::from(u16::from_le_bytes([s[0], s[1]])))
}

/// A payload read every way there is. Whatever reads is written back, and
/// reads back the same. A compound chain writes back byte for byte.
fn payload(data: &[u8], status: u32) {
    let Ok(packet) = Packet::parse(data) else { return };
    let bytes = packet.to_bytes().unwrap();
    assert!(bytes.len() <= MAX_MESSAGE);
    assert_eq!(Packet::parse(&bytes), Ok(packet.clone()));
    let Packet::Smb2(messages) = packet else { return };
    assert_eq!(bytes, data);
    for m in &messages {
        if let Ok(req) = m.request() {
            let body = req.to_body().unwrap();
            assert!(no_longer(&body, &m.body));
            assert_eq!(Request::parse(m.header.command, &body), Ok(req));
        }
        for s in [m.header.status, status] {
            if let Ok(resp) = Response::parse(m.header.command, s, &m.body) {
                let body = resp.to_body(m.header.command, s).unwrap();
                assert!(no_longer(&body, &m.body));
                assert_eq!(Response::parse(m.header.command, s, &body), Ok(resp));
            }
        }
    }
}

/// Bytes read as a body alone, under a command and status taken from the
/// first bytes.
fn body(data: &[u8]) {
    let [c, s, rest @ ..] = data else { return };
    let command = u16::from(*c % 0x16);
    let status = [0, 0x8000_0005, 0xc000_0016, 0xc000_0022, 0x103, 0x10c][usize::from(*s % 6)];
    if let Ok(req) = Request::parse(command, rest) {
        let back = req.to_body().unwrap();
        assert!(no_longer(&back, rest));
        assert_eq!(Request::parse(command, &back), Ok(req));
    }
    if let Ok(resp) = Response::parse(command, status, rest) {
        let back = resp.to_body(command, status).unwrap();
        assert!(no_longer(&back, rest));
        assert_eq!(Response::parse(command, status, &back), Ok(resp));
    }
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. Both
    // give the same payloads and the same error.
    let (payloads, err) = split(data, false);
    assert_eq!(split(data, true), (payloads.clone(), err));
    for p in &payloads {
        // A payload read can be framed, and reads back the same.
        let bytes = frame(p).unwrap();
        assert_eq!(parse_frame(&bytes), Ok(Some((&p[..], bytes.len()))));
        payload(p, 0);
    }
    // Any bytes as a payload on their own, and as a body.
    payload(data, 0xc000_0016);
    body(data);
    if data.len() > HEADER_LEN {
        body(&data[HEADER_LEN - 2..]);
    }
});
