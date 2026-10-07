//! Application protocols: DNS, DHCP, HTTP/1.1, HTTP/2, Modbus/TCP, and TLS,
//! which is decrypted when the world's TLS stack gave its session keys.
//!
//! A [`Conversation`](super::Conversation) is one TCP connection, both ways.
//! It guesses the protocol through the public registry, using ports or first
//! bytes, then decodes each
//! direction's byte stream as it arrives. Each message it finds becomes a
//! [`Layer`](super::Layer) of the packet that completed it. When the whole message lies
//! in that packet, its fields point at the packet's own bytes; otherwise
//! the message gets a buffer of its own, as Wireshark's "Reassembled TCP".

use fictionet::stdlib::http2;

use super::http2 as capture;

use super::decode::Decoded;

use super::protocols;
use super::tls::TlsSession;
use super::{Match, Registry};
use crate::events::Transport;
const MAX_BUFFER: usize = 32 << 10;

/// Sets the packet's protocol and info from a message at `level`: 1 for
/// TLS records, 2 for what they carry and for plain HTTP. A higher level
/// replaces what lower ones said; the same level adds to it.
pub(super) fn info(d: &mut Decoded, level: u8, proto: &str, text: &str) {
    if level > d.level {
        d.level = level;
        d.proto = proto.into();
        d.info = text.to_owned();
    } else if level == d.level {
        d.info.push_str(", ");
        d.info.push_str(text);
    }
    d.cap_info();
}

// ---------------------------------------------------------------------------
// TCP conversations

fn looks_like_http1(b: &[u8]) -> bool {
    let methods: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    b.starts_with(b"HTTP/1.") || methods.iter().any(|m| b.starts_with(m))
}

fn register_http(registry: &mut Registry) {
    registry.register_with_buffer(
        "http1",
        |s| {
            if s.transport == Transport::Tcp
                && (s.alpn == Some("http/1.1")
                    || (s.alpn != Some("h2") && looks_like_http1(s.first)))
            {
                Match::Yes
            } else {
                Match::No
            }
        },
        MAX_BUFFER + 1 + 65_535,
        |_| protocols::Http1::pair(),
    );
    let budget = capture::CaptureBudget::default();
    registry.register_with_buffer(
        "http2",
        |s| {
            if s.transport != Transport::Tcp || s.alpn == Some("http/1.1") {
                Match::No
            } else if s.alpn == Some("h2") || s.first.starts_with(http2::PREFACE) {
                Match::Yes
            } else if http2::PREFACE.starts_with(s.first) {
                Match::More
            } else {
                Match::No
            }
        },
        capture::CAPTURE_READ_AHEAD,
        move |_| capture::Capture::pair_in(&budget),
    );
}

pub(super) fn register(registry: &mut Registry) {
    register_http(registry);
    registry.register_protocol(
        "tls",
        |s| {
            if s.transport == Transport::Tcp && s.first.starts_with(&[0x16, 0x03]) {
                Match::Yes
            } else {
                Match::No
            }
        },
        |s, registry| Box::new(TlsSession::new(s.ports, registry.clone())),
    );
    registry.register_protocol(
        "modbus",
        |s| {
            if s.transport == Transport::Tcp
                && (s.ports.0 == crate::stdlib::modbus::PORT
                    || s.ports.1 == crate::stdlib::modbus::PORT)
            {
                Match::Yes
            } else {
                Match::No
            }
        },
        |s, _| Box::new(protocols::ModbusSession::new(s.ports)),
    );
    registry.register(
        "dhcp",
        |s| {
            if s.transport == Transport::Udp && matches!(s.ports, (67, 68) | (68, 67)) {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| [protocols::Dhcp::default(), protocols::Dhcp::default()],
    );
    registry.register_with_buffer(
        "dns",
        |s| {
            if s.ports.0 == 53 || s.ports.1 == 53 {
                Match::Yes
            } else {
                Match::No
            }
        },
        65_538,
        |s| {
            [
                protocols::Dns::new(s.transport == Transport::Tcp),
                protocols::Dns::new(s.transport == Transport::Tcp),
            ]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Conversation, Observed, Place};
    use http2::PREFACE as HTTP2_PREFACE;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Feeds one direction's next bytes, `chunk` bytes at a time, as
    /// separate packets. Returns what the last packet decoded to.
    struct Feeder {
        c: Conversation,
        at: [u64; 2],
    }

    impl Feeder {
        fn new(ports: (u16, u16)) -> Feeder {
            Feeder {
                c: Conversation::with_registry(ports.0, ports.1, Registry::default()),
                at: [0, 0],
            }
        }

        fn send(&mut self, dir: bool, bytes: &[u8], chunk: usize) -> Decoded {
            let mut d = Decoded::default();
            for piece in bytes.chunks(chunk) {
                d = Decoded::default();
                let place = Place { stream_start: self.at[dir as usize], buf: 0, offset: Some(0), len: piece.len() };
                self.c.data(dir, piece, place, &mut d, &[]);
                self.at[dir as usize] += piece.len() as u64;
            }
            d
        }

        /// An HTTP/2 connection whose client has sent its preface.
        fn h2() -> Feeder {
            let mut f = Feeder::new((40000, 80));
            f.send(false, HTTP2_PREFACE, 1500);
            f
        }
    }

    /// Every field with no bytes of its own, as (name, value).
    fn notes(d: &Decoded) -> Vec<(String, String)> {
        let fields = d.layers.iter().flat_map(|l| &l.fields);
        fields.filter(|f| f.range.is_none()).map(|f| (f.name.clone(), f.value.clone())).collect()
    }

    fn has(d: &Decoded, name: &str, value: &str) -> bool {
        notes(d).iter().any(|(n, v)| n == name && v == value)
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    const X_OLD: &str = "4001 7803 6f6c 64";
    const X_NEW: &str = "4001 7803 6e65 77";

    #[test]
    fn expanded_huffman_headers_keep_dynamic_references() {
        use fictionet::stdlib::{codec::Wire, prefix_int::Integer};

        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        let mut block = vec![0, 1, b'x'];
        Integer::<7> {
            flags: 0x80,
            value: 60_000,
        }
        .write(&mut block)
        .unwrap();
        block.extend(vec![0; 60_000]);
        let mut chunks = block.chunks(16_000).peekable();
        let mut kind = 1;
        while let Some(chunk) = chunks.next() {
            let flags = if chunks.peek().is_none() { 0x4 } else { 0 };
            let d = f.send(true, &frame(kind, flags, 3, chunk), 1500);
            assert!(!d.tags.contains(&"malformed"));
            kind = 9;
        }
        let d = f.send(true, &frame(1, 0x4, 5, &[0x88, 0xbe]), 1500);
        assert!(!d.tags.contains(&"malformed"));
        assert!(has(&d, "x", "old"));
    }

    /// A header block whose padding does not fit is not decoded, and the
    /// table it may have changed is forgotten.
    #[test]
    fn bad_padding_is_not_decoded() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        // PADDED, a pad length of 64, and seven bytes that read as x: new.
        let d = f.send(true, &frame(1, 0xc, 3, &hex("40 4001 7803 6e65 77")[1..]), 1500);
        assert!(d.tags.contains(&"malformed"));
        assert!(!has(&d, "x", "new"));
        let d = f.send(true, &frame(1, 0x4, 5, &[0x88, 0xbe]), 1500);
        assert!(!has(&d, "x", "new") && !has(&d, "x", "old"), "{:?}", notes(&d));
    }

    /// A PUSH_PROMISE's header block changes the table that later blocks
    /// rely on, so it is decoded too.
    #[test]
    fn push_promise_headers_update_the_table() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        let mut promise = vec![0, 0, 0, 2];
        promise.extend(hex(X_NEW));
        let d = f.send(true, &frame(5, 0x4, 1, &promise), 1500);
        assert!(has(&d, "Promised stream", "2"));
        assert!(has(&d, "x", "new"));
        let d = f.send(true, &frame(1, 0x4, 2, &[0x88, 0xbe]), 1500);
        assert!(has(&d, "x", "new"), "{:?}", notes(&d));
        assert!(d.info.starts_with("HEADERS[2]: 200"), "{}", d.info);
    }

    /// A header block goes on only in CONTINUATION frames of its own
    /// stream. One that is cut off is not joined to another frame's
    /// bytes, and the table it may have changed is forgotten.
    #[test]
    fn a_continuation_of_another_stream_is_not_joined() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        // An unfinished block on stream 1, "completed" on stream 3.
        f.send(true, &frame(1, 0, 3, &hex("4001 7903 6f")), 1500);
        let d = f.send(true, &frame(9, 0x4, 5, &hex("6c64")), 1500);
        assert!(d.tags.contains(&"malformed"));
        assert!(!notes(&d).iter().any(|(n, _)| n == "y"), "{:?}", notes(&d));
        // Entry 62 was x: old, but the cut-off block may have added one.
        let d = f.send(true, &frame(1, 0x4, 7, &[0x88, 0xbe]), 1500);
        assert!(!has(&d, "x", "old"), "{:?}", notes(&d));
        assert!(notes(&d).iter().any(|(n, v)| n == "Header" && v.starts_with("not known")), "{:?}", notes(&d));
        // A HEADERS frame does not continue an unfinished block either.
        f.send(true, &frame(1, 0, 9, &hex("82")), 1500);
        let d = f.send(true, &frame(1, 0x4, 9, &hex("82")), 1500);
        assert!(d.tags.contains(&"malformed"));
    }

    /// After lost bytes, where HTTP/2 frames start is not known, so the
    /// direction is not decoded further.
    #[test]
    fn lost_bytes_end_http2_decoding() {
        let mut session = Observed::new(capture::Capture::default());
        let mut packet = Decoded::default();
        session.data(&frame(1, 0x4, 1, &hex(X_OLD)), Place::default(), &mut packet);
        assert!(has(&packet, "x", "old"));
        session.data(&frame(1, 0, 3, &[0x88]), Place::default(), &mut packet);
        session = session.reset();
        let mut packet = Decoded::default();
        session.data(&frame(1, 0x4, 3, &[0x88, 0xbe]), Place::default(), &mut packet);
        assert!(packet.layers.is_empty());
        assert!(!session.waiting());
    }

    /// A DATA frame longer than the buffer is shown by its header and
    /// skipped, and the frames after it are still found.
    #[test]
    fn a_long_http2_frame_is_skipped_not_lost() {
        let mut f = Feeder::h2();
        let mut bytes = frame(0, 0, 1, &vec![b'a'; 40_000]);
        bytes.extend(frame(1, 0x5, 1, &[0x88]));
        let mut seen = Vec::new();
        for piece in bytes.chunks(1400) {
            let d = f.send(true, piece, 1400);
            seen.push(d.info);
        }
        assert!(seen.iter().any(|i| i == "DATA[1] 40000 bytes"), "{seen:?}");
        assert_eq!(seen.last().unwrap(), "HEADERS[1]: 200, end");
    }

    /// A DNS message over TCP longer than the buffer is skipped, and the
    /// next one is decoded.
    #[test]
    fn a_long_dns_message_is_skipped_not_lost() {
        let mut f = Feeder::new((40000, 53));
        let mut bytes = 39_959u16.to_be_bytes().to_vec();
        bytes.extend(vec![0; 39_959]);
        bytes.extend([0, 12, 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut infos = Vec::new();
        for piece in bytes.chunks(1400) {
            infos.push(f.send(true, piece, 1400).info);
        }
        assert_eq!(infos[0], "DNS message of 39959 bytes, not decoded");
        assert!(infos.last().unwrap().starts_with("Standard query response 0x1234"), "{infos:?}");
    }

    #[test]
    fn a_complete_large_item_keeps_its_packet_bytes() {
        let mut dns = Feeder::new((40000, 53));
        let mut message = 40_000u16.to_be_bytes().to_vec();
        message.resize(40_002, 0);
        let d = dns.send(false, &message, message.len());
        assert_eq!(d.layers[0].range, (2, message.len()));
        assert_eq!(d.layers[0].buf, 0);
        assert!(d.extra.is_empty());

        let mut tls = Feeder::new((40000, 443));
        tls.send(false, &[22, 3, 3, 0, 0], 1500);
        let mut record = vec![23, 3, 3, 0x9c, 0x40];
        record.resize(40_005, 1);
        let d = tls.send(false, &record, record.len());
        assert_eq!(d.layers[0].range, (0, record.len()));
        assert!(!d.tags.contains(&"malformed"));
        assert_eq!(d.info, "Application Data");

        let mut http = Feeder::new((40000, 80));
        let request = format!("GET /{} HTTP/1.1\r\n\r\n", "x".repeat(40_000));
        let d = http.send(false, request.as_bytes(), request.len());
        assert_eq!(d.layers[0].range, (0, request.len()));
        assert_eq!(d.layers[0].buf, 0);
        assert!(d.info.starts_with("GET /"));
    }

    #[test]
    fn modbus_requests_and_responses() {
        // Port 40000 sorts first, so direction 0 (false) is the client's.
        let mut f = Feeder::new((40000, 502));
        let query = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
        // Split across packets, it is decoded when the last byte comes.
        let d = f.send(false, &query, 5);
        assert_eq!(d.proto, "Modbus/TCP");
        assert_eq!(d.info, "Query: Trans: 7; Unit: 1, Func: 3: Read Holding Registers");
        assert!(has(&d, "Request", "address 2, quantity 1"));
        let d = f.send(true, &[0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2], 1500);
        assert!(has(&d, "Response", "registers [1234]"));
        let d = f.send(true, &[0, 8, 0, 0, 0, 3, 1, 0x83, 2], 1500);
        assert!(has(&d, "Response", "exception: illegal data address"));
        // Bytes that are not Modbus stop the decoding.
        let d = f.send(false, &[0, 9, 0, 5, 0, 6, 1, 3, 0, 0, 0, 1], 1500);
        assert_ne!(d.proto, "Modbus/TCP");
        let d = f.send(false, &query, 1500);
        assert_ne!(d.proto, "Modbus/TCP");
    }

    /// A large chunk of tiny HTTP/2 frames takes time in proportion to its
    /// size. Consuming each frame by moving the rest of the buffer would
    /// make a chunk of n frames take n^2 work.
    #[test]
    fn many_tiny_http2_frames_in_one_chunk_take_linear_time() {
        use fictionet::stdlib::codec::test_support::assert_linear;
        let one = frame(0xff, 0, 1, &[]);
        assert_linear("HTTP/2 frames in one chunk", 20_000, |n| {
            let bytes = one.repeat(n);
            let mut f = Feeder::h2();
            let d = f.send(false, &bytes, bytes.len());
            assert!(d.layers.len() + d.cut > 0);
        });
    }
}
