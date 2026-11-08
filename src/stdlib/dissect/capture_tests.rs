//! Captured packets read the whole passive way: the TCP observer, the
//! passive TLS reader and HTTP, with and without the session's keys, with
//! bytes missing, and with a capture that ends in the middle of a message.

use super::tls::tests::{handshake_message, seal};
use super::{Decoded, Dissector, KeyLine, Layer};

const CLIENT: ([u8; 4], u16) = ([10, 0, 0, 2], 40000);
const SERVER: ([u8; 4], u16) = ([10, 0, 0, 1], 443);
const RANDOM: [u8; 32] = [7; 32];
const CLIENT_HANDSHAKE: [u8; 32] = [2; 32];
const CLIENT_APP: [u8; 32] = [1; 32];
const SERVER_HANDSHAKE: [u8; 32] = [4; 32];
const SERVER_APP: [u8; 32] = [3; 32];
const REQUEST: &[u8] = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
const TO_CLIENT: &str = "10.0.0.1:443 → 10.0.0.2:40000";
const TO_SERVER: &str = "10.0.0.2:40000 → 10.0.0.1:443";
const HTTP: &str = "Hypertext Transfer Protocol";

/// The session's key log, as the world's TLS stack writes it.
fn key_log() -> Vec<KeyLine> {
    [
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", CLIENT_HANDSHAKE),
        ("CLIENT_TRAFFIC_SECRET_0", CLIENT_APP),
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", SERVER_HANDSHAKE),
        ("SERVER_TRAFFIC_SECRET_0", SERVER_APP),
    ]
    .into_iter()
    .map(|(label, secret)| KeyLine {
        label: label.into(),
        client_random: RANDOM.to_vec(),
        secret: secret.to_vec(),
    })
    .collect()
}

/// An IPv4 packet carrying one TCP segment.
fn packet(from_client: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let ((src, sport), (dst, dport)) = if from_client {
        (CLIENT, SERVER)
    } else {
        (SERVER, CLIENT)
    };
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 6, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    p.extend_from_slice(payload);
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

/// A plaintext TLS record.
fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![kind, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
    record.extend_from_slice(body);
    record
}

/// One TLS 1.3 connection as a capture sees it, packet by packet.
struct Capture {
    dissector: Dissector,
    keys: Vec<KeyLine>,
    /// The next sequence number each way, the client's first.
    next: [u32; 2],
}

impl Capture {
    /// The handshake, through the server's encrypted extensions, which
    /// choose HTTP/1.1. With `keys`, the dissector has the key log.
    fn new(keys: bool) -> Capture {
        let mut capture = Capture {
            dissector: Dissector::default(),
            keys: if keys { key_log() } else { Vec::new() },
            next: [1001, 5001],
        };
        capture
            .dissector
            .decode(&packet(true, 1000, 0x02, b""), &[]);
        capture
            .dissector
            .decode(&packet(false, 5000, 0x12, b""), &[]);
        let mut client = vec![3, 3];
        client.extend_from_slice(&RANDOM);
        client.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        capture.send(true, &record(22, &handshake_message(1, &client)));
        let mut server = vec![3, 3];
        server.extend_from_slice(&[8; 32]);
        server.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        capture.send(false, &record(22, &handshake_message(2, &server)));
        let alpn = b"\x00\x10\x00\x0b\x00\x09\x08http/1.1";
        let mut extensions = (alpn.len() as u16).to_be_bytes().to_vec();
        extensions.extend_from_slice(alpn);
        capture.send(
            false,
            &seal(&SERVER_HANDSHAKE, 0, 22, &handshake_message(8, &extensions)),
        );
        capture
    }

    /// Decodes the next segment one way.
    fn send(&mut self, from_client: bool, payload: &[u8]) -> Decoded {
        let next = &mut self.next[usize::from(!from_client)];
        let p = packet(from_client, *next, 0x18, payload);
        *next = next.wrapping_add(payload.len() as u32);
        self.dissector.decode(&p, &self.keys)
    }

    /// Loses the next `len` bytes one way: the capture never sees them.
    fn lose(&mut self, from_client: bool, len: usize) {
        let next = &mut self.next[usize::from(!from_client)];
        *next = next.wrapping_add(len as u32);
    }

    /// Decodes a FIN one way.
    fn fin(&mut self, from_client: bool) -> Decoded {
        let next = self.next[usize::from(!from_client)];
        self.dissector
            .decode(&packet(from_client, next, 0x11, b""), &self.keys)
    }

    fn finish(&mut self) -> Decoded {
        self.dissector.finish(&self.keys)
    }
}

/// The application layer `name` of `d`, if it has one.
fn layer<'a>(d: &'a Decoded, name: &str) -> Option<&'a Layer> {
    d.layers.iter().find(|l| l.name == name)
}

/// The values of every note called `name`.
fn notes(d: &Decoded, name: &str) -> Vec<String> {
    d.layers
        .iter()
        .flat_map(|l| &l.fields)
        .filter(|f| f.name == name && f.range.is_none())
        .map(|f| f.value.clone())
        .collect()
}

/// With the key log, the requests and responses inside TLS are HTTP. Their
/// fields point into the decrypted bytes, which the packet carries as a
/// buffer of their own, never into the captured packet, whose bytes are
/// the ciphertext.
#[test]
fn with_keys_tls_carries_http_from_its_decrypted_bytes() {
    let mut capture = Capture::new(true);
    let request = capture.send(true, &seal(&CLIENT_APP, 0, 23, REQUEST));
    assert_eq!(request.proto, "HTTP");
    assert_eq!(request.info, "GET /secret HTTP/1.1");
    assert!(request.tags.contains(&"decrypted"));
    let tls = layer(&request, "Transport Layer Security").unwrap();
    assert_eq!(tls.buf, 0, "the record is in the packet");
    let http = layer(&request, HTTP).unwrap();
    let (name, bytes) = &request.extra[http.buf - 1];
    assert_eq!(
        (name.as_str(), bytes.as_slice()),
        ("Decrypted TLS", REQUEST)
    );
    assert_eq!(http.range, (0, REQUEST.len()));

    let response = capture.send(false, &seal(&SERVER_APP, 0, 23, RESPONSE));
    assert_eq!(response.info, "HTTP/1.1 200 OK");
    let http = layer(&response, HTTP).unwrap();
    assert_eq!(response.extra[http.buf - 1].1, RESPONSE);
}

/// Without the key log, TLS shows its records and says why it cannot read
/// them. No HTTP comes out, and no plaintext.
#[test]
fn without_keys_tls_shows_encrypted_records_and_no_http() {
    let mut capture = Capture::new(false);
    for (from_client, sealed) in [
        (true, seal(&CLIENT_APP, 0, 23, REQUEST)),
        (false, seal(&SERVER_APP, 0, 23, RESPONSE)),
    ] {
        let d = capture.send(from_client, &sealed);
        assert_eq!(d.proto, "TLSv1.3");
        assert_eq!(d.info, "Application Data");
        assert!(layer(&d, HTTP).is_none());
        assert!(!d.tags.contains(&"decrypted"));
        assert!(d.extra.is_empty());
        assert_eq!(notes(&d, "Decryption"), ["no keys for this session"]);
    }
}

/// Bytes missing from the server's direction are shown with their count,
/// and that direction's TLS is not read past them: where its next record
/// starts and which sequence number it has are unknown. The client's
/// direction goes on as before.
#[test]
fn missing_bytes_are_shown_and_stop_only_their_direction() {
    for keys in [true, false] {
        let mut capture = Capture::new(keys);
        capture.send(true, &seal(&CLIENT_APP, 0, 23, REQUEST));
        let lost = seal(&SERVER_APP, 0, 23, RESPONSE);
        capture.lose(false, lost.len());
        let held = capture.send(false, &seal(&SERVER_APP, 1, 23, RESPONSE));
        assert_eq!(held.proto, "TCP", "held past the hole");
        let second = capture.send(true, &seal(&CLIENT_APP, 1, 23, REQUEST));
        if keys {
            assert_eq!(second.info, "GET /secret HTTP/1.1");
        } else {
            assert_eq!(second.info, "Application Data");
        }

        let end = capture.finish();
        assert!(end.tags.contains(&"missing"));
        assert_eq!(
            notes(&end, "Missing bytes"),
            [format!(
                "{TO_CLIENT}: {} bytes were not captured",
                lost.len()
            )]
        );
        assert_eq!(end.proto, "TLS");
        assert_eq!(end.info, "Not decoded: earlier bytes were not captured");
        assert!(layer(&end, HTTP).is_none());
        assert!(!end.tags.contains(&"decrypted"));
        let ends = notes(&end, "Stream end");
        assert!(
            ends.contains(&format!(
                "{TO_CLIENT}: the capture ended with bytes missing"
            )),
            "{ends:?}"
        );
    }
}

/// A capture that ends in the middle of a message says so: with keys, an
/// HTTP body shorter than its length; without, a TLS record cut short.
/// A capture that ends between messages ends its streams without that.
#[test]
fn a_capture_ending_mid_message_is_incomplete() {
    let cut = format!(
        "{TO_CLIENT}: the capture ended before the sender closed it, cutting a message short"
    );
    let mut capture = Capture::new(true);
    capture.send(true, &seal(&CLIENT_APP, 0, 23, REQUEST));
    let short = b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nonly ten b";
    capture.send(false, &seal(&SERVER_APP, 0, 23, short));
    let end = capture.finish();
    assert!(end.tags.contains(&"incomplete"));
    assert!(notes(&end, "Stream end").contains(&cut));

    let mut capture = Capture::new(false);
    let sealed = seal(&SERVER_APP, 0, 23, RESPONSE);
    let half = capture.send(false, &sealed[..sealed.len() / 2]);
    assert!(half.info.ends_with("[part of a longer message]"));
    let end = capture.finish();
    assert!(end.tags.contains(&"incomplete"));
    assert!(notes(&end, "Stream end").contains(&cut));

    for keys in [true, false] {
        let mut capture = Capture::new(keys);
        capture.send(true, &seal(&CLIENT_APP, 0, 23, REQUEST));
        capture.send(false, &seal(&SERVER_APP, 0, 23, RESPONSE));
        let end = capture.finish();
        assert!(!end.tags.contains(&"incomplete"));
        assert!(!end.tags.contains(&"missing"));
        let mut ends = notes(&end, "Stream end");
        ends.sort();
        let finalized = "the capture ended before the sender closed it";
        assert_eq!(
            ends,
            [
                format!("{TO_CLIENT}: {finalized}"),
                format!("{TO_SERVER}: {finalized}")
            ]
        );
    }
}

/// A FIN ends TLS's decrypted stream too: a request head the client
/// closed in the middle of is reported on the FIN, as a cut-off head is
/// over plain TCP.
#[test]
fn a_fin_ends_the_decrypted_stream() {
    let mut capture = Capture::new(true);
    let head = &REQUEST[..REQUEST.len() - 10];
    let open = capture.send(true, &seal(&CLIENT_APP, 0, 23, head));
    assert!(layer(&open, HTTP).is_none(), "{}", open.info);
    assert!(!open.tags.contains(&"malformed"));
    let fin = capture.fin(true);
    assert!(fin.tags.contains(&"malformed"), "{:?}", fin.tags);
    assert!(fin.info.starts_with("HTTP: "), "{}", fin.info);
}
