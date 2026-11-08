//! A world TLS session read back from its packets by the dissector: the
//! TCP observer, the passive TLS reader with the world's key log, and HTTP,
//! including an HTTP reader a capture owner copied and bound in.

use std::convert::Infallible;
use std::sync::Arc;

use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::dissect::{
    Decoded, Dissector, KeyLine, Layer, Match, Present, Registry, Selection,
};
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::services::ca::Ca;
use fictionet::stdlib::services::tls;
use fictionet::{Seed, block_on, lab};

use super::{Client, KeyObserver, Tap, client_config, server_config, tapped_pair};

const REQUEST: &[u8] = b"GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

/// Runs one HTTP exchange over TLS 1.3 in a lab: the world's TLS server,
/// a rustls client. Returns what each side wrote, the client's writes
/// marked, and the server's key log.
fn session() -> (Vec<(bool, Vec<u8>)>, Vec<KeyLine>) {
    let keys = Arc::new(KeyObserver::default());
    let tap = Tap::default();
    let (server_log, wire) = (keys.clone(), tap.clone());
    block_on(lab(Seed::from_u64(11), move |cx| async move {
        let ca = Ca::new(&cx, "Test CA")?;
        let mut config = (*server_config(&cx, &ca, "example.test", &[b"http/1.1"])).clone();
        config.key_log = server_log;
        let config = Arc::new(config);
        let (server_side, client_side) = tapped_pair(&wire);
        let server = cx.spawn(move |cx| async move {
            let mut conn = tls::server(&cx, server_side)
                .await?
                .finish(&cx, config)
                .await?;
            let mut request = Vec::new();
            let mut buf = [0; 256];
            while !request.ends_with(b"\r\n\r\n") {
                let n = conn.read(&cx, &mut buf).await?;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            assert_eq!(request, REQUEST);
            conn.write_all(&cx, RESPONSE).await?;
            conn.shutdown(&cx).await?;
            Ok(())
        });
        let client_config = client_config(&cx, &ca, &[b"http/1.1"]);
        let mut client = Client::connect(&cx, client_side, client_config, "example.test").await?;
        client.write_all(&cx, REQUEST).await?;
        let mut response = Vec::new();
        let mut buf = [0; 256];
        loop {
            let n = client.read(&cx, &mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }
        assert_eq!(response, RESPONSE);
        server.join(&cx).await?;
        Ok(())
    }))
    .unwrap();
    let keys = keys
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|(label, random, secret)| KeyLine {
            label: label.clone(),
            client_random: random.clone(),
            secret: secret.clone(),
        })
        .collect();
    let wire = tap.lock().unwrap().clone();
    (wire, keys)
}

/// The packets of the session: a handshake, then each write in segments
/// of at most 1,400 bytes, from 10.0.0.2:40000 (the client) to
/// 10.0.0.1:443 and back.
fn packets(wire: &[(bool, Vec<u8>)]) -> Vec<Vec<u8>> {
    fn packet(client: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (client_end, server_end) = (([10, 0, 0, 2], 40000u16), ([10, 0, 0, 1], 443u16));
        let ((src, sport), (dst, dport)) = if client {
            (client_end, server_end)
        } else {
            (server_end, client_end)
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
    let mut next = [1001u32, 9001];
    let mut out = vec![
        packet(true, 1000, 0x02, b""),
        packet(false, 9000, 0x12, b""),
    ];
    for (client, bytes) in wire {
        for segment in bytes.chunks(1400) {
            let seq = &mut next[usize::from(!client)];
            out.push(packet(*client, *seq, 0x18, segment));
            *seq = seq.wrapping_add(segment.len() as u32);
        }
    }
    out
}

fn decode(mut dissector: Dissector, packets: &[Vec<u8>], keys: &[KeyLine]) -> Vec<Decoded> {
    let mut decoded: Vec<_> = packets.iter().map(|p| dissector.decode(p, keys)).collect();
    decoded.push(dissector.finish(keys));
    decoded
}

/// With the server's key log, the request and response inside the world's
/// TLS come out as HTTP, read from the decrypted bytes. Without it, the
/// records stay encrypted and no HTTP comes out.
#[test]
fn the_dissector_reads_a_world_tls_session_from_its_packets() {
    let (wire, keys) = session();
    let packets = packets(&wire);
    let decoded = decode(Dissector::default(), &packets, &keys);
    for line in ["GET /secret HTTP/1.1", "HTTP/1.1 200 OK"] {
        let d = decoded
            .iter()
            .find(|d| d.info == line)
            .unwrap_or_else(|| panic!("{line}: {:?}", infos(&decoded)));
        assert_eq!(d.proto, "HTTP");
        assert!(d.tags.contains(&"decrypted"));
        let http = d
            .layers
            .iter()
            .find(|l| l.name == "Hypertext Transfer Protocol")
            .unwrap();
        assert_ne!(http.buf, 0, "HTTP is read from the decrypted bytes");
        assert_eq!(d.extra[http.buf - 1].0, "Decrypted TLS");
    }
    assert!(decoded.iter().all(|d| !d.tags.contains(&"malformed")));

    let blind = decode(Dissector::default(), &packets, &[]);
    assert!(blind.iter().any(|d| d.proto == "TLSv1.3"));
    assert!(
        blind
            .iter()
            .all(|d| d.proto != "HTTP" && !d.tags.contains(&"decrypted"))
    );
}

/// A capture owner's own HTTP/1 reader, cut down from the built-in one to
/// the first line of each message, binds into the passive path through
/// the public registry. TLS selects it for the decrypted stream by the
/// negotiated ALPN, in place of the built-in reader of that name.
#[test]
fn a_copied_reader_binds_into_the_passive_path() {
    struct FirstLines;
    impl Decode for FirstLines {
        type Item = String;
        type Error = Infallible;
        const NAME: &'static str = "First lines";
        fn capacity(&self) -> usize {
            4096
        }
        fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<String>, Infallible> {
            let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") else {
                return Ok(Step::Need);
            };
            let head = String::from_utf8_lossy(&input[..end]);
            let line = head.lines().next().unwrap_or_default().to_owned();
            Ok(Step::Item(line, end + 4))
        }
    }
    impl Present for FirstLines {
        fn summary(line: &String) -> String {
            line.clone()
        }
        fn fields(line: &String, _: &[u8], layer: &mut Layer) {
            layer.field("First line", line.clone(), (0, line.len()));
        }
    }
    let mut registry = Registry::default();
    registry.register(
        "http1",
        |s: Selection<'_>| {
            if s.alpn == Some("http/1.1") {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| [FirstLines, FirstLines],
    );
    let (wire, keys) = session();
    let decoded = decode(Dissector::with_registry(registry), &packets(&wire), &keys);
    for line in ["GET /secret HTTP/1.1", "HTTP/1.1 200 OK"] {
        let d = decoded
            .iter()
            .find(|d| d.info == line)
            .unwrap_or_else(|| panic!("{line}: {:?}", infos(&decoded)));
        assert_eq!(d.proto, "First lines");
        assert!(d.layers.iter().any(|l| l.name == "First lines"));
        assert!(d.tags.contains(&"decrypted"));
    }
    assert!(decoded.iter().all(|d| d.proto != "HTTP"));
}

fn infos(decoded: &[Decoded]) -> Vec<(&str, &str)> {
    decoded
        .iter()
        .map(|d| (d.proto.as_str(), d.info.as_str()))
        .collect()
}
