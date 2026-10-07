use fictionet::events::Transport;
use fictionet::observe::{Decoded, Dissector, Layer, Match, Present, Registry, Selection};
use fictionet::stdlib::codec::{Decode, Step};
use std::convert::Infallible;

// A user-owned protocol: one length byte followed by up to 255 payload bytes.
struct Tiny;
impl Decode for Tiny {
    type Item = Vec<u8>;
    type Error = Infallible;
    const NAME: &'static str = "Tiny";
    fn capacity(&self) -> usize {
        256
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, Infallible> {
        let Some(&len) = input.first() else {
            return Ok(Step::Need);
        };
        let end = 1 + usize::from(len);
        Ok(match input.get(1..end) {
            Some(payload) => Step::Item(payload.to_vec(), end),
            None => Step::Need,
        })
    }
}
impl Present for Tiny {
    fn summary(item: &Vec<u8>) -> String {
        format!("Message: {}", String::from_utf8_lossy(item))
    }
    fn fields(item: &Vec<u8>, _: &[u8], layer: &mut Layer) {
        layer.field("Length", item.len().to_string(), (0, 1));
        layer.field(
            "Payload",
            String::from_utf8_lossy(item),
            (1, 1 + item.len()),
        );
    }
}

fn registry() -> Registry {
    let mut registry = Registry::default();
    registry.register(
        "tiny",
        |s: Selection<'_>| {
            if s.transport == Transport::Tcp && (s.ports.0 == 9000 || s.ports.1 == 9000) {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| [Tiny, Tiny],
    );
    registry
}

fn tcp(seq: u32, flags: u8, bytes: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((40 + bytes.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&9000u16.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet.extend_from_slice(bytes);
    packet
}

fn tiny(d: &Decoded) -> Vec<&Layer> {
    d.layers.iter().filter(|l| l.name == "Tiny").collect()
}

#[test]
fn unidentified_prefixes_do_not_mark_packets_as_partial_messages() {
    let mut dissector = Dissector::with_registry(Registry::default());
    for (seq, bytes) in [(1, &b"hi\r\n"[..]), (5, &b"yo"[..])] {
        let mut packet = tcp(seq, 0x18, bytes);
        packet[22..24].copy_from_slice(&7u16.to_be_bytes());
        let decoded = dissector.decode(&packet, &[]);
        assert!(!decoded.info.contains("[part of a longer message]"));
    }
}

#[test]
fn a_user_decoder_places_split_and_batched_messages_in_packet_output() {
    let mut dissector = Dissector::with_registry(registry());
    dissector.decode(&tcp(100, 2, b""), &[]);
    let first = dissector.decode(&tcp(101, 0x18, b"\x05he"), &[]);
    assert!(tiny(&first).is_empty());
    assert!(first.info.ends_with("[part of a longer message]"));
    let middle = dissector.decode(&tcp(104, 0x18, b"l"), &[]);
    assert!(tiny(&middle).is_empty());
    // Completes the first message and carries two complete messages itself.
    let packet = tcp(105, 0x18, b"lo\x01!\x03bye");
    let done = dissector.decode(&packet, &[]);
    let layers = tiny(&done);
    assert_eq!(layers.len(), 3);
    assert_eq!((layers[0].buf, layers[0].range), (1, (0, 6)));
    assert_eq!(layers[0].fields[1].range, Some((1, 6)));
    assert_eq!(done.extra, [("Tiny".into(), b"\x05hello".to_vec())]);
    assert_eq!((layers[1].buf, layers[1].range), (0, (42, 44)));
    assert_eq!(layers[1].fields[1].range, Some((43, 44)));
    assert_eq!((layers[2].buf, layers[2].range), (0, (44, 48)));
    assert_eq!(layers[2].fields[1].range, Some((45, 48)));
    assert_eq!(done.proto, "Tiny");
    assert_eq!(done.info, "Message: hello, Message: !, Message: bye");
    let json = done.layers_json();
    assert!(json.contains(r#""name":"Tiny","summary":"Message: bye","buf":0,"range":[44,48]"#));
    let mut buffers = String::new();
    done.write_buffers(&mut buffers, &packet);
    assert!(buffers.contains(r#"{"name":"Tiny","hex":"0568656c6c6f"}"#));
}

#[test]
fn user_selection_by_prefix_and_explicit_name_runs_the_same_adapter() {
    for explicit in [false, true] {
        let mut registry = Registry::new();
        registry.register(
            "tiny",
            |s| {
                if s.first.starts_with(b"\x05hello") {
                    Match::Yes
                } else if b"\x05hello".starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            |_| [Tiny, Tiny],
        );
        if explicit {
            assert!(registry.choose(Transport::Tcp, "tiny"));
        }
        let mut dissector = Dissector::with_registry(registry);
        let mut seq = 1;
        for byte in b"\x05hello" {
            let done = dissector.decode(&tcp(seq, 0x18, &[*byte]), &[]);
            seq += 1;
            if seq == 7 {
                assert_eq!(done.proto, "Tiny");
                assert_eq!(tiny(&done)[0].range, (0, 6));
                assert_eq!(done.extra[0].1, b"\x05hello");
            }
        }
    }
}

#[test]
fn an_out_of_order_segment_still_places_completed_user_items() {
    let mut dissector = Dissector::with_registry(registry());
    dissector.decode(&tcp(100, 2, b""), &[]);
    dissector.decode(&tcp(104, 0x18, b"llo\x01!"), &[]);
    let done = dissector.decode(&tcp(101, 0x18, b"\x05he"), &[]);
    assert_eq!(done.info, "Message: hello, Message: !");
    let layers = tiny(&done);
    assert_eq!(layers.len(), 2);
    assert_eq!(done.extra[0].1, b"\x05hello");
    assert_eq!(done.extra[1].1, b"\x01!");
    assert!(layers.iter().all(|l| l.buf != 0));
}

#[test]
fn a_live_world_uses_the_registered_decoder_in_observe_json() {
    use fictionet::{
        Interface, InterfaceExt,
        relay::{self, Hello, Message, observer::Client, unix},
    };
    use std::os::fd::AsRawFd;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("fn-present-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("world.sock");
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone()), attacher).unwrap();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(move |cx| async move {
            cx.observe_protocols(registry());
            let Ok(mut sandbox) = attachments.next(&cx).await else {
                return Ok(());
            };
            while let Ok(packet) = sandbox.recv(&cx).await {
                sandbox.send(packet);
            }
            Ok(())
        }))
    });
    let mut client = Client::connect(path.to_str().unwrap(), "present-test").unwrap();
    client.set_timeout(Some(Duration::from_secs(10))).unwrap();
    client.request(r#"{"op":"watch"}"#).unwrap();
    let fd = unix::connect(&path).unwrap();
    let hello = Hello {
        version: relay::VERSION,
        mtu: 1500,
        kind: "tun".into(),
        name: "agent".into(),
    };
    unix::send(fd.as_raw_fd(), &Message::Hello(hello).encode(), false).unwrap();
    let mut buffer = vec![0; relay::MAX_MESSAGE + 1];
    let n = unix::recv(fd.as_raw_fd(), &mut buffer, false).unwrap();
    assert_eq!(relay::decode(&buffer[..n]), Ok(Message::Accept));
    let edge = loop {
        let value = client.next_value().unwrap().unwrap();
        let text = String::from_utf8(value.bytes).unwrap();
        if text.contains(r#""b":"s"#) {
            let start = text.find(r#""id":"e"#).unwrap() + 7;
            break text[start..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
        }
    };
    let subscription = client
        .request(&format!(r#"{{"op":"packets","link":"e{edge}"}}"#))
        .unwrap();
    loop {
        let value = client.next_value().unwrap().unwrap();
        if value.id == subscription && value.bytes.starts_with(br#"{"event":"link""#) {
            break;
        }
    }
    for packet in [
        tcp(100, 2, b""),
        tcp(101, 0x18, b"\x05he"),
        tcp(104, 0x18, b"llo\x01!"),
    ] {
        unix::send(fd.as_raw_fd(), &Message::Packet(&packet).encode(), false).unwrap();
    }
    let seq = loop {
        let value = client.next_value().unwrap().unwrap();
        let text = String::from_utf8(value.bytes).unwrap();
        if value.id == subscription && text.contains(r#""proto":"Tiny""#) {
            let start = text.find(r#""seq":"#).unwrap() + 6;
            break text[start..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
        }
    };
    let detail_id = client
        .request(&format!(
            r#"{{"op":"packet","link":"e{edge}","seq":{seq}}}"#
        ))
        .unwrap();
    loop {
        let value = client.next_value().unwrap().unwrap();
        if value.id == detail_id {
            let text = String::from_utf8(value.bytes).unwrap();
            assert!(
                text.contains(r#""name":"Tiny","summary":"Message: hello","buf":1,"range":[0,6]"#),
                "{text}"
            );
            assert!(
                text.contains(r#""name":"Payload","value":"!","range":[44,45]"#),
                "{text}"
            );
            break;
        }
    }
    drop(fd);
    drop(client);
    drop(listening);
    world.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
