use std::net::SocketAddr;

use crate::tcp_observer::Capture;
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::layer::{Direction, ObservedEvent};
use fictionet::stdlib::network::observer::Limits;
use fictionet::stdlib::{
    codec::{Demux, Wire},
    protocols::{grpc, hpack, http2},
};

/// The sender and receiver of direction 0, the client's, or 1.
fn ends(direction: usize) -> (SocketAddr, SocketAddr) {
    let a = "192.0.2.1:40000".parse().unwrap();
    let b = "192.0.2.2:50051".parse().unwrap();
    if direction == 0 { (a, b) } else { (b, a) }
}

/// The client's direction is the observer's forward one: the client sent
/// the first segment.
fn index(direction: Direction) -> usize {
    usize::from(direction == Direction::Reverse)
}
fn headers(
    encoder: &mut hpack::Encoder,
    stream: u32,
    fields: &[hpack::Field],
    end: bool,
) -> Vec<u8> {
    let mut fragment = Vec::new();
    encoder.encode_block(fields, &mut fragment).unwrap();
    let cut = fragment.len() / 2;
    let mut out = http2::Headers {
        stream,
        flags: u8::from(end),
        fragment: fragment[..cut].to_vec(),
        priority: None,
        padding: None,
    }
    .to_bytes()
    .unwrap();
    http2::Continuation {
        stream,
        flags: 4,
        fragment: fragment[cut..].to_vec(),
    }
    .write(&mut out)
    .unwrap();
    out
}
fn data(stream: u32, payload: &[u8], end: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<_> = payload.chunks(2).collect();
    for (i, part) in parts.iter().enumerate() {
        http2::Data {
            stream,
            flags: u8::from(end && i + 1 == parts.len()),
            data: part.to_vec(),
            padding: None,
        }
        .write(&mut out)
        .unwrap();
    }
    out
}
struct Stack {
    tcp: Capture,
    h2: [http2::Session; 2],
    calls: Demux<(usize, u32), Frames<grpc::Message>>,
    messages: Vec<(usize, u32, Vec<u8>)>,
    statuses: Vec<grpc::Status>,
    requests: Vec<grpc::Request>,
    gaps: usize,
    ends: usize,
}
impl Stack {
    fn new() -> Self {
        Self {
            tcp: Capture::new(Limits {
                buffered: 128,
                ..Default::default()
            }),
            h2: [
                http2::Session::client_side(Default::default()),
                http2::Session::server_side(Default::default()),
            ],
            calls: Demux::new(16, 1024, |_| Frames::<grpc::Message>::with_limit(128)),
            messages: Vec::new(),
            statuses: Vec::new(),
            requests: Vec::new(),
            gaps: 0,
            ends: 0,
        }
    }
    fn drain_calls(&mut self) {
        while let Some(((dir, stream), result)) = self.calls.next() {
            self.messages.push((dir, stream, result.unwrap().data));
        }
    }
    fn event(&mut self, dir: usize, event: http2::Event) {
        match event {
            http2::Event::Headers {
                stream,
                fields,
                end,
            } => {
                if dir == 0 {
                    self.h2[1].peer_open(stream).unwrap();
                    self.requests.push(
                        grpc::Request::parse(fields.iter().map(|f| (&f.name, &f.value))).unwrap(),
                    );
                }
                if end {
                    self.calls.end(&(dir, stream));
                    self.drain_calls();
                    self.calls.remove(&(dir, stream));
                }
            }
            http2::Event::Data { stream, data, end } => {
                let mut rest = data.as_slice();
                while !rest.is_empty() {
                    let n = self.calls.push(&(dir, stream), rest);
                    assert!(n > 0);
                    rest = &rest[n..];
                    self.drain_calls();
                }
                if end {
                    self.calls.end(&(dir, stream));
                    self.drain_calls();
                    self.calls.remove(&(dir, stream));
                }
            }
            http2::Event::Trailers { stream, fields } => {
                self.calls.end(&(dir, stream));
                self.drain_calls();
                self.calls.remove(&(dir, stream));
                self.statuses.push(grpc::Status::from_trailers(
                    fields.iter().map(|f| (&f.name, &f.value)),
                ));
            }
            http2::Event::Settings(s) => self.h2[1 - dir].peer_settings(&s).unwrap(),
            http2::Event::WindowUpdate(w) => self.h2[1 - dir].peer_window_update(&w).unwrap(),
            http2::Event::Reset { stream, .. } => {
                self.h2[1 - dir].peer_reset(stream);
                self.calls.remove(&(dir, stream));
                self.calls.remove(&(1 - dir, stream));
            }
            _ => {}
        }
    }
    fn segment(&mut self, dir: usize, seq: u32, flags: u8, payload: &[u8]) {
        let (from, to) = ends(dir);
        let ack = if dir == 1 { 101 } else { 0 };
        for event in self.tcp.segment(from, to, seq, ack, flags, payload) {
            match event {
                ObservedEvent::Data {
                    direction, bytes, ..
                } => {
                    let dir = index(direction);
                    let mut rest = &bytes[..];
                    while !rest.is_empty() {
                        let n = self.h2[dir].push(rest);
                        rest = &rest[n..];
                        while let Some(event) = self.h2[dir].next() {
                            self.event(dir, event.unwrap());
                        }
                        assert!(n > 0);
                    }
                }
                ObservedEvent::Gap { direction, .. } => {
                    let dir = index(direction);
                    self.h2[dir].lost();
                    // This test uses streams 1 and 5. A world keeps its active
                    // call keys and removes all keys of the affected direction.
                    for stream in [1, 5] {
                        self.calls.remove(&(dir, stream));
                    }
                    self.gaps += 1;
                }
                ObservedEvent::End { direction, .. } => {
                    let dir = index(direction);
                    self.h2[dir].end();
                    while let Some(event) = self.h2[dir].next() {
                        self.event(dir, event.unwrap());
                    }
                    for stream in [1, 5] {
                        self.calls.end(&(dir, stream));
                    }
                    self.drain_calls();
                    self.ends += 1;
                }
            }
        }
        assert!(self.calls.total() <= 1024);
    }
    fn reordered(&mut self, dir: usize, mut seq: u32, bytes: &[u8]) -> u32 {
        for pair in bytes.chunks(14) {
            let cut = pair.len().min(7);
            if cut < pair.len() {
                self.segment(dir, seq + cut as u32, 0x18, &pair[cut..]);
            }
            self.segment(dir, seq, 0x18, &pair[..cut]);
            seq += pair.len() as u32;
        }
        seq
    }
}
#[test]
fn peer_resets_allow_repeated_stream_retirement() {
    let mut stack = Stack::new();
    stack.segment(0, 100, 2, &[]);
    stack.segment(1, 200, 0x12, &[]);
    let settings = http2::Settings {
        flags: 0,
        entries: vec![],
    }
    .to_bytes()
    .unwrap();
    let mut client_seq = stack.reordered(0, 101, &[http2::PREFACE.as_slice(), &settings].concat());
    let mut server_seq = stack.reordered(1, 201, &settings);
    let mut encoder = hpack::Encoder::new(0);
    for stream in (1..601).step_by(2) {
        server_seq = stack.reordered(
            1,
            server_seq,
            &headers(
                &mut encoder,
                stream,
                &[hpack::Field::new(":status", "200")],
                false,
            ),
        );
        client_seq = stack.reordered(
            0,
            client_seq,
            &http2::Reset {
                stream,
                flags: 0,
                code: 8,
            }
            .to_bytes()
            .unwrap(),
        );
        assert!(stack.h2[1].retire(stream));
    }
    assert!(stack.h2[1].failed().is_none());
}

#[test]
fn request_opening_retains_credit_before_response_headers() {
    let mut stack = Stack::new();
    stack.segment(0, 100, 2, &[]);
    stack.segment(1, 200, 0x12, &[]);
    let settings = http2::Settings {
        flags: 0,
        entries: vec![],
    }
    .to_bytes()
    .unwrap();
    let request = grpc::Request::new(
        grpc::MethodPath::new("echo.Service", "Call").unwrap(),
        grpc::ContentType::plain(),
    );
    let fields: Vec<_> = request
        .to_headers()
        .unwrap()
        .into_iter()
        .map(|(n, v)| hpack::Field::new(n, v))
        .collect();
    let mut client = [http2::PREFACE.as_slice(), &settings].concat();
    client.extend(headers(&mut hpack::Encoder::new(0), 1, &fields, true));
    for stream in [1, 0] {
        http2::WindowUpdate {
            stream,
            flags: 0,
            increment: 65_536,
        }
        .write(&mut client)
        .unwrap();
    }
    let mut client_seq = stack.reordered(0, 101, &client);
    assert_eq!(stack.h2[1].stream_window(1), Some(131_071));
    let mut server = settings;
    server.extend(headers(
        &mut hpack::Encoder::new(0),
        1,
        &[hpack::Field::new(":status", "200")],
        false,
    ));
    let message = grpc::Message {
        compressed: false,
        data: vec![b'x'; 59],
    }
    .to_bytes()
    .unwrap();
    for i in 0..4 {
        http2::Data {
            stream: 1,
            flags: u8::from(i == 3),
            data: message.repeat(256),
            padding: None,
        }
        .write(&mut server)
        .unwrap();
    }
    stack.reordered(1, 201, &server);
    assert_eq!(stack.messages.len(), 1024);
    assert!(
        stack
            .messages
            .iter()
            .all(|(dir, stream, data)| *dir == 1 && *stream == 1 && data.as_slice() == [b'x'; 59])
    );
    assert_eq!(stack.h2[1].stream_window(1), Some(65_535));
    assert_eq!(stack.h2[1].connection_window(), 65_535);
    assert!(stack.h2[0].retire(1));
    assert!(stack.h2[1].retire(1));
    for _ in 0..2 {
        client_seq = stack.reordered(
            0,
            client_seq,
            &http2::WindowUpdate {
                stream: 1,
                flags: 0,
                increment: http2::MAX_WINDOW,
            }
            .to_bytes()
            .unwrap(),
        );
    }
    assert_eq!(stack.h2[1].stream_window(1), None);
    assert!(stack.h2[1].failed().is_none());
}

#[test]
fn tcp_to_http2_to_grpc_with_reordering_fragments_trailers_and_a_gap() {
    let mut stack = Stack::new();
    stack.segment(0, 100, 2, &[]);
    stack.segment(1, 200, 0x12, &[]);
    let settings = http2::Settings {
        flags: 0,
        entries: vec![],
    }
    .to_bytes()
    .unwrap();
    let mut request_encoder = hpack::Encoder::new(4096);
    let mut response_encoder = hpack::Encoder::new(4096);
    let request = grpc::Request::new(
        grpc::MethodPath::new("echo.Service", "Call").unwrap(),
        grpc::ContentType::plain(),
    );
    let request_fields: Vec<_> = request
        .to_headers()
        .unwrap()
        .into_iter()
        .map(|(n, v)| hpack::Field::new(n, v))
        .collect();
    let mut client = [http2::PREFACE.as_slice(), &settings].concat();
    client.extend(headers(&mut request_encoder, 1, &request_fields, false));
    let request_message = grpc::Message {
        compressed: false,
        data: b"request body".to_vec(),
    }
    .to_bytes()
    .unwrap();
    client.extend(data(1, &request_message, true));
    let mut client_seq = stack.reordered(0, 101, &client);
    let mut server = settings;
    server.extend(headers(
        &mut response_encoder,
        1,
        &[
            hpack::Field::new(":status", "200"),
            hpack::Field::new("content-type", "application/grpc"),
        ],
        false,
    ));
    let response_message = grpc::Message {
        compressed: false,
        data: b"response body".to_vec(),
    }
    .to_bytes()
    .unwrap();
    server.extend(data(1, &response_message, false));
    server.extend(headers(
        &mut response_encoder,
        1,
        &[hpack::Field::new("grpc-status", "0")],
        true,
    ));
    let server_seq = stack.reordered(1, 201, &server);
    assert_eq!(
        stack.messages,
        [
            (0, 1, b"request body".to_vec()),
            (1, 1, b"response body".to_vec())
        ]
    );
    assert_eq!(stack.statuses, [grpc::Status::ok()]);
    assert_eq!(stack.requests[0].path, request.path);
    assert_eq!(stack.calls.total(), 0);
    // A second request holds partial gRPC and HPACK input when TCP loses bytes.
    let mut pending = headers(&mut request_encoder, 5, &request_fields, false);
    pending.extend(data(5, &request_message[..2], false));
    http2::Headers {
        stream: 7,
        flags: 0,
        fragment: vec![0x40, 1, b'x'],
        priority: None,
        padding: None,
    }
    .write(&mut pending)
    .unwrap();
    client_seq = stack.reordered(0, client_seq, &pending);
    assert!(stack.h2[0].held() > 0);
    assert_eq!(stack.calls.total(), 2);
    // Bytes after a hole are held. A segment past the bound makes the
    // observer give up on the hole and skip to them.
    stack.segment(0, client_seq + 100, 0x18, &[0; 8]);
    assert_eq!(stack.gaps, 0);
    stack.segment(0, client_seq + 200, 0x18, &[0; 256]);
    assert_eq!(stack.gaps, 1);
    assert!(stack.h2[0].is_done());
    assert_eq!(stack.h2[0].held(), 0);
    assert_eq!(stack.calls.total(), 0);
    // The other direction remains readable and ends normally.
    stack.segment(1, server_seq, 0x11, &[]);
    assert_eq!(stack.ends, 1);
    assert!(stack.h2[1].failed().is_none());
}
