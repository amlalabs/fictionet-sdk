use super::*;
use fictionet::stdlib::layer::{Driver, Observations};
use fictionet::{Seed, SeededEntropy};
use std::sync::Arc;

struct Test {
    driver: Driver<Http3>,
    lower: Slots<()>,
}

impl Test {
    fn new() -> Self {
        Self::with_profile(Arc::new(Standard))
    }
    fn with_profile(profile: Arc<dyn Profile>) -> Self {
        Self {
            driver: Driver::new(
                Http3::new(Limits::default()).profile(profile),
                Arc::new(SeededEntropy::new(Seed::from_u64(8))),
                Budget::new(32 << 20),
                Instant::ZERO,
            ),
            lower: Slots::new(32),
        }
    }
    fn open(&mut self, stream: u64) -> ChildId {
        let child = self.lower.insert(()).unwrap();
        let id = child.id();
        let stream = Stream {
            id: quinn_proto::StreamId::from(VarInt::from_u64(stream).unwrap()),
            local: stream % 4 == 3,
        };
        assert!(matches!(
            self.driver
                .deliver(MuxEvent::Opened(child, stream, WINDOW))
                .unwrap(),
            Admit::Taken
        ));
        id
    }
    fn deliver(&mut self, id: ChildId, bytes: &[u8], fin: bool) {
        let bytes = Chunk::copy_of(self.driver.budget(), bytes).unwrap();
        assert!(matches!(
            self.driver
                .deliver(MuxEvent::Child(id, StreamEvent::Data(bytes)))
                .unwrap(),
            Admit::Taken
        ));
        if fin {
            assert!(matches!(
                self.driver
                    .deliver(MuxEvent::Child(id, StreamEvent::Ended))
                    .unwrap(),
                Admit::Taken
            ));
        }
        self.driver.run().unwrap();
    }
    fn event(&mut self) -> Option<Up> {
        self.driver.layer_mut().take_event()
    }
    fn closed(&mut self) -> Option<u64> {
        for _ in 0..128 {
            self.driver.run().unwrap();
            if let Some(command) = self.driver.take_command() {
                if let MuxOp::Control(ControlCommand::Close(code)) = command.op() {
                    return Some(code.into_inner());
                }
            } else {
                break;
            }
        }
        None
    }
    fn request(&mut self, stream: u64, length: Option<&str>) -> (ChildId, Child) {
        let lower = self.open(stream);
        let mut fields = vec![
            qpack::Field::new(":method", "POST"),
            qpack::Field::new(":scheme", "https"),
            qpack::Field::new(":authority", "localhost"),
            qpack::Field::new(":path", "/echo"),
        ];
        if let Some(length) = length {
            fields.push(qpack::Field::new("content-length", length));
        }
        self.deliver(lower, &headers(stream, fields), false);
        let Some(MuxEvent::Opened(child, opening, _)) = self.event() else {
            panic!("exchange opened");
        };
        assert_eq!(
            opening.head.version(),
            crate::stdlib::protocols::http1::Version::Http3
        );
        self.driver.run().unwrap();
        assert!(matches!(self.event(), Some(MuxEvent::Credit(_, WINDOW))));
        (lower, child)
    }
}

/// Advertises no dynamic table and never uses the peer's.
struct StaticOnly;
impl qpack::Policy for StaticOnly {
    fn capacity(&self, _: u64) -> u64 {
        0
    }
    fn insert(&self, _: &qpack::Field, _: &qpack::Table) -> bool {
        false
    }
    fn style(&self) -> qpack::Style {
        qpack::Style::DEFAULT
    }
}
impl Profile for StaticOnly {
    fn settings(&self) -> &[Setting] {
        &[]
    }
    fn streams(&self) -> &[Local] {
        &[Local::Control]
    }
    fn reserved_frames(&self) -> &[&'static [u8]] {
        &[]
    }
}

fn headers(stream: u64, fields: Vec<qpack::Field>) -> Vec<u8> {
    let mut encoder = qpack::Encoder::new(0, wire::MAX_FIELD_SECTION_SIZE);
    wire::Frame::headers(&encoder.section(stream, &fields).unwrap())
        .unwrap()
        .to_bytes()
        .unwrap()
}

#[test]
fn critical_streams_are_unique_even_when_prefixes_are_fragmented() {
    for kind in [0, 2, 3] {
        let mut t = Test::new();
        let first = t.open(2);
        let second = t.open(6);
        t.deliver(first, &[0x40], false);
        assert_eq!(t.closed(), None);
        t.deliver(first, &[kind], false);
        assert_eq!(t.closed(), None);
        t.deliver(second, &[kind], false);
        assert_eq!(t.closed(), Some(code::STREAM_CREATION_ERROR));
    }
}

#[test]
fn critical_fin_and_reset_are_connection_errors() {
    for kind in [0, 2, 3] {
        for reset in [false, true] {
            let mut t = Test::new();
            let lower = t.open(2);
            t.deliver(lower, &[kind], false);
            let event = if reset {
                StreamEvent::ReceiveReset(17u32.into())
            } else {
                StreamEvent::Ended
            };
            assert!(matches!(
                t.driver.deliver(MuxEvent::Child(lower, event)).unwrap(),
                Admit::Taken
            ));
            assert_eq!(t.closed(), Some(code::CLOSED_CRITICAL_STREAM));
        }
    }
}

#[test]
fn control_requires_settings_and_forbids_repetition() {
    let mut t = Test::new();
    let lower = t.open(2);
    t.deliver(lower, &[0, 7, 1, 0], false);
    assert_eq!(t.closed(), Some(code::MISSING_SETTINGS));
    let mut t = Test::new();
    let lower = t.open(2);
    t.deliver(lower, &[0, 4, 0, 4, 0], false);
    assert_eq!(t.closed(), Some(code::FRAME_UNEXPECTED));
}

#[test]
fn zero_capacity_rejects_dynamic_qpack_and_push_streams() {
    let mut t = Test::with_profile(Arc::new(StaticOnly));
    let lower = t.open(2);
    t.deliver(lower, &[2, 0x21], false);
    assert_eq!(t.closed(), Some(code::QPACK_ENCODER_STREAM_ERROR));
    let mut t = Test::new();
    let lower = t.open(2);
    t.deliver(lower, &[1, 0], false);
    assert_eq!(t.closed(), Some(code::STREAM_CREATION_ERROR));
}

#[test]
fn coalesced_critical_stream_items_keep_their_remainder() {
    let mut t = Test::new();
    let mut settings = vec![0];
    wire::Frame::Settings(wire::Settings {
        entries: vec![
            wire::Setting {
                id: wire::setting::MAX_FIELD_SECTION_SIZE,
                value: crate::stdlib::protocols::quic::MAX_VARINT,
            },
            wire::Setting {
                id: wire::setting::QPACK_MAX_TABLE_CAPACITY,
                value: 4096,
            },
            wire::Setting {
                id: wire::setting::QPACK_BLOCKED_STREAMS,
                value: 16,
            },
        ],
    })
    .write(&mut settings)
    .unwrap();
    let mut decoder = vec![3];
    let mut encoder = vec![2];
    for stream in (0..80).step_by(4) {
        qpack::DecoderInstruction::StreamCancel(stream)
            .write(&mut decoder)
            .unwrap();
        qpack::EncoderInstruction::SetCapacity(4096)
            .write(&mut encoder)
            .unwrap();
    }
    for (stream, bytes) in [(2, settings), (6, decoder), (10, encoder)] {
        let lower = t.open(stream);
        let mut event = MuxEvent::Child(
            lower,
            StreamEvent::Data(Chunk::copy_of(t.driver.budget(), &bytes).unwrap()),
        );
        let mut delivered = false;
        for _ in 0..bytes.len() + 1 {
            match t.driver.deliver(event).unwrap() {
                Admit::Taken => {
                    delivered = true;
                    break;
                }
                Admit::Partial(rest) | Admit::Blocked(rest) => event = rest,
                Admit::Closed(_) => panic!("valid critical stream delivery was refused"),
            }
            t.driver.run().unwrap();
        }
        assert!(delivered, "all coalesced bytes must be admitted");
        t.driver.run().unwrap();
        assert_eq!(t.closed(), None);
        let id = t.driver.layer().channel(lower).unwrap();
        assert_eq!(
            t.driver.layer().channels.get(id).unwrap().input.buffered(),
            0
        );
    }
    assert_eq!(t.driver.layer().decoder.capacity(), 4096);
    assert_eq!(t.driver.layer().encoder.table().capacity(), 4096);
}

#[test]
fn unknown_streams_do_not_occupy_critical_stream_types() {
    let mut t = Test::new();
    let unknown = t.open(2);
    t.deliver(unknown, &[0x21, 0, 4, 0], true);
    assert_eq!(t.closed(), None);
    let control = t.open(6);
    t.deliver(control, &[0, 4, 0], false);
    assert_eq!(t.closed(), None);
}

#[test]
fn blocked_request_does_not_block_siblings_or_control() {
    let mut t = Test::new();
    let (first, _) = t.request(0, Some("4"));
    t.deliver(
        first,
        &wire::Frame::Data(b"body".to_vec()).to_bytes().unwrap(),
        false,
    );
    assert!(t.event().is_none());
    let (second, child) = t.request(4, Some("0"));
    t.deliver(second, &[], true);
    assert!(matches!(t.event(), Some(MuxEvent::Child(id, ExchangeEvent::End)) if id == child.id()));
    let control = t.open(2);
    t.deliver(control, &[0, 4, 0], false);
    assert_eq!(t.closed(), None);
    assert!(t.driver.layer().critical.control);
}

#[test]
fn trailers_wait_for_fin_and_content_length_validation() {
    for length in ["4", "5"] {
        let mut t = Test::new();
        let (lower, child) = t.request(0, Some(length));
        assert!(matches!(
            t.driver.command(child.grant(4)).unwrap(),
            Admit::Taken
        ));
        t.deliver(
            lower,
            &wire::Frame::Data(b"body".to_vec()).to_bytes().unwrap(),
            false,
        );
        assert!(
            matches!(t.event(), Some(MuxEvent::Child(_, ExchangeEvent::Data(data))) if &*data == b"body")
        );
        t.deliver(
            lower,
            &headers(0, vec![qpack::Field::new("x-trailer", "end")]),
            false,
        );
        assert!(t.event().is_none());
        t.deliver(lower, &[], true);
        if length == "4" {
            assert!(
                matches!(t.event(), Some(MuxEvent::Child(_, ExchangeEvent::Trailers(trailers))) if trailers.fields().get(b"x-trailer") == Some(b"end".as_slice()))
            );
        } else {
            assert!(matches!(
                t.event(),
                Some(MuxEvent::Child(
                    _,
                    ExchangeEvent::Closed {
                        why: Ending::ApplicationReset(code::MESSAGE_ERROR),
                        ..
                    }
                ))
            ));
        }
        assert_eq!(t.closed(), None);
    }
}

#[test]
fn stopped_response_retires_only_its_exchange() {
    let mut t = Test::new();
    let (lower, first) = t.request(0, None);
    let (_, second) = t.request(4, None);
    assert!(matches!(
        t.driver
            .deliver(MuxEvent::Child(
                lower,
                StreamEvent::SendStopped(0x10cu32.into())
            ))
            .unwrap(),
        Admit::Taken
    ));
    t.driver.run().unwrap();
    assert!(
        matches!(t.event(), Some(MuxEvent::Child(id, ExchangeEvent::Closed { .. })) if id == first.id())
    );
    assert!(t.driver.layer().exchanges.contains(second.id()));
    assert_eq!(t.closed(), None);
}

#[test]
fn head_timeout_uses_injected_time_and_preserves_siblings() {
    let mut t = Test::new();
    let stalled = t.open(0);
    let (_, sibling) = t.request(4, None);
    t.driver
        .set_now(Instant::ZERO + std::time::Duration::from_secs(30));
    t.driver.run().unwrap();
    assert!(
        t.driver
            .layer()
            .channels
            .get(t.driver.layer().channel(stalled).unwrap())
            .unwrap()
            .reset
            .is_some()
    );
    assert!(t.driver.layer().exchanges.contains(sibling.id()));
    assert_eq!(t.closed(), None);
}

#[test]
fn data_framing_refuses_before_allocating_or_consuming_body() {
    let budget = Budget::new(19);
    assert!(data_frame(&budget, b"body").is_none());
    assert_eq!(budget.used(), 0);
    let budget = Budget::new(20);
    let frame = data_frame(&budget, b"body").unwrap();
    assert_eq!(
        wire::Frame::parse(&frame).unwrap(),
        wire::Frame::Data(b"body".to_vec())
    );
    drop(frame);
    assert_eq!(budget.used(), 0);
}

#[test]
fn write_completion_can_pass_a_blocked_receive_event() {
    let mut t = Test::new();
    let (lower, child) = t.request(0, None);
    let id = *t.driver.layer().exchanges.get(child.id()).unwrap();
    let bytes = Chunk::copy_of(t.driver.budget(), b"frame").unwrap();
    let channel = t.driver.layer_mut().channels.get_mut(id).unwrap();
    channel.sending = Some(Sending {
        bytes: Chunk::default(),
        flight: bytes.len() as u64,
        body: 3,
    });
    t.driver.layer_mut().up = Some(MuxEvent::Child(child.id(), ExchangeEvent::Data(bytes)));
    assert!(matches!(
        t.driver
            .deliver(MuxEvent::Child(lower, StreamEvent::Written(5)))
            .unwrap(),
        Admit::Taken
    ));
    assert!(
        matches!(t.driver.layer_mut().take_urgent(), Some(MuxEvent::Child(id, ExchangeEvent::Written(3))) if id == child.id())
    );
    assert!(matches!(
        t.event(),
        Some(MuxEvent::Child(_, ExchangeEvent::Data(_)))
    ));
}

#[test]
fn rejected_initial_storage_leaves_the_lower_event_owned() {
    let entropy = SeededEntropy::new(Seed::from_u64(9));
    let budget = Budget::new(0);
    let mut observations = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut observations);
    let mut h3 = Http3::new(Limits::default());
    assert!(matches!(
        h3.on_event(&mut env, MuxEvent::Control(ControlEvent::Connected))
            .unwrap(),
        Admit::Blocked(MuxEvent::Control(ControlEvent::Connected))
    ));
    assert!(!h3.connected);
    assert!(!h3.initialized);
    assert_eq!(budget.used(), 0);
}

#[test]
fn zero_length_data_does_not_hide_the_fin() {
    let mut t = Test::new();
    let (lower, child) = t.request(0, Some("0"));
    t.deliver(lower, &[0, 0], true);
    assert!(matches!(t.event(), Some(MuxEvent::Child(id, ExchangeEvent::End)) if id == child.id()));
}

#[test]
fn response_waiting_for_transport_credit_times_out_alone() {
    let mut t = Test::new();
    let (_, child) = t.request(0, None);
    let (_, sibling) = t.request(4, None);
    assert!(matches!(
        t.driver
            .command(child.send(ExchangeCommand::Head(Box::new(
                super::super::ResponseHead {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    end: true,
                }
            ))))
            .unwrap(),
        Admit::Taken
    ));
    t.driver
        .set_now(Instant::ZERO + std::time::Duration::from_secs(30));
    t.driver.run().unwrap();
    assert!(
        matches!(t.event(), Some(MuxEvent::Child(id, ExchangeEvent::Closed { .. })) if id == child.id())
    );
    assert!(t.driver.layer().exchanges.contains(sibling.id()));
    assert_eq!(t.closed(), None);
}

#[test]
fn goaway_cutoff_keeps_admitted_and_lower_numbered_requests() {
    let mut t = Test::new();
    let (_, first) = t.request(8, None);
    t.driver.layer_mut().graceful_shutdown();
    assert_eq!(t.driver.layer().shutdown, Some(12));
    let (_, older) = t.request(4, None);
    let rejected = t.open(12);
    t.deliver(
        rejected,
        &headers(
            12,
            vec![
                qpack::Field::new(":method", "GET"),
                qpack::Field::new(":scheme", "https"),
                qpack::Field::new(":authority", "localhost"),
                qpack::Field::new(":path", "/"),
            ],
        ),
        true,
    );
    assert!(t.event().is_none());
    let channel = t
        .driver
        .layer()
        .channels
        .get(t.driver.layer().channel(rejected).unwrap())
        .unwrap();
    assert_eq!(channel.reset, Some(code::REQUEST_REJECTED));
    assert!(t.driver.layer().exchanges.contains(first.id()));
    assert!(t.driver.layer().exchanges.contains(older.id()));
}

#[test]
fn qpack_sensitive_marks_survive_request_and_response_conversion() {
    let mut field = qpack::Field::new("authorization", "private");
    field.never_index = true;
    let budget = Budget::new(32 << 20);
    let fields = Http3::fields(
        &budget,
        wire::HeaderList {
            fields: vec![field],
        },
    )
    .unwrap();
    assert!(fields.iter_marked().next().unwrap().2);

    let entropy = SeededEntropy::new(Seed::from_u64(17));
    let mut reports = Observations::new(0);
    let env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
    let mut h3 = Http3::new(Limits::default());
    let mut headers = http::HeaderMap::new();
    let mut value = http::HeaderValue::from_static("private");
    value.set_sensitive(true);
    headers.insert("authorization", value);
    let encoded = h3
        .encode_headers(&env, 0, Some(http::StatusCode::OK), &headers)
        .unwrap();
    let wire::Frame::Headers(bytes) = wire::Frame::parse(&encoded).unwrap() else {
        panic!("HEADERS frame");
    };
    let qpack::SectionResult::Fields { fields, .. } =
        qpack::decode_section(&qpack::Table::new(0), 0, &bytes).unwrap()
    else {
        panic!("static field section");
    };
    assert!(
        fields
            .iter()
            .any(|f| f.name == b"authorization" && f.value == b"private" && f.never_index)
    );
}

#[test]
fn draining_does_not_discard_data_after_engine_admission() {
    let mut t = Test::new();
    t.driver.layer_mut().opening = true;
    let lower = t.open(3);
    let id = t.driver.layer().channel(lower).unwrap();
    t.driver
        .layer_mut()
        .channels
        .get_mut(id)
        .unwrap()
        .response_started = true;
    t.driver.layer_mut().goaway_sent = true;
    t.driver.layer_mut().graceful_shutdown();
    t.driver.run().unwrap();
    assert!(t.driver.layer().exchanges.is_empty());
    assert!(!t.driver.layer().closing);
    assert!(t.driver.take_command().is_none());
}

#[test]
fn a_small_response_head_reserves_only_its_encoded_output() {
    let budget = Budget::new(SCRATCH + 256);
    let entropy = SeededEntropy::new(Seed::from_u64(18));
    let mut reports = Observations::new(0);
    let env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
    let mut h3 = Http3::new(Limits::default());
    let encoded = h3
        .encode_headers(&env, 0, Some(http::StatusCode::OK), &http::HeaderMap::new())
        .unwrap();
    assert!(matches!(
        wire::Frame::parse(&encoded),
        Ok(wire::Frame::Headers(_))
    ));
    assert!(budget.used() <= 256);
}

/// Sends reserved SETTINGS, a reserved stream and reserved frames, and
/// writes Huffman code on ties.
struct Greased;
impl qpack::Policy for Greased {
    fn capacity(&self, _: u64) -> u64 {
        0
    }
    fn insert(&self, _: &qpack::Field, _: &qpack::Table) -> bool {
        false
    }
    fn style(&self) -> qpack::Style {
        qpack::Style {
            huffman: qpack::Huffman::NotLonger,
            never_index: false,
        }
    }
}
impl Profile for Greased {
    fn settings(&self) -> &[Setting] {
        &[
            Setting::Reserved,
            Setting::FieldSectionSize(1 << 12),
            Setting::QpackTableCapacity(1024),
        ]
    }
    fn streams(&self) -> &[Local] {
        &[Local::Control, Local::Decoder, Local::Reserved(b"reserved")]
    }
    fn reserved_frames(&self) -> &[&'static [u8]] {
        &[b"", b"reserved"]
    }
}

fn is_reserved(id: u64) -> bool {
    id >= 0x21 && (id - 0x21).is_multiple_of(0x1f)
}

/// Reads the frames in `bytes` as (type, payload) pairs.
fn frames(mut bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    use crate::stdlib::protocols::quic::read_varint;
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (kind, n) = read_varint(bytes).unwrap();
        let (length, m) = read_varint(&bytes[n..]).unwrap();
        let start = n + m;
        let end = start + length as usize;
        out.push((kind, bytes[start..end].to_vec()));
        bytes = &bytes[end..];
    }
    out
}

/// What the connection wrote on one local stream, and whether it ended it.
#[derive(Default)]
struct Written {
    bytes: Vec<u8>,
    ended: bool,
}

impl Test {
    fn take(&mut self, event: Input) {
        assert!(matches!(self.driver.deliver(event).unwrap(), Admit::Taken));
    }

    /// Plays a peer that allows `allowed` server unidirectional streams,
    /// and returns what the connection wrote on each one it opened.
    fn local_streams(&mut self, allowed: usize) -> Vec<Written> {
        self.take(MuxEvent::Control(ControlEvent::Connected));
        let mut streams: Vec<(ChildId, Written)> = Vec::new();
        for _ in 0..256 {
            self.driver.run().unwrap();
            let Some(command) = self.driver.take_command() else {
                break;
            };
            match command.into_op() {
                MuxOp::Control(ControlCommand::OpenOrClose { .. }) => {
                    assert!(streams.len() < allowed, "a required stream was refused");
                    let lower = self.open(3 + 4 * streams.len() as u64);
                    streams.push((lower, Written::default()));
                    self.take(MuxEvent::Credit(lower, 1 << 16));
                }
                MuxOp::Control(ControlCommand::OpenIfAllowed(Dir::Uni)) => {
                    if streams.len() < allowed {
                        let lower = self.open(3 + 4 * streams.len() as u64);
                        streams.push((lower, Written::default()));
                        self.take(MuxEvent::Credit(lower, 1 << 16));
                    } else {
                        self.take(MuxEvent::Control(ControlEvent::Unopened(Dir::Uni)));
                    }
                }
                MuxOp::Child(lower, StreamCommand::Write(bytes)) => {
                    let n = bytes.len() as u64;
                    let (_, written) = streams.iter_mut().find(|(l, _)| *l == lower).unwrap();
                    written.bytes.extend_from_slice(&bytes);
                    self.take(MuxEvent::Child(lower, StreamEvent::Written(n)));
                }
                MuxOp::Child(lower, StreamCommand::End) => {
                    streams
                        .iter_mut()
                        .find(|(l, _)| *l == lower)
                        .unwrap()
                        .1
                        .ended = true;
                }
                MuxOp::Control(ControlCommand::Close(code)) => {
                    panic!("connection closed with {:#x}", code.into_inner())
                }
                _ => {}
            }
        }
        streams.into_iter().map(|(_, written)| written).collect()
    }

    /// Answers a request on `stream` and returns the bytes written on it.
    fn respond(&mut self, stream: u64) -> Vec<u8> {
        let (lower, child) = self.request(stream, Some("0"));
        self.deliver(lower, &[], true);
        self.take(MuxEvent::Credit(lower, 1 << 16));
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(matches!(
            self.driver
                .command(child.send(ExchangeCommand::Head(Box::new(
                    super::super::ResponseHead {
                        status: http::StatusCode::OK,
                        headers,
                        end: true,
                    }
                ))))
                .unwrap(),
            Admit::Taken
        ));
        let mut written = Vec::new();
        for _ in 0..64 {
            self.driver.run().unwrap();
            let Some(command) = self.driver.take_command() else {
                break;
            };
            if let MuxOp::Child(id, StreamCommand::Write(bytes)) = command.into_op()
                && id == lower
            {
                let n = bytes.len() as u64;
                written.extend_from_slice(&bytes);
                self.take(MuxEvent::Child(lower, StreamEvent::Written(n)));
            }
        }
        // The exchange's own completion events are not under test here.
        while self.event().is_some() {
            self.driver.run().unwrap();
        }
        written
    }
}

/// Checks what a connection with `profile` shows a peer, using only the
/// profile's trait methods.
fn shows(profile: Arc<dyn Profile>) {
    let mut t = Test::with_profile(profile.clone());
    let streams = t.local_streams(usize::MAX);
    assert_eq!(streams.len(), profile.streams().len());
    for (kind, written) in profile.streams().iter().zip(&streams) {
        let (stream_type, n) = crate::stdlib::protocols::quic::read_varint(&written.bytes).unwrap();
        let rest = &written.bytes[n..];
        match *kind {
            Local::Control => {
                assert_eq!(stream_type, 0);
                let frames = frames(rest);
                assert_eq!(frames[0].0, wire::frame_type::SETTINGS);
                let sent = wire::Settings::parse(&frames[0].1).unwrap();
                assert_eq!(sent.entries.len(), profile.settings().len());
                for (setting, entry) in profile.settings().iter().zip(&sent.entries) {
                    match *setting {
                        Setting::FieldSectionSize(v) => {
                            assert_eq!(entry.id, wire::setting::MAX_FIELD_SECTION_SIZE);
                            assert!(entry.value <= v);
                        }
                        Setting::QpackTableCapacity(v) => {
                            assert_eq!(entry.id, wire::setting::QPACK_MAX_TABLE_CAPACITY);
                            assert_eq!(entry.value, v);
                        }
                        Setting::QpackBlockedStreams(v) => {
                            assert_eq!(entry.id, wire::setting::QPACK_BLOCKED_STREAMS);
                            assert_eq!(entry.value, v);
                        }
                        Setting::Reserved => {
                            assert!(is_reserved(entry.id) && is_reserved(entry.value));
                        }
                    }
                }
                assert!(!written.ended);
            }
            Local::Encoder => assert_eq!((stream_type, written.ended), (2, false)),
            Local::Decoder => assert_eq!((stream_type, written.ended), (3, false)),
            Local::Reserved(payload) => {
                assert!(is_reserved(stream_type));
                assert_eq!(rest, payload);
                assert!(written.ended);
            }
        }
    }
    // Reserved frames precede the first response's HEADERS and no other.
    for (stream, reserved) in [(0, profile.reserved_frames()), (4, &[][..])] {
        let frames = frames(&t.respond(stream));
        assert_eq!(frames.len(), reserved.len() + 1);
        for ((kind, payload), expected) in frames.iter().zip(reserved) {
            assert!(is_reserved(*kind));
            assert_eq!(payload, expected);
        }
        let (kind, section) = frames.last().unwrap();
        assert_eq!(*kind, wire::frame_type::HEADERS);
        let qpack::SectionResult::Fields { fields, .. } =
            qpack::decode_section(&qpack::Table::new(0), stream, section).unwrap()
        else {
            panic!("a response never waits for inserts")
        };
        assert!(
            fields
                .iter()
                .any(|f| f.name == b":status" && f.value == b"200")
        );
    }
    assert_eq!(t.closed(), None);
}

#[test]
fn every_profile_shows_what_it_lists() {
    shows(Arc::new(Standard));
    shows(Arc::new(StaticOnly));
    shows(Arc::new(Greased));
}

#[test]
fn a_reserved_stream_the_peer_cannot_take_is_left_out() {
    let mut t = Test::with_profile(Arc::new(Greased));
    let streams = t.local_streams(2);
    assert_eq!(streams.len(), 2);
    assert_eq!(t.closed(), None);
    let frames = frames(&t.respond(0));
    assert_eq!(frames.last().unwrap().0, wire::frame_type::HEADERS);
}

#[test]
fn advertised_limits_bind_the_connection() {
    let t = Test::with_profile(Arc::new(Greased));
    let h3 = t.driver.layer();
    assert_eq!(h3.qpack.table_capacity(), 1024);
    assert_eq!(h3.qpack.blocked_streams(), 0);
    assert_eq!(h3.decoder.max_capacity(), 1024);
    assert_eq!(h3.field_limit(), 1 << 12);
}

#[test]
#[should_panic(expected = "a table capacity needs a decoder stream")]
fn a_profile_without_the_streams_it_needs_is_refused() {
    struct NoDecoder;
    impl qpack::Policy for NoDecoder {
        fn capacity(&self, _: u64) -> u64 {
            0
        }
        fn insert(&self, _: &qpack::Field, _: &qpack::Table) -> bool {
            false
        }
        fn style(&self) -> qpack::Style {
            qpack::Style::DEFAULT
        }
    }
    impl Profile for NoDecoder {
        fn settings(&self) -> &[Setting] {
            &[Setting::QpackTableCapacity(4096)]
        }
        fn streams(&self) -> &[Local] {
            &[Local::Control]
        }
        fn reserved_frames(&self) -> &[&'static [u8]] {
            &[]
        }
    }
    let _ = Http3::new(Limits::default()).profile(Arc::new(NoDecoder));
}
