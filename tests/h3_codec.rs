//! QPACK session values and HTTP/3 stream handoffs under shared budgets.

use fictionet::stdlib::{
    codec::{self, Decode, Fail, Step, Stream, Wire, contract, finish, pump, test_support::chunks},
    http3::{self, Connection, Endpoint, Frame, StreamHeader, StreamItem},
    qpack::{
        self, DecoderInstruction as DI, EncoderInstruction as EI, Field, Representation as Rep, SectionResult, Table,
    },
};
use std::collections::BTreeMap;

fn wire<T: Wire>(value: &T) -> Vec<u8>
where
    T::WriteError: core::fmt::Debug,
{
    Wire::to_bytes(value).unwrap()
}

fn encoder_units() -> Vec<EI> {
    vec![
        EI::SetCapacity(4096),
        EI::InsertWithLiteralName { name: b"x-trace".to_vec(), value: vec![0xfe; 140] },
        EI::InsertWithNameRef { static_table: true, index: 17, value: b"PATCH".to_vec() },
        EI::InsertWithNameRef { static_table: false, index: 0, value: b"GET".to_vec() },
        EI::Duplicate(0),
    ]
}

fn section(required: u64, base: u64, max_entries: u64, lines: &[Rep]) -> Vec<u8> {
    let mut bytes = qpack::SectionPrefix { required_insert_count: required, base }.to_bytes(max_entries).unwrap();
    for rep in lines {
        Wire::write(rep, &mut bytes).unwrap();
    }
    bytes
}

#[test]
fn qpack_instructions_table_sections_and_acknowledgments() {
    let instructions = encoder_units();
    let mut bytes = Vec::new();
    for ins in &instructions {
        Wire::write(ins, &mut bytes).unwrap();
        contract::check_wire::<EI>(&wire(ins));
    }
    contract::check_decode(qpack::EncoderInstructions::new, &bytes);
    for pattern in [&[][..], &[1], &[2, 1, 7, 151], &[3, 5, 1, 256]] {
        let mut input = Stream::new(qpack::EncoderInstructions::new());
        let mut table = Table::new(4096);
        let mut decoded = Vec::new();
        for chunk in chunks(&bytes, pattern) {
            assert_eq!(input.push(chunk), chunk.len());
            while let Some(item) = input.next() {
                let ins = item.unwrap().unwrap();
                table.apply(ins.clone()).unwrap();
                decoded.push(ins);
            }
        }
        finish(&mut input, |_| panic!("already drained")).unwrap();
        assert_eq!(decoded, instructions);
        assert_eq!(table.insert_count(), 4);
        assert_eq!(table.get_relative(0), table.get(3));
        assert_eq!(table.get(0), Some((&b"x-trace"[..], &vec![0xfe; 140][..])));

        let fields = section(
            4,
            4,
            table.max_entries(),
            &[Rep::Indexed { static_table: false, index: 3 }, Rep::Indexed { static_table: false, index: 0 }],
        );
        assert_eq!(
            qpack::decode_section(&table, 1024, &fields),
            Ok(SectionResult::Fields {
                fields: vec![Field::new("x-trace", vec![0xfe; 140]), Field::new(":method", "GET")],
                ack: Some(DI::SectionAck(1024)),
            })
        );
        let delayed = section(5, 5, table.max_entries(), &[Rep::Indexed { static_table: false, index: 0 }]);
        let SectionResult::Blocked(blocked) = qpack::decode_section(&table, 8, &delayed).unwrap() else {
            panic!("section must wait for insert 5");
        };
        assert_eq!(blocked.required_insert_count(), 5);
        assert_eq!(blocked.stream_id(), 8);
        assert_eq!(blocked.clone().retry(&table), Ok(SectionResult::Blocked(blocked.clone())));
        let mut held = qpack::BlockedSections::new(2);
        held.push(blocked).unwrap();
        assert!(held.next_ready(&table).is_none());
        let late = wire(&EI::Duplicate(3));
        let mut decoder = Stream::new(qpack::EncoderInstructions::new());
        for b in &late {
            assert_eq!(decoder.push(core::slice::from_ref(b)), 1);
            if let Some(item) = decoder.next() {
                table.apply(item.unwrap().unwrap()).unwrap();
            }
        }
        assert_eq!(
            held.next_ready(&table),
            Some((
                8,
                Ok(SectionResult::Fields {
                    fields: vec![Field::new("x-trace", vec![0xfe; 140])],
                    ack: Some(DI::SectionAck(8)),
                })
            ))
        );
        assert_eq!(held.buffered(), 0);
        assert!(held.is_empty());

        let ack_values = [DI::InsertCountIncrement(5), DI::SectionAck(1024), DI::SectionAck(8), DI::StreamCancel(4096)];
        let mut pending = qpack::PendingInstructions::new();
        for ack in &ack_values {
            pending.push(ack).unwrap();
            contract::check_wire_value(ack);
        }
        let ack_bytes = pending.take();
        assert_eq!(pending.buffered(), 0);
        contract::check_decode(qpack::DecoderInstructions::new, &ack_bytes);
        let mut acks = Stream::new(qpack::DecoderInstructions::new());
        let mut got = Vec::new();
        for b in &ack_bytes {
            pump(&mut acks, core::slice::from_ref(b), |item| got.push(item.unwrap())).unwrap();
        }
        finish(&mut acks, |item| got.push(item.unwrap())).unwrap();
        assert_eq!(got, ack_values);
        table.increment_known_received(5).unwrap();
        table.acknowledge(4).unwrap();
        assert_eq!(table.known_received_count(), 5);
        assert_eq!(table.increment_known_received(1), Err(qpack::Error::Increment));
        assert_eq!(table.known_received_count(), 5);
    }
}

#[test]
fn qpack_table_eviction_and_transactional_application() {
    let mut table = Table::new(80);
    table.set_capacity(80).unwrap();
    table.insert(b"a".to_vec(), b"one".to_vec()).unwrap();
    table.insert(b"b".to_vec(), b"two".to_vec()).unwrap();
    assert_eq!(table.insert_count(), 2);
    let before = table.clone();
    assert_eq!(table.apply(EI::Duplicate(2)), Err(qpack::Error::DynamicIndex(2)));
    assert_eq!(table.set_capacity(81), Err(qpack::Error::Capacity(81)));
    assert_eq!(table, before);
    table.apply(EI::Duplicate(0)).unwrap();
    assert!(table.get(0).is_none());
    assert_eq!(table.get_relative(0), Some((&b"b"[..], &b"two"[..])));
    table.evict_to(36);
    assert_eq!(table.first_index(), 2);
    table.set_capacity(0).unwrap();
    assert!(table.is_empty());
    assert_eq!(table.insert_count(), 3);
}

#[test]
fn qpack_section_limits_and_static_ack_policy() {
    let table = Table::new(4096);
    let bytes = section(0, 0, table.max_entries(), &[Rep::Indexed { static_table: true, index: 17 }]);
    assert_eq!(
        qpack::decode_section(&table, 0, &bytes),
        Ok(SectionResult::Fields { fields: vec![Field::new(":method", "GET")], ack: None })
    );
    assert_eq!(qpack::decode_section_with_limit(&table, 0, &bytes, 1), Err(qpack::Error::FieldSectionTooLarge));
    assert_eq!(qpack::decode_section(&table, 0, &[0]), Err(qpack::Error::Truncated));
    assert_eq!(
        qpack::decode_section(&table, 0, &vec![0; qpack::MAX_SECTION_BYTES + 1]),
        Err(qpack::Error::FieldSectionTooLarge)
    );
    let lines = vec![Rep::Indexed { static_table: true, index: 17 }; qpack::MAX_FIELDS + 1];
    assert_eq!(
        qpack::decode_section(&table, 0, &section(0, 0, table.max_entries(), &lines)),
        Err(qpack::Error::TooManyFields)
    );
}

fn blocked(table: &Table, stream: u64, required: u64, body_len: usize) -> qpack::BlockedSection {
    let mut bytes =
        qpack::SectionPrefix { required_insert_count: required, base: required }.to_bytes(table.max_entries()).unwrap();
    bytes.resize(bytes.len() + body_len, 0x80);
    let SectionResult::Blocked(value) = qpack::decode_section(table, stream, &bytes).unwrap() else {
        panic!("expected a blocked value");
    };
    value
}

#[test]
fn qpack_blocked_storage_enforces_all_limits_and_stream_order() {
    let mut table = Table::new(4096);
    table.set_capacity(4096).unwrap();
    let mut held = qpack::BlockedSections::new(2);
    held.push(blocked(&table, 0, 2, 1)).unwrap();
    held.push(blocked(&table, 0, 1, 1)).unwrap();
    held.push(blocked(&table, 4, 1, 1)).unwrap();
    assert!(held.push(blocked(&table, 8, 1, 1)).is_err());
    table.insert(b"a".to_vec(), b"b".to_vec()).unwrap();
    let (stream, ready) = held.next_ready(&table).unwrap();
    assert_eq!(stream, 4);
    assert!(ready.is_ok());
    assert!(held.next_ready(&table).is_none());
    assert_eq!(held.cancel(0), Some(DI::StreamCancel(0)));
    assert_eq!(held.cancel(0), None);
    assert_eq!(held.buffered(), 0);

    let table = Table::new(4096);
    let mut held = qpack::BlockedSections::new(usize::MAX);
    for stream in 0..qpack::MAX_BLOCKED_STREAMS {
        held.push(blocked(&table, stream as u64 * 4, 1, 0)).unwrap();
    }
    assert!(held.push(blocked(&table, 999_999, 1, 0)).is_err());
    let mut held = qpack::BlockedSections::new(1);
    for _ in 0..qpack::MAX_BLOCKED_SECTIONS {
        held.push(blocked(&table, 0, 1, 0)).unwrap();
    }
    assert!(held.push(blocked(&table, 0, 1, 0)).is_err());
    let mut held = qpack::BlockedSections::new(1);
    for _ in 0..4 {
        held.push(blocked(&table, 0, 1, qpack::MAX_BLOCKED_BYTES / 4)).unwrap();
    }
    assert_eq!(held.buffered(), qpack::MAX_BLOCKED_BYTES);
    let refused = held.push(blocked(&table, 0, 1, 1)).unwrap_err();
    assert_eq!(refused.buffered(), 1);
    assert_eq!(held.buffered(), qpack::MAX_BLOCKED_BYTES);
}

#[test]
fn qpack_blocked_retry_preserves_insert_count_across_wrapping() {
    let mut table = Table::new(64);
    table.set_capacity(64).unwrap();
    let waiting = blocked(&table, 0, 1, 1);
    for _ in 0..5 {
        table.insert(b"a".to_vec(), b"b".to_vec()).unwrap();
    }
    // Rereading the wrapped prefix could select insert 5. Retry must keep
    // required=1 and correctly report that its original entry was evicted.
    assert_eq!(waiting.required_insert_count(), 1);
    assert_eq!(waiting.retry(&table), Err(qpack::Error::DynamicIndex(0)));
}

#[test]
fn qpack_instruction_failures_and_eof() {
    let mut over = vec![0xc0];
    qpack::encode_integer(&mut over, 7, 0, qpack::MAX_STRING as u64 + 1);
    let mut stream = Stream::new(qpack::EncoderInstructions::new());
    assert_eq!(stream.push(&over), over.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(qpack::Error::StringTooLong))));
    assert!(stream.next().is_none());
    assert_eq!(stream.buffered(), over.len());
    assert_eq!(stream.held(), 0);
    contract::check_decode(qpack::EncoderInstructions::new, &over);

    let mut overflow = vec![0x1f];
    overflow.extend_from_slice(&[0x80; 9]);
    for encoder in [false, true] {
        if encoder {
            contract::check_decode(qpack::EncoderInstructions::new, &overflow);
        } else {
            // Decoder increments use a six-bit prefix.
            let mut bytes = overflow.clone();
            bytes[0] = 0x3f;
            contract::check_decode(qpack::DecoderInstructions::new, &bytes);
        }
    }
    let mut partial = Stream::new(qpack::EncoderInstructions::new());
    assert_eq!(partial.push(&[0x41, b'a', 2, b'b']), 4);
    partial.end();
    assert_eq!(partial.next(), Some(Err(Fail::Truncated { unread: 4 })));
    assert!(partial.next().is_none());
    let mut partial = Stream::new(qpack::DecoderInstructions::new());
    assert_eq!(partial.push(&[0xff]), 1);
    partial.end();
    assert_eq!(partial.next(), Some(Err(Fail::Truncated { unread: 1 })));

    let mut malformed = vec![0x41, b'a', 0x81, 0];
    malformed.extend(wire(&EI::SetCapacity(128)));
    contract::check_decode(qpack::EncoderInstructions::new, &malformed);
    let mut input = Stream::new(qpack::EncoderInstructions::new());
    assert_eq!(input.push(&malformed), malformed.len());
    assert_eq!(input.next(), Some(Ok(Err(qpack::Error::Huffman))));
    assert_eq!(input.next(), Some(Ok(Ok(EI::SetCapacity(128)))));
    assert!(input.failed().is_none());
    let mut input = Stream::new(qpack::DecoderInstructions::new());
    assert_eq!(input.push(&[0, 1]), 2);
    assert_eq!(input.next(), Some(Ok(Err(qpack::Error::ZeroIncrement))));
    assert_eq!(input.next(), Some(Ok(Ok(DI::InsertCountIncrement(1)))));
    contract::check_decode(qpack::DecoderInstructions::new, &[0, 1]);
}

#[test]
fn qpack_strict_writers_and_explicit_output_limit() {
    for invalid in [
        EI::SetCapacity(qpack::MAX_TABLE_CAPACITY + 1),
        EI::Duplicate(qpack::MAX_INTEGER + 1),
        EI::InsertWithNameRef { static_table: true, index: 99, value: vec![] },
        EI::InsertWithLiteralName { name: vec![b'a'; qpack::MAX_STRING + 1], value: vec![] },
    ] {
        contract::check_wire_value(&invalid);
        let mut out = vec![7, 9];
        assert!(Wire::write(&invalid, &mut out).is_err());
        assert_eq!(out, [7, 9]);
    }
    for invalid in [DI::InsertCountIncrement(0), DI::SectionAck(u64::MAX), DI::StreamCancel(u64::MAX)] {
        contract::check_wire_value(&invalid);
    }
    let mut trailing = wire(&EI::SetCapacity(8));
    trailing.push(0);
    assert_eq!(<EI as Wire>::parse(&trailing), Err(qpack::Error::Trailing));
    let mut pending = qpack::PendingInstructions::new();
    let ins = DI::SectionAck(qpack::MAX_INTEGER);
    let length = wire(&ins).len();
    for _ in 0..qpack::MAX_PENDING_STREAM / length {
        pending.push(&ins).unwrap();
    }
    let size = pending.buffered();
    assert_eq!(pending.push(&ins), Err(qpack::Error::PendingFull));
    assert_eq!(pending.buffered(), size);
    assert_eq!(pending.take().len(), size);
    pending.push(&ins).unwrap();
}

fn settings() -> Frame {
    Frame::Settings(http3::Settings {
        entries: vec![
            http3::Setting { id: http3::setting::QPACK_MAX_TABLE_CAPACITY, value: 4096 },
            http3::Setting { id: http3::setting::QPACK_BLOCKED_STREAMS, value: 2 },
        ],
    })
}

fn frame_values() -> Vec<Frame> {
    vec![
        Frame::Data(vec![0xfe; 140]),
        Frame::Headers(vec![0, 0]),
        settings(),
        Frame::Goaway(1024),
        Frame::CancelPush(17),
        Frame::MaxPushId(255),
        Frame::PushPromise { push_id: 65, field_section: vec![0, 0] },
        Frame::PriorityUpdate { element: http3::PriorityElement::Request(256), value: b"u=3".to_vec() },
        Frame::Unknown { frame_type: 0xface, payload: b"extension".to_vec() },
    ]
}

#[test]
fn http3_chunked_frame_round_trips() {
    let frames = frame_values();
    let mut bytes = Vec::new();
    for frame in &frames {
        Wire::write(frame, &mut bytes).unwrap();
        contract::check_wire::<Frame>(&wire(frame));
    }
    contract::check_decode(http3::Frames::new, &bytes);
    for pattern in [&[][..], &[1], &[1, 2, 137, 5], &[4, 3, 256]] {
        let mut stream = Stream::new(http3::Frames::new());
        let mut got = Vec::new();
        for chunk in chunks(&bytes, pattern) {
            assert_eq!(pump(&mut stream, chunk, |f| got.push(f.unwrap())), Ok(chunk.len()));
        }
        finish(&mut stream, |f| got.push(f.unwrap())).unwrap();
        assert_eq!(got, frames);
    }
}

#[test]
fn http3_stream_header_end_swap_and_parts_preserve_bytes_and_eof() {
    let frame = Frame::Data(b"first payload".to_vec());
    // Nonminimal type varint and multibyte push ID, both split bytewise.
    let mut bytes = vec![0x40, 1, 0x41, 0];
    Wire::write(&frame, &mut bytes).unwrap();
    contract::check_decode(http3::StreamHeaders::new, &bytes);
    let mut stream = Stream::with_buffer(http3::StreamHeaders::new(), bytes.len());
    assert_eq!(stream.push(&bytes), bytes.len());
    stream.end();
    assert_eq!(stream.next_span(), Some(Ok((StreamHeader::Push(256), 0..4))));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.unread(), wire(&frame));
    let mut stream = stream.swap(http3::Frames::new());
    assert_eq!(stream.next_span(), Some(Ok((Ok(frame), 4..bytes.len() as u64))));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    let mut stream = Stream::with_buffer(http3::StreamHeaders::new(), 32);
    assert_eq!(stream.push(&[2, 0x20, 0x41, b'x', 0]), 5);
    assert_eq!(stream.next(), Some(Ok(StreamHeader::QpackEncoder)));
    assert_eq!(stream.next(), None);
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.offset(), 1);
    assert_eq!(buffer.unread(), [0x20, 0x41, b'x', 0]);
}

type ConnectionItems = BTreeMap<u64, Vec<StreamItem>>;

fn drain(connection: &mut Connection, items: &mut ConnectionItems, table: &mut Table) {
    while let Some((stream, item)) = connection.next() {
        let item = item.unwrap().unwrap();
        if let StreamItem::EncoderInstruction(ins) = &item {
            table.apply(ins.clone()).unwrap();
        }
        items.entry(stream).or_default().push(item);
    }
}

fn interleaved_connection(chunk_size: usize) {
    const BUDGET: usize = 512;
    let mut connection = Connection::new(Endpoint::Client, 5, BUDGET);
    let mut table = Table::new(4096);
    let mut items = ConnectionItems::new();
    let mut control = wire(&StreamHeader::Control);
    Wire::write(&settings(), &mut control).unwrap();
    Wire::write(&Frame::Goaway(128), &mut control).unwrap();
    let mut encoder = wire(&StreamHeader::QpackEncoder);
    for ins in encoder_units() {
        Wire::write(&ins, &mut encoder).unwrap();
    }
    let mut decoder = wire(&StreamHeader::QpackDecoder);
    Wire::write(&DI::SectionAck(1024), &mut decoder).unwrap();
    Wire::write(&DI::StreamCancel(4096), &mut decoder).unwrap();
    let dynamic = section(4, 4, table.max_entries(), &[Rep::Indexed { static_table: false, index: 0 }]);
    let first = [wire(&Frame::Headers(dynamic.clone())), wire(&Frame::Data(vec![0xfd; 140]))].concat();
    let second = [wire(&Frame::Headers(vec![0, 0])), wire(&Frame::Data(b"second".to_vec()))].concat();
    let inputs = [(2, control), (0, first), (6, encoder), (4, second), (10, decoder)];
    let mut chunks: Vec<_> = inputs.iter().map(|(id, b)| (*id, b.chunks(chunk_size))).collect();
    loop {
        let mut progressed = false;
        for (id, input) in &mut chunks {
            if let Some(mut chunk) = input.next() {
                progressed = true;
                while !chunk.is_empty() {
                    let used = connection.push(*id, chunk);
                    assert!(used > 0);
                    chunk = chunk.get(used..).unwrap();
                    assert!(connection.buffered() <= BUDGET);
                    drain(&mut connection, &mut items, &mut table);
                }
            }
        }
        if !progressed {
            break;
        }
    }
    assert_eq!(connection.buffered(), 0);
    assert_eq!(connection.len(), 5);
    assert_eq!(
        items.get(&2),
        Some(&vec![
            StreamItem::Header(StreamHeader::Control),
            StreamItem::Frame(settings()),
            StreamItem::Frame(Frame::Goaway(128))
        ])
    );
    assert_eq!(
        items.get(&0),
        Some(&vec![
            StreamItem::Frame(Frame::Headers(dynamic.clone())),
            StreamItem::Frame(Frame::Data(vec![0xfd; 140]))
        ])
    );
    assert_eq!(
        items.get(&4),
        Some(&vec![StreamItem::Frame(Frame::Headers(vec![0, 0])), StreamItem::Frame(Frame::Data(b"second".to_vec()))])
    );
    assert_eq!(
        items.get(&10),
        Some(&vec![
            StreamItem::Header(StreamHeader::QpackDecoder),
            StreamItem::DecoderInstruction(DI::SectionAck(1024)),
            StreamItem::DecoderInstruction(DI::StreamCancel(4096))
        ])
    );
    let mut expected = vec![StreamItem::Header(StreamHeader::QpackEncoder)];
    expected.extend(encoder_units().into_iter().map(StreamItem::EncoderInstruction));
    assert_eq!(items.get(&6), Some(&expected));
    assert_eq!(
        qpack::decode_section(&table, 0, &dynamic),
        Ok(SectionResult::Fields { fields: vec![Field::new(":method", "GET")], ack: Some(DI::SectionAck(0)) })
    );
    for id in [0, 4] {
        connection.end(id);
    }
    assert!(connection.next().is_none());
    for (id, bytes) in inputs {
        let stream = connection.remove(id).unwrap();
        assert_eq!(stream.offset(), bytes.len() as u64);
        assert_eq!(stream.buffered(), 0);
    }
    assert!(connection.is_empty());
}

#[test]
fn http3_connection_interleaves_control_qpack_and_two_requests() {
    for size in [1, 3, 7, 1024] {
        interleaved_connection(size);
    }
}

#[test]
fn http3_aggregate_demux_budget_refuses_across_streams() {
    // Every stream's frame limit exceeds this total connection budget.
    let mut connection = Connection::new(Endpoint::Client, 4, 9);
    assert_eq!(connection.push(0, &[0, 100, 1]), 3);
    assert_eq!(connection.push(4, &[0, 100, 2]), 3);
    assert_eq!(connection.push(2, &[0, 4, 100, 3, 4]), 3);
    assert_eq!(connection.buffered(), 9);
    assert_eq!(connection.push(6, &[2]), 0);
    // Type handoff consumes only the control type and releases one byte.
    assert_eq!(connection.next(), Some((2, Ok(Ok(StreamItem::Header(StreamHeader::Control))))));
    assert_eq!(connection.buffered(), 8);
    assert_eq!(connection.push(6, &[2, 0x20]), 1);
    assert_eq!(connection.buffered(), 9);
    assert_eq!(connection.push(0, &[9]), 0);
    assert!(connection.remove(4).is_some());
    assert_eq!(connection.buffered(), 6);
    assert_eq!(connection.push(0, &[9, 9, 9, 9]), 3);
    assert_eq!(connection.buffered(), 9);
}

#[test]
#[allow(deprecated)] // Measure the old session's allocation without changing its API.
fn http3_many_small_streams_allocate_in_proportion_to_input() {
    const COUNT: usize = 512;
    const FIRST: &[u8] = &[0, 100, 7];
    let mut connection = Connection::new(Endpoint::Client, COUNT, COUNT * FIRST.len());
    let mut legacy = Vec::new();
    for index in 0..COUNT {
        let id = index as u64 * 4;
        assert_eq!(connection.push(id, FIRST), FIRST.len());
        let mut decoder = http3::RequestDecoder::new(id, http3::MessageSide::Request, false).unwrap();
        assert_eq!(decoder.feed(FIRST), FIRST.len());
        legacy.push(decoder);
    }
    assert_eq!(connection.buffered(), COUNT * FIRST.len());
    let old_allocated: usize = legacy.iter().map(http3::RequestDecoder::capacity).sum();
    assert!(old_allocated <= COUNT * FIRST.len() * 2);
    let mut allocated = 0;
    for index in 0..COUNT {
        let (buffer, _) = connection.remove(index as u64 * 4).unwrap().into_parts();
        allocated += buffer.allocated();
    }
    assert!(allocated <= COUNT * FIRST.len() * 2);
    assert!(old_allocated < http3::MAX_FRAME_PAYLOAD);
    assert!(allocated < http3::MAX_FRAME_PAYLOAD);
}

#[test]
fn http3_errors_are_items_or_terminal_according_to_boundary() {
    // A complete malformed SETTINGS frame retains a trusted next boundary.
    let mut bytes = vec![4, 4, 1, 0, 1, 0];
    Wire::write(&Frame::Data(b"next".to_vec()), &mut bytes).unwrap();
    contract::check_decode(http3::Frames::new, &bytes);
    let mut input = Stream::new(http3::Frames::new());
    assert_eq!(input.push(&bytes), bytes.len());
    assert_eq!(input.next(), Some(Ok(Err(http3::Error::DuplicateSetting(1)))));
    assert_eq!(input.next(), Some(Ok(Ok(Frame::Data(b"next".to_vec())))));
    assert!(input.failed().is_none());
    // Even forbidden types are complete-unit errors in the new API.
    assert_eq!(http3::Frames.decode(&[2, 0], false), Ok(Step::Item(Err(http3::Error::UnexpectedFrame(2)), 2)));

    let mut over = vec![0];
    fictionet::stdlib::quic::write_varint(http3::MAX_FRAME_PAYLOAD as u64 + 1, &mut over).unwrap();
    let mut stream = Stream::new(http3::Frames::new());
    assert_eq!(stream.push(&over), over.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(http3::Error::Limit))));
    assert!(stream.next().is_none());
    assert!(stream.is_done());
    assert_eq!(stream.buffered(), over.len());
    assert_eq!(stream.held(), 0);
    contract::check_decode(http3::Frames::new, &over);
    for bytes in [&[0x40][..], &[0, 0x40], &[0, 2, 1]] {
        contract::check_decode(http3::Frames::new, bytes);
        let mut stream = Stream::new(http3::Frames::new());
        assert_eq!(stream.push(bytes), bytes.len());
        stream.end();
        assert_eq!(stream.next(), Some(Err(Fail::Truncated { unread: bytes.len() })));
        assert!(stream.next().is_none());
    }
}

#[test]
fn http3_control_and_selected_stream_contracts() {
    let mut control = wire(&settings());
    Wire::write(&Frame::Goaway(8), &mut control).unwrap();
    Wire::write(&Frame::Goaway(4), &mut control).unwrap();
    contract::check_decode(|| http3::ControlFrames::new(Endpoint::Server), &control);
    let mut stream = Stream::new(http3::ControlFrames::new(Endpoint::Server));
    let mut frames = Vec::new();
    pump(&mut stream, &control, |item| frames.push(item.unwrap())).unwrap();
    assert_eq!(frames, [settings(), Frame::Goaway(8), Frame::Goaway(4)]);
    assert_eq!(finish(&mut stream, |_| {}), Err(Fail::Protocol(http3::Error::ClosedCriticalStream)));
    let header = StreamHeader::QpackEncoder;
    let bytes = wire(&EI::SetCapacity(4096));
    contract::check_decode(|| http3::StreamDecoder::after_header(header, Endpoint::Client), &bytes);
    contract::check_decode(|| http3::StreamDecoder::after_header(StreamHeader::QpackDecoder, Endpoint::Client), &[1]);
    contract::check_decode(
        || http3::StreamDecoder::after_header(StreamHeader::Unknown(64), Endpoint::Client),
        &[0xff; 128],
    );
    contract::check_decode(http3::StreamDecoder::request, &wire(&Frame::Data(vec![1, 2])));
    contract::check_decode(http3::StreamDecoder::unidirectional, &[0x40, 2, 0x20]);
}

#[test]
fn http3_connection_eof_survives_handoff_and_unknown_streams_are_skipped() {
    let mut connection = Connection::new(Endpoint::Server, 3, 64);
    // Push ID is part of the header; the entire DATA frame is already buffered.
    let mut bytes = wire(&StreamHeader::Push(65));
    Wire::write(&Frame::Data(b"hello".to_vec()), &mut bytes).unwrap();
    assert_eq!(connection.push(3, &bytes), bytes.len());
    connection.end(3);
    assert_eq!(connection.next(), Some((3, Ok(Ok(StreamItem::Header(StreamHeader::Push(65)))))));
    assert_eq!(connection.next(), Some((3, Ok(Ok(StreamItem::Frame(Frame::Data(b"hello".to_vec())))))));
    assert!(connection.next().is_none());
    assert!(connection.remove(3).unwrap().is_done());
    assert_eq!(connection.push(7, &[0x40, 64, 0xff, 0xff]), 4);
    assert_eq!(connection.next(), Some((7, Ok(Ok(StreamItem::Header(StreamHeader::Unknown(64)))))));
    assert!(connection.next().is_none());
    assert_eq!(connection.buffered(), 0);
    assert_eq!(connection.push(11, &[2, 0x3f]), 2);
    connection.end(11);
    assert_eq!(connection.next(), Some((11, Ok(Ok(StreamItem::Header(StreamHeader::QpackEncoder))))));
    assert_eq!(connection.next(), Some((11, Err(Fail::Truncated { unread: 1 }))));
    assert!(connection.next().is_none());
}

#[test]
fn http3_strict_writers_are_transactional() {
    for frame in [
        Frame::Data(vec![0; http3::MAX_FRAME_PAYLOAD + 1]),
        Frame::Unknown { frame_type: 0, payload: vec![] },
        Frame::Goaway(http3::MAX_VARINT + 1),
        Frame::Settings(http3::Settings { entries: vec![http3::Setting { id: 8, value: 2 }] }),
    ] {
        contract::check_wire_value(&frame);
        let mut output = vec![0xaa, 0xbb];
        assert!(Wire::write(&frame, &mut output).is_err());
        assert_eq!(output, [0xaa, 0xbb]);
    }
    for header in
        [StreamHeader::Control, StreamHeader::Push(255), StreamHeader::Unknown(0), StreamHeader::Unknown(u64::MAX)]
    {
        contract::check_wire_value(&header);
    }
    contract::check_wire_value(&http3::Settings::default());
    let mut bytes = wire(&Frame::Data(vec![]));
    bytes.push(0);
    assert_eq!(<Frame as Wire>::parse(&bytes), Err(http3::Error::Frame));
}

#[test]
fn codec_contracts_on_bounded_arbitrary_inputs() {
    let mut random = codec::test_support::Lcg::new(0xface_1234);
    for length in [0, 1, 2, 3, 10, 31, 64, 129, 257] {
        let bytes: Vec<_> = (0..length).map(|_| random.next() as u8).collect();
        contract::check_decode(qpack::EncoderInstructions::new, &bytes);
        contract::check_decode(qpack::DecoderInstructions::new, &bytes);
        contract::check_decode(http3::Frames::new, &bytes);
        contract::check_decode(http3::StreamHeaders::new, &bytes);
        contract::check_wire::<EI>(&bytes);
        contract::check_wire::<DI>(&bytes);
        contract::check_wire::<Rep>(&bytes);
        contract::check_wire::<Frame>(&bytes);
        contract::check_wire::<StreamHeader>(&bytes);
        contract::check_wire::<http3::Settings>(&bytes);
    }
}

#[test]
fn qpack_encoder_session_accepts_one_decoded_instruction_at_a_time() {
    let mut encoder = qpack::Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    encoder.set_capacity(4096).unwrap();
    encoder.insert(b"x-example", b"value").unwrap();
    let mut bytes = wire(&DI::InsertCountIncrement(1));
    Wire::write(&DI::SectionAck(1024), &mut bytes).unwrap();
    let mut stream = Stream::new(qpack::DecoderInstructions::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    encoder.apply_instruction(stream.next().unwrap().unwrap().unwrap()).unwrap();
    assert_eq!(encoder.known_received_count(), 1);
    // The application emits a section between the two already buffered items.
    let encoded = encoder.encode_section(1024, &[Field::new("x-example", "value")]).unwrap();
    assert_eq!(encoded.len(), 3);
    encoder.apply_instruction(stream.next().unwrap().unwrap().unwrap()).unwrap();
    assert_eq!(stream.next(), None);
    assert_eq!(encoder.apply_instruction(DI::SectionAck(1024)), Err(qpack::Error::UnknownStream(1024)));
    assert_eq!(encoder.apply_instruction(DI::StreamCancel(u64::MAX)), Err(qpack::Error::IntegerOverflow));
    assert_eq!(encoder.apply_instruction(DI::InsertCountIncrement(0)), Err(qpack::Error::ZeroIncrement));
    assert_eq!(encoder.known_received_count(), 1);
}
