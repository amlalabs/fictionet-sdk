//! QPACK session values and HTTP/3 stream handoffs under shared budgets.

use fictionet::stdlib::{
    codec::{self, Decode, Fail, Stream, Wire, contract, finish, pump, test_support::chunks},
    http3::{self, Connection, Endpoint, Frame, StreamHeader, StreamItem},
    qpack::{
        self, DecoderInstruction as DI, EncoderInstruction as EI, Field, Representation as Rep, SectionResult, Table,
    },
};
use std::collections::BTreeMap;

fn received_request(lengths: &[&str]) -> Vec<Field> {
    let mut fields = vec![
        Field::new(":method", "POST"),
        Field::new(":scheme", "https"),
        Field::new(":authority", "a.example"),
        Field::new(":path", "/"),
    ];
    fields.extend(lengths.iter().map(|value| Field::new("content-length", *value)));
    fields
}

fn literal_headers(fields: &[Field]) -> Frame {
    Frame::Headers(section(
        0,
        0,
        0,
        &fields
            .iter()
            .map(|field| Rep::LiteralName { never_index: false, name: field.name.clone(), value: field.value.clone() })
            .collect::<Vec<_>>(),
    ))
}

#[test]
fn review_c_received_lengths_are_normalized_and_request_state_checks_body() {
    use http3::{Event, HeaderKind, HeaderList, MessageSide, RequestResult, RequestState};
    let fields = received_request(&["5", "5"]);
    let headers = HeaderList::from_fields(fields.clone(), HeaderKind::Request { extended_connect: false }).unwrap();
    assert_eq!(headers.fields.len(), 5);
    let frame = literal_headers(&fields);
    let Frame::Headers(bytes) = &frame else { unreachable!() };
    let mut legacy = qpack::Decoder::new(0, 0, http3::MAX_FIELD_SECTION_SIZE);
    assert_eq!(
        HeaderList::decode(&mut legacy, 0, bytes, HeaderKind::Request { extended_connect: false }),
        Ok(Some(headers.clone()))
    );
    let table = Table::new(0);
    let mut state = RequestState::new(0, MessageSide::Request, false).unwrap();
    assert_eq!(state.step(&frame, &table), Ok(RequestResult::Event { event: Ok(Event::Headers(headers)), ack: None }));
    assert_eq!(
        state.step(&Frame::Data(b"hello".to_vec()), &table),
        Ok(RequestResult::Event { event: Ok(Event::Data(b"hello".to_vec())), ack: None })
    );
    assert_eq!(state.finish(), Ok(()));
    let mut state = RequestState::new(0, MessageSide::Request, false).unwrap();
    state.step(&frame, &table).unwrap();
    assert_eq!(state.finish(), Err(http3::Error::Message("DATA differs from Content-Length")));
    assert!(
        HeaderList::from_fields(received_request(&["5", "6"]), HeaderKind::Request { extended_connect: false })
            .is_err()
    );
}

#[test]
fn review_c_request_blocked_value_resumes_after_table_update() {
    use http3::{Event, MessageSide, RequestResult, RequestState};
    let mut table = Table::new(4096);
    table.set_capacity(4096).unwrap();
    let frame = Frame::Headers(section(
        1,
        1,
        table.max_entries(),
        &[
            Rep::Indexed { static_table: false, index: 0 },
            Rep::Indexed { static_table: true, index: 23 },
            Rep::LiteralNameRef { never_index: false, static_table: true, index: 0, value: b"a.example".to_vec() },
            Rep::Indexed { static_table: true, index: 1 },
        ],
    ));
    let mut state = RequestState::new(4, MessageSide::Request, false).unwrap();
    let RequestResult::Blocked(blocked) = state.step(&frame, &table).unwrap() else { panic!("must block") };
    assert!(state.is_blocked());
    assert_eq!(state.step(&Frame::Data(vec![]), &table), Err(http3::Error::State));
    assert_eq!(state.finish(), Err(http3::Error::State));
    assert!(matches!(state.resume(4, blocked.clone().retry(&table)), Ok(RequestResult::Blocked(_))));
    table.apply(EI::InsertWithLiteralName { name: b":method".to_vec(), value: b"GET".to_vec() }).unwrap();
    assert!(matches!(state.resume(8, blocked.clone().retry(&table)), Err(http3::Error::State)));
    assert!(matches!(
        state.resume(4, blocked.retry(&table)),
        Ok(RequestResult::Event { event: Ok(Event::Headers(_)), ack: Some(DI::SectionAck(4)) })
    ));
    assert!(!state.is_blocked());
    assert_eq!(table.take_increment(), None);
    assert_eq!(state.finish(), Ok(()));
}

#[test]
fn request_state_and_legacy_session_agree_on_message_sequences() {
    use http3::{MessageSide as Side, RequestResult};
    let request = literal_headers(&received_request(&["5, 5"]));
    let response = |status| literal_headers(&[Field::new(":status", status)]);
    let length_response = |status| literal_headers(&[Field::new(":status", status), Field::new("content-length", "5")]);
    let data = Frame::Data(b"hello".to_vec());
    let trailers = literal_headers(&[Field::new("x-trailer", "done")]);
    let unknown = Frame::Unknown { frame_type: 0x21, payload: vec![1] };
    let Frame::Headers(promised) = literal_headers(&received_request(&[])) else { unreachable!() };
    let promise = Frame::PushPromise { push_id: 0, field_section: promised };
    let connect = literal_headers(&[Field::new(":method", "CONNECT"), Field::new(":authority", "a.example:443")]);
    for (side, push, frames) in [
        (Side::Request, false, vec![]),
        (Side::Request, false, vec![data.clone()]),
        (Side::Request, false, vec![unknown.clone(), request.clone(), data.clone(), trailers.clone()]),
        (Side::Request, false, vec![request.clone(), Frame::Data(vec![0; 6])]),
        (Side::Request, false, vec![request.clone(), Frame::Data(vec![0; 3])]),
        (Side::Request, false, vec![request.clone(), data.clone(), trailers.clone(), data.clone()]),
        (Side::Request, false, vec![request.clone(), data.clone(), trailers.clone(), trailers.clone()]),
        (Side::Request, false, vec![promise.clone()]),
        (Side::Request, false, vec![connect.clone(), data.clone()]),
        (Side::Request, false, vec![connect, request]),
        (Side::Response, false, vec![response("103")]),
        (
            Side::Response,
            false,
            vec![response("103"), promise.clone(), length_response("200"), data.clone(), trailers.clone()],
        ),
        (Side::Response, false, vec![response("204"), data.clone()]),
        (Side::Response, false, vec![response("204"), trailers.clone()]),
        (Side::Response, false, vec![length_response("304")]),
        (Side::HeadResponse, false, vec![length_response("200")]),
        (Side::HeadResponse, false, vec![length_response("200"), data.clone()]),
        (Side::ConnectResponse, false, vec![length_response("204"), Frame::Data(vec![0; 20])]),
        (Side::ConnectResponse, false, vec![response("200"), trailers]),
        (Side::Response, true, vec![response("200"), promise]),
        (Side::HeadResponse, true, vec![length_response("200"), unknown]),
    ] {
        let table = Table::new(0);
        let mut qpack = qpack::Decoder::new(0, 0, http3::MAX_FIELD_SECTION_SIZE);
        let (mut state, mut legacy) = if push {
            let mut state = http3::RequestState::push(3).unwrap();
            let mut legacy = http3::RequestDecoder::push(3).unwrap();
            state.set_push_side(side).unwrap();
            legacy.set_push_side(side).unwrap();
            (state, legacy)
        } else {
            (http3::RequestState::new(0, side, false).unwrap(), http3::RequestDecoder::new(0, side, false).unwrap())
        };
        for frame in frames {
            let bytes = wire(&frame);
            assert_eq!(legacy.feed(&bytes), bytes.len());
            let old = legacy.next_event(&mut qpack).unwrap();
            let new = state.step(&frame, &table).and_then(|result| match result {
                RequestResult::Event { event, ack: None } => event,
                other => panic!("unexpected dynamic result: {other:?}"),
            });
            assert_eq!(new, old, "{side:?}, push={push}, {frame:?}");
            if new.is_err() {
                break;
            }
        }
        assert_eq!(state.finish(), legacy.finish(), "{side:?}, push={push}");
    }
}

#[test]
fn request_state_resumes_blocked_trailers_and_push_promises() {
    use http3::{Event, MessageSide, RequestResult, RequestState};
    for promise in [false, true] {
        let mut state = RequestState::new(0, MessageSide::Response, false).unwrap();
        let mut table = Table::new(4096);
        table.set_capacity(4096).unwrap();
        state.step(&literal_headers(&[Field::new(":status", "200")]), &table).unwrap();
        let mut reps = vec![Rep::Indexed { static_table: false, index: 0 }];
        if promise {
            reps.extend(received_request(&[]).into_iter().map(|field| Rep::LiteralName {
                never_index: false,
                name: field.name,
                value: field.value,
            }));
            // Pseudo-headers must precede the dynamic regular field.
            reps.rotate_left(1);
        }
        let bytes = section(1, 1, table.max_entries(), &reps);
        let frame =
            if promise { Frame::PushPromise { push_id: 9, field_section: bytes } } else { Frame::Headers(bytes) };
        let RequestResult::Blocked(blocked) = state.step(&frame, &table).unwrap() else { panic!("must block") };
        table.apply(EI::InsertWithLiteralName { name: b"x-extra".to_vec(), value: b"value".to_vec() }).unwrap();
        let RequestResult::Event { event, ack } = state.resume(0, blocked.retry(&table)).unwrap() else {
            panic!("must resume")
        };
        assert_eq!(ack, Some(DI::SectionAck(0)));
        if promise {
            assert!(matches!(event, Ok(Event::PushPromise { push_id: 9, .. })));
        } else {
            assert!(matches!(event, Ok(Event::Trailers(_))));
        }
        assert_eq!(state.finish(), Ok(()));
    }
}

#[test]
fn request_field_errors_preserve_qpack_acknowledgments() {
    for delayed in [false, true] {
        let mut table = Table::new(4096);
        table.set_capacity(4096).unwrap();
        let insert = EI::InsertWithLiteralName { name: b":status".to_vec(), value: b"200".to_vec() };
        let frame =
            Frame::Headers(section(1, 1, table.max_entries(), &[Rep::Indexed { static_table: false, index: 0 }]));
        let mut state = http3::RequestState::new(0, http3::MessageSide::Request, false).unwrap();
        let result = if delayed {
            let http3::RequestResult::Blocked(blocked) = state.step(&frame, &table).unwrap() else {
                panic!("must block")
            };
            table.apply(insert).unwrap();
            state.resume(0, blocked.retry(&table))
        } else {
            table.apply(insert).unwrap();
            state.step(&frame, &table)
        };
        // HTTP rejects a response field in a request, but the QPACK section
        // was decoded, so its acknowledgment must still reach the caller.
        assert!(result.is_ok(), "acknowledgment was lost: {result:?}");
        let http3::RequestResult::Event { event, ack } = result.unwrap() else { panic!("must decode") };
        assert!(matches!(event, Err(http3::Error::Message(_))));
        assert_eq!(ack, Some(DI::SectionAck(0)));
        assert_eq!(state.finish(), Err(http3::Error::State));
        assert_eq!(table.take_increment(), None);
    }
}

#[test]
fn decoder_instruction_capacity_is_one_bounded_integer() {
    assert_eq!(qpack::DecoderInstructions.capacity(), qpack::MAX_INTEGER_BYTES);
    for ins in [
        DI::SectionAck(qpack::MAX_INTEGER),
        DI::StreamCancel(qpack::MAX_INTEGER),
        DI::InsertCountIncrement(qpack::MAX_INTEGER),
    ] {
        let bytes = wire(&ins);
        assert_eq!(bytes.len(), qpack::MAX_INTEGER_BYTES);
        contract::check_decode(qpack::DecoderInstructions::new, &bytes);
    }
    contract::check_decode(qpack::DecoderInstructions::new, &[0xff; qpack::MAX_INTEGER_BYTES]);
}

#[test]
fn http3_stream_errors_keep_role_specific_application_codes() {
    use http3::{Error, StreamError as E};
    for (header, bytes, expected, code) in [
        (
            StreamHeader::QpackEncoder,
            vec![0xc0, 0x81, 0],
            E::QpackEncoder(qpack::Error::Huffman),
            http3::error_code::QPACK_ENCODER_STREAM_ERROR,
        ),
        (
            StreamHeader::QpackDecoder,
            vec![0],
            E::QpackDecoder(qpack::Error::ZeroIncrement),
            http3::error_code::QPACK_DECODER_STREAM_ERROR,
        ),
    ] {
        let mut input = Stream::new(http3::StreamDecoder::after_header(header, Endpoint::Client));
        assert_eq!(input.push(&bytes), bytes.len());
        assert_eq!(input.next(), Some(Ok(Err(expected))));
        assert_eq!(expected.application_code(), Some(code));
    }
    let closed = E::Http3(Error::ClosedCriticalStream);
    assert_eq!(closed.application_code(), Some(http3::error_code::CLOSED_CRITICAL_STREAM));
}

#[test]
fn review_f_wire_errors_distinguish_truncation_trailing_and_protocol() {
    use http3::FrameParseError as H;
    use qpack::ParseError as Q;
    assert_eq!(<EI as Wire>::parse(&[0x3f]), Err(Q::Truncated));
    assert_eq!(<DI as Wire>::parse(&[0xff]), Err(Q::Truncated));
    assert_eq!(<Rep as Wire>::parse(&[]), Err(Q::Truncated));
    assert_eq!(<DI as Wire>::parse(&[0]), Err(Q::Instruction(qpack::Error::ZeroIncrement)));
    assert_eq!(<EI as Wire>::parse(&[0x20, 0]), Err(Q::Trailing));
    assert_eq!(<DI as Wire>::parse(&[1, 1]), Err(Q::Trailing));
    assert_eq!(<Rep as Wire>::parse(&[0xc0, 0]), Err(Q::Trailing));
    assert_eq!(<Frame as Wire>::parse(&[0, 2, 1]), Err(H::Truncated));
    assert_eq!(<Frame as Wire>::parse(&[0, 0, 0]), Err(H::Trailing));
    assert_eq!(<Frame as Wire>::parse(&[2, 0]), Err(H::Frame(http3::Error::UnexpectedFrame(2))));
    assert_eq!(<StreamHeader as Wire>::parse(&[0x40]), Err(H::Truncated));
    assert_eq!(<StreamHeader as Wire>::parse(&[0, 0]), Err(H::Trailing));
}

// Exhaustive external matches ensure the migration preserves both legacy enums.
#[test]
fn review_f_legacy_error_shapes() {
    let q = |error| match error {
        qpack::Error::Truncated
        | qpack::Error::IntegerOverflow
        | qpack::Error::StringTooLong
        | qpack::Error::Huffman
        | qpack::Error::StaticIndex(_)
        | qpack::Error::DynamicIndex(_)
        | qpack::Error::InsertCount
        | qpack::Error::Base
        | qpack::Error::Capacity(_)
        | qpack::Error::EntryTooLarge
        | qpack::Error::ZeroIncrement
        | qpack::Error::Increment
        | qpack::Error::UnknownStream(_)
        | qpack::Error::TooManyBlocked
        | qpack::Error::FieldSectionTooLarge
        | qpack::Error::TooManyFields
        | qpack::Error::Referenced
        | qpack::Error::Backlog => true,
    };
    let h = |error| match error {
        http3::Error::Limit
        | http3::Error::Varint
        | http3::Error::Frame
        | http3::Error::UnexpectedFrame(_)
        | http3::Error::DuplicateSetting(_)
        | http3::Error::Http2Setting(_)
        | http3::Error::SettingValue(_)
        | http3::Error::MissingSettings
        | http3::Error::Id
        | http3::Error::ClosedCriticalStream
        | http3::Error::Message(_)
        | http3::Error::Incomplete
        | http3::Error::Qpack(_)
        | http3::Error::Priority
        | http3::Error::State => true,
    };
    assert!(q(qpack::Error::Backlog));
    assert!(h(http3::Error::State));
}

#[test]
fn review_a_reset_before_section_decode_cancels() {
    let mut held = qpack::BlockedSections::new(4);
    assert_eq!(held.cancel(&Table::new(4096), 4), Some(DI::StreamCancel(4)));
    assert_eq!(held.cancel(&Table::new(0), 4), None);
}

#[test]
fn review_b_increments_without_blocked_streams_and_after_section_acks() {
    let mut encoder = qpack::Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    encoder.set_capacity(4096).unwrap();
    encoder.insert(b"x-first", b"one").unwrap();
    let mut table = Table::new(4096);
    table.apply(EI::SetCapacity(4096)).unwrap();
    table.apply(EI::InsertWithLiteralName { name: b"x-first".to_vec(), value: b"one".to_vec() }).unwrap();
    assert_eq!(table.take_increment(), Some(DI::InsertCountIncrement(1)));
    assert_eq!(table.take_increment(), None);
    encoder.apply_instruction(DI::InsertCountIncrement(1)).unwrap();
    // With zero blocked streams, the encoder can now reference this entry.
    let bytes = encoder.encode_section(4, &[Field::new("x-first", "one")]).unwrap();
    assert!(matches!(
        qpack::decode_section(&table, 4, &bytes),
        Ok(SectionResult::Fields { ack: Some(DI::SectionAck(4)), .. })
    ));
    table.apply(EI::Duplicate(0)).unwrap();
    table.apply(EI::Duplicate(0)).unwrap();
    let bytes = section(2, 2, table.max_entries(), &[Rep::Indexed { static_table: false, index: 0 }]);
    assert!(matches!(
        qpack::decode_section(&table, 8, &bytes),
        Ok(SectionResult::Fields { ack: Some(DI::SectionAck(8)), .. })
    ));
    assert_eq!(table.take_increment(), Some(DI::InsertCountIncrement(1)));
    assert_eq!(table.take_increment(), None);
    // An older section acknowledgment must not move the reported count back.
    qpack::decode_section(&table, 12, &bytes).unwrap();
    assert_eq!(table.take_increment(), None);

    table.apply(EI::Duplicate(0)).unwrap();
    let invalid = section(4, 4, table.max_entries(), &[]);
    assert_eq!(qpack::decode_section(&table, 16, &invalid), Err(qpack::Error::InsertCount));
    assert_eq!(table.take_increment(), Some(DI::InsertCountIncrement(1)));
}

#[test]
fn review_d_legacy_apis_remain_unmarked() {
    for source in [
        include_str!("../src/stdlib/qpack.rs"),
        include_str!("../src/stdlib/http3.rs"),
        include_str!("../fuzz/fuzz_targets/qpack.rs"),
        include_str!("../fuzz/fuzz_targets/http3.rs"),
    ] {
        assert!(!source.contains("#[deprecated"));
        assert!(!source.contains("allow(deprecated)"));
    }
}

#[test]
fn review_e_partial_critical_fin_is_closed_critical_stream() {
    let mut control = Stream::new(http3::ControlFrames::new(Endpoint::Client));
    assert_eq!(control.push(&[0x04, 0x02, 0x01]), 3);
    control.end();
    assert_eq!(control.next(), Some(Err(Fail::Protocol(http3::Error::ClosedCriticalStream))));
}

#[test]
fn review_e_connection_partial_critical_fin_survives_handoff() {
    for bytes in [&[0, 0x04, 0x02, 0x01][..], &[2, 0x3f], &[3, 0xff]] {
        let mut connection = Connection::new(Endpoint::Client, 4, http3::MAX_FRAME);
        assert_eq!(connection.push(2, bytes), bytes.len());
        connection.end(2);
        assert!(matches!(connection.next(), Some((2, Ok(Ok(StreamItem::Header(_)))))));
        assert_eq!(
            connection.next(),
            Some((2, Err(Fail::Protocol(http3::StreamError::Http3(http3::Error::ClosedCriticalStream)))))
        );
        assert!(connection.next().is_none());
    }
}

#[test]
fn http3_invalid_frame_headers_fail_without_buffering_payloads() {
    for kind in [2, 6, 8, 9] {
        let bytes = [kind, 0x43, 0xe8]; // Declares 1000 forbidden payload bytes.
        assert_eq!(http3::Frames.decode(&bytes, false), Err(http3::Error::UnexpectedFrame(kind as u64)));
    }
    for kind in [3, 7, 0x0d] {
        for length in [0, 9, 262_128] {
            let mut bytes = vec![kind];
            fictionet::stdlib::quic::write_varint(length, &mut bytes).unwrap();
            assert_eq!(http3::Frames.decode(&bytes, false), Err(http3::Error::Frame));
        }
    }
}

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
        let mut ack_bytes = Vec::new();
        for ack in &ack_values {
            Wire::write(ack, &mut ack_bytes).unwrap();
            contract::check_wire_value(ack);
        }
        contract::check_decode(qpack::DecoderInstructions::new, &ack_bytes);
        let mut acks = Stream::new(qpack::DecoderInstructions::new());
        let mut got = Vec::new();
        for b in &ack_bytes {
            pump(&mut acks, core::slice::from_ref(b), |item| got.push(item.unwrap())).unwrap();
        }
        finish(&mut acks, |item| got.push(item.unwrap())).unwrap();
        assert_eq!(got, ack_values);
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
    assert_eq!(held.cancel(&table, 0), Some(DI::StreamCancel(0)));
    assert_eq!(held.cancel(&table, 0), Some(DI::StreamCancel(0)));
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
fn qpack_strict_writers() {
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
    assert_eq!(<EI as Wire>::parse(&trailing), Err(qpack::ParseError::Trailing));
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
fn http3_many_small_streams_allocate_in_proportion_to_input() {
    const COUNT: usize = 512;
    const FIRST: &[u8] = &[0, 100, 7];
    let mut connection = Connection::new(Endpoint::Client, COUNT, COUNT * FIRST.len());
    for index in 0..COUNT {
        let id = index as u64 * 4;
        assert_eq!(connection.push(id, FIRST), FIRST.len());
    }
    assert_eq!(connection.buffered(), COUNT * FIRST.len());
    let mut allocated = 0;
    for index in 0..COUNT {
        let (buffer, _) = connection.remove(index as u64 * 4).unwrap().into_parts();
        allocated += buffer.allocated();
    }
    assert!(allocated <= COUNT * FIRST.len() * 2);
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
    assert_eq!(http3::Frames.decode(&[2, 0], false), Err(http3::Error::UnexpectedFrame(2)));

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
    assert_eq!(
        connection.next(),
        Some((11, Err(Fail::Protocol(http3::StreamError::Http3(http3::Error::ClosedCriticalStream)))))
    );
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
    assert_eq!(<Frame as Wire>::parse(&bytes), Err(http3::FrameParseError::Trailing));
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
