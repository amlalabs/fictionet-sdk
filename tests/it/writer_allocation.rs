//! Bounded protocol appends return allocation refusals without changing output.

use fictionet::stdlib::codec::{Buffer, Frames, Stream, Wire, pump};
use fictionet::stdlib::{dhcpv6, kafka, onc_rpc, opcua, syslog, thrift};

use crate::common::alloc::{AllocationStats, MEASUREMENT, measuring, refusing_large};

#[test]
fn measurement_excludes_fixture_construction() {
    let fixture = vec![7u8; 4096];
    let (sum, stats) = measuring(|| fixture.iter().copied().map(u64::from).sum::<u64>());
    assert_eq!(sum, 7 * 4096);
    assert_eq!(stats, AllocationStats::default());
}

#[test]
fn eager_invalid_count_allocation_is_measured() {
    for n in [1024, 4096] {
        let (bytes, stats) = measuring(|| std::hint::black_box(Vec::<u8>::with_capacity(n)));
        assert_eq!(bytes.capacity(), n);
        assert_eq!(
            stats,
            AllocationStats {
                allocations: 1,
                bytes_requested: n,
                peak_live_bytes: n,
                largest_request: n,
            }
        );
    }
}

#[test]
fn measurement_tracks_reallocation_and_released_storage() {
    let ((), stats) = measuring(|| {
        let mut bytes = std::hint::black_box(Vec::<u8>::with_capacity(32));
        bytes.reserve_exact(96);
        std::hint::black_box(&bytes);
        drop(bytes);
        let other = std::hint::black_box(Vec::<u8>::with_capacity(64));
        std::hint::black_box(&other);
    });
    assert_eq!(
        stats,
        AllocationStats {
            allocations: 3,
            bytes_requested: 32 + 96 + 64,
            peak_live_bytes: 96,
            largest_request: 96,
        }
    );
}

#[test]
fn measurement_tracks_fixture_growth_and_shrinkage() {
    let mut bytes = Vec::<u8>::with_capacity(32);
    let ((), stats) = measuring(|| {
        bytes.reserve_exact(96);
        bytes.resize(16, 0);
        bytes.shrink_to_fit();
        std::hint::black_box(&bytes);
    });
    assert_eq!(
        stats,
        AllocationStats {
            allocations: 2,
            bytes_requested: 96 + 16,
            peak_live_bytes: 64,
            largest_request: 96,
        }
    );
}

#[test]
fn measurement_counts_refused_requests_without_live_growth() {
    let mut bytes = Vec::<u8>::with_capacity(32);
    let (result, stats) = measuring(|| refusing_large(|| bytes.try_reserve_exact(4096)));
    assert!(result.is_err());
    assert_eq!(
        stats,
        AllocationStats {
            allocations: 1,
            bytes_requested: 4096,
            peak_live_bytes: 0,
            largest_request: 4096,
        }
    );
    assert_eq!(bytes.capacity(), 32);
}

#[test]
fn measurement_resets_after_unwinding() {
    let result = std::panic::catch_unwind(|| measuring(|| panic!("operation failed")));
    assert!(result.is_err());
    assert!(MEASUREMENT.get().is_none());
    assert_eq!(measuring(|| ()).1, AllocationStats::default());
}

#[test]
fn xdr_array_no_eager_reservation() {
    let mut bytes = (1u32 << 20).to_be_bytes().to_vec();
    bytes.resize(4 + (4 << 20), 0);
    let big = |reader: &mut onc_rpc::Reader<'_>| -> Result<[u8; 1 << 16], onc_rpc::Error> {
        reader.uint()?;
        Err(onc_rpc::Error::Padding)
    };
    let (result, stats) = measuring(|| onc_rpc::Reader::new(&bytes).array(usize::MAX, big));
    assert_eq!(result, Err(onc_rpc::Error::Padding));
    assert!(
        stats.largest_request <= onc_rpc::MAX_RESERVE_BYTES,
        "XDR first-item refusal exceeded the preallocation bound: {stats:?}"
    );
}

#[test]
fn opcua_opn_rejects_before_slice_collection() {
    let policy = "urn:other".to_string();
    let fixed = opcua::HEADER_LEN + 4 + (4 + policy.len()) + 4 + 4 + 8;
    let header = opcua::AsymmetricHeader {
        policy_uri: policy,
        // Leave one byte per chunk, so collecting slices scales with the body.
        sender_certificate: Some(vec![0; opcua::MIN_BUFFER_SIZE as usize - fixed - 1]),
        receiver_thumbprint: None,
    };
    let messages = [4 << 20, 16 << 20].map(|size| opcua::SecureMessage {
        kind: opcua::SecureKind::Open(header.clone()),
        channel_id: 0,
        sequence_number: 0,
        request_id: 0,
        body: vec![0; size],
    });
    let limits = opcua::Limits::default();
    let stats = messages.each_ref().map(|opn| {
        let (result, stats) = measuring(|| opn.chunks(&limits));
        assert_eq!(result, Err(opcua::Error::TooLong));
        // Security-header Writer requests 8 + 17 + 34 + 8171 + 16342 bytes,
        // counting each realloc's full new size. Four minimum buffers allow
        // this fixed header cost without allowing body-proportional storage.
        assert!(
            stats.bytes_requested <= 4 * opcua::MIN_BUFFER_SIZE as usize,
            "{}-byte OPN exceeded its temporary allocation budget: {stats:?}",
            opn.body.len()
        );
        stats
    });
    assert_eq!(
        stats[0].bytes_requested, stats[1].bytes_requested,
        "OPN temporary allocations depend on body size: {stats:?}"
    );
}

#[test]
fn xdr_allocation_refusal_is_sticky_and_preserves_written_bytes() {
    let mut writer = onc_rpc::Writer::new();
    writer.uint(42);
    let bytes = vec![7; 4096];
    refusing_large(|| {
        writer.opaque_fixed(&bytes);
    });
    writer.uint(1);
    writer.reject(onc_rpc::Error::Unwritable);
    assert_eq!(writer.as_bytes(), 42u32.to_be_bytes());
    assert_eq!(writer.finish(), Err(onc_rpc::Error::Allocation));
}

#[test]
fn kafka_allocation_refusal_leaves_output_unchanged() {
    let header = kafka::RequestHeader {
        api_key: kafka::api_key::API_VERSIONS,
        client_id: Some("x".repeat(4096)),
        ..Default::default()
    };
    let mut out = vec![42];
    assert_eq!(
        refusing_large(|| header.write(&mut out)),
        Err(kafka::Error::Unwritable)
    );
    assert_eq!(out, [42]);
}

#[test]
fn thrift_allocation_refusal_leaves_output_unchanged() {
    let value = thrift::ValueBody::<false, 11>(thrift::Value::Binary(vec![7; 4096]));
    let mut out = vec![42];
    assert_eq!(
        refusing_large(|| value.write(&mut out)),
        Err(thrift::Error::Unwritable)
    );
    assert_eq!(out, [42]);
}

#[test]
fn dhcpv6_allocation_refusal_leaves_output_unchanged() {
    let mut message = dhcpv6::Message::new(dhcpv6::msg::SOLICIT, 1);
    message
        .options
        .push(dhcpv6::DhcpOption::InterfaceId(vec![7; 4096]));
    let mut out = vec![42];
    assert_eq!(
        refusing_large(|| message.write(&mut out)),
        Err(dhcpv6::Error::Unwritable)
    );
    assert_eq!(out, [42]);
}

#[test]
fn dhcpv6_fragmented_prefix_allocates_only_for_buffer_growth_and_one_parse() {
    let mut message = dhcpv6::Message::new(dhcpv6::msg::SOLICIT, 7);
    // Each Preference occupies five wire bytes. An ElapsedTime fills the
    // remaining six bytes after the four-byte message header.
    let options = (dhcpv6::MAX_TCP_MESSAGE - dhcpv6::CLIENT_HEADER_LEN - 6) / 5;
    message.options = (0..options)
        .map(|i| dhcpv6::DhcpOption::Preference(i as u8))
        .collect();
    message.options.push(dhcpv6::DhcpOption::ElapsedTime(42));
    let expected = dhcpv6::Frame(message);
    let input = expected.to_bytes().unwrap();
    assert_eq!(input.len(), dhcpv6::MAX_BUFFERED);

    let (parsed, parse_stats) = measuring(|| dhcpv6::Frame::parse(&input).unwrap());
    assert_eq!(parsed, expected);
    assert!(parse_stats.allocations > 0);

    // Hold the message fixed while increasing the number of partial prefixes.
    for chunk_size in [input.len(), 1024, 256, 64, 1] {
        let ((), growth_stats) = measuring(|| {
            let mut buffer = Buffer::new(dhcpv6::MAX_BUFFERED);
            for chunk in input.chunks(chunk_size) {
                assert_eq!(buffer.push(chunk), chunk.len());
            }
            assert_eq!(buffer.unread(), input);
        });
        let mut stream = Stream::new(Frames::<dhcpv6::Message>::new());
        let mut decoded = None;
        let ((), stats) = measuring(|| {
            for chunk in input.chunks(chunk_size) {
                assert_eq!(
                    pump(&mut stream, chunk, |item| {
                        assert!(decoded.is_none(), "unexpected extra message");
                        decoded = Some(item.unwrap());
                    })
                    .unwrap(),
                    chunk.len()
                );
            }
        });
        assert_eq!(decoded.as_ref(), Some(&expected.0));
        assert_eq!(stream.buffered(), 0);
        stream.end();
        assert_eq!(stream.next(), None);
        let allowance = growth_stats.allocations + parse_stats.allocations;
        assert!(
            stats.allocations <= allowance,
            "chunk size {chunk_size}: {} allocations exceed {allowance} \
             ({} for buffer growth + {} for one parse)",
            stats.allocations,
            growth_stats.allocations,
            parse_stats.allocations
        );
    }
}

#[test]
fn syslog_allocation_refusal_leaves_output_unchanged() {
    let mut message = syslog::Message::new(syslog::Priority::new(
        syslog::Facility::User,
        syslog::Severity::Notice,
    ));
    message.msg = vec![b'x'; 4096];
    let mut out = vec![42];
    assert_eq!(
        refusing_large(|| message.write(&mut out)),
        Err(syslog::Error::Unwritable)
    );
    assert_eq!(out, [42]);
}
