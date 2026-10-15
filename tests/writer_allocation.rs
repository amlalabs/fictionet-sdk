//! Bounded protocol appends return allocation refusals without changing output.

use fictionet::stdlib::codec::{Buffer, Frames, Stream, Wire, pump};
use fictionet::stdlib::{dhcpv6, kafka, onc_rpc, syslog, thrift};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct RefusingAllocator;

thread_local! {
    static REFUSE_LARGE: Cell<bool> = const { Cell::new(false) };
    static MEASUREMENT: Cell<Option<Measurement>> = const { Cell::new(None) };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AllocationStats {
    // Allocation and reallocation requests, including refused requests.
    allocations: usize,
    bytes_requested: usize,
    // Peak net live bytes above the fixture baseline at scope entry.
    peak_live_bytes: usize,
    largest_request: usize,
}

#[derive(Clone, Copy, Default)]
struct Measurement {
    stats: AllocationStats,
    // Signed because an operation can release a prebuilt fixture.
    live: i128,
}

fn record(request: Option<usize>, live_change: i128) {
    // TLS may be unavailable during thread teardown, after the scope ended.
    MEASUREMENT
        .try_with(|cell| {
            if let Some(mut measurement) = cell.get() {
                if let Some(size) = request {
                    let stats = &mut measurement.stats;
                    stats.allocations = stats.allocations.saturating_add(1);
                    stats.bytes_requested = stats.bytes_requested.saturating_add(size);
                    stats.largest_request = stats.largest_request.max(size);
                }
                measurement.live = measurement.live.saturating_add(live_change);
                measurement.stats.peak_live_bytes = measurement
                    .stats
                    .peak_live_bytes
                    .max(usize::try_from(measurement.live.max(0)).unwrap_or(usize::MAX));
                cell.set(Some(measurement));
            }
        })
        .unwrap_or(());
}

fn refuses(size: usize) -> bool {
    size >= 1024 && REFUSE_LARGE.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: Accepted requests and all deallocations use System with the original
// layout. Refused requests return null, as the allocator contract permits.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = if refuses(layout.size()) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        };
        record(
            Some(layout.size()),
            if ptr.is_null() {
                0
            } else {
                layout.size() as i128
            },
        );
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(None, -(layout.size() as i128));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = if refuses(size) {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        };
        record(
            Some(size),
            if next.is_null() {
                0
            } else {
                size as i128 - layout.size() as i128
            },
        );
        next
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;

fn refusing_large<T>(write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE_LARGE.set(false);
        }
    }
    REFUSE_LARGE.set(true);
    let _reset = Reset;
    write()
}

// Build fixtures before calling. Only allocator events on this thread count.
// Reallocation requests count their full new size; live bytes change only on
// success. Freeing fixture storage lowers net live bytes, not requested bytes.
fn measuring<T>(operation: impl FnOnce() -> T) -> (T, AllocationStats) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MEASUREMENT.set(None);
        }
    }
    MEASUREMENT.with(|cell| {
        assert!(cell.get().is_none(), "nested allocation measurement");
        cell.set(Some(Measurement::default()));
    });
    let _reset = Reset;
    let result = operation();
    let measurement = MEASUREMENT.take().expect("active allocation measurement");
    let stats = measurement.stats;
    assert!(
        stats.allocations < usize::MAX
            && stats.bytes_requested < usize::MAX
            && stats.peak_live_bytes < usize::MAX
            && stats.largest_request < usize::MAX
            && measurement.live > i128::MIN,
        "allocation measurement saturated"
    );
    (result, stats)
}

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
