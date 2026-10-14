//! Bounded protocol appends return allocation refusals without changing output.

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::{dhcpv6, kafka, onc_rpc, syslog, thrift};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct RefusingAllocator;

thread_local! {
    static REFUSE_LARGE: Cell<bool> = const { Cell::new(false) };
}

fn refuses(size: usize) -> bool {
    size >= 1024 && REFUSE_LARGE.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: Accepted requests and all deallocations use System with the original
// layout. Refused requests return null, as the allocator contract permits.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuses(layout.size()) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuses(size) {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
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
