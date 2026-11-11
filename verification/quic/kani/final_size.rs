use super::*;

#[kani::proof]
fn final_sizes_preserve_received_bytes_and_known_end() {
    let known: Option<u64> = kani::any();
    let high: u64 = kani::any();
    let end: u64 = kani::any();
    let fin: bool = kani::any();
    let allowed = valid_final_size(known, high, end, fin);
    if allowed {
        assert!(!fin || end >= high);
        if let Some(size) = known {
            assert!(end <= size);
            assert!(!fin || end == size);
        }
    } else {
        assert!(
            (fin && end < high) || known.is_some_and(|size| end > size || (fin && end != size))
        );
    }
}

#[kani::proof]
fn a_short_final_frame_leaves_receive_state_unchanged() {
    let high: u64 = kani::any();
    let end: u64 = kani::any();
    kani::assume(high <= VarInt::MAX.into_inner());
    kani::assume(end < high);
    let stopped = kani::any();
    let mut recv = Recv {
        end: high,
        stopped,
        sent_max_stream_data: VarInt::MAX.into_inner(),
        ..Recv::default()
    };
    let frame = frame::Stream {
        id: StreamId::new(crate::Side::Client, crate::Dir::Uni, 0),
        offset: end,
        fin: true,
        data: bytes::Bytes::new(),
    };
    let error = recv
        .ingest(frame, 0, high, VarInt::MAX.into_inner())
        .unwrap_err();
    assert_eq!(u64::from(error.code), 6);
    assert_eq!(recv.end, high);
    assert_eq!(recv.final_offset(), None);
    assert_eq!(recv.stopped, stopped);
    assert_eq!(recv.assembler.bytes_read(), 0);
}
