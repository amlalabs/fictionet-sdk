//! Kani proof over the frame-level stream rules of RFC 9113 that the TLA+
//! models (`StreamRules.tla`, `H2Streams.tla`, `SessionStreams.tla`) take
//! as given: the frame decoder's refusals and their scope
//! (`Inputs::decode`). Compiled only under `cargo kani`, as a child module
//! of src/stdlib/protocols/http2.rs, so the harness calls the production
//! code both `Http2` and `Session` read frames with. The header-block
//! sequencing is the test `header_blocks_take_only_their_own_continuation`
//! in that file: CBMC did not finish it in 15 minutes.
//!
//! Header fields are symbolic over their whole types unless a harness
//! says otherwise; payloads are up to eight symbolic bytes.

use super::*;

/// The nine header bytes of a frame of `length` bytes.
fn header_bytes(length: usize, kind: u8, flags: u8, stream: u32) -> [u8; HEADER_LEN] {
    let [_, l0, l1, l2] = (length as u32).to_be_bytes();
    let [s0, s1, s2, s3] = stream.to_be_bytes();
    [l0, l1, l2, kind, flags, s0, s1, s2, s3]
}

/// RFC 9113 sections 6.1 to 6.10 and 4.2, for every frame type with a
/// stream rule: a frame that must name a stream and names stream 0, or
/// must name stream 0 and names another, is a connection error
/// PROTOCOL_ERROR; RST_STREAM of the wrong length is a connection error
/// FRAME_SIZE_ERROR. PRIORITY is judged alone (sections 5.3.2 and 6.3):
/// on stream 0 a connection error PROTOCOL_ERROR; of the wrong length a
/// FRAME_SIZE_ERROR with stream scope, and depending on its own stream a
/// PROTOCOL_ERROR with stream scope, which the caller turns into a
/// connection error only where a stream error cannot be sent (an idle
/// stream, or inside a header block); otherwise a frame that changes no
/// state. The reserved bit of the stream identifier is ignored (section
/// 4.1).
#[kani::proof]
#[kani::unwind(10)]
fn frame_refusals_have_the_rfcs_code_and_scope() {
    let kind: u8 = kani::any();
    kani::assume(kind <= 9);
    let flags: u8 = kani::any();
    let raw: u32 = kani::any();
    let stream = raw & MAX_WINDOW;
    let length: usize = kani::any();
    kani::assume(length <= 8);
    let payload: [u8; 8] = kani::any();
    let mut bytes = header_bytes(length, kind, flags, raw).to_vec();
    bytes.extend_from_slice(&payload[..length]);
    let mut inputs = Inputs::with_limit(16);
    let step = inputs
        .decode(&bytes, false)
        .expect("a header is never a framing fault");
    let Step::Item(item, _) = step else {
        panic!("a whole frame always gives an item");
    };
    let refused = |code: ErrorCode, scope: ErrorScope| matches!(&item, Input::Refused { error, scope: s, .. } if error.code == code && *s == scope);
    if matches!(kind, 0 | 1 | 2 | 3 | 5 | 9) && stream == 0 {
        assert!(refused(ErrorCode::ProtocolError, ErrorScope::Connection));
    } else if matches!(kind, 4 | 6 | 7) && stream != 0 {
        assert!(refused(ErrorCode::ProtocolError, ErrorScope::Connection));
    } else if kind == 2 {
        if length != 5 {
            assert!(refused(ErrorCode::FrameSizeError, ErrorScope::Stream));
        } else {
            let dependency = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if dependency & MAX_WINDOW == stream {
                assert!(refused(ErrorCode::ProtocolError, ErrorScope::Stream));
            } else {
                assert!(matches!(&item, Input::Frame(Frame::Priority(p)) if p.stream == stream));
            }
        }
    } else if kind == 3 {
        if length != 4 {
            assert!(refused(ErrorCode::FrameSizeError, ErrorScope::Connection));
        } else {
            assert!(matches!(&item, Input::Frame(Frame::Reset(r)) if r.stream == stream));
        }
    }
    // A stream scope is only ever PRIORITY's or a zero WINDOW_UPDATE
    // increment's, on a stream other than 0.
    if let Input::Refused {
        scope: ErrorScope::Stream,
        header,
        error,
        ..
    } = &item
    {
        assert!(header.stream != 0);
        assert!(header.kind == 2 || (header.kind == 8 && error.code == ErrorCode::ProtocolError));
    }
}
