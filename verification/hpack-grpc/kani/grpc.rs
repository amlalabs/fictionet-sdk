//! Kani proofs over gRPC message framing in src/stdlib/protocols/grpc.rs:
//! `parse_message`, which `Message::parse_prefix` (read by the `Grpc`
//! layer in src/stdlib/web/httpd/http2/grpc.rs) and the `Frames<Message>`
//! decoder both call, and `Message::write`, which the layer frames every
//! reply with. Compiled only under `cargo kani`, as a child module of
//! grpc.rs, so each harness calls the production code.
//!
//! How the layer reads a call's bytes through these, split anywhere and
//! with the application behind, is verification/hpack-grpc/tla/GrpcCall.tla.

use super::*;

/// For any input of up to eight bytes and any limit: no byte is a message
/// until the 5-byte prefix is whole, except that a flag other than 0 or 1
/// is refused at the first byte; a whole prefix whose big-endian length is
/// over the limit is refused from the prefix alone, however few body bytes
/// follow; otherwise the message waits until its body is whole, and then
/// is exactly the flag and the next `length` bytes, taking `5 + length`.
#[kani::proof]
#[kani::unwind(10)]
fn the_prefix_is_read_exactly() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let b = &bytes[..len];
    let limit: usize = kani::any();
    let result = parse_message(b, limit);
    if len == 0 {
        assert_eq!(result, Ok(None));
        return;
    }
    if bytes[0] > 1 {
        assert_eq!(result, Err(Error::Flag(bytes[0])));
        return;
    }
    if len < HEADER_LEN {
        assert_eq!(result, Ok(None));
        return;
    }
    let length = u32::from(bytes[1]) << 24
        | u32::from(bytes[2]) << 16
        | u32::from(bytes[3]) << 8
        | u32::from(bytes[4]);
    if length as usize > limit {
        assert_eq!(result, Err(Error::TooLarge { length, limit }));
        return;
    }
    let end = HEADER_LEN + length as usize;
    if len < end {
        assert_eq!(result, Ok(None));
        return;
    }
    let (message, used) = result.unwrap().unwrap();
    assert_eq!(used, end);
    assert_eq!(message.compressed, bytes[0] == 1);
    assert_eq!(message.data.as_slice(), &bytes[HEADER_LEN..end]);
}

/// Any message of up to three body bytes, either flag, is written as its
/// flag, its length big-endian and its body, appended after what `out`
/// held, and reads back as itself taking every byte; a body over
/// `MAX_MESSAGE` is refused before anything is written (`message_length`,
/// for every length).
#[kani::proof]
#[kani::unwind(10)]
fn messages_write_and_read_back() {
    let body: [u8; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 3);
    let message = Message {
        compressed: kani::any(),
        data: body[..len].to_vec(),
    };
    let before: u8 = kani::any();
    let mut out = vec![before];
    assert_eq!(message.write(&mut out), Ok(()));
    assert_eq!(out[0], before);
    let wire = &out[1..];
    assert_eq!(wire.len(), HEADER_LEN + len);
    assert_eq!(wire[0], u8::from(message.compressed));
    assert_eq!(&wire[1..5], &(len as u32).to_be_bytes());
    assert_eq!(
        parse_message(wire, MAX_MESSAGE),
        Ok(Some((message, wire.len())))
    );

    let any: usize = kani::any();
    match message_length(any) {
        Ok(n) => assert!(any <= MAX_MESSAGE && n as usize == any),
        Err(Error::TooLarge { limit, .. }) => assert!(any > MAX_MESSAGE && limit == MAX_MESSAGE),
        Err(_) => unreachable!(),
    }
}
