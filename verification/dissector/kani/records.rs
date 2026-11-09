//! Kani proofs over `TlsRecords::decode` in src/stdlib/dissect/protocols.rs,
//! the framing of a passive TLS direction. Compiled only under
//! `cargo kani`, as a child module of protocols.rs, so the harnesses call
//! the production decoder.

use super::*;

/// The longest input the first harness gives the decoder.
const INPUT: usize = 8;

/// For any bytes up to eight long, with any payload left to skip, and at
/// the end of the stream or not, one step keeps the `Decode` contract and
/// frames a record by its header:
///
/// - it never takes more than its input, and never takes nothing as a step;
/// - while skipping an oversized payload, it takes exactly what is left of
///   it in the input;
/// - otherwise a record starts at a whole header and takes exactly the
///   header and the length the header names, or, when that length is more
///   than the buffer keeps and not all there, the header alone, with the
///   length left to skip;
/// - it asks for more only while the record is not all there.
#[kani::proof]
#[kani::unwind(10)]
fn records_take_exactly_what_their_header_names() {
    let bytes: [u8; INPUT] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= INPUT);
    let input = &bytes[..len];
    let skip: usize = kani::any();
    let mut records = TlsRecords { skip };
    let length = (len >= 5).then(|| usize::from(u16::from_be_bytes([input[3], input[4]])));
    match records.decode(input, kani::any()) {
        Ok(Step::Skip(n)) => {
            assert!(skip != 0);
            assert!(n > 0 && n <= len);
            assert_eq!(n, skip.min(len));
            assert_eq!(records.skip, skip - n);
        }
        Ok(Step::Need) => {
            assert_eq!(records.skip, skip);
            if skip != 0 {
                assert_eq!(len, 0);
            } else if let Some(length) = length {
                assert!(length <= MAX_BUFFER - 5 && len < 5 + length);
            }
        }
        Ok(Step::Item(record, n)) => {
            assert_eq!(skip, 0);
            let length = length.unwrap();
            assert_eq!(record.length, length);
            if record.oversized {
                assert!(length > MAX_BUFFER - 5 && len < 5 + length);
                assert_eq!(n, 5);
                assert_eq!(records.skip, length);
            } else {
                assert_eq!(n, 5 + length);
                assert!(n <= len);
                assert_eq!(records.skip, 0);
            }
        }
        Ok(Step::End) => panic!("a record stream does not end itself"),
        Err(never) => match never {},
    }
}

/// Once the input fills the decoder's capacity, up to the 65,540 bytes of
/// read-ahead a session gives it, a step always takes something: the
/// driver never finds it stuck at a full buffer. Only the header bytes and
/// the length of the input are read.
#[kani::proof]
fn records_take_something_from_a_full_buffer() {
    let bytes: [u8; 65_540] = kani::any();
    let len: usize = kani::any();
    let mut records = TlsRecords::default();
    kani::assume(len >= records.capacity() && len <= bytes.len());
    match records.decode(&bytes[..len], kani::any()) {
        Ok(Step::Item(_, n)) => assert!(n > 0 && n <= len),
        _ => panic!("a full buffer must give a record"),
    }
}
