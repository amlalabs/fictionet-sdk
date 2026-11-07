//! `Reader` and the free offset readers: every read either consumes exactly
//! its width and returns those bytes, or fails and leaves the position where
//! it was (length-prefixed reads consume a complete prefix first).

use super::bytes;
use fictionet::stdlib::codec::{
    Reader, Trailing, Truncated, be16, be24, be32, be64, le16, le24, le32, le64,
};

const N: usize = 6;

#[kani::proof]
#[kani::unwind(8)]
fn take_skip_rest_and_finish() {
    let (bytes, len) = bytes::<N>();
    let bytes = &bytes[..len];
    let mut r = Reader::new(bytes);
    let skip: usize = kani::any();
    let skipped = r.skip(skip);
    assert_eq!(skipped.is_ok(), skip <= len);
    let position = r.position();
    assert_eq!(position, if skip <= len { skip } else { 0 });
    assert_eq!(r.remaining(), len - position);
    assert_eq!(r.is_empty(), position == len);
    assert_eq!(r.peek_u8(), bytes.get(position).copied());
    assert_eq!(
        r.finish(),
        if position == len {
            Ok(())
        } else {
            Err(Trailing(len - position))
        }
    );
    let n: usize = kani::any();
    match r.take(n) {
        Ok(slice) => {
            assert!(n <= len - position);
            assert_eq!(slice, &bytes[position..position + n]);
            assert_eq!(r.position(), position + n);
        }
        Err(Truncated) => {
            assert!(n > len - position);
            assert_eq!(r.position(), position);
        }
    }
    let position = r.position();
    assert_eq!(r.rest(), &bytes[position..]);
    assert!(r.is_empty());
    assert_eq!(r.finish(), Ok(()));
}

macro_rules! fixed_width {
    ($name:ident, $width:expr, $($read:ident => $from:expr),+ $(,)?) => {
        #[kani::proof]
        #[kani::unwind(12)]
        fn $name() {
            let (bytes, len) = bytes::<10>();
            let bytes = &bytes[..len];
            let at: usize = kani::any();
            kani::assume(at <= len);
            $(
                let mut r = Reader::new(bytes);
                r.skip(at).unwrap();
                match r.$read() {
                    Ok(value) => {
                        assert!(at + $width <= len);
                        let mut array = [0u8; $width];
                        array.copy_from_slice(&bytes[at..at + $width]);
                        assert_eq!(value, $from(array));
                        assert_eq!(r.position(), at + $width);
                    }
                    Err(Truncated) => {
                        assert!(at + $width > len);
                        assert_eq!(r.position(), at);
                    }
                }
            )+
        }
    };
}

fixed_width!(one_byte_reads, 1, u8 => |[a]: [u8; 1]| a, i8 => |[a]: [u8; 1]| a as i8);
fixed_width!(two_byte_reads, 2,
    u16_be => u16::from_be_bytes, u16_le => u16::from_le_bytes,
    i16_be => i16::from_be_bytes, i16_le => i16::from_le_bytes);
fixed_width!(three_byte_reads, 3,
    u24_be => |[a, b, c]: [u8; 3]| u32::from_be_bytes([0, a, b, c]),
    u24_le => |[a, b, c]: [u8; 3]| u32::from_le_bytes([a, b, c, 0]));
fixed_width!(four_byte_reads, 4,
    u32_be => u32::from_be_bytes, u32_le => u32::from_le_bytes,
    i32_be => i32::from_be_bytes, i32_le => i32::from_le_bytes);
fixed_width!(eight_byte_reads, 8,
    u64_be => u64::from_be_bytes, u64_le => u64::from_le_bytes,
    i64_be => i64::from_be_bytes, i64_le => i64::from_le_bytes);

#[kani::proof]
#[kani::unwind(12)]
fn float_reads_carry_every_bit_pattern() {
    let (bytes, len) = bytes::<10>();
    let bytes = &bytes[..len];
    let at: usize = kani::any();
    kani::assume(at <= len);
    for little in [false, true] {
        let mut r = Reader::new(bytes);
        r.skip(at).unwrap();
        let read = if little { r.f64_le() } else { r.f64_be() };
        match read {
            Ok(value) => {
                assert!(at + 8 <= len);
                let mut array = [0u8; 8];
                array.copy_from_slice(&bytes[at..at + 8]);
                let expected = if little {
                    u64::from_le_bytes(array)
                } else {
                    u64::from_be_bytes(array)
                };
                assert_eq!(value.to_bits(), expected);
                assert_eq!(r.position(), at + 8);
            }
            Err(Truncated) => {
                assert!(at + 8 > len);
                assert_eq!(r.position(), at);
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(12)]
fn offset_readers_agree_with_the_cursor() {
    let (bytes, len) = bytes::<10>();
    let bytes = &bytes[..len];
    let at: usize = kani::any();
    macro_rules! check {
        ($free:ident, $width:expr, $read:ident) => {
            let value = $free(bytes, at);
            assert_eq!(
                value.is_some(),
                at.checked_add($width).is_some_and(|end| end <= len)
            );
            if let Some(value) = value {
                let mut r = Reader::new(bytes);
                r.skip(at).unwrap();
                assert_eq!(r.$read(), Ok(value));
            }
        };
    }
    check!(be16, 2, u16_be);
    check!(le16, 2, u16_le);
    check!(be24, 3, u24_be);
    check!(le24, 3, u24_le);
    check!(be32, 4, u32_be);
    check!(le32, 4, u32_le);
    check!(be64, 8, u64_be);
    check!(le64, 8, u64_le);
}

#[kani::proof]
#[kani::unwind(8)]
fn length_prefixed_reads_consume_a_complete_prefix() {
    let (bytes, len) = bytes::<N>();
    let bytes = &bytes[..len];
    let at: usize = kani::any();
    kani::assume(at <= len);

    let mut r = Reader::new(bytes);
    r.skip(at).unwrap();
    match r.length_prefixed_u8() {
        Ok(slice) => {
            let n = usize::from(bytes[at]);
            assert_eq!(slice, &bytes[at + 1..at + 1 + n]);
            assert_eq!(r.position(), at + 1 + n);
        }
        Err(Truncated) => {
            if at == len {
                assert_eq!(r.position(), at);
            } else {
                assert!(at + 1 + usize::from(bytes[at]) > len);
                assert_eq!(r.position(), at + 1);
            }
        }
    }

    let mut r = Reader::new(bytes);
    r.skip(at).unwrap();
    match r.length_prefixed_u16_be() {
        Ok(slice) => {
            let n = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            assert_eq!(slice, &bytes[at + 2..at + 2 + n]);
            assert_eq!(r.position(), at + 2 + n);
        }
        Err(Truncated) => {
            if at + 2 > len {
                assert_eq!(r.position(), at);
            } else {
                let n = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
                assert!(at + 2 + n > len);
                assert_eq!(r.position(), at + 2);
            }
        }
    }

    let mut r = Reader::new(bytes);
    r.skip(at).unwrap();
    match r.tlv_u16_be() {
        Ok((tag, body)) => {
            assert_eq!(tag, u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            let n = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
            assert_eq!(body, &bytes[at + 4..at + 4 + n]);
            assert_eq!(r.position(), at + 4 + n);
        }
        Err(Truncated) => {
            assert_eq!(r.position(), at);
            if at + 4 <= len {
                let n = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
                assert!(at + 4 + n > len);
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn nul_terminated_reads_stop_at_the_first_nul() {
    let (bytes, len) = bytes::<N>();
    let bytes = &bytes[..len];
    let at: usize = kani::any();
    kani::assume(at <= len);
    let mut r = Reader::new(bytes);
    r.skip(at).unwrap();
    let rest = &bytes[at..];
    let nul = rest.iter().position(|&b| b == 0);
    match r.nul_bytes() {
        Ok(field) => {
            let end = nul.unwrap();
            assert_eq!(field, &rest[..end]);
            assert!(!field.contains(&0));
            assert_eq!(r.position(), at + end + 1);
        }
        Err(Truncated) => {
            assert!(nul.is_none());
            assert_eq!(r.position(), at);
        }
    }
}
