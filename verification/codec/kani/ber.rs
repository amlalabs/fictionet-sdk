//! BER lengths and base-128 integers: writing then reading gives the value
//! back in its minimal form for every `u128`, a value read is the only
//! encoding of itself, and a length prefix agrees with its octets.

extern crate alloc;

use super::bytes;
use alloc::vec::Vec;
use fictionet::stdlib::codec::ber::{
    Base128Prefix, Error, LengthPolicy, LengthPrefix, read_base128, read_length, write_base128,
};

/// The minimal base-128 length of `value`: one group per seven bits, at least one.
fn groups(value: u128) -> usize {
    ((128 - value.leading_zeros()) as usize).max(1).div_ceil(7)
}

#[kani::proof]
#[kani::unwind(21)]
fn every_u128_roundtrips_minimally() {
    let value: u128 = kani::any();
    let max: u128 = kani::any();
    let mut out = Vec::new();
    match write_base128(&mut out, value, max) {
        Err(error) => {
            assert_eq!(error, Error::Base128Limit);
            assert!(value > max);
            assert!(out.is_empty());
        }
        Ok(()) => {
            assert!(value <= max);
            assert_eq!(out.len(), groups(value));
            assert!(out[..out.len() - 1].iter().all(|b| b & 0x80 != 0));
            assert_eq!(out[out.len() - 1] & 0x80, 0);
            assert_eq!(
                read_base128(&out, max),
                Ok(Some(Base128Prefix {
                    value,
                    len: out.len()
                }))
            );
            out.push(kani::any());
            assert_eq!(
                read_base128(&out, max),
                Ok(Some(Base128Prefix {
                    value,
                    len: out.len() - 1
                }))
            );
        }
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn a_value_read_is_the_only_encoding_of_itself() {
    let (input, len) = bytes::<6>();
    let input = &input[..len];
    let max: u128 = kani::any();
    match read_base128(input, max) {
        Ok(Some(prefix)) => {
            assert!(prefix.len >= 1 && prefix.len <= len);
            assert!(prefix.value <= max);
            assert_eq!(input[prefix.len - 1] & 0x80, 0);
            assert!(input[..prefix.len - 1].iter().all(|b| b & 0x80 != 0));
            let mut again = Vec::new();
            write_base128(&mut again, prefix.value, max).unwrap();
            assert_eq!(again, &input[..prefix.len]);
        }
        Ok(None) => {
            assert!(input.iter().all(|b| b & 0x80 != 0));
            assert!(len == 0 || input[0] != 0x80);
        }
        Err(Error::NonMinimalBase128) => assert_eq!(input[0], 0x80),
        Err(Error::Base128Limit) => {
            // Some prefix of groups already exceeds `max`; with at most six
            // octets this is never a `u128` overflow.
            let mut value = 0u128;
            let mut exceeded = false;
            for &byte in input {
                value = value * 128 + u128::from(byte & 0x7f);
                if value > max {
                    exceeded = true;
                    break;
                }
                if byte & 0x80 == 0 {
                    break;
                }
            }
            assert!(exceeded);
        }
        Err(_) => unreachable!(),
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn length_prefixes_agree_with_their_octets() {
    let (input, len) = bytes::<6>();
    let input = &input[..len];
    let policy = LengthPolicy {
        max_octets: kani::any(),
        minimal: kani::any(),
    };
    let result = read_length(input, policy);
    let Some(&first) = input.first() else {
        assert_eq!(result, Ok(None));
        return;
    };
    let octets = usize::from(first & 0x7f);
    match result {
        Ok(Some(LengthPrefix { value: None, len })) => {
            assert_eq!(first, 0x80);
            assert_eq!(len, 1);
        }
        Ok(Some(LengthPrefix {
            value: Some(value),
            len: used,
        })) => {
            if first < 0x80 {
                assert_eq!(value, usize::from(first));
                assert_eq!(used, 1);
            } else {
                assert!(first != 0xff);
                assert!(octets <= policy.max_octets);
                assert_eq!(used, 1 + octets);
                assert!(used <= len);
                let mut expected = 0usize;
                for &byte in &input[1..used] {
                    expected = expected * 256 + usize::from(byte);
                }
                assert_eq!(value, expected);
                if policy.minimal {
                    assert!(input[1] != 0);
                    assert!(value >= 0x80);
                }
            }
        }
        Ok(None) => {
            assert!(first > 0x80 && first != 0xff);
            assert!(octets <= policy.max_octets);
            assert!(len < 1 + octets);
            assert!(!(policy.minimal && len >= 2 && input[1] == 0));
        }
        Err(Error::Reserved) => assert_eq!(first, 0xff),
        Err(Error::Octets) => {
            assert!(first > 0x80 && first != 0xff);
            assert!(octets > policy.max_octets);
        }
        Err(Error::NonMinimal) => {
            assert!(policy.minimal);
            assert!(first > 0x80 && first != 0xff);
            assert!(octets <= policy.max_octets);
            let leading_zero = len >= 2 && input[1] == 0;
            let complete = len >= 1 + octets;
            let mut value = 0usize;
            if complete {
                for &byte in &input[1..1 + octets] {
                    value = value * 256 + usize::from(byte);
                }
            }
            assert!(leading_zero || (complete && value < 0x80));
        }
        Err(Error::Overflow) => unreachable!("five octets fit a usize"),
        Err(_) => unreachable!(),
    }
}
