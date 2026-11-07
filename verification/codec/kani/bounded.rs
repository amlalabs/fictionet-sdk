//! `reserve_bytes` and `append_bounded`: a refusal leaves the vector's
//! contents unchanged, a success stays within the limit, and the copies
//! appended are exactly the bytes asked for.

extern crate alloc;

use super::bytes;
use alloc::vec::Vec;
use fictionet::stdlib::codec::{ReserveError, RewriteError, append_bounded, reserve_bytes};

const MAX_LIMIT: usize = 8;

#[kani::proof]
#[kani::unwind(6)]
fn reservations_keep_the_limit_and_the_contents() {
    let (data, len) = bytes::<4>();
    let mut out = data[..len].to_vec();
    let added: usize = kani::any();
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT || added == 0);
    match reserve_bytes(&mut out, added, limit) {
        Ok(()) => {
            assert!(len + added <= limit);
            assert!(out.capacity() >= len + added);
        }
        Err(ReserveError::TooLong { limit: reported }) => {
            assert_eq!(reported, limit);
            assert!(len.checked_add(added).is_none_or(|total| total > limit));
        }
        Err(ReserveError::Allocation) => {}
    }
    assert_eq!(out, &data[..len]);
}

#[kani::proof]
#[kani::unwind(10)]
fn appended_copies_are_all_or_nothing() {
    let (data, dlen) = bytes::<2>();
    let data = &data[..dlen];
    let (prefix, plen) = bytes::<2>();
    let prefix = &prefix[..plen];
    let mut out = prefix.to_vec();
    let copies: usize = kani::any();
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT);
    match append_bounded::<()>(data, copies, &mut out, limit) {
        Ok(()) => {
            let added = dlen * copies;
            assert!(plen + added <= limit);
            assert_eq!(out.len(), plen + added);
            assert_eq!(&out[..plen], prefix);
            for copy in out[plen..].chunks(dlen.max(1)) {
                assert_eq!(copy, data);
            }
        }
        Err(RewriteError::TooLong { limit: reported }) => {
            assert_eq!(reported, limit);
            assert!(
                dlen.checked_mul(copies)
                    .and_then(|added| added.checked_add(plen))
                    .is_none_or(|total| total > limit)
            );
            assert_eq!(out, prefix);
        }
        Err(RewriteError::Allocation) => assert_eq!(out, prefix),
        Err(RewriteError::Write(())) => unreachable!(),
    }
}
