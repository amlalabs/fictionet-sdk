//! `Buffer` is a bounded byte queue: for any sequence of pushes, direct
//! reads, consumes, shrinks and limit changes, the unread bytes are exactly
//! the accepted bytes not yet consumed, the offset counts the consumed
//! bytes, new input never passes the limit, and storage stays within twice
//! the largest limit. `write_bounded` is all or nothing on top of it.

extern crate alloc;

use super::bytes;
use alloc::vec::Vec;
use core::convert::Infallible;
use fictionet::stdlib::codec::{Buffer, RewriteError, Wire, write_bounded};

const MAX_LIMIT: usize = 4;
const CHUNK: usize = 3;
const STEPS: usize = 3;

#[kani::proof]
#[kani::unwind(6)]
fn the_buffer_is_a_bounded_byte_queue() {
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT);
    let mut buf = Buffer::new(limit);
    let mut model: Vec<u8> = Vec::new();
    let mut consumed = 0u64;
    let mut largest_limit = limit;
    for _ in 0..STEPS {
        let op: u8 = kani::any();
        match op % 5 {
            0 => {
                let (data, len) = bytes::<CHUNK>();
                let growth: usize = kani::any();
                let before = buf.len();
                let n = buf.push_with_budget(&data[..len], growth);
                assert!(n <= len);
                assert!(before + n <= buf.limit().max(before));
                // Growth never refuses bytes that fit without allocating more
                // than the budget; a short push is the limit or the budget.
                assert!(n == len || before + n == buf.limit() || growth < len);
                model.extend_from_slice(&data[..n]);
            }
            1 => {
                let k: usize = kani::any();
                buf.consume(k);
                let k = k.min(model.len());
                model.drain(..k);
                consumed += k as u64;
            }
            2 => {
                let room = buf.room();
                let spare = buf.spare();
                let offered = spare.len();
                assert!(offered <= room);
                let written: [u8; MAX_LIMIT] = kani::any();
                for (slot, byte) in spare.iter_mut().zip(written) {
                    *slot = byte;
                }
                let k: usize = kani::any();
                buf.commit(k);
                model.extend_from_slice(&written[..k.min(offered)]);
            }
            3 => buf.shrink(),
            _ => {
                let new_limit: usize = kani::any();
                kani::assume(new_limit <= MAX_LIMIT);
                buf.set_limit(new_limit);
                largest_limit = largest_limit.max(new_limit);
            }
        }
        assert_eq!(buf.unread(), &model[..]);
        assert_eq!(buf.len(), model.len());
        assert_eq!(buf.is_empty(), model.is_empty());
        assert_eq!(buf.offset(), consumed);
        assert_eq!(buf.room(), buf.limit().saturating_sub(buf.len()));
        assert!(buf.allocated() <= 2 * largest_limit);
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn commit_without_an_offer_adds_nothing() {
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT);
    let mut buf = Buffer::new(limit);
    let (data, len) = bytes::<CHUNK>();
    let n = buf.push(&data[..len]);
    let before = buf.unread().to_vec();
    // A push, consume or limit change invalidates the last offer.
    let _ = buf.spare();
    match kani::any::<u8>() % 3 {
        0 => {
            let _ = buf.push(&[]);
        }
        1 => buf.consume(0),
        _ => buf.set_limit(limit),
    }
    buf.commit(kani::any());
    assert_eq!(buf.unread(), &before[..]);
    assert_eq!(buf.len(), n);
}

#[derive(Debug, PartialEq, Eq)]
struct Raw(Vec<u8>);
impl Wire for Raw {
    type ParseError = Infallible;
    type WriteError = Infallible;
    fn parse(b: &[u8]) -> Result<Self, Infallible> {
        Ok(Raw(b.to_vec()))
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Infallible> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn bounded_writes_are_all_or_nothing() {
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT);
    let mut buf = Buffer::new(limit);
    let (first, flen) = bytes::<CHUNK>();
    let _ = buf.push(&first[..flen]);
    let before = buf.unread().to_vec();
    let (item, ilen) = bytes::<CHUNK>();
    let item = Raw(item[..ilen].to_vec());
    match write_bounded(&item, &mut buf) {
        Ok(()) => {
            assert!(before.len() + ilen <= limit);
            let mut expected = before.clone();
            expected.extend_from_slice(&item.0);
            assert_eq!(buf.unread(), &expected[..]);
        }
        Err(RewriteError::TooLong { limit: reported }) => {
            assert_eq!(reported, limit);
            assert!(before.len() + ilen > limit);
            assert_eq!(buf.unread(), &before[..]);
        }
        Err(RewriteError::Allocation) => assert_eq!(buf.unread(), &before[..]),
        Err(RewriteError::Write(never)) => match never {},
    }
}
