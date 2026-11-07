//! Dot transparency: `encoded_len` counts exactly what `write` emits, the
//! stuffed lines fed back through `Accumulator` give the body back, and the
//! accumulator never holds more than its limit.

extern crate alloc;

use super::bytes;
use alloc::vec::Vec;
use fictionet::stdlib::codec::{
    Step,
    dot_body::{Accumulator, encoded_len, write},
};

const BODY: usize = 5;
const LIMIT: usize = 8;

#[kani::proof]
#[kani::unwind(8)]
fn stuffing_counts_exactly_and_roundtrips_through_the_accumulator() {
    let (body, len) = bytes::<BODY>();
    let body = &body[..len];
    let valid = body.is_empty()
        || body
            .split_inclusive(|b| *b == b'\n')
            .all(|line| line.ends_with(b"\r\n"));
    let size = encoded_len(body, LIMIT, |_, _| true);
    assert_eq!(size.is_some(), valid);
    let Some(size) = size else { return };
    let mut wire = Vec::new();
    write(body, &mut wire);
    assert_eq!(wire.len(), size);
    assert!(wire.ends_with(b".\r\n"));
    // No stuffed line can be mistaken for the terminator.
    let lines: Vec<&[u8]> = wire.split_inclusive(|b| *b == b'\n').collect();
    assert!(
        lines[..lines.len() - 1]
            .iter()
            .all(|line| *line != b".\r\n")
    );

    let mut accumulator = Accumulator::<()>::new(LIMIT);
    let mut items = Vec::new();
    for line in lines {
        let content = line.strip_suffix(b"\r\n").unwrap();
        let step = accumulator
            .push(Ok(content), line.len(), |_| Ok::<_, ()>(None), |_| ())
            .unwrap();
        match step {
            Step::Item(item, used) => {
                assert_eq!(used, 3);
                items.push(item);
            }
            Step::Skip(used) => assert_eq!(used, line.len()),
            Step::Need | Step::End => unreachable!(),
        }
        assert!(accumulator.held() <= LIMIT);
    }
    assert_eq!(items, [Ok(body.to_vec())]);
    assert_eq!(accumulator.held(), 0);
}

#[kani::proof]
#[kani::unwind(6)]
fn the_accumulator_holds_at_most_its_limit() {
    let limit: usize = kani::any();
    kani::assume(limit <= LIMIT);
    let mut accumulator = Accumulator::<u8>::new(limit);
    let mut charged = 0usize;
    let mut rejected = false;
    let mut stored = 0usize;
    for _ in 0..3 {
        let (line, len) = bytes::<3>();
        let failed: bool = kani::any();
        let used: usize = kani::any();
        kani::assume(used <= 5);
        let reject: bool = kani::any();
        let line = if failed { Err(1u8) } else { Ok(&line[..len]) };
        let dotted = line.is_ok_and(|line| line.starts_with(b"."));
        let charge = (charged + used).checked_sub(usize::from(dotted));
        let result = accumulator.push(
            line,
            used,
            |content| {
                assert!(!content.starts_with(b".") || line.is_ok_and(|l| l.starts_with(b"..")));
                Ok::<_, u8>(reject.then_some(2u8))
            },
            |_| 3u8,
        );
        match result {
            Ok(Step::Item(item, n)) => {
                assert_eq!(line, Ok(&b"."[..]));
                assert_eq!(n, used);
                assert_eq!(item.is_err(), rejected);
                if let Ok(body) = &item {
                    assert_eq!(body.len(), stored);
                }
                charged = 0;
                rejected = false;
                stored = 0;
                assert_eq!(accumulator.held(), 0);
            }
            Ok(Step::Skip(n)) => {
                assert_eq!(n, used);
                charged = charge.unwrap();
                assert!(charged <= limit);
                if failed || reject {
                    rejected = true;
                    stored = 0;
                } else if !rejected {
                    stored += len - usize::from(dotted) + 2;
                }
                assert_eq!(accumulator.held(), stored);
                assert!(stored <= limit);
            }
            Ok(Step::Need | Step::End) => unreachable!(),
            Err(3) => {
                // Over the limit: either the charge or the stored CRLF form.
                assert!(
                    charge.is_none_or(|charge| charge > limit)
                        || (!failed
                            && !reject
                            && !rejected
                            && stored + len - usize::from(dotted) + 2 > limit)
                );
                return;
            }
            Err(_) => unreachable!(),
        }
    }
}
