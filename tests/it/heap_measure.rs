//! A value's [`Heap`] measure is what the allocator holds for it, and a
//! value parsed with [`parse_paid`] is charged exactly that.

use std::collections::VecDeque;

use crate::common::alloc::left_allocated;
use fictionet::heap_of;
use fictionet::stdlib::codec::{Heap, HeapBound, most_list_places, parse_paid};
use fictionet::stdlib::layer::Budget;
use fictionet::{Entropy, Seed, SeededEntropy};

struct Record {
    name: String,
    lines: Vec<Vec<u8>>,
    queue: VecDeque<u32>,
    note: Option<Box<str>>,
    code: u16,
}

heap_of! { Record { name, lines, queue, note, code } }

/// A record grown the ways code grows values: pushed, collected,
/// reserved, boxed, and sometimes left empty.
fn record(rng: &SeededEntropy) -> Record {
    let mut name = String::new();
    for _ in 0..rng.random_below(40) {
        name.push('n');
    }
    let lines = (0..rng.random_below(6))
        .map(|_| {
            let mut line = Vec::with_capacity(rng.random_below(16) as usize);
            line.extend((0..rng.random_below(24)).map(|b| b as u8));
            line
        })
        .collect();
    let mut queue = VecDeque::new();
    for value in 0..rng.random_below(20) {
        queue.push_back(value as u32);
    }
    let note = (rng.random_below(2) == 0)
        .then(|| "note".repeat(rng.random_below(5) as usize).into_boxed_str());
    Record {
        name,
        lines,
        queue,
        note,
        code: rng.random_below(9) as u16,
    }
}

#[test]
fn a_measure_is_what_the_allocator_holds() {
    let rng = SeededEntropy::new(Seed::from_u64(3));
    for _ in 0..256 {
        let (record, live) = left_allocated(|| record(&rng));
        assert_eq!(i128::try_from(record.heap()).unwrap(), live);
        assert!(record.code < 9);
    }
}

/// Comma-separated names, each parsed into its own string.
struct Names {
    names: Vec<String>,
}

heap_of! { Names { names } }

/// Each name takes at least its comma; the strings hold at most the bytes
/// of the input.
impl HeapBound for Names {
    fn most_heap(len: usize) -> usize {
        most_list_places::<String>(len + 1, 1) + len
    }
}

fn names(bytes: &[u8]) -> Result<Names, std::str::Utf8Error> {
    let text = std::str::from_utf8(bytes)?;
    Ok(Names {
        names: text.split(',').map(str::to_owned).collect(),
    })
}

#[test]
fn a_paid_parse_is_charged_what_the_allocator_holds() {
    let rng = SeededEntropy::new(Seed::from_u64(5));
    for _ in 0..256 {
        let mut input = Vec::new();
        for name in 0..rng.random_below(48) {
            if name > 0 {
                input.push(b',');
            }
            input.extend((0..rng.random_below(3)).map(|_| b'a'));
        }
        let budget = Budget::new(Names::most_heap(input.len()));
        let (paid, live) = left_allocated(|| parse_paid(&budget, &input, names));
        let paid = paid.expect("the bound fits").expect("the input parses");
        assert_eq!(i128::try_from(paid.charged()).unwrap(), live);
        assert_eq!(budget.used(), paid.charged());
        assert!(paid.charged() <= Names::most_heap(input.len()));
    }
}
