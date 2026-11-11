//! Kani proofs that HPACK's tables hold no more than is charged for them,
//! with every allocation counted (verification/resources/kani/counting.rs).
//! Compiled only under `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`,
//! as a child module of src/stdlib/protocols/hpack.rs, so each harness
//! calls the production code and builds its private state.
//!
//! What is charged. The server charges a connection's decoder table at
//! `Table::most_held()` when the connection opens (`Input::open`,
//! src/stdlib/web/httpd/http2.rs), and the bound holds while the settings
//! limit does not rise; `Encoder::most_held()` is the encoder's, while its
//! capacity does not rise. Each harness takes that charge before the step
//! and checks the step against it.
//!
//! The step. Every insertion into a table is one call: `Table::index` for
//! a literal with incremental indexing that `read_block` decodes, and
//! `Encoder::encode_block_into` for a field the encoder indexes. Harnesses
//! on `Table::decode_block` itself did not finish (see kani/hpack.rs), so
//! the decoder's harness runs the step `read_block` calls for each such
//! field; the vector replay in tests/hpack_vectors.rs runs whole blocks.
//!
//! The tables. Zero to four entries, each empty (32 octets) or with a
//! four-octet name and value (40 octets), under any capacity, and for the
//! decoder any settings limit, up to `CAP`. The new entry has a one-octet
//! name and a four-octet value (37 octets), so against that capacity it is
//! larger than the table, or evicts all, some or none of the entries
//! before it. Every length a harness gives is a constant: CBMC's formulas
//! for allocations of symbolic size, and for a symbolic count of entries,
//! did not finish (kani/hpack.rs found the same).
//!
//! The bounds:
//!
//! - **Within the charge**: the most bytes live at once, counting the
//!   table from its first allocation, is at most the charge taken before
//!   the step.
//! - **Linear copying**: the step asks the allocator for at most the
//!   octets it reads (the new name, if a literal, and the value) plus
//!   `name_copy()` plus the table's slot term, `most_held(c) - c`.
//!   `name_copy()` is a name's shared header (two `usize` counts, padded
//!   to their alignment) and the longest static name, which a name given
//!   by index copies; the slot term covers the one doubling of the entry
//!   slots a step can make.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// The largest capacity and settings limit taken: room for four entries
/// of 32 to 40 octets, with a fifth inserted.
const CAP: usize = 200;

/// The most a step allocates for a name beyond the octets it reads: the
/// shared name's header, padded, and a static name it copies. Both are
/// constants, so the step harnesses need not unwind the table.
fn name_copy() -> usize {
    NAME_HEADER + LONGEST_STATIC_NAME
}

/// The new entry's name, when a literal, and its value.
const NAME: &[u8] = b"n";
const VALUE: &[u8] = b"vvvv";

/// `count` entries that fit `capacity` together, inserted oldest first
/// with no eviction, so building them allocates only what they keep.
fn fill(table: &mut DynamicTable, capacity: usize, count: usize) {
    for _ in 0..count {
        if kani::any() {
            kani::assume(table.size() + ENTRY_OVERHEAD <= capacity);
            table.insert(Arc::from(&b""[..]), Vec::new());
        } else {
            kani::assume(table.size() + 8 + ENTRY_OVERHEAD <= capacity);
            table.insert(Arc::from(&b"nnnn"[..]), b"vvvv".to_vec());
        }
    }
}

/// Where a literal's name comes from.
#[derive(Clone, Copy, PartialEq)]
enum Named {
    /// A literal in the block.
    Literal,
    /// An index into the dynamic table: its newest entry.
    Dynamic,
    /// Index 2, `:method`. Every static name is copied alike; the bound
    /// allows the longest.
    Static,
}

/// The step `read_block` makes for a literal with incremental indexing,
/// its name from `named`, on a table of `count` entries: `Table::index`,
/// checked within the charge and with linear copying.
fn decode_one(named: Named, count: usize) {
    let settings: usize = kani::any();
    let max: usize = kani::any();
    kani::assume(settings <= CAP && max <= settings);
    let ((charge, read, step), cost) = measure(|| {
        let mut table = Table {
            table: DynamicTable::default(),
            max,
            settings,
            required_min: None,
        };
        fill(&mut table.table, max, count);
        let charge = table.most_held();
        let name = match named {
            Named::Literal => Name::Literal(Text::Raw(NAME.into())),
            Named::Dynamic => Name::Index(62),
            Named::Static => Name::Index(2),
        };
        let name_len = match name {
            Name::Literal(_) => NAME.len(),
            Name::Index(index) => table.table.get(index).unwrap().unwrap().name.len(),
        };
        // The octets the step reads from the block: a literal name's, and
        // the value's.
        let read = if named == Named::Literal { name_len } else { 0 } + VALUE.len();
        let before = so_far();
        table
            .index(
                name,
                Text::Raw(VALUE.into()),
                name_len + VALUE.len() + ENTRY_OVERHEAD,
            )
            .unwrap();
        let after = so_far();
        assert!(table.table.size() <= table.max);
        // Dropping the table is not the step, and its drop glue made the
        // formulas too large: the proof ends with the table held.
        std::mem::forget(table);
        (charge, read, after.requested - before.requested)
    });
    assert!(cost.peak <= charge, "the table held more than its charge");
    assert!(
        step <= read + name_copy() + (DynamicTable::most_held(max) - max),
        "the step copied more than its input and constants"
    );
}

counted_proof! {
    /// [`decode_one`] with the name a literal, for each count.
    #[kani::unwind(6)]
    fn decoding_a_literal_name_stays_within_its_charge() {
        for count in 0..=4 {
            decode_one(Named::Literal, count);
        }
    }
}

counted_proof! {
    /// [`decode_one`] with the name the dynamic table's newest entry, so
    /// from one entry up: with none the index names nothing.
    #[kani::unwind(6)]
    fn decoding_a_dynamic_name_stays_within_its_charge() {
        for count in 1..=4 {
            decode_one(Named::Dynamic, count);
        }
    }
}

counted_proof! {
    /// [`decode_one`] with a name from the static table, for each count.
    #[kani::unwind(6)]
    fn decoding_a_static_name_stays_within_its_charge() {
        for count in 0..=4 {
            decode_one(Named::Static, count);
        }
    }
}

/// A field the encoder indexes, written with `encode_block_into` into room
/// on the stack by an encoder whose table of `count` entries keeps to its
/// capacity: within the charge, and with linear copying.
fn encode_one(count: usize) {
    let max: usize = kani::any();
    kani::assume(max >= 1 && max <= CAP);
    let ((charge, step), cost) = measure(|| {
        let mut encoder = Encoder {
            table: Table {
                table: DynamicTable::default(),
                max,
                settings: max,
                required_min: None,
            },
            pending_min: None,
            huffman: false,
        };
        fill(&mut encoder.table.table, max, count);
        let charge = encoder.most_held();
        let mut room = [0u8; 16];
        let before = so_far();
        encoder
            .encode_block_into([FieldRef::new(NAME, VALUE)], &mut room)
            .unwrap();
        let after = so_far();
        assert!(encoder.table_size() <= max);
        // As in `decode_one`: the encoder is not dropped.
        std::mem::forget(encoder);
        (charge, after.requested - before.requested)
    });
    assert!(cost.peak <= charge, "the table held more than its charge");
    assert!(
        step <= NAME.len() + VALUE.len() + name_copy() + (DynamicTable::most_held(max) - max),
        "the step copied more than its input and constants"
    );
}

// [`encode_one`] for each count, a harness each: the encoder looks for
// the field's name through all 61 static entries and up to five dynamic
// ones, so it unwinds 67, and all five counts in one harness ran out of
// 16 GiB.
counted_proof! {
    #[kani::unwind(67)]
    fn encoding_into_an_empty_table_stays_within_its_charge() {
        encode_one(0);
    }
}
counted_proof! {
    #[kani::unwind(67)]
    fn encoding_into_a_table_of_one_stays_within_its_charge() {
        encode_one(1);
    }
}
counted_proof! {
    #[kani::unwind(67)]
    fn encoding_into_a_table_of_two_stays_within_its_charge() {
        encode_one(2);
    }
}
counted_proof! {
    #[kani::unwind(67)]
    fn encoding_into_a_table_of_three_stays_within_its_charge() {
        encode_one(3);
    }
}
counted_proof! {
    #[kani::unwind(67)]
    fn encoding_into_a_table_of_four_stays_within_its_charge() {
        encode_one(4);
    }
}
