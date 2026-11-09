//! Kani proofs over HPACK's dynamic table, index resolution, block grammar
//! and size updates in src/stdlib/protocols/hpack.rs: `DynamicTable`
//! (shared by the endpoint `Table` and the capture dissector's
//! `PartialTable` in src/stdlib/dissect/http2.rs), `Representations`, and
//! `Table::decode_block` with `Encoder::encode_block`. Compiled only under
//! `cargo kani`, as a child module of hpack.rs, so each harness calls the
//! production code and may set up its private state.
//!
//! The sequences of blocks, settings changes and capacity choices an
//! encoder and decoder go through together are in
//! verification/hpack-grpc/tla/HpackSync.tla; these harnesses prove the
//! steps that model takes as given.

use super::*;
use fictionet::stdlib::protocols::prefix_int;

// Every string the block harnesses below write is raw, so no Huffman code
// runs. CBMC cannot see that from bytes at symbolic positions and would
// unroll the Huffman decoder over every string; these stubs stand in for
// it, and reaching one fails the proof, so they hide nothing. The Huffman
// code itself is proved in kani/huffman.rs.
fn no_huffman_decode(_: &[u8], _: usize) -> Result<Vec<u8>, huffman::Error> {
    panic!("a harness string was Huffman coded");
}

fn no_huffman_encode(_: &[u8], _: &mut Vec<u8>) -> Result<(), huffman::Error> {
    panic!("a harness string was Huffman coded");
}

/// An entry with a name and a value of the given lengths. Contents do not
/// matter to the table's arithmetic.
fn entry(name: usize, value: usize) -> (Arc<[u8]>, Vec<u8>) {
    (vec![b'n'; name].into(), vec![b'v'; value])
}

/// Over any three steps, each an insertion of an entry with a name and a
/// value of up to 64 octets or an eviction to any capacity, from an empty
/// table: `size` is always exactly the sum of name + value + 32 over the
/// retained entries; an eviction leaves `size` at most the capacity,
/// removes only the oldest entries, and removes the fewest that do (the
/// last one removed did not fit with the rest), and says whether it
/// removed any. Kani's overflow checks are on for `size`.
#[kani::proof]
#[kani::unwind(5)]
fn table_size_is_exactly_its_entries() {
    let mut table = DynamicTable::default();
    // Entry sizes, newest first, kept beside the table.
    let mut sizes: Vec<usize> = Vec::new();
    for _ in 0..3 {
        if kani::any() {
            let name: usize = kani::any();
            let value: usize = kani::any();
            kani::assume(name <= 64 && value <= 64);
            let (n, v) = entry(name, value);
            table.insert(n, v);
            sizes.insert(0, name + value + ENTRY_OVERHEAD);
        } else {
            let capacity: usize = kani::any();
            let before: usize = sizes.iter().sum();
            let removed = table.evict(capacity);
            let mut kept = sizes.len();
            let mut total = before;
            while total > capacity && kept > 0 {
                kept -= 1;
                total -= sizes[kept];
            }
            assert_eq!(removed, kept < sizes.len());
            sizes.truncate(kept);
            assert!(table.size() <= capacity);
        }
        assert_eq!(table.len(), sizes.len());
        assert_eq!(table.size(), sizes.iter().sum::<usize>());
        for (i, &size) in sizes.iter().enumerate() {
            let (name, value) = &table.entries[i];
            assert_eq!(name.len() + value.len() + ENTRY_OVERHEAD, size);
        }
    }
}

/// For a table of zero to three dynamic entries and any `u64` index:
/// index 0 is an error; 1 to 61 give `STATIC_TABLE` in order; 62 to
/// 61 + len give the dynamic entries newest first; every index past them
/// is absent, never wrapped onto another entry. `name` agrees with `get`.
#[kani::proof]
#[kani::unwind(5)]
fn indexes_resolve_only_inside_the_tables() {
    let mut table = DynamicTable::default();
    let len: usize = kani::any();
    kani::assume(len <= 3);
    for i in 0..len {
        let (name, value) = entry(i, i + 1);
        table.insert(name, value);
    }
    let index: u64 = kani::any();
    let got = table.get(index);
    let name = table.name(index);
    if index == 0 {
        assert_eq!(got, Err(Error::Index));
        assert_eq!(name, Err(Error::Index));
    } else if index <= 61 {
        let (n, v) = STATIC_TABLE[index as usize - 1];
        let entry = got.unwrap().unwrap();
        assert_eq!((entry.name, entry.value), (n.as_bytes(), v.as_bytes()));
        assert_eq!(name.unwrap().as_deref(), Some(n.as_bytes()));
    } else if index <= 61 + len as u64 {
        // The newest entry, inserted last, is 62.
        let i = len - 1 - (index as usize - 62);
        let entry = got.unwrap().unwrap();
        assert_eq!((entry.name.len(), entry.value.len()), (i, i + 1));
        assert_eq!(name.unwrap().map(|n| n.len()), Some(i));
    } else {
        assert_eq!(got, Ok(None));
        assert_eq!(name, Ok(None));
    }
}

/// One representation chosen by Kani, as written on the wire: a size
/// update, an indexed field, or a literal of each indexing kind, with an
/// empty literal name or an indexed one and an empty value. Sizes and
/// indexes are any value up to 300, so their integers take one to three
/// bytes.
fn representation(out: &mut Vec<u8>) -> Representation {
    let n: u64 = kani::any();
    kani::assume(n <= 300);
    match kani::any::<u8>() {
        0 => {
            prefix_int::write(out, 5, 0x20, n).unwrap();
            Representation::SizeUpdate(n as usize)
        }
        1 => {
            kani::assume(n > 0);
            prefix_int::write(out, 7, 0x80, n).unwrap();
            Representation::Indexed(n)
        }
        kind => {
            let (prefix, flags, indexing) = match kind {
                2 => (6, 0x40, Indexing::Incremental),
                3 => (4, 0x00, Indexing::Without),
                _ => (4, 0x10, Indexing::Never),
            };
            prefix_int::write(out, prefix, flags, n).unwrap();
            let name = if n == 0 {
                out.push(0);
                Name::Literal(Vec::new())
            } else {
                Name::Index(n)
            };
            out.push(0);
            Representation::Literal {
                name,
                value: Vec::new(),
                indexing,
            }
        }
    }
}

/// For a block of any three representations, `Representations` reads back
/// each one exactly, in order, until a size update follows a field; that
/// one is `SizeUpdateOrder`, and nothing is read after it.
#[kani::proof]
#[kani::stub(crate::stdlib::protocols::huffman::decode_limited, no_huffman_decode)]
#[kani::unwind(5)]
fn size_updates_come_only_first() {
    let mut bytes = Vec::new();
    let written = [
        representation(&mut bytes),
        representation(&mut bytes),
        representation(&mut bytes),
    ];
    let mut read = Representations::new(&bytes, 0).unwrap();
    let mut field_seen = false;
    for expected in written {
        let late = matches!(expected, Representation::SizeUpdate(_)) && field_seen;
        if late {
            assert_eq!(read.next(), Some(Err(Error::SizeUpdateOrder)));
            assert_eq!(read.next(), None);
            return;
        }
        field_seen |= !matches!(expected, Representation::SizeUpdate(_));
        assert_eq!(read.next(), Some(Ok(expected)));
    }
    assert_eq!(read.next(), None);
}

/// From a table made with any settings limit, after any later settings
/// change (both up to `MAX_TABLE`), a block of one or two size updates of
/// any sizes, optionally followed by a field, is accepted exactly when
/// every update is at most the settings limit, a second is no smaller than
/// the first, the first is at most the smallest limit below the table's
/// maximum since the last block (when there was one), and an update came
/// when that reduction was owed. After it, the maximum is the last update
/// and the table fits in it.
#[kani::proof]
#[kani::stub(crate::stdlib::protocols::huffman::decode_limited, no_huffman_decode)]
#[kani::unwind(7)]
fn size_updates_obey_the_settings() {
    let first: usize = kani::any();
    let then: usize = kani::any();
    kani::assume(first <= MAX_TABLE + 1 && then <= MAX_TABLE + 1);
    let mut table = Table::new(first);
    table.set_settings_limit(then);
    let settings = then.min(MAX_TABLE);
    let initial = first.min(MAX_TABLE);
    let owed = [initial, settings]
        .into_iter()
        .filter(|&limit| limit < 4096)
        .min();
    let count: u8 = kani::any();
    kani::assume(count <= 2);
    let sizes: [u64; 2] = kani::any();
    // Every size past MAX_TABLE + 1 is past every settings limit, as that one is.
    kani::assume(sizes[0] <= MAX_TABLE as u64 + 1 && sizes[1] <= MAX_TABLE as u64 + 1);
    let mut block = Vec::new();
    for &size in &sizes[..usize::from(count)] {
        prefix_int::write(&mut block, 5, 0x20, size).unwrap();
    }
    let field: bool = kani::any();
    if field {
        block.push(0x82);
    }
    let sizes = &sizes[..usize::from(count)];
    let fits = sizes.iter().all(|&s| s <= settings as u64);
    let ordered = count < 2 || sizes[1] >= sizes[0];
    let reduced = match owed {
        Some(min) => count > 0 && sizes[0] <= min as u64,
        None => true,
    };
    let result = table.decode_block(&block, MAX_DECODED);
    assert_eq!(result.is_ok(), fits && ordered && reduced);
    if result.is_ok() {
        let last = sizes.last().map_or(4096, |&s| s as usize);
        assert_eq!(table.table_capacity(), last);
        assert!(table.table_capacity() <= settings);
        assert!(table.table_size() <= table.table_capacity());
    }
    if sizes.iter().any(|&s| s > settings as u64) {
        assert!(result.is_err());
    }
}

/// With any table maximum up to 120 and an entry already in it, a literal
/// with incremental indexing and a literal name and value of up to 40
/// octets leaves the table within its maximum: the new entry stays exactly
/// when it fits, older entries leave oldest first, and an entry larger than
/// the maximum empties the table. A literal without indexing, or never
/// indexed, leaves the table as it was.
#[kani::proof]
#[kani::stub(crate::stdlib::protocols::huffman::decode_limited, no_huffman_decode)]
#[kani::unwind(50)]
fn literals_keep_the_table_within_its_maximum() {
    let max: usize = kani::any();
    kani::assume(max <= 120);
    let mut table = Table::new(4096);
    table.max = max;
    let (n, v) = entry(1, 1);
    table.table.insert(n, v);
    table.table.evict(max);
    let old = table.table_size();
    let name: usize = kani::any();
    let value: usize = kani::any();
    kani::assume(name <= 40 && value <= 40);
    let mode: u8 = kani::any();
    kani::assume(mode < 3);
    let mut block = vec![[0x40, 0x00, 0x10][usize::from(mode)]];
    block.push(name as u8);
    block.extend(vec![b'n'; name]);
    block.push(value as u8);
    block.extend(vec![b'v'; value]);
    let decoded = table.decode_block(&block, MAX_DECODED).unwrap();
    assert_eq!(decoded.headers.len(), 1);
    let size = name + value + ENTRY_OVERHEAD;
    assert!(table.table_size() <= max);
    if mode != 0 {
        assert_eq!(table.table_size(), old);
    } else if size > max {
        assert_eq!(table.table_len(), 0);
    } else if size + old > max {
        assert_eq!(table.table_size(), size);
    } else {
        assert_eq!(table.table_size(), size + old);
    }
}

/// The names the round-trip harness chooses from: a static name with a
/// static value, a static name, and a new name.
const NAMES: [&[u8]; 3] = [b":method", b"accept", b"x"];

fn field() -> Field {
    let name: usize = kani::any();
    kani::assume(name < NAMES.len());
    let value: [u8; 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 1);
    let mut field = Field::new(NAMES[name], &value[..len]);
    field.never_index = kani::any();
    field
}

/// With a settings limit of 0, 40 (one small entry) or 4096, applied to
/// both sides, two blocks, the first of two fields and the second of one,
/// each field any of three names with any value of up to one octet and
/// either never-indexed flag, decode to exactly the fields encoded, never
/// indexed flags included, and leave the encoder's and decoder's tables
/// the same entries at the same maximum.
#[kani::proof]
#[kani::stub(crate::stdlib::protocols::huffman::encode, no_huffman_encode)]
#[kani::stub(crate::stdlib::protocols::huffman::decode_limited, no_huffman_decode)]
#[kani::unwind(65)]
fn blocks_decode_to_what_was_encoded() {
    let limit = [0, 40, 4096][kani::any::<bool>() as usize + kani::any::<bool>() as usize];
    let mut encoder = Encoder::new(limit);
    let mut decoder = Table::new(limit);
    for fields in [vec![field(), field()], vec![field()]] {
        let mut bytes = Vec::new();
        encoder.encode_block(&fields, &mut bytes).unwrap();
        let block = decoder.decode_block(&bytes, MAX_DECODED).unwrap();
        assert_eq!(block.headers, fields);
        assert_eq!(block.more, 0);
        assert_eq!(encoder.table.max, decoder.max);
        assert_eq!(encoder.table.table.entries, decoder.table.entries);
        assert_eq!(encoder.table_size(), decoder.table_size());
    }
}
