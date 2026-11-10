//! Kani proofs over HPACK's dynamic table, index resolution and block
//! grammar in src/stdlib/protocols/hpack.rs: `DynamicTable` (shared by the
//! endpoint `Table` and the capture dissector's `PartialTable` in
//! src/stdlib/dissect/http2.rs) and `Representations`. Compiled only under
//! `cargo kani`, as a child module of hpack.rs, so each harness calls the
//! production code and may set up its private state.
//!
//! What `Table::decode_block` and `Encoder::encode_block` do over
//! sequences of blocks, settings changes and capacity choices is
//! verification/hpack-grpc/tla/HpackSync.tla. Harnesses on `decode_block`
//! itself did not finish in ten minutes, even on a fixed one-byte block.

use super::*;

// Representations borrow their strings and decode none, so no Huffman
// code runs in the representation harnesses below; the Huffman code is
// proved in kani/huffman.rs.
//
// The same harnesses read integers through `prefix_int::proofs::rfc`, the
// RFC 7541 model that `read_is_the_rfc_integer` proves `prefix_int::read`
// equal to for every input at widths 1 to 8 (HPACK uses 4 to 7): the
// iterator in `read` unrolls into formulas CBMC did not finish with.

/// An entry with a name and a value of the given lengths. Contents do not
/// matter to the table's arithmetic.
fn entry(name: usize, value: usize) -> (Arc<[u8]>, Vec<u8>) {
    (vec![b'n'; name].into(), vec![b'v'; value])
}

/// A name of `len` octets, at most four, each length its own fixed
/// allocation: CBMC's formulas for an allocation of symbolic size are
/// far larger than for a choice among fixed ones.
fn any_name(len: usize) -> Arc<[u8]> {
    match len {
        0 => Arc::from(&b""[..]),
        1 => Arc::from(&b"n"[..]),
        2 => Arc::from(&b"nn"[..]),
        3 => Arc::from(&b"nnn"[..]),
        _ => Arc::from(&b"nnnn"[..]),
    }
}

/// A value of `len` octets, at most four, as `any_name` makes names.
fn any_value(len: usize) -> Vec<u8> {
    match len {
        0 => Vec::new(),
        1 => b"v".to_vec(),
        2 => b"vv".to_vec(),
        3 => b"vvv".to_vec(),
        _ => b"vvvv".to_vec(),
    }
}

/// The table's two steps keep `size` exactly the sum of name + value + 32
/// over the retained entries, from any table that holds to it: for each
/// count of zero to three, each insertion of an entry with a name and a
/// value of up to four octets adds exactly its own size and puts it first;
/// then an eviction to any capacity leaves `size` at most the capacity,
/// removes only the oldest entries, removes the fewest that do (the last
/// one removed did not fit with the rest), and says whether it removed
/// any. By induction, any sequence of insertions and evictions keeps the
/// sum. (Taken as one symbolic sequence, the steps made formulas CBMC did
/// not finish in ten minutes.)
#[kani::proof]
#[kani::unwind(8)]
fn table_size_is_exactly_its_entries() {
    for count in 0..=3 {
        let mut table = DynamicTable::default();
        // Entry sizes, newest first, kept beside the table.
        let mut sizes = [0usize; 3];
        for i in 0..count {
            let name: usize = kani::any();
            let value: usize = kani::any();
            kani::assume(name <= 4 && value <= 4);
            let before = table.size();
            table.insert(any_name(name), any_value(value));
            let size = name + value + ENTRY_OVERHEAD;
            assert_eq!(table.size(), before + size);
            assert_eq!(table.len(), i + 1);
            let (n, v) = &table.entries[0];
            assert_eq!(n.len() + v.len() + ENTRY_OVERHEAD, size);
            sizes.copy_within(0..2, 1);
            sizes[0] = size;
        }
        let capacity: usize = kani::any();
        let removed = table.evict(capacity);
        let mut kept = count;
        let mut total: usize = sizes[..count].iter().sum();
        while total > capacity && kept > 0 {
            kept -= 1;
            total -= sizes[kept];
        }
        assert_eq!(removed, kept < count);
        assert!(table.size() <= capacity);
        assert_eq!(table.len(), kept);
        assert_eq!(table.size(), total);
        for (i, &size) in sizes[..kept].iter().enumerate() {
            let (name, value) = &table.entries[i];
            assert_eq!(name.len() + value.len() + ENTRY_OVERHEAD, size);
        }
    }
}

/// For a table of zero to three dynamic entries: every index from 1 to 61,
/// in turn, gives `STATIC_TABLE` in order (checked with three entries, as
/// static lookups never read the dynamic ones); and for any other index,
/// 0 is an error, 62 to 61 + len give the dynamic entries newest first,
/// and every index past them is absent, never wrapped onto another entry.
/// `name` agrees with `get`.
#[kani::proof]
#[kani::unwind(64)]
fn indexes_resolve_only_inside_the_tables() {
    // The lengths are taken in turn, so each table has a fixed length.
    for len in 0..=3 {
        let mut table = DynamicTable::default();
        for i in 0..len {
            let (name, value) = entry(i, i + 1);
            table.insert(name, value);
        }
        if len == 3 {
            for (i, &(n, v)) in STATIC_TABLE.iter().enumerate() {
                let index = i as u64 + 1;
                let entry = table.get(index).unwrap().unwrap();
                assert_eq!((entry.name, entry.value), (n.as_bytes(), v.as_bytes()));
                assert_eq!(table.name(index).unwrap().as_deref(), Some(n.as_bytes()));
            }
        }
        let index: u64 = kani::any();
        kani::assume(index == 0 || index > 61);
        let got = table.get(index);
        let name = table.name(index);
        if index == 0 {
            assert_eq!(got, Err(Error::Index));
            assert_eq!(name, Err(Error::Index));
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
}

/// One representation of the given kind, as written on the wire: a size
/// update, an indexed field, a literal with incremental indexing and a
/// literal name, or a literal without indexing or never indexed with an
/// indexed name; names and values are empty. The size or index `n` is at
/// most 14, so every integer takes one byte and each kind has a
/// fixed length (prefix_int.rs's harnesses cover longer integers).
fn representation(out: &mut Vec<u8>, kind: u8, n: u64) -> Representation<'static> {
    kani::assume(n <= 14);
    match kind {
        0 => {
            out.push(0x20 | n as u8);
            Representation::SizeUpdate(n as usize)
        }
        1 => {
            kani::assume(n > 0);
            out.push(0x80 | n as u8);
            Representation::Indexed(n)
        }
        2 => {
            out.extend([0x40, 0, 0]);
            Representation::Literal {
                name: Name::Literal(Text::Raw(&[])),
                value: Text::Raw(&[]),
                indexing: Indexing::Incremental,
            }
        }
        _ => {
            kani::assume(n > 0);
            let (flags, indexing) = if kind == 3 {
                (0x00, Indexing::Without)
            } else {
                (0x10, Indexing::Never)
            };
            out.push(flags | n as u8);
            out.push(0);
            Representation::Literal {
                name: Name::Index(n),
                value: Text::Raw(&[]),
                indexing,
            }
        }
    }
}

/// For a block of any three representations, each a size update or an
/// indexed field of 5, taken in turn (8 blocks; literals set the same
/// flag as indexed fields, and any value of any kind is
/// `representations_read_back_exactly`), `Representations` reads back each
/// one exactly, in order, until a size update follows a field; that one is
/// `SizeUpdateOrder`, and nothing is read after it.
#[kani::proof]
#[kani::stub(
    crate::stdlib::protocols::prefix_int::read,
    crate::stdlib::protocols::prefix_int::proofs::rfc
)]
#[kani::unwind(30)]
fn size_updates_come_only_first() {
    for kinds in 0..8u8 {
        let mut bytes = Vec::new();
        let written = [
            representation(&mut bytes, kinds & 1, 5),
            representation(&mut bytes, kinds >> 1 & 1, 5),
            representation(&mut bytes, kinds >> 2, 5),
        ];
        let mut read = Representations::new(&bytes, 0).unwrap();
        let mut field_seen = false;
        let mut stopped = false;
        for expected in written {
            if stopped {
                break;
            }
            let late = matches!(expected, Representation::SizeUpdate(_)) && field_seen;
            if late {
                assert_eq!(read.next(), Some(Err(Error::SizeUpdateOrder)));
                stopped = true;
            } else {
                field_seen |= !matches!(expected, Representation::SizeUpdate(_));
                assert_eq!(read.next(), Some(Ok(expected)));
            }
        }
        assert_eq!(read.next(), None);
    }
}

/// A block of one representation of each of the five kinds
/// `representation` writes, the literals without indexing and never
/// indexed with an indexed name among them, reads back exactly.
#[kani::proof]
#[kani::stub(
    crate::stdlib::protocols::prefix_int::read,
    crate::stdlib::protocols::prefix_int::proofs::rfc
)]
#[kani::unwind(10)]
fn representations_read_back_exactly() {
    for kind in 0..5 {
        let mut bytes = Vec::new();
        let written = representation(&mut bytes, kind, kani::any());
        let mut read = Representations::new(&bytes, 0).unwrap();
        assert_eq!(read.next(), Some(Ok(written)));
        assert_eq!(read.next(), None);
    }
}
