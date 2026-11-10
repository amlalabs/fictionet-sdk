//! Header fields held in one block of bytes.
//!
//! A decoder writes each field it keeps straight into the block, once:
//! HPACK decodes a literal, Huffman coded or raw, into the place it keeps
//! it, and copies a table entry there. Reading the fields walks the block;
//! nothing else is allocated per field or per head.
//!
//! ```
//! use fictionet::Budget;
//! use fictionet::stdlib::protocols::fields::Fields;
//! let budget = Budget::unlimited();
//! let mut fields = Fields::new();
//! assert!(fields.push(&budget, b":method", b"GET"));
//! assert!(fields.push(&budget, b"accept", b"*/*"));
//! assert_eq!(fields.get(b"accept"), Some(&b"*/*"[..]));
//! assert_eq!(fields.iter().count(), 2);
//! ```

use fictionet::{Budget, Chunk};

/// The bytes a field takes in a block besides its name and value: the
/// lengths of the two.
pub const RECORD: usize = 8;

/// The least room a block grows to, so a few short fields written one at
/// a time do not each grow it.
const FIRST_ROOM: usize = 256;

/// The bit of a record's name length that marks the field sensitive.
const SENSITIVE: u32 = 1 << 31;
/// The bits of a record's lengths that hold them.
const LENGTH: u32 = SENSITIVE - 1;

/// Header fields, in order, in one block of bytes: for each field its
/// name's length, its value's length, its name and its value.
///
/// The block is a [`Chunk`]: whatever pays for it travels with it, so a
/// head or trailers carry their own charge wherever they go and give it
/// back when the last of them is dropped. A block taken from a
/// [`Pool`](fictionet::Pool) goes back to it.
///
/// Room is charged before a byte is written in it. When the block is full
/// it grows into a larger allocation, charged first; when the budget
/// refuses, the field is left out and counted
/// ([`refused`](Self::refused)), and so is a field past the writer's
/// limits ([`over`](Self::over)). A decoder goes on past a field it left
/// out, so its own state, such as an HPACK table, stays in step.
///
/// Cloning shares the block; a write to a shared block copies it first.
#[derive(Clone, Default)]
pub struct Fields {
    /// The records, from the chunk's cursor to its end, and room after
    /// them. `None` until the first field is written or a block is given.
    block: Option<Chunk>,
    count: usize,
    /// Name and value bytes kept.
    octets: usize,
    /// Fields left out for the writer's limits.
    over: usize,
    /// Fields left out because the budget refused room for them.
    refused: usize,
}

impl Fields {
    /// No fields, and no block yet: the first write charges one.
    pub fn new() -> Fields {
        Fields::default()
    }

    /// No fields, written into `block`'s room: an empty chunk its taker
    /// paid for, such as a [`Pool`](fictionet::Pool)'s. Panics if `block`
    /// holds bytes.
    pub fn in_block(block: Chunk) -> Fields {
        assert!(block.is_empty(), "a block for fields starts empty");
        Fields {
            block: Some(block),
            ..Fields::default()
        }
    }

    /// How many fields are kept.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no field is kept.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The name and value bytes of the fields kept.
    pub fn octets(&self) -> usize {
        self.octets
    }

    /// How many fields were left out for the writer's limits.
    pub fn over(&self) -> usize {
        self.over
    }

    /// How many fields were left out because the budget refused room for
    /// them.
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// How many fields were left out, for either reason.
    pub fn left_out(&self) -> usize {
        self.over + self.refused
    }

    /// What pays for the block: its capacity, whoever pays.
    pub fn charged(&self) -> usize {
        self.block.as_ref().map_or(0, Chunk::charged)
    }

    /// The bytes the block's allocation holds, written or not.
    pub fn capacity(&self) -> usize {
        self.block.as_ref().map_or(0, Chunk::capacity)
    }

    /// The block, if one was given or written.
    pub fn block(&self) -> Option<&Chunk> {
        self.block.as_ref()
    }

    /// The fields, in the order they were written.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            rest: self.block.as_deref().unwrap_or(&[]),
        }
    }

    /// The fields, each with whether it was written as sensitive.
    pub fn iter_marked(&self) -> impl Iterator<Item = (&[u8], &[u8], bool)> + '_ {
        let mut rest = self.block.as_deref().unwrap_or(&[]);
        std::iter::from_fn(move || {
            let (field, sensitive, after) = record(rest)?;
            rest = after;
            Some((field.0, field.1, sensitive))
        })
    }

    /// The value of the first field named exactly `name`.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    /// The value of the first field whose name is `name` in any ASCII
    /// case.
    pub fn field(&self, name: &[u8]) -> Option<&[u8]> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Counts a field the writer left out: past its limits when `over`,
    /// or for want of room.
    pub fn leave_out(&mut self, over: bool) {
        if over {
            self.over = self.over.saturating_add(1);
        } else {
            self.refused = self.refused.saturating_add(1);
        }
    }

    /// Writes a field, copying `name` and `value`, growing the block
    /// through `budget` if it has no room. Returns whether it was kept;
    /// one the budget refused room for is counted as
    /// [`refused`](Self::refused).
    pub fn push(&mut self, budget: &Budget, name: &[u8], value: &[u8]) -> bool {
        let most = name.len().saturating_add(value.len());
        let written = self.write(budget, most, false, |room| {
            let (n, rest) = room.split_at_mut(name.len());
            n.copy_from_slice(name);
            rest[..value.len()].copy_from_slice(value);
            Ok::<_, ()>((name.len(), value.len()))
        });
        written == Ok(true)
    }

    /// Writes a field that `write` puts in place: given room for at most
    /// `most` bytes, it writes the name from the start, the value right
    /// after it, and returns their lengths. The room is charged first,
    /// growing the block through `budget` if it is short; when the budget
    /// refuses, `write` is not called, the field is counted as
    /// [`refused`](Self::refused), and this returns `Ok(false)`. An error
    /// from `write` leaves the fields as they were. A `sensitive` field is
    /// one its sender asked never to be compressed into a table, which a
    /// forwarder keeps so ([`iter_marked`](Self::iter_marked)). Names and
    /// values are each at most 2^31 - 1 bytes.
    pub fn write<E>(
        &mut self,
        budget: &Budget,
        most: usize,
        sensitive: bool,
        write: impl FnOnce(&mut [u8]) -> Result<(usize, usize), E>,
    ) -> Result<bool, E> {
        let Some(need) = most.checked_add(RECORD).filter(|_| most <= LENGTH as usize) else {
            self.leave_out(false);
            return Ok(false);
        };
        if !self.room_for(budget, need) {
            self.leave_out(false);
            return Ok(false);
        }
        let block = self.block.as_mut().expect("room_for leaves a block");
        let mut result = None;
        block
            .fill(|room| {
                let room = &mut room[..need];
                let (lengths, rest) = room.split_at_mut(RECORD);
                match write(rest) {
                    Ok((name, value)) => {
                        assert!(
                            name.saturating_add(value) <= most,
                            "a field writer wrote past its room"
                        );
                        let mark = if sensitive { SENSITIVE } else { 0 };
                        lengths[..4].copy_from_slice(&(name as u32 | mark).to_le_bytes());
                        lengths[4..].copy_from_slice(&(value as u32).to_le_bytes());
                        result = Some(Ok(name + value));
                        RECORD + name + value
                    }
                    Err(error) => {
                        result = Some(Err(error));
                        0
                    }
                }
            })
            .expect("room_for leaves the block unique");
        let octets = result.expect("fill calls its writer")?;
        self.count += 1;
        self.octets += octets;
        Ok(true)
    }

    /// Makes sure the block alone holds at least `need` bytes of room,
    /// moving its records into a larger block charged to `budget` first
    /// when it does not. `false`, changing nothing, if the budget refuses.
    fn room_for(&mut self, budget: &Budget, need: usize) -> bool {
        let written = self.block.as_ref().map_or(0, Chunk::len);
        if let Some(block) = &mut self.block
            && block.room() >= need
            && block.get_mut().is_some()
        {
            return true;
        }
        // Doubling, so a block written a field at a time grows a few times.
        let Some(room) = written
            .checked_add(need)
            .map(|least| least.max(written.saturating_mul(2)).max(FIRST_ROOM))
        else {
            return false;
        };
        let Some(mut grown) = Chunk::with_room(budget, room) else {
            return false;
        };
        if let Some(old) = &self.block {
            grown
                .extend_within(old)
                .expect("a grown block holds the old records");
        }
        self.block = Some(grown);
        true
    }
}

impl PartialEq for Fields {
    /// The same fields in the same order, and as many left out for each
    /// reason, wherever the bytes are.
    fn eq(&self, other: &Fields) -> bool {
        self.over == other.over
            && self.refused == other.refused
            && self.count == other.count
            && self.iter().eq(other.iter())
    }
}

impl Eq for Fields {}

impl std::fmt::Debug for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for (name, value) in self.iter() {
            list.entry(&(
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(value),
            ));
        }
        list.finish()?;
        if self.left_out() > 0 {
            write!(f, " and {} left out", self.left_out())?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a Fields {
    type Item = (&'a [u8], &'a [u8]);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// The fields of a [`Fields`] block, as names and values, in order.
#[derive(Clone)]
pub struct Iter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        let (field, _, rest) = record(self.rest)?;
        self.rest = rest;
        Some(field)
    }
}

/// The first record of `bytes`, as its field and whether it is sensitive,
/// and the bytes after it. Only [`Fields::write`] writes records.
#[allow(clippy::type_complexity)]
fn record(bytes: &[u8]) -> Option<((&[u8], &[u8]), bool, &[u8])> {
    let (lengths, rest) = bytes.split_first_chunk::<RECORD>()?;
    let [n0, n1, n2, n3, v0, v1, v2, v3] = *lengths;
    let name = u32::from_le_bytes([n0, n1, n2, n3]);
    let value = u32::from_le_bytes([v0, v1, v2, v3]) as usize;
    let (n, rest) = rest.split_at((name & LENGTH) as usize);
    let (v, rest) = rest.split_at(value);
    Some(((n, v), name & SENSITIVE != 0, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{Entropy, Pool, Seed, SeededEntropy};

    /// Random field lists written into blocks that start in a pool slot,
    /// empty, or nowhere read back as written, in order; what the budget
    /// refused is counted and nothing else is lost; the charge on the
    /// budget is the block's, and it all goes back when the fields drop.
    #[test]
    fn fields_read_back_as_written_wherever_they_start() {
        let entropy = SeededEntropy::new(Seed::from_u64(11));
        for round in 0..300 {
            let budget = Budget::new(1 + (entropy.random_u64() % 6000) as usize);
            let pool = Pool::new(&budget, 512, 1);
            let mut fields = match round % 3 {
                0 => match pool.take(&budget, 0) {
                    Some(block) => Fields::in_block(block),
                    None => Fields::new(),
                },
                1 => Fields::new(),
                _ => Fields::in_block(Chunk::with_room(&budget, 0).unwrap()),
            };
            let mut model: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut refused = 0;
            for _ in 0..(entropy.random_u64() % 40) {
                let len = |e: &SeededEntropy| (e.random_u64() % 300) as usize;
                let name: Vec<u8> = (0..len(&entropy)).map(|i| b'a' + (i % 26) as u8).collect();
                let value: Vec<u8> = (0..len(&entropy))
                    .map(|_| entropy.random_u64() as u8)
                    .collect();
                if fields.push(&budget, &name, &value) {
                    model.push((name, value));
                } else {
                    refused += 1;
                }
                assert_eq!(budget.used(), fields.charged() + pool.charged());
            }
            let read: Vec<(Vec<u8>, Vec<u8>)> = fields
                .iter()
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect();
            assert_eq!(read, model);
            assert_eq!(fields.len(), model.len());
            assert_eq!(fields.refused(), refused);
            assert_eq!(
                fields.octets(),
                model.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>()
            );
            if let Some((name, value)) = model.first() {
                assert_eq!(fields.get(name), Some(&value[..]));
            }
            drop(fields);
            assert_eq!(budget.used(), pool.charged());
        }
    }

    /// A shared block is never written: a write copies the records first,
    /// and the other holder keeps what it saw.
    #[test]
    fn a_write_to_a_shared_block_leaves_the_other_holder_alone() {
        let budget = Budget::unlimited();
        let mut fields = Fields::new();
        assert!(fields.push(&budget, b"a", b"1"));
        let seen = fields.clone();
        assert!(fields.push(&budget, b"b", b"2"));
        assert_eq!(seen.iter().count(), 1);
        assert_eq!(fields.iter().count(), 2);
        assert_eq!(fields.get(b"a"), Some(&b"1"[..]));
    }
}
