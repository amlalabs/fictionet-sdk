use fictionet::Chunk;
use fictionet::stdlib::protocols::http1::Error;

/// Ordered HTTP fields in one backing, preserving duplicates and spelling.
#[derive(Clone, Default)]
pub struct Fields {
    block: Chunk,
    count: usize,
}

impl Fields {
    /// Explicitly allocates storage for a list of fields.
    pub fn new<N: AsRef<[u8]>, V: AsRef<[u8]>>(fields: impl IntoIterator<Item = (N, V)>) -> Self {
        let mut bytes = Vec::new();
        let mut count = 0;
        for (name, value) in fields {
            let (name, value) = (name.as_ref(), value.as_ref());
            write_length(name.len(), |part| bytes.extend_from_slice(part));
            write_length(value.len(), |part| bytes.extend_from_slice(part));
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(value);
            count += 1;
        }
        Self {
            block: Chunk::unpaid(bytes),
            count,
        }
    }

    /// Uses an empty, uniquely held block supplied by the caller's pool.
    pub fn in_block(mut block: Chunk) -> Result<Self, Error> {
        if !block.is_empty() || block.fill(|_| 0).is_none() {
            return Err(Error::HeadTooLong);
        }
        Ok(Self { block, count: 0 })
    }

    /// Appends a field atomically. Refusal leaves every field unchanged.
    pub fn push(&mut self, name: &str, value: &[u8]) -> Result<(), Error> {
        let need = Self::record_size(name.len(), value.len()).ok_or(Error::HeadTooLong)?;
        if need > self.block.room() || self.block.fill(|_| 0).is_none() {
            return Err(Error::HeadTooLong);
        }
        write_length(name.len(), |part| {
            self.block
                .extend_within(part)
                .expect("reserved record room")
        });
        write_length(value.len(), |part| {
            self.block
                .extend_within(part)
                .expect("reserved record room")
        });
        self.block
            .extend_within(name.as_bytes())
            .expect("reserved record room");
        self.block
            .extend_within(value)
            .expect("reserved record room");
        self.count += 1;
        Ok(())
    }

    pub(crate) fn record_size(name: usize, value: usize) -> Option<usize> {
        name.checked_add(value)?
            .checked_add(length_size(name) + length_size(value))
    }

    /// All fields in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + Clone {
        Records {
            bytes: &self.block,
            left: self.count,
        }
    }

    /// The first matching field, ignoring ASCII case.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Capacity retained by the backing, including unused space.
    pub fn held(&self) -> usize {
        self.block.capacity()
    }
}

#[derive(Clone)]
pub(super) struct Records<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) left: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = (&'a [u8], &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let name = read_length(&mut self.bytes);
        let value = read_length(&mut self.bytes);
        let bytes = self.bytes;
        let result = (&bytes[..name], &bytes[name..name + value]);
        self.bytes = &bytes[name + value..];
        self.left -= 1;
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}
impl ExactSizeIterator for Records<'_> {}

pub(super) fn length_size(n: usize) -> usize {
    ((usize::BITS - n.leading_zeros()).max(1) as usize).div_ceil(7)
}
pub(super) fn write_length(mut n: usize, mut write: impl FnMut(&[u8])) {
    while n >= 128 {
        write(&[(n as u8 & 127) | 128]);
        n >>= 7;
    }
    write(&[n as u8]);
}
fn read_length(bytes: &mut &[u8]) -> usize {
    let mut n = 0;
    let mut shift = 0;
    loop {
        let b = bytes[0];
        *bytes = &bytes[1..];
        n |= usize::from(b & 127) << shift;
        if b < 128 {
            return n;
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{Budget, Entropy, Pool, Seed, SeededEntropy};

    #[test]
    fn pooled_fields_match_ordered_lists_and_refuse_atomically() {
        let random = SeededEntropy::new(Seed::from_u64(43));
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, 2048, 2);
        for _ in 0..200 {
            let mut fields = Fields::in_block(pool.take(&budget, 0).unwrap()).unwrap();
            let mut model = Vec::new();
            for _ in 0..30 {
                let name = if random.random_below(2) == 0 {
                    "X-Field"
                } else {
                    "x-FIELD"
                };
                let value =
                    vec![b'a' + random.random_below(26) as u8; random.random_below(600) as usize];
                let fits =
                    Fields::record_size(name.len(), value.len()).unwrap() <= fields.block.room();
                let used = budget.used();
                assert_eq!(fields.push(name, &value).is_ok(), fits);
                if fits {
                    model.push((name, value));
                }
                assert!(
                    fields
                        .iter()
                        .eq(model.iter().map(|(n, v)| (n.as_bytes(), v.as_slice())))
                );
                assert_eq!(budget.used(), used);
            }
            let room = fields.block.room();
            if let Some(length) = (0..room).find(|&n| Fields::record_size(1, n) == Some(room)) {
                let value = vec![b'x'; length];
                fields.push("Z", &value).unwrap();
                model.push(("Z", value));
                assert_eq!(fields.block.room(), 0);
            }
            let copy = fields.clone();
            assert!(fields.push("another", b"value").is_err());
            assert!(fields.iter().eq(copy.iter()));
            assert!(
                fields
                    .iter()
                    .eq(model.iter().map(|(n, v)| (n.as_bytes(), v.as_slice())))
            );
        }
        assert_eq!(budget.used(), pool.charged());
    }
    #[test]
    fn exact_capacity_and_shared_records_refuse_without_mutation() {
        let budget = Budget::new(4096);
        let pool = Pool::new(&budget, 2048, 1);
        let mut fields = Fields::in_block(pool.take(&budget, 0).unwrap()).unwrap();
        fields.push("X", b"first").unwrap();
        let copy = fields.clone();
        assert!(fields.push("x", b"second").is_err());
        assert!(fields.iter().eq(copy.iter()));
        drop(copy);
        let room = fields.block.room();
        let length = (0..room)
            .find(|&n| Fields::record_size(1, n) == Some(room))
            .unwrap();
        let value = vec![b'x'; length];
        fields.push("x", &value).unwrap();
        assert_eq!(fields.block.room(), 0);
        let before: Vec<_> = fields
            .iter()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        assert!(fields.push("Z", b"").is_err());
        assert!(
            fields
                .iter()
                .eq(before.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
        );
    }
}
