use std::ops::Range;

use fictionet::Chunk;
use fictionet::stdlib::protocols::http1::{Error, FieldRef, Version};

/// A request head in one backing. Field records preserve order, duplicates,
/// and spelling. Cloning shares that backing without allocating.
#[derive(Clone)]
pub struct Head {
    block: Chunk,
    method: Range<usize>,
    target: Range<usize>,
    fields: Range<usize>,
    count: usize,
    pub(crate) version: Version,
}

impl Head {
    pub(crate) fn record_size(name: usize, value: usize) -> Option<usize> {
        name.checked_add(value)?
            .checked_add(length_size(name) + length_size(value))
    }
    /// Builds an explicitly allocated head. HTTP validation happens when
    /// writing it; decoders validate before handing a head to a service.
    pub fn new<N: AsRef<str>, V: AsRef<[u8]>>(
        method: &str,
        target: &str,
        version: Version,
        fields: impl IntoIterator<Item = (N, V)>,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(method.as_bytes());
        bytes.extend_from_slice(target.as_bytes());
        let start = bytes.len();
        let mut count = 0;
        for (name, value) in fields {
            let (name, value) = (name.as_ref().as_bytes(), value.as_ref());
            write_length(name.len(), |part| bytes.extend_from_slice(part));
            write_length(value.len(), |part| bytes.extend_from_slice(part));
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(value);
            count += 1;
        }
        let end = bytes.len();
        Self {
            block: Chunk::unpaid(bytes),
            method: 0..method.len(),
            target: method.len()..start,
            fields: start..end,
            count,
            version,
        }
    }

    pub(crate) fn in_block(
        mut block: Chunk,
        method: &str,
        target: &str,
        version: Version,
    ) -> Result<Self, Error> {
        if !block.is_empty() || method.len().saturating_add(target.len()) > block.room() {
            return Err(Error::HeadTooLong);
        }
        block
            .extend_within(method.as_bytes())
            .map_err(|_| Error::HeadTooLong)?;
        block
            .extend_within(target.as_bytes())
            .map_err(|_| Error::HeadTooLong)?;
        let start = block.len();
        Ok(Self {
            block,
            method: 0..method.len(),
            target: method.len()..start,
            fields: start..start,
            count: 0,
            version,
        })
    }

    pub(crate) fn push(&mut self, name: &str, value: &[u8]) -> Result<(), Error> {
        let need = name
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(length_size(name.len()) + length_size(value.len())))
            .ok_or(Error::HeadTooLong)?;
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
        for bytes in [name.as_bytes(), value] {
            self.block
                .extend_within(bytes)
                .map_err(|_| Error::HeadTooLong)?;
        }
        self.fields.end = self.block.len();
        self.count += 1;
        Ok(())
    }

    /// The method token, with its original case.
    pub fn method(&self) -> &str {
        std::str::from_utf8(&self.block[self.method.clone()]).expect("head method is UTF-8")
    }

    /// The original request target.
    pub fn target(&self) -> &str {
        std::str::from_utf8(&self.block[self.target.clone()]).expect("head target is UTF-8")
    }

    /// The protocol version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// All fields in their original order.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + Clone {
        Records {
            bytes: &self.block[self.fields.clone()],
            left: self.count,
        }
    }

    pub(crate) fn pairs(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + Clone {
        self.fields()
    }

    /// All fields, with UTF-8 names.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = FieldRef<'_>> + Clone {
        self.fields().map(|(name, value)| FieldRef {
            name: std::str::from_utf8(name).expect("head field name is UTF-8"),
            value,
        })
    }

    /// The first matching field, ignoring ASCII case.
    pub fn field(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// The first matching field, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.field(name.as_bytes())
    }

    /// The capacity retained by this head, including unused pool space.
    pub fn held(&self) -> usize {
        self.block.capacity()
    }

    /// Allocates an `http` request head.
    pub fn to_http(&self) -> Result<http::request::Parts, http::Error> {
        let mut request = http::Request::builder()
            .method(self.method())
            .uri(self.target())
            .version(match self.version {
                Version::Http10 => http::Version::HTTP_10,
                Version::Http11 => http::Version::HTTP_11,
            });
        for (name, value) in self.fields() {
            request = request.header(name, value);
        }
        Ok(request.body(())?.into_parts().0)
    }
}

#[derive(Clone)]
struct Records<'a> {
    bytes: &'a [u8],
    left: usize,
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

impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        self.method() == other.method()
            && self.target() == other.target()
            && self.version == other.version
            && self.fields().eq(other.fields())
    }
}
impl Eq for Head {}
impl std::fmt::Debug for Head {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Head")
            .field("method", &self.method())
            .field("target", &self.target())
            .field("version", &self.version)
            .field("fields", &self.headers().collect::<Vec<_>>())
            .finish()
    }
}

fn length_size(n: usize) -> usize {
    ((usize::BITS - n.leading_zeros()).max(1) as usize).div_ceil(7)
}
fn write_length(mut n: usize, mut write: impl FnMut(&[u8])) {
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
    use fictionet::stdlib::codec::Wire;
    use fictionet::{Budget, Entropy, Pool, Seed, SeededEntropy};

    #[test]
    fn field_records_round_trip_against_ordered_lists() {
        let random = SeededEntropy::new(Seed([23; 32]));
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, 16384 + 64, 4);
        for _ in 0..200 {
            let mut model = vec![("Host".to_owned(), b"example.test".to_vec())];
            for _ in 0..random.random_below(20) {
                let name = if random.random_below(2) == 0 {
                    "X-Field"
                } else {
                    "x-FIELD"
                };
                let value =
                    vec![b'a' + random.random_below(26) as u8; random.random_below(400) as usize];
                model.push((name.to_owned(), value));
            }
            let mut head = Head::in_block(
                pool.take(&budget, 0).unwrap(),
                "POST",
                "/path?q=yes",
                Version::Http11,
            )
            .unwrap();
            for (name, value) in &model {
                head.push(name, value).unwrap();
            }
            assert!(
                head.fields()
                    .eq(model.iter().map(|(n, v)| (n.as_bytes(), v.as_slice())))
            );
            let wire = head.to_bytes().unwrap();
            assert_eq!(Head::parse(&wire).unwrap(), head);
            let converted = head.to_http().unwrap();
            for (name, _) in &model {
                assert!(
                    converted
                        .headers
                        .get_all(name)
                        .iter()
                        .map(|v| v.as_bytes())
                        .eq(model
                            .iter()
                            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.as_slice()))
                );
            }
        }
        assert_eq!(budget.used(), pool.charged());
    }

    #[test]
    fn a_full_head_block_refuses_another_record_without_changing_fields() {
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, 2048, 2);
        let mut head =
            Head::in_block(pool.take(&budget, 0).unwrap(), "GET", "/", Version::Http11).unwrap();
        head.push("Host", b"example.test").unwrap();
        let room = head.block.room();
        let length = (0..room)
            .find(|&n| Head::record_size(1, n) == Some(room))
            .unwrap();
        let value = vec![b'x'; length];
        head.push("X", &value).unwrap();
        assert_eq!(head.block.room(), 0);
        let before: Vec<_> = head
            .fields()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(head.push("Y", b""), Err(Error::HeadTooLong));
        assert!(
            head.fields()
                .eq(before.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
        );
        assert_eq!(Head::parse(&head.to_bytes().unwrap()).unwrap(), head);
    }

    #[test]
    fn shared_head_storage_cannot_be_extended() {
        let budget = Budget::new(4096);
        let pool = Pool::new(&budget, 2048, 1);
        let mut head =
            Head::in_block(pool.take(&budget, 0).unwrap(), "GET", "/", Version::Http11).unwrap();
        head.push("Host", b"example.test").unwrap();
        let copy = head.clone();
        assert_eq!(head.push("X", b"value"), Err(Error::HeadTooLong));
        assert_eq!(head, copy);
        drop(copy);
        head.push("X", b"value").unwrap();
        assert_eq!(head.field(b"x"), Some(b"value".as_slice()));
    }

    #[test]
    fn pooled_head_refusal_does_not_charge_or_return_a_request() {
        use fictionet::stdlib::codec::Decode;
        use fictionet::stdlib::protocols::http1::RequestEvents;
        let budget = Budget::new(0);
        let small = Pool::new(&budget, 2048, 1);
        let large = Pool::new(&budget, 16384 + 64, 1);
        let mut decoder = RequestEvents::new();
        decoder.storage(budget.clone(), small.clone(), large.clone());
        let error = decoder
            .decode(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", false)
            .unwrap_err();
        assert_eq!(error.reason(), Error::Budget);
        assert_eq!(budget.used(), 0);
        assert_eq!(small.charged() + large.charged(), 0);
    }

    #[test]
    fn retained_heads_keep_their_charge_across_pool_classes() {
        use fictionet::stdlib::codec::{Decode, Step};
        use fictionet::stdlib::protocols::http1::{Event, Limits, RequestEvents};
        for length in [31, 2048, 12000, 20000] {
            let budget = Budget::new(1 << 20);
            let small = Pool::new(&budget, 2048, 2);
            let large = Pool::new(&budget, 16384 + 64, 2);
            let mut decoder = RequestEvents::with_limits(Limits {
                header_line: 32768,
                head: 65536,
                ..Limits::default()
            });
            decoder.storage(budget.clone(), small.clone(), large.clone());
            let value = vec![b'x'; length];
            let wire = [
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX: ".as_slice(),
                &value,
                b"\r\n\r\n",
            ]
            .concat();
            let Step::Item(Event::Head(head), _) = decoder.decode(&wire, false).unwrap() else {
                panic!("complete request head");
            };
            let retained = head.clone();
            drop(head);
            drop(decoder);
            drop(small);
            drop(large);
            assert_eq!(retained.field(b"x"), Some(value.as_slice()));
            assert!(retained.held() >= length);
            assert_eq!(budget.used(), retained.held());
            drop(retained);
            assert_eq!(budget.used(), 0);
        }
    }
}
