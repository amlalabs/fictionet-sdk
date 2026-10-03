//! An HPACK decoder (RFC 7541), for showing HTTP/2 headers.
//!
//! Each direction of a connection has its own decoder, whose dynamic table
//! follows the header blocks it has seen. When a block that may have
//! changed the table is not decoded, for example because packets were not
//! copied, the decoder forgets its table. A later header that names an
//! entry it no longer knows is shown as unknown, never with a stale value.

use std::collections::VecDeque;
use std::sync::Arc;

/// RFC 7541 Appendix A.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The length in bits of each symbol's Huffman code (RFC 7541 Appendix
/// B), 256 being EOS. The code is canonical, so the lengths fix the codes.
const HUFFMAN_LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12,
    10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6,
    5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22,
    22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20,
    22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28,
    27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28,
    27, 27, 27, 27, 27, 26, 30,
];

/// The canonical code: for each length, the first code of that length and
/// the symbols that have it, in order.
struct Huffman {
    /// `first[len]`: the first code of length `len`; `start[len]`: the
    /// index in `symbols` of its symbol.
    first: [u32; 31],
    count: [u32; 31],
    start: [usize; 31],
    symbols: Vec<u16>,
}

fn huffman() -> &'static Huffman {
    static TABLE: std::sync::OnceLock<Huffman> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut symbols: Vec<u16> = (0..257).collect();
        symbols.sort_by_key(|&s| (HUFFMAN_LENGTHS[s as usize], s));
        let mut h = Huffman { first: [0; 31], count: [0; 31], start: [0; 31], symbols };
        for &l in &HUFFMAN_LENGTHS {
            h.count[l as usize] += 1;
        }
        let mut code = 0u32;
        let mut index = 0usize;
        for len in 1..31 {
            code <<= 1;
            h.first[len] = code;
            h.start[len] = index;
            code += h.count[len];
            index += h.count[len] as usize;
        }
        h
    })
}

/// Decodes a Huffman-coded string.
pub(crate) fn decode_huffman(bytes: &[u8]) -> Option<Vec<u8>> {
    let h = huffman();
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5);
    let (mut code, mut len) = (0u32, 0usize);
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return None;
            }
            let offset = code.wrapping_sub(h.first[len]);
            if code >= h.first[len] && offset < h.count[len] {
                let sym = h.symbols[h.start[len] + offset as usize];
                if sym == 256 {
                    return None;
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // What is left must be padding: fewer than eight 1 bits.
    (len < 8 && code == (1 << len) - 1).then_some(out)
}

/// The most headers one block keeps for showing.
const MAX_HEADERS: usize = 256;
/// The most bytes of names and values one block keeps for showing.
pub(crate) const MAX_DECODED: usize = 64 << 10;
/// The most bytes of entries a decoder keeps in its dynamic table. A peer
/// may announce a larger table; entries past this are then not known.
const MAX_TABLE: usize = 64 << 10;
/// What RFC 7541 counts for each entry, besides its name and value.
const ENTRY_OVERHEAD: usize = 32;

/// One direction's HPACK state.
///
/// Names and values are kept as the octets they are, and counted that way,
/// as RFC 7541 counts them. They become text only for showing.
pub(crate) struct Decoder {
    /// The newest entry first. Names are shared, since a literal can name
    /// an entry and add a new one with the same name, many times over.
    table: VecDeque<(Arc<[u8]>, Vec<u8>)>,
    /// The size of the entries in `table`, as RFC 7541 counts it.
    size: usize,
    /// The table's maximum size, as the last size update set it, or `None`
    /// when a block not decoded may have changed it.
    max: Option<usize>,
    /// Entries older than those in `table` may exist, whose contents are
    /// not known: a header block was not decoded, or the table outgrew
    /// [`MAX_TABLE`]. A reference to one is shown as unknown.
    unsure: bool,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder { table: VecDeque::new(), size: 0, max: Some(4096), unsure: false }
    }
}

/// A decoded header, as text to show. A name or value is `None` when the
/// header named a table entry that is not known.
pub(crate) struct Header {
    pub(crate) name: Option<String>,
    pub(crate) value: Option<String>,
}

/// What one header block decoded to.
#[derive(Default)]
pub(crate) struct Block {
    pub(crate) headers: Vec<Header>,
    /// Headers decoded for the table but not kept for showing, past
    /// [`MAX_HEADERS`] or the byte limit.
    pub(crate) more: usize,
}

impl Block {
    fn keep(&mut self, limit: usize, used: &mut usize, name: Option<&[u8]>, value: Option<&[u8]>) {
        let len = name.map_or(0, <[u8]>::len) + value.map_or(0, <[u8]>::len);
        if self.headers.len() >= MAX_HEADERS || *used + len > limit {
            self.more += 1;
            return;
        }
        *used += len;
        let text = |b: Option<&[u8]>| b.map(|b| String::from_utf8_lossy(b).into_owned());
        self.headers.push(Header { name: text(name), value: text(value) });
    }
}

fn integer(b: &[u8], i: &mut usize, prefix: u8) -> Option<usize> {
    let mask = (1u16 << prefix) as usize - 1;
    let mut v = usize::from(*b.get(*i)?) & mask;
    *i += 1;
    if v < mask {
        return Some(v);
    }
    let mut shift = 0;
    loop {
        let byte = *b.get(*i)?;
        *i += 1;
        v = v.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

fn string(b: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    let huff = b.get(*i)? & 0x80 != 0;
    let len = integer(b, i, 7)?;
    let raw = b.get(*i..i.checked_add(len)?)?;
    *i += len;
    if huff { decode_huffman(raw) } else { Some(raw.to_vec()) }
}

/// What a table index names.
enum Entry<'a> {
    Known(&'a [u8], &'a [u8]),
    /// A dynamic entry, whose name can be shared.
    Dynamic(&'a Arc<[u8]>, &'a [u8]),
    /// An entry that exists, but whose contents are not known.
    Unknown,
}

impl Decoder {
    /// The entry at `index`; `None` if there cannot be one.
    fn get(&self, index: usize) -> Option<Entry<'_>> {
        match index {
            0 => None,
            1..=61 => Some(Entry::Known(STATIC[index - 1].0.as_bytes(), STATIC[index - 1].1.as_bytes())),
            n => match self.table.get(n - 62) {
                Some((name, value)) => Some(Entry::Dynamic(name, value)),
                None if self.unsure => Some(Entry::Unknown),
                None => None,
            },
        }
    }

    fn insert(&mut self, name: Arc<[u8]>, value: Vec<u8>) {
        self.size += name.len() + value.len() + ENTRY_OVERHEAD;
        self.table.push_front((name, value));
        self.evict();
    }

    fn pop(&mut self) {
        if let Some((n, v)) = self.table.pop_back() {
            self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
        }
    }

    fn evict(&mut self) {
        // With the maximum not known, entries are kept: a sender never
        // names one past those its own table holds, and the newest come
        // first in both.
        while self.max.is_some_and(|max| self.size > max) {
            self.pop();
        }
        // The sender's table still holds these, but they are not kept here.
        while self.size > MAX_TABLE {
            self.pop();
            self.unsure = true;
        }
        // Entries are evicted oldest first. When the known entries leave
        // no room for even an empty one, no older entry can be left.
        if self.max.is_some_and(|max| self.size + ENTRY_OVERHEAD > max) {
            self.unsure = false;
        }
    }

    /// Forgets the table: a block that changed it was not decoded, so the
    /// entries it holds, their indexes, and its maximum size, are not
    /// known. The next size update makes the maximum known again.
    pub(crate) fn forget(&mut self) {
        self.table.clear();
        self.size = 0;
        self.unsure = true;
        self.max = None;
    }

    /// Decodes a whole header block, keeping at most [`MAX_HEADERS`]
    /// headers and `limit` bytes of names and values for showing. Every
    /// header still updates the table, however many are kept, since one
    /// table entry can be named many times over.
    ///
    /// `None` if the block is broken. The table is then forgotten.
    pub(crate) fn decode(&mut self, b: &[u8], limit: usize) -> Option<Block> {
        let block = self.decode_block(b, limit.min(MAX_DECODED));
        if block.is_none() {
            self.forget();
        }
        block
    }

    fn decode_block(&mut self, b: &[u8], limit: usize) -> Option<Block> {
        let mut out = Block::default();
        let mut used = 0;
        let mut i = 0;
        while i < b.len() {
            let first = b[i];
            if first & 0x80 != 0 {
                match self.get(integer(b, &mut i, 7)?)? {
                    Entry::Known(name, value) => out.keep(limit, &mut used, Some(name), Some(value)),
                    Entry::Dynamic(name, value) => out.keep(limit, &mut used, Some(name), Some(value)),
                    Entry::Unknown => out.keep(limit, &mut used, None, None),
                }
            } else if first & 0xe0 == 0x20 {
                self.max = Some(integer(b, &mut i, 5)?);
                self.evict();
            } else {
                let indexing = first & 0xc0 == 0x40;
                let index = integer(b, &mut i, if indexing { 6 } else { 4 })?;
                // Names are shared, not copied: copying them could cost far
                // more than the bytes that name them.
                let name: Option<Arc<[u8]>> = match index {
                    0 => Some(string(b, &mut i)?.into()),
                    n => match self.get(n)? {
                        Entry::Known(name, _) => Some(name.into()),
                        Entry::Dynamic(name, _) => Some(name.clone()),
                        Entry::Unknown => None,
                    },
                };
                let value = string(b, &mut i)?;
                out.keep(limit, &mut used, name.as_deref(), Some(&value));
                match (indexing, name) {
                    (true, Some(name)) => self.insert(name, value),
                    // An entry of unknown size: nothing after it is known.
                    (true, None) => self.forget(),
                    (false, _) => {}
                }
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn pairs(h: &[Header]) -> Vec<(&str, &str)> {
        h.iter().map(|h| (h.name.as_deref().unwrap_or(""), h.value.as_deref().unwrap_or(""))).collect()
    }

    /// RFC 7541 C.4: three requests with Huffman coding, sharing a
    /// dynamic table.
    #[test]
    fn rfc_7541_requests_with_huffman() {
        let mut d = Decoder::default();
        let h = d.decode_all(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"));
        assert_eq!(pairs(&h), [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]);
        let h = d.decode_all(&hex("8286 84be 5886 a8eb 1064 9cbf"));
        assert_eq!(pairs(&h)[4], ("cache-control", "no-cache"));
        let h = d.decode_all(&hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"));
        assert_eq!(pairs(&h)[2], (":path", "/index.html"));
        assert_eq!(pairs(&h)[4], ("custom-key", "custom-value"));
        assert_eq!(d.table.len(), 3);
    }

    /// RFC 7541 C.6.1: a response, Huffman coded, in a 256-byte table.
    #[test]
    fn rfc_7541_response() {
        let mut d = Decoder { max: Some(256), ..Decoder::default() };
        let h = d
            .decode_all(&hex(
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            ));
        assert_eq!(
            pairs(&h),
            [
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com")
            ]
        );
    }

    #[test]
    fn broken_blocks_are_none() {
        let mut d = Decoder::default();
        assert!(d.decode(&[0xff], MAX_DECODED).is_none());
        assert!(d.decode(&[0x41, 0x85, 0xff], MAX_DECODED).is_none());
        assert!(decode_huffman(&[0xff, 0xff, 0xff, 0xff]).is_none());
    }

    /// One 4 KiB entry named 10,000 times would be 40 MB of headers: only
    /// as many as the limit allows are kept, and the rest are counted.
    #[test]
    fn a_block_keeps_only_what_the_limit_allows() {
        let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'v', 4000));
        let mut d = Decoder::default();
        assert_eq!(d.decode_all(&block).len(), 1);
        let b = d.decode(&vec![0xbe; 10_000], MAX_DECODED).unwrap();
        assert_eq!(b.headers.len(), MAX_DECODED / 4001);
        assert_eq!(b.headers.len() + b.more, 10_000);
        let b = d.decode(&[0xbe; 10], 100).unwrap();
        assert_eq!((b.headers.len(), b.more), (0, 10));
    }

    /// Headers past the limit still change the table: an insertion after
    /// 256 headers is seen by the next block.
    #[test]
    fn headers_past_the_limit_still_update_the_table() {
        let mut d = Decoder::default();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        let mut block = vec![0x82; 256];
        block.extend(hex("4001 7803 6e65 77")); // x: new
        let b = d.decode(&block, MAX_DECODED).unwrap();
        assert_eq!((b.headers.len(), b.more), (256, 1));
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        assert_eq!(pairs(&d.decode_all(&[0xbf])), [("x", "old")]);
    }

    /// Sizes count octets, not text: a one-byte value that is not UTF-8
    /// takes one byte of the table.
    #[test]
    fn table_sizes_count_octets() {
        let mut d = Decoder::default();
        // Table size 35, then x: 0xff, which takes 1 + 1 + 32 = 34 bytes.
        d.decode_all(&hex("3f04 4001 7801 ff"));
        let h = d.decode_all(&[0xbe]);
        assert_eq!(pairs(&h), [("x", "\u{fffd}")]);
        assert_eq!(d.size, 34);
    }

    /// A block that was not decoded leaves the table unknown: entries
    /// added later are known, older ones show as unknown, not stale.
    #[test]
    fn a_forgotten_table_shows_unknown_not_stale() {
        let mut d = Decoder::default();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        d.forget();
        d.decode_all(&hex("4001 7903 6e65 77")); // y: new
        let b = d.decode(&[0xbe, 0xbf, 0x82], MAX_DECODED).unwrap();
        assert_eq!(pairs(&b.headers), [("y", "new"), ("", ""), (":method", "GET")]);
        assert_eq!(b.headers.iter().map(|h| h.name.is_some()).collect::<Vec<_>>(), [true, false, true]);
        // A literal named after an unknown entry has a known value.
        let b = d.decode(&hex("0f30 0161"), MAX_DECODED).unwrap();
        assert_eq!((b.headers[0].name.as_deref(), b.headers[0].value.as_deref()), (None, Some("a")));
        // Once known entries fill the table, nothing older can be left.
        let mut d = Decoder::default();
        d.forget();
        d.decode_all(&hex("3f3b 4001 7801 61")); // size 90, then x: a (34)
        assert!(d.unsure, "an entry of 32 bytes or more may be left");
        d.decode_all(&hex("4001 7901 62")); // y: b, 68 in all
        assert!(!d.unsure, "no room for an older entry");
        assert!(d.decode(&[0xc0], MAX_DECODED).is_none(), "index 64 cannot exist");
    }

    /// A table larger than the decoder keeps: entries past what it keeps
    /// are unknown, not missing.
    #[test]
    fn a_table_past_what_is_kept_is_unsure() {
        let mut d = Decoder::default();
        // Size update to 1 MiB: 0x3f, then 1,048,576 - 31 as an integer.
        let mut block = vec![0x3f];
        let mut v = (1usize << 20) - 31;
        while v >= 0x80 {
            block.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        block.push(v as u8);
        d.decode_all(&block);
        // a: 16,000 bytes, a literal of length 127 + 15,873.
        let mut big = vec![0x40, 0x01, b'a', 0x7f, 0x81, 0x7c];
        big.extend(std::iter::repeat_n(b'v', 16_000));
        for _ in 0..5 {
            d.decode_all(&big);
        }
        assert_eq!(d.table.len(), 4, "only 64 KiB is kept");
        assert!(d.unsure);
        let b = d.decode(&[0xc2], MAX_DECODED).unwrap(); // index 66, the fifth
        assert!(b.headers[0].value.is_none());
    }

    /// A block not decoded may have changed the table's maximum, so after
    /// it, entries are kept until a size update says what the maximum is.
    #[test]
    fn a_forgotten_table_forgets_its_maximum() {
        let mut d = Decoder::default();
        d.decode_all(&hex("20")); // size 0
        d.forget(); // the block not decoded set it to 4,096
        d.decode_all(&hex("4001 7803 6e65 77")); // x: new
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        d.decode_all(&hex("3f e11f")); // size 4,096
        assert_eq!(d.max, Some(4096));
    }

    /// A literal that names a long entry shares its name, so a block of
    /// such literals costs no more than its own bytes.
    #[test]
    fn literals_share_long_names() {
        let mut d = Decoder::default();
        // Size 65,536, then an entry with a 4,000-byte name.
        let mut block = vec![0x3f, 0xe1, 0xff, 0x03, 0x40, 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'n', 4000));
        block.push(0);
        d.decode_all(&block);
        // 3,000 more entries named after the newest, each with no value.
        let b = d.decode(&[0x7e, 0x00].repeat(3000), 0).unwrap();
        assert_eq!(b.more, 3000);
        assert_eq!(d.table.len(), 16);
        assert!(d.table.iter().all(|(n, _)| Arc::ptr_eq(n, &d.table[0].0)));
    }

    impl Decoder {
        fn decode_all(&mut self, b: &[u8]) -> Vec<Header> {
            let block = self.decode(b, MAX_DECODED).unwrap();
            assert_eq!(block.more, 0);
            block.headers
        }
    }
}
