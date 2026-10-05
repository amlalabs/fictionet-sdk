//! application/x-www-form-urlencoded: reading and writing the name and
//! value pairs of HTML form bodies and URL query strings, with no I/O.
//!
//! When a browser submits a form with the POST method, the body is a list
//! of pairs such as `user=alice&note=hi+there%21`. The query string of a
//! URL, the part after `?`, uses the same format. Pairs are split by `&`,
//! each name is split from its value by the first `=`, a `+` stands for a
//! space, and `%` with two hex digits stands for any byte. This module
//! follows the urlencoded section of the WHATWG URL Standard, which is
//! what browsers do, byte for byte:
//!
//! - [`parse`] runs the urlencoded parser on a whole body.
//! - [`Fields`] with [`super::codec::Stream`] reads a body that arrives in
//!   pieces, and hands out each field as soon as its `&` arrives.
//! - [`serialize`] runs the urlencoded serializer.
//! - [`percent_encode`] and [`percent_decode`] encode and decode one
//!   string with any of the percent-encode sets the standard defines
//!   ([`EncodeSet`]), for building URLs as well as forms.
//!
//! Nothing here reads a socket. A world that plays a web server takes the
//! body of a request, or its query with [`query_of`], and reads the pairs
//! with [`parse`]. What the pairs mean is up to world code.
//!
//! The parser accepts any bytes, as browsers do: a stray `%` stays as it
//! is, and bytes that are not UTF-8 become U+FFFD. The only errors are
//! the size limits [`MAX_INPUT`] and [`MAX_PAIRS`], because the agent can
//! send as much as it likes. [`serialize`] checks the same limits, so it
//! never writes a form the parser would refuse.
//!
//! Use [`Fields`] with [`super::codec::Stream`] for bounded field decoding.
//! [`Field`] implements [`Wire`] for one complete field. The deprecated
//! [`Decoder`] keeps its original buffering and errors.
//!
//! ```
//! use fictionet::stdlib::urlencoded_form::{parse, percent_encode, serialize, EncodeSet};
//!
//! let pairs = parse(b"user=alice&note=hi+there%21&&flag").unwrap();
//! assert_eq!(
//!     pairs,
//!     vec![
//!         ("user".to_string(), "alice".to_string()),
//!         ("note".to_string(), "hi there!".to_string()),
//!         ("flag".to_string(), String::new()),
//!     ]
//! );
//! // Writing them back gives the form a browser would send.
//! assert_eq!(serialize(&pairs).unwrap(), "user=alice&note=hi+there%21&flag=");
//! // One path segment for a URL.
//! assert_eq!(percent_encode("a b/c".as_bytes(), EncodeSet::Path, false).unwrap(), "a%20b/c");
//! ```

extern crate alloc;

use alloc::{string::String, vec::Vec};
use super::codec::{Decode, Step, Wire};

/// The most bytes [`parse`] and a [`Decoder`] read, and the most
/// [`serialize`] writes. The same cap applies to the input and output of
/// [`percent_encode`] and the input of [`percent_decode`] and
/// [`decode_component`].
pub const MAX_INPUT: usize = 1 << 20;
/// The most pairs one form may hold. Empty pieces between two `&` are not
/// pairs and do not count.
pub const MAX_PAIRS: usize = 10_000;

/// One name and its value, both decoded.
pub type Pair = (String, String);

/// Why a form was not read or written. Both are size limits; any bytes
/// within them are a form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormError {
    /// The input, or the output being written, is longer than
    /// [`MAX_INPUT`] bytes.
    TooLong,
    /// The form holds more than [`MAX_PAIRS`] pairs.
    TooManyPairs,
}

impl core::fmt::Display for FormError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FormError::TooLong => write!(f, "form is longer than {MAX_INPUT} bytes"),
            FormError::TooManyPairs => write!(f, "form has more than {MAX_PAIRS} pairs"),
        }
    }
}

impl core::error::Error for FormError {}

/// Reads a whole form body or query string into its pairs, in order, as
/// the WHATWG urlencoded parser does. Give it the query without its
/// leading `?` ([`query_of`] finds it).
///
/// Empty pieces between `&` are skipped. A piece with no `=` is a name
/// with an empty value. Names may repeat, and every copy is kept.
///
/// [`serialize`] can write any pairs read here, but the form it writes
/// may be longer than the input. A byte that is not UTF-8 becomes U+FFFD,
/// which takes nine bytes once encoded. So pairs read from a long form
/// can be too long to write back.
pub fn parse(input: &[u8]) -> Result<Vec<Pair>, FormError> {
    if input.len() > MAX_INPUT {
        return Err(FormError::TooLong);
    }
    let mut out = Vec::new();
    for piece in input.split(|&b| b == b'&') {
        if piece.is_empty() {
            continue;
        }
        if out.len() >= MAX_PAIRS {
            return Err(FormError::TooManyPairs);
        }
        out.push(split_pair(piece));
    }
    Ok(out)
}

/// The name and value of one non-empty piece between `&`, decoded.
fn split_pair(piece: &[u8]) -> Pair {
    match piece.iter().position(|&b| b == b'=') {
        Some(i) => (decode_text(&piece[..i]), decode_text(&piece[i + 1..])),
        None => (decode_text(piece), String::new()),
    }
}

/// Decodes one name or value of a form: each `+` becomes a space, then
/// each `%` and two hex digits becomes that byte, then the bytes are read
/// as UTF-8, with U+FFFD for any that are not. A byte order mark is kept.
///
/// It fails when `bytes` is longer than [`MAX_INPUT`]. The output can be
/// up to three times as long as the input, since each byte that is not
/// UTF-8 becomes U+FFFD, three bytes long.
pub fn decode_component(bytes: &[u8]) -> Result<String, FormError> {
    if bytes.len() > MAX_INPUT {
        return Err(FormError::TooLong);
    }
    Ok(decode_text(bytes))
}

/// [`decode_component`] for input already within [`MAX_INPUT`].
fn decode_text(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    decode_into(bytes, true, &mut out);
    match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// Decodes `%` and two hex digits into that byte, as the WHATWG percent
/// decoder does. A `%` that is not followed by two hex digits stays as it
/// is. A `+` stays a `+`; use [`decode_component`] for form names and
/// values.
pub fn percent_decode(bytes: &[u8]) -> Result<Vec<u8>, FormError> {
    if bytes.len() > MAX_INPUT {
        return Err(FormError::TooLong);
    }
    let mut out = Vec::with_capacity(bytes.len());
    decode_into(bytes, false, &mut out);
    Ok(out)
}

/// Appends the percent-decoded `bytes` to `out`, reading `+` as a space
/// when `plus` is set.
fn decode_into(bytes: &[u8], plus: bool, out: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && let (Some(h), Some(l)) = (bytes.get(i + 1).and_then(|&c| hex(c)), bytes.get(i + 2).and_then(|&c| hex(c))) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        out.push(if plus && b == b'+' { b' ' } else { b });
        i += 1;
    }
}

/// The value of one hex digit, either case.
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The percent-encode sets of the WHATWG URL Standard. Each names the
/// bytes that must be written as `%` and two hex digits in one part of a
/// URL. Every set holds the C0 controls (0x00 to 0x1F) and every byte
/// above 0x7E, so UTF-8 text outside ASCII is always encoded. The path
/// set holds the query set but not the special-query set. From
/// [`EncodeSet::Userinfo`] on, each set holds the one before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncodeSet {
    /// The C0 controls and bytes above 0x7E, and nothing else. Used for
    /// the host and path of URLs that are not special, such as `data:`.
    C0Control,
    /// The C0 control set and space, `"`, `<`, `>` and `` ` ``. Used for
    /// the fragment, after `#`.
    Fragment,
    /// The C0 control set and space, `"`, `#`, `<` and `>`. Used for the
    /// query of URLs that are not special. It does not hold `` ` ``.
    Query,
    /// The query set and `'`. Used for the query of special URLs, such as
    /// `http:` and `https:`.
    SpecialQuery,
    /// The query set and `?`, `^`, `` ` ``, `{` and `}`. Used for path
    /// segments. It does not hold `'`.
    Path,
    /// The path set and `/`, `:`, `;`, `=`, `@`, `[`, `\`, `]` and `|`.
    /// Used for the username and password.
    Userinfo,
    /// The userinfo set and `$`, `%`, `&`, `+` and `,`. On UTF-8 text it
    /// gives the same output as JavaScript's `encodeURIComponent`.
    Component,
    /// The component set and `!`, `'`, `(`, `)` and `~`. Used by the
    /// urlencoded serializer: only ASCII letters, digits, `*`, `-`, `.`
    /// and `_` are left as they are.
    Form,
}

impl EncodeSet {
    /// Every set, smallest first.
    pub const ALL: [EncodeSet; 8] = [
        EncodeSet::C0Control,
        EncodeSet::Fragment,
        EncodeSet::Query,
        EncodeSet::SpecialQuery,
        EncodeSet::Path,
        EncodeSet::Userinfo,
        EncodeSet::Component,
        EncodeSet::Form,
    ];

    /// Whether this set holds `b`, so that `b` is written as `%` and two
    /// hex digits.
    pub fn contains(self, b: u8) -> bool {
        if !(0x20..=0x7e).contains(&b) {
            return true;
        }
        match self {
            EncodeSet::C0Control => false,
            EncodeSet::Fragment => matches!(b, b' ' | b'"' | b'<' | b'>' | b'`'),
            EncodeSet::Query => matches!(b, b' ' | b'"' | b'#' | b'<' | b'>'),
            EncodeSet::SpecialQuery => b == b'\'' || EncodeSet::Query.contains(b),
            EncodeSet::Path => matches!(b, b'?' | b'^' | b'`' | b'{' | b'}') || EncodeSet::Query.contains(b),
            EncodeSet::Userinfo => {
                matches!(b, b'/' | b':' | b';' | b'=' | b'@' | b'[' | b'\\' | b']' | b'|') || EncodeSet::Path.contains(b)
            }
            EncodeSet::Component => matches!(b, b'$' | b'%' | b'&' | b'+' | b',') || EncodeSet::Userinfo.contains(b),
            EncodeSet::Form => matches!(b, b'!' | b'\'' | b'(' | b')' | b'~') || EncodeSet::Component.contains(b),
        }
    }
}

/// Writes `bytes` with every byte in `set` as `%` and two upper-case hex
/// digits, as the WHATWG "percent-encode after encoding" algorithm does
/// for UTF-8. With `space_as_plus`, a space becomes `+` instead, as in
/// forms. Pass text as its UTF-8 bytes.
///
/// The output is ASCII. It fails when `bytes` or the output would be
/// longer than [`MAX_INPUT`], so [`percent_decode`] and [`parse`] can
/// always read what it writes.
pub fn percent_encode(bytes: &[u8], set: EncodeSet, space_as_plus: bool) -> Result<String, FormError> {
    if bytes.len() > MAX_INPUT {
        return Err(FormError::TooLong);
    }
    let len = encoded_len(bytes, set, space_as_plus);
    if len > MAX_INPUT {
        return Err(FormError::TooLong);
    }
    let mut out = String::with_capacity(len);
    encode_into(bytes, set, space_as_plus, &mut out);
    Ok(out)
}

/// How long [`encode_into`] makes `bytes`. It never overflows, since each
/// byte adds at most 3 and slices are far shorter than `usize::MAX / 3`.
fn encoded_len(bytes: &[u8], set: EncodeSet, space_as_plus: bool) -> usize {
    bytes.iter().fold(0usize, |n, &b| {
        n.saturating_add(if (space_as_plus && b == b' ') || !set.contains(b) { 1 } else { 3 })
    })
}

/// Appends `bytes` to `out`, percent-encoded with `set`.
fn encode_into(bytes: &[u8], set: EncodeSet, space_as_plus: bool, out: &mut String) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if space_as_plus && b == b' ' {
            out.push('+');
        } else if set.contains(b) {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        } else {
            // Not in any set, so ASCII.
            out.push(char::from(b));
        }
    }
}

/// Writes pairs as a form, as the WHATWG urlencoded serializer does: each
/// name and value encoded with [`EncodeSet::Form`] and spaces as `+`,
/// joined by `=`, pairs joined by `&`. Every pair gets an `=`, even when
/// its value is empty.
///
/// [`parse`] reads the result back to the same pairs. It fails, writing
/// nothing, when the form would hold more than [`MAX_PAIRS`] pairs or be
/// longer than [`MAX_INPUT`] bytes.
pub fn serialize<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> Result<String, FormError> {
    if pairs.len() > MAX_PAIRS {
        return Err(FormError::TooManyPairs);
    }
    // Each string is read once, so the bytes measured are the bytes written
    // even if an `AsRef` gives a different string on each call.
    let pairs: Vec<(&[u8], &[u8])> = pairs.iter().map(|(n, v)| (n.as_ref().as_bytes(), v.as_ref().as_bytes())).collect();
    let mut len = 0usize;
    for (i, &(n, v)) in pairs.iter().enumerate() {
        let piece = encoded_len(n, EncodeSet::Form, true).saturating_add(encoded_len(v, EncodeSet::Form, true)).saturating_add(1);
        len = len.saturating_add(piece).saturating_add(usize::from(i > 0));
        if len > MAX_INPUT {
            return Err(FormError::TooLong);
        }
    }
    let mut out = String::with_capacity(len);
    for (i, &(n, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_into(n, EncodeSet::Form, true, &mut out);
        out.push('=');
        encode_into(v, EncodeSet::Form, true, &mut out);
    }
    Ok(out)
}

/// The value of the first pair named `name`, if there is one.
pub fn first<'a>(pairs: &'a [Pair], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The values of every pair named `name`, in order. Forms repeat a name
/// for checkboxes and multiple selects.
pub fn values<'a>(pairs: &'a [Pair], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    pairs.iter().filter(move |(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The query of a request target or URL: the bytes after the first `?`,
/// up to any `#`. It is empty when there is no `?`.
pub fn query_of(target: &[u8]) -> &[u8] {
    let target = match target.iter().position(|&b| b == b'#') {
        Some(i) => &target[..i],
        None => target,
    };
    match target.iter().position(|&b| b == b'?') {
        Some(i) => &target[i + 1..],
        None => &[],
    }
}

/// One form field, with its decoded name and value.
///
/// The wire form contains exactly one nonempty field, without `&`.
/// Parsing also checks that its canonical encoding fits [`MAX_INPUT`].
/// [`parse`] and [`Fields`] accept fields whose canonical encoding is larger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field(
    /// The decoded name and value.
    pub Pair,
);

/// Why one exact field or a stream of fields could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    /// A form size or pair count limit was exceeded.
    Form(FormError),
    /// No field was present.
    Empty,
    /// A separator followed the field in an exact parse.
    Trailing,
}

impl core::fmt::Display for FieldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Form(e) => e.fmt(f),
            Self::Empty => f.write_str("no form field"),
            Self::Trailing => f.write_str("separator after the form field"),
        }
    }
}

impl core::error::Error for FieldError {}

impl Wire for Field {
    type ParseError = FieldError;
    type WriteError = FormError;

    fn parse(input: &[u8]) -> Result<Self, FieldError> {
        if input.len() > MAX_INPUT {
            return Err(FieldError::Form(FormError::TooLong));
        }
        if input.is_empty() {
            return Err(FieldError::Empty);
        }
        if input.contains(&b'&') {
            return Err(FieldError::Trailing);
        }
        let pair = split_pair(input);
        serialize(core::slice::from_ref(&pair)).map_err(FieldError::Form)?;
        Ok(Self(pair))
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), FormError> {
        out.extend_from_slice(serialize(core::slice::from_ref(&self.0))?.as_bytes());
        Ok(())
    }
}

/// Reads fields separated by `&` without holding input bytes.
///
/// Empty pieces are skipped. EOF completes the last nonempty field.
/// Percent escapes and UTF-8 use the same replacement rules as [`parse`].
/// Limits apply to the entire input form, as in [`parse`]. Writing a field
/// also checks that its canonical encoding fits [`MAX_INPUT`].
/// Capacity is [`MAX_INPUT`] plus one byte to detect overflow.
/// Errors end the stream. Use [`codec::Stream`](super::codec::Stream) to drive this decoder.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, finish, pump}, urlencoded_form::{Field, Fields}};
///
/// let mut stream = Stream::new(Fields::new());
/// let mut fields = Vec::new();
/// pump(&mut stream, b"name=Alice+", |field| fields.push(field))?;
/// pump(&mut stream, b"Smith&flag", |field| fields.push(field))?;
/// finish(&mut stream, |field| fields.push(field))?;
/// assert_eq!(fields, vec![
///     Field(("name".into(), "Alice Smith".into())),
///     Field(("flag".into(), String::new())),
/// ]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::urlencoded_form::FieldError>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Fields {
    scan: usize,
    consumed: usize,
    pairs: usize,
}

impl Fields {
    /// Starts a form bounded by [`MAX_INPUT`] and [`MAX_PAIRS`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decode for Fields {
    type Item = Field;
    type Error = FieldError;
    const NAME: &'static str = "URL-encoded form";

    fn capacity(&self) -> usize {
        MAX_INPUT.saturating_add(1)
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Field>, FieldError> {
        let room = MAX_INPUT.saturating_sub(self.consumed);
        let visible = input
            .get(..input.len().min(room.saturating_add(1)))
            .unwrap_or_default();
        let end = visible
            .get(self.scan..)
            .and_then(|r| r.iter().position(|b| *b == b'&'))
            .map(|n| self.scan.saturating_add(n));
        let (end, used) = match end {
            Some(end) if end < room => (end, end.saturating_add(1)),
            _ if visible.len() > room => return Err(FieldError::Form(FormError::TooLong)),
            None if eof && !visible.is_empty() => (visible.len(), visible.len()),
            _ => {
                self.scan = visible.len();
                return Ok(Step::Need);
            }
        };
        if end > 0 && self.pairs >= MAX_PAIRS {
            return Err(FieldError::Form(FormError::TooManyPairs));
        }
        let field = if end == 0 {
            None
        } else {
            Some(Field(split_pair(visible.get(..end).unwrap_or_default())))
        };
        self.scan = 0;
        self.consumed = self.consumed.saturating_add(used);
        Ok(match field {
            Some(field) => {
                self.pairs = self.pairs.saturating_add(1);
                Step::Item(field, used)
            }
            None => Step::Skip(used),
        })
    }
}

/// Reads a form that arrives in pieces, such as a request body read from
/// a connection, and hands out each pair once the `&` after it arrives.
/// Fed the same bytes, it gives the same pairs as [`parse`], however they
/// are split.
///
/// It holds at most [`MAX_INPUT`] bytes in all. Past that, or past
/// [`MAX_PAIRS`] pairs, it fails and stays failed.
#[derive(Clone, Debug, Default)]
#[deprecated(note = "use codec::Stream with urlencoded_form::Fields")]
pub struct Decoder {
    /// Bytes fed and not yet handed out, from `start`.
    buf: Vec<u8>,
    /// Where the bytes not yet handed out begin in `buf`.
    start: usize,
    /// Where the search for the next `&` resumes in `buf`.
    scan: usize,
    /// Bytes fed in all.
    total: usize,
    /// Pairs handed out.
    pairs: usize,
    /// Whether [`Decoder::finish`] was called.
    finished: bool,
    /// The error the form failed with, once it has.
    error: Option<FormError>,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Decoder {
    /// A decoder at the start of a form.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes of the form. Bytes fed after [`Decoder::finish`], or
    /// after the form failed, are ignored.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.finished || self.error.is_some() {
            return;
        }
        self.total = self.total.saturating_add(bytes.len());
        if self.total > MAX_INPUT {
            self.fail(FormError::TooLong);
            return;
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.scan -= self.start;
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Says the form is complete, so the bytes after the last `&` are a
    /// pair too.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// The next pair, `None` until more bytes or [`Decoder::finish`]
    /// arrive, or the error the form failed with.
    pub fn next_pair(&mut self) -> Option<Result<Pair, FormError>> {
        if let Some(e) = self.error {
            return Some(Err(e));
        }
        loop {
            let (end, next) = match self.buf[self.scan..].iter().position(|&b| b == b'&') {
                Some(i) => (self.scan + i, self.scan + i + 1),
                None if self.finished => (self.buf.len(), self.buf.len()),
                None => {
                    self.scan = self.buf.len();
                    return None;
                }
            };
            let piece = &self.buf[self.start..end];
            let pair = if piece.is_empty() { None } else { Some(split_pair(piece)) };
            self.start = next;
            self.scan = next;
            if let Some(pair) = pair {
                if self.pairs >= MAX_PAIRS {
                    self.fail(FormError::TooManyPairs);
                    return Some(Err(FormError::TooManyPairs));
                }
                self.pairs += 1;
                return Some(Ok(pair));
            }
            if self.start == self.buf.len() && self.finished {
                return None;
            }
        }
    }

    /// How many bytes are held and not yet handed out as pairs.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Fails the form for good and drops what it holds.
    fn fail(&mut self, e: FormError) {
        self.error = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        self.scan = 0;
    }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<Pair> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    /// Every pair a decoder gives for `input`, fed in pieces of `step`
    /// bytes, or its first error.
    fn decode(input: &[u8], step: usize) -> Result<Vec<Pair>, FormError> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for chunk in input.chunks(step.max(1)) {
            d.feed(chunk);
            while let Some(p) = d.next_pair() {
                out.push(p?);
            }
        }
        d.finish();
        while let Some(p) = d.next_pair() {
            out.push(p?);
        }
        assert_eq!(d.buffered(), 0);
        Ok(out)
    }

    // Examples from the WHATWG URL Standard and from what browsers do.

    #[test]
    fn parser_examples() {
        assert_eq!(parse(b"a=b&c=d").unwrap(), pairs(&[("a", "b"), ("c", "d")]));
        assert_eq!(parse(b"").unwrap(), pairs(&[]));
        assert_eq!(parse(b"&&&").unwrap(), pairs(&[]));
        assert_eq!(parse(b"a").unwrap(), pairs(&[("a", "")]));
        assert_eq!(parse(b"=").unwrap(), pairs(&[("", "")]));
        assert_eq!(parse(b"=b").unwrap(), pairs(&[("", "b")]));
        assert_eq!(parse(b"a=b=c").unwrap(), pairs(&[("a", "b=c")]));
        assert_eq!(parse(b"a=1&a=2").unwrap(), pairs(&[("a", "1"), ("a", "2")]));
        assert_eq!(parse(b"a+b=c+d").unwrap(), pairs(&[("a b", "c d")]));
        // A plus written as %2B stays a plus.
        assert_eq!(parse(b"q=1%2B1").unwrap(), pairs(&[("q", "1+1")]));
        // Stray percent signs stay as they are.
        assert_eq!(parse(b"%zz=%4&x=%").unwrap(), pairs(&[("%zz", "%4"), ("x", "%")]));
        assert_eq!(parse(b"%61=%41%42").unwrap(), pairs(&[("a", "AB")]));
        // %26 and %3D are data, not separators.
        assert_eq!(parse(b"k%3D=v%26w").unwrap(), pairs(&[("k=", "v&w")]));
        // UTF-8, in either hex case.
        assert_eq!(parse(b"x=%e2%80%bd").unwrap(), pairs(&[("x", "\u{203d}")]));
        // Bytes that are not UTF-8 become U+FFFD.
        assert_eq!(parse(b"x=%FF&y=\xc3").unwrap(), pairs(&[("x", "\u{fffd}"), ("y", "\u{fffd}")]));
        // A byte order mark is kept.
        assert_eq!(parse(b"%EF%BB%BFa=1").unwrap(), pairs(&[("\u{feff}a", "1")]));
        // Raw bytes outside ASCII are read as UTF-8 too.
        assert_eq!(parse("caf\u{e9}=\u{2603}".as_bytes()).unwrap(), pairs(&[("caf\u{e9}", "\u{2603}")]));
    }

    #[test]
    fn utf8_replacement_matches_the_encoding_standard() {
        // One U+FFFD per maximal subpart, as the WHATWG UTF-8 decoder does.
        assert_eq!(decode_component(b"%E2%80").unwrap(), "\u{fffd}");
        assert_eq!(decode_component(b"%E2%80a").unwrap(), "\u{fffd}a");
        assert_eq!(decode_component(b"%F0%80%80").unwrap(), "\u{fffd}\u{fffd}\u{fffd}");
        assert_eq!(decode_component(b"%ED%A0%80").unwrap(), "\u{fffd}\u{fffd}\u{fffd}");
        assert_eq!(decode_component(b"%C0%AF").unwrap(), "\u{fffd}\u{fffd}");
        assert_eq!(decode_component(b"%F4%90%80%80").unwrap(), "\u{fffd}\u{fffd}\u{fffd}\u{fffd}");
        assert_eq!(decode_component(b"%F0%9F%98").unwrap(), "\u{fffd}");
    }

    #[test]
    fn set_nesting() {
        let holds = |big: EncodeSet, small: EncodeSet| (0..=255u8).all(|b| !small.contains(b) || big.contains(b));
        assert!(holds(EncodeSet::Fragment, EncodeSet::C0Control));
        assert!(holds(EncodeSet::Query, EncodeSet::C0Control));
        assert!(holds(EncodeSet::SpecialQuery, EncodeSet::Query));
        assert!(holds(EncodeSet::Path, EncodeSet::Query));
        assert!(!holds(EncodeSet::Path, EncodeSet::SpecialQuery));
        assert!(holds(EncodeSet::Userinfo, EncodeSet::Path));
        assert!(holds(EncodeSet::Component, EncodeSet::Userinfo));
        assert!(holds(EncodeSet::Form, EncodeSet::Component));
        // Path is the query set and exactly ?, ^, `, { and }.
        let extra: Vec<u8> = (0..=255u8).filter(|&b| EncodeSet::Path.contains(b) && !EncodeSet::Query.contains(b)).collect();
        assert_eq!(extra, b"?^`{}");
        let extra: Vec<u8> = (0..=255u8).filter(|&b| EncodeSet::Userinfo.contains(b) && !EncodeSet::Path.contains(b)).collect();
        assert_eq!(extra, b"/:;=@[\\]|");
        let extra: Vec<u8> = (0..=255u8).filter(|&b| EncodeSet::Component.contains(b) && !EncodeSet::Userinfo.contains(b)).collect();
        assert_eq!(extra, b"$%&+,");
        let extra: Vec<u8> = (0..=255u8).filter(|&b| EncodeSet::Form.contains(b) && !EncodeSet::Component.contains(b)).collect();
        assert_eq!(extra, b"!'()~");
    }

    #[test]
    fn percent_decode_examples() {
        // From the standard's percent-decode examples.
        assert_eq!(percent_decode(b"%25%s%1G").unwrap(), b"%%s%1G");
        assert_eq!(percent_decode("\u{203d}%25%2E".as_bytes()).unwrap(), [0xe2, 0x80, 0xbd, 0x25, 0x2e]);
        assert_eq!(percent_decode(b"a+b").unwrap(), b"a+b");
        assert_eq!(decode_component(b"a+b%20c").unwrap(), "a b c");
    }

    #[test]
    fn percent_encode_examples() {
        // From the standard's percent-encode examples.
        assert_eq!(percent_encode("\u{2261}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "%E2%89%A1");
        assert_eq!(percent_encode("\u{203d}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "%E2%80%BD");
        assert_eq!(percent_encode("Say what\u{203d}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "Say%20what%E2%80%BD");
        assert_eq!(percent_encode("Say what\u{203d}".as_bytes(), EncodeSet::Form, true).unwrap(), "Say+what%E2%80%BD");
        // What each set leaves alone.
        let printable: Vec<u8> = (0x20..=0x7e).collect();
        let kept = |set: EncodeSet| -> String { printable.iter().filter(|&&b| !set.contains(b)).map(|&b| char::from(b)).collect() };
        assert_eq!(kept(EncodeSet::Form), "*-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz");
        assert_eq!(kept(EncodeSet::Component), "!'()*-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~");
        assert_eq!(kept(EncodeSet::C0Control).len(), printable.len());
        for b in [b' ', b'"', b'#', b'<', b'>'] {
            assert!(EncodeSet::Query.contains(b));
            assert!(!EncodeSet::C0Control.contains(b));
        }
        assert!(!EncodeSet::Query.contains(b'\''));
        assert!(EncodeSet::SpecialQuery.contains(b'\''));
        assert!(EncodeSet::Fragment.contains(b'`'));
        assert!(!EncodeSet::Fragment.contains(b'#'));
        assert!(!EncodeSet::Query.contains(b'`'));
        assert!(EncodeSet::Path.contains(b'^') && !EncodeSet::Path.contains(b'/'));
        assert!(EncodeSet::Userinfo.contains(b'/') && !EncodeSet::Userinfo.contains(b'%'));
        assert!(EncodeSet::Component.contains(b'%'));
        // Each set from Query on holds the one before it.
        for w in EncodeSet::ALL[2..].windows(2) {
            if w[0] == EncodeSet::SpecialQuery {
                continue;
            }
            for b in 0..=255u8 {
                assert!(!w[0].contains(b) || w[1].contains(b), "{:?} {b}", w[1]);
            }
        }
        for set in EncodeSet::ALL {
            for b in (0..0x20).chain(0x7f..=0xff) {
                assert!(set.contains(b), "{set:?} {b}");
            }
            assert!(!set.contains(b'a') && !set.contains(b'Z') && !set.contains(b'5'));
        }
        // A space without space_as_plus is %20 in the form set.
        assert_eq!(percent_encode(b" ", EncodeSet::Form, false).unwrap(), "%20");
        assert_eq!(percent_encode(b" ", EncodeSet::C0Control, true).unwrap(), "+");
    }

    #[test]
    fn serializer_examples() {
        let p = pairs(&[("a b", "c&d=e"), ("", ""), ("x", "1+1"), ("~", "\u{e9}*-._")]);
        let s = serialize(&p).unwrap();
        assert_eq!(s, "a+b=c%26d%3De&=&x=1%2B1&%7E=%C3%A9*-._");
        assert_eq!(parse(s.as_bytes()).unwrap(), p);
        assert_eq!(serialize::<&str, &str>(&[]).unwrap(), "");
        assert_eq!(serialize(&[("k", "")]).unwrap(), "k=");
        assert_eq!(serialize(&[("\u{0}\n", "%")]).unwrap(), "%00%0A=%25");
    }

    #[test]
    fn helpers() {
        let p = parse(b"a=1&b=2&a=3").unwrap();
        assert_eq!(first(&p, "a"), Some("1"));
        assert_eq!(first(&p, "c"), None);
        assert_eq!(values(&p, "a").collect::<Vec<_>>(), ["1", "3"]);
        assert_eq!(values(&p, "c").count(), 0);
        assert_eq!(query_of(b"/search?q=cats&page=2#top"), b"q=cats&page=2");
        assert_eq!(query_of(b"/search"), b"");
        assert_eq!(query_of(b"/a#b?c"), b"");
        assert_eq!(query_of(b"/a?b?c"), b"b?c");
        assert_eq!(query_of(b"?"), b"");
        assert_eq!(FormError::TooLong.to_string(), format!("form is longer than {MAX_INPUT} bytes"));
        assert_eq!(FormError::TooManyPairs.to_string(), format!("form has more than {MAX_PAIRS} pairs"));
    }

    #[test]
    fn too_long() {
        let big = vec![b'a'; MAX_INPUT + 1];
        assert_eq!(parse(&big), Err(FormError::TooLong));
        assert_eq!(decode(&big, 4096), Err(FormError::TooLong));
        assert_eq!(percent_decode(&big), Err(FormError::TooLong));
        assert_eq!(percent_encode(&big, EncodeSet::Form, true), Err(FormError::TooLong));
        // Exactly the limit is fine.
        assert_eq!(parse(&big[..MAX_INPUT]).unwrap().len(), 1);
        assert_eq!(decode(&big[..MAX_INPUT], 65536).unwrap().len(), 1);
        // The serializer refuses what the parser would refuse. Each byte
        // outside ASCII grows to 3.
        let wide = "\u{e9}".repeat(MAX_INPUT / 6 + 1);
        assert_eq!(serialize(&[("x", wide.as_str())]), Err(FormError::TooLong));
        let fits = "a".repeat(MAX_INPUT - 2);
        let s = serialize(&[("x", fits.as_str())]).unwrap();
        assert_eq!(s.len(), MAX_INPUT);
        assert!(parse(s.as_bytes()).is_ok());
        assert_eq!(serialize(&[("x", "a".repeat(MAX_INPUT - 1).as_str())]), Err(FormError::TooLong));
        // Writing can grow a form. Bytes that are not UTF-8 each become
        // U+FFFD, nine bytes once encoded, so a form the parser reads may
        // be too long to write back. The writer refuses it as too long.
        let bad = vec![0xffu8; MAX_INPUT / 9 + 1];
        let read = parse(&bad).unwrap();
        assert_eq!(read[0].0.chars().count(), bad.len());
        assert_eq!(serialize(&read), Err(FormError::TooLong));
        // A failed decoder stays failed.
        let mut d = Decoder::new();
        d.feed(&big);
        d.feed(b"a=b&");
        d.finish();
        assert_eq!(d.next_pair(), Some(Err(FormError::TooLong)));
        assert_eq!(d.next_pair(), Some(Err(FormError::TooLong)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decode_component_is_bounded() {
        // A byte that is not UTF-8 grows to three, so the output may be
        // longer than the input, but the input is capped.
        assert_eq!(decode_component(&[0xff]).unwrap(), "\u{fffd}");
        assert_eq!(decode_component(&vec![0xff; MAX_INPUT + 1]), Err(FormError::TooLong));
        assert_eq!(decode_component(&vec![b'a'; MAX_INPUT]).unwrap().len(), MAX_INPUT);
    }

    #[test]
    fn percent_encode_never_writes_what_percent_decode_refuses() {
        // Each % grows to three bytes with the component set.
        let over = vec![b'%'; MAX_INPUT / 3 + 1];
        assert_eq!(percent_encode(&over, EncodeSet::Component, false), Err(FormError::TooLong));
        assert_eq!(percent_encode(&over, EncodeSet::Form, true), Err(FormError::TooLong));
        let at = vec![b'%'; MAX_INPUT / 3];
        let s = percent_encode(&at, EncodeSet::Component, false).unwrap();
        assert!(s.len() <= MAX_INPUT);
        assert_eq!(percent_decode(s.as_bytes()).unwrap(), at);
        assert_eq!(parse(percent_encode(&at, EncodeSet::Form, true).unwrap().as_bytes()).unwrap().len(), 1);
        // A space written as + stays one byte.
        assert_eq!(percent_encode(&vec![b' '; MAX_INPUT], EncodeSet::Form, true).unwrap().len(), MAX_INPUT);
    }

    /// A name that reads as empty the first time and long after that.
    struct Shifty {
        seen: std::cell::Cell<bool>,
        long: String,
    }

    impl AsRef<str> for Shifty {
        fn as_ref(&self) -> &str {
            if self.seen.replace(true) { &self.long } else { "" }
        }
    }

    #[test]
    fn serialize_reads_each_string_once() {
        let v = Shifty { seen: std::cell::Cell::new(false), long: "a".repeat(MAX_INPUT + 1) };
        let pairs = [("k", v)];
        match serialize(&pairs) {
            Ok(s) => {
                assert!(s.len() <= MAX_INPUT);
                assert!(parse(s.as_bytes()).is_ok());
            }
            Err(e) => assert_eq!(e, FormError::TooLong),
        }
    }

    #[test]
    fn decoder_fails_after_pairs_and_stays_failed() {
        // Pairs handed out before the limit stay handed out; then the
        // decoder fails, drops what it holds, and keeps failing.
        let mut input = b"k=v&".to_vec();
        input.extend(std::iter::repeat_n(b'a', MAX_INPUT - 3));
        assert_eq!(parse(&input), Err(FormError::TooLong));
        for step in [1usize, 4, 5, 4096, input.len()] {
            let mut d = Decoder::new();
            let mut got = Vec::new();
            let mut err = None;
            for (i, chunk) in input.chunks(step).enumerate() {
                d.feed(chunk);
                // Drain only now and then, so bytes pile up.
                if i % 3 == 0 {
                    while let Some(p) = d.next_pair() {
                        match p {
                            Ok(p) => got.push(p),
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }
                }
                if err.is_some() {
                    break;
                }
            }
            d.finish();
            if err.is_none() {
                while let Some(p) = d.next_pair() {
                    match p {
                        Ok(p) => got.push(p),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
            }
            assert_eq!(err, Some(FormError::TooLong), "step {step}");
            assert!(got.len() <= 1 && got.iter().all(|p| p == &("k".to_string(), "v".to_string())), "step {step}");
            assert_eq!(d.buffered(), 0);
            d.feed(b"x=y&");
            assert_eq!(d.next_pair(), Some(Err(FormError::TooLong)));
        }
        // Too many pairs, fed a byte at a time, fail the same way.
        let over = b"a&".repeat(MAX_PAIRS + 1);
        let mut d = Decoder::new();
        let mut ok = 0;
        let mut err = None;
        for b in &over {
            d.feed(std::slice::from_ref(b));
            while let Some(p) = d.next_pair() {
                match p {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            if err.is_some() {
                break;
            }
        }
        assert_eq!((ok, err), (MAX_PAIRS, Some(FormError::TooManyPairs)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn too_many_pairs() {
        let at = b"a&".repeat(MAX_PAIRS);
        assert_eq!(parse(&at).unwrap().len(), MAX_PAIRS);
        assert_eq!(decode(&at, 7).unwrap().len(), MAX_PAIRS);
        let over = b"a&".repeat(MAX_PAIRS + 1);
        assert_eq!(parse(&over), Err(FormError::TooManyPairs));
        assert_eq!(decode(&over, 7), Err(FormError::TooManyPairs));
        // Empty pieces do not count.
        let mut sparse = b"&".repeat(MAX_PAIRS * 3);
        sparse.extend_from_slice(b"a=1");
        assert_eq!(parse(&sparse).unwrap().len(), 1);
        let many = vec![("a", "b"); MAX_PAIRS + 1];
        assert_eq!(serialize(&many), Err(FormError::TooManyPairs));
        assert!(parse(serialize(&many[..MAX_PAIRS]).unwrap().as_bytes()).is_ok());
    }

    #[test]
    fn decoder_waits_for_the_ampersand() {
        let mut d = Decoder::new();
        d.feed(b"a=1&b=");
        assert_eq!(d.next_pair(), Some(Ok(("a".into(), "1".into()))));
        assert_eq!(d.next_pair(), None);
        assert_eq!(d.buffered(), 2);
        d.feed(b"2");
        assert_eq!(d.next_pair(), None);
        d.finish();
        assert_eq!(d.next_pair(), Some(Ok(("b".into(), "2".into()))));
        assert_eq!(d.next_pair(), None);
        // Bytes after finish are ignored.
        d.feed(b"&c=3&");
        assert_eq!(d.next_pair(), None);
        // A finished decoder with nothing fed has no pairs.
        let mut e = Decoder::new();
        e.finish();
        assert_eq!(e.next_pair(), None);
    }

    #[test]
    fn every_truncated_prefix() {
        let full = b"name=J%C3%BCrgen+M%C3%BCller&&email=j%40example.com&note=%E2%80%BD&flag&=&x=%2";
        let whole = parse(full).unwrap();
        assert_eq!(whole.len(), 6);
        for n in 0..=full.len() {
            let prefix = &full[..n];
            let got = parse(prefix).unwrap();
            assert_eq!(decode(prefix, 1).unwrap(), got, "{n} bytes");
            assert_eq!(decode(prefix, 5).unwrap(), got, "{n} bytes");
            assert!(got.len() <= whole.len());
            assert_eq!(parse(serialize(&got).unwrap().as_bytes()).unwrap(), got);
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
    }

    #[test]
    fn fuzz_loop() {
        const ALPHABET: &[u8] = b"%%%&&==++aA0fF9gz \x00\x7f\x80\xbf\xc3\xa9\xe2\xff#?~!'";
        let mut rng = Lcg(0x5eed);
        for round in 0..5000 {
            let len = rng.below(48) as usize;
            let buf: Vec<u8> = (0..len)
                .map(|_| if rng.below(4) == 0 { rng.below(256) as u8 } else { ALPHABET[rng.below(ALPHABET.len() as u32) as usize] })
                .collect();
            let got = parse(&buf).unwrap();
            // The decoder agrees, whole, a byte at a time, and in pieces.
            assert_eq!(decode(&buf, buf.len()).unwrap(), got, "round {round}");
            assert_eq!(decode(&buf, 1).unwrap(), got, "round {round}");
            assert_eq!(decode(&buf, 1 + rng.below(5) as usize).unwrap(), got, "round {round}");
            // What is read can be written, and reads back the same.
            let s = serialize(&got).unwrap();
            assert_eq!(parse(s.as_bytes()).unwrap(), got, "round {round}");
            assert_eq!(serialize(&parse(s.as_bytes()).unwrap()).unwrap(), s);
            // Percent decoding never grows its input, and encoding with a
            // set that holds % comes back exactly.
            let raw = percent_decode(&buf).unwrap();
            assert!(raw.len() <= buf.len());
            for set in EncodeSet::ALL {
                let plain = percent_encode(&buf, set, false).unwrap();
                assert!(plain.is_ascii());
                let plus = percent_encode(&buf, set, true).unwrap();
                assert!(!plus.contains(' '));
                if set.contains(b'%') {
                    assert_eq!(percent_decode(plain.as_bytes()).unwrap(), buf, "{set:?}");
                    if set.contains(b'+') {
                        assert_eq!(decode_component(plus.as_bytes()).unwrap(), String::from_utf8_lossy(&buf));
                    }
                }
            }
            let _ = query_of(&buf);
        }
    }
}
