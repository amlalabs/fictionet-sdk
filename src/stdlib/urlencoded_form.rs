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
//! - [`Form::parse`] reads a whole form that fits the canonical output cap.
//! - [`Stream<Fields>`](fictionet::stdlib::codec::Stream) reads a body that arrives in
//!   pieces, and hands out each field as soon as its `&` arrives.
//! - [`Form`] writes complete forms through [`Wire::write`].
//! - [`PercentEncoded`] and [`percent_decode`] encode and decode one
//!   string with any of the percent-encode sets the standard defines
//!   ([`EncodeSet`]), for building URLs as well as forms.
//!
//! Nothing here reads a socket. A world that plays a web server takes the
//! body of a request, or its query with [`query_of`], and reads the pairs
//! with [`Form::parse`]. What the pairs mean is up to world code.
//!
//! The parser accepts any bytes, as browsers do: a stray `%` stays as it
//! is, and bytes that are not UTF-8 become U+FFFD. The only errors are
//! the size limits [`MAX_INPUT`] and [`MAX_PAIRS`]. [`Form::parse`] also
//! refuses input whose canonical encoding exceeds [`MAX_INPUT`].
//! [`Fields`] accepts expanding forms within the input and pair limits.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::urlencoded_form::{Form, PercentEncoded, EncodeSet};
//!
//! let pairs = Form::parse(b"user=alice&note=hi+there%21&&flag").unwrap().pairs;
//! assert_eq!(
//!     pairs,
//!     vec![
//!         ("user".to_string(), "alice".to_string()),
//!         ("note".to_string(), "hi there!".to_string()),
//!         ("flag".to_string(), String::new()),
//!     ]
//! );
//! // Writing them back gives the form a browser would send.
//! assert_eq!(Form::from_pairs(&pairs).unwrap().to_bytes().unwrap(), b"user=alice&note=hi+there%21&flag=");
//! // One path segment for a URL.
//! assert_eq!(PercentEncoded::new(b"a b/c", EncodeSet::Path, false).unwrap().to_bytes().unwrap(), b"a%20b/c");
//! ```

extern crate alloc;

use alloc::{string::String, vec::Vec};
use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The most bytes [`Form::parse`] and [`Fields`] read, and the most
/// [`Form`] writes. The same cap applies to the input and output of
/// [`PercentEncoded`] and the input of [`percent_decode`] and
/// [`decode_component`].
pub const MAX_INPUT: usize = 1 << 20;
/// The most pairs one form may hold. Empty pieces between two `&` are not
/// pairs and do not count.
pub const MAX_PAIRS: usize = 10_000;

/// Why a form or percent-encoded component was not read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormError {
    /// The input, or the output being written, is longer than
    /// [`MAX_INPUT`] bytes.
    TooLong,
    /// The form holds more than [`MAX_PAIRS`] pairs.
    TooManyPairs,
    /// An encoded component contains bytes outside ASCII.
    NonAscii,
    /// The value cannot be written without changing it.
    Unwritable,
}

impl core::fmt::Display for FormError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FormError::TooLong => write!(f, "form is longer than {MAX_INPUT} bytes"),
            FormError::Unwritable => f.write_str("value cannot be written without changing it"),
            FormError::TooManyPairs => write!(f, "form has more than {MAX_PAIRS} pairs"),
            FormError::NonAscii => f.write_str("encoded component contains non-ASCII bytes"),
        }
    }
}

impl core::error::Error for FormError {}

fn parse(input: &[u8]) -> Result<Vec<(String, String)>, FormError> {
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
fn split_pair(piece: &[u8]) -> (String, String) {
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

fn percent_encode(bytes: &[u8], set: EncodeSet, space_as_plus: bool) -> Result<String, FormError> {
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

fn canonical_len<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> Result<usize, FormError> {
    if pairs.len() > MAX_PAIRS {
        return Err(FormError::TooManyPairs);
    }
    let mut len = 0usize;
    for (i, (n, v)) in pairs.iter().enumerate() {
        let (n, v) = (n.as_ref().as_bytes(), v.as_ref().as_bytes());
        let piece = encoded_len(n, EncodeSet::Form, true).saturating_add(encoded_len(v, EncodeSet::Form, true)).saturating_add(1);
        len = len.saturating_add(piece).saturating_add(usize::from(i > 0));
        if len > MAX_INPUT {
            return Err(FormError::TooLong);
        }
    }
    Ok(len)
}

fn serialize(pairs: &[(String, String)]) -> Result<String, FormError> {
    let len = canonical_len(pairs)?;
    let mut out = String::with_capacity(len);
    for (i, (n, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_into(n.as_bytes(), EncodeSet::Form, true, &mut out);
        out.push('=');
        encode_into(v.as_bytes(), EncodeSet::Form, true, &mut out);
    }
    Ok(out)
}

/// A complete form with decoded pairs in their original order.
/// Duplicate names and empty names or values are kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Form {
    /// The decoded name and value pairs.
    pub pairs: Vec<(String, String)>,
}

impl Form {
    /// Copies pairs into a form. Refuses more than [`MAX_PAIRS`] pairs or
    /// text whose canonical form exceeds [`MAX_INPUT`]. Each string is read once.
    pub fn from_pairs<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> Result<Self, FormError> {
        if pairs.len() > MAX_PAIRS {
            return Err(FormError::TooManyPairs);
        }
        // Borrow each string once so a changing AsRef cannot bypass the cap.
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(n, v)| (n.as_ref(), v.as_ref()))
            .collect();
        canonical_len(&pairs)?;
        Ok(Self {
            pairs: pairs
                .into_iter()
                .map(|(n, v)| (n.into(), v.into()))
                .collect(),
        })
    }
}

impl Wire for Form {
    type ParseError = FormError;
    type WriteError = FormError;

    /// Reads one whole form. Stray percent signs are literal and invalid
    /// UTF-8 becomes U+FFFD. Refuses size or pair count excess, including
    /// forms whose canonical encoding would exceed [`MAX_INPUT`].
    /// Empty `&` pieces are skipped. A piece without `=` has an empty
    /// value. Duplicate names retain their order. Pass query bytes without
    /// the leading `?`; [`query_of`] extracts them from a request target.
    /// Use [`Fields`] to accept expanding input within its input cap.
    fn parse(input: &[u8]) -> Result<Self, FormError> {
        let pairs = parse(input)?;
        canonical_len(&pairs)?;
        Ok(Self { pairs })
    }

    /// Appends canonical form bytes with `=` for every pair and `&` between
    /// pairs. Uses [`EncodeSet::Form`], uppercase hex escapes, and `+` for
    /// spaces. Refuses excessive size or pair count before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FormError> {
        out.extend_from_slice(serialize(&self.pairs)?.as_bytes());
        Ok(())
    }
}

/// One percent-encoded URL component in its encoded form.
/// The chosen encode set is applied during construction. Parsing preserves
/// the encoded text, including literal percent signs and plus signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PercentEncoded {
    /// Encoded ASCII text, bounded by [`MAX_INPUT`] on read and write.
    pub text: String,
}

impl PercentEncoded {
    /// Builds a component with each byte in `set` encoded as `%` and two
    /// uppercase hex digits. A space becomes `+` when `space_as_plus` is
    /// set. Pass text as UTF-8 bytes. The result is ASCII. Refuses input or
    /// encoded output beyond [`MAX_INPUT`].
    pub fn new(bytes: &[u8], set: EncodeSet, space_as_plus: bool) -> Result<Self, FormError> {
        Ok(Self { text: percent_encode(bytes, set, space_as_plus)? })
    }
}

impl Wire for PercentEncoded {
    type ParseError = FormError;
    type WriteError = FormError;

    /// Keeps one encoded component. Refuses non-ASCII bytes and input over
    /// [`MAX_INPUT`]. Percent sequences are not decoded or normalized.
    fn parse(input: &[u8]) -> Result<Self, FormError> {
        if input.len() > MAX_INPUT {
            return Err(FormError::TooLong);
        }
        if !input.is_ascii() {
            return Err(FormError::NonAscii);
        }
        Ok(Self {
            text: input.iter().copied().map(char::from).collect(),
        })
    }

    /// Appends encoded text unchanged. Refuses non-ASCII text and values
    /// beyond [`MAX_INPUT`] before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FormError> {
        if self.text.len() > MAX_INPUT {
            return Err(FormError::TooLong);
        }
        if !self.text.is_ascii() {
            return Err(FormError::Unwritable);
        }
        out.extend_from_slice(self.text.as_bytes());
        Ok(())
    }
}

/// The value of the first pair named `name`, if there is one.
pub fn first<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The values of every pair named `name`, in order. Forms repeat a name
/// for checkboxes and multiple selects.
pub fn values<'a>(pairs: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
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
/// [`Fields`] accepts fields whose canonical encoding is larger.
/// [`Form::parse`] refuses them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field(
    /// The decoded name and value.
    pub (String, String),
);

/// Why one exact field or a stream of fields could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    /// A form size or pair count limit was exceeded.
    Form(FormError),
    /// No field was present.
    Empty,
    /// An exact field parse contained a separator.
    Trailing,
}

impl core::fmt::Display for FieldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Form(e) => e.fmt(f),
            Self::Empty => f.write_str("no form field"),
            Self::Trailing => f.write_str("separator in an exact form field"),
        }
    }
}

impl core::error::Error for FieldError {}

impl Wire for Field {
    type ParseError = FieldError;
    type WriteError = FormError;

    /// Reads exactly one nonempty field. Refuses `&`, empty input, or
    /// input whose raw or canonical size exceeds [`MAX_INPUT`].
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
        canonical_len(core::slice::from_ref(&pair)).map_err(FieldError::Form)?;
        Ok(Self(pair))
    }

    /// Appends one canonical field. Refuses encoded output beyond
    /// [`MAX_INPUT`] and leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FormError> {
        out.extend_from_slice(serialize(core::slice::from_ref(&self.0))?.as_bytes());
        Ok(())
    }
}

/// Reads fields separated by `&` without holding input bytes.
///
/// Empty pieces are skipped. EOF completes the last nonempty field.
/// Stray percent signs stay literal. Invalid UTF-8 becomes U+FFFD.
/// Limits apply to the entire input form, as in [`Form::parse`]. Writing a field
/// also checks that its canonical encoding fits [`MAX_INPUT`].
/// Capacity is [`MAX_INPUT`] plus one byte to detect overflow.
/// Only [`FieldError::Form`] occurs from the stream, and ends it.
/// Drive it with [`Stream<Fields>`](fictionet::stdlib::codec::Stream).
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream, contract, pump};
    use fictionet::stdlib::codec::{Lcg, test_support::decode_all};

    fn check(input: &[u8]) {
        contract::check_decode_with_alloc_limit(Fields::new, input, 2 * (MAX_INPUT + 1));
    }

    fn decoded(input: &[u8]) -> Result<Vec<(String, String)>, FormError> {
        let (fields, error) = decode_all(Fields::new, input);
        match error {
            None => Ok(fields.into_iter().map(|field| field.0).collect()),
            Some(Fail::Protocol(FieldError::Form(error))) => Err(error),
            Some(error) => panic!("{error:?}"),
        }
    }

    fn serialized<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> Result<String, FormError> {
        let bytes = Form::from_pairs(pairs)?.to_bytes()?;
        Ok(String::from_utf8(bytes).unwrap())
    }

    fn encoded(bytes: &[u8], set: EncodeSet, plus: bool) -> Result<String, FormError> {
        let bytes = PercentEncoded::new(bytes, set, plus)?.to_bytes()?;
        Ok(String::from_utf8(bytes).unwrap())
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn assert_pairs(input: &[u8], expected: Vec<(String, String)>) {
        assert_eq!(
            Form::parse(input).map(|form| form.pairs),
            Ok(expected.clone())
        );
        assert_eq!(decoded(input), Ok(expected));
    }

    // Examples from the WHATWG URL Standard and from what browsers do.

    #[test]
    fn parser_examples() {
        assert_pairs(b"a=b&c=d", pairs(&[("a", "b"), ("c", "d")]));
        assert_pairs(b"", pairs(&[]));
        assert_pairs(b"&&&", pairs(&[]));
        assert_pairs(b"a", pairs(&[("a", "")]));
        assert_pairs(b"=", pairs(&[("", "")]));
        assert_pairs(b"=b", pairs(&[("", "b")]));
        assert_pairs(b"a=b=c", pairs(&[("a", "b=c")]));
        assert_pairs(b"a=1&a=2", pairs(&[("a", "1"), ("a", "2")]));
        assert_pairs(b"a+b=c+d", pairs(&[("a b", "c d")]));
        // A plus written as %2B stays a plus.
        assert_pairs(b"q=1%2B1", pairs(&[("q", "1+1")]));
        // Stray percent signs stay as they are.
        assert_pairs(b"%zz=%4&x=%", pairs(&[("%zz", "%4"), ("x", "%")]));
        assert_pairs(b"%61=%41%42", pairs(&[("a", "AB")]));
        // %26 and %3D are data, not separators.
        assert_pairs(b"k%3D=v%26w", pairs(&[("k=", "v&w")]));
        // UTF-8, in either hex case.
        assert_pairs(b"x=%e2%80%bd", pairs(&[("x", "\u{203d}")]));
        // Bytes that are not UTF-8 become U+FFFD.
        assert_pairs(
            b"x=%FF&y=\xc3",
            pairs(&[("x", "\u{fffd}"), ("y", "\u{fffd}")]),
        );
        // A byte order mark is kept.
        assert_pairs(b"%EF%BB%BFa=1", pairs(&[("\u{feff}a", "1")]));
        // Raw bytes outside ASCII are read as UTF-8 too.
        assert_pairs(
            "caf\u{e9}=\u{2603}".as_bytes(),
            pairs(&[("caf\u{e9}", "\u{2603}")]),
        );
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
        assert_eq!(encoded("\u{2261}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "%E2%89%A1");
        assert_eq!(encoded("\u{203d}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "%E2%80%BD");
        assert_eq!(encoded("Say what\u{203d}".as_bytes(), EncodeSet::Userinfo, false).unwrap(), "Say%20what%E2%80%BD");
        assert_eq!(encoded("Say what\u{203d}".as_bytes(), EncodeSet::Form, true).unwrap(), "Say+what%E2%80%BD");
        // What each set leaves alone.
        let printable: Vec<u8> = (0x20..=0x7e).collect();
        let kept = |set: EncodeSet| -> String { printable.iter().filter(|&&b| !set.contains(b)).map(|&b| char::from(b)).collect() };
        assert_eq!(kept(EncodeSet::Form), "*-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz");
        assert_eq!(kept(EncodeSet::Component), "!'()*-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~");
        assert_eq!(kept(EncodeSet::C0Control).len(), printable.len());
        for b in *b" \"#<>" {
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
        assert_eq!(encoded(b" ", EncodeSet::Form, false).unwrap(), "%20");
        assert_eq!(encoded(b" ", EncodeSet::C0Control, true).unwrap(), "+");
    }

    #[test]
    fn serializer_examples() {
        let p = pairs(&[("a b", "c&d=e"), ("", ""), ("x", "1+1"), ("~", "\u{e9}*-._")]);
        let s = serialized(&p).unwrap();
        assert_eq!(s, "a+b=c%26d%3De&=&x=1%2B1&%7E=%C3%A9*-._");
        assert_eq!(decoded(s.as_bytes()).unwrap(), p);
        assert_eq!(serialized::<&str, &str>(&[]).unwrap(), "");
        assert_eq!(serialized(&[("k", "")]).unwrap(), "k=");
        assert_eq!(serialized(&[("\u{0}\n", "%")]).unwrap(), "%00%0A=%25");
    }

    #[test]
    fn helpers() {
        let p = decoded(b"a=1&b=2&a=3").unwrap();
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
        assert_eq!(decoded(&big), Err(FormError::TooLong));
        assert_eq!(
            Form::parse(&big).map(|form| form.pairs),
            Err(FormError::TooLong)
        );
        assert_eq!(percent_decode(&big), Err(FormError::TooLong));
        assert_eq!(encoded(&big, EncodeSet::Form, true), Err(FormError::TooLong));
        // The stream accepts the input limit. The whole form needs room for '='.
        assert_eq!(decoded(&big[..MAX_INPUT]).unwrap().len(), 1);
        assert_eq!(Form::parse(&big[..MAX_INPUT]), Err(FormError::TooLong));
        // The serializer refuses what the parser would refuse. Each byte
        // outside ASCII grows to 3.
        let wide = "\u{e9}".repeat(MAX_INPUT / 6 + 1);
        assert_eq!(serialized(&[("x", wide.as_str())]), Err(FormError::TooLong));
        let fits = "a".repeat(MAX_INPUT - 2);
        let s = serialized(&[("x", fits.as_str())]).unwrap();
        assert_eq!(s.len(), MAX_INPUT);
        assert_eq!(
            Form::parse(s.as_bytes()).map(|form| form.pairs),
            decoded(s.as_bytes())
        );
        assert_eq!(serialized(&[("x", "a".repeat(MAX_INPUT - 1).as_str())]), Err(FormError::TooLong));
        // Writing can grow a form. Bytes that are not UTF-8 each become
        // U+FFFD, nine bytes once encoded, so a form the parser reads may
        // be too long to write back. The writer refuses it as too long.
        let bad = vec![0xffu8; MAX_INPUT / 9 + 1];
        let read = decoded(&bad).unwrap();
        assert_eq!(read[0].0.chars().count(), bad.len());
        assert_eq!(serialized(&read), Err(FormError::TooLong));
        assert_eq!(Form::parse(&bad), Err(FormError::TooLong));
        let mut stream = Stream::new(Fields::new());
        let error = Fail::Protocol(FieldError::Form(FormError::TooLong));
        assert_eq!(pump(&mut stream, &big, |_| panic!("no field")), Err(error.clone()));
        assert_eq!(stream.push(b"a=b&"), 4);
        stream.end();
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
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
        assert_eq!(encoded(&over, EncodeSet::Component, false), Err(FormError::TooLong));
        assert_eq!(encoded(&over, EncodeSet::Form, true), Err(FormError::TooLong));
        let at = vec![b'%'; MAX_INPUT / 3];
        let s = encoded(&at, EncodeSet::Component, false).unwrap();
        assert!(s.len() <= MAX_INPUT);
        assert_eq!(percent_decode(s.as_bytes()).unwrap(), at);
        assert_eq!(decoded(encoded(&at, EncodeSet::Form, true).unwrap().as_bytes()).unwrap().len(), 1);
        // A space written as + stays one byte.
        assert_eq!(encoded(&vec![b' '; MAX_INPUT], EncodeSet::Form, true).unwrap().len(), MAX_INPUT);
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
        match serialized(&pairs) {
            Ok(s) => {
                assert!(s.len() <= MAX_INPUT);
                assert!(decoded(s.as_bytes()).is_ok());
            }
            Err(e) => assert_eq!(e, FormError::TooLong),
        }
    }

    #[test]
    fn stream_keeps_pairs_before_limit_errors() {
        let mut input = b"k=v&".to_vec();
        input.extend(std::iter::repeat_n(b'a', MAX_INPUT - 3));
        check(&input);
        assert_eq!(Form::parse(&input), Err(FormError::TooLong));
        assert_eq!(decode_all(Fields::new, &input),
            (vec![Field(("k".into(), "v".into()))], Some(Fail::Protocol(FieldError::Form(FormError::TooLong)))));
        let over = b"a&".repeat(MAX_PAIRS + 1);
        check(&over);
        let (fields, error) = decode_all(Fields::new, &over);
        assert_eq!(fields.len(), MAX_PAIRS);
        assert_eq!(error, Some(Fail::Protocol(FieldError::Form(FormError::TooManyPairs))));
    }

    #[test]
    fn too_many_pairs() {
        let at = b"a&".repeat(MAX_PAIRS);
        assert_eq!(decoded(&at).unwrap().len(), MAX_PAIRS);
        assert_eq!(Form::parse(&at).map(|form| form.pairs), decoded(&at));
        let over = b"a&".repeat(MAX_PAIRS + 1);
        assert_eq!(decoded(&over), Err(FormError::TooManyPairs));
        assert_eq!(Form::parse(&over), Err(FormError::TooManyPairs));
        // Empty pieces do not count.
        let mut sparse = b"&".repeat(MAX_PAIRS * 3);
        sparse.extend_from_slice(b"a=1");
        assert_eq!(decoded(&sparse).unwrap().len(), 1);
        assert_eq!(
            Form::parse(&sparse).map(|form| form.pairs),
            decoded(&sparse)
        );
        let many = vec![("a", "b"); MAX_PAIRS + 1];
        assert_eq!(serialized(&many), Err(FormError::TooManyPairs));
        assert!(decoded(serialized(&many[..MAX_PAIRS]).unwrap().as_bytes()).is_ok());
    }

    #[test]
    fn stream_waits_for_the_ampersand_or_eof() {
        let mut stream = Stream::new(Fields::new());
        assert_eq!(stream.push(b"a=1&b="), 6);
        assert_eq!(stream.next(), Some(Ok(Field(("a".into(), "1".into())))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.buffered(), 2);
        assert_eq!(stream.push(b"2"), 1);
        assert_eq!(stream.next(), None);
        stream.end();
        assert_eq!(stream.next(), Some(Ok(Field(("b".into(), "2".into())))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"&c=3&"), 5);
        assert_eq!(stream.next(), None);
        assert_eq!(decode_all(Fields::new, b""), (vec![], None));
    }

    #[test]
    fn every_truncated_prefix() {
        let full = b"name=J%C3%BCrgen+M%C3%BCller&&email=j%40example.com&note=%E2%80%BD&flag&=&x=%2";
        let whole = decoded(full).unwrap();
        assert_eq!(whole.len(), 6);
        for n in 0..=full.len() {
            let prefix = &full[..n];
            let got = decoded(prefix).unwrap();
            assert_eq!(Form::parse(prefix).unwrap().pairs, got, "{n} bytes");
            check(prefix);
            assert!(got.len() <= whole.len());
            assert_eq!(decoded(serialized(&got).unwrap().as_bytes()).unwrap(), got);
        }
    }

    #[test]
    fn wire_limits_and_encoded_text() {
        let mut bytes = b"a=".to_vec();
        bytes.extend_from_slice(&vec![0xff; MAX_INPUT / 8]);
        assert!(decoded(&bytes).is_ok());
        assert_eq!(Form::parse(&bytes), Err(FormError::TooLong));
        contract::check_wire::<Form>(&bytes);
        contract::check_wire_value(&PercentEncoded { text: "é".into() });
        assert_eq!(PercentEncoded { text: "é".into() }.to_bytes(), Err(FormError::Unwritable));
        for input in ["é".as_bytes(), &[0xff]] {
            assert_eq!(PercentEncoded::parse(input), Err(FormError::NonAscii));
        }
        assert_eq!(PercentEncoded::parse(b"%+%zz").unwrap().to_bytes().unwrap(), b"%+%zz");
        contract::check_wire::<PercentEncoded>(b"%+%zz");
    }

    #[test]
    fn generated_and_mutated_values() {
        const ALPHABET: &[u8] = b"%%%&&==++aA0fF9gz \x00\x7f\x80\xbf\xc3\xa9\xe2\xff#?~!'";
        let mut rng = Lcg::new(0x5eed);
        for round in 0..5000 {
            let len = rng.index(48);
            let buf: Vec<u8> = (0..len)
                .map(|_| if rng.index(4) == 0 { rng.index(256) as u8 } else { ALPHABET[rng.index(ALPHABET.len())] })
                .collect();
            let got = decoded(&buf).unwrap();
            check(&buf);
            assert_eq!(Form::parse(&buf).unwrap().pairs, got, "round {round}");
            contract::check_wire::<Form>(&buf);
            contract::check_wire::<Field>(&buf);
            // What is read can be written, and reads back the same.
            let s = serialized(&got).unwrap();
            assert_eq!(decoded(s.as_bytes()).unwrap(), got, "round {round}");
            assert_eq!(serialized(&decoded(s.as_bytes()).unwrap()).unwrap(), s);
            // Percent decoding never grows its input, and encoding with a
            // set that holds % comes back exactly.
            let raw = percent_decode(&buf).unwrap();
            assert!(raw.len() <= buf.len());
            for set in EncodeSet::ALL {
                let plain = encoded(&buf, set, false).unwrap();
                assert!(plain.is_ascii());
                let plus = encoded(&buf, set, true).unwrap();
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
