//! MIME multipart bodies: splitting them into parts and writing them, with
//! no I/O.
//!
//! A multipart body carries several parts in one message. HTML forms send
//! their fields and uploaded files this way (`multipart/form-data`), and
//! mail uses it for attachments (`multipart/mixed`). A boundary string,
//! named in the `Content-Type` header, separates the parts. Each part has
//! its own headers and body. Text before the first boundary line is the
//! preamble, and text after the closing one is the epilogue. This module
//! follows RFC 2046, section 5.1, and RFC 7578.
//!
//! Nothing here reads a socket. A world that plays a web server takes a
//! request body from its HTTP code, finds the boundary with [`boundary`],
//! and reads the parts with [`Multipart::parse`]. A body that comes in
//! pieces goes to a [`Parser`] instead, which hands back [`Event`]s and
//! holds only a few bytes of a part's body at a time. What the fields mean,
//! and where uploaded files go, is up to world code.
//!
//! Every reader checks lengths and counts, because the agent can send any
//! bytes it likes. The limits are the `MAX_` constants below. A writer
//! picks a boundary that appears nowhere in the parts, so what it writes
//! always reads back the same.
//!
//! Use [`Frames`] with [`super::codec::Stream`] for bounded complete parts.
//! [`Part`] implements [`Wire`] for a header block and its body. Boundaries
//! remain explicit configuration. The deprecated [`Parser`] keeps its
//! original buffering and event behavior.
//!
//! ```
//! use fictionet::stdlib::mime_multipart::{boundary, Multipart, Part};
//!
//! let content_type = "multipart/form-data; boundary=XyZ";
//! let body = b"--XyZ\r\n\
//!     Content-Disposition: form-data; name=\"user\"\r\n\
//!     \r\n\
//!     alice\r\n\
//!     --XyZ\r\n\
//!     Content-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n\
//!     Content-Type: text/plain\r\n\
//!     \r\n\
//!     hello\r\n\
//!     --XyZ--\r\n";
//! let form = Multipart::parse(body, &boundary(content_type).unwrap()).unwrap();
//! assert_eq!(form.parts.len(), 2);
//! assert_eq!(form.parts[0].name().as_deref(), Some("user"));
//! assert_eq!(form.parts[0].body, b"alice");
//! assert_eq!(form.parts[1].filename().as_deref(), Some("a.txt"));
//! assert_eq!(form.parts[1].headers.get("content-type"), Some("text/plain"));
//! assert_eq!(form.parts[1].body, b"hello");
//!
//! // A reply whose body holds "--XyZ", so the writer picks another boundary.
//! let reply = Multipart {
//!     parts: vec![Part::field("note", "--XyZ is taken").unwrap()],
//!     ..Multipart::default()
//! };
//! let (chosen, bytes) = reply.write("XyZ").unwrap();
//! assert_ne!(chosen, "XyZ");
//! assert_eq!(Multipart::parse(&bytes, &chosen).unwrap(), reply);
//! ```

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use super::codec::{Decode, Step, Wire};

/// The longest boundary RFC 2046 allows.
pub const MAX_BOUNDARY: usize = 70;
/// The most parts one body may hold.
pub const MAX_PARTS: usize = 256;
/// The most bytes a part's header block may take, counting the empty line
/// that ends it.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// The most header fields one part may have.
pub const MAX_HEADERS: usize = 32;
/// The most parameters one header value may have, such as `name` and
/// `filename` in `Content-Disposition`.
pub const MAX_PARAMETERS: usize = 16;
/// The most spaces and tabs read after a boundary, before the line ends.
/// A boundary followed by more is [`Error::Padding`].
pub const MAX_PADDING: usize = 64;
/// The codec API's cap on one part, including headers, or on the preamble.
/// MIME has no part size maximum. This module caps new codec callers at
/// 4 MiB. The compatibility [`Parser`] and [`Multipart`] keep their limits.
pub const MAX_PART: usize = 4 * 1024 * 1024;
/// The longest boundary line, including CR LF, dashes, padding, and CR LF.
/// Derived from RFC 2046's [`MAX_BOUNDARY`] and this module's [`MAX_PADDING`].
pub const MAX_BOUNDARY_LINE: usize = MAX_BOUNDARY + MAX_PADDING + 8;
/// How many bytes [`Multipart::parse`] hands its [`Parser`] at a time.
const PARSE_CHUNK: usize = 64 * 1024;
/// The buffer capacity a [`Parser`] keeps when it holds few bytes. A
/// larger buffer, left over from one big `feed`, is given back.
const KEEP_CAPACITY: usize = 16 * 1024;

/// Why bytes are not a multipart body. Once a [`Parser`] meets one, it
/// reads no further.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The boundary is empty, longer than [`MAX_BOUNDARY`], ends with a
    /// space, or holds a character RFC 2046 does not allow.
    Boundary,
    /// The body ended before the closing boundary line.
    Truncated,
    /// The body holds more than [`MAX_PARTS`] parts.
    TooManyParts,
    /// A part's header block is longer than [`MAX_HEADER_BYTES`].
    HeaderTooLong,
    /// A part has more than [`MAX_HEADERS`] header fields.
    TooManyHeaders,
    /// A header line has no colon, a bad name, a stray CR or LF, or a value
    /// that is not UTF-8.
    Header,
    /// A boundary at the start of a line is followed by more than
    /// [`MAX_PADDING`] spaces or tabs. RFC 2046 lets a boundary line carry
    /// any amount of padding, but a body part may not hold the boundary at
    /// all, so the parser refuses the body rather than guess.
    Padding,
    /// A codec part or preamble is longer than [`MAX_PART`].
    TooLong,
    /// EOF arrived before a multipart body was closed in [`Frames`].
    Incomplete,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Boundary => "not a valid multipart boundary",
            Error::Truncated => "multipart body ended before its closing boundary",
            Error::TooManyParts => "multipart body has too many parts",
            Error::HeaderTooLong => "multipart part header block is too long",
            Error::TooManyHeaders => "multipart part has too many header fields",
            Error::Header => "malformed multipart part header",
            Error::Padding => "multipart boundary line has too much padding",
            Error::TooLong => "multipart part or preamble is over the codec size limit",
            Error::Incomplete => "multipart body is not closed",
        })
    }
}

impl core::error::Error for Error {}

/// Why a [`Multipart`] cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteError {
    /// The boundary is not one RFC 2046 allows.
    Boundary,
    /// The boundary, after `--`, appears in the preamble or in a part.
    BoundaryInData,
    /// There are more than [`MAX_PARTS`] parts.
    TooManyParts,
    /// A part has more than [`MAX_HEADERS`] header fields.
    TooManyHeaders,
    /// A part's header block would be longer than [`MAX_HEADER_BYTES`].
    HeaderTooLong,
    /// A header name is empty or holds a character other than visible
    /// ASCII, or a colon.
    HeaderName,
    /// A header value holds CR or LF, or starts or ends with a space or tab.
    HeaderValue,
    /// A codec part is longer than [`MAX_PART`], including its headers.
    TooLong,
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            WriteError::Boundary => "not a valid multipart boundary",
            WriteError::BoundaryInData => "the boundary appears in the data",
            WriteError::TooManyParts => "too many parts",
            WriteError::TooManyHeaders => "too many header fields in a part",
            WriteError::HeaderTooLong => "a part's header block is too long",
            WriteError::HeaderName => "a header name is not valid",
            WriteError::HeaderValue => "a header value is not valid",
            WriteError::TooLong => "multipart part is over the codec size limit",
        })
    }
}

impl core::error::Error for WriteError {}

/// Whether `b` is a boundary RFC 2046 allows: 1 to 70 characters from its
/// set (letters, digits, space and `'()+_,-./:=?`), not ending in a space.
pub fn valid_boundary(b: &str) -> bool {
    let x = b.as_bytes();
    !x.is_empty() && x.len() <= MAX_BOUNDARY && x.iter().all(|&c| is_bchar(c)) && x[x.len() - 1] != b' '
}

/// The boundary named in a `Content-Type` value such as
/// `multipart/form-data; boundary=XyZ`. It returns `None` if the type is
/// not `multipart/` and a subtype token, or the boundary is missing or
/// not valid.
///
/// As RFC 2045 allows, comments in parentheses and spaces around the `/`
/// are skipped: `multipart / mixed; boundary=b (note)` names `b`. A
/// boundary split into RFC 2231 continuations (`boundary*0="ab";
/// boundary*1="cd"`) is joined. The value is `None` if the pieces skip a
/// number, use the encoded form (`boundary*0*`), or come with a plain
/// `boundary` as well.
pub fn boundary(content_type: &str) -> Option<String> {
    let cleaned = strip_comments(content_type)?;
    let v = ParamValue::parse(&cleaned)?;
    let (top, sub) = v.value.split_once('/')?;
    let (top, sub) = (top.trim_end_matches(is_wsp_char), sub.trim_start_matches(is_wsp_char));
    if !top.eq_ignore_ascii_case("multipart") || sub.is_empty() || !sub.bytes().all(is_token) {
        return None;
    }
    // RFC 2231 continuations: boundary*0, boundary*1, ... in any order.
    let mut pieces: Vec<(usize, &str)> = Vec::new();
    for (name, value) in &v.params {
        let Some(head) = name.get(..9) else { continue };
        if !head.eq_ignore_ascii_case("boundary*") {
            continue;
        }
        let digits = &name[9..];
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return None;
        }
        pieces.push((digits.parse().ok()?, value));
    }
    let b = match v.get("boundary") {
        Some(b) if pieces.is_empty() => b.to_string(),
        Some(_) => return None,
        None => {
            if pieces.is_empty() {
                return None;
            }
            pieces.sort_unstable();
            if pieces.iter().enumerate().any(|(i, (n, _))| *n != i) {
                return None;
            }
            pieces.iter().map(|(_, v)| *v).collect()
        }
    };
    valid_boundary(&b).then_some(b)
}

/// `s` with each comment, text in balanced parentheses outside a quoted
/// string, turned into one space, as RFC 822 reads structured headers.
/// It returns `None` if a comment is not closed.
fn strip_comments(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            if depth == 0 {
                out.push(c);
            }
            escaped = false;
        } else if depth > 0 {
            match c {
                '\\' => escaped = true,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(' ');
                    }
                }
                _ => {}
            }
        } else if quoted {
            out.push(c);
            match c {
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
        } else {
            match c {
                '(' => depth = 1,
                '"' => {
                    quoted = true;
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
    }
    (depth == 0).then_some(out)
}

/// The `Content-Type` value for a multipart body: `multipart/` and
/// `subtype`, with the boundary as a parameter. It returns `None` if the
/// subtype is empty or not a token, or the boundary is not valid.
pub fn content_type(subtype: &str, boundary: &str) -> Option<String> {
    if subtype.is_empty() || !subtype.bytes().all(is_token) || !valid_boundary(boundary) {
        return None;
    }
    ParamValue { value: format!("multipart/{subtype}"), params: vec![("boundary".into(), boundary.into())] }.to_header()
}

/// A header value with parameters, as in `Content-Type` and
/// `Content-Disposition`: `form-data; name="field"; filename="a.txt"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamValue {
    /// The text before the first semicolon, without surrounding spaces,
    /// such as `form-data` or `text/plain`.
    pub value: String,
    /// The parameters in order, as name and value. Quoted values are
    /// unquoted. Names keep their case.
    pub params: Vec<(String, String)>,
}

impl ParamValue {
    /// Reads a header value with parameters. It returns `None` if the
    /// value before the parameters is empty, a parameter is malformed, a
    /// parameter name appears twice (in any case), or there are more than
    /// [`MAX_PARAMETERS`].
    pub fn parse(s: &str) -> Option<ParamValue> {
        let (main, mut rest) = match s.find(';') {
            Some(i) => (&s[..i], &s[i..]),
            None => (s, ""),
        };
        let main = main.trim_matches(is_wsp_char);
        if main.is_empty() {
            return None;
        }
        let mut params: Vec<(String, String)> = Vec::new();
        loop {
            rest = rest.trim_start_matches(is_wsp_char);
            if rest.is_empty() {
                break;
            }
            rest = rest.strip_prefix(';')?.trim_start_matches(is_wsp_char);
            if rest.is_empty() || rest.starts_with(';') {
                // An empty parameter, which some senders write.
                continue;
            }
            let n = rest.bytes().take_while(|&b| is_token(b)).count();
            if n == 0 {
                return None;
            }
            let name = &rest[..n];
            rest = rest[n..].trim_start_matches(is_wsp_char).strip_prefix('=')?.trim_start_matches(is_wsp_char);
            let value;
            if let Some(q) = rest.strip_prefix('"') {
                let mut out = String::new();
                let mut escaped = false;
                let mut end = None;
                for (i, c) in q.char_indices() {
                    if escaped {
                        out.push(c);
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        end = Some(i + 1);
                        break;
                    } else {
                        out.push(c);
                    }
                }
                rest = &q[end?..];
                value = out;
            } else {
                let n = rest.bytes().take_while(|&b| is_token(b)).count();
                if n == 0 {
                    return None;
                }
                value = rest[..n].to_string();
                rest = &rest[n..];
            }
            if params.len() == MAX_PARAMETERS || params.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                return None;
            }
            params.push((name.to_string(), value));
        }
        Some(ParamValue { value: main.to_string(), params })
    }

    /// The value of the parameter called `name`, in any case. If a value
    /// built by hand has it twice, this is the first.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The header value, with each parameter as a token or a quoted
    /// string. It returns `None` if it could not read back the same: the
    /// value is empty, holds a semicolon, CR or LF, or starts or ends with
    /// a space or tab; a name is not a token or appears twice; a parameter
    /// value holds CR or LF; or there are more than [`MAX_PARAMETERS`]
    /// parameters.
    pub fn to_header(&self) -> Option<String> {
        let v = &self.value;
        if v.is_empty() || v.contains([';', '\r', '\n']) || v.trim_matches(is_wsp_char).len() != v.len() {
            return None;
        }
        if self.params.len() > MAX_PARAMETERS {
            return None;
        }
        let mut out = v.clone();
        for (i, (name, value)) in self.params.iter().enumerate() {
            if name.is_empty() || !name.bytes().all(is_token) || value.contains(['\r', '\n']) {
                return None;
            }
            if self.params[..i].iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                return None;
            }
            out.push_str("; ");
            out.push_str(name);
            out.push('=');
            if !value.is_empty() && value.bytes().all(is_token) {
                out.push_str(value);
            } else {
                out.push('"');
                for c in value.chars() {
                    if c == '"' || c == '\\' {
                        out.push('\\');
                    }
                    out.push(c);
                }
                out.push('"');
            }
        }
        Some(out)
    }
}

/// A part's header fields, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    /// Each field's name and value. Values have folded lines joined and
    /// surrounding spaces and tabs removed.
    pub fields: Vec<(String, String)>,
}

impl Headers {
    /// The value of the first field called `name`, in any case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The values of every field called `name`, in any case, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The value of the field called `name`, in any case, if there is
    /// exactly one.
    pub fn get_one(&self, name: &str) -> Option<&str> {
        let mut all = self.fields.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
        let (_, v) = all.next()?;
        all.next().is_none().then_some(v.as_str())
    }

    /// The `Content-Type` field, read with its parameters. It is `None` if
    /// the part has no such field or has it twice, since readers that take
    /// the first and readers that take the last would disagree.
    pub fn content_type(&self) -> Option<ParamValue> {
        ParamValue::parse(self.get_one("content-type")?)
    }

    /// The `Content-Disposition` field, read with its parameters. It is
    /// `None` if the part has no such field or has it twice.
    pub fn content_disposition(&self) -> Option<ParamValue> {
        ParamValue::parse(self.get_one("content-disposition")?)
    }
}

/// One part of a multipart body: its headers and its body bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Part {
    /// The part's header fields.
    pub headers: Headers,
    /// The part's body, as sent. A `Content-Transfer-Encoding` is not
    /// undone.
    pub body: Vec<u8>,
}

impl Part {
    /// A form field: `Content-Disposition: form-data; name="…"` and the
    /// value as the body. It returns `None` if `name` holds CR or LF.
    pub fn field(name: &str, value: impl Into<Vec<u8>>) -> Option<Part> {
        let d = ParamValue { value: "form-data".into(), params: vec![("name".into(), name.into())] };
        Some(Part {
            headers: Headers { fields: vec![("Content-Disposition".into(), d.to_header()?)] },
            body: value.into(),
        })
    }

    /// An uploaded file: a form-data part with a `filename` parameter and
    /// a `Content-Type` field. It returns `None` if a name holds CR or LF,
    /// or the content type is not a valid header value.
    pub fn file(name: &str, filename: &str, content_type: &str, body: impl Into<Vec<u8>>) -> Option<Part> {
        if !valid_value(content_type) {
            return None;
        }
        let d = ParamValue {
            value: "form-data".into(),
            params: vec![("name".into(), name.into()), ("filename".into(), filename.into())],
        };
        Some(Part {
            headers: Headers {
                fields: vec![
                    ("Content-Disposition".into(), d.to_header()?),
                    ("Content-Type".into(), content_type.into()),
                ],
            },
            body: body.into(),
        })
    }

    /// The form field's name: the `name` parameter of
    /// `Content-Disposition`.
    pub fn name(&self) -> Option<String> {
        Some(self.headers.content_disposition()?.get("name")?.to_string())
    }

    /// The uploaded file's name: the `filename` parameter of
    /// `Content-Disposition`, as sent. It may hold a path.
    pub fn filename(&self) -> Option<String> {
        Some(self.headers.content_disposition()?.get("filename")?.to_string())
    }
}

impl Wire for Part {
    type ParseError = Error;
    type WriteError = WriteError;

    /// Reads one header block and its complete body, without boundary lines.
    /// Every byte after the empty header line belongs to the body.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_PART {
            return Err(Error::TooLong);
        }
        let end = part_header_end(input, 0)?.ok_or(Error::Truncated)?;
        let headers = parse_headers(input.get(..end.saturating_sub(2)).unwrap_or_default())?;
        Ok(Self {
            headers,
            body: input.get(end..).unwrap_or_default().to_vec(),
        })
    }

    /// Appends one part without boundary lines. Header names, values, counts,
    /// and lengths are checked before any bytes are appended.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.headers.fields.len() > MAX_HEADERS {
            return Err(WriteError::TooManyHeaders);
        }
        for (name, value) in &self.headers.fields {
            if name.is_empty() || !name.bytes().all(is_ftext) {
                return Err(WriteError::HeaderName);
            }
            if !valid_value(value) {
                return Err(WriteError::HeaderValue);
            }
        }
        // Compact separators ensure a parsed header block can be written
        // within the same size limit, including folded input headers.
        let header = header_block_size(self, 1);
        if header > MAX_HEADER_BYTES {
            return Err(WriteError::HeaderTooLong);
        }
        if header.saturating_add(self.body.len()) > MAX_PART {
            return Err(WriteError::TooLong);
        }
        for (name, value) in &self.headers.fields {
            out.extend_from_slice(name.as_bytes());
            out.push(b':');
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

fn part_header_end(input: &[u8], scanned: usize) -> Result<Option<usize>, Error> {
    let limit = input.len().min(MAX_HEADER_BYTES);
    let from = scanned.saturating_sub(3).min(limit);
    let end = if input.starts_with(b"\r\n") {
        Some(2)
    } else {
        input
            .get(from..limit)
            .and_then(|r| find(r, b"\r\n\r\n"))
            .map(|i| from + i + 4)
    };
    if end.is_none() && input.len() >= MAX_HEADER_BYTES {
        return Err(Error::HeaderTooLong);
    }
    Ok(end)
}

/// Reads complete multipart parts without retaining input bytes.
///
/// The preamble and epilogue are skipped. Parts include their headers and
/// body, so chunking does not change items. Each part and the preamble are
/// bounded by [`MAX_PART`]. EOF may finish a closing boundary without CR LF.
/// A partial header returns [`Step::Need`]. An unclosed body returns
/// [`Error::Incomplete`]. Other syntax and limit errors also end the stream.
/// Capacity is [`MAX_PART`] plus [`MAX_BOUNDARY_LINE`] plus one overflow byte.
/// Use [`codec::Stream`](super::codec::Stream) to hold the bounded input.
#[derive(Clone, Debug)]
pub struct Frames {
    delim: Vec<u8>,
    state: State,
    scanned: usize,
    header_end: Option<usize>,
    parts: usize,
}

impl Frames {
    /// Starts a body with the supplied RFC 2046 boundary, without `--`.
    pub fn new(boundary: &str) -> Result<Self, Error> {
        if !valid_boundary(boundary) {
            return Err(Error::Boundary);
        }
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        Ok(Self {
            delim,
            state: State::Preamble,
            scanned: 0,
            header_end: None,
            parts: 0,
        })
    }

    fn boundary(&mut self, input: &[u8], eof: bool, first: bool) -> (usize, Found) {
        // The first line has an implicit preceding CR LF. The temporary
        // prefix is bounded by the maximum boundary line, never the body.
        if first && self.scanned == 0 {
            let head = input
                .get(..input.len().min(MAX_BOUNDARY_LINE))
                .unwrap_or_default();
            let mut initial = b"\r\n".to_vec();
            initial.extend_from_slice(head);
            let (at, found) = scan(&initial, &self.delim, eof && head.len() == input.len());
            if at == 0 {
                return (
                    0,
                    match found {
                        Found::Delim(n) => Found::Delim(n.saturating_sub(2)),
                        Found::Close(n) => Found::Close(n.saturating_sub(2)),
                        other => other,
                    },
                );
            }
        }
        let from = self.scanned;
        let (at, found) = scan(input.get(from..).unwrap_or_default(), &self.delim, eof);
        let at = from.saturating_add(at);
        self.scanned = at;
        (
            at,
            match found {
                Found::Delim(n) => Found::Delim(from.saturating_add(n)),
                Found::Close(n) => Found::Close(from.saturating_add(n)),
                other => other,
            },
        )
    }
}

impl Decode for Frames {
    type Item = Part;
    type Error = Error;
    const NAME: &'static str = "MIME multipart";

    fn capacity(&self) -> usize {
        MAX_PART + MAX_BOUNDARY_LINE + 1
    }

    fn held(&self) -> usize {
        self.delim.len()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Part>, Error> {
        if self.state == State::Epilogue {
            return Ok(if input.is_empty() {
                Step::Need
            } else {
                Step::Skip(input.len())
            });
        }
        let preamble = self.state == State::Preamble;
        if !preamble && self.header_end.is_none() {
            if self.parts >= MAX_PARTS {
                return Err(Error::TooManyParts);
            }
            let Some(end) = part_header_end(input, self.scanned)? else {
                self.scanned = input.len();
                if eof && input.is_empty() {
                    return Err(Error::Incomplete);
                }
                return Ok(Step::Need);
            };
            self.header_end = Some(end);
            self.scanned = end.saturating_sub(2);
        }
        let (at, found) = self.boundary(input, eof, preamble);
        let part_end = at.max(self.header_end.unwrap_or(0));
        if part_end > MAX_PART {
            return Err(Error::TooLong);
        }
        let (used, closed) = match found {
            Found::Delim(n) => (n, false),
            Found::Close(n) => (n, true),
            Found::Padding => return Err(Error::Padding),
            Found::Wait => {
                if input.len() >= self.capacity() {
                    return Err(Error::TooLong);
                }
                if eof && (!preamble || (!input.is_empty() && at == input.len())) {
                    return Err(Error::Incomplete);
                }
                return Ok(Step::Need);
            }
        };
        let item = if preamble {
            None
        } else {
            Some(<Part as Wire>::parse(
                input.get(..part_end).unwrap_or_default(),
            )?)
        };
        self.state = if closed {
            State::Epilogue
        } else {
            State::Headers
        };
        self.scanned = 0;
        self.header_end = None;
        Ok(match item {
            Some(part) => {
                self.parts += 1;
                Step::Item(part, used)
            }
            None => Step::Skip(used),
        })
    }
}

/// A whole multipart body: the preamble, the parts and the epilogue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Multipart {
    /// The bytes before the first boundary line, without the line break
    /// that ends them. Readers ignore it.
    pub preamble: Vec<u8>,
    /// The parts, in order.
    pub parts: Vec<Part>,
    /// The bytes after the closing boundary line. Readers ignore it.
    pub epilogue: Vec<u8>,
}

impl Multipart {
    /// Reads a whole multipart body whose parts are separated by
    /// `boundary` (without the leading `--`).
    #[allow(deprecated)] // Preserve the one-shot parser behavior.
    pub fn parse(body: &[u8], boundary: &str) -> Result<Multipart, Error> {
        let mut p = Parser::new(boundary)?;
        let mut m = Multipart::default();
        // In pieces, so the parser never holds a copy of the whole body.
        for chunk in body.chunks(PARSE_CHUNK) {
            p.feed(chunk);
            while let Some(event) = p.next_event() {
                m.push_event(event?);
            }
        }
        p.finish();
        while let Some(event) = p.next_event() {
            m.push_event(event?);
        }
        Ok(m)
    }

    /// Adds what an [`Event`] says to this body: a new part, more body
    /// bytes for the last part, or more preamble or epilogue.
    pub fn push_event(&mut self, event: Event) {
        match event {
            Event::Preamble(d) => self.preamble.extend_from_slice(&d),
            Event::Part(headers) => self.parts.push(Part { headers, body: Vec::new() }),
            Event::Body(d) => {
                if let Some(p) = self.parts.last_mut() {
                    p.body.extend_from_slice(&d);
                }
            }
            Event::PartEnd | Event::Close => {}
            Event::Epilogue(d) => self.epilogue.extend_from_slice(&d),
        }
    }

    /// The body's bytes, with `boundary` between the parts. It fails if
    /// the boundary is not valid or appears in the preamble or a part
    /// (header lines are checked as written, `name: value`), or if a part
    /// breaks a limit the parser holds to.
    ///
    /// A header line is written `name: value`, or `name:value` for every
    /// line of a part whose block would otherwise pass
    /// [`MAX_HEADER_BYTES`]. So any part the parser reads can be written
    /// again.
    pub fn to_bytes(&self, boundary: &str) -> Result<Vec<u8>, WriteError> {
        if !valid_boundary(boundary) {
            return Err(WriteError::Boundary);
        }
        if self.parts.len() > MAX_PARTS {
            return Err(WriteError::TooManyParts);
        }
        for part in &self.parts {
            if part.headers.fields.len() > MAX_HEADERS {
                return Err(WriteError::TooManyHeaders);
            }
            for (name, value) in &part.headers.fields {
                if name.is_empty() || !name.bytes().all(is_ftext) {
                    return Err(WriteError::HeaderName);
                }
                if !valid_value(value) {
                    return Err(WriteError::HeaderValue);
                }
            }
            if header_block_size(part, 1) > MAX_HEADER_BYTES {
                return Err(WriteError::HeaderTooLong);
            }
        }
        let mut dash = b"--".to_vec();
        dash.extend_from_slice(boundary.as_bytes());
        if self.slices().iter().any(|s| find(s, &dash).is_some()) {
            return Err(WriteError::BoundaryInData);
        }
        let mut out = Vec::new();
        if !self.preamble.is_empty() {
            out.extend_from_slice(&self.preamble);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(&dash);
        for part in &self.parts {
            out.extend_from_slice(b"\r\n");
            let sep = header_separator(part);
            for (name, value) in &part.headers.fields {
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(sep);
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&part.body);
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&dash);
        }
        out.extend_from_slice(b"--\r\n");
        out.extend_from_slice(&self.epilogue);
        Ok(out)
    }

    /// A boundary that appears nowhere in the preamble or the parts. It is
    /// `base` if that is free. Otherwise it is `base` (cut to 61
    /// characters), a hyphen and the lowest 8-digit hex number that makes
    /// it free. It fails only if `base` is not a valid boundary.
    pub fn pick_boundary(&self, base: &str) -> Result<String, WriteError> {
        if !valid_boundary(base) {
            return Err(WriteError::Boundary);
        }
        let mut dash = b"--".to_vec();
        dash.extend_from_slice(base.as_bytes());
        let slices = self.slices();
        if !slices.iter().any(|s| find(s, &dash).is_some()) {
            return Ok(base.to_string());
        }
        // A candidate appears only where `--prefix` is followed by its
        // hex digits, so collect every number found that way.
        let prefix = format!("{}-", &base[..base.len().min(MAX_BOUNDARY - 9)]);
        let mut needle = b"--".to_vec();
        needle.extend_from_slice(prefix.as_bytes());
        let mut used = Vec::new();
        for s in &slices {
            let mut at = 0;
            while let Some(i) = s.get(at..).and_then(|r| find(r, &needle)) {
                let start = at + i + needle.len();
                if let Some(hex) = s.get(start..start + 8)
                    && hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                        let text = core::str::from_utf8(hex).unwrap_or("");
                        if let Ok(n) = u32::from_str_radix(text, 16) {
                            used.push(n);
                        }
                    }
                at = at + i + 1;
            }
        }
        used.sort_unstable();
        used.dedup();
        let mut n: u32 = 0;
        while used.binary_search(&n).is_ok() {
            n = n.checked_add(1).ok_or(WriteError::BoundaryInData)?;
        }
        Ok(format!("{prefix}{n:08x}"))
    }

    /// Picks a boundary with [`Multipart::pick_boundary`] and writes the
    /// body with it. It returns the boundary, for the `Content-Type`
    /// header, and the bytes.
    pub fn write(&self, base: &str) -> Result<(String, Vec<u8>), WriteError> {
        let b = self.pick_boundary(base)?;
        let bytes = self.to_bytes(&b)?;
        Ok((b, bytes))
    }

    /// Every byte string a boundary must not appear in: the preamble,
    /// each header line as [`Multipart::to_bytes`] writes it, and each
    /// body. A boundary line can only start after a line break, and none
    /// of these hold one that the writer adds, so a boundary that is in
    /// none of them is nowhere in the output before the closing line.
    fn slices(&self) -> Vec<alloc::borrow::Cow<'_, [u8]>> {
        use alloc::borrow::Cow;
        let mut out = vec![Cow::Borrowed(self.preamble.as_slice())];
        for p in &self.parts {
            let sep = header_separator(p);
            for (n, v) in &p.headers.fields {
                let mut line = Vec::with_capacity(n.len() + sep.len() + v.len());
                line.extend_from_slice(n.as_bytes());
                line.extend_from_slice(sep);
                line.extend_from_slice(v.as_bytes());
                out.push(Cow::Owned(line));
            }
            out.push(Cow::Borrowed(p.body.as_slice()));
        }
        out
    }
}

/// How many bytes a part's header block takes, with each line's name and
/// value joined by `sep_len` bytes plus CR LF, and the empty line at the end.
fn header_block_size(part: &Part, sep_len: usize) -> usize {
    part.headers.fields.iter().fold(2usize, |size, (name, value)| {
        size.saturating_add(name.len()).saturating_add(value.len()).saturating_add(sep_len + 2)
    })
}

/// What goes between a header's name and value: `": "`, or `":"` if the
/// part's block would pass [`MAX_HEADER_BYTES`] with the spaces.
fn header_separator(part: &Part) -> &'static [u8] {
    if header_block_size(part, 2) <= MAX_HEADER_BYTES { b": " } else { b":" }
}

/// What a [`Parser`] found next in the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Bytes of the preamble. It may come in several pieces.
    Preamble(Vec<u8>),
    /// A new part begins, with these headers.
    Part(Headers),
    /// Bytes of the current part's body. It may come in several pieces,
    /// and they depend on how the bytes were fed.
    Body(Vec<u8>),
    /// The current part's body is complete.
    PartEnd,
    /// The closing boundary line. No more parts follow.
    Close,
    /// Bytes of the epilogue. It may come in several pieces.
    Epilogue(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Preamble,
    Headers,
    Body,
    Epilogue,
    Done,
    Failed(Error),
}

/// Reads a multipart body as it arrives. Feed it bytes in order, take
/// events out until it has none, and call [`Parser::finish`] when the body
/// is complete. It holds a part's headers until the block is complete, at
/// most [`MAX_HEADER_BYTES`], and of a body only the few bytes that might
/// start a boundary line.
///
/// A boundary line is `--` and the boundary at the start of a line, then
/// at most [`MAX_PADDING`] spaces or tabs, then CR LF. The closing line has
/// `--` right after the boundary, and then the same padding and CR LF, or
/// padding and the end of the body. More padding than that is
/// [`Error::Padding`]. A line that starts with `--` and the boundary but
/// goes on in any other way is body data, as in RFC 2046's grammar.
#[derive(Clone, Debug)]
#[deprecated(note = "use codec::Stream with mime_multipart::Frames")]
pub struct Parser {
    /// CR LF, `--` and the boundary.
    delim: Vec<u8>,
    buf: Vec<u8>,
    /// How many bytes at the start of `buf` have been read. They are
    /// dropped on the next `feed`, so reading a part costs no copy of
    /// the bytes after it.
    start: usize,
    /// How many bytes after `start` are a CR LF that is not data: the one
    /// the parser adds before the body, or the end of a header block. A
    /// boundary line right after them matches like any other.
    virt: usize,
    state: State,
    queued: Option<Event>,
    /// How many bytes of a header block have been searched for its end.
    searched: usize,
    parts: usize,
    finished: bool,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Parser {
    /// A parser for a body whose parts are separated by `boundary`
    /// (without the leading `--`). It fails if the boundary is not valid.
    pub fn new(boundary: &str) -> Result<Parser, Error> {
        if !valid_boundary(boundary) {
            return Err(Error::Boundary);
        }
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        Ok(Parser {
            delim,
            buf: b"\r\n".to_vec(),
            start: 0,
            virt: 2,
            state: State::Preamble,
            queued: None,
            searched: 0,
            parts: 0,
            finished: false,
        })
    }

    /// Adds bytes of the body. Bytes after [`Parser::finish`], or after an
    /// error, are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if !self.finished && !matches!(self.state, State::Failed(_) | State::Done) {
            self.compact();
            self.buf.extend_from_slice(bytes);
        }
    }

    /// Drops the bytes already read, and gives back a buffer much larger
    /// than what is left, so one large `feed` is not held on to.
    fn compact(&mut self) {
        self.buf.drain(..self.start);
        self.start = 0;
        let keep = self.buf.len().max(KEEP_CAPACITY);
        if self.buf.capacity() > keep.saturating_mul(2) {
            self.buf.shrink_to(keep);
        }
    }

    /// Says the body is complete. A body cut short then reads as
    /// [`Error::Truncated`].
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// The next event, if the bytes so far say what it is. It returns
    /// `None` when it needs more bytes, and after the epilogue once the
    /// body is finished. It keeps returning the same error once the body
    /// has broken. The bytes it holds are at most a header block, or a
    /// boundary line's worth, beyond what the last `feed` added.
    pub fn next_event(&mut self) -> Option<Result<Event, Error>> {
        if let Some(e) = self.queued.take() {
            return Some(Ok(e));
        }
        loop {
            match self.state {
                State::Failed(e) => return Some(Err(e)),
                State::Done => return None,
                State::Preamble | State::Body => {
                    let body = self.state == State::Body;
                    let (upto, found) = scan(&self.buf[self.start..], &self.delim, self.finished);
                    if upto > 0 {
                        let skip = self.virt.min(upto);
                        let data = self.buf[self.start + skip..self.start + upto].to_vec();
                        self.start += upto;
                        self.virt -= skip;
                        if data.is_empty() {
                            continue;
                        }
                        return Some(Ok(if body { Event::Body(data) } else { Event::Preamble(data) }));
                    }
                    match found {
                        Found::Wait if self.finished => return self.fail(Error::Truncated),
                        Found::Wait => {
                            self.compact();
                            return None;
                        }
                        Found::Padding => return self.fail(Error::Padding),
                        Found::Delim(end) => {
                            self.start += end;
                            self.virt = 0;
                            self.state = State::Headers;
                            if body {
                                return Some(Ok(Event::PartEnd));
                            }
                        }
                        Found::Close(end) => {
                            self.start += end;
                            self.virt = 0;
                            self.state = State::Epilogue;
                            if body {
                                self.queued = Some(Event::Close);
                                return Some(Ok(Event::PartEnd));
                            }
                            return Some(Ok(Event::Close));
                        }
                    }
                }
                State::Headers => {
                    if self.parts >= MAX_PARTS {
                        return self.fail(Error::TooManyParts);
                    }
                    // Search only the first MAX_HEADER_BYTES, and only from
                    // where the last search stopped, less a partial CR LF CR.
                    let held = &self.buf[self.start..];
                    let limit = held.len().min(MAX_HEADER_BYTES);
                    let from = self.searched.saturating_sub(3).min(limit);
                    let end = if held.starts_with(b"\r\n") {
                        Some(2)
                    } else {
                        find(&held[from..limit], b"\r\n\r\n").map(|i| from + i + 4)
                    };
                    let end = match end {
                        Some(e) => e,
                        None if held.len() >= MAX_HEADER_BYTES => {
                            return self.fail(Error::HeaderTooLong);
                        }
                        None if self.finished => return self.fail(Error::Truncated),
                        None => {
                            self.searched = limit;
                            self.compact();
                            return None;
                        }
                    };
                    self.searched = 0;
                    let headers = match parse_headers(&held[..end - 2]) {
                        Ok(h) => h,
                        Err(e) => return self.fail(e),
                    };
                    // The block's last CR LF stays, so a body that starts
                    // with the boundary line is empty.
                    self.start += end - 2;
                    self.virt = 2;
                    self.parts += 1;
                    self.state = State::Body;
                    return Some(Ok(Event::Part(headers)));
                }
                State::Epilogue => {
                    if self.start < self.buf.len() {
                        let data = self.buf[self.start..].to_vec();
                        self.start = self.buf.len();
                        self.compact();
                        return Some(Ok(Event::Epilogue(data)));
                    }
                    if self.finished {
                        self.state = State::Done;
                    }
                    return None;
                }
            }
        }
    }

    /// How many bytes of the body are held, waiting for what follows them.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start).saturating_sub(self.virt)
    }

    /// Whether the body has been read to its end: the closing boundary
    /// line, the epilogue, and [`Parser::finish`].
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    fn fail(&mut self, e: Error) -> Option<Result<Event, Error>> {
        self.state = State::Failed(e);
        self.buf = Vec::new();
        self.start = 0;
        self.virt = 0;
        self.queued = None;
        Some(Err(e))
    }
}

/// What follows a boundary.
enum Look {
    /// Padding and CR LF, this many bytes in all.
    Line(usize),
    /// Not the end of a line.
    No,
    /// Not known until more bytes come.
    More,
    /// More than [`MAX_PADDING`] spaces and tabs.
    TooMuch,
}

/// What [`scan`] found after the data it returns.
enum Found {
    /// A boundary line ending here.
    Delim(usize),
    /// The closing boundary line, its padding and line break ending here.
    Close(usize),
    /// A boundary with too much padding after it.
    Padding,
    /// Nothing yet.
    Wait,
}

/// Finds the first boundary line in `buf`. It returns how many bytes
/// before it are certainly data, and what follows them. `finished` says
/// no bytes follow `buf`, so a closing boundary may end there.
fn scan(buf: &[u8], delim: &[u8], finished: bool) -> (usize, Found) {
    for i in 0..buf.len() {
        if buf[i] != b'\r' {
            continue;
        }
        let rest = &buf[i..];
        if rest.len() < delim.len() {
            if delim.starts_with(rest) {
                return (i, Found::Wait);
            }
            continue;
        }
        if &rest[..delim.len()] != delim {
            continue;
        }
        let after = i + delim.len();
        match buf.get(after) {
            None => return (i, Found::Wait),
            Some(b'-') => match buf.get(after + 1) {
                None => return (i, Found::Wait),
                Some(b'-') => match line_end(buf, after + 2) {
                    Look::Line(n) => return (i, Found::Close(after + 2 + n)),
                    Look::TooMuch => return (i, Found::Padding),
                    // Padding up to the end of the body also closes it.
                    Look::More if finished && buf[after + 2..].iter().all(|&b| b == b' ' || b == b'\t') => {
                        return (i, Found::Close(buf.len()));
                    }
                    Look::More if finished => {}
                    Look::More => return (i, Found::Wait),
                    Look::No => {}
                },
                Some(_) => {}
            },
            Some(_) => match line_end(buf, after) {
                Look::Line(n) => return (i, Found::Delim(after + n)),
                Look::TooMuch => return (i, Found::Padding),
                Look::More => return (i, Found::Wait),
                Look::No => {}
            },
        }
    }
    (buf.len(), Found::Wait)
}

/// Whether `buf` at `at` holds spaces and tabs, at most [`MAX_PADDING`],
/// and then CR LF.
fn line_end(buf: &[u8], at: usize) -> Look {
    let mut n = 0usize;
    loop {
        let Some(i) = at.checked_add(n) else {
            return Look::No;
        };
        match buf.get(i) {
            None => return Look::More,
            Some(b' ' | b'\t') => {
                n += 1;
                if n > MAX_PADDING {
                    return Look::TooMuch;
                }
            }
            Some(b'\r') => {
                return match buf.get(i + 1) {
                    None => Look::More,
                    Some(b'\n') => Look::Line(n + 2),
                    Some(_) => Look::No,
                };
            }
            Some(_) => return Look::No,
        }
    }
}

/// Reads a header block: lines that each end with CR LF.
fn parse_headers(block: &[u8]) -> Result<Headers, Error> {
    let mut raw: Vec<(&[u8], Vec<u8>)> = Vec::new();
    let mut rest = block;
    while !rest.is_empty() {
        let i = find(rest, b"\r\n").ok_or(Error::Header)?;
        let line = &rest[..i];
        rest = &rest[i + 2..];
        if line.iter().any(|&b| b == b'\r' || b == b'\n') {
            return Err(Error::Header);
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            // A folded line continues the field before it.
            let last = raw.last_mut().ok_or(Error::Header)?;
            last.1.extend_from_slice(line);
            continue;
        }
        let c = line.iter().position(|&b| b == b':').ok_or(Error::Header)?;
        let name = &line[..c];
        if name.is_empty() || !name.iter().all(|&b| is_ftext(b)) {
            return Err(Error::Header);
        }
        if raw.len() == MAX_HEADERS {
            return Err(Error::TooManyHeaders);
        }
        raw.push((name, line[c + 1..].to_vec()));
    }
    let mut fields = Vec::with_capacity(raw.len());
    for (name, value) in raw {
        let name = String::from_utf8(name.to_vec()).map_err(|_| Error::Header)?;
        let value = String::from_utf8(value).map_err(|_| Error::Header)?;
        fields.push((name, value.trim_matches(is_wsp_char).to_string()));
    }
    Ok(Headers { fields })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn is_bchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b)
}

fn is_token(b: u8) -> bool {
    b > b' ' && b < 0x7f && !b"()<>@,;:\\\"/[]?=".contains(&b)
}

fn is_ftext(b: u8) -> bool {
    (33..=126).contains(&b) && b != b':'
}

fn is_wsp_char(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// A header value the parser reads back the same: no CR or LF, and no
/// space or tab at either end.
fn valid_value(v: &str) -> bool {
    !v.contains(['\r', '\n']) && v.trim_matches(is_wsp_char).len() == v.len()
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    /// Feeds `data` in pieces whose sizes come from `size`, and collects
    /// what the parser finds.
    fn parse_pieces(data: &[u8], boundary: &str, mut size: impl FnMut() -> usize) -> Result<Multipart, Error> {
        let mut p = Parser::new(boundary)?;
        let mut m = Multipart::default();
        let mut i = 0;
        while i < data.len() {
            let n = size().clamp(1, data.len() - i);
            p.feed(&data[i..i + n]);
            i += n;
            while let Some(e) = p.next_event() {
                m.push_event(e?);
            }
            assert!(p.buffered() <= MAX_HEADER_BYTES + n, "held {} bytes", p.buffered());
        }
        p.finish();
        while let Some(e) = p.next_event() {
            m.push_event(e?);
        }
        assert!(p.is_done());
        Ok(m)
    }

    fn crlf(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    // RFC 2046, section 5.1.1.
    #[test]
    fn rfc2046_example() {
        let body = crlf(
            "This is the preamble.  It is to be ignored, though it
is a handy place for composition agents to include an
explanatory note to non-MIME conformant readers.

--simple boundary

This is implicitly typed plain US-ASCII text.
It does NOT end with a linebreak.
--simple boundary
Content-type: text/plain; charset=us-ascii

This is explicitly typed plain US-ASCII text.
It DOES end with a linebreak.

--simple boundary--

This is the epilogue.  It is also to be ignored.
",
        );
        let ct = "multipart/mixed; boundary=\"simple boundary\"";
        let b = boundary(ct).unwrap();
        assert_eq!(b, "simple boundary");
        let m = Multipart::parse(&body, &b).unwrap();
        assert_eq!(
            m.preamble,
            crlf(
                "This is the preamble.  It is to be ignored, though it
is a handy place for composition agents to include an
explanatory note to non-MIME conformant readers.
"
            )
        );
        assert_eq!(m.parts.len(), 2);
        assert!(m.parts[0].headers.fields.is_empty());
        assert_eq!(
            m.parts[0].body,
            crlf("This is implicitly typed plain US-ASCII text.\nIt does NOT end with a linebreak.")
        );
        let ct = m.parts[1].headers.content_type().unwrap();
        assert_eq!(ct.value, "text/plain");
        assert_eq!(ct.get("CHARSET"), Some("us-ascii"));
        assert_eq!(
            m.parts[1].body,
            crlf("This is explicitly typed plain US-ASCII text.\nIt DOES end with a linebreak.\n")
        );
        assert_eq!(m.epilogue, crlf("\nThis is the epilogue.  It is also to be ignored.\n"));
        // Writing it again with the same boundary gives the same bytes back.
        let again = m.to_bytes("simple boundary").unwrap();
        assert_eq!(Multipart::parse(&again, "simple boundary").unwrap(), m);
        assert_eq!(again, body);
    }

    // RFC 7578, sections 4.2 and 4.6.
    #[test]
    fn rfc7578_form_data() {
        let body = crlf(
            "--AaB03x
content-disposition: form-data; name=\"_charset_\"

iso-8859-1
--AaB03x
content-disposition: form-data; name=\"field1\"
content-type: text/plain;charset=windows-1250
content-transfer-encoding: quoted-printable

Joe owes =E2=82=AC100.
--AaB03x
Content-Disposition: form-data; name=\"files\"; filename=\"file1.txt\"
Content-Type: text/plain

... contents of file1.txt ...
--AaB03x--",
        );
        let m = Multipart::parse(&body, &boundary("multipart/form-data; boundary=AaB03x").unwrap()).unwrap();
        assert_eq!(m.parts.len(), 3);
        assert_eq!(m.parts[0].name().as_deref(), Some("_charset_"));
        assert_eq!(m.parts[0].body, b"iso-8859-1");
        assert_eq!(m.parts[1].name().as_deref(), Some("field1"));
        assert_eq!(m.parts[1].filename(), None);
        let ct = m.parts[1].headers.content_type().unwrap();
        assert_eq!((ct.value.as_str(), ct.get("charset")), ("text/plain", Some("windows-1250")));
        assert_eq!(m.parts[1].headers.get("Content-Transfer-Encoding"), Some("quoted-printable"));
        assert_eq!(m.parts[1].body, b"Joe owes =E2=82=AC100.");
        assert_eq!(m.parts[2].name().as_deref(), Some("files"));
        assert_eq!(m.parts[2].filename().as_deref(), Some("file1.txt"));
        assert_eq!(m.parts[2].body, b"... contents of file1.txt ...");
        assert!(m.epilogue.is_empty() && m.preamble.is_empty());
    }

    #[test]
    fn parameters() {
        let v = ParamValue::parse("form-data; name=\"a \\\"q\\\" \\\\ b\";filename=x.txt ; ;").unwrap();
        assert_eq!(v.value, "form-data");
        assert_eq!(v.get("NAME"), Some("a \"q\" \\ b"));
        assert_eq!(v.get("filename"), Some("x.txt"));
        assert_eq!(v.get("other"), None);
        assert_eq!(ParamValue::parse(&v.to_header().unwrap()), Some(v));
        let u = ParamValue::parse("form-data; filename=\"résumé.pdf\"").unwrap();
        assert_eq!(u.get("filename"), Some("résumé.pdf"));
        assert_eq!(ParamValue::parse("x; name = \"\"").unwrap().get("name"), Some(""));
        for bad in ["", " ; a=b", "x; =b", "x; a", "x; a=", "x; a=\"open", "x; a=b c", "x; a b=c", "x; a=@"] {
            assert_eq!(ParamValue::parse(bad), None, "{bad:?}");
        }
        // A name given twice, in any case, is refused: readers that take
        // the first and readers that take the last would disagree.
        assert_eq!(ParamValue::parse("form-data; name=a; NAME=b"), None);
        assert_eq!(
            ParamValue { value: "a".into(), params: vec![("n".into(), "1".into()), ("N".into(), "2".into())] }
                .to_header(),
            None
        );
        let many: String = (0..=MAX_PARAMETERS).map(|i| format!("; p{i}=v")).collect();
        assert_eq!(ParamValue::parse(&format!("x{many}")), None);
        let ok: String = (0..MAX_PARAMETERS).map(|i| format!("; p{i}=v")).collect();
        assert_eq!(ParamValue::parse(&format!("x{ok}")).unwrap().params.len(), MAX_PARAMETERS);
        // Writers refuse what would not read back the same.
        let w = |value: &str, name: &str, pv: &str| {
            ParamValue { value: value.into(), params: vec![(name.into(), pv.into())] }.to_header()
        };
        assert_eq!(w("a", "n", "v").as_deref(), Some("a; n=v"));
        assert_eq!(w("a", "n", "v w").as_deref(), Some("a; n=\"v w\""));
        assert_eq!(w("a", "n", "").as_deref(), Some("a; n=\"\""));
        assert_eq!(w("a;b", "n", "v"), None);
        assert_eq!(w(" a", "n", "v"), None);
        assert_eq!(w("", "n", "v"), None);
        assert_eq!(w("a", "n=", "v"), None);
        assert_eq!(w("a", "", "v"), None);
        assert_eq!(w("a", "n", "v\r\n"), None);
    }

    #[test]
    fn boundaries() {
        assert!(valid_boundary("a"));
        assert!(valid_boundary("gc0pJq0M:08jU534c0p"));
        assert!(valid_boundary("with space"));
        assert!(valid_boundary(&"x".repeat(MAX_BOUNDARY)));
        assert!(!valid_boundary(&"x".repeat(MAX_BOUNDARY + 1)));
        assert!(!valid_boundary(""));
        assert!(!valid_boundary("trailing "));
        assert!(!valid_boundary("semi;colon"));
        assert!(!valid_boundary("é"));
        assert_eq!(boundary("Multipart/Mixed; Boundary=abc").as_deref(), Some("abc"));
        assert_eq!(boundary("multipart/form-data; boundary=\"a:b=c\"").as_deref(), Some("a:b=c"));
        assert_eq!(boundary("text/plain; boundary=abc"), None);
        assert_eq!(boundary("multipart/mixed"), None);
        assert_eq!(boundary("multipart/mixed; boundary=\"bad \""), None);
        let ct = content_type("form-data", "a:b").unwrap();
        assert_eq!(ct, "multipart/form-data; boundary=\"a:b\"");
        assert_eq!(boundary(&ct).as_deref(), Some("a:b"));
        assert_eq!(content_type("form-data", "bad;"), None);
        assert_eq!(content_type("", "a"), None);
        // RFC 2045: the type and subtype are both tokens.
        assert_eq!(boundary("multipart/; boundary=a"), None);
        assert_eq!(boundary("multipart; boundary=a"), None);
        assert_eq!(boundary("multipart/a b; boundary=a"), None);
        assert_eq!(boundary("multipart/x@y; boundary=a"), None);
        // Two boundaries would let readers disagree on where parts end.
        assert_eq!(boundary("multipart/mixed; boundary=a; BOUNDARY=b"), None);
        assert_eq!(Parser::new("").err(), Some(Error::Boundary));
        assert_eq!(Multipart::parse(b"--a--", "a b ").err(), Some(Error::Boundary));
    }

    #[test]
    fn lenient_shapes() {
        // Padding after a boundary, an empty part with no blank line before
        // the next boundary, and a boundary-like line that is data.
        let body = b"--b \t\r\nX: 1\r\n\r\n--b\r\n\r\n--bad\r\n--b-x\r\n--b--";
        let m = Multipart::parse(body, "b").unwrap();
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[0].headers.get("x"), Some("1"));
        assert_eq!(m.parts[0].body, b"");
        assert_eq!(m.parts[1].body, b"--bad\r\n--b-x");
        // No parts at all.
        let m = Multipart::parse(b"--b--", "b").unwrap();
        assert_eq!(m, Multipart::default());
        // The closing line ends with padding and a line break, or with
        // padding and the end of the body.
        assert_eq!(Multipart::parse(b"--b--  \r\nE", "b").unwrap().epilogue, b"E");
        assert_eq!(Multipart::parse(b"--b--  ", "b").unwrap().epilogue, b"");
        assert_eq!(Multipart::parse(b"--b--  E", "b"), Err(Error::Truncated));
        assert_eq!(Multipart::parse(b"--b-- \r", "b"), Err(Error::Truncated));
        // Folded header lines are joined.
        let m = Multipart::parse(b"--b\r\nA:  one\r\n  two \r\n\tthree\r\n\r\nz\r\n--b--", "b").unwrap();
        assert_eq!(m.parts[0].headers.get("a"), Some("one  two \tthree"));
        // A preamble that starts with CR LF.
        assert_eq!(Multipart::parse(b"\r\n--b--", "b").unwrap().preamble, b"");
        assert_eq!(Multipart::parse(b"\r\n\r\n--b--", "b").unwrap().preamble, b"\r\n");
    }

    #[test]
    fn header_errors() {
        let part = |h: &[u8]| {
            let mut v = b"--b\r\n".to_vec();
            v.extend_from_slice(h);
            v.extend_from_slice(b"\r\n\r\nbody\r\n--b--");
            Multipart::parse(&v, "b")
        };
        assert!(part(b"A: ok").is_ok());
        assert_eq!(part(b"no colon"), Err(Error::Header));
        assert_eq!(part(b": empty name"), Err(Error::Header));
        assert_eq!(part(b"Sp ace: x"), Err(Error::Header));
        assert_eq!(part(b"A: bare\nlf"), Err(Error::Header));
        assert_eq!(part(b"A: bare\rcr"), Err(Error::Header));
        assert_eq!(part(b" folded first"), Err(Error::Header));
        assert_eq!(part(b"A: \xff\xfe"), Err(Error::Header));
        let many: Vec<u8> = (0..=MAX_HEADERS).map(|i| format!("H{i}: v")).collect::<Vec<_>>().join("\r\n").into_bytes();
        assert_eq!(part(&many), Err(Error::TooManyHeaders));
        let ok: Vec<u8> = (0..MAX_HEADERS).map(|i| format!("H{i}: v")).collect::<Vec<_>>().join("\r\n").into_bytes();
        assert!(part(&ok).is_ok());
        // The block, with its CR LF CR LF, may be exactly the limit.
        let fits = format!("A: {}", "v".repeat(MAX_HEADER_BYTES - 7));
        assert!(part(fits.as_bytes()).is_ok());
        let long = format!("A: {}", "v".repeat(MAX_HEADER_BYTES - 6));
        assert_eq!(part(long.as_bytes()), Err(Error::HeaderTooLong));
        // Never ending, fed slowly: the parser stops at the limit.
        let mut p = Parser::new("b").unwrap();
        p.feed(b"--b\r\nA: ");
        let mut got = None;
        for _ in 0..MAX_HEADER_BYTES {
            p.feed(b"v");
            if let Some(e) = p.next_event() {
                got = Some(e);
                break;
            }
        }
        assert_eq!(got, Some(Err(Error::HeaderTooLong)));
        // An error sticks, and later bytes are dropped.
        p.feed(b"\r\n\r\n--b--");
        p.finish();
        assert_eq!(p.next_event(), Some(Err(Error::HeaderTooLong)));
        assert_eq!(p.buffered(), 0);
    }

    #[test]
    fn part_count_limit() {
        let mut ok = Multipart { parts: vec![Part::field("f", "v").unwrap(); MAX_PARTS], ..Multipart::default() };
        let bytes = ok.to_bytes("b").unwrap();
        assert_eq!(Multipart::parse(&bytes, "b").unwrap(), ok);
        let mut over = String::new();
        for _ in 0..=MAX_PARTS {
            over.push_str("--b\r\n\r\n\r\n");
        }
        over.push_str("--b--");
        assert_eq!(Multipart::parse(over.as_bytes(), "b"), Err(Error::TooManyParts));
        ok.parts.push(Part::default());
        assert_eq!(ok.to_bytes("b"), Err(WriteError::TooManyParts));
    }

    fn sample() -> Multipart {
        Multipart {
            preamble: b"pre".to_vec(),
            parts: vec![
                Part::field("user", "alice").unwrap(),
                Part::file("doc", "C:\\a \"b\".txt", "text/plain", "line\r\n").unwrap(),
                Part::default(),
                Part { headers: Headers::default(), body: b"\r\n".to_vec() },
            ],
            epilogue: b"\r\npost".to_vec(),
        }
    }

    #[test]
    fn every_truncated_prefix() {
        let m = sample();
        let bytes = m.to_bytes("bound").unwrap();
        let close = find(&bytes, b"--bound--").unwrap() + 9;
        for n in 0..bytes.len() {
            let got = Multipart::parse(&bytes[..n], "bound");
            // A lone CR after the closing boundary does not end its line.
            if n < close || n == close + 1 {
                assert_eq!(got, Err(Error::Truncated), "{n} bytes");
            } else {
                let got = got.unwrap();
                assert_eq!(got.parts, m.parts, "{n} bytes");
            }
        }
        assert_eq!(Multipart::parse(&bytes, "bound").unwrap(), m);
    }

    #[test]
    fn round_trips() {
        let m = sample();
        let (b, bytes) = m.write("bound").unwrap();
        assert_eq!(b, "bound");
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
        assert_eq!(m.parts[1].filename().as_deref(), Some("C:\\a \"b\".txt"));
        let back = Multipart::parse(&bytes, &b).unwrap();
        assert_eq!(back.parts[1].filename().as_deref(), Some("C:\\a \"b\".txt"));
        // Byte at a time, the same.
        assert_eq!(parse_pieces(&bytes, &b, || 1).unwrap(), m);
        // Empty preamble and epilogue.
        let bare = Multipart { parts: vec![Part::field("a", "").unwrap()], ..Multipart::default() };
        let bytes = bare.to_bytes("z").unwrap();
        assert_eq!(bytes, b"--z\r\nContent-Disposition: form-data; name=a\r\n\r\n\r\n--z--\r\n");
        assert_eq!(Multipart::parse(&bytes, "z").unwrap(), bare);
    }

    #[test]
    fn picking_a_boundary() {
        let mut m =
            Multipart { parts: vec![Part::field("x", "--XyZ and --XyZ-00000000").unwrap()], ..Multipart::default() };
        assert_eq!(m.to_bytes("XyZ"), Err(WriteError::BoundaryInData));
        assert_eq!(m.pick_boundary("XyZ").unwrap(), "XyZ-00000001");
        m.preamble = b"--XyZ-00000001".to_vec();
        assert_eq!(m.pick_boundary("XyZ").unwrap(), "XyZ-00000002");
        let (b, bytes) = m.write("XyZ").unwrap();
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
        // A long base is cut to fit.
        let base = "q".repeat(MAX_BOUNDARY);
        m.parts[0].body = format!("--{base}").into_bytes();
        let b = m.pick_boundary(&base).unwrap();
        assert!(valid_boundary(&b));
        assert_eq!(b.len(), MAX_BOUNDARY);
        assert_eq!(m.pick_boundary("bad;"), Err(WriteError::Boundary));
        // The boundary in a header counts too.
        let h = Multipart {
            parts: vec![Part { headers: Headers { fields: vec![("X".into(), "--k".into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(h.to_bytes("k"), Err(WriteError::BoundaryInData));
        assert_eq!(h.pick_boundary("k").unwrap(), "k-00000000");
    }

    #[test]
    fn write_errors() {
        let with = |name: &str, value: &str| Multipart {
            parts: vec![Part { headers: Headers { fields: vec![(name.into(), value.into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(with("A", "v").to_bytes(""), Err(WriteError::Boundary));
        assert!(with("A", "").to_bytes("b").is_ok());
        assert_eq!(with("", "v").to_bytes("b"), Err(WriteError::HeaderName));
        assert_eq!(with("A B", "v").to_bytes("b"), Err(WriteError::HeaderName));
        assert_eq!(with("A:", "v").to_bytes("b"), Err(WriteError::HeaderName));
        assert_eq!(with("A", "v\r\nX: y").to_bytes("b"), Err(WriteError::HeaderValue));
        assert_eq!(with("A", " v").to_bytes("b"), Err(WriteError::HeaderValue));
        assert_eq!(with("A", "v\t").to_bytes("b"), Err(WriteError::HeaderValue));
        assert_eq!(with("A", &"v".repeat(MAX_HEADER_BYTES)).to_bytes("b"), Err(WriteError::HeaderTooLong));
        let fits = with("A", &"v".repeat(MAX_HEADER_BYTES - 7));
        assert_eq!(Multipart::parse(&fits.to_bytes("b").unwrap(), "b").unwrap(), fits);
        let mut many = with("A", "v");
        many.parts[0].headers.fields = vec![("A".into(), "v".into()); MAX_HEADERS + 1];
        assert_eq!(many.to_bytes("b"), Err(WriteError::TooManyHeaders));
        assert_eq!(Part::field("a\r\n", "v"), None);
        assert_eq!(Part::file("a", "f", "text/plain\r\n", "v"), None);
        assert_eq!(Part::file("a", "f\n", "text/plain", "v"), None);
    }

    #[test]
    fn events_in_order() {
        let mut p = Parser::new("b").unwrap();
        let mut events = Vec::new();
        for &byte in b"P\r\n--b\r\nA: 1\r\n\r\nxy\r\n--b--\r\nE" {
            p.feed(&[byte]);
            while let Some(e) = p.next_event() {
                events.push(e.unwrap());
            }
            assert!(p.buffered() <= 8);
        }
        assert!(!p.is_done());
        p.finish();
        assert_eq!(p.next_event(), None);
        assert!(p.is_done());
        let mut joined: Vec<Event> = Vec::new();
        for e in events {
            match (joined.last_mut(), e) {
                (Some(Event::Body(a)), Event::Body(b)) => a.extend(b),
                (Some(Event::Preamble(a)), Event::Preamble(b)) => a.extend(b),
                (_, e) => joined.push(e),
            }
        }
        let headers = Headers { fields: vec![("A".into(), "1".into())] };
        assert_eq!(
            joined,
            [
                Event::Preamble(b"P".to_vec()),
                Event::Part(headers),
                Event::Body(b"xy".to_vec()),
                Event::PartEnd,
                Event::Close,
                Event::Epilogue(b"E".to_vec()),
            ]
        );
        // Truncated, then finished.
        let mut p = Parser::new("b").unwrap();
        p.feed(b"--b\r\n\r\nbody");
        while let Some(e) = p.next_event() {
            e.unwrap();
        }
        p.finish();
        assert_eq!(p.next_event(), Some(Err(Error::Truncated)));
        assert_eq!(p.next_event(), Some(Err(Error::Truncated)));
    }

    #[test]
    fn body_bytes_are_not_held() {
        // A large body passes through, the parser holding only a few bytes.
        let mut p = Parser::new("bound").unwrap();
        p.feed(b"--bound\r\n\r\n");
        let mut total = 0;
        for _ in 0..1000 {
            p.feed(&[b'\r'; 64]);
            while let Some(e) = p.next_event() {
                if let Event::Body(d) = e.unwrap() {
                    total += d.len();
                }
            }
            assert!(p.buffered() <= 10, "{}", p.buffered());
        }
        p.feed(b"\r\n--bound--");
        p.finish();
        while let Some(e) = p.next_event() {
            if let Event::Body(d) = e.unwrap() {
                total += d.len();
            }
        }
        assert_eq!(total, 64_000);
    }

    #[test]
    fn slow_headers_take_linear_time() {
        // Header blocks near the limit, fed a byte at a time. The parser
        // looks at each new byte once, not at the whole block again.
        let mut part = format!("--b\r\nA: {}\r\n\r\nx\r\n", "v".repeat(MAX_HEADER_BYTES - 9)).into_bytes();
        part = part.repeat(64);
        part.extend_from_slice(b"--b--");
        let start = std::time::Instant::now();
        let m = parse_pieces(&part, "b", || 1).unwrap();
        assert_eq!(m.parts.len(), 64);
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn many_parts_read_in_linear_time() {
        // A whole body of MAX_PARTS parts, each 40 KB. Reading a part must
        // not copy the bytes after it.
        let mut body = Vec::new();
        for _ in 0..MAX_PARTS {
            body.extend_from_slice(b"--b\r\n\r\n");
            body.extend(std::iter::repeat_n(b'x', 40_000));
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--b--");
        let start = std::time::Instant::now();
        let m = Multipart::parse(&body, "b").unwrap();
        assert_eq!(m.parts.len(), MAX_PARTS);
        assert!(m.parts.iter().all(|p| p.body.len() == 40_000));
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
        // A large piece, then single bytes: what the parser holds stays small.
        let mut p = Parser::new("b").unwrap();
        let cut = body.len() - 100_000;
        p.feed(&body[..cut]);
        let mut n = 0;
        let mut drain = |p: &mut Parser| {
            while let Some(e) = p.next_event() {
                if let Event::Part(_) = e.unwrap() {
                    n += 1;
                }
            }
        };
        drain(&mut p);
        for b in &body[cut..] {
            p.feed(std::slice::from_ref(b));
            drain(&mut p);
            assert!(p.buffered() <= 16, "{}", p.buffered());
        }
        p.finish();
        drain(&mut p);
        assert!(p.is_done());
        assert_eq!(n, MAX_PARTS);
    }

    #[test]
    fn repeated_fields() {
        let body = b"--b\r\nContent-Disposition: form-data; name=a\r\n\
            content-disposition: form-data; name=b\r\nContent-Type: text/plain\r\n\
            X: 1\r\nx: 2\r\n\r\nv\r\n--b--";
        let m = Multipart::parse(body, "b").unwrap();
        let h = &m.parts[0].headers;
        // Two dispositions: readers could disagree on the field name.
        assert_eq!(h.content_disposition(), None);
        assert_eq!(m.parts[0].name(), None);
        assert_eq!(m.parts[0].filename(), None);
        assert_eq!(h.content_type().unwrap().value, "text/plain");
        assert_eq!(h.get("x"), Some("1"));
        assert_eq!(h.get_all("X").collect::<Vec<_>>(), ["1", "2"]);
        assert_eq!(h.get_one("x"), None);
        assert_eq!(h.get_one("content-type"), Some("text/plain"));
        assert_eq!(h.get_one("missing"), None);
        // Writing keeps both, and reads back the same.
        let (b, bytes) = m.write("b").unwrap();
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
    }

    // Finding: a parser that took one large piece kept its whole buffer.
    #[test]
    fn large_feed_is_not_held() {
        let mut p = Parser::new("b").unwrap();
        let mut body = b"--b\r\n\r\n".to_vec();
        body.resize(1 << 20, b'x');
        p.feed(&body);
        let mut total = 0;
        while let Some(e) = p.next_event() {
            if let Event::Body(d) = e.unwrap() {
                total += d.len();
            }
        }
        assert_eq!(total, (1 << 20) - 7);
        assert!(p.buf.capacity() <= 2 * KEEP_CAPACITY, "{}", p.buf.capacity());
        // The epilogue is let go of as well.
        let mut p = Parser::new("b").unwrap();
        let mut body = b"--b--\r\n".to_vec();
        body.resize(1 << 20, b'e');
        p.feed(&body);
        while let Some(e) = p.next_event() {
            e.unwrap();
        }
        assert!(p.buf.capacity() <= 2 * KEEP_CAPACITY, "{}", p.buf.capacity());
    }

    // Finding: a boundary made of a header's name, the colon and its value.
    #[test]
    fn boundary_across_a_header_line() {
        let m = Multipart {
            parts: vec![Part { headers: Headers { fields: vec![("--x".into(), "y".into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(m.to_bytes("x: y"), Err(WriteError::BoundaryInData));
        let b = m.pick_boundary("x: y").unwrap();
        assert_ne!(b, "x: y");
        let bytes = m.to_bytes(&b).unwrap();
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
        // The same in the compact form.
        let mut c = m.clone();
        c.parts[0].headers.fields.push(("P".into(), "p".repeat(MAX_HEADER_BYTES - 14)));
        assert_eq!(header_separator(&c.parts[0]), b":");
        assert_eq!(c.to_bytes("x:y"), Err(WriteError::BoundaryInData));
        let b = c.pick_boundary("x:y").unwrap();
        assert_eq!(Multipart::parse(&c.to_bytes(&b).unwrap(), &b).unwrap(), c);
    }

    // Finding: `--b--junk` closed the body.
    #[test]
    fn closing_line_must_end() {
        assert_eq!(Multipart::parse(b"--b\r\n\r\nx\r\n--b--junk", "b"), Err(Error::Truncated));
        let m = Multipart::parse(b"--b\r\n\r\nx\r\n--b--junk\r\n--b--\r\nE", "b").unwrap();
        assert_eq!(m.parts.len(), 1);
        assert_eq!(m.parts[0].body, b"x\r\n--b--junk");
        assert_eq!(m.epilogue, b"E");
        assert_eq!(parse_pieces(b"--b\r\n\r\nx\r\n--b-- \t", "b", || 1).unwrap().parts[0].body, b"x");
    }

    // Finding: a boundary line with too much padding became body data.
    #[test]
    fn too_much_padding_is_an_error() {
        let pad = " ".repeat(MAX_PADDING + 1);
        let body = format!("--b\r\n\r\nx\r\n--b{pad}\r\n\r\ny\r\n--b--");
        assert_eq!(Multipart::parse(body.as_bytes(), "b"), Err(Error::Padding));
        assert_eq!(parse_pieces(body.as_bytes(), "b", || 1), Err(Error::Padding));
        let body = format!("--b\r\n\r\nx\r\n--b--{pad}");
        assert_eq!(Multipart::parse(body.as_bytes(), "b"), Err(Error::Padding));
        let fits = " ".repeat(MAX_PADDING);
        let body = format!("--b{fits}\r\n\r\nx\r\n--b{fits}\r\n\r\ny\r\n--b--{fits}");
        assert_eq!(Multipart::parse(body.as_bytes(), "b").unwrap().parts.len(), 2);
    }

    // Finding: comments and spaces in Content-Type hid the boundary.
    #[test]
    fn content_type_comments() {
        assert_eq!(boundary("multipart/mixed; boundary=b (comment)").as_deref(), Some("b"));
        assert_eq!(boundary("multipart / mixed; boundary=b").as_deref(), Some("b"));
        assert_eq!(boundary("(a (nested) \\) one) multipart/mixed (x); boundary=\"(q)\"").as_deref(), Some("(q)"));
        assert_eq!(boundary("multipart/mixed; boundary=b (open"), None);
        assert_eq!(boundary("multi(x)part/mixed; boundary=b"), None);
    }

    // Finding: RFC 2231 continuations of the boundary were not joined.
    #[test]
    fn boundary_continuations() {
        assert_eq!(boundary("multipart/mixed; boundary*0=\"ab\"; boundary*1=\"cd\"").as_deref(), Some("abcd"));
        assert_eq!(boundary("multipart/mixed; Boundary*1=cd; BOUNDARY*0=ab").as_deref(), Some("abcd"));
        assert_eq!(boundary("multipart/mixed; boundary*0=ab; boundary*2=cd"), None);
        assert_eq!(boundary("multipart/mixed; boundary*1=ab"), None);
        assert_eq!(boundary("multipart/mixed; boundary=x; boundary*0=ab"), None);
        assert_eq!(boundary("multipart/mixed; boundary*0*=us-ascii''ab"), None);
        assert_eq!(boundary("multipart/mixed; boundary*0=ab; boundary*01=cd"), None);
        let long = format!("multipart/mixed; boundary*0={}; boundary*1=b", "a".repeat(MAX_BOUNDARY));
        assert_eq!(boundary(&long), None);
    }

    // Finding: a header block the parser took could be too long to write.
    #[test]
    fn full_header_block_writes_again() {
        let mut block = Vec::new();
        for _ in 0..31 {
            block.extend_from_slice(format!("X:{}\r\n", "v".repeat(252)).as_bytes());
        }
        block.extend_from_slice(format!("X:{}\r\n\r\n", "v".repeat(250)).as_bytes());
        assert_eq!(block.len(), MAX_HEADER_BYTES);
        let mut body = b"--b\r\n".to_vec();
        body.extend_from_slice(&block);
        body.extend_from_slice(b"z\r\n--b--");
        let m = Multipart::parse(&body, "b").unwrap();
        let (b, bytes) = m.write("b").unwrap();
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
        // Folded lines get shorter when joined, so they fit too.
        let (v, w) = ("v".repeat(4000), "w".repeat(MAX_HEADER_BYTES - 4013));
        let folded = format!("--b\r\nA:{v}\r\n {w}\r\n\r\n\r\n--b--");
        let m = Multipart::parse(folded.as_bytes(), "b").unwrap();
        let (b, bytes) = m.write("b").unwrap();
        assert_eq!(Multipart::parse(&bytes, &b).unwrap(), m);
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n
        }
    }

    const PIECES: &[&[u8]] = &[
        b"--a",
        b"\r\n",
        b"--",
        b"-",
        b" ",
        b"\t",
        b"a",
        b"Content-Disposition: form-data; name=\"f\"; filename=\"x\"",
        b"X: y",
        b":",
        b"\r",
        b"\n",
        b"\"",
        b";",
        b"\r\n--a\r\n",
        b"\r\n--a--",
        b"\r\n\r\n",
        b"\xff",
        b"body",
        b"--a: y",
        b"y",
    ];

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg(0x5eed);
        let mut oks = 0;
        for round in 0..4000 {
            let mut data = Vec::new();
            for _ in 0..r.below(40) {
                if r.below(8) == 0 {
                    data.push(r.next() as u8);
                } else {
                    data.extend_from_slice(PIECES[r.below(PIECES.len())]);
                }
            }
            let whole = Multipart::parse(&data, "a");
            let bytewise = parse_pieces(&data, "a", || 1);
            assert_eq!(whole, bytewise, "round {round}: {data:?}");
            let mut r2 = Lcg(round);
            let random = parse_pieces(&data, "a", || r2.below(9));
            assert_eq!(whole, random, "round {round}");
            if let Ok(m) = whole {
                oks += 1;
                let (b, bytes) = m.write("a").unwrap();
                assert_eq!(Multipart::parse(&bytes, &b).as_ref(), Ok(&m), "round {round}");
                for p in &m.parts {
                    let _ = (p.name(), p.filename(), p.headers.content_type());
                }
            }
            if let Ok(s) = std::str::from_utf8(&data) {
                if let Some(v) = ParamValue::parse(s)
                    && let Some(h) = v.to_header() {
                        assert_eq!(ParamValue::parse(&h), Some(v));
                    }
                let _ = boundary(s);
            }
        }
        assert!(oks > 100, "only {oks} bodies parsed");

        // Structured bodies, with the boundary scattered through the data.
        for round in 0..2000 {
            let bytes = |r: &mut Lcg| -> Vec<u8> {
                let mut v = Vec::new();
                for _ in 0..r.below(6) {
                    v.extend_from_slice(PIECES[r.below(PIECES.len())]);
                }
                v
            };
            let mut m = Multipart { preamble: bytes(&mut r), parts: Vec::new(), epilogue: bytes(&mut r) };
            for _ in 0..r.below(5) {
                let name = String::from_utf8_lossy(&bytes(&mut r)).into_owned();
                let part = if r.below(2) == 0 {
                    Part::field(&name, bytes(&mut r))
                } else {
                    Part::file(&name, &name, "application/octet-stream", bytes(&mut r))
                };
                let mut part = part.unwrap_or_default();
                // A raw header field, kept only if a writer takes it.
                let name = String::from_utf8_lossy(&bytes(&mut r)).into_owned();
                let value = String::from_utf8_lossy(&bytes(&mut r)).into_owned();
                if !name.is_empty() && name.bytes().all(is_ftext) && valid_value(&value) {
                    part.headers.fields.push((name, value));
                }
                m.parts.push(part);
            }
            let base = ["a", "y", "a: y", "a:y", "-a"][r.below(5)];
            let (b, out) = m.write(base).unwrap();
            assert_eq!(Multipart::parse(&out, &b).as_ref(), Ok(&m), "round {round}");
            assert_eq!(parse_pieces(&out, &b, || 1).as_ref(), Ok(&m), "round {round}");
            for p in &m.parts {
                if let Some(n) = p.name() {
                    assert!(!n.contains('\r'));
                }
            }
        }
    }
}
