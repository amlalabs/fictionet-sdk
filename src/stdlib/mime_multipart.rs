//! MIME multipart bodies: splitting them into parts and writing them, with
//! no I/O.
//!
//! `Part`, `Body`, and `Entity` read and write complete values through `Wire`,
//! and `Parts` decodes complete parts from a stream. The caller supplies body
//! boundaries. This module does not implement HTTP or mail sessions, a
//! `Service`, or upload storage.
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
//! pieces goes to [`Stream<Parts>`](fictionet::stdlib::codec::Stream), which returns
//! complete [`Part`] values within a fixed size limit. What the fields mean,
//! and where uploaded files go, is up to world code.
//! Write raw HTTP bodies with [`Body`] and choose the multipart subtype in
//! the HTTP header. [`Entity`] writes complete `multipart/mixed` MIME entities.
//!
//! Every reader checks lengths and counts, because the agent can send any
//! bytes it likes. The limits are the `MAX_` constants below. A writer
//! picks a boundary that appears nowhere in the parts, so what it writes
//! always reads back the same.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::mime_multipart::{boundary, Entity, Multipart, Part};
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
//! let entity = reply.with_free_boundary("XyZ").unwrap();
//! assert_ne!(entity.boundary, "XyZ");
//! let bytes = entity.to_bytes().unwrap();
//! assert_eq!(Entity::parse(&bytes).unwrap(), entity);
//! ```

extern crate alloc;

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use fictionet::stdlib::codec::{Decode, Step, Wire};

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
/// The cap on one part, including headers, or on the preamble.
/// MIME has no part size maximum. This module caps parts at 4 MiB.
pub const MAX_PART: usize = 4 * 1024 * 1024;
/// The largest complete MIME entity, including its header, in bytes.
/// Streaming [`Parts`] has no aggregate limit beyond its per-part limits.
pub const MAX_ENTITY: usize = 16 * 1024 * 1024;
/// The longest boundary line, including CR LF, dashes, padding, and CR LF.
/// Derived from RFC 2046's [`MAX_BOUNDARY`] and this module's [`MAX_PADDING`].
pub const MAX_BOUNDARY_LINE: usize = MAX_BOUNDARY + MAX_PADDING + 8;
/// Why bytes are not a multipart body, or why a part, entity, or
/// parameterized header cannot be written. Once [`Parts`] meets one, it
/// reads no further.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The boundary is empty, longer than [`MAX_BOUNDARY`], ends with a
    /// space, or holds a character RFC 2046 does not allow.
    Boundary,
    /// The body ended before the closing boundary line.
    Truncated,
    /// The body holds, or a writer was given, more than [`MAX_PARTS`] parts.
    TooManyParts,
    /// A part's header block, or a parameterized value being written, is
    /// longer than [`MAX_HEADER_BYTES`].
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
    /// A part or preamble is longer than [`MAX_PART`]. A part being
    /// written counts its headers too.
    TooLong,
    /// A complete entity is longer than [`MAX_ENTITY`].
    EntityTooLong,
    /// The boundary, after `--`, appears in the preamble or in a part
    /// being written.
    BoundaryInData,
    /// A header name being written is empty or holds a character other
    /// than visible ASCII, or a colon. A parameter name is empty or is not
    /// a token.
    HeaderName,
    /// A header value being written holds CR or LF, or starts or ends with
    /// a space or tab.
    HeaderValue,
    /// The value cannot be written without changing it.
    Unwritable,
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
            Error::TooLong => "multipart part or preamble is over the size limit",
            Error::EntityTooLong => "multipart entity is over the size limit",
            Error::BoundaryInData => "the boundary appears in the data",
            Error::HeaderName => "a header name is not valid",
            Error::HeaderValue => "a header value is not valid",
            Error::Unwritable => "value cannot be written without changing it",
        })
    }
}

impl core::error::Error for Error {}

/// Whether `b` is a boundary RFC 2046 allows: 1 to 70 characters from its
/// set (letters, digits, space and `'()+_,-./:=?`), not ending in a space.
pub fn valid_boundary(b: &str) -> bool {
    let x = b.as_bytes();
    !x.is_empty() && x.len() <= MAX_BOUNDARY && x.iter().all(|&c| is_bchar(c)) && x[x.len() - 1] != b' '
}

/// The boundary named in a `Content-Type` value such as
/// `multipart/form-data; boundary=XyZ`. It returns `None` if the type is
/// not `multipart/` and a subtype token, or the boundary is missing or
/// not valid, or the Content-Type exceeds [`MAX_HEADER_BYTES`].
///
/// As RFC 2045 allows, comments in parentheses and spaces around the `/`
/// are skipped: `multipart / mixed; boundary=b (note)` names `b`. A
/// boundary split into RFC 2231 continuations (`boundary*0="ab";
/// boundary*1="cd"`) is joined. The value is `None` if the pieces skip a
/// number, use the encoded form (`boundary*0*`), or come with a plain
/// `boundary` as well.
pub fn boundary(content_type: &str) -> Option<String> {
    if content_type.len() > MAX_HEADER_BYTES {
        return None;
    }
    let cleaned = strip_comments(content_type)?;
    let v = ParamValue::parse_text(&cleaned)?;
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
/// subtype is empty, is not a token, or exceeds [`MAX_HEADER_BYTES`] minus
/// 128 bytes, or the boundary is not valid.
pub fn content_type(subtype: &str, boundary: &str) -> Option<ParamValue> {
    if subtype.is_empty() || subtype.len() > MAX_HEADER_BYTES.saturating_sub(128)
        || !subtype.bytes().all(is_token) || !valid_boundary(boundary) {
        return None;
    }
    Some(ParamValue { value: format!("multipart/{subtype}"), params: vec![("boundary".into(), boundary.into())] })
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
    fn parse_text(s: &str) -> Option<ParamValue> {
        if s.len() > MAX_HEADER_BYTES || s.contains(['\r', '\n']) {
            return None;
        }
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

    fn header_text(&self) -> Result<String, Error> {
        let v = &self.value;
        if v.contains(['\r', '\n']) || v.trim_matches(is_wsp_char).len() != v.len() {
            return Err(Error::HeaderValue);
        }
        if v.is_empty() || v.contains(';') {
            return Err(Error::Unwritable);
        }
        if self.params.len() > MAX_PARAMETERS {
            return Err(Error::Unwritable);
        }
        let len = self.params.iter().fold(v.len(), |n, (name, value)| {
            let quoted = value.is_empty() || !value.bytes().all(is_token);
            let escapes = if quoted { value.bytes().filter(|b| matches!(b, b'"' | b'\\')).count() } else { 0 };
            n.saturating_add(name.len()).saturating_add(value.len()).saturating_add(escapes)
                .saturating_add(3).saturating_add(if quoted { 2 } else { 0 })
        });
        if len > MAX_HEADER_BYTES {
            return Err(Error::HeaderTooLong);
        }
        let mut out = v.clone();
        for (i, (name, value)) in self.params.iter().enumerate() {
            if name.is_empty() || !name.bytes().all(is_token) {
                return Err(Error::HeaderName);
            }
            if value.contains(['\r', '\n']) {
                return Err(Error::HeaderValue);
            }
            if self.params[..i].iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                return Err(Error::Unwritable);
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
        Ok(out)
    }
}

impl Wire for ParamValue {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a UTF-8 parameterized header value. Refuses malformed or
    /// repeated parameters, CR or LF, and raw or canonical headers beyond
    /// [`MAX_HEADER_BYTES`]. The main value must be nonempty. Empty
    /// parameter separators are skipped. Names retain their case, but
    /// duplicate names are compared without case.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        let text = core::str::from_utf8(input).map_err(|_| Error::Header)?;
        let value = Self::parse_text(text).ok_or(Error::Header)?;
        value.header_text().map_err(|_| Error::Header)?;
        Ok(value)
    }

    /// Appends a header value with tokens or quoted parameters. Refuses
    /// invalid names, duplicate parameters, CR or LF, excessive counts or
    /// lengths, and values that would read back differently. The main value
    /// must be nonempty, have no semicolon, CR or LF, and have no surrounding
    /// spaces or tabs. A parameter name must be a token. Duplicate names
    /// are compared without case. Invalid names return [`Error::HeaderName`],
    /// CR, LF, or surrounding spaces or tabs in the main value return
    /// [`Error::HeaderValue`]. Oversized headers return
    /// [`Error::HeaderTooLong`]. Other refusals return
    /// [`Error::Unwritable`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let text = self.header_text()?;
        out.extend_from_slice(text.as_bytes());
        Ok(())
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
        ParamValue::parse_text(self.get_one("content-type")?)
    }

    /// The `Content-Disposition` field, read with its parameters. It is
    /// `None` if the part has no such field or has it twice.
    pub fn content_disposition(&self) -> Option<ParamValue> {
        ParamValue::parse_text(self.get_one("content-disposition")?)
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
    /// value as the body. Refuses CR or LF in `name`, or a disposition
    /// value beyond [`MAX_HEADER_BYTES`]. The writer checks the part cap.
    pub fn field(name: &str, value: impl Into<Vec<u8>>) -> Option<Part> {
        if name.len() > MAX_HEADER_BYTES {
            return None;
        }
        let d = ParamValue { value: "form-data".into(), params: vec![("name".into(), name.into())] };
        Some(Part {
            headers: Headers { fields: vec![("Content-Disposition".into(), d.header_text().ok()?)] },
            body: value.into(),
        })
    }

    /// An uploaded file: a form-data part with a `filename` parameter and
    /// a `Content-Type` field. It returns `None` if a name holds CR or LF,
    /// the disposition exceeds [`MAX_HEADER_BYTES`], or the content type
    /// is not a valid header value or exceeds [`MAX_HEADER_BYTES`]. The
    /// writer checks the part cap.
    pub fn file(name: &str, filename: &str, content_type: &str, body: impl Into<Vec<u8>>) -> Option<Part> {
        if name.len() > MAX_HEADER_BYTES || filename.len() > MAX_HEADER_BYTES
            || content_type.len() > MAX_HEADER_BYTES || !valid_value(content_type) {
            return None;
        }
        let d = ParamValue {
            value: "form-data".into(),
            params: vec![("name".into(), name.into()), ("filename".into(), filename.into())],
        };
        Some(Part {
            headers: Headers {
                fields: vec![
                    ("Content-Disposition".into(), d.header_text().ok()?),
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
    type WriteError = Error;

    /// Reads one header block and its complete body, without boundary lines.
    /// Every byte after the empty header line belongs to the body. Refuses
    /// incomplete or malformed headers, excessive header counts or sizes,
    /// and parts over [`MAX_PART`].
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

    /// Appends one part without boundary lines, using compact `name:value`
    /// headers. Refuses invalid header names, CR or LF or surrounding
    /// whitespace in values, excessive headers, and parts over [`MAX_PART`].
    /// On error, `out` is unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        validate_part(self)?;
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

fn validate_part(part: &Part) -> Result<usize, Error> {
    if part.headers.fields.len() > MAX_HEADERS {
        return Err(Error::TooManyHeaders);
    }
    for (name, value) in &part.headers.fields {
        if name.is_empty() || !name.bytes().all(is_ftext) {
            return Err(Error::HeaderName);
        }
        if !valid_value(value) {
            return Err(Error::HeaderValue);
        }
    }
    // Compact separators keep parsed folded headers within the same cap.
    let header = header_block_size(part, 1);
    if header > MAX_HEADER_BYTES {
        return Err(Error::HeaderTooLong);
    }
    if header.saturating_add(part.body.len()) > MAX_PART {
        return Err(Error::TooLong);
    }
    Ok(header)
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
            .map(|i| from.saturating_add(i).saturating_add(4))
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
/// Completed headers are validated and held as parsed state until the body
/// ends.
/// A partial header returns [`Step::Need`]. An unclosed body returns
/// [`Error::Truncated`]. Other syntax and limit errors also end the stream.
/// Capacity is [`MAX_PART`] plus [`MAX_BOUNDARY_LINE`] plus one overflow byte.
/// Drive it with [`Stream<Parts>`](fictionet::stdlib::codec::Stream).
/// An empty stream ends cleanly with no items, unlike [`Multipart::parse`],
/// while a preamble-only body is an error.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, finish, pump}, mime_multipart::Parts};
///
/// let mut stream = Stream::new(Parts::new("b").unwrap());
/// let mut parts = Vec::new();
/// pump(&mut stream, b"--b\r\n\r\nhello", |part| parts.push(part))?;
/// pump(&mut stream, b"\r\n--b--\r\n", |part| parts.push(part))?;
/// finish(&mut stream, |part| parts.push(part))?;
/// assert_eq!(parts.len(), 1);
/// assert_eq!(parts[0].body, b"hello");
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::mime_multipart::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Parts {
    delim: Vec<u8>,
    state: State,
    scanned: usize,
    preamble_bytes: usize,
    header_bytes: usize,
    headers: Headers,
    parts: usize,
}

impl Parts {
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
            preamble_bytes: 0,
            header_bytes: 0,
            headers: Headers::default(),
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

impl Decode for Parts {
    type Item = Part;
    type Error = Error;
    const NAME: &'static str = "MIME multipart";

    fn capacity(&self) -> usize {
        MAX_PART.saturating_add(MAX_BOUNDARY_LINE).saturating_add(1)
    }

    fn held(&self) -> usize {
        self.headers.fields.iter().fold(
            self.delim.len(),
            |n, (name, value)| n.saturating_add(name.len()).saturating_add(value.len()),
        )
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
        if self.state == State::Headers {
            if self.parts >= MAX_PARTS {
                return Err(Error::TooManyParts);
            }
            let Some(end) = part_header_end(input, self.scanned)? else {
                self.scanned = input.len();
                if eof && input.is_empty() {
                    return Err(Error::Truncated);
                }
                return Ok(Step::Need);
            };
            self.headers = parse_headers(input.get(..end.saturating_sub(2)).unwrap_or_default())?;
            self.header_bytes = end;
            self.state = State::Body;
            self.scanned = 0;
            return Ok(Step::Skip(end));
        }
        // A consumed header block supplies the implicit CR LF before an
        // empty body's boundary, just as at the start of the multipart.
        let first = !preamble || self.preamble_bytes == 0;
        let (at, found) = self.boundary(input, eof, first);
        // Consume the same preamble prefix before any boundary or limit
        // error, whether it arrived together with that error or earlier.
        if preamble && at > 0 {
            let room = MAX_PART.saturating_sub(self.preamble_bytes);
            if room == 0 {
                return Err(Error::TooLong);
            }
            let n = at.min(room);
            self.preamble_bytes = self.preamble_bytes.saturating_add(n);
            self.scanned = 0;
            return Ok(Step::Skip(n));
        }
        let size = if preamble {
            self.preamble_bytes.saturating_add(at)
        } else {
            self.header_bytes.saturating_add(at)
        };
        if size > MAX_PART {
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
                if eof && (!preamble || (size > 0 && at == input.len())) {
                    return Err(Error::Truncated);
                }
                return Ok(Step::Need);
            }
        };
        let item = if preamble {
            None
        } else {
            Some(Part {
                headers: core::mem::take(&mut self.headers),
                body: input.get(..at).unwrap_or_default().to_vec(),
            })
        };
        self.state = if closed {
            State::Epilogue
        } else {
            State::Headers
        };
        self.scanned = 0;
        self.header_bytes = 0;
        Ok(match item {
            Some(part) => {
                self.parts = self.parts.saturating_add(1);
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
    /// `boundary` (without the leading `--`). Refuses invalid boundaries,
    /// malformed headers, missing closure, excessive parts, preambles or
    /// parts over [`MAX_PART`], and bodies over [`MAX_ENTITY`].
    pub fn parse(body: &[u8], boundary: &str) -> Result<Multipart, Error> {
        if body.len() > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        let mut decoder = Parts::new(boundary)?;
        let mut rest = body;
        let mut consumed = 0usize;
        let mut multipart = Self::default();
        loop {
            let preamble = decoder.state == State::Preamble;
            let used = match decoder.decode(rest, true)? {
                Step::Item(part, used) => {
                    multipart.parts.push(part);
                    used
                }
                Step::Skip(used) => used,
                Step::Need | Step::End => return Err(Error::Truncated),
            };
            if preamble && decoder.state != State::Preamble {
                multipart.preamble = body.get(..consumed).unwrap_or_default().to_vec();
            }
            consumed = consumed.checked_add(used).ok_or(Error::EntityTooLong)?;
            rest = rest.get(used..).unwrap_or_default();
            if decoder.state == State::Epilogue {
                multipart.epilogue = rest.to_vec();
                return Ok(multipart);
            }
        }
    }

    /// Pairs this body with an explicit boundary for a complete MIME entity.
    /// [`Wire::write`] checks the boundary and all body limits.
    pub fn with_boundary(self, boundary: impl Into<String>) -> Entity {
        Entity { boundary: boundary.into(), multipart: self }
    }

    /// Chooses a free boundary and returns a complete MIME entity.
    /// Refuses invalid boundary bases and bodies beyond the writer limits.
    pub fn with_free_boundary(self, base: &str) -> Result<Entity, Error> {
        let boundary = self.pick_boundary(base)?;
        Ok(self.with_boundary(boundary))
    }

    fn render(&self, boundary: &str) -> Result<Vec<u8>, Error> {
        self.validate()?;
        if !valid_boundary(boundary) {
            return Err(Error::Boundary);
        }
        let mut dash = b"--".to_vec();
        dash.extend_from_slice(boundary.as_bytes());
        if self.slices().iter().any(|s| find(s, &dash).is_some()) {
            return Err(Error::BoundaryInData);
        }
        let mut size = self.preamble.len()
            .checked_add(if self.preamble.is_empty() { 0 } else { 2 })
            .and_then(|n| n.checked_add(dash.len()))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(self.epilogue.len()))
            .ok_or(Error::EntityTooLong)?;
        for part in &self.parts {
            size = size.checked_add(header_block_size(part, header_separator(part).len()))
                .and_then(|n| n.checked_add(part.body.len()))
                .and_then(|n| n.checked_add(dash.len() + 4))
                .ok_or(Error::EntityTooLong)?;
        }
        if size > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        let mut out = Vec::with_capacity(size);
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
        if out.len() > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        Ok(out)
    }

    /// A boundary that appears nowhere in the preamble or the parts. It is
    /// `base` if that is free. Otherwise it is `base` (cut to 61
    /// characters), a hyphen and the lowest 8-digit hex number that makes
    /// it free. Refuses invalid bases and bodies beyond the writer limits.
    pub fn pick_boundary(&self, base: &str) -> Result<String, Error> {
        self.validate()?;
        if !valid_boundary(base) {
            return Err(Error::Boundary);
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
        let mut used = BTreeSet::new();
        for s in &slices {
            let mut at = 0;
            while let Some(i) = s.get(at..).and_then(|r| find(r, &needle)) {
                let start = at + i + needle.len();
                if let Some(hex) = s.get(start..start + 8)
                    && hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                        let text = core::str::from_utf8(hex).unwrap_or("");
                        if let Ok(n) = u32::from_str_radix(text, 16) {
                            used.insert(n);
                        }
                    }
                at = at + i + 1;
            }
        }
        let mut n: u32 = 0;
        while used.contains(&n) {
            n = n.checked_add(1).ok_or(Error::BoundaryInData)?;
        }
        Ok(format!("{prefix}{n:08x}"))
    }

    fn validate(&self) -> Result<(), Error> {
        if self.parts.len() > MAX_PARTS {
            return Err(Error::TooManyParts);
        }
        if self.preamble.len() > MAX_PART {
            return Err(Error::TooLong);
        }
        let mut size = self.preamble.len().saturating_add(self.epilogue.len());
        for part in &self.parts {
            let header = validate_part(part)?;
            size = size.saturating_add(header).saturating_add(part.body.len());
        }
        if size > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        Ok(())
    }

    /// Every byte string a boundary must not appear in: the preamble,
    /// each header line as [`Entity::write`] writes it, and each
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

/// A multipart body with a boundary and no outer MIME header.
/// Use it for HTTP bodies with any multipart subtype. Parsing takes the
/// boundary from the first delimiter line, so a preamble cannot be written.
/// A first line ending in `--` is a closing delimiter. Nonempty bodies
/// therefore cannot use a boundary ending in `--`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// The boundary, without its leading dashes.
    pub boundary: String,
    /// The parts and epilogue. The preamble must be empty to write.
    pub multipart: Multipart,
}

impl Wire for Body {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete body starting with its delimiter line. Refuses a
    /// preamble, invalid or colliding boundaries, malformed parts, missing
    /// closure, excessive counts, parts over [`MAX_PART`], and raw or
    /// canonical bodies over [`MAX_ENTITY`]. A first closing delimiter
    /// represents an empty body followed by its epilogue.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        let prefix = &input[..input.len().min(MAX_BOUNDARY_LINE)];
        let end = find(prefix, b"\r\n").unwrap_or(prefix.len());
        let line = core::str::from_utf8(&prefix[..end]).map_err(|_| Error::Boundary)?;
        let delimiter = line
            .strip_prefix("--")
            .ok_or(Error::Boundary)?
            .trim_end_matches([' ', '\t']);
        let boundary = delimiter.strip_suffix("--").unwrap_or(delimiter);
        let multipart = Multipart::parse(input, boundary)?;
        let body = Self {
            boundary: boundary.into(),
            multipart,
        };
        body.to_bytes().map_err(parse_error)?;
        Ok(body)
    }

    /// Appends only the multipart body. Refuses nonempty preambles and
    /// nonempty bodies whose boundary ends in `--` as [`Error::Unwritable`].
    /// Also refuses invalid or colliding boundaries, invalid headers,
    /// excessive counts, parts over [`MAX_PART`], and output over
    /// [`MAX_ENTITY`]. On error, `out` is unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.multipart.preamble.is_empty()
            || (!self.multipart.parts.is_empty() && self.boundary.ends_with("--"))
        {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&self.multipart.render(&self.boundary)?);
        Ok(())
    }
}

/// Maps a write refusal met while checking parsed input to the parse
/// error a reader reports for it.
fn parse_error(error: Error) -> Error {
    match error {
        Error::BoundaryInData => Error::Boundary,
        Error::HeaderName | Error::HeaderValue | Error::Unwritable => Error::Header,
        other => other,
    }
}

/// A complete `multipart/mixed` MIME entity with a `Content-Type` header.
/// Other subtypes use [`Body`] with an outer header supplied by the caller.
/// Read bodies with a known boundary using [`Multipart::parse`] or [`Parts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entity {
    /// The boundary, without its leading dashes.
    pub boundary: String,
    /// The multipart preamble, parts, and epilogue.
    pub multipart: Multipart,
}

impl Wire for Entity {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a `Content-Type: multipart/mixed` header, an empty line, and
    /// its complete body. Refuses other headers, extra parameters, invalid
    /// boundaries, malformed parts, missing closure, and entities over [`MAX_ENTITY`]
    /// in raw or canonical form. The chosen boundary must be absent from
    /// the preamble, part headers, and part bodies. Comments and spaces
    /// around the media type's slash are skipped as in [`boundary`].
    fn parse(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        let end = part_header_end(input, 0)?.ok_or(Error::Truncated)?;
        let headers = parse_headers(input.get(..end.saturating_sub(2)).unwrap_or_default())?;
        if headers.fields.len() != 1 {
            return Err(Error::Header);
        }
        let value = headers.get("content-type").ok_or(Error::Header)?;
        let cleaned = strip_comments(value).ok_or(Error::Header)?;
        let content_type = ParamValue::parse(cleaned.as_bytes())?;
        let (top, sub) = content_type.value.split_once('/').ok_or(Error::Header)?;
        if !top.trim_end_matches(is_wsp_char).eq_ignore_ascii_case("multipart")
            || !sub.trim_start_matches(is_wsp_char).eq_ignore_ascii_case("mixed")
            || content_type.params.len() != 1 {
            return Err(Error::Header);
        }
        let boundary = boundary(value).ok_or(Error::Boundary)?;
        let multipart = Multipart::parse(input.get(end..).unwrap_or_default(), &boundary)?;
        let entity = Self { boundary, multipart };
        // Canonical header spacing must also fit the entity cap.
        entity.to_bytes().map_err(parse_error)?;
        Ok(entity)
    }

    /// Appends the MIME header and body. Refuses invalid or colliding
    /// boundaries, invalid headers, excessive counts, parts or preambles
    /// over [`MAX_PART`], and entities over [`MAX_ENTITY`]. On error, `out`
    /// is unchanged. Header lines use `name: value`, or compact `name:value`
    /// when spaces would exceed the header or part cap. Preamble, body,
    /// and epilogue bytes are preserved.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let content_type = content_type("mixed", &self.boundary).ok_or(Error::Boundary)?;
        let mut bytes = b"Content-Type: ".to_vec();
        content_type.write(&mut bytes)?;
        bytes.extend_from_slice(b"\r\n\r\n");
        let body = self.multipart.render(&self.boundary)?;
        if bytes.len().saturating_add(body.len()) > MAX_ENTITY {
            return Err(Error::EntityTooLong);
        }
        bytes.extend_from_slice(&body);
        out.extend_from_slice(&bytes);
        Ok(())
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
/// part would pass [`MAX_HEADER_BYTES`] or [`MAX_PART`] with the spaces.
fn header_separator(part: &Part) -> &'static [u8] {
    let size = header_block_size(part, 2);
    if size <= MAX_HEADER_BYTES && size.saturating_add(part.body.len()) <= MAX_PART { b": " } else { b":" }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Preamble,
    Headers,
    Body,
    Epilogue,
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
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream, contract, finish, pump};
    use fictionet::stdlib::codec::{Lcg, test_support::decode_all};

    // Tests of raw HTTP bodies omit the entity's Content-Type header.
    fn raw(input: &[u8]) -> &[u8] {
        if input.starts_with(b"Content-Type: ") {
            &input[find(input, b"\r\n\r\n").unwrap() + 4..]
        } else {
            input
        }
    }

    fn check(input: &[u8], boundary: &str) {
        let input = raw(input);
        let make = || Parts::new(boundary).unwrap();
        contract::check_decode_with_alloc_limit(make, input, 2 * make().capacity());
        let (parts, error) = decode_all(make, input);
        match Multipart::parse(input, boundary) {
            Ok(multipart) => assert_eq!((parts, error), (multipart.parts, None)),
            Err(expected) if !input.is_empty() => match error {
                Some(Fail::Protocol(error)) => assert_eq!(error, expected),
                Some(Fail::Truncated { .. }) => assert_eq!(expected, Error::Truncated),
                other => panic!("{other:?}"),
            },
            Err(_) => assert!(input.is_empty()),
        }
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
        let m = Multipart::parse(raw(&body), &b).unwrap();
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
        let again = m.clone().with_boundary("simple boundary").to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&again), "simple boundary").unwrap(), m);
        assert_eq!(raw(&again), body);
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
        let m = Multipart::parse(raw(&body), &boundary("multipart/form-data; boundary=AaB03x").unwrap()).unwrap();
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
    fn parsed_bodies_write_as_entities() {
        for input in [
            b"--b--".as_slice(),
            b"preamble\r\n--b\r\nX:v\r\n\r\nbody\r\n--b--\r\nepilogue",
            b"--b\r\nX:v\r\n\r\nx--b and --b-00000000\r\n--b--",
        ] {
            let multipart = Multipart::parse(input, "b").unwrap();
            let entity = multipart.with_free_boundary("b").expect("a parsed body picks a boundary");
            let bytes = entity.to_bytes().expect("a parsed body writes again");
            assert_eq!(Entity::parse(&bytes).as_ref(), Ok(&entity));
            contract::check_wire_value(&Body {
                boundary: entity.boundary,
                multipart: entity.multipart,
            });
        }
    }

    #[test]
    fn parameter_write_errors_are_specific() {
        for (value, expected) in [
            (ParamValue { value: "x".into(), params: vec![("bad name".into(), "v".into())] }, Error::HeaderName),
            (ParamValue { value: "x\r\ny".into(), params: vec![] }, Error::HeaderValue),
            (ParamValue { value: "x".into(), params: vec![("n".into(), "v\n".into())] }, Error::HeaderValue),
            (ParamValue { value: "x".repeat(MAX_HEADER_BYTES + 1), params: vec![] }, Error::HeaderTooLong),
            (ParamValue { value: "x".into(), params: vec![("n".into(), "\"".repeat(MAX_HEADER_BYTES / 2))] }, Error::HeaderTooLong),
            (ParamValue { value: " x".into(), params: vec![] }, Error::HeaderValue),
            (ParamValue { value: "x;y".into(), params: vec![] }, Error::Unwritable),
            (ParamValue { value: "x".into(), params: vec![("n".into(), "v".into()), ("N".into(), "v".into())] }, Error::Unwritable),
        ] {
            let mut out = b"keep".to_vec();
            assert_eq!(value.write(&mut out), Err(expected));
            assert_eq!(out, b"keep");
            contract::check_wire_value(&value);
        }
    }

    #[test]
    fn entity_limits_and_parameter_refusals() {
        let part = Part {
            headers: Headers { fields: vec![("X".into(), "v".into())] },
            body: vec![b'x'; MAX_PART - 7],
        };
        let entity = Multipart { parts: vec![part], ..Multipart::default() }.with_boundary("b");
        // A compact header keeps a part exactly at its limit writable.
        contract::check_wire_value(&entity);
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(Entity::parse(&bytes), Ok(entity));
        let oversized = Multipart {
            epilogue: vec![b'e'; MAX_ENTITY], ..Multipart::default()
        }.with_boundary("b");
        assert_eq!(oversized.to_bytes(), Err(Error::EntityTooLong));
        contract::check_wire_value(&oversized);
        assert_eq!(Multipart::parse(&vec![b'x'; MAX_ENTITY + 1], "b"), Err(Error::EntityTooLong));
        let long = ParamValue { value: "x".repeat(MAX_HEADER_BYTES + 1), params: vec![] };
        assert_eq!(long.to_bytes(), Err(Error::HeaderTooLong));
        contract::check_wire_value(&long);
        assert_eq!(ParamValue::parse(b"x\r\ny"), Err(Error::Header));
        contract::check_wire::<ParamValue>(b"x;n=\"a b\"");
        assert_eq!(Entity::parse(b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx--b\r\n--b--\r\n"), Err(Error::Boundary));
        for input in [
            b"Content-Type: text/plain\r\n\r\n--b--".as_slice(),
            b"Content-Type: multipart/mixed; boundary=b\r\nX: y\r\n\r\n--b--",
            b"Content-Type: multipart/mixed; boundary=b; boundary=c\r\n\r\n--b--",
        ] {
            contract::check_wire::<Entity>(input);
            assert!(Entity::parse(input).is_err());
        }
    }

    #[test]
    fn parameters() {
        let v = ParamValue::parse(("form-data; name=\"a \\\"q\\\" \\\\ b\";filename=x.txt ; ;").as_bytes()).ok().unwrap();
        assert_eq!(v.value, "form-data");
        assert_eq!(v.get("NAME"), Some("a \"q\" \\ b"));
        assert_eq!(v.get("filename"), Some("x.txt"));
        assert_eq!(v.get("other"), None);
        assert_eq!(ParamValue::parse(&v.to_bytes().unwrap()).ok(), Some(v));
        let u = ParamValue::parse(("form-data; filename=\"résumé.pdf\"").as_bytes()).ok().unwrap();
        assert_eq!(u.get("filename"), Some("résumé.pdf"));
        assert_eq!(ParamValue::parse(("x; name = \"\"").as_bytes()).ok().unwrap().get("name"), Some(""));
        for bad in ["", " ; a=b", "x; =b", "x; a", "x; a=", "x; a=\"open", "x; a=b c", "x; a b=c", "x; a=@"] {
            assert_eq!(ParamValue::parse((bad).as_bytes()).ok(), None, "{bad:?}");
        }
        // A name given twice, in any case, is refused: readers that take
        // the first and readers that take the last would disagree.
        assert_eq!(ParamValue::parse(("form-data; name=a; NAME=b").as_bytes()).ok(), None);
        assert_eq!(
            ParamValue { value: "a".into(), params: vec![("n".into(), "1".into()), ("N".into(), "2".into())] }
                .to_bytes().ok().map(|bytes| String::from_utf8(bytes).unwrap()),
            None
        );
        let many: String = (0..=MAX_PARAMETERS).map(|i| format!("; p{i}=v")).collect();
        assert_eq!(ParamValue::parse(format!("x{many}").as_bytes()).ok(), None);
        let ok: String = (0..MAX_PARAMETERS).map(|i| format!("; p{i}=v")).collect();
        assert_eq!(ParamValue::parse(format!("x{ok}").as_bytes()).ok().unwrap().params.len(), MAX_PARAMETERS);
        // Writers refuse what would not read back the same.
        let w = |value: &str, name: &str, pv: &str| {
            ParamValue { value: value.into(), params: vec![(name.into(), pv.into())] }.to_bytes().ok().map(|bytes| String::from_utf8(bytes).unwrap())
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
        let ct = String::from_utf8(content_type("form-data", "a:b").unwrap().to_bytes().unwrap()).unwrap();
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
        assert_eq!(Parts::new("").err(), Some(Error::Boundary));
        assert_eq!(Multipart::parse(raw(b"--a--"), "a b ").err(), Some(Error::Boundary));
    }

    #[test]
    fn lenient_shapes() {
        // Padding after a boundary, an empty part with no blank line before
        // the next boundary, and a boundary-like line that is data.
        let body = b"--b \t\r\nX: 1\r\n\r\n--b\r\n\r\n--bad\r\n--b-x\r\n--b--";
        let m = Multipart::parse(raw(body), "b").unwrap();
        assert_eq!(m.parts.len(), 2);
        assert_eq!(m.parts[0].headers.get("x"), Some("1"));
        assert_eq!(m.parts[0].body, b"");
        assert_eq!(m.parts[1].body, b"--bad\r\n--b-x");
        // No parts at all.
        let m = Multipart::parse(raw(b"--b--"), "b").unwrap();
        assert_eq!(m, Multipart::default());
        // The closing line ends with padding and a line break, or with
        // padding and the end of the body.
        assert_eq!(Multipart::parse(raw(b"--b--  \r\nE"), "b").unwrap().epilogue, b"E");
        assert_eq!(Multipart::parse(raw(b"--b--  "), "b").unwrap().epilogue, b"");
        assert_eq!(Multipart::parse(raw(b"--b--  E"), "b"), Err(Error::Truncated));
        assert_eq!(Multipart::parse(raw(b"--b-- \r"), "b"), Err(Error::Truncated));
        // Folded header lines are joined.
        let m = Multipart::parse(raw(b"--b\r\nA:  one\r\n  two \r\n\tthree\r\n\r\nz\r\n--b--"), "b").unwrap();
        assert_eq!(m.parts[0].headers.get("a"), Some("one  two \tthree"));
        // A preamble that starts with CR LF.
        assert_eq!(Multipart::parse(raw(b"\r\n--b--"), "b").unwrap().preamble, b"");
        assert_eq!(Multipart::parse(raw(b"\r\n\r\n--b--"), "b").unwrap().preamble, b"\r\n");
    }

    #[test]
    fn header_errors() {
        let part = |h: &[u8]| {
            let mut v = b"--b\r\n".to_vec();
            v.extend_from_slice(h);
            v.extend_from_slice(b"\r\n\r\nbody\r\n--b--");
            Multipart::parse(raw(&v), "b")
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
        // The header cap is enforced before the part body ends.
        let mut input = b"--b\r\nA: ".to_vec();
        input.extend_from_slice(&vec![b'v'; MAX_HEADER_BYTES]);
        check(&input, "b");
        let mut stream = Stream::new(Parts::new("b").unwrap());
        let error = Fail::Protocol(Error::HeaderTooLong);
        assert_eq!(pump(&mut stream, &input, |_| panic!("invalid header")), Err(error.clone()));
        assert_eq!(stream.push(b"\r\n\r\n--b--"), 9);
        stream.end();
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
    }

    #[test]
    fn part_count_limit() {
        let mut ok = Multipart { parts: vec![Part::field("f", "v").unwrap(); MAX_PARTS], ..Multipart::default() };
        let bytes = ok.clone().with_boundary("b").to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), "b").unwrap(), ok);
        let mut over = String::new();
        for _ in 0..=MAX_PARTS {
            over.push_str("--b\r\n\r\n\r\n");
        }
        over.push_str("--b--");
        assert_eq!(Multipart::parse(raw(over.as_bytes()), "b"), Err(Error::TooManyParts));
        ok.parts.push(Part::default());
        assert_eq!(ok.clone().with_boundary("b").to_bytes(), Err(Error::TooManyParts));
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
        let bytes = m.clone().with_boundary("bound").to_bytes().unwrap();
        let bytes = raw(&bytes).to_vec();
        let close = find(&bytes, b"--bound--").unwrap() + 9;
        for n in 0..bytes.len() {
            let got = Multipart::parse(raw(&bytes[..n]), "bound");
            // A lone CR after the closing boundary does not end its line.
            if n < close || n == close + 1 {
                assert_eq!(got, Err(Error::Truncated), "{n} bytes");
            } else {
                let got = got.unwrap();
                assert_eq!(got.parts, m.parts, "{n} bytes");
            }
        }
        assert_eq!(Multipart::parse(raw(&bytes), "bound").unwrap(), m);
    }

    #[test]
    fn round_trips() {
        let m = sample();
        let entity = m.clone().with_free_boundary("bound").unwrap();
        let b = entity.boundary.clone();
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(b, "bound");
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
        assert_eq!(m.parts[1].filename().as_deref(), Some("C:\\a \"b\".txt"));
        let back = Multipart::parse(raw(&bytes), &b).unwrap();
        assert_eq!(back.parts[1].filename().as_deref(), Some("C:\\a \"b\".txt"));
        // Byte at a time, the same.
        check(&bytes, &b);
        // Empty preamble and epilogue.
        let bare = Multipart { parts: vec![Part::field("a", "").unwrap()], ..Multipart::default() };
        let bytes = bare.clone().with_boundary("z").to_bytes().unwrap();
        assert_eq!(raw(&bytes), b"--z\r\nContent-Disposition: form-data; name=a\r\n\r\n\r\n--z--\r\n");
        assert_eq!(Multipart::parse(raw(&bytes), "z").unwrap(), bare);
    }

    #[test]
    fn picking_a_boundary() {
        let mut m =
            Multipart { parts: vec![Part::field("x", "--XyZ and --XyZ-00000000").unwrap()], ..Multipart::default() };
        assert_eq!(m.clone().with_boundary("XyZ").to_bytes(), Err(Error::BoundaryInData));
        assert_eq!(m.pick_boundary("XyZ").unwrap(), "XyZ-00000001");
        m.preamble = b"--XyZ-00000001".to_vec();
        assert_eq!(m.pick_boundary("XyZ").unwrap(), "XyZ-00000002");
        let entity = m.clone().with_free_boundary("XyZ").unwrap();
        let b = entity.boundary.clone();
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
        // A long base is cut to fit.
        let base = "q".repeat(MAX_BOUNDARY);
        m.parts[0].body = format!("--{base}").into_bytes();
        let b = m.pick_boundary(&base).unwrap();
        assert!(valid_boundary(&b));
        assert_eq!(b.len(), MAX_BOUNDARY);
        assert_eq!(m.pick_boundary("bad;"), Err(Error::Boundary));
        // The boundary in a header counts too.
        let h = Multipart {
            parts: vec![Part { headers: Headers { fields: vec![("X".into(), "--k".into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(h.clone().with_boundary("k").to_bytes(), Err(Error::BoundaryInData));
        assert_eq!(h.pick_boundary("k").unwrap(), "k-00000000");
    }

    #[test]
    fn write_errors() {
        let with = |name: &str, value: &str| Multipart {
            parts: vec![Part { headers: Headers { fields: vec![(name.into(), value.into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(with("A", "v").clone().with_boundary("").to_bytes(), Err(Error::Boundary));
        assert!(with("A", "").clone().with_boundary("b").to_bytes().is_ok());
        assert_eq!(with("", "v").clone().with_boundary("b").to_bytes(), Err(Error::HeaderName));
        assert_eq!(with("A B", "v").clone().with_boundary("b").to_bytes(), Err(Error::HeaderName));
        assert_eq!(with("A:", "v").clone().with_boundary("b").to_bytes(), Err(Error::HeaderName));
        assert_eq!(with("A", "v\r\nX: y").clone().with_boundary("b").to_bytes(), Err(Error::HeaderValue));
        assert_eq!(with("A", " v").clone().with_boundary("b").to_bytes(), Err(Error::HeaderValue));
        assert_eq!(with("A", "v\t").clone().with_boundary("b").to_bytes(), Err(Error::HeaderValue));
        assert_eq!(with("A", &"v".repeat(MAX_HEADER_BYTES)).clone().with_boundary("b").to_bytes(), Err(Error::HeaderTooLong));
        let fits = with("A", &"v".repeat(MAX_HEADER_BYTES - 7));
        assert_eq!(Multipart::parse(raw(&fits.clone().with_boundary("b").to_bytes().unwrap()), "b").unwrap(), fits);
        let mut many = with("A", "v");
        many.parts[0].headers.fields = vec![("A".into(), "v".into()); MAX_HEADERS + 1];
        assert_eq!(many.clone().with_boundary("b").to_bytes(), Err(Error::TooManyHeaders));
        assert_eq!(Part::field("a\r\n", "v"), None);
        assert_eq!(Part::file("a", "f", "text/plain\r\n", "v"), None);
        assert_eq!(Part::file("a", "f\n", "text/plain", "v"), None);
    }

    #[test]
    fn parts_in_order_and_truncated_body() {
        let bytes = b"P\r\n--b\r\nA: 1\r\n\r\nxy\r\n--b--\r\nE";
        check(bytes, "b");
        assert_eq!(decode_all(|| Parts::new("b").unwrap(), bytes), (vec![Part {
            headers: Headers { fields: vec![("A".into(), "1".into())] }, body: b"xy".to_vec(),
        }], None));
        assert_eq!(decode_all(|| Parts::new("b").unwrap(), b"--b\r\n\r\nbody").1,
            Some(Fail::Protocol(Error::Truncated)));
    }

    #[test]
    fn complete_body_is_bounded() {
        let mut bytes = b"--bound\r\n\r\n".to_vec();
        bytes.extend_from_slice(&vec![b'\r'; 64_000]);
        bytes.extend_from_slice(b"\r\n--bound--");
        check(&bytes, "bound");
        let (parts, error) = decode_all(|| Parts::new("bound").unwrap(), &bytes);
        assert_eq!(error, None);
        assert_eq!(parts[0].body.len(), 64_000);
    }

    #[test]
    fn slow_headers_take_linear_time() {
        // Header blocks near the limit, decoded a byte at a time. The parser
        // looks at each new byte once, not at the whole block again.
        let mut part = format!("--b\r\nA: {}\r\n\r\nx\r\n", "v".repeat(MAX_HEADER_BYTES - 9)).into_bytes();
        part = part.repeat(64);
        part.extend_from_slice(b"--b--");
        let start = std::time::Instant::now();
        check(&part, "b");
        let m = Multipart::parse(&part, "b").unwrap();
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
        let m = Multipart::parse(raw(&body), "b").unwrap();
        assert_eq!(m.parts.len(), MAX_PARTS);
        assert!(m.parts.iter().all(|p| p.body.len() == 40_000));
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
        let mut stream = Stream::new(Parts::new("b").unwrap());
        let mut count = 0;
        pump(&mut stream, &body, |_| count += 1).unwrap();
        finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, MAX_PARTS);
        assert!(stream.into_parts().0.allocated() <= 2 * Parts::new("b").unwrap().capacity());
    }

    #[test]
    fn repeated_fields() {
        let body = b"--b\r\nContent-Disposition: form-data; name=a\r\n\
            content-disposition: form-data; name=b\r\nContent-Type: text/plain\r\n\
            X: 1\r\nx: 2\r\n\r\nv\r\n--b--";
        let m = Multipart::parse(raw(body), "b").unwrap();
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
        let entity = m.clone().with_free_boundary("b").unwrap();
        let b = entity.boundary.clone();
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
    }

    #[test]
    fn large_body_and_epilogue_use_bounded_storage() {
        for body in [
            [b"--b\r\n\r\n".as_slice(), &vec![b'x'; 1 << 20], b"\r\n--b--\r\n"].concat(),
            [b"--b--\r\n".as_slice(), &vec![b'e'; 1 << 20]].concat(),
        ] {
            check(&body, "b");
        }
    }

    // Finding: a boundary made of a header's name, the colon and its value.
    #[test]
    fn boundary_across_a_header_line() {
        let m = Multipart {
            parts: vec![Part { headers: Headers { fields: vec![("--x".into(), "y".into())] }, body: vec![] }],
            ..Multipart::default()
        };
        assert_eq!(m.clone().with_boundary("x: y").to_bytes(), Err(Error::BoundaryInData));
        let b = m.pick_boundary("x: y").unwrap();
        assert_ne!(b, "x: y");
        let bytes = m.clone().with_boundary(&b).to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
        // The same in the compact form.
        let mut c = m.clone();
        c.parts[0].headers.fields.push(("P".into(), "p".repeat(MAX_HEADER_BYTES - 14)));
        assert_eq!(header_separator(&c.parts[0]), b":");
        assert_eq!(c.clone().with_boundary("x:y").to_bytes(), Err(Error::BoundaryInData));
        let b = c.pick_boundary("x:y").unwrap();
        assert_eq!(Multipart::parse(raw(&c.clone().with_boundary(&b).to_bytes().unwrap()), &b).unwrap(), c);
    }

    // Finding: `--b--junk` closed the body.
    #[test]
    fn closing_line_must_end() {
        assert_eq!(Multipart::parse(raw(b"--b\r\n\r\nx\r\n--b--junk"), "b"), Err(Error::Truncated));
        let m = Multipart::parse(raw(b"--b\r\n\r\nx\r\n--b--junk\r\n--b--\r\nE"), "b").unwrap();
        assert_eq!(m.parts.len(), 1);
        assert_eq!(m.parts[0].body, b"x\r\n--b--junk");
        assert_eq!(m.epilogue, b"E");
        check(b"--b\r\n\r\nx\r\n--b-- \t", "b");
    }

    // Finding: a boundary line with too much padding became body data.
    #[test]
    fn too_much_padding_is_an_error() {
        let pad = " ".repeat(MAX_PADDING + 1);
        let body = format!("--b\r\n\r\nx\r\n--b{pad}\r\n\r\ny\r\n--b--");
        assert_eq!(Multipart::parse(raw(body.as_bytes()), "b"), Err(Error::Padding));
        check(body.as_bytes(), "b");
        let body = format!("--b\r\n\r\nx\r\n--b--{pad}");
        assert_eq!(Multipart::parse(raw(body.as_bytes()), "b"), Err(Error::Padding));
        let fits = " ".repeat(MAX_PADDING);
        let body = format!("--b{fits}\r\n\r\nx\r\n--b{fits}\r\n\r\ny\r\n--b--{fits}");
        assert_eq!(Multipart::parse(raw(body.as_bytes()), "b").unwrap().parts.len(), 2);
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

    #[test]
    fn entity_content_type_comments() {
        for value in [
            "multipart/mixed; boundary=b (comment)",
            "multipart / mixed; boundary=b",
            "(a (nested) \\) one) MULTIPART (x) / MIXED; boundary=\"(q)\"",
        ] {
            let boundary = boundary(value).unwrap();
            let input = format!("Content-Type: {value}\r\n\r\n--{boundary}--");
            let entity = Multipart::default().with_boundary(boundary);
            assert_eq!(Entity::parse(input.as_bytes()), Ok(entity.clone()));
            contract::check_wire_value(&entity);
        }
        for value in [
            "multipart/mixed; boundary=b (open",
            "multi(x)part/mixed; boundary=b",
            "multipart/form-data; boundary=b (comment)",
            "multipart/mixed; boundary=b; x=y (comment)",
        ] {
            let input = format!("Content-Type: {value}\r\n\r\n--b--");
            assert_eq!(Entity::parse(input.as_bytes()), Err(Error::Header));
        }
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
        let m = Multipart::parse(raw(&body), "b").unwrap();
        let entity = m.clone().with_free_boundary("b").unwrap();
        let b = entity.boundary.clone();
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
        // Folded lines get shorter when joined, so they fit too.
        let (v, w) = ("v".repeat(4000), "w".repeat(MAX_HEADER_BYTES - 4013));
        let folded = format!("--b\r\nA:{v}\r\n {w}\r\n\r\n\r\n--b--");
        let m = Multipart::parse(raw(folded.as_bytes()), "b").unwrap();
        let entity = m.clone().with_free_boundary("b").unwrap();
        let b = entity.boundary.clone();
        let bytes = entity.to_bytes().unwrap();
        assert_eq!(Multipart::parse(raw(&bytes), &b).unwrap(), m);
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
    fn generated_and_mutated_values() {
        let mut r = Lcg::new(0x5eed);
        let mut oks = 0;
        for round in 0..4000 {
            let mut data = Vec::new();
            for _ in 0..r.index(40) {
                if r.index(8) == 0 {
                    data.push(r.next() as u8);
                } else {
                    data.extend_from_slice(PIECES[r.index(PIECES.len())]);
                }
            }
            let whole = Multipart::parse(raw(&data), "a");
            check(&data, "a");
            if let Ok(m) = whole {
                oks += 1;
                let entity = m.clone().with_free_boundary("a").unwrap();
                contract::check_wire_value(&entity);
                let b = entity.boundary.clone();
                let bytes = entity.to_bytes().unwrap();
                assert_eq!(Entity::parse(&bytes).as_ref(), Ok(&entity));
                assert_eq!(Multipart::parse(raw(&bytes), &b).as_ref(), Ok(&m), "round {round}");
                for p in &m.parts {
                    let _ = (p.name(), p.filename(), p.headers.content_type());
                }
            }
            if let Ok(s) = std::str::from_utf8(&data) {
                if let Ok(v) = ParamValue::parse(s.as_bytes())
                    && let Some(h) = v.to_bytes().ok().map(|bytes| String::from_utf8(bytes).unwrap()) {
                        assert_eq!(ParamValue::parse(h.as_bytes()).ok(), Some(v));
                    }
                let _ = boundary(s);
            }
        }
        assert!(oks > 100, "only {oks} bodies parsed");

        // Structured bodies, with the boundary scattered through the data.
        for round in 0..2000 {
            let bytes = |r: &mut Lcg| -> Vec<u8> {
                let mut v = Vec::new();
                for _ in 0..r.index(6) {
                    v.extend_from_slice(PIECES[r.index(PIECES.len())]);
                }
                v
            };
            let mut m = Multipart { preamble: bytes(&mut r), parts: Vec::new(), epilogue: bytes(&mut r) };
            for _ in 0..r.index(5) {
                let name = String::from_utf8_lossy(&bytes(&mut r)).into_owned();
                let part = if r.index(2) == 0 {
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
            let base = ["a", "y", "a: y", "a:y", "-a"][r.index(5)];
            let entity = m.clone().with_free_boundary(base).unwrap();
            contract::check_wire_value(&entity);
            let b = entity.boundary.clone();
            let out = entity.to_bytes().unwrap();
            assert_eq!(Entity::parse(&out).as_ref(), Ok(&entity));
            assert_eq!(Multipart::parse(raw(&out), &b).as_ref(), Ok(&m), "round {round}");
            check(&out, &b);
            for p in &m.parts {
                if let Some(n) = p.name() {
                    assert!(!n.contains('\r'));
                }
            }
        }
    }
}
