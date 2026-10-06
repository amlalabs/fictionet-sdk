//! Internet Message Format headers: fields, addresses, dates, message IDs
//! and encoded words, with no I/O.
//!
//! Mail messages start with a header: lines of `Name: value`, then a blank
//! line, then the body. HTTP borrows the same layout for its own headers.
//! This module reads and writes that header. It follows RFC 5322 (the
//! message format), RFC 2047 (encoded words, such as
//! `=?utf-8?q?Caf=C3=A9?=`, which carry non-ASCII text in old mail) and
//! RFC 6532 (UTF-8 written directly in header fields).
//!
//! Nothing here reads a socket. A world that plays a mail server takes the
//! bytes of a message from its SMTP session and hands them to
//! [`split_message`], or uses [`Stream<Head>`](fictionet::stdlib::codec::Stream). It gets back a
//! [`Header`] of [`Field`]s and the body bytes. The structured fields are
//! read on demand: [`parse_address_list`] for `From`, `To` and `Cc`,
//! [`DateTime::parse`] for `Date`, [`MessageId::parse`] and
//! [`parse_message_ids`] for `Message-ID`, `In-Reply-To` and `References`,
//! and [`decode_text`] for `Subject`. What the server does with the
//! message is up to world code. After the header item, the body stays
//! unread for `Stream::swap` into a bounded collector or multipart decoder.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A header section is at most [`MAX_HEADER_BYTES`] long and holds
//! at most [`MAX_FIELDS`] fields. Comments nest at most
//! [`MAX_COMMENT_DEPTH`] deep. Every writer checks what it is given and
//! returns an [`Error`] rather than write something the readers here would
//! refuse.
//!
//! ```
//! use fictionet::stdlib::imf::{
//!     decode_text, parse_address_list, AddressList, Address, DateTime, Head, Header,
//! };
//! use fictionet::stdlib::codec::{Stream, Wire};
//!
//! let message = "From: John Doe <jdoe@machine.example>\r\n\
//!                Subject: =?utf-8?q?Caf=C3=A9?= hours\r\n\
//!                Date: Fri, 21 Nov 1997 09:55:06 -0600\r\n\
//!                \r\n\
//!                Is it open?\r\n";
//! let mut stream = Stream::new(Head::new());
//! assert_eq!(stream.push(message.as_bytes()), message.len());
//! let header = stream.next().unwrap().unwrap().unwrap();
//! assert_eq!(stream.next(), None);
//! assert_eq!(stream.unread(), b"Is it open?\r\n");
//!
//! let from = parse_address_list(header.get("from").unwrap()).unwrap();
//! let Address::Mailbox(sender) = &from[0] else { panic!("not a mailbox") };
//! assert_eq!(sender.name.as_deref(), Some("John Doe"));
//! assert_eq!(sender.local, "jdoe");
//! assert_eq!(sender.domain, "machine.example");
//!
//! assert_eq!(decode_text(header.get("Subject").unwrap()), "Café hours");
//! let date = DateTime::parse(header.get("Date").unwrap().as_bytes()).unwrap();
//! assert_eq!((date.year, date.month, date.day, date.zone), (1997, 11, 21, Some(-360)));
//!
//! // The reply's header.
//! let mut reply = Header::default();
//! reply.push("To", &String::from_utf8(AddressList(from).to_bytes().unwrap()).unwrap());
//! reply.push("Subject", "Re: Café hours");
//! let bytes = Wire::to_bytes(&reply).unwrap();
//! assert_eq!(bytes, "To: John Doe <jdoe@machine.example>\r\nSubject: Re: Café hours\r\n\r\n".as_bytes());
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The longest header section, counting the blank line that ends it.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// The most fields one header section may hold.
pub const MAX_FIELDS: usize = 256;
/// The longest structured value the parsers here read: an address list,
/// a date or a list of message IDs.
pub const MAX_VALUE_BYTES: usize = MAX_HEADER_BYTES;
/// The most addresses one address list may hold. A group counts as one,
/// and so does each of its members.
pub const MAX_ADDRESSES: usize = 1024;
/// The most message IDs one list may hold.
pub const MAX_MESSAGE_IDS: usize = 1024;
/// How deep comments, such as `(a (b) c)`, may nest.
pub const MAX_COMMENT_DEPTH: usize = 32;
/// The line length the writer folds to when a field has room to fold.
/// RFC 5322 asks for lines of at most 78 characters.
pub const FOLD_AT: usize = 78;
/// The longest line the writer writes, not counting its CRLF. RFC 5322
/// allows no longer line. [`Head`] and [`split_message`] take longer lines.
pub const MAX_LINE_BYTES: usize = 998;
/// The longest encoded word [`EncodedText`] writes and [`decode_word`]
/// reads, as RFC 2047 requires.
pub const ENCODED_WORD_LEN: usize = 75;
/// The line length the writer folds to when a field holds an encoded word.
/// RFC 2047 asks for lines of at most 76 characters there.
pub const ENCODED_LINE_LEN: usize = 76;

/// Why bytes or text are not what a reader expected, or why a writer
/// cannot write what it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The strict reader cannot preserve this header or value in the
    /// supported wire form. Lenient readers may accept it.
    UnsupportedForm,
    /// The header section, or a value, is longer than this module reads:
    /// [`MAX_HEADER_BYTES`] or [`MAX_VALUE_BYTES`].
    TooLarge,
    /// The header section holds more than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// A line has no colon, a field name is empty or holds a character
    /// names may not hold, or the header starts with a folded line.
    FieldName,
    /// A field value holds a NUL, or a carriage return that does not end
    /// a line.
    FieldValue,
    /// A field value is not UTF-8.
    Utf8,
    /// Text is not an address list.
    Address,
    /// A list holds more than [`MAX_ADDRESSES`] addresses or
    /// [`MAX_MESSAGE_IDS`] message IDs.
    TooManyItems,
    /// Text is not a date and time.
    Date,
    /// Text is not a message ID.
    MessageId,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::Unwritable => "value cannot be written without changing it",
            Error::UnsupportedForm => "unsupported header or value form",
            Error::TooLarge => "header or value too large",
            Error::TooManyFields => "too many header fields",
            Error::FieldName => "bad or missing field name",
            Error::FieldValue => "bad character in a field value",
            Error::Utf8 => "field value is not UTF-8",
            Error::Address => "not a well-formed address list",
            Error::TooManyItems => "too many addresses or message IDs",
            Error::Date => "not a well-formed date and time",
            Error::MessageId => "not a well-formed message ID",
        })
    }
}

impl std::error::Error for Error {}

/// One header field: its name and its value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// The name, as written. Names compare without regard to case.
    pub name: String,
    /// The value, unfolded: each line break that folded it is taken out,
    /// and the white space that began the next line is kept. White space
    /// after the colon is left out.
    pub value: String,
}

impl Field {
    /// Whether this field has the name `name`, in any case.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// A header section: its fields, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Header {
    /// The fields, in the order they came.
    pub fields: Vec<Field>,
}

impl Header {
    // Reads a bounded header prefix for split_message and Wire.
    fn prefix(b: &[u8]) -> Result<Option<(Header, usize)>, Error> {
        let window = &b[..b.len().min(MAX_HEADER_BYTES)];
        match find_end(window, 0) {
            Some((fields_end, end)) => Ok(Some((parse_fields(&b[..fields_end])?, end))),
            None if b.len() >= MAX_HEADER_BYTES => Err(Error::TooLarge),
            None => Ok(None),
        }
    }

    /// The value of the first field named `name`, in any case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.is(name)).map(|f| f.value.as_str())
    }

    /// The values of every field named `name`, in any case, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields.iter().filter(move |f| f.is(name)).map(|f| f.value.as_str())
    }

    /// Adds a field at the end.
    pub fn push(&mut self, name: &str, value: &str) {
        self.fields.push(Field { name: name.to_string(), value: value.to_string() });
    }
}

/// Why bytes do not contain exactly one writable header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Header fields or their strict encoding were refused.
    Header(Error),
    /// The terminating blank line has not arrived.
    Truncated,
    /// Bytes follow the terminating blank line.
    Trailing,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header(e) => e.fmt(f),
            Self::Truncated => f.write_str("IMF header ended before its blank line"),
            Self::Trailing => f.write_str("bytes follow the IMF header"),
        }
    }
}
impl core::error::Error for ParseError {}

impl Wire for Header {
    type ParseError = ParseError;
    type WriteError = Error;

    /// Reads one header through its blank line. Accepts CRLF or LF line
    /// endings and unfolds fields. Refuses trailing bytes, missing blank
    /// lines, invalid names or UTF-8, obsolete control text, and headers
    /// that exceed the field, line, or total size limits when written.
    /// Forms that cannot be preserved use [`Error::UnsupportedForm`].
    /// [`Head`] and [`split_message`] also read obsolete field text.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (header, used) = Self::prefix(bytes)
            .map_err(ParseError::Header)?
            .ok_or(ParseError::Truncated)?;
        if used != bytes.len() {
            return Err(ParseError::Trailing);
        }
        header
            .write(&mut Vec::new())
            .map_err(|_| ParseError::Header(Error::UnsupportedForm))?;
        Ok(header)
    }

    /// Appends `Name: value` fields and a terminating blank line, using
    /// CRLF. Folds before whitespace toward [`FOLD_AT`], or
    /// [`ENCODED_LINE_LEN`] for encoded words. Never splits a quoted pair
    /// or makes a whitespace-only continuation line. Refuses invalid names,
    /// leading value whitespace, controls other than tab, more than
    /// [`MAX_FIELDS`] fields, lines over [`MAX_LINE_BYTES`], or output over
    /// [`MAX_HEADER_BYTES`]. Returns [`Error::Unwritable`] and leaves `out`
    /// unchanged on refusal.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.fields.len() > MAX_FIELDS {
            return Err(Error::Unwritable);
        }
        let mut size = 2usize;
        for f in &self.fields {
            size = size
                .saturating_add(f.name.len())
                .saturating_add(f.value.len())
                .saturating_add(4);
            if size > MAX_HEADER_BYTES
                || !valid_name(f.name.as_bytes())
                || f.value.starts_with([' ', '\t'])
                || f.value.contains(is_control)
            {
                return Err(Error::Unwritable);
            }
        }
        let mut bytes = Vec::new();
        for f in &self.fields {
            let start = bytes.len();
            // At most one CRLF per input byte, so staging stays bounded.
            fold(&mut bytes, &f.name, f.value.as_bytes());
            if bytes.len() > MAX_HEADER_BYTES - 2
                || bytes[start..]
                    .split(|&c| c == b'\n')
                    .any(|l| l.len() > MAX_LINE_BYTES + 1)
            {
                return Err(Error::Unwritable);
            }
        }
        bytes.extend_from_slice(b"\r\n");
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads one header item, then returns [`Step::End`] unconditionally.
///
/// The enclosing SMTP or MIME layer supplies EOF. A blank line ends the
/// header; all following bytes remain unread for [`fictionet::stdlib::codec::Stream::swap`]
/// into a body collector or a multipart decoder. No input bytes are retained.
/// Capacity is the header limit, including the terminating blank line.
///
/// At EOF, non-empty input below the limit without a blank line is the
/// whole header, as RFC 5322 allows. Empty input at EOF is a clean end with
/// no item. Reaching the limit without a blank line ends the stream with
/// [`Error::TooLarge`]. Field errors are error items, followed by End too.
///
/// ```
/// use fictionet::stdlib::{codec::{Collect, Stream, Wire, finish, pump}, imf::Head};
/// use core::convert::Infallible;
///
/// // The world chooses a body type and a total size limit.
/// const MAX_MAIL_BODY: usize = 16 * 1024 * 1024;
/// struct Body(Vec<u8>);
/// impl Wire for Body {
///     type ParseError = Infallible;
///     type WriteError = Infallible;
///     /// Copies bytes unchanged. The collector bounds their length. Refuses no bytes.
///     fn parse(bytes: &[u8]) -> Result<Self, Infallible> { Ok(Self(bytes.to_vec())) }
///     /// Appends bytes unchanged. Refuses no values.
///     fn write(&self, out: &mut Vec<u8>) -> Result<(), Infallible> {
///         out.extend_from_slice(&self.0);
///         Ok(())
///     }
/// }
/// let input = b"Subject: hi\r\n\r\nhello";
/// let mut stream = Stream::new(Head::new());
/// let accepted = pump(&mut stream, input, |header| {
///     assert_eq!(header.unwrap().get("Subject"), Some("hi"));
/// }).unwrap();
/// assert!(stream.is_done());
/// let mut body = stream.swap(Collect::<Body>::new(MAX_MAIL_BODY));
/// pump(&mut body, &input[accepted..], |_| unreachable!()).unwrap();
/// finish(&mut body, |Body(bytes)| assert_eq!(bytes, b"hello")).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Head {
    header_limit: usize,
    scanned: usize,
    done: bool,
}

impl Head {
    /// Reads headers up to [`MAX_HEADER_BYTES`].
    pub fn new() -> Self {
        Self::with_limit(MAX_HEADER_BYTES)
    }

    /// Sets the header limit, including the blank line, clamped from 1
    /// through [`MAX_HEADER_BYTES`].
    pub fn with_limit(header_limit: usize) -> Self {
        Self {
            header_limit: header_limit.clamp(1, MAX_HEADER_BYTES),
            scanned: 0,
            done: false,
        }
    }

    /// The largest header, including its terminating blank line.
    pub fn header_limit(&self) -> usize {
        self.header_limit
    }
}

impl Default for Head {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Head {
    type Item = Result<Header, Error>;
    type Error = Error;
    const NAME: &'static str = "IMF";

    fn capacity(&self) -> usize {
        self.header_limit
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.done {
            return Ok(Step::End);
        }
        let window = input
            .get(..input.len().min(self.header_limit))
            .ok_or(Error::TooLarge)?;
        if let Some((fields_end, end)) = find_end(window, self.scanned) {
            let fields = window.get(..fields_end).ok_or(Error::TooLarge)?;
            self.done = true;
            return Ok(Step::Item(parse_fields(fields), end));
        }
        if window.len() == self.header_limit {
            return Err(Error::TooLarge);
        }
        if eof && !window.is_empty() {
            self.done = true;
            return Ok(Step::Item(parse_fields(window), window.len()));
        }
        self.scanned = window.len().saturating_sub(1);
        Ok(Step::Need)
    }
}

/// Splits a whole message into its header and its body. A message with no
/// blank line is all header, with an empty body, as RFC 5322 allows.
pub fn split_message(b: &[u8]) -> Result<(Header, &[u8]), Error> {
    match Header::prefix(b)? {
        Some((header, used)) => Ok((header, &b[used..])),
        None => Ok((parse_fields(b)?, &b[b.len()..])),
    }
}

/// Where the first blank line in `b` starts and ends, looking at lines
/// that start at `from` or later.
fn find_end(b: &[u8], from: usize) -> Option<(usize, usize)> {
    for i in from..b.len() {
        if i != 0 && b[i - 1] != b'\n' {
            continue;
        }
        match b[i] {
            b'\n' => return Some((i, i + 1)),
            b'\r' if b.get(i + 1) == Some(&b'\n') => return Some((i, i + 2)),
            _ => {}
        }
    }
    None
}

/// Reads the fields in `b`, which holds no blank line except, perhaps, a
/// lone carriage return at the end.
fn parse_fields(b: &[u8]) -> Result<Header, Error> {
    let mut fields = Vec::new();
    let mut current: Option<(&[u8], Vec<u8>)> = None;
    let mut rest = b;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(&first) = line.first() else { break };
        if first == b' ' || first == b'\t' {
            match current.as_mut() {
                Some((_, value)) => value.extend_from_slice(line),
                None => return Err(Error::FieldName),
            }
            continue;
        }
        if let Some((name, value)) = current.take() {
            fields.push(finish(name, value)?);
        }
        let colon = line.iter().position(|&c| c == b':').ok_or(Error::FieldName)?;
        // The obsolete syntax allows white space before the colon.
        let mut name = &line[..colon];
        while let [rest @ .., b' ' | b'\t'] = name {
            name = rest;
        }
        if !valid_name(name) {
            return Err(Error::FieldName);
        }
        if fields.len() >= MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        current = Some((name, line[colon + 1..].to_vec()));
    }
    if let Some((name, value)) = current {
        fields.push(finish(name, value)?);
    }
    Ok(Header { fields })
}

/// A field from its name and its unfolded value's bytes.
fn finish(name: &[u8], value: Vec<u8>) -> Result<Field, Error> {
    if value.iter().any(|&c| c == 0 || c == b'\r') {
        return Err(Error::FieldValue);
    }
    let start = value.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(value.len());
    let value = String::from_utf8(value[start..].to_vec()).map_err(|_| Error::Utf8)?;
    let name = String::from_utf8(name.to_vec()).map_err(|_| Error::FieldName)?;
    Ok(Field { name, value })
}

/// Whether `name` is a field name: printable ASCII with no colon or space.
fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&c| (33..=126).contains(&c) && c != b':')
}

/// Writes `name: value` and CRLF, folding before white space.
fn fold(out: &mut Vec<u8>, name: &str, v: &[u8]) {
    // RFC 2047 section 2: a line holding an encoded word is at most 76
    // characters long.
    let limit = if v.windows(2).any(|w| w == b"=?") { ENCODED_LINE_LEN } else { FOLD_AT };
    let is_ws = |c: u8| c == b' ' || c == b'\t';
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    // Fold right after the colon when the first word fits on a line of
    // its own but not after the name.
    let first = v.iter().position(|&c| is_ws(c)).unwrap_or(v.len());
    let mut used = name.len() + 2;
    if first > 0 && used + first > limit && first < limit {
        out.extend_from_slice(b"\r\n");
        used = 1;
    }
    out.push(b' ');
    let last_text = v.iter().rposition(|&c| !is_ws(c)).unwrap_or(0);
    let mut start = 0;
    loop {
        let rest = &v[start..];
        if used + rest.len() <= limit {
            out.extend_from_slice(rest);
            break;
        }
        // Fold before white space, where the line so far holds some text
        // and some text is left for the next line: RFC 5322 allows no
        // line of white space alone. White space after a backslash is the
        // second half of a quoted-pair, which a fold may not split.
        let (mut within, mut beyond) = (None, None);
        let (mut text, mut escaped) = (false, false);
        for (j, &c) in v.iter().enumerate().take(last_text).skip(start) {
            if is_ws(c) && text && !escaped {
                if used + (j - start) <= limit {
                    within = Some(j);
                } else {
                    beyond = Some(j);
                    break;
                }
            }
            text |= !is_ws(c);
            escaped = c == b'\\' && !escaped;
        }
        match within.or(beyond) {
            Some(j) => {
                out.extend_from_slice(&v[start..j]);
                out.extend_from_slice(b"\r\n");
                start = j;
                used = 0;
            }
            None => {
                out.extend_from_slice(rest);
                break;
            }
        }
    }
    out.extend_from_slice(b"\r\n");
}

/// One mailbox: an address, and the display name that may come with it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Mailbox {
    /// The display name, with quoting taken off and encoded words decoded.
    /// `None` when the address came alone.
    pub name: Option<String>,
    /// The part before the `@`, with quoting taken off.
    pub local: String,
    /// The part after the `@`. A domain literal keeps its brackets, as in
    /// `[192.0.2.1]`.
    pub domain: String,
}

/// One entry of an address list: a mailbox, or a named group of them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// A single mailbox.
    Mailbox(Mailbox),
    /// A group, such as `Team: a@x.test, b@x.test;`. Its member list may
    /// be empty, as in `Undisclosed recipients:;`.
    Group {
        /// The group's display name.
        name: String,
        /// The mailboxes in the group.
        members: Vec<Mailbox>,
    },
}

impl Mailbox {
    fn render(&self) -> Result<String, Error> {
        // The text is at least as long as its parts.
        let parts = self
            .name
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(self.local.len())
            .saturating_add(self.domain.len())
            .saturating_add(1);
        if parts > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut out = String::new();
        if let Some(name) = &self.name {
            write_phrase(&mut out, name)?;
            out.push_str(" <");
        }
        write_local(&mut out, &self.local, Error::Address)?;
        out.push('@');
        write_domain(&mut out, &self.domain, Error::Address, true)?;
        if self.name.is_some() {
            out.push('>');
        }
        fits(out)
    }
}

impl Address {
    fn render(&self) -> Result<String, Error> {
        match self {
            Address::Mailbox(m) => m.render(),
            Address::Group { name, members } => {
                if self.weight() > MAX_ADDRESSES {
                    return Err(Error::TooManyItems);
                }
                if name.len() > MAX_VALUE_BYTES {
                    return Err(Error::TooLarge);
                }
                let mut out = String::new();
                write_phrase(&mut out, name)?;
                out.push(':');
                for (k, m) in members.iter().enumerate() {
                    if k > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&m.render()?);
                    if out.len() > MAX_VALUE_BYTES {
                        return Err(Error::TooLarge);
                    }
                }
                out.push(';');
                fits(out)
            }
        }
    }

    /// How many entries this counts as against [`MAX_ADDRESSES`].
    fn weight(&self) -> usize {
        match self {
            Address::Mailbox(_) => 1,
            Address::Group { members, .. } => members.len().saturating_add(1),
        }
    }
}

/// Reads an address list, such as the value of `From`, `To` or `Cc`.
/// Comments and folding white space may come between any two parts.
/// Empty entries (`a@x.test, , b@x.test`) are skipped, as RFC 5322's
/// obsolete syntax allows, and so is a source route inside angle brackets.
pub fn parse_address_list(s: &str) -> Result<Vec<Address>, Error> {
    if s.len() > MAX_VALUE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut p = Parser::new(s).ok_or(Error::Address)?;
    let mut out = Vec::new();
    let mut count = 0;
    loop {
        while p.eat(',') {}
        if p.done() {
            break;
        }
        out.push(p.address(&mut count)?);
        if p.done() {
            break;
        }
        if !p.eat(',') {
            return Err(Error::Address);
        }
    }
    Ok(out)
}

fn render_address_list(list: &[Address]) -> Result<String, Error> {
    if list
        .iter()
        .map(Address::weight)
        .fold(0usize, usize::saturating_add)
        > MAX_ADDRESSES
    {
        return Err(Error::TooManyItems);
    }
    let mut out = String::new();
    for (k, a) in list.iter().enumerate() {
        if k > 0 {
            out.push_str(", ");
        }
        out.push_str(&a.render()?);
        if out.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
    }
    Ok(out)
}

/// A message ID, such as `<1234@local.machine.example>`, without its
/// angle brackets.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MessageId {
    /// The part before the `@`, with any quoting taken off.
    pub left: String,
    /// The part after the `@`. A literal keeps its brackets.
    pub right: String,
}

impl MessageId {
    fn read(s: &str) -> Result<MessageId, Error> {
        match &read_message_ids(s, false)?[..] {
            [id] => Ok(id.clone()),
            _ => Err(Error::MessageId),
        }
    }

    fn render(&self) -> Result<String, Error> {
        if self
            .left
            .len()
            .saturating_add(self.right.len())
            .saturating_add(3)
            > MAX_VALUE_BYTES
        {
            return Err(Error::TooLarge);
        }
        if !is_dot_atom(&self.left) {
            return Err(Error::MessageId);
        }
        let mut out = format!("<{}@", self.left);
        write_domain(&mut out, &self.right, Error::MessageId, false)?;
        out.push('>');
        Ok(out)
    }
}

/// Reads a list of message IDs, such as the value of `References` or
/// `In-Reply-To`. An empty value gives an empty list. Old mail may put
/// phrases between the IDs, as in `In-Reply-To: Your message of "Mon, 1
/// Jan" <a@x.test>`. RFC 5322's obsolete syntax allows them, and they are
/// skipped.
pub fn parse_message_ids(s: &str) -> Result<Vec<MessageId>, Error> {
    read_message_ids(s, true)
}

/// Reads message IDs, skipping phrases between them when `phrases` is set.
fn read_message_ids(s: &str, phrases: bool) -> Result<Vec<MessageId>, Error> {
    if s.len() > MAX_VALUE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut p = Parser::new(s).ok_or(Error::MessageId)?;
    let mut out = Vec::new();
    while !p.done() {
        if phrases {
            let words = p.words();
            if !words.is_empty() {
                // A phrase starts with a word, not a dot.
                p.phrase(words).ok_or(Error::MessageId)?;
                continue;
            }
        }
        if out.len() >= MAX_MESSAGE_IDS {
            return Err(Error::TooManyItems);
        }
        out.push(p.message_id().ok_or(Error::MessageId)?);
    }
    Ok(out)
}

fn render_message_ids(ids: &[MessageId]) -> Result<String, Error> {
    if ids.len() > MAX_MESSAGE_IDS {
        return Err(Error::TooManyItems);
    }
    let mut out = String::new();
    for (k, id) in ids.iter().enumerate() {
        if k > 0 {
            out.push(' ');
        }
        out.push_str(&id.render()?);
        if out.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
    }
    Ok(out)
}

/// A date and time from a `Date` field, in its parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DateTime {
    /// The day of the week, if the field named one: 0 is Monday and 6 is
    /// Sunday. RFC 5322 requires it to be the date's own, and readers and
    /// writers both check it.
    pub weekday: Option<u8>,
    /// The year, from 1900 to 9999. Two-digit years from the obsolete
    /// syntax are read as 2000 to 2049 below 50, and 1950 to 1999 from 50
    /// up. Three-digit years have 1900 added.
    pub year: u16,
    /// The month, from 1 (January) to 12.
    pub month: u8,
    /// The day of the month, from 1.
    pub day: u8,
    /// The hour, from 0 to 23.
    pub hour: u8,
    /// The minute, from 0 to 59.
    pub minute: u8,
    /// The second, from 0 to 60 (a leap second). 0 when the field left
    /// seconds out.
    pub second: u8,
    /// The zone's offset from UTC in minutes, east positive: `-0600` is
    /// `Some(-360)`. Obsolete zone names (`GMT`, `EST` and so on) are read
    /// as their offsets. `None` is `-0000`, which RFC 5322 uses for a time
    /// in UTC whose local zone is unknown. Military letters are read as
    /// `None` too, as RFC 5322 section 4.3 asks.
    pub zone: Option<i16>,
}

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ZONES: [(&str, i16); 10] = [
    ("UT", 0),
    ("GMT", 0),
    ("EST", -300),
    ("EDT", -240),
    ("CST", -360),
    ("CDT", -300),
    ("MST", -420),
    ("MDT", -360),
    ("PST", -480),
    ("PDT", -420),
];
/// The largest zone offset a `+hhmm` zone can write: 99 hours, 59 minutes.
const MAX_ZONE: i32 = 99 * 60 + 59;

impl DateTime {
    fn read(s: &str) -> Result<DateTime, Error> {
        if s.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        let toks = lex(s).ok_or(Error::Date)?;
        read_date(&toks).ok_or(Error::Date)
    }

    fn render(&self) -> Result<String, Error> {
        if !self.valid() {
            return Err(Error::Unwritable);
        }
        let zone = i32::from(self.zone.unwrap_or(0));
        let mut out = String::new();
        if let Some(w) = self.weekday {
            out.push_str(DAYS[usize::from(w)]);
            out.push_str(", ");
        }
        let sign = if zone < 0 || self.zone.is_none() { '-' } else { '+' };
        out.push_str(&format!(
            "{} {} {:04} {:02}:{:02}:{:02} {sign}{:02}{:02}",
            self.day,
            MONTHS[usize::from(self.month - 1)],
            self.year,
            self.hour,
            self.minute,
            self.second,
            zone.abs() / 60,
            zone.abs() % 60,
        ));
        Ok(out)
    }
    fn valid(&self) -> bool {
        let zone = i32::from(self.zone.unwrap_or(0));
        (1900..=9999).contains(&self.year)
            && (1..=12).contains(&self.month)
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 60
            && self
                .weekday
                .is_none_or(|w| w == weekday(self.year, self.month, self.day))
            && zone.abs() <= MAX_ZONE
    }
}

fn read_date(t: &[Lexed]) -> Option<DateTime> {
    let atom = |k: usize| match t.get(k).map(|l| &l.tok) {
        Some(Tok::Atom(a)) => Some(a.as_str()),
        _ => None,
    };
    let special = |k: usize, c: char| matches!(t.get(k).map(|l| &l.tok), Some(Tok::Special(x)) if *x == c);
    let mut i = 0;
    let weekday = if special(1, ',') {
        i = 2;
        let name = atom(0)?;
        Some(DAYS.iter().position(|d| d.eq_ignore_ascii_case(name))? as u8)
    } else {
        None
    };
    let day = digits(atom(i)?, 1, 2)? as u8;
    let name = atom(i + 1)?;
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name))? as u8 + 1;
    let y = atom(i + 2)?;
    // A year is four or more digits, or two or three in the obsolete
    // syntax. Zeros in front of a long year count for nothing.
    let year = match y.len() {
        0 | 1 => return None,
        2 | 3 => digits(y, 2, 3)?,
        _ if y.bytes().all(|c| c.is_ascii_digit()) => digits(y.trim_start_matches('0'), 0, 4)?,
        _ => return None,
    };
    let year = match y.len() {
        2 if year < 50 => year + 2000,
        2 => year + 1900,
        3 => year + 1900,
        _ => year,
    } as u16;
    let hour = digits(atom(i + 3)?, 2, 2)? as u8;
    if !special(i + 4, ':') {
        return None;
    }
    let minute = digits(atom(i + 5)?, 2, 2)? as u8;
    i += 6;
    let mut second = 0;
    if special(i, ':') {
        second = digits(atom(i + 1)?, 2, 2)? as u8;
        i += 2;
    }
    let zone = read_zone(atom(i)?)?;
    if i + 1 != t.len() {
        return None;
    }
    let date = DateTime { weekday, year, month, day, hour, minute, second, zone };
    date.valid().then_some(date)
}

/// A zone: `Some` offset, or `Some(None)` for an unknown one.
fn read_zone(s: &str) -> Option<Option<i16>> {
    let b = s.as_bytes();
    if b.len() == 5 && (b[0] == b'+' || b[0] == b'-') {
        let n = digits(&s[1..], 4, 4)?;
        if n % 100 > 59 {
            return None;
        }
        let minutes = (n / 100 * 60 + n % 100) as i16;
        return Some(match b[0] {
            b'-' if minutes == 0 => None,
            b'-' => Some(-minutes),
            _ => Some(minutes),
        });
    }
    if let Some(&(_, z)) = ZONES.iter().find(|(name, _)| name.eq_ignore_ascii_case(s)) {
        return Some(Some(z));
    }
    match b {
        [c] if c.is_ascii_alphabetic() && !c.eq_ignore_ascii_case(&b'j') => Some(None),
        _ => None,
    }
}

/// The number written in `s`, if it is `min` to `max` ASCII digits. No
/// digits at all is 0.
fn digits(s: &str, min: usize, max: usize) -> Option<u32> {
    if s.len() < min || s.len() > max || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

/// The day of the week of a date, 0 for Monday to 6 for Sunday. The
/// month must be 1 to 12.
fn weekday(year: u16, month: u8, day: u8) -> u8 {
    // Sakamoto's method, which counts from Sunday.
    const T: [u32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = u32::from(year) - u32::from(month < 3);
    let from_sunday = (y + y / 4 - y / 100 + y / 400 + T[usize::from(month - 1)] + u32::from(day)) % 7;
    ((from_sunday + 6) % 7) as u8
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Decodes one RFC 2047 encoded word, such as `=?utf-8?q?Caf=C3=A9?=`.
/// It reads the `B` (base64) and `Q` encodings, and the character sets
/// UTF-8, US-ASCII and ISO-8859-1, with any `*language` suffix ignored. It
/// returns `None` for anything else, for text that does not decode, and
/// for text that decodes to a NUL, carriage return or line feed, which no
/// header may hold. A word longer than [`ENCODED_WORD_LEN`] is not an
/// encoded word, as RFC 2047 says, and is `None` too.
pub fn decode_word(word: &str) -> Option<String> {
    if word.len() > ENCODED_WORD_LEN {
        return None;
    }
    let inner = word.strip_prefix("=?")?.strip_suffix("?=")?;
    let (charset, rest) = inner.split_once('?')?;
    let (encoding, text) = rest.split_once('?')?;
    if text.is_empty() || text.bytes().any(|c| !(0x21..=0x7e).contains(&c) || c == b'?') {
        return None;
    }
    let bytes = match encoding {
        "B" | "b" => base64_decode(text.as_bytes())?,
        "Q" | "q" => q_decode(text.as_bytes())?,
        _ => return None,
    };
    let charset = charset.split('*').next().unwrap_or("").to_ascii_lowercase();
    let decoded = match charset.as_str() {
        "utf-8" | "utf8" => String::from_utf8(bytes).ok()?,
        "us-ascii" | "ascii" if bytes.is_ascii() => String::from_utf8(bytes).ok()?,
        "iso-8859-1" | "iso_8859-1" | "latin1" => bytes.iter().map(|&c| char::from(c)).collect(),
        _ => return None,
    };
    if decoded.contains(['\0', '\r', '\n']) {
        return None;
    }
    Some(decoded)
}

/// Decodes the encoded words in unstructured text, such as a `Subject`.
/// Each word that stands alone between white space and decodes is
/// replaced by its text, and white space between two such words is left
/// out, as RFC 2047 says. Anything else stays as it is.
pub fn decode_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = "";
    let mut after_word = false;
    let mut rest = s;
    while !rest.is_empty() {
        let ws = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        if ws > 0 {
            space = &rest[..ws];
            rest = &rest[ws..];
            continue;
        }
        let n = rest.find([' ', '\t']).unwrap_or(rest.len());
        let token = &rest[..n];
        rest = &rest[n..];
        match decode_word(token) {
            Some(d) => {
                if !after_word {
                    out.push_str(space);
                }
                out.push_str(&d);
                after_word = true;
            }
            None => {
                out.push_str(space);
                out.push_str(token);
                after_word = false;
            }
        }
        space = "";
    }
    out.push_str(space);
    out
}

/// Text as RFC 2047 encoded words in UTF-8 and base64, split by spaces,
/// each at most [`ENCODED_WORD_LEN`] long. [`decode_text`] reads it back.
/// The caller checks the size and refuses NUL, carriage return, and line feed.
/// Empty text gives an empty string.
fn encoded_text(s: &str) -> String {
    const PREFIX: &str = "=?utf-8?b?";
    // Each 3 bytes become 4 characters, inside the prefix and "?=".
    const CHUNK: usize = (ENCODED_WORD_LEN - PREFIX.len() - 2) / 4 * 3;
    let mut out = String::new();
    let mut chunk = String::new();
    let flush = |chunk: &mut String, out: &mut String| {
        if chunk.is_empty() {
            return;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(PREFIX);
        out.push_str(&base64_encode(chunk.as_bytes()));
        out.push_str("?=");
        chunk.clear();
    };
    for c in s.chars() {
        if chunk.len() + c.len_utf8() > CHUNK {
            flush(&mut chunk, &mut out);
        }
        chunk.push(c);
    }
    flush(&mut chunk, &mut out);
    out
}

/// An address list used by From, To, or Cc.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddressList(
    /// Mailboxes and groups, in order.
    pub Vec<Address>,
);

/// A list of message IDs used by References or In-Reply-To.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MessageIds(
    /// Message IDs, in order.
    pub Vec<MessageId>,
);

/// Decoded unstructured text written as RFC 2047 UTF-8 base64 words.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EncodedText(
    /// Text to encode. NUL, carriage return, and line feed are refused.
    pub String,
);

impl Mailbox {
    fn read(text: &str) -> Result<Self, Error> {
        match &parse_address_list(text)?[..] {
            [Address::Mailbox(mailbox)] => Ok(mailbox.clone()),
            _ => Err(Error::Address),
        }
    }
}
impl Address {
    fn read(text: &str) -> Result<Self, Error> {
        match &parse_address_list(text)?[..] {
            [address] => Ok(address.clone()),
            _ => Err(Error::Address),
        }
    }
}
impl AddressList {
    fn read(text: &str) -> Result<Self, Error> {
        parse_address_list(text).map(Self)
    }
    fn render(&self) -> Result<String, Error> {
        render_address_list(&self.0)
    }
}
impl MessageIds {
    fn read(text: &str) -> Result<Self, Error> {
        parse_message_ids(text).map(Self)
    }
    fn render(&self) -> Result<String, Error> {
        render_message_ids(&self.0)
    }
}
impl EncodedText {
    fn read(text: &str) -> Result<Self, Error> {
        Ok(Self(decode_text(text)))
    }
    fn render(&self) -> Result<String, Error> {
        if self.0.len() > MAX_VALUE_BYTES || self.0.contains(['\0', '\r', '\n']) {
            return Err(Error::Unwritable);
        }
        fits(encoded_text(&self.0))
    }
}

// All structured text units use the same bounded, transactional writer.
// Permissive readers above retain obsolete syntax for inspecting old mail.
macro_rules! text_wire {
    ($ty:ty, $parse:literal, $write:literal) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            #[doc = $parse]
            /// Forms that cannot be preserved use [`Error::UnsupportedForm`].
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > MAX_VALUE_BYTES {
                    return Err(Error::TooLarge);
                }
                let text = std::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                let value = Self::read(text)?;
                value
                    .write(&mut Vec::new())
                    .map_err(|_| Error::UnsupportedForm)?;
                Ok(value)
            }

            #[doc = $write]
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let text = self.render().map_err(|_| Error::Unwritable)?;
                if text.len() > MAX_VALUE_BYTES || Self::read(&text).as_ref() != Ok(self) {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(text.as_bytes());
                Ok(())
            }
        }
    };
}

text_wire!(
    Mailbox,
    "Reads one mailbox, allowing comments, folds, and source routes. Refuses invalid UTF-8, lists or groups, oversized text, and obsolete local parts or literals that cannot be written unchanged.",
    "Appends `Name <local@domain>`, or `local@domain` without a name, as UTF-8 text. Quotes names and local parts when needed; encodes controls in display names as RFC 2047 words. Refuses NUL, CR, or LF in names, controls other than tab in local parts or literals, invalid domains, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    Address,
    "Reads one mailbox or named group. Refuses invalid UTF-8, extra addresses, too many members, oversized text, and obsolete local parts or literals that cannot be written unchanged.",
    "Appends a mailbox or a `Name:member, member;` group. Uses the mailbox quoting rules. Refuses invalid names or mailboxes, more than [`MAX_ADDRESSES`] entries counting the group, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    AddressList,
    "Reads an address list. Accepts comments, folds, empty entries, and source routes. Refuses invalid UTF-8, malformed addresses, excessive nesting or counts, oversized text, and obsolete forms that cannot be written unchanged.",
    "Appends addresses separated by comma and space. Refuses invalid mailboxes or groups, more than [`MAX_ADDRESSES`] entries, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    MessageId,
    "Reads one message ID with optional surrounding comments or whitespace. Refuses invalid UTF-8, extra IDs or phrases, malformed IDs, oversized text, and obsolete forms that cannot be written unchanged.",
    "Appends one ID in angle brackets. Refuses a left part that is not dot-atom text, an invalid domain, whitespace or controls in a literal, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    MessageIds,
    "Reads message IDs, allowing obsolete phrases between them. Refuses invalid UTF-8, malformed IDs, excessive counts, oversized text, and obsolete ID forms that cannot be written unchanged.",
    "Appends IDs separated by single spaces. Refuses invalid IDs, more than [`MAX_MESSAGE_IDS`] entries, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    DateTime,
    "Reads a date with comments, folds, obsolete years, or named zones. Refuses invalid UTF-8, oversized text, impossible dates, incorrect weekdays, and out-of-range times or zones.",
    "Appends a date with optional weekday, a four-digit year, seconds, and numeric zone. Uses -0000 for an unknown zone. Refuses fields outside their documented ranges or an incorrect weekday. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);
text_wire!(
    EncodedText,
    "Reads unstructured UTF-8 text and decodes recognized RFC 2047 words. Refuses invalid UTF-8, NUL, CR, LF, and text whose encoded form exceeds [`MAX_VALUE_BYTES`].",
    "Appends UTF-8 base64 words of at most [`ENCODED_WORD_LEN`] bytes, separated by spaces. Empty text writes no bytes. Refuses NUL, CR, LF, and output over [`MAX_VALUE_BYTES`]. Returns [`Error::Unwritable`] and leaves `out` unchanged on refusal."
);

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * k) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64 to bytes. Padding may be left off, but padding that is there
/// must fill the last group of four, and a lone final character is
/// refused.
fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let padded = s.len();
    let s = s.strip_suffix(b"==").or_else(|| s.strip_suffix(b"=")).unwrap_or(s);
    if s.len() % 4 == 1 || (padded != s.len() && (s.is_empty() || !padded.is_multiple_of(4))) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        let v = BASE64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6 | v) & 0xff_ffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// RFC 2047's Q encoding to bytes: `_` is a space and `=XX` a byte in hex.
fn q_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'_' => out.push(b' '),
            b'=' => {
                let hex = s.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(out)
}

/// A token of a structured field value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    /// A run of atom characters.
    Atom(String),
    /// A quoted string's content, with quoting taken off.
    Quoted(String),
    /// A domain literal's content, without its brackets.
    Literal(String),
    /// One of `< > : ; @ , .`.
    Special(char),
}

/// A token, and whether white space or a comment came before it.
#[derive(Clone, Debug)]
struct Lexed {
    tok: Tok,
    space: bool,
}

/// Whether `c` may appear in an atom. RFC 6532 adds every non-ASCII
/// character.
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c) || !c.is_ascii()
}

/// Takes a fold after a carriage return or line feed `c`: CRLF, or LF
/// alone, then white space. The white space stays in `chars`. It returns
/// `None` for any other line break.
fn unfold(c: char, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<()> {
    if c == '\r' && chars.next()? != '\n' {
        return None;
    }
    matches!(chars.peek(), Some(' ' | '\t')).then_some(())
}

/// Splits a structured value into tokens, dropping white space and
/// comments. Folds (a line break, then white space) are unfolded, also
/// inside quoted strings, comments and literals. It returns `None` for an
/// unclosed quote, comment or literal, a comment nested past
/// [`MAX_COMMENT_DEPTH`], a line break that is not a fold, or a character
/// that cannot appear.
fn lex(s: &str) -> Option<Vec<Lexed>> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    let mut space = false;
    while let Some(c) = chars.next() {
        let tok = match c {
            ' ' | '\t' => {
                space = true;
                continue;
            }
            '\r' | '\n' => {
                unfold(c, &mut chars)?;
                continue;
            }
            '(' => {
                let mut depth = 1;
                while depth > 0 {
                    match chars.next()? {
                        '\\' => match chars.next()? {
                            '\0' | '\r' | '\n' => return None,
                            _ => {}
                        },
                        '\0' => return None,
                        c @ ('\r' | '\n') => unfold(c, &mut chars)?,
                        '(' => {
                            depth += 1;
                            if depth > MAX_COMMENT_DEPTH {
                                return None;
                            }
                        }
                        ')' => depth -= 1,
                        _ => {}
                    }
                }
                space = true;
                continue;
            }
            '"' => {
                let mut q = String::new();
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            '\0' | '\r' | '\n' => return None,
                            c => q.push(c),
                        },
                        '\0' => return None,
                        c @ ('\r' | '\n') => unfold(c, &mut chars)?,
                        c => q.push(c),
                    }
                }
                Tok::Quoted(q)
            }
            '[' => {
                let mut l = String::new();
                loop {
                    match chars.next()? {
                        ']' => break,
                        // The obsolete syntax allows quoted-pairs here.
                        '\\' => match chars.next()? {
                            '\0' | '\r' | '\n' => return None,
                            c => l.push(c),
                        },
                        '[' | '\0' => return None,
                        c @ ('\r' | '\n') => unfold(c, &mut chars)?,
                        c => l.push(c),
                    }
                }
                Tok::Literal(l)
            }
            '<' | '>' | ':' | ';' | '@' | ',' | '.' => Tok::Special(c),
            c if is_atext(c) => {
                let mut a = String::from(c);
                while let Some(&n) = chars.peek() {
                    if !is_atext(n) {
                        break;
                    }
                    a.push(n);
                    chars.next();
                }
                Tok::Atom(a)
            }
            _ => return None,
        };
        out.push(Lexed { tok, space });
        space = false;
    }
    Some(out)
}

/// Reads addresses and message IDs from tokens.
struct Parser {
    toks: Vec<Lexed>,
    i: usize,
}

impl Parser {
    fn new(s: &str) -> Option<Parser> {
        Some(Parser { toks: lex(s)?, i: 0 })
    }

    fn done(&self) -> bool {
        self.i >= self.toks.len()
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|l| &l.tok)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i)?.tok.clone();
        self.i += 1;
        Some(t)
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(&Tok::Special(c));
        if found {
            self.i += 1;
        }
        found
    }

    /// Takes atoms, quoted strings and dots, and returns where they are.
    fn words(&mut self) -> std::ops::Range<usize> {
        let start = self.i;
        while matches!(self.peek(), Some(Tok::Atom(_) | Tok::Quoted(_) | Tok::Special('.'))) {
            self.i += 1;
        }
        start..self.i
    }

    /// A display name from words: a word, then words and dots. Encoded
    /// words are decoded, and white space between two of them dropped.
    fn phrase(&self, words: std::ops::Range<usize>) -> Option<String> {
        let mut out = String::new();
        let mut after_word = false;
        for (k, l) in self.toks[words.clone()].iter().enumerate() {
            let (text, encoded) = match &l.tok {
                Tok::Atom(a) => match decode_word(a) {
                    Some(d) => (d, true),
                    None => (a.clone(), false),
                },
                Tok::Quoted(q) => (q.clone(), false),
                Tok::Special('.') if k > 0 => (".".to_string(), false),
                _ => return None,
            };
            if k > 0 && l.space && !(after_word && encoded) {
                out.push(' ');
            }
            out.push_str(&text);
            after_word = encoded;
        }
        if words.is_empty() { None } else { Some(out) }
    }

    /// A local part from words: words split by single dots.
    fn local_part(&self, words: std::ops::Range<usize>) -> Option<String> {
        if words.len().is_multiple_of(2) {
            return None;
        }
        let mut out = String::new();
        for (k, l) in self.toks[words].iter().enumerate() {
            match (&l.tok, k % 2) {
                (Tok::Atom(w) | Tok::Quoted(w), 0) => out.push_str(w),
                (Tok::Special('.'), 1) => out.push('.'),
                _ => return None,
            }
        }
        Some(out)
    }

    /// A domain: atoms split by dots, or a bracketed literal.
    fn domain(&mut self) -> Option<String> {
        match self.next()? {
            Tok::Literal(l) => Some(format!("[{l}]")),
            Tok::Atom(a) => {
                let mut d = a;
                while self.eat('.') {
                    let Tok::Atom(a) = self.next()? else { return None };
                    d.push('.');
                    d.push_str(&a);
                }
                Some(d)
            }
            _ => None,
        }
    }

    /// A mailbox: `name <local@domain>`, `<local@domain>` or
    /// `local@domain`.
    fn mailbox(&mut self) -> Option<Mailbox> {
        let words = self.words();
        if self.eat('<') {
            let name = if words.is_empty() { None } else { Some(self.phrase(words)?) };
            if matches!(self.peek(), Some(Tok::Special(',' | '@'))) {
                // An obsolete source route, `@a.test,@b.test:`, is read
                // and dropped. RFC 5322 section 4.4: commas, then `@` and
                // a domain, then more domains, each after a comma.
                while self.eat(',') {}
                if !self.eat('@') {
                    return None;
                }
                self.domain()?;
                while self.eat(',') {
                    if self.eat('@') {
                        self.domain()?;
                    }
                }
                if !self.eat(':') {
                    return None;
                }
            }
            let local = self.words();
            if !self.eat('@') {
                return None;
            }
            let local = self.local_part(local)?;
            let domain = self.domain()?;
            if !self.eat('>') {
                return None;
            }
            Some(Mailbox { name, local, domain })
        } else if self.eat('@') {
            let local = self.local_part(words)?;
            let domain = self.domain()?;
            Some(Mailbox { name: None, local, domain })
        } else {
            None
        }
    }

    /// A mailbox or a group, counting each against [`MAX_ADDRESSES`].
    fn address(&mut self, count: &mut usize) -> Result<Address, Error> {
        let mut bump = || {
            *count += 1;
            if *count > MAX_ADDRESSES { Err(Error::TooManyItems) } else { Ok(()) }
        };
        let start = self.i;
        let words = self.words();
        if !self.eat(':') {
            self.i = start;
            let m = self.mailbox().ok_or(Error::Address)?;
            bump()?;
            return Ok(Address::Mailbox(m));
        }
        let name = self.phrase(words).ok_or(Error::Address)?;
        bump()?;
        let mut members = Vec::new();
        loop {
            while self.eat(',') {}
            if self.eat(';') {
                break;
            }
            members.push(self.mailbox().ok_or(Error::Address)?);
            bump()?;
            if self.eat(';') {
                break;
            }
            if !self.eat(',') {
                return Err(Error::Address);
            }
        }
        Ok(Address::Group { name, members })
    }

    /// A message ID: `<left@right>`.
    fn message_id(&mut self) -> Option<MessageId> {
        if !self.eat('<') {
            return None;
        }
        let words = self.words();
        if !self.eat('@') {
            return None;
        }
        let left = self.local_part(words)?;
        let right = self.domain()?;
        if !self.eat('>') {
            return None;
        }
        Some(MessageId { left, right })
    }
}

/// `out`, if it fits in [`MAX_VALUE_BYTES`].
fn fits(out: String) -> Result<String, Error> {
    if out.len() > MAX_VALUE_BYTES { Err(Error::TooLarge) } else { Ok(out) }
}

/// Whether `s` is words of atom characters split by single dots.
fn is_dot_atom(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|w| !w.is_empty() && w.chars().all(is_atext))
}

/// Writes a display name: as atoms when it is atom words split by single
/// spaces, and quoted otherwise. A name holding `=?` is quoted, so that a
/// reader does not take part of it for an encoded word. A name holding a
/// control character other than a tab, which only an encoded word may
/// carry, is written as encoded words. NUL, carriage return and line feed
/// cannot be carried at all.
fn write_phrase(out: &mut String, s: &str) -> Result<(), Error> {
    if s.contains(is_control) {
        if s.contains(['\0', '\r', '\n']) {
            return Err(Error::Address);
        }
        // The reader drops the spaces between encoded words.
        out.push_str(&encoded_text(s));
        return Ok(());
    }
    let atoms = !s.is_empty() && !s.contains("=?") && s.split(' ').all(|w| !w.is_empty() && w.chars().all(is_atext));
    if atoms {
        out.push_str(s);
        Ok(())
    } else {
        write_quoted(out, s, Error::Address)
    }
}

fn write_local(out: &mut String, s: &str, err: Error) -> Result<(), Error> {
    if is_dot_atom(s) {
        out.push_str(s);
        Ok(())
    } else {
        write_quoted(out, s, err)
    }
}

/// Whether `c` is a control character other than a tab. Readers take
/// these as obsolete text, and writers refuse them.
fn is_control(c: char) -> bool {
    c.is_ascii_control() && c != '\t'
}

fn write_quoted(out: &mut String, s: &str, err: Error) -> Result<(), Error> {
    if s.contains(is_control) {
        return Err(err);
    }
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(())
}

/// Writes a domain: dot-separated words, or a bracketed literal. With
/// `spaces` false, as in a message ID, the literal may hold no white space.
fn write_domain(out: &mut String, s: &str, err: Error, spaces: bool) -> Result<(), Error> {
    let literal = s.len() >= 2
        && s.starts_with('[')
        && s.ends_with(']')
        && s[1..s.len() - 1].chars().all(|c| match c {
            '[' | ']' | '\\' => false,
            ' ' | '\t' => spaces,
            c => !is_control(c),
        });
    if is_dot_atom(s) || literal {
        out.push_str(s);
        Ok(())
    } else {
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract,
        test_support::{decode_all, mutate},
    };

    fn mailbox(name: Option<&str>, local: &str, domain: &str) -> Mailbox {
        Mailbox { name: name.map(str::to_string), local: local.to_string(), domain: domain.to_string() }
    }

    fn one(s: &str) -> Mailbox {
        match &parse_address_list(s).unwrap()[..] {
            [Address::Mailbox(m)] => m.clone(),
            other => panic!("{other:?}"),
        }
    }

    // RFC 5322, appendix A.1.1.
    const SIMPLE: &str = "From: John Doe <jdoe@machine.example>\r\n\
                          To: Mary Smith <mary@example.net>\r\n\
                          Subject: Saying Hello\r\n\
                          Date: Fri, 21 Nov 1997 09:55:06 -0600\r\n\
                          Message-ID: <1234@local.machine.example>\r\n\
                          \r\n\
                          This is a message just to say hello.\r\n\
                          So, \"Hello\".\r\n";

    #[test]
    fn simple_message() {
        let (h, body) = split_message(SIMPLE.as_bytes()).unwrap();
        assert_eq!(body, b"This is a message just to say hello.\r\nSo, \"Hello\".\r\n");
        assert_eq!(h.fields.len(), 5);
        assert_eq!(h.get("subject"), Some("Saying Hello"));
        assert_eq!(one(h.get("From").unwrap()), mailbox(Some("John Doe"), "jdoe", "machine.example"));
        assert_eq!(one(h.get("To").unwrap()), mailbox(Some("Mary Smith"), "mary", "example.net"));
        let id = MessageId::parse((h.get("message-id").unwrap()).as_bytes()).unwrap();
        assert_eq!(id, MessageId { left: "1234".into(), right: "local.machine.example".into() });
        assert_eq!(id.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(), "<1234@local.machine.example>");
        let d = DateTime::parse((h.get("Date").unwrap()).as_bytes()).unwrap();
        let want = DateTime {
            weekday: Some(4),
            year: 1997,
            month: 11,
            day: 21,
            hour: 9,
            minute: 55,
            second: 6,
            zone: Some(-360),
        };
        assert_eq!(d, want);
        assert_eq!(
            d.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(),
            "Fri, 21 Nov 1997 09:55:06 -0600"
        );
    }

    #[test]
    fn every_prefix_waits_for_the_blank_line() {
        let bytes = SIMPLE.as_bytes();
        let end = SIMPLE.find("\r\n\r\n").unwrap() + 4;
        for n in 0..end {
            assert_eq!(Head::new().decode(&bytes[..n], false), Ok(Step::Need));
            assert_eq!(Header::parse(&bytes[..n]), Err(ParseError::Truncated));
            let _ = split_message(&bytes[..n]);
        }
        let header = Header::parse(&bytes[..end]).unwrap();
        assert_eq!(header.fields.len(), 5);
        assert_eq!(Header::parse(bytes), Err(ParseError::Trailing));
        let line2 = SIMPLE.find("To:").unwrap();
        let (header, body) = split_message(&bytes[..line2]).unwrap();
        assert_eq!((header.fields.len(), body.len()), (1, 0));
    }

    #[test]
    fn addresses_from_the_rfc() {
        // A.1.2.
        assert_eq!(
            one("\"Joe Q. Public\" <john.q.public@example.com>"),
            mailbox(Some("Joe Q. Public"), "john.q.public", "example.com")
        );
        let list = parse_address_list("Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>").unwrap();
        assert_eq!(
            list,
            [
                Address::Mailbox(mailbox(Some("Mary Smith"), "mary", "x.test")),
                Address::Mailbox(mailbox(None, "jdoe", "example.org")),
                Address::Mailbox(mailbox(Some("Who?"), "one", "y.test")),
            ]
        );
        let list = parse_address_list("<boss@nil.test>, \"Giant; \\\"Big\\\" Box\" <sysservices@example.net>").unwrap();
        assert_eq!(
            list,
            [
                Address::Mailbox(mailbox(None, "boss", "nil.test")),
                Address::Mailbox(mailbox(Some("Giant; \"Big\" Box"), "sysservices", "example.net")),
            ]
        );
        // A.1.3: groups.
        let list = parse_address_list("A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;").unwrap();
        assert_eq!(
            list,
            [Address::Group {
                name: "A Group".into(),
                members: vec![
                    mailbox(Some("Ed Jones"), "c", "a.test"),
                    mailbox(None, "joe", "where.test"),
                    mailbox(Some("John"), "jdoe", "one.test"),
                ],
            }]
        );
        assert_eq!(
            parse_address_list("Undisclosed recipients:;").unwrap(),
            [Address::Group { name: "Undisclosed recipients".into(), members: vec![] }]
        );
        // A.5: white space and comments.
        assert_eq!(
            one("Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>"),
            mailbox(Some("Pete"), "pete", "silly.test")
        );
        let list = parse_address_list(
            "A Group(Some people)\r\n     :Chris Jones <c@(Chris's host.)public.example>,\r\n         \
             joe@example.org,\r\n  John <jdoe@one.test> (my dear friend); (the end of the group)",
        )
        .unwrap();
        let [Address::Group { name, members }] = &list[..] else { panic!("{list:?}") };
        assert_eq!(name, "A Group");
        assert_eq!(members[0], mailbox(Some("Chris Jones"), "c", "public.example"));
        assert_eq!(members.len(), 3);
        // A.6.1: an obsolete phrase with a dot, and a source route.
        assert_eq!(
            one("Joe Q. Public <john.q.public@example.com>"),
            mailbox(Some("Joe Q. Public"), "john.q.public", "example.com")
        );
        assert_eq!(one("<@machine.tld:mary@example.net>"), mailbox(None, "mary", "example.net"));
        // Empty entries, quoted local parts and domain literals.
        assert_eq!(parse_address_list(" , a@b , ,").unwrap().len(), 1);
        assert_eq!(parse_address_list("").unwrap(), []);
        assert_eq!(one("\"a b\"@[192.0.2.1]"), mailbox(None, "a b", "[192.0.2.1]"));
    }

    #[test]
    fn utf8_headers() {
        // RFC 6532 lets UTF-8 stand in names, addresses and text.
        let (h, _) = split_message("From: Jöhn Dœ <jöhn@exämple.de>\r\nSubject: Grüße\r\n\r\n".as_bytes()).unwrap();
        assert_eq!(one(h.get("from").unwrap()), mailbox(Some("Jöhn Dœ"), "jöhn", "exämple.de"));
        assert_eq!(h.get("subject"), Some("Grüße"));
        assert_eq!(split_message(b"Subject: \xff\r\n\r\n"), Err(Error::Utf8));
    }

    #[test]
    fn encoded_words_from_the_rfc() {
        // RFC 2047, section 8.
        assert_eq!(one("=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>").name.as_deref(), Some("Keith Moore"));
        assert_eq!(
            one("=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>").name.as_deref(),
            Some("Keld Jørn Simonsen")
        );
        assert_eq!(one("=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>").name.as_deref(), Some("André Pirard"));
        assert_eq!(
            decode_text(
                "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-1?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
            ),
            "If you can read this you understand the example."
        );
        // ISO-8859-2 is not read, so that word stays as it is.
        assert_eq!(
            decode_text(
                "=?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?= =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
            ),
            "If you can read this yo =?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
        );
        assert_eq!(decode_text("=?ISO-8859-1?Q?a?="), "a");
        assert_eq!(decode_text("=?ISO-8859-1?Q?a?= b"), "a b");
        assert_eq!(decode_text("=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(decode_text("=?ISO-8859-1?Q?a?=  \t =?ISO-8859-1?Q?b?="), "ab");
        assert_eq!(decode_text("=?ISO-8859-1?Q?a_b?="), "a b");
        assert_eq!(decode_text("=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?="), "a =?ISO-8859-2?Q?_b?=");
        // A language suffix (RFC 2231) is ignored.
        assert_eq!(decode_word("=?utf-8*en?q?hi?="), Some("hi".into()));
        // Words that do not decode stay.
        for w in [
            "=?utf-8?q?a=?=",
            "=?utf-8?q?a=4?=",
            "=?utf-8?q?a=G0?=",
            "=?utf-8?b?A?=",
            "=?utf-8?b?@@@@?=",
            "=?utf-8?x?a?=",
            "=?utf-8?q?a b?=",
            "=?utf-8?q?=FF?=",
            "=?us-ascii?q?=E9?=",
            "=?utf-8?q?a=0Db?=",
            "=?utf-8?q?a",
            "=?=",
            "=??=",
            "=?utf-8?q?=",
        ] {
            assert_eq!(decode_word(w), None, "{w}");
            assert_eq!(decode_text(w), w);
        }
        // Text around and between keeps its spacing.
        assert_eq!(decode_text("  Re:  =?utf-8?q?Caf=C3=A9?=  ok "), "  Re:  Café  ok ");
        // Inside quotes, nothing is decoded.
        assert_eq!(one("\"=?utf-8?q?x?=\" <a@b>").name.as_deref(), Some("=?utf-8?q?x?="));
    }

    #[test]
    fn encoded_word_writer() {
        assert_eq!(
            String::from_utf8(EncodedText(("").to_owned()).to_bytes().unwrap()).unwrap(),
            ""
        );
        assert_eq!(
            String::from_utf8(EncodedText(("Café").to_owned()).to_bytes().unwrap()).unwrap(),
            "=?utf-8?b?Q2Fmw6k=?="
        );
        let long = "Ünïcödé ".repeat(40);
        let enc = String::from_utf8(EncodedText(long.clone()).to_bytes().unwrap()).unwrap();
        assert!(enc.split(' ').all(|w| w.len() <= ENCODED_WORD_LEN));
        assert_eq!(decode_text(&enc), long);
        for value in ["a\r", "a\n", "a\0"] {
            let encoded = EncodedText(value.into());
            let mut out = b"prefix".to_vec();
            assert_eq!(encoded.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, b"prefix");
        }
        for n in 0..10 {
            let s = "xyz".repeat(n);
            assert_eq!(base64_decode(base64_encode(s.as_bytes()).as_bytes()).unwrap(), s.as_bytes());
        }
        assert_eq!(base64_decode(b"QUI"), Some(b"AB".to_vec()));
    }

    #[test]
    fn dates_from_the_rfc() {
        // A.5: comments and folding inside the date.
        let d = DateTime::parse("Thu,\r\n      13\r\n        Feb\r\n          1969\r\n      23:32\r\n               -0330 (Newfoundland Time)".as_bytes()).unwrap();
        assert_eq!(
            d,
            DateTime {
                weekday: Some(3),
                year: 1969,
                month: 2,
                day: 13,
                hour: 23,
                minute: 32,
                second: 0,
                zone: Some(-210)
            }
        );
        assert_eq!(
            d.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(),
            "Thu, 13 Feb 1969 23:32:00 -0330"
        );
        // A.6.2: obsolete two-digit years and zone names.
        let d = DateTime::parse("21 Nov 97 09:55:06 GMT".as_bytes()).unwrap();
        assert_eq!((d.weekday, d.year, d.zone), (None, 1997, Some(0)));
        assert_eq!(
            DateTime::parse("1 Jan 07 00:00 EDT".as_bytes())
                .unwrap()
                .year,
            2007
        );
        assert_eq!(
            DateTime::parse("1 jan 107 00:00 pst".as_bytes())
                .unwrap()
                .year,
            2007
        );
        assert_eq!(
            DateTime::parse("29 Feb 2000 00:00 Z".as_bytes())
                .unwrap()
                .zone,
            None
        );
        assert_eq!(
            DateTime::parse("fri , 31 Dec 9999 23:59:60 +9959".as_bytes())
                .unwrap()
                .zone,
            Some(5999)
        );
    }

    #[test]
    fn date_errors() {
        for s in [
            "",
            "Fri, 21 Nov 1997 09:55:06",
            "Fri 21 Nov 1997 09:55:06 -0600",
            "Fry, 21 Nov 1997 09:55:06 -0600",
            "21 Nov 1997 09:55:06 -0600 extra",
            "21 Nox 1997 09:55:06 -0600",
            "30 Feb 2000 09:55:06 -0600",
            "29 Feb 1900 09:55:06 -0600",
            "0 Feb 2000 09:55:06 -0600",
            "123 Feb 2000 09:55:06 -0600",
            "21 Nov 1 09:55:06 -0600",
            "21 Nov 19977 09:55:06 -0600",
            "21 Nov 1899 09:55:06 -0600",
            "21 Nov 1997 24:55:06 -0600",
            "21 Nov 1997 9:55:06 -0600",
            "21 Nov 1997 09:60:06 -0600",
            "21 Nov 1997 09:55:61 -0600",
            "21 Nov 1997 09 55 -0600",
            "21 Nov 1997 09:55: -0600",
            "21 Nov 1997 09:55:06 -0660",
            "21 Nov 1997 09:55:06 -06000",
            "21 Nov 1997 09:55:06 J",
            "21 Nov 1997 09:55:06 XYZ",
            "21 Nov 1997 09:55:06 -0600 (unclosed",
            "21 Nov 1997 09:55:06 \u{1}",
        ] {
            assert_eq!(DateTime::parse(s.as_bytes()), Err(Error::Date), "{s}");
        }
        assert_eq!(
            DateTime::parse(" ".repeat(MAX_VALUE_BYTES + 1).as_bytes()),
            Err(Error::TooLarge)
        );
        // Every prefix of a date fails, but never panics.
        let s = "Fri, 21 Nov 1997 09:55:06 -0600";
        for n in 0..s.len() {
            assert!(
                DateTime::parse(&s.as_bytes()[..n]).is_err() || n >= 23,
                "{n}"
            );
        }
        // The writer refuses what the reader refuses.
        let good =
            DateTime { weekday: None, year: 2000, month: 2, day: 29, hour: 0, minute: 0, second: 0, zone: Some(0) };
        assert!(good.to_bytes().map(|b| String::from_utf8(b).unwrap()).is_ok());
        for bad in [
            DateTime { year: 1899, ..good },
            DateTime { year: 10000, ..good },
            DateTime { month: 0, ..good },
            DateTime { month: 13, ..good },
            DateTime { day: 0, ..good },
            DateTime { year: 2001, ..good },
            DateTime { hour: 24, ..good },
            DateTime { minute: 60, ..good },
            DateTime { second: 61, ..good },
            DateTime { weekday: Some(7), ..good },
            DateTime { zone: Some(6000), ..good },
            DateTime { zone: Some(i16::MIN), ..good },
        ] {
            assert_eq!(
                bad.to_bytes().map(|b| String::from_utf8(b).unwrap()),
                Err(Error::Unwritable),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn message_ids() {
        let ids = parse_message_ids("<1234@local.machine.example> (a comment)\r\n <3456@example.net>").unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(
            MessageIds(ids.clone())
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
                .unwrap(),
            "<1234@local.machine.example> <3456@example.net>"
        );
        assert_eq!(parse_message_ids("").unwrap(), []);
        let id = parse_message_ids("<\"a b\"@[x]>").unwrap().remove(0);
        assert_eq!(
            MessageId::parse(b"<\"a b\"@[x]>"),
            Err(Error::UnsupportedForm)
        );
        assert_eq!(
            id,
            MessageId {
                left: "a b".into(),
                right: "[x]".into()
            }
        );
        // The writer does not write the obsolete quoted left part back.
        assert_eq!(id.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        for s in
            ["", "1234@x", "<1234>", "<@x>", "<a@>", "<a@x", "<a@x> <b@y>", "<a@x.>", "<a..b@x>", "<a@x>>", "<a@x)"]
        {
            assert_eq!(MessageId::parse(s.as_bytes()), Err(Error::MessageId), "{s}");
        }
        let many = "<a@b>".repeat(MAX_MESSAGE_IDS + 1);
        assert_eq!(parse_message_ids(&many), Err(Error::TooManyItems));
        assert_eq!(parse_message_ids(&" ".repeat(MAX_VALUE_BYTES + 1)), Err(Error::TooLarge));
        let bad = MessageId { left: "a\r".into(), right: "x".into() };
        assert_eq!(bad.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let bad = MessageId { left: "a".into(), right: "x y".into() };
        assert_eq!(bad.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let id = MessageId { left: "a".into(), right: "x".into() };
        assert_eq!(MessageIds(vec![id; MAX_MESSAGE_IDS + 1]).to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let id = MessageId { left: "a".repeat(MAX_VALUE_BYTES), right: "x".into() };
        assert_eq!(MessageIds(vec![id]).to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
    }

    #[test]
    fn address_errors() {
        for s in [
            "a",
            "a@",
            "@b",
            "a@b.",
            "a@.b",
            "a.@b",
            ".a@b",
            "a@b c@d",
            "<a@b",
            "<>",
            "<a>",
            "Name <a@b> extra",
            "\"unclosed <a@b>",
            "(unclosed a@b",
            "a@b)",
            "a@[x",
            "a@[x[y]",
            "Group: a@b",
            "Group: a@b c",
            "Group: G2: a@b;;",
            ": a@b;",
            ". <a@b>",
            "a@b; c@d",
            "<@route a@b>",
            "<@route>",
            "a\u{1}@b",
            "a@b\\",
            "\"a\\",
            "\"a\0\"@b",
        ] {
            assert_eq!(parse_address_list(s), Err(Error::Address), "{s:?}");
        }
        let deep = format!("{}{}a@b", "(".repeat(MAX_COMMENT_DEPTH + 1), ")".repeat(MAX_COMMENT_DEPTH + 1));
        assert_eq!(parse_address_list(&deep), Err(Error::Address));
        let ok = format!("{}{}a@b", "(".repeat(MAX_COMMENT_DEPTH), ")".repeat(MAX_COMMENT_DEPTH));
        assert!(parse_address_list(&ok).is_ok());
        let many = "a@b,".repeat(MAX_ADDRESSES + 1);
        assert_eq!(parse_address_list(&many), Err(Error::TooManyItems));
        let group = format!("G:{};", "a@b,".repeat(MAX_ADDRESSES));
        assert_eq!(parse_address_list(&group), Err(Error::TooManyItems));
        assert_eq!(parse_address_list(&" ".repeat(MAX_VALUE_BYTES + 1)), Err(Error::TooLarge));
        // Every prefix of a list either reads or fails, but never panics.
        let s = "A Group(x):\"Ed \\\" J\" <c@[1.2.3.4]>,joe@where.test (y);, =?utf-8?q?Z?= <z@q>";
        for (n, _) in s.char_indices() {
            let _ = parse_address_list(&s[..n]);
        }
        // Writers refuse what they cannot write.
        for m in [
            mailbox(Some("a\nb"), "x", "y"),
            mailbox(None, "a\rb", "y"),
            mailbox(None, "x", ""),
            mailbox(None, "x", "a b"),
            mailbox(None, "x", "a..b"),
            mailbox(None, "x", "[a]b]"),
        ] {
            assert_eq!(
                m.to_bytes().map(|b| String::from_utf8(b).unwrap()),
                Err(Error::Unwritable),
                "{m:?}"
            );
        }
        let list = vec![Address::Mailbox(mailbox(None, "a", "b")); MAX_ADDRESSES + 1];
        assert_eq!(AddressList(list.to_vec()).to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let list = [Address::Mailbox(mailbox(None, &"a".repeat(MAX_VALUE_BYTES), "b"))];
        assert_eq!(AddressList(list.to_vec()).to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
    }

    #[test]
    fn address_writer() {
        let list = [
            Address::Mailbox(mailbox(Some("John Doe"), "jdoe", "machine.example")),
            Address::Mailbox(mailbox(Some("Joe Q. Public"), "john.q.public", "example.com")),
            Address::Mailbox(mailbox(Some(""), "a b", "[192.0.2.1]")),
            Address::Mailbox(mailbox(None, ".x", "y")),
            Address::Mailbox(mailbox(Some("say \"hi\" \\ =?x?q?y?="), "s", "t")),
            Address::Group { name: "".into(), members: vec![] },
            Address::Group {
                name: "Team".into(),
                members: vec![mailbox(None, "a", "x"), mailbox(Some("B"), "b", "x")],
            },
        ];
        let text = AddressList(list.to_vec())
            .to_bytes()
            .map(|b| String::from_utf8(b).unwrap())
            .unwrap();
        assert_eq!(
            text,
            "John Doe <jdoe@machine.example>, \"Joe Q. Public\" <john.q.public@example.com>, \
             \"\" <\"a b\"@[192.0.2.1]>, \".x\"@y, \"say \\\"hi\\\" \\\\ =?x?q?y?=\" <s@t>, \"\":;, Team:a@x, B <b@x>;"
        );
        assert_eq!(parse_address_list(&text).unwrap(), list);
    }

    #[test]
    fn folding_and_unfolding() {
        // RFC 5322 section 2.2.3: unfolding takes out each CRLF before
        // white space.
        let (h, _) = split_message(b"Subject: This\r\n is a test\r\n\tof folding\nX:\r\n\r\n").unwrap();
        assert_eq!(h.get("subject"), Some("This is a test\tof folding"));
        assert_eq!(h.get("x"), Some(""));
        let words = "word ".repeat(60);
        let mut h = Header::default();
        h.push("Subject", words.trim_end());
        h.push("X-Long", &"y".repeat(200));
        h.push("To", &format!("{} z", "q".repeat(100)));
        h.push("Lead", "trimmed");
        let bytes = h.to_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let subject = &text[..text.find("X-Long").unwrap()];
        assert!(subject.split("\r\n").all(|line| line.len() <= FOLD_AT), "{subject:?}");
        assert!(subject.split("\r\n").count() > 3);
        assert!(text.contains(&format!("X-Long: {}\r\n", "y".repeat(200))));
        assert!(text.contains(&format!("To: {}\r\n z\r\n", "q".repeat(100))));
        let back = Header::parse(&bytes).unwrap();
        assert_eq!(back.get("subject"), Some(words.trim_end()));
        assert_eq!(back.get("x-long").unwrap().len(), 200);
        assert_eq!(back.get("lead"), Some("trimmed"));
        h.push("Leading", "  \t trimmed");
        assert_eq!(h.to_bytes(), Err(Error::Unwritable));
        // White space with no text before it is not a fold point.
        let mut h = Header::default();
        h.push("A", &format!("b{}c", " ".repeat(200)));
        let bytes = h.to_bytes().unwrap();
        assert_eq!(Header::parse(&bytes).unwrap(), h);
    }

    #[test]
    fn empty_value_under_a_long_name_has_no_whitespace_only_line() {
        let mut header = Header::default();
        header.push(&"N".repeat(78), "");
        let bytes = header.to_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.split("\r\n").all(|line| {
                line.is_empty() || line.bytes().any(|c| !matches!(c, b' ' | b'\t'))
            })
        );
        assert_eq!(Header::parse(&bytes), Ok(header));

        let mut header = Header::default();
        header.push(&"N".repeat(MAX_LINE_BYTES - 2), "");
        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.iter().position(|&c| c == b'\r'), Some(MAX_LINE_BYTES));
        header.fields[0].name.push('N');
        let mut out = b"prefix".to_vec();
        assert_eq!(header.write(&mut out), Err(Error::Unwritable));
        assert_eq!(out, b"prefix");
    }

    #[test]
    fn header_helpers() {
        let mut h = Header::default();
        h.push("Received", "a");
        h.push("received", "b");
        h.push("To", "c");
        assert_eq!(h.get_all("RECEIVED").collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(h.get("cc"), None);
        assert!(h.fields[2].is("to"));
    }

    #[test]
    fn header_errors() {
        let cases: [(&[u8], Error); 10] = [
            (b"No colon here\r\n\r\n", Error::FieldName),
            (b": empty name\r\n\r\n", Error::FieldName),
            (b"Bad Name: x\r\n\r\n", Error::FieldName),
            (b"Bad\x7f: x\r\n\r\n", Error::FieldName),
            (b"Na\xc3\xa9: x\r\n\r\n", Error::FieldName),
            (b" folded: first\r\n\r\n", Error::FieldName),
            (b"A: b\0c\r\n\r\n", Error::FieldValue),
            (b"A: b\rc\r\n\r\n", Error::FieldValue),
            (b"A: b\r\n \r c\r\n\r\n", Error::FieldValue),
            (b"A: \xc3\r\n\r\n", Error::Utf8),
        ];
        for (b, e) in cases {
            assert_eq!(
                Header::parse(b),
                Err(ParseError::Header(e)),
                "{:?}",
                String::from_utf8_lossy(b)
            );
            assert_eq!(split_message(b).map(|_| ()), Err(e));
        }
        let many = "A: b\r\n".repeat(MAX_FIELDS + 1) + "\r\n";
        assert_eq!(
            Header::parse(many.as_bytes()),
            Err(ParseError::Header(Error::TooManyFields))
        );
        let enough = "A: b\r\n".repeat(MAX_FIELDS) + "\r\n";
        assert_eq!(
            Header::parse(enough.as_bytes()).unwrap().fields.len(),
            MAX_FIELDS
        );
        // No blank line within the limit.
        let big = format!("A: {}", "b".repeat(MAX_HEADER_BYTES));
        assert_eq!(Header::parse(big.as_bytes()), Err(ParseError::Header(Error::TooLarge)));
        assert_eq!(split_message(big.as_bytes()).map(|_| ()), Err(Error::TooLarge));
        // A blank line that ends exactly at the limit.
        let fits = format!("A: {}\r\n\r\n", "b".repeat(MAX_HEADER_BYTES - 7));
        assert_eq!(fits.len(), MAX_HEADER_BYTES);
        assert_eq!(
            split_message(fits.as_bytes()).unwrap().0.fields[0]
                .value
                .len(),
            MAX_HEADER_BYTES - 7
        );
        assert_eq!(
            Header::parse(fits.as_bytes()),
            Err(ParseError::Header(Error::UnsupportedForm))
        );
        let over = format!("A: {}\r\n\r\n", "b".repeat(MAX_HEADER_BYTES - 6));
        assert_eq!(
            Header::parse(over.as_bytes()),
            Err(ParseError::Header(Error::TooLarge))
        );
        // An empty header section, and a message with no header at all.
        assert_eq!(split_message(b"\r\nbody").unwrap(), (Header::default(), &b"body"[..]));
        assert_eq!(split_message(b"").unwrap(), (Header::default(), &b""[..]));
        // Writers refuse what readers refuse.
        let field = |name: &str, value: &str| Header { fields: vec![Field { name: name.into(), value: value.into() }] };
        assert_eq!(field("", "x").to_bytes(), Err(Error::Unwritable));
        assert_eq!(field("A B", "x").to_bytes(), Err(Error::Unwritable));
        assert_eq!(field("A:", "x").to_bytes(), Err(Error::Unwritable));
        assert_eq!(field("A", "x\r\n y").to_bytes(), Err(Error::Unwritable));
        assert_eq!(field("A", "x\0").to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            field("A", &"b".repeat(MAX_HEADER_BYTES)).to_bytes(),
            Err(Error::Unwritable)
        );
        // Full lines of 1,000 bytes with their CRLF, then a last field and
        // the blank line that end exactly at the limit.
        let full = |last: usize| {
            let mut h = Header { fields: vec![Field { name: "A".into(), value: "b".repeat(995) }; 65] };
            h.push("A", &"b".repeat(last));
            h.to_bytes()
        };
        assert_eq!(full(529).map(|b| b.len()), Ok(MAX_HEADER_BYTES));
        assert_eq!(full(530), Err(Error::Unwritable));
        let many = Header { fields: vec![Field { name: "A".into(), value: "b".into() }; MAX_FIELDS + 1] };
        assert_eq!(many.to_bytes(), Err(Error::Unwritable));
        for e in [Error::TooLarge, Error::FieldName, Error::Date, Error::TooManyItems] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn head_reads_a_stream() {
        let bytes = SIMPLE.as_bytes();
        contract::check_decode_with_alloc_limit(Head::new, bytes, 2 * MAX_HEADER_BYTES);
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(bytes), bytes.len());
        assert_eq!(stream.next().unwrap().unwrap().unwrap().fields.len(), 5);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), split_message(bytes).unwrap().1);
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(b"A: b\n\r"), 6);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"\nrest"), 5);
        assert_eq!(stream.next().unwrap().unwrap().unwrap().get("a"), Some("b"));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), b"rest");
        assert_eq!(
            decode_all(Head::new, b"bad line\r\n\r\n"),
            (vec![Err(Error::FieldName)], None)
        );
        let input = vec![b'x'; MAX_HEADER_BYTES + 1000];
        assert_eq!(
            decode_all(Head::new, &input),
            (vec![], Some(Fail::Protocol(Error::TooLarge)))
        );
    }

    #[test]
    fn review_obsolete_space_before_colon() {
        // RFC 5322 section 4.5: obsolete fields allow white space between
        // the name and the colon.
        let (h, _) = split_message(b"Subject : hi\r\nTo\t: a@b\r\n\r\n").unwrap();
        assert_eq!(h.fields[0], Field { name: "Subject".into(), value: "hi".into() });
        assert_eq!(h.get("to"), Some("a@b"));
        assert_eq!(split_message(b" : x\r\n\r\n").map(|_| ()), Err(Error::FieldName));
    }

    #[test]
    fn review_no_white_space_only_lines() {
        // RFC 5322 section 3.2.2: a folded line may not be white space alone.
        let mut h = Header::default();
        h.push("A", &format!("{}{}", "a".repeat(76), " ".repeat(10)));
        h.push("B", &format!("x {}{}", "a".repeat(80), " ".repeat(5)));
        let bytes = h.to_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for line in text.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(!line.bytes().all(|c| c == b' ' || c == b'\t'), "{text:?}");
        }
        assert_eq!(Header::parse(&bytes).unwrap(), h);
    }

    #[test]
    fn review_line_limit() {
        // RFC 5322 section 2.1.1: lines are at most 998 characters.
        let field = |v: String| Header { fields: vec![Field { name: "A".into(), value: v }] };
        assert!(field("b".repeat(MAX_LINE_BYTES - 3)).to_bytes().is_ok());
        assert_eq!(
            field("b".repeat(MAX_LINE_BYTES - 2)).to_bytes(),
            Err(Error::Unwritable)
        );
        // A long value with room to fold is fine.
        assert!(field("bb ".repeat(1000)).to_bytes().is_ok());
    }

    #[test]
    fn review_folding_inside_quotes_and_comments() {
        // FWS may fold a quoted string: the CRLF goes, the space stays.
        assert_eq!(one("\"Joe\r\n Doe\" <j@x>").name.as_deref(), Some("Joe Doe"));
        assert_eq!(one("(a\r\n b) j@x"), mailbox(None, "j", "x"));
        // A line break not followed by white space is not folding.
        for s in ["a@b\r\n", "a@b\n,c@d", "\"a\r\nb\"@c", "a@b\r c@d", "(x\ny) a@b"] {
            assert_eq!(parse_address_list(s), Err(Error::Address), "{s:?}");
        }
    }

    #[test]
    fn review_writers_refuse_obsolete_text() {
        // Control characters are only obsolete text: readers take them,
        // writers do not write them.
        assert!(parse_address_list("\"a\u{1}\" <x@y>").is_ok());
        assert_eq!(
            mailbox(Some("a\u{1}"), "x", "y")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
                .unwrap(),
            "=?utf-8?b?YQE=?= <x@y>"
        );
        assert_eq!(
            mailbox(None, "a\u{7f}", "y")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
        assert_eq!(
            mailbox(None, "x", "[a\u{1}]")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
        assert_eq!(
            mailbox(Some("tab\there"), "x", "[1.2.3.4]")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
                .unwrap(),
            "\"tab\there\" <x@[1.2.3.4]>"
        );
        // A message ID's left part is dot-atom text, and its right part
        // dot-atom text or a literal with no white space (section 3.6.4).
        assert!(parse_message_ids("<\"a b\"@x>").is_ok());
        assert_eq!(
            MessageId::parse(b"<\"a b\"@x>"),
            Err(Error::UnsupportedForm)
        );
        for (l, r) in [("a b", "x"), ("a", "[x y]"), ("", "x"), ("a", "[x\u{1}]")] {
            let id = MessageId { left: l.into(), right: r.into() };
            assert_eq!(id.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable), "{id:?}");
        }
        assert_eq!(
            MessageId {
                left: "a.b".into(),
                right: "[1.2]".into()
            }
            .to_bytes()
            .map(|b| String::from_utf8(b).unwrap())
            .unwrap(),
            "<a.b@[1.2]>"
        );
    }

    #[test]
    fn review_obsolete_phrases_in_reply_lists() {
        // RFC 5322 section 4.5.4: In-Reply-To and References may hold
        // phrases, which readers ignore.
        let ids = parse_message_ids("Your message of \"Mon, 1 Jan\" <a@x> and. <b@y>").unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(parse_message_ids("just words").unwrap(), []);
        assert_eq!(parse_message_ids(". <a@x>"), Err(Error::MessageId));
        // A Message-ID field is one message ID alone.
        assert_eq!(
            MessageId::parse("Hi <a@x>".as_bytes()),
            Err(Error::MessageId)
        );
    }

    #[test]
    fn review_weekday_matches_date() {
        // RFC 5322 section 3.3: the weekday must be the date's own.
        assert_eq!(DateTime::parse("Mon, 21 Nov 1997 09:55:06 -0600".as_bytes()), Err(Error::Date));
        assert_eq!(DateTime::parse("Sat, 1 Jan 2000 00:00 +0000".as_bytes()).unwrap().weekday, Some(5));
        assert_eq!(DateTime::parse("Fri, 31 Dec 9999 23:59 +0000".as_bytes()).unwrap().weekday, Some(4));
        assert_eq!(DateTime::parse("Mon, 1 Jan 1900 00:00 +0000".as_bytes()).unwrap().weekday, Some(0));
        let d =
            DateTime { weekday: Some(0), year: 1997, month: 11, day: 21, hour: 0, minute: 0, second: 0, zone: Some(0) };
        assert_eq!(d.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        assert!(DateTime { weekday: Some(4), ..d }.to_bytes().map(|b| String::from_utf8(b).unwrap()).is_ok());
    }

    #[test]
    fn review_empty_encoded_text() {
        // RFC 2047 section 2: encoded-text is at least one character.
        assert_eq!(decode_word("=?utf-8?q??="), None);
        assert_eq!(decode_word("=?utf-8?b??="), None);
        assert_eq!(decode_text("=?utf-8?q??="), "=?utf-8?q??=");
    }

    #[test]
    fn review_encoded_name_with_control_round_trips() {
        // An encoded word may decode to a control character. The reader
        // takes it, so the writer writes it back as an encoded word.
        for s in ["=?utf-8?q?a=01b?= <x@y>", "G=?utf-8?b?AQ==?=: a@b;", "=?utf-8?q?=7F?= <x@y>"] {
            let list = parse_address_list(s).unwrap();
            let text = AddressList(list.to_vec()).to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap();
            assert_eq!(parse_address_list(&text).unwrap(), list, "{s:?} -> {text:?}");
            check_value(s);
        }
        let m = mailbox(Some("a\u{1}b \"c\""), "x", "y");
        assert_eq!(
            m.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(),
            "=?utf-8?b?YQFiICJjIg==?= <x@y>"
        );
        assert_eq!(
            one(&m.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap()),
            m
        );
        let long = mailbox(Some(&"\u{1}é".repeat(100)), "x", "y");
        assert_eq!(
            one(&long
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
                .unwrap()),
            long
        );
        // Line breaks and NUL cannot be carried even then.
        assert_eq!(
            mailbox(Some("a\u{1}\n"), "x", "y")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
        assert_eq!(
            mailbox(Some("a\0"), "x", "y")
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn head_bounds_its_buffer() {
        let input = vec![b'x'; 1_000_000];
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&input), MAX_HEADER_BYTES);
        assert_eq!(stream.push(&input), 0);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLarge))));
        assert_eq!(stream.next(), None);
        contract::check_decode_with_alloc_limit(Head::new, &input, 2 * MAX_HEADER_BYTES);
        let mut input = b"A: b\r\n\r\n".to_vec();
        input.extend_from_slice(&vec![b'y'; MAX_HEADER_BYTES]);
        let mut stream = Stream::new(Head::new());
        let accepted = stream.push(&input);
        assert_eq!(accepted, MAX_HEADER_BYTES);
        assert_eq!(stream.next().unwrap().unwrap().unwrap().get("a"), Some("b"));
        assert_eq!(stream.next(), None);
        assert_eq!(
            [stream.unread(), &input[accepted..]].concat(),
            vec![b'y'; MAX_HEADER_BYTES]
        );
    }

    #[test]
    fn astra_standalone_writers_stay_in_bounds() {
        // A group of MAX_ADDRESSES members counts as one more entry.
        let group = Address::Group { name: "G".into(), members: vec![mailbox(None, "a", "b"); MAX_ADDRESSES] };
        assert_eq!(group.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let group = Address::Group { name: "G".into(), members: vec![mailbox(None, "a", "b"); MAX_ADDRESSES - 1] };
        assert_eq!(parse_address_list(&group.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap()).unwrap(), [group]);
        let m = mailbox(None, &"a".repeat(MAX_VALUE_BYTES), "b");
        assert_eq!(
            m.to_bytes().map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
        let m = mailbox(None, &"a".repeat(MAX_VALUE_BYTES - 2), "b");
        assert_eq!(one(&m.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap()), m);
        let id = MessageId { left: "a".repeat(MAX_VALUE_BYTES), right: "b".into() };
        assert_eq!(id.to_bytes().map(|b| String::from_utf8(b).unwrap()), Err(Error::Unwritable));
        let h = Header { fields: vec![Field { name: "N".repeat(MAX_HEADER_BYTES + 1), value: "x".into() }] };
        assert_eq!(h.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn astra_encoded_lines_fit_76() {
        // RFC 2047 section 2: a line holding an encoded word is at most 76
        // characters long.
        let mut h = Header::default();
        h.push(
            "Subject",
            &String::from_utf8(EncodedText("é".repeat(22)).to_bytes().unwrap()).unwrap(),
        );
        h.push(
            "Subject",
            &String::from_utf8(EncodedText("é ".repeat(100)).to_bytes().unwrap()).unwrap(),
        );
        h.push(
            "X-A-Long-Field-Name",
            &format!(
                "Re: {}",
                String::from_utf8(EncodedText("ü".repeat(30)).to_bytes().unwrap()).unwrap()
            ),
        );
        let bytes = h.to_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for line in text.split("\r\n") {
            assert!(line.len() <= 76, "{line:?}");
        }
        assert_eq!(Header::parse(&bytes).unwrap(), h);
        // The fold after the colon is only taken when it helps.
        let mut h = Header::default();
        h.push("To", &format!("{} z", "q".repeat(100)));
        assert_eq!(h.to_bytes().unwrap(), format!("To: {}\r\n z\r\n\r\n", "q".repeat(100)).as_bytes());
    }

    #[test]
    fn astra_no_fold_inside_quoted_pair() {
        // RFC 5322 section 3.2.1: a quoted-pair is a backslash and the
        // character after it, with no fold between them.
        let v = format!("\"{}\\ b\"@example.com", "a".repeat(70));
        let mut h = Header::default();
        h.push("To", &v);
        let bytes = h.to_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("\\\r\n"), "{text:?}");
        // The raw folded value, before unfolding, still reads.
        let raw = &text["To: ".len()..text.len() - 4];
        assert_eq!(parse_address_list(raw).unwrap(), parse_address_list(&v).unwrap());
        // An escaped backslash before white space leaves a fold point.
        let v = format!("\"{}\\\\ b\"@example.com", "a".repeat(70));
        let mut h = Header::default();
        h.push("To", &v);
        assert!(std::str::from_utf8(&h.to_bytes().unwrap()).unwrap().contains("\\\\\r\n b"));
    }

    #[test]
    fn astra_writer_refuses_controls() {
        // RFC 5322 sections 3.2.5 and 4: controls other than a tab are
        // obsolete text, which a writer may not write.
        for v in ["hello\u{7f}", "a\u{1}b", "\u{1b}[0m"] {
            let h = Header { fields: vec![Field { name: "Subject".into(), value: v.into() }] };
            assert_eq!(h.to_bytes(), Err(Error::Unwritable), "{v:?}");
        }
        let h = Header { fields: vec![Field { name: "Subject".into(), value: "a\tb".into() }] };
        assert!(h.to_bytes().is_ok());
        // The reader still takes them.
        assert_eq!(split_message(b"Subject: a\x7f\r\n\r\n").unwrap().0.get("subject"), Some("a\u{7f}"));
    }

    #[test]
    fn astra_obsolete_domain_literal_escapes() {
        // RFC 5322 section 4.4: obs-dtext includes quoted-pair.
        assert_eq!(one(r"a@[127.0.0.\1]"), mailbox(None, "a", "[127.0.0.1]"));
        assert_eq!(
            MessageId::parse((r"<a@[127.0.0.\1]>").as_bytes())
                .unwrap()
                .right,
            "[127.0.0.1]"
        );
        // An escaped bracket reads, but is not written back.
        let m = one(r"a@[x\]]");
        assert_eq!(m.domain, "[x]]");
        assert_eq!(
            m.to_bytes().map(|b| String::from_utf8(b).unwrap()),
            Err(Error::Unwritable)
        );
        for s in ["a@[x\\", "a@[x\\\0]", "a@[x\\\r\n ]"] {
            assert_eq!(parse_address_list(s), Err(Error::Address), "{s:?}");
        }
    }

    #[test]
    fn astra_source_routes() {
        // RFC 5322 section 4.4: obs-route = obs-domain-list ":".
        for s in [
            "<,@route.example:a@example.com>",
            "<@a.test,@b.test:a@example.com>",
            "<@a.test,,@b.test,:a@example.com>",
            "Joe < , ,@a.test : a@example.com>",
        ] {
            assert_eq!(parse_address_list(s).unwrap().len(), 1, "{s:?}");
        }
        for s in ["<@:a@b>", "<@a b:x@y>", "<,:a@b>", "<,a@b>", "<@a.test,b.test:x@y>", "<@[x]@y:a@b>", "<@a.test>"] {
            assert_eq!(parse_address_list(s), Err(Error::Address), "{s:?}");
        }
    }

    #[test]
    fn astra_long_years() {
        // RFC 5322 section 3.3: a year is four or more digits.
        assert_eq!(
            DateTime::parse("1 Jan 02024 00:00 +0000".as_bytes())
                .unwrap()
                .year,
            2024
        );
        assert_eq!(
            DateTime::parse("1 Jan 0000000002024 00:00 +0000".as_bytes())
                .unwrap()
                .year,
            2024
        );
        assert_eq!(
            DateTime::parse("1 Jan 00097 00:00 +0000".as_bytes()),
            Err(Error::Date)
        );
        assert_eq!(
            DateTime::parse(format!("1 Jan {} 00:00 +0000", "9".repeat(40)).as_bytes()),
            Err(Error::Date)
        );
    }

    #[test]
    fn astra_base64_padding() {
        // RFC 2047 section 4.1 uses RFC 2045 base64: padding fills a
        // four-character group.
        for w in [
            "=?utf-8?b?==?=",
            "=?utf-8?b?=?=",
            "=?utf-8?b?YQ=?=",
            "=?utf-8?b?YQ===?=",
            "=?utf-8?b?Y===?=",
            "=?utf-8?b?YW=J?=",
        ] {
            assert_eq!(decode_word(w), None, "{w}");
            assert_eq!(decode_text(w), w);
        }
        assert_eq!(decode_word("=?utf-8?b?YQ==?="), Some("a".into()));
        assert_eq!(decode_word("=?utf-8?b?YWI=?="), Some("ab".into()));
        assert_eq!(decode_word("=?utf-8?b?YQ?="), Some("a".into()));
    }

    #[test]
    fn astra_encoded_word_length() {
        // RFC 2047 section 2: an encoded word is at most 75 characters.
        let w = format!("=?utf-8?q?{}?=", "A".repeat(63));
        assert_eq!(w.len(), ENCODED_WORD_LEN);
        assert_eq!(decode_word(&w), Some("A".repeat(63)));
        let w = format!("=?utf-8?q?{}?=", "A".repeat(64));
        assert_eq!(decode_word(&w), None);
        assert_eq!(decode_text(&w), w);
    }

    #[test]
    fn head_leaves_large_bodies_for_the_next_decoder() {
        let mut input = b"\r\n".to_vec();
        input.extend_from_slice(&vec![b'y'; 3 * MAX_HEADER_BYTES]);
        let mut stream = Stream::new(Head::new());
        let accepted = stream.push(&input);
        assert_eq!(accepted, MAX_HEADER_BYTES);
        assert_eq!(stream.next(), Some(Ok(Ok(Header::default()))));
        assert_eq!(stream.next(), None);
        assert_eq!([stream.unread(), &input[accepted..]].concat(), input[2..]);
        contract::check_decode_with_alloc_limit(Head::new, &input, 2 * MAX_HEADER_BYTES);
    }

    #[test]
    fn head_reads_header_only_messages_at_eof() {
        let message = b"From: a@b\r\nDate: 1 Jan 2024 00:00 +0000\r\n";
        assert_eq!(
            decode_all(Head::new, message),
            (vec![Ok(split_message(message).unwrap().0)], None)
        );
        let mut stream = Stream::new(Head::new());
        let input = b"A: b\r\n\r\nbody";
        assert_eq!(stream.push(input), input.len());
        stream.end();
        assert_eq!(stream.next().unwrap().unwrap().unwrap().get("a"), Some("b"));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), b"body");
        assert_eq!(
            decode_all(Head::new, b"bad"),
            (vec![Err(Error::FieldName)], None)
        );
        assert_eq!(decode_all(Head::new, b""), (vec![], None));
    }

    #[test]
    fn astra_unknown_zone() {
        // RFC 5322 sections 3.3 and 4.3: -0000 means the local zone is
        // unknown, and military letters are read as -0000.
        for s in ["1 Jan 2024 00:00 -0000", "1 Jan 2024 00:00 Z", "1 Jan 2024 00:00 a"] {
            let d = DateTime::parse(s.as_bytes()).unwrap();
            assert_eq!(d.zone, None, "{s}");
            assert_eq!(
                d.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(),
                "1 Jan 2024 00:00:00 -0000"
            );
        }
        let d = DateTime::parse("1 Jan 2024 00:00 +0000".as_bytes()).unwrap();
        assert_eq!(d.zone, Some(0));
        assert_eq!(
            d.to_bytes().map(|b| String::from_utf8(b).unwrap()).unwrap(),
            "1 Jan 2024 00:00:00 +0000"
        );
        assert_eq!(
            DateTime::parse("1 Jan 2024 00:00 GMT".as_bytes())
                .unwrap()
                .zone,
            Some(0)
        );
    }

    const VALUE_PIECES: &[&str] = &[
        "a",
        "b.c",
        "x y",
        " ",
        "\t",
        "\"",
        "\\",
        "é",
        "\u{1}",
        "\u{7f}",
        "=?",
        "?=",
        "=?utf-8?q?x?=",
        "[",
        "]",
        ".",
        "(",
        ")",
        "<",
        ">",
        "@",
        ",",
        ";",
        ":",
        "\r",
        "\n",
        "\0",
        "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    ];

    fn random_text(rng: &mut Lcg) -> String {
        (0..rng.index(6))
            .map(|_| VALUE_PIECES[rng.index(VALUE_PIECES.len())])
            .collect()
    }

    fn random_domain(rng: &mut Lcg) -> String {
        match rng.index(3) {
            0 => format!("[{}]", random_text(rng)),
            1 => (0..1 + rng.index(3))
                .map(|_| ["a", "b-c", "é", "x"][rng.index(4)])
                .collect::<Vec<_>>()
                .join("."),
            _ => random_text(rng),
        }
    }

    fn random_mailbox(rng: &mut Lcg) -> Mailbox {
        let name = if rng.coin() { None } else { Some(random_text(rng)) };
        let local = if rng.coin() { "a.b".to_string() } else { random_text(rng) };
        Mailbox { name, local, domain: random_domain(rng) }
    }

    /// A header holding `value` as its one field must read back, folded
    /// or not, as the value was written.
    fn folds_back(value: &str) -> String {
        let mut h = Header::default();
        h.push("Long-Field-Name-For-Folding", &format!("{} {value}", "w".repeat(rng_pad(value))));
        let bytes = h.to_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(Header::parse(text.as_bytes()).unwrap(), h);
        // The raw value, still folded, with the padding taken off.
        let raw = text["Long-Field-Name-For-Folding:".len()..text.len() - 4].trim_start_matches([' ', '\r', '\n']);
        raw.split_once(' ').map_or(raw, |(_, r)| r).to_string()
    }

    /// A padding length that moves fold points around the value.
    fn rng_pad(value: &str) -> usize {
        1 + value.len() % 60
    }

    #[test]
    fn astra_writers_write_what_readers_read() {
        // Arbitrary values, not only those a reader made: whatever a
        // writer writes reads back as the same value, folded or not.
        let mut rng = Lcg::new(0xa57a);
        for _ in 0..20000 {
            let list: Vec<Address> = (0..rng.index(3))
                .map(|_| match rng.index(3) {
                    0 => Address::Group {
                        name: random_text(&mut rng),
                        members: (0..rng.index(3))
                            .map(|_| random_mailbox(&mut rng))
                            .collect(),
                    },
                    _ => Address::Mailbox(random_mailbox(&mut rng)),
                })
                .collect();
            if let Ok(text) = AddressList(list.to_vec())
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
            {
                assert_eq!(parse_address_list(&text).as_ref(), Ok(&list), "{text:?}");
                let raw = folds_back(&text);
                assert_eq!(parse_address_list(&raw).as_ref(), Ok(&list), "{raw:?}");
            }
            let ids: Vec<MessageId> = (0..rng.index(3))
                .map(|_| MessageId {
                    left: if rng.coin() {
                        "a.b".into()
                    } else {
                        random_text(&mut rng)
                    },
                    right: random_domain(&mut rng),
                })
                .collect();
            if let Ok(text) = MessageIds(ids.clone())
                .to_bytes()
                .map(|b| String::from_utf8(b).unwrap())
            {
                assert_eq!(parse_message_ids(&text).as_ref(), Ok(&ids), "{text:?}");
                assert_eq!(parse_message_ids(&folds_back(&text)).as_ref(), Ok(&ids));
            }
            let d = DateTime {
                weekday: if rng.coin() {
                    None
                } else {
                    Some(rng.index(8) as u8)
                },
                year: 1890 + rng.index(8200) as u16,
                month: rng.index(14) as u8,
                day: rng.index(33) as u8,
                hour: rng.index(25) as u8,
                minute: rng.index(61) as u8,
                second: rng.index(62) as u8,
                zone: if rng.index(4) == 0 {
                    None
                } else {
                    Some(rng.index(12002) as i16 - 6001)
                },
            };
            if let Ok(text) = d.to_bytes().map(|b| String::from_utf8(b).unwrap()) {
                assert_eq!(DateTime::parse(text.as_bytes()), Ok(d), "{text:?}");
            }
            let v = random_text(&mut rng);
            let h = Header { fields: vec![Field { name: "X".into(), value: v.clone() }] };
            match h.to_bytes() {
                Ok(bytes) => assert_eq!(Header::parse(&bytes).unwrap().fields[0].value, v),
                Err(e) => assert_eq!(e, Error::Unwritable),
            }
        }
    }

    const PIECES: &[&str] = &[
        "From",
        "To",
        "Date",
        "Message-ID",
        ":",
        ": ",
        " ",
        "\t",
        "\r\n",
        "\n",
        "\r",
        "<",
        ">",
        "@",
        ",",
        ";",
        "\"",
        "\\",
        "(",
        ")",
        "[",
        "]",
        ".",
        "a",
        "b.c",
        "x y",
        "=?utf-8?q?",
        "?=",
        "=?iso-8859-1?b?",
        "QUJD",
        "=C3=A9",
        "Fri, 21 Nov 1997 09:55:06 -0600",
        "21 Nov 97 09:55 GMT",
        "é",
        "\0",
        "<1@x>",
        "Joe <j@x.test>",
        "G:;",
        "\u{1}",
        "<\"q\"@[1 2]>",
        "Re: <a@x>",
        "Fri, 31 Dec 9999 23:59 +0000",
        "=?utf-8?q?=01?=",
        "=?utf-8?b?AQ==?=",
        "\u{7f}",
        "[1.2]",
        "a.b@c.d",
    ];

    fn random_message(rng: &mut Lcg) -> Vec<u8> {
        let mut b = Vec::new();
        for _ in 0..rng.index(40) {
            if rng.index(8) == 0 {
                b.push(rng.index(256) as u8);
            } else {
                b.extend_from_slice(PIECES[rng.index(PIECES.len())].as_bytes());
            }
        }
        b
    }

    /// The same checks the fuzz target makes.
    fn check(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEADER_BYTES);
        contract::check_wire::<Header>(data);
        let (items, failure) = decode_all(Head::new, data);
        let (header, body) = match split_message(data) {
            Ok(parts) => parts,
            Err(error) => {
                assert!(items == [Err(error)] || failure == Some(Fail::Protocol(error)));
                return;
            }
        };
        assert_eq!(
            (items, failure),
            (
                if data.is_empty() {
                    vec![]
                } else {
                    vec![Ok(header.clone())]
                },
                None
            )
        );
        if !data.is_empty() {
            let mut stream = Stream::with_buffer(Head::new(), data.len());
            assert_eq!(stream.push(data), data.len());
            stream.end();
            assert_eq!(stream.next(), Some(Ok(Ok(header.clone()))));
            assert_eq!(stream.unread(), body);
        }
        contract::check_wire_value(&header);
        if let Err(Error::Unwritable) = header.to_bytes() {
            let mut rendered = Vec::new();
            for field in &header.fields {
                fold(&mut rendered, &field.name, field.value.as_bytes());
            }
            assert!(
                header
                    .fields
                    .iter()
                    .any(|field| field.value.contains(is_control))
                    || header.fields.len() > MAX_FIELDS
                    || rendered.len().saturating_add(2) > MAX_HEADER_BYTES
                    || rendered
                        .split(|&c| c == b'\n')
                        .any(|line| line.len() > MAX_LINE_BYTES + 1)
            );
        }
        for field in &header.fields {
            check_value(&field.value);
        }
    }

    fn check_value(value: &str) {
        let _ = decode_text(value);
        let bytes = value.as_bytes();
        contract::check_wire::<Mailbox>(bytes);
        contract::check_wire::<Address>(bytes);
        contract::check_wire::<AddressList>(bytes);
        contract::check_wire::<DateTime>(bytes);
        contract::check_wire::<MessageId>(bytes);
        contract::check_wire::<MessageIds>(bytes);
        contract::check_wire::<EncodedText>(bytes);
        let encoded = EncodedText(value.into());
        contract::check_wire_value(&encoded);
        let result = encoded.to_bytes();
        if !value.contains(['\0', '\r', '\n']) && encoded_text(value).len() <= MAX_VALUE_BYTES {
            assert!(result.is_ok(), "{value:?}");
        }
        if let Ok(bytes) = result {
            let text = String::from_utf8(bytes).unwrap();
            assert_eq!(decode_text(&text), value);
            let mut header = Header::default();
            header.push("Subject", &text);
            if let Ok(bytes) = header.to_bytes() {
                assert!(
                    bytes
                        .split(|&c| c == b'\n')
                        .all(|line| line.len() <= ENCODED_LINE_LEN + 1)
                );
            }
        }
        if let Ok(list) = parse_address_list(value) {
            let list = AddressList(list);
            contract::check_wire_value(&list);
            if let Err(Error::Unwritable) = list.to_bytes() {
                assert!(
                    value.contains(is_control)
                        || value.contains('\\')
                        || render_address_list(&list.0) == Err(Error::TooLarge),
                    "{value:?}"
                );
            }
        }
        if let Ok(ids) = parse_message_ids(value) {
            let ids = MessageIds(ids);
            contract::check_wire_value(&ids);
            if let Err(Error::Unwritable) = ids.to_bytes() {
                assert!(
                    ids.0.iter().any(|id| id.to_bytes().is_err())
                        || ids.0.len() > MAX_MESSAGE_IDS
                        || render_message_ids(&ids.0) == Err(Error::TooLarge),
                    "{value:?}"
                );
            }
        }
    }

    #[test]
    fn strict_reader_refusals_use_read_errors() {
        let header = format!("Subject: {}\r\n\r\n", "x".repeat(MAX_LINE_BYTES));
        assert!(split_message(header.as_bytes()).is_ok());
        assert_eq!(
            Header::parse(header.as_bytes()),
            Err(ParseError::Header(Error::UnsupportedForm))
        );
        assert_eq!(
            MessageId::parse(b"<\"a b\"@example.test>"),
            Err(Error::UnsupportedForm)
        );
        assert_eq!(EncodedText::parse(b"a\0b"), Err(Error::UnsupportedForm));
    }

    #[test]
    fn stream_and_writer_checks_cover_size_boundaries() {
        check(format!("X: {}\r\n\r\nbody", "x".repeat(MAX_LINE_BYTES)).as_bytes());
        check(format!("X: {}", "x".repeat(MAX_HEADER_BYTES)).as_bytes());
        for value in [
            "a\x01b@example.test".to_owned(),
            "<\"a b\"@example.test>".to_owned(),
            "漢".repeat(MAX_VALUE_BYTES / 3),
            "x".repeat(MAX_VALUE_BYTES),
        ] {
            check_value(&value);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5e_ed1f);
        for _ in 0..4000 {
            let mut data = random_message(&mut rng);
            mutate(&mut rng, &mut data);
            check(&data);
            // Each piece as a value on its own, and every prefix of it.
            let text = String::from_utf8_lossy(&data);
            check_value(&text);
            for (n, _) in text.char_indices().step_by(3) {
                check_value(&text[..n]);
            }
        }
        // Fully random bytes, too.
        for _ in 0..2000 {
            let data: Vec<u8> = rng.bytes(120);
            check(&data);
            check_value(&String::from_utf8_lossy(&data));
        }
    }
}
