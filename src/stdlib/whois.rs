//! WHOIS: reading and writing queries and responses, with no I/O.
//!
//! WHOIS is how people and tools look up who holds a domain name, an IP
//! block or an AS number. A client connects to a server over TCP, on port
//! 43, and sends one line of text: the query, ended by CR LF. The server
//! answers with free text and closes the connection, and the close is the
//! only sign the answer is over. This module follows RFC 3912.
//!
//! RFC 3912 says nothing about what a query or an answer holds, so this
//! module also reads what the large registries have in common. Queries
//! may start with flags in the style of the RIPE database, such as
//! `-B -T inetnum 193.0.0.0`, which RIPE, APNIC, AFRINIC, LACNIC, RADb and
//! DENIC accept. [`Query::flags`] splits them out as text and
//! [`Query::terms`] gives the rest. Other forms stay in the terms as they
//! were sent: ARIN's `n + 8.8.8.8`, Verisign's `domain example.com` and
//! `=example.com`, and JPRS's `example.jp/e`. Answers are mostly lines of
//! `Key: value`, with comment lines, blank lines between objects, and
//! values that go on over more lines. A [`FieldReader`] reads that layout
//! into [`Field`]s, and [`Referral::from_field`] finds where a thin answer
//! says to ask next: IANA's `refer:`, a registry's
//! `Registrar WHOIS Server:`, and ARIN's `ReferralServer:`.
//!
//! Nothing here reads a socket. A world that plays a WHOIS server feeds
//! the bytes it reads from a [`tcp`](crate::stdlib::tcp) connection to a
//! [`QueryDecoder`], gets a [`Query`] back, writes a [`Response`]'s bytes
//! and closes the connection. A world that plays a client writes a query
//! and feeds what comes back to a [`ResponseDecoder`] until the server
//! closes. Which names exist, who holds them, and where a referral points
//! are up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A query line longer than [`MAX_QUERY`] is an error, and the
//! decoder skips it and goes on to the next line. A response is held to
//! [`MAX_RESPONSE`] bytes, and bytes past that are dropped. Writers return
//! an [`EncodeError`] or a [`QueryError`] rather than write bytes a reader
//! would refuse or read back as something else.
//!
//! ```
//! use fictionet::stdlib::whois::{Field, Query, QueryDecoder, ReferralKind, Response, ResponseDecoder};
//!
//! // A client asks the RIPE database about an address, with two flags.
//! let query = Query::new("-B -T inetnum 193.0.0.1").unwrap();
//! assert_eq!(query.to_bytes(), b"-B -T inetnum 193.0.0.1\r\n");
//!
//! // A registry reads a query for a name.
//! let mut decoder = QueryDecoder::new();
//! let bytes = b"example.com\r\n";
//! assert_eq!(decoder.feed(bytes), bytes.len());
//! let got = decoder.next_query().unwrap().unwrap();
//! assert!(got.flags().is_empty());
//! assert_eq!(got.terms(), "example.com");
//!
//! // It answers with two fields, then closes the connection.
//! let fields = [
//!     Field::new(0, "Domain Name", "EXAMPLE.COM"),
//!     Field::new(0, "Registrar WHOIS Server", "whois.registrar.example"),
//! ];
//! let response = Response::from_fields(&fields).unwrap();
//! assert_eq!(
//!     response.as_bytes(),
//!     b"Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: whois.registrar.example\r\n"
//! );
//!
//! // The client reads until the close, then finds where to ask next.
//! let mut reader = ResponseDecoder::new();
//! reader.feed(response.as_bytes());
//! assert!(!reader.truncated());
//! let response = reader.finish();
//! assert_eq!(response.fields().unwrap(), fields);
//! let referral = response.referral().unwrap();
//! assert_eq!(referral.kind, ReferralKind::RegistrarWhoisServer);
//! assert_eq!(referral.host, "whois.registrar.example");
//! assert_eq!(referral.port, 43);
//! ```

use std::borrow::Cow;

/// The TCP port WHOIS servers listen on.
pub const PORT: u16 = 43;
/// The longest query line, in bytes, not counting its CR LF.
pub const MAX_QUERY: usize = 1024;
/// The most bytes a [`QueryDecoder`] holds that have not been taken out:
/// one longest query line and its CR LF.
pub const MAX_BUFFERED: usize = MAX_QUERY + 2;
/// The longest response a [`ResponseDecoder`] keeps, and a [`Response`]
/// may hold.
pub const MAX_RESPONSE: usize = 1 << 20;
/// The most fields [`parse_fields`] reads and [`write_fields`] writes.
pub const MAX_FIELDS: usize = 10_000;
/// The longest key, in bytes, a line may have to be read as a field.
pub const MAX_KEY: usize = 128;
/// The longest host name, in bytes, a referral may name.
pub const MAX_HOST: usize = 253;
/// How deep [`write_fields`] indents the second and later lines of a
/// value.
pub const CONTINUATION_INDENT: &str = "        ";

/// Flags in the style of the RIPE database that take the word after them
/// as an argument, such as `-T inetnum`, and DENIC's `-C`, which names a
/// character set, as in `-T dn,ace -C UTF-8 example.de`. [`Query::flags`]
/// uses this list.
pub const FLAGS_WITH_ARGUMENT: &[&str] = &[
    "-C",
    "-i",
    "-T",
    "-s",
    "-t",
    "-v",
    "-q",
    "-V",
    "-g",
    "--inverse",
    "--select-types",
    "--sources",
    "--template",
    "--verbose",
    "--client",
    "--show-version",
    "--diff-versions",
];

/// Why a query line was refused, by a reader or a writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryError {
    /// The line was longer than [`MAX_QUERY`] bytes.
    TooLong,
    /// The line was not UTF-8.
    NotUtf8,
    /// The line held a control character other than a tab, such as a CR
    /// on its own. The value is the character.
    Control(char),
    /// [`Query::build`] was given flags and terms that would not read back
    /// as given: a flag that is empty or holds a space or tab, a word that
    /// does not start with a dash where a flag should be, a flag that wants
    /// an argument and has none, or terms whose first word reads as a flag.
    Flags,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::TooLong => write!(f, "a query line longer than {MAX_QUERY} bytes"),
            QueryError::NotUtf8 => f.write_str("a query line that is not UTF-8"),
            QueryError::Control(c) => write!(f, "control character {:#x} in a query line", u32::from(*c)),
            QueryError::Flags => f.write_str("query flags and terms that would not read back as given"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Why a writer refused a value: its bytes would be too long, or a reader
/// would read them back as something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncodeError {
    /// A key that is empty, longer than [`MAX_KEY`], holds a colon or a
    /// control character, has space at either end, or starts with a
    /// character that makes a line a comment or a continuation (`%`, `#`,
    /// `>` or `+`).
    Key,
    /// A value with a control character other than a tab, a line with
    /// space at either end, or an empty first line followed by more lines.
    Value,
    /// Blocks that do not start at 0 and go up by 0 or 1 from one field to
    /// the next.
    Block,
    /// More than [`MAX_FIELDS`] fields, or more than [`MAX_RESPONSE`]
    /// bytes.
    TooLong,
    /// A referral host that is empty, longer than [`MAX_HOST`], or holds
    /// anything but lowercase ASCII letters, digits, `.`, `-` and `_`, or
    /// starts with `.` or `-`.
    Host,
    /// A referral to port 0.
    Port,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::Key => f.write_str("a key a reader would not read back"),
            EncodeError::Value => f.write_str("a value a reader would not read back"),
            EncodeError::Block => f.write_str("blocks out of order"),
            EncodeError::TooLong => f.write_str("more than one WHOIS response may hold"),
            EncodeError::Host => f.write_str("a referral host a reader would not read back"),
            EncodeError::Port => f.write_str("a referral to port 0"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// A response held more than [`MAX_FIELDS`] fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TooManyFields;

impl std::fmt::Display for TooManyFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "more than {MAX_FIELDS} fields")
    }
}

impl std::error::Error for TooManyFields {}

/// One query: the text of the line a client sends, without its CR LF. It
/// is at most [`MAX_QUERY`] bytes and holds no control characters but
/// tabs. It may be empty, which most servers answer with help text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    text: String,
}

/// A flag at the start of a query, as text, such as `-B`, or `-T` with
/// its argument `inetnum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flag<'a> {
    /// The flag itself, with its dashes.
    pub name: &'a str,
    /// The word after the flag, for flags in [`FLAGS_WITH_ARGUMENT`].
    pub argument: Option<&'a str>,
}

impl Query {
    /// A query with this text. It is an error if the text is longer than
    /// [`MAX_QUERY`] bytes or holds a control character other than a tab.
    pub fn new(text: &str) -> Result<Query, QueryError> {
        check_query(text)?;
        Ok(Query { text: text.to_string() })
    }

    /// A query of `flags` and then `terms`, each word with one space
    /// between. A flag's argument is its own word in `flags`, as in
    /// `["-T", "inetnum"]`. The same checks as [`Query::new`] apply. It is
    /// also an error, [`QueryError::Flags`], if [`Query::flags`] and
    /// [`Query::terms`] would not read the query back as these flags and
    /// these terms without space at either end.
    pub fn build(flags: &[&str], terms: &str) -> Result<Query, QueryError> {
        let mut text = String::new();
        for f in flags {
            if f.is_empty() || f.contains([' ', '\t']) {
                return Err(QueryError::Flags);
            }
            if text.len().saturating_add(f.len()) > MAX_QUERY {
                return Err(QueryError::TooLong);
            }
            text.push_str(f);
            text.push(' ');
        }
        if text.len().saturating_add(terms.len()) > MAX_QUERY {
            return Err(QueryError::TooLong);
        }
        text.push_str(terms);
        let query = Query::new(&text)?;
        let (read, read_terms) = query.split();
        let words = read.iter().flat_map(|f| std::iter::once(f.name).chain(f.argument));
        if !words.eq(flags.iter().copied()) || read_terms != trim(terms) {
            return Err(QueryError::Flags);
        }
        Ok(query)
    }

    /// Reads a query line: the bytes before its line ending, with no CR
    /// or LF at the end.
    pub fn parse_line(line: &[u8]) -> Result<Query, QueryError> {
        if line.len() > MAX_QUERY {
            return Err(QueryError::TooLong);
        }
        let text = std::str::from_utf8(line).map_err(|_| QueryError::NotUtf8)?;
        Query::new(text)
    }

    /// The query's text, as sent.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The bytes a client sends: the text, then CR LF.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.text.len() + 2);
        out.extend_from_slice(self.text.as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The flags at the start of the query: each word that starts with a
    /// dash and has more after it, up to the first word that does not.
    /// A flag in [`FLAGS_WITH_ARGUMENT`] takes the next word with it.
    pub fn flags(&self) -> Vec<Flag<'_>> {
        self.split().0
    }

    /// The query after its flags, without space at either end. For a
    /// query with no flags, this is the whole text, trimmed.
    pub fn terms(&self) -> &str {
        self.split().1
    }

    fn split(&self) -> (Vec<Flag<'_>>, &str) {
        let words = words(&self.text);
        let mut flags = Vec::new();
        let mut i = 0;
        while let Some(&(_, w)) = words.get(i) {
            if !(w.len() > 1 && w.starts_with('-')) {
                break;
            }
            i += 1;
            let mut argument = None;
            if FLAGS_WITH_ARGUMENT.contains(&w)
                && let Some(&(_, a)) = words.get(i)
            {
                argument = Some(a);
                i += 1;
            }
            flags.push(Flag { name: w, argument });
        }
        let terms = match words.get(i) {
            Some(&(start, _)) => trim(&self.text[start..]),
            None => "",
        };
        (flags, terms)
    }
}

/// The words of `s`, split at spaces and tabs, with where each starts.
fn words(s: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in s.char_indices() {
        if c == ' ' || c == '\t' {
            if let Some(st) = start.take() {
                out.push((st, &s[st..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(st) = start {
        out.push((st, &s[st..]));
    }
    out
}

fn check_query(text: &str) -> Result<(), QueryError> {
    if text.len() > MAX_QUERY {
        return Err(QueryError::TooLong);
    }
    match text.chars().find(|&c| c.is_control() && c != '\t') {
        Some(c) => Err(QueryError::Control(c)),
        None => Ok(()),
    }
}

/// Splits the bytes a server reads into query lines. A line ends at LF,
/// and a CR just before the LF is dropped, so clients that send a bare LF
/// are read too. Most servers read one query and close, but some, such as
/// the RIPE database with `-k`, read more, so the decoder goes on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryDecoder {
    buf: Vec<u8>,
    /// How many bytes at the start of `buf` are known to hold no LF, so
    /// feeding a byte at a time does not search the same bytes again.
    scanned: usize,
    /// Dropping the rest of a line that was too long, up to its LF.
    skipping: bool,
}

impl QueryDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> QueryDecoder {
        QueryDecoder::default()
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than [`MAX_BUFFERED`] bytes. Then take queries
    /// out with [`QueryDecoder::next_query`] and feed it the rest. Once it
    /// is full, `next_query` always gives a query or an error, so a loop
    /// of feeding and taking out always ends.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        let mut taken = 0;
        if self.skipping {
            match bytes.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    taken = i + 1;
                    self.skipping = false;
                }
                None => return bytes.len(),
            }
        }
        let rest = &bytes[taken..];
        let n = rest.len().min(MAX_BUFFERED.saturating_sub(self.buf.len()));
        self.buf.extend_from_slice(&rest[..n]);
        taken + n
    }

    /// The next whole query line, if one has come. It returns `None` when
    /// it needs more bytes. A line longer than [`MAX_QUERY`] gives
    /// [`QueryError::TooLong`] once, and the decoder drops the rest of it.
    pub fn next_query(&mut self) -> Option<Result<Query, QueryError>> {
        let from = self.scanned.min(self.buf.len());
        if let Some(i) = self.buf[from..].iter().position(|&b| b == b'\n').map(|i| from + i) {
            let line = &self.buf[..i];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let query = Query::parse_line(line);
            self.buf.drain(..=i);
            self.scanned = 0;
            return Some(query);
        }
        self.scanned = self.buf.len();
        if self.buf.len() >= MAX_BUFFERED {
            self.buf.clear();
            self.scanned = 0;
            self.skipping = true;
            return Some(Err(QueryError::TooLong));
        }
        None
    }

    /// How many bytes are held, waiting for the rest of a line.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

/// A server's answer: free text, at most [`MAX_RESPONSE`] bytes. Nothing
/// in it marks its end. The server closes the connection after it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Response {
    bytes: Vec<u8>,
}

impl Response {
    /// A response of these bytes, sent as they are. It is an error if
    /// there are more than [`MAX_RESPONSE`].
    pub fn new(bytes: &[u8]) -> Result<Response, EncodeError> {
        if bytes.len() > MAX_RESPONSE {
            return Err(EncodeError::TooLong);
        }
        Ok(Response { bytes: bytes.to_vec() })
    }

    /// A response of `fields`, written by [`write_fields`].
    pub fn from_fields(fields: &[Field]) -> Result<Response, EncodeError> {
        Ok(Response { bytes: write_fields(fields)?.into_bytes() })
    }

    /// The bytes a server sends before it closes the connection.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The response as text. Bytes that are not UTF-8 become U+FFFD, since
    /// some servers still answer in Latin-1.
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    /// The fields of the response, read by [`parse_fields`].
    pub fn fields(&self) -> Result<Vec<Field>, TooManyFields> {
        parse_fields(&self.text())
    }

    /// The first referral in the response, if it has one. See
    /// [`Referral::from_field`].
    pub fn referral(&self) -> Option<Referral> {
        FieldReader::new(&self.text()).find_map(|f| Referral::from_field(&f))
    }
}

/// Collects the bytes of a response until the server closes the
/// connection. It keeps the first [`MAX_RESPONSE`] bytes and drops the
/// rest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseDecoder {
    buf: Vec<u8>,
    truncated: bool,
}

impl ResponseDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> ResponseDecoder {
        ResponseDecoder::default()
    }

    /// Takes bytes read from the connection. All are taken, but only the
    /// first [`MAX_RESPONSE`] in all are kept.
    pub fn feed(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(MAX_RESPONSE.saturating_sub(self.buf.len()));
        self.buf.extend_from_slice(&bytes[..n]);
        if n < bytes.len() {
            self.truncated = true;
        }
    }

    /// Whether bytes were dropped because the response was longer than
    /// [`MAX_RESPONSE`].
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// How many bytes are kept so far.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The response, once the server has closed the connection.
    pub fn finish(self) -> Response {
        Response { bytes: self.buf }
    }
}

/// One `Key: value` field of a response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// Which object the field is in, counting from 0. Objects are split by
    /// blank lines, as in the RIPE database's answers.
    pub block: usize,
    /// The text before the colon, without space at either end.
    pub key: String,
    /// The text after the colon, without space at either end. Each
    /// continuation line adds its own text, after a LF unless the value is
    /// still empty. So a key line with nothing after the colon takes its
    /// value from the lines after it.
    pub value: String,
}

impl Field {
    /// A field with this block, key and value.
    pub fn new(block: usize, key: &str, value: &str) -> Field {
        Field { block, key: key.to_string(), value: value.to_string() }
    }

    /// Whether the key is `key`, ignoring ASCII case.
    pub fn key_is(&self, key: &str) -> bool {
        self.key.eq_ignore_ascii_case(key)
    }
}

/// Reads the `Key: value` layout most WHOIS servers answer with, one
/// field at a time. Lines end at LF, with a CR before it dropped.
///
/// - A line holding only spaces and tabs ends a field and, after one or
///   more fields, the block.
/// - A line that starts with `+`, or is indented deeper than the key line
///   of the field before it, goes on with that field's value. The RIPE
///   database writes values this way. Verisign indents every key by three
///   spaces, so a line indented as deep as the key is a new line.
/// - A line that starts with `%`, `#` or `>>>`, after its indent, is a
///   comment.
/// - A line with a colon followed by a space, a tab or the line's end is
///   a field, if the text before that colon is a key: at most [`MAX_KEY`]
///   bytes, no control characters but tabs, and not starting with `+`.
/// - Any other line is free text and is skipped.
#[derive(Clone, Debug)]
pub struct FieldReader<'a> {
    lines: std::str::Split<'a, char>,
    block: usize,
    block_has_field: bool,
    /// The field being read, and how deep its key line was indented.
    pending: Option<(Field, usize)>,
}

impl<'a> FieldReader<'a> {
    /// A reader of the fields of `text`.
    pub fn new(text: &'a str) -> FieldReader<'a> {
        FieldReader { lines: text.split('\n'), block: 0, block_has_field: false, pending: None }
    }
}

impl Iterator for FieldReader<'_> {
    type Item = Field;

    fn next(&mut self) -> Option<Field> {
        loop {
            let Some(raw) = self.lines.next() else {
                return self.pending.take().map(|(f, _)| f);
            };
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            let body = &line[indent..];
            if body.is_empty() {
                if self.block_has_field {
                    self.block = self.block.saturating_add(1);
                    self.block_has_field = false;
                }
                match self.pending.take() {
                    Some((f, _)) => return Some(f),
                    None => continue,
                }
            }
            if let Some((field, key_indent)) = &mut self.pending {
                let more = if let Some(rest) = line.strip_prefix('+') {
                    Some(trim(rest))
                } else if indent > *key_indent {
                    Some(trim(body))
                } else {
                    None
                };
                if let Some(more) = more {
                    if !field.value.is_empty() {
                        field.value.push('\n');
                    }
                    field.value.push_str(more);
                    continue;
                }
            }
            let finished = self.pending.take().map(|(f, _)| f);
            if !is_comment(body)
                && let Some((key, value)) = key_line(body)
            {
                let field = Field { block: self.block, key: key.to_string(), value: value.to_string() };
                self.pending = Some((field, indent));
                self.block_has_field = true;
            }
            if finished.is_some() {
                return finished;
            }
        }
    }
}

fn is_comment(body: &str) -> bool {
    body.starts_with('%') || body.starts_with('#') || body.starts_with(">>>")
}

/// The key and value of a line with its indent taken off, if it is a
/// field.
fn key_line(body: &str) -> Option<(&str, &str)> {
    let b = body.as_bytes();
    let colon = (0..b.len()).find(|&i| b[i] == b':' && matches!(b.get(i + 1), None | Some(b' ' | b'\t')))?;
    let key = trim(&body[..colon]);
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY
        && !key.starts_with('+')
        && !key.chars().any(|c| c.is_control() && c != '\t');
    if !ok {
        return None;
    }
    Some((key, trim(&body[colon + 1..])))
}

/// Takes spaces and tabs off both ends.
fn trim(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// The fields of `text`, read by a [`FieldReader`]. It is an error if
/// there are more than [`MAX_FIELDS`].
pub fn parse_fields(text: &str) -> Result<Vec<Field>, TooManyFields> {
    let mut out = Vec::new();
    for f in FieldReader::new(text) {
        if out.len() >= MAX_FIELDS {
            return Err(TooManyFields);
        }
        out.push(f);
    }
    Ok(out)
}

/// Writes fields as `Key: value` lines ended by CR LF, with a blank line
/// between blocks. Further lines of a value are indented by
/// [`CONTINUATION_INDENT`], and an empty one is written as `+`.
/// [`parse_fields`] reads the text back as the same fields.
pub fn write_fields(fields: &[Field]) -> Result<String, EncodeError> {
    if fields.len() > MAX_FIELDS {
        return Err(EncodeError::TooLong);
    }
    let mut out = String::new();
    let mut block = 0usize;
    for (i, f) in fields.iter().enumerate() {
        let next_block = block.checked_add(1).ok_or(EncodeError::Block)?;
        if (i == 0 && f.block != 0) || (f.block != block && f.block != next_block) {
            return Err(EncodeError::Block);
        }
        check_key(&f.key)?;
        // Bound the work before splitting the value into lines.
        if f.value.len() > MAX_RESPONSE {
            return Err(EncodeError::TooLong);
        }
        let lines: Vec<&str> = f.value.split('\n').collect();
        if lines.len() > 1 && lines[0].is_empty() {
            return Err(EncodeError::Value);
        }
        for line in &lines {
            if trim(line) != *line || line.chars().any(|c| c.is_control() && c != '\t') {
                return Err(EncodeError::Value);
            }
        }
        // The most this field adds: a blank line, the key line, and each
        // further line with its indent.
        let need = lines
            .len()
            .saturating_mul(CONTINUATION_INDENT.len() + 2)
            .saturating_add(f.key.len())
            .saturating_add(f.value.len())
            .saturating_add(6);
        if out.len().saturating_add(need) > MAX_RESPONSE {
            return Err(EncodeError::TooLong);
        }
        if f.block != block {
            out.push_str("\r\n");
            block = f.block;
        }
        out.push_str(&f.key);
        out.push(':');
        if !lines[0].is_empty() {
            out.push(' ');
            out.push_str(lines[0]);
        }
        out.push_str("\r\n");
        for line in &lines[1..] {
            if line.is_empty() {
                out.push('+');
            } else {
                out.push_str(CONTINUATION_INDENT);
                out.push_str(line);
            }
            out.push_str("\r\n");
        }
    }
    Ok(out)
}

fn check_key(key: &str) -> Result<(), EncodeError> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY
        && trim(key) == key
        && !key.contains(':')
        && !key.chars().any(char::is_control)
        && !key.starts_with(['%', '#', '>', '+']);
    if ok { Ok(()) } else { Err(EncodeError::Key) }
}

/// Which field a referral came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReferralKind {
    /// `refer:`, as IANA answers, naming the registry to ask.
    Refer,
    /// `Registrar WHOIS Server:`, as a thin registry such as Verisign
    /// answers, naming the registrar to ask.
    RegistrarWhoisServer,
    /// `ReferralServer:`, as ARIN answers, naming another regional
    /// registry, usually as `whois://host`.
    ReferralServer,
}

impl ReferralKind {
    /// The key of the field this kind of referral is written as.
    pub fn key(self) -> &'static str {
        match self {
            ReferralKind::Refer => "refer",
            ReferralKind::RegistrarWhoisServer => "Registrar WHOIS Server",
            ReferralKind::ReferralServer => "ReferralServer",
        }
    }

    /// The kind of referral a field's key gives, ignoring ASCII case.
    pub fn from_key(key: &str) -> Option<ReferralKind> {
        [ReferralKind::Refer, ReferralKind::RegistrarWhoisServer, ReferralKind::ReferralServer]
            .into_iter()
            .find(|k| key.eq_ignore_ascii_case(k.key()))
    }
}

/// Where a response says to ask next.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Referral {
    /// The field it came from.
    pub kind: ReferralKind,
    /// The server's host name or address, in lowercase.
    pub host: String,
    /// The server's port: [`PORT`] unless the referral names another.
    pub port: u16,
}

impl Referral {
    /// The referral in a field, if the field is one. The value may be a
    /// host, a host and port (`host:4343`), or either after `whois://`.
    /// A trailing `/` is dropped. Values with another scheme, such as
    /// ARIN's `rwhois://` or a web address, are not WHOIS referrals and
    /// give `None`. So does an empty value, which some registries send
    /// when there is no registrar server. A client that follows referrals
    /// should stop after a few, and when one names the server it just
    /// asked.
    pub fn from_field(field: &Field) -> Option<Referral> {
        let kind = ReferralKind::from_key(&field.key)?;
        let v = trim(&field.value);
        let v = match v.get(..8) {
            Some(s) if s.eq_ignore_ascii_case("whois://") => &v[8..],
            _ if v.contains("://") => return None,
            _ => v,
        };
        let v = v.strip_suffix('/').unwrap_or(v);
        let (host, port) = match v.split_once(':') {
            Some((h, p)) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                match p.parse::<u16>() {
                    Ok(n) if n != 0 => (h, n),
                    _ => return None,
                }
            }
            None => (v, PORT),
        };
        let host = host.to_ascii_lowercase();
        check_host(&host).ok()?;
        Some(Referral { kind, host, port })
    }

    /// The field that names this referral, in block `block`: the host, or
    /// the host and port when the port is not [`PORT`], after `whois://`
    /// for [`ReferralKind::ReferralServer`] as ARIN writes it.
    /// [`Referral::from_field`] reads it back as the same referral.
    pub fn to_field(&self, block: usize) -> Result<Field, EncodeError> {
        check_host(&self.host)?;
        if self.port == 0 {
            return Err(EncodeError::Port);
        }
        let mut value = String::new();
        if self.kind == ReferralKind::ReferralServer {
            value.push_str("whois://");
        }
        value.push_str(&self.host);
        if self.port != PORT {
            value.push(':');
            value.push_str(&self.port.to_string());
        }
        Ok(Field { block, key: self.kind.key().to_string(), value })
    }
}

/// The first referral among `fields`, if there is one.
pub fn find_referral(fields: &[Field]) -> Option<Referral> {
    fields.iter().find_map(Referral::from_field)
}

fn check_host(host: &str) -> Result<(), EncodeError> {
    let ok = !host.is_empty()
        && host.len() <= MAX_HOST
        && !host.starts_with(['.', '-'])
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'));
    if ok { Ok(()) } else { Err(EncodeError::Host) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer in the layout Verisign uses for .com, cut short.
    const VERISIGN: &str = concat!(
        "   Domain Name: EXAMPLE.COM\r\n",
        "   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n",
        "   Registrar WHOIS Server: whois.iana.org\r\n",
        "   Registrar URL: http://res-dom.iana.org\r\n",
        "   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n",
        "   Name Server: A.IANA-SERVERS.NET\r\n",
        "   DNSSEC: signedDelegation\r\n",
        "   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n",
        "   >>> Last update of whois database: 2026-10-05T12:00:00Z <<<\r\n",
        "\r\n",
        "For more information on Whois status codes, please visit https://icann.org/epp\r\n",
        "\r\n",
        "NOTICE: The expiration date displayed in this record is the date the\r\n",
        "registrar's sponsorship of the domain name registration in the registry is\r\n",
    );

    /// An answer in the layout of the RIPE database, cut short.
    const RIPE: &str = concat!(
        "% This is the RIPE Database query service.\n",
        "% The objects are in RPSL format.\n",
        "\n",
        "inetnum:        193.0.0.0 - 193.0.7.255\n",
        "netname:        RIPE-NCC\n",
        "descr:          RIPE Network Coordination Centre\n",
        "                Amsterdam, Netherlands\n",
        "+\n",
        "+               main office\n",
        "country:        NL\n",
        "\n",
        "% Information related to '193.0.0.0/21AS3333'\n",
        "\n",
        "route:          193.0.0.0/21\n",
        "origin:         AS3333\n",
        "\n",
        "% This query was served by the RIPE Database Query Service version 1.0\n",
    );

    /// An answer from IANA for a top-level domain.
    const IANA: &str = concat!(
        "% IANA WHOIS server\n",
        "% for more information on IANA, visit http://www.iana.org\n",
        "% This query returned 1 object\n",
        "\n",
        "refer:        whois.verisign-grs.com\n",
        "\n",
        "domain:       COM\n",
        "\n",
        "organisation: VeriSign Global Registry Services\n",
        "address:      12061 Bluemont Way\n",
        "address:      Reston VA 20190\n",
        "address:      United States of America (the)\n",
    );

    /// An answer from ARIN that sends the client on to RIPE.
    const ARIN: &str = concat!(
        "#\n",
        "# ARIN WHOIS data and services are subject to the Terms of Use\n",
        "#\n",
        "\n",
        "NetRange:       193.0.0.0 - 193.255.255.255\n",
        "CIDR:           193.0.0.0/8\n",
        "NetName:        RIPE-CIDR-BLOCK\n",
        "Organization:   RIPE Network Coordination Centre (RIPE)\n",
        "\n",
        "ReferralServer:  whois://whois.ripe.net\n",
    );

    #[test]
    fn query_line_from_rfc_3912() {
        // RFC 3912, section 2: a single line of text, ended by CR LF.
        let q = Query::new("example.com").unwrap();
        assert_eq!(q.to_bytes(), b"example.com\r\n");
        let mut d = QueryDecoder::new();
        assert_eq!(d.feed(b"example.com\r\n"), 13);
        assert_eq!(d.next_query(), Some(Ok(q)));
        assert_eq!(d.next_query(), None);
        assert_eq!(d.buffered(), 0);
        // A bare LF is read too.
        assert_eq!(d.feed(b"10.0.0.1\n"), 9);
        assert_eq!(d.next_query().unwrap().unwrap().as_str(), "10.0.0.1");
        // An empty line is a query, which servers answer with help.
        assert_eq!(d.feed(b"\r\n"), 2);
        assert_eq!(d.next_query().unwrap().unwrap().as_str(), "");
    }

    #[test]
    fn registry_flags() {
        let q = Query::new("-B -T inetnum 193.0.0.1").unwrap();
        assert_eq!(
            q.flags(),
            [Flag { name: "-B", argument: None }, Flag { name: "-T", argument: Some("inetnum") }]
        );
        assert_eq!(q.terms(), "193.0.0.1");
        let q = Query::new("-T dn,ace example.de").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-T", argument: Some("dn,ace") }]);
        assert_eq!(q.terms(), "example.de");
        let q = Query::new("  --sources\tRIPE  -r   AS3333  ").unwrap();
        assert_eq!(
            q.flags(),
            [Flag { name: "--sources", argument: Some("RIPE") }, Flag { name: "-r", argument: None }]
        );
        assert_eq!(q.terms(), "AS3333");
        // ARIN and Verisign keywords stay in the terms.
        let q = Query::new("n + 8.8.8.8").unwrap();
        assert!(q.flags().is_empty());
        assert_eq!(q.terms(), "n + 8.8.8.8");
        assert_eq!(Query::new("domain example.com").unwrap().terms(), "domain example.com");
        assert_eq!(Query::new("=example.com").unwrap().terms(), "=example.com");
        // A flag that wants an argument at the end has none.
        let q = Query::new("-i").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-i", argument: None }]);
        assert_eq!(q.terms(), "");
        // A dash alone is a term.
        assert_eq!(Query::new("- x").unwrap().terms(), "- x");
        // Built from parts.
        let q = Query::build(&["-B", "-T", "inetnum"], "193.0.0.1").unwrap();
        assert_eq!(q.as_str(), "-B -T inetnum 193.0.0.1");
    }

    #[test]
    fn denic_charset_flag() {
        // DENIC's `-C` takes a character set, as whois clients send it.
        let q = Query::new("-T dn,ace -C UTF-8 example.de").unwrap();
        assert_eq!(
            q.flags(),
            [Flag { name: "-T", argument: Some("dn,ace") }, Flag { name: "-C", argument: Some("UTF-8") }]
        );
        assert_eq!(q.terms(), "example.de");
    }

    #[test]
    fn build_reads_back_as_given() {
        // Terms that start like a flag would be read as one.
        assert_eq!(Query::build(&["-B"], "-r 193.0.0.1"), Err(QueryError::Flags));
        // A flag word that is not a flag would be read as a term.
        assert_eq!(Query::build(&["inetnum"], "193.0.0.1"), Err(QueryError::Flags));
        // Flags must be one word each.
        assert_eq!(Query::build(&["-B -r"], "x"), Err(QueryError::Flags));
        assert_eq!(Query::build(&[""], "x"), Err(QueryError::Flags));
        // A flag that takes an argument and has none eats the terms.
        assert_eq!(Query::build(&["-T"], "inetnum"), Err(QueryError::Flags));
        // These read back as given.
        let q = Query::build(&["-T", "dn,ace", "-C", "UTF-8"], " example.de ").unwrap();
        assert_eq!(q.terms(), "example.de");
        assert_eq!(q.flags().len(), 2);
        assert_eq!(Query::build(&["-B"], "").unwrap().as_str(), "-B ");
        assert_eq!(Query::build(&[], "- x").unwrap().terms(), "- x");
    }

    #[test]
    fn query_errors() {
        assert_eq!(Query::new("a\rb"), Err(QueryError::Control('\r')));
        assert_eq!(Query::new("a\nb"), Err(QueryError::Control('\n')));
        assert_eq!(Query::new("a\u{85}"), Err(QueryError::Control('\u{85}')));
        assert!(Query::new("a\tb").is_ok());
        assert_eq!(Query::parse_line(b"\xffabc"), Err(QueryError::NotUtf8));
        assert_eq!(Query::parse_line(&[b'a'; MAX_QUERY + 1]), Err(QueryError::TooLong));
        assert!(Query::parse_line(&[b'a'; MAX_QUERY]).is_ok());
        assert_eq!(Query::new(&"a".repeat(MAX_QUERY + 1)), Err(QueryError::TooLong));
        assert_eq!(Query::build(&["x"; 2000], ""), Err(QueryError::TooLong));
        assert_eq!(Query::build(&[&"a".repeat(MAX_QUERY)], "b"), Err(QueryError::TooLong));
        for e in [QueryError::TooLong, QueryError::NotUtf8, QueryError::Control('\0'), QueryError::Flags] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_skips_long_lines() {
        let mut d = QueryDecoder::new();
        let mut bytes = vec![b'a'; 3000];
        bytes.extend_from_slice(b"\r\nok\r\n");
        let mut got = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let n = d.feed(rest);
            assert!(d.buffered() <= MAX_BUFFERED);
            rest = &rest[n..];
            while let Some(q) = d.next_query() {
                got.push(q);
            }
        }
        assert_eq!(got, [Err(QueryError::TooLong), Ok(Query::new("ok").unwrap())]);
        // A line one byte too long, ended by a bare LF, is an error too.
        let mut d = QueryDecoder::new();
        let mut line = vec![b'a'; MAX_QUERY + 1];
        line.push(b'\n');
        assert_eq!(d.feed(&line), line.len());
        assert_eq!(d.next_query(), Some(Err(QueryError::TooLong)));
        // The longest line is read.
        let mut line = vec![b'a'; MAX_QUERY];
        line.extend_from_slice(b"\r\n");
        assert_eq!(d.feed(&line), line.len());
        assert_eq!(d.next_query().unwrap().unwrap().as_str().len(), MAX_QUERY);
    }

    #[test]
    fn verisign_layout() {
        let fields = parse_fields(VERISIGN).unwrap();
        assert_eq!(fields[0], Field::new(0, "Domain Name", "EXAMPLE.COM"));
        assert_eq!(fields[2], Field::new(0, "Registrar WHOIS Server", "whois.iana.org"));
        assert_eq!(fields[3].value, "http://res-dom.iana.org");
        assert_eq!(fields[7].key, "URL of the ICANN Whois Inaccuracy Complaint Form");
        assert_eq!(fields[7].value, "https://www.icann.org/wicf/");
        // NOTICE starts a field in block 1, and the next line, at the
        // same indent, is free text.
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[8].key, "NOTICE");
        assert_eq!(fields[8].block, 1);
        let r = Response::new(VERISIGN.as_bytes()).unwrap().referral().unwrap();
        assert_eq!(r, Referral { kind: ReferralKind::RegistrarWhoisServer, host: "whois.iana.org".into(), port: 43 });
    }

    #[test]
    fn ripe_layout() {
        let fields = parse_fields(RIPE).unwrap();
        assert_eq!(
            fields,
            [
                Field::new(0, "inetnum", "193.0.0.0 - 193.0.7.255"),
                Field::new(0, "netname", "RIPE-NCC"),
                Field::new(0, "descr", "RIPE Network Coordination Centre\nAmsterdam, Netherlands\n\nmain office"),
                Field::new(0, "country", "NL"),
                Field::new(1, "route", "193.0.0.0/21"),
                Field::new(1, "origin", "AS3333"),
            ]
        );
        assert_eq!(find_referral(&fields), None);
    }

    #[test]
    fn iana_and_arin_referrals() {
        let fields = parse_fields(IANA).unwrap();
        assert_eq!(fields[0], Field::new(0, "refer", "whois.verisign-grs.com"));
        assert_eq!(fields[1], Field::new(1, "domain", "COM"));
        assert_eq!(fields[2].block, 2);
        assert_eq!(fields.len(), 6);
        assert_eq!(
            find_referral(&fields),
            Some(Referral { kind: ReferralKind::Refer, host: "whois.verisign-grs.com".into(), port: 43 })
        );
        let r = Response::new(ARIN.as_bytes()).unwrap().referral().unwrap();
        assert_eq!(r, Referral { kind: ReferralKind::ReferralServer, host: "whois.ripe.net".into(), port: 43 });
    }

    #[test]
    fn referral_values() {
        let read = |k: &str, v: &str| Referral::from_field(&Field::new(0, k, v));
        let r = read("ReferralServer", "WHOIS://Whois.Example.NET:4343/").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("whois.example.net", 4343));
        assert_eq!(read("refer", "whois.nic.example:43").unwrap().port, 43);
        assert_eq!(read("REFER", "whois.nic.example").unwrap().kind, ReferralKind::Refer);
        assert_eq!(read("registrar whois server", "whois.x").unwrap().kind, ReferralKind::RegistrarWhoisServer);
        assert_eq!(read("ReferralServer", "rwhois://rwhois.example.net:4321"), None);
        assert_eq!(read("Registrar WHOIS Server", "https://whois.example"), None);
        assert_eq!(read("Registrar WHOIS Server", ""), None);
        assert_eq!(read("refer", "host:0"), None);
        assert_eq!(read("refer", "host:"), None);
        assert_eq!(read("refer", "host:99999"), None);
        assert_eq!(read("refer", "host:+43"), None);
        assert_eq!(read("refer", "a b"), None);
        assert_eq!(read("refer", "-host"), None);
        assert_eq!(read("refer", &"a".repeat(MAX_HOST + 1)), None);
        assert_eq!(read("whois", "whois.x"), None);
        assert!(read("refer", &"a".repeat(MAX_HOST)).is_some());
    }

    #[test]
    fn referral_round_trips() {
        for kind in [ReferralKind::Refer, ReferralKind::RegistrarWhoisServer, ReferralKind::ReferralServer] {
            for port in [43, 1, 4343, 65535] {
                let r = Referral { kind, host: "whois.example-1.net".into(), port };
                let f = r.to_field(2).unwrap();
                assert_eq!(f.block, 2);
                assert_eq!(Referral::from_field(&f), Some(r.clone()));
                let resp = Response::from_fields(&[Field::new(0, "a", "b"), Field::new(1, &f.key, &f.value)]).unwrap();
                assert_eq!(resp.referral(), Some(r));
            }
        }
        let r = Referral { kind: ReferralKind::ReferralServer, host: "h".into(), port: 4343 };
        assert_eq!(r.to_field(0).unwrap().value, "whois://h:4343");
        let bad = |host: &str, port| Referral { kind: ReferralKind::Refer, host: host.into(), port }.to_field(0);
        assert_eq!(bad("Upper.example", 43), Err(EncodeError::Host));
        assert_eq!(bad("", 43), Err(EncodeError::Host));
        assert_eq!(bad(".x", 43), Err(EncodeError::Host));
        assert_eq!(bad("a:b", 43), Err(EncodeError::Host));
        assert_eq!(bad("x", 0), Err(EncodeError::Port));
    }

    #[test]
    fn field_layout_rules() {
        // Comments end a field, and so does free text.
        let text = "a: 1\n% c\n  more\nb: 2\nfree text\n  more\n";
        assert_eq!(parse_fields(text).unwrap(), [Field::new(0, "a", "1"), Field::new(0, "b", "2")]);
        // A colon must be followed by a space, a tab or the end.
        let text = "http://x\nk:v\ntime 12:30\nk:\nj:\tv \r\n";
        assert_eq!(parse_fields(text).unwrap(), [Field::new(0, "k", ""), Field::new(0, "j", "v")]);
        // A value on the lines after an empty one.
        let text = "    Registrant:\n        Example Ltd\n        London\n    Status: ok\n";
        assert_eq!(
            parse_fields(text).unwrap(),
            [Field::new(0, "Registrant", "Example Ltd\nLondon"), Field::new(0, "Status", "ok")]
        );
        // Keys that are too long, empty, or start with + are not keys.
        let long = format!("{}: v\n", "k".repeat(MAX_KEY + 1));
        assert_eq!(parse_fields(&long).unwrap(), []);
        assert_eq!(parse_fields(&format!("{}: v", "k".repeat(MAX_KEY))).unwrap().len(), 1);
        assert_eq!(parse_fields(": v\n+k: v\n").unwrap(), []);
        // Blank lines with no field before them do not start a block.
        assert_eq!(parse_fields("\n\n \t\na: 1\n\n\nb: 2").unwrap(), [Field::new(0, "a", "1"), Field::new(1, "b", "2")]);
        assert_eq!(parse_fields("").unwrap(), []);
        assert!(Field::new(0, "Refer", "x").key_is("REFER"));
    }

    #[test]
    fn too_many_fields() {
        let text = "k: v\n".repeat(MAX_FIELDS);
        assert_eq!(parse_fields(&text).unwrap().len(), MAX_FIELDS);
        let text = "k: v\n".repeat(MAX_FIELDS + 1);
        assert_eq!(parse_fields(&text), Err(TooManyFields));
        assert_eq!(Response::new(text.as_bytes()).unwrap().fields(), Err(TooManyFields));
        assert!(!TooManyFields.to_string().is_empty());
        let fields = vec![Field::new(0, "k", "v"); MAX_FIELDS + 1];
        assert_eq!(write_fields(&fields), Err(EncodeError::TooLong));
        assert!(write_fields(&fields[..MAX_FIELDS]).is_ok());
    }

    #[test]
    fn writer_errors() {
        let one = |k: &str, v: &str| write_fields(&[Field::new(0, k, v)]);
        for key in ["", " k", "k ", "a:b", "%k", "#k", ">k", "+k", "k\tx", "k\u{7f}"] {
            assert_eq!(one(key, "v"), Err(EncodeError::Key), "{key:?}");
        }
        assert_eq!(one(&"k".repeat(MAX_KEY + 1), "v"), Err(EncodeError::Key));
        for value in [" v", "v ", "v\r", "a\n b", "\nb", "a\u{1}"] {
            assert_eq!(one("k", value), Err(EncodeError::Value), "{value:?}");
        }
        assert_eq!(write_fields(&[Field::new(1, "k", "v")]), Err(EncodeError::Block));
        assert_eq!(write_fields(&[Field::new(0, "k", "v"), Field::new(2, "k", "v")]), Err(EncodeError::Block));
        assert_eq!(write_fields(&[Field::new(0, "k", "v"), Field::new(1, "k", "v"), Field::new(0, "k", "v")]), Err(EncodeError::Block));
        let big = "v".repeat(MAX_RESPONSE);
        assert_eq!(one("k", &big), Err(EncodeError::TooLong));
        assert_eq!(Response::from_fields(&[Field::new(0, "k", &big)]), Err(EncodeError::TooLong));
        // A value with more lines than one response holds is refused
        // before it is split.
        assert_eq!(one("k", &"a\n".repeat(MAX_RESPONSE)), Err(EncodeError::TooLong));
        assert_eq!(Response::new(&vec![0; MAX_RESPONSE + 1]), Err(EncodeError::TooLong));
        assert!(Response::new(&vec![0; MAX_RESPONSE]).is_ok());
        for e in [EncodeError::Key, EncodeError::Value, EncodeError::Block, EncodeError::TooLong, EncodeError::Host, EncodeError::Port] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writer_round_trips() {
        let fields = [
            Field::new(0, "inetnum", "193.0.0.0 - 193.0.7.255"),
            Field::new(0, "descr", "line one\n\n+plus\n#hash\nkey: like"),
            Field::new(0, "empty", ""),
            Field::new(1, "Registrar WHOIS Server", "whois.example"),
            Field::new(1, "tab", "a\tb"),
            Field::new(2, "trailing", "a\n"),
        ];
        let text = write_fields(&fields).unwrap();
        assert!(text.contains("descr: line one\r\n+\r\n        +plus\r\n"));
        assert_eq!(parse_fields(&text).unwrap(), fields);
        assert_eq!(write_fields(&[]).unwrap(), "");
    }

    #[test]
    fn response_decoder_keeps_the_first_bytes() {
        let mut d = ResponseDecoder::new();
        d.feed(&vec![b'x'; MAX_RESPONSE - 1]);
        assert!(!d.truncated());
        d.feed(b"yz");
        assert!(d.truncated());
        assert_eq!(d.buffered(), MAX_RESPONSE);
        d.feed(b"more");
        let r = d.finish();
        assert_eq!(r.as_bytes().len(), MAX_RESPONSE);
        assert_eq!(r.as_bytes().last(), Some(&b'y'));
        // Latin-1 bytes read as U+FFFD.
        let r = Response::new(b"owner: M\xfcller\n").unwrap();
        assert_eq!(r.fields().unwrap()[0].value, "M\u{fffd}ller");
    }

    #[test]
    fn every_truncated_prefix() {
        let q = Query::new("-B -T inetnum 193.0.0.1").unwrap().to_bytes();
        for n in 0..q.len() {
            let mut d = QueryDecoder::new();
            assert_eq!(d.feed(&q[..n]), n);
            assert_eq!(d.next_query(), None, "{n}");
        }
        for text in [VERISIGN, RIPE, IANA, ARIN] {
            let full = parse_fields(text).unwrap();
            for n in 0..=text.len() {
                let mut d = ResponseDecoder::new();
                d.feed(&text.as_bytes()[..n]);
                let r = d.finish();
                let fields = r.fields().unwrap();
                assert!(fields.len() <= full.len());
                // Every field but the last that was cut is read whole.
                if fields.len() > 1 {
                    assert_eq!(fields[..fields.len() - 1], full[..fields.len() - 1]);
                }
                let _ = r.referral();
            }
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Bytes drawn mostly from those that matter to the layout.
    fn buffer(rng: &mut Lcg) -> Vec<u8> {
        const ALPHABET: &[u8] = b"  \t\t\r\n\n\n::::++%#>-abcKwhois.:/0439\xff\xc3\xa9\x01";
        // Now and then a buffer longer than one query line, so the
        // decoder's long-line path runs.
        let len = if rng.below(16) == 0 { MAX_QUERY - 8 + rng.below(2 * MAX_QUERY) } else { rng.below(300) };
        (0..len)
            .map(|_| if rng.below(20) == 0 { rng.next() as u8 } else { ALPHABET[rng.below(ALPHABET.len())] })
            .collect()
    }

    fn split_queries(data: &[u8], bytewise: bool) -> Vec<Result<Query, QueryError>> {
        let mut d = QueryDecoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
        for chunk in chunks {
            let mut rest = chunk;
            while !rest.is_empty() {
                let took = d.feed(rest);
                assert!(d.buffered() <= MAX_BUFFERED);
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(q) = d.next_query() {
                    out.push(q);
                    progress = true;
                }
                assert!(progress);
            }
        }
        out
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x5eed_3912);
        for _ in 0..4000 {
            let data = buffer(&mut rng);
            // Queries, all at once and a byte at a time.
            let queries = split_queries(&data, false);
            assert_eq!(split_queries(&data, true), queries);
            for q in queries.iter().flatten() {
                let bytes = q.to_bytes();
                assert_eq!(Query::parse_line(&bytes[..bytes.len() - 2]).as_ref(), Ok(q));
                let flags = q.flags();
                let terms = q.terms();
                assert!(flags.len() <= q.as_str().len());
                assert!(terms.len() <= q.as_str().len());
            }
            // Queries built from random words: what build takes reads
            // back as the same flags and terms.
            let text = String::from_utf8_lossy(&data);
            let mut parts: Vec<&str> = text.split(' ').collect();
            let terms = parts.pop().unwrap_or("");
            if let Ok(q) = Query::build(&parts, terms) {
                let words: Vec<&str> = q.flags().iter().flat_map(|f| std::iter::once(f.name).chain(f.argument)).collect();
                assert_eq!(words, parts);
                assert_eq!(q.terms(), trim(terms));
                assert_eq!(split_queries(&q.to_bytes(), false), [Ok(q)]);
            }
            if let Ok(q) = Query::parse_line(&data) {
                assert_eq!(split_queries(&q.to_bytes(), true), [Ok(q)]);
            }
            // Responses, all at once and a byte at a time.
            let mut whole = ResponseDecoder::new();
            whole.feed(&data);
            let mut bytewise = ResponseDecoder::new();
            for b in data.chunks(1) {
                bytewise.feed(b);
            }
            let (whole, bytewise) = (whole.finish(), bytewise.finish());
            assert_eq!(whole, bytewise);
            let fields = whole.fields().unwrap();
            // Fields read can be written back if the writer takes them,
            // and read back the same.
            if let Ok(text) = write_fields(&fields) {
                assert_eq!(parse_fields(&text).unwrap(), fields);
            }
            for f in &fields {
                if let Some(r) = Referral::from_field(f) {
                    assert_eq!(Referral::from_field(&r.to_field(f.block).unwrap()), Some(r));
                }
            }
            assert_eq!(whole.referral(), find_referral(&fields));
            // Fields built from random text: what the writer takes reads
            // back the same.
            let n = rng.below(5);
            let mut built = Vec::new();
            let mut block = 0;
            for i in 0..n {
                if i > 0 && rng.below(3) == 0 {
                    block += 1;
                }
                let key = String::from_utf8_lossy(&buffer(&mut rng)[..]).chars().take(12).collect::<String>();
                let value = String::from_utf8_lossy(&buffer(&mut rng)).into_owned();
                built.push(Field { block, key, value });
            }
            if let Ok(text) = write_fields(&built) {
                assert_eq!(parse_fields(&text).unwrap(), built);
            }
        }
    }

    /// What a [`QueryDecoder`] gives for `data`, worked out line by line: a
    /// line whose bytes and LF fit in [`MAX_BUFFERED`] is read, and a
    /// longer one, ended or not, is one [`QueryError::TooLong`].
    fn expected_queries(data: &[u8]) -> Vec<Result<Query, QueryError>> {
        let mut out = Vec::new();
        let mut parts: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
        let last = parts.pop().unwrap_or(&[]);
        for line in parts {
            if line.len() < MAX_BUFFERED {
                out.push(Query::parse_line(line.strip_suffix(b"\r").unwrap_or(line)));
            } else {
                out.push(Err(QueryError::TooLong));
            }
        }
        if last.len() >= MAX_BUFFERED {
            out.push(Err(QueryError::TooLong));
        }
        out
    }

    #[test]
    fn lcg_fuzz_long_query_lines() {
        // Lines near and past the limit, fed in chunks of random size.
        let mut rng = Lcg(0x1026);
        for _ in 0..1500 {
            let mut data = Vec::new();
            for _ in 0..rng.below(4) {
                let len = match rng.below(4) {
                    0 => rng.below(20),
                    1 => MAX_QUERY - 2 + rng.below(6),
                    _ => rng.below(3 * MAX_QUERY),
                };
                data.extend((0..len).map(|_| b"ab -\t\r"[rng.below(6)]));
                match rng.below(3) {
                    0 => data.extend_from_slice(b"\r\n"),
                    1 => data.push(b'\n'),
                    _ => {}
                }
            }
            let want = expected_queries(&data);
            assert_eq!(split_queries(&data, false), want);
            let mut d = QueryDecoder::new();
            let mut got = Vec::new();
            let mut rest = &data[..];
            while !rest.is_empty() {
                let chunk = &rest[..rest.len().min(1 + rng.below(1500))];
                let took = d.feed(chunk);
                assert!(d.buffered() <= MAX_BUFFERED);
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(q) = d.next_query() {
                    got.push(q);
                    progress = true;
                }
                assert!(progress);
            }
            assert_eq!(got, want);
        }
    }

    #[test]
    fn decoder_is_clone() {
        // A world may copy a decoder part way through a line.
        let mut d = QueryDecoder::new();
        assert_eq!(d.feed(b"exam"), 4);
        assert_eq!(d.next_query(), None);
        let mut e = d.clone();
        assert_eq!(d, e);
        assert_eq!(e.feed(b"ple.com\r\n"), 9);
        assert_eq!(e.next_query().unwrap().unwrap().as_str(), "example.com");
        assert_eq!(d.buffered(), 4);
        let r = ResponseDecoder::new();
        assert_eq!(r.clone(), r);
    }

    #[test]
    fn lcg_fuzz_clean_fields_round_trip() {
        // Keys and values made to pass the writer, so the round trip runs
        // every time.
        let mut rng = Lcg(43);
        const KEY: &[u8] = b"abcXYZ0 -_.";
        const VALUE: &[u8] = b"abc 12:+%#>/\t";
        for _ in 0..2000 {
            let n = 1 + rng.below(6);
            let mut fields = Vec::new();
            let mut block = 0;
            for i in 0..n {
                if i > 0 && rng.below(4) == 0 {
                    block += 1;
                }
                let key: String = (0..1 + rng.below(10)).map(|_| KEY[rng.below(KEY.len())] as char).collect();
                let key = format!("k{}k", key);
                let lines: Vec<String> = (0..1 + rng.below(3))
                    .map(|_| {
                        let s: String = (0..rng.below(12)).map(|_| VALUE[rng.below(VALUE.len())] as char).collect();
                        trim(&s).to_string()
                    })
                    .collect();
                let mut value = lines.join("\n");
                if value.starts_with('\n') {
                    value.insert(0, 'v');
                }
                fields.push(Field { block, key, value });
            }
            let text = write_fields(&fields).unwrap();
            assert_eq!(parse_fields(&text).unwrap(), fields);
            let resp = Response::from_fields(&fields).unwrap();
            let mut d = ResponseDecoder::new();
            for b in resp.as_bytes().chunks(1) {
                d.feed(b);
            }
            assert_eq!(d.finish().fields().unwrap(), fields);
        }
    }
}
