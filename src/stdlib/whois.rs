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
//! A world that plays a WHOIS server pushes query lines into
//! [`Stream<Queries>`](super::codec::Stream), writes a [`Response`], and
//! closes the connection. Query lines accept CRLF and bare LF. A client
//! collects replies with [`Stream<Responses>`](super::codec::Stream) and
//! calls `end` at connection close. The resulting [`CollectedResponse`]
//! preserves the truncation flag. Names, owners, and referrals belong to
//! world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A query line longer than [`MAX_QUERY`] is an error, and the
//! decoder skips it and goes on to the next line. A response is held to
//! [`MAX_RESPONSE`] bytes, and bytes past that are dropped. Writers return
//! an [`EncodeError`] or a [`QueryError`] rather than write bytes a reader
//! would refuse or read back as something else.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, pump};
//! use fictionet::stdlib::whois::{Field, Query, Queries, ReferralKind, Response, Responses};
//!
//! // A client asks the RIPE database about an address, with two flags.
//! let query = Query::new("-B -T inetnum 193.0.0.1").unwrap();
//! assert_eq!(query.to_bytes().unwrap(), b"-B -T inetnum 193.0.0.1\r\n");
//!
//! // A registry reads a query for a name.
//! let mut decoder = Stream::new(Queries::new());
//! let bytes = b"example.com\r\n";
//! assert_eq!(decoder.push(bytes), bytes.len());
//! let got = decoder.next().unwrap().unwrap().unwrap();
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
//! let mut reader = Stream::new(Responses::new());
//! pump(&mut reader, response.as_bytes(), |_| unreachable!()).unwrap();
//! reader.end();
//! let collected = reader.next().unwrap().unwrap();
//! assert!(!collected.truncated);
//! let response = collected.response;
//! assert_eq!(response.fields().unwrap(), fields);
//! let referral = response.referral().unwrap();
//! assert_eq!(referral.kind, ReferralKind::RegistrarWhoisServer);
//! assert_eq!(referral.host, "whois.registrar.example");
//! assert_eq!(referral.port, 43);
//! ```

use super::codec::{self, Decode, Step, Wire};
use std::borrow::Cow;

/// The TCP port WHOIS servers listen on.
pub const PORT: u16 = 43;
/// The longest query line, in bytes, not counting its CR LF.
pub const MAX_QUERY: usize = 1024;
/// The longest response retained by [`Responses`] or held by [`Response`].
pub const MAX_RESPONSE: usize = 1 << 20;
/// Input buffer capacity for [`Responses`], independent of its retained byte limit.
pub const RESPONSE_WINDOW: usize = 4096;
/// The most fields [`parse_fields`] reads and [`Response::from_fields`] writes.
pub const MAX_FIELDS: usize = 10_000;
/// The longest key, in bytes, a line may have to be read as a field.
pub const MAX_KEY: usize = 128;
/// The longest host name, in bytes, a referral may name.
pub const MAX_HOST: usize = 253;
/// How deep [`Response::from_fields`] indents the second and later lines of a
/// value.
pub const CONTINUATION_INDENT: &str = "        ";

/// Flags in the style of the RIPE database that take the word after them
/// as an argument, such as `-T inetnum`. [`Query::flags`] uses this list.
///
/// `-C` is not in it. The RIPE database reads `-C` (`--no-irt`) on its
/// own, while DENIC reads `-C` with a character set, as in
/// `-T dn,ace -C UTF-8 example.de`. So `-C` takes the next word only when
/// that word is one of DENIC's character sets: `UTF-8`, `ISO-8859-1` or
/// `US-ASCII`, in any case.
pub const FLAGS_WITH_ARGUMENT: &[&str] = &[
    "-i",
    "-T",
    "-s",
    "-S",
    "-t",
    "-v",
    "-q",
    "-V",
    "-g",
    "-Z",
    "--inverse",
    "--select-types",
    "--sources",
    "--resources",
    "--template",
    "--verbose",
    "--client",
    "--show-version",
    "--diff-versions",
    "--charset",
];

/// The character sets DENIC's `-C` takes. See [`FLAGS_WITH_ARGUMENT`].
const DENIC_CHARSETS: &[&str] = &["UTF-8", "ISO-8859-1", "US-ASCII"];

/// Whether flag word `w` takes the next word as its argument. A word of
/// short flags grouped together, such as `-Bi`, reads as getopt reads it:
/// the first flag in it that takes an argument takes the rest of the word,
/// or the next word if it is last.
fn takes_next_word(w: &str, next: &str) -> bool {
    if FLAGS_WITH_ARGUMENT.contains(&w) {
        return true;
    }
    if w == "-C" {
        return DENIC_CHARSETS.iter().any(|c| c.eq_ignore_ascii_case(next));
    }
    let Some(group) = w.strip_prefix('-') else { return false };
    if group.starts_with('-') {
        return false;
    }
    let mut chars = group.chars();
    while let Some(c) = chars.next() {
        let wants = FLAGS_WITH_ARGUMENT.iter().any(|f| f.strip_prefix('-').is_some_and(|r| r.chars().eq([c])));
        if wants {
            return chars.as_str().is_empty();
        }
    }
    false
}

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
    /// A key, value, block order, or referral would change when read back.
    /// Keys must be nonempty, at most [`MAX_KEY`] bytes, and have no colon,
    /// control character, outer whitespace, or leading `%`, `#`, `>` or `+`.
    /// Value lines must have no outer whitespace or controls other than tabs.
    /// An empty first value line cannot precede continuation lines. Blocks
    /// start at zero and advance by at most one. Referral hosts must follow
    /// [`Referral::to_field`]'s rules, and ports must be nonzero.
    Unwritable,
    /// More than [`MAX_FIELDS`] fields, or more than [`MAX_RESPONSE`] bytes.
    TooLong,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::Unwritable => f.write_str("value cannot be written without changing it"),
            EncodeError::TooLong => f.write_str("more than one WHOIS response may hold"),
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
    /// The word after the flag, for flags that take one. See
    /// [`Query::flags`].
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
    fn parse_line(line: &[u8]) -> Result<Query, QueryError> {
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

    /// The flags at the start of the query: each word that starts with a
    /// dash and has more after it, up to the first word that does not.
    /// A flag in [`FLAGS_WITH_ARGUMENT`] takes the next word with it, and
    /// so does a group of short flags in one word, such as `-Bi`, that
    /// ends with one. A group with such a flag inside, such as `-Tinetnum`,
    /// holds its argument and stays one [`Flag`] with no `argument`. Flags
    /// after the first term are part of the terms.
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
            if let Some(&(_, a)) = words.get(i)
                && takes_next_word(w, a)
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

    /// Builds a response of `Key: value` lines ended by CRLF, with a blank
    /// line between blocks. Continuations use [`CONTINUATION_INDENT`];
    /// empty continuation lines use `+`. Refuses fields that would change
    /// when read back, unordered blocks, and limits above [`MAX_FIELDS`]
    /// or [`MAX_RESPONSE`]. Keys must be nonempty, at most [`MAX_KEY`]
    /// bytes, without colons, controls, or outer whitespace. They must not
    /// begin with `%`, `#`, `>`, or `+`. Value lines must have no outer
    /// whitespace or controls other than tabs. An empty first value line
    /// cannot precede continuation lines. Blocks start at zero and advance
    /// by at most one.
    pub fn from_fields(fields: &[Field]) -> Result<Response, EncodeError> {
        if fields.len() > MAX_FIELDS {
            return Err(EncodeError::TooLong);
        }
        let mut out = String::new();
        let mut block = 0usize;
        for (i, f) in fields.iter().enumerate() {
            let next_block = block.checked_add(1).ok_or(EncodeError::Unwritable)?;
            if (i == 0 && f.block != 0) || (f.block != block && f.block != next_block) {
                return Err(EncodeError::Unwritable);
            }
            check_key(&f.key)?;
            // Bound the work before splitting the value into lines.
            if f.value.len() > MAX_RESPONSE {
                return Err(EncodeError::TooLong);
            }
            let mut lines = f.value.split('\n');
            let first = lines.next().unwrap_or("");
            if first.is_empty() && f.value.contains('\n') {
                return Err(EncodeError::Unwritable);
            }
            // The exact bytes this field adds: a blank line before a new
            // block, the key line, and each further line.
            let mut need = f.key.len() + 3;
            if f.block != block {
                need += 2;
            }
            if !first.is_empty() {
                need += first.len() + 1;
            }
            for (i, line) in f.value.split('\n').enumerate() {
                if trim(line) != line || line.chars().any(|c| c.is_control() && c != '\t') {
                    return Err(EncodeError::Unwritable);
                }
                if i > 0 {
                    let extra = if line.is_empty() { 3 } else { CONTINUATION_INDENT.len() + line.len() + 2 };
                    need = need.checked_add(extra).ok_or(EncodeError::TooLong)?;
                }
            }
            if out.len().saturating_add(need) > MAX_RESPONSE {
                return Err(EncodeError::TooLong);
            }
            if f.block != block {
                out.push_str("\r\n");
                block = f.block;
            }
            out.push_str(&f.key);
            out.push(':');
            if !first.is_empty() {
                out.push(' ');
                out.push_str(first);
            }
            out.push_str("\r\n");
            for line in lines {
                if line.is_empty() {
                    out.push('+');
                } else {
                    out.push_str(CONTINUATION_INDENT);
                    out.push_str(line);
                }
                out.push_str("\r\n");
            }
        }
        Ok(Response { bytes: out.into_bytes() })
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
/// - A line is a field if the text before its first colon is a key: at
///   most [`MAX_KEY`] bytes, no control characters but tabs, and not
///   starting with `+`. The colon must be followed by a space, a tab or
///   the line's end, unless the key is an RPSL name (RFC 2622, section
///   2), such as `origin` in `origin:AS3333`, and the colon is not
///   followed by `//`, as in a URL.
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
/// field. The key is the text before the first colon.
fn key_line(body: &str) -> Option<(&str, &str)> {
    let colon = body.find(':')?;
    let key = trim(&body[..colon]);
    let rest = &body[colon + 1..];
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY
        && !key.starts_with('+')
        && !key.chars().any(|c| c.is_control() && c != '\t');
    // A colon followed by a space, a tab or the end ends any key. Any
    // other colon ends only an RPSL name, and not before `//`, so a URL
    // at the start of a line stays free text.
    let delimited = rest.is_empty() || rest.starts_with([' ', '\t']) || (is_rpsl_name(key) && !rest.starts_with("//"));
    if !ok || !delimited {
        return None;
    }
    Some((key, trim(rest)))
}

/// Whether `s` is an RPSL name (RFC 2622, section 2): ASCII letters,
/// digits, `_` and `-`, starting with a letter and ending with a letter or
/// a digit.
fn is_rpsl_name(s: &str) -> bool {
    let b = s.as_bytes();
    matches!(b.first(), Some(c) if c.is_ascii_alphabetic())
        && matches!(b.last(), Some(c) if c.is_ascii_alphanumeric())
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
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

fn check_key(key: &str) -> Result<(), EncodeError> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY
        && trim(key) == key
        && !key.contains(':')
        && !key.chars().any(char::is_control)
        && !key.starts_with(['%', '#', '>', '+']);
    if ok { Ok(()) } else { Err(EncodeError::Unwritable) }
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
    /// The server's host name or address, in lowercase. An IPv6 address
    /// is held without its brackets.
    pub host: String,
    /// The server's port: [`PORT`] unless the referral names another.
    pub port: u16,
}

impl Referral {
    /// The referral in a field, if the field is one. The value may be a
    /// host, a host and port (`host:4343`), or either after `whois://`.
    /// An IPv6 address is written in brackets, as in `[2001:db8::1]:4343`,
    /// or bare with no port.
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
        let (host, port) = if let Some(rest) = v.strip_prefix('[') {
            // An IPv6 address in brackets (RFC 3986, section 3.2.2).
            let (h, after) = rest.split_once(']')?;
            if !h.contains(':') {
                return None;
            }
            match after {
                "" => (h, PORT),
                _ => (h, parse_port(after.strip_prefix(':')?)?),
            }
        } else if v.matches(':').count() > 1 {
            // An IPv6 address without brackets, which has no port.
            (v, PORT)
        } else {
            match v.split_once(':') {
                Some((h, p)) => (h, parse_port(p)?),
                None => (v, PORT),
            }
        };
        if host.len() > MAX_HOST {
            return None;
        }
        let host = host.to_ascii_lowercase();
        check_host(&host).ok()?;
        Some(Referral { kind, host, port })
    }

    /// The field that names this referral, in block `block`: the host, in
    /// brackets if it is an IPv6 address, or the host and port when the
    /// port is not [`PORT`], after `whois://`
    /// for [`ReferralKind::ReferralServer`] as ARIN writes it.
    /// [`Referral::from_field`] reads it back as the same referral.
    /// Refuses port zero, hosts above [`MAX_HOST`], and hosts that are not
    /// canonical lowercase IPv6 addresses or ASCII names. Name labels
    /// must have 1 to 63 letters, digits, hyphens, or underscores, with
    /// no leading hyphen. A final dot is allowed.
    pub fn to_field(&self, block: usize) -> Result<Field, EncodeError> {
        check_host(&self.host)?;
        if self.port == 0 {
            return Err(EncodeError::Unwritable);
        }
        let mut value = String::new();
        if self.kind == ReferralKind::ReferralServer {
            value.push_str("whois://");
        }
        if self.host.contains(':') {
            value.push('[');
            value.push_str(&self.host);
            value.push(']');
        } else {
            value.push_str(&self.host);
        }
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

/// A port of 1 to 65535, written in at most five digits.
fn parse_port(p: &str) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse::<u16>().ok().filter(|&n| n != 0)
}

fn check_host(host: &str) -> Result<(), EncodeError> {
    if host.is_empty() || host.len() > MAX_HOST || host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncodeError::Unwritable);
    }
    if host.contains(':') {
        return match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(()),
            Err(_) => Err(EncodeError::Unwritable),
        };
    }
    // Labels of 1 to 63 bytes (RFC 1035, section 2.3.4), and a dot at the
    // end for the root.
    let name = host.strip_suffix('.').unwrap_or(host);
    let ok = !host.starts_with('-')
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'));
    if ok { Ok(()) } else { Err(EncodeError::Unwritable) }
}

/// Why an exact query wire value could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryParseError {
    /// A complete query line was refused.
    Query(QueryError),
    /// The query line was not terminated.
    Incomplete,
    /// Bytes followed the query line.
    Trailing,
}

impl core::fmt::Display for QueryParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Query(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete WHOIS query"),
            Self::Trailing => f.write_str("bytes after WHOIS query"),
        }
    }
}
impl core::error::Error for QueryParseError {}

/// Why bytes cannot be read as one WHOIS response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseParseError {
    /// The response exceeds [`MAX_RESPONSE`].
    TooLong,
}

impl core::fmt::Display for ResponseParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WHOIS response exceeds its byte limit")
    }
}
impl core::error::Error for ResponseParseError {}

impl Wire for Query {
    type ParseError = QueryParseError;
    type WriteError = QueryError;

    /// Reads one UTF-8 query with CRLF or bare LF. Refuses invalid UTF-8,
    /// control characters other than tabs, more than [`MAX_QUERY`] content
    /// bytes, incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Self::ParseError> {
        let mut decoder = Queries::new();
        match decoder
            .decode(bytes, true)
            .map_err(|_| QueryParseError::Incomplete)?
        {
            Step::Item(query, used) if used == bytes.len() => query.map_err(QueryParseError::Query),
            Step::Item(Err(e), _) => Err(QueryParseError::Query(e)),
            Step::Item(_, _) => Err(QueryParseError::Trailing),
            _ => Err(QueryParseError::Incomplete),
        }
    }

    /// Appends a query with CRLF. Refuses text over [`MAX_QUERY`] bytes
    /// or control characters other than tabs. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), QueryError> {
        check_query(&self.text)?;
        out.extend_from_slice(self.text.as_bytes());
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

impl Wire for Response {
    type ParseError = ResponseParseError;
    type WriteError = EncodeError;

    /// Reads a complete response, refusing more than [`MAX_RESPONSE`]
    /// bytes. All byte values are accepted; no line terminator is stripped.
    fn parse(bytes: &[u8]) -> Result<Self, ResponseParseError> {
        Self::new(bytes).map_err(|_| ResponseParseError::TooLong)
    }

    /// Appends response bytes unchanged, refusing an oversized response
    /// before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.bytes.len() > MAX_RESPONSE {
            return Err(EncodeError::TooLong);
        }
        out.extend_from_slice(&self.bytes);
        Ok(())
    }
}

/// Reads one query per item with [`super::codec::Lines`].
///
/// CRLF and bare LF are accepted. Content is
/// bounded by [`MAX_QUERY`]. Bad and overlong lines are error items; an
/// unfinished line at EOF is a terminal [`codec::LineError::Unterminated`].
/// Persistent connections may send several query lines.
pub struct Queries {
    lines: codec::Lines,
}

impl core::fmt::Debug for Queries {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Queries").finish_non_exhaustive()
    }
}
impl Queries {
    /// Creates a reader with a capacity of [`MAX_QUERY`] plus two bytes.
    pub fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_QUERY, codec::Ending::LfOrCrlf),
        }
    }
}
impl Default for Queries {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Queries {
    type Item = Result<Query, QueryError>;
    type Error = codec::LineError;
    const NAME: &'static str = "WHOIS queries";

    fn capacity(&self) -> usize {
        self.lines.capacity()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self
            .lines
            .decode(input, eof)
            .unwrap_or_else(|never| match never {});
        Ok(match step {
            Step::Item(Ok(line), n) => Step::Item(Query::parse_line(&line), n),
            Step::Item(Err(codec::LineError::TooLong { .. }), n) => {
                Step::Item(Err(QueryError::TooLong), n)
            }
            Step::Item(Err(e), _) => return Err(e),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}

/// A response produced at EOF, including whether excess bytes were dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedResponse {
    /// The first bytes of the response, up to the collector's limit.
    pub response: Response,
    /// True only if at least one byte beyond the limit was received.
    pub truncated: bool,
}

/// Collects one response at EOF under a byte limit.
///
/// Free text has no line framing or terminator requirement. Excess bytes
/// are consumed without retaining them. The truncation flag is false
/// at exactly the limit.
/// Input capacity is [`RESPONSE_WINDOW`]; retained state is bounded by the byte limit.
#[derive(Clone, Debug)]
pub struct Responses {
    limit: usize,
    bytes: Vec<u8>,
    truncated: bool,
    taken: bool,
}

impl Responses {
    /// Creates a collector that keeps at most [`MAX_RESPONSE`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_RESPONSE)
    }

    /// Sets the retained byte limit, clamped to [`MAX_RESPONSE`].
    /// Zero keeps no bytes and still produces a response at EOF.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_RESPONSE),
            bytes: Vec::new(),
            truncated: false,
            taken: false,
        }
    }

    /// The maximum number of retained response bytes.
    pub fn limit(&self) -> usize {
        self.limit
    }
}
impl Default for Responses {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Responses {
    type Item = CollectedResponse;
    type Error = core::convert::Infallible;
    const NAME: &'static str = "WHOIS response";

    fn capacity(&self) -> usize {
        RESPONSE_WINDOW
    }
    fn held(&self) -> usize {
        self.bytes.len()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        if self.taken {
            return Ok(Step::End);
        }
        let n = input.len().min(self.limit.saturating_sub(self.bytes.len()));
        self.bytes
            .extend_from_slice(input.get(..n).unwrap_or_default());
        self.truncated |= n < input.len();
        if eof {
            self.taken = true;
            return Ok(Step::Item(
                CollectedResponse {
                    response: Response {
                        bytes: core::mem::take(&mut self.bytes),
                    },
                    truncated: self.truncated,
                },
                input.len(),
            ));
        }
        Ok(if input.is_empty() {
            Step::Need
        } else {
            Step::Skip(input.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Stream, contract, test_support::{Lcg, decode_all, mutate}};

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
        assert_eq!(q.to_bytes().unwrap(), b"example.com\r\n");
        let mut d = Stream::new(Queries::new());
        assert_eq!(d.push(b"example.com\r\n"), 13);
        assert_eq!(d.next(), Some(Ok(Ok(q))));
        assert_eq!(d.next(), None);
        assert_eq!(d.buffered(), 0);
        // A bare LF is read too.
        assert_eq!(d.push(b"10.0.0.1\n"), 9);
        assert_eq!(d.next().unwrap().unwrap().unwrap().as_str(), "10.0.0.1");
        // An empty line is a query, which servers answer with help.
        assert_eq!(d.push(b"\r\n"), 2);
        assert_eq!(d.next().unwrap().unwrap().unwrap().as_str(), "");
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
        assert_eq!(Query::parse(b"\xffabc\r\n"), Err(QueryParseError::Query(QueryError::NotUtf8)));
        assert_eq!(Query::parse(&[vec![b'a'; MAX_QUERY + 1], b"\r\n".to_vec()].concat()), Err(QueryParseError::Query(QueryError::TooLong)));
        assert!(Query::parse(&[vec![b'a'; MAX_QUERY], b"\r\n".to_vec()].concat()).is_ok());
        assert_eq!(Query::new(&"a".repeat(MAX_QUERY + 1)), Err(QueryError::TooLong));
        assert_eq!(Query::build(&["x"; 2000], ""), Err(QueryError::TooLong));
        assert_eq!(Query::build(&[&"a".repeat(MAX_QUERY)], "b"), Err(QueryError::TooLong));
        for e in [QueryError::TooLong, QueryError::NotUtf8, QueryError::Control('\0'), QueryError::Flags] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_skips_long_lines() {
        let mut bytes = vec![b'a'; 3000];
        bytes.extend_from_slice(b"\r\nok\r\n");
        let got = decode_all(Queries::new, &bytes).0;
        contract::check_decode_with_alloc_limit(Queries::new, &bytes, 2 * (MAX_QUERY + 2));
        assert_eq!(got, [Err(QueryError::TooLong), Ok(Query::new("ok").unwrap())]);
        // A line one byte too long, ended by a bare LF, is an error too.
        let mut d = Stream::new(Queries::new());
        let mut line = vec![b'a'; MAX_QUERY + 1];
        line.push(b'\n');
        assert_eq!(d.push(&line), line.len());
        assert_eq!(d.next(), Some(Ok(Err(QueryError::TooLong))));
        // The longest line is read.
        let mut line = vec![b'a'; MAX_QUERY];
        line.extend_from_slice(b"\r\n");
        assert_eq!(d.push(&line), line.len());
        assert_eq!(d.next().unwrap().unwrap().unwrap().as_str().len(), MAX_QUERY);
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
        // A single label longer than 63 bytes is not a host name.
        assert_eq!(read("refer", &"a".repeat(MAX_HOST)), None);
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
        assert_eq!(bad("Upper.example", 43), Err(EncodeError::Unwritable));
        assert_eq!(bad("", 43), Err(EncodeError::Unwritable));
        assert_eq!(bad(".x", 43), Err(EncodeError::Unwritable));
        assert_eq!(bad("a:b", 43), Err(EncodeError::Unwritable));
        assert_eq!(bad("x", 0), Err(EncodeError::Unwritable));
    }

    #[test]
    fn field_layout_rules() {
        // Comments end a field, and so does free text.
        let text = "a: 1\n% c\n  more\nb: 2\nfree text\n  more\n";
        assert_eq!(parse_fields(text).unwrap(), [Field::new(0, "a", "1"), Field::new(0, "b", "2")]);
        // A colon must be followed by a space, a tab or the end, unless
        // the key is an RPSL name.
        let text = "http://x\nk:v\ntime 12:30\nk:\nj:\tv \r\n";
        assert_eq!(
            parse_fields(text).unwrap(),
            [Field::new(0, "k", "v"), Field::new(0, "k", ""), Field::new(0, "j", "v")]
        );
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
        assert_eq!(Response::from_fields(&fields).map(|r| r.text().into_owned()), Err(EncodeError::TooLong));
        assert!(Response::from_fields(&fields[..MAX_FIELDS]).map(|r| r.text().into_owned()).is_ok());
    }

    #[test]
    fn writer_errors() {
        let one = |k: &str, v: &str| Response::from_fields(&[Field::new(0, k, v)]).map(|r| r.text().into_owned());
        for key in ["", " k", "k ", "a:b", "%k", "#k", ">k", "+k", "k\tx", "k\u{7f}"] {
            assert_eq!(one(key, "v"), Err(EncodeError::Unwritable), "{key:?}");
        }
        assert_eq!(one(&"k".repeat(MAX_KEY + 1), "v"), Err(EncodeError::Unwritable));
        for value in [" v", "v ", "v\r", "a\n b", "\nb", "a\u{1}"] {
            assert_eq!(one("k", value), Err(EncodeError::Unwritable), "{value:?}");
        }
        assert_eq!(Response::from_fields(&[Field::new(1, "k", "v")]).map(|r| r.text().into_owned()), Err(EncodeError::Unwritable));
        assert_eq!(Response::from_fields(&[Field::new(0, "k", "v"), Field::new(2, "k", "v")]).map(|r| r.text().into_owned()), Err(EncodeError::Unwritable));
        assert_eq!(Response::from_fields(&[Field::new(0, "k", "v"), Field::new(1, "k", "v"), Field::new(0, "k", "v")]).map(|r| r.text().into_owned()), Err(EncodeError::Unwritable));
        let big = "v".repeat(MAX_RESPONSE);
        assert_eq!(one("k", &big), Err(EncodeError::TooLong));
        assert_eq!(Response::from_fields(&[Field::new(0, "k", &big)]), Err(EncodeError::TooLong));
        // A value with more lines than one response holds is refused
        // before it is split.
        assert_eq!(one("k", &"a\n".repeat(MAX_RESPONSE)), Err(EncodeError::TooLong));
        assert_eq!(Response::new(&vec![0; MAX_RESPONSE + 1]), Err(EncodeError::TooLong));
        assert!(Response::new(&vec![0; MAX_RESPONSE]).is_ok());
        for e in [EncodeError::Unwritable, EncodeError::TooLong] {
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
        let text = Response::from_fields(&fields).map(|r| r.text().into_owned()).unwrap();
        assert!(text.contains("descr: line one\r\n+\r\n        +plus\r\n"));
        assert_eq!(parse_fields(&text).unwrap(), fields);
        assert_eq!(Response::from_fields(&[]).map(|r| r.text().into_owned()).unwrap(), "");
    }

    #[test]
    fn response_collection_keeps_the_first_bytes() {
        let bytes = [vec![b'x'; MAX_RESPONSE - 1], b"yzmore".to_vec()].concat();
        let (items, failure) = decode_all(Responses::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(items.len(), 1);
        assert!(items[0].truncated);
        let r = &items[0].response;
        assert_eq!(r.as_bytes().len(), MAX_RESPONSE);
        assert_eq!(r.as_bytes().last(), Some(&b'y'));
        contract::check_decode_with_alloc_limit(Responses::new, &bytes, 2 * RESPONSE_WINDOW);
        let r = Response::new(b"owner: M\xfcller\n").unwrap();
        assert_eq!(r.fields().unwrap()[0].value, "M\u{fffd}ller");
    }

    #[test]
    fn every_truncated_prefix() {
        let q = Query::new("-B -T inetnum 193.0.0.1").unwrap().to_bytes().unwrap();
        for n in 0..q.len() {
            let mut d = Stream::new(Queries::new());
            assert_eq!(d.push(&q[..n]), n);
            assert_eq!(d.next(), None, "{n}");
        }
        for text in [VERISIGN, RIPE, IANA, ARIN] {
            let full = parse_fields(text).unwrap();
            for n in 0..=text.len() {
                let (items, failure) = decode_all(Responses::new, &text.as_bytes()[..n]);
                assert_eq!(failure, None);
                let r = &items[0].response;
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

    #[test]
    fn random_queries_and_fields() {
        let mut rng = Lcg::new(0x5eed_3912);
        let seeds = [VERISIGN, RIPE, IANA, ARIN, "-B -T inetnum 193.0.0.1\r\n"];
        for _ in 0..4000 {
            let mut data = if rng.coin() { seeds[rng.index(seeds.len())].as_bytes().to_vec() } else { rng.bytes(300) };
            if rng.index(16) == 0 {
                data = vec![b'x'; MAX_QUERY + 1 + rng.index(MAX_QUERY)];
                data.extend_from_slice(b"\r\nexample.com\r\n");
            }
            mutate(&mut rng, &mut data);
            contract::check_decode_with_alloc_limit(Queries::new, &data, 2 * (MAX_QUERY + 2));
            contract::check_decode_with_alloc_limit(Responses::new, &data, 2 * RESPONSE_WINDOW);
            contract::check_wire::<Query>(&data);
            contract::check_wire::<Response>(&data);
            for q in decode_all(Queries::new, &data).0.iter().flatten() {
                contract::check_wire_value(q);
                q.to_bytes().unwrap();
                assert!(q.flags().len() <= q.as_str().len());
                assert!(q.terms().len() <= q.as_str().len());
            }
            let text = String::from_utf8_lossy(&data);
            let mut parts: Vec<_> = text.split(' ').collect();
            let terms = parts.pop().unwrap_or("");
            if let Ok(query) = Query::build(&parts, terms) {
                let words: Vec<_> = query.flags().iter().flat_map(|f| std::iter::once(f.name).chain(f.argument)).collect();
                assert_eq!(words, parts);
                assert_eq!(query.terms(), trim(terms));
                contract::check_wire_value(&query);
            }
            let response = &decode_all(Responses::new, &data).0[0].response;
            let fields = response.fields().unwrap();
            if let Ok(response) = Response::from_fields(&fields) {
                assert_eq!(response.fields().unwrap(), fields);
                contract::check_wire_value(&response);
            }
            for field in &fields {
                if let Some(referral) = Referral::from_field(field) {
                    assert_eq!(Referral::from_field(&referral.to_field(field.block).unwrap()), Some(referral));
                }
            }
            assert_eq!(response.referral(), find_referral(&fields));
            let fields = [Field::new(0, &rng.text(12), &rng.text(80))];
            if let Ok(response) = Response::from_fields(&fields) {
                assert_eq!(response.fields().unwrap(), fields);
                contract::check_wire_value(&response);
            }
        }
    }

    #[test]
    fn long_query_lines() {
        for length in [0, 1, MAX_QUERY - 1, MAX_QUERY, MAX_QUERY + 1, 3 * MAX_QUERY] {
            for ending in [b"\r\n".as_slice(), b"\n"] {
                let data = [vec![b'a'; length], ending.to_vec(), b"next\r\n".to_vec()].concat();
                let expected = if length > MAX_QUERY { Err(QueryError::TooLong) } else { Query::new(&"a".repeat(length)) };
                assert_eq!(decode_all(Queries::new, &data), (vec![expected, Query::new("next")], None));
                contract::check_decode_with_alloc_limit(Queries::new, &data, 2 * (MAX_QUERY + 2));
            }
        }
    }

    #[test]
    fn ripe_flags_read_as_ripe_documents_them() {
        // RIPE's `-C` (`--no-irt`) takes no argument, so the address is the
        // term. DENIC's `-C` takes a character set name.
        let q = Query::new("-C 193.0.0.1").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-C", argument: None }]);
        assert_eq!(q.terms(), "193.0.0.1");
        assert_eq!(Query::new("-C AS3333 x").unwrap().terms(), "AS3333 x");
        assert_eq!(Query::new("-C utf-8 example.de").unwrap().flags()[0].argument, Some("utf-8"));
        assert_eq!(Query::build(&["-C"], "193.0.0.1").unwrap().terms(), "193.0.0.1");
        // `-Z` (`--charset`) and `-S` (`--resources`) take an argument.
        let q = Query::new("-Z UTF-8 AS3333").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-Z", argument: Some("UTF-8") }]);
        assert_eq!(q.terms(), "AS3333");
        assert_eq!(Query::new("-S ARIN-GRS 193.201.1.1").unwrap().terms(), "193.201.1.1");
        assert_eq!(Query::new("--charset UTF-8 AS3333").unwrap().terms(), "AS3333");
        // Short flags grouped in one word: the last one may take the
        // next word, and one inside the group takes the rest of the word.
        let q = Query::new("-Bi tech-c DW-RIPE").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-Bi", argument: Some("tech-c") }]);
        assert_eq!(q.terms(), "DW-RIPE");
        let q = Query::new("-Tas-set AS-FOO").unwrap();
        assert_eq!(q.flags(), [Flag { name: "-Tas-set", argument: None }]);
        assert_eq!(q.terms(), "AS-FOO");
        assert_eq!(Query::new("-rB AS3333").unwrap().terms(), "AS3333");
        assert_eq!(Query::build(&["-Bi", "origin"], "AS3333").unwrap().terms(), "AS3333");
        assert_eq!(Query::build(&["-Bi"], "origin AS3333"), Err(QueryError::Flags));
    }

    #[test]
    fn rpsl_values_right_after_the_colon() {
        // RFC 2622, section 2: the name, a colon, then the value.
        assert_eq!(parse_fields("origin:AS3333\n").unwrap(), [Field::new(0, "origin", "AS3333")]);
        assert_eq!(parse_fields("remarks:a: b\n").unwrap(), [Field::new(0, "remarks", "a: b")]);
        assert_eq!(parse_fields("descr: a: b\n").unwrap(), [Field::new(0, "descr", "a: b")]);
        // A key is never read with a colon in it.
        assert_eq!(parse_fields("time 12:30: x\n").unwrap(), []);
        // Free text that is not an RPSL name, or a URL, is not a field.
        assert_eq!(parse_fields("see https://icann.org/epp\nhttp://x\nab-:c\n1a:b\n").unwrap(), []);
    }

    #[test]
    fn ipv6_referrals() {
        let read = |v: &str| Referral::from_field(&Field::new(0, "ReferralServer", v));
        let r = read("whois://[2001:DB8::1]:4343").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("2001:db8::1", 4343));
        assert_eq!(read("whois://[2001:db8::1]/").unwrap().port, 43);
        assert_eq!(read("2001:db8::1").unwrap().host, "2001:db8::1");
        assert_eq!(read("[2001:db8::1]").unwrap().host, "2001:db8::1");
        assert_eq!(read("[2001:db8::1]:0"), None);
        assert_eq!(read("[2001:db8::1]x"), None);
        assert_eq!(read("[2001:db8::1"), None);
        assert_eq!(read("[example.net]"), None);
        assert_eq!(read("[fe80::1%eth0]"), None);
        for kind in [ReferralKind::Refer, ReferralKind::RegistrarWhoisServer, ReferralKind::ReferralServer] {
            for port in [43, 4343] {
                let r = Referral { kind, host: "2001:db8::1".into(), port };
                let f = r.to_field(0).unwrap();
                assert_eq!(Referral::from_field(&f), Some(r));
            }
        }
        let r = Referral { kind: ReferralKind::Refer, host: "2001:db8::1".into(), port: 4343 };
        assert_eq!(r.to_field(0).unwrap().value, "[2001:db8::1]:4343");
        let bad = Referral { kind: ReferralKind::Refer, host: "2001:DB8::1".into(), port: 43 };
        assert_eq!(bad.to_field(0), Err(EncodeError::Unwritable));
    }

    #[test]
    fn host_labels() {
        // RFC 1035, section 2.3.4: labels are 1 to 63 bytes.
        let read = |v: &str| Referral::from_field(&Field::new(0, "refer", v));
        assert_eq!(read(&format!("{}.example", "a".repeat(64))), None);
        assert!(read(&format!("{}.example", "a".repeat(63))).is_some());
        assert_eq!(read("a..example"), None);
        assert!(read("whois.example.").is_some());
        assert_eq!(read("whois.example.."), None);
        let longest = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
        assert_eq!(longest.len(), MAX_HOST);
        assert!(read(&longest).is_some());
        assert_eq!(read(&format!("{longest}e")), None);
        let bad = Referral { kind: ReferralKind::Refer, host: "a..b".into(), port: 43 };
        assert_eq!(bad.to_field(0), Err(EncodeError::Unwritable));
    }

    #[test]
    fn writer_takes_what_fits() {
        // "k: " and CR LF around a value make exactly MAX_RESPONSE bytes.
        let text = Response::from_fields(&[Field::new(0, "k", &"a".repeat(MAX_RESPONSE - 5))]).map(|r| r.text().into_owned()).unwrap();
        assert_eq!(text.len(), MAX_RESPONSE);
        assert_eq!(Response::from_fields(&[Field::new(0, "k", &"a".repeat(MAX_RESPONSE - 4))]).map(|r| r.text().into_owned()), Err(EncodeError::TooLong));
        // Empty further lines are written as "+" and CR LF.
        let value = format!("a{}", "\n".repeat(100_000));
        assert_eq!(Response::from_fields(&[Field::new(0, "k", &value)]).map(|r| r.text().into_owned()).unwrap().len(), 300_006);
        // A blank line between blocks counts too.
        let fields = [Field::new(0, "k", ""), Field::new(1, "k", &"a".repeat(MAX_RESPONSE - 11))];
        assert_eq!(Response::from_fields(&fields).map(|r| r.text().into_owned()).unwrap().len(), MAX_RESPONSE);
        let fields = [Field::new(0, "k", ""), Field::new(1, "k", &"a".repeat(MAX_RESPONSE - 10))];
        assert_eq!(Response::from_fields(&fields).map(|r| r.text().into_owned()), Err(EncodeError::TooLong));
    }

    #[test]
    fn partial_query_waits_and_eof_refuses() {
        let mut stream = Stream::new(Queries::new());
        assert_eq!(stream.push(b"exam"), 4);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.buffered(), 4);
        assert_eq!(stream.push(b"ple.com\r\n"), 9);
        assert_eq!(stream.next().unwrap().unwrap().unwrap().as_str(), "example.com");
        assert_eq!(stream.buffered(), 0);
        let (_, failure) = decode_all(Queries::new, b"exam");
        assert_eq!(failure, Some(codec::Fail::Protocol(codec::LineError::Unterminated)));
    }

    #[test]
    fn random_clean_fields_round_trip() {
        // Keys and values made to pass the writer, so the round trip runs
        // every time.
        let mut rng = Lcg::new(43);
        const KEY: &[u8] = b"abcXYZ0 -_.";
        const VALUE: &[u8] = b"abc 12:+%#>/\t";
        for _ in 0..2000 {
            let n = 1 + rng.index(6);
            let mut fields = Vec::new();
            let mut block = 0;
            for i in 0..n {
                if i > 0 && rng.index(4) == 0 {
                    block += 1;
                }
                let key: String = (0..1 + rng.index(10)).map(|_| KEY[rng.index(KEY.len())] as char).collect();
                let key = format!("k{}k", key);
                let lines: Vec<String> = (0..1 + rng.index(3))
                    .map(|_| {
                        let s: String = (0..rng.index(12)).map(|_| VALUE[rng.index(VALUE.len())] as char).collect();
                        trim(&s).to_string()
                    })
                    .collect();
                let mut value = lines.join("\n");
                if value.starts_with('\n') {
                    value.insert(0, 'v');
                }
                fields.push(Field { block, key, value });
            }
            let text = Response::from_fields(&fields).map(|r| r.text().into_owned()).unwrap();
            assert_eq!(parse_fields(&text).unwrap(), fields);
            let resp = Response::from_fields(&fields).unwrap();
            contract::check_decode_with_alloc_limit(Responses::new, resp.as_bytes(), 2 * RESPONSE_WINDOW);
            assert_eq!(decode_all(Responses::new, resp.as_bytes()).0[0].response.fields().unwrap(), fields);
        }
    }
}
