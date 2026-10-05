//! XML 1.0: a pull parser and a writer, with no I/O.
//!
//! XML carries the bodies of SOAP calls, XMPP streams, RSS and Atom feeds,
//! SAML assertions and many web APIs. A document is a tree of elements,
//! each with a name and attributes, holding text and other elements. This
//! module follows W3C Extensible Markup Language (XML) 1.0, Fifth Edition,
//! and Namespaces in XML 1.0, Third Edition.
//!
//! Nothing here reads a socket. A world feeds the bytes of a body to a
//! [`Parser`], as they arrive, and takes [`Event`]s out: the declaration,
//! start and end tags with their attributes, text, CDATA sections,
//! comments and processing instructions. Names come back with their
//! namespaces resolved. A [`Writer`] builds a document from the same
//! pieces and escapes what needs escaping.
//!
//! The parser does not validate. It checks that a document is well formed,
//! resolves the five predefined entities (`&lt;` and the rest) and character
//! references, and refuses any other entity. It checks the grammar of a
//! DTD's internal subset and applies the attribute declarations there:
//! defaults are supplied and values of tokenized types are normalized. It
//! never expands an entity declared there, which keeps out entity expansion
//! attacks, and it refuses parameter entity references. It reads UTF-8
//! only.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Depth, name length, attribute count, namespace bindings and the
//! size of the whole document are capped by the `MAX_` constants, and a
//! document past a cap is an [`Error`], not a crash or a long stall. What a
//! [`Writer`] writes, the [`Parser`] reads. Attribute defaults supplied
//! from a DTD count toward the size cap too, so a short declaration used on
//! many elements cannot grow the events past it.
//!
//! Use [`Frames`] with [`codec::Stream`] for bounded event decoding.
//! [`Frame`] implements [`Wire`] for complete documents without losing bytes.
//! The deprecated [`Parser`] keeps its original buffering and errors.
//!
//! ```
//! # #![allow(deprecated)]
//! use fictionet::stdlib::xml::{Event, Parser, Writer};
//!
//! let mut parser = Parser::new();
//! parser.feed(br#"<?xml version="1.0"?>
//! <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
//!   <s:Body><price currency="EUR">3 &lt; 4</price></s:Body>
//! </s:Envelope>"#);
//! parser.finish();
//! let mut currency = None;
//! let mut text = String::new();
//! let mut inside_price = false;
//! while let Some(event) = parser.next_event() {
//!     match event.unwrap() {
//!         Event::Start(start) if start.name.local == "price" => {
//!             currency = start.attribute(None, "currency").map(String::from);
//!             inside_price = true;
//!         }
//!         Event::Start(start) if start.name.local == "Body" => {
//!             assert_eq!(start.name.namespace.as_deref(), Some("http://www.w3.org/2003/05/soap-envelope"));
//!         }
//!         Event::Text(t) if inside_price => text.push_str(&t),
//!         Event::End(_) => inside_price = false,
//!         _ => {}
//!     }
//! }
//! assert!(parser.is_done());
//! assert_eq!(currency.as_deref(), Some("EUR"));
//! assert_eq!(text, "3 < 4");
//!
//! let mut w = Writer::new();
//! w.start("reply", &[("ok", "a\"b")]).unwrap();
//! w.text("1 & 2").unwrap();
//! w.end().unwrap();
//! assert_eq!(w.finish().unwrap(), r#"<reply ok="a&quot;b">1 &amp; 2</reply>"#);
//! ```

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use super::codec::{self, Decode, Wire};

/// The largest document a [`Parser`] reads or a [`Writer`] writes, in
/// bytes.
pub const MAX_DOCUMENT: usize = 4 << 20;
/// The most elements that may be open at once.
pub const MAX_DEPTH: usize = 256;
/// The longest name, in bytes: element and attribute names with their
/// prefixes, processing instruction targets, the doctype's name and entity
/// names.
pub const MAX_NAME: usize = 256;
/// The most attributes one start tag may carry, namespace declarations
/// included.
pub const MAX_ATTRIBUTES: usize = 256;
/// The most namespace bindings in scope at once, counted over all open
/// elements.
pub const MAX_NAMESPACES: usize = 1024;
/// The namespace the `xml` prefix is always bound to.
pub const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
/// The namespace of `xmlns` attributes, which declare namespaces.
pub const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;

/// A name as written, split at its colon, with the namespace it resolves
/// to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    /// The part before the colon, if there is one.
    pub prefix: Option<String>,
    /// The part after the colon, or the whole name.
    pub local: String,
    /// The namespace URI the name is in. An element without a prefix is in
    /// the default namespace, if one is declared. An attribute without a
    /// prefix is in none, except `xmlns`. The names one declaration binds
    /// share one copy of its URI.
    pub namespace: Option<Arc<str>>,
}

impl Name {
    /// The name as written: the prefix, a colon and the local part.
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    /// Whether this is `local` in `namespace`.
    pub fn is(&self, namespace: Option<&str>, local: &str) -> bool {
        self.namespace.as_deref() == namespace && self.local == local
    }
}

/// One attribute of a start tag. Namespace declarations (`xmlns` and
/// `xmlns:p`) are attributes too, in [`XMLNS_NAMESPACE`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attribute {
    /// The attribute's name.
    pub name: Name,
    /// The value, with references replaced and whitespace normalized as the
    /// specification says: each tab, newline or carriage return written
    /// as such becomes a space.
    pub value: String,
}

/// A start tag: an element's name and attributes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Start {
    /// The element's name.
    pub name: Name,
    /// The attributes, in the order written.
    pub attributes: Vec<Attribute>,
}

impl Start {
    /// The value of the attribute `local` in `namespace`, if the tag has
    /// one.
    pub fn attribute(&self, namespace: Option<&str>, local: &str) -> Option<&str> {
        self.attributes.iter().find(|a| a.name.is(namespace, local)).map(|a| a.value.as_str())
    }
}

/// One piece of a document, in the order it comes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Event {
    /// The XML declaration, `<?xml version="1.0" ...?>`, which may only
    /// open a document.
    Declaration {
        /// The version, such as `1.0`.
        version: String,
        /// The encoding named, if any. This module reads only UTF-8.
        encoding: Option<String>,
        /// Whether the document said it stands alone, if it said.
        standalone: Option<bool>,
    },
    /// A document type declaration. Only its name is kept. The external
    /// identifier is not read. The internal subset is checked, and the
    /// attribute defaults it declares show up as attributes of the start
    /// tags they apply to.
    Doctype {
        /// The name of the root element it declares.
        name: String,
    },
    /// A start tag. An empty element, `<a/>`, gives a start and then an
    /// end.
    Start(Start),
    /// An end tag, with the same name its start had.
    End(Name),
    /// Character data inside the root element, with references replaced
    /// and line ends turned into `\n`. Whitespace outside the root element
    /// gives no event.
    Text(String),
    /// The content of a CDATA section, as written, with line ends turned
    /// into `\n`.
    CData(String),
    /// The content of a comment, between `<!--` and `-->`.
    Comment(String),
    /// A processing instruction, `<?target data?>`.
    Pi {
        /// The target, which names what the instruction is for.
        target: String,
        /// Everything after the whitespace that follows the target.
        data: String,
    },
}

/// What is wrong with a document, or with what a [`Writer`] was asked to
/// write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The bytes are not UTF-8.
    InvalidUtf8,
    /// A character XML does not allow, such as a control character, even
    /// written as a reference.
    InvalidChar,
    /// A name that is empty, starts with a character a name may not start
    /// with, or has a colon where a namespace-aware name may not.
    BadName,
    /// Markup that does not follow the grammar: a missing `=`, quote or
    /// space, a stray `<` in a tag or an attribute value, or an unknown
    /// `<!` construct.
    BadSyntax,
    /// An XML declaration that is malformed or not at the very start.
    BadDeclaration,
    /// A declaration names an encoding other than UTF-8.
    UnsupportedEncoding,
    /// A comment holds `--` or ends with `-`.
    BadComment,
    /// A `&` that does not start a well-formed reference, or a character
    /// reference to a number that is not a character.
    BadReference,
    /// A reference to an entity other than the five predefined ones, or a
    /// parameter entity reference in the internal subset.
    UnknownEntity,
    /// Text holds `]]>`, or CDATA given to a writer does.
    CdataEndInText,
    /// A processing instruction's target is `xml` in any case, outside the
    /// declaration.
    ReservedPi,
    /// Processing instruction data given to a writer holds `?>`.
    BadPi,
    /// A doctype after another one or after the root element.
    MisplacedDoctype,
    /// Two attributes of a tag have the same name, or the same local name
    /// in the same namespace.
    DuplicateAttribute,
    /// An end tag whose name is not that of the open element.
    MismatchedEnd,
    /// Text, CDATA, an end tag or a second root element outside the root
    /// element.
    OutsideRoot,
    /// A prefix with no namespace declared for it.
    UndeclaredPrefix,
    /// A namespace declaration the Namespaces specification forbids, such
    /// as `xmlns:p=""` or binding `xmlns`, or an element named with the
    /// `xmlns` prefix. A [`Writer`] also gives it for an event whose names
    /// would read back in a different namespace.
    BadNamespace,
    /// The input ended inside markup, with elements still open, or before
    /// any root element.
    UnexpectedEnd,
    /// EOF arrived with an element still open in [`Frames`].
    Incomplete,
    /// The document is longer than [`MAX_DOCUMENT`], or the attribute
    /// defaults it supplies add up to more than that. For a [`Writer`], the
    /// piece would not fit with the end tags of the open elements.
    TooLarge,
    /// More than [`MAX_DEPTH`] elements open at once, or groups in a DTD's
    /// content model nested deeper than that.
    TooDeep,
    /// A name longer than [`MAX_NAME`].
    NameTooLong,
    /// A tag with more than [`MAX_ATTRIBUTES`] attributes, defaults
    /// included, or more declared for one element in a DTD.
    TooManyAttributes,
    /// More than [`MAX_NAMESPACES`] namespace bindings in scope.
    TooManyNamespaces,
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ErrorKind::InvalidUtf8 => "not UTF-8",
            ErrorKind::InvalidChar => "a character XML does not allow",
            ErrorKind::BadName => "a malformed name",
            ErrorKind::BadSyntax => "malformed markup",
            ErrorKind::BadDeclaration => "a malformed or misplaced XML declaration",
            ErrorKind::UnsupportedEncoding => "an encoding other than UTF-8",
            ErrorKind::BadComment => "a comment holding -- or ending with -",
            ErrorKind::BadReference => "a malformed reference",
            ErrorKind::UnknownEntity => "a reference to an undeclared entity",
            ErrorKind::CdataEndInText => "]]> in text",
            ErrorKind::ReservedPi => "a processing instruction named xml",
            ErrorKind::BadPi => "?> in processing instruction data",
            ErrorKind::MisplacedDoctype => "a misplaced doctype",
            ErrorKind::DuplicateAttribute => "a repeated attribute",
            ErrorKind::MismatchedEnd => "an end tag that does not match its start",
            ErrorKind::OutsideRoot => "content outside the root element",
            ErrorKind::UndeclaredPrefix => "an undeclared namespace prefix",
            ErrorKind::BadNamespace => "a forbidden namespace declaration",
            ErrorKind::UnexpectedEnd => "the input ended early",
            ErrorKind::Incomplete => "the input ended with an open element",
            ErrorKind::TooLarge => "a document over the size limit",
            ErrorKind::TooDeep => "elements nested past the depth limit",
            ErrorKind::NameTooLong => "a name over the length limit",
            ErrorKind::TooManyAttributes => "a tag with too many attributes",
            ErrorKind::TooManyNamespaces => "too many namespace bindings",
        })
    }
}

impl core::error::Error for ErrorKind {}

/// Why a document is not well formed, and where. Once a parser gives an
/// error, the document cannot be read any further.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Error {
    /// What is wrong.
    pub kind: ErrorKind,
    /// The byte offset, from the start of the document, of the markup or
    /// text where it went wrong.
    pub offset: usize,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for Error {}

/// One complete XML document in its original wire form.
///
/// Keeping the bytes preserves declarations and spacing that [`Event`]
/// intentionally omits. [`Wire`] validates the complete document and
/// refuses trailing content outside XML's document grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The document bytes, bounded by [`MAX_DOCUMENT`] when parsed or written.
    pub data: Vec<u8>,
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(input: &[u8]) -> Result<Self, Error> {
        parse(input)?;
        Ok(Self {
            data: input.to_vec(),
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        parse(&self.data)?;
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Reads XML events from caller-owned input.
///
/// The document and each token are bounded by [`MAX_DOCUMENT`]. Scanning
/// resumes where it stopped when more bytes arrive. EOF completes final
/// text. Partial markup returns [`codec::Step::Need`]; an open element
/// returns [`ErrorKind::Incomplete`]. Syntax and limit errors are terminal.
/// Capacity is [`MAX_DOCUMENT`] plus one byte to detect overflow.
/// Use [`codec::Stream`] for bounded buffering and one-time errors.
#[derive(Clone, Debug, Default)]
pub struct Frames {
    offset: usize,
    state_held: usize,
    declarations_held: usize,
    bom_checked: bool,
    pending: Option<Event>,
    scan: Scan,
    doc: Doc,
}

impl Frames {
    /// Starts a document within the module's named limits.
    pub fn new() -> Self {
        Self::default()
    }

    fn error(&self, kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: self.offset,
        }
    }

    fn consume(&mut self, n: usize) {
        self.offset += n;
        self.scan = Scan::default();
        self.update_held();
    }

    fn update_held(&mut self) {
        // Shared namespace text is counted once in interned. Names and
        // bindings are bounded by the document, depth, and namespace caps.
        let names = self.doc.stack.iter().fold(0usize, |n, open| {
            n.saturating_add(open.qname.len())
                .saturating_add(open.name.local.len())
                .saturating_add(open.name.prefix.as_ref().map_or(0, String::len))
                .saturating_add(open.bound.iter().map(String::len).sum::<usize>())
        });
        let namespaces = self.doc.interned.keys().map(|s| s.len()).sum::<usize>();
        let prefixes = self.doc.scope.keys().map(String::len).sum::<usize>();
        let pending = match &self.pending {
            Some(Event::End(n)) => {
                n.local.len()
                    + n.prefix.as_ref().map_or(0, String::len)
                    + n.namespace.as_ref().map_or(0, |s| s.len())
            }
            _ => 0,
        };
        self.state_held = names
            .saturating_add(namespaces)
            .saturating_add(prefixes)
            .saturating_add(self.declarations_held)
            .saturating_add(pending);
    }

    fn need(&self, input: &[u8], eof: bool) -> Result<codec::Step<Event>, Error> {
        if self.offset.saturating_add(input.len()) > MAX_DOCUMENT {
            return Err(self.error(ErrorKind::TooLarge));
        }
        if eof && !self.doc.stack.is_empty() {
            return Err(self.error(ErrorKind::Incomplete));
        }
        Ok(codec::Step::Need)
    }
}

impl Decode for Frames {
    type Item = Event;
    type Error = Error;
    const NAME: &'static str = "XML";

    fn capacity(&self) -> usize {
        MAX_DOCUMENT + 1
    }

    fn held(&self) -> usize {
        self.state_held
            .saturating_add(XML_NAMESPACE.len() + XMLNS_NAMESPACE.len())
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Event>, Error> {
        if let Some(event) = self.pending.take() {
            self.update_held();
            return Ok(codec::Step::Item(event, 0));
        }
        if input.is_empty() {
            if eof && self.offset > 0 && !self.doc.root_seen {
                return Err(self.error(ErrorKind::UnexpectedEnd));
            }
            return self.need(input, eof);
        }
        // Do not let bytes beyond the document cap complete a token.
        let room = MAX_DOCUMENT.saturating_sub(self.offset);
        let rest = input.get(..input.len().min(room)).unwrap_or_default();
        let finished = eof && input.len() <= room;
        if !self.bom_checked {
            match prefix_state(rest, b"\xEF\xBB\xBF") {
                None => return self.need(input, eof),
                Some(true) => {
                    self.bom_checked = true;
                    self.consume(3);
                    return Ok(codec::Step::Skip(3));
                }
                Some(false) => self.bom_checked = true,
            }
        }
        let kind = match token_kind(rest) {
            Some(k) => k.map_err(|k| self.error(k))?,
            None => return self.need(input, eof),
        };
        let len = match find_end(rest, kind, &mut self.scan, finished).map_err(|k| self.error(k))? {
            Some(len) if len > 0 => len,
            _ => return self.need(input, eof),
        };
        let tok = core::str::from_utf8(rest.get(..len).unwrap_or_default())
            .map_err(|_| self.error(ErrorKind::InvalidUtf8))?;
        if !tok.chars().all(is_xml_char) {
            return Err(self.error(ErrorKind::InvalidChar));
        }
        let empty = kind == Kind::StartTag && tok.ends_with("/>");
        let event = read_token(&mut self.doc, kind, tok).map_err(|k| self.error(k))?;
        if kind == Kind::Doctype {
            // The DTD table is set once. Do not walk it on every token.
            self.declarations_held = self.doc.attlists.iter().fold(0usize, |n, (name, list)| {
                n.saturating_add(name.len())
                    .saturating_add(list.types.keys().map(String::len).sum::<usize>())
                    .saturating_add(
                        list.defaults
                            .iter()
                            .map(|(k, v)| k.len() + v.len())
                            .sum::<usize>(),
                    )
            });
        }
        if let Some(Event::Start(start)) = &event
            && empty
        {
            let name = self
                .doc
                .end(&start.name.qname())
                .map_err(|k| self.error(k))?;
            self.pending = Some(Event::End(name));
        }
        self.consume(len);
        Ok(match event {
            Some(event) => codec::Step::Item(event, len),
            None => codec::Step::Skip(len),
        })
    }
}

/// A pull parser. Feed it a document's bytes, in order and in pieces of any
/// size, call [`Parser::finish`] when they end, and take events out until
/// it has none.
///
/// The events and errors do not depend on how the bytes were split. A
/// parser holds at most [`MAX_DOCUMENT`] bytes, and scans each byte a
/// bounded number of times, however the input arrives.
#[derive(Clone, Debug, Default)]
#[deprecated(note = "use codec::Stream with xml::Frames")]
pub struct Parser {
    buf: Vec<u8>,
    /// Where the next token starts in `buf`.
    start: usize,
    /// The document offset of `buf[0]`.
    base: usize,
    /// How many bytes have been taken in.
    total: usize,
    overflow: bool,
    finished: bool,
    done: bool,
    bom_checked: bool,
    failed: Option<Error>,
    pending: Option<Event>,
    scan: Scan,
    doc: Doc,
}

/// What kind of token starts the unread bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Text,
    StartTag,
    EndTag,
    Pi,
    Comment,
    CData,
    Doctype,
}

/// How far the search for the current token's end has gone, so a parser
/// fed a byte at a time does not search the same bytes again.
#[derive(Clone, Copy, Debug, Default)]
struct Scan {
    pos: usize,
    quote: u8,
    state: u8,
}

/// What one step of the parser found.
enum Step {
    Event(Event),
    Skip,
    More,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Parser {
    /// A parser at the start of a document.
    pub fn new() -> Parser {
        Parser::default()
    }

    /// Adds the document's next bytes. Bytes past [`MAX_DOCUMENT`] are
    /// dropped, and the parser gives [`ErrorKind::TooLarge`] once it has
    /// read the rest. Bytes fed after an error or after
    /// [`Parser::finish`] are dropped too.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() || self.finished || self.overflow {
            return;
        }
        let room = MAX_DOCUMENT.saturating_sub(self.total);
        let take = bytes.len().min(room);
        if take < bytes.len() {
            self.overflow = true;
        }
        self.buf.extend_from_slice(&bytes[..take]);
        self.total += take;
    }

    /// Says the document has no more bytes. Markup or elements still open
    /// then are an [`ErrorKind::UnexpectedEnd`].
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// Whether the whole document has been read, well formed, after
    /// [`Parser::finish`].
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// How many bytes are held, waiting to be read.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The next event. It returns `None` when it needs more bytes, or when
    /// the document is done, and keeps returning the same error once the
    /// document has broken.
    pub fn next_event(&mut self) -> Option<Result<Event, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if let Some(ev) = self.pending.take() {
            return Some(Ok(ev));
        }
        if self.done {
            return None;
        }
        loop {
            let offset = self.base + self.start;
            match self.step() {
                Ok(Step::Event(ev)) => return Some(Ok(ev)),
                Ok(Step::Skip) => continue,
                Ok(Step::More) => {
                    if self.overflow {
                        return Some(Err(self.fail(ErrorKind::TooLarge, offset)));
                    }
                    if !self.finished {
                        return None;
                    }
                    if self.start < self.buf.len() {
                        return Some(Err(self.fail(ErrorKind::UnexpectedEnd, offset)));
                    }
                    return match self.doc.finish() {
                        Ok(()) => {
                            self.done = true;
                            self.buf = Vec::new();
                            self.start = 0;
                            None
                        }
                        Err(kind) => Some(Err(self.fail(kind, offset))),
                    };
                }
                Err(kind) => return Some(Err(self.fail(kind, offset))),
            }
        }
    }

    fn fail(&mut self, kind: ErrorKind, offset: usize) -> Error {
        let e = Error { kind, offset };
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        self.pending = None;
        e
    }

    /// Takes `n` bytes as read and moves on to the next token.
    fn consume(&mut self, n: usize) {
        self.start += n;
        self.scan = Scan::default();
        if self.start == self.buf.len() {
            self.base += self.start;
            self.buf.clear();
            self.start = 0;
        } else if self.start > 4096 && self.start * 2 > self.buf.len() {
            self.buf.drain(..self.start);
            self.base += self.start;
            self.start = 0;
        }
    }

    /// Reads one token, if all of it is there.
    fn step(&mut self) -> Result<Step, ErrorKind> {
        // Past the size limit the input did not end; it was cut. A token
        // still open then waits, and the caller gives TooLarge, whether or
        // not finish came first.
        let finished = self.finished && !self.overflow;
        let rest = &self.buf[self.start..];
        if rest.is_empty() {
            return Ok(Step::More);
        }
        if !self.bom_checked {
            match prefix_state(rest, b"\xEF\xBB\xBF") {
                None if !finished => return Ok(Step::More),
                Some(true) => {
                    self.bom_checked = true;
                    self.consume(3);
                    return Ok(Step::Skip);
                }
                _ => self.bom_checked = true,
            }
        }
        let kind = match token_kind(rest) {
            Some(k) => k?,
            None if finished => return Err(ErrorKind::UnexpectedEnd),
            None => return Ok(Step::More),
        };
        let len = match find_end(rest, kind, &mut self.scan, finished)? {
            Some(n) => n,
            None if finished => return Err(ErrorKind::UnexpectedEnd),
            None => return Ok(Step::More),
        };
        let tok = core::str::from_utf8(&rest[..len]).map_err(|_| ErrorKind::InvalidUtf8)?;
        if !tok.chars().all(is_xml_char) {
            return Err(ErrorKind::InvalidChar);
        }
        let empty = kind == Kind::StartTag && tok.ends_with("/>");
        let event = read_token(&mut self.doc, kind, tok)?;
        self.consume(len);
        Ok(match event {
            Some(Event::Start(start)) if empty => {
                let name = self.doc.end(&start.name.qname())?;
                self.pending = Some(Event::End(name));
                Step::Event(Event::Start(start))
            }
            Some(ev) => Step::Event(ev),
            None => Step::Skip,
        })
    }
}

/// Reads a whole document at once: its events, or the first error.
#[allow(deprecated)] // Preserve the one-shot parser behavior.
pub fn parse(document: &[u8]) -> Result<Vec<Event>, Error> {
    let mut p = Parser::new();
    p.feed(document);
    p.finish();
    let mut events = Vec::new();
    while let Some(ev) = p.next_event() {
        events.push(ev?);
    }
    Ok(events)
}

/// Whether `b` starts with `pat`: `None` if it is too short to say.
fn prefix_state(b: &[u8], pat: &[u8]) -> Option<bool> {
    if b.len() >= pat.len() {
        Some(b.starts_with(pat))
    } else if pat.starts_with(b) {
        None
    } else {
        Some(false)
    }
}

/// The kind of token at the start of `rest`, or `None` if more bytes are
/// needed to say.
fn token_kind(rest: &[u8]) -> Option<Result<Kind, ErrorKind>> {
    if rest.first() != Some(&b'<') {
        return Some(Ok(Kind::Text));
    }
    match rest.get(1)? {
        b'/' => Some(Ok(Kind::EndTag)),
        b'?' => Some(Ok(Kind::Pi)),
        b'!' => {
            let mut waiting = false;
            for (pat, kind) in
                [(&b"<!--"[..], Kind::Comment), (b"<![CDATA[", Kind::CData), (b"<!DOCTYPE", Kind::Doctype)]
            {
                match prefix_state(rest, pat) {
                    Some(true) => return Some(Ok(kind)),
                    None => waiting = true,
                    Some(false) => {}
                }
            }
            if waiting { None } else { Some(Err(ErrorKind::BadSyntax)) }
        }
        _ => Some(Ok(Kind::StartTag)),
    }
}

/// The length of the token of `kind` at the start of `rest`, or `None` if
/// its end has not come. Text ends at the next `<`, or at the end of the
/// input once it has finished.
fn find_end(rest: &[u8], kind: Kind, s: &mut Scan, finished: bool) -> Result<Option<usize>, ErrorKind> {
    match kind {
        Kind::Text => match rest.get(s.pos..).and_then(|r| r.iter().position(|&b| b == b'<')) {
            Some(i) => Ok(Some(s.pos + i)),
            None => {
                s.pos = rest.len();
                Ok(if finished { Some(rest.len()) } else { None })
            }
        },
        Kind::Comment => Ok(find_pattern(rest, b"-->", 4, s)),
        Kind::CData => Ok(find_pattern(rest, b"]]>", 9, s)),
        Kind::Pi => Ok(find_pattern(rest, b"?>", 2, s)),
        Kind::StartTag | Kind::EndTag => {
            let mut i = s.pos.max(1);
            while let Some(&b) = rest.get(i) {
                if b == b'<' {
                    return Err(ErrorKind::BadSyntax);
                }
                if s.quote != 0 {
                    if b == s.quote {
                        s.quote = 0;
                    }
                } else if b == b'"' || b == b'\'' {
                    s.quote = b;
                } else if b == b'>' {
                    return Ok(Some(i + 1));
                }
                i += 1;
            }
            s.pos = i;
            Ok(None)
        }
        Kind::Doctype => doctype_end(rest, s, finished),
    }
}

/// Finds `pat` at or after `from`, starting where the last search stopped.
fn find_pattern(rest: &[u8], pat: &[u8], from: usize, s: &mut Scan) -> Option<usize> {
    let begin = from.max(s.pos.saturating_sub(pat.len() - 1));
    let found = rest.get(begin..).and_then(|r| r.windows(pat.len()).position(|w| w == pat));
    match found {
        Some(i) => Some(begin + i + pat.len()),
        None => {
            s.pos = rest.len();
            None
        }
    }
}

/// The end of a doctype, skipping quoted strings and the internal subset
/// with the comments and processing instructions in it.
fn doctype_end(rest: &[u8], s: &mut Scan, finished: bool) -> Result<Option<usize>, ErrorKind> {
    const NORMAL: u8 = 0;
    const SUBSET: u8 = 1;
    const COMMENT: u8 = 2;
    const PI: u8 = 3;
    const AFTER: u8 = 4;
    let mut i = s.pos.max(9);
    while let Some(&b) = rest.get(i) {
        if s.quote != 0 {
            if b == s.quote {
                s.quote = 0;
            }
            i += 1;
            continue;
        }
        let here = &rest[i..];
        match s.state {
            NORMAL => match b {
                b'"' | b'\'' => s.quote = b,
                b'[' => s.state = SUBSET,
                b'>' => return Ok(Some(i + 1)),
                b'<' => return Err(ErrorKind::BadSyntax),
                _ => {}
            },
            SUBSET => match b {
                b'"' | b'\'' => s.quote = b,
                b']' => s.state = AFTER,
                b'<' => match (prefix_state(here, b"<!--"), prefix_state(here, b"<?")) {
                    (Some(true), _) => {
                        s.state = COMMENT;
                        i += 4;
                        continue;
                    }
                    (_, Some(true)) => {
                        s.state = PI;
                        i += 2;
                        continue;
                    }
                    (None, _) | (_, None) if !finished => {
                        s.pos = i;
                        return Ok(None);
                    }
                    _ => {}
                },
                _ => {}
            },
            COMMENT | PI => {
                let pat: &[u8] = if s.state == COMMENT { b"-->" } else { b"?>" };
                if b == pat[0] {
                    match prefix_state(here, pat) {
                        Some(true) => {
                            s.state = SUBSET;
                            i += pat.len();
                            continue;
                        }
                        None if !finished => {
                            s.pos = i;
                            return Ok(None);
                        }
                        _ => {}
                    }
                }
            }
            _ => match b {
                b'>' => return Ok(Some(i + 1)),
                b' ' | b'\t' | b'\r' | b'\n' => {}
                _ => return Err(ErrorKind::BadSyntax),
            },
        }
        i += 1;
    }
    s.pos = i;
    Ok(None)
}

/// Reads one whole token, already checked to be UTF-8 and XML characters.
fn read_token(doc: &mut Doc, kind: Kind, tok: &str) -> Result<Option<Event>, ErrorKind> {
    match kind {
        Kind::Text => {
            let ws = tok.bytes().all(is_space);
            if !doc.text(ws)? {
                return Ok(None);
            }
            if tok.contains("]]>") {
                return Err(ErrorKind::CdataEndInText);
            }
            Ok(Some(Event::Text(decode(tok, false)?)))
        }
        Kind::Comment => {
            let body = &tok[4..tok.len() - 3];
            if body.contains("--") || body.ends_with('-') {
                return Err(ErrorKind::BadComment);
            }
            doc.misc();
            Ok(Some(Event::Comment(normalize(body))))
        }
        Kind::CData => {
            doc.cdata()?;
            Ok(Some(Event::CData(normalize(&tok[9..tok.len() - 3]))))
        }
        Kind::Pi => read_pi(doc, &tok[2..tok.len() - 2]).map(Some),
        Kind::Doctype => {
            let (name, attlists) = read_doctype(&tok[9..tok.len() - 1])?;
            doc.doctype()?;
            doc.attlists = attlists;
            Ok(Some(Event::Doctype { name: name.to_string() }))
        }
        Kind::EndTag => {
            let mut c = Cur::new(&tok[2..tok.len() - 1]);
            let name = c.name()?;
            c.ws();
            if !c.at_end() {
                return Err(ErrorKind::BadSyntax);
            }
            Ok(Some(Event::End(doc.end(name)?)))
        }
        Kind::StartTag => {
            let mut c = Cur::new(&tok[1..tok.len() - 1]);
            let name = c.name()?;
            let mut attrs: Vec<(String, String)> = Vec::new();
            loop {
                let ws = c.ws();
                if c.at_end() {
                    break;
                }
                if c.eat("/") {
                    if !c.at_end() {
                        return Err(ErrorKind::BadSyntax);
                    }
                    break;
                }
                if !ws {
                    return Err(ErrorKind::BadSyntax);
                }
                let an = c.name()?;
                if attrs.len() >= MAX_ATTRIBUTES {
                    return Err(ErrorKind::TooManyAttributes);
                }
                c.eq()?;
                let raw = c.quoted()?;
                attrs.push((an.to_string(), decode(raw, true)?));
            }
            Ok(Some(Event::Start(doc.start(name, attrs, &[])?)))
        }
    }
}

/// Reads a doctype, given what lies between `<!DOCTYPE` and the final `>`,
/// and returns its name and the attribute declarations of its internal
/// subset. The name is a QName, and an external identifier is `SYSTEM` and
/// a literal, or `PUBLIC` and two.
fn read_doctype(inner: &str) -> Result<(&str, BTreeMap<String, AttList>), ErrorKind> {
    let mut c = Cur::new(inner);
    need_ws(&mut c)?;
    let name = c.name()?;
    split_qname(name)?;
    if c.ws() && (c.rest().starts_with("PUBLIC") || c.rest().starts_with("SYSTEM")) {
        external_id(&mut c, false)?;
        c.ws();
    }
    if c.at_end() {
        Ok((name, BTreeMap::new()))
    } else if c.eat("[") {
        Ok((name, read_subset(&mut c)?))
    } else {
        Err(ErrorKind::BadSyntax)
    }
}

/// The attributes a DTD declares for one element type.
#[derive(Clone, Debug, Default)]
struct AttList {
    /// Each declared attribute's name, and whether its type is tokenized
    /// (anything but CDATA). The first declaration of a name counts.
    types: BTreeMap<String, bool>,
    /// The attributes with a default value, in the order declared.
    defaults: Vec<(String, String)>,
}

fn need_ws(c: &mut Cur<'_>) -> Result<(), ErrorKind> {
    if c.ws() { Ok(()) } else { Err(ErrorKind::BadSyntax) }
}

fn need(c: &mut Cur<'_>, p: &str) -> Result<(), ErrorKind> {
    if c.eat(p) { Ok(()) } else { Err(ErrorKind::BadSyntax) }
}

/// Reads a name that must be a QName: element and attribute names.
fn qname_at<'a>(c: &mut Cur<'a>) -> Result<&'a str, ErrorKind> {
    let n = c.name()?;
    split_qname(n)?;
    Ok(n)
}

/// Reads a name that may hold no colon: entity and notation names.
fn ncname_at<'a>(c: &mut Cur<'a>) -> Result<&'a str, ErrorKind> {
    let n = c.name()?;
    if is_ncname(n) { Ok(n) } else { Err(ErrorKind::BadName) }
}

/// Reads an external identifier: `SYSTEM` and a literal, or `PUBLIC` and a
/// public identifier and a literal. In a notation declaration the last
/// literal after `PUBLIC` may be left out.
fn external_id(c: &mut Cur<'_>, system_optional: bool) -> Result<(), ErrorKind> {
    let public = c.eat("PUBLIC");
    if !public && !c.eat("SYSTEM") {
        return Err(ErrorKind::BadSyntax);
    }
    need_ws(c)?;
    if public {
        let id = c.quoted()?;
        let pubid = |b: u8| b.is_ascii_alphanumeric() || b" \r\n-'()+,./:=?;!*#@$_%".contains(&b);
        if !id.bytes().all(pubid) {
            return Err(ErrorKind::BadSyntax);
        }
        if system_optional {
            let save = c.i;
            if !(c.ws() && c.rest().starts_with(['"', '\''])) {
                c.i = save;
                return Ok(());
            }
        } else {
            need_ws(c)?;
        }
    }
    c.quoted()?;
    Ok(())
}

/// Reads the internal subset after its `[`, through the `]` and the
/// whitespace after it (section 2.8, productions 28b to 29). It returns the
/// attribute declarations, by element name.
fn read_subset(c: &mut Cur<'_>) -> Result<BTreeMap<String, AttList>, ErrorKind> {
    let mut lists = BTreeMap::new();
    loop {
        c.ws();
        if c.eat("]") {
            c.ws();
            return if c.at_end() { Ok(lists) } else { Err(ErrorKind::BadSyntax) };
        }
        if c.eat("<!--") {
            let r = c.rest();
            let end = r.find("-->").ok_or(ErrorKind::BadSyntax)?;
            let body = &r[..end];
            if body.contains("--") || body.ends_with('-') {
                return Err(ErrorKind::BadComment);
            }
            c.i += end + 3;
        } else if c.eat("<?") {
            let r = c.rest();
            let end = r.find("?>").ok_or(ErrorKind::BadSyntax)?;
            let mut p = Cur::new(&r[..end]);
            check_pi_target(p.name()?)?;
            if !p.at_end() && !p.ws() {
                return Err(ErrorKind::BadSyntax);
            }
            c.i += end + 2;
        } else if c.eat("<!ELEMENT") {
            element_decl(c)?;
        } else if c.eat("<!ATTLIST") {
            attlist_decl(c, &mut lists)?;
        } else if c.eat("<!ENTITY") {
            entity_decl(c)?;
        } else if c.eat("<!NOTATION") {
            need_ws(c)?;
            ncname_at(c)?;
            need_ws(c)?;
            external_id(c, true)?;
            c.ws();
            need(c, ">")?;
        } else if c.eat("%") {
            // A parameter entity reference. This module expands no entity
            // a DTD declares.
            return Err(match c.name() {
                Ok(_) if c.eat(";") => ErrorKind::UnknownEntity,
                Err(ErrorKind::NameTooLong) => ErrorKind::NameTooLong,
                _ => ErrorKind::BadReference,
            });
        } else {
            return Err(ErrorKind::BadSyntax);
        }
    }
}

/// Reads an element type declaration after `<!ELEMENT` (section 3.2).
fn element_decl(c: &mut Cur<'_>) -> Result<(), ErrorKind> {
    need_ws(c)?;
    qname_at(c)?;
    need_ws(c)?;
    if c.eat("EMPTY") || c.eat("ANY") {
    } else if c.eat("(") {
        c.ws();
        if c.eat("#PCDATA") {
            // Mixed content: names after #PCDATA need the closing `)*`.
            let mut names = false;
            loop {
                c.ws();
                if c.eat(")") {
                    if names {
                        need(c, "*")?;
                    } else {
                        c.eat("*");
                    }
                    break;
                }
                need(c, "|")?;
                c.ws();
                qname_at(c)?;
                names = true;
            }
        } else {
            content_group(c, 1)?;
            occurrence(c);
        }
    } else {
        return Err(ErrorKind::BadSyntax);
    }
    c.ws();
    need(c, ">")
}

/// Reads a choice or sequence after its `(`, through its `)`. Groups nest
/// at most [`MAX_DEPTH`] deep.
fn content_group(c: &mut Cur<'_>, depth: usize) -> Result<(), ErrorKind> {
    if depth > MAX_DEPTH {
        return Err(ErrorKind::TooDeep);
    }
    c.ws();
    content_particle(c, depth)?;
    c.ws();
    for sep in ["|", ","] {
        if c.eat(sep) {
            loop {
                c.ws();
                content_particle(c, depth)?;
                c.ws();
                if !c.eat(sep) {
                    break;
                }
            }
            break;
        }
    }
    need(c, ")")
}

fn content_particle(c: &mut Cur<'_>, depth: usize) -> Result<(), ErrorKind> {
    if c.eat("(") {
        content_group(c, depth + 1)?;
    } else {
        qname_at(c)?;
    }
    occurrence(c);
    Ok(())
}

fn occurrence(c: &mut Cur<'_>) {
    let _ = c.eat("?") || c.eat("*") || c.eat("+");
}

/// Reads an attribute-list declaration after `<!ATTLIST` (section 3.3),
/// adding what it declares to `lists`.
fn attlist_decl(c: &mut Cur<'_>, lists: &mut BTreeMap<String, AttList>) -> Result<(), ErrorKind> {
    need_ws(c)?;
    let element = qname_at(c)?;
    let list = lists.entry(element.to_string()).or_default();
    loop {
        let ws = c.ws();
        if c.eat(">") {
            return Ok(());
        }
        if !ws {
            return Err(ErrorKind::BadSyntax);
        }
        let name = qname_at(c)?;
        need_ws(c)?;
        let tokenized = if c.eat("(") {
            token_list(c, false)?;
            true
        } else {
            match c.name()? {
                "CDATA" => false,
                "ID" | "IDREF" | "IDREFS" | "ENTITY" | "ENTITIES" | "NMTOKEN" | "NMTOKENS" => true,
                "NOTATION" => {
                    need_ws(c)?;
                    need(c, "(")?;
                    token_list(c, true)?;
                    true
                }
                _ => return Err(ErrorKind::BadSyntax),
            }
        };
        need_ws(c)?;
        let default = if c.eat("#REQUIRED") || c.eat("#IMPLIED") {
            None
        } else {
            if c.eat("#FIXED") {
                need_ws(c)?;
            }
            let value = decode(c.quoted()?, true)?;
            Some(if tokenized { collapse_spaces(&value) } else { value })
        };
        if list.types.contains_key(name) {
            continue;
        }
        if list.types.len() >= MAX_ATTRIBUTES {
            return Err(ErrorKind::TooManyAttributes);
        }
        list.types.insert(name.to_string(), tokenized);
        if let Some(v) = default {
            list.defaults.push((name.to_string(), v));
        }
    }
}

/// Reads an enumeration's tokens, or a notation type's names, after `(`
/// and through `)`.
fn token_list(c: &mut Cur<'_>, names: bool) -> Result<(), ErrorKind> {
    loop {
        c.ws();
        if names {
            ncname_at(c)?;
        } else {
            c.nmtoken()?;
        }
        c.ws();
        if c.eat(")") {
            return Ok(());
        }
        need(c, "|")?;
    }
}

/// Reads an entity declaration after `<!ENTITY` (section 4.2). The entity
/// is never expanded, but its declaration must be well formed.
fn entity_decl(c: &mut Cur<'_>) -> Result<(), ErrorKind> {
    need_ws(c)?;
    let parameter = c.eat("%");
    if parameter {
        need_ws(c)?;
    }
    ncname_at(c)?;
    need_ws(c)?;
    if c.rest().starts_with(['"', '\'']) {
        entity_value(c.quoted()?)?;
    } else {
        external_id(c, false)?;
        if !parameter {
            let save = c.i;
            if c.ws() && c.eat("NDATA") {
                need_ws(c)?;
                ncname_at(c)?;
            } else {
                c.i = save;
            }
        }
    }
    c.ws();
    need(c, ">")
}

/// Checks a literal entity value. In the internal subset it may hold no
/// parameter entity reference, and each `&` starts a reference.
fn entity_value(v: &str) -> Result<(), ErrorKind> {
    let mut rest = v;
    while let Some(i) = rest.find(['%', '&']) {
        if rest.as_bytes()[i] == b'%' {
            return Err(ErrorKind::BadSyntax);
        }
        let tail = &rest[i + 1..];
        let semi = match tail.bytes().position(|b| b == b';' || b == b'&') {
            Some(n) if tail.as_bytes()[n] == b';' => n,
            _ => return Err(ErrorKind::BadReference),
        };
        let r = &tail[..semi];
        if r.starts_with('#') {
            resolve(r)?;
        } else {
            let mut n = Cur::new(r);
            match n.name() {
                Ok(_) if n.at_end() => {}
                Err(ErrorKind::NameTooLong) => return Err(ErrorKind::NameTooLong),
                _ => return Err(ErrorKind::BadReference),
            }
        }
        rest = &tail[semi + 1..];
    }
    Ok(())
}

/// Drops leading and trailing spaces and turns each run of spaces into
/// one, as section 3.3.3 does to values of a tokenized type.
fn collapse_spaces(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for word in v.split(' ').filter(|w| !w.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// Reads a processing instruction or the XML declaration, given what lies
/// between `<?` and `?>`.
fn read_pi(doc: &mut Doc, inner: &str) -> Result<Event, ErrorKind> {
    let mut c = Cur::new(inner);
    let target = c.name()?;
    if target == "xml" {
        if doc.started {
            return Err(ErrorKind::BadDeclaration);
        }
        return read_declaration(doc, c);
    }
    check_pi_target(target)?;
    let data = if c.at_end() {
        ""
    } else if c.ws() {
        c.rest()
    } else {
        return Err(ErrorKind::BadSyntax);
    };
    doc.misc();
    Ok(Event::Pi { target: target.to_string(), data: normalize(data) })
}

fn check_pi_target(target: &str) -> Result<(), ErrorKind> {
    if target.contains(':') {
        return Err(ErrorKind::BadName);
    }
    if target.eq_ignore_ascii_case("xml") {
        return Err(ErrorKind::ReservedPi);
    }
    Ok(())
}

/// Reads the XML declaration after its `xml`.
fn read_declaration(doc: &mut Doc, mut c: Cur<'_>) -> Result<Event, ErrorKind> {
    let bad = |_| ErrorKind::BadDeclaration;
    if !c.ws() || !c.eat("version") {
        return Err(ErrorKind::BadDeclaration);
    }
    c.eq().map_err(bad)?;
    let version = c.quoted().map_err(bad)?;
    check_version(version)?;
    let mut ws = c.ws();
    let mut encoding = None;
    if ws && c.eat("encoding") {
        c.eq().map_err(bad)?;
        let e = c.quoted().map_err(bad)?;
        check_encoding(e)?;
        encoding = Some(e.to_string());
        ws = c.ws();
    }
    let mut standalone = None;
    if ws && c.eat("standalone") {
        c.eq().map_err(bad)?;
        standalone = Some(match c.quoted().map_err(bad)? {
            "yes" => true,
            "no" => false,
            _ => return Err(ErrorKind::BadDeclaration),
        });
        c.ws();
    }
    if !c.at_end() {
        return Err(ErrorKind::BadDeclaration);
    }
    doc.decl()?;
    Ok(Event::Declaration { version: version.to_string(), encoding, standalone })
}

fn check_version(v: &str) -> Result<(), ErrorKind> {
    match v.strip_prefix("1.") {
        Some(d) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()) => Ok(()),
        _ => Err(ErrorKind::BadDeclaration),
    }
}

fn check_encoding(e: &str) -> Result<(), ErrorKind> {
    let mut b = e.bytes();
    let ok = b.next().is_some_and(|f| f.is_ascii_alphabetic())
        && b.all(|x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'_' | b'-'));
    if !ok {
        Err(ErrorKind::BadDeclaration)
    } else if !e.eq_ignore_ascii_case("UTF-8") {
        Err(ErrorKind::UnsupportedEncoding)
    } else {
        Ok(())
    }
}

/// Replaces references and normalizes line ends. In an attribute value,
/// each literal tab, newline or carriage return becomes a space, a
/// carriage return and newline together becoming one.
fn decode(s: &str, attr: bool) -> Result<String, ErrorKind> {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(ch) = s.get(i..).and_then(|r| r.chars().next()) {
        i += ch.len_utf8();
        match ch {
            '&' => {
                // A reference holds no `&`, so stopping at the next one
                // keeps the whole search linear.
                let tail = &s[i..];
                let semi = match tail.bytes().position(|b| b == b';' || b == b'&') {
                    Some(n) if tail.as_bytes()[n] == b';' => n,
                    _ => return Err(ErrorKind::BadReference),
                };
                out.push(resolve(&tail[..semi])?);
                i += semi + 1;
            }
            '\r' => {
                out.push(if attr { ' ' } else { '\n' });
                if s.as_bytes().get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            '\n' | '\t' if attr => out.push(' '),
            '<' => return Err(ErrorKind::BadSyntax),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// The character a reference names, given what lies between `&` and `;`.
fn resolve(r: &str) -> Result<char, ErrorKind> {
    let code = if let Some(hex) = r.strip_prefix("#x") {
        number(hex, 16)?
    } else if let Some(dec) = r.strip_prefix('#') {
        number(dec, 10)?
    } else {
        return match r {
            "lt" => Ok('<'),
            "gt" => Ok('>'),
            "amp" => Ok('&'),
            "apos" => Ok('\''),
            "quot" => Ok('"'),
            _ => {
                let mut c = Cur::new(r);
                match c.name() {
                    Ok(_) if c.at_end() => Err(ErrorKind::UnknownEntity),
                    Err(ErrorKind::NameTooLong) => Err(ErrorKind::NameTooLong),
                    _ => Err(ErrorKind::BadReference),
                }
            }
        };
    };
    char::from_u32(code).filter(|&c| is_xml_char(c)).ok_or(ErrorKind::BadReference)
}

fn number(digits: &str, radix: u32) -> Result<u32, ErrorKind> {
    if digits.is_empty() {
        return Err(ErrorKind::BadReference);
    }
    let mut n: u32 = 0;
    for ch in digits.chars() {
        let d = ch.to_digit(radix).ok_or(ErrorKind::BadReference)?;
        n = n.checked_mul(radix).and_then(|n| n.checked_add(d)).ok_or(ErrorKind::BadReference)?;
    }
    Ok(n)
}

/// Turns each `\r\n` and lone `\r` into `\n`.
fn normalize(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Whether XML 1.0 allows `c` in a document (the Char production).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn is_name_start(c: char) -> bool {
    matches!(c,
        ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}'
        | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// Whether `s` is a name with no colon (an NCName).
fn is_ncname(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c != ':' && is_name_start(c) => cs.all(|c| c != ':' && is_name_char(c)),
        _ => false,
    }
}

/// Splits a namespace-aware name at its colon, checking both parts.
fn split_qname(q: &str) -> Result<(Option<&str>, &str), ErrorKind> {
    if q.len() > MAX_NAME {
        return Err(ErrorKind::NameTooLong);
    }
    let (p, l) = match q.split_once(':') {
        Some((p, l)) => (Some(p), l),
        None => (None, q),
    };
    if p.is_some_and(|p| !is_ncname(p)) || !is_ncname(l) {
        return Err(ErrorKind::BadName);
    }
    Ok((p, l))
}

/// A cursor over the inside of one token.
struct Cur<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a str) -> Cur<'a> {
        Cur { s, i: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn at_end(&self) -> bool {
        self.i >= self.s.len()
    }

    fn eat(&mut self, p: &str) -> bool {
        let ok = self.rest().starts_with(p);
        if ok {
            self.i += p.len();
        }
        ok
    }

    /// Skips whitespace, saying whether there was any.
    fn ws(&mut self) -> bool {
        let n = self.rest().bytes().take_while(|&b| is_space(b)).count();
        self.i += n;
        n > 0
    }

    /// Reads a name (the Name production, colons allowed).
    fn name(&mut self) -> Result<&'a str, ErrorKind> {
        let r = self.rest();
        let mut end = 0;
        for (k, c) in r.char_indices() {
            let ok = if k == 0 { is_name_start(c) } else { is_name_char(c) };
            if !ok {
                break;
            }
            end = k + c.len_utf8();
            if end > MAX_NAME {
                return Err(ErrorKind::NameTooLong);
            }
        }
        if end == 0 {
            return Err(ErrorKind::BadName);
        }
        self.i += end;
        Ok(&r[..end])
    }

    /// Reads a name token (the Nmtoken production): name characters, any
    /// of them first.
    fn nmtoken(&mut self) -> Result<&'a str, ErrorKind> {
        let r = self.rest();
        let end = r.find(|c: char| !is_name_char(c)).unwrap_or(r.len());
        if end == 0 {
            return Err(ErrorKind::BadName);
        }
        if end > MAX_NAME {
            return Err(ErrorKind::NameTooLong);
        }
        self.i += end;
        Ok(&r[..end])
    }

    fn eq(&mut self) -> Result<(), ErrorKind> {
        self.ws();
        if !self.eat("=") {
            return Err(ErrorKind::BadSyntax);
        }
        self.ws();
        Ok(())
    }

    fn quoted(&mut self) -> Result<&'a str, ErrorKind> {
        let q = match self.rest().as_bytes().first() {
            Some(b'"') => '"',
            Some(b'\'') => '\'',
            _ => return Err(ErrorKind::BadSyntax),
        };
        self.i += 1;
        let r = self.rest();
        let end = r.find(q).ok_or(ErrorKind::BadSyntax)?;
        self.i += end + 1;
        Ok(&r[..end])
    }
}

/// An open element.
#[derive(Clone, Debug)]
struct Open {
    qname: String,
    name: Name,
    /// The prefixes its own `xmlns` attributes bound, empty for the
    /// default namespace.
    bound: Vec<String>,
}

/// The shape of a document so far: where in it we are, which elements are
/// open and which namespaces are in scope. The parser and the writer share
/// it, so the writer cannot write what the parser would refuse. Each
/// method checks everything before it changes anything.
///
/// Namespace URIs are shared, not copied, so a long URI declared once costs
/// nothing more on each name in it. Each prefix maps to its bindings,
/// innermost last, so a lookup does not depend on how many are in scope.
/// The default namespace is under the empty prefix, which no name has.
///
/// The URIs in scope are interned: two bindings to equal URIs share one
/// copy, so two names are in the same namespace exactly when their URIs
/// are the same allocation, and telling attributes apart never compares
/// long URIs.
#[derive(Clone, Debug)]
struct Doc {
    started: bool,
    doctype: bool,
    root_seen: bool,
    stack: Vec<Open>,
    scope: BTreeMap<String, Vec<Arc<str>>>,
    /// How many bindings are in scope, over all prefixes.
    bindings: usize,
    /// Each URI bound now, with the shared copy and how many bindings
    /// hold it.
    interned: BTreeMap<Arc<str>, (Arc<str>, usize)>,
    xml_ns: Arc<str>,
    xmlns_ns: Arc<str>,
    /// The attribute declarations of the internal subset, by element name.
    attlists: BTreeMap<String, AttList>,
    /// The bytes of names and values supplied as defaults so far.
    defaulted: usize,
}

impl Default for Doc {
    fn default() -> Doc {
        Doc {
            started: false,
            doctype: false,
            root_seen: false,
            stack: Vec::new(),
            scope: BTreeMap::new(),
            bindings: 0,
            interned: BTreeMap::new(),
            xml_ns: Arc::from(XML_NAMESPACE),
            xmlns_ns: Arc::from(XMLNS_NAMESPACE),
            attlists: BTreeMap::new(),
            defaulted: 0,
        }
    }
}

impl Doc {
    fn decl(&mut self) -> Result<(), ErrorKind> {
        if self.started {
            return Err(ErrorKind::BadDeclaration);
        }
        self.started = true;
        Ok(())
    }

    fn doctype(&mut self) -> Result<(), ErrorKind> {
        if self.doctype || self.root_seen {
            return Err(ErrorKind::MisplacedDoctype);
        }
        self.started = true;
        self.doctype = true;
        Ok(())
    }

    fn misc(&mut self) {
        self.started = true;
    }

    /// Text, all whitespace or not. It says whether the text is content
    /// (inside the root), which gives an event.
    fn text(&mut self, ws: bool) -> Result<bool, ErrorKind> {
        if self.stack.is_empty() && !ws {
            return Err(ErrorKind::OutsideRoot);
        }
        self.started = true;
        Ok(!self.stack.is_empty())
    }

    fn cdata(&mut self) -> Result<(), ErrorKind> {
        if self.stack.is_empty() {
            return Err(ErrorKind::OutsideRoot);
        }
        Ok(())
    }

    /// The URI a prefix is bound to now.
    fn lookup(&self, prefix: Option<&str>) -> Option<&Arc<str>> {
        self.scope.get(prefix.unwrap_or("")).and_then(|v| v.last())
    }

    /// The shared copy of `uri`, counting one more binding to it. A new
    /// URI takes the copy in `hints` equal to it, if there is one, so names
    /// a writer is given keep their copies.
    fn intern(&mut self, uri: &str, hints: &[Arc<str>]) -> Arc<str> {
        if let Some((shared, n)) = self.interned.get_mut(uri) {
            *n += 1;
            return shared.clone();
        }
        let shared =
            hints.iter().find(|h| h.len() == uri.len() && ***h == *uri).cloned().unwrap_or_else(|| Arc::from(uri));
        self.interned.insert(shared.clone(), (shared.clone(), 1));
        shared
    }

    /// Counts one binding to `uri` fewer.
    fn release(&mut self, uri: &str) {
        if let Some((_, n)) = self.interned.get_mut(uri) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.interned.remove(uri);
            }
        }
    }

    /// Removes the innermost binding of each prefix in `prefixes`.
    fn unbind(&mut self, prefixes: &[String]) {
        for p in prefixes {
            let mut gone = None;
            if let Some(v) = self.scope.get_mut(p) {
                gone = v.pop();
                self.bindings = self.bindings.saturating_sub(1);
                if v.is_empty() {
                    self.scope.remove(p);
                }
            }
            if let Some(u) = gone {
                self.release(&u);
            }
        }
    }

    /// Takes back the start [`Doc::start`] just made, leaving the flags as
    /// they were before it.
    fn undo_start(&mut self, started: bool, root_seen: bool) {
        if let Some(open) = self.stack.pop() {
            self.unbind(&open.bound);
        }
        self.started = started;
        self.root_seen = root_seen;
    }

    /// Opens an element. Attribute defaults the DTD declares for it are
    /// added after the attributes written, and values of a tokenized type
    /// are normalized. `hints` are URIs a writer was given, to share.
    fn start(&mut self, qname: &str, mut attrs: Vec<(String, String)>, hints: &[Arc<str>]) -> Result<Start, ErrorKind> {
        if self.stack.is_empty() && self.root_seen {
            return Err(ErrorKind::OutsideRoot);
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(ErrorKind::TooDeep);
        }
        let mut defaulted = self.defaulted;
        if let Some(list) = self.attlists.get(qname) {
            let mut extra = Vec::new();
            {
                let written: BTreeSet<&str> = attrs.iter().map(|(n, _)| n.as_str()).collect();
                for (n, v) in &list.defaults {
                    if written.contains(n.as_str()) {
                        continue;
                    }
                    defaulted = defaulted.saturating_add(n.len() + v.len() + 1);
                    if defaulted > MAX_DOCUMENT {
                        return Err(ErrorKind::TooLarge);
                    }
                    if attrs.len() + extra.len() >= MAX_ATTRIBUTES {
                        return Err(ErrorKind::TooManyAttributes);
                    }
                    extra.push((n.clone(), v.clone()));
                }
            }
            for (n, v) in attrs.iter_mut() {
                if list.types.get(n.as_str()) == Some(&true) {
                    *v = collapse_spaces(v);
                }
            }
            attrs.extend(extra);
        }
        if attrs.len() > MAX_ATTRIBUTES {
            return Err(ErrorKind::TooManyAttributes);
        }
        let (prefix, local) = split_qname(qname)?;
        let mut split = Vec::with_capacity(attrs.len());
        let mut seen = BTreeSet::new();
        for (n, _) in &attrs {
            split.push(split_qname(n)?);
            if !seen.insert(n.as_str()) {
                return Err(ErrorKind::DuplicateAttribute);
            }
        }
        let mut decls: Vec<(String, &str)> = Vec::new();
        for (&(p, l), (_, v)) in split.iter().zip(&attrs) {
            let reserved = v == XML_NAMESPACE || v == XMLNS_NAMESPACE;
            match (p, l) {
                (None, "xmlns") => {
                    if reserved {
                        return Err(ErrorKind::BadNamespace);
                    }
                    decls.push((String::new(), v.as_str()));
                }
                (Some("xmlns"), "xmlns") => return Err(ErrorKind::BadNamespace),
                (Some("xmlns"), "xml") => {
                    if v != XML_NAMESPACE {
                        return Err(ErrorKind::BadNamespace);
                    }
                }
                (Some("xmlns"), l) => {
                    if v.is_empty() || reserved {
                        return Err(ErrorKind::BadNamespace);
                    }
                    decls.push((l.to_string(), v.as_str()));
                }
                _ => {}
            }
        }
        if prefix == Some("xmlns") {
            return Err(ErrorKind::BadNamespace);
        }
        match self.bindings.checked_add(decls.len()) {
            Some(n) if n <= MAX_NAMESPACES => {}
            _ => return Err(ErrorKind::TooManyNamespaces),
        }
        // Bind this tag's declarations, so its own names see them, and take
        // them back if a name does not resolve.
        let bound: Vec<String> = decls.iter().map(|(p, _)| p.clone()).collect();
        for (p, v) in decls {
            let u = self.intern(v, hints);
            self.scope.entry(p).or_default().push(u);
            self.bindings += 1;
        }
        match self.resolve(prefix, local, &split, &attrs) {
            Ok(start) => {
                self.stack.push(Open { qname: qname.to_string(), name: start.name.clone(), bound });
                self.started = true;
                self.root_seen = true;
                self.defaulted = defaulted;
                Ok(start)
            }
            Err(e) => {
                self.unbind(&bound);
                Err(e)
            }
        }
    }

    /// Resolves an element's name and its attributes' names, with the
    /// element's own declarations in scope.
    fn resolve(
        &self,
        prefix: Option<&str>,
        local: &str,
        split: &[(Option<&str>, &str)],
        attrs: &[(String, String)],
    ) -> Result<Start, ErrorKind> {
        let element_ns = match prefix {
            Some("xml") => Some(self.xml_ns.clone()),
            Some(p) => Some(self.lookup(Some(p)).ok_or(ErrorKind::UndeclaredPrefix)?.clone()),
            None => self.lookup(None).filter(|u| !u.is_empty()).cloned(),
        };
        let mut attributes = Vec::with_capacity(attrs.len());
        let mut expanded = BTreeSet::new();
        for (&(p, l), (_, v)) in split.iter().zip(attrs) {
            let namespace = match (p, l) {
                (Some("xmlns"), _) | (None, "xmlns") => Some(self.xmlns_ns.clone()),
                (Some("xml"), _) => Some(self.xml_ns.clone()),
                (Some(p), _) => Some(self.lookup(Some(p)).ok_or(ErrorKind::UndeclaredPrefix)?.clone()),
                (None, _) => None,
            };
            // Interned URIs are equal exactly when they are the same copy,
            // and the two reserved ones are never bound, so the address
            // stands for the namespace.
            if let Some(ns) = &namespace
                && !expanded.insert((Arc::as_ptr(ns) as *const u8 as usize, l))
            {
                return Err(ErrorKind::DuplicateAttribute);
            }
            let name = Name { prefix: p.map(String::from), local: l.to_string(), namespace };
            attributes.push(Attribute { name, value: v.clone() });
        }
        let name = Name { prefix: prefix.map(String::from), local: local.to_string(), namespace: element_ns };
        Ok(Start { name, attributes })
    }

    fn end(&mut self, qname: &str) -> Result<Name, ErrorKind> {
        let top = self.stack.last().ok_or(ErrorKind::OutsideRoot)?;
        if top.qname != qname {
            return Err(ErrorKind::MismatchedEnd);
        }
        let open = self.stack.pop().ok_or(ErrorKind::OutsideRoot)?;
        self.unbind(&open.bound);
        Ok(open.name)
    }

    fn finish(&self) -> Result<(), ErrorKind> {
        if !self.stack.is_empty() || !self.root_seen { Err(ErrorKind::UnexpectedEnd) } else { Ok(()) }
    }
}

/// Builds a document, checking each piece as it goes. A method that
/// returns an error writes nothing, and the writer can go on. What
/// [`Writer::finish`] returns, a [`Parser`] reads without error, and gives
/// back the events written, with four exceptions. Whitespace outside the
/// root element gives no event. Text written in more than one call, with
/// nothing between, reads back as one [`Event::Text`]. Carriage returns in
/// comments, CDATA and processing instructions read back as newlines. And
/// whitespace at the start of processing instruction data is dropped.
///
/// A writer keeps room for the end tags of the elements open, so each one
/// can always be closed within [`MAX_DOCUMENT`]. It sizes each piece
/// before it builds it, so a long string given to it costs no more memory
/// than the room left.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    out: String,
    doc: Doc,
    /// The bytes the end tags of the open elements will take.
    closing: usize,
}

impl Writer {
    /// A writer with nothing written.
    pub fn new() -> Writer {
        Writer::default()
    }

    /// What has been written so far.
    pub fn as_str(&self) -> &str {
        &self.out
    }

    /// How many elements are open.
    pub fn depth(&self) -> usize {
        self.doc.stack.len()
    }

    /// The document, once its root element is closed.
    pub fn finish(self) -> Result<String, ErrorKind> {
        self.doc.finish()?;
        Ok(self.out)
    }

    /// How many more bytes may be written, keeping room for the end tags.
    fn left(&self) -> usize {
        MAX_DOCUMENT.saturating_sub(self.out.len().saturating_add(self.closing))
    }

    fn room(&self, len: usize) -> Result<(), ErrorKind> {
        if len <= self.left() { Ok(()) } else { Err(ErrorKind::TooLarge) }
    }

    /// Writes `<?xml version="1.0" encoding="UTF-8"?>`. It must come first.
    pub fn declaration(&mut self) -> Result<(), ErrorKind> {
        self.write_declaration("1.0", Some("UTF-8"), None)
    }

    fn write_declaration(
        &mut self,
        version: &str,
        encoding: Option<&str>,
        standalone: Option<bool>,
    ) -> Result<(), ErrorKind> {
        self.room(version.len().saturating_add(encoding.map_or(0, str::len)).saturating_add(64))?;
        check_version(version)?;
        let mut piece = format!("<?xml version=\"{version}\"");
        if let Some(e) = encoding {
            check_encoding(e)?;
            piece.push_str(&format!(" encoding=\"{e}\""));
        }
        if let Some(s) = standalone {
            piece.push_str(if s { " standalone=\"yes\"" } else { " standalone=\"no\"" });
        }
        piece.push_str("?>");
        self.room(piece.len())?;
        if self.doc.started {
            return Err(ErrorKind::BadDeclaration);
        }
        self.doc.decl()?;
        self.out.push_str(&piece);
        Ok(())
    }

    /// Writes `<!DOCTYPE name>`, before the root element.
    pub fn doctype(&mut self, name: &str) -> Result<(), ErrorKind> {
        let mut c = Cur::new(name);
        c.name()?;
        if !c.at_end() {
            return Err(ErrorKind::BadName);
        }
        split_qname(name)?;
        let piece = format!("<!DOCTYPE {name}>");
        self.room(piece.len())?;
        self.doc.doctype()?;
        self.out.push_str(&piece);
        Ok(())
    }

    /// Opens an element with the given attributes, as `(name, value)`
    /// pairs. Namespaces are declared with `xmlns` attributes, as in a
    /// document.
    pub fn start(&mut self, name: &str, attributes: &[(&str, &str)]) -> Result<(), ErrorKind> {
        self.write_start(name, attributes, false, None)
    }

    /// Writes an element with no content, `<name/>`.
    pub fn empty(&mut self, name: &str, attributes: &[(&str, &str)]) -> Result<(), ErrorKind> {
        self.write_start(name, attributes, true, None)
    }

    /// Writes a start tag. With `expect`, the names must resolve to the
    /// namespaces it gives them, or nothing is written.
    fn write_start(
        &mut self,
        name: &str,
        attributes: &[(&str, &str)],
        empty: bool,
        expect: Option<&Start>,
    ) -> Result<(), ErrorKind> {
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(ErrorKind::TooManyAttributes);
        }
        if name.len() > MAX_NAME || attributes.iter().any(|(n, _)| n.len() > MAX_NAME) {
            return Err(ErrorKind::NameTooLong);
        }
        let close = if empty { 0 } else { name.len() + 3 };
        let limit = self.left().checked_sub(close).ok_or(ErrorKind::TooLarge)?;
        let mut piece = String::new();
        piece.push('<');
        piece.push_str(name);
        for (n, v) in attributes {
            piece.push(' ');
            piece.push_str(n);
            piece.push_str("=\"");
            escape(&mut piece, v, true, limit)?;
            piece.push('"');
        }
        piece.push_str(if empty { "/>" } else { ">" });
        if piece.len() > limit {
            return Err(ErrorKind::TooLarge);
        }
        let attrs = attributes.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        let (started, root_seen) = (self.doc.started, self.doc.root_seen);
        let mut hints: Vec<Arc<str>> = Vec::new();
        if let Some(e) = expect {
            let names = core::iter::once(&e.name).chain(e.attributes.iter().map(|a| &a.name));
            for ns in names.filter_map(|n| n.namespace.as_ref()) {
                if !hints.iter().any(|h| Arc::ptr_eq(h, ns)) {
                    hints.push(ns.clone());
                }
            }
        }
        let start = self.doc.start(name, attrs, &hints)?;
        if let Some(e) = expect
            && !same_names(&start, e)
        {
            self.doc.undo_start(started, root_seen);
            return Err(ErrorKind::BadNamespace);
        }
        if empty {
            self.doc.end(name)?;
        }
        self.closing += close;
        self.out.push_str(&piece);
        Ok(())
    }

    /// Closes the element opened last. Its end tag always fits, since the
    /// room for it was kept when the element was opened.
    pub fn end(&mut self) -> Result<(), ErrorKind> {
        let qname = self.doc.stack.last().ok_or(ErrorKind::OutsideRoot)?.qname.clone();
        let piece = format!("</{qname}>");
        self.doc.end(&qname)?;
        self.closing = self.closing.saturating_sub(piece.len());
        self.out.push_str(&piece);
        Ok(())
    }

    /// Writes text, escaping `&`, `<`, `>` and carriage returns. Outside
    /// the root element, only whitespace may be written, and it is written
    /// as is, since a reference there is not whitespace.
    pub fn text(&mut self, text: &str) -> Result<(), ErrorKind> {
        if text.is_empty() {
            return Ok(());
        }
        let limit = self.left();
        let ws = text.bytes().all(is_space);
        let mut piece = String::new();
        if ws && self.doc.stack.is_empty() {
            self.room(text.len())?;
            piece.push_str(text);
        } else {
            escape(&mut piece, text, false, limit)?;
        }
        self.doc.text(ws)?;
        self.out.push_str(&piece);
        Ok(())
    }

    /// Writes a CDATA section inside the root element. Its content may not
    /// hold `]]>`.
    pub fn cdata(&mut self, content: &str) -> Result<(), ErrorKind> {
        self.room(content.len().saturating_add(12))?;
        check_chars(content)?;
        if content.contains("]]>") {
            return Err(ErrorKind::CdataEndInText);
        }
        self.doc.cdata()?;
        self.out.push_str("<![CDATA[");
        self.out.push_str(content);
        self.out.push_str("]]>");
        Ok(())
    }

    /// Writes a comment. It may not hold `--` or end with `-`.
    pub fn comment(&mut self, content: &str) -> Result<(), ErrorKind> {
        self.room(content.len().saturating_add(7))?;
        check_chars(content)?;
        if content.contains("--") || content.ends_with('-') {
            return Err(ErrorKind::BadComment);
        }
        self.doc.misc();
        self.out.push_str("<!--");
        self.out.push_str(content);
        self.out.push_str("-->");
        Ok(())
    }

    /// Writes a processing instruction. The target is a name with no colon,
    /// and not `xml` in any case. The data may not hold `?>`.
    pub fn pi(&mut self, target: &str, data: &str) -> Result<(), ErrorKind> {
        let mut c = Cur::new(target);
        c.name()?;
        if !c.at_end() {
            return Err(ErrorKind::BadName);
        }
        check_pi_target(target)?;
        self.room(target.len().saturating_add(data.len()).saturating_add(5))?;
        check_chars(data)?;
        if data.contains("?>") {
            return Err(ErrorKind::BadPi);
        }
        self.doc.misc();
        self.out.push_str("<?");
        self.out.push_str(target);
        if !data.is_empty() {
            self.out.push(' ');
            self.out.push_str(data);
        }
        self.out.push_str("?>");
        Ok(())
    }

    /// Writes an event, as a parser gave it. An end event must name the
    /// element opened last. A writer adds no namespace declarations: each
    /// name must resolve, with the `xmlns` attributes written, to the
    /// namespace it carries, or the writer refuses it with
    /// [`ErrorKind::BadNamespace`] rather than write a name that reads back
    /// in another namespace.
    pub fn event(&mut self, event: &Event) -> Result<(), ErrorKind> {
        match event {
            Event::Declaration { version, encoding, standalone } => {
                self.write_declaration(version, encoding.as_deref(), *standalone)
            }
            Event::Doctype { name } => self.doctype(name),
            Event::Start(s) => {
                if s.attributes.len() > MAX_ATTRIBUTES {
                    return Err(ErrorKind::TooManyAttributes);
                }
                let qlen = |n: &Name| n.prefix.as_ref().map_or(0, |p| p.len() + 1).saturating_add(n.local.len());
                if qlen(&s.name) > MAX_NAME || s.attributes.iter().any(|a| qlen(&a.name) > MAX_NAME) {
                    return Err(ErrorKind::NameTooLong);
                }
                let names: Vec<String> = s.attributes.iter().map(|a| a.name.qname()).collect();
                let attrs: Vec<(&str, &str)> =
                    names.iter().zip(&s.attributes).map(|(n, a)| (n.as_str(), a.value.as_str())).collect();
                self.write_start(&s.name.qname(), &attrs, false, Some(s))
            }
            Event::End(name) => {
                let top = &self.doc.stack.last().ok_or(ErrorKind::OutsideRoot)?.name;
                if top.prefix != name.prefix || top.local != name.local {
                    return Err(ErrorKind::MismatchedEnd);
                }
                if !same_namespace(top.namespace.as_ref(), name.namespace.as_ref()) {
                    return Err(ErrorKind::BadNamespace);
                }
                self.end()
            }
            Event::Text(t) => self.text(t),
            Event::CData(t) => self.cdata(t),
            Event::Comment(t) => self.comment(t),
            Event::Pi { target, data } => self.pi(target, data),
        }
    }
}

/// Whether two namespaces are the same: the same copy, or equal URIs.
fn same_namespace(a: Option<&Arc<str>>, b: Option<&Arc<str>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || (a.len() == b.len() && **a == **b),
        (None, None) => true,
        _ => false,
    }
}

/// Whether a start tag's names are in the namespaces `want` gives them.
fn same_names(got: &Start, want: &Start) -> bool {
    same_namespace(got.name.namespace.as_ref(), want.name.namespace.as_ref())
        && got.attributes.len() == want.attributes.len()
        && got
            .attributes
            .iter()
            .zip(&want.attributes)
            .all(|(g, w)| same_namespace(g.name.namespace.as_ref(), w.name.namespace.as_ref()))
}

fn check_chars(s: &str) -> Result<(), ErrorKind> {
    if s.chars().all(is_xml_char) { Ok(()) } else { Err(ErrorKind::InvalidChar) }
}

/// Appends `s` escaped for text, or for a double-quoted attribute value.
/// It stops with [`ErrorKind::TooLarge`] once `out` is longer than `limit`,
/// so it never holds much more than that.
fn escape(out: &mut String, s: &str, attr: bool, limit: usize) -> Result<(), ErrorKind> {
    for c in s.chars() {
        if out.len() > limit {
            return Err(ErrorKind::TooLarge);
        }
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' if attr => out.push_str("&#10;"),
            '\t' if attr => out.push_str("&#9;"),
            c if is_xml_char(c) => out.push(c),
            _ => return Err(ErrorKind::InvalidChar),
        }
    }
    if out.len() > limit { Err(ErrorKind::TooLarge) } else { Ok(()) }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    /// Feeds `chunks` in order, then finishes, taking events out after
    /// each piece. It returns the events and the error, if any.
    fn run<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> (Vec<Event>, Option<Error>) {
        let mut p = Parser::new();
        let mut events = Vec::new();
        let drain = |p: &mut Parser, events: &mut Vec<Event>| -> Option<Error> {
            while let Some(ev) = p.next_event() {
                match ev {
                    Ok(e) => events.push(e),
                    Err(e) => return Some(e),
                }
            }
            None
        };
        for c in chunks {
            p.feed(c);
            if let Some(e) = drain(&mut p, &mut events) {
                return (events, Some(e));
            }
        }
        p.finish();
        let err = drain(&mut p, &mut events);
        if err.is_none() {
            assert!(p.is_done());
        }
        (events, err)
    }

    fn whole(doc: &[u8]) -> (Vec<Event>, Option<Error>) {
        run([doc])
    }

    fn bytewise(doc: &[u8]) -> (Vec<Event>, Option<Error>) {
        run(doc.chunks(1))
    }

    fn kind(doc: &str) -> ErrorKind {
        let r = whole(doc.as_bytes());
        assert_eq!(r, bytewise(doc.as_bytes()), "{doc:?}");
        r.1.unwrap_or_else(|| panic!("no error in {doc:?}")).kind
    }

    fn name(local: &str) -> Name {
        Name { prefix: None, local: local.into(), namespace: None }
    }

    fn start(local: &str) -> Event {
        Event::Start(Start { name: name(local), attributes: vec![] })
    }

    // Examples from XML 1.0, Fifth Edition.

    #[test]
    fn hello_world() {
        // Section 2.8.
        let doc = b"<?xml version=\"1.0\"?><!DOCTYPE greeting SYSTEM \"hello.dtd\"><greeting>Hello, world!</greeting>";
        let events = parse(doc).unwrap();
        assert_eq!(
            events,
            [
                Event::Declaration { version: "1.0".into(), encoding: None, standalone: None },
                Event::Doctype { name: "greeting".into() },
                start("greeting"),
                Event::Text("Hello, world!".into()),
                Event::End(name("greeting")),
            ]
        );
        // The same with an internal subset, which is skipped.
        let doc = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<!DOCTYPE greeting [\n  <!ELEMENT greeting (#PCDATA)>\n  <!-- a ] in a comment -->\n  <?pi ]> ?>\n  <!ATTLIST greeting a CDATA \"]>\">\n]>\n<greeting>Hello, world!</greeting>";
        let events = parse(doc.as_bytes()).unwrap();
        assert_eq!(events[1], Event::Doctype { name: "greeting".into() });
        assert_eq!(events[3], Event::Text("Hello, world!".into()));
        assert_eq!(whole(doc.as_bytes()), bytewise(doc.as_bytes()));
    }

    #[test]
    fn comments_cdata_and_pis() {
        // Sections 2.5, 2.6 and 2.7.
        let doc = "<a><!-- declarations for <head> & <body> --><![CDATA[<greeting>Hello, world!</greeting>]]><?xml-stylesheet href=\"s.css\"?><?t?></a>";
        let events = parse(doc.as_bytes()).unwrap();
        assert_eq!(events[1], Event::Comment(" declarations for <head> & <body> ".into()));
        assert_eq!(events[2], Event::CData("<greeting>Hello, world!</greeting>".into()));
        assert_eq!(events[3], Event::Pi { target: "xml-stylesheet".into(), data: "href=\"s.css\"".into() });
        assert_eq!(events[4], Event::Pi { target: "t".into(), data: String::new() });
        assert_eq!(kind("<a><!-- B+, B, or B--->--></a>"), ErrorKind::BadComment);
    }

    #[test]
    fn references_and_line_ends() {
        let events = parse(b"<a>&lt;&gt;&amp;&apos;&quot;&#38;&#x41;&#x1F600;\r\nx\ry</a>").unwrap();
        assert_eq!(events[1], Event::Text("<>&'\"&A\u{1F600}\nx\ny".into()));
        // Section 3.3.3: attribute value normalization.
        let events = parse(b"<a b=\"&#xd;&#xd;A&#xa;&#xa;B&#xd;&#xa;\" c=\"\r\n\nxyz\tq\"/>").unwrap();
        let Event::Start(s) = &events[0] else { panic!() };
        assert_eq!(s.attribute(None, "b"), Some("\r\rA\n\nB\r\n"));
        assert_eq!(s.attribute(None, "c"), Some("  xyz q"));
        assert_eq!(events[1], Event::End(name("a")));
        // A > in text and in attributes is fine; ]]> in text is not.
        assert!(parse(b"<a b='>'>x > y</a>").is_ok());
        assert_eq!(kind("<a>x ]]> y</a>"), ErrorKind::CdataEndInText);
    }

    // Examples from Namespaces in XML 1.0, Third Edition.

    #[test]
    fn namespaces() {
        let doc = "<x xmlns:edi='http://ecommerce.example.org/schema'><lineItem edi:taxClass=\"exempt\">Baby food</lineItem></x>";
        let events = parse(doc.as_bytes()).unwrap();
        let Event::Start(s) = &events[1] else { panic!() };
        assert_eq!(s.attribute(Some("http://ecommerce.example.org/schema"), "taxClass"), Some("exempt"));
        assert_eq!(s.name.namespace, None);
        // A default namespace, and undeclaring it.
        let doc = "<html xmlns='http://www.w3.org/1999/xhtml'><p/><q xmlns=''><r/></q></html>";
        let events = parse(doc.as_bytes()).unwrap();
        let ns = |i: usize| match &events[i] {
            Event::Start(s) => s.name.namespace.clone(),
            Event::End(n) => n.namespace.clone(),
            _ => panic!(),
        };
        assert_eq!(ns(0).as_deref(), Some("http://www.w3.org/1999/xhtml"));
        assert_eq!(ns(1).as_deref(), Some("http://www.w3.org/1999/xhtml"));
        assert_eq!(ns(3), None);
        assert_eq!(ns(4), None);
        assert_eq!(ns(7).as_deref(), Some("http://www.w3.org/1999/xhtml"));
        // Section 6.3: unique attributes.
        let ok = "<x xmlns:n1=\"http://www.w3.org\" xmlns=\"http://www.w3.org\"><good a=\"1\" b=\"2\"/><good a=\"1\" n1:a=\"2\"/></x>";
        assert!(parse(ok.as_bytes()).is_ok());
        let bad = "<x xmlns:n1=\"http://www.w3.org\" xmlns:n2=\"http://www.w3.org\"><bad n1:a=\"1\" n2:a=\"2\"/></x>";
        assert_eq!(kind(bad), ErrorKind::DuplicateAttribute);
        assert_eq!(kind("<x><bad a=\"1\" a=\"2\"/></x>"), ErrorKind::DuplicateAttribute);
        // The xml prefix is always bound.
        let events = parse(b"<a xml:lang='en'/>").unwrap();
        let Event::Start(s) = &events[0] else { panic!() };
        assert_eq!(s.attribute(Some(XML_NAMESPACE), "lang"), Some("en"));
        assert!(parse(b"<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>").is_ok());
    }

    #[test]
    fn each_error() {
        assert_eq!(kind("<a>\u{1}</a>"), ErrorKind::InvalidChar);
        assert_eq!(kind("<a>&#0;</a>"), ErrorKind::BadReference);
        assert_eq!(kind("<a>&#xFFFE;</a>"), ErrorKind::BadReference);
        assert_eq!(kind("<a>&#99999999999;</a>"), ErrorKind::BadReference);
        assert_eq!(kind("<a>&#x;</a>"), ErrorKind::BadReference);
        assert_eq!(kind("<a>& b</a>"), ErrorKind::BadReference);
        assert_eq!(kind("<a>&nbsp;</a>"), ErrorKind::UnknownEntity);
        assert_eq!(kind("<a>&amp &amp;</a>"), ErrorKind::BadReference);
        assert_eq!(kind(&format!("<a>&{};</a>", "e".repeat(MAX_NAME + 1))), ErrorKind::NameTooLong);
        // Production [66] puts no bound on a character reference's digits.
        let zeros = format!("<a b='&#{0}65;'>&#x{0}41;</a>", "0".repeat(1000));
        let events = parse(zeros.as_bytes()).unwrap();
        assert_eq!(events[1], Event::Text("A".into()));
        assert_eq!(kind("<1a/>"), ErrorKind::BadName);
        assert_eq!(kind("<a:b:c/>"), ErrorKind::BadName);
        assert_eq!(kind("<a b='1'c='2'/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a b/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a b=1/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a b='<'/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a <b/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!ELEMENT a><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a></a >x"), ErrorKind::OutsideRoot);
        assert_eq!(kind(" <?xml version='1.0'?><a/>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<?xml version='2.0'?><a/>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<?xml?><a/>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<?xml version='1.0' standalone='maybe'?><a/>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<?xml version='1.0'encoding='UTF-8'?><a/>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<?xml version='1.0' encoding='ISO-8859-1'?><a/>"), ErrorKind::UnsupportedEncoding);
        assert_eq!(kind("<a/><?xml version='1.0'?>"), ErrorKind::BadDeclaration);
        assert_eq!(kind("<a/><?Xml?>"), ErrorKind::ReservedPi);
        assert_eq!(kind("<?XML x?><a/>"), ErrorKind::ReservedPi);
        assert_eq!(kind("<?a:b?><a/>"), ErrorKind::BadName);
        assert_eq!(kind("<?ab#?><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a/><!DOCTYPE a>"), ErrorKind::MisplacedDoctype);
        assert_eq!(kind("<!DOCTYPE a><!DOCTYPE a><a/>"), ErrorKind::MisplacedDoctype);
        assert_eq!(kind("<!DOCTYPE a [ ] x><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<a></b>"), ErrorKind::MismatchedEnd);
        assert_eq!(kind("</a>"), ErrorKind::OutsideRoot);
        assert_eq!(kind("<a/><b/>"), ErrorKind::OutsideRoot);
        assert_eq!(kind("x<a/>"), ErrorKind::OutsideRoot);
        assert_eq!(kind("<![CDATA[x]]><a/>"), ErrorKind::OutsideRoot);
        assert_eq!(kind("<p:a/>"), ErrorKind::UndeclaredPrefix);
        assert_eq!(kind("<a p:b='1'/>"), ErrorKind::UndeclaredPrefix);
        assert_eq!(kind("<a xmlns:p=''/>"), ErrorKind::BadNamespace);
        assert_eq!(kind("<a xmlns:xmlns='u'/>"), ErrorKind::BadNamespace);
        assert_eq!(kind("<a xmlns:xml='u'/>"), ErrorKind::BadNamespace);
        assert_eq!(kind("<a xmlns:p='http://www.w3.org/XML/1998/namespace'/>"), ErrorKind::BadNamespace);
        assert_eq!(kind("<a xmlns='http://www.w3.org/2000/xmlns/'/>"), ErrorKind::BadNamespace);
        assert_eq!(kind("<xmlns:a/>"), ErrorKind::BadNamespace);
        assert_eq!(kind(""), ErrorKind::UnexpectedEnd);
        assert_eq!(kind("<!-- only -->"), ErrorKind::UnexpectedEnd);
        assert_eq!(kind("<a>"), ErrorKind::UnexpectedEnd);
        assert_eq!(kind("<a><!-- x"), ErrorKind::UnexpectedEnd);
        assert_eq!(kind(&format!("<{}/>", "a".repeat(MAX_NAME + 1))), ErrorKind::NameTooLong);
        assert!(parse(format!("<{}/>", "a".repeat(MAX_NAME)).as_bytes()).is_ok());
        let deep = format!("{}{}", "<a>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1));
        assert_eq!(kind(&deep), ErrorKind::TooDeep);
        let deep = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(parse(deep.as_bytes()).is_ok());
        let attrs: String = (0..=MAX_ATTRIBUTES).map(|i| format!(" a{i}=''")).collect();
        assert_eq!(kind(&format!("<a{attrs}/>")), ErrorKind::TooManyAttributes);
        let decls: String = (0..200).map(|i| format!(" xmlns:p{i}='u'")).collect();
        let many = format!("{}{}", format!("<a{decls}>").repeat(6), "</a>".repeat(6));
        assert_eq!(kind(&many), ErrorKind::TooManyNamespaces);
        // Bytes that are not UTF-8.
        assert_eq!(whole(b"<a>\xff</a>").1.unwrap().kind, ErrorKind::InvalidUtf8);
        // Offsets point at the token that broke.
        assert_eq!(whole(b"<a><b></c></a>").1, Some(Error { kind: ErrorKind::MismatchedEnd, offset: 6 }));
    }

    #[test]
    fn doctype_grammar() {
        // Section 2.8: S? may come before the internal subset.
        let events = parse(b"<!DOCTYPE a[<!ELEMENT a ANY>]><a/>").unwrap();
        assert_eq!(events[0], Event::Doctype { name: "a".into() });
        assert!(parse(b"<!DOCTYPE a SYSTEM 'a.dtd'[]><a/>").is_ok());
        assert!(parse(b"<!DOCTYPE a PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" 'x.dtd' ><a/>").is_ok());
        assert!(parse(b"<!DOCTYPE a\n>\n<a/>").is_ok());
        // An external identifier is SYSTEM or PUBLIC with its literals.
        assert_eq!(kind("<!DOCTYPE a junk><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a 'x'><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a SYSTEM><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a SYSTEM'x'><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a PUBLIC 'p'><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a PUBLIC 'p''s'><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a PUBLIC 'p{' 's'><a/>"), ErrorKind::BadSyntax);
        assert_eq!(kind("<!DOCTYPE a SYSTEM 's' x [ ]><a/>"), ErrorKind::BadSyntax);
        // Namespaces in XML, section 5: the doctype's name is a QName.
        assert_eq!(kind("<!DOCTYPE a:b:c><a/>"), ErrorKind::BadName);
        assert_eq!(Writer::new().doctype("a:b:c"), Err(ErrorKind::BadName));
    }

    #[test]
    fn writer_whitespace_outside_root() {
        // A carriage return outside the root must stay a literal, since a
        // character reference there is not whitespace.
        let mut w = Writer::new();
        w.text("\r\n").unwrap();
        w.empty("a", &[]).unwrap();
        w.text(" \r\t").unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out, "\r\n<a/> \r\t");
        assert_eq!(parse(out.as_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn namespace_scope() {
        // An inner binding shadows an outer one until its element ends.
        let doc = "<a xmlns:p='u1'><b xmlns:p='u2'><p:c/></b><p:d/></a>";
        let events = parse(doc.as_bytes()).unwrap();
        let ns = |i: usize| match &events[i] {
            Event::Start(s) => s.name.namespace.clone(),
            _ => panic!(),
        };
        assert_eq!(ns(2).as_deref(), Some("u2"));
        assert_eq!(ns(5).as_deref(), Some("u1"));
        // A tag that fails leaves no binding behind.
        let mut w = Writer::new();
        w.start("a", &[("xmlns:p", "u1")]).unwrap();
        assert_eq!(w.start("b", &[("xmlns:p", "u2"), ("q:x", "1")]), Err(ErrorKind::UndeclaredPrefix));
        assert_eq!(w.start("c", &[("xmlns", "u3"), ("x", "1"), ("x", "2")]), Err(ErrorKind::DuplicateAttribute));
        w.empty("p:d", &[]).unwrap();
        w.empty("e", &[]).unwrap();
        w.end().unwrap();
        let events = parse(w.finish().unwrap().as_bytes()).unwrap();
        let Event::Start(d) = &events[1] else { panic!() };
        assert_eq!(d.name.namespace.as_deref(), Some("u1"));
        let Event::Start(e) = &events[3] else { panic!() };
        assert_eq!(e.name.namespace, None);
        // Failed tags do not use up the binding limit either.
        let mut w = Writer::new();
        w.start("a", &[]).unwrap();
        let names: Vec<String> = (0..MAX_ATTRIBUTES).map(|i| format!("xmlns:p{i}")).collect();
        let attrs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "u")).collect();
        for _ in 0..MAX_NAMESPACES {
            assert_eq!(w.start("q:x", &attrs), Err(ErrorKind::UndeclaredPrefix));
        }
        for _ in 0..MAX_NAMESPACES / MAX_ATTRIBUTES {
            w.start("p0:x", &attrs).unwrap();
        }
        assert_eq!(w.start("x", &[("xmlns:z", "u")]), Err(ErrorKind::TooManyNamespaces));
    }

    #[test]
    fn shared_namespaces() {
        // A long URI, declared once, is shared by every name in it rather
        // than copied, so a short element does not cost the URI's length.
        let uri = "u".repeat(64 << 10);
        let mut doc = format!("<p:r xmlns:p='{uri}' xmlns='{uri}'>");
        for _ in 0..20_000 {
            doc.push_str("<p:a p:b=''/><c/>");
        }
        doc.push_str("</p:r>");
        let events = parse(doc.as_bytes()).unwrap();
        assert_eq!(events.len(), 80_002);
        let namespace = |i: usize| match &events[i] {
            Event::Start(s) => s.name.namespace.clone().unwrap(),
            _ => panic!(),
        };
        // The prefix and the default are two declarations, each shared.
        let (p, default) = (namespace(0), namespace(3));
        assert_eq!(*p, *default);
        for e in &events[1..events.len() - 1] {
            let Event::Start(s) = e else { continue };
            let want = if s.name.prefix.is_some() { &p } else { &default };
            assert!(Arc::ptr_eq(want, s.name.namespace.as_ref().unwrap()));
            for a in &s.attributes {
                assert!(Arc::ptr_eq(&p, a.name.namespace.as_ref().unwrap()));
            }
        }
    }

    #[test]
    fn too_large() {
        let mut doc = b"<a>".to_vec();
        doc.resize(MAX_DOCUMENT + 10, b'x');
        let r = whole(&doc);
        assert_eq!(r.1.unwrap().kind, ErrorKind::TooLarge);
        let r = run(doc.chunks(65536));
        assert_eq!(r.1.unwrap().kind, ErrorKind::TooLarge);
        // A document just under the limit is fine.
        let mut doc = b"<a>".to_vec();
        doc.resize(MAX_DOCUMENT - 4, b'x');
        doc.extend_from_slice(b"</a>");
        let events = parse(&doc).unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn byte_order_mark() {
        let doc = b"\xEF\xBB\xBF<?xml version='1.0'?><a/>";
        assert_eq!(whole(doc), bytewise(doc));
        assert!(whole(doc).1.is_none());
        assert_eq!(kind("\u{FEFF}\u{FEFF}<a/>"), ErrorKind::OutsideRoot);
    }

    const SAMPLE: &str = "\u{FEFF}<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n<!DOCTYPE r [<!ENTITY e \"x\">]>\n<!-- c -->\n<r xmlns=\"urn:r\" xmlns:p=\"urn:p\" p:a=\"1 &amp; 2\" b='\"'>\n  <p:s>t&#233;xt</p:s><e/><![CDATA[<raw>]]><?go now?>\u{1F600}</r>";

    #[test]
    fn truncated_prefixes() {
        let full = SAMPLE.as_bytes();
        let (events, err) = whole(full);
        assert_eq!(err, None);
        for n in 0..full.len() {
            let (got, err) = whole(&full[..n]);
            assert!(err.is_some(), "prefix of {n} bytes read as a document");
            assert!(got.len() <= events.len(), "{n}");
            // Without finishing, a prefix gives no error, and a prefix of the
            // events.
            let mut p = Parser::new();
            p.feed(&full[..n]);
            let mut part = Vec::new();
            while let Some(ev) = p.next_event() {
                part.push(ev.unwrap());
            }
            assert!(events.starts_with(&part), "{n}");
        }
    }

    #[test]
    fn round_trip() {
        let (events, err) = whole(SAMPLE.as_bytes());
        assert_eq!(err, None);
        let mut w = Writer::new();
        for e in &events {
            w.event(e).unwrap();
        }
        let out = w.finish().unwrap();
        assert_eq!(parse(out.as_bytes()).unwrap(), events);
    }

    #[test]
    fn writer() {
        let mut w = Writer::new();
        w.declaration().unwrap();
        assert_eq!(w.declaration(), Err(ErrorKind::BadDeclaration));
        w.doctype("r").unwrap();
        w.comment(" hi ").unwrap();
        assert_eq!(w.text("x"), Err(ErrorKind::OutsideRoot));
        assert_eq!(w.cdata("x"), Err(ErrorKind::OutsideRoot));
        assert_eq!(w.end(), Err(ErrorKind::OutsideRoot));
        w.start("r", &[("xmlns:p", "urn:p"), ("a", "<\"&'\t\n\r>")]).unwrap();
        assert_eq!(w.start("q:x", &[]), Err(ErrorKind::UndeclaredPrefix));
        assert_eq!(w.start("x", &[("a", "1"), ("a", "2")]), Err(ErrorKind::DuplicateAttribute));
        assert_eq!(w.start("1x", &[]), Err(ErrorKind::BadName));
        assert_eq!(w.text("\u{0}"), Err(ErrorKind::InvalidChar));
        assert_eq!(w.cdata("a]]>b"), Err(ErrorKind::CdataEndInText));
        assert_eq!(w.comment("a--b"), Err(ErrorKind::BadComment));
        assert_eq!(w.comment("a-"), Err(ErrorKind::BadComment));
        assert_eq!(w.pi("xMl", ""), Err(ErrorKind::ReservedPi));
        assert_eq!(w.pi("a", "?>"), Err(ErrorKind::BadPi));
        assert_eq!(w.pi("a:b", ""), Err(ErrorKind::BadName));
        assert_eq!(w.doctype("r"), Err(ErrorKind::MisplacedDoctype));
        assert_eq!(w.event(&Event::End(name("x"))), Err(ErrorKind::MismatchedEnd));
        w.empty("p:e", &[]).unwrap();
        w.text("]]> & <\r").unwrap();
        w.cdata("<raw>").unwrap();
        w.pi("go", "now").unwrap();
        assert_eq!(w.depth(), 1);
        let unfinished = w.clone();
        assert_eq!(unfinished.finish(), Err(ErrorKind::UnexpectedEnd));
        w.end().unwrap();
        assert_eq!(w.start("again", &[]), Err(ErrorKind::OutsideRoot));
        w.text("\n").unwrap();
        let out = w.finish().unwrap();
        assert_eq!(
            out,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE r><!-- hi --><r xmlns:p=\"urn:p\" a=\"&lt;&quot;&amp;'&#9;&#10;&#13;&gt;\"><p:e/>]]&gt; &amp; &lt;&#13;<![CDATA[<raw>]]><?go now?></r>\n"
        );
        let events = parse(out.as_bytes()).unwrap();
        let Event::Start(s) = &events[3] else { panic!() };
        assert_eq!(s.attribute(None, "a"), Some("<\"&'\t\n\r>"));
        assert_eq!(events[6], Event::Text("]]> & <\r".into()));
        // A writer stops at the size limit.
        let mut w = Writer::new();
        w.start("a", &[]).unwrap();
        let big = "x".repeat(MAX_DOCUMENT);
        assert_eq!(w.text(&big), Err(ErrorKind::TooLarge));
        w.text(&big[..MAX_DOCUMENT - 7]).unwrap();
        w.end().unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out.len(), MAX_DOCUMENT);
        assert!(parse(out.as_bytes()).is_ok());
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

    const PIECES: &[&str] = &[
        "<",
        ">",
        "</",
        "/>",
        "a",
        "b:c",
        "xmlns",
        "xmlns:b",
        "=",
        "\"",
        "'",
        " ",
        "\n",
        "\r",
        "&",
        "&lt;",
        "&#",
        "x41",
        ";",
        "<!--",
        "-->",
        "-",
        "<![CDATA[",
        "]]>",
        "]",
        "[",
        "<?",
        "?>",
        "<?xml version=\"1.0\"?>",
        "<!DOCTYPE a [",
        "<!DOCTYPE a",
        " SYSTEM 'x'",
        " PUBLIC \"p\"",
        "<!ENTITY",
        "<a>",
        "</a>",
        "<b:c xmlns:b='u'>",
        "</b:c>",
        "<a x='1'/>",
        "é",
        "\u{0}",
        "\u{FEFF}",
        "text",
        "&amp;",
        "&#x1F600;",
    ];

    fn random_doc(rng: &mut Lcg) -> Vec<u8> {
        let mut doc = Vec::new();
        if rng.below(2) == 0 {
            doc.extend_from_slice(b"<a>");
        }
        for _ in 0..rng.below(30) {
            if rng.below(10) == 0 {
                doc.push(rng.next() as u8);
            } else {
                doc.extend_from_slice(PIECES[rng.below(PIECES.len())].as_bytes());
            }
        }
        if rng.below(2) == 0 {
            doc.extend_from_slice(b"</a>");
        }
        doc
    }

    #[test]
    fn fuzz() {
        let mut rng = Lcg(7);
        let mut good = 0;
        for _ in 0..5000 {
            let doc = random_doc(&mut rng);
            let (events, err) = whole(&doc);
            assert_eq!((events.clone(), err), bytewise(&doc), "{:?}", String::from_utf8_lossy(&doc));
            // Split at random places too.
            let cut = rng.below(doc.len() + 1);
            assert_eq!((events.clone(), err), run([&doc[..cut], &doc[cut..]]));
            if err.is_none() {
                good += 1;
                let mut w = Writer::new();
                for e in &events {
                    w.event(e).unwrap();
                }
                let out = w.finish().unwrap();
                assert_eq!(parse(out.as_bytes()).unwrap(), events, "{out:?}");
            }
            // Whatever a writer accepts, a parser reads.
            let s = String::from_utf8_lossy(&doc).into_owned();
            let mut w = Writer::new();
            let _ = w.pi("t", &s);
            let _ = w.comment(&s);
            let _ = w.start("r", &[("v", &s), ("xmlns:q", &s)]);
            let _ = w.start(&s, &[]);
            let _ = w.text(&s);
            let _ = w.cdata(&s);
            let _ = w.comment(&s);
            let _ = w.pi(&s, &s);
            while w.depth() > 0 {
                w.end().unwrap();
            }
            let _ = w.text(&s);
            let _ = w.text(&s.replace(|c: char| !c.is_ascii_whitespace(), "\r"));
            if let Ok(out) = w.finish() {
                assert!(parse(out.as_bytes()).is_ok(), "{out:?}");
            }
        }
        assert!(good > 100, "only {good} well-formed documents");
    }

    #[test]
    fn long_namespace_prefixes() {
        // Two URIs that share a long prefix, bound to two prefixes, and many
        // tags with an attribute in each. Telling the attributes apart must
        // not compare the URIs each time.
        let shared = "u".repeat(1 << 20);
        let time = |child: &str| {
            let mut doc = format!("<r xmlns:p='{shared}a' xmlns:q='{shared}b'>");
            while doc.len() < MAX_DOCUMENT - 100 {
                doc.push_str(child);
            }
            doc.push_str("</r>");
            let begin = std::time::Instant::now();
            assert!(parse(doc.as_bytes()).is_ok());
            begin.elapsed()
        };
        // The same document with one prefixed attribute per tag, which
        // needs no comparison, is the baseline.
        let one = time("<x p:a='' b=''/>  ");
        let two = time("<x p:a='' q:a=''/>");
        assert!(two < one * 3 + std::time::Duration::from_millis(200), "{two:?} against {one:?}");
        // The same URI under two prefixes is still a duplicate.
        let bad = format!("<r xmlns:p='{shared}' xmlns:q='{shared}'><x p:a='' q:a=''/></r>");
        assert_eq!(kind(&bad), ErrorKind::DuplicateAttribute);
        let bad = format!("<r xmlns:p='{shared}'><x xmlns:q='{shared}' p:a='' q:a=''/></r>");
        assert_eq!(kind(&bad), ErrorKind::DuplicateAttribute);
    }

    #[test]
    fn writer_escapes_within_the_limit() {
        // Escaping stops once the piece passes the room left, rather than
        // building all of it first.
        let mut out = String::new();
        assert_eq!(escape(&mut out, &"&".repeat(1 << 20), false, 100), Err(ErrorKind::TooLarge));
        assert!(out.len() <= 100 + 6, "{}", out.len());
        let mut w = Writer::new();
        w.start("r", &[]).unwrap();
        assert_eq!(w.text(&"&".repeat(MAX_DOCUMENT)), Err(ErrorKind::TooLarge));
        assert_eq!(w.comment(&"x".repeat(MAX_DOCUMENT)), Err(ErrorKind::TooLarge));
        assert_eq!(w.cdata(&"x".repeat(MAX_DOCUMENT)), Err(ErrorKind::TooLarge));
        assert_eq!(w.pi("t", &"x".repeat(MAX_DOCUMENT)), Err(ErrorKind::TooLarge));
        let many: Vec<String> = (0..=MAX_ATTRIBUTES).map(|i| format!("a{i}")).collect();
        let attrs: Vec<(&str, &str)> = many.iter().map(|n| (n.as_str(), "")).collect();
        assert_eq!(w.start("x", &attrs), Err(ErrorKind::TooManyAttributes));
        let long = "a".repeat(MAX_DOCUMENT);
        assert_eq!(w.start(&long, &[]), Err(ErrorKind::NameTooLong));
        assert_eq!(w.start("x", &[(&long, "")]), Err(ErrorKind::NameTooLong));
        w.end().unwrap();
        assert!(parse(w.finish().unwrap().as_bytes()).is_ok());
    }

    #[test]
    fn internal_subset_grammar() {
        // Section 2.8: the internal subset holds markup declarations, PIs,
        // comments, parameter entity references and whitespace, and a
        // non-validating processor checks that it is well formed.
        let ok = [
            "<!DOCTYPE r [<!ELEMENT r (#PCDATA|a|b)*>]><r/>",
            "<!DOCTYPE r [<!ELEMENT r (a,(b|c)+,d?)*> <!ELEMENT a EMPTY><!ELEMENT b ANY>]><r/>",
            "<!DOCTYPE r [<!ELEMENT r ( #PCDATA ) >]><r/>",
            "<!DOCTYPE r [<!ATTLIST r a CDATA #IMPLIED b (x|y) 'x' c NOTATION (n) #REQUIRED d ID #FIXED 'i'>]><r/>",
            "<!DOCTYPE r [<!ENTITY e 'a &#38; &amp; b'><!ENTITY % pe 'x'><!ENTITY f SYSTEM 'f' NDATA n>]><r/>",
            "<!DOCTYPE r [<!NOTATION n PUBLIC 'p'><!NOTATION m SYSTEM 's'><!NOTATION o PUBLIC 'p' 's'>]><r/>",
            "<!DOCTYPE r [ <!-- c --> <?pi data?> <?pi?>\n]><r/>",
            "<!DOCTYPE r []><r/>",
        ];
        for doc in ok {
            let r = whole(doc.as_bytes());
            assert_eq!(r.1, None, "{doc}");
            assert_eq!(r, bytewise(doc.as_bytes()), "{doc}");
        }
        let bad = [
            ("<!DOCTYPE r [garbage]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!--a--b-->]><r/>", ErrorKind::BadComment),
            ("<!DOCTYPE r [<?xml version='1.0'?>]><r/>", ErrorKind::ReservedPi),
            ("<!DOCTYPE r [<?a:b?>]><r/>", ErrorKind::BadName),
            ("<!DOCTYPE r [<!ELEMENT r>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ELEMENT r (a|b,c)>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ELEMENT r (#PCDATA|a)>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ELEMENT r EMPTY]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ATTLIST r a CDATA>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ATTLIST r a CDATA '<'>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ATTLIST r a BOGUS #IMPLIED>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ENTITY e '%pe;'>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!ENTITY e '& x'>]><r/>", ErrorKind::BadReference),
            ("<!DOCTYPE r [<!ENTITY a:b 'x'>]><r/>", ErrorKind::BadName),
            ("<!DOCTYPE r [<!NOTATION n>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [<!FOO r>]><r/>", ErrorKind::BadSyntax),
            ("<!DOCTYPE r [%pe;]><r/>", ErrorKind::UnknownEntity),
        ];
        for (doc, want) in bad {
            assert_eq!(kind(doc), want, "{doc}");
        }
        // Content models nest, up to a limit.
        let nested = format!("<!DOCTYPE r [<!ELEMENT r {}a{}>]><r/>", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
        assert!(parse(nested.as_bytes()).is_ok());
        let nested = format!("<!DOCTYPE r [<!ELEMENT r {}a{}>]><r/>", "(".repeat(100_000), ")".repeat(100_000));
        assert_eq!(kind(&nested), ErrorKind::TooDeep);
    }

    #[test]
    fn attribute_declarations() {
        // Section 3.3.2: a declared default is supplied, and it can declare
        // a namespace.
        let events = parse(b"<!DOCTYPE r [<!ATTLIST r xmlns CDATA 'urn:r' a CDATA 'x'>]><r a='y'/>").unwrap();
        let Event::Start(s) = &events[1] else { panic!() };
        assert_eq!(s.name.namespace.as_deref(), Some("urn:r"));
        assert_eq!(s.attribute(None, "a"), Some("y"));
        assert_eq!(s.attribute(Some(XMLNS_NAMESPACE), "xmlns"), Some("urn:r"));
        let events = parse(b"<!DOCTYPE p:r [<!ATTLIST p:r xmlns:p CDATA 'urn:r'>]><p:r/>").unwrap();
        let Event::Start(s) = &events[1] else { panic!() };
        assert_eq!(s.name.namespace.as_deref(), Some("urn:r"));
        // Section 3.3.3: values of a tokenized type lose leading, trailing
        // and repeated spaces, defaults and written values alike. The first
        // declaration of an attribute is the one that counts.
        let doc = "<!DOCTYPE r [<!ATTLIST r t NMTOKENS ' a  b ' c CDATA ' a  b '><!ATTLIST r t CDATA 'z' u CDATA 'v'>]><r><r t=' x&#32; y\t'/></r>";
        let events = parse(doc.as_bytes()).unwrap();
        let Event::Start(s) = &events[1] else { panic!() };
        assert_eq!(s.attribute(None, "t"), Some("a b"));
        assert_eq!(s.attribute(None, "c"), Some(" a  b "));
        assert_eq!(s.attribute(None, "u"), Some("v"));
        let Event::Start(s) = &events[2] else { panic!() };
        assert_eq!(s.attribute(None, "t"), Some("x y"));
        // #IMPLIED and #REQUIRED supply nothing.
        let events = parse(b"<!DOCTYPE r [<!ATTLIST r a CDATA #IMPLIED b CDATA #REQUIRED>]><r/>").unwrap();
        let Event::Start(s) = &events[1] else { panic!() };
        assert!(s.attributes.is_empty());
        // A default naming an undeclared prefix is an error where it is used.
        assert_eq!(kind("<!DOCTYPE r [<!ATTLIST r p:a CDATA 'x'>]><r/>"), ErrorKind::UndeclaredPrefix);
        // What a parser read with defaults, a writer writes and a parser
        // reads back the same.
        let doc = "<!DOCTYPE r [<!ATTLIST r xmlns CDATA 'urn:r' t NMTOKENS ' a  b '>]><r/>";
        let events = parse(doc.as_bytes()).unwrap();
        let mut w = Writer::new();
        for e in &events {
            w.event(e).unwrap();
        }
        assert_eq!(parse(w.finish().unwrap().as_bytes()).unwrap(), events);
    }

    #[test]
    fn attribute_defaults_are_bounded() {
        // A long default on an element written many times would grow the
        // events far past the document's size.
        let value = "v".repeat(1 << 20);
        let mut doc = format!("<!DOCTYPE r [<!ATTLIST x a CDATA '{value}'>]><r>");
        while doc.len() < (2 << 20) {
            doc.push_str("<x/>");
        }
        doc.push_str("</r>");
        assert_eq!(kind(&doc), ErrorKind::TooLarge);
        // Declarations for one element are capped like its attributes.
        let defs: String = (0..=MAX_ATTRIBUTES).map(|i| format!(" a{i} CDATA #IMPLIED")).collect();
        assert_eq!(kind(&format!("<!DOCTYPE r [<!ATTLIST r{defs}>]><r/>")), ErrorKind::TooManyAttributes);
        // The same declaration repeated counts once.
        let defs = " a CDATA #IMPLIED".repeat(MAX_ATTRIBUTES * 4);
        assert!(parse(format!("<!DOCTYPE r [<!ATTLIST r{defs}>]><r/>").as_bytes()).is_ok());
    }

    #[test]
    fn overflow_does_not_depend_on_finish() {
        // A document past the limit gives the same events and error whether
        // the parser was told it ended before or after reading.
        for tail in ["<!--", "", "<a b='"] {
            for extra in [0usize, 1, 2] {
                let mut doc = format!("<r>{tail}").into_bytes();
                doc.resize(MAX_DOCUMENT - 1 + extra, b'x');
                let streamed = whole(&doc);
                let mut p = Parser::new();
                p.feed(&doc);
                p.finish();
                let mut events = Vec::new();
                let mut err = None;
                while let Some(ev) = p.next_event() {
                    match ev {
                        Ok(e) => events.push(e),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                assert_eq!((events, err), streamed, "{tail:?} {extra}");
                if extra > 1 {
                    assert_eq!(streamed.1.unwrap().kind, ErrorKind::TooLarge);
                }
            }
        }
    }

    #[test]
    fn writer_keeps_namespaces() {
        // An event's names carry namespaces; a writer that cannot give a name
        // the same namespace refuses it rather than change it.
        let ns = |u: &str| Some(Arc::<str>::from(u));
        let r = Name { prefix: None, local: "r".into(), namespace: ns("urn:r") };
        let mut w = Writer::new();
        let start = Event::Start(Start { name: r.clone(), attributes: vec![] });
        assert_eq!(w.event(&start), Err(ErrorKind::BadNamespace));
        assert_eq!(w.depth(), 0);
        let decl = Attribute {
            name: Name { prefix: None, local: "xmlns".into(), namespace: ns(XMLNS_NAMESPACE) },
            value: "urn:r".into(),
        };
        w.event(&Event::Start(Start { name: r.clone(), attributes: vec![decl] })).unwrap();
        let attr =
            Attribute { name: Name { prefix: None, local: "a".into(), namespace: ns("urn:r") }, value: "".into() };
        let bad = Event::Start(Start { name: r.clone(), attributes: vec![attr] });
        assert_eq!(w.event(&bad), Err(ErrorKind::BadNamespace));
        assert_eq!(w.depth(), 1);
        assert_eq!(w.event(&Event::End(name("r"))), Err(ErrorKind::BadNamespace));
        w.event(&Event::End(r)).unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out, "<r xmlns=\"urn:r\"></r>");
        // A failed start leaves nothing behind: the document can still have
        // its root.
        let mut w = Writer::new();
        assert_eq!(w.event(&start), Err(ErrorKind::BadNamespace));
        w.start("r", &[]).unwrap();
        w.end().unwrap();
        assert!(w.finish().is_ok());
    }

    #[test]
    fn writer_reserves_end_tags() {
        // Every element a writer opened can be closed: room for the end
        // tags is kept back.
        let mut w = Writer::new();
        w.start("r", &[]).unwrap();
        w.start("s", &[]).unwrap();
        assert_eq!(w.text(&"x".repeat(MAX_DOCUMENT - 3 - 3)), Err(ErrorKind::TooLarge));
        w.text(&"x".repeat(MAX_DOCUMENT - 6 - 8)).unwrap();
        assert_eq!(w.start("t", &[]), Err(ErrorKind::TooLarge));
        assert_eq!(w.empty("t", &[]), Err(ErrorKind::TooLarge));
        w.end().unwrap();
        w.end().unwrap();
        let out = w.finish().unwrap();
        assert_eq!(out.len(), MAX_DOCUMENT);
        assert!(parse(out.as_bytes()).is_ok());
        // The fuzz target's case: spaces escape to nothing longer, and the
        // closing loop must not fail.
        let s = " ".repeat(838_853);
        let mut w = Writer::new();
        let _ = w.comment(&s);
        let _ = w.start("r", &[("v", &s), ("xmlns:q", &s)]);
        let _ = w.start(&s, &[(&s, "x")]);
        let _ = w.text(&s);
        let _ = w.cdata(&s);
        let _ = w.pi(&s, &s);
        while w.depth() > 0 {
            w.end().unwrap();
        }
        assert!(parse(w.finish().unwrap().as_bytes()).is_ok());
    }
}
