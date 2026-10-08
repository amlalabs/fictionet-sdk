//! Runtime schemas and messages for FIX Simple Binary Encoding 1.0.
//!
//! This implementation uses the public FIX Trading Community
//! [1.0 standard sources](https://github.com/FIXTradingCommunity/fix-simple-binary-encoding/tree/master/v1-0-STANDARD/doc):
//! section 2 (Field Encoding), section 3 (Message Structure), section 4
//! (Message Schema), and section 5 (Schema Extension Mechanism). No private
//! schemas or licensed documents are needed.
//!
//! [`Schema::parse`] reads a bounded XML subset with [`stdlib::xml`](fictionet::stdlib::xml),
//! including namespaces, comments, an XML declaration, and character references.
//! Namespaces and whitespace follow the XML module's validation and normalization.
//! DTDs, entity declarations, processing instructions other than the initial
//! XML declaration, CDATA, and external includes are refused. Metadata such
//! as descriptions and semantic types does not drive application validation.
//! Character arrays and variable data remain bytes; character encoding and
//! FIX business semantics belong to the caller.
//!
//! [`Schema::decode`] reads one exact message. [`Messages`] reads a sequence
//! of header-prefixed messages (section 3.1). It caches a schema walk rather
//! than reparsing an incomplete tree. Larger fixed blocks are skipped
//! (section 5.3). Unknown templates and enum values are refused. Undeclared
//! set bits are refused under section 2.12's rule to clear unassigned bits.
//! Mismatched `numGroups` and `numVarDataFields` counts are refused, unlike
//! section 5's "Number of repeating groups and variable data" extension
//! mechanism. Load the newer schema for those extensions.
//! Without counts, the sender must keep the known group and data layout.
//! Float ranges default to finite values and exclude infinities (section 2.6).
//!
//! [`MessageWire`] supplies the static schema context required by [`Wire`].
//! A runtime caller can use [`Schema::write`] directly. Both writers validate
//! every value and leave the destination unchanged on error. Constants are
//! present in the value tree but occupy no wire bytes. Fields introduced
//! after the acting version become [`Value::Absent`] (section 5.4).

use fictionet::stdlib::codec::{Decode, Step, Wire, Work};
use fictionet::stdlib::xml;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

/// Maximum UTF-8 XML input size in bytes.
pub const MAX_XML_BYTES: usize = 1024 * 1024;
/// Maximum nesting of XML elements.
pub const MAX_XML_DEPTH: usize = 32;
/// Maximum number of XML elements, including metadata elements.
pub const MAX_XML_ELEMENTS: usize = 16_384;
/// Maximum attributes on one XML element.
pub const MAX_XML_ATTRIBUTES: usize = 32;
/// Maximum bytes in an XML name or an SBE symbolic name.
pub const MAX_NAME_BYTES: usize = 128;
/// Maximum nesting of composite references and repeating groups.
pub const MAX_NESTING: usize = 24;
/// Maximum encoded message size, including the schema-defined header.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum elements in a primitive array or entries in one group.
pub const MAX_ARRAY_LENGTH: usize = 65_536;
/// Maximum values, named members, and group entries visited in one message.
/// Also bounds the block work of one message, including empty groups.
pub const MAX_VALUES: usize = 65_536;
/// Maximum total byte and name storage in one decoded value tree.
pub const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum compiled type and block definitions, including inline types.
pub const MAX_SCHEMA_NODES: usize = MAX_XML_ELEMENTS + 16;
/// Maximum version and length entries read while compiling the minimum
/// block lengths of every acting version.
pub const MAX_LAYOUT_ENTRIES: usize = 1 << 18;

/// A schema, wire, or value validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An implementation limit was exceeded. The string names the limit.
    Limit(&'static str),
    /// XML syntax or an unsupported XML construct at this byte offset.
    Xml(usize),
    /// A schema violates an encoding or layout rule from sections 2 through 5.
    Schema(&'static str),
    /// A complete message was required, but bytes were missing.
    Truncated,
    /// Bytes followed the end of the message.
    Trailing,
    /// The header names another schema or an unknown template.
    Header,
    /// A block cannot hold the fields present in the acting version.
    BlockLength,
    /// A group or data count does not match the known schema layout.
    Layout,
    /// A scalar, enum, set, or constant violates its encoding.
    Value,
    /// A tree has missing, extra, reordered, or incorrectly typed members.
    Tree,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Limit(name) => write!(f, "SBE limit exceeded: {name}"),
            Self::Xml(at) => write!(f, "unsupported or malformed XML at byte {at}"),
            Self::Schema(reason) => write!(f, "invalid SBE schema: {reason}"),
            Self::Truncated => f.write_str("truncated SBE message"),
            Self::Trailing => f.write_str("bytes after SBE message"),
            Self::Header => f.write_str("unknown SBE schema or template"),
            Self::BlockLength => f.write_str("short SBE fixed block"),
            Self::Layout => f.write_str("unknown SBE variable layout"),
            Self::Value => f.write_str("invalid SBE field value"),
            Self::Tree => f.write_str("SBE value tree does not match schema"),
        }
    }
}
impl core::error::Error for Error {}

/// Schema-wide byte order (sections 2.3 and 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least significant byte first. The XML default.
    LittleEndian,
    /// Most significant byte first.
    BigEndian,
}

/// Field presence (section 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// A non-null value is transmitted.
    Required,
    /// A value or its null sentinel is transmitted.
    Optional,
    /// The schema supplies the value; no bytes are transmitted.
    Constant,
}

/// Primitive encodings from sections 2.3, 2.5, and 2.6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primitive {
    /// One US-ASCII character.
    Char,
    /// Signed 8-bit integer.
    Int8,
    /// Signed 16-bit integer.
    Int16,
    /// Signed 32-bit integer.
    Int32,
    /// Signed 64-bit integer.
    Int64,
    /// Unsigned 8-bit integer.
    Uint8,
    /// Unsigned 16-bit integer.
    Uint16,
    /// Unsigned 32-bit integer.
    Uint32,
    /// Unsigned 64-bit integer.
    Uint64,
    /// IEEE 754 binary32.
    Float,
    /// IEEE 754 binary64.
    Double,
}

/// A primitive value. Float variants store IEEE bits so equality is exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    /// A single character code.
    Char(u8),
    /// A signed integer. Its width comes from the schema.
    Int(i64),
    /// An unsigned integer. Its width comes from the schema.
    Uint(u64),
    /// Binary32 bits, obtainable with `f32::to_bits`.
    Float(u32),
    /// Binary64 bits, obtainable with `f64::to_bits`.
    Double(u64),
}

/// A named field or composite member in schema order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedValue {
    /// The exact schema name.
    pub name: String,
    /// The field value, including constants and unavailable fields.
    pub value: Value,
}

/// A bounded dynamic message value (sections 2 and 3).
///
/// Readers and writers enforce [`MAX_VALUES`], [`MAX_VALUE_BYTES`], and
/// [`MAX_NESTING`]. Public vectors may be constructed freely; writers
/// refuse trees outside those bounds before descending into them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// The field does not exist in the acting version (section 5.4).
    Absent,
    /// An optional scalar or enum holds its null sentinel.
    Null,
    /// A primitive scalar.
    Scalar(Scalar),
    /// A fixed char/uint8 array or variable data, with no text conversion.
    /// Fixed arrays retain padding. Their bytes have no scalar null meaning.
    Bytes(Vec<u8>),
    /// An array of primitives other than char and uint8. Nulls are per element.
    Array(Vec<Value>),
    /// The name of a declared enum value.
    Enum(String),
    /// Choice bits, with bit zero as the least significant bit (section 2.11).
    Set(u64),
    /// Composite members in schema order, including nested composites and refs.
    Composite(Vec<NamedValue>),
    /// A repeating group and its wire block length (section 3.4).
    Group(Group),
}

/// A repeating group. Each entry contains members in schema order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Space reserved for each entry's fixed fields. Extra bytes are skipped
    /// on decode and zero-filled on write (sections 3.4 and 5.3).
    pub block_length: u64,
    /// Entries in wire order, limited by [`MAX_ARRAY_LENGTH`].
    pub entries: Vec<Vec<NamedValue>>,
}

/// Message header values (section 3.2). Widths and offsets come from XML.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Root fixed block size, excluding the header, groups, and data.
    pub block_length: u64,
    /// The message template identifier.
    pub template_id: u64,
    /// The schema identifier.
    pub schema_id: u64,
    /// The sender's schema version, also called the acting version.
    pub version: u64,
}

/// One header and its decoded fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Schema-defined header values.
    pub header: Header,
    /// Root members in schema order, including constants and absent fields.
    pub fields: Vec<NamedValue>,
}

impl Primitive {
    /// Width of one value in bytes (section 2).
    pub fn size(self) -> usize {
        match self {
            Self::Char | Self::Int8 | Self::Uint8 => 1,
            Self::Int16 | Self::Uint16 => 2,
            Self::Int32 | Self::Uint32 | Self::Float => 4,
            Self::Int64 | Self::Uint64 | Self::Double => 8,
        }
    }

    /// Default minimum, maximum, and null sentinel (sections 2.3, 2.5, 2.6).
    /// Float ranges cover finite values; their null sentinel is a quiet NaN.
    pub fn bounds(self) -> (Scalar, Scalar, Scalar) {
        use Scalar::{Char, Double, Float, Int, Uint};
        match self {
            Self::Char => (Char(0x20), Char(0x7e), Char(0)),
            Self::Int8 => (Int(-127), Int(127), Int(-128)),
            Self::Int16 => (Int(-32767), Int(32767), Int(-32768)),
            Self::Int32 => (
                Int(i32::MIN as i64 + 1),
                Int(i32::MAX as i64),
                Int(i32::MIN as i64),
            ),
            Self::Int64 => (Int(i64::MIN + 1), Int(i64::MAX), Int(i64::MIN)),
            Self::Uint8 => (Uint(0), Uint(254), Uint(255)),
            Self::Uint16 => (Uint(0), Uint(65534), Uint(65535)),
            Self::Uint32 => (Uint(0), Uint(u32::MAX as u64 - 1), Uint(u32::MAX as u64)),
            Self::Uint64 => (Uint(0), Uint(u64::MAX - 1), Uint(u64::MAX)),
            Self::Float => (
                Float(f32::MIN.to_bits()),
                Float(f32::MAX.to_bits()),
                Float(f32::NAN.to_bits()),
            ),
            Self::Double => (
                Double(f64::MIN.to_bits()),
                Double(f64::MAX.to_bits()),
                Double(f64::NAN.to_bits()),
            ),
        }
    }

    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "char" => Self::Char,
            "int8" => Self::Int8,
            "int16" => Self::Int16,
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "uint8" => Self::Uint8,
            "uint16" => Self::Uint16,
            "uint32" => Self::Uint32,
            "uint64" => Self::Uint64,
            "float" => Self::Float,
            "double" => Self::Double,
            _ => return None,
        })
    }

    fn unsigned(self) -> bool {
        matches!(
            self,
            Self::Uint8 | Self::Uint16 | Self::Uint32 | Self::Uint64
        )
    }

    fn literal(self, text: &str) -> Result<Scalar, Error> {
        let v = match self {
            Self::Char => {
                let [byte] = text.as_bytes() else {
                    return Err(Error::Schema("char literal"));
                };
                Scalar::Char(*byte)
            }
            Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64 => {
                Scalar::Int(text.parse().map_err(|_| Error::Schema("integer literal"))?)
            }
            Self::Uint8 | Self::Uint16 | Self::Uint32 | Self::Uint64 => {
                Scalar::Uint(text.parse().map_err(|_| Error::Schema("integer literal"))?)
            }
            Self::Float => Scalar::Float(
                text.parse::<f32>()
                    .map_err(|_| Error::Schema("float literal"))?
                    .to_bits(),
            ),
            Self::Double => Scalar::Double(
                text.parse::<f64>()
                    .map_err(|_| Error::Schema("double literal"))?
                    .to_bits(),
            ),
        };
        if !self.fits(v) {
            return Err(Error::Schema("literal outside primitive width"));
        }
        Ok(v)
    }

    fn fits(self, v: Scalar) -> bool {
        match (self, v) {
            (Self::Char, Scalar::Char(_))
            | (Self::Float, Scalar::Float(_))
            | (Self::Double, Scalar::Double(_)) => true,
            (p, Scalar::Uint(n)) if p.unsigned() => p.size() == 8 || n < (1u64 << (p.size() * 8)),
            (Self::Int8, Scalar::Int(n)) => i8::try_from(n).is_ok(),
            (Self::Int16, Scalar::Int(n)) => i16::try_from(n).is_ok(),
            (Self::Int32, Scalar::Int(n)) => i32::try_from(n).is_ok(),
            (Self::Int64, Scalar::Int(_)) => true,
            _ => false,
        }
    }
}

fn scalar_le(a: Scalar, b: Scalar) -> bool {
    match (a, b) {
        (Scalar::Char(a), Scalar::Char(b)) => a <= b,
        (Scalar::Int(a), Scalar::Int(b)) => a <= b,
        (Scalar::Uint(a), Scalar::Uint(b)) => a <= b,
        (Scalar::Float(a), Scalar::Float(b)) => f32::from_bits(a) <= f32::from_bits(b),
        (Scalar::Double(a), Scalar::Double(b)) => f64::from_bits(a) <= f64::from_bits(b),
        _ => false,
    }
}
fn nan(v: Scalar) -> bool {
    match v {
        Scalar::Float(n) => f32::from_bits(n).is_nan(),
        Scalar::Double(n) => f64::from_bits(n).is_nan(),
        _ => false,
    }
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .filter(|n| *n <= MAX_MESSAGE_BYTES)
        .ok_or(Error::Limit("MAX_MESSAGE_BYTES"))
}
fn size(n: u64) -> Result<usize, Error> {
    usize::try_from(n)
        .ok()
        .filter(|n| *n <= MAX_MESSAGE_BYTES)
        .ok_or(Error::Limit("MAX_MESSAGE_BYTES"))
}
fn nesting(depth: usize) -> Result<(), Error> {
    if depth > MAX_NESTING {
        Err(Error::Limit("MAX_NESTING"))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct XmlNode {
    tag: String,
    attrs: BTreeMap<String, String>,
    text: String,
    children: Vec<usize>,
}
impl XmlNode {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(String::as_str)
    }
    fn required(&self, name: &str) -> Result<&str, Error> {
        self.attr(name).ok_or(Error::Schema("missing attribute"))
    }
    fn number(&self, name: &str, default: u64) -> Result<u64, Error> {
        self.attr(name).map_or(Ok(default), |v| {
            v.parse().map_err(|_| Error::Schema("unsigned attribute"))
        })
    }
    fn symbol(&self) -> Result<String, Error> {
        let name = self.required("name")?;
        if name.len() > MAX_NAME_BYTES {
            return Err(Error::Limit("MAX_NAME_BYTES"));
        }
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::Schema("symbolic name"));
        }
        Ok(name.to_owned())
    }
    fn since(&self, version: u64) -> Result<u64, Error> {
        let n = self.number("sinceVersion", 0)?;
        if n > version || self.number("deprecated", 0)? > version {
            return Err(Error::Schema("version attribute"));
        }
        Ok(n)
    }
    fn presence(&self) -> Result<Option<Presence>, Error> {
        self.attr("presence")
            .map(|v| match v {
                "required" => Ok(Presence::Required),
                "optional" => Ok(Presence::Optional),
                "constant" => Ok(Presence::Constant),
                _ => Err(Error::Schema("presence")),
            })
            .transpose()
    }
}

fn parse_xml(input: &str) -> Result<Vec<XmlNode>, Error> {
    if input.len() > MAX_XML_BYTES {
        return Err(Error::Limit("MAX_XML_BYTES"));
    }
    let mut parser = xml::Events::new();
    let mut pos = 0;
    let mut nodes: Vec<XmlNode> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    loop {
        let at = pos;
        match parser
            .decode(input.as_bytes().get(pos..).ok_or(Error::Xml(at))?, true)
            .map_err(|_| Error::Xml(at))?
        {
            Step::Item(event, used) => {
                pos += used;
                match event {
                    xml::Event::Start(start) => {
                        if stack.len() >= MAX_XML_DEPTH {
                            return Err(Error::Limit("MAX_XML_DEPTH"));
                        }
                        if nodes.len() >= MAX_XML_ELEMENTS {
                            return Err(Error::Limit("MAX_XML_ELEMENTS"));
                        }
                        if start.attributes.len() > MAX_XML_ATTRIBUTES {
                            return Err(Error::Limit("MAX_XML_ATTRIBUTES"));
                        }
                        if start.name.qname().len() > MAX_NAME_BYTES {
                            return Err(Error::Limit("MAX_NAME_BYTES"));
                        }
                        let mut attrs = BTreeMap::new();
                        for attr in start.attributes {
                            let name = attr.name.qname();
                            if name.len() > MAX_NAME_BYTES {
                                return Err(Error::Limit("MAX_NAME_BYTES"));
                            }
                            attrs.insert(name, attr.value);
                        }
                        let id = nodes.len();
                        if let Some(parent) = stack.last() {
                            nodes.get_mut(*parent).ok_or(Error::Xml(at))?.children.push(id);
                        }
                        nodes.push(XmlNode {
                            tag: start.name.local,
                            attrs,
                            text: String::new(),
                            children: Vec::new(),
                        });
                        stack.push(id);
                    }
                    xml::Event::End(_) => {
                        stack.pop().ok_or(Error::Xml(at))?;
                    }
                    xml::Event::Text(text) => {
                        let id = stack.last().ok_or(Error::Xml(at))?;
                        nodes.get_mut(*id).ok_or(Error::Xml(at))?.text.push_str(&text);
                    }
                    xml::Event::Declaration { version, .. } => {
                        if version != "1.0" {
                            return Err(Error::Xml(at));
                        }
                    }
                    xml::Event::Comment(_) => {}
                    xml::Event::Doctype { .. } | xml::Event::Pi { .. } | xml::Event::CData(_) => {
                        return Err(Error::Xml(at));
                    }
                }
            }
            Step::Skip(used) => pos += used,
            Step::Need | Step::End => break,
        }
    }
    if pos != input.len() || !stack.is_empty() || nodes.is_empty() {
        return Err(Error::Xml(pos));
    }
    Ok(nodes)
}

#[derive(Clone, Debug)]
struct Simple {
    primitive: Primitive,
    length: usize,
    array: bool,
    presence: Presence,
    explicit_presence: bool,
    min: Scalar,
    max: Scalar,
    null: Scalar,
    constant: Option<Value>,
    explicit_max: bool,
}
impl Simple {
    fn new(primitive: Primitive) -> Self {
        let (min, max, null) = primitive.bounds();
        Self {
            primitive,
            length: 1,
            array: false,
            presence: Presence::Required,
            explicit_presence: false,
            min,
            max,
            null,
            constant: None,
            explicit_max: false,
        }
    }
    fn valid(&self, v: Scalar) -> bool {
        self.primitive.fits(v) && scalar_le(self.min, v) && scalar_le(v, self.max)
    }
    fn is_null(&self, v: Scalar) -> bool {
        v == self.null || (nan(v) && nan(self.null))
    }
    /// Moves a default bound past an explicit null that sits on it, so
    /// `nullValue="127"` on an int8 leaves -127..=126 (section 2.5 lets a
    /// schema override the default null). Explicit bounds are kept as given.
    fn exclude_null(&mut self, explicit_min: bool, explicit_max: bool) {
        let step = |v: Scalar, up: bool| match v {
            Scalar::Char(n) => if up {
                n.checked_add(1)
            } else {
                n.checked_sub(1)
            }
            .map(Scalar::Char),
            Scalar::Int(n) => if up {
                n.checked_add(1)
            } else {
                n.checked_sub(1)
            }
            .map(Scalar::Int),
            Scalar::Uint(n) => if up {
                n.checked_add(1)
            } else {
                n.checked_sub(1)
            }
            .map(Scalar::Uint),
            _ => None,
        };
        if !explicit_max && self.null == self.max {
            if let Some(v) = step(self.null, false) {
                self.max = v;
            }
        } else if !explicit_min
            && self.null == self.min
            && let Some(v) = step(self.null, true)
        {
            self.min = v;
        }
    }
    fn decode(&self, v: Scalar, presence: Presence) -> Result<Value, Error> {
        if self.is_null(v) {
            if presence == Presence::Optional {
                return Ok(Value::Null);
            }
            return Err(Error::Value);
        }
        if !self.valid(v) {
            return Err(Error::Value);
        }
        Ok(Value::Scalar(v))
    }
}

#[derive(Clone, Debug)]
struct Choice {
    name: String,
    value: Scalar,
    since: u64,
}
#[derive(Clone, Debug)]
struct TypeMember {
    name: String,
    ty: usize,
    offset: usize,
    since: u64,
}
#[derive(Clone, Debug)]
enum Kind {
    Simple(Simple),
    Enum(Simple, Vec<Choice>),
    Set(Primitive, Vec<Choice>),
    Composite(Vec<TypeMember>),
}
#[derive(Clone, Debug)]
struct TypeDef {
    kind: Kind,
    length: Option<usize>,
    since: u64,
    depth: usize,
    work: usize,
    /// Minimum encoded length by acting version: `(since, end)` pairs with
    /// both parts increasing. See [`Block::minimum`].
    ends: Vec<(u64, usize)>,
}
impl TypeDef {
    fn presence(&self) -> Presence {
        match &self.kind {
            Kind::Simple(s) | Kind::Enum(s, _) => s.presence,
            _ => Presence::Required,
        }
    }
    fn member_presence(&self, optional: &mut bool) -> Presence {
        let presence = self.presence();
        if *optional && presence != Presence::Constant {
            *optional = false;
            Presence::Optional
        } else {
            presence
        }
    }
}
#[derive(Clone, Debug)]
struct Field {
    ty: usize,
    offset: usize,
    presence: Presence,
    constant: Option<Value>,
}
#[derive(Clone, Debug)]
enum MemberKind {
    Field(Field),
    Group { block: usize, dimensions: Layout },
    Data { length: Simple, prefix: usize },
}
#[derive(Clone, Debug)]
struct Member {
    name: String,
    since: u64,
    kind: MemberKind,
}
#[derive(Clone, Debug)]
struct Block {
    members: Vec<Member>,
    length: usize,
    tail: usize,
    work: usize,
    minimums: Vec<(u64, usize)>,
}
#[derive(Clone, Debug)]
struct Template {
    name: String,
    block: usize,
    since: u64,
}
#[derive(Clone, Debug)]
struct LayoutField {
    role: usize,
    offset: usize,
    encoding: Simple,
}
#[derive(Clone, Debug)]
struct Layout {
    length: usize,
    fields: Vec<LayoutField>,
}

/// An immutable, validated SBE XML schema (section 4).
///
/// Definitions use an arena so repeated references do not expand the schema.
/// XML is limited by [`MAX_XML_BYTES`] and [`MAX_XML_ELEMENTS`]; compiled
/// definitions by [`MAX_SCHEMA_NODES`]. Reference cycles and excessive
/// combined group/composite nesting are refused. No schema files are loaded
/// implicitly. Resolve external includes before passing the XML here.
#[derive(Clone, Debug)]
pub struct Schema {
    id: u64,
    version: u64,
    order: ByteOrder,
    header: Layout,
    types: Vec<TypeDef>,
    blocks: Vec<Block>,
    messages: BTreeMap<u64, Template>,
}

struct Compiler<'a> {
    xml: &'a [XmlNode],
    names: BTreeMap<String, usize>,
    resolved: BTreeMap<usize, usize>,
    primitives: BTreeMap<String, usize>,
    active: BTreeSet<usize>,
    types: Vec<TypeDef>,
    blocks: Vec<Block>,
    version: u64,
    layout_work: usize,
}
impl Compiler<'_> {
    fn ty(&self, id: usize) -> Result<&TypeDef, Error> {
        self.types.get(id).ok_or(Error::Schema("type reference"))
    }
    fn node(&self, id: usize) -> Result<&XmlNode, Error> {
        self.xml.get(id).ok_or(Error::Schema("XML reference"))
    }
    fn insert(&mut self, t: TypeDef) -> Result<usize, Error> {
        if self.types.len() + self.blocks.len() >= MAX_SCHEMA_NODES {
            return Err(Error::Limit("MAX_SCHEMA_NODES"));
        }
        let id = self.types.len();
        self.types.push(t);
        Ok(id)
    }
    fn named(&mut self, name: &str, depth: usize) -> Result<usize, Error> {
        nesting(depth)?;
        if let Some(id) = self.names.get(name) {
            return self.compile(*id, depth);
        }
        if let Some(id) = self.primitives.get(name) {
            return Ok(*id);
        }
        let p = Primitive::named(name).ok_or(Error::Schema("undefined type"))?;
        let id = self.insert(TypeDef {
            kind: Kind::Simple(Simple::new(p)),
            length: Some(p.size()),
            since: 0,
            depth: 1,
            work: 1,
            ends: vec![(0, p.size())],
        })?;
        self.primitives.insert(name.to_owned(), id);
        Ok(id)
    }
    fn compile(&mut self, node_id: usize, depth: usize) -> Result<usize, Error> {
        nesting(depth)?;
        if let Some(id) = self.resolved.get(&node_id) {
            nesting(depth + self.ty(*id)?.depth - 1)?;
            return Ok(*id);
        }
        if !self.active.insert(node_id) {
            return Err(Error::Schema("cyclic type reference"));
        }
        let n = self
            .xml
            .get(node_id)
            .ok_or(Error::Schema("XML reference"))?;
        n.symbol()?;
        let mut since = n.since(self.version)?;
        let t = match n.tag.as_str() {
            "type" => {
                if !n.children.is_empty() {
                    return Err(Error::Schema("type children"));
                }
                let p = Primitive::named(n.required("primitiveType")?)
                    .ok_or(Error::Schema("primitiveType"))?;
                let mut s = Simple::new(p);
                s.explicit_presence = n.presence()?.is_some();
                s.presence = n.presence()?.unwrap_or(Presence::Required);
                s.length = usize::try_from(n.number("length", 1)?)
                    .map_err(|_| Error::Limit("MAX_ARRAY_LENGTH"))?;
                s.array = n.attr("length").is_some();
                let value_ref = n.attr("valueRef");
                if value_ref.is_some() && s.presence != Presence::Constant {
                    return Err(Error::Schema("valueRef requires constant"));
                }
                if s.presence == Presence::Constant
                    && p == Primitive::Char
                    && n.attr("length").is_none()
                    && value_ref.is_none()
                {
                    s.length = n.text.len();
                    s.array = s.length != 1;
                }
                if s.length > MAX_ARRAY_LENGTH {
                    return Err(Error::Limit("MAX_ARRAY_LENGTH"));
                }
                if n.attr("nullValue").is_some() && s.presence != Presence::Optional {
                    return Err(Error::Schema("nullValue needs optional presence"));
                }
                if let Some(v) = n.attr("minValue") {
                    s.min = p.literal(v)?;
                }
                if let Some(v) = n.attr("maxValue") {
                    s.max = p.literal(v)?;
                    s.explicit_max = true;
                }
                if let Some(v) = n.attr("nullValue") {
                    s.null = p.literal(v)?;
                    s.exclude_null(n.attr("minValue").is_some(), s.explicit_max);
                }
                if !scalar_le(s.min, s.max) {
                    return Err(Error::Schema("inverted value range"));
                }
                if matches!(p, Primitive::Float | Primitive::Double) && !nan(s.null) {
                    return Err(Error::Schema("float null must be NaN"));
                }
                if s.presence == Presence::Optional && s.valid(s.null) {
                    return Err(Error::Schema("null overlaps value range"));
                }
                if let Some(reference) = value_ref {
                    // Section 2's "Timestamp with constant time unit" names an
                    // enum value; the constant takes that value's encoding.
                    if !n.text.trim().is_empty() {
                        return Err(Error::Schema("valueRef with constant text"));
                    }
                    if s.length != 1 {
                        return Err(Error::Schema("constant requires scalar or char array"));
                    }
                    let (_, choice) = self.value_ref(reference, depth)?;
                    if !s.valid(choice.value) || s.is_null(choice.value) {
                        return Err(Error::Schema("constant outside range"));
                    }
                    since = since.max(choice.since);
                    s.constant = Some(match choice.value {
                        Scalar::Char(c) if s.array => Value::Bytes(vec![c]),
                        v => Value::Scalar(v),
                    });
                } else if s.presence == Presence::Constant {
                    let v = if p == Primitive::Char && s.array {
                        if n.text.len() != s.length || s.length == 0 {
                            return Err(Error::Schema("constant array length"));
                        }
                        if !n
                            .text
                            .bytes()
                            .all(|b| (0x20..=0x7e).contains(&b) && s.valid(Scalar::Char(b)))
                        {
                            return Err(Error::Schema("constant outside range"));
                        }
                        Value::Bytes(n.text.as_bytes().to_vec())
                    } else {
                        if s.length != 1 {
                            return Err(Error::Schema("constant requires scalar or char array"));
                        }
                        let v = p.literal(if p == Primitive::Char {
                            &n.text
                        } else {
                            n.text.trim()
                        })?;
                        if !s.valid(v) || s.is_null(v) {
                            return Err(Error::Schema("constant outside range"));
                        }
                        Value::Scalar(v)
                    };
                    s.constant = Some(v);
                } else if !n.text.trim().is_empty() {
                    return Err(Error::Schema("nonconstant type text"));
                }
                let length = if s.presence == Presence::Constant {
                    Some(0)
                } else if s.length == 0 {
                    None
                } else {
                    Some(
                        s.length
                            .checked_mul(p.size())
                            .filter(|n| *n <= MAX_MESSAGE_BYTES)
                            .ok_or(Error::Limit("MAX_MESSAGE_BYTES"))?,
                    )
                };
                let work = if matches!(p, Primitive::Char | Primitive::Uint8) {
                    1
                } else {
                    s.length.max(1)
                };
                TypeDef {
                    kind: Kind::Simple(s),
                    length,
                    since,
                    depth: 1,
                    work,
                    ends: vec![(since, length.unwrap_or(0))],
                }
            }
            "enum" | "set" => {
                if !n.text.trim().is_empty() {
                    return Err(Error::Schema("enum or set text"));
                }
                let encoding = n.required("encodingType")?.to_owned();
                let id = self.named(&encoding, depth + 1)?;
                let Kind::Simple(mut s) = self.ty(id)?.kind.clone() else {
                    return Err(Error::Schema("enum/set scalar encoding"));
                };
                let is_set = n.tag == "set";
                if s.length != 1
                    || s.presence == Presence::Constant
                    || !(s.primitive.unsigned() || (!is_set && s.primitive == Primitive::Char))
                {
                    return Err(Error::Schema("enum/set encodingType"));
                }
                if let Some(p) = n.presence()? {
                    s.presence = p;
                    s.explicit_presence = true;
                }
                if s.presence == Presence::Constant || (is_set && s.presence != Presence::Required)
                {
                    return Err(Error::Schema("enum/set presence"));
                }
                if let Some(v) = n.attr("nullValue") {
                    if s.presence != Presence::Optional || is_set {
                        return Err(Error::Schema("enum nullValue"));
                    }
                    s.null = s.primitive.literal(v)?;
                }
                let mut choices = Vec::new();
                let mut names = BTreeSet::new();
                let mut values = BTreeSet::new();
                for child in &n.children {
                    let c = self.node(*child)?;
                    if c.tag != if is_set { "choice" } else { "validValue" }
                        || !c.children.is_empty()
                    {
                        return Err(Error::Schema("enum/set child"));
                    }
                    let name = c.symbol()?;
                    let since = c.since(self.version)?.max(since);
                    let value = if is_set {
                        let bit = c
                            .text
                            .trim()
                            .parse::<u32>()
                            .map_err(|_| Error::Schema("choice bit"))?;
                        if bit >= (s.primitive.size() * 8) as u32 {
                            return Err(Error::Schema("choice outside bitset"));
                        }
                        Scalar::Uint(1u64.checked_shl(bit).ok_or(Error::Schema("choice bit"))?)
                    } else {
                        s.primitive.literal(if s.primitive == Primitive::Char {
                            &c.text
                        } else {
                            c.text.trim()
                        })?
                    };
                    if !is_set && !s.valid(value) && !s.is_null(value) {
                        return Err(Error::Schema("enum value outside encoding range"));
                    }
                    let key = match value {
                        Scalar::Uint(v) => v,
                        Scalar::Char(v) => u64::from(v),
                        _ => return Err(Error::Schema("enum value")),
                    };
                    if !names.insert(name.clone()) || !values.insert(key) {
                        return Err(Error::Schema("duplicate choice"));
                    }
                    if !is_set && s.presence == Presence::Optional && s.is_null(value) {
                        return Err(Error::Schema("enum value equals null"));
                    }
                    choices.push(Choice { name, value, since });
                }
                if choices.is_empty() {
                    return Err(Error::Schema("empty enum/set"));
                }
                let length = s.primitive.size();
                TypeDef {
                    kind: if is_set {
                        Kind::Set(s.primitive, choices)
                    } else {
                        Kind::Enum(s, choices)
                    },
                    length: Some(length),
                    since,
                    depth: 1,
                    work: 1,
                    ends: vec![(since, length)],
                }
            }
            "composite" => {
                if !n.text.trim().is_empty()
                    || n.presence()?.is_some_and(|p| p != Presence::Required)
                {
                    return Err(Error::Schema("composite content or presence"));
                }
                let mut members = Vec::new();
                let mut names = BTreeSet::new();
                let mut end = 0;
                let mut variable = false;
                let mut tree_depth = 1;
                let mut last_since = 0;
                let mut work = 1usize;
                for child in &n.children {
                    if variable {
                        return Err(Error::Schema("variable member must be last"));
                    }
                    let c = self.xml.get(*child).ok_or(Error::Schema("XML reference"))?;
                    let name = c.symbol()?;
                    if !names.insert(name.clone()) {
                        return Err(Error::Schema("duplicate composite member"));
                    }
                    let ty = if c.tag == "ref" {
                        if !c.children.is_empty() || !c.text.trim().is_empty() {
                            return Err(Error::Schema("ref content"));
                        }
                        self.named(c.required("type")?, depth + 1)?
                    } else {
                        self.compile(*child, depth + 1)?
                    };
                    let t = self.ty(ty)?;
                    let member_since = c.since(self.version)?.max(t.since).max(since);
                    if t.presence() != Presence::Constant {
                        if member_since < last_since {
                            return Err(Error::Schema("sinceVersion order"));
                        }
                        last_since = member_since;
                    }
                    let offset = size(c.number("offset", end as u64)?)?;
                    if offset < end {
                        return Err(Error::Schema("overlapping composite members"));
                    }
                    tree_depth = tree_depth.max(t.depth + 1);
                    work = work
                        .checked_add(t.work + 1)
                        .filter(|n| *n <= MAX_VALUES)
                        .ok_or(Error::Limit("MAX_VALUES"))?;
                    end = add(offset, t.length.unwrap_or(0))?;
                    variable = t.length.is_none();
                    members.push(TypeMember {
                        name,
                        ty,
                        offset,
                        since: member_since,
                    });
                }
                if members.is_empty() {
                    return Err(Error::Schema("empty composite"));
                }
                nesting(tree_depth)?;
                let mut ends = vec![(since, 0)];
                for m in &members {
                    self.extend_ends(m.ty, m.offset, m.since, &mut ends)?;
                }
                TypeDef {
                    kind: Kind::Composite(members),
                    length: if variable { None } else { Some(end) },
                    since,
                    depth: tree_depth,
                    work,
                    ends: minimums(ends),
                }
            }
            _ => return Err(Error::Schema("unknown encoding element")),
        };
        let id = self.insert(t)?;
        self.active.remove(&node_id);
        self.resolved.insert(node_id, id);
        Ok(id)
    }

    /// Resolves a `valueRef` of the form `Enum.value` (section 4) to the
    /// enum's id and the named valid value.
    fn value_ref(&mut self, reference: &str, depth: usize) -> Result<(usize, Choice), Error> {
        let (enum_name, choice_name) =
            reference.split_once('.').ok_or(Error::Schema("valueRef"))?;
        let id = self.named(enum_name, depth + 1)?;
        let t = self.ty(id)?;
        let Kind::Enum(_, choices) = &t.kind else {
            return Err(Error::Schema("valueRef requires enum"));
        };
        let choice = choices
            .iter()
            .find(|c| c.name == choice_name)
            .ok_or(Error::Schema("unknown valueRef"))?;
        Ok((
            id,
            Choice {
                name: choice.name.clone(),
                value: choice.value,
                since: choice.since.max(t.since),
            },
        ))
    }

    fn layout(&mut self, name: &str, header: bool) -> Result<Layout, Error> {
        let id = self.named(name, 1)?;
        let t = self.ty(id)?;
        let Kind::Composite(members) = &t.kind else {
            return Err(Error::Schema("header/dimensions composite"));
        };
        if t.since != 0 {
            return Err(Error::Schema("versioned header/dimensions"));
        }
        let mut fields = Vec::new();
        let mut roles = BTreeSet::new();
        for m in members {
            let role = match m.name.as_str() {
                "blockLength" => 0,
                "templateId" if header => 1,
                "schemaId" if header => 2,
                "version" if header => 3,
                "numInGroup" if !header => 1,
                "numGroups" => 4,
                "numVarDataFields" => 5,
                _ => return Err(Error::Schema("unknown header/dimensions member")),
            };
            let Kind::Simple(mut encoding) = self.ty(m.ty)?.kind.clone() else {
                return Err(Error::Schema("header/dimensions scalar"));
            };
            if !encoding.primitive.unsigned()
                || encoding.length != 1
                || encoding.presence != Presence::Required
                || m.since != 0
            {
                return Err(Error::Schema("header/dimensions unsigned required scalar"));
            }
            // Section 3.4.10 permits the full unsigned range for numInGroup.
            if !header && role == 1 && !encoding.explicit_max {
                encoding.max = encoding.primitive.bounds().2;
            }
            roles.insert(role);
            fields.push(LayoutField {
                role,
                offset: m.offset,
                encoding,
            });
        }
        if !(0..if header { 4 } else { 2 }).all(|r| roles.contains(&r)) {
            return Err(Error::Schema("missing header/dimensions member"));
        }
        Ok(Layout {
            length: t
                .length
                .ok_or(Error::Schema("variable header/dimensions"))?,
            fields,
        })
    }

    fn block(
        &mut self,
        node_id: usize,
        depth: usize,
        inherited_since: u64,
    ) -> Result<usize, Error> {
        nesting(depth)?;
        let n = self
            .xml
            .get(node_id)
            .ok_or(Error::Schema("XML reference"))?;
        if !n.text.trim().is_empty() {
            return Err(Error::Schema("message/group text"));
        }
        let mut members = Vec::new();
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut end = 0;
        let mut phase = 0;
        let mut tail = 0;
        let mut last_since = [0; 3];
        for child in &n.children {
            let c = self.xml.get(*child).ok_or(Error::Schema("XML reference"))?;
            let name = c.symbol()?;
            let id = c
                .required("id")?
                .parse::<u16>()
                .map_err(|_| Error::Schema("member id"))?;
            if !names.insert(name.clone()) || !ids.insert(id) {
                return Err(Error::Schema("duplicate block member"));
            }
            let mut since = c.since(self.version)?.max(inherited_since);
            let category = match c.tag.as_str() {
                "field" => 0,
                "group" => 1,
                "data" => 2,
                _ => return Err(Error::Schema("unknown message member")),
            };
            if category < phase {
                return Err(Error::Schema("field/group/data order"));
            }
            phase = category;
            let kind = match c.tag.as_str() {
                "field" => {
                    if !c.children.is_empty() || !c.text.trim().is_empty() {
                        return Err(Error::Schema("field content"));
                    }
                    let ty = self.named(c.required("type")?, 1)?;
                    let t = self.ty(ty)?;
                    nesting(depth + t.depth)?;
                    since = since.max(t.since);
                    let base_presence = t.presence();
                    let presence = c.presence()?.unwrap_or(base_presence);
                    let explicit = match &t.kind {
                        Kind::Simple(s) | Kind::Enum(s, _) => s.explicit_presence,
                        _ => false,
                    };
                    if explicit && presence != base_presence {
                        return Err(Error::Schema("presence mismatch"));
                    }
                    if (matches!(t.kind, Kind::Set(..)) && presence != Presence::Required)
                        || (matches!(t.kind, Kind::Composite(_)) && presence == Presence::Constant)
                    {
                        return Err(Error::Schema("composite/set field presence"));
                    }
                    if presence == Presence::Optional {
                        self.optional(ty, 1)?;
                    }
                    let constant = if presence == Presence::Constant {
                        if let Some(reference) = c.attr("valueRef") {
                            // Section 4 only requires that valueRef name a
                            // valid value. On an enum field it must be that
                            // enum's; on a scalar field it must fit the type.
                            let (enum_id, choice) = self.value_ref(reference, 1)?;
                            since = since.max(choice.since);
                            match &self.ty(ty)?.kind {
                                Kind::Enum(..) => {
                                    if enum_id != ty {
                                        return Err(Error::Schema("valueRef type mismatch"));
                                    }
                                    Some(Value::Enum(choice.name))
                                }
                                Kind::Simple(s) if s.constant.is_none() && s.length == 1 => {
                                    if !s.valid(choice.value) || s.is_null(choice.value) {
                                        return Err(Error::Schema("constant outside range"));
                                    }
                                    Some(match choice.value {
                                        Scalar::Char(v) if s.array => Value::Bytes(vec![v]),
                                        v => Value::Scalar(v),
                                    })
                                }
                                _ => return Err(Error::Schema("valueRef field type")),
                            }
                        } else {
                            // Primitive constants stay in the type arena. A
                            // large string reused by many fields is stored once.
                            None
                        }
                    } else {
                        if c.attr("valueRef").is_some() {
                            return Err(Error::Schema("valueRef requires constant"));
                        }
                        None
                    };
                    let t = self.ty(ty)?;
                    if presence == Presence::Constant
                        && constant.is_none()
                        && !matches!(&t.kind, Kind::Simple(s) if s.constant.is_some())
                    {
                        return Err(Error::Schema("missing constant"));
                    }
                    let len = if presence == Presence::Constant {
                        0
                    } else {
                        t.length.ok_or(Error::Schema("variable fixed field"))?
                    };
                    let offset = size(c.number("offset", end as u64)?)?;
                    if offset < end {
                        return Err(Error::Schema("overlapping fields"));
                    }
                    end = add(offset, len)?;
                    tail += 1;
                    MemberKind::Field(Field {
                        ty,
                        offset,
                        presence,
                        constant,
                    })
                }
                "group" => {
                    if c.presence()?.is_some() || c.attr("offset").is_some() {
                        return Err(Error::Schema("group attributes"));
                    }
                    let dimensions = self.layout(
                        c.attr("dimensionType").unwrap_or("groupSizeEncoding"),
                        false,
                    )?;
                    let block = self.block(*child, depth + 1, since)?;
                    MemberKind::Group { block, dimensions }
                }
                "data" => {
                    if !c.children.is_empty()
                        || !c.text.trim().is_empty()
                        || c.attr("offset").is_some()
                        || c.presence()?.is_some_and(|p| p == Presence::Constant)
                    {
                        return Err(Error::Schema("data attributes/content"));
                    }
                    let ty = self.named(c.required("type")?, 1)?;
                    let t = self.ty(ty)?;
                    since = since.max(t.since);
                    let Kind::Composite(parts) = &t.kind else {
                        return Err(Error::Schema("data composite"));
                    };
                    let [length, data] = parts.as_slice() else {
                        return Err(Error::Schema("data length/varData members"));
                    };
                    let Kind::Simple(length_encoding) = &self.ty(length.ty)?.kind else {
                        return Err(Error::Schema("data length"));
                    };
                    let Kind::Simple(data_encoding) = &self.ty(data.ty)?.kind else {
                        return Err(Error::Schema("varData type"));
                    };
                    if length.name != "length"
                        || !matches!(data.name.as_str(), "varData" | "data")
                        || !length_encoding.primitive.unsigned()
                        || length_encoding.length != 1
                        || length_encoding.presence != Presence::Required
                        || length.offset != 0
                        || data.offset != length_encoding.primitive.size()
                        || data_encoding.length != 0
                        || !matches!(data_encoding.primitive, Primitive::Uint8 | Primitive::Char)
                        || data_encoding.presence == Presence::Constant
                    {
                        return Err(Error::Schema("data length/varData encoding"));
                    }
                    since = since.max(length.since).max(data.since);
                    MemberKind::Data {
                        length: length_encoding.clone(),
                        prefix: data.offset,
                    }
                }
                _ => return Err(Error::Schema("unknown member")),
            };
            if !matches!(&kind, MemberKind::Field(f) if f.presence == Presence::Constant) {
                let last = last_since
                    .get_mut(category)
                    .ok_or(Error::Schema("member category"))?;
                if since < *last {
                    return Err(Error::Schema("sinceVersion order"));
                }
                *last = since;
            }
            members.push(Member { name, since, kind });
        }
        let length = size(n.number("blockLength", end as u64)?)?;
        if length < end {
            return Err(Error::Schema("blockLength below fields"));
        }
        if self.types.len() + self.blocks.len() >= MAX_SCHEMA_NODES {
            return Err(Error::Limit("MAX_SCHEMA_NODES"));
        }
        let mut work = 1usize;
        for m in &members {
            let n = match &m.kind {
                MemberKind::Field(f) => self.ty(f.ty)?.work + 2,
                _ => 2,
            };
            work = work
                .checked_add(n)
                .filter(|n| *n <= MAX_VALUES)
                .ok_or(Error::Limit("MAX_VALUES"))?;
        }
        // Minimum lengths for every acting version, computed once here so
        // that readers never walk composite trees per group entry.
        let mut ends = Vec::new();
        for m in &members {
            if let MemberKind::Field(f) = &m.kind
                && f.presence != Presence::Constant
            {
                self.extend_ends(f.ty, f.offset, m.since, &mut ends)?;
            }
        }
        let minimums = minimums(ends);
        let id = self.blocks.len();
        self.blocks.push(Block {
            members,
            length,
            tail,
            work,
            minimums,
        });
        Ok(id)
    }

    fn optional(&self, id: usize, depth: usize) -> Result<(), Error> {
        nesting(depth)?;
        match &self.ty(id)?.kind {
            Kind::Simple(s) if s.valid(s.null) => Err(Error::Schema("null overlaps value range")),
            Kind::Enum(s, choices) if choices.iter().any(|c| s.is_null(c.value)) => {
                Err(Error::Schema("enum value equals null"))
            }
            Kind::Composite(members) => {
                for m in members {
                    if self.ty(m.ty)?.presence() != Presence::Constant {
                        return self.optional(m.ty, depth + 1);
                    }
                }
                Err(Error::Schema("composite has no null member"))
            }
            Kind::Set(..) => Err(Error::Schema("set has no null encoding")),
            _ => Ok(()),
        }
    }

    /// Appends the minimum-length table of type `id`, placed at `offset`
    /// and available from `since`. Charges every entry read.
    fn extend_ends(
        &mut self,
        id: usize,
        offset: usize,
        since: u64,
        out: &mut Vec<(u64, usize)>,
    ) -> Result<(), Error> {
        let n = self.ty(id)?.ends.len();
        self.layout_work = self
            .layout_work
            .checked_add(n)
            .filter(|n| *n <= MAX_LAYOUT_ENTRIES)
            .ok_or(Error::Limit("MAX_LAYOUT_ENTRIES"))?;
        for &(s, e) in &self.ty(id)?.ends {
            out.push((s.max(since), add(offset, e)?));
        }
        Ok(())
    }
}

/// Sorts `(since, end)` pairs into a table where the minimum length at
/// version `v` is the end of the last pair with `since <= v`, or 0.
fn minimums(mut ends: Vec<(u64, usize)>) -> Vec<(u64, usize)> {
    ends.sort_unstable();
    let mut table: Vec<(u64, usize)> = Vec::new();
    for (since, end) in ends {
        match table.last_mut() {
            Some(last) if end <= last.1 => {}
            Some(last) if last.0 == since => last.1 = end,
            None if end == 0 => {}
            _ => table.push((since, end)),
        }
    }
    table
}

impl Schema {
    /// Parses the public XML schema format from section 4.
    /// Refuses malformed XML, unresolved or cyclic refs, duplicate members,
    /// overlapping layouts, invalid scalar ranges, and all named limits.
    pub fn parse(xml: &str) -> Result<Self, Error> {
        let nodes = parse_xml(xml)?;
        let root = nodes.first().ok_or(Error::Schema("missing root"))?;
        if root.tag != "messageSchema" || !root.text.trim().is_empty() {
            return Err(Error::Schema("messageSchema root"));
        }
        let id = root
            .required("id")?
            .parse::<u32>()
            .map_err(|_| Error::Schema("schema id"))? as u64;
        let version = root.number("version", 0)?;
        let order = match root.attr("byteOrder").unwrap_or("littleEndian") {
            "littleEndian" => ByteOrder::LittleEndian,
            "bigEndian" => ByteOrder::BigEndian,
            _ => return Err(Error::Schema("byteOrder")),
        };
        let mut c = Compiler {
            xml: &nodes,
            names: BTreeMap::new(),
            resolved: BTreeMap::new(),
            primitives: BTreeMap::new(),
            active: BTreeSet::new(),
            types: Vec::new(),
            blocks: Vec::new(),
            version,
            layout_work: 0,
        };
        for child in &root.children {
            let n = nodes.get(*child).ok_or(Error::Schema("XML reference"))?;
            if n.tag == "types" {
                if !n.text.trim().is_empty() {
                    return Err(Error::Schema("types text"));
                }
                for child in &n.children {
                    let t = nodes.get(*child).ok_or(Error::Schema("XML reference"))?;
                    if !matches!(t.tag.as_str(), "type" | "composite" | "enum" | "set") {
                        return Err(Error::Schema("encoding element"));
                    }
                    if c.names.insert(t.symbol()?, *child).is_some() {
                        return Err(Error::Schema("duplicate type"));
                    }
                }
            } else if n.tag != "message" {
                return Err(Error::Schema("root child or external include"));
            }
        }
        // Validate unused definitions too, without expanding repeated references.
        let definitions: Vec<_> = c.names.values().copied().collect();
        for node in definitions {
            c.compile(node, 1)?;
        }
        let header = c.layout(root.attr("headerType").unwrap_or("messageHeader"), true)?;
        let mut messages = BTreeMap::new();
        let mut names = BTreeSet::new();
        for child in &root.children {
            let n = nodes.get(*child).ok_or(Error::Schema("XML reference"))?;
            if n.tag != "message" {
                continue;
            }
            let name = n.symbol()?;
            let since = n.since(version)?;
            let template_id = n
                .required("id")?
                .parse::<u32>()
                .map_err(|_| Error::Schema("template id"))? as u64;
            let block = c.block(*child, 1, since)?;
            if messages
                .insert(
                    template_id,
                    Template {
                        name: name.clone(),
                        block,
                        since,
                    },
                )
                .is_some()
                || !names.insert(name)
            {
                return Err(Error::Schema("duplicate message"));
            }
        }
        if messages.is_empty() {
            return Err(Error::Schema("no messages"));
        }
        let schema = Self {
            id,
            version,
            order,
            header,
            types: c.types,
            blocks: c.blocks,
            messages,
        };
        // Every declared message must have a representable header.
        for (id, template) in &schema.messages {
            let block = schema.block(template.block)?;
            let values = [
                block.length as u64,
                *id,
                schema.id,
                schema.version,
                block.counts(schema.version).0,
                block.counts(schema.version).1,
            ];
            schema
                .header
                .validate(values)
                .map_err(|_| Error::Schema("header range cannot represent schema"))?;
        }
        Ok(schema)
    }

    /// Schema identifier from section 4.3.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Current schema version from section 5.2.
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Schema-wide wire byte order.
    pub fn byte_order(&self) -> ByteOrder {
        self.order
    }
    /// Encoded header length, including explicit offsets.
    pub fn header_length(&self) -> usize {
        self.header.length
    }
    /// Returns a known template's symbolic name.
    pub fn template_name(&self, id: u64) -> Option<&str> {
        self.messages.get(&id).map(|t| t.name.as_str())
    }
    /// Recommended root block length for the acting version.
    /// Older versions use the end of their known fields; current and newer
    /// versions also include the schema's reserved trailing padding.
    pub fn block_length(&self, template_id: u64, version: u64) -> Result<usize, Error> {
        let t = self.template(template_id, version)?;
        let b = self.block(t.block)?;
        if version >= self.version {
            Ok(b.length)
        } else {
            Ok(b.minimum(version))
        }
    }
    fn ty(&self, id: usize) -> Result<&TypeDef, Error> {
        self.types.get(id).ok_or(Error::Schema("type reference"))
    }
    fn block(&self, id: usize) -> Result<&Block, Error> {
        self.blocks.get(id).ok_or(Error::Schema("block reference"))
    }
    fn template(&self, id: u64, version: u64) -> Result<&Template, Error> {
        self.messages
            .get(&id)
            .filter(|t| t.since <= version)
            .ok_or(Error::Header)
    }
}

impl Block {
    /// The shortest block that holds every field of the acting version,
    /// from the table built at schema compile time. O(log n).
    fn minimum(&self, version: u64) -> usize {
        let n = self
            .minimums
            .partition_point(|(since, _)| *since <= version);
        n.checked_sub(1)
            .and_then(|i| self.minimums.get(i))
            .map_or(0, |(_, end)| *end)
    }

    /// Adds the work of `count` entries to `work`, plus one visit of this
    /// definition, so an empty group still costs its member walk.
    fn charge(&self, work: &mut Work, count: usize) -> Result<(), Error> {
        work.charge_product(count, self.work, self.members.len() + 1)
            .map_err(|_| Error::Limit("MAX_VALUES"))
    }
    fn counts(&self, version: u64) -> (u64, u64) {
        let mut groups = 0;
        let mut data = 0;
        for m in self.members.iter().filter(|m| m.since <= version) {
            match m.kind {
                MemberKind::Group { .. } => groups += 1,
                MemberKind::Data { .. } => data += 1,
                _ => {}
            }
        }
        (groups, data)
    }
}

fn slice(bytes: &[u8], at: usize, length: usize) -> Result<&[u8], Error> {
    bytes.get(at..add(at, length)?).ok_or(Error::Truncated)
}
fn read_scalar(p: Primitive, order: ByteOrder, bytes: &[u8], at: usize) -> Result<Scalar, Error> {
    let b = slice(bytes, at, p.size())?;
    let mut n = 0u64;
    match order {
        ByteOrder::LittleEndian => {
            for byte in b.iter().rev() {
                n = (n << 8) | u64::from(*byte);
            }
        }
        ByteOrder::BigEndian => {
            for byte in b {
                n = (n << 8) | u64::from(*byte);
            }
        }
    }
    Ok(match p {
        Primitive::Char => Scalar::Char(n as u8),
        Primitive::Float => Scalar::Float(n as u32),
        Primitive::Double => Scalar::Double(n),
        p if p.unsigned() => Scalar::Uint(n),
        _ => {
            let shift = 64 - p.size() * 8;
            Scalar::Int(((n << shift) as i64) >> shift)
        }
    })
}
fn write_scalar(
    p: Primitive,
    order: ByteOrder,
    value: Scalar,
    out: &mut [u8],
    at: usize,
) -> Result<(), Error> {
    if !p.fits(value) {
        return Err(Error::Value);
    }
    let n = match value {
        Scalar::Char(n) => u64::from(n),
        Scalar::Int(n) => n as u64,
        Scalar::Uint(n) | Scalar::Double(n) => n,
        Scalar::Float(n) => u64::from(n),
    };
    let bytes = out
        .get_mut(at..add(at, p.size())?)
        .ok_or(Error::BlockLength)?;
    for (i, byte) in bytes.iter_mut().enumerate() {
        let shift = match order {
            ByteOrder::LittleEndian => i * 8,
            ByteOrder::BigEndian => (p.size() - 1 - i) * 8,
        };
        *byte = (n >> shift) as u8;
    }
    Ok(())
}

impl Layout {
    fn validate(&self, values: [u64; 6]) -> Result<(), Error> {
        for f in &self.fields {
            let n = *values.get(f.role).ok_or(Error::Layout)?;
            if !f.encoding.valid(Scalar::Uint(n)) {
                return Err(Error::Value);
            }
        }
        Ok(())
    }
    fn read(&self, bytes: &[u8], at: usize, order: ByteOrder) -> Result<[u64; 6], Error> {
        slice(bytes, at, self.length)?;
        let mut values = [0; 6];
        for f in &self.fields {
            let v = read_scalar(f.encoding.primitive, order, bytes, add(at, f.offset)?)?;
            let Scalar::Uint(n) = v else {
                return Err(Error::Value);
            };
            if !f.encoding.valid(v) {
                return Err(Error::Value);
            }
            *values.get_mut(f.role).ok_or(Error::Layout)? = n;
        }
        Ok(values)
    }
    fn counts(&self, values: [u64; 6], block: &Block, version: u64) -> Result<(), Error> {
        let (groups, data) = block.counts(version);
        for f in &self.fields {
            let expected = match f.role {
                4 => groups,
                5 => data,
                _ => continue,
            };
            if values.get(f.role) != Some(&expected) {
                return Err(Error::Layout);
            }
        }
        Ok(())
    }
    fn write(&self, values: [u64; 6], order: ByteOrder, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate(values)?;
        let at = extend_zero(out, self.length)?;
        for f in &self.fields {
            write_scalar(
                f.encoding.primitive,
                order,
                Scalar::Uint(*values.get(f.role).ok_or(Error::Layout)?),
                out,
                add(at, f.offset)?,
            )?;
        }
        Ok(())
    }
}

struct Budget {
    nodes: Work,
    bytes: usize,
    work: Work,
}
impl Default for Budget {
    fn default() -> Self {
        Self { nodes: Work::new("MAX_VALUES", MAX_VALUES), bytes: 0,
            work: Work::new("MAX_VALUES", MAX_VALUES) }
    }
}
impl Budget {
    fn nodes(&mut self, n: usize) -> Result<(), Error> {
        self.nodes.charge(n).map_err(|_| Error::Limit("MAX_VALUES"))
    }
    fn bytes(&mut self, n: usize) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(n)
            .filter(|v| *v <= MAX_VALUE_BYTES)
            .ok_or(Error::Limit("MAX_VALUE_BYTES"))?;
        Ok(())
    }
    fn name(&mut self, n: &str) -> Result<(), Error> {
        self.nodes(1)?;
        self.bytes(n.len())
    }
    fn constant(&mut self, v: &Value) -> Result<(), Error> {
        self.nodes(1)?;
        match v {
            Value::Bytes(b) => self.bytes(b.len()),
            Value::Enum(s) => self.bytes(s.len()),
            _ => Ok(()),
        }
    }
}

struct Reader<'s, 'b, 'w> {
    schema: &'s Schema,
    input: &'b [u8],
    version: u64,
    budget: &'w mut Budget,
}
impl Reader<'_, '_, '_> {
    fn value(
        &mut self,
        id: usize,
        at: usize,
        end: usize,
        presence: Presence,
        depth: usize,
    ) -> Result<Value, Error> {
        nesting(depth)?;
        self.budget.nodes(1)?;
        let t = self.schema.ty(id)?;
        if t.since > self.version {
            return Ok(Value::Absent);
        }
        match &t.kind {
            Kind::Simple(s) => {
                if let Some(v) = &s.constant {
                    self.budget.constant(v)?;
                    return Ok(v.clone());
                }
                let length = t.length.ok_or(Error::Tree)?;
                if add(at, length)? > end {
                    return Err(Error::BlockLength);
                }
                if s.array && matches!(s.primitive, Primitive::Char | Primitive::Uint8) {
                    self.budget.bytes(length)?;
                    return Ok(Value::Bytes(slice(self.input, at, length)?.to_vec()));
                }
                if !s.array {
                    return s.decode(
                        read_scalar(s.primitive, self.schema.order, self.input, at)?,
                        presence,
                    );
                }
                self.budget.nodes(s.length)?;
                let mut array = Vec::with_capacity(s.length);
                let mut pos = at;
                for _ in 0..s.length {
                    array.push(s.decode(
                        read_scalar(s.primitive, self.schema.order, self.input, pos)?,
                        presence,
                    )?);
                    pos = add(pos, s.primitive.size())?;
                }
                Ok(Value::Array(array))
            }
            Kind::Enum(s, choices) => {
                if add(at, s.primitive.size())? > end {
                    return Err(Error::BlockLength);
                }
                let v = read_scalar(s.primitive, self.schema.order, self.input, at)?;
                if presence == Presence::Optional && s.is_null(v) {
                    return Ok(Value::Null);
                }
                let c = choices
                    .iter()
                    .find(|c| c.value == v && c.since <= self.version)
                    .ok_or(Error::Value)?;
                self.budget.bytes(c.name.len())?;
                Ok(Value::Enum(c.name.clone()))
            }
            Kind::Set(p, choices) => {
                if add(at, p.size())? > end {
                    return Err(Error::BlockLength);
                }
                let Scalar::Uint(bits) = read_scalar(*p, self.schema.order, self.input, at)? else {
                    return Err(Error::Value);
                };
                if bits & !choice_mask(choices, self.version) != 0 {
                    return Err(Error::Value);
                }
                Ok(Value::Set(bits))
            }
            Kind::Composite(members) => {
                let mut values = Vec::new();
                let mut optional = presence == Presence::Optional;
                for m in members {
                    self.budget.name(&m.name)?;
                    let presence = self.schema.ty(m.ty)?.member_presence(&mut optional);
                    let v = if m.since > self.version {
                        Value::Absent
                    } else {
                        self.value(m.ty, add(at, m.offset)?, end, presence, depth + 1)?
                    };
                    values.push(NamedValue {
                        name: m.name.clone(),
                        value: v,
                    });
                }
                Ok(Value::Composite(values))
            }
        }
    }

    fn block(
        &mut self,
        id: usize,
        pos: &mut usize,
        length: usize,
        depth: usize,
    ) -> Result<Vec<NamedValue>, Error> {
        nesting(depth)?;
        self.budget.nodes(1)?;
        let block = self.schema.block(id)?;
        if length < block.minimum(self.version) {
            return Err(Error::BlockLength);
        }
        let start = *pos;
        let end = add(start, length)?;
        slice(self.input, start, length)?;
        *pos = end;
        let mut fields = Vec::new();
        for m in &block.members {
            self.budget.name(&m.name)?;
            let value = if m.since > self.version {
                Value::Absent
            } else {
                match &m.kind {
                    MemberKind::Field(f) => {
                        if let Some(v) = &f.constant {
                            self.budget.constant(v)?;
                            v.clone()
                        } else {
                            self.value(f.ty, add(start, f.offset)?, end, f.presence, depth + 1)?
                        }
                    }
                    MemberKind::Data { length, prefix } => {
                        let n = read_length(length, self.schema.order, self.input, *pos)?;
                        *pos = add(*pos, *prefix)?;
                        self.budget.bytes(n)?;
                        let data = slice(self.input, *pos, n)?.to_vec();
                        *pos = add(*pos, n)?;
                        Value::Bytes(data)
                    }
                    MemberKind::Group {
                        block: id,
                        dimensions,
                    } => {
                        let values = dimensions.read(self.input, *pos, self.schema.order)?;
                        let [block_length, count, _, _, _, _] = values;
                        let count = group_count(count)?;
                        let definition = self.schema.block(*id)?;
                        definition.charge(&mut self.budget.work, count)?;
                        dimensions.counts(values, definition, self.version)?;
                        // Charge entries before allocating, including zero-byte entries.
                        self.budget.nodes(count)?;
                        *pos = add(*pos, dimensions.length)?;
                        let mut entries = Vec::with_capacity(count);
                        let length = size(block_length)?;
                        if length < definition.minimum(self.version) {
                            return Err(Error::BlockLength);
                        }
                        for _ in 0..count {
                            entries.push(self.block(*id, pos, length, depth + 1)?);
                        }
                        Value::Group(Group {
                            block_length,
                            entries,
                        })
                    }
                }
            };
            fields.push(NamedValue {
                name: m.name.clone(),
                value,
            });
        }
        Ok(fields)
    }
}

fn choice_mask(choices: &[Choice], version: u64) -> u64 {
    choices
        .iter()
        .filter(|c| c.since <= version)
        .fold(0, |mask, c| match c.value {
            Scalar::Uint(n) => mask | n,
            _ => mask,
        })
}
fn group_count(n: u64) -> Result<usize, Error> {
    usize::try_from(n)
        .ok()
        .filter(|n| *n <= MAX_ARRAY_LENGTH)
        .ok_or(Error::Limit("MAX_ARRAY_LENGTH"))
}
fn read_length(s: &Simple, order: ByteOrder, input: &[u8], at: usize) -> Result<usize, Error> {
    let v = read_scalar(s.primitive, order, input, at)?;
    if !s.valid(v) || s.is_null(v) {
        return Err(Error::Value);
    }
    let Scalar::Uint(n) = v else {
        return Err(Error::Value);
    };
    size(n)
}
fn extend_zero(out: &mut Vec<u8>, n: usize) -> Result<usize, Error> {
    let start = out.len();
    out.resize(add(start, n)?, 0);
    Ok(start)
}
fn scalar_value(s: &Simple, value: &Value, presence: Presence) -> Result<Scalar, Error> {
    match value {
        Value::Null if presence == Presence::Optional => Ok(s.null),
        Value::Scalar(v) if s.valid(*v) && !s.is_null(*v) => Ok(*v),
        _ => Err(Error::Value),
    }
}

struct Writer<'s> {
    schema: &'s Schema,
    version: u64,
    out: Vec<u8>,
    budget: Budget,
}
impl Writer<'_> {
    fn value(
        &mut self,
        id: usize,
        value: &Value,
        at: usize,
        end: usize,
        presence: Presence,
        depth: usize,
    ) -> Result<(), Error> {
        nesting(depth)?;
        self.budget.nodes(1)?;
        let t = self.schema.ty(id)?;
        if t.since > self.version {
            return if *value == Value::Absent {
                Ok(())
            } else {
                Err(Error::Tree)
            };
        }
        match &t.kind {
            Kind::Simple(s) => {
                if let Some(v) = &s.constant {
                    self.budget.constant(v)?;
                    return if v == value {
                        Ok(())
                    } else {
                        Err(Error::Value)
                    };
                }
                if add(at, t.length.ok_or(Error::Tree)?)? > end {
                    return Err(Error::BlockLength);
                }
                if s.array && matches!(s.primitive, Primitive::Char | Primitive::Uint8) {
                    let Value::Bytes(bytes) = value else {
                        return Err(Error::Tree);
                    };
                    if bytes.len() != s.length {
                        return Err(Error::Tree);
                    }
                    self.budget.bytes(bytes.len())?;
                    self.out
                        .get_mut(at..add(at, bytes.len())?)
                        .ok_or(Error::BlockLength)?
                        .copy_from_slice(bytes);
                } else if !s.array {
                    write_scalar(
                        s.primitive,
                        self.schema.order,
                        scalar_value(s, value, presence)?,
                        &mut self.out,
                        at,
                    )?;
                } else {
                    let Value::Array(array) = value else {
                        return Err(Error::Tree);
                    };
                    if array.len() != s.length {
                        return Err(Error::Tree);
                    }
                    self.budget.nodes(array.len())?;
                    let mut pos = at;
                    for v in array {
                        write_scalar(
                            s.primitive,
                            self.schema.order,
                            scalar_value(s, v, presence)?,
                            &mut self.out,
                            pos,
                        )?;
                        pos = add(pos, s.primitive.size())?;
                    }
                }
            }
            Kind::Enum(s, choices) => {
                let v = match value {
                    Value::Null if presence == Presence::Optional => s.null,
                    Value::Enum(name) => {
                        self.budget.bytes(name.len())?;
                        choices
                            .iter()
                            .find(|c| &c.name == name && c.since <= self.version)
                            .ok_or(Error::Value)?
                            .value
                    }
                    _ => return Err(Error::Tree),
                };
                if add(at, s.primitive.size())? > end {
                    return Err(Error::BlockLength);
                }
                write_scalar(s.primitive, self.schema.order, v, &mut self.out, at)?;
            }
            Kind::Set(p, choices) => {
                let Value::Set(bits) = value else {
                    return Err(Error::Tree);
                };
                if bits & !choice_mask(choices, self.version) != 0 {
                    return Err(Error::Value);
                }
                if add(at, p.size())? > end {
                    return Err(Error::BlockLength);
                }
                write_scalar(
                    *p,
                    self.schema.order,
                    Scalar::Uint(*bits),
                    &mut self.out,
                    at,
                )?;
            }
            Kind::Composite(members) => {
                let Value::Composite(values) = value else {
                    return Err(Error::Tree);
                };
                if values.len() != members.len() {
                    return Err(Error::Tree);
                }
                let mut optional = presence == Presence::Optional;
                for (m, v) in members.iter().zip(values) {
                    self.budget.name(&v.name)?;
                    if m.name != v.name {
                        return Err(Error::Tree);
                    }
                    let presence = self.schema.ty(m.ty)?.member_presence(&mut optional);
                    if m.since > self.version {
                        if v.value != Value::Absent {
                            return Err(Error::Tree);
                        }
                    } else {
                        self.value(m.ty, &v.value, add(at, m.offset)?, end, presence, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn block(
        &mut self,
        id: usize,
        fields: &[NamedValue],
        length: usize,
        depth: usize,
    ) -> Result<(), Error> {
        nesting(depth)?;
        self.budget.nodes(1)?;
        let block = self.schema.block(id)?;
        if fields.len() != block.members.len() {
            return Err(Error::Tree);
        }
        if length < block.minimum(self.version) {
            return Err(Error::BlockLength);
        }
        let start = extend_zero(&mut self.out, length)?;
        let end = self.out.len();
        for (m, v) in block.members.iter().zip(fields) {
            self.budget.name(&v.name)?;
            if m.name != v.name {
                return Err(Error::Tree);
            }
            if m.since > self.version {
                if v.value != Value::Absent {
                    return Err(Error::Tree);
                }
                continue;
            }
            match &m.kind {
                MemberKind::Field(f) => {
                    if let Some(constant) = &f.constant {
                        self.budget.constant(constant)?;
                        if &v.value != constant {
                            return Err(Error::Value);
                        }
                    } else {
                        self.value(
                            f.ty,
                            &v.value,
                            add(start, f.offset)?,
                            end,
                            f.presence,
                            depth + 1,
                        )?;
                    }
                }
                MemberKind::Data { length, prefix } => {
                    let Value::Bytes(bytes) = &v.value else {
                        return Err(Error::Tree);
                    };
                    self.budget.bytes(bytes.len())?;
                    let n = Scalar::Uint(
                        u64::try_from(bytes.len())
                            .map_err(|_| Error::Limit("MAX_MESSAGE_BYTES"))?,
                    );
                    if !length.valid(n) || length.is_null(n) {
                        return Err(Error::Value);
                    }
                    let at = extend_zero(&mut self.out, *prefix)?;
                    write_scalar(length.primitive, self.schema.order, n, &mut self.out, at)?;
                    add(self.out.len(), bytes.len())?;
                    self.out.extend_from_slice(bytes);
                }
                MemberKind::Group { block, dimensions } => {
                    let Value::Group(group) = &v.value else {
                        return Err(Error::Tree);
                    };
                    let count = group_count(group.entries.len() as u64)?;
                    let definition = self.schema.block(*block)?;
                    definition.charge(&mut self.budget.work, count)?;
                    self.budget.nodes(count)?;
                    let (groups, data) = definition.counts(self.version);
                    dimensions.write(
                        [group.block_length, count as u64, 0, 0, groups, data],
                        self.schema.order,
                        &mut self.out,
                    )?;
                    let length = size(group.block_length)?;
                    if length < definition.minimum(self.version) {
                        return Err(Error::BlockLength);
                    }
                    for entry in &group.entries {
                        self.block(*block, entry, length, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl Schema {
    /// Reads exactly one message, using this schema's header composite.
    /// Refuses truncation, trailing bytes, unknown templates, invalid values,
    /// short blocks, unknown variable layouts, and all message/tree limits.
    pub fn decode(&self, input: &[u8]) -> Result<Message, Error> {
        if input.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit("MAX_MESSAGE_BYTES"));
        }
        match Messages::new(self).decode(input, true)? {
            Step::Item(message, used) if used == input.len() => Ok(message),
            Step::Item(_, _) => Err(Error::Trailing),
            _ => Err(Error::Truncated),
        }
    }

    /// Appends a header and body after validating the entire tree.
    /// Refuses wrong names, order, types, lengths, constants, versions,
    /// ranges, and limits. On error, `out` is unchanged. Reserved bytes are
    /// zero-filled; null NaNs use the encoding's null bit pattern.
    pub fn write(&self, message: &Message, out: &mut Vec<u8>) -> Result<(), Error> {
        let h = message.header;
        if h.schema_id != self.id {
            return Err(Error::Header);
        }
        let template = self.template(h.template_id, h.version)?;
        let (groups, data) = self.block(template.block)?.counts(h.version);
        let mut w = Writer {
            schema: self,
            version: h.version,
            out: Vec::new(),
            budget: Budget::default(),
        };
        self.block(template.block)?.charge(&mut w.budget.work, 1)?;
        self.header.write(
            [
                h.block_length,
                h.template_id,
                h.schema_id,
                h.version,
                groups,
                data,
            ],
            self.order,
            &mut w.out,
        )?;
        w.block(template.block, &message.fields, size(h.block_length)?, 1)?;
        // This also checks framing work limits before publishing any bytes.
        if self.decode(&w.out)? != *message {
            return Err(Error::Tree);
        }
        out.len()
            .checked_add(w.out.len())
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(Error::Limit("destination length"))?;
        out.extend_from_slice(&w.out);
        Ok(())
    }

    fn read_message(&self, input: &[u8], header: Header, block: usize, budget: &mut Budget) -> Result<Message, Error> {
        let mut reader = Reader {
            schema: self,
            input,
            version: header.version,
            budget,
        };
        self.block(block)?.charge(&mut reader.budget.work, 1)?;
        let mut pos = self.header.length;
        let fields = reader.block(block, &mut pos, size(header.block_length)?, 1)?;
        if pos != input.len() {
            return Err(Error::Trailing);
        }
        Ok(Message { header, fields })
    }
}

/// Supplies a stable schema for a [`MessageWire`] type.
///
/// The schema may be loaded from XML into a `OnceLock` at runtime. It must
/// remain the same for every call. The fallible return lets a source report
/// a bad configuration without panicking. No schema is compiled into this module.
pub trait SchemaSource {
    /// Returns this type's immutable schema, or a schema loading error.
    fn schema() -> Result<&'static Schema, Error>;
}

/// A schema-bound message implementing [`Wire`].
///
/// `S` supplies schema context because `Wire::parse` is an associated
/// function. Use [`Schema::decode`] and [`Schema::write`] when a borrowed
/// runtime schema is more convenient.
pub struct MessageWire<S: SchemaSource> {
    /// The dynamic message. Writing validates it against `S`.
    pub message: Message,
    source: PhantomData<fn() -> S>,
}
impl<S: SchemaSource> MessageWire<S> {
    /// Wraps a message. Validation occurs on write.
    pub fn new(message: Message) -> Self {
        Self {
            message,
            source: PhantomData,
        }
    }
}
impl<S: SchemaSource> Clone for MessageWire<S> {
    fn clone(&self) -> Self {
        Self::new(self.message.clone())
    }
}
impl<S: SchemaSource> core::fmt::Debug for MessageWire<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.message.fmt(f)
    }
}
impl<S: SchemaSource> PartialEq for MessageWire<S> {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
    }
}
impl<S: SchemaSource> Eq for MessageWire<S> {}
impl<S: SchemaSource> Wire for MessageWire<S> {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads exactly one message using `S`. Refuses an unavailable schema,
    /// malformed or truncated messages, trailing bytes, invalid field values,
    /// unknown templates/layouts, and all named limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::new(S::schema()?.decode(bytes)?))
    }
    /// Appends this message using `S`. Refuses an unavailable schema or any
    /// tree that does not match it, including wrong types, order, constants,
    /// ranges, lengths, or presence. All errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        S::schema()?.write(&self.message, out)
    }
}

#[derive(Clone, Copy, Debug)]
struct ScanFrame {
    block: usize,
    left: usize,
    length: usize,
    member: usize,
    fixed: bool,
}

/// Incremental framing of header-prefixed SBE messages (section 3.1).
///
/// The borrowed schema supplies all group and data encodings. A fixed stack
/// stores only positions and counters. No input or partial value tree is
/// retained. Each group dimension is visited once; incomplete data bodies
/// only recheck their fixed-size length prefix. One-byte feeds take linear
/// time under the schema and message work limits.
///
/// Unknown templates and malformed messages end the stream. Partial input
/// returns [`Step::Need`], including at EOF. [`codec::Stream`](fictionet::stdlib::codec::Stream)
/// reports truncation. Use [`Decode::map`] to interpret complete messages.
/// A combinator that makes decoders on demand, such as
/// [`codec::Demux`](fictionet::stdlib::codec::Demux), needs a
/// `&'static Schema`, for example one kept in a `OnceLock`.
#[derive(Clone, Debug)]
pub struct Messages<'s> {
    schema: &'s Schema,
    limit: usize,
    header: Option<Header>,
    root: usize,
    stack: [Option<ScanFrame>; MAX_NESTING],
    level: usize,
    pos: usize,
    work: Work,
    examined: u64,
}
impl<'s> Messages<'s> {
    /// Creates a decoder with a [`MAX_MESSAGE_BYTES`] input bound.
    pub fn new(schema: &'s Schema) -> Self {
        Self::with_limit(schema, MAX_MESSAGE_BYTES)
    }
    /// Creates a decoder that refuses any message longer than `limit`
    /// bytes, header included, from the first length that shows it. Limits
    /// above [`MAX_MESSAGE_BYTES`] are clamped; limits below the header
    /// length are raised to it.
    pub fn with_limit(schema: &'s Schema, limit: usize) -> Self {
        Self {
            schema,
            limit: limit.clamp(schema.header.length, MAX_MESSAGE_BYTES),
            header: None,
            root: 0,
            stack: [None; MAX_NESTING],
            level: 0,
            pos: 0,
            work: Work::new("MAX_VALUES", MAX_VALUES),
            examined: 0,
        }
    }
    /// Cumulative charged scanner and parser work, including failed calls.
    /// Saturates at `u64::MAX`.
    #[inline]
    pub fn examined(&self) -> u64 {
        self.examined
    }
    /// The largest message this decoder accepts, header included.
    pub fn limit(&self) -> usize {
        self.limit
    }
    /// `a + b`, refused when it passes this decoder's message limit.
    fn end(&self, a: usize, b: usize) -> Result<usize, Error> {
        let n = add(a, b)?;
        if n > self.limit {
            return Err(Error::Limit("Messages::limit"));
        }
        Ok(n)
    }
    fn push(&mut self, block: usize, left: usize, length: usize) -> Result<(), Error> {
        let definition = self.schema.block(block)?;
        definition.charge(&mut self.work, left)?;
        if left == 0 {
            return Ok(());
        }
        let slot = self
            .stack
            .get_mut(self.level)
            .ok_or(Error::Limit("MAX_NESTING"))?;
        *slot = Some(ScanFrame {
            block,
            left,
            length,
            member: definition.tail,
            fixed: false,
        });
        self.level += 1;
        Ok(())
    }
    fn update(&mut self, frame: ScanFrame) -> Result<(), Error> {
        let i = self.level.checked_sub(1).ok_or(Error::Layout)?;
        *self.stack.get_mut(i).ok_or(Error::Layout)? = Some(frame);
        Ok(())
    }
    fn scan(&mut self, input: &[u8]) -> Result<Option<usize>, Error> {
        if self.header.is_none() {
            if input.len() < self.schema.header.length {
                return Ok(None);
            }
            let values = self.schema.header.read(input, 0, self.schema.order)?;
            let [block_length, template_id, schema_id, version, _, _] = values;
            if schema_id != self.schema.id {
                return Err(Error::Header);
            }
            let t = self.schema.template(template_id, version)?;
            let b = self.schema.block(t.block)?;
            self.schema.header.counts(values, b, version)?;
            let length = size(block_length)?;
            if length < b.minimum(version) {
                return Err(Error::BlockLength);
            }
            self.root = t.block;
            self.pos = self.schema.header.length;
            self.end(self.pos, length)?;
            self.push(t.block, 1, length)?;
            self.header = Some(Header {
                block_length,
                template_id,
                schema_id,
                version,
            });
        }
        let header = self.header.ok_or(Error::Header)?;
        while self.level != 0 {
            let index = self.level.checked_sub(1).ok_or(Error::Layout)?;
            let mut frame = self
                .stack
                .get(index)
                .copied()
                .flatten()
                .ok_or(Error::Layout)?;
            let block = self.schema.block(frame.block)?;
            if !frame.fixed {
                let end = self.end(self.pos, frame.length)?;
                if end > input.len() {
                    return Ok(None);
                }
                self.pos = end;
                frame.fixed = true;
                self.update(frame)?;
            }
            let Some(m) = block.members.get(frame.member) else {
                frame.left = frame.left.checked_sub(1).ok_or(Error::Layout)?;
                if frame.left == 0 {
                    *self.stack.get_mut(index).ok_or(Error::Layout)? = None;
                    self.level -= 1;
                } else {
                    frame.fixed = false;
                    frame.member = block.tail;
                    self.update(frame)?;
                }
                continue;
            };
            if m.since > header.version {
                frame.member += 1;
                self.update(frame)?;
                continue;
            }
            match &m.kind {
                MemberKind::Field(_) => return Err(Error::Layout),
                MemberKind::Data { length, prefix } => {
                    if self.end(self.pos, *prefix)? > input.len() {
                        return Ok(None);
                    }
                    let n = read_length(length, self.schema.order, input, self.pos)?;
                    let end = self.end(add(self.pos, *prefix)?, n)?;
                    if end > input.len() {
                        return Ok(None);
                    }
                    self.pos = end;
                    frame.member += 1;
                    self.update(frame)?;
                }
                MemberKind::Group { block, dimensions } => {
                    if self.end(self.pos, dimensions.length)? > input.len() {
                        return Ok(None);
                    }
                    let values = dimensions.read(input, self.pos, self.schema.order)?;
                    let [length, count, _, _, _, _] = values;
                    let definition = self.schema.block(*block)?;
                    let length = size(length)?;
                    let count = group_count(count)?;
                    dimensions.counts(values, definition, header.version)?;
                    if length < definition.minimum(header.version) {
                        return Err(Error::BlockLength);
                    }
                    let fixed = length
                        .checked_mul(count)
                        .ok_or(Error::Limit("MAX_MESSAGE_BYTES"))?;
                    self.end(add(self.pos, dimensions.length)?, fixed)?;
                    self.pos = add(self.pos, dimensions.length)?;
                    frame.member += 1;
                    self.update(frame)?;
                    self.push(*block, count, length)?;
                }
            }
        }
        Ok(Some(self.pos))
    }
}
impl Decode for Messages<'_> {
    type Item = Message;
    type Error = Error;
    const NAME: &'static str = "SBE 1.0";
    /// The message limit. Oversized lengths fail as soon as they are read.
    fn capacity(&self) -> usize {
        self.limit
    }
    /// Reads one message. Refuses unknown headers/layouts, invalid values,
    /// short fixed blocks, and all named limits. Incomplete messages return
    /// `Need`, including at EOF. No input bytes are retained.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Message>, Error> {
        let before = self.work.used();
        let scanned = self.scan(input);
        self.examined = self.examined.saturating_add((self.work.used() - before) as u64);
        let Some(used) = scanned? else {
            // Every position the scan needs is checked against the limit,
            // so this is only a guard for rule 5 (progress at capacity).
            if !eof && input.len() >= self.limit {
                return Err(Error::Limit("Messages::limit"));
            }
            return Ok(Step::Need);
        };
        let bytes = input.get(..used).ok_or(Error::Truncated)?;
        let mut budget = Budget::default();
        let message = self.schema.read_message(
            bytes, self.header.ok_or(Error::Header)?, self.root, &mut budget);
        self.examined = self.examined.saturating_add(budget.work.used() as u64)
            .saturating_add(budget.nodes.used() as u64);
        let message = message?;
        let examined = self.examined;
        *self = Self::with_limit(self.schema, self.limit);
        self.examined = examined;
        Ok(Step::Item(message, used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream, contract, test_support};
    use std::sync::OnceLock;

    // A small rewrite of the public Real Logic car example, with nested refs,
    // explicit version additions, and a smaller set of fields. Test data only.
    // https://github.com/real-logic/simple-binary-encoding/blob/master/sbe-samples/src/main/resources/example-schema.xml
    const CAR: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
    <sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" id="7" version="2" byteOrder="littleEndian">
      <types>
        <composite name="messageHeader">
          <type name="blockLength" primitiveType="uint16"/>
          <type name="templateId" primitiveType="uint16"/>
          <type name="schemaId" primitiveType="uint16"/>
          <type name="version" primitiveType="uint16"/>
        </composite>
        <composite name="groupSizeEncoding">
          <type name="blockLength" primitiveType="uint16"/>
          <type name="numInGroup" primitiveType="uint16"/>
        </composite>
        <composite name="varDataEncoding">
          <type name="length" primitiveType="uint8"/>
          <type name="varData" primitiveType="uint8" length="0"/>
        </composite>
        <enum name="Model" encodingType="char"><validValue name="A">A</validValue><validValue name="B" sinceVersion="2">B</validValue></enum>
        <set name="Extras" encodingType="uint8"><choice name="Cruise">0</choice><choice name="Sports">3</choice><choice name="Roof">7</choice></set>
        <type name="Torque" primitiveType="int16"/>
        <composite name="Engine">
          <type name="capacity" primitiveType="uint16"/>
          <composite name="details"><type name="cylinders" primitiveType="uint8"/><ref name="torque" type="Torque"/></composite>
          <type name="fuel" primitiveType="char" presence="constant">Petrol</type>
        </composite>
        <type name="VehicleCode" primitiveType="char" length="4"/>
        <type name="Gears" primitiveType="uint16" length="2"/>
      </types>
      <sbe:message name="Car" id="1">
        <field name="serial" id="1" type="uint32"/>
        <field name="model" id="2" type="Model"/>
        <field name="extras" id="3" type="Extras"/>
        <field name="engine" id="4" type="Engine"/>
        <field name="code" id="5" type="VehicleCode"/>
        <field name="gears" id="6" type="Gears"/>
        <field name="discount" id="7" type="Model" presence="constant" valueRef="Model.A"/>
        <field name="rating" id="8" type="uint8" sinceVersion="2"/>
        <group name="performance" id="10">
          <field name="speed" id="11" type="uint16"/>
          <group name="acceleration" id="12"><field name="mph" id="13" type="uint8"/><field name="seconds" id="14" type="float"/></group>
          <data name="note" id="15" type="varDataEncoding"/>
        </group>
        <group name="service" id="16" sinceVersion="2"><field name="code" id="17" type="int8"/></group>
        <data name="maker" id="20" type="varDataEncoding"/>
        <data name="notes" id="21" type="varDataEncoding" sinceVersion="2"/>
      </sbe:message>
    </sbe:messageSchema>"#;

    const CAR_BYTES: &[u8] = &[
        20, 0, 1, 0, 7, 0, 2, 0, // header
        0xd2, 4, 0, 0, b'A', 0x89, 0xd0, 7, 4, 0xd4, 0xfe, b'S', b'B', b'E', 0, 3, 0, 5, 0, 9, 2,
        0, 1, 0, 100, 0, // one performance entry
        5, 0, 2, 0, 30, 0, 0, 0xc0, 0x3f, 60, 0, 0, 0x20, 0x40, 2, b'o',
        b'k', // entry's variable data
        1, 0, 0, 0, // empty service group
        3, b'A', b'B', b'C', 0,
    ];
    struct Car;
    impl SchemaSource for Car {
        fn schema() -> Result<&'static Schema, Error> {
            static S: OnceLock<Result<Schema, Error>> = OnceLock::new();
            S.get_or_init(|| Schema::parse(CAR))
                .as_ref()
                .map_err(|e| *e)
        }
    }
    fn named(name: &str, value: Value) -> NamedValue {
        NamedValue {
            name: name.into(),
            value,
        }
    }
    fn uint(n: u64) -> Value {
        Value::Scalar(Scalar::Uint(n))
    }
    fn int(n: i64) -> Value {
        Value::Scalar(Scalar::Int(n))
    }
    fn field<'a>(fields: &'a [NamedValue], name: &str) -> &'a Value {
        &fields.iter().find(|v| v.name == name).unwrap().value
    }
    fn field_mut<'a>(fields: &'a mut [NamedValue], name: &str) -> &'a mut Value {
        &mut fields.iter_mut().find(|v| v.name == name).unwrap().value
    }

    fn header_types() -> &'static str {
        r#"<composite name="messageHeader"><type name="blockLength" primitiveType="uint16"/><type name="templateId" primitiveType="uint16"/><type name="schemaId" primitiveType="uint16"/><type name="version" primitiveType="uint16"/></composite>"#
    }
    fn schema_xml(types: &str, fields: &str) -> String {
        format!(
            r#"<messageSchema id="7" version="2"><types>{}{types}</types><message name="Test" id="1">{fields}</message></messageSchema>"#,
            header_types()
        )
    }
    fn packet(block: usize, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![block as u8, (block >> 8) as u8, 1, 0, 7, 0, 2, 0];
        bytes.extend_from_slice(body);
        bytes
    }

    // Authored from SBE 1.0 sections 2.3, 2.5, and 4. These are small
    // market-data-style encodings, not an exchange's production schema.
    const NULL_TYPES: &str = r#"
        <type name="Int32NULL" primitiveType="int32" presence="optional" nullValue="2147483647"/>
        <type name="Int8NULL" primitiveType="int8" presence="optional" nullValue="127"/>
        <composite name="PRICENULL9">
          <type name="mantissa" primitiveType="int64" presence="optional" nullValue="9223372036854775807"/>
          <type name="exponent" primitiveType="int8" presence="constant">-9</type>
        </composite>"#;
    struct MarketNulls;
    impl SchemaSource for MarketNulls {
        fn schema() -> Result<&'static Schema, Error> {
            static S: OnceLock<Result<Schema, Error>> = OnceLock::new();
            S.get_or_init(|| {
                Schema::parse(&schema_xml(
                    NULL_TYPES,
                    r#"
                <field name="quantity" id="1" type="Int32NULL"/>
                <field name="flag" id="2" type="Int8NULL"/>
                <field name="price" id="3" type="PRICENULL9"/>"#,
                ))
            })
            .as_ref()
            .map_err(|e| *e)
        }
    }

    #[test]
    fn explicit_null_at_default_boundary() {
        let s = MarketNulls::schema().unwrap();
        let bytes = packet(
            13,
            &[
                0xff, 0xff, 0xff, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
        );
        let mut wire = MessageWire::<MarketNulls>::parse(&bytes).unwrap();
        assert_eq!(
            wire.message.fields,
            vec![
                named("quantity", Value::Null),
                named("flag", Value::Null),
                named(
                    "price",
                    Value::Composite(vec![
                        named("mantissa", Value::Null),
                        named("exponent", int(-9)),
                    ])
                ),
            ]
        );
        assert_eq!(wire.to_bytes().unwrap(), bytes);
        contract::check_wire::<MessageWire<MarketNulls>>(&bytes);
        contract::check_decode_with_alloc_limit(|| Messages::new(s), &bytes, 2 * MAX_MESSAGE_BYTES);
        wire.message.fields[0].value = int(i64::from(i32::MAX));
        let mut out = vec![1, 2, 3];
        assert_eq!(wire.write(&mut out), Err(Error::Value));
        assert_eq!(out, [1, 2, 3]);
        contract::check_wire_value(&wire);
    }

    #[test]
    fn constant_fields_do_not_order_versions() {
        let types =
            r#"<enum name="E" encodingType="uint8"><validValue name="A">1</validValue></enum>"#;
        let s = Schema::parse(&schema_xml(
            types,
            r#"
            <field name="new" id="1" type="E" presence="constant" valueRef="E.A" sinceVersion="2"/>
            <field name="old" id="2" type="E" presence="constant" valueRef="E.A"/>
            <field name="value" id="3" type="uint8"/>"#,
        ))
        .unwrap();
        for version in [0, 2, 3] {
            let mut bytes = packet(1, &[42]);
            bytes[6] = version;
            let m = s.decode(&bytes).unwrap();
            assert_eq!(
                m.fields[0].value,
                if version < 2 {
                    Value::Absent
                } else {
                    Value::Enum("A".into())
                }
            );
            let mut out = Vec::new();
            s.write(&m, &mut out).unwrap();
            assert_eq!(out, bytes);
            contract::check_decode_with_alloc_limit(
                || Messages::new(&s),
                &bytes,
                2 * MAX_MESSAGE_BYTES,
            );
        }
    }

    #[test]
    fn constant_composite_members_do_not_order_versions() {
        let types = r#"<composite name="C">
            <type name="new" primitiveType="int8" presence="constant" sinceVersion="2">2</type>
            <type name="old" primitiveType="int8" presence="constant">1</type>
            <type name="value" primitiveType="uint8"/>
        </composite>"#;
        let s = Schema::parse(&schema_xml(types, r#"<field name="c" id="1" type="C"/>"#)).unwrap();
        for version in [0, 2, 3] {
            let mut bytes = packet(1, &[42]);
            bytes[6] = version;
            let m = s.decode(&bytes).unwrap();
            assert_eq!(
                m.fields[0].value,
                Value::Composite(vec![
                    named("new", if version < 2 { Value::Absent } else { int(2) }),
                    named("old", int(1)),
                    named("value", uint(42)),
                ])
            );
            let mut out = Vec::new();
            s.write(&m, &mut out).unwrap();
            assert_eq!(out, bytes);
            contract::check_decode_with_alloc_limit(
                || Messages::new(&s),
                &bytes,
                2 * MAX_MESSAGE_BYTES,
            );
        }
    }

    /// Both composite shapes from the work-amplification reports: a 31-way
    /// tree three levels deep, and a binary tree thirteen levels deep.
    fn deep_composites() -> [(String, u16); 2] {
        let mut wide = String::new();
        for (name, child) in [("C2", "uint8"), ("C1", "C2"), ("C0", "C1")] {
            wide.push_str(&format!(r#"<composite name="{name}">"#));
            for n in 0..31 {
                wide.push_str(&format!(r#"<ref name="v{n}" type="{child}"/>"#));
            }
            wide.push_str("</composite>");
        }
        let mut binary = String::from(
            r#"<composite name="B0"><type name="a" primitiveType="uint8"/></composite>"#,
        );
        for k in 1..=13 {
            binary.push_str(&format!(
                r#"<composite name="B{k}"><ref name="x" type="B{0}"/><ref name="y" type="B{0}"/></composite>"#,
                k - 1
            ));
        }
        binary = binary.replace(r#"name="B13""#, r#"name="C0""#);
        [(wide, 29791), (binary, 8192)]
    }

    /// An outer group of `count` entries, each holding one empty inner
    /// group whose entries would be `block_length` bytes long.
    fn empty_groups(count: u16, block_length: u16) -> Vec<u8> {
        let mut bytes = packet(0, &[0, 0]);
        bytes.extend_from_slice(&count.to_le_bytes());
        for _ in 0..count {
            bytes.extend_from_slice(&block_length.to_le_bytes());
            bytes.extend_from_slice(&[0, 0]);
        }
        bytes
    }

    #[test]
    fn empty_groups_cost_linear_work() {
        let group_size = r#"<composite name="groupSizeEncoding"><type name="blockLength" primitiveType="uint16"/><type name="numInGroup" primitiveType="uint16"/></composite>"#;
        for (types, block_length) in deep_composites() {
            let s = Schema::parse(&schema_xml(
                &format!("{group_size}{types}"),
                r#"<group name="outer" id="1">
                <group name="inner" id="2"><field name="value" id="3" type="C0"/></group>
                </group>"#,
            ))
            .unwrap();
            // Minimum lengths are a table lookup, so a group costs its member
            // walk whatever its composites hold, and work stays below two
            // units per input byte.
            let bytes = empty_groups(10_000, block_length);
            let mut frames = Messages::new(&s);
            assert_eq!(frames.scan(&bytes), Ok(Some(bytes.len())));
            assert!(frames.work.used() <= 2 * bytes.len(), "{}", frames.work.used());
            // Group counts reserve work before their entries arrive.
            for count in [0, 1, 100, 10_000, 20_000] {
                test_support::check_work(|| Messages::new(&s), &empty_groups(count, block_length),
                    Messages::examined, MAX_VALUES as u64, 8);
            }
            let m = s.decode(&bytes).unwrap();
            let mut out = vec![0xaa];
            s.write(&m, &mut out).unwrap();
            assert_eq!(out[1..], bytes);
            // The 80 KB message from the report is refused by the work
            // limit, not decoded in quadratic time.
            let bytes = empty_groups(20_000, block_length);
            assert_eq!(s.decode(&bytes), Err(Error::Limit("MAX_VALUES")));
            let mut stream = Stream::new(Messages::new(&s));
            for b in &bytes {
                assert_eq!(stream.push(core::slice::from_ref(b)), 1);
                if let Some(r) = stream.next() {
                    assert_eq!(r, Err(Fail::Protocol(Error::Limit("MAX_VALUES"))));
                    break;
                }
            }
            let short = empty_groups(1, block_length - 1);
            assert_eq!(s.decode(&short), Err(Error::BlockLength));
        }
    }

    #[test]
    fn optional_composite_uses_first_nonconstant_member() {
        let types = r#"<composite name="Price">
            <type name="exponent" primitiveType="int8" presence="constant">-9</type>
            <type name="mantissa" primitiveType="int64"/>
            <type name="flag" primitiveType="uint8"/>
        </composite><composite name="Quote"><ref name="price" type="Price"/></composite>"#;
        for ty in ["Price", "Quote"] {
            let s = Schema::parse(&schema_xml(
                types,
                &format!(
                    r#"
                <field name="optional" id="1" type="{ty}" presence="optional"/>
                <field name="required" id="2" type="{ty}"/>"#
                ),
            ))
            .unwrap();
            let bytes = packet(
                18,
                &[0, 0, 0, 0, 0, 0, 0, 0x80, 1, 42, 0, 0, 0, 0, 0, 0, 0, 2],
            );
            let m = s.decode(&bytes).unwrap();
            let mut price = Value::Composite(vec![
                named("exponent", int(-9)),
                named("mantissa", Value::Null),
                named("flag", uint(1)),
            ]);
            if ty == "Quote" {
                price = Value::Composite(vec![named("price", price)]);
            }
            assert_eq!(m.fields[0].value, price);
            let mut out = Vec::new();
            s.write(&m, &mut out).unwrap();
            assert_eq!(out, bytes);
            contract::check_decode_with_alloc_limit(
                || Messages::new(&s),
                &bytes,
                2 * MAX_MESSAGE_BYTES,
            );
            let mut bad = bytes.clone();
            bad[16] = 255; // A later member remains required.
            assert_eq!(s.decode(&bad), Err(Error::Value));
            bad = bytes;
            bad[17..25].copy_from_slice(&i64::MIN.to_le_bytes());
            assert_eq!(s.decode(&bad), Err(Error::Value));
        }
    }

    #[test]
    fn optional_field_overrides_refuse_null_overlap() {
        for (types, reason) in [
            (
                r#"<enum name="E" encodingType="uint8"><validValue name="a">1</validValue><validValue name="z">255</validValue></enum>"#,
                "enum value equals null",
            ),
            (
                r#"<type name="E" primitiveType="uint8" maxValue="255"/>"#,
                "null overlaps value range",
            ),
        ] {
            for (types, ty) in [
                (types.to_owned(), "E"),
                (
                    format!(
                        r#"{types}<composite name="C"><ref name="value" type="E"/></composite>"#
                    ),
                    "C",
                ),
            ] {
                let xml = schema_xml(
                    &types,
                    &format!(r#"<field name="value" id="1" type="{ty}" presence="optional"/>"#),
                );
                assert!(matches!(Schema::parse(&xml), Err(Error::Schema(r)) if r == reason));
            }
        }
    }

    #[test]
    fn constant_char_arrays_require_printable_ascii() {
        for (text, valid) in [
            (" ~", true),
            ("é", false),
            ("a&#x7f;", false),
            ("a&#9;", false),
        ] {
            let types = format!(
                r#"<type name="Text" primitiveType="char" presence="constant">{text}</type>"#
            );
            let result = Schema::parse(&schema_xml(
                &types,
                r#"<field name="text" id="1" type="Text"/>"#,
            ));
            assert_eq!(result.is_ok(), valid, "{text}");
        }
    }

    // Section 2, "Timestamp with constant time unit": the unit is a
    // constant taken from an enum by valueRef. The composite comes before
    // the enum to check forward references.
    const TIMESTAMP_TYPES: &str = r#"
        <composite name="UTCTimestampNanos">
          <type name="time" primitiveType="uint64"/>
          <type name="unit" primitiveType="uint8" presence="constant" valueRef="TimeUnit.nanosecond"/>
        </composite>
        <enum name="TimeUnit" encodingType="uint8">
          <validValue name="second">0</validValue>
          <validValue name="millisecond">3</validValue>
          <validValue name="microsecond">6</validValue>
          <validValue name="nanosecond">9</validValue>
        </enum>
        <enum name="EntryType" encodingType="char">
          <validValue name="bid">0</validValue>
          <validValue name="reset">J</validValue>
        </enum>
        <type name="ResetType" primitiveType="char" length="1" presence="constant" valueRef="EntryType.reset"/>"#;

    #[test]
    fn constant_types_take_value_ref() {
        let s = Schema::parse(&schema_xml(
            TIMESTAMP_TYPES,
            r#"<field name="sent" id="1" type="UTCTimestampNanos"/>
            <field name="unit" id="2" type="uint8" presence="constant" valueRef="TimeUnit.second"/>
            <field name="entry" id="3" type="ResetType"/>
            <field name="kind" id="4" type="EntryType" presence="constant" valueRef="EntryType.bid"/>"#,
        ))
        .unwrap();
        // 1_000_000_001 ns after the epoch, little-endian.
        let bytes = packet(8, &[0x01, 0xca, 0x9a, 0x3b, 0, 0, 0, 0]);
        let m = s.decode(&bytes).unwrap();
        assert_eq!(
            m.fields,
            vec![
                named(
                    "sent",
                    Value::Composite(vec![
                        named("time", uint(1_000_000_001)),
                        named("unit", uint(9))
                    ])
                ),
                named("unit", uint(0)),
                named("entry", Value::Bytes(b"J".to_vec())),
                named("kind", Value::Enum("bid".into())),
            ]
        );
        let mut out = Vec::new();
        s.write(&m, &mut out).unwrap();
        assert_eq!(out, bytes);
        contract::check_decode(|| Messages::new(&s), &bytes);
        let mut bad = m.clone();
        bad.fields[0].value =
            Value::Composite(vec![named("time", uint(1)), named("unit", uint(3))]);
        let mut out = vec![1];
        assert_eq!(s.write(&bad, &mut out), Err(Error::Value));
        assert_eq!(out, [1]);

        for (types, field, reason) in [
            (
                r#"<type name="T" primitiveType="uint8" presence="constant" valueRef="TimeUnit.second">0</type>"#,
                r#"<field name="t" id="1" type="T"/>"#,
                "valueRef with constant text",
            ),
            (
                r#"<type name="T" primitiveType="uint8" valueRef="TimeUnit.second"/>"#,
                r#"<field name="t" id="1" type="T"/>"#,
                "valueRef requires constant",
            ),
            (
                r#"<type name="T" primitiveType="uint8" presence="constant" valueRef="EntryType.reset"/>"#,
                r#"<field name="t" id="1" type="T"/>"#,
                "constant outside range",
            ),
            (
                r#"<type name="T" primitiveType="uint8" presence="constant" valueRef="TimeUnit.hour"/>"#,
                r#"<field name="t" id="1" type="T"/>"#,
                "unknown valueRef",
            ),
            (
                "",
                r#"<field name="t" id="1" type="EntryType" presence="constant" valueRef="TimeUnit.second"/>"#,
                "valueRef type mismatch",
            ),
            (
                "",
                r#"<field name="t" id="1" type="int8" presence="constant" valueRef="TimeUnit.second"/>"#,
                "constant outside range",
            ),
        ] {
            let xml = schema_xml(&format!("{TIMESTAMP_TYPES}{types}"), field);
            assert_eq!(
                Schema::parse(&xml).err(),
                Some(Error::Schema(reason)),
                "{types}{field}"
            );
        }
    }

    #[test]
    fn frames_with_limit() {
        let types = r#"<composite name="Var"><type name="length" primitiveType="uint32"/><type name="varData" primitiveType="uint8" length="0"/></composite>"#;
        let s = Schema::parse(&schema_xml(
            types,
            r#"<data name="first" id="1" type="Var"/><data name="second" id="2" type="Var"/>"#,
        ))
        .unwrap();
        assert_eq!(Messages::with_limit(&s, 0).limit(), s.header_length());
        assert_eq!(
            Messages::with_limit(&s, usize::MAX).limit(),
            MAX_MESSAGE_BYTES
        );
        let mut small = packet(0, &[3, 0, 0, 0]);
        small.extend_from_slice(b"abc");
        small.extend_from_slice(&[0; 4]);
        let frames = Messages::with_limit(&s, small.len());
        assert_eq!(frames.capacity(), small.len());
        contract::check_decode(|| Messages::with_limit(&s, small.len()), &small);
        // Truncated below the limit: Need at EOF, so the driver reports it.
        let cut = &small[..small.len() - 1];
        assert_eq!(Messages::with_limit(&s, 64).decode(cut, true), Ok(Step::Need));
        // A length past the limit is refused as soon as it is read.
        let long = packet(0, &[100, 0, 0, 0]);
        assert_eq!(
            Messages::with_limit(&s, 64).decode(&long, false),
            Err(Error::Limit("Messages::limit"))
        );
        // At the default limit, a length past it is refused the same way.
        let huge = packet(0, &((MAX_MESSAGE_BYTES - 11) as u32).to_le_bytes());
        assert_eq!(
            Messages::new(&s).decode(&huge, true),
            Err(Error::Limit("MAX_MESSAGE_BYTES"))
        );
    }

    #[test]
    fn scanner_holds_no_input() {
        let mut frames = Messages::new(Car::schema().unwrap());
        assert_eq!(frames.held(), 0);
        assert_eq!(frames.decode(&CAR_BYTES[..20], false), Ok(Step::Need));
        assert_eq!(frames.held(), 0);
    }

    #[test]
    fn null_boundaries_and_explicit_ranges() {
        for (primitive, null, adjacent) in [
            ("int8", "-127", int(-126)),
            ("uint8", "0", uint(1)),
            ("uint8", "254", uint(253)),
        ] {
            let types = format!(
                r#"<type name="T" primitiveType="{primitive}" presence="optional" nullValue="{null}"/>"#
            );
            let s = Schema::parse(&schema_xml(
                &types,
                r#"<field name="value" id="1" type="T"/>"#,
            ))
            .unwrap();
            let byte = null.parse::<i16>().unwrap() as u8;
            assert_eq!(
                s.decode(&packet(1, &[byte])).unwrap().fields[0].value,
                Value::Null
            );
            let mut m = s.decode(&packet(1, &[byte])).unwrap();
            m.fields[0].value = adjacent;
            let mut out = Vec::new();
            s.write(&m, &mut out).unwrap();
            assert_eq!(s.decode(&out), Ok(m));
        }
        for attrs in [
            r#"nullValue="1""#,
            r#"nullValue="127" maxValue="127""#,
            r#"nullValue="-127" minValue="-127""#,
            r#"nullValue="5" minValue="0" maxValue="10""#,
        ] {
            let types =
                format!(r#"<type name="T" primitiveType="int8" presence="optional" {attrs}/>"#);
            assert!(matches!(
                Schema::parse(&schema_xml(&types, "")),
                Err(Error::Schema("null overlaps value range"))
            ));
        }
        // An explicit bound on the other end keeps the null out of range.
        for attrs in [
            r#"nullValue="127" minValue="0" maxValue="126""#,
            r#"nullValue="127" minValue="0""#,
            r#"nullValue="-127" maxValue="5""#,
        ] {
            let types =
                format!(r#"<type name="T" primitiveType="int8" presence="optional" {attrs}/>"#);
            let s = Schema::parse(&schema_xml(
                &types,
                r#"<field name="value" id="1" type="T"/>"#,
            ))
            .unwrap();
            let null = if attrs.contains("-127") { 0x81 } else { 0x7f };
            assert_eq!(
                s.decode(&packet(1, &[null])).unwrap().fields[0].value,
                Value::Null
            );
        }
    }

    #[test]
    fn exact_car_nested_groups_refs_arrays_and_constants() {
        let s = Car::schema().unwrap();
        let wire = MessageWire::<Car>::parse(CAR_BYTES).unwrap();
        let m = &wire.message;
        assert_eq!(
            m.header,
            Header {
                block_length: 20,
                template_id: 1,
                schema_id: 7,
                version: 2
            }
        );
        assert_eq!(field(&m.fields, "serial"), &uint(1234));
        assert_eq!(field(&m.fields, "model"), &Value::Enum("A".into()));
        assert_eq!(field(&m.fields, "extras"), &Value::Set(0x89));
        assert_eq!(
            field(&m.fields, "engine"),
            &Value::Composite(vec![
                named("capacity", uint(2000)),
                named(
                    "details",
                    Value::Composite(vec![
                        named("cylinders", uint(4)),
                        named("torque", int(-300))
                    ])
                ),
                named("fuel", Value::Bytes(b"Petrol".to_vec())),
            ])
        );
        assert_eq!(field(&m.fields, "code"), &Value::Bytes(b"SBE\0".to_vec()));
        assert_eq!(
            field(&m.fields, "gears"),
            &Value::Array(vec![uint(3), uint(5)])
        );
        assert_eq!(field(&m.fields, "discount"), &Value::Enum("A".into()));
        assert_eq!(
            field(&m.fields, "performance"),
            &Value::Group(Group {
                block_length: 2,
                entries: vec![vec![
                    named("speed", uint(100)),
                    named(
                        "acceleration",
                        Value::Group(Group {
                            block_length: 5,
                            entries: vec![
                                vec![
                                    named("mph", uint(30)),
                                    named(
                                        "seconds",
                                        Value::Scalar(Scalar::Float(1.5f32.to_bits()))
                                    )
                                ],
                                vec![
                                    named("mph", uint(60)),
                                    named(
                                        "seconds",
                                        Value::Scalar(Scalar::Float(2.5f32.to_bits()))
                                    )
                                ],
                            ]
                        })
                    ),
                    named("note", Value::Bytes(b"ok".to_vec())),
                ]]
            })
        );
        assert_eq!(field(&m.fields, "maker"), &Value::Bytes(b"ABC".to_vec()));
        assert_eq!(s.header_length(), 8);
        assert_eq!(s.block_length(1, 2), Ok(20));
        assert_eq!(s.template_name(1), Some("Car"));
        assert_eq!(wire.to_bytes().unwrap(), CAR_BYTES);
        contract::check_wire::<MessageWire<Car>>(CAR_BYTES);
        contract::check_wire_value(&wire);
        contract::check_decode_with_alloc_limit(
            || Messages::new(s),
            CAR_BYTES,
            2 * MAX_MESSAGE_BYTES,
        );
        let mut twice = CAR_BYTES.to_vec();
        twice.extend_from_slice(CAR_BYTES);
        let (messages, failure) = test_support::decode_all(|| Messages::new(s), &twice);
        assert_eq!(messages, vec![m.clone(), m.clone()]);
        assert_eq!(failure, None);
        assert_eq!(s.decode(&twice), Err(Error::Trailing));
    }

    #[test]
    fn larger_blocks_are_skipped_and_padding_is_canonical() {
        let mut bytes = CAR_BYTES.to_vec();
        // Grow the performance entry before inserting root padding.
        bytes[28] = 4;
        bytes.splice(34..34, [0x11, 0x22]);
        bytes[0] = 22;
        bytes.splice(28..28, [0xaa, 0xbb]);
        let wire = MessageWire::<Car>::parse(&bytes).unwrap();
        assert_eq!(wire.message.header.block_length, 22);
        let Value::Group(group) = field(&wire.message.fields, "performance") else {
            panic!()
        };
        assert_eq!(group.block_length, 4);
        assert_eq!(
            field(&wire.message.fields, "maker"),
            &Value::Bytes(b"ABC".to_vec())
        );
        let encoded = wire.to_bytes().unwrap();
        assert_eq!(&encoded[28..30], &[0, 0]);
        assert_eq!(&encoded[36..38], &[0, 0]);
        contract::check_wire::<MessageWire<Car>>(&bytes);
        contract::check_decode_with_alloc_limit(
            || Messages::new(Car::schema().unwrap()),
            &bytes,
            2 * MAX_MESSAGE_BYTES,
        );
    }

    #[test]
    fn older_versions_absent_and_newer_fixed_extensions() {
        let s = Car::schema().unwrap();
        let mut old = CAR_BYTES.to_vec();
        old.pop(); // notes added in version 2
        old.drain(51..55); // service group added in version 2
        old.remove(27); // rating added in version 2
        old[0] = 19;
        old[6] = 0;
        let wire = MessageWire::<Car>::parse(&old).unwrap();
        for name in ["rating", "service", "notes"] {
            assert_eq!(field(&wire.message.fields, name), &Value::Absent);
        }
        assert_eq!(s.block_length(1, 0), Ok(19));
        assert_eq!(wire.to_bytes().unwrap(), old);
        contract::check_wire::<MessageWire<Car>>(&old);
        contract::check_decode_with_alloc_limit(|| Messages::new(s), &old, 2 * MAX_MESSAGE_BYTES);
        let mut future = CAR_BYTES.to_vec();
        future[6] = 3;
        future[0] = 21;
        future.insert(28, 99);
        let newer = MessageWire::<Car>::parse(&future).unwrap();
        assert_eq!(newer.message.header.version, 3);
        contract::check_wire::<MessageWire<Car>>(&future);
        let mut unavailable = wire.clone();
        *field_mut(&mut unavailable.message.fields, "rating") = uint(9);
        assert!(unavailable.to_bytes().is_err());
        contract::check_wire_value(&unavailable);
        let mut invalid_enum = old.clone();
        invalid_enum[12] = b'B';
        assert_eq!(s.decode(&invalid_enum), Err(Error::Value));
    }

    #[test]
    fn every_primitive_null_minimum_and_maximum() {
        let cases: &[(&str, Primitive, &[u8])] = &[
            ("char", Primitive::Char, &[0]),
            ("int8", Primitive::Int8, &[0x80]),
            ("int16", Primitive::Int16, &[0, 0x80]),
            ("int32", Primitive::Int32, &[0, 0, 0, 0x80]),
            ("int64", Primitive::Int64, &[0, 0, 0, 0, 0, 0, 0, 0x80]),
            ("uint8", Primitive::Uint8, &[0xff]),
            ("uint16", Primitive::Uint16, &[0xff, 0xff]),
            ("uint32", Primitive::Uint32, &[0xff; 4]),
            ("uint64", Primitive::Uint64, &[0xff; 8]),
            ("float", Primitive::Float, &[0, 0, 0xc0, 0x7f]),
            ("double", Primitive::Double, &[0, 0, 0, 0, 0, 0, 0xf8, 0x7f]),
        ];
        for (name, primitive, null_bytes) in cases {
            let xml = schema_xml(
                "",
                &format!(r#"<field name="value" id="1" type="{name}" presence="optional"/>"#),
            );
            for order in [ByteOrder::LittleEndian, ByteOrder::BigEndian] {
                let xml = if order == ByteOrder::BigEndian {
                    xml.replace("<messageSchema ", "<messageSchema byteOrder=\"bigEndian\" ")
                } else {
                    xml.clone()
                };
                let s = Schema::parse(&xml).unwrap();
                let mut bytes = packet(null_bytes.len(), null_bytes);
                if order == ByteOrder::BigEndian {
                    bytes = vec![0, null_bytes.len() as u8, 0, 1, 0, 7, 0, 2];
                    bytes.extend(null_bytes.iter().rev());
                }
                let mut m = s.decode(&bytes).unwrap();
                assert_eq!(field(&m.fields, "value"), &Value::Null, "{name}");
                let mut out = Vec::new();
                s.write(&m, &mut out).unwrap();
                assert_eq!(out, bytes);
                for v in [primitive.bounds().0, primitive.bounds().1] {
                    m.fields[0].value = Value::Scalar(v);
                    let mut out = Vec::new();
                    s.write(&m, &mut out).unwrap();
                    assert_eq!(s.decode(&out), Ok(m.clone()), "{name}");
                }
                let required =
                    Schema::parse(&xml.replace("presence=\"optional\"", "presence=\"required\""))
                        .unwrap();
                assert_eq!(required.decode(&bytes), Err(Error::Value), "{name}");
            }
        }
        // Public specification section 2.5 examples, independently stated bytes.
        for (name, bytes, scalar) in [
            (
                "float",
                vec![0x91, 0xad, 0x7f, 0x43],
                Scalar::Float(255.678f32.to_bits()),
            ),
            (
                "double",
                vec![0x04, 0x56, 0x0e, 0x2d, 0xb2, 0xf5, 0x6f, 0x40],
                Scalar::Double(255.678f64.to_bits()),
            ),
        ] {
            let s = Schema::parse(&schema_xml(
                "",
                &format!(r#"<field name="ratio" id="1" type="{name}"/>"#),
            ))
            .unwrap();
            assert_eq!(
                s.decode(&packet(bytes.len(), &bytes)).unwrap().fields[0].value,
                Value::Scalar(scalar)
            );
        }
    }

    #[test]
    fn ranges_optional_arrays_optional_enums_and_nan() {
        let xml = schema_xml(
            r#"
            <type name="Small" primitiveType="uint8" presence="optional" minValue="1" maxValue="10" nullValue="0"/>
            <type name="Samples" primitiveType="int16" presence="optional" length="2"/>
            <enum name="Flag" encodingType="uint8"><validValue name="Off">0</validValue><validValue name="On">1</validValue></enum>
            <type name="Octets" primitiveType="uint8" length="2"/>
            <type name="Exponent" primitiveType="int8" presence="constant">-2</type>"#,
            r#"<field name="small" id="1" type="Small"/><field name="samples" id="2" type="Samples"/>
            <field name="flag" id="3" type="Flag" presence="optional"/><field name="bytes" id="4" type="Octets"/>
            <field name="exponent" id="5" type="Exponent"/>"#,
        );
        let s = Schema::parse(&xml).unwrap();
        let bytes = packet(8, &[0, 2, 0, 0, 0x80, 255, 0, 255]);
        let m = s.decode(&bytes).unwrap();
        assert_eq!(field(&m.fields, "small"), &Value::Null);
        assert_eq!(
            field(&m.fields, "samples"),
            &Value::Array(vec![int(2), Value::Null])
        );
        assert_eq!(field(&m.fields, "flag"), &Value::Null);
        assert_eq!(field(&m.fields, "bytes"), &Value::Bytes(vec![0, 255]));
        assert_eq!(field(&m.fields, "exponent"), &int(-2));
        let mut out = Vec::new();
        s.write(&m, &mut out).unwrap();
        assert_eq!(out, bytes);
        for invalid in [11, 255] {
            let mut b = bytes.clone();
            b[8] = invalid;
            assert_eq!(s.decode(&b), Err(Error::Value));
        }
        let s = Schema::parse(&schema_xml(
            "",
            r#"<field name="f" id="1" type="float" presence="optional"/>"#,
        ))
        .unwrap();
        let m = s.decode(&packet(4, &[0x42, 0, 0xc0, 0x7f])).unwrap();
        assert_eq!(m.fields[0].value, Value::Null);
        let mut bad = m;
        bad.fields[0].value = Value::Scalar(Scalar::Float(f32::NAN.to_bits()));
        let mut out = vec![1, 2, 3];
        assert!(s.write(&bad, &mut out).is_err());
        assert_eq!(out, [1, 2, 3]);
    }

    #[test]
    fn big_endian_header_and_custom_header_composite() {
        let xml = schema_xml("", r#"<field name="sequence" id="1" type="uint32"/>"#)
            .replace("<messageSchema ", "<messageSchema byteOrder=\"bigEndian\" ");
        let s = Schema::parse(&xml).unwrap();
        let bytes = [0, 4, 0, 1, 0, 7, 0, 2, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(
            s.decode(&bytes).unwrap().fields,
            vec![named("sequence", uint(0x12345678))]
        );
        let custom = r#"<messageSchema id="7" version="2" headerType="Header"><types>
          <composite name="Header"><type name="blockLength" primitiveType="uint32"/>
          <type name="templateId" primitiveType="uint8" offset="5"/><type name="schemaId" primitiveType="uint8"/>
          <type name="version" primitiveType="uint8"/><type name="numGroups" primitiveType="uint8"/>
          <type name="numVarDataFields" primitiveType="uint8"/></composite></types>
          <message name="Empty" id="1"/></messageSchema>"#;
        let s = Schema::parse(custom).unwrap();
        let bytes = [0, 0, 0, 0, 99, 1, 7, 2, 0, 0];
        let m = s.decode(&bytes).unwrap();
        assert_eq!(s.header_length(), 10);
        assert!(m.fields.is_empty());
        let mut out = Vec::new();
        s.write(&m, &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 0, 0, 1, 7, 2, 0, 0]);
        let mut invalid = bytes;
        invalid[8] = 1;
        assert_eq!(s.decode(&invalid), Err(Error::Layout));
    }

    #[test]
    fn group_count_full_range_and_data_length_limits() {
        let types = r#"<composite name="groupSizeEncoding"><type name="blockLength" primitiveType="uint8"/><type name="numInGroup" primitiveType="uint8"/></composite>
            <composite name="Var"><type name="length" primitiveType="uint32"/><type name="varData" primitiveType="uint8" length="0"/></composite>"#;
        let s = Schema::parse(&schema_xml(types, r#"<group name="rows" id="1"><field name="v" id="2" type="uint8"/></group><data name="data" id="3" type="Var"/>"#)).unwrap();
        let mut body = vec![1, 255];
        body.extend([1; 255]);
        body.extend([0; 4]);
        let bytes = packet(0, &body);
        let m = s.decode(&bytes).unwrap();
        let Value::Group(g) = &m.fields[0].value else {
            panic!()
        };
        assert_eq!(g.entries.len(), 255);
        let mut out = Vec::new();
        s.write(&m, &mut out).unwrap();
        assert_eq!(out, bytes);
        let oversized = packet(0, &[1, 0, 1, 0, 0x10, 0]); // 1 MiB + 1 data bytes, declared only
        assert_eq!(s.decode(&oversized), Err(Error::Limit("MAX_MESSAGE_BYTES")));
        contract::check_decode_with_alloc_limit(
            || Messages::new(&s),
            &oversized,
            2 * MAX_MESSAGE_BYTES,
        );
        let null = packet(0, &[1, 0, 255, 255, 255, 255]);
        assert_eq!(s.decode(&null), Err(Error::Value));
        let small = packet(0, &[0, 0, 0, 0, 0, 0]);
        assert_eq!(s.decode(&small), Err(Error::BlockLength));
    }

    #[test]
    fn truncations_malformed_values_and_transactional_writes() {
        let s = Car::schema().unwrap();
        for cut in 0..CAR_BYTES.len() {
            assert_eq!(
                s.decode(&CAR_BYTES[..cut]),
                Err(Error::Truncated),
                "cut {cut}"
            );
            contract::check_wire::<MessageWire<Car>>(&CAR_BYTES[..cut]);
        }
        for (at, byte, error) in [
            (0, 19, Error::BlockLength),
            (2, 2, Error::Header),
            (4, 8, Error::Header),
            (12, b'Z', Error::Value),
            (13, 2, Error::Value),
        ] {
            let mut bytes = CAR_BYTES.to_vec();
            bytes[at] = byte;
            assert_eq!(s.decode(&bytes), Err(error));
            contract::check_decode_with_alloc_limit(
                || Messages::new(s),
                &bytes,
                2 * MAX_MESSAGE_BYTES,
            );
        }
        let good = MessageWire::<Car>::parse(CAR_BYTES).unwrap();
        for mode in 0..10 {
            let mut bad = good.clone();
            match mode {
                0 => {
                    bad.message.fields.pop();
                }
                1 => bad.message.fields.push(named("extra", uint(0))),
                2 => bad.message.fields.swap(0, 1),
                3 => bad.message.fields[0].name = "wrong".into(),
                4 => bad.message.fields[0].value = Value::Null,
                5 => bad.message.fields[0].value = int(1),
                6 => *field_mut(&mut bad.message.fields, "gears") = Value::Array(vec![uint(1)]),
                7 => *field_mut(&mut bad.message.fields, "discount") = Value::Enum("B".into()),
                8 => *field_mut(&mut bad.message.fields, "code") = Value::Bytes(vec![0; 5]),
                _ => bad.message.header.block_length = 19,
            }
            let mut out = vec![0x55, 0xaa];
            assert!(bad.write(&mut out).is_err());
            assert_eq!(out, [0x55, 0xaa]);
            contract::check_wire_value(&bad);
        }
    }

    #[test]
    fn xml_events_tree() {
        let input = "\u{feff}<?xml version='1.0' encoding='utf-8' standalone='yes'?>\n\
            <!--before--><s:x xmlns:s='urn:sbe' s:a='&amp;'> a&#32;\
            <y/>b<!--inside--> c</s:x><!--after-->\n";
        let nodes = parse_xml(input).expect("XML tree");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].tag, "x");
        assert_eq!(nodes[0].attr("s:a"), Some("&"));
        assert_eq!(nodes[0].attr("xmlns:s"), Some("urn:sbe"));
        assert_eq!(nodes[0].text, " a b c");
        assert_eq!(nodes[0].children, [1]);
        assert_eq!(nodes[1].tag, "y");
        for input in [
            "<x><![CDATA[test]]></x>",
            "<?xml version='1.1'?><x/>",
            "<?xml version='1.0' encoding='UTF-16'?><x/>",
            "<?xml version='1.0' standalone='maybe'?><x/>",
            "<!--before--><?xml version='1.0'?><x/>",
            "<!DOCTYPE x><x/>",
            "<?bad?><x/>",
            "<x><?bad?></x>",
            "<x/><?bad?>",
            "<x/><x/>",
            "<x/>trailing",
            "<x>",
        ] {
            assert!(matches!(parse_xml(input), Err(Error::Xml(_))), "{input}");
        }
        assert!(matches!(parse_xml("<x>&bad;</x>"), Err(Error::Xml(3))));
        let name = "a".repeat(MAX_NAME_BYTES + 1);
        assert!(matches!(
            parse_xml(&format!("<x {name}='0'/>")),
            Err(Error::Limit("MAX_NAME_BYTES"))
        ));
        let qualified = format!("s:{}", "a".repeat(MAX_NAME_BYTES - 1));
        assert!(matches!(
            parse_xml(&format!("<{qualified} xmlns:s='urn:sbe'/>")),
            Err(Error::Limit("MAX_NAME_BYTES"))
        ));
    }

    #[test]
    fn malformed_xml_and_schema_limits() {
        for input in [
            "",
            "<",
            "<!DOCTYPE x><messageSchema/>",
            "<x>&unknown;</x>",
            "<x>&#0;</x>",
            "<x>&#x110000;</x>",
            "<x a='1' a='2'/>",
            "<x><y></x>",
            "<x/ ><y/>",
            "<x/><x/>",
            "<x><![CDATA[test]]></x>",
            "<x><!--a--b--></x>",
            "<?bad?><x/>",
            "<x a='<'/>",
            "<x>]]></x>",
        ] {
            assert!(Schema::parse(input).is_err(), "{input}");
        }
        assert!(matches!(
            Schema::parse(&" ".repeat(MAX_XML_BYTES + 1)),
            Err(Error::Limit("MAX_XML_BYTES"))
        ));
        let deep = format!(
            "{}{}",
            "<x>".repeat(MAX_XML_DEPTH + 1),
            "</x>".repeat(MAX_XML_DEPTH + 1)
        );
        assert!(matches!(
            Schema::parse(&deep),
            Err(Error::Limit("MAX_XML_DEPTH"))
        ));
        let many = format!("<x>{}</x>", "<x/>".repeat(MAX_XML_ELEMENTS));
        assert!(matches!(
            Schema::parse(&many),
            Err(Error::Limit("MAX_XML_ELEMENTS"))
        ));
        let attrs = (0..=MAX_XML_ATTRIBUTES)
            .map(|n| format!(" a{n}='0'"))
            .collect::<String>();
        assert!(matches!(
            Schema::parse(&format!("<x{attrs}/>")),
            Err(Error::Limit("MAX_XML_ATTRIBUTES"))
        ));
        assert!(matches!(
            Schema::parse(&format!("<{} />", "x".repeat(MAX_NAME_BYTES + 1))),
            Err(Error::Limit("MAX_NAME_BYTES"))
        ));
        for types in [
            r#"<type name="X" primitiveType="uint8" minValue="10" maxValue="9"/>"#,
            r#"<type name="X" primitiveType="uint8" nullValue="255"/>"#,
            r#"<type name="X" primitiveType="uint8" maxValue="256"/>"#,
            r#"<type name="X" primitiveType="uint64" maxValue="18446744073709551616"/>"#,
            r#"<type name="X" primitiveType="uint8" presence="optional" nullValue="1"/>"#,
            r#"<type name="X" primitiveType="char" presence="constant" length="3">ab</type>"#,
            r#"<type name="X" primitiveType="uint8" length="65537"/>"#,
            r#"<composite name="X"><ref name="self" type="X"/></composite>"#,
            r#"<composite name="X"><ref name="unknown" type="Missing"/></composite>"#,
            r#"<composite name="X"><type name="a" primitiveType="uint32"/><type name="b" primitiveType="uint8" offset="1"/></composite>"#,
            r#"<set name="X" encodingType="uint8"><choice name="Bad">8</choice></set>"#,
            r#"<enum name="X" encodingType="uint8"><validValue name="A">1</validValue><validValue name="B">1</validValue></enum>"#,
            r#"<type name="X" primitiveType="uint8"/><type name="X" primitiveType="uint8"/>"#,
        ] {
            assert!(Schema::parse(&schema_xml(types, "")).is_err(), "{types}");
        }
        for fields in [
            r#"<field name="a" id="1" type="Missing"/>"#,
            r#"<field name="a" id="1" type="uint8" sinceVersion="3"/>"#,
            r#"<field name="a" id="1" type="uint8"/><field name="b" id="1" type="uint8"/>"#,
            r#"<field name="a" id="1" type="uint8" sinceVersion="2"/><field name="b" id="2" type="uint8"/>"#,
            r#"<field name="a" id="1" type="uint16"/><field name="b" id="2" type="uint8" offset="1"/>"#,
        ] {
            assert!(Schema::parse(&schema_xml("", fields)).is_err(), "{fields}");
        }
        let xml = schema_xml("", "").replace(
            "<message ",
            "<message description=\"A &amp; B &#x41; &#65;\" ",
        );
        assert!(Schema::parse(&xml).is_ok());
        let xml = schema_xml("", "").replace("<types>", "<xi:include href='elsewhere'/><types>");
        assert!(Schema::parse(&xml).is_err());
    }

    #[test]
    fn referenced_depth_expansion_and_zero_byte_entries_are_bounded() {
        let mut types =
            String::from(r#"<type name="T0" primitiveType="uint8" presence="constant">1</type>"#);
        for n in 1..=MAX_NESTING {
            types.push_str(&format!(r#"<composite name="T{n}"><ref name="a" type="T{}"/><ref name="b" type="T{}"/></composite>"#, n - 1, n - 1));
        }
        assert!(matches!(
            Schema::parse(&schema_xml(&types, "")),
            Err(Error::Limit(_))
        ));
        let types = r#"<composite name="groupSizeEncoding"><type name="blockLength" primitiveType="uint16"/><type name="numInGroup" primitiveType="uint32"/></composite>"#;
        let s = Schema::parse(&schema_xml(types, r#"<group name="empty" id="1"/>"#)).unwrap();
        let bytes = packet(0, &[0, 0, 0xff, 0xff, 0xff, 0x7f]);
        assert!(matches!(
            s.decode(&bytes),
            Err(Error::Limit("MAX_ARRAY_LENGTH"))
        ));
        contract::check_decode_with_alloc_limit(|| Messages::new(&s), &bytes, 2 * MAX_MESSAGE_BYTES);
        let bytes = packet(0, &[0, 0, 0, 0, 1, 0]);
        assert!(matches!(s.decode(&bytes), Err(Error::Limit("MAX_VALUES"))));
    }

    #[test]
    fn one_byte_stream_and_map() {
        let schema = Car::schema().unwrap();
        for count in [1, 2, 8] {
            test_support::check_work(|| Messages::new(schema), &CAR_BYTES.repeat(count),
                Messages::examined, MAX_VALUES as u64, 16);
        }
        let mut stream = Stream::new(Messages::new(schema).map(|m| m.header.template_id));
        for chunk in test_support::chunks(CAR_BYTES, &[1]) {
            assert_eq!(stream.push(chunk), chunk.len());
            if stream.buffered() < CAR_BYTES.len() {
                assert_eq!(stream.next(), None);
            }
        }
        assert_eq!(stream.next(), Some(Ok(1)));
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.failed().is_none());
    }

    #[test]
    fn full_car_in_big_endian() {
        let s = Schema::parse(&CAR.replace("littleEndian", "bigEndian")).unwrap();
        let bytes = [
            0, 20, 0, 1, 0, 7, 0, 2, 0, 0, 4, 0xd2, b'A', 0x89, 7, 0xd0, 4, 0xfe, 0xd4, b'S', b'B',
            b'E', 0, 0, 3, 0, 5, 9, 0, 2, 0, 1, 0, 100, 0, 5, 0, 2, 30, 0x3f, 0xc0, 0, 0, 60, 0x40,
            0x20, 0, 0, 2, b'o', b'k', 0, 1, 0, 0, 3, b'A', b'B', b'C', 0,
        ];
        let message = s.decode(&bytes).unwrap();
        assert_eq!(message, Car::schema().unwrap().decode(CAR_BYTES).unwrap());
        let mut out = Vec::new();
        s.write(&message, &mut out).unwrap();
        assert_eq!(out, bytes);
        contract::check_decode_with_alloc_limit(|| Messages::new(&s), &bytes, 2 * MAX_MESSAGE_BYTES);
    }

    #[test]
    fn composite_offsets_and_decimal_constant() {
        let types = r#"<composite name="Price"><type name="mantissa" primitiveType="int32"/>
            <type name="exponent" primitiveType="int8" presence="constant">-2</type></composite>
            <composite name="Quote"><ref name="price" type="Price" offset="1"/><type name="flag" primitiveType="char" offset="7"/></composite>"#;
        let s = Schema::parse(&schema_xml(
            types,
            r#"<field name="quote" id="1" type="Quote" offset="2"/>"#,
        ))
        .unwrap();
        let bytes = packet(10, &[0xaa, 0xbb, 0xcc, 0x39, 0x30, 0, 0, 0xdd, 0xee, b'Y']);
        let message = s.decode(&bytes).unwrap();
        assert_eq!(
            message.fields,
            vec![named(
                "quote",
                Value::Composite(vec![
                    named(
                        "price",
                        Value::Composite(vec![
                            named("mantissa", int(12345)),
                            named("exponent", int(-2))
                        ])
                    ),
                    named("flag", Value::Scalar(Scalar::Char(b'Y'))),
                ])
            )]
        );
        let mut out = Vec::new();
        s.write(&message, &mut out).unwrap();
        assert_eq!(out, packet(10, &[0, 0, 0, 0x39, 0x30, 0, 0, 0, 0, b'Y']));
        let s = Schema::parse(&schema_xml(
            r#"<type name="Space" primitiveType="char" presence="constant">&#32;</type>"#,
            r#"<field name="space" id="1" type="Space"/>"#,
        ))
        .unwrap();
        assert_eq!(
            s.decode(&packet(0, &[])).unwrap().fields[0].value,
            Value::Scalar(Scalar::Char(b' '))
        );
    }

    #[test]
    fn constant_storage_and_value_bytes_are_bounded() {
        let literal = "a".repeat(MAX_ARRAY_LENGTH);
        let types = format!(
            r#"<type name="Text" primitiveType="char" presence="constant">{literal}</type>"#
        );
        let fields = (0..70)
            .map(|n| format!(r#"<field name="f{n}" id="{n}" type="Text"/>"#))
            .collect::<String>();
        let s = Schema::parse(&schema_xml(&types, &fields)).unwrap();
        // References to the large constant have no per-field byte allocation.
        for block in &s.blocks {
            for member in &block.members {
                let MemberKind::Field(field) = &member.kind else {
                    panic!()
                };
                assert!(field.constant.is_none());
            }
        }
        assert_eq!(
            s.decode(&packet(0, &[])),
            Err(Error::Limit("MAX_VALUE_BYTES"))
        );
    }

    #[test]
    fn scanner_keeps_position_while_large_data_arrives() {
        let types = r#"<composite name="groupSizeEncoding"><type name="blockLength" primitiveType="uint8"/><type name="numInGroup" primitiveType="uint8"/></composite>
            <composite name="Var"><type name="length" primitiveType="uint16"/><type name="varData" primitiveType="uint8" length="0"/></composite>"#;
        let s = Schema::parse(&schema_xml(types, r#"<group name="rows" id="1"><field name="v" id="2" type="uint8"/></group><data name="payload" id="3" type="Var"/>"#)).unwrap();
        let mut bytes = packet(0, &[1, 200]);
        bytes.extend([3; 200]);
        let payload_start = bytes.len();
        bytes.extend(60_000u16.to_le_bytes());
        bytes.extend([42; 60_000]);
        let mut frames = Messages::new(&s);
        for cut in 0..bytes.len() {
            assert_eq!(frames.decode(&bytes[..cut], false), Ok(Step::Need));
            if cut >= payload_start {
                assert_eq!(frames.pos, payload_start);
            }
        }
        assert!(matches!(frames.decode(&bytes, true), Ok(Step::Item(_, n)) if n == bytes.len()));
    }

    #[test]
    fn explicit_one_element_arrays_keep_array_semantics() {
        let s = Schema::parse(&schema_xml(r#"
            <type name="Byte" primitiveType="uint8" length="1"/>
            <type name="Text" primitiveType="char" length="1"/>
            <type name="Number" primitiveType="int16" length="1"/>"#,
            r#"<field name="byte" id="1" type="Byte"/><field name="text" id="2" type="Text"/><field name="number" id="3" type="Number"/>"#)).unwrap();
        let bytes = packet(4, &[255, 0, 1, 0]);
        let message = s.decode(&bytes).unwrap();
        assert_eq!(
            message.fields,
            vec![
                named("byte", Value::Bytes(vec![255])),
                named("text", Value::Bytes(vec![0])),
                named("number", Value::Array(vec![int(1)]))
            ]
        );
        let mut out = Vec::new();
        s.write(&message, &mut out).unwrap();
        assert_eq!(out, bytes);
    }
}
