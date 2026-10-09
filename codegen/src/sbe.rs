//! The `sbe` front end: FIX Simple Binary Encoding 1.0 XML message schemas.
//!
//! It maps one `messageSchema` document onto the IR. Enums and sets become
//! named enums and sets. Enums preserve unrecognized values as `Unknown(raw)`;
//! a schema choice named `Unknown` becomes `UnknownValue`. Composites used by messages become structs, with
//! their member offsets. Messages and repeating groups become blocks with
//! their declared `blockLength`. Groups use their dimension composite as a
//! [`Header`] with a length and a count. Variable data becomes bytes with
//! the length prefix of its encoding. The message header composite becomes
//! the header of one union, `Message`, with a case per template.
//!
//! Required scalars become ranges that exclude the null value, as section
//! 2 requires. Optional scalars and enums use their null value. Constants
//! become associated constants. `sinceVersion` must not exceed the schema
//! version. Generated readers accept acting versions from the schema
//! version up: newer senders' longer blocks are skipped (section 5.3), and
//! older senders are refused.
//!
//! Not mapped, with an [`ErrorKind::Unsupported`] error: primitive arrays
//! other than `char` and `uint8`, optional floats (their null is NaN),
//! optional composite fields, and header or dimension composites with
//! `numGroups` or `numVarDataFields`. External includes are refused.
use crate::{
    Error, ErrorKind, FrontEnd, Input,
    ir::*,
    xml::{self, Document, Node},
};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// The SBE 1.0 XML schema front end, registered as `sbe`.
#[derive(Clone, Copy, Debug)]
pub struct SbeFrontEnd;

impl FrontEnd for SbeFrontEnd {
    fn name(&self) -> &'static str {
        "sbe"
    }
    fn parse(&self, inputs: &[Input], defaults: Limits) -> Result<Schema, Error> {
        let [input] = inputs else {
            return Err(Error::new(
                ErrorKind::Cli,
                "inputs",
                "sbe requires exactly one XML schema",
            ));
        };
        if input.name.len() > MAX_INPUT {
            return Err(Error::new(
                ErrorKind::InputLimit,
                "input.name",
                "input path exceeds MAX_INPUT",
            ));
        }
        let located = |mut e: Error| {
            e.location = format!("{}: {}", input.name, e.location);
            e
        };
        let document = xml::parse(&input.bytes).map_err(located)?;
        Compiler::new(&document, defaults)
            .and_then(Compiler::schema)
            .map_err(located)
    }
}

fn shape(path: &str, message: &str) -> Error {
    Error::new(ErrorKind::SchemaShape, path, message)
}
fn unsupported(path: &str, message: &str) -> Error {
    Error::new(ErrorKind::Unsupported, path, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prim {
    Char,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
}
impl Prim {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "char" => Self::Char,
            "int8" => Self::I8,
            "int16" => Self::I16,
            "int32" => Self::I32,
            "int64" => Self::I64,
            "uint8" => Self::U8,
            "uint16" => Self::U16,
            "uint32" => Self::U32,
            "uint64" => Self::U64,
            "float" => Self::F32,
            "double" => Self::F64,
            _ => return None,
        })
    }
    fn ir(self) -> Primitive {
        match self {
            Self::Char | Self::U8 => Primitive::U8,
            Self::I8 => Primitive::I8,
            Self::I16 => Primitive::I16,
            Self::I32 => Primitive::I32,
            Self::I64 => Primitive::I64,
            Self::U16 => Primitive::U16,
            Self::U32 => Primitive::U32,
            Self::U64 => Primitive::U64,
            Self::F32 => Primitive::F32,
            Self::F64 => Primitive::F64,
        }
    }
    fn unsigned(self) -> bool {
        matches!(self, Self::U8 | Self::U16 | Self::U32 | Self::U64)
    }
    fn float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }
    fn width(self) -> Option<Width> {
        match self {
            Self::U8 => Some(Width::U8),
            Self::U16 => Some(Width::U16),
            Self::U32 => Some(Width::U32),
            Self::U64 => Some(Width::U64),
            _ => None,
        }
    }
    /// Default minimum, maximum, and null (sections 2.3, 2.5, and 2.6).
    fn bounds(self) -> (Val, Val, Val) {
        use Val::{Float, Int};
        let signed = |bits: u32| {
            let edge = 1i128 << (bits - 1);
            (Int(1 - edge), Int(edge - 1), Int(-edge))
        };
        let unsigned = |bits: u32| {
            let max = (1i128 << bits) - 1;
            (Int(0), Int(max - 1), Int(max))
        };
        match self {
            Self::Char => (Int(0x20), Int(0x7e), Int(0)),
            Self::I8 => signed(8),
            Self::I16 => signed(16),
            Self::I32 => signed(32),
            Self::I64 => signed(64),
            Self::U8 => unsigned(8),
            Self::U16 => unsigned(16),
            Self::U32 => unsigned(32),
            Self::U64 => unsigned(64),
            Self::F32 => (
                Float(f64::from(f32::MIN)),
                Float(f64::from(f32::MAX)),
                Float(f64::NAN),
            ),
            Self::F64 => (Float(f64::MIN), Float(f64::MAX), Float(f64::NAN)),
        }
    }
    fn size(self) -> usize {
        self.ir().bytes()
    }
    fn fits(self, v: Val) -> bool {
        match (self, v) {
            (Self::F32 | Self::F64, Val::Float(_)) => true,
            (Self::Char, Val::Int(n)) => (0..=255).contains(&n),
            (p, Val::Int(n)) if !p.float() => crate::validate::fits(&Number::Integer(n), p.ir()),
            _ => false,
        }
    }
    /// Parses a literal. Char literals are one byte, used as given.
    fn literal(self, text: &str, path: &str) -> Result<Val, Error> {
        let v = match self {
            Self::Char => match text.as_bytes() {
                [b] => Val::Int(i128::from(*b)),
                _ => return Err(shape(path, "char literals are one byte")),
            },
            Self::F32 => Val::Float(f64::from(
                text.parse::<f32>()
                    .map_err(|_| shape(path, "invalid float literal"))?,
            )),
            Self::F64 => Val::Float(
                text.parse::<f64>()
                    .map_err(|_| shape(path, "invalid double literal"))?,
            ),
            _ => Val::Int(
                text.parse::<i128>()
                    .map_err(|_| shape(path, "invalid integer literal"))?,
            ),
        };
        if !self.fits(v) {
            return Err(shape(path, "literal outside the primitive's width"));
        }
        Ok(v)
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Val {
    Int(i128),
    Float(f64),
}
impl Val {
    fn le(self, other: Self) -> bool {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a <= b,
            (Self::Float(a), Self::Float(b)) => a <= b,
            _ => false,
        }
    }
    fn number(self) -> Number {
        match self {
            Self::Int(n) => Number::Integer(n),
            Self::Float(f) => Number::Float(f),
        }
    }
    fn nan(self) -> bool {
        matches!(self, Self::Float(f) if f.is_nan())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Required,
    Optional,
    Constant,
}

#[derive(Clone, Debug)]
enum Const {
    Number(Val),
    Bytes(Vec<u8>),
}

/// A `<type>` encoding (section 4.4.1).
#[derive(Clone, Debug)]
struct Simple {
    prim: Prim,
    length: usize,
    array: bool,
    presence: Presence,
    explicit_presence: bool,
    min: Val,
    max: Val,
    null: Val,
    explicit_min: bool,
    explicit_max: bool,
    constant: Option<Const>,
}
impl Simple {
    fn new(prim: Prim) -> Self {
        let (min, max, null) = prim.bounds();
        Self {
            prim,
            length: 1,
            array: false,
            presence: Presence::Required,
            explicit_presence: false,
            min,
            max,
            null,
            explicit_min: false,
            explicit_max: false,
            constant: None,
        }
    }
    fn valid(&self, v: Val) -> bool {
        self.prim.fits(v) && self.min.le(v) && v.le(self.max)
    }
    fn is_null(&self, v: Val) -> bool {
        v == self.null || (v.nan() && self.null.nan())
    }
    /// Moves a default bound past an explicit null that sits on it.
    fn exclude_null(&mut self) {
        let step = |v: Val, up: bool| match v {
            Val::Int(n) => Some(Val::Int(if up { n + 1 } else { n - 1 })),
            Val::Float(_) => None,
        };
        if !self.explicit_max && self.null == self.max {
            if let Some(v) = step(self.null, false) {
                self.max = v;
            }
        } else if !self.explicit_min
            && self.null == self.min
            && let Some(v) = step(self.null, true)
        {
            self.min = v;
        }
    }
    fn wire_size(&self) -> usize {
        if self.presence == Presence::Constant {
            0
        } else {
            self.length.saturating_mul(self.prim.size())
        }
    }
    /// The IR type for a use of this encoding with `presence`.
    fn ir(&self, presence: Presence, path: &str) -> Result<Type, Error> {
        if presence == Presence::Constant {
            return match &self.constant {
                Some(Const::Bytes(b)) => Ok(Type::Constant(Constant::Bytes(b.clone()))),
                Some(Const::Number(v)) => Ok(Type::Constant(Constant::Number {
                    ty: self.prim.ir(),
                    value: v.number(),
                })),
                None => Err(shape(path, "constant field without a value")),
            };
        }
        if self.array {
            return match (self.prim, self.length) {
                (_, 0) => Err(shape(
                    path,
                    "zero-length arrays are only allowed in variable data encodings",
                )),
                (Prim::Char | Prim::U8, n) => Ok(Type::Bytes(Length::Fixed(n))),
                _ => Err(unsupported(
                    path,
                    "arrays of primitives other than char and uint8",
                )),
            };
        }
        let range = if self.prim.float() && !self.explicit_min && !self.explicit_max {
            Type::Scalar(self.prim.ir())
        } else {
            Type::Range {
                item: self.prim.ir(),
                min: self.min.number(),
                max: self.max.number(),
            }
        };
        match presence {
            Presence::Optional if self.prim.float() => Err(unsupported(
                path,
                "optional floats, whose null value is NaN",
            )),
            Presence::Optional => Ok(Type::Optional {
                item: Box::new(range),
                presence: crate::ir::Presence::Null(self.null.number()),
            }),
            _ => Ok(range),
        }
    }
}

/// What a field or member needs to know about an enum. Shared through an
/// `Rc`, so each reference does not copy the choices.
#[derive(Clone, Debug)]
struct EnumInfo {
    ir: String,
    encoding: Simple,
    choices: Vec<(String, Val)>,
}

/// A named encoding, once compiled.
#[derive(Clone, Debug)]
enum Encoding {
    Simple(Simple),
    Enum(Rc<EnumInfo>),
    Set { ir: String, size: usize },
    Composite { ir: String, length: usize },
}

struct Compiler<'a> {
    doc: &'a Document,
    defaults: Limits,
    version: u64,
    /// Top-level encoding elements by symbolic name.
    names: BTreeMap<String, usize>,
    compiled: BTreeMap<usize, Encoding>,
    active: BTreeSet<usize>,
    /// Named IR types, keyed by XML node for document order.
    types: BTreeMap<usize, NamedType>,
    /// Fields, members, and choices so far. The validator counts at least
    /// these against [`MAX_FIELDS`]; refusing early bounds the work.
    fields: usize,
}

impl<'a> Compiler<'a> {
    fn new(doc: &'a Document, defaults: Limits) -> Result<Self, Error> {
        let root = doc
            .nodes
            .first()
            .ok_or_else(|| shape("schema", "empty document"))?;
        if root.tag != "messageSchema" || !root.text.trim().is_empty() {
            return Err(shape("schema", "root must be a messageSchema element"));
        }
        let version = number(root, "version", 0, "messageSchema")?;
        Ok(Self {
            doc,
            defaults,
            version,
            names: BTreeMap::new(),
            compiled: BTreeMap::new(),
            active: BTreeSet::new(),
            types: BTreeMap::new(),
            fields: 0,
        })
    }
    fn node(&self, id: usize) -> Result<&'a Node, Error> {
        self.doc
            .nodes
            .get(id)
            .ok_or_else(|| shape("schema", "missing XML node"))
    }
    /// Counts one IR field, variant, or bit against [`MAX_FIELDS`].
    fn count(&mut self, path: &str) -> Result<(), Error> {
        self.fields += 1;
        if self.fields > MAX_FIELDS {
            return Err(Error::new(ErrorKind::IrLimit, path, "MAX_FIELDS exceeded"));
        }
        Ok(())
    }
    fn since(&self, n: &Node, path: &str) -> Result<(), Error> {
        if number(n, "sinceVersion", 0, path)? > self.version
            || number(n, "deprecated", 0, path)? > self.version
        {
            return Err(shape(
                path,
                "sinceVersion and deprecated must not exceed the schema version",
            ));
        }
        Ok(())
    }
    /// A member's `sinceVersion`, raised to that of the type it names.
    fn effective_since(&self, n: &Node) -> u64 {
        let own = n
            .attr("sinceVersion")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let named = n
            .attr("type")
            .and_then(|t| self.names.get(t))
            .and_then(|&id| self.doc.nodes.get(id))
            .and_then(|t| t.attr("sinceVersion"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        own.max(named)
    }
    fn schema(mut self) -> Result<Schema, Error> {
        let root = self.node(0)?;
        let id = root
            .attr("id")
            .ok_or_else(|| shape("messageSchema", "missing id"))?
            .parse::<u32>()
            .map_err(|_| shape("messageSchema", "id must be a u32"))?;
        let byte_order = match root.attr("byteOrder").unwrap_or("littleEndian") {
            "littleEndian" => ByteOrder::Little,
            "bigEndian" => ByteOrder::Big,
            _ => return Err(shape("messageSchema", "byteOrder")),
        };
        let mut messages = Vec::new();
        for &child in &root.children {
            let n = self.node(child)?;
            match n.tag.as_str() {
                "types" => {
                    if !n.text.trim().is_empty() {
                        return Err(shape("types", "unexpected text"));
                    }
                    for &t in &n.children {
                        let node = self.node(t)?;
                        if !matches!(node.tag.as_str(), "type" | "composite" | "enum" | "set") {
                            return Err(shape("types", "unknown encoding element"));
                        }
                        let name = symbol(node, "types")?;
                        if self.names.insert(name, t).is_some() {
                            return Err(Error::new(
                                ErrorKind::DuplicateName,
                                format!("types.{}", symbol(node, "types")?),
                                "duplicate type name",
                            ));
                        }
                    }
                }
                "message" => messages.push(child),
                _ => {
                    return Err(unsupported(
                        &n.tag,
                        "root children other than types and message, such as includes",
                    ));
                }
            }
        }
        // Every enum and set is emitted, even when unused. Simple types and
        // composites are compiled where they are used.
        let declared: Vec<_> = self.names.values().copied().collect();
        for node in declared {
            if matches!(self.node(node)?.tag.as_str(), "enum" | "set" | "type") {
                self.compile(node, "types", 0)?;
            }
        }
        let header_name = root.attr("headerType").unwrap_or("messageHeader");
        let header = self.header(header_name, true)?;
        let mut cases = Vec::new();
        let mut names = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for &m in &messages {
            let n = self.node(m)?;
            let name = symbol(n, "message")?;
            let path = format!("message {name}");
            self.since(n, &path)?;
            let tag = n
                .attr("id")
                .ok_or_else(|| shape(&path, "missing id"))?
                .parse::<u64>()
                .map_err(|_| shape(&path, "id must be unsigned"))?;
            if !names.insert(name.clone()) || !tags.insert(tag) {
                return Err(Error::new(
                    ErrorKind::DuplicateName,
                    path,
                    "duplicate message name or id",
                ));
            }
            self.block(m, &name, &path, 0, self.effective_since(n))?;
            cases.push(Case {
                name: name.clone(),
                doc: description(n),
                tag,
                item: name,
            });
        }
        if cases.is_empty() {
            return Err(shape("messageSchema", "no messages"));
        }
        let package = root.attr("package").unwrap_or_default();
        let mut types: Vec<NamedType> = std::mem::take(&mut self.types).into_values().collect();
        types.push(NamedType {
            name: "Message".into(),
            doc: format!(
                "One message: the `{header_name}` header, then the template's root block."
            ),
            definition: Definition::Union { header, cases },
        });
        let mut doc_text = format!("SBE schema {package} id {id} version {}.", self.version);
        if let Some(d) = root.attr("description") {
            doc_text.push_str(&format!(" {d}"));
        }
        Ok(Schema {
            doc: doc_text,
            byte_order,
            types,
            streams: Vec::new(),
        })
    }

    /// Resolves an encoding by name: a declared type or a primitive.
    fn named(&mut self, name: &str, path: &str, depth: usize) -> Result<Encoding, Error> {
        if let Some(&id) = self.names.get(name) {
            return self.compile(id, path, depth + 1);
        }
        let prim = Prim::named(name).ok_or_else(|| {
            Error::new(
                ErrorKind::UnknownReference,
                path,
                format!("unknown type {name:?}"),
            )
        })?;
        Ok(Encoding::Simple(Simple::new(prim)))
    }

    fn compile(&mut self, id: usize, path: &str, depth: usize) -> Result<Encoding, Error> {
        if depth > MAX_NESTING {
            return Err(Error::new(
                ErrorKind::IrLimit,
                path,
                "type references nest deeper than MAX_NESTING",
            ));
        }
        if let Some(e) = self.compiled.get(&id) {
            return Ok(e.clone());
        }
        if !self.active.insert(id) {
            return Err(shape(path, "cyclic type reference"));
        }
        let n = self.node(id)?;
        let name = symbol(n, path)?;
        let path = format!("{} {name}", n.tag);
        self.since(n, &path)?;
        let encoding = match n.tag.as_str() {
            "type" => Encoding::Simple(self.simple(n, &path, depth)?),
            "enum" | "set" => self.choices(id, n, &name, &path, depth)?,
            "composite" => self.composite(id, n, &name, &path, depth)?,
            _ => return Err(shape(&path, "unknown encoding element")),
        };
        self.active.remove(&id);
        self.compiled.insert(id, encoding.clone());
        Ok(encoding)
    }

    fn simple(&mut self, n: &Node, path: &str, depth: usize) -> Result<Simple, Error> {
        if !n.children.is_empty() {
            return Err(shape(path, "type elements have no children"));
        }
        let prim = Prim::named(
            n.attr("primitiveType")
                .ok_or_else(|| shape(path, "missing primitiveType"))?,
        )
        .ok_or_else(|| shape(path, "unknown primitiveType"))?;
        let mut s = Simple::new(prim);
        if let Some(p) = presence(n, path)? {
            s.presence = p;
            s.explicit_presence = true;
        }
        s.length = usize::try_from(number(n, "length", 1, path)?)
            .ok()
            .filter(|n| *n <= self.defaults.max_message)
            .ok_or_else(|| {
                Error::new(ErrorKind::InvalidSize, path, "length exceeds max_message")
            })?;
        s.array = n.attr("length").is_some();
        let value_ref = n.attr("valueRef");
        if value_ref.is_some() && s.presence != Presence::Constant {
            return Err(shape(path, "valueRef requires constant presence"));
        }
        if s.presence == Presence::Constant && prim == Prim::Char && !s.array && value_ref.is_none()
        {
            s.length = n.text.len();
            s.array = s.length != 1;
        }
        if n.attr("nullValue").is_some() && s.presence != Presence::Optional {
            return Err(shape(path, "nullValue requires optional presence"));
        }
        if let Some(v) = n.attr("minValue") {
            s.min = prim.literal(v, path)?;
            s.explicit_min = true;
        }
        if let Some(v) = n.attr("maxValue") {
            s.max = prim.literal(v, path)?;
            s.explicit_max = true;
        }
        if let Some(v) = n.attr("nullValue") {
            s.null = prim.literal(v, path)?;
            s.exclude_null();
        }
        if !s.min.le(s.max) {
            return Err(shape(path, "minValue exceeds maxValue"));
        }
        if prim.float() && !s.null.nan() {
            return Err(shape(path, "float null values must be NaN"));
        }
        if s.presence == Presence::Optional && s.valid(s.null) {
            return Err(shape(path, "null value inside the valid range"));
        }
        if let Some(reference) = value_ref {
            if !n.text.trim().is_empty() || s.length != 1 {
                return Err(shape(path, "valueRef constants are single values"));
            }
            let (_, value) = self.value_ref(reference, path, depth)?;
            if !s.valid(value) || s.is_null(value) {
                return Err(shape(path, "constant outside the valid range"));
            }
            s.constant = Some(match value {
                Val::Int(c) if s.array => Const::Bytes(vec![u8::try_from(c).unwrap_or(0)]),
                v => Const::Number(v),
            });
        } else if s.presence == Presence::Constant {
            if prim == Prim::Char && s.array {
                if n.text.len() != s.length
                    || s.length == 0
                    || !n
                        .text
                        .bytes()
                        .all(|b| (0x20..=0x7e).contains(&b) && s.valid(Val::Int(i128::from(b))))
                {
                    return Err(shape(path, "constant char array"));
                }
                if n.text.len() > MAX_CONSTANT {
                    return Err(Error::new(
                        ErrorKind::IrLimit,
                        path,
                        "MAX_CONSTANT exceeded",
                    ));
                }
                s.constant = Some(Const::Bytes(n.text.as_bytes().to_vec()));
            } else {
                if s.length != 1 {
                    return Err(unsupported(path, "constant arrays other than char"));
                }
                let text = if prim == Prim::Char {
                    n.text.as_str()
                } else {
                    n.text.trim()
                };
                let v = prim.literal(text, path)?;
                if !s.valid(v) || s.is_null(v) {
                    return Err(shape(path, "constant outside the valid range"));
                }
                s.constant = Some(Const::Number(v));
            }
        } else if !n.text.trim().is_empty() {
            return Err(shape(path, "text in a non-constant type"));
        }
        Ok(s)
    }

    /// Resolves `Enum.value` to the enum's IR name and the value.
    fn value_ref(
        &mut self,
        reference: &str,
        path: &str,
        depth: usize,
    ) -> Result<(String, Val), Error> {
        let (enum_name, choice) = reference
            .split_once('.')
            .ok_or_else(|| shape(path, "valueRef must be Enum.value"))?;
        let Encoding::Enum(info) = self.named(enum_name, path, depth)? else {
            return Err(shape(path, "valueRef must name an enum"));
        };
        let value = info
            .choices
            .iter()
            .find(|(n, _)| n == choice)
            .map(|(_, v)| *v)
            .ok_or_else(|| shape(path, "valueRef names no valid value"))?;
        Ok((info.ir.clone(), value))
    }

    fn choices(
        &mut self,
        id: usize,
        n: &Node,
        name: &str,
        path: &str,
        depth: usize,
    ) -> Result<Encoding, Error> {
        if !n.text.trim().is_empty() {
            return Err(shape(path, "unexpected text"));
        }
        let is_set = n.tag == "set";
        let encoding = n
            .attr("encodingType")
            .ok_or_else(|| shape(path, "missing encodingType"))?;
        let Encoding::Simple(mut s) = self.named(encoding, path, depth)? else {
            return Err(shape(path, "encodingType must be a scalar type"));
        };
        if s.length != 1
            || s.array
            || s.presence == Presence::Constant
            || !(s.prim.unsigned() || (!is_set && s.prim == Prim::Char))
        {
            return Err(shape(
                path,
                "encodingType must be an unsigned or char scalar",
            ));
        }
        if let Some(p) = presence(n, path)? {
            s.presence = p;
            s.explicit_presence = true;
        }
        if s.presence == Presence::Constant || (is_set && s.presence != Presence::Required) {
            return Err(shape(path, "invalid enum or set presence"));
        }
        if let Some(v) = n.attr("nullValue") {
            if s.presence != Presence::Optional || is_set {
                return Err(shape(path, "nullValue requires an optional enum"));
            }
            s.null = s.prim.literal(v, path)?;
        }
        let mut variants = Vec::new();
        let mut bits = Vec::new();
        let mut choices = Vec::new();
        let mut names = BTreeSet::new();
        let mut values = BTreeSet::new();
        for &child in &n.children {
            let c = self.node(child)?;
            if c.tag != if is_set { "choice" } else { "validValue" } || !c.children.is_empty() {
                return Err(shape(path, "unexpected child element"));
            }
            let choice = symbol(c, path)?;
            let choice_path = format!("{path}.{choice}");
            self.count(&choice_path)?;
            self.since(c, &choice_path)?;
            let value = if is_set {
                let bit = c
                    .text
                    .trim()
                    .parse::<u8>()
                    .ok()
                    .filter(|b| usize::from(*b) < s.prim.size() * 8)
                    .ok_or_else(|| shape(&choice_path, "choice bit outside the encoding"))?;
                bits.push(Bit {
                    name: choice.clone(),
                    doc: description(c),
                    bit,
                });
                Val::Int(1i128 << bit)
            } else {
                let text = if s.prim == Prim::Char {
                    c.text.as_str()
                } else {
                    c.text.trim()
                };
                let v = s.prim.literal(text, &choice_path)?;
                if !s.valid(v) && !s.is_null(v) {
                    return Err(shape(&choice_path, "value outside the encoding's range"));
                }
                if s.presence == Presence::Optional && s.is_null(v) {
                    return Err(shape(&choice_path, "value equals the null value"));
                }
                let Val::Int(value) = v else {
                    return Err(shape(&choice_path, "enum values are integers"));
                };
                variants.push(Variant {
                    name: enum_choice(&choice)?,
                    doc: description(c),
                    value,
                });
                v
            };
            let Val::Int(key) = value else {
                return Err(shape(&choice_path, "invalid value"));
            };
            if !names.insert(choice.clone()) || !values.insert(key) {
                return Err(Error::new(
                    ErrorKind::DuplicateName,
                    choice_path,
                    "duplicate choice name or value",
                ));
            }
            choices.push((choice, value));
        }
        if choices.is_empty() {
            return Err(shape(path, "enums and sets need at least one choice"));
        }
        let definition = if is_set {
            Definition::Set {
                repr: s.prim.width().ok_or_else(|| shape(path, "set encoding"))?,
                bits,
            }
        } else {
            Definition::Enum {
                open: true,
                repr: s.prim.ir(),
                variants,
            }
        };
        self.types.insert(
            id,
            NamedType {
                name: name.into(),
                doc: description(n),
                definition,
            },
        );
        Ok(if is_set {
            Encoding::Set {
                ir: name.into(),
                size: s.prim.size(),
            }
        } else {
            Encoding::Enum(Rc::new(EnumInfo {
                ir: name.into(),
                encoding: s,
                choices,
            }))
        })
    }

    fn composite(
        &mut self,
        id: usize,
        n: &Node,
        name: &str,
        path: &str,
        depth: usize,
    ) -> Result<Encoding, Error> {
        if !n.text.trim().is_empty() || presence(n, path)?.is_some_and(|p| p != Presence::Required)
        {
            return Err(shape(path, "composites have no text or presence"));
        }
        let mut fields = Vec::new();
        let mut end = 0usize;
        let mut names = BTreeSet::new();
        let mut last_since = 0;
        for &child in &n.children {
            let c = self.node(child)?;
            let member = symbol(c, path)?;
            let member_path = format!("{path}.{member}");
            self.count(&member_path)?;
            if !names.insert(member.clone()) {
                return Err(Error::new(
                    ErrorKind::DuplicateName,
                    member_path,
                    "duplicate composite member",
                ));
            }
            self.since(c, &member_path)?;
            let (ty, size) = match c.tag.as_str() {
                "ref" => {
                    if !c.children.is_empty() || !c.text.trim().is_empty() {
                        return Err(shape(&member_path, "ref elements have no content"));
                    }
                    let target = c
                        .attr("type")
                        .ok_or_else(|| shape(&member_path, "missing type"))?;
                    let e = self.named(target, &member_path, depth)?;
                    self.member(&e, None, None, &member_path, depth)?
                }
                "type" => {
                    let s = self.simple(c, &member_path, depth)?;
                    let size = s.wire_size();
                    (s.ir(s.presence, &member_path)?, size)
                }
                "enum" | "set" | "composite" => {
                    // Inline definitions are named after their owner.
                    let inline = format!("{name}_{member}");
                    let e = match c.tag.as_str() {
                        "composite" => {
                            self.composite(child, c, &inline, &member_path, depth + 1)?
                        }
                        _ => self.choices(child, c, &inline, &member_path, depth + 1)?,
                    };
                    self.member(&e, None, None, &member_path, depth)?
                }
                _ => return Err(shape(&member_path, "unknown composite member")),
            };
            let offset = c
                .attr("offset")
                .map(|_| number(c, "offset", 0, &member_path))
                .transpose()?
                .map(|o| usize::try_from(o).unwrap_or(usize::MAX));
            let offset = if matches!(ty, Type::Constant(_)) {
                None
            } else {
                let since = self.effective_since(c).max(self.effective_since(n));
                if since < last_since {
                    return Err(shape(&member_path, "sinceVersion decreases (section 5)"));
                }
                last_since = since;
                let start = offset.unwrap_or(end);
                if start < end {
                    return Err(Error::new(
                        ErrorKind::InvalidSize,
                        member_path,
                        "overlapping composite members",
                    ));
                }
                end = start.saturating_add(size);
                offset
            };
            fields.push(Field {
                name: member,
                doc: description(c),
                ty,
                byte_order: None,
                fixed_size: None,
                offset,
            });
        }
        if fields.is_empty() {
            return Err(shape(path, "empty composite"));
        }
        self.types.insert(
            id,
            NamedType {
                name: name.into(),
                doc: description(n),
                definition: Definition::Struct(fields),
            },
        );
        Ok(Encoding::Composite {
            ir: name.into(),
            length: end,
        })
    }

    /// The IR type and wire size of a field or member using encoding `e`.
    /// `field_presence` and `value_ref` come from a message field.
    fn member(
        &mut self,
        e: &Encoding,
        field_presence: Option<Presence>,
        value_ref: Option<&str>,
        path: &str,
        depth: usize,
    ) -> Result<(Type, usize), Error> {
        match e {
            Encoding::Simple(s) => {
                let mut s = s.clone();
                let presence = match field_presence {
                    Some(p) if s.explicit_presence && p != s.presence => {
                        return Err(shape(path, "field presence differs from its type"));
                    }
                    Some(p) => p,
                    None => s.presence,
                };
                if presence == Presence::Constant && s.constant.is_none() {
                    let reference =
                        value_ref.ok_or_else(|| shape(path, "constant field needs a value"))?;
                    if s.length != 1 {
                        return Err(shape(path, "valueRef needs a single-value type"));
                    }
                    let (_, value) = self.value_ref(reference, path, depth)?;
                    if !s.valid(value) || s.is_null(value) {
                        return Err(shape(path, "constant outside the valid range"));
                    }
                    s.constant = Some(match value {
                        Val::Int(c) if s.array => Const::Bytes(vec![u8::try_from(c).unwrap_or(0)]),
                        v => Const::Number(v),
                    });
                } else if value_ref.is_some() && presence != Presence::Constant {
                    return Err(shape(path, "valueRef requires constant presence"));
                }
                if presence == Presence::Optional && s.valid(s.null) {
                    return Err(shape(path, "null value inside the valid range"));
                }
                s.presence = presence;
                let size = s.wire_size();
                Ok((s.ir(presence, path)?, size))
            }
            Encoding::Enum(info) => {
                let s = &info.encoding;
                let presence = match field_presence {
                    Some(p) if s.explicit_presence && p != s.presence => {
                        return Err(shape(path, "field presence differs from its type"));
                    }
                    Some(p) => p,
                    None => s.presence,
                };
                match presence {
                    Presence::Constant => {
                        let reference =
                            value_ref.ok_or_else(|| shape(path, "constant enum needs valueRef"))?;
                        let (ty, _) = self.value_ref(reference, path, depth)?;
                        let (_, choice) = reference.split_once('.').unwrap_or_default();
                        if ty != info.ir {
                            return Err(shape(path, "valueRef names another enum"));
                        }
                        Ok((
                            Type::Constant(Constant::Variant {
                                ty,
                                name: enum_choice(choice)?,
                            }),
                            0,
                        ))
                    }
                    Presence::Optional => {
                        if info.choices.iter().any(|(_, v)| s.is_null(*v)) {
                            return Err(shape(path, "an enum value equals the null value"));
                        }
                        Ok((
                            Type::Optional {
                                item: Box::new(Type::Ref(info.ir.clone())),
                                presence: crate::ir::Presence::Null(s.null.number()),
                            },
                            s.prim.size(),
                        ))
                    }
                    Presence::Required => {
                        no_value_ref(value_ref, path)?;
                        Ok((Type::Ref(info.ir.clone()), s.prim.size()))
                    }
                }
            }
            Encoding::Set { ir, size } => {
                no_value_ref(value_ref, path)?;
                if field_presence.is_some_and(|p| p != Presence::Required) {
                    return Err(shape(path, "sets are always required"));
                }
                Ok((Type::Ref(ir.clone()), *size))
            }
            Encoding::Composite { ir, length } => {
                no_value_ref(value_ref, path)?;
                match field_presence {
                    Some(Presence::Optional) => Err(unsupported(path, "optional composite fields")),
                    Some(Presence::Constant) => Err(shape(path, "constant composite field")),
                    _ => Ok((Type::Ref(ir.clone()), *length)),
                }
            }
        }
    }

    /// A header or group dimension composite (sections 3.2 and 3.4).
    fn header(&mut self, name: &str, message: bool) -> Result<Header, Error> {
        let path = format!("composite {name}");
        let id = *self.names.get(name).ok_or_else(|| {
            Error::new(
                ErrorKind::UnknownReference,
                &path,
                "unknown header composite",
            )
        })?;
        let n = self.node(id)?;
        if n.tag != "composite" {
            return Err(shape(&path, "headers are composites"));
        }
        if number(n, "sinceVersion", 0, &path)? != 0 {
            return Err(shape(&path, "headers cannot be versioned"));
        }
        let mut fields: Vec<HeaderField> = Vec::new();
        let mut end = 0usize;
        for &child in &n.children {
            let c = self.node(child)?;
            let member = symbol(c, &path)?;
            let member_path = format!("{path}.{member}");
            // Each role appears once, so a header has at most four fields,
            // however many groups reuse it.
            if fields.iter().any(|f| f.name == member) {
                return Err(Error::new(
                    ErrorKind::DuplicateName,
                    member_path,
                    "duplicate header field",
                ));
            }
            let s = match c.tag.as_str() {
                "type" => self.simple(c, &member_path, 1)?,
                "ref" => match self.named(
                    c.attr("type")
                        .ok_or_else(|| shape(&member_path, "missing type"))?,
                    &member_path,
                    1,
                )? {
                    Encoding::Simple(s) => s,
                    _ => return Err(shape(&member_path, "header fields are scalars")),
                },
                _ => return Err(shape(&member_path, "header fields are scalars")),
            };
            let since = number(c, "sinceVersion", 0, &member_path)?;
            let width = s
                .prim
                .width()
                .filter(|_| !s.array && s.presence == Presence::Required && since == 0);
            let width = width.ok_or_else(|| {
                shape(&member_path, "header fields are unsigned required scalars")
            })?;
            let Val::Int(max) = s.max else {
                return Err(shape(&member_path, "header maximum"));
            };
            let mut max = u64::try_from(max).unwrap_or(0);
            let role = match (member.as_str(), message) {
                ("blockLength", _) => Role::Length,
                ("templateId", true) => Role::Tag,
                ("schemaId", true) => Role::Constant(self.schema_id()?),
                ("version", true) => Role::Version {
                    current: self.version,
                    minimum: self.version,
                },
                ("numInGroup", false) => {
                    // Section 3.4.10 permits the full unsigned range.
                    if !s.explicit_max {
                        max = width.max();
                    }
                    Role::Count
                }
                ("numGroups" | "numVarDataFields", _) => {
                    return Err(unsupported(
                        &member_path,
                        "numGroups and numVarDataFields header fields",
                    ));
                }
                _ => return Err(shape(&member_path, "unknown header field")),
            };
            if s.explicit_min {
                return Err(unsupported(&member_path, "minValue on header fields"));
            }
            let offset = usize::try_from(number(c, "offset", end as u64, &member_path)?)
                .unwrap_or(usize::MAX);
            if offset < end {
                return Err(Error::new(
                    ErrorKind::InvalidSize,
                    member_path,
                    "overlapping header fields",
                ));
            }
            end = offset.saturating_add(width.bytes());
            fields.push(HeaderField {
                name: member,
                offset,
                width,
                role,
                max: (max != width.max()).then_some(max),
            });
        }
        Ok(Header { size: end, fields })
    }

    fn schema_id(&self) -> Result<u64, Error> {
        self.node(0)?
            .attr("id")
            .and_then(|s| s.parse::<u32>().ok())
            .map(u64::from)
            .ok_or_else(|| shape("messageSchema", "id must be a u32"))
    }

    /// Compiles a message or group into a block named `name`.
    fn block(
        &mut self,
        id: usize,
        name: &str,
        path: &str,
        depth: usize,
        inherited: u64,
    ) -> Result<(), Error> {
        if depth > MAX_NESTING {
            return Err(Error::new(
                ErrorKind::IrLimit,
                path,
                "groups nest deeper than MAX_NESTING",
            ));
        }
        let n = self.node(id)?;
        if !n.text.trim().is_empty() {
            return Err(shape(path, "unexpected text"));
        }
        let mut fields = Vec::new();
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut phase = 0;
        let mut end = 0usize;
        let mut last_since = [0u64; 3];
        for &child in &n.children {
            let c = self.node(child)?;
            let member = symbol(c, path)?;
            let member_path = format!("{path}/{member}");
            self.count(&member_path)?;
            let field_id = c
                .attr("id")
                .ok_or_else(|| shape(&member_path, "missing id"))?
                .parse::<u16>()
                .map_err(|_| shape(&member_path, "id must be a u16"))?;
            if !names.insert(member.clone()) || !ids.insert(field_id) {
                return Err(Error::new(
                    ErrorKind::DuplicateName,
                    member_path,
                    "duplicate member name or id",
                ));
            }
            self.since(c, &member_path)?;
            let category = match c.tag.as_str() {
                "field" => 0,
                "group" => 1,
                "data" => 2,
                _ => return Err(shape(&member_path, "unknown message member")),
            };
            if category < phase {
                return Err(shape(&member_path, "fields, then groups, then data"));
            }
            phase = category;
            let (ty, offset) = match category {
                0 => {
                    if !c.children.is_empty() || !c.text.trim().is_empty() {
                        return Err(shape(&member_path, "fields have no content"));
                    }
                    let target = c
                        .attr("type")
                        .ok_or_else(|| shape(&member_path, "missing type"))?;
                    let e = self.named(target, &member_path, 0)?;
                    let (ty, size) = self.member(
                        &e,
                        presence(c, &member_path)?,
                        c.attr("valueRef"),
                        &member_path,
                        0,
                    )?;
                    let offset = c
                        .attr("offset")
                        .map(|_| number(c, "offset", 0, &member_path))
                        .transpose()?
                        .map(|o| usize::try_from(o).unwrap_or(usize::MAX));
                    if matches!(ty, Type::Constant(_)) {
                        (ty, None)
                    } else {
                        let start = offset.unwrap_or(end);
                        if start < end {
                            return Err(Error::new(
                                ErrorKind::InvalidSize,
                                member_path,
                                "overlapping fields",
                            ));
                        }
                        end = start.saturating_add(size);
                        (ty, offset)
                    }
                }
                1 => {
                    if presence(c, &member_path)?.is_some() || c.attr("offset").is_some() {
                        return Err(shape(&member_path, "groups take no presence or offset"));
                    }
                    let header = self.header(
                        c.attr("dimensionType").unwrap_or("groupSizeEncoding"),
                        false,
                    )?;
                    let item = format!("{name}_{member}");
                    let since = self.effective_since(c).max(inherited);
                    self.block(child, &item, &member_path, depth + 1, since)?;
                    if !header.fields.iter().any(|f| f.role == Role::Count) {
                        return Err(shape(&member_path, "dimension needs numInGroup"));
                    }
                    if !header.fields.iter().any(|f| f.role == Role::Length) {
                        return Err(shape(&member_path, "dimension needs blockLength"));
                    }
                    (
                        Type::BlockGroup {
                            item,
                            header,
                            limit: None,
                        },
                        None,
                    )
                }
                _ => {
                    if !c.children.is_empty()
                        || !c.text.trim().is_empty()
                        || c.attr("offset").is_some()
                        || presence(c, &member_path)? == Some(Presence::Constant)
                    {
                        return Err(shape(&member_path, "invalid data attributes or content"));
                    }
                    let target = c
                        .attr("type")
                        .ok_or_else(|| shape(&member_path, "missing type"))?;
                    (self.data(target, &member_path)?, None)
                }
            };
            if !matches!(ty, Type::Constant(_)) {
                let since = self.effective_since(c).max(inherited);
                let last = &mut last_since[category];
                if since < *last {
                    return Err(shape(&member_path, "sinceVersion decreases (section 5)"));
                }
                *last = since;
            }
            fields.push(Field {
                name: member,
                doc: description(c),
                ty,
                byte_order: None,
                fixed_size: None,
                offset,
            });
        }
        let length =
            usize::try_from(number(n, "blockLength", end as u64, path)?).unwrap_or(usize::MAX);
        if length < end {
            return Err(Error::new(
                ErrorKind::InvalidSize,
                path,
                "blockLength is below the end of the fields",
            ));
        }
        self.types.insert(
            id,
            NamedType {
                name: name.into(),
                doc: description(n),
                definition: Definition::Block { length, fields },
            },
        );
        Ok(())
    }

    /// A variable data encoding: a `length` and a `varData` member.
    fn data(&mut self, name: &str, path: &str) -> Result<Type, Error> {
        let id = *self
            .names
            .get(name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReference, path, "unknown data type"))?;
        let n = self.node(id)?;
        if n.tag != "composite" {
            return Err(shape(path, "data types are composites"));
        }
        let [length, data] = n.children.as_slice() else {
            return Err(shape(path, "data composites have length and varData"));
        };
        let (length, data) = (self.node(*length)?, self.node(*data)?);
        let encoding = |c: &Node, this: &mut Self| -> Result<Simple, Error> {
            match c.tag.as_str() {
                "type" => this.simple(c, path, 1),
                "ref" => match this.named(c.attr("type").unwrap_or_default(), path, 1)? {
                    Encoding::Simple(s) => Ok(s),
                    _ => Err(shape(path, "data members are scalars")),
                },
                _ => Err(shape(path, "data members are scalars")),
            }
        };
        let (l, d) = (encoding(length, self)?, encoding(data, self)?);
        let width = l
            .prim
            .width()
            .filter(|_| !l.array && l.presence == Presence::Required);
        let width =
            width.ok_or_else(|| shape(path, "data length is an unsigned required scalar"))?;
        let data_offset = number(data, "offset", width.bytes() as u64, path)?;
        if length.attr("name") != Some("length")
            || !matches!(data.attr("name"), Some("varData" | "data"))
            || number(length, "offset", 0, path)? != 0
            || data_offset != width.bytes() as u64
            || d.length != 0
            || !matches!(d.prim, Prim::U8 | Prim::Char)
            || d.presence == Presence::Constant
        {
            return Err(shape(path, "invalid length and varData encoding"));
        }
        let Val::Int(max) = l.max else {
            return Err(shape(path, "data length maximum"));
        };
        let limit = usize::try_from(max)
            .unwrap_or(0)
            .min(self.defaults.max_collection);
        Ok(Type::Bytes(Length::Variable {
            prefix: width,
            limit: Some(limit),
        }))
    }
}

fn no_value_ref(value_ref: Option<&str>, path: &str) -> Result<(), Error> {
    match value_ref {
        Some(_) => Err(shape(path, "valueRef requires constant presence")),
        None => Ok(()),
    }
}
fn number(n: &Node, name: &str, default: u64, path: &str) -> Result<u64, Error> {
    n.attr(name).map_or(Ok(default), |v| {
        v.parse()
            .map_err(|_| shape(path, &format!("{name} must be unsigned")))
    })
}
fn symbol(n: &Node, path: &str) -> Result<String, Error> {
    let name = n
        .attr("name")
        .ok_or_else(|| shape(&format!("{path} at byte {}", n.at), "missing name"))?;
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Error::new(
            ErrorKind::InvalidName,
            format!("{path} at byte {}", n.at),
            "names are 1..=MAX_NAME ASCII letters, digits, and underscores",
        ));
    }
    Ok(name.into())
}
fn presence(n: &Node, path: &str) -> Result<Option<Presence>, Error> {
    n.attr("presence")
        .map(|v| match v {
            "required" => Ok(Presence::Required),
            "optional" => Ok(Presence::Optional),
            "constant" => Ok(Presence::Constant),
            _ => Err(shape(
                path,
                "presence must be required, optional, or constant",
            )),
        })
        .transpose()
}
fn description(n: &Node) -> String {
    let text = n.attr("description").unwrap_or_default().trim();
    let mut doc: String = text.chars().take(MAX_DOC).collect();
    while doc.len() > MAX_DOC {
        doc.pop();
    }
    doc
}

/// Keeps the raw-value variant distinct from a schema's named Unknown value.
fn enum_choice(name: &str) -> Result<String, Error> {
    Ok(
        if crate::rust_identifier(name, crate::IdentifierCase::Type)? == "Unknown" {
            "UnknownValue".into()
        } else {
            name.into()
        },
    )
}
