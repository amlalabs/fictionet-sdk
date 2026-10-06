//! The shared, ordered binary schema. Front ends construct these types.

/// Default maximum encoded value size: one MiB.
pub const DEFAULT_MAX_MESSAGE: usize = 1 << 20;
/// Default number of entries in a collection, or bytes in variable data.
pub const DEFAULT_MAX_COLLECTION: usize = 4096;
/// Default maximum nesting while reading or writing values.
pub const DEFAULT_MAX_DEPTH: usize = 32;
/// Maximum source size in bytes, per input and across all inputs.
pub const MAX_INPUT: usize = 1 << 20;
/// Maximum JSON nesting depth.
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum JSON values and object keys per document.
pub const MAX_JSON_ELEMENTS: usize = 65_536;
/// Maximum named types in one schema.
pub const MAX_TYPES: usize = 256;
/// Maximum fields, variants, and bits across a schema.
pub const MAX_FIELDS: usize = 4096;
/// Maximum fields in one struct.
pub const MAX_STRUCT_FIELDS: usize = 256;
/// Maximum inline type nesting.
pub const MAX_NESTING: usize = 16;
/// Maximum source name length in UTF-8 bytes.
pub const MAX_NAME: usize = 128;
/// Maximum documentation length in UTF-8 bytes per item.
pub const MAX_DOC: usize = 4096;
/// Maximum generated source size in bytes.
pub const MAX_OUTPUT: usize = 32 << 20;

/// Defaults supplied when a schema omits a resource limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum encoded bytes per value. Allowed range: 1 through 16 MiB.
    pub max_message: usize,
    /// Default collection count or variable data length. At most one MiB.
    pub max_collection: usize,
    /// Maximum value nesting. Allowed range: 1 through 64.
    pub max_depth: usize,
    /// Total heap storage requested while parsing a value. At most 64 MiB.
    pub max_allocation: usize,
    /// Total visited value nodes, including empty values. At most one MiB.
    pub max_nodes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: DEFAULT_MAX_MESSAGE,
            max_collection: DEFAULT_MAX_COLLECTION,
            max_depth: DEFAULT_MAX_DEPTH,
            max_allocation: 8 << 20,
            max_nodes: 65_536,
        }
    }
}

/// Byte order inherited by fields and named references.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ByteOrder {
    /// Most significant byte first.
    #[default]
    Big,
    /// Least significant byte first.
    Little,
}

/// Unsigned integer widths for counts, lengths, and sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// One byte.
    U8,
    /// Two bytes.
    U16,
    /// Four bytes.
    U32,
    /// Eight bytes.
    U64,
}
impl Width {
    /// Width in bytes.
    pub fn bytes(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }
    /// Largest representable unsigned value.
    pub fn max(self) -> u64 {
        match self {
            Self::U8 => u8::MAX.into(),
            Self::U16 => u16::MAX.into(),
            Self::U32 => u32::MAX.into(),
            Self::U64 => u64::MAX,
        }
    }
}

/// A fixed-width scalar. Floats use IEEE 754 and refuse non-finite values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primitive {
    /// Unsigned eight-bit integer.
    U8,
    /// Unsigned sixteen-bit integer.
    U16,
    /// Unsigned thirty-two-bit integer.
    U32,
    /// Unsigned sixty-four-bit integer.
    U64,
    /// Signed eight-bit integer.
    I8,
    /// Signed sixteen-bit integer.
    I16,
    /// Signed thirty-two-bit integer.
    I32,
    /// Signed sixty-four-bit integer.
    I64,
    /// Finite single-precision float.
    F32,
    /// Finite double-precision float.
    F64,
}
impl Primitive {
    /// Rust scalar name.
    pub fn rust(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }
    /// Width in bytes.
    pub fn bytes(self) -> usize {
        match self {
            Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            _ => 8,
        }
    }
    /// Whether this is a floating-point type.
    pub fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }
    /// Whether this is a signed integer.
    pub fn is_signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }
}

/// A numeric literal with integer precision through all supported widths.
#[derive(Clone, Debug, PartialEq)]
pub enum Number {
    /// Signed or unsigned integer in a wider container.
    Integer(i128),
    /// Finite float; validation checks exact representation at its width.
    Float(f64),
}

/// A byte or UTF-8 string length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Length {
    /// Exactly this many bytes. Fixed strings are not padded or terminated.
    Fixed(usize),
    /// An unsigned prefix, followed by at most `limit` bytes.
    Variable {
        /// Prefix width.
        prefix: Width,
        /// Byte limit. Validation fills an omitted limit from [`Limits`].
        limit: Option<usize>,
    },
}

/// How an optional field represents absence.
#[derive(Clone, Debug, PartialEq)]
pub enum Presence {
    /// An unsigned 0 or 1 before the value.
    Flag(Width),
    /// A reserved scalar value. Only scalar items are allowed.
    Null(Number),
}

/// An inline field type. Named structs, enums, and sets use [`Type::Ref`].
#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    /// A fixed-width number.
    Scalar(Primitive),
    /// Raw bytes.
    Bytes(Length),
    /// UTF-8 text, measured in bytes.
    String(Length),
    /// A counted sequence. Nested sequences represent repeating groups.
    Group {
        /// The type of each entry.
        item: Box<Type>,
        /// Unsigned entry-count width.
        count: Width,
        /// Maximum entries. Validation fills an omitted limit.
        limit: Option<usize>,
    },
    /// An optional value.
    Optional {
        /// The present type.
        item: Box<Type>,
        /// Absence encoding.
        presence: Presence,
    },
    /// An exact source name. Generated references are boxed to allow cycles.
    Ref(String),
}

/// One ordered struct field.
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    /// Source name, unique within the struct.
    pub name: String,
    /// Field documentation.
    pub doc: String,
    /// Wire type.
    pub ty: Type,
    /// Overrides the inherited byte order, including nested values.
    pub byte_order: Option<ByteOrder>,
    /// Optional assertion of a fixed wire size, checked during validation.
    pub fixed_size: Option<usize>,
}

/// One enum variant and its integer value.
#[derive(Clone, Debug, PartialEq)]
pub struct Variant {
    /// Source variant name.
    pub name: String,
    /// Variant documentation.
    pub doc: String,
    /// Integer discriminant.
    pub value: i128,
}

/// One named bit in a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bit {
    /// Source bit name.
    pub name: String,
    /// Bit documentation.
    pub doc: String,
    /// Zero-based bit position.
    pub bit: u8,
}

/// The body of a named definition.
#[derive(Clone, Debug, PartialEq)]
pub enum Definition {
    /// Fields in wire order.
    Struct(Vec<Field>),
    /// A closed integer enum. Unknown discriminants are refused.
    Enum {
        /// Integer storage type.
        repr: Primitive,
        /// Unique names and discriminants; must not be empty.
        variants: Vec<Variant>,
    },
    /// A closed set. Bits not declared here are refused.
    Set {
        /// Unsigned storage width.
        repr: Width,
        /// Unique names and bit positions.
        bits: Vec<Bit>,
    },
}

/// One named wire type.
#[derive(Clone, Debug, PartialEq)]
pub struct NamedType {
    /// Unique source name.
    pub name: String,
    /// Type documentation.
    pub doc: String,
    /// Ordered wire definition.
    pub definition: Definition,
}

/// A stream of length-prefixed values, optionally preceded by fixed magic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    /// Unique name for the generated decoder type.
    pub name: String,
    /// Source name of the framed value type.
    pub item: String,
    /// Length of the body, excluding the header and this prefix.
    pub prefix: Width,
    /// Prefix byte order. Body order remains the schema default.
    pub byte_order: ByteOrder,
    /// Fixed bytes before each length prefix. At most 256 bytes.
    pub magic: Vec<u8>,
}

/// A complete schema. Declaration and field order are preserved in output.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Schema {
    /// Schema documentation.
    pub doc: String,
    /// Default byte order.
    pub byte_order: ByteOrder,
    /// Named definitions.
    pub types: Vec<NamedType>,
    /// Stream forms, if any.
    pub streams: Vec<Stream>,
}
