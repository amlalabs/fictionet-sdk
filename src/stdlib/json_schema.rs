//! Checked JSON schemas for tool arguments, API bodies, and mock values.
//!
//! [`Schema`] supports `type`, `const`, `enum`, numeric bounds and `multipleOf`,
//! string lengths, array counts, `uniqueItems`, `prefixItems`, `items`, `contains`,
//! object counts, `properties`, `required`, `additionalProperties`, `propertyNames`,
//! `dependentRequired`, `dependentSchemas`, `allOf`, `anyOf`, `oneOf`, `not`,
//! `if`/`then`/`else`, and local `$ref`, `$defs`, and `$anchor`.
//! Unsupported `unevaluatedProperties`, `unevaluatedItems`, `$dynamicRef`,
//! `$dynamicAnchor`, `$recursiveRef`, and `contentSchema` fail compilation.
//! Other unknown keywords are ignored.
//!
//! `format` is an annotation by default, as in the 2020-12 annotation vocabulary.
//! This lets callers accept custom formats without inventing assertions.
//! [`FormatPolicy::Assert`] checks date-time, date, time, email, uuid, uri, ipv4,
//! ipv6, and hostname. Dates and times use RFC 3339; email uses ASCII mailboxes;
//! URI uses RFC 3986 syntax. Checks do not perform DNS or network lookups.
//! Generation uses these formats when a value fits the string length bounds;
//! otherwise it tries letters, which asserted formats may reject.
//! There is no regex engine: `pattern` and `patternProperties` are rejected by
//! default. [`PatternPolicy::Annotate`] records and ignores them, including
//! their effect on `additionalProperties`. Generation refuses such schemas.
//!
//! Numbers use their decimal text, including for equality and `multipleOf`.
//! No floating point rounding or tolerance is used by validation. Precision
//! is limited only by [`fictionet::stdlib::json::MAX_NUMBER_LEN`] and [`Limits::number_exponent`].
//! Out-of-range exponents are errors, including in enum values and instances.
//! Object order does not affect equality. Duplicate object keys are refused.
//!
//! [`Schema::compile_at`] selects a schema within a document, such as an OpenAPI
//! component or request body. Only its reachable schemas are compiled.
//! References stay in that document. Pointers and simple anchors are supported.
//! `$id` is accepted only on the document root, where it does not change
//! same-document references; a reached schema with a nested `$id` (an embedded
//! resource) fails compilation, since its references would resolve elsewhere.
//! Recursive schemas may descend through instances. Revisiting a schema at the
//! same instance is a reference-cycle error, even inside `not` or `anyOf`.
//! All evaluation, including speculative branches, shares one work budget.
//!
//! [`Dialect::OpenApi30`] adds `nullable` for explicit types, boolean exclusive
//! bounds, single-string types, and Reference Object sibling suppression.
//! `example`, `default`, and array-valued `examples` are generation hints.
//! OpenAPI 3.0 ignores non-array `examples`. `discriminator`,
//! `readOnly`, and `writeOnly` do not assert anything; request/response policy
//! belongs to the caller. This module performs no I/O.

use fictionet::stdlib::codec::Lcg;
use fictionet::stdlib::codec::ascii;
use fictionet::stdlib::json::{Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Schema keyword dialect. The default is JSON Schema 2020-12.
///
/// ```
/// use fictionet::stdlib::json_schema::{Dialect, Options};
/// let options = Options { dialect: Dialect::OpenApi30, ..Options::default() };
/// assert_eq!(options.dialect, Dialect::OpenApi30);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Dialect {
    /// JSON Schema 2020-12. `nullable` is an unknown keyword.
    #[default]
    Draft202012,
    /// OpenAPI 3.0 JSON bodies, with the differences described in this module.
    OpenApi30,
}

/// Handling of keywords that require a regex engine.
///
/// ```
/// use fictionet::stdlib::{json::Value, json_schema::{Options, PatternPolicy, Schema}};
/// let source = Value::Object(vec![("pattern".into(), Value::from("^id-"))]);
/// let options = Options { patterns: PatternPolicy::Annotate, ..Options::default() };
/// let schema = Schema::compile_with(&source, options).unwrap();
/// assert_eq!(schema.annotations()[0].keyword, "pattern");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PatternPolicy {
    /// Refuse compilation at the unsupported keyword. This is the default.
    #[default]
    Reject,
    /// Ignore the keyword and expose it in schema annotations.
    /// Generation returns [`GenerationError::UnsupportedPattern`].
    Annotate,
}

/// Whether the common string formats listed in this module are asserted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FormatPolicy {
    /// Record format as an annotation. Unknown formats always remain annotations.
    #[default]
    Annotate,
    /// Assert date-time, date, time, email, uuid, uri, ipv4, ipv6, and hostname.
    Assert,
}

/// Resource bounds. Callers can raise the defaults. Only the documented stack
/// and decimal arithmetic ceilings are clamped.
/// Zero is allowed and means no work or storage for that resource.
///
/// ```
/// use fictionet::stdlib::json_schema::{Limits, Options};
/// let limits = Limits { work: 10_000, ..Limits::default() };
/// let options = Options { limits, ..Options::default() };
/// assert_eq!(options.limits.work, 10_000);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Distinct reached source values, including keyword data. Default 16,384.
    /// Unused definitions and document siblings are excluded.
    pub schema_nodes: usize,
    /// Values in an instance. Object names are not nodes. Default 100,000.
    pub instance_nodes: usize,
    /// Sum of string, name, and number bytes plus one per reached source value,
    /// or per instance value, separately. Default 1 MiB.
    pub bytes: usize,
    /// Source or instance nesting before copying. Default 128; ceiling 256.
    /// Each entry or reference target starts at zero. Document ancestors do
    /// not count. The ceiling bounds recursive value cloning and comparison.
    pub depth: usize,
    /// Simultaneous evaluations on the explicit stack, including applicators.
    /// Default 512. Recursive lists fit JSON depth 128.
    pub validation_depth: usize,
    /// Reference hops at one instance location. Default 32. The count resets
    /// on instance descent; `validation_depth` also bounds the stack.
    pub ref_depth: usize,
    /// Bytes in a JSON Pointer diagnostic or resolved schema path. Default 4,096.
    pub pointer_bytes: usize,
    /// Collected validation errors. Default 64. Zero still returns one error.
    pub errors: usize,
    /// Work units per compilation or validation. Default 1,000,000.
    /// Units charge visits, searches, comparisons, and decimal digit operations.
    pub work: usize,
    /// Additional validation work ceiling per schema/instance size pair.
    /// Default 32. The effective budget is the smaller of `work` and
    /// this field times `(schema_size + 1) * (instance_size + 1)`.
    pub work_per_pair: usize,
    /// Absolute decimal exponent before normalization. Default 10,000;
    /// ceiling 1,000,000 keeps decimal index arithmetic bounded.
    pub number_exponent: usize,
}
impl Default for Limits {
    /// Returns the documented resource defaults.
    fn default() -> Self {
        Self {
            schema_nodes: 16_384,
            instance_nodes: 100_000,
            bytes: 1 << 20,
            depth: 128,
            validation_depth: 512,
            ref_depth: 32,
            pointer_bytes: 4096,
            errors: 64,
            work: 1_000_000,
            work_per_pair: 32,
            number_exponent: 10_000,
        }
    }
}
impl Limits {
    fn bounded(mut self) -> Self {
        self.depth = self.depth.min(256);
        self.number_exponent = self.number_exponent.min(1_000_000);

        self
    }
}

/// Compilation settings.
///
/// ```
/// use fictionet::stdlib::json_schema::{Options, PatternPolicy};
/// let options = Options { patterns: PatternPolicy::Annotate, ..Options::default() };
/// assert_eq!(options.patterns, PatternPolicy::Annotate);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Keyword meanings. Defaults to 2020-12.
    pub dialect: Dialect,
    /// Regex keyword policy. Defaults to rejection.
    pub patterns: PatternPolicy,
    /// String format policy. Defaults to annotations.
    pub formats: FormatPolicy,
    /// Shared resource bounds, retained by the compiled schema.
    pub limits: Limits,
}

/// Error collection policy.
///
/// ```
/// use fictionet::stdlib::{json::Value, json_schema::{ErrorMode, Schema}};
/// let schema = Schema::compile(&Value::Bool(false)).unwrap();
/// assert_eq!(schema.validate_with(&Value::Null, ErrorMode::All).errors.len(), 1);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ErrorMode {
    /// Stop at the first failed assertion. Branch probes remain isolated.
    #[default]
    First,
    /// Collect failed assertions up to [`Limits::errors`].
    All,
}

/// A reason compilation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileKind {
    /// A keyword has the wrong JSON shape or value.
    InvalidKeyword,
    /// An object repeats a name.
    DuplicateKey,
    /// Regex assertions need an explicit annotation-only policy.
    UnsupportedPattern,
    /// An assertion keyword is not implemented. The string names the keyword.
    UnsupportedKeyword(String),
    /// A reference names another document.
    ExternalReference,
    /// A fragment, pointer, anchor, or reference target is invalid or missing.
    InvalidReference,
    /// A simple anchor is invalid or appears more than once.
    InvalidAnchor,
    /// A named resource bound was reached.
    Limit(&'static str),
}

impl std::fmt::Display for CompileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyword => f.write_str("invalid keyword value"),
            Self::DuplicateKey => f.write_str("duplicate object name"),
            Self::UnsupportedPattern => {
                f.write_str("regex assertions require an annotation-only policy")
            }
            Self::UnsupportedKeyword(name) => write!(f, "unsupported assertion keyword {name}"),
            Self::ExternalReference => f.write_str("reference to another document"),
            Self::InvalidReference => f.write_str("invalid or missing reference target"),
            Self::InvalidAnchor => f.write_str("invalid or duplicate anchor"),
            Self::Limit(name) => write!(f, "compilation exceeded the {name} limit"),
        }
    }
}

/// A compile failure at a JSON Pointer in the source document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    /// Pointer to the invalid keyword or value. An empty pointer names the root.
    pub schema_path: String,
    /// The reason compilation stopped.
    pub kind: CompileKind,
}
impl std::fmt::Display for CompileError {
    /// Formats the reason and source pointer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at schema {}", self.kind, self.schema_path)
    }
}
impl std::error::Error for CompileError {}

/// A reason an instance could not be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationKind {
    /// The boolean schema `false` rejects this instance.
    FalseSchema,
    /// An assertion failed. The string is its JSON Schema keyword.
    Assertion(&'static str),
    /// A required property is absent. The string is the missing name.
    Missing(String),
    /// An instance object repeats a name.
    DuplicateKey,
    /// A schema was revisited without descending to another instance.
    ReferenceCycle,
    /// A named resource bound was reached. This is never a branch mismatch.
    Limit(&'static str),
}

impl std::fmt::Display for ValidationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FalseSchema => f.write_str("the false schema rejects this instance"),
            Self::Assertion(name) => write!(f, "assertion {name} failed"),
            Self::Missing(name) => write!(f, "required property {name} is missing"),
            Self::DuplicateKey => f.write_str("duplicate object name"),
            Self::ReferenceCycle => f.write_str("reference cycle without instance descent"),
            Self::Limit(name) => write!(f, "validation exceeded the {name} limit"),
        }
    }
}

/// A validation failure, with JSON Pointer locations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    /// Instance location. Missing required names point to their parent object.
    pub instance_path: String,
    /// Absolute source location of the failing keyword, including through refs.
    pub schema_path: String,
    /// What failed.
    pub kind: ValidationKind,
}
impl std::fmt::Display for ValidationError {
    /// Formats the reason and both pointers.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at instance {} (schema {})",
            self.kind, self.instance_path, self.schema_path
        )
    }
}
impl std::error::Error for ValidationError {}

/// A recorded format or ignored regex keyword.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation {
    /// Absolute pointer to the keyword.
    pub schema_path: String,
    /// `format`, `pattern`, or `patternProperties`.
    pub keyword: &'static str,
    /// Original keyword value.
    pub value: Value,
}

/// Validation output. Static keyword annotations are available from [`Schema::annotations`].
///
/// ```
/// use fictionet::stdlib::{json::Value, json_schema::Schema};
/// let schema = Schema::compile(&Value::Bool(false)).unwrap();
/// let report = schema.validate(&Value::Null);
/// assert!(!report.is_valid());
/// assert_eq!(report.errors[0].instance_path, "");
/// ```
#[derive(Debug)]
pub struct Validation {
    /// Failed assertions, or a terminal resource/cycle error.
    pub errors: Vec<ValidationError>,
    /// Evaluation stopped early because of policy, an error cap, or a fatal error.
    pub truncated: bool,
}
impl Validation {
    /// Whether evaluation completed without any failure.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Bounds for deterministic candidate search. Defaults are hard ceilings.
/// Containers are limited by `items`; strings and object names by `string_length`.
///
/// ```
/// use fictionet::stdlib::{json::Value, json_schema::{Schema, GenerationLimits}};
/// let schema = Schema::compile(&Value::Bool(true)).unwrap();
/// let limits = GenerationLimits { total_nodes: 8, ..GenerationLimits::default() };
/// let value = schema.generate(7, limits).unwrap();
/// assert!(schema.validate(&value).is_valid());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationLimits {
    /// Value nesting, with root at zero. Default 12.
    pub depth: usize,
    /// Elements or properties per container. Default 32.
    pub items: usize,
    /// Unicode code points per string or object name. Default 128.
    pub string_length: usize,
    /// Nodes in the returned value. Default 1,024.
    pub total_nodes: usize,
    /// Candidate attempts, shared by all descendants. Default 256.
    pub attempts: usize,
    /// Work units across synthesis and candidate validation. Default 1,000,000.
    pub work: usize,
}
impl Default for GenerationLimits {
    /// Returns the documented generation ceilings.
    fn default() -> Self {
        Self {
            depth: 12,
            items: 32,
            string_length: 128,
            total_nodes: 1024,
            attempts: 256,
            work: 1_000_000,
        }
    }
}
impl GenerationLimits {
    fn bounded(mut self) -> Self {
        let cap = Self::default();
        self.depth = self.depth.min(cap.depth);
        self.items = self.items.min(cap.items);
        self.string_length = self.string_length.min(cap.string_length);
        self.total_nodes = self.total_nodes.min(cap.total_nodes);
        self.attempts = self.attempts.min(cap.attempts);
        self.work = self.work.min(cap.work);
        self
    }
}

/// Why deterministic search did not produce an example. Search is incomplete:
/// failure does not prove that the mathematical schema is unsatisfiable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerationError {
    /// The compiled document contains a regex keyword that was ignored.
    UnsupportedPattern,
    /// A named search bound was reached.
    Limit(&'static str),
    /// All attempted candidates failed assertions or size bounds.
    NoCandidate,
    /// Validation encountered a cycle or exhausted a schema resource bound.
    /// Work exhaustion is always [`GenerationError::Limit`] with `"work"`.
    Validation(ValidationError),
}
impl std::fmt::Display for GenerationError {
    /// Formats the generation failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPattern => {
                f.write_str("example generation cannot enforce ignored regex keywords")
            }
            Self::Limit(name) => write!(f, "example generation exceeded the {name} limit"),
            Self::NoCandidate => f.write_str("example generation found no acceptable candidate"),
            Self::Validation(_) => f.write_str("example generation could not validate a candidate"),
        }
    }
}
impl std::error::Error for GenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            _ => None,
        }
    }
}

/// An owned, checked schema arena. Compilation does not expand references.
///
/// Validation preflights input in bounded depth, then evaluates under a shared
/// work cap. For schema size S and instance size I (nodes plus text bytes),
/// evaluation performs at most `min(work, work_per_pair*(S+1)*(I+1))`
/// charged operations. Text comparisons and decimal parsing charge bytes read.
/// Preflight uses ordered sets for duplicate names: O((S+I) log(S+I)) in the
/// worst case. `uniqueItems` sorts normalized values in O(n log n) comparisons.
/// Uniqueness, enum equality, and branch retries spend the same
/// budget; they can return a limit error instead of finishing a costly check.
///
/// ```
/// use fictionet::stdlib::{json, json_schema::Schema};
/// let source = json::parse_with(br#"{"type":"integer","minimum":1}"#,
///     &json::Limits::default()).unwrap();
/// let schema = Schema::compile(&source).unwrap();
/// assert!(schema.validate(&json::Value::from(3)).is_valid());
/// let example = schema.generate(42, Default::default()).unwrap();
/// assert!(schema.validate(&example).is_valid());
/// ```
#[derive(Clone, Debug)]
pub struct Schema {
    nodes: Vec<Node>,
    paths: Paths,
    annotations: Vec<StoredAnnotation>,
    options: Options,
    size: usize,
}

#[derive(Clone, Debug)]
struct StoredAnnotation {
    path: usize,
    keyword: &'static str,
    value: Value,
}

#[derive(Clone, Debug, Default)]
struct Node {
    path: usize,
    reject: bool,
    types: Option<u8>,
    constant: Option<Value>,
    enumeration: Option<Vec<Value>>,
    minimum: Option<Decimal>,
    maximum: Option<Decimal>,
    exclusive_minimum: Option<Decimal>,
    exclusive_maximum: Option<Decimal>,
    multiple_of: Option<Decimal>,
    min_length: Option<Decimal>,
    max_length: Option<Decimal>,
    min_items: Option<Decimal>,
    max_items: Option<Decimal>,
    min_contains: Option<Decimal>,
    max_contains: Option<Decimal>,
    min_properties: Option<Decimal>,
    max_properties: Option<Decimal>,
    items: Option<usize>,
    contains: Option<usize>,
    additional_properties: Option<usize>,
    property_names: Option<usize>,
    not: Option<usize>,
    condition: Option<usize>,
    then_schema: Option<usize>,
    else_schema: Option<usize>,
    prefix_items: Option<Vec<usize>>,
    all_of: Option<Vec<usize>>,
    any_of: Option<Vec<usize>>,
    one_of: Option<Vec<usize>>,
    properties: BTreeMap<String, usize>,
    required: Vec<String>,
    dependent: BTreeMap<String, Vec<String>>,
    dependent_schemas: BTreeMap<String, usize>,
    format: Option<String>,
    unique: bool,
    reference: Option<usize>,
    hints: Vec<Value>,
}

impl Node {
    fn numeric_bounds(&self) -> impl Iterator<Item = (&'static str, &Decimal)> {
        [
            ("minimum", self.minimum.as_ref()),
            ("maximum", self.maximum.as_ref()),
            ("exclusiveMinimum", self.exclusive_minimum.as_ref()),
            ("exclusiveMaximum", self.exclusive_maximum.as_ref()),
            ("multipleOf", self.multiple_of.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, bound)| bound.map(|bound| (key, bound)))
    }
}

fn pointer(base: &str, token: &str, max: usize) -> Result<String, &'static str> {
    let mut size = base.len().checked_add(1).ok_or("pointer_bytes")?;
    for b in token.bytes() {
        size = size
            .checked_add(if b == b'~' || b == b'/' { 2 } else { 1 })
            .ok_or("pointer_bytes")?;
    }
    if size > max {
        return Err("pointer_bytes");
    }
    let mut out = String::with_capacity(size);
    out.push_str(base);
    out.push('/');
    for ch in token.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            _ => out.push(ch),
        }
    }
    Ok(out)
}

// An instance location as a parent-linked list of borrowed tokens. Clones
// share the parent, and the pointer text is made only for a report, so a
// pending child costs one small node, not a copy of its parent's pointer.
#[derive(Clone, Copy)]
enum Token<'v> {
    Index(usize),
    Name(&'v str),
}
struct Step<'v> {
    parent: InstancePath<'v>,
    token: Token<'v>,
}
#[derive(Clone, Default)]
struct InstancePath<'v> {
    last: Option<std::rc::Rc<Step<'v>>>,
    bytes: usize,
}
impl<'v> InstancePath<'v> {
    fn child(&self, token: Token<'v>, max: usize) -> Result<Self, &'static str> {
        let size = match token {
            Token::Index(i) => i.checked_ilog10().unwrap_or(0) as usize + 1,
            Token::Name(name) => name
                .bytes()
                .try_fold(0usize, |n, b| {
                    n.checked_add(if matches!(b, b'~' | b'/') { 2 } else { 1 })
                })
                .ok_or("pointer_bytes")?,
        };
        let bytes = self
            .bytes
            .checked_add(1)
            .and_then(|n| n.checked_add(size))
            .filter(|&n| n <= max)
            .ok_or("pointer_bytes")?;
        Ok(Self {
            last: Some(std::rc::Rc::new(Step {
                parent: self.clone(),
                token,
            })),
            bytes,
        })
    }
    fn render(&self) -> String {
        let mut tokens = Vec::new();
        let mut at = self;
        while let Some(step) = &at.last {
            tokens.push(step.token);
            at = &step.parent;
        }
        let mut out = String::with_capacity(self.bytes);
        for token in tokens.into_iter().rev() {
            out.push('/');
            match token {
                Token::Index(i) => out.push_str(&i.to_string()),
                Token::Name(name) => {
                    for ch in name.chars() {
                        match ch {
                            '~' => out.push_str("~0"),
                            '/' => out.push_str("~1"),
                            _ => out.push(ch),
                        }
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug)]
struct InputError {
    path: String,
    limit: Option<&'static str>,
}
fn inspect(value: &Value, limits: &Limits, max_nodes: usize) -> Result<usize, InputError> {
    fn visit(
        v: &Value,
        path: &InstancePath<'_>,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
        l: &Limits,
        cap: usize,
    ) -> Result<(), InputError> {
        let err = |limit| InputError {
            path: path.render(),
            limit,
        };
        if depth > l.depth {
            return Err(err(Some("depth")));
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > cap {
            return Err(err(Some("max_nodes")));
        }
        *bytes = bytes.saturating_add(1);
        match v {
            Value::String(s) => *bytes = bytes.saturating_add(s.len()),
            Value::Number(n) => {
                *bytes = bytes.saturating_add(n.text().len());
                Decimal::new(n, l).map_err(|s| err(Some(s)))?;
            }
            Value::Array(a) => {
                if a.len() > cap.saturating_sub(*nodes) {
                    return Err(err(Some("max_nodes")));
                }
                for (i, child) in a.iter().enumerate() {
                    let p = path
                        .child(Token::Index(i), l.pointer_bytes)
                        .map_err(|s| err(Some(s)))?;
                    visit(child, &p, depth + 1, nodes, bytes, l, cap)?;
                }
            }
            Value::Object(o) => {
                if o.len() > cap.saturating_sub(*nodes) {
                    return Err(err(Some("max_nodes")));
                }
                let mut names = BTreeSet::new();
                for (key, child) in o {
                    *bytes = bytes.saturating_add(key.len());
                    if *bytes > l.bytes {
                        return Err(err(Some("bytes")));
                    }
                    let p = path
                        .child(Token::Name(key), l.pointer_bytes)
                        .map_err(|s| err(Some(s)))?;
                    if !names.insert(key) {
                        return Err(InputError {
                            path: p.render(),
                            limit: None,
                        });
                    }
                    visit(child, &p, depth + 1, nodes, bytes, l, cap)?;
                }
            }
            _ => {}
        }
        if *bytes > l.bytes {
            return Err(err(Some("bytes")));
        }
        Ok(())
    }
    let (mut nodes, mut bytes) = (0, 0);
    let root = InstancePath::default();
    visit(value, &root, 0, &mut nodes, &mut bytes, limits, max_nodes)?;
    Ok(bytes)
}

// Normalized coefficient digits times 10^exponent. Zero has empty digits.
#[derive(Clone, Debug)]
struct Decimal {
    negative: bool,
    digits: Vec<u8>,
    exponent: i64,
}
impl Decimal {
    fn new(number: &Number, limits: &Limits) -> Result<Self, &'static str> {
        let text = number.text();
        let (mantissa, exp) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
        let exponent: i64 = exp.parse().map_err(|_| "number_exponent")?;
        if exponent.unsigned_abs() > limits.number_exponent as u64 {
            return Err("number_exponent");
        }
        let fraction = mantissa.split_once('.').map_or(0, |(_, s)| s.len());
        let mut digits: Vec<u8> = mantissa
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect();
        let first = digits.iter().position(|&d| d != 0).unwrap_or(digits.len());
        digits.drain(..first);
        let mut exponent = exponent - fraction as i64;
        while digits.last() == Some(&0) {
            digits.pop();
            exponent += 1;
        }
        if digits.is_empty() {
            exponent = 0;
        }
        Ok(Self {
            negative: text.starts_with('-') && !digits.is_empty(),
            digits,
            exponent,
        })
    }
    fn integer(&self) -> bool {
        self.digits.is_empty() || self.exponent >= 0
    }
    fn cmp(&self, other: &Self) -> Ordering {
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let magnitude = if self.digits.is_empty() || other.digits.is_empty() {
            self.digits.len().cmp(&other.digits.len())
        } else {
            (self.digits.len() as i64 + self.exponent)
                .cmp(&(other.digits.len() as i64 + other.exponent))
                .then_with(|| {
                    for i in 0..self.digits.len().max(other.digits.len()) {
                        let c = self
                            .digits
                            .get(i)
                            .unwrap_or(&0)
                            .cmp(other.digits.get(i).unwrap_or(&0));
                        if c != Ordering::Equal {
                            return c;
                        }
                    }
                    Ordering::Equal
                })
        };
        if self.negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
    fn count(n: usize) -> Self {
        Self {
            negative: false,
            digits: if n == 0 {
                vec![]
            } else {
                n.to_string().bytes().map(|b| b - b'0').collect()
            },
            exponent: 0,
        }
    }
    fn as_usize(&self) -> Option<usize> {
        if self.negative || !self.integer() {
            return None;
        }
        if self.digits.is_empty() {
            return Some(0);
        }
        if self.exponent > usize::BITS as i64 {
            return None;
        }
        let mut n = 0usize;
        for &d in &self.digits {
            n = n.checked_mul(10)?.checked_add(d as usize)?;
        }
        for _ in 0..self.exponent {
            n = n.checked_mul(10)?;
        }
        Some(n)
    }
    // The coefficient remainder is exact. Trailing zeros of the dividend use
    // square-and-multiply, so the cost grows with log(shift), not shift.
    fn multiple(&self, divisor: &Self, work: &mut Work) -> Result<bool, &'static str> {
        if self.digits.is_empty() {
            return Ok(true);
        }
        let shift = self.exponent - divisor.exponent;
        if shift < 0 {
            return Ok(false);
        }
        let d = &divisor.digits;
        let r = remainder(&self.digits, d, work)?;
        if r.is_empty() || shift == 0 {
            return Ok(r.is_empty());
        }
        // power = 10^shift mod d, built from the most significant bit down.
        let ten = remainder(&[1, 0], d, work)?;
        let mut power = remainder(&[1], d, work)?;
        for bit in (0..u64::BITS - (shift as u64).leading_zeros()).rev() {
            power = remainder(&product(&power, &power, work)?, d, work)?;
            if (shift as u64 >> bit) & 1 == 1 {
                power = remainder(&product(&power, &ten, work)?, d, work)?;
            }
        }
        Ok(remainder(&product(&r, &power, work)?, d, work)?.is_empty())
    }
    fn number(&self) -> Option<Value> {
        let mut text = if self.negative {
            "-".into()
        } else {
            String::new()
        };
        if self.digits.is_empty() {
            text.push('0');
        }
        for &digit in &self.digits {
            text.push(char::from(b'0' + digit));
        }
        if self.exponent != 0 {
            text.push_str(&format!("e{}", self.exponent));
        }
        Number::from_text(&text).map(Value::Number)
    }
}
// Big-endian decimal digits without leading zeros; zero is empty.
fn remainder(dividend: &[u8], divisor: &[u8], work: &mut Work) -> Result<Vec<u8>, &'static str> {
    let mut r = Vec::<u8>::with_capacity(divisor.len().saturating_add(1));
    for &digit in dividend {
        work.spend(divisor.len().saturating_mul(12).saturating_add(1))?;
        if !r.is_empty() || digit != 0 {
            r.push(digit);
        }
        while r.len() > divisor.len() || (r.len() == divisor.len() && r.as_slice() >= divisor) {
            let mut borrow = 0i16;
            for i in 0..r.len() {
                let at = r.len() - 1 - i;
                let d = divisor.len().checked_sub(i + 1).map_or(0, |j| divisor[j]);
                let n = i16::from(r[at]) - i16::from(d) - borrow;
                r[at] = n.rem_euclid(10) as u8;
                borrow = i16::from(n < 0);
            }
            let first = r.iter().position(|&d| d != 0).unwrap_or(r.len());
            r.drain(..first);
        }
    }
    Ok(r)
}
fn product(a: &[u8], b: &[u8], work: &mut Work) -> Result<Vec<u8>, &'static str> {
    if a.is_empty() || b.is_empty() {
        return Ok(Vec::new());
    }
    work.spend(a.len().saturating_mul(b.len()).saturating_add(1))?;
    let mut sum = vec![0u32; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate().rev() {
        let mut carry = 0u32;
        for (j, &y) in b.iter().enumerate().rev() {
            let t = sum[i + j + 1] + u32::from(x) * u32::from(y) + carry;
            sum[i + j + 1] = t % 10;
            carry = t / 10;
        }
        sum[i] += carry;
    }
    let first = sum.iter().position(|&d| d != 0).unwrap_or(sum.len());
    Ok(sum[first..].iter().map(|&d| d as u8).collect())
}
struct Work {
    left: usize,
}
impl Work {
    fn spend(&mut self, n: usize) -> Result<(), &'static str> {
        self.left = self.left.checked_sub(n).ok_or("work")?;
        Ok(())
    }
}

const NULL: u8 = 1;
const BOOL: u8 = 2;
const NUMBER: u8 = 4;
const INTEGER: u8 = 8;
const STRING: u8 = 16;
const ARRAY: u8 = 32;
const OBJECT: u8 = 64;
const ANY: u8 = 127;
fn type_bit(s: &str) -> Option<u8> {
    match s {
        "null" => Some(NULL),
        "boolean" => Some(BOOL),
        "number" => Some(NUMBER),
        "integer" => Some(INTEGER),
        "string" => Some(STRING),
        "array" => Some(ARRAY),
        "object" => Some(OBJECT),
        _ => None,
    }
}

// Each source edge is stored once. Complete pointers are made for reports only.
#[derive(Clone, Debug)]
struct Location {
    parent: Option<usize>,
    token: String,
    bytes: usize,
}
#[derive(Clone, Debug, Default)]
struct Paths(Vec<Location>);
impl Paths {
    fn root(&mut self) -> usize {
        let id = self.0.len();
        self.0.push(Location {
            parent: None,
            token: String::new(),
            bytes: 0,
        });
        id
    }
    fn child(&mut self, parent: usize, token: &str, max: usize) -> Result<usize, &'static str> {
        let bytes = token.bytes().try_fold(
            self.0[parent].bytes.checked_add(1).ok_or("pointer_bytes")?,
            |n, b| {
                n.checked_add(if matches!(b, b'~' | b'/') { 2 } else { 1 })
                    .ok_or("pointer_bytes")
            },
        )?;
        if bytes > max {
            return Err("pointer_bytes");
        }
        let id = self.0.len();
        self.0.push(Location {
            parent: Some(parent),
            token: token.into(),
            bytes,
        });
        Ok(id)
    }
    fn render(&self, mut id: usize) -> String {
        let mut tokens = Vec::new();
        let mut out = String::with_capacity(self.0[id].bytes);
        while let Some(parent) = self.0[id].parent {
            tokens.push(self.0[id].token.as_str());
            id = parent;
        }
        for token in tokens.into_iter().rev() {
            out.push('/');
            for ch in token.chars() {
                match ch {
                    '~' => out.push_str("~0"),
                    '/' => out.push_str("~1"),
                    _ => out.push(ch),
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy)]
enum SourceKind {
    Schema,
    Map,
    Array,
    Data,
    Definitions,
}
impl SourceKind {
    fn child(self, key: &str) -> Self {
        match self {
            Self::Map | Self::Array => Self::Schema,
            Self::Schema => match key {
                "$defs" | "definitions" => Self::Definitions,
                "properties" | "dependentSchemas" | "patternProperties" => Self::Map,
                "prefixItems" | "allOf" | "anyOf" | "oneOf" => Self::Array,
                "items"
                | "contains"
                | "additionalProperties"
                | "propertyNames"
                | "not"
                | "if"
                | "then"
                | "else" => Self::Schema,
                _ => Self::Data,
            },
            _ => Self::Data,
        }
    }
}

struct Compiler<'a> {
    root: &'a Value,
    options: Options,
    queue: Vec<(&'a Value, usize)>,
    ids: BTreeMap<*const Value, usize>,
    locations: BTreeMap<*const Value, usize>,
    checked: BTreeSet<*const Value>,
    paths: Paths,
    size: usize,
    anchors: BTreeMap<String, usize>,
    refs: Vec<(usize, String)>,
    entry: Option<(&'a Value, String)>,
    nodes: Vec<Node>,
    annotations: Vec<StoredAnnotation>,
    work: Work,
}
impl<'a> Compiler<'a> {
    fn error(&self, path: usize, kind: CompileKind) -> CompileError {
        CompileError {
            schema_path: self.paths.render(path),
            kind,
        }
    }
    fn location(
        &mut self,
        value: &'a Value,
        parent: usize,
        token: &str,
    ) -> Result<usize, CompileError> {
        if let Some(&id) = self.locations.get(&(value as *const Value)) {
            return Ok(id);
        }
        let id = self
            .paths
            .child(parent, token, self.options.limits.pointer_bytes)
            .map_err(|s| self.error(parent, CompileKind::Limit(s)))?;
        self.locations.insert(value, id);
        Ok(id)
    }
    fn at(&self, value: &Value) -> usize {
        self.locations[&(value as *const Value)]
    }
    fn spend(&mut self, amount: usize, path: usize) -> Result<(), CompileError> {
        self.work
            .spend(amount)
            .map_err(|s| self.error(path, CompileKind::Limit(s)))
    }
    fn inspect(&mut self, value: &'a Value, path: usize) -> Result<(), CompileError> {
        let mut stack = vec![(value, path, 0usize, SourceKind::Schema)];
        while let Some((v, p, depth, kind)) = stack.pop() {
            if matches!(kind, SourceKind::Definitions) {
                continue;
            }
            if !self.checked.insert(v as *const Value) {
                continue;
            }
            let l = self.options.limits;
            if depth > l.depth {
                return Err(self.error(p, CompileKind::Limit("depth")));
            }
            if self.checked.len() > l.schema_nodes {
                return Err(self.error(p, CompileKind::Limit("schema_nodes")));
            }
            let text_bytes = match v {
                Value::String(s) => s.len(),
                Value::Number(n) => n.text().len(),
                _ => 0,
            };
            let bytes = text_bytes
                .checked_add(1)
                .ok_or_else(|| self.error(p, CompileKind::Limit("bytes")))?;
            self.size = self
                .size
                .checked_add(bytes)
                .filter(|&n| n <= l.bytes)
                .ok_or_else(|| self.error(p, CompileKind::Limit("bytes")))?;
            self.spend(bytes, p)?;
            if let Value::Number(n) = v {
                Decimal::new(n, &l).map_err(|s| self.error(p, CompileKind::Limit(s)))?;
            }
            let children = match v {
                Value::Array(a) => a.len(),
                Value::Object(o) if matches!(kind, SourceKind::Schema) => {
                    let ref_only =
                        self.options.dialect == Dialect::OpenApi30 && v.get("$ref").is_some();
                    o.iter()
                        .filter(|(key, _)| {
                            (!ref_only || key == "$ref")
                                && !matches!(kind.child(key), SourceKind::Definitions)
                        })
                        .count()
                }
                Value::Object(o) => o.len(),
                _ => 0,
            };
            if children
                > l.schema_nodes
                    .saturating_sub(self.checked.len())
                    .saturating_sub(stack.len())
            {
                return Err(self.error(p, CompileKind::Limit("schema_nodes")));
            }
            match v {
                Value::Array(a) => {
                    for (i, child) in a.iter().enumerate().rev() {
                        let at = self.location(child, p, &i.to_string())?;
                        stack.push((child, at, depth + 1, kind.child("")));
                    }
                }
                Value::Object(o) => {
                    let ref_only = matches!(kind, SourceKind::Schema)
                        && self.options.dialect == Dialect::OpenApi30
                        && v.get("$ref").is_some();
                    let mut names = BTreeSet::new();
                    for (key, child) in o.iter().rev() {
                        if ref_only && key != "$ref" {
                            continue;
                        }
                        self.size = self
                            .size
                            .checked_add(key.len())
                            .filter(|&n| n <= l.bytes)
                            .ok_or_else(|| self.error(p, CompileKind::Limit("bytes")))?;
                        self.spend(key.len().saturating_add(1), p)?;
                        let at = self.location(child, p, key)?;
                        if !names.insert(key) {
                            return Err(self.error(at, CompileKind::DuplicateKey));
                        }
                        let child_kind = kind.child(key);
                        if !matches!(child_kind, SourceKind::Definitions) {
                            stack.push((child, at, depth + 1, child_kind));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn enqueue(&mut self, value: &'a Value, path: usize) -> Result<usize, CompileError> {
        self.spend(1, path)?;
        if let Some(&id) = self.ids.get(&(value as *const Value)) {
            return Ok(id);
        }
        self.inspect(value, path)?;
        let id = self.queue.len();
        self.ids.insert(value, id);
        self.queue.push((value, path));
        Ok(id)
    }
    fn resolve(&mut self, pointer: &str) -> Result<(&'a Value, usize), CompileKind> {
        use CompileKind::{InvalidReference, Limit};
        if pointer.len() > self.options.limits.pointer_bytes {
            return Err(Limit("pointer_bytes"));
        }
        let mut value = self.root;
        let mut path = 0;
        if pointer.is_empty() {
            return Ok((value, path));
        }
        for part in pointer
            .strip_prefix('/')
            .ok_or(InvalidReference)?
            .split('/')
        {
            self.work
                .spend(part.len().saturating_add(1))
                .map_err(Limit)?;
            let mut token = String::new();
            let mut chars = part.chars();
            while let Some(ch) = chars.next() {
                token.push(if ch == '~' {
                    match chars.next().ok_or(InvalidReference)? {
                        '0' => '~',
                        '1' => '/',
                        _ => return Err(InvalidReference),
                    }
                } else {
                    ch
                });
            }
            value = match value {
                Value::Object(o) => {
                    let mut found = None;
                    for (key, v) in o {
                        self.work
                            .spend(key.len().min(token.len()).saturating_add(1))
                            .map_err(Limit)?;
                        if key == &token {
                            if found.is_some() {
                                return Err(CompileKind::DuplicateKey);
                            }
                            found = Some(v);
                        }
                    }
                    found.ok_or(InvalidReference)?
                }
                Value::Array(a) => {
                    if token.is_empty()
                        || (token.len() > 1 && token.starts_with('0'))
                        || !token.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(InvalidReference);
                    }
                    a.get(token.parse::<usize>().map_err(|_| InvalidReference)?)
                        .ok_or(InvalidReference)?
                }
                _ => return Err(InvalidReference),
            };
            path = self.location(value, path, &token).map_err(|e| e.kind)?;
        }
        Ok((value, path))
    }
    // Anchor lookup is lazy. Pointer-only entry points never scan the document.
    // The search follows schema positions only, from the document root and from
    // the compile_at entry, so `$anchor` inside keyword data such as `examples`,
    // `const`, or extensions is never a target.
    fn anchor_pointer(&mut self, anchor: &str) -> Result<String, CompileKind> {
        use CompileKind::{InvalidAnchor, InvalidReference, Limit};
        let max = self.options.limits.pointer_bytes;
        let mut found: Option<(*const Value, String)> = None;
        let mut starts = vec![(self.root, String::new())];
        if let Some((value, pointer)) = &self.entry {
            starts.push((*value, pointer.clone()));
        }
        for (start, prefix) in starts {
            // Each frame holds a schema-position value, its pointer, and the
            // next member to visit with that member's source kind.
            let mut stack = vec![(start, prefix, 0usize, SourceKind::Schema)];
            while let Some((v, path, next, kind)) = stack.last_mut() {
                self.work.spend(1).map_err(Limit)?;
                let schema = matches!(kind, SourceKind::Schema);
                // A nested `$id` starts another resource; its anchors are not ours.
                let hidden = schema
                    && match self.options.dialect {
                        Dialect::OpenApi30 => v.get("$ref").is_some(),
                        Dialect::Draft202012 => {
                            !std::ptr::eq(*v, self.root) && v.get("$id").is_some()
                        }
                    };
                if *next == 0
                    && schema
                    && !hidden
                    && let Some(name) = v.get("$anchor").and_then(Value::as_str)
                {
                    self.work.spend(name.len()).map_err(Limit)?;
                    if name == anchor {
                        let at = *v as *const Value;
                        match &found {
                            Some((seen, _)) if *seen == at => {}
                            Some(_) => return Err(InvalidAnchor),
                            None => found = Some((at, path.clone())),
                        }
                    }
                }
                let child = match (&**v, *kind) {
                    (Value::Object(_), SourceKind::Schema) if hidden => None,
                    (Value::Object(o), SourceKind::Schema) => {
                        o.get(*next).map(|(k, c)| (k.as_str(), c, kind.child(k)))
                    }
                    (Value::Object(o), SourceKind::Map | SourceKind::Definitions) => o
                        .get(*next)
                        .map(|(k, c)| (k.as_str(), c, SourceKind::Schema)),
                    (Value::Array(a), SourceKind::Array) => {
                        a.get(*next).map(|c| ("", c, SourceKind::Schema))
                    }
                    _ => None,
                };
                let Some((key, child, child_kind)) = child else {
                    stack.pop();
                    continue;
                };
                let index = *next;
                *next += 1;
                if matches!(child_kind, SourceKind::Data)
                    || !matches!(child, Value::Object(_) | Value::Array(_))
                {
                    continue;
                }
                let token = if matches!(kind, SourceKind::Array) {
                    index.to_string()
                } else {
                    key.to_string()
                };
                self.work
                    .spend(token.len().saturating_add(1))
                    .map_err(Limit)?;
                let p = pointer(path, &token, max).map_err(Limit)?;
                stack.push((child, p, 0, child_kind));
            }
        }
        found.map(|(_, p)| p).ok_or(InvalidReference)
    }
    fn names(&self, v: &Value, p: usize) -> Result<Vec<String>, CompileError> {
        let invalid = || self.error(p, CompileKind::InvalidKeyword);
        let a = v.as_array().ok_or_else(invalid)?;
        let mut seen = BTreeSet::new();
        let mut names = Vec::new();
        for v in a {
            let s = v.as_str().ok_or_else(invalid)?;
            if !seen.insert(s) {
                return Err(invalid());
            }
            names.push(s.into());
        }
        Ok(names)
    }
    fn numeric(
        &self,
        v: &Value,
        p: usize,
        positive: bool,
        exclusive: bool,
    ) -> Result<Option<Decimal>, CompileError> {
        let invalid = || self.error(p, CompileKind::InvalidKeyword);
        if exclusive && self.options.dialect == Dialect::OpenApi30 {
            v.as_bool().ok_or_else(invalid)?;
            return Ok(None);
        }
        let n = Decimal::new(v.as_number().ok_or_else(invalid)?, &self.options.limits)
            .map_err(|s| self.error(p, CompileKind::Limit(s)))?;
        if positive && (n.negative || n.digits.is_empty()) {
            return Err(invalid());
        }
        Ok(Some(n))
    }
    fn count(&self, v: &Value, p: usize) -> Result<Decimal, CompileError> {
        let invalid = || self.error(p, CompileKind::InvalidKeyword);
        let n = Decimal::new(v.as_number().ok_or_else(invalid)?, &self.options.limits)
            .map_err(|s| self.error(p, CompileKind::Limit(s)))?;
        if n.negative || !n.integer() {
            return Err(invalid());
        }
        Ok(n)
    }
    fn group(&mut self, v: &'a Value, p: usize) -> Result<Vec<usize>, CompileError> {
        let a = v
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| self.error(p, CompileKind::InvalidKeyword))?;
        a.iter().map(|v| self.enqueue(v, self.at(v))).collect()
    }
    fn node(&mut self, id: usize) -> Result<Node, CompileError> {
        let (value, path) = self.queue[id];
        let mut node = Node {
            path,
            ..Node::default()
        };
        if let Value::Bool(b) = value {
            node.reject = !b;
            return Ok(node);
        }
        let object = value
            .as_object()
            .ok_or_else(|| self.error(path, CompileKind::InvalidKeyword))?;
        // OAS 3.0 Reference Objects have no effective siblings.
        let ref_only = self.options.dialect == Dialect::OpenApi30 && value.get("$ref").is_some();
        for (key, v) in object {
            if ref_only && key != "$ref" {
                continue;
            }
            let p = self.location(v, path, key)?;
            self.work
                .spend(key.len().saturating_add(1))
                .map_err(|s| self.error(p, CompileKind::Limit(s)))?;
            let invalid = || CompileError {
                schema_path: self.paths.render(p),
                kind: CompileKind::InvalidKeyword,
            };
            match key.as_str() {
                "type" => {
                    let strings: Vec<&str> = if let Some(s) = v.as_str() {
                        vec![s]
                    } else if self.options.dialect == Dialect::Draft202012 {
                        let a = v.as_array().ok_or_else(invalid)?;
                        if a.is_empty() {
                            return Err(invalid());
                        }
                        a.iter()
                            .map(|v| v.as_str().ok_or_else(invalid))
                            .collect::<Result<_, _>>()?
                    } else {
                        return Err(invalid());
                    };
                    let mut mask = 0;
                    for s in strings {
                        let bit = type_bit(s).ok_or_else(invalid)?;
                        if bit & mask != 0
                            || (self.options.dialect == Dialect::OpenApi30 && bit == NULL)
                        {
                            return Err(invalid());
                        }
                        mask |= bit;
                    }
                    node.types = Some(mask);
                }
                "nullable" if self.options.dialect == Dialect::OpenApi30 => {
                    v.as_bool().ok_or_else(invalid)?;
                }
                "enum" => {
                    node.enumeration = Some(v.as_array().ok_or_else(invalid)?.to_vec());
                }
                "const" => node.constant = Some(v.clone()),
                "minimum" => node.minimum = self.numeric(v, p, false, false)?,
                "maximum" => node.maximum = self.numeric(v, p, false, false)?,
                "exclusiveMinimum" => node.exclusive_minimum = self.numeric(v, p, false, true)?,
                "exclusiveMaximum" => node.exclusive_maximum = self.numeric(v, p, false, true)?,
                "multipleOf" => node.multiple_of = self.numeric(v, p, true, false)?,
                "minLength" => node.min_length = Some(self.count(v, p)?),
                "maxLength" => node.max_length = Some(self.count(v, p)?),
                "minItems" => node.min_items = Some(self.count(v, p)?),
                "maxItems" => node.max_items = Some(self.count(v, p)?),
                "minContains" => node.min_contains = Some(self.count(v, p)?),
                "maxContains" => node.max_contains = Some(self.count(v, p)?),
                "minProperties" => node.min_properties = Some(self.count(v, p)?),
                "maxProperties" => node.max_properties = Some(self.count(v, p)?),
                "uniqueItems" => node.unique = v.as_bool().ok_or_else(invalid)?,
                "required" => node.required = self.names(v, p)?,
                "dependentRequired" => {
                    for (name, required) in v.as_object().ok_or_else(invalid)? {
                        node.dependent
                            .insert(name.clone(), self.names(required, self.at(required))?);
                    }
                }
                "$defs" | "definitions" => {
                    v.as_object().ok_or_else(invalid)?;
                }
                "properties" | "dependentSchemas" | "patternProperties" => {
                    let entries = v.as_object().ok_or_else(invalid)?;
                    if key == "patternProperties" {
                        if self.options.patterns == PatternPolicy::Reject {
                            return Err(self.error(p, CompileKind::UnsupportedPattern));
                        }
                        self.annotations.push(StoredAnnotation {
                            path: p,
                            keyword: "patternProperties",
                            value: v.clone(),
                        });
                    }
                    for (name, child) in entries {
                        let at = self.enqueue(child, self.at(child))?;
                        if key == "properties" {
                            node.properties.insert(name.clone(), at);
                        } else if key == "dependentSchemas" {
                            node.dependent_schemas.insert(name.clone(), at);
                        }
                    }
                }
                "items" => node.items = Some(self.enqueue(v, p)?),
                "contains" => node.contains = Some(self.enqueue(v, p)?),
                "additionalProperties" => node.additional_properties = Some(self.enqueue(v, p)?),
                "propertyNames" => node.property_names = Some(self.enqueue(v, p)?),
                "not" => node.not = Some(self.enqueue(v, p)?),
                "if" => node.condition = Some(self.enqueue(v, p)?),
                "then" => node.then_schema = Some(self.enqueue(v, p)?),
                "else" => node.else_schema = Some(self.enqueue(v, p)?),
                "prefixItems" => node.prefix_items = Some(self.group(v, p)?),
                "allOf" => node.all_of = Some(self.group(v, p)?),
                "anyOf" => node.any_of = Some(self.group(v, p)?),
                "oneOf" => node.one_of = Some(self.group(v, p)?),
                "pattern" | "format" => {
                    let name = v.as_str().ok_or_else(invalid)?;
                    if key == "format" {
                        node.format = Some(name.into());
                    }
                    let k = if key == "pattern" {
                        "pattern"
                    } else {
                        "format"
                    };
                    if k == "pattern" && self.options.patterns == PatternPolicy::Reject {
                        return Err(self.error(p, CompileKind::UnsupportedPattern));
                    }
                    self.annotations.push(StoredAnnotation {
                        path: p,
                        keyword: k,
                        value: v.clone(),
                    });
                }
                "$anchor" => {
                    let s = v.as_str().ok_or_else(invalid)?;
                    if !simple_anchor(s) || self.anchors.insert(s.into(), id).is_some() {
                        return Err(self.error(p, CompileKind::InvalidAnchor));
                    }
                }
                "$ref" => {
                    let s = v.as_str().ok_or_else(invalid)?;
                    if !s.starts_with('#') {
                        return Err(self.error(p, CompileKind::ExternalReference));
                    }
                    self.refs.push((id, s.into()));
                }
                // Only the document root may name a resource. A nested `$id`
                // would change the base for references and anchors below it.
                "$id" if self.options.dialect == Dialect::Draft202012 => {
                    v.as_str().ok_or_else(invalid)?;
                    if path != 0 {
                        return Err(self.error(p, CompileKind::UnsupportedKeyword(key.clone())));
                    }
                }
                "default" | "example" => node.hints.push(v.clone()),
                "examples" => {
                    if let Some(a) = v.as_array() {
                        node.hints.extend_from_slice(a);
                    } else if self.options.dialect != Dialect::OpenApi30 {
                        return Err(invalid());
                    }
                }
                "unevaluatedProperties"
                | "unevaluatedItems"
                | "$dynamicRef"
                | "$dynamicAnchor"
                | "$recursiveRef"
                | "contentSchema" => {
                    return Err(self.error(p, CompileKind::UnsupportedKeyword(key.clone())));
                }
                _ => {}
            }
        }
        if self.options.dialect == Dialect::OpenApi30 {
            if value.get("nullable").and_then(Value::as_bool) == Some(true)
                && let Some(mask) = &mut node.types
            {
                *mask |= NULL;
            }
            if value.get("exclusiveMinimum").and_then(Value::as_bool) == Some(true) {
                node.exclusive_minimum = node.minimum.take();
            }
            if value.get("exclusiveMaximum").and_then(Value::as_bool) == Some(true) {
                node.exclusive_maximum = node.maximum.take();
            }
        }
        Ok(node)
    }
    fn finish(mut self, entry: &str) -> Result<Schema, CompileError> {
        let (value, path) = self.resolve(entry).map_err(|kind| CompileError {
            schema_path: {
                let mut end = entry.len().min(self.options.limits.pointer_bytes);
                while !entry.is_char_boundary(end) {
                    end -= 1;
                }
                entry[..end].into()
            },
            kind,
        })?;
        if !entry.is_empty() {
            self.entry = Some((value, entry.into()));
        }
        self.enqueue(value, path)?;
        let mut resolved = 0;
        loop {
            while self.nodes.len() < self.queue.len() {
                let node = self.node(self.nodes.len())?;
                self.nodes.push(node);
            }
            if resolved == self.refs.len() {
                break;
            }
            while resolved < self.refs.len() {
                let (id, reference) = self.refs[resolved].clone();
                resolved += 1;
                let source = self.queue[id].0;
                let p = source
                    .get("$ref")
                    .map_or(self.nodes[id].path, |v| self.at(v));
                self.spend(reference.len(), p)?;
                let fragment = decode_fragment(&reference[1..])
                    .ok_or_else(|| self.error(p, CompileKind::InvalidReference))?;
                let pointer = if fragment.is_empty() || fragment.starts_with('/') {
                    fragment
                } else {
                    self.anchor_pointer(&fragment)
                        .map_err(|kind| self.error(p, kind))?
                };
                let (value, path) = self.resolve(&pointer).map_err(|kind| self.error(p, kind))?;
                let target = self.enqueue(value, path)?;
                self.nodes[id].reference = Some(target);
            }
        }
        Ok(Schema {
            nodes: self.nodes,
            paths: self.paths,
            annotations: self.annotations,
            options: self.options,
            size: self.size,
        })
    }
}

fn simple_anchor(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}
fn decode_fragment(s: &str) -> Option<String> {
    String::from_utf8(ascii::percent_decode_strict(s.as_bytes())?).ok()
}

impl Schema {
    /// Compiles a boolean or object schema with default options.
    pub fn compile(source: &Value) -> Result<Self, CompileError> {
        Self::compile_with(source, Options::default())
    }
    /// Compiles the document's root schema. This is `compile_at(source, "", options)`.
    pub fn compile_with(source: &Value, options: Options) -> Result<Self, CompileError> {
        Self::compile_at(source, "", options)
    }
    /// Compiles the schema at a JSON Pointer, resolving local references against
    /// `document`. Only reachable schemas and their keyword data spend the source
    /// node, byte, and depth limits. Unused definitions and document siblings are
    /// not compiled. Reference targets start at depth zero; repeated values count
    /// once. Pointer lookup spends work, but does not preflight the document.
    /// Anchor references require a lazy, work-bounded document search.
    /// No source data is borrowed by the returned schema.
    pub fn compile_at(
        document: &Value,
        entry: &str,
        mut options: Options,
    ) -> Result<Self, CompileError> {
        options.limits = options.limits.bounded();
        let mut paths = Paths::default();
        let root = paths.root();
        Compiler {
            root: document,
            options,
            queue: Vec::new(),
            ids: BTreeMap::new(),
            locations: BTreeMap::from([(document as *const Value, root)]),
            checked: BTreeSet::new(),
            paths,
            size: 0,
            anchors: BTreeMap::new(),
            refs: Vec::new(),
            entry: None,
            nodes: Vec::new(),
            annotations: Vec::new(),
            work: Work {
                left: options.limits.work,
            },
        }
        .finish(entry)
    }
    /// Returns the effective options, including stack and arithmetic ceilings.
    pub fn options(&self) -> Options {
        self.options
    }
    /// Returns format and ignored regex keywords in reachable schemas.
    /// These are static metadata, not a record of successful evaluation paths.
    /// Pointers and values are materialized only when this method is called.
    pub fn annotations(&self) -> Vec<Annotation> {
        self.annotations
            .iter()
            .map(|a| Annotation {
                schema_path: self.paths.render(a.path),
                keyword: a.keyword,
                value: a.value.clone(),
            })
            .collect()
    }
    /// Validates an instance, stopping at the first failed assertion.
    pub fn validate(&self, instance: &Value) -> Validation {
        self.validate_with(instance, ErrorMode::First)
    }
    /// Validates with the selected error policy. Fatal errors in speculative
    /// branches propagate; they cannot satisfy `not` or be hidden by `anyOf`.
    pub fn validate_with(&self, instance: &Value, mode: ErrorMode) -> Validation {
        let mut report = Validation {
            errors: Vec::new(),
            truncated: false,
        };
        let l = &self.options.limits;
        let size = match inspect(instance, l, l.instance_nodes) {
            Ok(size) => size,
            Err(e) => {
                report.errors.push(ValidationError {
                    instance_path: e.path,
                    schema_path: String::new(),
                    kind: match e.limit {
                        Some("max_nodes") => ValidationKind::Limit("instance_nodes"),
                        Some(l) => ValidationKind::Limit(l),
                        None => ValidationKind::DuplicateKey,
                    },
                });
                report.truncated = true;
                return report;
            }
        };
        let mut work = Work {
            left: self.budget(size),
        };
        let mut eval = Eval {
            schema: self,
            work: &mut work,
            active: BTreeSet::new(),
            errors: Vec::new(),
            cap: if mode == ErrorMode::First {
                1
            } else {
                l.errors.max(1)
            },
            truncated: false,
        };
        if let Err(e) = eval.run(0, instance, 0, 0, true) {
            if eval.errors.len() >= eval.cap {
                eval.errors.pop();
            }
            eval.errors.push(e);
            eval.truncated = true;
        }
        report.errors = eval.errors;
        report.truncated = eval.truncated;
        report
    }
    fn budget(&self, size: usize) -> usize {
        self.options.limits.work.min(
            self.size
                .saturating_add(1)
                .saturating_mul(size.saturating_add(1))
                .saturating_mul(self.options.limits.work_per_pair),
        )
    }
}

fn equal(a: &Value, b: &Value, limits: &Limits, work: &mut Work) -> Result<bool, &'static str> {
    work.spend(1)?;
    Ok(match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            work.spend(a.text().len().saturating_add(b.text().len()))?;
            Decimal::new(a, limits)?.cmp(&Decimal::new(b, limits)?) == Ordering::Equal
        }
        (Value::String(a), Value::String(b)) => {
            work.spend(a.len().min(b.len()))?;
            a == b
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (a, b) in a.iter().zip(b) {
                if !equal(a, b, limits, work)? {
                    return Ok(false);
                }
            }
            true
        }
        (Value::Object(a), Value::Object(b)) => {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (key, value) in a {
                let mut found = None;
                for (other, v) in b {
                    work.spend(key.len().min(other.len()).saturating_add(1))?;
                    if key == other {
                        found = Some(v);
                        break;
                    }
                }
                if !match found {
                    Some(v) => equal(value, v, limits, work)?,
                    None => false,
                } {
                    return Ok(false);
                }
            }
            true
        }
        _ => false,
    })
}

fn digits(bytes: &[u8]) -> Option<u32> {
    ascii::decimal(bytes, usize::MAX, u64::from(u32::MAX)).map(|n| n as u32)
}
fn date_parts(s: &str) -> Option<(u32, u32, u32)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (year, month, day) = (digits(&b[..4])?, digits(&b[5..7])?, digits(&b[8..])?);
    let leap = fictionet::stdlib::codec::civil::is_leap_year(i64::from(year));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return None,
    };
    (day > 0 && day <= days).then_some((year, month, day))
}
// Returns whether this is a leap second and whether its UTC date is yesterday.
fn time_parts(s: &str) -> Option<(bool, bool)> {
    let b = s.as_bytes();
    if b.len() < 9 || b[2] != b':' || b[5] != b':' {
        return None;
    }
    let (hour, minute, second) = (digits(&b[..2])?, digits(&b[3..5])?, digits(&b[6..8])?);
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut at = 8;
    if b.get(at) == Some(&b'.') {
        at += 1;
        let first = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if first == at {
            return None;
        }
    }
    let zone = b.get(at..)?;
    let offset = match zone {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return None;
            }
            (h as i32 * 60 + m as i32) * if *sign == b'-' { -1 } else { 1 }
        }
        _ => return None,
    };
    let utc = hour as i32 * 60 + minute as i32 - offset;
    if second == 60 && utc.rem_euclid(1440) != 1439 {
        return None;
    }
    Some((second == 60, utc < 0))
}
fn hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || s.len() > 254 {
        return false;
    }
    let valid_local =
        if let Some(quoted) = local.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            let mut bytes = quoted.bytes();
            let mut valid = true;
            while let Some(b) = bytes.next() {
                if b == b'\\' {
                    valid &= bytes.next().is_some_and(|b| (32..=126).contains(&b));
                } else {
                    valid &= (32..=126).contains(&b) && b != b'"';
                }
            }
            valid
        } else {
            local.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b))
            })
        };
    let valid_domain = if let Some(ip) = domain.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        if ip.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("IPv6:")) {
            ip[5..].parse::<std::net::Ipv6Addr>().is_ok()
        } else {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
        }
    } else {
        hostname(domain)
    };
    valid_local && valid_domain
}
fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~".contains(&b)
}
fn sub_delim(b: u8) -> bool {
    b"!$&'()*+,;=".contains(&b)
}
fn uri_component(s: &str, extra: &[u8]) -> bool {
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !(unreserved(b) || sub_delim(b) || extra.contains(&b)) {
            return false;
        }
    }
    true
}
fn uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return false;
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if !uri_component(query, b"/?@:") || !uri_component(fragment, b"/?@:") {
        return false;
    }
    let path = if let Some(rest) = path.strip_prefix("//") {
        let (authority, path) = rest
            .find('/')
            .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
        let host = if let Some((user, host)) = authority.rsplit_once('@') {
            if !uri_component(user, b":") {
                return false;
            }
            host
        } else {
            authority
        };
        let port = if let Some(ip) = host.strip_prefix('[') {
            let Some((ip, tail)) = ip.split_once(']') else {
                return false;
            };
            let valid = if let Some(future) = ip.strip_prefix(['v', 'V']) {
                future.split_once('.').is_some_and(|(version, address)| {
                    !version.is_empty()
                        && version.bytes().all(|b| b.is_ascii_hexdigit())
                        && !address.is_empty()
                        && address
                            .bytes()
                            .all(|b| unreserved(b) || sub_delim(b) || b == b':')
                })
            } else {
                ip.parse::<std::net::Ipv6Addr>().is_ok()
            };
            if !valid {
                return false;
            }
            if tail.is_empty() {
                ""
            } else if let Some(port) = tail.strip_prefix(':') {
                port
            } else {
                return false;
            }
        } else {
            let (host, port) = host.split_once(':').unwrap_or((host, ""));
            if !uri_component(host, b"") {
                return false;
            }
            port
        };
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        path
    } else {
        path
    };
    uri_component(path, b"/:@")
}
fn valid_format(format: &str, s: &str) -> bool {
    match format {
        "date" => date_parts(s).is_some(),
        "time" => time_parts(s).is_some(),
        "date-time" => {
            let Some((_, month, day)) = s.get(..10).and_then(date_parts) else {
                return false;
            };
            if !matches!(s.as_bytes().get(10), Some(b'T' | b't')) {
                return false;
            }
            let Some((leap, yesterday)) = s.get(11..).and_then(time_parts) else {
                return false;
            };
            !leap
                || if yesterday {
                    matches!((month, day), (1 | 7, 1))
                } else {
                    matches!((month, day), (6, 30) | (12, 31))
                }
        }
        "email" => email(s),
        "hostname" => hostname(s),
        "uri" => uri(s),
        "uuid" => {
            s.len() == 36
                && s.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
        }
        "ipv4" => s.parse::<std::net::Ipv4Addr>().is_ok(),
        "ipv6" => s.parse::<std::net::Ipv6Addr>().is_ok(),
        _ => true,
    }
}
fn hostname_example(n: usize) -> Option<String> {
    if !(1..=253).contains(&n) {
        return None;
    }
    let mut s = String::with_capacity(n);
    while s.len() < n {
        let remaining = n - s.len();
        let size = if remaining == 64 {
            62
        } else {
            remaining.min(63)
        };
        s.extend(std::iter::repeat_n('a', size));
        if s.len() < n {
            s.push('.');
        }
    }
    Some(s)
}
fn ipv4_example(n: usize) -> Option<String> {
    if !(7..=15).contains(&n) {
        return None;
    }
    let mut extra = n - 7;
    let mut parts = Vec::new();
    for _ in 0..4 {
        let width = extra.min(2);
        extra -= width;
        parts.push(["1", "10", "100"][width]);
    }
    Some(parts.join("."))
}
fn ipv6_example(n: usize) -> Option<String> {
    if n == 2 {
        return Some("::".into());
    }
    for groups in 1usize..=8 {
        let base = if groups == 8 { 15 } else { groups * 2 + 1 };
        if n >= base && n - base <= groups * 3 {
            let mut extra = n - base;
            let parts: Vec<_> = (0..groups)
                .map(|_| {
                    let add = extra.min(3);
                    extra -= add;
                    "1".repeat(add + 1)
                })
                .collect();
            return Some(parts.join(":") + if groups == 8 { "" } else { "::" });
        }
    }
    if (40..=45).contains(&n) {
        return Some(format!(
            "1111:1111:1111:1111:1111:1111:{}",
            ipv4_example(n - 30)?
        ));
    }
    None
}
fn format_example(format: &str, low: usize, high: usize) -> Option<String> {
    let sample = match format {
        "date-time" => "2000-01-01T00:00:00Z",
        "date" => "2000-01-01",
        "time" => "00:00:00Z",
        "email" => "a@example.test",
        "uuid" => "00000000-0000-4000-8000-000000000000",
        "uri" => "https://example.test/",
        "ipv4" => "192.0.2.1",
        "ipv6" => "2001:db8::1",
        "hostname" => "example.test",
        _ => return None,
    };
    if (low..=high).contains(&sample.len()) {
        return Some(sample.into());
    }
    let minimum = match format {
        "date-time" => 22,
        "time" => 11,
        "email" => 3,
        "uri" | "ipv6" => 2,
        "ipv4" => 7,
        "hostname" => 1,
        _ => return None,
    };
    let n = low.max(minimum);
    if n > high {
        return None;
    }
    let s = match format {
        "date-time" | "time" => format!(
            "{}.{}Z",
            sample.strip_suffix('Z')?,
            "0".repeat(n - sample.len() - 1)
        ),
        "email" if n <= 254 => {
            let local = (n - 2).min(64);
            format!("{}@{}", "a".repeat(local), hostname_example(n - local - 1)?)
        }
        "uri" => format!("a:{}", "x".repeat(n - 2)),
        "hostname" => hostname_example(n)?,
        "ipv4" => ipv4_example(n)?,
        "ipv6" => ipv6_example(n)?,
        _ => return None,
    };
    valid_format(format, &s).then_some(s)
}

// Fallible merge sort stops as soon as comparison work runs out.
fn sorted_indices(
    len: usize,
    mut compare: impl FnMut(usize, usize) -> Result<Ordering, &'static str>,
) -> Result<Vec<usize>, &'static str> {
    let mut order: Vec<_> = (0..len).collect();
    let mut next = Vec::with_capacity(len);
    let mut width = 1usize;
    while width < len {
        next.clear();
        let mut start = 0;
        while start < len {
            let mid = start.saturating_add(width).min(len);
            let end = mid.saturating_add(width).min(len);
            let (mut a, mut b) = (start, mid);
            while a < mid && b < end {
                if compare(order[a], order[b])? != Ordering::Greater {
                    next.push(order[a]);
                    a += 1;
                } else {
                    next.push(order[b]);
                    b += 1;
                }
            }
            next.extend_from_slice(&order[a..mid]);
            next.extend_from_slice(&order[b..end]);
            start = end;
        }
        std::mem::swap(&mut order, &mut next);
        width = width.saturating_mul(2);
    }
    Ok(order)
}
fn compare_bytes(a: &[u8], b: &[u8], work: &mut Work) -> Result<Ordering, &'static str> {
    for (a, b) in a.iter().zip(b) {
        work.spend(1)?;
        let order = a.cmp(b);
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    work.spend(1)?;
    Ok(a.len().cmp(&b.len()))
}
// This total order need only agree with JSON equality, not numeric magnitude.
// Numbers are normalized once; object keys are sorted once.
enum Canonical<'a> {
    Null,
    Bool(bool),
    Number(Decimal),
    String(&'a str),
    Array(Vec<Self>),
    Object(Vec<(&'a str, Self)>),
}
impl<'a> Canonical<'a> {
    fn new(v: &'a Value, limits: &Limits, work: &mut Work) -> Result<Self, &'static str> {
        work.spend(1)?;
        Ok(match v {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(*b),
            Value::Number(n) => {
                work.spend(n.text().len())?;
                Self::Number(Decimal::new(n, limits)?)
            }
            Value::String(s) => Self::String(s),
            Value::Array(a) => Self::Array(
                a.iter()
                    .map(|v| Self::new(v, limits, work))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(o) => {
                let order = sorted_indices(o.len(), |a, b| {
                    compare_bytes(o[a].0.as_bytes(), o[b].0.as_bytes(), work)
                })?;
                Self::Object(
                    order
                        .into_iter()
                        .map(|i| Ok((o[i].0.as_str(), Self::new(&o[i].1, limits, work)?)))
                        .collect::<Result<_, &'static str>>()?,
                )
            }
        })
    }
    fn tag(&self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Bool(_) => 1,
            Self::Number(_) => 2,
            Self::String(_) => 3,
            Self::Array(_) => 4,
            Self::Object(_) => 5,
        }
    }
    fn compare(&self, other: &Self, work: &mut Work) -> Result<Ordering, &'static str> {
        work.spend(1)?;
        Ok(match (self, other) {
            (Self::Null, Self::Null) => Ordering::Equal,
            (Self::Bool(a), Self::Bool(b)) => a.cmp(b),
            (Self::Number(a), Self::Number(b)) => {
                let order = a
                    .negative
                    .cmp(&b.negative)
                    .then(a.exponent.cmp(&b.exponent));
                if order == Ordering::Equal {
                    compare_bytes(&a.digits, &b.digits, work)?
                } else {
                    order
                }
            }
            (Self::String(a), Self::String(b)) => compare_bytes(a.as_bytes(), b.as_bytes(), work)?,
            (Self::Array(a), Self::Array(b)) => {
                for (a, b) in a.iter().zip(b) {
                    let order = a.compare(b, work)?;
                    if order != Ordering::Equal {
                        return Ok(order);
                    }
                }
                a.len().cmp(&b.len())
            }
            (Self::Object(a), Self::Object(b)) => {
                for ((ka, a), (kb, b)) in a.iter().zip(b) {
                    let order = compare_bytes(ka.as_bytes(), kb.as_bytes(), work)?;
                    if order != Ordering::Equal {
                        return Ok(order);
                    }
                    let order = a.compare(b, work)?;
                    if order != Ordering::Equal {
                        return Ok(order);
                    }
                }
                a.len().cmp(&b.len())
            }
            _ => self.tag().cmp(&other.tag()),
        })
    }
}
fn unique(items: &[Value], limits: &Limits, work: &mut Work) -> Result<bool, &'static str> {
    let keys: Vec<_> = items
        .iter()
        .map(|v| Canonical::new(v, limits, work))
        .collect::<Result<_, _>>()?;
    let order = sorted_indices(keys.len(), |a, b| keys[a].compare(&keys[b], work))?;
    for pair in order.windows(2) {
        if keys[pair[0]].compare(&keys[pair[1]], work)? == Ordering::Equal {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone)]
enum Instance<'a> {
    Value(&'a Value),
    Name(std::rc::Rc<Value>),
}
impl Instance<'_> {
    fn get(&self) -> &Value {
        match self {
            Self::Value(v) => v,
            Self::Name(v) => v,
        }
    }
}
struct Context<'a> {
    id: usize,
    value: Instance<'a>,
    path: InstancePath<'a>,
    depth: usize,
    refs: usize,
    collect: bool,
}
enum Check<'s, 'v> {
    Enter,
    Leaf,
    Prepare,
    Child(usize, Instance<'v>, InstancePath<'v>, usize),
    Group {
        keyword: &'static str,
        ids: &'s [usize],
        next: usize,
        count: usize,
    },
    Contains {
        schema: usize,
        items: &'v [Value],
        next: usize,
        count: usize,
    },
    Not(usize),
    If(usize),
}
struct Evaluation<'s, 'v> {
    context: Context<'v>,
    checks: Vec<Check<'s, 'v>>,
    waiting: Option<Check<'s, 'v>>,
    valid: bool,
}
impl<'s, 'v> Evaluation<'s, 'v> {
    fn new(context: Context<'v>) -> Self {
        Self {
            context,
            checks: vec![Check::Prepare, Check::Leaf, Check::Enter],
            waiting: None,
            valid: true,
        }
    }
}

struct Eval<'a, 'w> {
    schema: &'a Schema,
    work: &'w mut Work,
    active: BTreeSet<(usize, *const Value)>,
    errors: Vec<ValidationError>,
    cap: usize,
    truncated: bool,
}
impl<'s> Eval<'s, '_> {
    fn error(
        &self,
        id: usize,
        path: &InstancePath<'_>,
        keyword: &str,
        kind: ValidationKind,
    ) -> ValidationError {
        let base = self.schema.paths.render(self.schema.nodes[id].path);
        ValidationError {
            instance_path: path.render(),
            schema_path: if keyword.is_empty() {
                base.clone()
            } else {
                pointer(&base, keyword, self.schema.options.limits.pointer_bytes)
                    .unwrap_or_else(|_| base.clone())
            },
            kind,
        }
    }
    fn spend(
        &mut self,
        n: usize,
        id: usize,
        p: &InstancePath<'_>,
        keyword: &str,
    ) -> Result<(), ValidationError> {
        self.work
            .spend(n)
            .map_err(|s| self.error(id, p, keyword, ValidationKind::Limit(s)))
    }
    fn child_path<'v>(
        &self,
        id: usize,
        p: &InstancePath<'v>,
        token: Token<'v>,
    ) -> Result<InstancePath<'v>, ValidationError> {
        p.child(token, self.schema.options.limits.pointer_bytes)
            .map_err(|s| self.error(id, p, "", ValidationKind::Limit(s)))
    }
    fn assertion(
        &mut self,
        c: &Context<'_>,
        keyword: &'static str,
        ok: bool,
        kind: ValidationKind,
    ) -> bool {
        if !ok && c.collect {
            self.errors.push(self.error(c.id, &c.path, keyword, kind));
            self.truncated |= self.errors.len() >= self.cap;
        }
        ok
    }
    fn run(
        &mut self,
        id: usize,
        value: &Value,
        depth: usize,
        refs: usize,
        collect: bool,
    ) -> Result<bool, ValidationError> {
        let result = self.evaluate(Context {
            id,
            value: Instance::Value(value),
            path: InstancePath::default(),
            depth,
            refs,
            collect,
        });
        self.active.clear();
        result
    }
    fn evaluate<'v>(&mut self, context: Context<'v>) -> Result<bool, ValidationError> {
        let mut stack = vec![Evaluation::new(context)];
        let mut returned: Option<bool> = None;
        while let Some(frame) = stack.last_mut() {
            let c = &frame.context;
            let node = &self.schema.nodes[c.id];
            if let Some(passed) = returned.take() {
                match frame.waiting.take() {
                    Some(Check::Child(..)) => frame.valid &= passed,
                    Some(Check::Group {
                        keyword,
                        ids,
                        next,
                        count,
                    }) => {
                        frame.checks.push(Check::Group {
                            keyword,
                            ids,
                            next,
                            count: count + usize::from(passed),
                        });
                    }
                    Some(Check::Contains {
                        schema,
                        items,
                        next,
                        count,
                    }) => {
                        frame.checks.push(Check::Contains {
                            schema,
                            items,
                            next,
                            count: count + usize::from(passed),
                        });
                    }
                    Some(Check::Not(_)) => {
                        frame.valid &=
                            self.assertion(c, "not", !passed, ValidationKind::Assertion("not"))
                    }
                    Some(Check::If(_)) => {
                        if let Some(&id) = if passed {
                            node.then_schema.as_ref()
                        } else {
                            node.else_schema.as_ref()
                        } {
                            frame.checks.push(Check::Child(
                                id,
                                c.value.clone(),
                                c.path.clone(),
                                c.refs,
                            ));
                        }
                    }
                    _ => {}
                }
            }
            if !frame.valid && (!c.collect || self.errors.len() >= self.cap) {
                self.active.remove(&(c.id, c.value.get() as *const Value));
                stack.pop();
                returned = Some(false);
                continue;
            }
            let Some(check) = frame.checks.pop() else {
                let valid = frame.valid;
                self.active.remove(&(c.id, c.value.get() as *const Value));
                stack.pop();
                returned = Some(valid);
                continue;
            };
            let mut child = None;
            match check {
                Check::Enter => {
                    self.spend(1, c.id, &c.path, "")?;
                    if c.depth > self.schema.options.limits.validation_depth {
                        return Err(self.error(
                            c.id,
                            &c.path,
                            "",
                            ValidationKind::Limit("validation_depth"),
                        ));
                    }
                    if c.refs > self.schema.options.limits.ref_depth {
                        return Err(self.error(
                            c.id,
                            &c.path,
                            "$ref",
                            ValidationKind::Limit("ref_depth"),
                        ));
                    }
                    if !self.active.insert((c.id, c.value.get())) {
                        return Err(self.error(
                            c.id,
                            &c.path,
                            "$ref",
                            ValidationKind::ReferenceCycle,
                        ));
                    }
                    if node.reject {
                        if c.collect {
                            self.errors.push(self.error(
                                c.id,
                                &c.path,
                                "",
                                ValidationKind::FalseSchema,
                            ));
                            self.truncated |= self.errors.len() >= self.cap;
                        }
                        frame.valid = false;
                        frame.checks.clear();
                    } else if let Some(id) = node.reference {
                        frame.checks.push(Check::Child(
                            id,
                            c.value.clone(),
                            c.path.clone(),
                            c.refs.saturating_add(1),
                        ));
                    }
                }
                Check::Leaf => frame.valid &= self.leaf(c.id, c.value.get(), &c.path, c.collect)?,
                Check::Prepare => {
                    self.prepare(frame)?;
                }
                Check::Child(id, value, path, refs) => {
                    child = Some(Context {
                        id,
                        value: value.clone(),
                        path: path.clone(),
                        depth: c.depth.saturating_add(1),
                        refs,
                        collect: c.collect,
                    });
                    frame.waiting = Some(Check::Child(id, value, path, refs));
                }
                Check::Group {
                    keyword,
                    ids,
                    next,
                    count,
                } => {
                    if next == ids.len() || (keyword == "anyOf" && count > 0) {
                        frame.valid &= self.assertion(
                            c,
                            keyword,
                            if keyword == "anyOf" {
                                count > 0
                            } else {
                                count == 1
                            },
                            ValidationKind::Assertion(keyword),
                        );
                    } else {
                        child = Some(Context {
                            id: ids[next],
                            value: c.value.clone(),
                            path: c.path.clone(),
                            depth: c.depth.saturating_add(1),
                            refs: c.refs,
                            collect: false,
                        });
                        frame.waiting = Some(Check::Group {
                            keyword,
                            ids,
                            next: next + 1,
                            count,
                        });
                    }
                }
                Check::Contains {
                    schema,
                    items,
                    next,
                    count,
                } => {
                    if next == items.len() {
                        let count = Decimal::count(count);
                        let min = node
                            .min_contains
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| Decimal::count(1));
                        let keyword = if node.min_contains.is_some() {
                            "minContains"
                        } else {
                            "contains"
                        };
                        frame.valid &= self.assertion(
                            c,
                            keyword,
                            count.cmp(&min) != Ordering::Less,
                            ValidationKind::Assertion(keyword),
                        );
                        if (frame.valid || (c.collect && self.errors.len() < self.cap))
                            && let Some(max) = node.max_contains.as_ref()
                        {
                            frame.valid &= self.assertion(
                                c,
                                "maxContains",
                                count.cmp(max) != Ordering::Greater,
                                ValidationKind::Assertion("maxContains"),
                            );
                        }
                    } else {
                        let path = self.child_path(c.id, &c.path, Token::Index(next))?;
                        child = Some(Context {
                            id: schema,
                            value: Instance::Value(&items[next]),
                            path,
                            depth: c.depth.saturating_add(1),
                            refs: 0,
                            collect: false,
                        });
                        frame.waiting = Some(Check::Contains {
                            schema,
                            items,
                            next: next + 1,
                            count,
                        });
                    }
                }
                Check::Not(id) | Check::If(id) => {
                    child = Some(Context {
                        id,
                        value: c.value.clone(),
                        path: c.path.clone(),
                        depth: c.depth.saturating_add(1),
                        refs: c.refs,
                        collect: false,
                    });
                    frame.waiting = Some(check);
                }
            }
            if let Some(child) = child {
                stack.push(Evaluation::new(child));
            }
        }
        Ok(returned.unwrap_or(true))
    }
    fn prepare<'v>(&mut self, frame: &mut Evaluation<'s, 'v>) -> Result<(), ValidationError> {
        let c = &frame.context;
        let node = &self.schema.nodes[c.id];
        // Collect each node's direct checks once. Reference and branch execution
        // use the explicit evaluation stack, including property-name instances.
        let mut checks = Vec::new();
        if let Instance::Value(Value::Array(items)) = c.value {
            if node.unique {
                let ok = unique(items, &self.schema.options.limits, self.work).map_err(|s| {
                    self.error(c.id, &c.path, "uniqueItems", ValidationKind::Limit(s))
                })?;
                frame.valid &= self.assertion(
                    c,
                    "uniqueItems",
                    ok,
                    ValidationKind::Assertion("uniqueItems"),
                );
                if !frame.valid && (!c.collect || self.errors.len() >= self.cap) {
                    return Ok(());
                }
            }
            let prefix = node.prefix_items.as_deref().unwrap_or_default();
            for (i, v) in items.iter().enumerate() {
                self.spend(1, c.id, &c.path, "items")?;
                if let Some(&id) = prefix.get(i).or(node.items.as_ref()) {
                    checks.push(Check::Child(
                        id,
                        Instance::Value(v),
                        self.child_path(c.id, &c.path, Token::Index(i))?,
                        0,
                    ));
                }
            }
            if let Some(&schema) = node.contains.as_ref() {
                checks.push(Check::Contains {
                    schema,
                    items,
                    next: 0,
                    count: 0,
                });
            }
        }
        if let Instance::Value(Value::Object(object)) = c.value {
            let mut members = BTreeSet::new();
            for (name, _) in object {
                self.spend(name.len().saturating_add(1), c.id, &c.path, "properties")?;
                members.insert(name.as_str());
            }
            for name in &node.required {
                self.spend(name.len().saturating_add(1), c.id, &c.path, "required")?;
                frame.valid &= self.assertion(
                    c,
                    "required",
                    members.contains(name.as_str()),
                    ValidationKind::Missing(name.clone()),
                );
                if !frame.valid && (!c.collect || self.errors.len() >= self.cap) {
                    return Ok(());
                }
            }
            for (trigger, names) in &node.dependent {
                self.spend(
                    trigger.len().saturating_add(1),
                    c.id,
                    &c.path,
                    "dependentRequired",
                )?;
                if members.contains(trigger.as_str()) {
                    for name in names {
                        self.spend(
                            name.len().saturating_add(1),
                            c.id,
                            &c.path,
                            "dependentRequired",
                        )?;
                        frame.valid &= self.assertion(
                            c,
                            "dependentRequired",
                            members.contains(name.as_str()),
                            ValidationKind::Missing(name.clone()),
                        );
                        if !frame.valid && (!c.collect || self.errors.len() >= self.cap) {
                            return Ok(());
                        }
                    }
                }
            }
            for (trigger, &id) in &node.dependent_schemas {
                self.spend(
                    trigger.len().saturating_add(1),
                    c.id,
                    &c.path,
                    "dependentSchemas",
                )?;
                if members.contains(trigger.as_str()) {
                    checks.push(Check::Child(id, c.value.clone(), c.path.clone(), c.refs));
                }
            }
            for (name, v) in object {
                self.spend(1, c.id, &c.path, "properties")?;
                if let Some(&id) = node.property_names.as_ref() {
                    checks.push(Check::Child(
                        id,
                        Instance::Name(std::rc::Rc::new(Value::String(name.clone()))),
                        c.path.clone(),
                        0,
                    ));
                }
                if let Some(&id) = node
                    .properties
                    .get(name)
                    .or(node.additional_properties.as_ref())
                {
                    checks.push(Check::Child(
                        id,
                        Instance::Value(v),
                        self.child_path(c.id, &c.path, Token::Name(name))?,
                        0,
                    ));
                }
            }
        }
        if let Some(group) = node.all_of.as_ref() {
            self.spend(group.len(), c.id, &c.path, "allOf")?;
            for &id in group {
                checks.push(Check::Child(id, c.value.clone(), c.path.clone(), c.refs));
            }
        }
        for (keyword, group) in [("anyOf", &node.any_of), ("oneOf", &node.one_of)] {
            if let Some(ids) = group {
                checks.push(Check::Group {
                    keyword,
                    ids,
                    next: 0,
                    count: 0,
                });
            }
        }
        if let Some(&id) = node.not.as_ref() {
            checks.push(Check::Not(id));
        }
        if let Some(&id) = node.condition.as_ref() {
            checks.push(Check::If(id));
        }
        frame.checks.extend(checks.into_iter().rev());
        Ok(())
    }
    fn leaf(
        &mut self,
        id: usize,
        value: &Value,
        p: &InstancePath<'_>,
        collect: bool,
    ) -> Result<bool, ValidationError> {
        let node = &self.schema.nodes[id];
        let limits = &self.schema.options.limits;
        let mut valid = true;
        macro_rules! assertion {
            ($ok:expr, $key:expr) => {
                assertion!($ok, $key, ValidationKind::Assertion($key))
            };
            ($ok:expr, $key:expr, $kind:expr) => {
                if !$ok {
                    valid = false;
                    if !collect {
                        return Ok(false);
                    }
                    self.errors.push(self.error(id, p, $key, $kind));
                    if self.errors.len() >= self.cap {
                        self.truncated = true;
                        return Ok(false);
                    }
                }
            };
        }
        let decimal = if let Value::Number(n) = value {
            if node.types.is_some() || node.numeric_bounds().next().is_some() {
                self.spend(n.text().len(), id, p, "")?;
                Some(
                    Decimal::new(n, limits)
                        .map_err(|s| self.error(id, p, "", ValidationKind::Limit(s)))?,
                )
            } else {
                None
            }
        } else {
            None
        };
        if let Some(mask) = node.types {
            let bit = match value {
                Value::Null => NULL,
                Value::Bool(_) => BOOL,
                Value::String(_) => STRING,
                Value::Array(_) => ARRAY,
                Value::Object(_) => OBJECT,
                Value::Number(_) => {
                    if decimal.as_ref().is_some_and(Decimal::integer) {
                        NUMBER | INTEGER
                    } else {
                        NUMBER
                    }
                }
            };
            assertion!(mask & bit != 0, "type");
        }
        if let Some(c) = &node.constant {
            let same = equal(value, c, limits, self.work)
                .map_err(|s| self.error(id, p, "const", ValidationKind::Limit(s)))?;
            assertion!(same, "const");
        }
        if let Some(choices) = &node.enumeration {
            let mut found = false;
            for c in choices {
                if equal(value, c, limits, self.work)
                    .map_err(|s| self.error(id, p, "enum", ValidationKind::Limit(s)))?
                {
                    found = true;
                    break;
                }
            }
            assertion!(found, "enum");
        }
        if let Some(d) = &decimal {
            for (key, bound) in node.numeric_bounds() {
                self.spend(
                    d.digits.len().saturating_add(bound.digits.len()),
                    id,
                    p,
                    key,
                )?;
                let order = d.cmp(bound);
                let ok = match key {
                    "minimum" => order != Ordering::Less,
                    "maximum" => order != Ordering::Greater,
                    "exclusiveMinimum" => order == Ordering::Greater,
                    "exclusiveMaximum" => order == Ordering::Less,
                    _ => d
                        .multiple(bound, self.work)
                        .map_err(|s| self.error(id, p, key, ValidationKind::Limit(s)))?,
                };
                assertion!(ok, key);
            }
        }
        if self.schema.options.formats == FormatPolicy::Assert
            && let (Value::String(s), Some(format)) = (value, &node.format)
        {
            self.spend(s.len(), id, p, "format")?;
            assertion!(valid_format(format, s), "format");
        }
        let count = match value {
            Value::String(s) => {
                self.spend(s.len(), id, p, "minLength")?;
                Some((
                    "minLength",
                    &node.min_length,
                    "maxLength",
                    &node.max_length,
                    s.chars().count(),
                ))
            }
            Value::Array(a) => Some((
                "minItems",
                &node.min_items,
                "maxItems",
                &node.max_items,
                a.len(),
            )),
            Value::Object(o) => Some((
                "minProperties",
                &node.min_properties,
                "maxProperties",
                &node.max_properties,
                o.len(),
            )),
            _ => None,
        };
        if let Some((min, lower, max, upper, count)) = count {
            let n = Decimal::count(count);
            for (key, bound, lower) in [(min, lower, true), (max, upper, false)] {
                if let Some(bound) = bound {
                    assertion!(
                        if lower {
                            n.cmp(bound) != Ordering::Less
                        } else {
                            n.cmp(bound) != Ordering::Greater
                        },
                        key
                    );
                }
            }
        }
        Ok(valid)
    }
}

impl Schema {
    /// Searches deterministically for an example using [`Lcg`].
    /// Every returned value passes this schema's validator and the supplied
    /// size bounds. The search uses hints, exact constants, intersected bounds,
    /// and branch candidates; it is not a complete constraint solver. Numeric
    /// candidate selection may use `f64`, but acceptance always uses exact text.
    /// Known string formats guide synthesis even when they are annotations.
    /// Identical seeds, schemas, and limits produce identical results.
    pub fn generate(&self, seed: u64, limits: GenerationLimits) -> Result<Value, GenerationError> {
        if self.annotations.iter().any(|a| a.keyword != "format") {
            return Err(GenerationError::UnsupportedPattern);
        }
        let limits = limits.bounded();
        let mut generator = Generator {
            schema: self,
            rng: Lcg::new(seed),
            limits,
            work: Work { left: limits.work },
            attempts: limits.attempts,
        };
        let mut last = GenerationError::NoCandidate;
        let mut round = 0usize;
        while generator.attempts > 0 {
            let mut room = limits.total_nodes;
            let value = match generator.build(vec![0], 0, &mut room, round) {
                Ok(v) => v,
                Err(GenerationError::Limit("work")) => {
                    return Err(GenerationError::Limit("work"));
                }
                Err(e) => {
                    last = e;
                    round += 1;
                    continue;
                }
            };
            round += 1;
            if !generator.fits(&value, 0)? {
                last = GenerationError::NoCandidate;
                continue;
            }
            let size = match inspect(
                &value,
                &self.options.limits,
                self.options.limits.instance_nodes,
            ) {
                Ok(size) => size,
                Err(_) => {
                    last = GenerationError::NoCandidate;
                    continue;
                }
            };
            let budget = self.budget(size).min(generator.work.left);
            let mut work = Work { left: budget };
            let result = Eval {
                schema: self,
                work: &mut work,
                active: BTreeSet::new(),
                errors: Vec::new(),
                cap: 1,
                truncated: false,
            }
            .run(0, &value, 0, 0, false);
            generator
                .work
                .spend(budget - work.left)
                .map_err(|_| GenerationError::Limit("work"))?;
            match result {
                Ok(true) => return Ok(value),
                Ok(false) => last = GenerationError::NoCandidate,
                Err(e) if e.kind == ValidationKind::Limit("work") => {
                    return Err(GenerationError::Limit("work"));
                }
                Err(e) => return Err(GenerationError::Validation(e)),
            }
        }
        if limits.attempts == 0 {
            Err(GenerationError::Limit("attempts"))
        } else {
            Err(last)
        }
    }
}
struct Generator<'a> {
    schema: &'a Schema,
    rng: Lcg,
    limits: GenerationLimits,
    work: Work,
    attempts: usize,
}
impl Generator<'_> {
    fn spend(&mut self, n: usize) -> Result<(), GenerationError> {
        self.work
            .spend(n)
            .map_err(|_| GenerationError::Limit("work"))
    }
    fn expand(&mut self, mut ids: Vec<usize>) -> Result<Vec<usize>, GenerationError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        while let Some(id) = ids.pop() {
            self.spend(1)?;
            if !seen.insert(id) {
                continue;
            }
            let node = &self.schema.nodes[id];
            if node.reject {
                return Err(GenerationError::NoCandidate);
            }
            out.push(id);
            if let Some(target) = node.reference {
                ids.push(target);
            }
            if let Some(group) = node.all_of.as_ref() {
                self.spend(group.len())?;
                ids.extend(group);
            }
            for group in [&node.any_of, &node.one_of] {
                if let Some(group) = group
                    && let Some(&id) = group.get(self.rng.index(group.len()))
                {
                    ids.push(id);
                }
            }
            if let Some(&condition) = node.condition.as_ref() {
                if self.rng.coin() {
                    ids.push(condition);
                    if let Some(&id) = node.then_schema.as_ref() {
                        ids.push(id);
                    }
                } else if let Some(&id) = node.else_schema.as_ref() {
                    ids.push(id);
                }
            }
        }
        Ok(out)
    }
    fn fits(&mut self, value: &Value, depth: usize) -> Result<bool, GenerationError> {
        fn walk(
            g: &mut Generator<'_>,
            v: &Value,
            depth: usize,
            count: &mut usize,
        ) -> Result<bool, GenerationError> {
            g.spend(1)?;
            *count = count.saturating_add(1);
            if depth > g.limits.depth || *count > g.limits.total_nodes {
                return Ok(false);
            }
            match v {
                Value::String(s) => {
                    g.spend(s.len())?;
                    if s.chars().count() > g.limits.string_length {
                        return Ok(false);
                    }
                }
                Value::Array(a) => {
                    if a.len() > g.limits.items {
                        return Ok(false);
                    }
                    for v in a {
                        if !walk(g, v, depth + 1, count)? {
                            return Ok(false);
                        }
                    }
                }
                Value::Object(o) => {
                    if o.len() > g.limits.items {
                        return Ok(false);
                    }
                    for (s, v) in o {
                        g.spend(s.len())?;
                        if s.chars().count() > g.limits.string_length
                            || !walk(g, v, depth + 1, count)?
                        {
                            return Ok(false);
                        }
                    }
                }
                _ => {}
            }
            Ok(true)
        }
        walk(self, value, depth, &mut 0)
    }
    fn bounds(
        &self,
        ids: &[usize],
        select: fn(&Node) -> (Option<&Decimal>, Option<&Decimal>),
        cap: usize,
    ) -> Result<(usize, usize), GenerationError> {
        let (mut low, mut high) = (0, cap);
        for &id in ids {
            let node = &self.schema.nodes[id];
            let (min, max) = select(node);
            if let Some(n) = min {
                low = low.max(n.as_usize().ok_or(GenerationError::NoCandidate)?);
            }
            if let Some(n) = max
                && let Some(n) = n.as_usize()
            {
                high = high.min(n);
            }
        }
        if low > high {
            Err(GenerationError::NoCandidate)
        } else {
            Ok((low, high))
        }
    }
    fn build(
        &mut self,
        ids: Vec<usize>,
        depth: usize,
        room: &mut usize,
        round: usize,
    ) -> Result<Value, GenerationError> {
        if self.attempts == 0 {
            return Err(GenerationError::Limit("attempts"));
        }
        self.attempts -= 1;
        self.spend(1)?;
        if depth > self.limits.depth {
            return Err(GenerationError::Limit("depth"));
        }
        *room = room
            .checked_sub(1)
            .ok_or(GenerationError::Limit("total_nodes"))?;
        let ids = self.expand(ids)?;
        let mut mask = ANY;
        let mut preferred = NULL;
        for &id in &ids {
            let node = &self.schema.nodes[id];
            if let Some(types) = node.types {
                mask &= if types & NUMBER != 0 {
                    types | INTEGER
                } else {
                    types
                };
            }
            if !node.properties.is_empty()
                || !node.required.is_empty()
                || node.min_properties.is_some()
            {
                preferred = OBJECT;
            } else if node.items.is_some()
                || node.contains.is_some()
                || node.prefix_items.is_some()
                || node.min_items.is_some()
            {
                preferred = ARRAY;
            } else if node.min_length.is_some() || node.format.is_some() {
                preferred = STRING;
            } else if node.numeric_bounds().next().is_some() {
                preferred = INTEGER;
            }
            let candidate = if let Some(c) = &node.constant {
                Some(c)
            } else if let Some(a) = &node.enumeration {
                if a.is_empty() {
                    return Err(GenerationError::NoCandidate);
                }
                a.get(self.rng.index(a.len()))
            } else if round.is_multiple_of(3) {
                node.hints.get(self.rng.index(node.hints.len()))
            } else {
                None
            };
            if let Some(c) = candidate
                && self.fits(c, depth)?
            {
                let count = count_nodes(c);
                if count.saturating_sub(1) <= *room {
                    *room -= count.saturating_sub(1);
                    return Ok(c.clone());
                }
            }
        }
        let choices: Vec<u8> = [NULL, BOOL, INTEGER, NUMBER, STRING, ARRAY, OBJECT]
            .into_iter()
            .filter(|b| mask & b != 0)
            .collect();
        if choices.is_empty() {
            return Err(GenerationError::NoCandidate);
        }
        let kind = if round.is_multiple_of(2) && mask & preferred != 0 {
            preferred
        } else {
            choices[self.rng.index(choices.len())]
        };
        match kind {
            NULL => Ok(Value::Null),
            BOOL => Ok(Value::Bool(self.rng.coin())),
            INTEGER | NUMBER => self.number(&ids, kind == INTEGER, round),
            STRING => {
                let (low, high) = self.bounds(
                    &ids,
                    |n| (n.min_length.as_ref(), n.max_length.as_ref()),
                    self.limits.string_length,
                )?;
                for &id in &ids {
                    if let Some(format) = &self.schema.nodes[id].format {
                        self.spend(high.saturating_add(1))?;
                        if let Some(s) = format_example(format, low, high) {
                            return Ok(Value::String(s));
                        }
                    }
                }
                let n = low
                    + self.rng.index(
                        high.min(low.saturating_add(8))
                            .saturating_sub(low)
                            .saturating_add(1),
                    );
                self.spend(n)?;
                let s = (0..n)
                    .map(|_| char::from(b'a' + self.rng.below(26) as u8))
                    .collect();
                Ok(Value::String(s))
            }
            ARRAY => self.array(&ids, depth, room, round),
            _ => self.object(&ids, depth, room, round),
        }
    }
    fn number(
        &mut self,
        ids: &[usize],
        integer: bool,
        round: usize,
    ) -> Result<Value, GenerationError> {
        let (mut low, mut high) = (-16.0f64, 16.0f64);
        let (mut lower, mut upper) = (false, false);
        let mut candidates = Vec::new();
        let mut multiple = None;
        for &id in ids {
            for (key, d) in self.schema.nodes[id].numeric_bounds() {
                self.spend(d.digits.len().saturating_add(1))?;
                if key == "multipleOf" {
                    multiple = Some(d);
                    continue;
                }
                if let Some(v) = d.number() {
                    let f = v.as_f64().unwrap_or(0.0);
                    if key.ends_with("Minimum") || key == "minimum" {
                        let f = if key == "exclusiveMinimum" {
                            f.next_up()
                        } else {
                            f
                        };
                        low = if lower { low.max(f) } else { f };
                        lower = true;
                    } else {
                        let f = if key == "exclusiveMaximum" {
                            f.next_down()
                        } else {
                            f
                        };
                        high = if upper { high.min(f) } else { f };
                        upper = true;
                    }
                    candidates.push(v);
                }
            }
        }
        if lower && !upper {
            high = low.max(0.0) + 32.0;
        }
        if upper && !lower {
            low = high.min(0.0) - 32.0;
        }
        if integer {
            low = low.ceil();
            high = high.floor();
        }
        if let Some(d) = multiple {
            if let Some(v) = d.number() {
                candidates.push(v);
            }
            let unit = d.number().and_then(|v| v.as_f64()).unwrap_or(0.0);
            if unit.is_finite() && unit > 0.0 {
                let lo = (low / unit).ceil();
                let hi = (high / unit).floor();
                if lo.is_finite()
                    && hi.is_finite()
                    && lo <= hi
                    && lo >= i64::MIN as f64
                    && hi < i64::MAX as f64
                {
                    let span = (hi - lo).min(1024.0) as u64;
                    let multiplier =
                        (lo as i64).checked_add(self.rng.below(span.saturating_add(1)) as i64);
                    if let Some(n) = multiplier
                        && let Some(v) = multiply_small(d, n)
                    {
                        candidates.push(v);
                    }
                    if let Some(v) = multiply_small(d, lo as i64) {
                        candidates.push(v);
                    }
                }
            }
        } else if low.is_finite() && high.is_finite() && low <= high {
            for f in [
                low,
                high,
                low + (high - low) * (self.rng.next() as f64 / 2147483648.0),
            ] {
                if let Some(n) = Number::from_f64(if integer { f.floor() } else { f }) {
                    candidates.push(Value::Number(n));
                }
            }
        }
        candidates.push(Value::from(0));
        candidates.push(Value::from(self.rng.below(33) as i64 - 16));
        // Cycle through boundary candidates as well as random candidates.
        let at = if round.is_multiple_of(2) {
            round / 2 % candidates.len()
        } else {
            self.rng.index(candidates.len())
        };
        Ok(candidates.swap_remove(at))
    }
    fn array(
        &mut self,
        ids: &[usize],
        depth: usize,
        room: &mut usize,
        round: usize,
    ) -> Result<Value, GenerationError> {
        let (mut low, high) = self.bounds(
            ids,
            |n| (n.min_items.as_ref(), n.max_items.as_ref()),
            self.limits.items.min(*room),
        )?;
        for &id in ids {
            let node = &self.schema.nodes[id];
            if node.contains.is_some() {
                let n = node
                    .min_contains
                    .as_ref()
                    .map_or(Some(1), Decimal::as_usize)
                    .ok_or(GenerationError::NoCandidate)?;
                low = low.max(n);
            }
        }
        if low > high {
            return Err(GenerationError::NoCandidate);
        }
        let n = if round.is_multiple_of(2) {
            low
        } else {
            low + self.rng.index(high.min(low.saturating_add(3)) - low + 1)
        };
        let mut out = Vec::new();
        for i in 0..n {
            let mut children = Vec::new();
            for &id in ids {
                let node = &self.schema.nodes[id];
                let child = node
                    .prefix_items
                    .as_ref()
                    .and_then(|p| p.get(i))
                    .or(node.items.as_ref());
                if let Some(&id) = child {
                    children.push(id);
                }
                if let Some(&id) = node.contains.as_ref() {
                    let need = node
                        .min_contains
                        .as_ref()
                        .and_then(Decimal::as_usize)
                        .unwrap_or(1);
                    if i < need {
                        children.push(id);
                    }
                }
            }
            out.push(self.build(children, depth + 1, room, round.saturating_add(i))?);
        }
        Ok(Value::Array(out))
    }
    fn object(
        &mut self,
        ids: &[usize],
        depth: usize,
        room: &mut usize,
        round: usize,
    ) -> Result<Value, GenerationError> {
        let mut ids = ids.to_vec();
        let mut seen: BTreeSet<_> = ids.iter().copied().collect();
        let mut names = BTreeSet::new();
        let mut processed = 0;
        loop {
            let previous = (names.len(), ids.len());
            let (low, high) = self.bounds(
                &ids,
                |n| (n.min_properties.as_ref(), n.max_properties.as_ref()),
                self.limits.items.min(*room),
            )?;
            let mut available = BTreeSet::new();
            for &id in &ids[processed..] {
                let node = &self.schema.nodes[id];
                self.spend(node.required.len().saturating_add(node.properties.len()))?;
                names.extend(node.required.iter().cloned());
                available.extend(node.properties.keys().cloned());
                if let Some(id) = node.property_names {
                    let n = &self.schema.nodes[id];
                    if let Some(Value::String(s)) = &n.constant {
                        available.insert(s.clone());
                    }
                    if let Some(a) = &n.enumeration {
                        for v in a {
                            if let Value::String(s) = v {
                                available.insert(s.clone());
                            }
                        }
                    }
                }
            }
            processed = ids.len();
            for s in available {
                if names.len() >= high {
                    break;
                }
                if names.len() < low || (!round.is_multiple_of(2) && self.rng.coin()) {
                    names.insert(s);
                }
            }
            for i in 0..=self.limits.items {
                if names.len() >= low {
                    break;
                }
                names.insert(format!("p{i}"));
            }
            let mut triggered = Vec::new();
            for &id in &ids {
                let node = &self.schema.nodes[id];
                for (trigger, required) in &node.dependent {
                    self.spend(
                        trigger
                            .len()
                            .saturating_add(required.len())
                            .saturating_add(1),
                    )?;
                    if names.contains(trigger) {
                        names.extend(required.iter().cloned());
                    }
                }
                for (trigger, &child) in &node.dependent_schemas {
                    self.spend(trigger.len().saturating_add(1))?;
                    if names.contains(trigger) && !seen.contains(&child) {
                        triggered.push(child);
                    }
                }
            }
            for id in self.expand(triggered)? {
                if seen.insert(id) {
                    ids.push(id);
                }
            }
            if names.len() > high {
                return Err(GenerationError::NoCandidate);
            }
            if previous == (names.len(), ids.len()) {
                break;
            }
        }
        let mut out = Vec::new();
        for name in names {
            if name.chars().count() > self.limits.string_length {
                return Err(GenerationError::Limit("string_length"));
            }
            let mut children = Vec::new();
            for &id in &ids {
                let node = &self.schema.nodes[id];
                if let Some(&id) = node
                    .properties
                    .get(&name)
                    .or(node.additional_properties.as_ref())
                {
                    children.push(id);
                }
            }
            let value = self.build(children, depth + 1, room, round)?;
            out.push((name, value));
        }
        Ok(Value::Object(out))
    }
}
fn count_nodes(v: &Value) -> usize {
    match v {
        Value::Array(a) => a
            .iter()
            .fold(1usize, |n, v| n.saturating_add(count_nodes(v))),
        Value::Object(o) => o
            .iter()
            .fold(1usize, |n, (_, v)| n.saturating_add(count_nodes(v))),
        _ => 1,
    }
}
fn multiply_small(d: &Decimal, n: i64) -> Option<Value> {
    let mut digits = Vec::new();
    let multiplier = u128::from(n.unsigned_abs());
    let mut carry = 0u128;
    for &digit in d.digits.iter().rev() {
        let product = u128::from(digit)
            .checked_mul(multiplier)?
            .checked_add(carry)?;
        digits.push((product % 10) as u8);
        carry = product / 10;
    }
    while carry > 0 {
        digits.push((carry % 10) as u8);
        carry /= 10;
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    digits.reverse();
    Decimal {
        negative: (n < 0) != d.negative && !digits.is_empty(),
        digits,
        exponent: d.exponent,
    }
    .number()
}

#[cfg(test)]
mod tests {
    #[test]
    fn schema_errors_describe_the_failure_and_chain_validation() {
        use fictionet::stdlib::json_schema::{
            CompileError, CompileKind, GenerationError, ValidationError, ValidationKind,
        };
        use std::error::Error;
        let compile = CompileError {
            schema_path: "/type".into(),
            kind: CompileKind::InvalidKeyword,
        };
        assert_eq!(compile.to_string(), "invalid keyword value at schema /type");
        let validation = ValidationError {
            instance_path: "/user".into(),
            schema_path: "/required".into(),
            kind: ValidationKind::Missing("name".into()),
        };
        assert_eq!(
            validation.to_string(),
            "required property name is missing at instance /user (schema /required)"
        );
        let error = GenerationError::Validation(validation.clone());
        assert_eq!(
            error.to_string(),
            "example generation could not validate a candidate"
        );
        assert_eq!(
            error.source().unwrap().downcast_ref::<ValidationError>(),
            Some(&validation)
        );
        assert!(GenerationError::NoCandidate.source().is_none());
        assert_eq!(
            GenerationError::Limit("work").to_string(),
            "example generation exceeded the work limit"
        );
    }

    use super::*;
    use fictionet::stdlib::json;
    use fictionet::stdlib::test_support;
    use fictionet::stdlib::test_support::contract;

    fn value(text: &str) -> Value {
        json::parse_with(text.as_bytes(), &json::Limits::default()).unwrap()
    }
    fn schema(text: &str) -> Schema {
        Schema::compile(&value(text)).unwrap()
    }
    fn cases(source: &str, good: &[&str], bad: &[&str]) {
        let schema = schema(source);
        for text in good {
            assert!(
                schema.validate(&value(text)).is_valid(),
                "{source}: {text}: {:?}",
                schema.validate(&value(text))
            );
        }
        for text in bad {
            assert!(
                !schema.validate(&value(text)).is_valid(),
                "{source}: {text}"
            );
        }
    }

    #[test]
    fn types_and_json_equality() {
        cases(
            r#"{"type":"integer"}"#,
            &["1", "1.0", "10e-1", "-0.0", "1e1000"],
            &["0.1", "1e-1000", "null"],
        );
        cases(
            r#"{"type":["string","null"]}"#,
            &["null", "\"abc\""],
            &["true", "[]"],
        );
        cases(
            r#"{"enum":[{"a":1,"b":[2,3]}]}"#,
            &[r#"{"b":[2.0,3e0],"a":1.0}"#],
            &[r#"{"a":1,"b":[3,2]}"#],
        );
        cases(
            r#"{"const":1.0}"#,
            &["1", "10e-1"],
            &["1.00000000000000000001", "1e1", "0.1"],
        );
        cases(r#"{"enum":[]}"#, &[], &["null", "0", "[]"]);
        cases("true", &["null", "{}", "[1]"], &[]);
        cases("false", &[], &["null", "{}", "[1]"]);
    }

    #[test]
    fn exact_numeric_bounds_and_multiples() {
        cases(
            r#"{"minimum":9007199254740993,"maximum":9007199254740994}"#,
            &["9007199254740993", "9007199254740994", "\"unaffected\""],
            &["9007199254740992", "9007199254740995"],
        );
        cases(
            r#"{"exclusiveMinimum":-1.2,"exclusiveMaximum":2.0}"#,
            &["-1.19", "0", "1.99999999999999999999"],
            &["-1.2", "2", "2.1"],
        );
        cases(
            r#"{"multipleOf":0.1}"#,
            &["0.3", "-1.2", "0", "1e1000"],
            &["0.31", "1e-1000", "0.30000000000000000001"],
        );
        cases(
            r#"{"multipleOf":3}"#,
            &["-9", "0", "3e1000"],
            &["1e1000", "1", "0.3"],
        );
        cases(
            r#"{"minimum":1e1000,"maximum":2e1000}"#,
            &["1e1000", "15e999"],
            &["9e999", "3e1000"],
        );
        cases(r#"{"const":-0}"#, &["0.0", "0e1000"], &["0.0001"]);
        for numerator in -30i64..=30 {
            for denominator in 1i64..=12 {
                let s = schema(&format!(r#"{{"multipleOf":{denominator}e-2}}"#));
                let n = value(&format!("{numerator}e-2"));
                assert_eq!(s.validate(&n).is_valid(), numerator % denominator == 0);
            }
        }
    }

    #[test]
    fn strings_arrays_and_objects() {
        cases(
            r#"{"minLength":2,"maxLength":2}"#,
            &[r#""é😀""#, r#""a\u0000""#, "12"],
            &[r#""😀""#, r#""abc""#],
        );
        cases(
            r#"{"prefixItems":[{"type":"integer"},{"type":"string"}],"items":false}"#,
            &["[]", "[1]", r#"[1,"a"]"#],
            &[r#"["a"]"#, r#"[1,"a",3]"#],
        );
        cases(
            r#"{"items":{"type":"boolean"},"minItems":1,"maxItems":2,"uniqueItems":true}"#,
            &["[true]", "[true,false]"],
            &["[]", "[true,true]", "[0]", "[true,false,true]"],
        );
        cases(
            r#"{"uniqueItems":true}"#,
            &["[1,2]"],
            &["[1,1.0]", r#"[{"a":1,"b":2},{"b":2.0,"a":1}]"#],
        );
        cases(
            r#"{"contains":{"type":"integer"},"minContains":2,"maxContains":3}"#,
            &["[1,2,null]", "[1,2,3]"],
            &["[]", "[1,null]", "[1,2,3,4]"],
        );
        cases(
            r#"{"contains":true,"minContains":0,"maxContains":0}"#,
            &["[]"],
            &["[1]"],
        );
        cases(r#"{"minContains":5,"maxContains":0}"#, &["[]", "[1]"], &[]);
        cases(
            r#"{"properties":{"a":{"type":"integer"}},"required":["a"],"additionalProperties":false}"#,
            &[r#"{"a":1}"#],
            &["{}", r#"{"a":null}"#, r#"{"a":1,"b":2}"#],
        );
        cases(
            r#"{"additionalProperties":{"type":"boolean"},"propertyNames":{"maxLength":2},"minProperties":1,"maxProperties":2}"#,
            &[r#"{"é":true}"#],
            &[
                "{}",
                r#"{"aaa":true}"#,
                r#"{"a":1}"#,
                r#"{"a":true,"b":false,"c":true}"#,
            ],
        );
        cases(
            r#"{"dependentRequired":{"a":["b"]}}"#,
            &["{}", r#"{"b":2}"#, r#"{"a":1,"b":2}"#],
            &[r#"{"a":1}"#],
        );
    }

    #[test]
    fn combinators_and_branch_errors() {
        cases(
            r#"{"allOf":[{"minimum":2},{"maximum":4}]}"#,
            &["2", "3", "4"],
            &["1", "5"],
        );
        cases(
            r#"{"anyOf":[{"type":"string"},{"minimum":2,"type":"number"}]}"#,
            &[r#""x""#, "2"],
            &["null", "1"],
        );
        cases(
            r#"{"oneOf":[{"type":"number"},{"type":"integer"}]}"#,
            &["0.1"],
            &["1", "null"],
        );
        cases(
            r#"{"not":{"type":"integer"}}"#,
            &["null", "0.1"],
            &["1", "1.0"],
        );
        cases(
            r#"{"if":{"type":"number"},"then":{"minimum":2},"else":{"type":"string"}}"#,
            &["2", r#""x""#],
            &["1", "null"],
        );
        cases(r#"{"then":false,"else":false}"#, &["null", "12"], &[]);
        let s = schema(r#"{"anyOf":[{"type":"string"},{"type":"integer"}],"minimum":2}"#);
        let r = s.validate_with(&value("1"), ErrorMode::All);
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.errors[0].schema_path, "/minimum");
    }

    #[test]
    fn references_pointers_anchors_and_recursive_instances() {
        cases(
            r##"{"$defs":{"a/b~ c":{"type":"integer"}},"$ref":"#/$defs/a~1b~0%20c"}"##,
            &["1"],
            &["null"],
        );
        cases(
            r##"{"$defs":{"x":{"$anchor":"int","type":"integer"}},"$ref":"#int"}"##,
            &["1"],
            &["null"],
        );
        cases(
            r##"{"custom":[{"type":"integer"}],"$ref":"#/custom/0"}"##,
            &["1"],
            &["null"],
        );
        cases(
            r##"{"type":"object","properties":{"next":{"$ref":"#"}}}"##,
            &["{}", r#"{"next":{"next":{}}}"#],
            &[r#"{"next":2}"#],
        );
        for s in [
            r##"{"$ref":"#"}"##,
            r##"{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}"##,
            r##"{"not":{"$ref":"#"}}"##,
            r##"{"anyOf":[{"$ref":"#"},true]}"##,
        ] {
            assert_eq!(
                schema(s).validate(&Value::Null).errors[0].kind,
                ValidationKind::ReferenceCycle
            );
        }
        let s = schema(
            r##"{"$defs":{"i":{"type":"integer"}},"properties":{"a/b":{"$ref":"#/$defs/i"}}}"##,
        );
        let r = s.validate(&value(r#"{"a/b":false}"#));
        assert_eq!(r.errors[0].instance_path, "/a~1b");
        assert_eq!(r.errors[0].schema_path, "/$defs/i/type");
        for reference in [
            "else.json#/x",
            "https://example.test/schema",
            "#/absent",
            "#bad%xx",
            "#/a~2b",
            "#%ff",
            "#missing",
        ] {
            let source = Value::Object(vec![("$ref".into(), Value::from(reference))]);
            let e = Schema::compile(&source).unwrap_err();
            assert_eq!(e.schema_path, "/$ref");
        }
        for s in [
            r#"{"$anchor":"0bad"}"#,
            r##"{"$ref":"#x","$defs":{"a":{"$anchor":"x"},"b":{"$anchor":"x"}}}"##,
        ] {
            assert_eq!(
                Schema::compile(&value(s)).unwrap_err().kind,
                CompileKind::InvalidAnchor
            );
        }
    }

    #[test]
    fn patterns_are_explicit_and_formats_are_annotations() {
        for text in [
            r#"{"pattern":"^x+$"}"#,
            r#"{"patternProperties":{"^x":{"type":"integer"}}}"#,
        ] {
            assert_eq!(
                Schema::compile(&value(text)).unwrap_err().kind,
                CompileKind::UnsupportedPattern
            );
            let s = Schema::compile_with(
                &value(text),
                Options {
                    patterns: PatternPolicy::Annotate,
                    ..Options::default()
                },
            )
            .unwrap();
            assert_eq!(s.annotations().len(), 1);
            let r = s.validate(&value(r#"{"x":false}"#));
            assert!(r.is_valid());
            assert_eq!(s.annotations().len(), 1);
            assert_eq!(
                s.generate(0, GenerationLimits::default()),
                Err(GenerationError::UnsupportedPattern)
            );
        }
        let s = schema(r#"{"type":"string","format":"email","unknown":{"type":7}}"#);
        assert!(s.validate(&Value::from("not an email")).is_valid());
        assert_eq!(s.annotations()[0].keyword, "format");
    }

    #[test]
    fn openapi_dialect_is_opt_in() {
        let source =
            value(r#"{"type":"number","nullable":true,"minimum":2,"exclusiveMinimum":true}"#);
        assert_eq!(
            Schema::compile(&source).unwrap_err().schema_path,
            "/exclusiveMinimum"
        );
        let options = Options {
            dialect: Dialect::OpenApi30,
            ..Options::default()
        };
        let s = Schema::compile_with(&source, options).unwrap();
        for v in [Value::Null, Value::from(3)] {
            assert!(s.validate(&v).is_valid());
        }
        assert!(!s.validate(&Value::from(2)).is_valid());
        let source = value(r#"{"type":"string","nullable":true}"#);
        assert!(
            !Schema::compile(&source)
                .unwrap()
                .validate(&Value::Null)
                .is_valid()
        );
        assert!(
            Schema::compile_with(&source, options)
                .unwrap()
                .validate(&Value::Null)
                .is_valid()
        );
        let source = value(r#"{"type":"string","nullable":true,"enum":["x"]}"#);
        assert!(
            !Schema::compile_with(&source, options)
                .unwrap()
                .validate(&Value::Null)
                .is_valid()
        );
        assert!(Schema::compile_with(&value(r#"{"exclusiveMinimum":2}"#), options).is_err());
        assert!(Schema::compile_with(&value(r#"{"type":["string","null"]}"#), options).is_err());
        let source = value(r##"{"$ref":"#/$defs/n","type":17,"$defs":{"n":{"type":"integer"}}}"##);
        assert!(
            Schema::compile_with(&source, options)
                .unwrap()
                .validate(&Value::from(2))
                .is_valid()
        );
        let s = Schema::compile_with(&value(r#"{"maximum":2,"exclusiveMaximum":true}"#), options)
            .unwrap();
        assert!(s.validate(&Value::from(1)).is_valid());
        assert!(!s.validate(&Value::from(2)).is_valid());
        let s = Schema::compile_with(&value(r#"{"minimum":2,"exclusiveMinimum":false}"#), options)
            .unwrap();
        assert!(s.validate(&Value::from(2)).is_valid());
    }

    #[test]
    fn malformed_keywords_and_duplicate_keys() {
        for source in [
            "null",
            "[]",
            r#"{"type":[]}"#,
            r#"{"type":["null","null"]}"#,
            r#"{"type":"wat"}"#,
            r#"{"minimum":true}"#,
            r#"{"multipleOf":0}"#,
            r#"{"multipleOf":-1}"#,
            r#"{"minItems":-1}"#,
            r#"{"maxLength":1.5}"#,
            r#"{"required":["a","a"]}"#,
            r#"{"required":[1]}"#,
            r#"{"properties":[]}"#,
            r#"{"items":[]}"#,
            r#"{"allOf":[]}"#,
            r#"{"not":null}"#,
            r#"{"dependentRequired":{"x":1}}"#,
        ] {
            assert!(Schema::compile(&value(source)).is_err(), "{source}");
        }
        assert_eq!(
            Schema::compile(&value(r#"{"type":"string","type":"number"}"#))
                .unwrap_err()
                .kind,
            CompileKind::DuplicateKey
        );
        let s = schema("true");
        assert_eq!(
            s.validate(&value(r#"{"x":1,"x":2}"#)).errors[0].kind,
            ValidationKind::DuplicateKey
        );
    }

    #[test]
    fn error_modes_caps_and_paths() {
        let source = value(
            r#"{"properties":{"a/b":{"type":"integer"},"~":{"type":"boolean"}},"required":["missing"]}"#,
        );
        let s = Schema::compile(&source).unwrap();
        let instance = value(r#"{"a/b":null,"~":null}"#);
        assert_eq!(s.validate(&instance).errors.len(), 1);
        let report = s.validate_with(&instance, ErrorMode::All);
        assert_eq!(report.errors.len(), 3);
        assert!(!report.truncated);
        assert_eq!(report.errors[1].instance_path, "/a~1b");
        assert_eq!(report.errors[1].schema_path, "/properties/a~1b/type");
        assert_eq!(report.errors[2].instance_path, "/~0");
        for cap in [0, 1, 2] {
            let s = Schema::compile_with(
                &source,
                Options {
                    limits: Limits {
                        errors: cap,
                        ..Limits::default()
                    },
                    ..Options::default()
                },
            )
            .unwrap();
            let report = s.validate_with(&instance, ErrorMode::All);
            assert_eq!(report.errors.len(), cap.max(1));
            assert!(report.truncated);
        }
    }

    #[test]
    fn hostile_inputs_and_limits() {
        let huge = value("1e99999999999999999999999999999999");
        assert!(matches!(
            Schema::compile(&Value::Object(vec![("minimum".into(), huge.clone())]))
                .unwrap_err()
                .kind,
            CompileKind::Limit("number_exponent")
        ));
        assert_eq!(
            schema("true").validate(&huge).errors[0].kind,
            ValidationKind::Limit("number_exponent")
        );
        let source = Value::Object(vec![(
            "enum".into(),
            Value::Array(vec![Value::Null; 17_000]),
        )]);
        assert_eq!(
            Schema::compile(&source).unwrap_err().kind,
            CompileKind::Limit("schema_nodes")
        );
        let mut deep = Value::Null;
        for _ in 0..200 {
            deep = Value::Array(vec![deep]);
        }
        assert!(matches!(
            Schema::compile(&deep).unwrap_err().kind,
            CompileKind::Limit("depth")
        ));
        assert_eq!(
            schema("true").validate(&deep).errors[0].kind,
            ValidationKind::Limit("depth")
        );
        let options = Options {
            limits: Limits {
                ref_depth: 1,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(
            &value(r##"{"$defs":{"a":{"$ref":"#/$defs/b"},"b":true},"$ref":"#/$defs/a"}"##),
            options,
        )
        .unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("ref_depth")
        );
        let options = Options {
            limits: Limits {
                validation_depth: 0,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(&value(r#"{"allOf":[true]}"#), options).unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("validation_depth")
        );
        // A small DAG expands exponentially without a shared budget.
        let mut defs = Vec::new();
        defs.push(("d0".into(), Value::Bool(true)));
        for i in 1..18 {
            let r = Value::Object(vec![(
                "$ref".into(),
                Value::from(format!("#/$defs/d{}", i - 1)),
            )]);
            defs.push((
                format!("d{i}"),
                Value::Object(vec![("oneOf".into(), Value::Array(vec![r.clone(), r]))]),
            ));
        }
        let source = Value::Object(vec![
            ("$defs".into(), Value::Object(defs)),
            ("$ref".into(), Value::from("#/$defs/d17")),
        ]);
        let options = Options {
            limits: Limits {
                work: 5000,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(&source, options).unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("work")
        );
        let options = Options {
            limits: Limits {
                pointer_bytes: 3,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert!(Schema::compile_with(&value(r#"{"properties":{"long":true}}"#), options).is_err());
        let options = Options {
            limits: Limits {
                work: 0,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert!(Schema::compile_with(&Value::Bool(true), options).is_err());
    }

    #[test]
    fn generation_is_valid_deterministic_and_bounded() {
        let corpus = [
            "true",
            r#"{"type":"null"}"#,
            r#"{"type":"boolean"}"#,
            r#"{"type":"integer","minimum":5,"maximum":8}"#,
            r#"{"type":"number","minimum":0.3,"maximum":0.9,"multipleOf":0.1}"#,
            r#"{"type":"number","exclusiveMinimum":1,"exclusiveMaximum":2}"#,
            r#"{"type":"integer","minimum":1,"maximum":99,"multipleOf":3}"#,
            r#"{"type":"string","minLength":2,"maxLength":7}"#,
            r#"{"const":{"a":[1,null]}}"#,
            r#"{"enum":[1,"x",null]}"#,
            r#"{"type":"array","minItems":2,"maxItems":4,"items":{"type":"integer"},"uniqueItems":true}"#,
            r#"{"type":"array","prefixItems":[{"const":1},{"const":"x"}],"items":false,"minItems":2}"#,
            r#"{"type":"array","contains":{"type":"integer"},"minContains":2,"maxContains":3}"#,
            r#"{"type":"object","required":["x"],"properties":{"x":{"type":"integer"}},"additionalProperties":false}"#,
            r#"{"type":"object","minProperties":2,"maxProperties":3,"additionalProperties":{"type":"boolean"}}"#,
            r#"{"type":"object","required":["a"],"dependentRequired":{"a":["b"],"b":["c"]}}"#,
            r#"{"allOf":[{"type":"object","required":["a"],"properties":{"a":{"const":1}}},{"required":["b"],"properties":{"b":{"const":2}}}]}"#,
            r#"{"anyOf":[{"type":"integer"},{"type":"string"}]}"#,
            r#"{"oneOf":[{"type":"integer","minimum":1},{"type":"string"}]}"#,
            r#"{"type":"integer","not":{"const":0}}"#,
            r#"{"if":{"type":"number"},"then":{"minimum":1},"else":{"type":"string"}}"#,
            r##"{"$defs":{"x":{"type":"integer","minimum":2}},"$ref":"#/$defs/x"}"##,
            r#"{"type":"string","default":17,"example":"yes","format":"uuid"}"#,
        ];
        for text in corpus {
            let s = schema(text);
            for seed in 0..64 {
                let v = s
                    .generate(seed, GenerationLimits::default())
                    .unwrap_or_else(|e| panic!("{text} seed {seed}: {e}"));
                assert!(s.validate(&v).is_valid(), "{text}: {v:?}");
                assert_eq!(s.generate(seed, GenerationLimits::default()).unwrap(), v);
                contract::check_wire_value(&v);
            }
        }
        for text in [
            "false",
            r#"{"type":"integer","minimum":2,"maximum":1}"#,
            r#"{"oneOf":[true,true]}"#,
            r#"{"type":"string","minLength":1000}"#,
            r#"{"type":"array","minItems":1000}"#,
        ] {
            assert!(
                schema(text)
                    .generate(0, GenerationLimits::default())
                    .is_err(),
                "{text}"
            );
        }
        for limits in [
            GenerationLimits {
                total_nodes: 0,
                ..GenerationLimits::default()
            },
            GenerationLimits {
                attempts: 0,
                ..GenerationLimits::default()
            },
            GenerationLimits {
                work: 0,
                ..GenerationLimits::default()
            },
        ] {
            assert!(schema("true").generate(0, limits).is_err());
        }
        let s = schema(r#"{"const":[["too long"]]}"#);
        for limits in [
            GenerationLimits {
                depth: 0,
                ..GenerationLimits::default()
            },
            GenerationLimits {
                string_length: 1,
                ..GenerationLimits::default()
            },
            GenerationLimits {
                items: 0,
                ..GenerationLimits::default()
            },
            GenerationLimits {
                total_nodes: 1,
                ..GenerationLimits::default()
            },
        ] {
            assert!(s.generate(0, limits).is_err());
        }
    }

    #[test]
    fn mutated_schema_and_instance_inputs() {
        let mut rng = Lcg::new(27);
        let mut bytes =
            br#"{"type":"object","properties":{"a":{"type":"integer"}},"required":["a"]}"#.to_vec();
        for _ in 0..500 {
            test_support::mutate(&mut rng, &mut bytes);
            if let Ok(v) = json::parse_with(&bytes, &json::Limits::default())
                && let Ok(s) = Schema::compile(&v)
            {
                let _ = s.validate_with(&v, ErrorMode::All);
                if let Ok(example) = s.generate(rng.next(), GenerationLimits::default()) {
                    assert!(s.validate(&example).is_valid());
                }
            }
        }
    }
    #[test]
    fn limits_apply_to_preflight_resolution_and_search() {
        let source = value(r#"{"type":"integer"}"#);
        for limits in [
            Limits {
                schema_nodes: 0,
                ..Limits::default()
            },
            Limits {
                bytes: 0,
                ..Limits::default()
            },
        ] {
            assert!(
                Schema::compile_with(
                    &source,
                    Options {
                        limits,
                        ..Options::default()
                    }
                )
                .is_err()
            );
        }
        let s = Schema::compile_with(
            &Value::Bool(true),
            Options {
                limits: Limits {
                    instance_nodes: 1,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&value("[1]")).errors[0].kind,
            ValidationKind::Limit("instance_nodes")
        );
        let s = Schema::compile_with(
            &Value::Bool(true),
            Options {
                limits: Limits {
                    bytes: 4,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&Value::from("1234")).errors[0].kind,
            ValidationKind::Limit("bytes")
        );
        let s = Schema::compile_with(
            &Value::Bool(true),
            Options {
                limits: Limits {
                    depth: usize::MAX,
                    number_exponent: usize::MAX,
                    work: usize::MAX,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(s.options().limits.work, usize::MAX);
        assert_eq!(s.options().limits.depth, 256);
        assert_eq!(s.options().limits.number_exponent, 1_000_000);
        let s = Schema::compile_with(
            &value(r#"{"not":false}"#),
            Options {
                limits: Limits {
                    work_per_pair: 0,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("work")
        );
        let source = value(r##"{"a/b~c":{"type":"integer"},"$ref":"#%2Fa~1b~0c"}"##);
        assert!(
            Schema::compile(&source)
                .unwrap()
                .validate(&Value::from(1))
                .is_valid()
        );
        cases(r#"{"minLength":2.0}"#, &[r#""ab""#], &[r#""a""#]);
        cases(r#"{"minLength":1e1000}"#, &["null"], &[r#""ab""#]);
        // Large object searches spend the compilation budget too.
        let mut entries: Vec<_> = (0..100)
            .map(|i| (format!("n{i}"), Value::Bool(true)))
            .collect();
        entries.push(("last".into(), Value::Bool(true)));
        let refs = (0..100)
            .map(|_| value(r##"{"$ref":"#/unknown/last"}"##))
            .collect();
        let source = Value::Object(vec![
            ("unknown".into(), Value::Object(entries)),
            ("allOf".into(), Value::Array(refs)),
        ]);
        let e = Schema::compile_with(
            &source,
            Options {
                limits: Limits {
                    work: 2500,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.kind, CompileKind::Limit("work"));
    }
    #[test]
    fn review_unique_items_scales_and_normalizes() {
        let s = schema(r#"{"uniqueItems":true}"#);
        for values in [
            (0..1000)
                .map(|i| Value::from(format!("item-{i:06}")))
                .collect(),
            (0..20_000).map(Value::from).collect(),
        ] {
            let report = s.validate(&Value::Array(values));
            assert!(report.is_valid(), "{report:?}");
        }
        for text in ["[1,1.0]", r#"[{"a":1,"b":2},{"b":2.0,"a":1}]"#] {
            assert_eq!(
                s.validate(&value(text)).errors[0].kind,
                ValidationKind::Assertion("uniqueItems")
            );
        }
    }

    #[test]
    fn review_dependent_schemas_and_unsupported_keywords() {
        cases(
            r#"{"dependentSchemas":{"a":{"required":["b"]}}}"#,
            &["{}", r#"{"a":1,"b":2}"#],
            &[r#"{"a":1}"#],
        );
        for (key, v) in [
            ("unevaluatedProperties", Value::Bool(false)),
            ("unevaluatedItems", Value::Bool(false)),
            ("$dynamicRef", Value::from("#x")),
            ("$dynamicAnchor", Value::from("x")),
            ("$recursiveRef", Value::from("#")),
            ("contentSchema", Value::Bool(false)),
        ] {
            let source = Value::Object(vec![(key.into(), v)]);
            assert_eq!(
                Schema::compile(&source).unwrap_err().kind,
                CompileKind::UnsupportedKeyword(key.into())
            );
        }
    }

    #[test]
    fn review_format_generation() {
        for (format, expected) in [
            ("date-time", "2000-01-01T00:00:00Z"),
            ("date", "2000-01-01"),
            ("time", "00:00:00Z"),
            ("email", "a@example.test"),
            ("uuid", "00000000-0000-4000-8000-000000000000"),
            ("uri", "https://example.test/"),
            ("ipv4", "192.0.2.1"),
            ("ipv6", "2001:db8::1"),
            ("hostname", "example.test"),
        ] {
            let s = schema(&format!(r#"{{"type":"string","format":"{format}"}}"#));
            let generated = s.generate(7, GenerationLimits::default()).unwrap();
            assert_eq!(generated.as_str(), Some(expected), "{format}");
        }
    }

    #[test]
    fn review_path_storage_is_proportional_to_source() {
        let mut source = Value::Object(vec![(
            "properties".into(),
            Value::Object(
                (0..16_000)
                    .map(|i| (i.to_string(), Value::Bool(true)))
                    .collect(),
            ),
        )]);
        for _ in 0..4 {
            source = Value::Object(vec![(
                "properties".into(),
                Value::Object(vec![("x".repeat(1000), source)]),
            )]);
        }
        let s = Schema::compile(&source).unwrap();
        let path_bytes: usize = s.paths.0.iter().map(|path| path.token.len()).sum();
        assert!(path_bytes < 100_000, "stored {path_bytes} path bytes");
    }

    #[test]
    fn review_recursive_list_reaches_json_depth() {
        let s = schema(
            r##"{"$defs":{"n":{"anyOf":[{"type":"null"},{"type":"object","required":["next"],"properties":{"next":{"$ref":"#/$defs/n"}}}]}},"$ref":"#/$defs/n"}"##,
        );
        let mut instance = Value::Null;
        for _ in 0..json::MAX_DEPTH {
            instance = Value::Object(vec![("next".into(), instance)]);
        }
        contract::check_wire_value(&instance);
        let report = s.validate(&instance);
        assert!(report.is_valid(), "{report:?}");
    }

    #[test]
    fn review_property_names_path_and_oas_examples() {
        let s = schema(r#"{"propertyNames":{"maxLength":2}}"#);
        assert_eq!(
            s.validate(&value(r#"{"abc":1}"#)).errors[0].instance_path,
            ""
        );
        assert!(
            Schema::compile_with(
                &value(r#"{"type":"string","examples":{"a":"b"}}"#),
                Options {
                    dialect: Dialect::OpenApi30,
                    ..Options::default()
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn review_raised_schema_limits_take_effect() {
        let source = Value::Object(vec![(
            "enum".into(),
            Value::Array(vec![Value::Null; 17_000]),
        )]);
        let options = Options {
            limits: Limits {
                schema_nodes: 20_000,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert!(Schema::compile_with(&source, options).is_ok());
        let source = Value::Object(vec![(
            "description".into(),
            Value::from("x".repeat((1 << 20) + 1)),
        )]);
        let options = Options {
            limits: Limits {
                bytes: 2 << 20,
                work: 4_000_000,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert!(Schema::compile_with(&source, options).is_ok());
    }
    #[test]
    fn review_format_assertions_share_generation_checks() {
        for (name, good, bad) in [
            (
                "date-time",
                "2024-02-29t23:59:59.01+05:30",
                "2023-02-29T00:00:00Z",
            ),
            ("date", "2024-02-29", "2024-04-31"),
            ("time", "23:59:60Z", "24:00:00Z"),
            ("email", "\"a b\"@example.test", "a..b@example.test"),
            (
                "uuid",
                "00000000-0000-4000-8000-000000000000",
                "urn:uuid:00000000-0000-4000-8000-000000000000",
            ),
            (
                "uri",
                "https://example.test/a%20b?x=1#ok",
                "https://example.test/%xx",
            ),
            ("ipv4", "192.0.2.1", "192.0.2.256"),
            ("ipv6", "2001:db8::1", "2001:db8:::1"),
            ("hostname", "api.example.test", "-api.example.test"),
        ] {
            let source = value(&format!(r#"{{"type":"string","format":"{name}"}}"#));
            let s = Schema::compile_with(
                &source,
                Options {
                    formats: FormatPolicy::Assert,
                    ..Options::default()
                },
            )
            .unwrap();
            assert!(s.validate(&Value::from(good)).is_valid(), "{name}: {good}");
            assert_eq!(
                s.validate(&Value::from(bad)).errors[0].kind,
                ValidationKind::Assertion("format")
            );
            let example = s.generate(1, GenerationLimits::default()).unwrap();
            assert!(s.validate(&example).is_valid());
            assert!(valid_format(name, example.as_str().unwrap()));
            for length in 0..=48 {
                let bounded = value(&format!(
                    r#"{{"type":"string","format":"{name}","minLength":{length},"maxLength":{length}}}"#
                ));
                let annotation = Schema::compile(&bounded).unwrap();
                let example = annotation.generate(3, GenerationLimits::default()).unwrap();
                assert_eq!(example.as_str().unwrap().len(), length);
                if let Some(expected) = format_example(name, length, length) {
                    assert!(valid_format(name, &expected), "{name}: {expected}");
                    assert_eq!(example.as_str(), Some(expected.as_str()));
                } else {
                    assert!(
                        example
                            .as_str()
                            .unwrap()
                            .bytes()
                            .all(|b| b.is_ascii_lowercase())
                    );
                }
            }
        }
        let s = Schema::compile_with(
            &value(r#"{"format":"custom-format"}"#),
            Options {
                formats: FormatPolicy::Assert,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(s.validate(&Value::from("anything")).is_valid());
    }

    #[test]
    fn review_missing_names_and_generation_work_errors() {
        let s = schema(r#"{"required":["a","b"],"dependentRequired":{"x":["c"]}}"#);
        let errors = s.validate_with(&value(r#"{"x":1}"#), ErrorMode::All).errors;
        assert_eq!(
            errors.iter().map(|e| e.kind.clone()).collect::<Vec<_>>(),
            [
                ValidationKind::Missing("a".into()),
                ValidationKind::Missing("b".into()),
                ValidationKind::Missing("c".into())
            ]
        );
        for source in [
            "true",
            r#"{"const":"example"}"#,
            r#"{"allOf":[true,true,true,true]}"#,
        ] {
            for work in 0..12 {
                if let Err(e) = schema(source).generate(
                    7,
                    GenerationLimits {
                        work,
                        ..GenerationLimits::default()
                    },
                ) {
                    assert_eq!(e, GenerationError::Limit("work"));
                }
            }
        }
    }
    #[test]
    fn review_compile_at_limits_exclude_document_ancestors_and_unused_defs() {
        let unused = value(r#"{"$defs":{"bad":{"unevaluatedProperties":false}}}"#);
        assert!(
            Schema::compile_with(
                &unused,
                Options {
                    limits: Limits {
                        schema_nodes: 1,
                        depth: 0,
                        ..Limits::default()
                    },
                    ..Options::default()
                }
            )
            .is_ok()
        );
        let source = value(
            r##"{"entry":{"$ref":"#/target"},"target":{"type":"integer","minimum":1,"$defs":{"unused":{"unevaluatedProperties":false}}},"unused":{"type":17}}"##,
        );
        let options = Options {
            limits: Limits {
                schema_nodes: 8,
                bytes: 100,
                depth: 1,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_at(&source, "/entry", options).unwrap();
        assert!(s.validate(&Value::from(1)).is_valid());
        assert_eq!(
            s.validate(&Value::from(0)).errors[0].schema_path,
            "/target/minimum"
        );
        assert!(Schema::compile_at(&source, "/unused", options).is_err());
        for pointer in ["entry", "/missing", "/~2", "/entry/~"] {
            assert_eq!(
                Schema::compile_at(&source, pointer, Options::default())
                    .unwrap_err()
                    .kind,
                CompileKind::InvalidReference
            );
        }
        let a = Schema::compile(source.get("target").unwrap()).unwrap();
        let b = Schema::compile_at(source.get("target").unwrap(), "", Options::default()).unwrap();
        assert_eq!(
            a.validate(&Value::from(0)).errors,
            b.validate(&Value::from(0)).errors
        );
        assert_eq!(
            a.generate(5, GenerationLimits::default()),
            b.generate(5, GenerationLimits::default())
        );
    }

    #[test]
    fn review_raised_evaluation_ceiling_stays_bounded() {
        let defs = (0..1030)
            .map(|i| {
                (
                    format!("n{i}"),
                    Value::Object(vec![(
                        "$ref".into(),
                        Value::from(format!("#/$defs/n{}", i + 1)),
                    )]),
                )
            })
            .chain(std::iter::once(("n1030".into(), Value::Bool(true))))
            .collect();
        let source = Value::Object(vec![
            ("$defs".into(), Value::Object(defs)),
            ("$ref".into(), Value::from("#/$defs/n0")),
        ]);
        let s = Schema::compile_with(
            &source,
            Options {
                limits: Limits {
                    validation_depth: 1024,
                    ref_depth: usize::MAX,
                    work: 100_000_000,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("validation_depth")
        );
    }

    #[test]
    fn review_generation_applies_triggered_dependent_schemas() {
        let s = schema(
            r#"{"type":"object","required":["a"],"properties":{"a":{"const":true}},"dependentSchemas":{"a":{"required":["b"],"properties":{"b":{"const":7}},"dependentSchemas":{"b":{"required":["c"],"properties":{"c":{"const":"yes"}}}}}}}"#,
        );
        for seed in 0..32 {
            let generated = s.generate(seed, GenerationLimits::default()).unwrap();
            assert!(s.validate(&generated).is_valid());
            assert_eq!(generated.get("b"), Some(&Value::from(7)));
            assert_eq!(generated.get("c"), Some(&Value::from("yes")));
        }
    }

    #[test]
    fn review_multiple_of_large_exponents_is_exact() {
        let kind = |source: &str, instance: &str| {
            schema(source)
                .validate(&value(instance))
                .errors
                .first()
                .map(|e| e.kind.clone())
        };
        let fail = Some(ValidationKind::Assertion("multipleOf"));
        assert_eq!(kind(r#"{"multipleOf":3}"#, "1e1000"), fail);
        assert_eq!(kind(r#"{"multipleOf":3}"#, "1e10000"), fail);
        assert_eq!(kind(r#"{"multipleOf":7}"#, "-1e9999"), fail);
        assert_eq!(kind(r#"{"multipleOf":3}"#, "3e10000"), None);
        assert_eq!(kind(r#"{"multipleOf":8}"#, "1e3"), None);
        assert_eq!(kind(r#"{"multipleOf":8}"#, "1e2"), fail);
        assert_eq!(kind(r#"{"multipleOf":1024}"#, "1e10000"), None);
        assert_eq!(kind(r#"{"multipleOf":0.0625}"#, "1e-4"), fail);
        assert_eq!(kind(r#"{"multipleOf":1e-10000}"#, "7e10000"), None);
        // A long divisor costs O(len^2 log shift) work, beyond the per-pair budget of a tiny input.
        let big = "123456789012345678901234567890123456789";
        let wide = Options {
            limits: Limits {
                work_per_pair: 1 << 20,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(&value(&format!(r#"{{"multipleOf":{big}}}"#)), wide).unwrap();
        let kind = |instance: String| {
            s.validate(&value(&instance))
                .errors
                .first()
                .map(|e| e.kind.clone())
        };
        assert_eq!(kind(format!("{big}e9000")), None);
        assert_eq!(kind("1e9000".into()), fail);
        assert_eq!(kind(format!("2{big}e9000")), fail);
        assert_eq!(kind(format!("-{big}{big}e1")), None);
        for exponent in 0..40 {
            for divisor in [3u64, 6, 7, 12, 16, 25, 40, 625, 999_983] {
                let s = schema(&format!(r#"{{"multipleOf":{divisor}}}"#));
                let n = value(&format!("13e{exponent}"));
                let expected = (0..exponent).fold(13u128 % u128::from(divisor), |r, _| {
                    r * 10 % u128::from(divisor)
                }) == 0;
                assert_eq!(
                    s.validate(&n).is_valid(),
                    expected,
                    "13e{exponent} / {divisor}"
                );
            }
        }
    }

    #[test]
    fn review_anchors_are_found_only_in_schema_positions() {
        for source in [
            r##"{"examples":[{"$anchor":"foo","type":"integer"}],"$ref":"#foo"}"##,
            r##"{"default":{"$anchor":"foo"},"$ref":"#foo"}"##,
            r##"{"const":{"$anchor":"foo"},"$ref":"#foo"}"##,
            r##"{"enum":[{"$anchor":"foo"}],"$ref":"#foo"}"##,
            r##"{"x-data":{"$anchor":"foo"},"$ref":"#foo"}"##,
            r##"{"properties":{"p":{"default":{"$anchor":"foo"}}},"$ref":"#foo"}"##,
        ] {
            assert_eq!(
                Schema::compile(&value(source)).unwrap_err().kind,
                CompileKind::InvalidReference,
                "{source}"
            );
        }
        cases(
            r##"{"$defs":{"a":{"$anchor":"foo","type":"string"}},"examples":[{"$anchor":"foo"}],"$ref":"#foo"}"##,
            &[r#""a""#],
            &["1"],
        );
        cases(
            r##"{"properties":{"p":{"$anchor":"foo","type":"string"}},"items":{"$ref":"#foo"}}"##,
            &[r#"["a"]"#, r#"{"p":"b"}"#],
            &["[1]", r#"{"p":2}"#],
        );
        // An OpenAPI 3.0 Reference Object hides its siblings, anchors included.
        let oas = value(
            r##"{"allOf":[{"$ref":"#/$defs/s","$anchor":"foo"}],"$defs":{"s":{}},"not":{"$ref":"#foo"}}"##,
        );
        let options = Options {
            dialect: Dialect::OpenApi30,
            ..Options::default()
        };
        assert_eq!(
            Schema::compile_with(&oas, options).unwrap_err().kind,
            CompileKind::InvalidReference
        );
        // compile_at searches the entry schema even when the document root is not a schema.
        let document = value(
            r##"{"info":{"x":{"$anchor":"n","type":"string"}},"components":{"schemas":{"Pet":{"$defs":{"n":{"$anchor":"n","type":"integer"}},"properties":{"id":{"$ref":"#n"}}}}}}"##,
        );
        let s =
            Schema::compile_at(&document, "/components/schemas/Pet", Options::default()).unwrap();
        assert!(s.validate(&value(r#"{"id":1}"#)).is_valid());
        assert!(!s.validate(&value(r#"{"id":"x"}"#)).is_valid());
    }

    #[test]
    fn review_nested_ids_fail_closed() {
        // In 2020-12 the inner reference resolves to /$defs/a/$defs/b, a string.
        let nested = r##"{"$defs":{"a":{"$id":"https://example.test/a","$defs":{"b":{"type":"string"}},"$ref":"#/$defs/b"},"b":{"type":"integer"}},"$ref":"#/$defs/a"}"##;
        assert_eq!(
            Schema::compile(&value(nested)).unwrap_err(),
            CompileError {
                schema_path: "/$defs/a/$id".into(),
                kind: CompileKind::UnsupportedKeyword("$id".into()),
            }
        );
        // Anchors inside an embedded resource belong to it, not to the root.
        let anchored = r##"{"$defs":{"a":{"$id":"https://example.test/a","$defs":{"b":{"$anchor":"x"}}}},"$ref":"#x"}"##;
        assert_eq!(
            Schema::compile(&value(anchored)).unwrap_err().kind,
            CompileKind::InvalidReference
        );
        cases(
            r##"{"$id":"https://example.test/root","$defs":{"i":{"type":"integer"}},"$ref":"#/$defs/i"}"##,
            &["1"],
            &["\"1\""],
        );
        assert_eq!(
            Schema::compile(&value(r#"{"$id":7}"#)).unwrap_err().kind,
            CompileKind::InvalidKeyword
        );
        let document = value(r#"{"components":{"schemas":{"Pet":{"$id":"pet"}}}}"#);
        assert!(
            Schema::compile_at(&document, "/components/schemas/Pet", Options::default()).is_err()
        );
    }
}
