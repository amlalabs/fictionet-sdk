//! Checked JSON schemas for tool arguments, API bodies, and mock values.
//!
//! [`Schema`] implements the listed JSON Schema 2020-12 assertions. Unknown
//! keywords are ignored. `format` is always an annotation, never an assertion.
//! There is no regex engine: `pattern` and `patternProperties` are rejected by
//! default. [`PatternPolicy::Annotate`] records and ignores them, including
//! their effect on `additionalProperties`. Generation refuses such schemas.
//!
//! Numbers use their decimal text, including for equality and `multipleOf`.
//! No floating point rounding or tolerance is used by validation. Precision
//! is limited only by [`fictionet::stdlib::json::MAX_NUMBER_LEN`] and [`Limits::max_number_exponent`].
//! Out-of-range exponents are errors, including in enum values and instances.
//! Object order does not affect equality. Duplicate object keys are refused.
//!
//! References stay in one document. Pointers and simple anchors are supported;
//! `$id` does not establish another resource or change the reference base.
//! Recursive schemas may descend through instances. Revisiting a schema at the
//! same instance is a reference-cycle error, even inside `not` or `anyOf`.
//! All evaluation, including speculative branches, shares one work budget.
//!
//! [`Dialect::OpenApi30`] adds `nullable` for explicit types, boolean exclusive
//! bounds, single-string types, and Reference Object sibling suppression.
//! `example`, `default`, and `examples` are generation hints. `discriminator`,
//! `readOnly`, and `writeOnly` do not assert anything; request/response policy
//! belongs to the caller. This module performs no I/O.

use fictionet::stdlib::codec::test_support::Lcg;
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
/// assert_eq!(schema.validate(&Value::Null).annotations[0].keyword, "pattern");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PatternPolicy {
    /// Refuse compilation at the unsupported keyword. This is the default.
    #[default]
    Reject,
    /// Ignore the keyword and expose it in schema and validation annotations.
    /// Generation returns [`GenerationError::UnsupportedPattern`].
    Annotate,
}

/// Resource bounds. Defaults are also hard ceilings; fields can only lower them.
/// Zero is allowed and means no work or storage for that resource.
///
/// ```
/// use fictionet::stdlib::json_schema::{Limits, Options};
/// let limits = Limits { max_work: 10_000, ..Limits::default() };
/// let options = Options { limits, ..Options::default() };
/// assert_eq!(options.limits.max_work, 10_000);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Values in the source schema document, including annotations. Default 16,384.
    pub max_schema_nodes: usize,
    /// Values in an instance. Object names are not nodes. Default 100,000.
    pub max_instance_nodes: usize,
    /// Sum of string, name, and number bytes plus one per value. Default 1 MiB.
    pub max_bytes: usize,
    /// Value nesting, with the root at zero, before any copying. Default 64.
    pub max_depth: usize,
    /// Simultaneous schema evaluations, including applicators. Default 64.
    pub max_validation_depth: usize,
    /// Simultaneous reference hops during evaluation. Default 32.
    pub max_ref_depth: usize,
    /// Bytes in a JSON Pointer diagnostic or resolved schema path. Default 4,096.
    pub max_pointer_bytes: usize,
    /// Collected validation errors. Default 64. Zero still returns one error.
    pub max_errors: usize,
    /// Work units per compilation or validation. Default 1,000,000.
    /// Units charge visits, searches, comparisons, and decimal digit operations.
    pub max_work: usize,
    /// Additional validation work ceiling per schema/instance size pair.
    /// Default 32. The effective budget is the smaller of `max_work` and
    /// this field times `(schema_size + 1) * (instance_size + 1)`.
    pub work_per_pair: usize,
    /// Absolute decimal exponent, before normalization. Default 10,000.
    pub max_number_exponent: usize,
}
impl Default for Limits {
    /// Returns the documented resource ceilings.
    fn default() -> Self {
        Self {
            max_schema_nodes: 16_384,
            max_instance_nodes: 100_000,
            max_bytes: 1 << 20,
            max_depth: 64,
            max_validation_depth: 64,
            max_ref_depth: 32,
            max_pointer_bytes: 4096,
            max_errors: 64,
            max_work: 1_000_000,
            work_per_pair: 32,
            max_number_exponent: 10_000,
        }
    }
}
impl Limits {
    fn bounded(mut self) -> Self {
        let cap = Self::default();
        macro_rules! clamp { ($($f:ident),*) => { $(self.$f = self.$f.min(cap.$f);)* }; }
        clamp!(
            max_schema_nodes,
            max_instance_nodes,
            max_bytes,
            max_depth,
            max_validation_depth,
            max_ref_depth,
            max_pointer_bytes,
            max_errors,
            max_work,
            work_per_pair,
            max_number_exponent
        );
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
    /// Collect failed assertions up to [`Limits::max_errors`].
    All,
}

/// A reason compilation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileErrorKind {
    /// A keyword has the wrong JSON shape or value.
    InvalidKeyword,
    /// An object repeats a name.
    DuplicateKey,
    /// Regex assertions need an explicit annotation-only policy.
    UnsupportedPattern,
    /// A reference names another document.
    ExternalReference,
    /// A fragment, pointer, anchor, or reference target is invalid or missing.
    InvalidReference,
    /// A simple anchor is invalid or appears more than once.
    InvalidAnchor,
    /// A named resource bound was reached.
    Limit(&'static str),
}

/// A compile failure at a JSON Pointer in the source document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    /// Pointer to the invalid keyword or value. An empty pointer names the root.
    pub schema_path: String,
    /// The reason compilation stopped.
    pub kind: CompileErrorKind,
}
impl std::fmt::Display for CompileError {
    /// Formats the reason and source pointer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at schema {}", self.kind, self.schema_path)
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
    /// An instance object repeats a name.
    DuplicateKey,
    /// A schema was revisited without descending to another instance.
    ReferenceCycle,
    /// A named resource bound was reached. This is never a branch mismatch.
    Limit(&'static str),
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
            "{:?} at instance {} (schema {})",
            self.kind, self.instance_path, self.schema_path
        )
    }
}
impl std::error::Error for ValidationError {}

/// A recorded, non-asserting schema keyword.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation {
    /// Absolute pointer to the keyword.
    pub schema_path: String,
    /// `format`, `pattern`, or `patternProperties`.
    pub keyword: &'static str,
    /// Original keyword value.
    pub value: Value,
}

/// Validation output. Annotations describe the compiled schema, including
/// unused definitions; they are not a record of successful evaluation paths.
///
/// ```
/// use fictionet::stdlib::{json::Value, json_schema::Schema};
/// let schema = Schema::compile(&Value::Bool(false)).unwrap();
/// let report = schema.validate(&Value::Null);
/// assert!(!report.is_valid());
/// assert_eq!(report.errors[0].instance_path, "");
/// ```
#[derive(Debug)]
pub struct Validation<'a> {
    /// Failed assertions, or a terminal resource/cycle error.
    pub errors: Vec<ValidationError>,
    /// Schema annotations, also present when the instance is invalid.
    pub annotations: &'a [Annotation],
    /// Evaluation stopped early because of policy, an error cap, or a fatal error.
    pub truncated: bool,
}
impl Validation<'_> {
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
    Validation(ValidationError),
}
impl std::fmt::Display for GenerationError {
    /// Formats the generation failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "example generation: {self:?}")
    }
}
impl std::error::Error for GenerationError {}

/// An owned, checked schema arena. Compilation does not expand references.
///
/// Validation preflights input in bounded depth, then evaluates under a shared
/// work cap. For schema size S and instance size I (nodes plus text bytes),
/// evaluation performs at most `min(max_work, work_per_pair*(S+1)*(I+1))`
/// charged operations. Each operation has bounded decimal and pointer costs.
/// Preflight uses ordered sets for duplicate names: O((S+I) log(S+I)) in the
/// worst case. `uniqueItems`, enum equality, and branch retries spend the same
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
    annotations: Vec<Annotation>,
    options: Options,
    size: usize,
}

#[derive(Clone, Debug, Default)]
struct Node {
    path: String,
    reject: bool,
    types: Option<u8>,
    constant: Option<Value>,
    enumeration: Option<Vec<Value>>,
    numbers: BTreeMap<&'static str, Decimal>,
    counts: BTreeMap<&'static str, Decimal>,
    single: BTreeMap<&'static str, usize>,
    groups: BTreeMap<&'static str, Vec<usize>>,
    properties: BTreeMap<String, usize>,
    required: Vec<String>,
    dependent: BTreeMap<String, Vec<String>>,
    unique: bool,
    reference: Option<usize>,
    hints: Vec<Value>,
}

fn pointer(base: &str, token: &str, max: usize) -> Result<String, &'static str> {
    let mut size = base.len().checked_add(1).ok_or("max_pointer_bytes")?;
    for b in token.bytes() {
        size = size
            .checked_add(if b == b'~' || b == b'/' { 2 } else { 1 })
            .ok_or("max_pointer_bytes")?;
    }
    if size > max {
        return Err("max_pointer_bytes");
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

#[derive(Debug)]
struct InputError {
    path: String,
    limit: Option<&'static str>,
}
fn inspect(value: &Value, limits: &Limits, max_nodes: usize) -> Result<usize, InputError> {
    fn visit(
        v: &Value,
        path: &str,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
        l: &Limits,
        cap: usize,
    ) -> Result<(), InputError> {
        let err = |limit| InputError {
            path: path.into(),
            limit,
        };
        if depth > l.max_depth {
            return Err(err(Some("max_depth")));
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
                    let p = pointer(path, &i.to_string(), l.max_pointer_bytes)
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
                    if *bytes > l.max_bytes {
                        return Err(err(Some("max_bytes")));
                    }
                    let p = pointer(path, key, l.max_pointer_bytes).map_err(|s| err(Some(s)))?;
                    if !names.insert(key) {
                        return Err(InputError {
                            path: p,
                            limit: None,
                        });
                    }
                    visit(child, &p, depth + 1, nodes, bytes, l, cap)?;
                }
            }
            _ => {}
        }
        if *bytes > l.max_bytes {
            return Err(err(Some("max_bytes")));
        }
        Ok(())
    }
    let (mut nodes, mut bytes) = (0, 0);
    visit(value, "", 0, &mut nodes, &mut bytes, limits, max_nodes)?;
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
        let exponent: i64 = exp.parse().map_err(|_| "max_number_exponent")?;
        if exponent.unsigned_abs() > limits.max_number_exponent as u64 {
            return Err("max_number_exponent");
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
    fn multiple(&self, divisor: &Self, work: &mut Work) -> Result<bool, &'static str> {
        if self.digits.is_empty() {
            return Ok(true);
        }
        let shift = self.exponent - divisor.exponent;
        if shift < 0 {
            return Ok(false);
        }
        let mut remainder = Vec::<u8>::new();
        for (index, digit) in self
            .digits
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, shift as usize))
            .enumerate()
        {
            if index >= self.digits.len() && remainder.is_empty() {
                return Ok(true);
            }
            work.spend(divisor.digits.len().saturating_mul(12).saturating_add(1))?;
            if !remainder.is_empty() || digit != 0 {
                remainder.push(digit);
            }
            while remainder.len() > divisor.digits.len()
                || (remainder.len() == divisor.digits.len() && remainder >= divisor.digits)
            {
                let mut borrow = 0i16;
                for i in 0..remainder.len() {
                    let r = remainder.len() - 1 - i;
                    let d = divisor
                        .digits
                        .len()
                        .checked_sub(i + 1)
                        .map_or(0, |j| divisor.digits[j]);
                    let n = i16::from(remainder[r]) - i16::from(d) - borrow;
                    remainder[r] = n.rem_euclid(10) as u8;
                    borrow = i16::from(n < 0);
                }
                let first = remainder
                    .iter()
                    .position(|&d| d != 0)
                    .unwrap_or(remainder.len());
                remainder.drain(..first);
            }
        }
        Ok(remainder.is_empty())
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
struct Work {
    left: usize,
}
impl Work {
    fn spend(&mut self, n: usize) -> Result<(), &'static str> {
        self.left = self.left.checked_sub(n).ok_or("max_work")?;
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

struct Compiler<'a> {
    root: &'a Value,
    options: Options,
    queue: Vec<(&'a Value, String)>,
    ids: BTreeMap<String, usize>,
    anchors: BTreeMap<String, usize>,
    refs: Vec<(usize, String)>,
    nodes: Vec<Node>,
    annotations: Vec<Annotation>,
    work: Work,
}
impl<'a> Compiler<'a> {
    fn error(&self, path: &str, kind: CompileErrorKind) -> CompileError {
        CompileError {
            schema_path: path.into(),
            kind,
        }
    }
    fn path(&self, base: &str, token: &str) -> Result<String, CompileError> {
        pointer(base, token, self.options.limits.max_pointer_bytes)
            .map_err(|s| self.error(base, CompileErrorKind::Limit(s)))
    }
    fn enqueue(&mut self, value: &'a Value, path: String) -> Result<usize, CompileError> {
        self.work
            .spend(1)
            .map_err(|s| self.error(&path, CompileErrorKind::Limit(s)))?;
        if let Some(&id) = self.ids.get(&path) {
            return Ok(id);
        }
        if self.queue.len() >= self.options.limits.max_schema_nodes {
            return Err(self.error(&path, CompileErrorKind::Limit("max_schema_nodes")));
        }
        let id = self.queue.len();
        self.ids.insert(path.clone(), id);
        self.queue.push((value, path));
        Ok(id)
    }
    fn names(&self, v: &Value, p: &str) -> Result<Vec<String>, CompileError> {
        let invalid = || self.error(p, CompileErrorKind::InvalidKeyword);
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
    fn node(&mut self, id: usize) -> Result<Node, CompileError> {
        let (value, path) = self.queue[id].clone();
        let mut node = Node {
            path: path.clone(),
            ..Node::default()
        };
        if let Value::Bool(b) = value {
            node.reject = !b;
            return Ok(node);
        }
        let object = value
            .as_object()
            .ok_or_else(|| self.error(&path, CompileErrorKind::InvalidKeyword))?;
        // OAS 3.0 Reference Objects have no effective siblings.
        let ref_only = self.options.dialect == Dialect::OpenApi30 && value.get("$ref").is_some();
        for (key, v) in object {
            let p = self.path(&path, key)?;
            self.work
                .spend(key.len().saturating_add(1))
                .map_err(|s| self.error(&p, CompileErrorKind::Limit(s)))?;
            if ref_only && key != "$ref" {
                continue;
            }
            let invalid = || CompileError {
                schema_path: p.clone(),
                kind: CompileErrorKind::InvalidKeyword,
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
                "minimum" | "maximum" | "multipleOf" | "exclusiveMinimum" | "exclusiveMaximum" => {
                    let k = match key.as_str() {
                        "minimum" => "minimum",
                        "maximum" => "maximum",
                        "multipleOf" => "multipleOf",
                        "exclusiveMinimum" => "exclusiveMinimum",
                        _ => "exclusiveMaximum",
                    };
                    if self.options.dialect == Dialect::OpenApi30 && k.starts_with("exclusive") {
                        v.as_bool().ok_or_else(invalid)?;
                    } else {
                        let n =
                            Decimal::new(v.as_number().ok_or_else(invalid)?, &self.options.limits)
                                .map_err(|s| self.error(&p, CompileErrorKind::Limit(s)))?;
                        if k == "multipleOf" && (n.negative || n.digits.is_empty()) {
                            return Err(invalid());
                        }
                        node.numbers.insert(k, n);
                    }
                }
                "minLength" | "maxLength" | "minItems" | "maxItems" | "minContains"
                | "maxContains" | "minProperties" | "maxProperties" => {
                    let k = match key.as_str() {
                        "minLength" => "minLength",
                        "maxLength" => "maxLength",
                        "minItems" => "minItems",
                        "maxItems" => "maxItems",
                        "minContains" => "minContains",
                        "maxContains" => "maxContains",
                        "minProperties" => "minProperties",
                        _ => "maxProperties",
                    };
                    let n = Decimal::new(v.as_number().ok_or_else(invalid)?, &self.options.limits)
                        .map_err(|s| self.error(&p, CompileErrorKind::Limit(s)))?;
                    if n.negative || !n.integer() {
                        return Err(invalid());
                    }
                    node.counts.insert(k, n);
                }
                "uniqueItems" => node.unique = v.as_bool().ok_or_else(invalid)?,
                "required" => node.required = self.names(v, &p)?,
                "dependentRequired" => {
                    for (name, required) in v.as_object().ok_or_else(invalid)? {
                        node.dependent
                            .insert(name.clone(), self.names(required, &self.path(&p, name)?)?);
                    }
                }
                "properties" | "$defs" | "patternProperties" => {
                    let entries = v.as_object().ok_or_else(invalid)?;
                    if key == "patternProperties" {
                        if self.options.patterns == PatternPolicy::Reject {
                            return Err(self.error(&p, CompileErrorKind::UnsupportedPattern));
                        }
                        self.annotations.push(Annotation {
                            schema_path: p.clone(),
                            keyword: "patternProperties",
                            value: v.clone(),
                        });
                    }
                    for (name, child) in entries {
                        let at = self.enqueue(child, self.path(&p, name)?)?;
                        if key == "properties" {
                            node.properties.insert(name.clone(), at);
                        }
                    }
                }
                "items"
                | "contains"
                | "additionalProperties"
                | "propertyNames"
                | "not"
                | "if"
                | "then"
                | "else" => {
                    let k = match key.as_str() {
                        "items" => "items",
                        "contains" => "contains",
                        "additionalProperties" => "additionalProperties",
                        "propertyNames" => "propertyNames",
                        "not" => "not",
                        "if" => "if",
                        "then" => "then",
                        _ => "else",
                    };
                    let at = self.enqueue(v, p)?;
                    node.single.insert(k, at);
                }
                "prefixItems" | "allOf" | "anyOf" | "oneOf" => {
                    let a = v.as_array().ok_or_else(invalid)?;
                    if a.is_empty() {
                        return Err(invalid());
                    }
                    let k = match key.as_str() {
                        "prefixItems" => "prefixItems",
                        "allOf" => "allOf",
                        "anyOf" => "anyOf",
                        _ => "oneOf",
                    };
                    let mut ids = Vec::new();
                    for (i, child) in a.iter().enumerate() {
                        ids.push(self.enqueue(child, self.path(&p, &i.to_string())?)?);
                    }
                    node.groups.insert(k, ids);
                }
                "pattern" | "format" => {
                    v.as_str().ok_or_else(invalid)?;
                    let k = if key == "pattern" {
                        "pattern"
                    } else {
                        "format"
                    };
                    if k == "pattern" && self.options.patterns == PatternPolicy::Reject {
                        return Err(self.error(&p, CompileErrorKind::UnsupportedPattern));
                    }
                    self.annotations.push(Annotation {
                        schema_path: p,
                        keyword: k,
                        value: v.clone(),
                    });
                }
                "$anchor" => {
                    let s = v.as_str().ok_or_else(invalid)?;
                    if !simple_anchor(s) || self.anchors.insert(s.into(), id).is_some() {
                        return Err(self.error(&p, CompileErrorKind::InvalidAnchor));
                    }
                }
                "$ref" => {
                    let s = v.as_str().ok_or_else(invalid)?;
                    if !s.starts_with('#') {
                        return Err(self.error(&p, CompileErrorKind::ExternalReference));
                    }
                    self.refs.push((id, s.into()));
                }
                "default" | "example" => node.hints.push(v.clone()),
                "examples" => {
                    node.hints
                        .extend_from_slice(v.as_array().ok_or_else(invalid)?);
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
            for (exclusive, inclusive) in [
                ("exclusiveMinimum", "minimum"),
                ("exclusiveMaximum", "maximum"),
            ] {
                if value.get(exclusive).and_then(Value::as_bool) == Some(true)
                    && let Some(n) = node.numbers.remove(inclusive)
                {
                    node.numbers.insert(exclusive, n);
                }
            }
        }
        Ok(node)
    }
    fn finish(mut self, size: usize) -> Result<Schema, CompileError> {
        self.enqueue(self.root, String::new())?;
        let mut resolved = 0;
        let mut anchor_refs = Vec::new();
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
                let p = self.path(&self.nodes[id].path, "$ref")?;
                self.work
                    .spend(reference.len())
                    .map_err(|l| self.error(&p, CompileErrorKind::Limit(l)))?;
                let fragment = decode_fragment(&reference[1..])
                    .ok_or_else(|| self.error(&p, CompileErrorKind::InvalidReference))?;
                if fragment.is_empty() || fragment.starts_with('/') {
                    let (value, canonical) = resolve_pointer(
                        self.root,
                        &fragment,
                        self.options.limits.max_pointer_bytes,
                        &mut self.work,
                    )
                    .map_err(|kind| self.error(&p, kind))?;
                    let target = self.enqueue(value, canonical)?;
                    self.nodes[id].reference = Some(target);
                } else {
                    anchor_refs.push((id, fragment));
                }
            }
        }
        for (id, anchor) in anchor_refs {
            let p = self.path(&self.nodes[id].path, "$ref")?;
            let target = self
                .anchors
                .get(&anchor)
                .copied()
                .ok_or_else(|| self.error(&p, CompileErrorKind::InvalidReference))?;
            self.nodes[id].reference = Some(target);
        }
        Ok(Schema {
            nodes: self.nodes,
            annotations: self.annotations,
            options: self.options,
            size,
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
    let mut bytes = Vec::new();
    let mut it = s.bytes();
    while let Some(b) = it.next() {
        if b == b'%' {
            let a = char::from(it.next()?).to_digit(16)?;
            let b = char::from(it.next()?).to_digit(16)?;
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}
fn resolve_pointer<'a>(
    mut value: &'a Value,
    p: &str,
    max: usize,
    work: &mut Work,
) -> Result<(&'a Value, String), CompileErrorKind> {
    use CompileErrorKind::{InvalidReference, Limit};
    let mut canonical = String::new();
    if p.is_empty() {
        return Ok((value, canonical));
    }
    for part in p.strip_prefix('/').ok_or(InvalidReference)?.split('/') {
        work.spend(part.len().saturating_add(1)).map_err(Limit)?;
        let mut token = String::new();
        let mut chars = part.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                token.push(match chars.next().ok_or(InvalidReference)? {
                    '0' => '~',
                    '1' => '/',
                    _ => return Err(InvalidReference),
                });
            } else {
                token.push(ch);
            }
        }
        canonical = pointer(&canonical, &token, max).map_err(Limit)?;
        value = match value {
            Value::Object(members) => {
                let mut found = None;
                for (name, v) in members {
                    work.spend(name.len().min(token.len()).saturating_add(1))
                        .map_err(Limit)?;
                    if name == &token {
                        found = Some(v);
                        break;
                    }
                }
                found.ok_or(InvalidReference)?
            }
            Value::Array(a) => {
                if token.is_empty()
                    || (token.len() > 1 && token.starts_with('0'))
                    || !token.bytes().all(|c| c.is_ascii_digit())
                {
                    return Err(InvalidReference);
                }
                a.get(token.parse::<usize>().map_err(|_| InvalidReference)?)
                    .ok_or(InvalidReference)?
            }
            _ => return Err(InvalidReference),
        };
    }
    Ok((value, canonical))
}

impl Schema {
    /// Compiles a boolean or object schema with default options.
    pub fn compile(source: &Value) -> Result<Self, CompileError> {
        Self::compile_with(source, Options::default())
    }
    /// Checks all recognized schema locations, resolves local references, and
    /// owns the resulting arena. Unknown keyword values are not schemas unless
    /// reached by a pointer reference. No borrowed source data is retained.
    pub fn compile_with(source: &Value, mut options: Options) -> Result<Self, CompileError> {
        options.limits = options.limits.bounded();
        let size =
            inspect(source, &options.limits, options.limits.max_schema_nodes).map_err(|e| {
                CompileError {
                    schema_path: e.path,
                    kind: match e.limit {
                        Some("max_nodes") => CompileErrorKind::Limit("max_schema_nodes"),
                        Some(l) => CompileErrorKind::Limit(l),
                        None => CompileErrorKind::DuplicateKey,
                    },
                }
            })?;
        Compiler {
            root: source,
            options,
            queue: Vec::new(),
            ids: BTreeMap::new(),
            anchors: BTreeMap::new(),
            refs: Vec::new(),
            nodes: Vec::new(),
            annotations: Vec::new(),
            work: Work {
                left: options.limits.max_work,
            },
        }
        .finish(size)
    }
    /// Returns the effective options after hard ceilings were applied.
    pub fn options(&self) -> Options {
        self.options
    }
    /// Returns recorded non-asserting keywords, including unused definitions.
    pub fn annotations(&self) -> &[Annotation] {
        &self.annotations
    }
    /// Validates an instance, stopping at the first failed assertion.
    pub fn validate(&self, instance: &Value) -> Validation<'_> {
        self.validate_with(instance, ErrorMode::First)
    }
    /// Validates with the selected error policy. Fatal errors in speculative
    /// branches propagate; they cannot satisfy `not` or be hidden by `anyOf`.
    pub fn validate_with(&self, instance: &Value, mode: ErrorMode) -> Validation<'_> {
        let mut report = Validation {
            errors: Vec::new(),
            annotations: &self.annotations,
            truncated: false,
        };
        let l = &self.options.limits;
        let size = match inspect(instance, l, l.max_instance_nodes) {
            Ok(size) => size,
            Err(e) => {
                report.errors.push(ValidationError {
                    instance_path: e.path,
                    schema_path: String::new(),
                    kind: match e.limit {
                        Some("max_nodes") => ValidationKind::Limit("max_instance_nodes"),
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
            active: Vec::new(),
            errors: Vec::new(),
            cap: if mode == ErrorMode::First {
                1
            } else {
                l.max_errors.max(1)
            },
            truncated: false,
        };
        if let Err(e) = eval.run(0, instance, "", 0, 0, true) {
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
        self.options.limits.max_work.min(
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

struct Eval<'a, 'w> {
    schema: &'a Schema,
    work: &'w mut Work,
    active: Vec<(usize, *const Value)>,
    errors: Vec<ValidationError>,
    cap: usize,
    truncated: bool,
}
impl Eval<'_, '_> {
    fn error(&self, id: usize, path: &str, keyword: &str, kind: ValidationKind) -> ValidationError {
        let base = &self.schema.nodes[id].path;
        ValidationError {
            instance_path: path.into(),
            schema_path: if keyword.is_empty() {
                base.clone()
            } else {
                pointer(base, keyword, self.schema.options.limits.max_pointer_bytes)
                    .unwrap_or_else(|_| base.clone())
            },
            kind,
        }
    }
    fn spend(
        &mut self,
        n: usize,
        id: usize,
        p: &str,
        keyword: &str,
    ) -> Result<(), ValidationError> {
        self.work
            .spend(n)
            .map_err(|s| self.error(id, p, keyword, ValidationKind::Limit(s)))
    }
    fn child_path(&self, id: usize, p: &str, token: &str) -> Result<String, ValidationError> {
        pointer(p, token, self.schema.options.limits.max_pointer_bytes)
            .map_err(|s| self.error(id, p, "", ValidationKind::Limit(s)))
    }
    fn run(
        &mut self,
        id: usize,
        value: &Value,
        p: &str,
        depth: usize,
        refs: usize,
        collect: bool,
    ) -> Result<bool, ValidationError> {
        self.spend(1, id, p, "")?;
        let l = &self.schema.options.limits;
        if depth > l.max_validation_depth {
            return Err(self.error(id, p, "", ValidationKind::Limit("max_validation_depth")));
        }
        if refs > l.max_ref_depth {
            return Err(self.error(id, p, "$ref", ValidationKind::Limit("max_ref_depth")));
        }
        if self.active.contains(&(id, value as *const Value)) {
            return Err(self.error(id, p, "$ref", ValidationKind::ReferenceCycle));
        }
        self.active.push((id, value));
        let result = self.body(id, value, p, depth, refs, collect);
        self.active.pop();
        result
    }
    fn body(
        &mut self,
        id: usize,
        value: &Value,
        p: &str,
        depth: usize,
        refs: usize,
        collect: bool,
    ) -> Result<bool, ValidationError> {
        let node = &self.schema.nodes[id];
        let limits = &self.schema.options.limits;
        let mut valid = true;
        macro_rules! assertion {
            ($ok:expr, $key:expr) => {
                if !$ok {
                    valid = false;
                    if !collect {
                        return Ok(false);
                    }
                    self.errors
                        .push(self.error(id, p, $key, ValidationKind::Assertion($key)));
                    if self.errors.len() >= self.cap {
                        self.truncated = true;
                        return Ok(false);
                    }
                }
            };
        }
        macro_rules! child {
            ($child:expr, $v:expr, $p:expr, $refs:expr) => {
                if !self.run($child, $v, $p, depth + 1, $refs, collect)? {
                    valid = false;
                    if !collect || self.errors.len() >= self.cap {
                        return Ok(false);
                    }
                }
            };
        }
        if node.reject {
            if collect {
                self.errors
                    .push(self.error(id, p, "", ValidationKind::FalseSchema));
                self.truncated = self.errors.len() >= self.cap;
            }
            return Ok(false);
        }
        if let Some(target) = node.reference {
            child!(target, value, p, refs + 1);
        }
        if let Some(mask) = node.types {
            let bit = match value {
                Value::Null => NULL,
                Value::Bool(_) => BOOL,
                Value::String(_) => STRING,
                Value::Array(_) => ARRAY,
                Value::Object(_) => OBJECT,
                Value::Number(n) => {
                    self.spend(n.text().len(), id, p, "type")?;
                    let d = Decimal::new(n, limits)
                        .map_err(|s| self.error(id, p, "type", ValidationKind::Limit(s)))?;
                    if d.integer() {
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
        if let Value::Number(n) = value {
            let d = Decimal::new(n, limits)
                .map_err(|s| self.error(id, p, "", ValidationKind::Limit(s)))?;
            for (&key, bound) in &node.numbers {
                self.spend(
                    n.text().len().saturating_add(bound.digits.len()),
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
        let counts: &[(&str, &str, usize)] = match value {
            Value::String(s) => {
                self.spend(s.len(), id, p, "minLength")?;
                &[("minLength", "maxLength", s.chars().count())]
            }
            Value::Array(a) => &[("minItems", "maxItems", a.len())],
            Value::Object(o) => &[("minProperties", "maxProperties", o.len())],
            _ => &[],
        };
        for &(min, max, count) in counts {
            let n = Decimal::count(count);
            for (key, lower) in [(min, true), (max, false)] {
                if let Some((&key, bound)) = node.counts.get_key_value(key) {
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
        if let Value::Array(items) = value {
            if node.unique {
                for (i, a) in items.iter().enumerate() {
                    for b in &items[..i] {
                        let same = equal(a, b, limits, self.work).map_err(|s| {
                            self.error(id, p, "uniqueItems", ValidationKind::Limit(s))
                        })?;
                        assertion!(!same, "uniqueItems");
                    }
                }
            }
            let prefix = node
                .groups
                .get("prefixItems")
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut matches = 0usize;
            for (i, item) in items.iter().enumerate() {
                self.spend(1, id, p, "items")?;
                let at = self.child_path(id, p, &i.to_string())?;
                if let Some(&schema) = prefix.get(i).or_else(|| node.single.get("items")) {
                    child!(schema, item, &at, refs);
                }
                if let Some(&schema) = node.single.get("contains")
                    && self.run(schema, item, &at, depth + 1, refs, false)?
                {
                    matches += 1;
                }
            }
            if node.single.contains_key("contains") {
                let count = Decimal::count(matches);
                let min = node
                    .counts
                    .get("minContains")
                    .cloned()
                    .unwrap_or_else(|| Decimal::count(1));
                let keyword = if node.counts.contains_key("minContains") {
                    "minContains"
                } else {
                    "contains"
                };
                assertion!(count.cmp(&min) != Ordering::Less, keyword);
                if let Some(max) = node.counts.get("maxContains") {
                    assertion!(count.cmp(max) != Ordering::Greater, "maxContains");
                }
            }
        }
        if let Value::Object(object) = value {
            let mut members = BTreeMap::new();
            for (name, v) in object {
                self.spend(name.len().saturating_add(1), id, p, "properties")?;
                members.insert(name.as_str(), v);
            }
            for name in &node.required {
                self.spend(name.len().saturating_add(1), id, p, "required")?;
                assertion!(members.contains_key(name.as_str()), "required");
            }
            for (trigger, required) in &node.dependent {
                self.spend(trigger.len().saturating_add(1), id, p, "dependentRequired")?;
                if members.contains_key(trigger.as_str()) {
                    for name in required {
                        self.spend(name.len().saturating_add(1), id, p, "dependentRequired")?;
                        assertion!(members.contains_key(name.as_str()), "dependentRequired");
                    }
                }
            }
            for (name, v) in object {
                let at = self.child_path(id, p, name)?;
                if let Some(&schema) = node.single.get("propertyNames") {
                    child!(schema, &Value::String(name.clone()), &at, refs);
                }
                if let Some(&schema) = node
                    .properties
                    .get(name)
                    .or_else(|| node.single.get("additionalProperties"))
                {
                    child!(schema, v, &at, refs);
                }
            }
        }
        if let Some(group) = node.groups.get("allOf") {
            for &schema in group {
                child!(schema, value, p, refs);
            }
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(group) = node.groups.get(key) {
                let mut count = 0usize;
                for &schema in group {
                    if self.run(schema, value, p, depth + 1, refs, false)? {
                        count += 1;
                    }
                    if key == "anyOf" && count == 1 {
                        break;
                    }
                }
                assertion!(
                    if key == "anyOf" {
                        count > 0
                    } else {
                        count == 1
                    },
                    key
                );
            }
        }
        if let Some(&schema) = node.single.get("not") {
            assertion!(!self.run(schema, value, p, depth + 1, refs, false)?, "not");
        }
        if let Some(&condition) = node.single.get("if") {
            let key = if self.run(condition, value, p, depth + 1, refs, false)? {
                "then"
            } else {
                "else"
            };
            if let Some(&schema) = node.single.get(key) {
                child!(schema, value, p, refs);
            }
        }
        Ok(valid)
    }
}

impl Schema {
    /// Searches deterministically for an example using the shared codec LCG.
    /// Every returned value passes this schema's validator and the supplied
    /// size bounds. The search uses hints, exact constants, intersected bounds,
    /// and branch candidates; it is not a complete constraint solver. Numeric
    /// candidate selection may use `f64`, but acceptance always uses exact text.
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
                Err(GenerationError::Limit("max_work")) => {
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
                self.options.limits.max_instance_nodes,
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
                active: Vec::new(),
                errors: Vec::new(),
                cap: 1,
                truncated: false,
            }
            .run(0, &value, "", 0, 0, false);
            generator
                .work
                .spend(budget - work.left)
                .map_err(GenerationError::Limit)?;
            match result {
                Ok(true) => return Ok(value),
                Ok(false) => last = GenerationError::NoCandidate,
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
        self.work.spend(n).map_err(GenerationError::Limit)
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
            if let Some(group) = node.groups.get("allOf") {
                self.spend(group.len())?;
                ids.extend(group);
            }
            for key in ["anyOf", "oneOf"] {
                if let Some(group) = node.groups.get(key)
                    && let Some(&id) = group.get(self.rng.index(group.len()))
                {
                    ids.push(id);
                }
            }
            if let Some(&condition) = node.single.get("if") {
                if self.rng.coin() {
                    ids.push(condition);
                    if let Some(&id) = node.single.get("then") {
                        ids.push(id);
                    }
                } else if let Some(&id) = node.single.get("else") {
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
        min: &str,
        max: &str,
        cap: usize,
    ) -> Result<(usize, usize), GenerationError> {
        let (mut low, mut high) = (0, cap);
        for &id in ids {
            let node = &self.schema.nodes[id];
            if let Some(n) = node.counts.get(min) {
                low = low.max(n.as_usize().ok_or(GenerationError::NoCandidate)?);
            }
            if let Some(n) = node.counts.get(max)
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
                || node.counts.contains_key("minProperties")
            {
                preferred = OBJECT;
            } else if node.single.contains_key("items")
                || node.single.contains_key("contains")
                || node.groups.contains_key("prefixItems")
                || node.counts.contains_key("minItems")
            {
                preferred = ARRAY;
            } else if node.counts.contains_key("minLength") {
                preferred = STRING;
            } else if !node.numbers.is_empty() {
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
                let (low, high) =
                    self.bounds(&ids, "minLength", "maxLength", self.limits.string_length)?;
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
            for (&key, d) in &self.schema.nodes[id].numbers {
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
        let (mut low, high) =
            self.bounds(ids, "minItems", "maxItems", self.limits.items.min(*room))?;
        for &id in ids {
            let node = &self.schema.nodes[id];
            if node.single.contains_key("contains") {
                let n = node
                    .counts
                    .get("minContains")
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
                    .groups
                    .get("prefixItems")
                    .and_then(|p| p.get(i))
                    .or_else(|| node.single.get("items"));
                if let Some(&id) = child {
                    children.push(id);
                }
                if let Some(&id) = node.single.get("contains") {
                    let need = node
                        .counts
                        .get("minContains")
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
        let (low, high) = self.bounds(
            ids,
            "minProperties",
            "maxProperties",
            self.limits.items.min(*room),
        )?;
        let mut names = BTreeSet::new();
        let mut available = BTreeSet::new();
        for &id in ids {
            let node = &self.schema.nodes[id];
            self.spend(node.required.len().saturating_add(node.properties.len()))?;
            names.extend(node.required.iter().cloned());
            available.extend(node.properties.keys().cloned());
            if let Some(&id) = node.single.get("propertyNames") {
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
        loop {
            let previous = names.len();
            for &id in ids {
                for (trigger, required) in &self.schema.nodes[id].dependent {
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
            }
            if names.len() > high {
                return Err(GenerationError::NoCandidate);
            }
            if previous == names.len() {
                break;
            }
        }
        let mut out = Vec::new();
        for name in names {
            if name.chars().count() > self.limits.string_length {
                return Err(GenerationError::Limit("string_length"));
            }
            let mut children = Vec::new();
            for &id in ids {
                let node = &self.schema.nodes[id];
                if let Some(&id) = node
                    .properties
                    .get(&name)
                    .or_else(|| node.single.get("additionalProperties"))
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
    use super::*;
    use fictionet::stdlib::codec::{contract, test_support};
    use fictionet::stdlib::json;

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
            r#"{"$defs":{"a":{"$anchor":"x"},"b":{"$anchor":"x"}}}"#,
        ] {
            assert_eq!(
                Schema::compile(&value(s)).unwrap_err().kind,
                CompileErrorKind::InvalidAnchor
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
                CompileErrorKind::UnsupportedPattern
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
            assert_eq!(r.annotations.len(), 1);
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
            CompileErrorKind::DuplicateKey
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
                        max_errors: cap,
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
            CompileErrorKind::Limit("max_number_exponent")
        ));
        assert_eq!(
            schema("true").validate(&huge).errors[0].kind,
            ValidationKind::Limit("max_number_exponent")
        );
        let source = Value::Object(vec![(
            "enum".into(),
            Value::Array(vec![Value::Null; 17_000]),
        )]);
        assert_eq!(
            Schema::compile(&source).unwrap_err().kind,
            CompileErrorKind::Limit("max_schema_nodes")
        );
        let mut deep = Value::Null;
        for _ in 0..200 {
            deep = Value::Array(vec![deep]);
        }
        assert!(matches!(
            Schema::compile(&deep).unwrap_err().kind,
            CompileErrorKind::Limit("max_depth")
        ));
        assert_eq!(
            schema("true").validate(&deep).errors[0].kind,
            ValidationKind::Limit("max_depth")
        );
        let options = Options {
            limits: Limits {
                max_ref_depth: 1,
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
            ValidationKind::Limit("max_ref_depth")
        );
        let options = Options {
            limits: Limits {
                max_validation_depth: 0,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(&value(r#"{"allOf":[true]}"#), options).unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("max_validation_depth")
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
                max_work: 5000,
                ..Limits::default()
            },
            ..Options::default()
        };
        let s = Schema::compile_with(&source, options).unwrap();
        assert_eq!(
            s.validate(&Value::Null).errors[0].kind,
            ValidationKind::Limit("max_work")
        );
        let options = Options {
            limits: Limits {
                max_pointer_bytes: 3,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert!(Schema::compile_with(&value(r#"{"properties":{"long":true}}"#), options).is_err());
        let options = Options {
            limits: Limits {
                max_work: 0,
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
        let mut rng = test_support::Lcg::new(27);
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
                max_schema_nodes: 0,
                ..Limits::default()
            },
            Limits {
                max_bytes: 0,
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
                    max_instance_nodes: 1,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&value("[1]")).errors[0].kind,
            ValidationKind::Limit("max_instance_nodes")
        );
        let s = Schema::compile_with(
            &Value::Bool(true),
            Options {
                limits: Limits {
                    max_bytes: 4,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.validate(&Value::from("1234")).errors[0].kind,
            ValidationKind::Limit("max_bytes")
        );
        let s = Schema::compile_with(
            &Value::Bool(true),
            Options {
                limits: Limits {
                    max_depth: usize::MAX,
                    max_number_exponent: usize::MAX,
                    max_work: usize::MAX,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap();
        assert_eq!(s.options().limits, Limits::default());
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
            ValidationKind::Limit("max_work")
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
                    max_work: 2500,
                    ..Limits::default()
                },
                ..Options::default()
            },
        )
        .unwrap_err();
        assert_eq!(e.kind, CompileErrorKind::Limit("max_work"));
    }
}
