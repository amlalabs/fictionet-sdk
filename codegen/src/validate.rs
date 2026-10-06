//! Validation and stable Rust name mapping.
use crate::{Error, ErrorKind, ir::*};
use std::collections::{BTreeMap, BTreeSet};

/// Identifier spelling selected for an emitted scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierCase {
    /// UpperCamelCase for types and enum variants.
    Type,
    /// snake_case for fields.
    Field,
    /// SCREAMING_SNAKE_CASE for set constants.
    Constant,
}
/// Maps ASCII words and case boundaries to Rust identifiers.
///
/// Non-ASCII and punctuation bytes separate words. Leading digits gain `N`
/// for types or `n_` for fields (`N_` for constants). Keywords gain `_`.
/// Names with no ASCII letters or digits are refused. Scope collisions are
/// checked by [`validate`], not by this function.
pub fn rust_identifier(name: &str, case: IdentifierCase) -> Result<String, Error> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(err(
            ErrorKind::InvalidName,
            "name",
            "name length must be 1..=MAX_NAME",
        ));
    }
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        let previous = i.checked_sub(1).and_then(|i| chars.get(i));
        let next = chars.get(i + 1);
        let boundary = ch.is_ascii_uppercase()
            && previous.is_some_and(|c| {
                c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || (c.is_ascii_uppercase() && next.is_some_and(char::is_ascii_lowercase))
            });
        if boundary && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        word.push(ch.to_ascii_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    if words.is_empty() {
        return Err(err(
            ErrorKind::InvalidName,
            "name",
            "name requires an ASCII letter or digit",
        ));
    }
    let mut result = match case {
        IdentifierCase::Type => words
            .iter()
            .map(|s| {
                let mut c = s.chars();
                let mut out = String::new();
                if let Some(first) = c.next() {
                    out.push(first.to_ascii_uppercase());
                }
                out.extend(c);
                out
            })
            .collect(),
        IdentifierCase::Field => words.join("_"),
        IdentifierCase::Constant => words.join("_").to_ascii_uppercase(),
    };
    if result.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        result.insert_str(
            0,
            match case {
                IdentifierCase::Type => "N",
                IdentifierCase::Field => "n_",
                IdentifierCase::Constant => "N_",
            },
        );
    }
    if KEYWORDS.contains(&result.as_str()) {
        result.push('_');
    }
    Ok(result)
}
const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen", "union",
];
const RESERVED: &[&str] = &[
    "Error", "String", "Vec", "Box", "Option", "Result", "Some", "None", "Ok", "Err",
];

/// A validated schema with resolved limits and detected recursive definitions.
/// Its private fields prevent bypassing validation before emission.
#[derive(Clone, Debug)]
pub struct ValidatedSchema {
    pub(crate) schema: Schema,
    pub(crate) limits: Limits,
    pub(crate) recursion: Recursion,
    pub(crate) minimum: BTreeMap<String, Minimum>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Recursion {
    types: BTreeSet<String>,
    boxed: BTreeSet<(String, String)>,
}
impl Recursion {
    pub(crate) fn needs_box(&self, owner: &str, target: &str) -> bool {
        self.boxed.contains(&(owner.into(), target.into()))
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Minimum {
    pub(crate) size: usize,
    depth: usize,
}
impl ValidatedSchema {
    /// Normalized schema. Every variable-length item has an explicit limit.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }
    /// Limits baked into the generated module.
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Source names participating in reference cycles, in sorted order.
    pub fn recursive_types(&self) -> impl Iterator<Item = &str> {
        self.recursion.types.iter().map(String::as_str)
    }
}
fn err(kind: ErrorKind, path: &str, message: &str) -> Error {
    Error::new(kind, path, message)
}
fn doc(s: &str, path: &str) -> Result<(), Error> {
    if s.len() > MAX_DOC {
        Err(err(ErrorKind::IrLimit, path, "MAX_DOC exceeded"))
    } else {
        Ok(())
    }
}
fn scope<'a>(
    names: impl Iterator<Item = &'a str>,
    case: IdentifierCase,
    path: &str,
    reserved: &[&str],
) -> Result<(), Error> {
    let mut raw = BTreeSet::new();
    let mut mapped = BTreeSet::new();
    for name in names {
        let rust = rust_identifier(name, case).map_err(|mut e| {
            e.location = path.into();
            e
        })?;
        let p = format!("{path}.{name}");
        if !raw.insert(name) {
            return Err(err(ErrorKind::DuplicateName, &p, "duplicate source name"));
        }
        if reserved.contains(&rust.as_str()) || !mapped.insert(rust) {
            return Err(err(
                ErrorKind::RustCollision,
                &p,
                "Rust identifier collision",
            ));
        }
    }
    Ok(())
}
/// Checks resource limits, identifiers, widths, references, and cycles.
/// Missing collection limits are filled from `limits.max_collection`.
/// Minimum encoded sizes and nesting depths must fit the configured limits.
/// Mandatory cycles with no finite value are refused. Other cycles are
/// recorded and use the generated `MAX_DEPTH` guard on both read and write.
pub fn validate(mut schema: Schema, limits: Limits) -> Result<ValidatedSchema, Error> {
    match validate_inner(&mut schema, limits) {
        Ok((recursion, minimum)) => Ok(ValidatedSchema {
            schema,
            limits,
            recursion,
            minimum,
        }),
        Err(error) => {
            // A caller may construct an arbitrarily deep boxed IR. Dispose of
            // rejected field chains iteratively, including before returning an error.
            for named in schema.types {
                if let Definition::Struct(fields) = named.definition {
                    for field in fields {
                        let mut ty = field.ty;
                        while let Type::Group { item, .. } | Type::Optional { item, .. } = ty {
                            ty = *item;
                        }
                    }
                }
            }
            Err(error)
        }
    }
}
fn validate_inner(
    schema: &mut Schema,
    limits: Limits,
) -> Result<(Recursion, BTreeMap<String, Minimum>), Error> {
    if !(1..=16 << 20).contains(&limits.max_message)
        || limits.max_collection > 1 << 20
        || !(1..=64).contains(&limits.max_depth)
        || !(1..=64 << 20).contains(&limits.max_allocation)
        || !(1..=1 << 20).contains(&limits.max_nodes)
    {
        return Err(err(
            ErrorKind::InvalidLimit,
            "limits",
            "message <=16 MiB; collection <=1 MiB; depth 1..=64; allocation <=64 MiB; nodes <=1 MiB; other limits positive",
        ));
    }
    if schema.types.len() > MAX_TYPES || schema.streams.len() > MAX_TYPES {
        return Err(err(ErrorKind::IrLimit, "schema", "MAX_TYPES exceeded"));
    }
    doc(&schema.doc, "schema.doc")?;
    scope(
        schema
            .types
            .iter()
            .map(|t| t.name.as_str())
            .chain(schema.streams.iter().map(|s| s.name.as_str())),
        IdentifierCase::Type,
        "schema",
        RESERVED,
    )?;
    let names: BTreeSet<String> = schema.types.iter().map(|t| t.name.clone()).collect();
    let mut fields = 0usize;
    for t in &mut schema.types {
        let path = format!("types.{}", t.name);
        doc(&t.doc, &path)?;
        match &mut t.definition {
            Definition::Struct(fs) => {
                fields += fs.len();
                if fs.len() > MAX_STRUCT_FIELDS {
                    return Err(err(ErrorKind::IrLimit, &path, "MAX_STRUCT_FIELDS exceeded"));
                }
                scope(
                    fs.iter().map(|f| f.name.as_str()),
                    IdentifierCase::Field,
                    &path,
                    &[],
                )?;
                for f in fs {
                    let path = format!("{path}.{}", f.name);
                    doc(&f.doc, &path)?;
                    normalize(&mut f.ty, &path, 0, &names, limits)?;
                }
            }
            Definition::Enum { repr, variants } => {
                fields += variants.len();
                scope(
                    variants.iter().map(|v| v.name.as_str()),
                    IdentifierCase::Type,
                    &path,
                    &[],
                )?;
                if repr.is_float() || variants.is_empty() {
                    return Err(err(
                        ErrorKind::InvalidValue,
                        &path,
                        "enums need an integer width and at least one variant",
                    ));
                }
                let mut values = BTreeSet::new();
                for v in variants {
                    doc(&v.doc, &path)?;
                    if !fits(&Number::Integer(v.value), *repr) || !values.insert(v.value) {
                        return Err(err(
                            ErrorKind::InvalidValue,
                            &format!("{path}.{}", v.name),
                            "enum value outside width or duplicated",
                        ));
                    }
                }
            }
            Definition::Set { repr, bits } => {
                fields += bits.len();
                scope(
                    bits.iter().map(|v| v.name.as_str()),
                    IdentifierCase::Constant,
                    &path,
                    &[],
                )?;
                let mut values = BTreeSet::new();
                for b in bits {
                    doc(&b.doc, &path)?;
                    if usize::from(b.bit) >= repr.bytes() * 8 || !values.insert(b.bit) {
                        return Err(err(
                            ErrorKind::InvalidValue,
                            &format!("{path}.{}", b.name),
                            "set bit outside width or duplicated",
                        ));
                    }
                }
            }
        }
        if fields > MAX_FIELDS {
            return Err(err(ErrorKind::IrLimit, &path, "MAX_FIELDS exceeded"));
        }
    }
    for s in &schema.streams {
        if !names.contains(&s.item) {
            return Err(err(
                ErrorKind::UnknownReference,
                &format!("streams.{}", s.name),
                "unknown item type",
            ));
        }
        if s.magic.len() > 256 {
            return Err(err(
                ErrorKind::IrLimit,
                &format!("streams.{}", s.name),
                "magic exceeds 256 bytes",
            ));
        }
    }
    let definitions: BTreeMap<&str, &Definition> = schema
        .types
        .iter()
        .map(|t| (t.name.as_str(), &t.definition))
        .collect();
    let mut fixed = BTreeMap::new();
    for t in &schema.types {
        if let Definition::Struct(fs) = &t.definition {
            for f in fs {
                if let Some(size) = f.fixed_size
                    && fixed_size(&f.ty, &definitions, &mut fixed, &mut BTreeSet::new())
                        != Some(size)
                {
                    return Err(err(
                        ErrorKind::InvalidSize,
                        &format!("types.{}.{}", t.name, f.name),
                        "fixed_size disagrees with wire type",
                    ));
                }
            }
        }
    }
    let mut minimum = BTreeMap::new();
    loop {
        let before = minimum.len();
        for t in &schema.types {
            let value = match &t.definition {
                Definition::Struct(fs) => fs.iter().try_fold(Minimum::default(), |mut sum, f| {
                    let field = minimum_type(&f.ty, &minimum)?;
                    sum.size = sum.size.saturating_add(field.size);
                    sum.depth = sum.depth.max(field.depth);
                    Some(sum)
                }),
                Definition::Enum { repr, .. } => Some(Minimum {
                    size: repr.bytes(),
                    depth: 0,
                }),
                Definition::Set { repr, .. } => Some(Minimum {
                    size: repr.bytes(),
                    depth: 0,
                }),
            };
            if let Some(mut value) = value {
                value.depth += 1;
                if value.size > limits.max_message || value.depth > limits.max_depth {
                    return Err(err(
                        ErrorKind::IrLimit,
                        &format!("types.{}", t.name),
                        "minimum encoded size or nesting depth exceeds the configured limit",
                    ));
                }
                minimum.insert(t.name.clone(), value);
            }
        }
        if before == minimum.len() {
            break;
        }
    }
    if let Some(t) = schema.types.iter().find(|t| !minimum.contains_key(&t.name)) {
        return Err(err(
            ErrorKind::UninhabitedType,
            &format!("types.{}", t.name),
            "mandatory cycle has no finite value",
        ));
    }
    let edges = |through_groups| -> BTreeMap<String, Vec<String>> {
        schema
            .types
            .iter()
            .map(|t| {
                let mut refs = Vec::new();
                if let Definition::Struct(fs) = &t.definition {
                    for f in fs {
                        references(&f.ty, &mut refs, through_groups);
                    }
                }
                (t.name.clone(), refs)
            })
            .collect()
    };
    let all = edges(true);
    let inline = edges(false);
    let mut recursion = Recursion::default();
    for t in &schema.types {
        if reachable(&t.name, &all).contains(&t.name) {
            recursion.types.insert(t.name.clone());
        }
        // A Vec already breaks the Rust layout cycle. Only inline paths need boxes.
        for source in reachable(&t.name, &inline) {
            if inline
                .get(&source)
                .is_some_and(|targets| targets.contains(&t.name))
            {
                recursion.boxed.insert((source, t.name.clone()));
            }
        }
    }
    Ok((recursion, minimum))
}
fn reachable(start: &str, edges: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut pending = edges.get(start).cloned().unwrap_or_default();
    let mut seen = BTreeSet::new();
    while let Some(next) = pending.pop() {
        if seen.insert(next.clone())
            && let Some(nexts) = edges.get(&next)
        {
            pending.extend(nexts.iter().cloned());
        }
    }
    seen
}
pub(crate) fn minimum_type(ty: &Type, named: &BTreeMap<String, Minimum>) -> Option<Minimum> {
    let size = match ty {
        Type::Ref(n) => return named.get(n).copied(),
        Type::Scalar(p) => p.bytes(),
        Type::Bytes(Length::Fixed(n)) | Type::String(Length::Fixed(n)) => *n,
        Type::Bytes(Length::Variable { prefix, .. })
        | Type::String(Length::Variable { prefix, .. }) => prefix.bytes(),
        Type::Group { count, .. } => count.bytes(),
        Type::Optional {
            presence: Presence::Flag(flag),
            ..
        } => flag.bytes(),
        Type::Optional {
            item,
            presence: Presence::Null(_),
        } => return minimum_type(item, named),
    };
    Some(Minimum { size, depth: 0 })
}
fn references(ty: &Type, refs: &mut Vec<String>, through_groups: bool) {
    match ty {
        Type::Ref(n) => refs.push(n.clone()),
        Type::Group { item, .. } if through_groups => references(item, refs, through_groups),
        Type::Optional { item, .. } => references(item, refs, through_groups),
        _ => {}
    }
}
fn normalize(
    ty: &mut Type,
    path: &str,
    depth: usize,
    names: &BTreeSet<String>,
    limits: Limits,
) -> Result<(), Error> {
    if depth >= MAX_NESTING {
        return Err(err(ErrorKind::IrLimit, path, "MAX_NESTING exceeded"));
    }
    match ty {
        Type::Scalar(_) => {}
        Type::Bytes(length) | Type::String(length) => match length {
            Length::Fixed(n) => {
                if *n > limits.max_message {
                    return Err(err(
                        ErrorKind::InvalidSize,
                        path,
                        "fixed data exceeds max_message",
                    ));
                }
            }
            Length::Variable { prefix, limit } => collection(limit, *prefix, limits, path)?,
        },
        Type::Group { item, count, limit } => {
            collection(limit, *count, limits, path)?;
            normalize(item, path, depth + 1, names, limits)?;
        }
        Type::Optional { item, presence } => {
            if let Presence::Null(null) = presence {
                match item.as_ref() {
                    Type::Scalar(p) if fits(null, *p) => {}
                    _ => {
                        return Err(err(
                            ErrorKind::InvalidValue,
                            path,
                            "null requires a scalar and an exactly representable finite value",
                        ));
                    }
                }
            }
            normalize(item, path, depth + 1, names, limits)?;
        }
        Type::Ref(name) => {
            if !names.contains(name) {
                return Err(err(ErrorKind::UnknownReference, path, "unknown named type"));
            }
        }
    }
    Ok(())
}
fn collection(
    limit: &mut Option<usize>,
    width: Width,
    defaults: Limits,
    path: &str,
) -> Result<(), Error> {
    let n = *limit.get_or_insert(
        defaults
            .max_collection
            .min(usize::try_from(width.max()).unwrap_or(usize::MAX)),
    );
    if n > 1 << 20 || u64::try_from(n).map_or(true, |n| n > width.max()) {
        return Err(err(
            ErrorKind::InvalidLimit,
            path,
            "collection limit exceeds prefix width or one MiB",
        ));
    }
    Ok(())
}
pub(crate) fn fits(n: &Number, p: Primitive) -> bool {
    if p.is_float() {
        let f = match n {
            Number::Integer(n) => {
                let magnitude = n.unsigned_abs();
                let precision = if p == Primitive::F32 { 24 } else { 53 };
                let bits = u128::BITS - magnitude.leading_zeros();
                if bits > precision && magnitude.trailing_zeros() < bits - precision {
                    return false;
                }
                *n as f64
            }
            Number::Float(f) => *f,
        };
        return f.is_finite() && (p == Primitive::F64 || (f as f32) as f64 == f);
    }
    let Number::Integer(n) = n else {
        return false;
    };
    let bits = p.bytes() * 8;
    if p.is_signed() {
        let edge = 1i128 << (bits - 1);
        (-edge..edge).contains(n)
    } else {
        (0..(1i128 << bits)).contains(n)
    }
}
fn fixed_size(
    ty: &Type,
    defs: &BTreeMap<&str, &Definition>,
    memo: &mut BTreeMap<String, Option<usize>>,
    active: &mut BTreeSet<String>,
) -> Option<usize> {
    match ty {
        Type::Scalar(p) => Some(p.bytes()),
        Type::Bytes(Length::Fixed(n)) | Type::String(Length::Fixed(n)) => Some(*n),
        Type::Optional {
            item,
            presence: Presence::Null(_),
        } => fixed_size(item, defs, memo, active),
        Type::Ref(name) => {
            if let Some(size) = memo.get(name) {
                return *size;
            }
            if !active.insert(name.clone()) {
                return None;
            }
            let size = match defs.get(name.as_str())? {
                Definition::Enum { repr, .. } => Some(repr.bytes()),
                Definition::Set { repr, .. } => Some(repr.bytes()),
                Definition::Struct(fs) => fs.iter().try_fold(0usize, |sum, f| {
                    sum.checked_add(fixed_size(&f.ty, defs, memo, active)?)
                }),
            };
            active.remove(name);
            memo.insert(name.clone(), size);
            size
        }
        _ => None,
    }
}
