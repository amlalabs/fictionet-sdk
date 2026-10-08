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
    /// Fixed layout of each block, by source name.
    pub(crate) blocks: BTreeMap<String, BlockLayout>,
    /// Fields, by type name and field index, whose offset skips bytes.
    pub(crate) gaps: BTreeSet<(String, usize)>,
}
/// Where a block's fixed fields end.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BlockLayout {
    /// End of the fixed fields in bytes.
    pub(crate) end: usize,
    /// Index of the first variable field, or the field count.
    pub(crate) split: usize,
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
/// What validation needs to know about a named type while checking others.
#[derive(Clone, Debug)]
enum Kind {
    Struct,
    Block(usize),
    Enum(Primitive, Vec<(String, i128)>),
    Other,
}
/// Checks resource limits, identifiers, widths, references, and cycles.
/// Missing collection limits are filled from `limits.max_collection`.
/// Minimum encoded sizes and nesting depths must fit the configured limits.
/// Mandatory cycles with no finite value are refused. Other cycles are
/// recorded and use the generated `MAX_DEPTH` guard on both read and write.
/// Unions may not take part in cycles. Field offsets, block layouts,
/// headers, ranges, and constants are checked against their types.
pub fn validate(mut schema: Schema, limits: Limits) -> Result<ValidatedSchema, Error> {
    match validate_inner(&mut schema, limits) {
        Ok((recursion, minimum, blocks, gaps)) => Ok(ValidatedSchema {
            schema,
            limits,
            recursion,
            minimum,
            blocks,
            gaps,
        }),
        Err(error) => {
            // A caller may construct an arbitrarily deep boxed IR. Dispose of
            // rejected field chains iteratively, including before returning an error.
            for named in schema.types {
                if let Definition::Struct(fields) | Definition::Block { fields, .. } =
                    named.definition
                {
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
type Validated = (
    Recursion,
    BTreeMap<String, Minimum>,
    BTreeMap<String, BlockLayout>,
    BTreeSet<(String, usize)>,
);
fn validate_inner(schema: &mut Schema, limits: Limits) -> Result<Validated, Error> {
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
    let kinds: BTreeMap<String, Kind> = schema
        .types
        .iter()
        .map(|t| {
            let kind = match &t.definition {
                Definition::Struct(_) => Kind::Struct,
                Definition::Block { length, .. } => Kind::Block(*length),
                Definition::Enum { repr, variants } => Kind::Enum(
                    *repr,
                    variants.iter().map(|v| (v.name.clone(), v.value)).collect(),
                ),
                _ => Kind::Other,
            };
            (t.name.clone(), kind)
        })
        .collect();
    let mut fields = 0usize;
    for t in &mut schema.types {
        let path = format!("types.{}", t.name);
        doc(&t.doc, &path)?;
        match &mut t.definition {
            Definition::Struct(fs) | Definition::Block { fields: fs, .. } => {
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
                scope(
                    fs.iter()
                        .filter(|f| matches!(f.ty, Type::Constant(_)))
                        .map(|f| f.name.as_str()),
                    IdentifierCase::Constant,
                    &path,
                    &[],
                )?;
                for f in fs {
                    let path = format!("{path}.{}", f.name);
                    doc(&f.doc, &path)?;
                    if let Type::Constant(c) = &f.ty {
                        if f.offset.is_some() || f.byte_order.is_some() {
                            return Err(err(
                                ErrorKind::InvalidSize,
                                &path,
                                "constants take no offset or byte order",
                            ));
                        }
                        constant(c, &path, &kinds)?;
                    } else {
                        normalize(&mut f.ty, &path, 0, &kinds, limits)?;
                    }
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
            Definition::Union { header, cases } => {
                fields += cases.len() + header.fields.len();
                scope(
                    cases.iter().map(|c| c.name.as_str()),
                    IdentifierCase::Type,
                    &path,
                    &[],
                )?;
                check_header(header, &path, HeaderUse::Union)?;
                if cases.is_empty() {
                    return Err(err(
                        ErrorKind::InvalidValue,
                        &path,
                        "unions need at least one case",
                    ));
                }
                let tag = header
                    .fields
                    .iter()
                    .find(|f| f.role == Role::Tag)
                    .map_or(0, field_max);
                let length = header
                    .fields
                    .iter()
                    .find(|f| f.role == Role::Length)
                    .map(field_max);
                let mut tags = BTreeSet::new();
                for c in cases.iter() {
                    let path = format!("{path}.{}", c.name);
                    doc(&c.doc, &path)?;
                    if c.tag > tag || !tags.insert(c.tag) {
                        return Err(err(
                            ErrorKind::InvalidValue,
                            &path,
                            "case tag above the tag field's maximum, or duplicated",
                        ));
                    }
                    item_kind(&c.item, length, &path, &kinds, false)?;
                }
            }
        }
        if fields > MAX_FIELDS {
            return Err(err(ErrorKind::IrLimit, &path, "MAX_FIELDS exceeded"));
        }
    }
    for s in &schema.streams {
        if !kinds.contains_key(&s.item) {
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
    let mut blocks = BTreeMap::new();
    let mut gaps = BTreeSet::new();
    for t in &schema.types {
        let Some(fs) = t.definition.fields() else {
            continue;
        };
        let mut position = Some(0usize);
        let mut layout = BlockLayout {
            end: 0,
            split: fs.len(),
        };
        for (i, f) in fs.iter().enumerate() {
            let path = format!("types.{}.{}", t.name, f.name);
            let size = fixed_size(&f.ty, &definitions, &mut fixed, &mut BTreeSet::new());
            if let Some(expected) = f.fixed_size
                && size != Some(expected)
            {
                return Err(err(
                    ErrorKind::InvalidSize,
                    &path,
                    "fixed_size disagrees with wire type",
                ));
            }
            if matches!(f.ty, Type::Constant(_)) {
                continue;
            }
            if let Some(offset) = f.offset {
                if size.is_none() && matches!(t.definition, Definition::Block { .. }) {
                    return Err(err(
                        ErrorKind::InvalidSize,
                        &path,
                        "variable-size block fields cannot have an offset",
                    ));
                }
                match position {
                    Some(p) if offset >= p && offset <= limits.max_message => {
                        if offset > p {
                            gaps.insert((t.name.clone(), i));
                        }
                        position = Some(offset);
                    }
                    _ => {
                        return Err(err(
                            ErrorKind::InvalidSize,
                            &path,
                            "offset overlaps an earlier field or follows a variable field",
                        ));
                    }
                }
            }
            position = position.zip(size).and_then(|(p, n)| p.checked_add(n));
            if size.is_none() {
                layout.split = layout.split.min(i);
            } else if layout.split < fs.len() && matches!(t.definition, Definition::Block { .. }) {
                return Err(err(
                    ErrorKind::InvalidSize,
                    &path,
                    "block fields of fixed size must precede variable fields",
                ));
            } else if let Some(p) = position {
                layout.end = p;
            }
        }
        if let Definition::Block { length, .. } = &t.definition {
            if layout.end > *length || *length > limits.max_message {
                return Err(err(
                    ErrorKind::InvalidSize,
                    &format!("types.{}", t.name),
                    "block length is below its fixed fields or above max_message",
                ));
            }
            blocks.insert(t.name.clone(), layout);
        }
    }
    let mut minimum = BTreeMap::new();
    loop {
        let before = minimum.len();
        for t in &schema.types {
            let value = match &t.definition {
                Definition::Struct(fs) => layout_minimum(fs, &minimum, None),
                Definition::Block { length, fields } => layout_minimum(
                    fields,
                    &minimum,
                    Some((*length, blocks.get(&t.name).map_or(0, |b| b.end))),
                ),
                Definition::Enum { repr, .. } => Some(Minimum {
                    size: repr.bytes(),
                    depth: 0,
                }),
                Definition::Set { repr, .. } => Some(Minimum {
                    size: repr.bytes(),
                    depth: 0,
                }),
                // Cases read through a length may be shorter than declared,
                // so only the header is a safe lower bound.
                Definition::Union { header, cases } => cases
                    .iter()
                    .filter_map(|c| minimum.get(&c.item).map(|m: &Minimum| m.depth))
                    .min()
                    .map(|depth| Minimum {
                        size: header.size,
                        depth,
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
                match &t.definition {
                    Definition::Struct(fs) | Definition::Block { fields: fs, .. } => {
                        for f in fs {
                            references(&f.ty, &mut refs, through_groups);
                        }
                    }
                    Definition::Union { cases, .. } => {
                        refs.extend(cases.iter().map(|c| c.item.clone()));
                    }
                    _ => {}
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
            if matches!(t.definition, Definition::Union { .. }) {
                return Err(err(
                    ErrorKind::IrLimit,
                    &format!("types.{}", t.name),
                    "unions may not take part in reference cycles",
                ));
            }
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
    Ok((recursion, minimum, blocks, gaps))
}
fn layout_minimum(
    fields: &[Field],
    named: &BTreeMap<String, Minimum>,
    block: Option<(usize, usize)>,
) -> Option<Minimum> {
    let mut sum = Minimum::default();
    for f in fields {
        if matches!(f.ty, Type::Constant(_)) {
            continue;
        }
        let field = minimum_type(&f.ty, named)?;
        if let Some(offset) = f.offset {
            sum.size = sum.size.max(offset);
        }
        sum.size = sum.size.saturating_add(field.size);
        sum.depth = sum.depth.max(field.depth);
    }
    // Blocks read through their codec use the declared length in place of
    // the end of their fixed fields.
    if let Some((length, end)) = block {
        sum.size = sum.size.saturating_sub(end).saturating_add(length);
    }
    Some(sum)
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
        Type::Scalar(p) | Type::Range { item: p, .. } => p.bytes(),
        Type::Bytes(Length::Fixed(n)) | Type::String(Length::Fixed(n)) => *n,
        Type::Bytes(Length::Variable { prefix, .. })
        | Type::String(Length::Variable { prefix, .. }) => prefix.bytes(),
        Type::Group { count, .. } => count.bytes(),
        Type::BlockGroup { header, .. } => header.size,
        Type::Constant(_) => 0,
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
        Type::BlockGroup { item, .. } if through_groups => refs.push(item.clone()),
        Type::Optional { item, .. } => references(item, refs, through_groups),
        _ => {}
    }
}
fn field_max(f: &HeaderField) -> u64 {
    f.max.unwrap_or(f.width.max())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderUse {
    Union,
    Group,
}
fn check_header(h: &Header, path: &str, usage: HeaderUse) -> Result<(), Error> {
    if h.size > MAX_HEADER || h.fields.len() > MAX_HEADER {
        return Err(err(ErrorKind::IrLimit, path, "header exceeds MAX_HEADER"));
    }
    let mut spans = Vec::new();
    let (mut tags, mut lengths, mut counts, mut versions) = (0, 0, 0, 0);
    for f in &h.fields {
        let p = format!("{path}.header.{}", f.name);
        if f.name.is_empty() || f.name.len() > MAX_NAME {
            return Err(err(
                ErrorKind::InvalidName,
                &p,
                "header field names must be 1..=MAX_NAME bytes",
            ));
        }
        let end = f.offset.checked_add(f.width.bytes());
        if end.is_none_or(|end| end > h.size) {
            return Err(err(
                ErrorKind::InvalidSize,
                &p,
                "field ends past the header",
            ));
        }
        spans.push((f.offset, f.width.bytes()));
        let max = field_max(f);
        if max > f.width.max() {
            return Err(err(ErrorKind::InvalidValue, &p, "max exceeds the width"));
        }
        match &f.role {
            Role::Tag => tags += 1,
            Role::Length => lengths += 1,
            Role::Count => counts += 1,
            Role::Version { current, minimum } => {
                versions += 1;
                if minimum > current || *current > max {
                    return Err(err(
                        ErrorKind::InvalidValue,
                        &p,
                        "version needs minimum <= current <= max",
                    ));
                }
            }
            Role::Constant(v) => {
                if *v > max {
                    return Err(err(ErrorKind::InvalidValue, &p, "constant above max"));
                }
            }
        }
    }
    spans.sort_unstable();
    if spans.windows(2).any(|w| match w {
        [(a, n), (b, _)] => a + n > *b,
        _ => false,
    }) {
        return Err(err(ErrorKind::InvalidSize, path, "header fields overlap"));
    }
    let valid = match usage {
        HeaderUse::Union => tags == 1 && lengths <= 1 && counts == 0 && versions <= 1,
        HeaderUse::Group => counts == 1 && lengths <= 1 && tags == 0 && versions == 0,
    };
    if !valid {
        return Err(err(
            ErrorKind::InvalidValue,
            path,
            "unions need one tag, groups one count; at most one length and version",
        ));
    }
    Ok(())
}
/// Checks that `item` names a type usable as a case or entry. A header
/// length requires a block whose declared length fits the length field.
fn item_kind(
    item: &str,
    length: Option<u64>,
    path: &str,
    kinds: &BTreeMap<String, Kind>,
    entry: bool,
) -> Result<(), Error> {
    let kind = kinds
        .get(item)
        .ok_or_else(|| err(ErrorKind::UnknownReference, path, "unknown named type"))?;
    match (kind, length) {
        (Kind::Block(n), Some(max)) if u64::try_from(*n).is_ok_and(|n| n <= max) => Ok(()),
        (_, Some(_)) => Err(err(
            ErrorKind::InvalidValue,
            path,
            "a header length needs a block whose length fits the length field",
        )),
        (Kind::Struct | Kind::Block(_), None) => Ok(()),
        (_, None) if !entry => Ok(()),
        _ => Err(err(
            ErrorKind::InvalidValue,
            path,
            "group entries must be structs or blocks",
        )),
    }
}
fn constant(c: &Constant, path: &str, kinds: &BTreeMap<String, Kind>) -> Result<(), Error> {
    let ok = match c {
        Constant::Number { ty, value } => fits(value, *ty),
        Constant::Bytes(b) => b.len() <= MAX_CONSTANT,
        Constant::Variant { ty, name } => match kinds.get(ty) {
            Some(Kind::Enum(_, variants)) => variants.iter().any(|(n, _)| n == name),
            Some(_) => false,
            None => {
                return Err(err(ErrorKind::UnknownReference, path, "unknown named type"));
            }
        },
    };
    if ok {
        Ok(())
    } else {
        Err(err(
            ErrorKind::InvalidValue,
            path,
            "constant does not fit its type, exceeds MAX_CONSTANT, or names no variant",
        ))
    }
}
fn number_le(a: &Number, b: &Number, p: Primitive) -> bool {
    let float = |n: &Number| match n {
        Number::Integer(n) => *n as f64,
        Number::Float(f) => *f,
    };
    match (a, b) {
        (Number::Integer(a), Number::Integer(b)) if !p.is_float() => a <= b,
        _ => float(a) <= float(b),
    }
}
fn normalize(
    ty: &mut Type,
    path: &str,
    depth: usize,
    kinds: &BTreeMap<String, Kind>,
    limits: Limits,
) -> Result<(), Error> {
    if depth >= MAX_NESTING {
        return Err(err(ErrorKind::IrLimit, path, "MAX_NESTING exceeded"));
    }
    match ty {
        Type::Scalar(_) => {}
        Type::Range { item, min, max } => {
            if !fits(min, *item) || !fits(max, *item) || !number_le(min, max, *item) {
                return Err(err(
                    ErrorKind::InvalidValue,
                    path,
                    "range bounds must fit the scalar and satisfy min <= max",
                ));
            }
        }
        Type::Constant(_) => {
            return Err(err(
                ErrorKind::InvalidValue,
                path,
                "constants are only allowed as direct struct fields",
            ));
        }
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
            normalize(item, path, depth + 1, kinds, limits)?;
        }
        Type::BlockGroup {
            item,
            header,
            limit,
        } => {
            check_header(header, path, HeaderUse::Group)?;
            let count = header
                .fields
                .iter()
                .find(|f| f.role == Role::Count)
                .ok_or_else(|| err(ErrorKind::InvalidValue, path, "group header needs a count"))?;
            let length = header
                .fields
                .iter()
                .find(|f| f.role == Role::Length)
                .map(field_max);
            if limit.is_none() {
                let max = usize::try_from(field_max(count)).unwrap_or(usize::MAX);
                *limit = Some(limits.max_collection.min(max));
            }
            collection(limit, count.width, limits, path)?;
            if limit.is_some_and(|n| u64::try_from(n).map_or(true, |n| n > field_max(count))) {
                return Err(err(
                    ErrorKind::InvalidLimit,
                    path,
                    "group limit exceeds the count field's maximum",
                ));
            }
            item_kind(item, length, path, kinds, true)?;
        }
        Type::Optional { item, presence } => {
            if let Presence::Null(null) = presence {
                let valid = match item.as_ref() {
                    Type::Scalar(p) => fits(null, *p),
                    Type::Range { item: p, min, max } => {
                        // Check representability before comparing as floats.
                        fits(null, *p) && fits(min, *p) && fits(max, *p)
                            && !(number_le(min, null, *p) && number_le(null, max, *p))
                    }
                    Type::Ref(name) => match (kinds.get(name), &*null) {
                        (Some(Kind::Enum(repr, variants)), Number::Integer(n)) => {
                            fits(null, *repr) && variants.iter().all(|(_, v)| v != n)
                        }
                        _ => false,
                    },
                    _ => false,
                };
                if !valid {
                    return Err(err(
                        ErrorKind::InvalidValue,
                        path,
                        "null requires a scalar, range, or enum item and an exactly representable value that is not a variant and lies outside the range",
                    ));
                }
            }
            normalize(item, path, depth + 1, kinds, limits)?;
        }
        Type::Ref(name) => {
            if !kinds.contains_key(name) {
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
/// Wire size of fixed-size layouts. Offsets that move backwards make a
/// layout invalid; validation reports them separately.
fn fixed_size(
    ty: &Type,
    defs: &BTreeMap<&str, &Definition>,
    memo: &mut BTreeMap<String, Option<usize>>,
    active: &mut BTreeSet<String>,
) -> Option<usize> {
    match ty {
        Type::Scalar(p) | Type::Range { item: p, .. } => Some(p.bytes()),
        Type::Bytes(Length::Fixed(n)) | Type::String(Length::Fixed(n)) => Some(*n),
        Type::Constant(_) => Some(0),
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
                Definition::Union { .. } => None,
                Definition::Struct(fs) => fs.iter().try_fold(0usize, |sum, f| {
                    let size = fixed_size(&f.ty, defs, memo, active)?;
                    if matches!(f.ty, Type::Constant(_)) {
                        return Some(sum);
                    }
                    let start = match f.offset {
                        Some(o) if o >= sum => o,
                        Some(_) => return None,
                        None => sum,
                    };
                    start.checked_add(size)
                }),
                Definition::Block { length, fields } => {
                    let all_fixed = fields
                        .iter()
                        .all(|f| fixed_size(&f.ty, defs, memo, active).is_some());
                    all_fixed.then_some(*length)
                }
            };
            active.remove(name);
            memo.insert(name.clone(), size);
            size
        }
        _ => None,
    }
}
