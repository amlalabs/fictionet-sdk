//! Generated SBE modules against the runtime SBE decoder, `stdlib::sbe`,
//! loaded with the same schema: CME MDP 3.0 in `stdlib::cme_mdp3`, and the
//! front end's sample schema in `codegen/tests/golden/sbe_sample.rs`.
//!
//! Messages come from a third, IR-driven encoder in this file. Each one is
//! decoded by both sides and compared value by value, re-encoded by both
//! sides and compared byte by byte, re-encoded by `stdlib::sbe` with longer
//! blocks and a newer version for the generated decoder, and mutated to
//! check that both sides accept and refuse the same bytes.
#![allow(dead_code)]
#[path = "../codegen/tests/golden/sbe_sample.rs"]
mod sample;

use fictionet::stdlib::{
    codec::{Lcg, Wire},
    sbe,
};
use fictionet_codegen::{
    Constant, Definition, Field, FrontEnd, IdentifierCase, Input, Length, Limits, NamedType,
    Number, Presence, Role, SbeFrontEnd, Schema, Type, ValidatedSchema, generate, rust_identifier,
    validate,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

const XML: &str = include_str!("../data/cme/templates_FixBinary.xml");
const SAMPLE: &str = include_str!("../codegen/tests/schemas/sbe_sample.xml");
const MODULE: &str = include_str!("../src/stdlib/cme_mdp3.rs");

fn input() -> Input {
    Input {
        name: "templates_FixBinary.xml".into(),
        bytes: XML.as_bytes().to_vec(),
    }
}
fn ir(xml: &str) -> ValidatedSchema {
    let limits = Limits::default();
    let input = Input {
        name: "schema.xml".into(),
        bytes: xml.as_bytes().to_vec(),
    };
    validate(SbeFrontEnd.parse(&[input], limits).unwrap(), limits).unwrap()
}

/// The hand-written part starts at this line. `BLESS_CODEGEN=1` replaces
/// everything before it with fresh generator output.
const MARKER: &str = "\n// Hand-written below this line";

#[test]
fn module_is_generator_output_plus_hand_written_framing() {
    let generated = generate("sbe", &[input()], Limits::default())
        .unwrap()
        .source;
    let tail = &MODULE[MODULE.find(MARKER).expect("marker")..];
    if std::env::var_os("BLESS_CODEGEN").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/stdlib/cme_mdp3.rs");
        std::fs::write(path, format!("{generated}{tail}")).unwrap();
        return;
    }
    assert_eq!(
        &MODULE[..MODULE.len() - tail.len()],
        generated,
        "src/stdlib/cme_mdp3.rs differs from the generator; set BLESS_CODEGEN=1 to update"
    );
}

/// A value as both sides can print it: leaves in schema order, with
/// brackets around byte arrays and groups. Constants are left out.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Int(i128),
    Null,
    Ident(String),
    Open,
    Close,
}

struct Ir<'a> {
    types: BTreeMap<&'a str, &'a NamedType>,
    rust_types: BTreeSet<String>,
    little: bool,
}
impl<'a> Ir<'a> {
    fn new(schema: &'a Schema) -> Self {
        Self {
            types: schema.types.iter().map(|t| (t.name.as_str(), t)).collect(),
            rust_types: schema
                .types
                .iter()
                .map(|t| rust_identifier(&t.name, IdentifierCase::Type).unwrap())
                .collect(),
            little: schema.byte_order == fictionet_codegen::ByteOrder::Little,
        }
    }
    fn get(&self, name: &str) -> &'a NamedType {
        self.types[name]
    }
    fn union(&self) -> (&'a fictionet_codegen::Header, &'a [fictionet_codegen::Case]) {
        match &self.get("Message").definition {
            Definition::Union { header, cases } => (header, cases),
            _ => unreachable!(),
        }
    }
    /// The oldest acting version the generated decoder reads.
    fn version(&self) -> u64 {
        self.union()
            .0
            .fields
            .iter()
            .find_map(|f| match f.role {
                Role::Version { minimum, .. } => Some(minimum),
                _ => None,
            })
            .unwrap()
    }
    fn bytes(&self, value: i128, width: usize) -> Vec<u8> {
        if self.little {
            value.to_le_bytes()[..width].to_vec()
        } else {
            value.to_be_bytes()[16 - width..].to_vec()
        }
    }
}

fn int(n: &Number) -> i128 {
    match n {
        Number::Integer(n) => *n,
        Number::Float(_) => panic!("the CME schema has no floats"),
    }
}
fn width(ty: &Type, ir: &Ir<'_>) -> usize {
    match ty {
        Type::Scalar(p) | Type::Range { item: p, .. } => p.bytes(),
        Type::Ref(n) => match &ir.get(n).definition {
            Definition::Enum { repr, .. } => repr.bytes(),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}
fn put(out: &mut Vec<u8>, at: usize, bytes: &[u8]) -> usize {
    let end = at + bytes.len();
    if out.len() < end {
        out.resize(end, 0);
    }
    out[at..end].copy_from_slice(bytes);
    end
}
fn variable(ty: &Type) -> bool {
    matches!(
        ty,
        Type::BlockGroup { .. } | Type::Bytes(Length::Variable { .. })
    )
}

/// The third encoder: random valid messages straight from the IR, with
/// the tokens each decoder should print.
struct Gen<'a> {
    ir: &'a Ir<'a>,
    rng: Lcg,
}
impl Gen<'_> {
    fn wide(&mut self) -> u128 {
        let mut n = 0u128;
        for _ in 0..5 {
            n = (n << 31) | u128::from(self.rng.next());
        }
        n
    }
    fn pick(&mut self, min: i128, max: i128) -> i128 {
        match self.rng.below(8) {
            0 => min,
            1 => max,
            _ => {
                let span = (max - min) as u128 + 1;
                min + (self.wide() % span) as i128
            }
        }
    }
    fn message(&mut self, case: usize) -> (Vec<u8>, Vec<Tok>) {
        let (header, cases) = self.ir.union();
        let case = &cases[case];
        let Definition::Block { length, .. } = &self.ir.get(&case.item).definition else {
            unreachable!()
        };
        let mut out = vec![0; header.size];
        for f in &header.fields {
            let value = match &f.role {
                Role::Length => *length as i128,
                Role::Tag => i128::from(case.tag),
                Role::Constant(v) => i128::from(*v),
                Role::Version { current, .. } => i128::from(*current),
                Role::Count => unreachable!(),
            };
            put(&mut out, f.offset, &self.ir.bytes(value, f.width.bytes()));
        }
        let mut toks = Vec::new();
        let start = out.len();
        self.block(&case.item, start, &mut out, &mut toks);
        (out, toks)
    }
    /// Writes a block or struct starting at `start`; returns its end.
    fn block(&mut self, name: &str, start: usize, out: &mut Vec<u8>, toks: &mut Vec<Tok>) -> usize {
        match &self.ir.get(name).definition {
            Definition::Block { length, fields } => {
                put(out, start, &vec![0; *length]);
                self.fields(fields, start, Some(*length), out, toks)
            }
            Definition::Struct(fields) => self.fields(fields, start, None, out, toks),
            _ => unreachable!(),
        }
    }
    fn fields(
        &mut self,
        fields: &[Field],
        start: usize,
        block: Option<usize>,
        out: &mut Vec<u8>,
        toks: &mut Vec<Tok>,
    ) -> usize {
        let mut pos = start;
        let mut in_block = block.is_some();
        for f in fields {
            if matches!(f.ty, Type::Constant(_)) {
                continue;
            }
            if let Some(o) = f.offset {
                pos = start + o;
            }
            if in_block && variable(&f.ty) {
                pos = start + block.unwrap();
                in_block = false;
            }
            pos = self.value(&f.ty, pos, out, toks);
        }
        if in_block {
            pos = start + block.unwrap();
        }
        pos
    }
    fn value(&mut self, ty: &Type, pos: usize, out: &mut Vec<u8>, toks: &mut Vec<Tok>) -> usize {
        match ty {
            Type::Range { item, min, max } => {
                let v = self.pick(int(min), int(max));
                toks.push(Tok::Int(v));
                put(out, pos, &self.ir.bytes(v, item.bytes()))
            }
            Type::Bytes(Length::Fixed(n)) => {
                let mut b = vec![0; *n];
                self.rng.fill(&mut b);
                toks.push(Tok::Open);
                toks.extend(b.iter().map(|b| Tok::Int(i128::from(*b))));
                toks.push(Tok::Close);
                put(out, pos, &b)
            }
            Type::Bytes(Length::Variable { prefix, limit }) => {
                let n = self.rng.index(limit.unwrap().min(6) + 1);
                let mut b = vec![0; n];
                self.rng.fill(&mut b);
                toks.push(Tok::Open);
                toks.extend(b.iter().map(|b| Tok::Int(i128::from(*b))));
                toks.push(Tok::Close);
                let pos = put(out, pos, &self.ir.bytes(n as i128, prefix.bytes()));
                put(out, pos, &b)
            }
            Type::Optional {
                item,
                presence: Presence::Null(null),
            } => {
                if self.rng.below(3) == 0 {
                    toks.push(Tok::Null);
                    put(out, pos, &self.ir.bytes(int(null), width(item, self.ir)))
                } else {
                    self.value(item, pos, out, toks)
                }
            }
            Type::Ref(name) => match &self.ir.get(name).definition {
                Definition::Enum { repr, variants } => {
                    let v = &variants[self.rng.index(variants.len())];
                    toks.push(Tok::Ident(
                        rust_identifier(&v.name, IdentifierCase::Type).unwrap(),
                    ));
                    put(out, pos, &self.ir.bytes(v.value, repr.bytes()))
                }
                Definition::Set { repr, bits } => {
                    let mask = bits.iter().fold(0u64, |m, b| m | 1 << b.bit);
                    let v = (self.wide() as u64) & mask;
                    toks.push(Tok::Int(i128::from(v)));
                    put(out, pos, &self.ir.bytes(i128::from(v), repr.bytes()))
                }
                _ => self.block(name, pos, out, toks),
            },
            Type::BlockGroup {
                item,
                header,
                limit,
            } => {
                let Definition::Block { length, .. } = &self.ir.get(item).definition else {
                    unreachable!()
                };
                let n = self.rng.index(limit.unwrap().min(3) + 1);
                let mut head = vec![0; header.size];
                for f in &header.fields {
                    let value = match &f.role {
                        Role::Length => *length as i128,
                        Role::Count => n as i128,
                        Role::Constant(v) => i128::from(*v),
                        _ => unreachable!(),
                    };
                    put(&mut head, f.offset, &self.ir.bytes(value, f.width.bytes()));
                }
                let mut pos = put(out, pos, &head);
                toks.push(Tok::Open);
                for _ in 0..n {
                    pos = self.block(item, pos, out, toks);
                }
                toks.push(Tok::Close);
                pos
            }
            other => panic!("no CME field uses {other:?}"),
        }
    }
}

/// Tokens from the generated value's `Debug` output. Field names, type
/// names, and `Some` are dropped; numbers, `None`, and enum variants stay.
fn debug_tokens(text: &str, ir: &Ir<'_>) -> Vec<Tok> {
    let chars: Vec<char> = text.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            let next = chars[i..].iter().find(|c| **c != ' ');
            if matches!(next, Some('{' | '(' | ':')) || ir.rust_types.contains(&ident) {
                continue;
            }
            toks.push(if ident == "None" {
                Tok::Null
            } else {
                Tok::Ident(ident)
            });
        } else if c.is_ascii_digit()
            || (c == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit))
        {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let n: String = chars[start..i].iter().collect();
            toks.push(Tok::Int(n.parse().unwrap()));
        } else {
            match c {
                '[' => toks.push(Tok::Open),
                ']' => toks.push(Tok::Close),
                _ => {}
            }
            i += 1;
        }
    }
    toks
}

/// Tokens from a `stdlib::sbe` message, walking the IR beside it. Also
/// checks that the runtime's constants equal the IR's.
fn sbe_tokens(message: &sbe::Message, ir: &Ir<'_>) -> Vec<Tok> {
    let (_, cases) = ir.union();
    let case = cases
        .iter()
        .find(|c| c.tag == message.header.template_id)
        .unwrap();
    let mut toks = Vec::new();
    sbe_fields(ir.get(&case.item), &message.fields, ir, &mut toks);
    toks
}
fn sbe_fields(t: &NamedType, values: &[sbe::NamedValue], ir: &Ir<'_>, toks: &mut Vec<Tok>) {
    let fields = t.definition.fields().unwrap();
    assert_eq!(fields.len(), values.len(), "{}", t.name);
    for (f, v) in fields.iter().zip(values) {
        assert_eq!(f.name, v.name);
        if let Type::Constant(c) = &f.ty {
            let expected = match c {
                Constant::Number { value, .. } => sbe::Value::Scalar(match v.value {
                    sbe::Value::Scalar(sbe::Scalar::Char(_)) => sbe::Scalar::Char(int(value) as u8),
                    sbe::Value::Scalar(sbe::Scalar::Int(_)) => sbe::Scalar::Int(int(value) as i64),
                    _ => sbe::Scalar::Uint(int(value) as u64),
                }),
                Constant::Bytes(b) => sbe::Value::Bytes(b.clone()),
                Constant::Variant { name, .. } => sbe::Value::Enum(name.clone()),
            };
            assert_eq!(v.value, expected, "constant {}.{}", t.name, f.name);
            continue;
        }
        sbe_value(&f.ty, &v.value, ir, toks);
    }
}
fn sbe_value(ty: &Type, v: &sbe::Value, ir: &Ir<'_>, toks: &mut Vec<Tok>) {
    use sbe::{Scalar, Value};
    match (ty, v) {
        (Type::Optional { .. }, Value::Null) => toks.push(Tok::Null),
        (Type::Optional { item, .. }, v) => sbe_value(item, v, ir, toks),
        (Type::Range { .. } | Type::Scalar(_), Value::Scalar(s)) => toks.push(Tok::Int(match s {
            Scalar::Int(n) => i128::from(*n),
            Scalar::Uint(n) => i128::from(*n),
            Scalar::Char(c) => i128::from(*c),
            other => panic!("unexpected {other:?}"),
        })),
        (Type::Bytes(_), Value::Bytes(b)) => {
            toks.push(Tok::Open);
            toks.extend(b.iter().map(|b| Tok::Int(i128::from(*b))));
            toks.push(Tok::Close);
        }
        (Type::Ref(n), Value::Enum(name)) => {
            assert!(matches!(ir.get(n).definition, Definition::Enum { .. }));
            toks.push(Tok::Ident(
                rust_identifier(name, IdentifierCase::Type).unwrap(),
            ));
        }
        (Type::Ref(_), Value::Set(bits)) => toks.push(Tok::Int(i128::from(*bits))),
        (Type::Ref(n), Value::Composite(members)) => sbe_fields(ir.get(n), members, ir, toks),
        (Type::BlockGroup { item, .. }, Value::Group(g)) => {
            toks.push(Tok::Open);
            for entry in &g.entries {
                sbe_fields(ir.get(item), entry, ir, toks);
            }
            toks.push(Tok::Close);
        }
        (ty, v) => panic!("{ty:?} does not match {v:?}"),
    }
}

/// Lengthens every block of a runtime message, as a newer sender would.
fn widen(fields: &mut [sbe::NamedValue], rng: &mut Lcg) {
    for f in fields {
        if let sbe::Value::Group(g) = &mut f.value {
            g.block_length += rng.below(5);
            for entry in &mut g.entries {
                widen(entry, rng);
            }
        }
    }
}

/// What the mutated inputs did.
#[derive(Debug, Default)]
struct Stats {
    messages: usize,
    tokens: usize,
    agreed: usize,
    refused: usize,
    older: usize,
}

fn differential<M>(xml: &str, rounds: usize) -> Stats
where
    M: Wire + Debug + PartialEq,
    M::ParseError: Debug,
    M::WriteError: Debug,
{
    let runtime = sbe::Schema::parse(xml).unwrap();
    let checked = ir(xml);
    let ir = Ir::new(checked.schema());
    let (_, cases) = ir.union();
    let version = ir.version();
    let mut stats = Stats::default();
    let mut encoder = Gen {
        ir: &ir,
        rng: Lcg::new(0x5be),
    };
    let mut rng = Lcg::new(0xc3e);
    for (k, case) in cases.iter().enumerate() {
        assert_eq!(runtime.template_name(case.tag), Some(case.name.as_str()));
        for _ in 0..rounds {
            let (bytes, toks) = encoder.message(k);
            stats.messages += 1;
            stats.tokens += toks.len();

            // Generated decoder, then generated encoder.
            let value = M::parse(&bytes)
                .unwrap_or_else(|e| panic!("{}: generated parse: {e:?}", case.name));
            assert_eq!(
                debug_tokens(&format!("{value:?}"), &ir),
                toks,
                "{}",
                case.name
            );
            assert_eq!(value.to_bytes().unwrap(), bytes, "{}", case.name);

            // Runtime decoder, then runtime encoder.
            let message = runtime
                .decode(&bytes)
                .unwrap_or_else(|e| panic!("{}: runtime decode: {e:?}", case.name));
            assert_eq!(sbe_tokens(&message, &ir), toks, "{}", case.name);
            let mut again = Vec::new();
            runtime.write(&message, &mut again).unwrap();
            assert_eq!(again, bytes, "{}", case.name);

            // The runtime encodes longer blocks and a newer version; the
            // generated decoder skips the extra bytes.
            let mut newer = message.clone();
            newer.header.block_length += rng.below(5);
            newer.header.version += rng.below(3);
            widen(&mut newer.fields, &mut rng);
            let mut wide = Vec::new();
            runtime.write(&newer, &mut wide).unwrap();
            let read =
                M::parse(&wide).unwrap_or_else(|e| panic!("{}: widened parse: {e:?}", case.name));
            assert_eq!(read, value, "{}", case.name);

            // Mutated bytes: both accept the same values or both refuse,
            // except that only the runtime reads versions before 13.
            for _ in 0..16 {
                let mut bad = if rng.coin() {
                    bytes.clone()
                } else {
                    wide.clone()
                };
                let at = rng.index(bad.len());
                bad[at] = rng.next() as u8;
                if rng.below(4) == 0 {
                    bad.truncate(rng.index(bad.len() + 1));
                }
                match (M::parse(&bad), runtime.decode(&bad)) {
                    (Ok(g), Ok(m)) => {
                        assert_eq!(
                            debug_tokens(&format!("{g:?}"), &ir),
                            sbe_tokens(&m, &ir),
                            "{}",
                            case.name
                        );
                        stats.agreed += 1;
                    }
                    (Err(_), Err(_)) => stats.refused += 1,
                    (Err(_), Ok(m)) if m.header.version < version => stats.older += 1,
                    (g, m) => panic!("{}: generated {g:?}, runtime {m:?}", case.name),
                }
            }
        }
    }
    stats
}

#[test]
fn cme_mdp3_decoders_agree_on_every_template() {
    let stats = differential::<fictionet::stdlib::cme_mdp3::Message>(XML, 64);
    eprintln!("CME MDP 3.0: {stats:?}");
    assert_eq!(stats.messages, 31 * 64);
    assert!(stats.agreed > 1000 && stats.refused > 1000 && stats.tokens > 100_000);
}

#[test]
fn sample_decoders_agree_on_every_template() {
    let stats = differential::<sample::Message>(SAMPLE, 512);
    eprintln!("sample: {stats:?}");
    assert!(stats.agreed > 500 && stats.refused > 500);
}
