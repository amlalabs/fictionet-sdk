//! Front end registry and the JSON representation of the IR.
use crate::{
    Error, ErrorKind,
    ir::*,
    json::{self, Value},
};
use std::collections::BTreeMap;

/// One local input. `name` is used only for diagnostics and the output header.
#[derive(Clone, Debug)]
pub struct Input {
    /// File name; directory components are removed from generated headers.
    pub name: String,
    /// File contents, bounded by [`MAX_INPUT`].
    pub bytes: Vec<u8>,
}

/// A schema parser. Implementations must bound all input and intermediate data.
pub trait FrontEnd: Sync {
    /// Stable CLI name.
    fn name(&self) -> &'static str;
    /// Parses inputs into the shared IR. Validation is a separate step.
    fn parse(&self, inputs: &[Input], defaults: Limits) -> Result<Schema, Error>;
}

/// The built-in, dependency-free IR JSON front end.
#[derive(Clone, Copy, Debug)]
pub struct IrFrontEnd;
/// Registered front ends. Add one instance here to expose another format.
pub static FORMATS: &[&dyn FrontEnd] = &[&IrFrontEnd];

/// Parses, validates, and emits a format from [`FORMATS`].
pub fn generate(format: &str, inputs: &[Input], defaults: Limits) -> Result<String, Error> {
    let frontend = FORMATS.iter().find(|f| f.name() == format).ok_or_else(|| {
        Error::new(
            ErrorKind::UnknownFormat,
            "format",
            "format is not registered",
        )
    })?;
    let checked = crate::validate(frontend.parse(inputs, defaults)?, defaults)?;
    crate::emit(
        &checked,
        &inputs.iter().map(|i| i.name.clone()).collect::<Vec<_>>(),
    )
}
impl FrontEnd for IrFrontEnd {
    fn name(&self) -> &'static str {
        "ir"
    }
    fn parse(&self, inputs: &[Input], _: Limits) -> Result<Schema, Error> {
        if inputs.len() != 1 {
            return Err(Error::new(
                ErrorKind::JsonShape,
                "inputs",
                "ir requires exactly one JSON document",
            ));
        }
        let input = inputs
            .first()
            .ok_or_else(|| shape("inputs", "missing document"))?;
        if input.name.len() > MAX_INPUT {
            return Err(Error::new(
                ErrorKind::InputLimit,
                "input.name",
                "input path exceeds MAX_INPUT",
            ));
        }
        parse_schema(json::parse(&input.bytes).map_err(|mut e| {
            e.location = format!("{}:{}", input.name, e.location);
            e
        })?)
    }
}
fn shape(path: &str, msg: &str) -> Error {
    Error::new(ErrorKind::JsonShape, path, msg)
}
struct Object {
    values: BTreeMap<String, Value>,
    path: String,
}
impl Object {
    fn new(value: Value, path: &str) -> Result<Self, Error> {
        match value {
            Value::Object(values) => Ok(Self {
                values,
                path: path.into(),
            }),
            _ => Err(shape(path, "expected object")),
        }
    }
    fn take(&mut self, key: &str) -> Option<Value> {
        self.values.remove(key)
    }
    fn required(&mut self, key: &str) -> Result<Value, Error> {
        self.take(key)
            .ok_or_else(|| shape(&format!("{}.{}", self.path, key), "required member"))
    }
    fn text(&mut self, key: &str) -> Result<String, Error> {
        text(self.required(key)?, &format!("{}.{}", self.path, key))
    }
    fn doc(&mut self) -> Result<String, Error> {
        self.take("doc")
            .map(|v| text(v, &self.path))
            .transpose()
            .map(|v| v.unwrap_or_default())
    }
    fn limit(&mut self, key: &str) -> Result<Option<usize>, Error> {
        self.take(key)
            .map(|v| size(v, &format!("{}.{}", self.path, key)))
            .transpose()
    }
    fn finish(self) -> Result<(), Error> {
        if let Some(key) = self.values.keys().next() {
            return Err(shape(&format!("{}.{}", self.path, key), "unknown member"));
        }
        Ok(())
    }
}
fn text(v: Value, path: &str) -> Result<String, Error> {
    match v {
        Value::String(s) => Ok(s),
        _ => Err(shape(path, "expected string")),
    }
}
fn array(v: Value, path: &str) -> Result<Vec<Value>, Error> {
    match v {
        Value::Array(s) => Ok(s),
        _ => Err(shape(path, "expected array")),
    }
}
fn integer(v: Value, path: &str) -> Result<i128, Error> {
    match v {
        Value::Number(n) => n
            .parse()
            .map_err(|_| shape(path, "expected integer within i128")),
        _ => Err(shape(path, "expected integer")),
    }
}
fn size(v: Value, path: &str) -> Result<usize, Error> {
    usize::try_from(integer(v, path)?).map_err(|_| shape(path, "expected nonnegative usize"))
}
fn number(v: Value, path: &str) -> Result<Number, Error> {
    match v {
        Value::Number(n) => {
            if n.contains(['.', 'e', 'E']) {
                n.parse()
                    .map(Number::Float)
                    .map_err(|_| shape(path, "invalid float"))
            } else {
                n.parse()
                    .map(Number::Integer)
                    .map_err(|_| shape(path, "invalid integer"))
            }
        }
        _ => Err(shape(path, "expected number")),
    }
}
fn order(v: Value, path: &str) -> Result<ByteOrder, Error> {
    match text(v, path)?.as_str() {
        "big" => Ok(ByteOrder::Big),
        "little" => Ok(ByteOrder::Little),
        _ => Err(shape(path, "byte order must be big or little")),
    }
}
fn primitive(s: &str, path: &str) -> Result<Primitive, Error> {
    match s {
        "u8" => Ok(Primitive::U8),
        "u16" => Ok(Primitive::U16),
        "u32" => Ok(Primitive::U32),
        "u64" => Ok(Primitive::U64),
        "i8" => Ok(Primitive::I8),
        "i16" => Ok(Primitive::I16),
        "i32" => Ok(Primitive::I32),
        "i64" => Ok(Primitive::I64),
        "f32" => Ok(Primitive::F32),
        "f64" => Ok(Primitive::F64),
        _ => Err(shape(path, "unknown primitive")),
    }
}
fn width(v: Value, path: &str) -> Result<Width, Error> {
    match text(v, path)?.as_str() {
        "u8" => Ok(Width::U8),
        "u16" => Ok(Width::U16),
        "u32" => Ok(Width::U32),
        "u64" => Ok(Width::U64),
        _ => Err(shape(path, "expected unsigned prefix width")),
    }
}
fn parse_schema(v: Value) -> Result<Schema, Error> {
    let mut o = Object::new(v, "schema")?;
    let doc = o.doc()?;
    let byte_order = o
        .take("byte_order")
        .map(|v| order(v, "schema.byte_order"))
        .transpose()?
        .unwrap_or_default();
    let types = array(o.required("types")?, "schema.types")?
        .into_iter()
        .enumerate()
        .map(|(i, v)| named(v, &format!("types[{i}]")))
        .collect::<Result<_, _>>()?;
    let streams = o
        .take("streams")
        .map(|v| array(v, "streams"))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, v)| stream(v, &format!("streams[{i}]")))
        .collect::<Result<_, _>>()?;
    o.finish()?;
    Ok(Schema {
        doc,
        byte_order,
        types,
        streams,
    })
}
fn named(v: Value, path: &str) -> Result<NamedType, Error> {
    let mut o = Object::new(v, path)?;
    let name = o.text("name")?;
    let doc = o.doc()?;
    let kind = o.text("kind")?;
    let definition = match kind.as_str() {
        "struct" => Definition::Struct(
            array(o.required("fields")?, path)?
                .into_iter()
                .enumerate()
                .map(|(i, v)| field(v, &format!("{path}.fields[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        "enum" => {
            let repr = primitive(&o.text("repr")?, path)?;
            let variants = array(o.required("variants")?, path)?
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    let p = format!("{path}.variants[{i}]");
                    let mut o = Object::new(v, &p)?;
                    let name = o.text("name")?;
                    let doc = o.doc()?;
                    let value = integer(o.required("value")?, &p)?;
                    o.finish()?;
                    Ok(Variant { name, doc, value })
                })
                .collect::<Result<_, Error>>()?;
            Definition::Enum { repr, variants }
        }
        "set" => {
            let repr = width(o.required("repr")?, path)?;
            let bits = array(o.required("bits")?, path)?
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    let p = format!("{path}.bits[{i}]");
                    let mut o = Object::new(v, &p)?;
                    let name = o.text("name")?;
                    let doc = o.doc()?;
                    let bit = u8::try_from(integer(o.required("bit")?, &p)?)
                        .map_err(|_| shape(&p, "bit must fit u8"))?;
                    o.finish()?;
                    Ok(Bit { name, doc, bit })
                })
                .collect::<Result<_, Error>>()?;
            Definition::Set { repr, bits }
        }
        _ => return Err(shape(path, "kind must be struct, enum, or set")),
    };
    o.finish()?;
    Ok(NamedType {
        name,
        doc,
        definition,
    })
}
fn field(v: Value, path: &str) -> Result<Field, Error> {
    let mut o = Object::new(v, path)?;
    let name = o.text("name")?;
    let doc = o.doc()?;
    let ty = ty(o.required("type")?, &format!("{path}.type"))?;
    let byte_order = o.take("byte_order").map(|v| order(v, path)).transpose()?;
    let fixed_size = o.limit("fixed_size")?;
    o.finish()?;
    Ok(Field {
        name,
        doc,
        ty,
        byte_order,
        fixed_size,
    })
}
fn ty(v: Value, path: &str) -> Result<Type, Error> {
    if let Value::String(s) = v {
        return Ok(Type::Scalar(primitive(&s, path)?));
    }
    let mut o = Object::new(v, path)?;
    let kind = o.text("kind")?;
    let result = match kind.as_str() {
        "ref" => Type::Ref(o.text("name")?),
        "bytes" | "string" => {
            let len = match o.limit("size")? {
                Some(n) => Length::Fixed(n),
                None => Length::Variable {
                    prefix: width(o.required("prefix")?, path)?,
                    limit: o.limit("limit")?,
                },
            };
            if kind == "bytes" {
                Type::Bytes(len)
            } else {
                Type::String(len)
            }
        }
        "group" => Type::Group {
            item: Box::new(ty(o.required("item")?, &format!("{path}.item"))?),
            count: width(o.required("count")?, path)?,
            limit: o.limit("limit")?,
        },
        "optional" => {
            let item = Box::new(ty(o.required("item")?, &format!("{path}.item"))?);
            let presence = match o.take("null") {
                Some(v) => Presence::Null(number(v, path)?),
                None => Presence::Flag(width(o.required("flag")?, path)?),
            };
            Type::Optional { item, presence }
        }
        _ => return Err(shape(path, "unknown type kind")),
    };
    o.finish()?;
    Ok(result)
}
fn stream(v: Value, path: &str) -> Result<Stream, Error> {
    let mut o = Object::new(v, path)?;
    let name = o.text("name")?;
    let item = o.text("item")?;
    let prefix = width(o.required("prefix")?, path)?;
    let byte_order = o
        .take("byte_order")
        .map(|v| order(v, path))
        .transpose()?
        .unwrap_or_default();
    let magic = o
        .take("magic")
        .map(|v| array(v, path))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(|v| {
            u8::try_from(integer(v, path)?).map_err(|_| shape(path, "magic bytes must fit u8"))
        })
        .collect::<Result<_, _>>()?;
    o.finish()?;
    Ok(Stream {
        name,
        item,
        prefix,
        byte_order,
        magic,
    })
}
