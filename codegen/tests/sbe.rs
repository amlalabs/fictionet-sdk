//! The `sbe` front end: mapping, refusals, and bounded input.
use fictionet_codegen::*;

const HEADERS: &str = r#"
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
    <composite name="varData">
      <type name="length" primitiveType="uint16"/>
      <type name="varData" primitiveType="uint8" length="0"/>
    </composite>"#;

fn xml(types: &str, body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" id="5" version="2">
  <types>{HEADERS}{types}</types>
  <sbe:message name="M" id="1">{body}</sbe:message>
</sbe:messageSchema>"#
    )
}
fn parse(text: &str) -> Result<Schema, Error> {
    SbeFrontEnd.parse(
        &[Input {
            name: "s.xml".into(),
            bytes: text.as_bytes().to_vec(),
        }],
        Limits::default(),
    )
}
fn fail(text: &str, kind: ErrorKind) {
    let e = parse(text)
        .and_then(|s| validate(s, Limits::default()).map(|_| ()))
        .unwrap_err();
    assert_eq!(e.kind, kind, "{e}");
    // Front end errors name the input; validation errors name the IR path.
    assert!(!e.location.is_empty() && !e.message.is_empty(), "{e}");
}
fn fields(schema: &Schema, name: &str) -> Vec<Field> {
    schema
        .types
        .iter()
        .find(|t| t.name == name)
        .and_then(|t| t.definition.fields())
        .unwrap()
        .to_vec()
}

#[test]
fn maps_scalars_nulls_constants_and_layouts() {
    let schema = parse(&xml(
        r#"<type name="Small" primitiveType="int8" presence="optional" nullValue="127"/>
           <type name="Name" primitiveType="char" length="4"/>
           <type name="Tag" primitiveType="char" presence="constant">T</type>
           <enum name="E" encodingType="uint8"><validValue name="a">3</validValue></enum>"#,
        r#"<field name="u" id="1" type="uint8"/>
           <field name="c" id="2" type="char"/>
           <field name="s" id="3" type="Small" offset="4"/>
           <field name="n" id="4" type="Name"/>
           <field name="t" id="5" type="Tag"/>
           <field name="o" id="6" type="E" presence="optional"/>
           <field name="k" id="7" type="E" presence="constant" valueRef="E.a"/>
           <group name="g" id="8"><field name="x" id="9" type="uint32"/></group>
           <data name="d" id="10" type="varData"/>"#,
    ))
    .unwrap();
    let f = fields(&schema, "M");
    let range = |min: i128, max: i128, item| Type::Range {
        item,
        min: Number::Integer(min),
        max: Number::Integer(max),
    };
    assert_eq!(f[0].ty, range(0, 254, Primitive::U8));
    assert_eq!(f[1].ty, range(0x20, 0x7e, Primitive::U8));
    assert_eq!(
        f[2].ty,
        Type::Optional {
            item: Box::new(range(-127, 126, Primitive::I8)),
            presence: Presence::Null(Number::Integer(127)),
        }
    );
    assert_eq!(f[2].offset, Some(4));
    assert_eq!(f[3].ty, Type::Bytes(Length::Fixed(4)));
    assert_eq!(
        f[4].ty,
        Type::Constant(Constant::Number {
            ty: Primitive::U8,
            value: Number::Integer(i128::from(b'T')),
        })
    );
    assert_eq!(
        f[5].ty,
        Type::Optional {
            item: Box::new(Type::Ref("E".into())),
            presence: Presence::Null(Number::Integer(255)),
        }
    );
    assert_eq!(
        f[6].ty,
        Type::Constant(Constant::Variant {
            ty: "E".into(),
            name: "a".into(),
        })
    );
    let Type::BlockGroup {
        item,
        header,
        limit,
    } = &f[7].ty
    else {
        panic!("{:?}", f[7].ty)
    };
    assert_eq!((item.as_str(), *limit), ("M_g", None));
    assert_eq!(header.size, 4);
    assert_eq!(
        f[8].ty,
        Type::Bytes(Length::Variable {
            prefix: Width::U16,
            limit: Some(4096),
        })
    );
    let Definition::Block { length, .. } = &schema
        .types
        .iter()
        .find(|t| t.name == "M")
        .unwrap()
        .definition
    else {
        panic!()
    };
    assert_eq!(*length, 10);
    let Definition::Union { header, cases } = &schema.types.last().unwrap().definition else {
        panic!()
    };
    assert_eq!(cases.len(), 1);
    assert!(header.fields.iter().any(|f| f.role == Role::Constant(5)));
    assert!(header.fields.iter().any(|f| f.role
        == Role::Version {
            current: 2,
            minimum: 2,
        }));
    // Unused composites are left out; enums are kept.
    assert!(schema.types.iter().all(|t| t.name != "varData"));
    let checked = validate(schema, Limits::default()).unwrap();
    assert!(matches!(
        fields(checked.schema(), "M")[7].ty,
        Type::BlockGroup { limit: Some(4096), .. }
    ));
}

#[test]
fn refuses_unsupported_features() {
    for (types, body) in [
        (
            r#"<type name="F" primitiveType="double" presence="optional"/>"#,
            r#"<field name="f" id="1" type="F"/>"#,
        ),
        (
            r#"<type name="A" primitiveType="uint32" length="2"/>"#,
            r#"<field name="a" id="1" type="A"/>"#,
        ),
        (
            r#"<composite name="P"><type name="m" primitiveType="int64"/></composite>"#,
            r#"<field name="p" id="1" type="P" presence="optional"/>"#,
        ),
        (
            r#"<composite name="dims"><type name="blockLength" primitiveType="uint16"/><type name="numInGroup" primitiveType="uint8"/><type name="numGroups" primitiveType="uint16"/></composite>"#,
            r#"<group name="g" id="1" dimensionType="dims"><field name="x" id="2" type="uint8"/></group>"#,
        ),
    ] {
        fail(&xml(types, body), ErrorKind::Unsupported);
    }
    fail(
        &xml("", "").replace("<types>", "<xi:include href=\"other.xml\"/><types>"),
        ErrorKind::Unsupported,
    );
}

#[test]
fn refuses_invalid_schemas() {
    use ErrorKind::*;
    for (types, body, kind) in [
        ("", r#"<field id="1" type="uint8"/>"#, SchemaShape),
        (
            "",
            r#"<field name="a-b" id="1" type="uint8"/>"#,
            InvalidName,
        ),
        (
            "",
            r#"<field name="a" id="1" type="Nope"/>"#,
            UnknownReference,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8" sinceVersion="3"/>"#,
            SchemaShape,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8" sinceVersion="2"/><field name="b" id="2" type="uint8"/>"#,
            SchemaShape,
        ),
        (
            "",
            r#"<group name="g" id="1"><field name="x" id="2" type="uint8"/></group><field name="a" id="3" type="uint8"/>"#,
            SchemaShape,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8"/><field name="a" id="2" type="uint8"/>"#,
            DuplicateName,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8"/><field name="b" id="1" type="uint8"/>"#,
            DuplicateName,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8" presence="sometimes"/>"#,
            SchemaShape,
        ),
        (
            r#"<type name="X" primitiveType="uint8" nullValue="3"/>"#,
            r#"<field name="a" id="1" type="X"/>"#,
            SchemaShape,
        ),
        (
            r#"<type name="X" primitiveType="uint8" presence="optional" nullValue="3"/>"#,
            r#"<field name="a" id="1" type="X"/>"#,
            SchemaShape,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint8" presence="constant"/>"#,
            SchemaShape,
        ),
        (
            r#"<composite name="A"><ref name="b" type="B"/></composite><composite name="B"><ref name="a" type="A"/></composite>"#,
            r#"<field name="a" id="1" type="A"/>"#,
            SchemaShape,
        ),
        (
            r#"<enum name="E" encodingType="uint8"><validValue name="a">1</validValue><validValue name="b">1</validValue></enum>"#,
            "",
            DuplicateName,
        ),
        (
            r#"<enum name="E" encodingType="int8"><validValue name="a">1</validValue></enum>"#,
            "",
            SchemaShape,
        ),
        (
            r#"<set name="S" encodingType="uint8"><choice name="a">8</choice></set>"#,
            "",
            SchemaShape,
        ),
        (
            "",
            r#"<field name="a" id="1" type="uint16" offset="0"/><field name="b" id="2" type="uint8" offset="1"/>"#,
            InvalidSize,
        ),
        (
            "",
            r#"<data name="d" id="1" type="messageHeader"/>"#,
            SchemaShape,
        ),
    ] {
        fail(&xml(types, body), kind);
    }
    fail(
        &xml("", "").replace(
            r#"<sbe:message name="M" id="1">"#,
            r#"<sbe:message name="M" id="1" blockLength="0"><field name="a" id="1" type="uint8"/>"#,
        ),
        InvalidSize,
    );
    fail(
        &xml("", "").replace("version=\"2\"", "version=\"2\" byteOrder=\"middle\""),
        SchemaShape,
    );
    fail(&xml("", "").replace(" id=\"5\"", ""), SchemaShape);
    let two = xml("", "").replace(
        "</sbe:messageSchema>",
        "<sbe:message name=\"N\" id=\"1\"/></sbe:messageSchema>",
    );
    fail(&two, DuplicateName);
    let none = xml("", "").replace("<sbe:message name=\"M\" id=\"1\"></sbe:message>", "");
    fail(&none, SchemaShape);
    let reserved = xml("", "").replace("name=\"M\"", "name=\"Error\"");
    fail(&reserved, RustCollision);
}

#[test]
fn refuses_malformed_and_oversized_xml() {
    use ErrorKind::*;
    let good = xml("", "");
    for text in [
        "<messageSchema",
        "<a></b>",
        "<!DOCTYPE a><a/>",
        "<a><![CDATA[x]]></a>",
        "<a><?pi?></a>",
        "<a x='1' x='2'/>",
        "<a>&bogus;</a>",
        "<a/><b/>",
        "<?xml version=\"1.1\"?><a/>",
        "<a>\u{1}</a>",
    ] {
        fail(text, XmlSyntax);
    }
    let invalid_utf8 = Input {
        name: "s.xml".into(),
        bytes: vec![b'<', 0xff, b'/', b'>'],
    };
    assert_eq!(
        SbeFrontEnd
            .parse(&[invalid_utf8], Limits::default())
            .unwrap_err()
            .kind,
        XmlSyntax
    );
    fail(
        &format!("{}{}", "<a>".repeat(40), "</a>".repeat(40)),
        InputLimit,
    );
    fail(
        &format!("<a>{}</a>", "<b/>".repeat(MAX_XML_ELEMENTS)),
        InputLimit,
    );
    let attrs: String = (0..40).map(|i| format!(" a{i}='1'")).collect();
    fail(&format!("<a{attrs}/>"), InputLimit);
    fail(&format!("<{}/>", "a".repeat(MAX_NAME + 1)), InputLimit);
    let huge = format!("{good}<!--{}-->", " ".repeat(MAX_INPUT));
    fail(&huge, InputLimit);
    assert_eq!(
        SbeFrontEnd.parse(&[], Limits::default()).unwrap_err().kind,
        Cli
    );
}

#[test]
fn mutated_schemas_never_panic() {
    let base = include_str!("schemas/sbe_sample.xml").as_bytes();
    let mut rng = fictionet::stdlib::codec::Lcg::new(17);
    let mut generated = 0;
    for _ in 0..2000 {
        let mut bytes = base.to_vec();
        for _ in 0..1 + rng.below(3) {
            match rng.below(3) {
                0 => {
                    let at = rng.index(bytes.len());
                    bytes[at] = b"<>/=\"'0129aZ -_&;"[rng.index(17)];
                }
                1 => bytes.truncate(rng.index(bytes.len() + 1)),
                _ => {
                    let at = rng.index(bytes.len());
                    let len = rng.index(16).min(bytes.len() - at);
                    bytes.drain(at..at + len);
                }
            }
        }
        let input = Input {
            name: "m.xml".into(),
            bytes,
        };
        if let Ok(g) = generate("sbe", &[input], Limits::default()) {
            assert!(g.source.contains("pub enum Message"));
            generated += 1;
        }
    }
    assert!(generated > 50, "{generated}");
}

/// Schemas whose IR would grow with the product of two counts are refused
/// by the front end itself, before that IR exists.
#[test]
fn refuses_amplifying_schemas_early() {
    // A dimension composite repeating a role would be copied into every
    // group that uses it.
    let repeated: String = (0..64)
        .map(|_| r#"<type name="blockLength" primitiveType="uint16"/>"#)
        .collect();
    let groups: String = (0..64)
        .map(|i| format!(r#"<group name="g{i}" id="{i}" dimensionType="Dim"/>"#))
        .collect();
    let schema = xml(
        &format!(
            r#"<composite name="Dim"><type name="numInGroup" primitiveType="uint8"/>{repeated}</composite>"#
        ),
        &groups,
    );
    assert_eq!(parse(&schema).unwrap_err().kind, ErrorKind::DuplicateName);
    // Fields, members, and choices count against MAX_FIELDS as they are
    // read, so a large enum cannot be referenced by many fields.
    let choices: String = (0..3000)
        .map(|i| format!(r#"<validValue name="v{i}">{i}</validValue>"#))
        .collect();
    let fields: String = (0..3000)
        .map(|i| format!(r#"<field name="f{i}" id="{i}" type="E"/>"#))
        .collect();
    let schema = xml(
        &format!(r#"<enum name="E" encodingType="uint16">{choices}</enum>"#),
        &fields,
    );
    assert_eq!(parse(&schema).unwrap_err().kind, ErrorKind::IrLimit);
}
