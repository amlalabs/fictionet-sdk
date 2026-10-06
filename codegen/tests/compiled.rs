//! Compile generated modules against the public SDK and run their contracts.
#![allow(dead_code)]

#[path = "golden/float_nulls.rs"]
mod float_nulls;
#[path = "golden/long_names.rs"]
mod long_names;
#[path = "golden/one_field.rs"]
mod one_field;
#[path = "../../tests/codegen.rs"]
mod sdk;
#[path = "golden/short_names.rs"]
mod short_names;

#[test]
fn optional_flags_and_float_null_bits() {
    use fictionet::stdlib::codec::Wire;
    use float_nulls::{Error, Floats};
    let value = Floats {
        small: None,
        large: None,
        decimal: None,
        negative_zero: Some(0.0),
        flag: None,
    };
    let mut bytes = value.to_bytes().unwrap();
    assert_eq!(Floats::parse(&bytes).unwrap(), value);
    *bytes.last_mut().unwrap() = 2;
    assert_eq!(Floats::parse(&bytes), Err(Error::Value));
    let mut invalid = value;
    invalid.small = Some(f32::MAX);
    let mut out = vec![7];
    assert_eq!(invalid.write(&mut out), Err(Error::Value));
    assert_eq!(out, [7]);
}
