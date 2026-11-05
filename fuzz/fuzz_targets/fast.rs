//! FAST 1.1 wire units, blocks, XML templates, messages, and strict writers.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::fast::*;
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

// Original test templates. These are not templates for an exchange feed.
const XML: &[u8] = br#"<templates xmlns="http://www.fixprotocol.org/ns/fast/td/1.1">
<template name="Sample" id="1">
  <uInt32 name="fixed"><constant value="1"/></uInt32>
  <uInt32 name="counter"><increment value="0"/></uInt32>
  <int64 name="change" presence="optional"><delta/></int64>
  <string name="text" presence="optional"><copy/></string>
  <string name="utf8" charset="unicode"><tail/></string>
  <byteVector name="blob"><default value=""/></byteVector>
  <decimal name="price" presence="optional"><exponent><copy/></exponent><mantissa><delta/></mantissa></decimal>
  <group name="group" presence="optional"><templateRef name="Fields"/></group>
  <sequence name="rows"><length><copy value="0"/></length><uInt64 name="value"/></sequence>
  <templateRef/>
</template>
<template name="Fields"><int32 name="field"><default value="0"/></int32></template>
<template name="Leaf" id="2"><string name="name"/><uInt64 name="number"><delta/></uInt64></template>
</templates>"#;

fuzz_target!(|data: &[u8]| {
    // The harness checks partitions and EOF prefixes. Bound its workload too.
    let input = data.get(..data.len().min(4096)).unwrap_or_default();
    if let Ok(value) = <Int32 as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <UInt32 as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Int64 as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <UInt64 as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<Int32> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<UInt32> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<Int64> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<UInt64> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Ascii as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<Ascii> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Unicode as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<Unicode> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ByteVector as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<ByteVector> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Decimal as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Nullable<Decimal> as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <PresenceMap as Wire>::parse(input) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&ByteVector(input.to_vec()));
    let _ = assert_write(&Ascii(String::from_utf8_lossy(input).into_owned()));
    let templates = Templates::from_xml(XML).expect("test templates");
    let bound = 2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES);
    assert_eq!(
        decode_chunks(&mut Stream::new(Blocks), chunks(input, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(|| Blocks, input),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(BlockMessages::new(Messages::new(templates.clone()))),
            chunks(input, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
            }
        ),
        decode_all(
            || BlockMessages::new(Messages::new(templates.clone())),
            input
        ),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Messages::new(templates.clone())),
            chunks(input, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
            }
        ),
        decode_all(|| Messages::new(templates.clone()), input),
    );
    let (messages, _) = decode_all(|| Messages::new(templates.clone()), input);
    let mut encoder = Encoder::new(templates.clone());
    let mut decoder = Messages::new(templates.clone());
    for message in messages {
        let mut bytes = Vec::new();
        encoder
            .write(&message, &mut bytes)
            .expect("decoded message is writable");
        assert_eq!(decoder.parse_exact(&bytes), Ok(message));
    }
    let n = input
        .iter()
        .take(8)
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let value = Message {
        template_id: 2,
        fields: vec![
            Value::Ascii(String::from_utf8_lossy(input).into_owned()),
            Value::UInt64(n),
        ],
    };
    let mut output = vec![0x55];
    match encoder.write(&value, &mut output) {
        Ok(()) => assert_eq!(
            decoder.parse_exact(output.get(1..).unwrap_or_default()),
            Ok(value)
        ),
        Err(_) => assert_eq!(output, [0x55]),
    }
    encoder.reset();
    decoder.reset();
    encoder.reset_dictionary(&Dictionary::Global);
    decoder.reset_dictionary(&Dictionary::Global);
    if let Ok(t) = Templates::from_xml(input) {
        for template in t.templates().iter().take(4) {
            if let Some(id) = template.id {
                let mut bytes = vec![0xc0];
                UInt32(id).write(&mut bytes).expect("integer");
                bytes.extend_from_slice(input.get(..input.len().min(128)).unwrap_or_default());
                assert_eq!(
                    decode_chunks(
                        &mut Stream::new(Messages::new(t.clone())),
                        chunks(&bytes, &[1, 7, 64]),
                        |s| {
                            assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
                        }
                    ),
                    decode_all(|| Messages::new(t.clone()), &bytes),
                );
            }
        }
    }
});
