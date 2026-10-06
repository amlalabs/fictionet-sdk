//! FAST 1.1 wire units, blocks, XML templates, messages, and strict writers.
#![no_main]

use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode_with_alloc_limit, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::fast::*;
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
    check_wire::<Int32>(input);
    check_wire::<UInt32>(input);
    check_wire::<Int64>(input);
    check_wire::<UInt64>(input);
    check_wire::<Nullable<Int32>>(input);
    check_wire::<Nullable<UInt32>>(input);
    check_wire::<Nullable<Int64>>(input);
    check_wire::<Nullable<UInt64>>(input);
    check_wire::<Ascii>(input);
    check_wire::<Nullable<Ascii>>(input);
    check_wire::<Unicode>(input);
    check_wire::<Nullable<Unicode>>(input);
    check_wire::<ByteVector>(input);
    check_wire::<Nullable<ByteVector>>(input);
    check_wire::<Decimal>(input);
    check_wire::<Nullable<Decimal>>(input);
    check_wire::<PresenceMap>(input);
    check_wire_value(&ByteVector(input.to_vec()));
    check_wire_value(&Ascii(String::from_utf8_lossy(input).into_owned()));
    let templates = Templates::from_xml(XML).expect("test templates");
    check_decode_with_alloc_limit(
        || Blocks,
        input,
        2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES),
    );
    check_decode_with_alloc_limit(
        || BlockFrames::new(Frames::new(templates.clone())),
        input,
        2 * MAX_MESSAGE_BYTES,
    );
    check_decode_with_alloc_limit(
        || Frames::new(templates.clone()),
        input,
        2 * MAX_MESSAGE_BYTES,
    );
    let (messages, _) = decode_all(|| Frames::new(templates.clone()), input);
    let mut encoder = Encoder::new(templates.clone());
    let mut decoder = Frames::new(templates.clone());
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
                check_decode_with_alloc_limit(
                    || Frames::new(t.clone()),
                    &bytes,
                    2 * MAX_MESSAGE_BYTES,
                );
            }
        }
    }
});
