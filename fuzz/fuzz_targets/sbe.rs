//! Bounded SBE XML schemas, dynamic messages, and codec contracts.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::sbe::{
    Error, Messages, MAX_MESSAGE_BYTES, MessageWire, Scalar, Schema, SchemaSource, Value,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// A test-only rewrite of the public Real Logic car example. Keep in sync
// with the exact-byte fixture in sbe.rs tests. No production schema is embedded.
const CAR: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
    <sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" id="7" version="2" byteOrder="littleEndian">
      <types>
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
        <composite name="varDataEncoding">
          <type name="length" primitiveType="uint8"/>
          <type name="varData" primitiveType="uint8" length="0"/>
        </composite>
        <enum name="Model" encodingType="char"><validValue name="A">A</validValue><validValue name="B" sinceVersion="2">B</validValue></enum>
        <set name="Extras" encodingType="uint8"><choice name="Cruise">0</choice><choice name="Sports">3</choice><choice name="Roof">7</choice></set>
        <type name="Torque" primitiveType="int16"/>
        <composite name="Engine">
          <type name="capacity" primitiveType="uint16"/>
          <composite name="details"><type name="cylinders" primitiveType="uint8"/><ref name="torque" type="Torque"/></composite>
          <type name="fuel" primitiveType="char" presence="constant">Petrol</type>
        </composite>
        <type name="VehicleCode" primitiveType="char" length="4"/>
        <type name="Gears" primitiveType="uint16" length="2"/>
      </types>
      <sbe:message name="Car" id="1">
        <field name="serial" id="1" type="uint32"/>
        <field name="model" id="2" type="Model"/>
        <field name="extras" id="3" type="Extras"/>
        <field name="engine" id="4" type="Engine"/>
        <field name="code" id="5" type="VehicleCode"/>
        <field name="gears" id="6" type="Gears"/>
        <field name="discount" id="7" type="Model" presence="constant" valueRef="Model.A"/>
        <field name="rating" id="8" type="uint8" sinceVersion="2"/>
        <group name="performance" id="10">
          <field name="speed" id="11" type="uint16"/>
          <group name="acceleration" id="12"><field name="mph" id="13" type="uint8"/><field name="seconds" id="14" type="float"/></group>
          <data name="note" id="15" type="varDataEncoding"/>
        </group>
        <group name="service" id="16" sinceVersion="2"><field name="code" id="17" type="int8"/></group>
        <data name="maker" id="20" type="varDataEncoding"/>
        <data name="notes" id="21" type="varDataEncoding" sinceVersion="2"/>
      </sbe:message>
    </sbe:messageSchema>"#;

const CAR_BYTES: &[u8] = &[
    20, 0, 1, 0, 7, 0, 2, 0, // header
    0xd2, 4, 0, 0, b'A', 0x89, 0xd0, 7, 4, 0xd4, 0xfe, b'S', b'B', b'E', 0, 3, 0, 5, 0, 9, 2, 0, 1,
    0, 100, 0, // one performance entry
    5, 0, 2, 0, 30, 0, 0, 0xc0, 0x3f, 60, 0, 0, 0x20, 0x40, 2, b'o',
    b'k', // entry's variable data
    1, 0, 0, 0, // empty service group
    3, b'A', b'B', b'C', 0,
];

struct Car;
impl SchemaSource for Car {
    fn schema() -> Result<&'static Schema, Error> {
        static SCHEMA: OnceLock<Result<Schema, Error>> = OnceLock::new();
        SCHEMA
            .get_or_init(|| Schema::parse(CAR))
            .as_ref()
            .map_err(|e| *e)
    }
}

const MAX_FUZZ_BYTES: usize = 8192;
fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_BYTES))
        .unwrap_or_default();
    // Exercise arbitrary schemas both as a whole and with a binary suffix.
    if let Ok(xml) = std::str::from_utf8(data) {
        let _ = Schema::parse(xml);
    }
    if let Some(at) = data.iter().position(|b| *b == 0) {
        if let (Some(xml), Some(bytes)) = (data.get(..at), data.get(at + 1..)) {
            if let Ok(xml) = std::str::from_utf8(xml) {
                if let Ok(schema) = Schema::parse(xml) {
                    contract::check_decode_with_alloc_limit(
                        || Messages::new(&schema),
                        bytes,
                        2 * MAX_MESSAGE_BYTES,
                    );
                    if let Ok(message) = schema.decode(bytes) {
                        let mut out = vec![0xaa];
                        schema.write(&message, &mut out).unwrap();
                        assert_eq!(schema.decode(&out[1..]), Ok(message));
                    }
                }
            }
        }
    }
    let schema = Car::schema().unwrap();
    contract::check_decode_with_alloc_limit(|| Messages::new(schema), data, 2 * MAX_MESSAGE_BYTES);
    contract::check_wire::<MessageWire<Car>>(data);
    // Mutate valid framing so fuzzing reaches values and nested groups.
    let mut bytes = CAR_BYTES.to_vec();
    for pair in data.chunks_exact(2) {
        if let [at, byte] = pair {
            let len = bytes.len();
            if let Some(slot) = bytes.get_mut(usize::from(*at) % len) {
                *slot = *byte;
            }
        }
    }
    contract::check_wire::<MessageWire<Car>>(&bytes);
    contract::check_decode_with_alloc_limit(|| Messages::new(schema), &bytes, 2 * MAX_MESSAGE_BYTES);
    let mut value = MessageWire::<Car>::parse(CAR_BYTES).unwrap();
    if let Some(first) = data.first() {
        value.message.header.version = u64::from(*first);
        if let Some(field) = value.message.fields.get_mut(0) {
            field.value = match first % 4 {
                0 => Value::Null,
                1 => Value::Scalar(Scalar::Uint(u64::from(*first))),
                2 => Value::Bytes(data.to_vec()),
                _ => Value::Absent,
            };
        }
    }
    contract::check_wire_value(&value);
});
