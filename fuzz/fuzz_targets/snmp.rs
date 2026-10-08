//! SNMP v1 and v2c messages, BER elements and object identifiers, as a
//! world playing an agent reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::snmp::harness::{check_message, check_scalars};
use fictionet::stdlib::snmp::{
    BasicPdu, Error, MAX_MESSAGE, Message, Oid, Pdu, Value, VarBind, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Message>::new, data, 2 * MAX_MESSAGE);
    contract::check_decode_with_alloc_limit(
        || Frames::<Message>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
        510,
    );
    contract::check_wire::<Message>(data);

    check_message(data);

    // A message built from the bytes, as world code builds one: it is
    // written whole and reads back the same, or refused as too long.
    let data = &data[..data.len().min(MAX_MESSAGE + 1)];
    let name: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let copies = usize::from(data.first().copied().unwrap_or(0) % 4);
    let built = Message {
        version: if data.len() % 2 == 0 {
            Version::V1
        } else {
            Version::V2c
        },
        community: data.to_vec(),
        pdu: Pdu::Set(BasicPdu::new(
            1,
            vec![
                VarBind::new(name.clone(), Value::OctetString(data.to_vec())),
                VarBind::new(name, Value::Opaque(data.repeat(copies))),
            ],
        )),
    };
    contract::check_wire_value(&built);
    match built.to_bytes() {
        Ok(b) => {
            assert_eq!(b.len(), built.encoded_len());
            assert!(b.len() <= MAX_MESSAGE);
            assert_eq!(Message::parse(&b), Ok(built));
        }
        Err(e) => {
            assert!(built.encoded_len() > MAX_MESSAGE);
            assert_eq!(e, Error::Unwritable);
        }
    }

    check_scalars(data);
});
