//! BACnet wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::bacnet::*;
use fictionet::stdlib::codec::{Wire, contract};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bvlc) = Bvlc::parse(data) {
        assert_eq!(bvlc.to_bytes().unwrap(), data);
        for n in 0..data.len() {
            assert!(Bvlc::parse(&data[..n]).is_err());
        }
        if let Some(npdu) = bvlc.npdu() {
            layers(npdu);
        }
    }
    layers(data);
    writers(data);
    contract::check_wire::<Bvlc>(data);
    contract::check_wire::<Npdu>(data);
    contract::check_wire::<Apdu>(data);
    contract::check_wire::<Tag>(data);
    contract::check_wire::<Value>(data);
    contract::check_wire::<Values>(data);
    contract::check_wire::<WhoIs>(data);
    contract::check_wire::<IAm>(data);
    contract::check_wire::<ContextValue<0>>(data);
    contract::check_wire::<ContextValue<1>>(data);
    contract::check_wire::<ContextValue<2>>(data);
    contract::check_wire::<ContextValue<3>>(data);
    contract::check_wire::<ContextValue<4>>(data);
    contract::check_wire::<ContextValue<5>>(data);
    contract::check_wire::<ContextValue<6>>(data);
    contract::check_wire::<ContextValue<7>>(data);
    contract::check_wire::<ContextValue<8>>(data);
    contract::check_wire::<ContextValue<9>>(data);
    contract::check_wire::<ContextValue<10>>(data);
    contract::check_wire::<ContextValue<11>>(data);
    contract::check_wire::<ContextValue<12>>(data);
});

/// Checks an NPDU and its APDU payload through their complete units.
fn layers(data: &[u8]) {
    contract::check_wire::<Npdu>(data);
    if let Ok(npdu) = Npdu::parse(data)
        && let Some(apdu) = npdu.apdu()
    {
        contract::check_wire::<Apdu>(apdu);
    }
    if let Ok(apdu) = Apdu::parse(data) {
        contract::check_wire_value(&apdu);
        assert_eq!(
            apdu.data().is_some(),
            apdu.service().is_some() && !matches!(apdu, Apdu::SimpleAck { .. })
        );
    }
}

/// Exercises fields that a parser cannot produce, including invalid identifiers.
fn writers(b: &[u8]) {
    let b = &b[..b.len().min(MAX_MESSAGE + 1)];
    let byte = |i: usize| b.get(i).copied().unwrap_or(0);
    let word = |i: usize| u16::from_be_bytes([byte(i), byte(i + 1)]);
    let instance = u32::from(word(0)) << 16 | u32::from(word(2));
    contract::check_wire_value(&ContextValue::<{ tag::UNSIGNED }> {
        number: byte(2),
        value: Value::Unsigned(u64::from(word(0))),
    });
    let npdu = Npdu {
        destination: (byte(3) & 1 != 0).then(|| Destination {
            address: NetAddress {
                network: word(4),
                mac: vec![byte(6); usize::from(byte(3) % 8)],
            },
            hop_count: byte(7),
        }),
        source: (byte(3) & 2 != 0).then(|| NetAddress {
            network: word(8),
            mac: vec![byte(10); usize::from(byte(3) >> 5)],
        }),
        expecting_reply: byte(3) & 4 != 0,
        priority: Priority::from_bits(byte(3) >> 3),
        body: NpduBody::Apdu(b.to_vec()),
    };
    contract::check_wire_value(&npdu);
    contract::check_wire_value(&Npdu::local(b.to_vec()));
    let id = ObjectId {
        object_type: word(4),
        instance,
    };
    assert_eq!(
        id.to_u32().is_some(),
        id.object_type <= MAX_OBJECT_TYPE && instance <= MAX_INSTANCE
    );
    contract::check_wire_value(&Value::ObjectId(id));
    contract::check_wire_value(&WhoIs {
        range: Some((instance, u32::from(word(6)))),
    });
    contract::check_wire_value(&IAm {
        device: ObjectId::from_u32(instance),
        max_apdu: u32::from(word(4)),
        segmentation: [
            Segmentation::Both,
            Segmentation::Transmit,
            Segmentation::Receive,
            Segmentation::NoSegmentation,
        ][usize::from(byte(6) % 4)],
        vendor: word(7),
    });
    let string = CharString {
        charset: byte(0),
        bytes: b.to_vec(),
    };
    contract::check_wire_value(&Value::CharacterString(string));
}
