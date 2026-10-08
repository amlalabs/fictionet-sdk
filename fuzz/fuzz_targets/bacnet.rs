//! BACnet wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::Frames;

use fictionet::stdlib::bacnet::*;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bvlc) = Bvlc::parse(data) {
        assert_eq!(bvlc.to_bytes().unwrap(), data);
        // Each strict prefix fails a constant-time header check, so this loop is linear.
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
    contract::check_decode_with_alloc_limit(Frames::<Tag>::new, data, 2 * Frames::<Tag>::new().capacity());
    contract::check_decode_with_alloc_limit(Frames::<Value>::new, data, 2 * Frames::<Value>::new().capacity());
    let _ = ContextValue::<9>::read(data, data.first().copied().unwrap_or(0));
    contract::check_wire::<Tag>(data);
    contract::check_wire::<Value>(data);
    contract::check_wire::<ValueList>(data);
    contract::check_wire::<WhoIs>(data);
    contract::check_wire::<IAm>(data);
    macro_rules! context_values {
        ($($tag:literal),+) => {$(contract::check_wire::<ContextValue<$tag>>(data);)+};
    }
    context_values!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
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
            address: NetAddress { network: word(4), mac: vec![byte(6); usize::from(byte(3) % 8)] },
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
