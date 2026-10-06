//! RDP connection codecs, transport framing and bounded streaming.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::rdp::Frames;
use fictionet::stdlib::rdp::{
    ActiveKind, ActivePdu, CapabilitySet, CapabilityType, ChannelDefinition, ClientInfo,
    Connection, ConnectionKind, DataBlock, DataBlocks, FailureCode, Frame, GccConference,
    INFO_RESERVED, INFO_UNICODE, LicenseError, MAX_CAPABILITY, MAX_CHANNELS, MAX_CONNECTION_DATA,
    MAX_EXTRA_INFO, MAX_FAST_PATH, MAX_FRAME, MAX_GCC_DATA, MAX_INFO_STRING, MAX_PDU,
    MAX_PER_LENGTH, McsConnect, McsPdu, Negotiation, Protocols, SERVER_CHANNEL_ID, SecurityPayload,
    read_data, write_data,
};
use libfuzzer_sys::fuzz_target;

// Bound work and every test-owned allocation even with huge fuzzer inputs.
const MAX_FUZZ_INPUT: usize = 2 * MAX_FRAME;
const MAX_BUILT_BODY: usize = 4096;

fn prefix(data: &[u8], n: usize) -> &[u8] {
    data.get(..data.len().min(n)).unwrap_or_default()
}

fn plaintext(data: &[u8]) {
    macro_rules! roundtrip {
        ($ty:ty) => {
            if let Ok(value) = <$ty as Wire>::parse(data) {
                check_wire_value(&value);
                let bytes = value.to_bytes().unwrap();
                assert!(bytes.len() <= MAX_PDU);
            }
        };
    }
    roundtrip!(ClientInfo);
    roundtrip!(LicenseError);
    roundtrip!(ActivePdu);
    roundtrip!(CapabilitySet);
}

fn pdu(data: &[u8]) {
    macro_rules! roundtrip {
        ($ty:ty) => {
            if let Ok(value) = <$ty as Wire>::parse(data) {
                check_wire_value(&value);
                let bytes = value.to_bytes().unwrap();
                assert!(bytes.len() <= MAX_PDU);
            }
        };
    }
    roundtrip!(Negotiation);
    roundtrip!(DataBlock);
    roundtrip!(GccConference);
    roundtrip!(McsConnect);
    check_wire::<DataBlocks>(data);
    if let Ok(blocks) = DataBlocks::parse(data) {
        let bytes = blocks.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_GCC_DATA);
    }
    if let Ok(value) = <McsPdu as Wire>::parse(data) {
        check_wire_value(&value);
        let bytes = value.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_PDU);
        if let McsPdu::SendData { data, .. } = value {
            security(&data);
            plaintext(&data);
        }
    }
    security(data);
    plaintext(data);
}

fn security(data: &[u8]) {
    check_wire::<SecurityPayload>(data);
    if let Ok(value) = <SecurityPayload as Wire>::parse(data) {
        if let Ok(data) = value.plaintext() {
            plaintext(data);
        }
    }
}

fn frame(value: &Frame) -> Vec<u8> {
    check_wire_value(value);
    let bytes = value.to_bytes().unwrap();
    assert!(bytes.len() <= MAX_FRAME);
    if let Frame::SlowPath(packet) = value {
        if let Ok(c) = Connection::from_packet(packet) {
            assert_eq!(Connection::from_packet(&c.to_packet().unwrap()), Ok(c));
        }
        if let Ok(data) = read_data(packet) {
            assert_eq!(read_data(&write_data(&data).unwrap()), Ok(data.clone()));
            pdu(&data);
        }
    }
    bytes
}

fn built(data: &[u8]) {
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    let word = |i: usize| u32::from_le_bytes([byte(i), byte(i + 1), byte(i + 2), byte(i + 3)]);
    let body = prefix(data, MAX_BUILT_BODY);
    macro_rules! check {
        ($ty:ty, $value:expr) => {{
            let value: $ty = $value;
            check_wire_value(&value);
            if let Ok(bytes) = value.to_bytes() {
                assert!(bytes.len() <= MAX_PDU);
            }
        }};
    }
    let negotiation = match byte(0) % 3 {
        0 => Negotiation::Request {
            flags: byte(1),
            protocols: Protocols(word(2)),
        },
        1 => Negotiation::Response {
            flags: byte(1),
            protocol: Protocols(word(2)),
        },
        _ => Negotiation::Failure(FailureCode(word(2))),
    };
    check!(Negotiation, negotiation);
    let connection = Connection {
        kind: if byte(0) & 1 == 0 {
            ConnectionKind::Request
        } else {
            ConnectionKind::Confirm
        },
        source: byte(1).into(),
        destination: byte(2).into(),
        routing_token: prefix(body, MAX_CONNECTION_DATA).to_vec(),
        negotiation: Some(negotiation),
        correlation_id: if byte(3) & 1 != 0 {
            Some([byte(4); 16])
        } else {
            None
        },
    };
    if let Ok(packet) = connection.to_packet() {
        assert_eq!(Connection::from_packet(&packet), Ok(connection));
    }
    let fast = Frame::FastPath {
        header: byte(0),
        payload: prefix(data, MAX_FAST_PATH).to_vec(),
    };
    check_wire_value(&fast);
    check!(
        DataBlock,
        DataBlock::Other {
            kind: byte(0).into(),
            data: body.to_vec()
        }
    );
    // A terminator at index 8 means none, which the codec refuses.
    let mut name = [byte(1); 8];
    if let Some(b) = name.get_mut(usize::from(byte(6)) % 9) {
        *b = 0;
    }
    let channels = vec![
        ChannelDefinition {
            name,
            options: word(2)
        };
        usize::from(byte(0)) % (MAX_CHANNELS + 2)
    ];
    check!(DataBlock, DataBlock::ClientNetwork(channels));
    let block = DataBlock::ServerSecurity {
        encryption_method: word(0),
        encryption_level: word(4),
        random: prefix(data, usize::from(byte(8)) % 34).to_vec(),
        certificate: body.to_vec(),
    };
    check!(DataBlock, block);
    check!(
        GccConference,
        GccConference::Request(DataBlocks(vec![DataBlock::ClientMultitransport(word(0))]))
    );
    check!(
        GccConference,
        GccConference::Response {
            node_id: word(0),
            tag: word(4) as i32,
            result: byte(8),
            blocks: DataBlocks(vec![DataBlock::ServerMultitransport(word(9))]),
        }
    );
    let mcs = McsPdu::SendData {
        indication: byte(0) & 1 != 0,
        initiator: 1001 + u32::from(byte(1)),
        channel_id: u16::from_le_bytes([byte(2), byte(3)]),
        priority: byte(4) & 7,
        segmentation: byte(5) & 7,
        data: prefix(data, MAX_PER_LENGTH).to_vec(),
    };
    check!(McsPdu, mcs);
    check!(
        McsPdu,
        McsPdu::AttachUserConfirm {
            result: byte(0),
            initiator: if byte(1) & 1 != 0 {
                Some(word(2))
            } else {
                None
            },
        }
    );
    // Strings straddle the limit; bits 1 and 2 of byte 1 set reserved flags.
    let length = usize::from(u16::from_le_bytes([byte(7), byte(8)]));
    let string = prefix(body, length % (MAX_INFO_STRING + 2));
    let info = ClientInfo {
        code_page: word(0),
        flags: (if byte(1) & 1 == 0 { INFO_UNICODE } else { 0 })
            | ((u32::from(byte(1)) << 22) & INFO_RESERVED),
        domain: string.to_vec(),
        user_name: string.to_vec(),
        password: Vec::new(),
        alternate_shell: Vec::new(),
        working_dir: Vec::new(),
        extra_info: prefix(data, MAX_EXTRA_INFO).to_vec(),
    };
    check!(ClientInfo, info);
    check!(
        SecurityPayload,
        SecurityPayload {
            flags: byte(0).into(),
            flags_hi: byte(1).into(),
            data: body.to_vec()
        }
    );
    check!(
        LicenseError,
        LicenseError {
            flags: byte(0),
            error_code: word(1),
            state_transition: word(5),
            blob_type: if byte(9) & 1 == 0 { 4 } else { byte(9).into() },
            blob: body.to_vec()
        }
    );
    let capability = CapabilitySet {
        kind: CapabilityType(byte(0).into()),
        data: prefix(data, MAX_CAPABILITY).to_vec(),
    };
    check!(CapabilitySet, capability.clone());
    check!(
        ActivePdu,
        ActivePdu {
            kind: if byte(1) & 1 == 0 {
                ActiveKind::Demand {
                    session_id: word(2),
                }
            } else {
                ActiveKind::Confirm {
                    originator_id: if byte(2) & 1 == 0 {
                        SERVER_CHANNEL_ID
                    } else {
                        u16::from_le_bytes([byte(2), byte(10)])
                    },
                }
            },
            source: byte(3).into(),
            share_id: word(4),
            source_descriptor: prefix(body, 32).to_vec(),
            capabilities: vec![capability],
            padding: u16::from_le_bytes([byte(8), byte(9)]),
        }
    );
}

fuzz_target!(|data: &[u8]| {
    let data = prefix(data, MAX_FUZZ_INPUT);
    check_decode(Frames::new, data);
    check_wire::<Frame>(data);
    pdu(data);
    let mut stream = Stream::new(Frames);
    let _ = pump(&mut stream, data, |value| {
        frame(&value);
    });
    built(data);
});
