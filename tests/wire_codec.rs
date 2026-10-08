//! Public wire units preserve protocol boundaries and constructor choices.

use fictionet::stdlib::{
    bacnet,
    codec::{Wire},
    test_support::contract,
    dtls, l2tp, nbns, ntlmssp, pcp,
};
use std::net::Ipv4Addr;

#[test]
fn complete_units_refuse_a_second_unit() {
    let values = bacnet::ValueList(vec![bacnet::Value::Real(72.3), bacnet::Value::Unsigned(85)]);
    let bytes = values.to_bytes().unwrap();
    assert_eq!(bacnet::ValueList::parse(&bytes), Ok(values));
    assert_eq!(
        bacnet::Value::parse(&bytes),
        Err(bacnet::Error::TrailingBytes)
    );

    let pairs = ntlmssp::AvPairs(vec![
        ntlmssp::AvPair {
            id: ntlmssp::av_id::FLAGS,
            value: vec![2, 0, 0, 0],
        },
        ntlmssp::AvPair {
            id: ntlmssp::av_id::TIMESTAMP,
            value: vec![0; 8],
        },
    ]);
    let mut bytes = pairs.to_bytes().unwrap();
    assert_eq!(ntlmssp::AvPairs::parse(&bytes), Ok(pairs));
    bytes.extend_from_slice(&[0; 4]);
    assert_eq!(
        ntlmssp::AvPairs::parse(&bytes),
        Err(ntlmssp::Error::Trailing)
    );

    let record = dtls::Record::Plain(dtls::PlainRecord {
        content_type: dtls::ContentType::TLS12_CID,
        version: dtls::version::DTLS_1_2,
        epoch: 1,
        sequence: 0,
        connection_id: vec![3; 8],
        fragment: vec![7; 16],
    });
    let datagram = dtls::Datagram::new(&[record.clone(), record.clone()], 8).unwrap();
    let bytes = datagram.to_bytes().unwrap();
    assert_eq!(dtls::Datagram::read(&bytes, 8), Ok(vec![record.clone(), record]));
    contract::check_wire_value(&datagram);
    assert_eq!(
        dtls::Record::read(&bytes, 8),
        Err(dtls::Error::RecordTrailing)
    );
}

#[test]
fn control_ignores_trailing_bytes_and_nat_pmp_refuses_them() {
    let control = l2tp::V3Control::new(1, 2, 3, &l2tp::ControlMessage::zlb()).unwrap();
    let mut bytes = control.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(l2tp::V3Control::parse(&bytes), Ok(control));
    contract::check_wire::<l2tp::V3Control>(&bytes);

    let mut bytes = pcp::NatPmpRequest::ExternalAddress.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(pcp::NatPmpRequest::parse(&bytes), Err(pcp::Error::NatPmpTrailing));
    contract::check_wire::<pcp::NatPmpRequest>(&bytes);
}

#[test]
fn nbns_reply_construction_sets_tc_before_writing() {
    let name = nbns::Name::new("WORLD", 0x20).with_scope("EXAMPLE.TEST");
    let query = nbns::Packet::name_query(7, name.clone(), false);
    let owner = nbns::NbEntry {
        group: false,
        node_type: nbns::NodeType::B,
        address: Ipv4Addr::LOCALHOST,
    };
    let reply = query.query_response(name, 60, vec![owner; 1000]);
    assert!(reply.flags.truncated);
    contract::check_wire_value(&reply);
    let bytes = reply.to_bytes().unwrap();
    assert!(bytes.len() <= nbns::MAX_DATAGRAM);
    assert_eq!(nbns::Packet::parse(&bytes), Ok(reply));
}

#[test]
fn invalid_bacnet_identifiers_refuse_packing_and_leave_output_unchanged() {
    let id = bacnet::ObjectId::device(bacnet::MAX_INSTANCE + 1);
    assert_eq!(id.to_u32(), None);
    let value = bacnet::Value::ObjectId(id);
    let mut out = vec![1, 2, 3];
    assert_eq!(value.write(&mut out), Err(bacnet::Error::Unwritable));
    assert_eq!(out, [1, 2, 3]);
}
