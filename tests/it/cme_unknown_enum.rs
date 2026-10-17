use fictionet::stdlib::cme_mdp3::{
    AdminHeartbeat12, HaltReason, MatchEventIndicator, Message, Messages, Packet, PacketHeader,
    SecurityStatus30, SecurityTradingEvent,
};
use fictionet::stdlib::codec::{Decode, Step, Wire};

#[test]
fn unknown_enum_preserves_every_message_in_the_datagram() {
    let status = SecurityStatus30 {
        transact_time: 1,
        security_group: b"ES    ".to_vec(),
        asset: b"ES    ".to_vec(),
        security_id: Some(1),
        trade_date: Some(1),
        match_event_indicator: MatchEventIndicator(0),
        security_trading_status: None,
        halt_reason: HaltReason::GroupSchedule,
        security_trading_event: SecurityTradingEvent::NoEvent,
    };
    let packet = Packet {
        header: PacketHeader {
            sequence: 1,
            sending_time: 1,
        },
        messages: vec![
            Message::AdminHeartbeat12(AdminHeartbeat12 {}),
            Message::SecurityStatus30(status),
        ],
    };
    let mut bytes = packet.to_bytes().unwrap();
    assert_eq!(Packet::parse(&bytes).unwrap(), packet);
    // The last byte is SecurityTradingEvent: a value this schema lacks.
    *bytes.last_mut().unwrap() = 200;
    let mut rest = &bytes[12..];
    let mut items = Vec::new();
    while !rest.is_empty() {
        let Ok(Step::Item(m, used)) = Messages.decode(rest, true) else {
            break;
        };
        items.push(m.map(|_| "ok").map_err(|e| e.to_string()));
        rest = &rest[used..];
    }
    assert_eq!(items, vec![Ok("ok"), Ok("ok")]);
    assert!(rest.is_empty());
    let whole = Packet::parse(&bytes).unwrap();
    assert_eq!(whole.messages.len(), 2);
    assert_eq!(whole.messages[0], packet.messages[0]);
    let Message::SecurityStatus30(status) = &whole.messages[1] else {
        panic!("status message is retained")
    };
    assert_eq!(
        status.security_trading_event,
        SecurityTradingEvent::Unknown(200)
    );
    assert_eq!(whole.to_bytes().unwrap(), bytes);
}
