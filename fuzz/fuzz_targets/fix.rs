#![no_main]

use fictionet::stdlib::{
    codec::{
        Stream, Wire,
        contract::{check_decode_with_alloc_limit, check_wire, check_wire_value},
        test_support::decode_all,
    },
    fix::{
        Action, ExecutionReport, Frames, GroupLayout, MAX_ACTIONS, MAX_MESSAGE_SIZE,
        MarketDataIncrementalRefresh, MarketDataRequest, MarketDataSnapshotFullRefresh, Message,
        NewOrderSingle, OrderCancelReplaceRequest, OrderCancelRequest, Role, Session,
        SessionConfig, Version,
    },
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const MAX_SESSION_STEPS: usize = 64;
const TIME: &[u8] = b"20261006-12:00:00";
const GROUP: GroupLayout<'static> = GroupLayout {
    count_tag: 268,
    delimiter_tag: 279,
    members: &[279, 269, 278, 55, 270, 271],
    nested: &[],
};

fn check_actions(actions: &[Action]) {
    assert!(actions.len() <= MAX_ACTIONS);
    for action in actions {
        if let Action::Send(message) = action {
            check_wire_value(message);
            assert!(message.to_bytes().is_ok());
        }
    }
}

fn peer(kind: &[u8], sequence: u32) -> Message {
    let mut message = Message::new(Version::Fix44, kind).unwrap();
    message
        .push(49, b"PEER")
        .unwrap()
        .push(56, b"LOCAL")
        .unwrap()
        .push(34, sequence.to_string().as_bytes())
        .unwrap()
        .push(52, TIME)
        .unwrap();
    message
}

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Message>(data);
    check_decode_with_alloc_limit(Frames::default, data, 2 * MAX_MESSAGE_SIZE);
    let (messages, _) = decode_all(Frames::default, data);
    for message in messages {
        check_wire_value(&message);
        let _ = NewOrderSingle::view(&message);
        let _ = ExecutionReport::view(&message);
        let _ = OrderCancelRequest::view(&message);
        let _ = OrderCancelReplaceRequest::view(&message);
        let _ = MarketDataRequest::view(&message);
        let _ = MarketDataSnapshotFullRefresh::view(&message);
        let _ = MarketDataIncrementalRefresh::view(&message);
        for (i, field) in message.fields().iter().enumerate() {
            if field.tag() == GROUP.count_tag {
                let _ = message.group(i, &GROUP);
            }
        }
    }
    let mut built = Message::new(Version::Fix44, b"X").unwrap();
    // Successful raw-data construction puts arbitrary SOH bytes through framing.
    if !data.is_empty() {
        built.push_data(95, data).unwrap();
        check_wire_value(&built);
        let wire = built.to_bytes().unwrap();
        check_decode_with_alloc_limit(Frames::default, &wire, 2 * MAX_MESSAGE_SIZE);
        // A complete garbled frame must not hide the valid frame after it.
        let mut corrupt = wire.clone();
        let digit = corrupt.len() - 2;
        corrupt[digit] = if corrupt[digit] == b'0' { b'1' } else { b'0' };
        corrupt.extend_from_slice(&wire);
        check_decode_with_alloc_limit(Frames::default, &corrupt, 2 * MAX_MESSAGE_SIZE);
        let mut stream = Stream::new(Frames::default());
        assert_eq!(stream.push(&corrupt), corrupt.len());
        assert_eq!(stream.next(), Some(Ok(built.clone())));
        stream.end();
        assert!(stream.next().is_none());
        assert!(stream.failed().is_none());
        assert_eq!(stream.decoder().garbled(), 1);
    }
    let mut group = Message::new(Version::Fix44, b"X").unwrap();
    group
        .push(
            268,
            data.first().copied().unwrap_or(0).to_string().as_bytes(),
        )
        .unwrap();
    for bytes in data.chunks(3).take(32) {
        let tag = match bytes.first().copied().unwrap_or(0) % 4 {
            0 => 279,
            1 => 269,
            2 => 270,
            _ => 271,
        };
        group
            .push(
                tag,
                bytes.last().copied().unwrap_or(0).to_string().as_bytes(),
            )
            .unwrap();
    }
    let _ = group.group(2, &GROUP);
    check_wire_value(&group);

    let config = SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap();
    let mut session = Session::new(config, 1, 1, 0).unwrap();
    let mut logon = peer(b"A", 1);
    logon.push(98, b"0").unwrap().push(108, b"1").unwrap();
    check_actions(&session.receive(&logon, 0, TIME).unwrap());
    let mut now = 0u64;
    for step in data.chunks(5).take(MAX_SESSION_STEPS) {
        let code = step.first().copied().unwrap_or(0);
        let n = if code & 16 == 0 {
            session.next_inbound()
        } else {
            u32::from(step.get(1).copied().unwrap_or(1))
        };
        let kind = match code % 8 {
            0 => b"0",
            1 => b"1",
            2 => b"2",
            3 => b"3",
            4 => b"4",
            5 => b"5",
            6 => b"D",
            _ => b"A",
        };
        let mut message = peer(kind, n);
        if code & 32 != 0 {
            message
                .push(43, if step.get(4) == Some(&0) { b"X" } else { b"Y" })
                .unwrap();
        }
        if step.get(4) == Some(&1) {
            message.push(112, b"a").unwrap().push(112, b"b").unwrap();
        }
        if code & 64 != 0 {
            message.push(122, TIME).unwrap();
        }
        let value = u32::from(step.get(2).copied().unwrap_or(1)).to_string();
        match kind {
            b"1" => {
                message.push(112, value.as_bytes()).unwrap();
            }
            b"2" => {
                message
                    .push(7, value.as_bytes())
                    .unwrap()
                    .push(16, b"0")
                    .unwrap();
            }
            b"3" => {
                message.push(45, value.as_bytes()).unwrap();
            }
            b"4" => {
                message
                    .push(36, value.as_bytes())
                    .unwrap()
                    .push(123, if code & 128 != 0 { b"Y" } else { b"N" })
                    .unwrap();
            }
            b"A" => {
                message.push(98, b"0").unwrap().push(108, b"1").unwrap();
            }
            _ => {}
        }
        check_wire_value(&message);
        now += u64::from(step.get(3).copied().unwrap_or(0)) * 100;
        if let Ok(actions) = session.receive(&message, now, TIME) {
            check_actions(&actions);
        }
        if let Ok(actions) = session.tick(now, TIME) {
            check_actions(&actions);
        }
        if let Some(event) = session.next_resend_range() {
            let _ = event;
        }
    }
});
