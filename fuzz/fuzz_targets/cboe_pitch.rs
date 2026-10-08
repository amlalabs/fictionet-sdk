//! Cboe Multicast PITCH as a feed handler reads it: one unit, one message,
//! a GRP or spin TCP stream of units, and the gap detector and order book
//! the units drive.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::cboe_pitch::AddOrderExpanded;

use fictionet::stdlib::cboe_pitch::Book;

use fictionet::stdlib::cboe_pitch::BookConfig;

use fictionet::stdlib::cboe_pitch::Control;

use fictionet::stdlib::cboe_pitch::GapDetector;

use fictionet::stdlib::cboe_pitch::HEADER_LENGTH;

use fictionet::stdlib::cboe_pitch::Message;

use fictionet::stdlib::cboe_pitch::Unit;
use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode, check_wire, check_wire_value},
    test_support::decode_all,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Unit>(data);
    check_wire::<Message>(data);
    check_wire::<Control>(data);
    check_wire::<AddOrderExpanded>(data);
    check_decode(Frames::<Unit>::default, data);
    check_decode(|| Frames::<Unit>::with_limit(HEADER_LENGTH + 64), data);
    let (units, _) = decode_all(Frames::<Unit>::default, data);

    // Every unit that parses goes through the gap detector, and its new
    // messages to a small book, whose limits must hold.
    let config = BookConfig {
        max_orders: 16,
        max_levels: 8,
        max_symbols: 4,
    };
    let mut book = Book::new(config).unwrap();
    let mut gaps = GapDetector::new();
    for unit in units.into_iter().flatten() {
        check_wire_value(&unit);
        let seen = gaps.receive(&unit);
        assert_eq!(seen.skip + seen.count, unit.messages.len());
        if let Some(gap) = seen.gap {
            let requested: u32 = gap.requests().iter().map(|r| u32::from(r.count)).sum();
            assert_eq!(requested, gap.count);
        }
        for bytes in &unit.messages[seen.skip..] {
            let Ok(message) = Message::parse(bytes) else {
                continue;
            };
            check_wire_value(&message);
            let before = format!("{book:?}");
            if book.apply(unit.unit, &message).is_err() {
                assert_eq!(format!("{book:?}"), before);
            }
            assert!(book.order_count() <= config.max_orders);
            assert!(book.level_count() <= config.max_levels);
            assert!(book.symbol_count() <= config.max_symbols);
        }
    }
    // Unframed: messages back to back, each by its Length byte.
    let mut rest = data;
    while let Some(&len) = rest.first() {
        let len = usize::from(len).clamp(1, rest.len());
        let (one, after) = rest.split_at(len);
        if let Ok(message) = Message::parse(one) {
            assert_eq!(message.to_bytes().unwrap(), one);
            let _ = book.apply(1, &message);
        }
        rest = after;
    }
});
