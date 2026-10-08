//! ITCH 5.0 messages as a feed handler reads them: one message, a framed
//! file of them, and the order book they drive.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::itch::{
    AddOrder, Book, BookConfig, MAX_MESSAGE_LENGTH, Message, Noii, OrderReplace, StockDirectory,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Message>(data);
    check_wire::<AddOrder>(data);
    check_wire::<OrderReplace>(data);
    check_wire::<StockDirectory>(data);
    check_wire::<Noii>(data);
    check_decode(Frames::<Message>::default, data);
    check_decode(|| Frames::<Message>::with_limit(MAX_MESSAGE_LENGTH), data);
    let (items, _) = decode_all(Frames::<Message>::default, data);

    // Every framed message that parses goes to a small book, whose
    // limits must hold whatever it is fed.
    let config = BookConfig {
        max_orders: 16,
        max_levels: 8,
        max_stocks: 4,
    };
    let mut book = Book::new(config).unwrap();
    for message in items.into_iter().flatten() {
        check_wire_value(&message);
        let before = format!("{book:?}");
        if book.apply(&message).is_err() {
            assert_eq!(format!("{book:?}"), before);
        }
        assert!(book.order_count() <= config.max_orders);
        assert!(book.level_count() <= config.max_levels);
        assert!(book.stock_count() <= config.max_stocks);
    }
    // Unframed: each slice the length of its type byte's message.
    let mut rest = data;
    while let Some(&kind) = rest.first() {
        let len = Message::length_of(kind).unwrap_or(1).min(rest.len());
        let (one, after) = rest.split_at(len);
        if let Ok(message) = Message::parse(one) {
            assert_eq!(message.to_bytes().unwrap(), one);
            let _ = book.apply(&message);
        }
        rest = after;
    }
});
