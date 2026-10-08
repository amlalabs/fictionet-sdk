//! OUCH 5.0 messages in both directions, and the exchange-side order
//! entry state machine driven by whatever inbound messages parse.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::ouch::{
    EnterOrder, Event, Exchange, ExchangeConfig, Inbound, Outbound, Price,
};
use fictionet::stdlib::session::Action;
use fictionet::stdlib::test_support::contract::{check_wire, check_wire_value};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const MAX_ORDERS: usize = 16;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Inbound>(data);
    check_wire::<Outbound>(data);
    check_wire::<EnterOrder>(data);

    // Split on 0xff: each piece is one inbound message for one exchange.
    // The first byte after each message steers the world's answers.
    let mut exchange = Exchange::new(ExchangeConfig {
        max_orders: MAX_ORDERS,
        max_executions: 8,
        ..ExchangeConfig::default()
    })
    .unwrap();
    for (now, piece) in data.split(|b| *b == 0xff).enumerate() {
        let now = now as u64;
        let Ok(message) = Inbound::parse(piece) else {
            continue;
        };
        let steer = piece.last().copied().unwrap_or(0);
        for action in exchange.receive(&message, now).unwrap() {
            match action {
                Action::Send(out) => check_wire_value(&out),
                Action::Event(Event::EnterRequested(t)) => {
                    let out = if steer & 1 == 0 {
                        exchange.accept(t, now).unwrap()
                    } else {
                        exchange.reject(t, u16::from(steer), now).unwrap()
                    };
                    check_wire_value(&out);
                }
                Action::Event(Event::ReplaceRequested { replacement, .. }) => {
                    let out = if steer & 2 == 0 {
                        exchange.accept(replacement, now)
                    } else {
                        exchange.reject(replacement, 1, now)
                    };
                    if let Ok(out) = out {
                        check_wire_value(&out);
                    }
                }
                Action::Event(Event::Ignored(_)) => {}
            }
        }
        // The world fills or cancels part of an open order.
        let open: Vec<_> = exchange
            .orders()
            .filter(|o| o.live)
            .map(|o| (o.token, o.quantity))
            .collect();
        if let Some(&(token, quantity)) = open.get(usize::from(steer) % open.len().max(1)) {
            let shares = (u32::from(steer) % quantity).max(1);
            let out = if steer & 4 == 0 {
                exchange.execute(token, shares, Price(1), b'A', now)
            } else {
                exchange.cancel(token, shares, b'U', now)
            };
            check_wire_value(&out.unwrap());
        }
        if steer & 8 != 0 {
            let _ = exchange.break_trade(u64::from(steer), b'E', now);
        }
        assert!(exchange.orders().count() <= MAX_ORDERS);
        for o in exchange.orders() {
            assert!(!o.live || o.quantity > 0);
        }
    }
});
