//! Cboe BOE messages in both directions, both framers, and a logged-in
//! server and exchange driven by whatever inbound messages parse.
#![no_main]

use fictionet::stdlib::cboe_boe::{
    Action, ClientHeartbeat, Event, Exchange, ExchangeConfig, Frames, Inbound, LoginRequest,
    NewOrder, OrderEvent, Outbound, Price, Server, Timers, UnitSequence,
};
use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode, check_wire, check_wire_value},
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const MAX_ORDERS: usize = 16;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Inbound>(data);
    check_wire::<Outbound>(data);
    check_wire::<NewOrder>(data);
    check_wire::<LoginRequest>(data);
    check_decode(Frames::<Inbound>::default, data);
    check_decode(Frames::<Outbound>::default, data);

    // A server logged in with no return fields; each piece split on 0xff
    // is one inbound message, and the byte after it steers the world.
    let mut server = Server::new(Timers::default(), 0).unwrap();
    server.receive(&LoginRequest::default().into(), 0).unwrap();
    server
        .accept(
            0,
            &[UnitSequence {
                unit: 1,
                sequence: 0,
            }],
            0,
        )
        .unwrap();
    let mut exchange = Exchange::new(
        ExchangeConfig {
            max_orders: MAX_ORDERS,
            max_executions: 8,
            ..ExchangeConfig::default()
        },
        server.returns().clone(),
    )
    .unwrap();
    for (now, piece) in data.split(|b| *b == 0xff).enumerate() {
        let now = now as u64;
        let steer = piece.last().copied().unwrap_or(0);
        let message = Inbound::parse(piece).unwrap_or_else(|_| ClientHeartbeat::default().into());
        let before = format!("{server:?}");
        let Ok(actions) = server.receive(&message, now) else {
            assert_eq!(format!("{server:?}"), before);
            continue;
        };
        for action in actions {
            match action {
                Action::Send(out) => check_wire_value(&out),
                Action::Event(Event::Application) => {
                    for a in exchange.receive(&message, now) {
                        let out = match a {
                            Action::Send(out) => Ok(out),
                            Action::Event(OrderEvent::NewOrderRequested(id)) => {
                                if steer & 1 == 0 {
                                    exchange.accept(id, 1, now)
                                } else {
                                    exchange.reject(id, b'Z', "No", now)
                                }
                            }
                            Action::Event(_) => continue,
                        };
                        if let Ok(out) = out {
                            check_wire_value(&out);
                            if let Ok(numbered) = server.send(out, now) {
                                check_wire_value(&numbered);
                            }
                        }
                    }
                }
                Action::Event(_) => {}
            }
        }
        // The world fills, restates or cancels part of a live order.
        let live: Vec<_> = exchange
            .orders()
            .filter(|o| o.live)
            .map(|o| (o.cl_ord_id, o.leaves_qty))
            .collect();
        if let Some(&(id, leaves)) = live.get(usize::from(steer) % live.len().max(1)) {
            let shares = (u32::from(steer) % leaves).max(1);
            let out = match steer % 3 {
                0 => exchange.execute(id, shares, Price(1), b'A', now),
                1 => exchange.restate(id, leaves - shares, b'L', now),
                _ => exchange.cancel(id, b'A', now),
            };
            check_wire_value(&out.unwrap());
        }
        if steer & 8 != 0 {
            let _ = exchange.bust(u64::from(steer), Price(0), now);
        }
        assert!(exchange.orders().count() <= MAX_ORDERS);
        for o in exchange.orders() {
            assert!(!o.live || o.leaves_qty > 0);
        }
        let _ = server.tick(now);
    }
});
