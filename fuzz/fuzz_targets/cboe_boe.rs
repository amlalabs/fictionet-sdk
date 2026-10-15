//! Cboe BOE messages in both directions, both framers, and a logged-in
//! server and exchange driven by whatever inbound messages parse.
#![no_main]

use fictionet::stdlib::cboe_boe::{
    ClientHeartbeat, CloseReason, Error, Event, Exchange, ExchangeConfig, Header, Inbound,
    LoginRequest, MAX_MESSAGE, NewOrder, Opt, Optional, OrderEvent, Outbound, ParamGroup,
    ParamGroups, Price, ReturnTable, Server, ServerPhase, Text, Timers, UnitSequence,
};
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::session::Action;
use fictionet::stdlib::test_support::contract::{check_decode, check_wire, check_written};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const MAX_ORDERS: usize = 16;

fn check_actions<E>(actions: &[Action<Outbound, E>]) {
    for action in actions {
        if let Action::Send(out) = action {
            check_written(out);
        }
    }
}

// Compact steering reaches both sides of the response limit without making
// the raw parser and framer paths consume large inputs on every iteration.
fn check_negotiation(groups: &[ParamGroup], steer: u8, count: u8) {
    let reject = steer & 4 != 0;
    let available: Vec<_> = (1..=count)
        .map(|unit| UnitSequence { unit, sequence: 0 })
        .collect();
    let overhead = 49 + if reject { 0 } else { 5 * available.len() };
    let len = match steer & 3 {
        0 => MAX_MESSAGE - overhead - 1,
        1 => MAX_MESSAGE - overhead,
        2 => MAX_MESSAGE - overhead + 1,
        _ => MAX_MESSAGE,
    };
    let mut request = LoginRequest {
        params: ParamGroups(groups.to_vec()),
        ..LoginRequest::default()
    };
    request.params.0.push(ParamGroup::Other {
        kind: 0x99,
        data: vec![0; len - request.wire_len() - 3],
    });
    let bytes = check_written(&request);
    assert_eq!(bytes.len(), len);
    let mut server = Server::new(Timers::default(), 0).unwrap();
    check_actions(&server.receive(&request.into(), 0).unwrap());
    let actions = if reject {
        server.reject(b'N', "No", 1)
    } else {
        server.accept(0, &available, 1)
    }
    .unwrap();
    check_actions(&actions);
    if len + overhead > MAX_MESSAGE {
        assert_eq!(
            actions,
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
    } else {
        let Some(Action::Send(Outbound::LoginResponse(response))) = actions.first() else {
            panic!("missing login response")
        };
        assert_eq!(response.status, if reject { b'N' } else { b'A' });
        assert_eq!(response.wire_len(), len + overhead);
    }
}

fn check_history(server: &Server, fields: &Optional<ReturnTable>, shares: u32, partial: bool) {
    let mut exchange = Exchange::new(ExchangeConfig::default(), server.returns().clone()).unwrap();
    let id = Text::new("A1").unwrap();
    for (now, symbol, qty, price) in [
        (1, "OLD", shares + u32::from(partial), 10),
        (5, "NEW", 500, 20),
    ] {
        let order = NewOrder {
            header: Header::default(),
            cl_ord_id: id,
            side: b'1',
            order_qty: qty,
            fields: Optional::new()
                .with(Opt::Symbol(Text::new(symbol).unwrap()))
                .unwrap()
                .with(Opt::Capacity(b'A'))
                .unwrap()
                .with(Opt::Price(Price(price)))
                .unwrap(),
        };
        check_written(&order);
        let actions = exchange.receive(&order.into(), now);
        check_actions(&actions);
        assert_eq!(actions, [Action::Event(OrderEvent::NewOrderRequested(id))]);
        check_written(&exchange.accept(id, 1, now).unwrap());
        if now == 1 {
            check_written(&exchange.execute(id, shares, Price(9), b'A', 2).unwrap());
            if partial {
                check_written(&exchange.cancel(id, b'A', 3).unwrap());
            }
            assert!(exchange.order(id).is_none());
        }
    }
    let before = exchange.order(id).cloned();
    let bust = exchange.bust(1, Price(0), 6).unwrap();
    check_written(&bust);
    let Outbound::TradeCancelOrCorrect(bust) = bust else {
        panic!("missing bust")
    };
    assert_eq!(bust.fields, *fields);
    assert_eq!(
        (bust.cl_ord_id, bust.order_id, bust.exec_ref_id),
        (id, 1, 1)
    );
    assert_eq!(
        (bust.last_shares, bust.last_px, bust.orig_time),
        (shares, Price(9), 2)
    );
    assert_eq!(exchange.order(id), before.as_ref());
    assert_eq!(
        exchange.bust(1, Price(0), 7),
        Err(Error::UnknownExecution(1))
    );
}

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

    let steer = data.first().copied().unwrap_or(0);
    let count = data.get(1).copied().unwrap_or(0);
    let mask = data.get(2).copied().unwrap_or(0);
    let shares = u32::from(count) + 1;
    let partial = steer & 8 != 0;
    let mut fields = Optional::<ReturnTable>::new();
    for (bit, field) in [
        Opt::Symbol(Text::new("OLD").unwrap()),
        Opt::Price(Price(10)),
        Opt::OrderQty(shares + u32::from(partial)),
        Opt::LeavesQty(u32::from(partial)),
        Opt::LastShares(shares),
        Opt::LastPx(Price(9)),
        Opt::DisplayPrice(Price(10)),
        Opt::WorkingPrice(Price(10)),
    ]
    .into_iter()
    .enumerate()
    {
        if mask & (1 << bit) != 0 {
            fields.set(field).unwrap();
        }
    }
    let groups: Vec<_> = [0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x48]
        .into_iter()
        .map(|message_type| ParamGroup::ReturnBitfields {
            message_type,
            bitfields: fields.bitfields(),
        })
        .collect();
    check_negotiation(&groups, steer, count);

    // Each piece split on 0xff is one inbound message; its last byte
    // steers the world. Keep this path's raw input independent of steering.
    let mut server = Server::new(Timers::default(), 0).unwrap();
    let request = LoginRequest {
        params: ParamGroups(groups),
        ..LoginRequest::default()
    };
    let bytes = check_written(&request);
    let inbound = Inbound::parse(&bytes).expect("login bytes parse as Inbound");
    assert_eq!(inbound, Inbound::LoginRequest(request.clone()));
    check_actions(&server.receive(&inbound, 0).unwrap());
    check_actions(
        &server
            .accept(
                0,
                &[UnitSequence {
                    unit: 1,
                    sequence: 0,
                }],
                0,
            )
            .unwrap(),
    );
    assert_eq!(server.phase(), ServerPhase::LoggedIn);
    check_history(&server, &fields, shares, partial);
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
                Action::Send(out) => {
                    check_written(&out);
                }
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
                            check_written(&out);
                            if let Ok(numbered) = server.send(out, now) {
                                check_written(&numbered);
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
            check_written(&out.unwrap());
        }
        if steer & 8 != 0 {
            if let Ok(out) = exchange.bust(u64::from(steer), Price(0), now) {
                check_written(&out);
            }
        }
        assert!(exchange.orders().count() <= MAX_ORDERS);
        for o in exchange.orders() {
            assert!(!o.live || o.leaves_qty > 0);
        }
        check_actions(&server.tick(now).unwrap());
    }
    let now = data.len() as u64 + 1;
    check_actions(&server.tick(now + Timers::default().heartbeat_ms).unwrap());
    check_actions(
        &server
            .tick(now + Timers::default().idle_timeout_ms)
            .unwrap(),
    );
});
