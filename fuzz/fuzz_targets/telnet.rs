//! Telnet events, option negotiation, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::telnet::harness::merged;
use fictionet::stdlib::telnet::{
    self, BinaryEvent, Event, Events, Negotiation, Side, Subnegotiation, option,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

struct Session {
    events: Events,
    options: Negotiation,
}

impl Session {
    fn new(ask: bool, allow: bool) -> Self {
        let mut options = Negotiation::new();
        options.allow_remote(option::BINARY, allow);
        if ask {
            options.enable_remote(option::BINARY);
        }
        Self {
            events: Events::new(),
            options,
        }
    }
}

impl Decode for Session {
    type Item = Event;
    type Error = telnet::Error;
    const NAME: &'static str = "Telnet fuzz session";

    fn capacity(&self) -> usize {
        self.events.capacity()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, Self::Error> {
        let step = self.events.decode(input, eof)?;
        if let Step::Item(Event::Negotiation { verb, option }, _) = &step {
            let reaction = self.options.receive(*verb, *option);
            if let Some(reply) = reaction.send {
                contract::check_wire_value(&reply);
            }
            if let Some(change) = reaction.change
                && change.side == Side::Remote
                && change.option == option::BINARY
            {
                self.events.set_binary(change.enabled);
            }
        }
        Ok(step)
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Event>(data);
    contract::check_wire::<BinaryEvent>(data);
    contract::check_wire::<Subnegotiation>(data);
    for binary in [false, true] {
        for limit in [1, telnet::MAX_DATA] {
            let make = || {
                let mut events = Events::with_limit(limit);
                events.set_binary(binary);
                events
            };
            contract::check_decode_with_alloc_limit(make, data, 2 * telnet::MAX_EVENT_WIRE);
            contract::check_decode_with_held_limit(make, data, 0);
            let (events, _) = decode_all(make, data);
            let kept: Vec<_> = events
                .into_iter()
                .filter(|event| !matches!(event, Event::Error(_)))
                .collect();
            let mut written = Vec::new();
            for event in &kept {
                if binary {
                    let event = BinaryEvent(event.clone());
                    contract::check_wire_value(&event);
                    event.write(&mut written).unwrap();
                } else {
                    contract::check_wire_value(event);
                    event.write(&mut written).unwrap();
                }
                if let Event::Subnegotiation { option, data } = event
                    && let Ok(sub) = Subnegotiation::parse_data(*option, data)
                {
                    assert_eq!(sub.to_event().unwrap(), *event);
                    contract::check_wire_value(&sub);
                }
            }
            let (back, failure) = decode_all(make, &written);
            assert_eq!(failure, None);
            assert_eq!(merged(back), merged(kept));
        }
    }
    let mode = data.first().copied().unwrap_or_default();
    contract::check_decode_with_alloc_limit(
        || Session::new(mode & 2 != 0, mode & 4 != 0),
        data,
        2 * telnet::MAX_EVENT_WIRE,
    );
    let event = Event::Data(data.iter().take(telnet::MAX_DATA + 1).copied().collect());
    contract::check_wire_value(&event);
    contract::check_wire_value(&BinaryEvent(event));
    let payload: Vec<_> = data
        .iter()
        .take(telnet::MAX_SUBNEGOTIATION + 1)
        .copied()
        .collect();
    contract::check_wire_value(&Event::Subnegotiation {
        option: mode,
        data: payload.clone(),
    });
    for option in 0..=255u8 {
        if let Ok(sub) = Subnegotiation::parse_data(option, data) {
            contract::check_wire_value(&sub);
            assert_eq!(
                sub.to_event().unwrap(),
                Event::Subnegotiation {
                    option,
                    data: data.to_vec()
                }
            );
        }
        contract::check_wire_value(&Subnegotiation::Other {
            option,
            data: payload.clone(),
        });
    }
    contract::check_wire_value(&Subnegotiation::TerminalTypeIs(
        String::from_utf8_lossy(&payload).into_owned(),
    ));
    contract::check_wire_value(&Event::Error(telnet::Error::Truncated));
    let mut options = Negotiation::new();
    for option in 0..=255u8 {
        options.allow_local(option, option % 2 == 0);
        options.allow_remote(option, option % 3 == 0);
        for verb in [
            telnet::Verb::Will,
            telnet::Verb::Wont,
            telnet::Verb::Do,
            telnet::Verb::Dont,
        ] {
            if let Some(reply) = options.receive(verb, option).send {
                let bytes = reply.to_bytes().unwrap();
                assert_eq!(Event::parse(&bytes), Ok(reply));
            }
        }
    }
});
