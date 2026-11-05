//! Telnet events, option negotiation, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::telnet::harness::merged;
use fictionet::stdlib::protocols::telnet::{
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
                let _ = assert_write(&reply);
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

fn check_control_scanner(data: &[u8], chunk: usize) {
    let make = || {
        let mut events = Events::new();
        events.set_binary(true);
        events
    };
    let (events, failure) = decode_all(make, data);
    let mut expected = events.into_iter();
    let mut scanner = telnet::ControlScanner::new();
    let mut at = 0;
    let mut end = 0;
    loop {
        let input = &data[at..end];
        let used = match scanner.scan(input, end == data.len()) {
            Ok(Step::Item(telnet::ControlSpan::Data, used)) => {
                for &byte in &input[..used] {
                    assert_eq!(expected.next(), Some(Event::Data(vec![byte])));
                }
                used
            }
            Ok(Step::Item(telnet::ControlSpan::Error(error), used)) => {
                assert_eq!(expected.next(), Some(Event::Error(error)));
                used
            }
            Ok(Step::Item(_, used)) => {
                assert_eq!(
                    expected.next(),
                    Some(BinaryEvent::parse(&input[..used]).unwrap().0)
                );
                used
            }
            Ok(Step::Skip(used)) => used,
            Ok(Step::Need) if end < data.len() => {
                end = end.saturating_add(chunk).min(data.len());
                continue;
            }
            Ok(Step::Need) => {
                let want = if input.is_empty() {
                    None
                } else {
                    Some(fictionet::stdlib::codec::Fail::Truncated {
                        unread: input.len(),
                    })
                };
                assert_eq!(failure, want);
                break;
            }
            Err(error) => {
                assert_eq!(
                    failure,
                    Some(fictionet::stdlib::codec::Fail::Protocol(error))
                );
                break;
            }
            Ok(Step::End) => panic!("scanner ended early"),
        };
        assert!(used <= input.len());
        at += used;
    }
    assert_eq!(expected.next(), None);
}

fuzz_target!(|data: &[u8]| {
    check_control_scanner(data, 1);
    check_control_scanner(data, telnet::MAX_EVENT_WIRE);
    if let Ok(value) = <Event as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <BinaryEvent as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Subnegotiation as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for binary in [false, true] {
        for limit in [1, telnet::MAX_DATA] {
            let make = || {
                let mut events = Events::with_limit(limit);
                events.set_binary(binary);
                events
            };
            assert_eq!(
                decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                    assert!(s.allocated() <= 2 * telnet::MAX_EVENT_WIRE);
                    assert_eq!(s.held(), 0);
                }),
                decode_all(make, data),
            );
            let (events, _) = decode_all(make, data);
            let kept: Vec<_> = events
                .into_iter()
                .filter(|event| !matches!(event, Event::Error(_)))
                .collect();
            let mut written = Vec::new();
            for event in &kept {
                if binary {
                    let event = BinaryEvent(event.clone());
                    let _ = assert_write(&event);
                    event.write(&mut written).unwrap();
                } else {
                    let _ = assert_write(event);
                    event.write(&mut written).unwrap();
                }
                if let Event::Subnegotiation { option, data } = event
                    && let Ok(sub) = Subnegotiation::parse_data(*option, data)
                {
                    assert_eq!(sub.to_event().unwrap(), *event);
                    let _ = assert_write(&sub);
                }
            }
            let (back, failure) = decode_all(make, &written);
            assert_eq!(failure, None);
            assert_eq!(merged(back), merged(kept));
        }
    }
    let mode = data.first().copied().unwrap_or_default();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Session::new(mode & 2 != 0, mode & 4 != 0)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * telnet::MAX_EVENT_WIRE);
            }
        ),
        decode_all(|| Session::new(mode & 2 != 0, mode & 4 != 0), data),
    );
    let event = Event::Data(data.iter().take(telnet::MAX_DATA + 1).copied().collect());
    let _ = assert_write(&event);
    let _ = assert_write(&BinaryEvent(event));
    let payload: Vec<_> = data
        .iter()
        .take(telnet::MAX_SUBNEGOTIATION + 1)
        .copied()
        .collect();
    let _ = assert_write(&Event::Subnegotiation {
        option: mode,
        data: payload.clone(),
    });
    for option in 0..=255u8 {
        if let Ok(sub) = Subnegotiation::parse_data(option, data) {
            let _ = assert_write(&sub);
            assert_eq!(
                sub.to_event().unwrap(),
                Event::Subnegotiation {
                    option,
                    data: data.to_vec()
                }
            );
        }
        let _ = assert_write(&Subnegotiation::Other {
            option,
            data: payload.clone(),
        });
    }
    let _ = assert_write(&Subnegotiation::TerminalTypeIs(
        String::from_utf8_lossy(&payload).into_owned(),
    ));
    let _ = assert_write(&Event::Error(telnet::Error::Truncated));
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
