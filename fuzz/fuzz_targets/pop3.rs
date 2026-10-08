//! POP3 commands, reply expectations, AUTH lines, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::pop3::{
    Command, Error, Input, Inputs, MAX_AUTH_LINE, MAX_REPLY_HELD, Output, Outputs, Reply,
    Request, ScanListing, UniqueIdListing,
};
use libfuzzer_sys::fuzz_target;

fn check_reply(reply: &Reply) {
    contract::check_wire_value(reply);
    if let Ok(bytes) = reply.to_bytes() {
        let make = || {
            let mut replies = Outputs::new();
            replies.expect(reply.body.is_some()).unwrap();
            replies
        };
        contract::check_decode_with_held_limit(make, &bytes, MAX_REPLY_HELD);
        assert_eq!(
            decode_all(make, &bytes),
            (vec![Ok(Output::Reply(reply.clone()))], None)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Inputs::new, data, 2 * (MAX_AUTH_LINE + 2));
    contract::check_decode_with_held_limit(Inputs::new, data, 0);
    let raw = || {
        let mut commands = Inputs::new();
        commands.expect_line().unwrap();
        commands
    };
    contract::check_decode_with_alloc_limit(raw, data, 2 * (MAX_AUTH_LINE + 2));
    let auth = || {
        let mut replies = Outputs::new();
        replies.expect(false).unwrap();
        replies.expect_line().unwrap();
        replies.expect(true).unwrap();
        replies.map(|item: Result<Output, Error>| {
            if let Ok(Output::Line(line)) = &item {
                assert!(line == b"+" || line.starts_with(b"+ "));
            }
            item
        })
    };
    contract::check_decode_with_alloc_limit(auth, data, 2 * (MAX_AUTH_LINE + 2));
    contract::check_decode_with_held_limit(auth, data, MAX_REPLY_HELD);
    for multi in [false, true] {
        let make = || {
            let mut replies = Outputs::new();
            for _ in 0..4 {
                replies.expect(multi).unwrap();
            }
            replies
        };
        contract::check_decode_with_alloc_limit(make, data, 2 * (MAX_AUTH_LINE + 2));
        contract::check_decode_with_held_limit(make, data, MAX_REPLY_HELD);
        for item in decode_all(make, data).0 {
            if let Ok(Output::Reply(reply)) = item {
                check_reply(&reply);
                if let Some(code) = &reply.code {
                    assert!(reply.has_code(code) && reply.has_code(&code.to_ascii_lowercase()));
                }
                if let Some((count, size)) = reply.drop_listing() {
                    assert_eq!(Reply::stat(count, size).drop_listing(), Some((count, size)));
                }
                for line in reply.lines() {
                    contract::check_wire::<ScanListing>(line);
                    contract::check_wire::<UniqueIdListing>(line);
                }
            }
        }
    }
    contract::check_wire::<Command>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Reply>(data);
    contract::check_wire::<ScanListing>(data);
    contract::check_wire::<UniqueIdListing>(data);
    for item in decode_all(Inputs::new, data).0 {
        if let Ok(Input::Command(command)) = item {
            contract::check_wire::<Command>(&command.to_bytes().unwrap());
            if let Ok(request) = Request::from_command(&command) {
                contract::check_wire::<Request>(&request.to_bytes().unwrap());
            }
        }
    }
    let (a, b) = data.split_at(data.len() / 2);
    let (sa, sb) = (String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    let pick = data.first().copied().unwrap_or(0);
    let command = Command {
        keyword: sa.to_string(),
        argument: Some(sb.to_string()),
    };
    contract::check_wire_value(&command);
    check_reply(&Reply {
        ok: pick & 1 == 0,
        code: (pick & 2 != 0).then(|| sa.to_string()),
        text: sb.to_string(),
        body: (pick & 4 != 0).then(|| data.to_vec()),
    });
    for request in [
        Request::Other(command),
        Request::User(sa.to_string()),
        Request::Pass(sb.to_string()),
        Request::Apop {
            name: sb.to_string(),
            digest: [pick; 16],
        },
    ] {
        contract::check_wire_value(&request);
    }
    contract::check_wire_value(&UniqueIdListing {
        message: std::num::NonZeroU32::MIN,
        id: sa.to_string(),
    });
});
