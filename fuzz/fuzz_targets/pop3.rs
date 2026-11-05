//! POP3 commands, reply expectations, AUTH lines, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::pop3::{
    Command, Error, Input, Inputs, MAX_AUTH_LINE, MAX_REPLY_HELD, Output, Outputs, Reply, Request,
    ScanListing, UniqueIdListing,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fn check_reply(reply: &Reply) {
    let _ = assert_write(reply);
    if let Ok(bytes) = reply.to_bytes() {
        let make = || {
            let mut replies = Outputs::new();
            replies.expect(reply.body.is_some()).unwrap();
            replies
        };
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(&bytes, &[1, 7, 64]), |s| {
                assert!(s.held() <= MAX_REPLY_HELD);
            }),
            decode_all(make, &bytes),
        );
        assert_eq!(
            decode_all(make, &bytes),
            (vec![Ok(Output::Reply(reply.clone()))], None)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Inputs::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
                assert_eq!(s.held(), 0);
            }
        ),
        decode_all(Inputs::new, data),
    );
    let raw = || {
        let mut commands = Inputs::new();
        commands.expect_line().unwrap();
        commands
    };
    let bound = 2 * (MAX_AUTH_LINE + 2);
    assert_eq!(
        decode_chunks(&mut Stream::new(raw()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(raw, data),
    );
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
    assert_eq!(
        decode_chunks(&mut Stream::new(auth()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
            assert!(s.held() <= MAX_REPLY_HELD);
        }),
        decode_all(auth, data),
    );
    for multi in [false, true] {
        let make = || {
            let mut replies = Outputs::new();
            for _ in 0..4 {
                replies.expect(multi).unwrap();
            }
            replies
        };
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
                assert!(s.held() <= MAX_REPLY_HELD);
            }),
            decode_all(make, data),
        );
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
                    if let Ok(value) = <ScanListing as Wire>::parse(line) {
                        let _ = assert_write(&value);
                    }
                    if let Ok(value) = <UniqueIdListing as Wire>::parse(line) {
                        let _ = assert_write(&value);
                    }
                }
            }
        }
    }
    if let Ok(value) = <Command as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Reply as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ScanListing as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <UniqueIdListing as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for item in decode_all(Inputs::new, data).0 {
        if let Ok(Input::Command(command)) = item {
            if let Ok(value) = <Command as Wire>::parse(&command.to_bytes().unwrap()) {
                let _ = assert_write(&value);
            }
            if let Ok(request) = Request::from_command(&command) {
                if let Ok(value) = <Request as Wire>::parse(&request.to_bytes().unwrap()) {
                    let _ = assert_write(&value);
                }
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
    let _ = assert_write(&command);
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
        let _ = assert_write(&request);
    }
    let _ = assert_write(&UniqueIdListing {
        message: std::num::NonZeroU32::MIN,
        id: sa.to_string(),
    });
});
