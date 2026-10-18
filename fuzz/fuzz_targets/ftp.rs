//! FTP control commands, replies, and address tokens.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract::{
    check_decode_with_alloc_limit, check_decode_with_held_limit, check_wire, check_wire_value,
};

use fictionet::stdlib::protocols::ftp::{
    Command, Commands, EprtAddress, Feature, MAX_LINE, MAX_REPLY_BYTES, PortAddress, Replies,
    Reply, ReplyCode, Request,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode_with_alloc_limit(Commands::new, data, 2 * MAX_LINE);
    check_decode_with_alloc_limit(Replies::new, data, 2 * MAX_LINE);
    check_decode_with_held_limit(Commands::new, data, MAX_LINE);
    check_decode_with_held_limit(Replies::new, data, MAX_REPLY_BYTES);
    check_wire::<Command>(data);
    check_wire::<Reply>(data);
    check_wire::<Request>(data);
    check_wire::<PortAddress>(data);
    check_wire::<EprtAddress>(data);

    for command in decode_all(Commands::new, data).0.iter().flatten() {
        check_wire_value(command);
        let bytes = command.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_LINE);
        assert_eq!(
            decode_all(Commands::new, &bytes),
            (vec![Ok(command.clone())], None)
        );
        if let Ok(request) = Request::from_command(command) {
            check_wire_value(&request);
            assert_eq!(Request::parse(&request.to_bytes().unwrap()), Ok(request));
        }
    }

    // Insert controls into independently specified application text, including
    // between the bytes of CR NUL LF and the final CRLF.
    let (plain, expected) = match data.first().copied().unwrap_or(0) % 3 {
        0 => (b"RETR ab\r\n".as_slice(), Command::new("RETR", Some("ab"))),
        1 => (
            b"STOR a\r\0\nb\r\n".as_slice(),
            Command::new("STOR", Some("a\r\nb")),
        ),
        _ => (b"NOOP\n".as_slice(), Command::new("NOOP", None)),
    };
    let at = usize::from(data.get(1).copied().unwrap_or(0)) % plain.len();
    let mut controlled = plain[..at].to_vec();
    controlled.extend_from_slice(b"\xff\xf4\xff\xfb");
    controlled.push(data.get(2).copied().unwrap_or(0));
    controlled.extend_from_slice(b"\xff\xfa*\r\n");
    for &byte in data.iter().take(128) {
        controlled.push(byte);
        if byte == 0xff {
            controlled.push(byte);
        }
    }
    controlled.extend_from_slice(b"\xff\xf0");
    controlled.extend_from_slice(&plain[at..]);
    assert_eq!(Command::parse(&controlled), Ok(expected.clone()));
    assert_eq!(
        check_decode_with_held_limit(Commands::new, &controlled, MAX_LINE),
        (vec![Ok(expected)], None)
    );

    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text.split_once(' ').unwrap_or((&text, ""));
    check_wire_value(&Command::new(verb, Some(arg)));
    for request in [
        Request::Dele(arg.into()),
        Request::Allo(arg.into()),
        Request::Rest(arg.into()),
        Request::Opts(arg.into()),
    ] {
        check_wire_value(&request);
    }
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let code = ReplyCode::new(100 + u16::from(data.first().copied().unwrap_or(0)) % 500);
    if let Some(code) = code {
        check_wire_value(&Reply {
            code,
            lines: lines.clone(),
        });
        if let Ok(reply) = Reply::from_lines(code, lines.clone()) {
            check_wire_value(&reply);
            assert_eq!(
                Reply::parse(&reply.to_bytes().unwrap()).as_ref(),
                Ok(&reply)
            );
        }
        let features: Vec<Feature> = lines
            .iter()
            .map(|line| {
                let (name, params) = line
                    .split_once(' ')
                    .map_or((line.as_str(), None), |(n, p)| (n, Some(p.into())));
                Feature {
                    name: name.into(),
                    params,
                }
            })
            .collect();
        if let Ok(reply) = Reply::feature_list(&features) {
            check_wire_value(&reply);
            assert_eq!(
                Reply::parse(&reply.to_bytes().unwrap()).unwrap().features(),
                Ok(features)
            );
        }
    }

    for reply in decode_all(Replies::new, data).0.iter().flatten() {
        check_wire_value(reply);
        assert_eq!(Reply::parse(&reply.to_bytes().unwrap()).as_ref(), Ok(reply));
        if let Ok(features) = reply.features()
            && let Ok(list) = Reply::feature_list(&features)
        {
            check_wire_value(&list);
            assert_eq!(list.features(), Ok(features));
        }
        if let Ok(address) = reply.passive_address() {
            check_wire_value(&PortAddress { address });
            let bytes = Reply::passive(address).to_bytes().unwrap();
            assert_eq!(Reply::parse(&bytes).unwrap().passive_address(), Ok(address));
        }
        if let Ok(port) = reply.extended_passive_port() {
            let bytes = Reply::extended_passive(port).to_bytes().unwrap();
            assert_eq!(
                Reply::parse(&bytes).unwrap().extended_passive_port(),
                Ok(port)
            );
        }
    }
});
