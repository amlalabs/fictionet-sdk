//! FTP control commands, replies, and address tokens.
#![no_main]

use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode_with_alloc_limit, check_decode_with_held_limit, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::ftp::{
    Command, Commands, EprtAddress, Feature, MAX_LINE, MAX_REPLY_BYTES, PortAddress,
    Replies, Reply, ReplyCode, Request,
};
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
        assert_eq!(decode_all(Commands::new, &bytes), (vec![Ok(command.clone())], None));
        if let Ok(request) = Request::from_command(command) {
            check_wire_value(&request);
            assert_eq!(Request::parse(&request.to_bytes().unwrap()), Ok(request));
        }
    }

    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text.split_once(' ').unwrap_or((&text, ""));
    check_wire_value(&Command::new(verb, Some(arg)));
    for request in [
        Request::Dele(arg.into()), Request::Allo(arg.into()),
        Request::Rest(arg.into()), Request::Opts(arg.into()),
    ] {
        check_wire_value(&request);
    }
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let code = ReplyCode::new(100 + u16::from(data.first().copied().unwrap_or(0)) % 500);
    if let Some(code) = code {
        check_wire_value(&Reply { code, lines: lines.clone() });
        if let Ok(reply) = Reply::from_lines(code, lines.clone()) {
            check_wire_value(&reply);
            assert_eq!(Reply::parse(&reply.to_bytes().unwrap()).as_ref(), Ok(&reply));
        }
        let features: Vec<Feature> = lines.iter().map(|line| {
            let (name, params) = line.split_once(' ').map_or((line.as_str(), None), |(n, p)| (n, Some(p.into())));
            Feature { name: name.into(), params }
        }).collect();
        if let Ok(reply) = Reply::feature_list(&features) {
            check_wire_value(&reply);
            assert_eq!(Reply::parse(&reply.to_bytes().unwrap()).unwrap().features(), Ok(features));
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
            assert_eq!(Reply::parse(&bytes).unwrap().extended_passive_port(), Ok(port));
        }
    }
});
