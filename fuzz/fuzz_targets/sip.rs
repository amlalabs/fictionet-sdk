//! SIP messages and header values through codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::sip::{
    CSeq, Contacts, Error, Frames, MAX_BODY, MAX_HEAD, MAX_MESSAGE, Message, NameAddr, Param, Scheme, Uri, Via,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_MESSAGE);
    contract::check_decode_with_held_limit(Frames::new, data, 0);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Uri>(data);
    contract::check_wire::<NameAddr>(data);
    contract::check_wire::<Contacts>(data);
    contract::check_wire::<Via>(data);
    contract::check_wire::<CSeq>(data);
    let mut message = Message::response(200, "OK");
    message.body = data.get(..MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("l", &message.body.len().to_string());
    contract::check_wire_value(&message);
    if let Ok(bytes) = message.to_bytes() {
        contract::check_wire::<Message>(&bytes);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE);
    }

    let (messages, _) = decode_all(Frames::new, data);
    for message in messages.iter().flatten() {
        round_trip(message);
    }
    if let Ok(mut message) = Message::read_datagram(data) {
        // The read-only UDP path preserves a missing length. Add it for Wire.
        if message.content_length().unwrap().is_none() {
            message.push_header("Content-Length", &message.body.len().to_string());
        }
        round_trip(&message);
    }
    if data.len() <= MAX_HEAD + 1
        && let Ok(text) = core::str::from_utf8(data)
    {
        // Accessors reach the text readers before any writer validation.
        let mut message = Message::request("OPTIONS", "sip:a@b");
        for name in ["Via", "From", "Contact", "CSeq"] {
            message.push_header(name, text);
        }
        if let Ok(values) = message.vias() {
            for value in values {
                text_value(Ok(value));
            }
        }
        text_value(NameAddr::new(text).sip_uri());
        text_value(message.from());
        text_value(message.contacts());
        if let Ok(value) = message.cseq() {
            cseq_round_trip(&value);
        }
    }
    writers(data);
});

// Exercise constructed values, including ones the parser cannot produce.
fn writers(data: &[u8]) {
    let bounded = data.get(..MAX_HEAD + 1).unwrap_or(data);
    let parts: Vec<String> =
        bounded.split(|&b| b == 0xff).take(12).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    let part = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let opt = |i: usize| parts.get(i).cloned();
    let params = |from: usize| -> Vec<Param> {
        (from..parts.len().min(from + 6))
            .step_by(2)
            .map(|i| Param { name: part(i), value: opt(i + 1) })
            .collect()
    };
    let scheme = if data.first().is_some_and(|b| b & 1 == 1) { Scheme::Sips } else { Scheme::Sip };
    let mut uri = Uri::new(scheme, &part(0));
    uri.user = opt(1);
    uri.password = opt(2);
    uri.params = params(3);
    contract::check_wire_value(&uri);
    let address = NameAddr { display: opt(0), uri: part(1), params: params(2) };
    contract::check_wire_value(&address);
    contract::check_wire_value(&Contacts::List(vec![address]));
    contract::check_wire_value(&Via { transport: part(0), host: part(1), port: None, params: params(2) });
    let seq = bounded.iter().fold(0u32, |n, &b| n.rotate_left(8) ^ u32::from(b));
    contract::check_wire_value(&CSeq { seq, method: part(0) });
    let mut message = if data.first().is_some_and(|b| b & 2 == 2) {
        Message::request(&part(0), &part(1))
    } else {
        Message::response(u16::from(data.first().copied().unwrap_or(0)) * 3, &part(1))
    };
    for i in (2..parts.len()).step_by(2) {
        message.push_header(&part(i), &part(i + 1));
    }
    message.body = parts.last().map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    contract::check_wire_value(&message);
    message.set_header("Content-Length", &message.body.len().to_string());
    contract::check_wire_value(&message);
}

fn round_trip(message: &Message) {
    contract::check_wire_value(message);
    if let Err(error) = message.to_bytes() {
        assert!(matches!(error, Error::TooLong | Error::TooMany), "{error:?} for {message:?}");
        return;
    }
    if let Ok(vias) = message.vias() {
        for value in vias {
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
        }
    }
    for read in [Message::from, Message::to] {
        if let Ok(value) = read(message) {
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
        }
    }
    if let Ok(value) = message.cseq() {
        cseq_round_trip(&value);
    }
    if let Ok(value) = message.contacts() {
        contract::check_wire_value(&value);
        if let Err(error) = value.to_bytes() {
            assert_eq!(value, Contacts::List(vec![]), "{error:?}");
        }
    }
    if let Some(uri) = message.request_uri()
        && let Ok(value) = NameAddr::new(uri).sip_uri()
    {
        contract::check_wire_value(&value);
        value.to_bytes().unwrap();
        for param in &value.params {
            assert!(value.param(&param.name).is_some());
        }
    }
    if message.method().is_some() {
        let mut reply = message.reply(100, "Trying");
        reply.set_header("Content-Length", "0");
        contract::check_wire_value(&reply);
        assert!(matches!(reply.to_bytes(), Ok(_) | Err(Error::TooLong | Error::TooMany)));
    }
}

fn cseq_round_trip(value: &CSeq) {
    contract::check_wire_value(value);
    if let Err(error) = value.to_bytes() {
        assert!(value.seq >= 1 << 31, "{error:?} for {value:?}");
    }
}

fn text_value<T: Wire<ParseError = Error, WriteError = Error> + PartialEq + core::fmt::Debug>(value: Result<T, Error>) {
    if let Ok(value) = value {
        contract::check_wire_value(&value);
        assert!(matches!(value.to_bytes(), Ok(_) | Err(Error::TooLong)), "{value:?}");
    }
}
