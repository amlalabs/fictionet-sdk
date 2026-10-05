//! SPNEGO tokens, as a world playing an HTTP, SMB or LDAP server reads
//! them from the agent and writes them back.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::spnego::{
    Decoder, Error, Frames, InitialContextToken, MAX_TOKEN, Mech, NegotiationToken, token_len,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<InitialContextToken>(data);
    contract::check_wire::<NegotiationToken>(data);
    contract::check_wire_value(&InitialContextToken {
        mech: Mech::Spnego,
        inner: data.get(..MAX_TOKEN + 1).unwrap_or(data).to_vec(),
    });

    // The stream, split two ways: all at once, as much as the decoder
    // takes, and a byte at a time. It never holds more than MAX_TOKEN.
    let mut whole = Decoder::new();
    let mut tokens = Vec::new();
    let mut rest = data;
    'whole: loop {
        let n = whole.feed(rest);
        rest = &rest[n..];
        assert!(whole.buffered() <= MAX_TOKEN);
        let mut took = false;
        loop {
            match whole.next_token() {
                Some(Ok(t)) => {
                    tokens.push(t);
                    took = true;
                }
                Some(Err(_)) => break 'whole,
                None => break,
            }
        }
        if rest.is_empty() || (n == 0 && !took) {
            // A full decoder always gives a token or an error.
            assert!(rest.is_empty());
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    'stream: for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        loop {
            match bytewise.next_token() {
                Some(Ok(t)) => again.push(t),
                Some(Err(_)) => break 'stream,
                None => break,
            }
        }
    }
    assert_eq!(tokens, again);

    // Each token, and the input on its own.
    for t in tokens.iter().map(Vec::as_slice).chain([data]) {
        // A token read can be written, and reads back the same. Only a
        // token near the size limit may grow past it when written, and a
        // hintAddress an agent sent is never written.
        if let Ok(token) = NegotiationToken::parse(t) {
            contract::check_wire_value(&token);
            let address = matches!(&token, NegotiationToken::Init(i)
                if i.neg_hints.as_ref().is_some_and(|h| h.hint_address.is_some()));
            match token.to_bytes() {
                Ok(bytes) => assert_eq!(NegotiationToken::parse(&bytes).as_ref(), Ok(&token)),
                Err(Error::HintAddress) => assert!(address),
                Err(e) => assert_eq!(e, Error::TooLong),
            }
            // Only a negTokenInit is wrapped.
            match token.to_gss_bytes() {
                Ok(bytes) => assert_eq!(NegotiationToken::parse(&bytes).as_ref(), Ok(&token)),
                Err(Error::HintAddress) => assert!(address),
                Err(e) => assert!(matches!(e, Error::TooLong | Error::WrappedResp)),
            }
        }
        if let Ok(wrapper) = InitialContextToken::parse(t) {
            let bytes = wrapper.to_bytes().unwrap();
            assert_eq!(InitialContextToken::parse(&bytes), Ok(wrapper));
        }
        if let Ok(Some(n)) = token_len(t) {
            assert!(n <= t.len());
        }
    }
});
