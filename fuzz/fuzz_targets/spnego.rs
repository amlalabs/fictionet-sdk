//! SPNEGO tokens, as a world playing an HTTP, SMB or LDAP server reads
//! them from the agent and writes them back.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire, contract, finish, pump};
use fictionet::stdlib::spnego::{
    Frames, InitialContextToken, MAX_TOKEN, Mech, NegotiationToken, token_len,
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

    let mut stream = Stream::new(Frames::new());
    let mut tokens = Vec::new();
    let _ = pump(&mut stream, data, |token| tokens.push(token));
    let _ = finish(&mut stream, |token| tokens.push(token));

    // Each token, and the input on its own.
    for t in tokens.iter().map(Vec::as_slice).chain([data]) {
        contract::check_wire::<NegotiationToken>(t);
        contract::check_wire::<InitialContextToken>(t);
        if let Ok(token @ NegotiationToken::Init(_)) = NegotiationToken::parse(t) {
            let wrapper = InitialContextToken {
                mech: Mech::Spnego,
                inner: token.to_bytes().unwrap(),
            };
            contract::check_wire_value(&wrapper);
            if let Ok(bytes) = wrapper.to_bytes() {
                assert_eq!(NegotiationToken::parse(&bytes), Ok(token));
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
