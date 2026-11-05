//! SPNEGO tokens, as a world playing an HTTP, SMB or LDAP server reads
//! them from the agent and writes them back.
#![no_main]

use fictionet::stdlib::codec::{Frames, Stream, Wire, finish, pump};
use fictionet::stdlib::protocols::spnego::{
    Error, Frame, InitialContextToken, MAX_TOKEN, Mech, NegotiationToken, token_len,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    if let Ok(value) = <InitialContextToken as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <NegotiationToken as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&InitialContextToken {
        mech: Mech::Spnego,
        inner: data.get(..MAX_TOKEN + 1).unwrap_or(data).to_vec(),
    });

    let mut stream = Stream::new(Frames::<Frame>::new());
    let mut tokens = Vec::new();
    let _ = pump(&mut stream, data, |token| tokens.push(token));
    let _ = finish(&mut stream, |token| tokens.push(token));

    // Each token, and the input on its own.
    for t in tokens.iter().map(Vec::as_slice).chain([data]) {
        if let Ok(value) = <NegotiationToken as Wire>::parse(t) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <InitialContextToken as Wire>::parse(t) {
            let _ = assert_write(&value);
        }
        if let Ok(token) = NegotiationToken::parse(t) {
            let wrapped = InitialContextToken::spnego(&token);
            match token {
                NegotiationToken::Resp(_) => assert_eq!(wrapped, Err(Error::WrappedResp)),
                NegotiationToken::Init(_) => match wrapped {
                    Ok(wrapper) => {
                        let _ = assert_write(&wrapper);
                        let bytes = wrapper.to_bytes().unwrap();
                        assert_eq!(NegotiationToken::parse(&bytes), Ok(token));
                    }
                    Err(e) => assert_eq!(e, Error::TooLong),
                },
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
