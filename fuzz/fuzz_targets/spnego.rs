//! SPNEGO tokens, as a world playing an HTTP, SMB or LDAP server reads
//! them from the agent and writes them back.
#![no_main]

use fictionet::stdlib::spnego::{Decoder, Error, InitialContextToken, NegotiationToken, token_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut tokens = Vec::new();
    while let Some(Ok(t)) = whole.next_token() {
        tokens.push(t);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    'stream: for b in data {
        bytewise.feed(std::slice::from_ref(b));
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
        // token near the size limit may grow past it when written.
        if let Ok(token) = NegotiationToken::parse(t) {
            match token.to_bytes() {
                Ok(bytes) => assert_eq!(NegotiationToken::parse(&bytes).as_ref(), Ok(&token)),
                Err(e) => assert_eq!(e, Error::TooLong),
            }
            // Only a negTokenInit is wrapped.
            match token.to_gss_bytes() {
                Ok(bytes) => assert_eq!(NegotiationToken::parse(&bytes).as_ref(), Ok(&token)),
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
