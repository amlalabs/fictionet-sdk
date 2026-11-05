//! PostgreSQL startup, authentication, and typed messages.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::postgres::{
    BackendEvent, BackendEvents, BackendMessage, EncryptionReply, FrontendMessage,
    FrontendMessages, Password, SMALL_MESSAGE, SaslInitialResponse, Startup,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for make in [
        || FrontendMessages::with_limit(64),
        || FrontendMessages::established(64),
        || FrontendMessages::established(SMALL_MESSAGE),
    ] {
        let bound = 2 * make().capacity();
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= bound);
            }),
            decode_all(make, data),
        );
        for message in decode_all(make, data).0.into_iter().flatten() {
            if let FrontendMessage::Startup(startup) = &message {
                if startup.database().is_some() {
                    assert!(
                        startup.user().is_some()
                            || startup.get("database").is_some_and(|db| !db.is_empty())
                    );
                }
            }
            if let FrontendMessage::AuthResponse(body) = &message {
                if let Ok(value) = <Password as Wire>::parse(body) {
                    let _ = assert_write(&value);
                }
                if let Ok(value) = <SaslInitialResponse as Wire>::parse(body) {
                    let _ = assert_write(&value);
                }
                if let Ok(sasl) = SaslInitialResponse::parse(body) {
                    let _ = assert_write(&sasl.to_message().unwrap());
                }
            }
            let m = message;
            let b = m.to_bytes().unwrap();
            assert_eq!(FrontendMessage::parse(&b), Ok(m));
            if let Ok(value) = <FrontendMessage as Wire>::parse(&b) {
                let _ = assert_write(&value);
            }
        }
    }
    for make in [
        || BackendEvents::with_limit(64),
        || {
            let mut messages = BackendEvents::with_limit(64);
            messages.expect_encryption();
            messages
        },
        || BackendEvents::with_limit(SMALL_MESSAGE),
        || {
            let mut messages = BackendEvents::with_limit(SMALL_MESSAGE);
            messages.expect_encryption();
            messages
        },
    ] {
        let bound = 2 * make().capacity();
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= bound);
            }),
            decode_all(make, data),
        );
        for item in decode_all(make, data).0.into_iter().flatten() {
            if let BackendEvent::Message(m) = item {
                let b = m.to_bytes().unwrap();
                assert_eq!(BackendMessage::parse(&b), Ok(m));
                if let Ok(value) = <BackendMessage as Wire>::parse(&b) {
                    let _ = assert_write(&value);
                }
            }
        }
    }
    if let Ok(value) = <FrontendMessage as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <BackendMessage as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <EncryptionReply as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Password as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <SaslInitialResponse as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let text = String::from_utf8_lossy(data.get(..4096).unwrap_or(data)).into_owned();
    let _ = assert_write(&FrontendMessage::Query(text.clone()));
    let _ = assert_write(&Password(text.clone()));
    let _ = assert_write(&BackendMessage::CommandComplete(text.clone()));
    let _ = assert_write(&SaslInitialResponse {
        mechanism: text,
        data: Some(data.get(..4096).unwrap_or(data).to_vec()),
    });
    let _ = assert_write(&FrontendMessage::CancelRequest {
        process_id: 7,
        secret_key: data.get(..257).unwrap_or(data).to_vec(),
    });
    let mut startup = FrontendMessage::Startup(Startup::new("u", "d"))
        .to_bytes()
        .unwrap();
    startup.extend_from_slice(data);
    for make in [
        || FrontendMessages::with_limit(64),
        || FrontendMessages::with_limit(SMALL_MESSAGE),
    ] {
        let bound = 2 * make().capacity();
        assert_eq!(
            decode_chunks(
                &mut Stream::new(make()),
                chunks(&startup, &[1, 7, 64]),
                |s| {
                    assert!(s.allocated() <= bound);
                }
            ),
            decode_all(make, &startup),
        );
        for m in decode_all(make, &startup).0.into_iter().flatten() {
            let b = m.to_bytes().unwrap();
            assert_eq!(FrontendMessage::parse(&b), Ok(m));
            if let Ok(value) = <FrontendMessage as Wire>::parse(&b) {
                let _ = assert_write(&value);
            }
        }
    }
});
