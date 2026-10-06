//! PostgreSQL startup, authentication, and typed messages.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::postgres::{
    Backend, BackendEvent, BackendMessages, EncryptionReply, Frontend, FrontendMessages, Password,
    SaslInitialResponse, Startup,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for make in [
        || FrontendMessages::with_limit(64),
        || FrontendMessages::established(64),
    ] {
        contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
        for message in decode_all(make, data).0.into_iter().flatten() {
            if let Frontend::Startup(startup) = &message {
                if startup.database().is_some() {
                    assert!(
                        startup.user().is_some()
                            || startup.get("database").is_some_and(|db| !db.is_empty())
                    );
                }
            }
            if let Frontend::AuthResponse(body) = &message {
                contract::check_wire::<Password>(body);
                contract::check_wire::<SaslInitialResponse>(body);
                if let Ok(sasl) = SaslInitialResponse::parse(body) {
                    contract::check_wire_value(&sasl.to_message().unwrap());
                }
            }
            let m = message;
            let b = m.to_bytes().unwrap();
            assert_eq!(Frontend::parse(&b), Ok(m));
            contract::check_wire::<Frontend>(&b);
        }
    }
    for make in [
        || BackendMessages::with_limit(64),
        || {
            let mut messages = BackendMessages::with_limit(64);
            messages.expect_encryption();
            messages
        },
    ] {
        contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
        for item in decode_all(make, data).0.into_iter().flatten() {
            if let BackendEvent::Message(m) = item {
                let b = m.to_bytes().unwrap();
                assert_eq!(Backend::parse(&b), Ok(m));
                contract::check_wire::<Backend>(&b);
            }
        }
    }
    contract::check_wire::<Frontend>(data);
    contract::check_wire::<Backend>(data);
    contract::check_wire::<EncryptionReply>(data);
    contract::check_wire::<Password>(data);
    contract::check_wire::<SaslInitialResponse>(data);
    let text = String::from_utf8_lossy(data.get(..4096).unwrap_or(data)).into_owned();
    contract::check_wire_value(&Frontend::Query(text.clone()));
    contract::check_wire_value(&Password(text.clone()));
    contract::check_wire_value(&Backend::CommandComplete(text.clone()));
    contract::check_wire_value(&SaslInitialResponse {
        mechanism: text,
        data: Some(data.get(..4096).unwrap_or(data).to_vec()),
    });
    contract::check_wire_value(&Frontend::CancelRequest {
        process_id: 7,
        secret_key: data.get(..257).unwrap_or(data).to_vec(),
    });
    let mut startup = Frontend::Startup(Startup::new("u", "d"))
        .to_bytes()
        .unwrap();
    startup.extend_from_slice(data);
    let make = || FrontendMessages::with_limit(64);
    contract::check_decode_with_alloc_limit(make, &startup, 2 * make().capacity());
    for m in decode_all(make, &startup).0.into_iter().flatten() {
        let b = m.to_bytes().unwrap();
        assert_eq!(Frontend::parse(&b), Ok(m));
        contract::check_wire::<Frontend>(&b);
    }
});
