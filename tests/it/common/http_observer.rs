use std::sync::Mutex;

use fictionet::events::{ConnInfo, Event, Fields};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::httpd::{Observer, Received};

pub const SECRET: &[u8] = b"private-credential!!";

pub fn assert_redacted(event: &Event) {
    let json = event.to_json().to_bytes().unwrap();
    assert!(!json.windows(SECRET.len()).any(|w| w == SECRET));
}

#[derive(Clone, Default)]
struct Receipt {
    path: String,
    bytes: usize,
    classified: bool,
}

#[derive(Default)]
pub struct Exposure {
    pub heads: Mutex<Vec<(http::request::Parts, ConnInfo)>>,
    pub ends: Mutex<Vec<(String, usize, Received)>>,
}

impl Observer for Exposure {
    fn head(
        &self,
        head: &http::request::Parts,
        conn: &ConnInfo,
        state: &mut http::Extensions,
    ) -> Option<Fields> {
        self.heads
            .lock()
            .unwrap()
            .push((head.clone(), conn.clone()));
        state.insert(Receipt {
            path: head.uri.path().to_owned(),
            ..Receipt::default()
        });
        Some(
            Fields::new()
                .with("source", "observer")
                .with("method", "wrong")
                .with("answer", "wrong")
                .with("received", "wrong"),
        )
    }

    fn body(&self, bytes: &[u8], state: &mut http::Extensions) -> Option<Fields> {
        let receipt = state.get_mut::<Receipt>().unwrap();
        receipt.bytes += bytes.len();
        receipt.classified |= bytes.contains(&b'!');
        None
    }

    fn end(&self, received: Received, state: &mut http::Extensions) -> Option<Fields> {
        let receipt = state.remove::<Receipt>().unwrap();
        self.ends
            .lock()
            .unwrap()
            .push((receipt.path, receipt.bytes, received));
        Some(
            Fields::new()
                .with("classified", receipt.classified)
                .with("observed_bytes", receipt.bytes as u64),
        )
    }
}
