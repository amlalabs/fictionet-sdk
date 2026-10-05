//! OCSP requests and responses, as a world playing a responder reads
//! them, and the GET path a request comes in. Also values built from the
//! bytes, as a world playing a client or responder writes them.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::ocsp::{
    AlgorithmIdentifier, BasicResponse, CertId, CertStatus, CrlReason, Decoder, Extension, Frames, MAX_MESSAGE,
    MAX_NONCE, OcspRequest, OcspResponse, Request, ResponderId, ResponseBytes, ResponseData, ResponseStatus,
    SingleResponse, decode_get_path, find_nonce,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` to `d` in pieces of at most `step` bytes, taking messages
/// out as they come, and checks the decoder never holds more than a
/// message.
fn split(data: &[u8], step: usize) -> Vec<Vec<u8>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let n = d.feed(&rest[..rest.len().min(step)]);
        rest = &rest[n..];
        assert!(d.buffered() <= MAX_MESSAGE);
        let mut broken = false;
        while let Some(m) = d.next_message() {
            match m {
                Ok(m) => out.push(m),
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        if broken || rest.is_empty() {
            return out;
        }
        assert!(n > 0 || d.buffered() < MAX_MESSAGE, "the decoder stalled");
    }
}

/// Takes the next `n` bytes, or what is left.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (a, b) = data.split_at(n.min(data.len()));
    *data = b;
    a
}

fn byte(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

/// Takes a byte `n`, then the next `n % modulus` bytes.
fn some(data: &mut &[u8], modulus: u16) -> Vec<u8> {
    let n = u16::from(byte(data)) % modulus;
    take(data, usize::from(n)).to_vec()
}

/// Builds a request and a response from the bytes, writes them, and checks
/// that what writes reads back the same.
fn written(mut data: &[u8]) {
    let d = &mut data;
    let hash = match byte(d) % 3 {
        0 => AlgorithmIdentifier::sha1(),
        1 => AlgorithmIdentifier::sha256(),
        _ => AlgorithmIdentifier { algorithm: "1.2.3.4".parse().unwrap(), parameters: None },
    };
    let n = usize::from(byte(d) % 40);
    let cert_id = CertId {
        hash_algorithm: hash,
        issuer_name_hash: take(d, n).to_vec(),
        issuer_key_hash: take(d, n).to_vec(),
        serial_number: some(d, 4),
    };
    let requests = (0..byte(d) % 3).map(|_| Request { cert_id: cert_id.clone(), extensions: vec![] }).collect();
    let mut req = OcspRequest::new(requests);
    let name = some(d, 12);
    if !name.is_empty() {
        req.requestor_name = Some(name);
    }
    let nonce = some(d, 256);
    match Extension::nonce(&nonce) {
        Ok(ext) => {
            assert!((1..=MAX_NONCE).contains(&nonce.len()));
            assert_eq!(find_nonce(std::slice::from_ref(&ext)), Some(&nonce[..]));
            req.extensions.push(ext);
        }
        Err(_) => assert!(nonce.is_empty() || nonce.len() > MAX_NONCE),
    }
    contract::check_wire_value(&req);
    if let Ok(der) = req.to_der() {
        assert_eq!(OcspRequest::parse(&der).unwrap(), req);
        // Unsigned, the request is a SEQUENCE header and the TBSRequest.
        let tbs = req.tbs_der().unwrap();
        assert!(der.ends_with(&tbs) && der.len() - tbs.len() <= 4);
    }

    let status = match byte(d) % 3 {
        0 => CertStatus::Good,
        1 => CertStatus::Unknown,
        c => CertStatus::Revoked { time: "20260101000000Z".to_string(), reason: CrlReason::from_code(i64::from(c)) },
    };
    let data = ResponseData {
        version: 0,
        responder_id: ResponderId::ByKey(some(d, 24)),
        produced_at: "20261005120000Z".to_string(),
        responses: vec![SingleResponse {
            cert_id,
            status,
            this_update: "20261005120000Z".to_string(),
            next_update: None,
            extensions: vec![],
        }],
        extensions: vec![],
    };
    let basic = BasicResponse {
        data,
        signature_algorithm: AlgorithmIdentifier::sha1(),
        signature: take(d, 8).to_vec(),
        certs: vec![],
    };
    let code = i64::from(byte(d) % 8);
    let bytes = match byte(d) % 3 {
        0 => None,
        1 => Some(ResponseBytes::Basic(basic)),
        _ => Some(ResponseBytes::Other { response_type: "1.2.3.4".parse().unwrap(), response: d.to_vec() }),
    };
    if let Some(status) = ResponseStatus::from_code(code) {
        let resp = OcspResponse { status, bytes };
        contract::check_wire_value(&resp);
        if let Ok(der) = resp.to_der() {
            assert_eq!(OcspResponse::parse(&der).unwrap(), resp);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<OcspRequest>(data);
    contract::check_wire::<OcspResponse>(data);
    contract::check_wire::<BasicResponse>(data);

    // The body, split two ways: all at once, and a byte at a time.
    let messages = split(data, usize::MAX);
    assert_eq!(messages, split(data, 1));

    // Any bytes as each message on its own. What reads can be written,
    // and reads back the same.
    for m in messages.iter().map(Vec::as_slice).chain([data]) {
        if let Ok(req) = OcspRequest::parse(m) {
            let der = req.to_der().unwrap();
            assert_eq!(OcspRequest::parse(&der).unwrap(), req);
            let path = req.to_get_path().unwrap();
            assert_eq!(OcspRequest::from_get_path(&path).unwrap(), req);
            if let Some(nonce) = req.nonce() {
                assert!((1..=MAX_NONCE).contains(&nonce.len()));
            }
        }
        if let Ok(resp) = OcspResponse::parse(m) {
            let der = resp.to_der().unwrap();
            assert_eq!(OcspResponse::parse(&der).unwrap(), resp);
        }
        if let Ok(basic) = BasicResponse::parse(m) {
            let der = basic.to_der().unwrap();
            assert_eq!(BasicResponse::parse(&der).unwrap(), basic);
        }
    }
    // Any text as a GET path.
    if let Ok(der) = decode_get_path(&String::from_utf8_lossy(data)) {
        let _ = OcspRequest::parse(&der);
    }
    written(data);
});
