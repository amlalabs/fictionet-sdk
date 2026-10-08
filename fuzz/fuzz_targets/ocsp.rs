//! OCSP requests and responses, as a world playing a responder reads
//! them, and the GET path a request comes in. Also values built from the
//! bytes, as a world playing a client or responder writes them.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
use fictionet::stdlib::ocsp::{
    AlgorithmIdentifier, BasicResponse, CertId, CertStatus, CrlReason, Extension, Frames,
    MAX_NONCE, Request, ResponderId, Response, ResponseBytes, ResponseData, ResponseStatus,
    SingleRequest, SingleResponse, decode_get_path, encode_get_path, find_nonce,
};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

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
        _ => AlgorithmIdentifier {
            algorithm: "1.2.3.4".parse().unwrap(),
            parameters: None,
        },
    };
    let n = usize::from(byte(d) % 40);
    let cert_id = CertId {
        hash_algorithm: hash,
        issuer_name_hash: take(d, n).to_vec(),
        issuer_key_hash: take(d, n).to_vec(),
        serial_number: some(d, 4),
    };
    let requests = (0..byte(d) % 3)
        .map(|_| SingleRequest {
            cert_id: cert_id.clone(),
            extensions: vec![],
        })
        .collect();
    let mut req = Request::new(requests);
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
    if let Ok(der) = req.to_bytes() {
        assert_eq!(Request::parse(&der).unwrap(), req);
        // Unsigned, the request is a SEQUENCE header and the TBSRequest.
        let tbs = Request::tbs_request(&der).unwrap();
        assert!(der.ends_with(&tbs) && der.len() - tbs.len() <= 4);
    }

    let status = match byte(d) % 3 {
        0 => CertStatus::Good,
        1 => CertStatus::Unknown,
        c => CertStatus::Revoked {
            time: "20260101000000Z".to_string(),
            reason: CrlReason::from_code(i64::from(c)),
        },
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
        _ => Some(ResponseBytes::Other {
            response_type: "1.2.3.4".parse().unwrap(),
            response: d.to_vec(),
        }),
    };
    if let Some(status) = ResponseStatus::from_code(code) {
        let resp = Response { status, bytes };
        contract::check_wire_value(&resp);
        if let Ok(der) = resp.to_bytes() {
            assert_eq!(Response::parse(&der).unwrap(), resp);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<BasicResponse>(data);

    let mut stream = Stream::new(Frames::new());
    let mut messages = Vec::new();
    let _ = pump(&mut stream, data, |m| messages.push(m));
    let _ = finish(&mut stream, |m| messages.push(m));
    contract::check_wire::<ResponseData>(data);

    // Any bytes as each message on its own. What reads can be written,
    // and reads back the same.
    for m in messages.iter().map(Vec::as_slice).chain([data]) {
        if let Ok(req) = Request::parse(m) {
            let der = req.to_bytes().unwrap();
            assert_eq!(Request::parse(&der).unwrap(), req);
            let path = encode_get_path(&req.to_bytes().unwrap()).unwrap();
            assert_eq!(Request::from_get_path(&path).unwrap(), req);
            if let Some(nonce) = req.nonce() {
                assert!((1..=MAX_NONCE).contains(&nonce.len()));
            }
        }
        if let Ok(resp) = Response::parse(m) {
            let der = resp.to_bytes().unwrap();
            assert_eq!(Response::parse(&der).unwrap(), resp);
        }
        if let Ok(basic) = BasicResponse::parse(m) {
            let der = basic.to_bytes().unwrap();
            assert_eq!(BasicResponse::parse(&der).unwrap(), basic);
        }
    }
    // Any text as a GET path.
    if let Ok(der) = decode_get_path(&String::from_utf8_lossy(data)) {
        let _ = Request::parse(&der);
    }
    written(data);
});
