//! NTLMSSP messages, AV pair lists and responses, as a world playing a
//! server reads them, and values a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::ntlmssp::{
    Authenticate, AvPair, Challenge, ClientChallenge, LmV2Response, MAX_AV_PAIRS, MAX_MESSAGE, MIC_END, MIC_LEN,
    Message, Negotiate, NtResponse, NtlmV2Response, Version, flags,
};
use libfuzzer_sys::fuzz_target;

/// Any bytes read as each kind of thing this module reads. Whatever reads
/// is written back, and reads back the same.
fn read(b: &[u8]) {
    if let Ok(m) = Message::parse(b) {
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_MESSAGE);
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        if let Message::Challenge(c) = &m {
            pairs(&c.target_info);
        }
        if let Message::Authenticate(a) = &m {
            response(&a.nt_response);
            // A message with a MIC can have it zeroed, and nothing else changes.
            if let Some(z) = Authenticate::zero_mic(b) {
                assert!(a.mic.is_some());
                assert_eq!(z.len(), b.len());
                assert_eq!(z[..MIC_END - MIC_LEN], b[..MIC_END - MIC_LEN]);
                assert_eq!(z[MIC_END..], b[MIC_END..]);
            } else {
                assert!(a.mic.is_none());
            }
        }
    }
    pairs(b);
    response(b);
    if let Ok(r) = LmV2Response::parse(b) {
        assert_eq!(r.to_bytes(), b);
    }
}

/// An AV pair list read, written and read again.
fn pairs(b: &[u8]) {
    if let Ok((list, used)) = AvPair::parse_list(b) {
        assert!(used <= b.len());
        assert!(list.len() <= MAX_AV_PAIRS);
        let bytes = AvPair::write_list(&list).unwrap();
        assert_eq!(AvPair::parse_list(&bytes), Ok((list, bytes.len())));
    }
}

/// An NT response read, written and read again.
fn response(b: &[u8]) {
    if let Ok(nt) = NtResponse::parse(b) {
        let bytes = nt.to_bytes().unwrap();
        assert_eq!(NtResponse::parse(&bytes), Ok(nt));
    }
}

/// A version built from fuzz bytes.
fn version(u: &mut Unstructured) -> Result<Option<Version>> {
    Ok(if u.arbitrary()? {
        Some(Version { major: u.arbitrary()?, minor: u.arbitrary()?, build: u.arbitrary()?, revision: u.arbitrary()? })
    } else {
        None
    })
}

/// Bytes of up to `max` from fuzz bytes.
fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

/// AV pairs built from fuzz bytes, valid or not.
fn av_pairs(u: &mut Unstructured) -> Result<Vec<AvPair>> {
    let n = u.int_in_range(0..=8usize)?;
    (0..n).map(|_| Ok(AvPair { id: u.arbitrary()?, value: bytes(u, 300)? })).collect()
}

/// A message built from fuzz bytes, valid or not.
fn message(u: &mut Unstructured) -> Result<Message> {
    let flags: u32 = u.arbitrary()?;
    let version = version(u)?;
    Ok(match u.int_in_range(0..=2u8)? {
        0 => Message::Negotiate(Negotiate { flags, domain: bytes(u, 300)?, workstation: bytes(u, 300)?, version }),
        1 => Message::Challenge(Challenge {
            flags,
            target_name: bytes(u, 300)?,
            server_challenge: u.arbitrary()?,
            target_info: bytes(u, 300)?,
            version,
        }),
        _ => Message::Authenticate(Authenticate {
            flags,
            lm_response: bytes(u, 300)?,
            nt_response: bytes(u, 300)?,
            domain: bytes(u, 300)?,
            user: bytes(u, 300)?,
            workstation: bytes(u, 300)?,
            session_key: bytes(u, 300)?,
            version,
            mic: if u.arbitrary()? { Some(u.arbitrary()?) } else { None },
        }),
    })
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let m = message(&mut u)?;
    if let Ok(bytes) = m.to_bytes() {
        assert!(bytes.len() <= MAX_MESSAGE);
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        // A message with a version always has the flag that says so.
        let with_version = match &m {
            Message::Negotiate(n) => n.version.is_some(),
            Message::Challenge(c) => c.version.is_some(),
            Message::Authenticate(a) => a.version.is_some(),
        };
        assert_eq!(with_version, m.flags() & flags::NEGOTIATE_VERSION != 0);
    }
    let list = av_pairs(&mut u)?;
    if let Ok(bytes) = AvPair::write_list(&list) {
        assert_eq!(AvPair::parse_list(&bytes), Ok((list.clone(), bytes.len())));
    }
    let nt = match u.int_in_range(0..=2u8)? {
        0 => NtResponse::Empty,
        1 => NtResponse::V1(u.arbitrary()?),
        _ => NtResponse::V2(NtlmV2Response {
            nt_proof: u.arbitrary()?,
            client: ClientChallenge {
                resp_type: u.arbitrary()?,
                hi_resp_type: u.arbitrary()?,
                timestamp: u.arbitrary()?,
                challenge: u.arbitrary()?,
                av_pairs: list,
                trailing: bytes(&mut u, 16)?,
            },
        }),
    };
    if let Ok(bytes) = nt.to_bytes() {
        assert_eq!(NtResponse::parse(&bytes), Ok(nt));
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    read(data);
    // Every prefix of a message that reads is read too, as a world sees a
    // token cut short.
    if Message::parse(data).is_ok() {
        for n in 0..data.len().min(256) {
            read(&data[..n]);
        }
    }
    let _ = built(data);
});
