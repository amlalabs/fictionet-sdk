//! DCE/RPC connection-oriented PDUs, as a world playing an RPC server
//! reads them, and values a world builds, as it writes them.
#![no_main]

#[path = "../common/input.rs"]
mod input;
use input::{bytes, list};

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::protocols::dcerpc::harness::rewrite;
use fictionet::stdlib::protocols::dcerpc::{
    Auth, Bind, BindAck, BindNak, Body, Context, ContextResult, DataRep, Error, MAX_FRAG,
    MAX_FRAGMENTS, MAX_STUB, Pdu, Reassembler, SyntaxId, Uuid, flags,
};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fn syntax(u: &mut Unstructured) -> Result<SyntaxId> {
    Ok(SyntaxId {
        uuid: Uuid(u.arbitrary()?),
        major: u.arbitrary()?,
        minor: u.arbitrary()?,
    })
}

fn bind(u: &mut Unstructured) -> Result<Bind> {
    Ok(Bind {
        max_xmit_frag: u.arbitrary()?,
        max_recv_frag: u.arbitrary()?,
        assoc_group: u.arbitrary()?,
        contexts: list(u, 260, |u| {
            Ok(Context {
                id: u.arbitrary()?,
                abstract_syntax: syntax(u)?,
                transfer_syntaxes: list(u, 260, syntax)?,
            })
        })?,
    })
}

fn bind_ack(u: &mut Unstructured) -> Result<BindAck> {
    Ok(BindAck {
        max_xmit_frag: u.arbitrary()?,
        max_recv_frag: u.arbitrary()?,
        assoc_group: u.arbitrary()?,
        secondary_address: bytes(u, 300)?,
        results: list(u, 260, |u| {
            Ok(ContextResult {
                result: u.arbitrary()?,
                reason: u.arbitrary()?,
                transfer_syntax: syntax(u)?,
            })
        })?,
    })
}

/// A PDU built from fuzz bytes, valid or not.
fn pdu(u: &mut Unstructured) -> Result<Pdu> {
    let body = match u.int_in_range(0..=11u8)? {
        0 => Body::Request {
            alloc_hint: u.arbitrary()?,
            context_id: u.arbitrary()?,
            opnum: u.arbitrary()?,
            object: if u.arbitrary()? {
                Some(Uuid(u.arbitrary()?))
            } else {
                None
            },
            stub: bytes(u, 70_000)?,
        },
        1 => Body::Response {
            alloc_hint: u.arbitrary()?,
            context_id: u.arbitrary()?,
            cancel_count: u.arbitrary()?,
            stub: bytes(u, 70_000)?,
        },
        2 => Body::Fault {
            alloc_hint: u.arbitrary()?,
            context_id: u.arbitrary()?,
            cancel_count: u.arbitrary()?,
            fault_flags: u.arbitrary()?,
            status: u.arbitrary()?,
            stub: bytes(u, 300)?,
        },
        3 => Body::Bind(bind(u)?),
        4 => Body::AlterContext(bind(u)?),
        5 => Body::BindAck(bind_ack(u)?),
        6 => Body::AlterContextResp(bind_ack(u)?),
        7 => Body::BindNak(BindNak {
            reason: u.arbitrary()?,
            versions: list(u, 260, |u| u.arbitrary())?,
        }),
        8 => Body::Auth3,
        9 => Body::Shutdown,
        10 => Body::Cancel,
        _ => Body::Orphaned,
    };
    let auth = if u.arbitrary()? {
        Some(Auth {
            kind: u.arbitrary()?,
            level: u.arbitrary()?,
            context_id: u.arbitrary()?,
            value: bytes(u, 300)?,
        })
    } else {
        None
    };
    Ok(Pdu {
        version_minor: u.int_in_range(0..=2)?,
        flags: u.arbitrary()?,
        drep: DataRep(u.arbitrary()?),
        call_id: u.arbitrary()?,
        body,
        auth,
    })
}

fn alloc_hint(p: &Pdu) -> Option<u32> {
    match p.body {
        Body::Request { alloc_hint, .. } | Body::Response { alloc_hint, .. } => Some(alloc_hint),
        _ => None,
    }
}

/// Values a world builds: whatever a writer accepts reads back the same,
/// and whatever is split joins back into the same call, including calls
/// longer than one fragment.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let p = pdu(&mut u)?;
    contract::check_wire_value(&p);
    if let Ok(bytes) = p.to_bytes() {
        assert!(bytes.len() <= MAX_FRAG);
        assert_eq!(Pdu::parse(&bytes), Ok(p.clone()));
    }
    let max: u16 = u.arbitrary()?;
    let call = matches!(p.body, Body::Request { .. } | Body::Response { .. });
    let Ok(parts) = p.fragments(max) else {
        return Ok(());
    };
    assert!(parts.len() <= MAX_FRAGMENTS);
    let mut r = Reassembler::default();
    let mut got = None;
    let mut sent = 0usize;
    for f in &parts {
        // Every fragment writes, within the size asked for.
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= usize::from(max));
        assert_eq!(Pdu::parse(&bytes), Ok(f.clone()));
        // A nonzero hint counts down by the stub data already sent.
        if let (Some(whole), Some(hint)) = (alloc_hint(&p), alloc_hint(f)) {
            let left = if whole == 0 {
                0
            } else {
                whole.saturating_sub(u32::try_from(sent).unwrap_or(u32::MAX))
            };
            assert_eq!(hint, left);
        }
        sent += f.body.stub().map_or(0, <[u8]>::len);
        got = r.push(f.clone()).unwrap();
    }
    let mut want = p.clone();
    if call {
        want.flags |= flags::FIRST_FRAG | flags::LAST_FRAG;
    }
    assert_eq!(got, Some(want.clone()));
    if call && parts.len() > 1 {
        related(&mut u, parts, want)?;
    }
    Ok(())
}

/// The fragments of one call, each given a verifier and maybe a cancel:
/// they join only if every verifier and semantic representation agrees,
/// and the joined call keeps any cancel. Reserved representation bytes may vary.
fn related(u: &mut Unstructured, mut parts: Vec<Pdu>, mut want: Pdu) -> Result<()> {
    let recovery = parts.clone();
    let recovered = want.clone();
    let first: Option<(u8, u8, u32)> = u.arbitrary()?;
    let mut fail = None;
    for (i, f) in parts.iter_mut().enumerate() {
        let s = if i == 0 || u.ratio(3, 4)? {
            first
        } else {
            u.arbitrary()?
        };
        f.auth = s.map(|(kind, level, context_id)| Auth {
            kind,
            level,
            context_id,
            value: vec![1],
        });
        if i > 0 {
            match u.int_in_range(0..=5u8)? {
                0 => f.drep.0[0] ^= 0x10,
                1 => f.drep.0[0] ^= 1,
                2 => f.drep.0[1] ^= 1,
                3 => f.drep.0[2..].copy_from_slice(&u.arbitrary::<[u8; 2]>()?),
                _ => {}
            }
        }
        // The first two wire bytes carry integer, character and float formats.
        if i > 0 && (s != first || f.drep.0[..2] != want.drep.0[..2]) && fail.is_none() {
            fail = Some(i);
        }
        if u.ratio(1, 8)? {
            f.flags |= flags::PENDING_CANCEL;
            want.flags |= flags::PENDING_CANCEL;
        }
        if let Body::Response { cancel_count, .. } = &mut f.body
            && u.ratio(1, 8)?
        {
            *cancel_count = u.arbitrary()?;
        }
    }
    // A response's cancel count is the highest any fragment gave.
    if let Body::Response {
        cancel_count: w, ..
    } = &mut want.body
    {
        *w = parts
            .iter()
            .filter_map(|f| match f.body {
                Body::Response { cancel_count, .. } => Some(cancel_count),
                _ => None,
            })
            .fold(0, u8::max);
    }
    check_related(parts, want, fail, recovery, recovered);
    Ok(())
}

/// Checks related fragments against their expected outcome and valid-call recovery.
fn check_related(
    parts: Vec<Pdu>,
    want: Pdu,
    fail: Option<usize>,
    recovery: Vec<Pdu>,
    recovered: Pdu,
) {
    let mut r = Reassembler::default();
    let n = parts.len();
    for (i, f) in parts.into_iter().enumerate() {
        let got = r.push(f);
        match fail {
            Some(at) if i >= at => {
                assert_eq!(
                    got,
                    Err(Error::UnexpectedFragment {
                        call_id: want.call_id
                    })
                );
                assert_eq!(r.pending(), 0);
            }
            _ if i + 1 == n => assert_eq!(got, Ok(Some(want.clone()))),
            _ => assert_eq!(got, Ok(None)),
        }
        assert!(r.pending() <= MAX_STUB);
    }
    assert_eq!(r.pending(), 0);
    // A valid fragmented call with the same ID must recover after rejection.
    let n = recovery.len();
    for (i, f) in recovery.into_iter().enumerate() {
        let got = r.push(f).unwrap();
        if i + 1 == n {
            assert_eq!(got, Some(recovered.clone()));
        } else {
            assert_eq!(got, None);
        }
        assert!(r.pending() <= MAX_STUB);
    }
    assert_eq!(r.pending(), 0);
}

/// REP\0, request/response selector, two four-byte representations, then stub.
/// This mode reaches the representation oracle without generating a valid PDU
/// and fragmentation size through Unstructured first.
fn representations(data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    let body = |stub: Vec<u8>| {
        if data[0] & 1 == 0 {
            Body::Request {
                alloc_hint: 0,
                context_id: 0,
                opnum: 1,
                object: None,
                stub,
            }
        } else {
            Body::Response {
                alloc_hint: 0,
                context_id: 0,
                cancel_count: 0,
                stub,
            }
        }
    };
    let stub = &data[9..data.len().min(1033)];
    let mut want = Pdu::new(7, body(stub.to_vec()));
    want.drep = DataRep(data[1..5].try_into().unwrap());
    want.drep.0[0] &= 0x1f;
    let mut first = Pdu::new(7, body(stub[..stub.len() / 2].to_vec()));
    first.flags = flags::FIRST_FRAG;
    first.drep = want.drep;
    let mut last = Pdu::new(7, body(stub[stub.len() / 2..].to_vec()));
    last.flags = flags::LAST_FRAG;
    last.drep = DataRep(data[5..9].try_into().unwrap());
    last.drep.0[0] &= 0x1f;
    // Exercise each fragment's own byte order on the wire before reassembly.
    let parse = |p: &Pdu| Pdu::parse(&p.to_bytes().unwrap()).unwrap();
    let parts = vec![parse(&first), parse(&last)];
    let fail = (first.drep.0[..2] != last.drep.0[..2]).then_some(1);
    last.drep = first.drep;
    let recovery = vec![parse(&first), parse(&last)];
    check_related(parts, want.clone(), fail, recovery, want);
}

fuzz_target!(|data: &[u8]| {
    if let Some(data) = data.strip_prefix(b"REP\0") {
        representations(data);
        return;
    }
    contract::check_decode_capacity(Frames::<Pdu>::new, data);
    contract::check_wire::<Pdu>(data);
    contract::check_decode_capacity(|| Frames::<Pdu>::with_limit(0), data);
    contract::check_decode_capacity(|| Frames::<Pdu>::with_limit(64), data);

    let (results, _) = decode_all(Frames::<Pdu>::new, data);
    let mut rest = data;
    for result in &results {
        let length = Pdu::frame_length(rest).unwrap().unwrap();
        let (raw, tail) = rest.split_at(length);
        assert_eq!(
            Frames::<Pdu>::new().decode(raw, false),
            Ok(Step::Item(result.clone(), length))
        );
        // Exact parsing also checks that the canonical rewrite fits.
        let exact = result.clone().and_then(|pdu| {
            pdu.to_bytes()?;
            Ok(pdu)
        });
        assert_eq!(Pdu::parse(raw), exact);
        rest = tail;
    }

    let mut r = Reassembler::new(4096);
    for p in results.into_iter().flatten() {
        rewrite(&p);
        let _ = r.push(p);
        assert!(r.pending() <= 4096);
    }
    // A valid call must recover even when the stream left an incomplete call.
    let request = |stub| {
        Pdu::new(
            7,
            Body::Request {
                alloc_hint: 0,
                context_id: 0,
                opnum: 1,
                object: None,
                stub,
            },
        )
    };
    let mut first = request(vec![1]);
    first.flags = flags::FIRST_FRAG;
    let mut last = request(vec![2]);
    last.flags = flags::LAST_FRAG;
    let mut got = r.push(first.clone());
    if matches!(got, Err(Error::Interleaved { .. })) {
        assert_eq!(r.pending(), 0);
        got = r.push(first);
    }
    assert_eq!(got, Ok(None));
    assert_eq!(r.push(last), Ok(Some(request(vec![1, 2]))));
    assert_eq!(r.pending(), 0);
    let _ = Pdu::parse(data);
    let _ = built(data);
});
