//! DCE/RPC connection-oriented PDUs, as a world playing an RPC server
//! reads them, and values a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::dcerpc::{
    Auth, Bind, BindAck, BindNak, Body, Context, ContextResult, DataRep, Error, Frames,
    MAX_FRAG, MAX_FRAGMENTS, Pdu, Reassembler, ReassemblyError, SyntaxId, Uuid, flags,
};
use libfuzzer_sys::fuzz_target;

/// A PDU read is written back and reads the same, unless the writer's
/// padding or reserved fields make it longer than a fragment.
fn rewrite(pdu: &Pdu) {
    contract::check_wire_value(pdu);
    match pdu.to_bytes() {
        Ok(bytes) => {
            assert!(bytes.len() <= MAX_FRAG);
            assert_eq!(Pdu::parse(&bytes), Ok(pdu.clone()));
        }
        Err(e) => assert_eq!(e, Error::Unwritable),
    }
}

fn syntax(u: &mut Unstructured) -> Result<SyntaxId> {
    Ok(SyntaxId { uuid: Uuid(u.arbitrary()?), major: u.arbitrary()?, minor: u.arbitrary()? })
}

fn list<T>(u: &mut Unstructured, max: usize, f: impl Fn(&mut Unstructured) -> Result<T>) -> Result<Vec<T>> {
    let n = u.int_in_range(0..=max)?;
    (0..n).map(|_| f(u)).collect()
}

fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

fn bind(u: &mut Unstructured) -> Result<Bind> {
    Ok(Bind {
        max_xmit_frag: u.arbitrary()?,
        max_recv_frag: u.arbitrary()?,
        assoc_group: u.arbitrary()?,
        contexts: list(u, 260, |u| {
            Ok(Context { id: u.arbitrary()?, abstract_syntax: syntax(u)?, transfer_syntaxes: list(u, 260, syntax)? })
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
            Ok(ContextResult { result: u.arbitrary()?, reason: u.arbitrary()?, transfer_syntax: syntax(u)? })
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
            object: if u.arbitrary()? { Some(Uuid(u.arbitrary()?)) } else { None },
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
        7 => Body::BindNak(BindNak { reason: u.arbitrary()?, versions: list(u, 260, |u| u.arbitrary())? }),
        8 => Body::Auth3,
        9 => Body::Shutdown,
        10 => Body::Cancel,
        _ => Body::Orphaned,
    };
    let auth = if u.arbitrary()? {
        Some(Auth { kind: u.arbitrary()?, level: u.arbitrary()?, context_id: u.arbitrary()?, value: bytes(u, 300)? })
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
    let Ok(parts) = p.fragments(max) else { return Ok(()) };
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
            let left = if whole == 0 { 0 } else { whole.saturating_sub(u32::try_from(sent).unwrap_or(u32::MAX)) };
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
/// they join only if every verifier has the first one's type, level and
/// context ID, and the joined call keeps any cancel.
fn related(u: &mut Unstructured, mut parts: Vec<Pdu>, mut want: Pdu) -> Result<()> {
    let first: Option<(u8, u8, u32)> = u.arbitrary()?;
    let mut fail = None;
    for (i, f) in parts.iter_mut().enumerate() {
        let s = if i == 0 || u.ratio(3, 4)? { first } else { u.arbitrary()? };
        f.auth = s.map(|(kind, level, context_id)| Auth { kind, level, context_id, value: vec![1] });
        if i > 0 && s != first && fail.is_none() {
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
    if let Body::Response { cancel_count: w, .. } = &mut want.body {
        *w = parts
            .iter()
            .filter_map(|f| match f.body {
                Body::Response { cancel_count, .. } => Some(cancel_count),
                _ => None,
            })
            .fold(0, u8::max);
    }
    let mut r = Reassembler::default();
    let n = parts.len();
    for (i, f) in parts.into_iter().enumerate() {
        let got = r.push(f);
        match fail {
            Some(at) if i == at => {
                assert_eq!(got, Err(ReassemblyError::Unexpected { call_id: want.call_id }));
                return Ok(());
            }
            _ if i + 1 == n => assert_eq!(got, Ok(Some(want.clone()))),
            _ => assert_eq!(got, Ok(None)),
        }
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
    contract::check_wire::<Pdu>(data);
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(0), data, 2 * Frames::with_limit(0).capacity());
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(64), data, 2 * Frames::with_limit(64).capacity());

    let (results, _) = decode_all(Frames::new, data);

    let mut r = Reassembler::new(4096);
    for p in results.into_iter().flatten() {
        rewrite(&p);
        let _ = r.push(p);
        assert!(r.pending() <= 4096);
    }
    let _ = Pdu::parse(data);
    let _ = built(data);
});
