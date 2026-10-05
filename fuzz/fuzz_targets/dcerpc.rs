//! DCE/RPC connection-oriented PDUs, as a world playing an RPC server
//! reads them, and values a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::dcerpc::{
    Auth, Bind, BindAck, BindNak, Body, Context, ContextResult, DataRep, Decoder, EncodeError, Error, MAX_BUFFERED,
    MAX_FRAG, MAX_FRAGMENTS, Pdu, Reassembler, SyntaxId, Uuid, flags,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks, taking PDUs out after each feed, as a world
/// does. Every result, ending with the error that broke the stream, if one
/// did.
fn split(data: &[u8], bytewise: bool) -> Vec<std::result::Result<Pdu, Error>> {
    let mut decoder = Decoder::new();
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_pdu() {
                let fatal = matches!(r, Err(e) if e.breaks_stream());
                out.push(r);
                if fatal {
                    return out;
                }
                progress = true;
            }
            // A full decoder always gives a PDU or an error.
            assert!(progress);
        }
    }
    out
}

/// A PDU read is written back and reads the same, unless the writer's
/// padding or reserved fields make it longer than a fragment.
fn rewrite(pdu: &Pdu) {
    match pdu.to_bytes() {
        Ok(bytes) => {
            assert!(bytes.len() <= MAX_FRAG);
            assert_eq!(Pdu::parse(&bytes), Ok(Some((pdu.clone(), bytes.len()))));
        }
        Err(e) => assert_eq!(e, EncodeError::TooLong),
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

/// Values a world builds: whatever a writer accepts reads back the same,
/// and whatever is split joins back into the same call.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let p = pdu(&mut u)?;
    if let Ok(bytes) = p.to_bytes() {
        assert!(bytes.len() <= MAX_FRAG);
        assert_eq!(Pdu::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
    }
    let max: u16 = u.arbitrary()?;
    if let Ok(parts) = p.fragments(max)
        && p.to_bytes().is_ok()
    {
        assert!(parts.len() <= MAX_FRAGMENTS);
        let mut r = Reassembler::default();
        let mut got = None;
        for f in parts {
            let bytes = f.to_bytes().unwrap();
            if matches!(p.body, Body::Request { .. } | Body::Response { .. }) {
                assert!(bytes.len() <= usize::from(max));
            }
            assert_eq!(Pdu::parse(&bytes), Ok(Some((f.clone(), bytes.len()))));
            got = r.push(f).unwrap();
        }
        let mut want = p.clone();
        if matches!(want.body, Body::Request { .. } | Body::Response { .. }) {
            want.flags |= flags::FIRST_FRAG | flags::LAST_FRAG;
        }
        assert_eq!(got, Some(want));
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. Both
    // give the same PDUs and the same errors.
    let results = split(data, false);
    assert_eq!(split(data, true), results);

    let mut r = Reassembler::new(4096);
    for p in results.into_iter().flatten() {
        rewrite(&p);
        let _ = r.push(p);
        assert!(r.pending() <= 4096);
    }
    let _ = Pdu::parse(data);
    let _ = built(data);
});
