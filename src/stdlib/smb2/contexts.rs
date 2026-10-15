//! Negotiate, create and error contexts: their types, builders, and the
//! readers and writers that place them in a message body.

use super::{Error, HEADER_LEN, apart, fit16, fit32, pad8, put16, put32, too_long};
use fictionet::stdlib::codec::{le16, le32};

/// Negotiate context types, SMB 3.1.1 only.
pub mod negotiate_context {
    /// The PREAUTH-INTEGRITY-CAPABILITIES negotiate context type.
    pub const PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
    /// The ENCRYPTION-CAPABILITIES negotiate context type.
    pub const ENCRYPTION_CAPABILITIES: u16 = 0x0002;
    /// The COMPRESSION-CAPABILITIES negotiate context type.
    pub const COMPRESSION_CAPABILITIES: u16 = 0x0003;
    /// The NETNAME-NEGOTIATE-CONTEXT-ID negotiate context type.
    pub const NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
    /// The TRANSPORT-CAPABILITIES negotiate context type.
    pub const TRANSPORT_CAPABILITIES: u16 = 0x0006;
    /// The RDMA-TRANSFORM-CAPABILITIES negotiate context type.
    pub const RDMA_TRANSFORM_CAPABILITIES: u16 = 0x0007;
    /// The SIGNING-CAPABILITIES negotiate context type.
    pub const SIGNING_CAPABILITIES: u16 = 0x0008;
    /// The one preauthentication hash, SHA-512.
    pub const SHA_512: u16 = 0x0001;
}

/// Create context names, as they travel.
pub mod create_context {
    /// The EA-BUFFER create context name.
    pub const EA_BUFFER: &[u8] = b"ExtA";
    /// The SD-BUFFER create context name.
    pub const SD_BUFFER: &[u8] = b"SecD";
    /// The DURABLE-HANDLE-REQUEST create context name.
    pub const DURABLE_HANDLE_REQUEST: &[u8] = b"DHnQ";
    /// The DURABLE-HANDLE-RECONNECT create context name.
    pub const DURABLE_HANDLE_RECONNECT: &[u8] = b"DHnC";
    /// The ALLOCATION-SIZE create context name.
    pub const ALLOCATION_SIZE: &[u8] = b"AlSi";
    /// The QUERY-MAXIMAL-ACCESS create context name.
    pub const QUERY_MAXIMAL_ACCESS: &[u8] = b"MxAc";
    /// The TIMEWARP-TOKEN create context name.
    pub const TIMEWARP_TOKEN: &[u8] = b"TWrp";
    /// The QUERY-ON-DISK-ID create context name.
    pub const QUERY_ON_DISK_ID: &[u8] = b"QFid";
    /// The REQUEST-LEASE create context name.
    pub const REQUEST_LEASE: &[u8] = b"RqLs";
    /// The DURABLE-HANDLE-REQUEST-V2 create context name.
    pub const DURABLE_HANDLE_REQUEST_V2: &[u8] = b"DH2Q";
    /// The DURABLE-HANDLE-RECONNECT-V2 create context name.
    pub const DURABLE_HANDLE_RECONNECT_V2: &[u8] = b"DH2C";
}

/// A negotiate context, SMB 3.1.1 only: its type (see
/// [`negotiate_context`]) and its data as bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegotiateContext {
    /// The context type.
    pub kind: u16,
    /// The data, at most 65535 bytes.
    pub data: Vec<u8>,
}

impl NegotiateContext {
    /// A preauthentication integrity context: hash algorithm IDs (see
    /// [`negotiate_context::SHA_512`]) and a salt. Lists too long for the
    /// context's 16-bit counts and length are an error.
    pub fn preauth_integrity(hashes: &[u16], salt: &[u8]) -> Result<NegotiateContext, Error> {
        let mut data = Vec::new();
        put16(&mut data, fit16(hashes.len())?);
        put16(&mut data, fit16(salt.len())?);
        for h in hashes {
            put16(&mut data, *h);
        }
        data.extend_from_slice(salt);
        fit16(data.len())?;
        Ok(NegotiateContext {
            kind: negotiate_context::PREAUTH_INTEGRITY_CAPABILITIES,
            data,
        })
    }

    /// The hash algorithm IDs and salt of a preauthentication integrity
    /// context, or `None` if it is another type or its counts do not fit
    /// its data.
    pub fn preauth_integrity_parts(&self) -> Option<(Vec<u16>, Vec<u8>)> {
        if self.kind != negotiate_context::PREAUTH_INTEGRITY_CAPABILITIES {
            return None;
        }
        let d = &self.data;
        let hashes = usize::from(le16(d, 0).ok_or(Error::Truncated).ok()?);
        let salt = usize::from(le16(d, 2).ok_or(Error::Truncated).ok()?);
        let list = (0..hashes)
            .map(|i| le16(d, 4 + 2 * i).ok_or(Error::Truncated).ok())
            .collect::<Option<Vec<u16>>>()?;
        let start = 4 + 2 * hashes;
        Some((list, d.get(start..start + salt)?.to_vec()))
    }

    /// A context that is a 16-bit count and a list of 16-bit IDs, as the
    /// encryption and signing capabilities are. A list too long for the
    /// context's 16-bit length is an error.
    pub fn algorithms(kind: u16, ids: &[u16]) -> Result<NegotiateContext, Error> {
        let mut data = Vec::new();
        put16(&mut data, fit16(ids.len())?);
        for id in ids {
            put16(&mut data, *id);
        }
        fit16(data.len())?;
        Ok(NegotiateContext { kind, data })
    }

    /// The IDs of a context written by [`NegotiateContext::algorithms`], or
    /// `None` if its count does not fit its data.
    pub fn algorithm_list(&self) -> Option<Vec<u16>> {
        let n = usize::from(le16(&self.data, 0).ok_or(Error::Truncated).ok()?);
        (0..n)
            .map(|i| le16(&self.data, 2 + 2 * i).ok_or(Error::Truncated).ok())
            .collect()
    }
}

/// A create context: a name (see [`create_context`]) and data, both bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateContext {
    /// The name, usually four ASCII letters.
    pub name: Vec<u8>,
    /// The data.
    pub data: Vec<u8>,
}

/// Whether `data` starts with `count` SMB2 ERROR Context structures, each
/// 8-byte aligned from the start of the error data, which is itself
/// 8-byte aligned from the start of the ERROR response (MS-SMB2 section
/// 2.2.2). Bytes after the last context are not read.
pub(super) fn error_contexts_fit(count: u8, data: &[u8]) -> bool {
    let mut at = 0usize;
    for i in 0..count {
        if i > 0 {
            at = at.next_multiple_of(8);
        }
        let Ok(len) = le32(data, at).ok_or(Error::Truncated) else {
            return false;
        };
        if le32(data, at + 4).ok_or(Error::Truncated).is_err() {
            return false;
        }
        let Some(end) = (at + 8).checked_add(len as usize) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        at = end;
    }
    true
}

/// Whether an SMB 3.1.1 NEGOTIATE response's contexts pass the checks of
/// MS-SMB2 section 3.2.5.2: exactly one preauthentication integrity
/// context, and at most one each of the encryption, compression, RDMA
/// transform, signing and transport contexts.
pub(super) fn response_contexts_ok(contexts: &[NegotiateContext]) -> bool {
    use negotiate_context::*;
    let count = |kind: u16| contexts.iter().filter(|c| c.kind == kind).count();
    count(PREAUTH_INTEGRITY_CAPABILITIES) == 1
        && [
            ENCRYPTION_CAPABILITIES,
            COMPRESSION_CAPABILITIES,
            RDMA_TRANSFORM_CAPABILITIES,
            SIGNING_CAPABILITIES,
            TRANSPORT_CAPABILITIES,
        ]
        .iter()
        .all(|&kind| count(kind) <= 1)
}

/// Checks that contexts at `offset` start 8-byte aligned and at or after
/// the end of the buffer `before`, an offset and a length. An empty
/// buffer before them puts no limit on where they start.
pub(super) fn contexts_after(offset: u32, before: (u32, u32)) -> Result<(), Error> {
    if !offset.is_multiple_of(8) {
        return Err(Error::Align(offset));
    }
    if before.1 != 0 && u64::from(offset) < u64::from(before.0) + u64::from(before.1) {
        return Err(Error::Overlap);
    }
    Ok(())
}

/// Negotiate contexts: `count` of them from `offset`, each 8-byte aligned
/// from the header's start. The first starts after the body's fixed part
/// and after the buffer `before` (see [`contexts_after`]).
pub(super) fn negotiate_contexts(
    b: &[u8],
    offset: u32,
    count: u16,
    before: (u32, u32),
) -> Result<Vec<NegotiateContext>, Error> {
    let mut out = Vec::new();
    if count == 0 {
        return Ok(out);
    }
    let fixed = usize::from(le16(b, 0).ok_or(Error::Truncated)? & !1);
    let mut at = (offset as usize)
        .checked_sub(HEADER_LEN)
        .ok_or(Error::Buffer)?;
    if at < fixed {
        return Err(Error::Buffer);
    }
    contexts_after(offset, before)?;
    for i in 0..count {
        if i > 0 {
            at = at.checked_next_multiple_of(8).ok_or(Error::Buffer)?;
        }
        let kind = le16(b, at)
            .ok_or(Error::Truncated)
            .map_err(|_| Error::Buffer)?;
        let len = usize::from(
            le16(b, at.checked_add(2).ok_or(Error::Buffer)?)
                .ok_or(Error::Truncated)
                .map_err(|_| Error::Buffer)?,
        );
        let start = at.checked_add(8).ok_or(Error::Buffer)?;
        let end = start.checked_add(len).ok_or(Error::Buffer)?;
        let data = b.get(start..end).ok_or(Error::Buffer)?;
        out.push(NegotiateContext {
            kind,
            data: data.to_vec(),
        });
        at = end;
    }
    Ok(out)
}

pub(super) fn write_negotiate_contexts(
    w: &mut Vec<u8>,
    contexts: &[NegotiateContext],
) -> Result<(), Error> {
    for (i, c) in contexts.iter().enumerate() {
        if i > 0 {
            pad8(w);
        }
        put16(w, c.kind);
        put16(w, fit16(c.data.len())?);
        put32(w, 0);
        w.extend_from_slice(&c.data);
        too_long(w.len())?;
    }
    Ok(())
}

/// Create contexts in `region`, each linked to the next by its Next field,
/// a multiple of 8. A Next that is not 0 must point at another context
/// inside the region. A context's name and data must lie inside it, each
/// 8-byte aligned and after its 16-byte header, in either order and apart,
/// as MS-SMB2 section 2.2.13.2 lays them out. So the bytes copied out are
/// never more than the region holds.
pub(super) fn create_contexts(region: &[u8]) -> Result<Vec<CreateContext>, Error> {
    let mut out = Vec::new();
    if region.is_empty() {
        return Ok(out);
    }
    let mut at = 0;
    loop {
        let rest = region.get(at..).ok_or(Error::Buffer)?;
        if rest.len() < 16 {
            return Err(Error::Buffer);
        }
        let next = le32(rest, 0).ok_or(Error::Truncated)? as usize;
        let this = if next == 0 {
            rest
        } else if next >= 16 && next <= rest.len() {
            &rest[..next]
        } else {
            return Err(Error::Buffer);
        };
        if !next.is_multiple_of(8) {
            return Err(Error::Align(next as u32));
        }
        let field = |off: usize, len: usize| -> Result<Vec<u8>, Error> {
            if len == 0 {
                return Ok(Vec::new());
            }
            Ok(this
                .get(off..off.checked_add(len).ok_or(Error::Buffer)?)
                .ok_or(Error::Buffer)?
                .to_vec())
        };
        let (name_at, name_len) = (
            le16(rest, 4).ok_or(Error::Truncated)?,
            le16(rest, 6).ok_or(Error::Truncated)?,
        );
        let (data_at, data_len) = (
            le16(rest, 10).ok_or(Error::Truncated)?,
            le32(rest, 12).ok_or(Error::Truncated)?,
        );
        if name_len != 0 {
            if name_at < 16 {
                return Err(Error::Buffer);
            }
            if name_at % 8 != 0 {
                return Err(Error::Align(name_at.into()));
            }
        }
        // DataOffset is ignored when DataLength is 0.
        if data_len != 0 {
            if data_at < 16 {
                return Err(Error::Buffer);
            }
            if data_at % 8 != 0 {
                return Err(Error::Align(data_at.into()));
            }
            apart(
                (name_at.into(), name_len.into()),
                (data_at.into(), data_len),
            )?;
        }
        let name = field(usize::from(name_at), usize::from(name_len))?;
        let data = field(usize::from(data_at), data_len as usize)?;
        out.push(CreateContext { name, data });
        if next == 0 {
            return Ok(out);
        }
        at += next;
    }
}

/// Writes create contexts after the bytes already in `w`, 8-byte aligned,
/// and puts their offset and length at `field` in the fixed part.
pub(super) fn write_create_contexts(
    w: &mut Vec<u8>,
    contexts: &[CreateContext],
    field: usize,
) -> Result<(), Error> {
    if contexts.is_empty() {
        return Ok(());
    }
    pad8(w);
    let start = w.len();
    for (i, c) in contexts.iter().enumerate() {
        let here = w.len();
        let name_end = 16usize.checked_add(c.name.len()).ok_or(Error::Unwritable)?;
        let data_at = if c.data.is_empty() {
            0
        } else {
            name_end.next_multiple_of(8)
        };
        let size = if c.data.is_empty() {
            name_end
        } else {
            data_at.saturating_add(c.data.len())
        };
        too_long(here.saturating_add(size))?;
        let last = i + 1 == contexts.len();
        let next = if last {
            0
        } else {
            fit32(size.next_multiple_of(8))?
        };
        put32(w, next);
        put16(w, 16);
        put16(w, fit16(c.name.len())?);
        put16(w, 0);
        put16(w, fit16(data_at)?);
        put32(w, fit32(c.data.len())?);
        w.extend_from_slice(&c.name);
        if !c.data.is_empty() {
            w.resize(here + data_at, 0);
            w.extend_from_slice(&c.data);
        }
        if !last {
            w.resize(here + size.next_multiple_of(8), 0);
        }
    }
    let at = fit32(HEADER_LEN + start)?;
    let len = fit32(w.len() - start)?;
    w[field..field + 4].copy_from_slice(&at.to_le_bytes());
    w[field + 4..field + 8].copy_from_slice(&len.to_le_bytes());
    Ok(())
}
