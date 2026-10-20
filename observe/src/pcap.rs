//! Captures in the pcapng format, which Wireshark and tcpdump read.
//!
//! The packets are raw IP with no link layer (`LINKTYPE_RAW`). Available
//! TLS secrets go in a Decryption Secrets Block, so Wireshark decrypts the
//! TLS in the file with no `SSLKEYLOGFILE` setting. The writer appends one
//! block at a time, so a caller can send a file in pieces as it walks the
//! packets.

/// `LINKTYPE_RAW`: each packet starts with its IPv4 or IPv6 header.
const LINKTYPE_RAW: u16 = 101;
/// The secrets type of a TLS key log: "TLSK".
const TLS_KEY_LOG: u32 = 0x544c_534b;

fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let padded = body.len().div_ceil(4) * 4;
    let total = (12 + padded) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + padded - body.len(), 0);
    out.extend_from_slice(&total.to_le_bytes());
}

/// Appends the section header, the one interface and, if `keylog` (an
/// `SSLKEYLOGFILE`) is not empty, its Decryption Secrets Block.
pub(crate) fn start(out: &mut Vec<u8>, keylog: &[u8]) {
    // Section header: byte-order magic, version 1.0, length unknown.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    block(out, 0x0a0d_0d0a, &shb);
    // One interface. Timestamps are in microseconds, the default.
    let mut idb = Vec::new();
    idb.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&0u32.to_le_bytes());
    block(out, 1, &idb);
    if !keylog.is_empty() {
        let mut dsb = Vec::with_capacity(8 + keylog.len() + 3);
        dsb.extend_from_slice(&TLS_KEY_LOG.to_le_bytes());
        dsb.extend_from_slice(&(keylog.len() as u32).to_le_bytes());
        dsb.extend_from_slice(keylog);
        dsb.resize(8 + keylog.len().div_ceil(4) * 4, 0);
        block(out, 0x0000_000a, &dsb);
    }
}

/// Appends one packet with its time in microseconds since the Unix epoch.
/// `original` is its length on the link; `data` may be shorter.
pub(crate) fn packet(
    out: &mut Vec<u8>,
    micros: u64,
    original: usize,
    data: &[u8],
    comment: Option<&str>,
) {
    let mut epb = Vec::with_capacity(20 + data.len());
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
    epb.extend_from_slice(&(micros as u32).to_le_bytes());
    epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
    epb.extend_from_slice(&(original.max(data.len()) as u32).to_le_bytes());
    epb.extend_from_slice(data);
    if let Some(mut comment) = comment {
        epb.resize(20 + data.len().div_ceil(4) * 4, 0);
        while !comment.is_empty() {
            let mut len = comment.len().min(u16::MAX as usize);
            while !comment.is_char_boundary(len) {
                len -= 1;
            }
            epb.extend_from_slice(&1u16.to_le_bytes());
            epb.extend_from_slice(&(len as u16).to_le_bytes());
            epb.extend_from_slice(&comment.as_bytes()[..len]);
            epb.resize(epb.len().div_ceil(4) * 4, 0);
            comment = &comment[len..];
        }
        epb.extend_from_slice(&[0; 4]);
    }
    block(out, 6, &epb);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::le32;

    /// Walks the blocks: every block's two lengths agree and are a
    /// multiple of four, and the blocks come in the expected order.
    #[test]
    fn blocks_are_well_formed() {
        let packet = [
            0x45u8, 0, 0, 21, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 7,
        ];
        let micros = 1_700_000_000_000_000;
        let keys = b"CLIENT_RANDOM aa bbbb\n";
        let mut file = Vec::new();
        start(&mut file, keys);
        super::packet(&mut file, micros, 40, &packet, None);
        let mut kinds = Vec::new();
        let mut i = 0;
        while i < file.len() {
            let (kind, len) = (
                le32(&file, i).unwrap(),
                le32(&file, i + 4).unwrap() as usize,
            );
            assert_eq!(len % 4, 0);
            assert_eq!(le32(&file, i + len - 4).unwrap() as usize, len);
            if kind == 0x0a {
                assert_eq!(le32(&file, i + 8).unwrap(), 0x544c_534b);
                assert_eq!(le32(&file, i + 12).unwrap() as usize, keys.len());
                assert_eq!(&file[i + 16..i + 16 + keys.len()], keys);
                let padding = &file[i + 16 + keys.len()..i + len - 4];
                assert_eq!(padding, &[0, 0]);
            }
            kinds.push(kind);
            i += len;
        }
        assert_eq!(i, file.len());
        assert_eq!(kinds, [0x0a0d_0d0a, 1, 0x0a, 6]);
        // The packet block holds the packet whole, with its original length.
        let epb = file.len() - (12 + 20 + 24);
        let timestamp =
            ((le32(&file, epb + 12).unwrap() as u64) << 32) | le32(&file, epb + 16).unwrap() as u64;
        assert_eq!(timestamp, micros);
        assert_eq!(le32(&file, epb + 20).unwrap(), 21);
        assert_eq!(le32(&file, epb + 24).unwrap(), 40);
        assert_eq!(&file[epb + 28..epb + 28 + 21], &packet);
    }

    #[test]
    fn a_file_without_keys_has_no_secrets_block() {
        let mut file = Vec::new();
        start(&mut file, b"");
        assert_eq!(file.len(), 28 + 20);
        assert_eq!(le32(&file, 28).unwrap(), 1);
    }
}
