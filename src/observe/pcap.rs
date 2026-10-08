//! Captures in the pcapng format, which Wireshark and tcpdump read.
//!
//! The packets are raw IP with no link layer (`LINKTYPE_RAW`). The world's
//! TLS secrets go in a Decryption Secrets Block, so Wireshark decrypts the
//! TLS in the file with no `SSLKEYLOGFILE` setting.

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

/// A pcapng file of `packets`, each with its time in microseconds since
/// the Unix epoch, and `keylog` (an `SSLKEYLOGFILE`), if not empty.
pub(crate) fn pcapng(packets: &[(u64, &[u8])], keylog: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Section header: byte-order magic, version 1.0, length unknown.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    block(&mut out, 0x0a0d_0d0a, &shb);
    // One interface. Timestamps are in microseconds, the default.
    let mut idb = Vec::new();
    idb.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&0u32.to_le_bytes());
    block(&mut out, 1, &idb);
    if !keylog.is_empty() {
        let mut dsb = Vec::new();
        dsb.extend_from_slice(&TLS_KEY_LOG.to_le_bytes());
        dsb.extend_from_slice(&(keylog.len() as u32).to_le_bytes());
        dsb.extend_from_slice(keylog);
        dsb.resize(8 + keylog.len().div_ceil(4) * 4, 0);
        block(&mut out, 0x0000_000a, &dsb);
    }
    for (micros, data) in packets {
        let mut epb = Vec::with_capacity(20 + data.len());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(*micros as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(data);
        block(&mut out, 6, &epb);
    }
    out
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
        let file = pcapng(
            &[(1_700_000_000_000_000, &packet[..])],
            b"CLIENT_RANDOM aa bb\n",
        );
        let mut kinds = Vec::new();
        let mut i = 0;
        while i < file.len() {
            let (kind, len) = (
                le32(&file, i).unwrap(),
                le32(&file, i + 4).unwrap() as usize,
            );
            assert_eq!(len % 4, 0);
            assert_eq!(le32(&file, i + len - 4).unwrap() as usize, len);
            kinds.push(kind);
            i += len;
        }
        assert_eq!(i, file.len());
        assert_eq!(kinds, [0x0a0d_0d0a, 1, 0x0a, 6]);
        // The packet block holds the packet whole.
        let epb = file.len() - (12 + 20 + 24);
        assert_eq!(le32(&file, epb + 20).unwrap(), 21);
        assert_eq!(&file[epb + 28..epb + 28 + 21], &packet);
    }
}
