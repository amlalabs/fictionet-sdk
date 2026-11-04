//! Ethernet inputs shared by the QEMU peer and guest assertions.

pub fn fixtures() -> Vec<Vec<u8>> {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = bytes
            .chunks(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32)
            .sum::<u32>();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    }
    fn tcp(options: &[u8], flags: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 54 + options.len()];
        frame[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0, 0xab, 0xcd, 0xef]);
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((40 + options.len()) as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        frame[34..38].copy_from_slice(&[0x12, 0x34, 0, 80]);
        frame[46] = ((20 + options.len()) / 4) as u8 * 16;
        frame[47] = flags;
        frame[48..50].copy_from_slice(&4096u16.to_be_bytes());
        frame[54..].copy_from_slice(options);
        let ip_checksum = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        let mut pseudo = frame[26..34].to_vec();
        pseudo.extend([0, 6]);
        pseudo.extend(((20 + options.len()) as u16).to_be_bytes());
        pseudo.extend(&frame[34..]);
        frame[50..52].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        frame.resize(frame.len().max(60), 0);
        frame
    }
    let capable = tcp(&[30, 4, 1, 1], 2);
    let dss = tcp(&[30, 8, 0x20, 1, 0x12, 0x34, 0x56, 0x78], 16);
    let mut vlan = capable.clone();
    vlan.splice(12..12, [0x81, 0, 0, 42]);
    let mut malformed = capable.clone();
    malformed[14] = 0x4f;
    malformed[24] ^= 0xff;
    malformed[50] ^= 0xff;
    let unknown = vec![0xff; 61];
    let mut maximum = vec![0xa5; 1514];
    maximum[..6].copy_from_slice(&capable[..6]);
    maximum[12..14].copy_from_slice(&[0x88, 0xb5]);
    vec![capable, dss, vlan, malformed, unknown, maximum]
}
