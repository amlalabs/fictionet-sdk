//! Bounded TLS hello decoding from captured IPv4 TCP packets.
//!
//! TCP retransmissions are trimmed and gaps reset the affected direction. TLS
//! records and handshake messages may span segments. Only public ClientHello
//! and ServerHello fields are retained. Unknown numeric identifiers stay numeric;
//! missing hellos or groups stay absent. No secret or encrypted payload is shown.

use super::view::Rows;
use fictionet_observe::page::{StateLimits, StateTopic};
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const SESSIONS: usize = 16;
const BUFFER: usize = 65536;
#[derive(Clone, Debug, Default, Serialize)]
pub struct Hello {
    pub sni: Option<String>,
    pub legacy_version: u16,
    pub versions: Vec<u16>,
    pub ciphers: Vec<u16>,
    pub groups: Vec<u16>,
    pub key_shares: Vec<u16>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub link: u64,
    pub sandbox: String,
    pub client: String,
    pub server: String,
    pub at_ms: u64,
    pub offered: Option<Hello>,
    pub chosen: Option<Hello>,
    pub gaps: u64,
    /// What the decoder holds of each direction: the client's, then the
    /// server's.
    #[serde(skip)]
    directions: [Direction; 2],
}
#[derive(Default, Serialize)]
pub struct View {
    pub sessions: Rows<Session, SESSIONS>,
    pub lost: u64,
}
struct Packet {
    link: u64,
    sandbox: String,
    at_ms: u64,
    bytes: Vec<u8>,
}
#[derive(Clone)]
pub struct Capture {
    sender: tokio::sync::mpsc::Sender<Packet>,
    lost: Arc<AtomicU64>,
    pub topic: StateTopic<View>,
}
impl Capture {
    pub fn new() -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Packet>(16);
        let lost = Arc::new(AtomicU64::new(0));
        let lost_worker = lost.clone();
        let topic = StateTopic::new(StateLimits {
            max_bytes: 128 << 10,
            deltas: 0,
        });
        let output = topic.clone();
        tokio::spawn(async move {
            let mut decoder = Decoder::default();
            while let Some(packet) = receiver.recv().await {
                let at = packet.at_ms;
                decoder.packet(packet);
                decoder.view.lost = lost_worker.load(Ordering::Relaxed);
                let _ = output.publish(
                    fictionet::time::Instant::from_since_start(std::time::Duration::from_millis(
                        at,
                    )),
                    &decoder.view,
                );
            }
        });
        Self {
            sender,
            lost,
            topic,
        }
    }
    pub fn packet(&self, link: u64, sandbox: &str, at_ms: u64, bytes: &[u8]) {
        let Some((h, p)) = ipv4(bytes) else {
            return;
        };
        if h[9] != 6
            || p.len() < 20
            || (u16::from_be_bytes([p[0], p[1]]) != 443 && u16::from_be_bytes([p[2], p[3]]) != 443)
        {
            return;
        }
        if self
            .sender
            .try_send(Packet {
                link,
                sandbox: sandbox.into(),
                at_ms,
                bytes: bytes[..h.len() + p.len()].to_vec(),
            })
            .is_err()
        {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[derive(Clone, Debug, Default)]
struct Direction {
    next: Option<u32>,
    records: Vec<u8>,
    messages: Vec<u8>,
}
#[derive(Default)]
struct Decoder {
    view: View,
}
impl Decoder {
    fn packet(&mut self, packet: Packet) {
        let Some((h, tcp)) = ipv4(&packet.bytes) else {
            return;
        };
        let header = usize::from(tcp[12] >> 4) * 4;
        if header < 20 || tcp.len() < header {
            return;
        }
        let address = |a: &[u8], p: &[u8]| {
            format!(
                "{}.{}.{}.{}:{}",
                a[0],
                a[1],
                a[2],
                a[3],
                u16::from_be_bytes([p[0], p[1]])
            )
        };
        let source = address(&h[12..16], &tcp[..2]);
        let destination = address(&h[16..20], &tcp[2..4]);
        let from_server = u16::from_be_bytes([tcp[0], tcp[1]]) == 443;
        let (client, server) = if from_server {
            (destination, source)
        } else {
            (source, destination)
        };
        let payload = &tcp[header..];
        let syn = tcp[13] & 2 != 0;
        let sessions = &mut self.view.sessions;
        let same = |s: &Session| s.link == packet.link && s.client == client && s.server == server;
        // A client's new SYN on the same addresses starts a new session.
        if syn
            && !from_server
            && let Some(index) = sessions.rows.iter().position(same)
        {
            sessions.drop_at(index);
        }
        let index = match sessions.rows.iter().position(same) {
            Some(i) => i,
            None => {
                if payload.first() != Some(&22) {
                    return;
                }
                sessions.push(Session {
                    link: packet.link,
                    sandbox: packet.sandbox,
                    client,
                    server,
                    at_ms: packet.at_ms,
                    offered: None,
                    chosen: None,
                    gaps: 0,
                    directions: Default::default(),
                });
                sessions.rows.len() - 1
            }
        };
        if payload.is_empty() {
            return;
        }
        let session = &mut sessions.rows[index];
        let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap()).wrapping_add(u32::from(syn));
        let (hello, gaps) =
            session.directions[usize::from(from_server)].push(seq, payload, from_server);
        session.gaps += gaps;
        if let Some(hello) = hello {
            if from_server {
                session.chosen = Some(hello);
            } else {
                session.offered = Some(hello);
            }
        }
    }
}
impl Direction {
    fn push(&mut self, seq: u32, mut payload: &[u8], server: bool) -> (Option<Hello>, u64) {
        let mut gaps = 0;
        let end = seq.wrapping_add(payload.len() as u32);
        if let Some(next) = self.next {
            let offset = seq.wrapping_sub(next) as i32;
            if offset > 0 {
                self.records.clear();
                self.messages.clear();
                gaps += 1;
            } else if offset < 0 {
                let overlap = offset.unsigned_abs() as usize;
                if overlap >= payload.len() {
                    return (None, 0);
                }
                payload = &payload[overlap..];
            }
        }
        self.next = Some(end);
        if self.records.len() + payload.len() > BUFFER {
            self.records.clear();
            self.messages.clear();
            return (None, gaps + 1);
        }
        self.records.extend_from_slice(payload);
        let mut found = None;
        while self.records.len() >= 5 {
            let size = usize::from(u16::from_be_bytes([self.records[3], self.records[4]]));
            if size > 18432 || !matches!(self.records[0], 20..=23) || self.records[1] != 3 {
                self.records.clear();
                self.messages.clear();
                return (found, gaps + 1);
            }
            if self.records.len() < size + 5 {
                break;
            }
            if self.records[0] == 22 {
                if self.messages.len() + size > BUFFER {
                    self.messages.clear();
                    gaps += 1;
                } else {
                    self.messages.extend_from_slice(&self.records[5..5 + size]);
                }
            }
            self.records.drain(..size + 5);
            while self.messages.len() >= 4 {
                let size = (usize::from(self.messages[1]) << 16)
                    | (usize::from(self.messages[2]) << 8)
                    | usize::from(self.messages[3]);
                if size > BUFFER - 4 {
                    self.messages.clear();
                    gaps += 1;
                    break;
                }
                if self.messages.len() < size + 4 {
                    break;
                }
                if self.messages[0] == if server { 2 } else { 1 } {
                    match hello(&self.messages[4..4 + size], server) {
                        Some(h) => found = Some(h),
                        None => gaps += 1,
                    }
                }
                self.messages.drain(..4 + size);
            }
        }
        (found, gaps)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.0.get(..n)?;
        self.0 = &self.0[n..];
        Some(bytes)
    }
    fn byte(&mut self) -> Option<usize> {
        Some(usize::from(self.take(1)?[0]))
    }
    fn word(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn vector(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.word()?);
        self.take(n)
    }
}
fn words(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) || bytes.len() > 512 {
        return None;
    }
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect(),
    )
}
fn hello(bytes: &[u8], server: bool) -> Option<Hello> {
    let mut r = Reader(bytes);
    let legacy = r.word()?;
    r.take(32)?;
    let n = r.byte()?;
    r.take(n)?;
    let ciphers = if server {
        vec![r.word()?]
    } else {
        words(r.vector()?)?
    };
    let n = if server { 1 } else { r.byte()? };
    r.take(n)?;
    let mut result = Hello {
        legacy_version: legacy,
        versions: if server { vec![legacy] } else { vec![] },
        ciphers,
        ..Hello::default()
    };
    if r.0.is_empty() {
        return Some(result);
    }
    let mut ext = Reader(r.vector()?);
    if !r.0.is_empty() {
        return None;
    }
    while !ext.0.is_empty() {
        let kind = ext.word()?;
        let mut data = Reader(ext.vector()?);
        match kind {
            0 if !server => {
                let mut names = Reader(data.vector()?);
                while !names.0.is_empty() {
                    let kind = names.byte()?;
                    let value = names.vector()?;
                    if kind == 0 {
                        if value.len() > 253 || result.sni.is_some() {
                            return None;
                        }
                        result.sni = Some(std::str::from_utf8(value).ok()?.into());
                    }
                }
            }
            43 if server => {
                result.versions = vec![data.word()?];
            }
            43 => {
                let n = data.byte()?;
                result.versions = words(data.take(n)?)?;
            }
            10 => {
                result.groups = words(data.vector()?)?;
            }
            51 if server => {
                result.groups = vec![data.word()?];
                if !data.0.is_empty() {
                    data.vector()?;
                    result.key_shares = result.groups.clone();
                }
            }
            51 => {
                let mut shares = Reader(data.vector()?);
                while !shares.0.is_empty() {
                    if result.key_shares.len() == 256 {
                        return None;
                    }
                    result.key_shares.push(shares.word()?);
                    shares.vector()?;
                }
            }
            _ => {
                continue;
            }
        }
        if !data.0.is_empty() {
            return None;
        }
    }
    Some(result)
}

/// A checked, unfragmented IPv4 packet, clipped to its declared length.
pub fn ipv4(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let h = usize::from(bytes[0] & 15) * 4;
    let n = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if h < 20 || n < h || bytes.len() < n || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
    {
        return None;
    }
    Some((&bytes[..h], &bytes[h..n]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_hello_keeps_the_server_name() {
        let mut bytes = vec![3, 3];
        bytes.extend([0; 32]);
        bytes.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let name = b"kestrelmoor.co.uk";
        let mut extension = vec![0, 0];
        extension.extend(u16::try_from(name.len() + 5).unwrap().to_be_bytes());
        extension.extend(u16::try_from(name.len() + 3).unwrap().to_be_bytes());
        extension.push(0);
        extension.extend(u16::try_from(name.len()).unwrap().to_be_bytes());
        extension.extend(name);
        bytes.extend(u16::try_from(extension.len()).unwrap().to_be_bytes());
        bytes.extend(extension);
        assert_eq!(
            hello(&bytes, false).unwrap().sni.as_deref(),
            Some("kestrelmoor.co.uk")
        );
        bytes.pop();
        assert!(hello(&bytes, false).is_none());
    }

    #[test]
    fn a_legacy_client_version_is_not_an_explicit_version_list() {
        let mut bytes = vec![3, 3];
        bytes.extend([0; 32]);
        bytes.extend([0, 0, 2, 0xc0, 0x2f, 1, 0]);
        let parsed = hello(&bytes, false).unwrap();
        assert_eq!(parsed.legacy_version, 0x0303);
        assert!(parsed.versions.is_empty());
        assert_eq!(parsed.ciphers, [0xc02f]);
    }
    #[test]
    fn ipv4_length_bounds_the_captured_bytes() {
        let mut packet = vec![0u8; BUFFER + 100];
        packet[0] = 0x45;
        packet[3] = 28;
        let (header, payload) = ipv4(&packet).unwrap();
        assert_eq!(header.len() + payload.len(), 28);
        packet[6] = 0x20;
        assert!(ipv4(&packet).is_none());
        packet[6] = 0;
        packet[3] = 19;
        assert!(ipv4(&packet).is_none());
    }
    /// A TCP packet from the guest's `port` to the bank's port 443.
    fn to_bank(port: u16, flags: u8, payload: &[u8]) -> Packet {
        let mut bytes = vec![0u8; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&u16::try_from(40 + payload.len()).unwrap().to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 2]);
        bytes[16..20].copy_from_slice(&[84, 21, 44, 10]);
        bytes[20..22].copy_from_slice(&port.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes[32] = 5 << 4;
        bytes[33] = flags;
        bytes.extend(payload);
        Packet {
            link: 1,
            sandbox: "desktop".into(),
            at_ms: 0,
            bytes,
        }
    }
    #[test]
    fn sessions_are_bounded_and_a_new_syn_starts_over() {
        let mut decoder = Decoder::default();
        let record = [22, 3, 1, 0, 0];
        for port in 0..SESSIONS as u16 + 2 {
            decoder.packet(to_bank(40000 + port, 0, &record));
        }
        let sessions = &decoder.view.sessions;
        assert_eq!(sessions.rows.len(), SESSIONS);
        assert_eq!(sessions.dropped, 2);
        assert_eq!(sessions.rows[0].client, "10.0.0.2:40002");
        // The client's SYN on a retained session's addresses replaces it.
        decoder.packet(to_bank(40002, 2, &record));
        let sessions = &decoder.view.sessions;
        assert_eq!(sessions.rows.len(), SESSIONS);
        assert_eq!(sessions.dropped, 3);
        assert_eq!(sessions.rows[0].client, "10.0.0.2:40003");
        assert_eq!(sessions.rows.back().unwrap().client, "10.0.0.2:40002");
    }
    fn server() -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([0; 32]);
        h.extend([
            0, 0x13, 1, 0, 0, 14, 0, 43, 0, 2, 3, 4, 0, 51, 0, 4, 0, 29, 0, 0,
        ]);
        h
    }
    #[test]
    fn hello_fields_survive_segment_and_record_boundaries() {
        let h = server();
        let mut message = vec![2, 0, 0, h.len() as u8];
        message.extend(h);
        let record = |data: &[u8]| {
            let mut r = vec![22, 3, 3, 0, data.len() as u8];
            r.extend(data);
            r
        };
        let mut bytes = record(&message[..20]);
        bytes.extend(record(&message[20..]));
        let mut direction = Direction::default();
        let mut result = None;
        for (n, b) in bytes.iter().enumerate() {
            let (h, gaps) = direction.push(n as u32, &[*b], true);
            assert_eq!(gaps, 0);
            result = h.or(result);
        }
        let hello = result.unwrap();
        assert_eq!(hello.versions, [0x304]);
        assert_eq!(hello.ciphers, [0x1301]);
        assert_eq!(hello.groups, [29]);
        assert!(direction.push(0, &bytes, true).0.is_none());
        assert!(direction.push(bytes.len() as u32 + 1, &[22], true).1 > 0);
    }
    #[test]
    fn malformed_lengths_are_rejected_and_buffers_are_bounded() {
        let h = server();
        let mut record = vec![22, 3, 3, 0, (h.len() + 4) as u8, 2, 0, 0, h.len() as u8];
        record.extend(h);
        for end in 0..record.len() {
            assert!(
                Direction::default()
                    .push(0, &record[..end], true)
                    .0
                    .is_none()
            );
        }
        let mut direction = Direction::default();
        let (_, gaps) = direction.push(0, &vec![22; BUFFER + 1], false);
        assert_eq!(gaps, 1);
        assert!(direction.records.is_empty());
        assert!(direction.messages.is_empty());
    }
}
