//! DHCP messages (RFC 2131 and RFC 2132): reading and writing them, with no
//! I/O. The DHCP server in [`web::Sites`](crate::stdlib::web::Sites) uses
//! it, and so does the DHCP server that `fictionet attach --type tap` runs
//! for a VM.
//!
//! Hidden from the docs until its API settles.

use std::net::Ipv4Addr;

/// The UDP port of DHCP servers.
pub const SERVER_PORT: u16 = 67;
/// The UDP port of DHCP clients.
pub const CLIENT_PORT: u16 = 68;

/// `op` of a message from a client.
pub const BOOTREQUEST: u8 = 1;
/// `op` of a message from a server.
pub const BOOTREPLY: u8 = 2;

/// The four bytes after the fixed fields, before the options.
pub const MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Message types (option 53).
pub const DISCOVER: u8 = 1;
#[allow(missing_docs)]
pub const OFFER: u8 = 2;
#[allow(missing_docs)]
pub const REQUEST: u8 = 3;
#[allow(missing_docs)]
pub const DECLINE: u8 = 4;
#[allow(missing_docs)]
pub const ACK: u8 = 5;
#[allow(missing_docs)]
pub const NAK: u8 = 6;
#[allow(missing_docs)]
pub const RELEASE: u8 = 7;
#[allow(missing_docs)]
pub const INFORM: u8 = 8;

/// Option codes used here.
pub mod opt {
    #![allow(missing_docs)]
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const END: u8 = 255;
}

/// One DHCP message. Fields not kept here (`secs`, `sname`, `file`) are
/// written as zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    /// Options in order, without pad and end. Long options split over
    /// several entries (RFC 3396) are joined.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Message {
    /// A message with every field zero and no options.
    pub fn new(op: u8, xid: u32) -> Message {
        Message {
            op,
            htype: 1,
            hlen: 6,
            xid,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            options: Vec::new(),
        }
    }

    /// Reads a message from a UDP payload. `None` if it is too short, lacks
    /// the magic cookie, or its options run past the end.
    pub fn parse(b: &[u8]) -> Option<Message> {
        if b.len() < 240 || b[236..240] != MAGIC {
            return None;
        }
        let ip = |at: usize| Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]);
        let mut m = Message {
            op: b[0],
            htype: b[1],
            hlen: b[2],
            xid: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            flags: u16::from_be_bytes([b[10], b[11]]),
            ciaddr: ip(12),
            yiaddr: ip(16),
            siaddr: ip(20),
            giaddr: ip(24),
            chaddr: b[28..44].try_into().unwrap(),
            options: Vec::new(),
        };
        let mut at = 240;
        while at < b.len() {
            let code = b[at];
            match code {
                opt::PAD => at += 1,
                opt::END => break,
                _ => {
                    let len = *b.get(at + 1)? as usize;
                    let value = b.get(at + 2..at + 2 + len)?;
                    match m.options.iter_mut().find(|(c, _)| *c == code) {
                        Some((_, v)) => v.extend_from_slice(value),
                        None => m.options.push((code, value.to_vec())),
                    }
                    at += 2 + len;
                }
            }
        }
        Some(m)
    }

    /// Writes the message as a UDP payload, at least 300 bytes long as
    /// BOOTP clients expect.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[0] = self.op;
        b[1] = self.htype;
        b[2] = self.hlen;
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        b[10..12].copy_from_slice(&self.flags.to_be_bytes());
        b[12..16].copy_from_slice(&self.ciaddr.octets());
        b[16..20].copy_from_slice(&self.yiaddr.octets());
        b[20..24].copy_from_slice(&self.siaddr.octets());
        b[24..28].copy_from_slice(&self.giaddr.octets());
        b[28..44].copy_from_slice(&self.chaddr);
        b[236..240].copy_from_slice(&MAGIC);
        for (code, value) in &self.options {
            // Values longer than 255 bytes go in several entries.
            let mut chunks = value.chunks(255).peekable();
            if chunks.peek().is_none() {
                b.extend_from_slice(&[*code, 0]);
            }
            for chunk in chunks {
                b.push(*code);
                b.push(chunk.len() as u8);
                b.extend_from_slice(chunk);
            }
        }
        b.push(opt::END);
        if b.len() < 300 {
            b.resize(300, opt::PAD);
        }
        b
    }

    /// The value of option `code`.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }

    /// The message type (option 53).
    pub fn message_type(&self) -> Option<u8> {
        match self.option(opt::MESSAGE_TYPE)? {
            [t] => Some(*t),
            _ => None,
        }
    }

    /// An option holding one IPv4 address, such as the requested address.
    pub fn option_addr(&self, code: u8) -> Option<Ipv4Addr> {
        let v: [u8; 4] = self.option(code)?.try_into().ok()?;
        Some(Ipv4Addr::from(v))
    }

    /// An option holding a 32-bit number, such as the lease time.
    pub fn option_u32(&self, code: u8) -> Option<u32> {
        let v: [u8; 4] = self.option(code)?.try_into().ok()?;
        Some(u32::from_be_bytes(v))
    }

    /// Adds an option.
    pub fn push(&mut self, code: u8, value: impl Into<Vec<u8>>) {
        self.options.push((code, value.into()));
    }
}
