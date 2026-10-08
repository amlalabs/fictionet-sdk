//! DHCP messages (RFC 2131 and RFC 2132): reading and writing them, with no
//! I/O. The DHCP server in [`web::Sites`](fictionet::stdlib::web::Sites) uses
//! it, and so does the DHCP server that `fictionet attach --type tap` runs
//! for a VM.
//!
//! `Message` reads and writes complete datagrams through `Wire`. This file
//! supplies no stream decoder, lease state machine, or `Service`. Address
//! assignment and socket handling belong to its callers.

use std::net::Ipv4Addr;

use fictionet::stdlib::codec::Wire;

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

/// The fixed fields and the magic cookie: the shortest message.
pub const MIN_MESSAGE: usize = 240;
/// The longest message: the most a UDP datagram over IPv4 holds.
pub const MAX_MESSAGE: usize = 65_507;
/// Written messages are padded to this length, as BOOTP clients expect.
pub const PADDED_LEN: usize = 300;

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

/// One DHCP message. Fields not kept here (`hops`, `secs`, `sname`,
/// `file`) are read past and written as zeros.
///
/// [`Wire::parse`] reads a whole UDP payload: the fixed fields, the magic
/// cookie, then options up to the end option, after which only padding may
/// follow. A missing end option is allowed. An option whose code appears
/// more than once is joined into one value, as RFC 3396 asks for long
/// options. [`Wire::write`] splits a value longer than 255 bytes the same
/// way, ends the options, and pads the message to [`PADDED_LEN`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// [`BOOTREQUEST`] from a client, [`BOOTREPLY`] from a server.
    pub op: u8,
    /// The hardware address type: 1 for Ethernet.
    pub htype: u8,
    /// The hardware address length: 6 for Ethernet.
    pub hlen: u8,
    /// The transaction ID the client picks, copied into the reply.
    pub xid: u32,
    /// Flags: the top bit asks the server to broadcast its reply.
    pub flags: u16,
    /// The client's address, when it already has one.
    pub ciaddr: Ipv4Addr,
    /// "Your" address: the one the server offers or assigns.
    pub yiaddr: Ipv4Addr,
    /// The next server to use, such as for network boot.
    pub siaddr: Ipv4Addr,
    /// The relay agent's address, when a relay forwarded the message.
    pub giaddr: Ipv4Addr,
    /// The client's hardware address, padded with zeros to 16 bytes.
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

/// Why bytes are not a DHCP message, or why a message cannot be written
/// as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than [`MIN_MESSAGE`].
    Short,
    /// Longer than [`MAX_MESSAGE`], or would be when written; the length
    /// is given.
    TooLong(usize),
    /// The magic cookie is not [`MAGIC`].
    Magic,
    /// An option runs past the end of the message.
    Truncated,
    /// A byte other than padding follows the end option, at this offset.
    Trailing(usize),
    /// An option has code [`opt::PAD`] or [`opt::END`], which carry no
    /// value.
    Reserved(u8),
    /// Two options have this code. They would read back as one.
    Duplicate(u8),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Short => f.write_str("shorter than a DHCP message"),
            Error::TooLong(n) => write!(f, "{n} bytes, longer than a DHCP message may be"),
            Error::Magic => f.write_str("no DHCP magic cookie"),
            Error::Truncated => f.write_str("an option runs past the end of the message"),
            Error::Trailing(at) => write!(f, "byte {at} follows the end option and is not padding"),
            Error::Reserved(c) => write!(f, "option code {c} is padding or the end, not an option"),
            Error::Duplicate(c) => write!(f, "option {c} appears twice"),
        }
    }
}

impl std::error::Error for Error {}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong(b.len()));
        }
        if b.len() < MIN_MESSAGE {
            return Err(Error::Short);
        }
        if b[236..240] != MAGIC {
            return Err(Error::Magic);
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
            chaddr: b[28..44].try_into().expect("16 bytes"),
            options: Vec::new(),
        };
        let mut at = MIN_MESSAGE;
        while at < b.len() {
            let code = b[at];
            match code {
                opt::PAD => at += 1,
                opt::END => {
                    if let Some(i) = b[at + 1..].iter().position(|x| *x != opt::PAD) {
                        return Err(Error::Trailing(at + 1 + i));
                    }
                    break;
                }
                _ => {
                    let len = *b.get(at + 1).ok_or(Error::Truncated)? as usize;
                    let value = b.get(at + 2..at + 2 + len).ok_or(Error::Truncated)?;
                    match m.options.iter_mut().find(|(c, _)| *c == code) {
                        Some((_, v)) => v.extend_from_slice(value),
                        None => m.options.push((code, value.to_vec())),
                    }
                    at += 2 + len;
                }
            }
        }
        Ok(m)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut len = MIN_MESSAGE + 1;
        for (i, (code, value)) in self.options.iter().enumerate() {
            if matches!(*code, opt::PAD | opt::END) {
                return Err(Error::Reserved(*code));
            }
            if self.options[..i].iter().any(|(c, _)| c == code) {
                return Err(Error::Duplicate(*code));
            }
            // Two bytes of code and length for every entry of up to 255.
            len += value.len() + 2 * value.len().div_ceil(255).max(1);
        }
        if len > MAX_MESSAGE {
            return Err(Error::TooLong(len));
        }
        let start = out.len();
        out.resize(start + MIN_MESSAGE, 0);
        let b = &mut out[start..];
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
            if value.is_empty() {
                out.extend_from_slice(&[*code, 0]);
            }
            for chunk in value.chunks(255) {
                out.push(*code);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out.push(opt::END);
        if out.len() - start < PADDED_LEN {
            out.resize(start + PADDED_LEN, opt::PAD);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::test_support::contract::{check_wire, check_wire_value};

    fn discover() -> Message {
        let mut m = Message::new(BOOTREQUEST, 0x1234_5678);
        m.chaddr[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        m.push(opt::MESSAGE_TYPE, [DISCOVER]);
        m.push(opt::REQUESTED_IP, [10, 0, 0, 2]);
        m
    }

    #[test]
    fn a_message_reads_back() {
        let m = discover();
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), PADDED_LEN);
        assert_eq!(&bytes[236..247], &[99, 130, 83, 99, 53, 1, 1, 50, 4, 10, 0]);
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        assert_eq!((m.message_type(), m.option_addr(opt::REQUESTED_IP)), (Some(DISCOVER), Some(Ipv4Addr::new(10, 0, 0, 2))));
        check_wire::<Message>(&bytes);
        check_wire_value(&m);
    }

    /// RFC 3396: an option split over several entries reads as one value,
    /// and a value longer than 255 bytes is written split.
    #[test]
    fn long_options_are_split_and_joined() {
        let mut m = discover();
        m.push(77, (0..600u32).map(|i| i as u8).collect::<Vec<u8>>());
        m.push(12, Vec::new());
        let bytes = m.to_bytes().unwrap();
        // 53, 50, then 77 as 255 + 255 + 90 bytes, then 12 empty, then end.
        let at = MIN_MESSAGE + 3 + 6;
        assert_eq!(&bytes[at..at + 2], &[77, 255]);
        assert_eq!(&bytes[at + 257..at + 259], &[77, 255]);
        assert_eq!(&bytes[at + 514..at + 516], &[77, 90]);
        assert_eq!(&bytes[at + 606..], &[12, 0, opt::END]);
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        check_wire::<Message>(&bytes);
        // Entries of one option apart from each other join too, at the
        // first one's place.
        let mut split = discover().to_bytes().unwrap();
        split.truncate(MIN_MESSAGE);
        split.extend_from_slice(&[6, 4, 1, 1, 1, 1, 53, 1, 3, 6, 4, 8, 8, 8, 8, opt::END]);
        let m = Message::parse(&split).unwrap();
        assert_eq!(m.options, [(6, vec![1, 1, 1, 1, 8, 8, 8, 8]), (53, vec![3])]);
        check_wire::<Message>(&split);
    }

    #[test]
    fn bad_messages_are_refused() {
        let bytes = discover().to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes[..239]), Err(Error::Short));
        let mut magic = bytes.clone();
        magic[236] = 0;
        assert_eq!(Message::parse(&magic), Err(Error::Magic));
        // An option cut short, in its length or its value.
        assert_eq!(Message::parse(&[&bytes[..MIN_MESSAGE], &[53]].concat()), Err(Error::Truncated));
        assert_eq!(Message::parse(&[&bytes[..MIN_MESSAGE], &[53, 2, 1]].concat()), Err(Error::Truncated));
        // No end option is allowed; anything but padding after it is not.
        assert!(Message::parse(&[&bytes[..MIN_MESSAGE], &[53, 1, 1]].concat()).is_ok());
        let mut trailing = bytes.clone();
        trailing[299] = 7;
        assert_eq!(Message::parse(&trailing), Err(Error::Trailing(299)));
        let long = [&bytes[..], &vec![0; MAX_MESSAGE]].concat();
        assert_eq!(Message::parse(&long), Err(Error::TooLong(long.len())));
    }

    #[test]
    fn messages_that_would_read_back_otherwise_are_not_written() {
        let mut out = vec![1, 2, 3];
        for (code, err) in [(opt::PAD, Error::Reserved(0)), (opt::END, Error::Reserved(255)), (53, Error::Duplicate(53))] {
            let mut m = discover();
            m.push(code, [1]);
            assert_eq!(m.write(&mut out), Err(err));
            check_wire_value(&m);
        }
        let mut m = discover();
        m.push(77, vec![0; MAX_MESSAGE]);
        assert!(matches!(m.write(&mut out), Err(Error::TooLong(_))));
        assert_eq!(out, [1, 2, 3]);
        // The longest message that fits is written.
        let mut m = Message::new(BOOTREPLY, 1);
        let room = MAX_MESSAGE - MIN_MESSAGE - 1;
        m.push(77, vec![0; room / 257 * 255 + (room % 257 - 2)]);
        assert_eq!(m.to_bytes().map(|b| b.len()), Ok(MAX_MESSAGE));
        check_wire_value(&m);
    }

    #[test]
    fn every_cut_and_flipped_byte_keeps_the_contract() {
        let mut m = discover();
        m.push(77, vec![9; 300]);
        let bytes = m.to_bytes().unwrap();
        for n in 0..bytes.len() {
            check_wire::<Message>(&bytes[..n]);
        }
        for i in MIN_MESSAGE..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0xff;
            check_wire::<Message>(&b);
        }
    }
}
