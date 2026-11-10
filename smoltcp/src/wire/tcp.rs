use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, ops};

use super::{Error, Result};
use crate::wire::ip::checksum;
use crate::wire::{IpAddress, IpProtocol};

#[cfg(kani)]
#[path = "../../../verification/tcp-port-zero/Wire.rs"]
mod port_proofs;

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo 2<sup>32</sup>.
/// Sequence numbers do not have a discontiguity when compared pairwise across a signed overflow.
/// Pairwise ordering is defined within a half-space; numbers exactly 2^31
/// apart are unordered. Addition and subtraction of lengths require a length
/// smaller than that half-space.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SeqNumber(pub(crate) i32);

impl SeqNumber {
    /// Reads the unsigned bits of a sequence number from a TCP header.
    pub const fn new(bits: u32) -> Self {
        Self(bits as i32)
    }

    /// The unsigned bits to write to a TCP header.
    pub const fn to_bits(self) -> u32 {
        self.0 as u32
    }

    /// The modulo-2^32 offset from an origin, such as the subflow's SYN.
    /// This is a wire offset, not a serial-number ordering comparison.
    pub const fn relative_to(self, origin: Self) -> u32 {
        self.0.wrapping_sub(origin.0) as u32
    }

    /// Resolves a modulo-2^32 wire offset from this origin. Unlike advancing
    /// within a receive window, a subflow offset may span the whole space.
    pub const fn at_offset(self, offset: u32) -> Self {
        Self(self.0.wrapping_add(offset as i32))
    }

    pub(crate) fn max(self, rhs: Self) -> Self {
        if self > rhs { self } else { rhs }
    }

    pub(crate) fn min(self, rhs: Self) -> Self {
        if self < rhs { self } else { rhs }
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl ops::AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl ops::Sub for SeqNumber {
    type Output = usize;

    fn sub(self, rhs: SeqNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        result as usize
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        let distance = self.0.wrapping_sub(other.0);
        (distance != i32::MIN).then(|| distance.cmp(&0))
    }
}

/// A read/write wrapper around a Transmission Control Protocol packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub(super) const SRC_PORT: Field = 0..2;
    pub(super) const DST_PORT: Field = 2..4;
    pub(super) const SEQ_NUM: Field = 4..8;
    pub(super) const ACK_NUM: Field = 8..12;
    pub(super) const FLAGS: Field = 12..14;
    pub(super) const WIN_SIZE: Field = 14..16;
    pub(super) const CHECKSUM: Field = 16..18;
    pub(super) const URGENT: Field = 18..20;

    pub(crate) const fn OPTIONS(length: u8) -> Field {
        URGENT.end..(length as usize)
    }

    pub(super) const FLG_FIN: u16 = 0x001;
    pub(super) const FLG_SYN: u16 = 0x002;
    pub(super) const FLG_RST: u16 = 0x004;
    pub(super) const FLG_PSH: u16 = 0x008;
    pub(super) const FLG_ACK: u16 = 0x010;
    pub(super) const FLG_ECE: u16 = 0x040;
    pub(super) const FLG_CWR: u16 = 0x080;
    pub(super) const FLG_NS: u16 = 0x100;

    pub(super) const OPT_END: u8 = 0x00;
    pub(super) const OPT_NOP: u8 = 0x01;
    pub(super) const OPT_MSS: u8 = 0x02;
    pub(super) const OPT_WS: u8 = 0x03;
    pub(super) const OPT_SACKPERM: u8 = 0x04;
    pub(super) const OPT_SACKRNG: u8 = 0x05;
    pub(super) const OPT_TSTAMP: u8 = 0x08;
}

pub(crate) const HEADER_LEN: usize = field::URGENT.end;

/// The most option bytes a header holds. The data offset counts 32-bit
/// words in four bits, so a header is at most 60 bytes (RFC 9293 section
/// 3.1), and the fixed part takes 20 of them.
pub const OPTIONS_MAX_LEN: usize = 40;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with TCP packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the header length field has a value smaller
    /// than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub(crate) fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::URGENT.end {
            Err(Error)
        } else {
            let header_len = self.header_len() as usize;
            if len < header_len || header_len < field::URGENT.end {
                Err(Error)
            } else {
                Ok(())
            }
        }
    }

    /// Return the source port field.
    #[inline]
    pub(crate) fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub(crate) fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT])
    }

    /// Return the sequence number field.
    #[inline]
    pub(crate) fn seq_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::SEQ_NUM]))
    }

    /// Return the acknowledgement number field.
    #[inline]
    pub(crate) fn ack_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::ACK_NUM]))
    }

    /// Return the FIN flag.
    #[inline]
    pub(crate) fn fin(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_FIN != 0
    }

    /// Return the SYN flag.
    #[inline]
    pub(crate) fn syn(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_SYN != 0
    }

    /// Return the RST flag.
    #[inline]
    pub(crate) fn rst(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_RST != 0
    }

    /// Return the PSH flag.
    #[inline]
    pub(crate) fn psh(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_PSH != 0
    }

    /// Return the ACK flag.
    #[inline]
    pub(crate) fn ack(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ACK != 0
    }

    /// Return the ECE flag.
    #[inline]
    pub fn ece(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ECE != 0
    }

    /// Return the CWR flag.
    #[inline]
    pub fn cwr(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_CWR != 0
    }

    /// Return the NS flag.
    #[inline]
    pub fn ns(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_NS != 0
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        ((raw >> 12) * 4) as u8
    }

    /// Return the window size field.
    #[inline]
    pub(crate) fn window_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::WIN_SIZE])
    }

    /// Parse and summarize all TCP options in a single pass.
    pub fn options_summary(&self) -> Result<TcpOptionSummary> {
        let data = self.buffer.as_ref();
        let mut options = &data[field::OPTIONS(self.header_len())];
        let mut summary = TcpOptionSummary::default();
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => {}
                TcpOption::MaxSegmentSize(mss) => summary.max_segment_size = Some(mss),
                TcpOption::WindowScale(ws) => summary.window_scale = Some(ws),
                TcpOption::SackPermitted => summary.sack_permitted = true,
                TcpOption::SackRange([first, second, third, _]) => {
                    summary.sack_ranges = [first, second, third]
                }
                TcpOption::TimeStamp { tsval, tsecr } => summary.timestamp = Some((tsval, tsecr)),
                TcpOption::Unknown { .. } => {}
            }
            options = next_options;
        }
        Ok(summary)
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub(crate) fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
            checksum::data(data),
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let header_len = self.header_len();
        let data = self.buffer.as_ref();
        &data[field::OPTIONS(header_len)]
    }

    /// Return the options, in the order they appear, unknown kinds
    /// included. Fails if the buffer is shorter than the fixed header or
    /// the header length field says, or that field is under 20.
    pub fn options_iter(&self) -> Result<TcpOptions<'a>> {
        self.check_len()?;
        Ok(TcpOptions::new(self.options()))
    }

    /// Return a pointer to the payload.
    #[inline]
    pub(crate) fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[header_len..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the source port field.
    #[inline]
    pub(crate) fn set_src_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SRC_PORT], value)
    }

    /// Set the destination port field.
    #[inline]
    pub(crate) fn set_dst_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value)
    }

    /// Set the sequence number field.
    #[inline]
    pub(crate) fn set_seq_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::SEQ_NUM], value.0)
    }

    /// Set the acknowledgement number field.
    #[inline]
    pub(crate) fn set_ack_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::ACK_NUM], value.0)
    }

    /// Clear the entire flags field.
    #[inline]
    pub(crate) fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = raw & !0x0fff;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the FIN flag.
    #[inline]
    pub(crate) fn set_fin(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_FIN
        } else {
            raw & !field::FLG_FIN
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the SYN flag.
    #[inline]
    pub(crate) fn set_syn(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_SYN
        } else {
            raw & !field::FLG_SYN
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the RST flag.
    #[inline]
    pub(crate) fn set_rst(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_RST
        } else {
            raw & !field::FLG_RST
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the PSH flag.
    #[inline]
    pub(crate) fn set_psh(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_PSH
        } else {
            raw & !field::FLG_PSH
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ACK flag.
    #[inline]
    pub(crate) fn set_ack(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_ACK
        } else {
            raw & !field::FLG_ACK
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ECE flag.
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_ECE
        } else {
            raw & !field::FLG_ECE
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the CWR flag.
    #[inline]
    pub fn set_cwr(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_CWR
        } else {
            raw & !field::FLG_CWR
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the NS flag.
    #[inline]
    pub fn set_ns(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value {
            raw | field::FLG_NS
        } else {
            raw & !field::FLG_NS
        };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the header length, in octets.
    #[inline]
    pub(crate) fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = (raw & !0xf000) | ((value as u16) / 4) << 12;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the window size field.
    #[inline]
    pub(crate) fn set_window_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::WIN_SIZE], value)
    }

    /// Set the checksum field.
    #[inline]
    pub(crate) fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the urgent pointer field.
    #[inline]
    pub(crate) fn set_urgent_at(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::URGENT], value)
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub(crate) fn fill_checksum(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a pointer to the options.
    #[inline]
    pub(crate) fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        let data = self.buffer.as_mut();
        &mut data[field::OPTIONS(header_len)]
    }

    /// Return a mutable pointer to the payload data.
    #[inline]
    pub(crate) fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[header_len..]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A summary of all standard options contained in a TCP header.
#[non_exhaustive]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct TcpOptionSummary {
    pub max_segment_size: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_ranges: [Option<(u32, u32)>; 3],
    pub timestamp: Option<(u32, u32)>,
}

/// A representation of a single TCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption<'a> {
    /// End of Option List: kind 0, one byte.
    EndOfList,
    /// No-Operation: kind 1, one byte.
    NoOperation,
    /// Maximum Segment Size: kind 2 (RFC 9293).
    MaxSegmentSize(u16),
    /// Window Scale: kind 3 (RFC 7323).
    WindowScale(u8),
    /// SACK-Permitted: kind 4 (RFC 2018).
    SackPermitted,
    /// SACK: kind 5 (RFC 2018). The 40 option bytes hold at most four blocks.
    SackRange([Option<(u32, u32)>; 4]),
    /// Timestamps: kind 8 (RFC 7323).
    TimeStamp { tsval: u32, tsecr: u32 },
    /// Any other kind, or a known kind with a Length its RFC does not
    /// define: the bytes after Kind and Length. Linux ignores those
    /// (tcp_parse_options), and so does [`Repr::parse`].
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
    /// Reads the first option, returning the remaining bytes and its value.
    /// End of Option List consumes one byte; the remainder is padding.
    /// Fails if the option's length is missing, under two, or exceeds the buffer.
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>)> {
        let (length, option);
        match *buffer.first().ok_or(Error)? {
            field::OPT_END => {
                length = 1;
                option = TcpOption::EndOfList;
            }
            field::OPT_NOP => {
                length = 1;
                option = TcpOption::NoOperation;
            }
            kind => {
                length = *buffer.get(1).ok_or(Error)? as usize;
                let data = buffer.get(2..length).ok_or(Error)?;
                match (kind, length) {
                    (field::OPT_END, _) | (field::OPT_NOP, _) => unreachable!(),
                    (field::OPT_MSS, 4) => {
                        option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data))
                    }
                    (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
                    (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
                    (field::OPT_SACKRNG, n) if n >= 10 && (n - 2) % 8 == 0 => {
                        // Four blocks fill the option space; Repr keeps the first three.
                        let mut sack_ranges: [Option<(u32, u32)>; 4] = [None; 4];

                        sack_ranges.iter_mut().enumerate().for_each(|(i, nmut)| {
                            let left = i * 8;
                            *nmut = if left < data.len() {
                                let mid = left + 4;
                                let right = mid + 4;
                                let range_left = NetworkEndian::read_u32(&data[left..mid]);
                                let range_right = NetworkEndian::read_u32(&data[mid..right]);
                                Some((range_left, range_right))
                            } else {
                                None
                            };
                        });
                        option = TcpOption::SackRange(sack_ranges);
                    }
                    (field::OPT_TSTAMP, 10) => {
                        let tsval = NetworkEndian::read_u32(&data[0..4]);
                        let tsecr = NetworkEndian::read_u32(&data[4..8]);
                        option = TcpOption::TimeStamp { tsval, tsecr };
                    }
                    (_, _) => option = TcpOption::Unknown { kind, data },
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    pub(crate) fn buffer_len(&self) -> usize {
        match *self {
            TcpOption::EndOfList => 1,
            TcpOption::NoOperation => 1,
            TcpOption::MaxSegmentSize(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::SackRange(s) => s.iter().filter(|s| s.is_some()).count() * 8 + 2,
            TcpOption::TimeStamp { tsval: _, tsecr: _ } => 10,
            TcpOption::Unknown { data, .. } => 2 + data.len(),
        }
    }

    pub(crate) fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match *self {
            TcpOption::EndOfList => {
                length = 1;
                // There may be padding space which also should be initialized.
                for p in buffer.iter_mut() {
                    *p = field::OPT_END;
                }
            }
            TcpOption::NoOperation => {
                length = 1;
                buffer[0] = field::OPT_NOP;
            }
            _ => {
                length = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &TcpOption::EndOfList | &TcpOption::NoOperation => unreachable!(),
                    &TcpOption::MaxSegmentSize(value) => {
                        buffer[0] = field::OPT_MSS;
                        NetworkEndian::write_u16(&mut buffer[2..], value)
                    }
                    &TcpOption::WindowScale(value) => {
                        buffer[0] = field::OPT_WS;
                        buffer[2] = value;
                    }
                    &TcpOption::SackPermitted => {
                        buffer[0] = field::OPT_SACKPERM;
                    }
                    &TcpOption::SackRange(slice) => {
                        buffer[0] = field::OPT_SACKRNG;
                        slice
                            .iter()
                            .filter(|s| s.is_some())
                            .enumerate()
                            .for_each(|(i, s)| {
                                let (first, second) = *s.as_ref().unwrap();
                                let pos = i * 8 + 2;
                                NetworkEndian::write_u32(&mut buffer[pos..], first);
                                NetworkEndian::write_u32(&mut buffer[pos + 4..], second);
                            });
                    }
                    &TcpOption::TimeStamp { tsval, tsecr } => {
                        buffer[0] = field::OPT_TSTAMP;
                        NetworkEndian::write_u32(&mut buffer[2..], tsval);
                        NetworkEndian::write_u32(&mut buffer[6..], tsecr);
                    }
                    &TcpOption::Unknown {
                        kind,
                        data: provided,
                    } => {
                        buffer[0] = kind;
                        buffer[2..length].copy_from_slice(provided)
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// The options of one header, in order. Ends at End of Option List or at
/// the end of the option space, and after the first malformed option,
/// which it returns as an error.
#[derive(Debug, Clone)]
pub struct TcpOptions<'a> {
    rest: &'a [u8],
}

impl<'a> TcpOptions<'a> {
    /// The options in `area`, a TCP header's option space.
    pub fn new(area: &'a [u8]) -> TcpOptions<'a> {
        TcpOptions { rest: area }
    }
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = Result<TcpOption<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match TcpOption::parse(self.rest) {
            Ok((_, TcpOption::EndOfList)) => {
                self.rest = &[];
                None
            }
            Ok((rest, option)) => {
                self.rest = rest;
                Some(Ok(option))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// The possible control flags of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Control {
    None,
    Psh,
    Syn,
    Fin,
    Rst,
}

#[allow(clippy::len_without_is_empty)]
impl Control {
    /// Return the length of a control flag, in terms of sequence space.
    pub(crate) const fn len(self) -> usize {
        match self {
            Control::Syn | Control::Fin => 1,
            _ => 0,
        }
    }

    /// Turn the PSH flag into no flag, and keep the rest as-is.
    pub(crate) const fn quash_psh(self) -> Control {
        match self {
            Control::Psh => Control::None,
            _ => self,
        }
    }
}

/// Ordering of the standard TCP options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OptionOrder {
    /// MSS, Window Scale, SACK, Timestamps.
    #[default]
    WindowBeforeSack,
    /// MSS, SACK, Timestamps, Window Scale.
    WindowAfterTimestamp,
}

/// Placement and padding of TCP options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OptionLayout {
    /// Ordering of the standard options.
    pub order: OptionOrder,
    /// Align option groups to four bytes with leading No-Operations.
    pub align: bool,
}

/// Whether [`Repr::parse_with`] checks a segment's checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sum {
    /// Check it, as for every segment from outside the process.
    Check,
    /// A stack in this process computed or checked it, and nothing has
    /// changed a byte since: the packet says so, and only the stack can.
    Verified,
}

/// A high-level representation of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) control: Control,
    pub(crate) seq_number: SeqNumber,
    pub(crate) ack_number: Option<SeqNumber>,
    pub(crate) window_len: u16,
    pub(crate) window_scale: Option<u8>,
    pub(crate) max_seg_size: Option<u16>,
    pub(crate) sack_permitted: bool,
    pub(crate) sack_ranges: [Option<(u32, u32)>; 3],
    pub(crate) timestamp: Option<TcpTimestampRepr>,
    /// Options emitted after the ones above, already encoded: whole
    /// options, with no End of Option List. [`Repr::parse`] leaves this
    /// empty; [`Packet::options_iter`] reads every option of a segment.
    pub(crate) extra: &'a [u8],
    pub(crate) layout: OptionLayout,
    pub payload: &'a [u8],
}

/// Produces a TCP timestamp from the stack clock.
pub type TcpTimestampGenerator = fn(crate::time::Instant) -> u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct TcpTimestampRepr {
    pub(crate) tsval: u32,
    pub(crate) tsecr: u32,
}

impl TcpTimestampRepr {
    pub(crate) fn new(tsval: u32, tsecr: u32) -> Self {
        Self { tsval, tsecr }
    }

    pub(crate) fn generate_reply_with_tsval(
        generator: Option<TcpTimestampGenerator>,
        tsval: u32,
        now: crate::time::Instant,
    ) -> Option<Self> {
        Some(Self::new(generator?(now), tsval))
    }
}

impl<'a> Repr<'a> {
    /// This segment with `extra` options and `payload` in place of its own,
    /// borrowing nothing of it.
    pub(crate) fn with_parts<'b>(&self, extra: &'b [u8], payload: &'b [u8]) -> Repr<'b> {
        Repr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            control: self.control,
            seq_number: self.seq_number,
            ack_number: self.ack_number,
            window_len: self.window_len,
            window_scale: self.window_scale,
            max_seg_size: self.max_seg_size,
            sack_permitted: self.sack_permitted,
            sack_ranges: self.sack_ranges,
            timestamp: self.timestamp,
            extra,
            layout: self.layout,
            payload,
        }
    }

    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Self::parse_with(packet, src_addr, dst_addr, false, Sum::Check)
    }

    /// Parses a segment, optionally keeping the valid prefix of a malformed
    /// list. Its checksum is checked unless `sum` says a stack in this
    /// process verified it and nothing changed the bytes since.
    pub fn parse_with<T>(
        packet: &Packet<&'a T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        ignore_malformed: bool,
        sum: Sum,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        // Valid checksum is expected.
        if sum == Sum::Check && !packet.verify_checksum(src_addr, dst_addr) {
            return Err(Error);
        }

        // RFC 9293 processes RST before SYN or FIN.
        let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
            (false, false, false, false) => Control::None,
            (false, false, false, true) => Control::Psh,
            (true, false, false, _) => Control::Syn,
            (false, true, false, _) => Control::Fin,
            (_, _, true, _) => Control::Rst,
            _ => return Err(Error),
        };
        let ack_number = match packet.ack() {
            true => Some(packet.ack_number()),
            false => None,
        };
        // Urgent data stays in the byte stream.

        let mut max_seg_size = None;
        let mut window_scale = None;
        let mut options = packet.options();
        let mut sack_permitted = false;
        let mut sack_ranges = [None, None, None];
        let mut timestamp = None;
        while !options.is_empty() {
            let (next_options, option) = match TcpOption::parse(options) {
                Ok(parsed) => parsed,
                Err(_) if ignore_malformed => break,
                Err(error) => return Err(error),
            };
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => max_seg_size = Some(value),
                TcpOption::WindowScale(value) => {
                    // RFC 7323 limits the window scale to 14.
                    window_scale = Some(value.min(14));
                }
                TcpOption::SackPermitted => sack_permitted = true,
                TcpOption::SackRange([first, second, third, _]) => {
                    sack_ranges = [first, second, third]
                }
                TcpOption::TimeStamp { tsval, tsecr } => {
                    timestamp = Some(TcpTimestampRepr::new(tsval, tsecr));
                }
                // The socket has no use for them; `Packet::options_iter` has them.
                TcpOption::Unknown { .. } => (),
            }
            options = next_options;
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len: packet.window_len(),
            window_scale,
            max_seg_size,
            sack_permitted,
            sack_ranges,
            timestamp,
            extra: &[],
            layout: crate::wire::OptionLayout {
                order: crate::wire::OptionOrder::WindowBeforeSack,
                align: false,
            },
            payload: packet.payload(),
        })
    }

    /// How many SACK blocks `emit` writes: those of an ACK whose segment
    /// does not offer SACK-Permitted.
    fn sack_blocks(&self) -> usize {
        if self.sack_permitted || self.ack_number.is_none() {
            return 0;
        }
        self.sack_ranges.iter().flatten().count()
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// This should be used for buffer space calculations.
    /// The TCP header length is a multiple of 4.
    pub(crate) fn header_len(&self) -> usize {
        let mut bytes = [0; OPTIONS_MAX_LEN];
        HEADER_LEN + self.emit_options(&mut bytes)
    }

    fn emit_options(&self, bytes: &mut [u8; OPTIONS_MAX_LEN]) -> usize {
        let mut rest = &mut bytes[..];
        let mut put = |option: TcpOption, align: bool| {
            if align {
                for _ in 0..(4 - option.buffer_len() % 4) % 4 {
                    let tmp = core::mem::take(&mut rest);
                    rest = TcpOption::NoOperation.emit(tmp);
                }
            }
            let tmp = core::mem::take(&mut rest);
            rest = option.emit(tmp);
        };
        if let Some(mss) = self.max_seg_size {
            put(TcpOption::MaxSegmentSize(mss), false);
        }
        if self.layout.order == OptionOrder::WindowBeforeSack
            && let Some(scale) = self.window_scale
        {
            put(TcpOption::WindowScale(scale), self.layout.align);
        }
        if self.sack_permitted {
            put(
                TcpOption::SackPermitted,
                self.layout.align && self.timestamp.is_none(),
            );
        }
        if let Some(ts) = self.timestamp {
            put(
                TcpOption::TimeStamp {
                    tsval: ts.tsval,
                    tsecr: ts.tsecr,
                },
                self.layout.align && !self.sack_permitted,
            );
        }
        if self.layout.order == OptionOrder::WindowAfterTimestamp
            && let Some(scale) = self.window_scale
        {
            put(TcpOption::WindowScale(scale), self.layout.align);
        }
        if self.sack_blocks() > 0 {
            let [a, b, c] = self.sack_ranges;
            put(TcpOption::SackRange([a, b, c, None]), self.layout.align);
        }
        let (extra, tail) = rest.split_at_mut(self.extra.len());
        extra.copy_from_slice(self.extra);
        let length = OPTIONS_MAX_LEN - tail.len();
        let padded = (length + 3) & !3;
        tail[..padded - length].fill(0);
        padded
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub(crate) fn buffer_len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>, src_addr: &IpAddress, dst_addr: &IpAddress)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(SeqNumber(0)));
        packet.set_window_len(self.window_len);
        // The data offset holds no more; sockets keep their options within it.
        debug_assert!(self.header_len() <= HEADER_LEN + OPTIONS_MAX_LEN);
        packet.set_header_len(self.header_len() as u8);
        packet.clear_flags();
        match self.control {
            Control::None => (),
            Control::Psh => packet.set_psh(true),
            Control::Syn => packet.set_syn(true),
            Control::Fin => packet.set_fin(true),
            Control::Rst => packet.set_rst(true),
        }
        packet.set_ack(self.ack_number.is_some());
        {
            let mut bytes = [0; OPTIONS_MAX_LEN];
            let len = self.emit_options(&mut bytes);
            packet.options_mut().copy_from_slice(&bytes[..len]);
        }

        packet.set_urgent_at(0);
        packet.payload_mut()[..self.payload.len()].copy_from_slice(self.payload);

        packet.fill_checksum(src_addr, dst_addr)
    }

    /// Return the length of the segment, in terms of sequence space.
    pub(crate) const fn segment_len(&self) -> usize {
        self.payload.len() + self.control.len()
    }

    /// Return whether the segment has no flags set (except PSH) and no data.
    pub(crate) const fn is_empty(&self) -> bool {
        match self.control {
            _ if !self.payload.is_empty() => false,
            Control::Syn | Control::Fin | Control::Rst => false,
            Control::None | Control::Psh => true,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::wire::Ipv4Address;

    #[test]
    fn serial_order_wraps_but_does_not_order_opposite_numbers() {
        let zero = SeqNumber::new(0);
        let last = SeqNumber::new(u32::MAX);
        let half = SeqNumber::new(1 << 31);
        assert_eq!(last + 1, zero);
        assert!(last < zero);
        assert!(zero > last);
        assert_eq!(zero.partial_cmp(&half), None);
        assert_eq!(half.partial_cmp(&zero), None);
        assert_eq!(last.at_offset(2), SeqNumber::new(1));
        assert_eq!(SeqNumber::new(1).relative_to(last), 2);
    }

    const SRC_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);

    const DST_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    static PACKET_BYTES: [u8; 28] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x60, 0x35, 0x01,
        0x23, 0x01, 0xb6, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01, 0xaa, 0x00, 0x00, 0xff,
    ];

    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_parse_reset_with_other_control_flags() {
        for flags in [0x04, 0x05, 0x06, 0x07, 0x3f] {
            let mut bytes = SYN_PACKET_BYTES;
            bytes[13] = flags;
            Packet::new_unchecked(&mut bytes).fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
            let packet = Packet::new_checked(&bytes).unwrap();
            let repr = Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).unwrap();
            assert_eq!(repr.control, Control::Rst, "flags {flags:#x}");
        }
    }

    #[test]
    fn test_unknown_option_emit_preserves_following_options() {
        let option = TcpOption::parse(&[30, 4, 0xab, 0xcd]).unwrap().1;
        let mut bytes = [0xa5; 8];
        let rest = option.emit(&mut bytes);
        assert_eq!(rest, [0xa5; 4]);
        TcpOption::MaxSegmentSize(1460).emit(rest);
        assert_eq!(bytes, [30, 4, 0xab, 0xcd, 2, 4, 5, 0xb4]);
    }

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), SeqNumber(0x01234567));
        assert_eq!(packet.ack_number(), SeqNumber(0x89abcdefu32 as i32));
        assert_eq!(packet.header_len(), 24);
        assert!(packet.fin());
        assert!(!packet.syn());
        assert!(packet.rst());
        assert!(!packet.psh());
        assert!(packet.ack());
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.options(), &OPTION_BYTES[..]);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; PACKET_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(80);
        packet.set_seq_number(SeqNumber(0x01234567));
        packet.set_ack_number(SeqNumber(0x89abcdefu32 as i32));
        packet.set_header_len(24);
        packet.clear_flags();
        packet.set_fin(true);
        packet.set_syn(false);
        packet.set_rst(true);
        packet.set_psh(false);
        packet.set_ack(true);
        packet.buffer[13] |= 0x20;
        packet.set_window_len(0x0123);
        packet.set_urgent_at(0x0201);
        packet.set_checksum(0xEEEE);
        packet.options_mut().copy_from_slice(&OPTION_BYTES[..]);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&bytes[..], &PACKET_BYTES[..]);
    }

    #[test]
    fn test_truncated() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..23]);
        assert_eq!(packet.check_len(), Err(Error));
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 20];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(10);
        assert_eq!(packet.check_len(), Err(Error));
    }

    static SYN_PACKET_BYTES: [u8; 24] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01,
        0x23, 0x7a, 0x8d, 0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    fn packet_repr() -> Repr<'static> {
        Repr {
            src_port: 48896,
            dst_port: 80,
            seq_number: SeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            window_scale: None,
            control: Control::Syn,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            extra: &[],
            layout: crate::wire::OptionLayout {
                order: crate::wire::OptionOrder::WindowBeforeSack,
                align: false,
            },
            timestamp: None,
            payload: &PAYLOAD_BYTES,
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&SYN_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet, &SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&bytes[..], &SYN_PACKET_BYTES[..]);
    }

    #[test]
    fn test_header_len_multiple_of_4() {
        let mut repr = packet_repr();
        repr.window_scale = Some(0);
        assert_eq!(repr.header_len(), 24);
        let mut bytes = vec![0xa5; repr.buffer_len()];
        repr.emit(
            &mut Packet::new_unchecked(&mut bytes),
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
        );
        let packet = Packet::new_checked(&bytes).unwrap();
        assert_eq!(packet.options(), &[3, 3, 0, 0]);
        assert_eq!(
            Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()),
            Ok(repr)
        );
    }

    /// Default options have no internal padding and end on a word boundary.
    #[test]
    fn test_default_options_use_compact_layout() {
        let timestamp = Some(TcpTimestampRepr {
            tsval: 0x0102_0304,
            tsecr: 0x0506_0708,
        });
        let options = |repr: &Repr| {
            let mut bytes = vec![0xa5; repr.buffer_len()];
            repr.emit(
                &mut Packet::new_unchecked(&mut bytes),
                &SRC_ADDR.into(),
                &DST_ADDR.into(),
            );
            let packet = Packet::new_checked(&bytes).unwrap();
            assert_eq!(
                Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()),
                Ok(*repr)
            );
            packet.options().to_vec()
        };
        let syn_ack = Repr {
            ack_number: Some(SeqNumber(1)),
            max_seg_size: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamp,
            payload: &[],
            ..packet_repr()
        };
        assert_eq!(
            options(&syn_ack),
            [
                2, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0
            ]
        );
        let no_timestamps = Repr {
            timestamp: None,
            ..syn_ack
        };
        assert_eq!(
            options(&no_timestamps),
            [2, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 0, 0, 0]
        );
        let segment = Repr {
            control: Control::None,
            max_seg_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_ranges: [Some((10, 20)), None, None],
            ..syn_ack
        };
        assert_eq!(
            options(&segment),
            [
                8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 5, 10, 0, 0, 0, 10, 0, 0, 0, 20
            ]
        );
    }

    macro_rules! assert_option_parses {
        ($opt:expr, $data:expr) => {{
            assert_eq!(TcpOption::parse($data), Ok((&[][..], $opt)));
            let buffer = &mut [0; 40][..$opt.buffer_len()];
            assert_eq!($opt.emit(buffer), &mut []);
            assert_eq!(&*buffer, $data);
        }};
    }

    #[test]
    fn test_tcp_options() {
        assert_option_parses!(TcpOption::EndOfList, &[0x00]);
        assert_option_parses!(TcpOption::NoOperation, &[0x01]);
        assert_option_parses!(TcpOption::MaxSegmentSize(1500), &[0x02, 0x04, 0x05, 0xdc]);
        assert_option_parses!(TcpOption::WindowScale(12), &[0x03, 0x03, 0x0c]);
        assert_option_parses!(TcpOption::SackPermitted, &[0x4, 0x02]);
        assert_option_parses!(
            TcpOption::SackRange([Some((500, 1500)), None, None, None]),
            &[0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc]
        );
        assert_option_parses!(
            TcpOption::SackRange([Some((875, 1225)), Some((1500, 2500)), None, None]),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc,
                0x00, 0x00, 0x09, 0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((875000, 1225000)),
                Some((1500000, 2500000)),
                Some((876543210, 876654320)),
                None
            ]),
            &[
                0x05, 0x1a, 0x00, 0x0d, 0x59, 0xf8, 0x00, 0x12, 0xb1, 0x28, 0x00, 0x16, 0xe3, 0x60,
                0x00, 0x26, 0x25, 0xa0, 0x34, 0x3e, 0xfc, 0xea, 0x34, 0x40, 0xae, 0xf0
            ]
        );
        assert_option_parses!(
            TcpOption::TimeStamp {
                tsval: 5000000,
                tsecr: 7000000
            },
            &[
                0x08, // data length
                0x0a, // type
                0x00, 0x4c, 0x4b, 0x40, //tsval
                0x00, 0x6a, 0xcf, 0xc0 //tsecr
            ]
        );
        assert_option_parses!(
            TcpOption::Unknown {
                kind: 12,
                data: &[1, 2, 3][..]
            },
            &[0x0c, 0x05, 0x01, 0x02, 0x03]
        )
    }

    #[test]
    fn test_malformed_tcp_options() {
        assert_eq!(TcpOption::parse(&[]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc, 0x05, 0x01, 0x02]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc, 0x01]), Err(Error));
        assert_eq!(TcpOption::parse(&[0x2, 0x00]), Err(Error));
    }

    /// A known kind with a Length its RFC does not define reads as
    /// unknown, which Linux ignores: MSS other than 4, Window Scale other
    /// than 3, SACK-Permitted other than 2, SACK that is not whole blocks,
    /// and Timestamps other than 10.
    #[test]
    fn test_known_kinds_of_other_lengths_are_unknown() {
        for bytes in [
            &[2, 2][..],
            &[2, 3, 5],
            &[2, 5, 5, 0xb4, 0],
            &[3, 2],
            &[3, 4, 7, 0],
            &[4, 3, 0],
            &[5, 2],
            &[5, 9, 0, 0, 0, 1, 0, 0, 0],
            &[5, 11, 0, 0, 0, 1, 0, 0, 0, 2, 0],
            &[8, 9, 0, 0, 0, 1, 0, 0, 0],
        ] {
            assert_eq!(
                TcpOption::parse(bytes),
                Ok((
                    &[][..],
                    TcpOption::Unknown {
                        kind: bytes[0],
                        data: &bytes[2..]
                    }
                )),
                "{bytes:?}"
            );
        }
    }

    /// Malformed option lists are rejected unless prefix parsing is requested.
    #[test]
    fn test_repr_stops_at_a_malformed_option() {
        let options = [2, 4, 5, 0xb4, 3, 2, 30, 12, 0x01, 0x81, 0, 0];
        let mut bytes = vec![0; 20 + options.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(2);
        packet.set_header_len(20 + options.len() as u8);
        packet.set_syn(true);
        packet.options_mut().copy_from_slice(&options);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        let packet = Packet::new_unchecked(&bytes[..]);
        assert!(Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).is_err());
        let repr = Repr::parse_with(
            &packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            true,
            Sum::Check,
        )
        .unwrap();
        assert_eq!(repr.control, Control::Syn);
        assert_eq!(repr.max_seg_size, Some(1460));
        assert_eq!(repr.window_scale, None);
    }

    #[test]
    fn test_four_sack_blocks() {
        let mut bytes = vec![5, 34];
        for n in 1..=8u32 {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
        assert_option_parses!(
            TcpOption::SackRange([Some((1, 2)), Some((3, 4)), Some((5, 6)), Some((7, 8))]),
            &bytes[..]
        );
    }

    /// A SYN as Linux sends it with MPTCP, then End of Option List and
    /// padding that is not read.
    #[test]
    fn test_options_iter_keeps_unknown_kinds() {
        let options = [
            2, 4, 5, 0xb4, 4, 2, 1, 3, 3, 7, 30, 4, 0x01, 0x81, 1, 0, 30, 2, 0xff, 0xff,
        ];
        let mut bytes = vec![0; 20 + options.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(40);
        packet.options_mut().copy_from_slice(&options);
        let packet = Packet::new_unchecked(&bytes[..]);
        let read: Vec<_> = packet.options_iter().unwrap().collect();
        assert_eq!(
            read,
            [
                Ok(TcpOption::MaxSegmentSize(1460)),
                Ok(TcpOption::SackPermitted),
                Ok(TcpOption::NoOperation),
                Ok(TcpOption::WindowScale(7)),
                Ok(TcpOption::Unknown {
                    kind: 30,
                    data: &[0x01, 0x81]
                }),
                Ok(TcpOption::NoOperation),
            ]
        );
    }

    #[test]
    fn test_options_iter_ends_at_a_malformed_option() {
        let mut bytes = vec![0; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(28);
        packet
            .options_mut()
            .copy_from_slice(&[1, 30, 9, 0, 0, 1, 1, 1]);
        let packet = Packet::new_unchecked(&bytes[..]);
        let read: Vec<_> = packet.options_iter().unwrap().collect();
        assert_eq!(read, [Ok(TcpOption::NoOperation), Err(Error)]);
    }

    #[test]
    fn test_options_iter_checks_the_header_length() {
        for len in 0..64 {
            for offset in 0..16u8 {
                let mut bytes = vec![0; len.max(20)];
                Packet::new_unchecked(&mut bytes).set_header_len(offset * 4);
                bytes.truncate(len);
                let packet = Packet::new_unchecked(&bytes[..]);
                let fits = len >= 20 && (5..=len / 4).contains(&(offset as usize));
                assert_eq!(packet.options_iter().is_ok(), fits, "{len} {offset}");
            }
        }
    }

    /// The bytes of a header with every option area a peer can send: no
    /// parse panics, at most one option fails to read, and `Repr::parse`
    /// rejects malformed lists while prefix parsing retains their valid options.
    #[test]
    fn test_hostile_option_areas() {
        fn check(options: &[u8]) {
            let mut bytes = vec![0; 20 + options.len()];
            let mut packet = Packet::new_unchecked(&mut bytes);
            packet.set_src_port(1);
            packet.set_dst_port(2);
            packet.set_header_len(20 + options.len() as u8);
            packet.set_syn(true);
            packet.options_mut().copy_from_slice(options);
            packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
            let packet = Packet::new_unchecked(&bytes[..]);
            let read: Vec<_> = packet.options_iter().unwrap().collect();
            let repr = Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into());
            assert_eq!(repr.is_ok(), read.iter().all(Result::is_ok), "{options:?}");
            assert!(
                Repr::parse_with(
                    &packet,
                    &SRC_ADDR.into(),
                    &DST_ADDR.into(),
                    true,
                    Sum::Check
                )
                .is_ok()
            );
            assert!(read.iter().filter(|o| o.is_err()).count() <= 1);
            let _ = packet.options_summary();
        }
        // Every kind and length at the start of a full option area, with
        // the rest of the area all zeros and all ones.
        for kind in 0..=255u8 {
            for length in 0..=255u8 {
                for fill in [0, 0xff] {
                    let mut options = [fill; OPTIONS_MAX_LEN];
                    options[0] = kind;
                    options[1] = length;
                    check(&options);
                }
            }
        }
        // Random areas of every length that fits the data offset.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        for _ in 0..20_000 {
            let len = 4 * (next() as usize % 11);
            let options: Vec<u8> = (0..len)
                .map(|_| match next() % 4 {
                    // Small values make plausible kinds and lengths.
                    0 => next() % 12,
                    1 => 30,
                    _ => next(),
                })
                .collect();
            check(&options);
        }
    }

    /// Extra options go after the standard ones and count in the header
    /// length, which stays a multiple of four.
    #[test]
    fn test_extra_options_emit() {
        let extra = [1, 30, 12, 0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8];
        for (repr, header_len) in [
            (
                Repr {
                    extra: &extra,
                    ..packet_repr()
                },
                36,
            ),
            (
                Repr {
                    max_seg_size: Some(1460),
                    window_scale: Some(7),
                    sack_permitted: true,
                    timestamp: Some(TcpTimestampRepr::new(1, 2)),
                    extra: &extra,
                    ..packet_repr()
                },
                52,
            ),
        ] {
            assert_eq!(repr.header_len(), header_len);
            let mut bytes = vec![0xa5; repr.buffer_len()];
            repr.emit(
                &mut Packet::new_unchecked(&mut bytes),
                &SRC_ADDR.into(),
                &DST_ADDR.into(),
            );
            let packet = Packet::new_checked(&bytes[..]).unwrap();
            assert_eq!(packet.header_len() as usize, header_len);
            let read: Vec<_> = packet.options_iter().unwrap().map(Result::unwrap).collect();
            assert_eq!(
                &read[read.len() - 2..],
                [
                    TcpOption::NoOperation,
                    TcpOption::Unknown {
                        kind: 30,
                        data: &extra[3..]
                    }
                ]
            );
            assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
            assert_eq!(
                Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()),
                Ok(Repr { extra: &[], ..repr })
            );
        }
    }

    #[test]
    fn test_tcp_options_summary() {
        let mut bytes = vec![0; 32];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(32);
        // MSS=1460 (4b: 02 04 05 b4), WS=7 (3b: 03 03 07), SACK_PERM (2b: 04 02), NOP (1b: 01), END (1b: 00)
        let options_bytes: [u8; 12] = [
            0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0x01, 0x00, 0x00,
        ];
        packet.options_mut()[..12].copy_from_slice(&options_bytes);

        let summary = packet.options_summary().unwrap();
        assert_eq!(summary.max_segment_size, Some(1460));
        assert_eq!(summary.window_scale, Some(7));
        assert!(summary.sack_permitted);
        assert_eq!(summary.sack_ranges, [None, None, None]);
    }
}
