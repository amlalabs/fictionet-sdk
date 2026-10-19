use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, ops};

use super::{Error, Result};
use crate::wire::ip::checksum;
use crate::wire::{IpAddress, IpProtocol};

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo 2<sup>32</sup>.
/// Sequence numbers do not have a discontiguity when compared pairwise across a signed overflow.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub(crate) struct SeqNumber(pub(crate) i32);

impl SeqNumber {
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
        self.0.wrapping_sub(other.0).partial_cmp(&0)
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

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with TCP packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub(crate) fn new_checked(buffer: T) -> Result<Packet<T>> {
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
    pub(crate) fn header_len(&self) -> u8 {
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
                TcpOption::SackRange(ranges) => summary.sack_ranges = ranges,
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
    pub(crate) fn options(&self) -> &'a [u8] {
        let header_len = self.header_len();
        let data = self.buffer.as_ref();
        &data[field::OPTIONS(header_len)]
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
pub(crate) enum TcpOption<'a> {
    EndOfList,
    NoOperation,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    SackRange([Option<(u32, u32)>; 3]),
    TimeStamp { tsval: u32, tsecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
    pub(crate) fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>)> {
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
                    (field::OPT_MSS, _) => return Err(Error),
                    (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
                    (field::OPT_WS, _) => return Err(Error),
                    (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
                    (field::OPT_SACKPERM, _) => return Err(Error),
                    (field::OPT_SACKRNG, n) => {
                        if n < 10 || (n - 2) % 8 != 0 {
                            return Err(Error);
                        }
                        // Keep up to three SACK blocks; RFC 2018 permits four without timestamps.
                        let mut sack_ranges: [Option<(u32, u32)>; 3] = [None; 3];

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
    pub payload: &'a [u8],
}

pub type TcpTimestampGenerator = fn() -> u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct TcpTimestampRepr {
    pub(crate) tsval: u32,
    pub(crate) tsecr: u32,
}

impl TcpTimestampRepr {
    pub(crate) fn new(tsval: u32, tsecr: u32) -> Self {
        Self { tsval, tsecr }
    }

    pub(crate) fn generate_reply(&self, generator: Option<TcpTimestampGenerator>) -> Option<Self> {
        Self::generate_reply_with_tsval(generator, self.tsval)
    }

    pub(crate) fn generate_reply_with_tsval(
        generator: Option<TcpTimestampGenerator>,
        tsval: u32,
    ) -> Option<Self> {
        Some(Self::new(generator?(), tsval))
    }
}

impl<'a> Repr<'a> {
    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        // Source and destination ports must be present.
        if packet.src_port() == 0 {
            return Err(Error);
        }
        if packet.dst_port() == 0 {
            return Err(Error);
        }
        // Valid checksum is expected.
        if !packet.verify_checksum(src_addr, dst_addr) {
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
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => max_seg_size = Some(value),
                TcpOption::WindowScale(value) => {
                    // RFC 7323 limits the window scale to 14.
                    window_scale = Some(value.min(14));
                }
                TcpOption::SackPermitted => sack_permitted = true,
                TcpOption::SackRange(slice) => sack_ranges = slice,
                TcpOption::TimeStamp { tsval, tsecr } => {
                    timestamp = Some(TcpTimestampRepr::new(tsval, tsecr));
                }
                _ => (),
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
            payload: packet.payload(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// This should be used for buffer space calculations.
    /// The TCP header length is a multiple of 4.
    pub(crate) fn header_len(&self) -> usize {
        let mut length = field::URGENT.end;
        if self.max_seg_size.is_some() {
            length += 4
        }
        if self.window_scale.is_some() {
            length += 3
        }
        if self.sack_permitted {
            length += 2;
        }
        if self.timestamp.is_some() {
            length += 10;
        }
        let sack_range_len: usize = self
            .sack_ranges
            .iter()
            .map(|o| o.map(|_| 8).unwrap_or(0))
            .sum();
        if sack_range_len > 0 {
            length += sack_range_len + 2;
        }
        if !length.is_multiple_of(4) {
            length += 4 - length % 4;
        }
        length
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub(crate) fn buffer_len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    pub(crate) fn emit<T>(
        &self,
        packet: &mut Packet<&mut T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(SeqNumber(0)));
        packet.set_window_len(self.window_len);
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
            // SYN and SYN-ACK options are emitted in this order.
            let mut options = packet.options_mut();
            if let Some(value) = self.max_seg_size {
                let tmp = options;
                options = TcpOption::MaxSegmentSize(value).emit(tmp);
            }
            if let Some(value) = self.window_scale {
                let tmp = options;
                options = TcpOption::WindowScale(value).emit(tmp);
            }
            if self.sack_permitted {
                let tmp = options;
                options = TcpOption::SackPermitted.emit(tmp);
            } else if self.ack_number.is_some() && self.sack_ranges.iter().any(|s| s.is_some()) {
                let tmp = options;
                options = TcpOption::SackRange(self.sack_ranges).emit(tmp);
            }
            if let Some(timestamp) = self.timestamp {
                let tmp = options;
                options = TcpOption::TimeStamp {
                    tsval: timestamp.tsval,
                    tsecr: timestamp.tsecr,
                }
                .emit(tmp);
            }

            if !options.is_empty() {
                TcpOption::EndOfList.emit(options);
            }
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
            TcpOption::SackRange([Some((500, 1500)), None, None]),
            &[0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc]
        );
        assert_option_parses!(
            TcpOption::SackRange([Some((875, 1225)), Some((1500, 2500)), None]),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc,
                0x00, 0x00, 0x09, 0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((875000, 1225000)),
                Some((1500000, 2500000)),
                Some((876543210, 876654320))
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
        assert_eq!(TcpOption::parse(&[0x2, 0x02]), Err(Error));
        assert_eq!(TcpOption::parse(&[0x3, 0x02]), Err(Error));
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
