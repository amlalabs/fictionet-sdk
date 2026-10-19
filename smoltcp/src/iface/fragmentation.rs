#[cfg(any(test, feature = "proto-ipv4-fragmentation"))]
mod reassembly;

#[cfg(feature = "proto-ipv4-fragmentation")]
use crate::{config::FRAGMENTATION_BUFFER_SIZE, time::Duration, wire::*};
#[cfg(feature = "proto-ipv4-fragmentation")]
pub(super) use reassembly::PacketAssemblerSet;

#[cfg(feature = "proto-ipv4-fragmentation")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub(crate) enum FragKey {
    Ipv4(Ipv4FragKey),
}

pub(crate) struct FragmentsBuffer {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub assembler: PacketAssemblerSet<FragKey>,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub reassembly_timeout: Duration,
}

#[cfg(not(feature = "proto-ipv4-fragmentation"))]
pub(crate) struct Fragmenter {}

#[cfg(not(feature = "proto-ipv4-fragmentation"))]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Fragmenter {
    /// The buffer that holds the unfragmented IPv4 packet.
    pub buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
    /// The size of the packet including its original IP header.
    pub packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    pub sent_bytes: usize,

    pub ipv4: Ipv4Fragmenter,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The IPv4 representation.
    pub repr: Ipv4Repr,

    /// The offset of the next fragment.
    pub frag_offset: u16,
    /// The identifier of the stream.
    pub ident: u16,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
            packet_len: 0,
            sent_bytes: 0,

            ipv4: Ipv4Fragmenter {
                repr: Ipv4Repr {
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: Ipv4Address::new(0, 0, 0, 0),
                    next_header: IpProtocol::Unknown(0),
                    payload_len: 0,
                    hop_limit: 0,
                },

                frag_offset: 0,
                ident: 0,
            },
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    pub(crate) fn reset(&mut self) {
        self.packet_len = 0;
        self.sent_bytes = 0;

        {
            self.ipv4.repr = Ipv4Repr {
                src_addr: Ipv4Address::new(0, 0, 0, 0),
                dst_addr: Ipv4Address::new(0, 0, 0, 0),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            };
        }
    }
}
