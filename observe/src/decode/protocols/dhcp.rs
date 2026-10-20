use super::Display;
use fictionet::events::Transport;
use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::protocols::dhcp;
use fictionet_observe::{Decoded, Layer, Match, Placement, Present, Registry};
use std::convert::Infallible;

/// One DHCP datagram, parsed at EOF with the stdlib message parser.
#[derive(Default)]
pub struct Dhcp {
    taken: bool,
}
impl Dhcp {
    /// Registers `dhcp` for UDP between the server and client ports.
    pub fn register(registry: &mut Registry) {
        registry.register(
            "dhcp",
            |s| {
                if s.transport == Transport::Udp
                    && matches!(
                        s.ports,
                        (dhcp::SERVER_PORT, dhcp::CLIENT_PORT)
                            | (dhcp::CLIENT_PORT, dhcp::SERVER_PORT)
                    )
                {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            |_| [Self::default(), Self::default()],
        );
    }
}
impl Decode for Dhcp {
    type Item = Display;
    type Error = Infallible;
    const NAME: &'static str = "DHCP";
    fn capacity(&self) -> usize {
        65_536
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Display>, Infallible> {
        if self.taken || input.len() >= self.capacity() || (eof && input.is_empty()) {
            return Ok(Step::End);
        }
        if !eof {
            return Ok(Step::Need);
        }
        self.taken = true;
        Ok(Step::Item(dhcp_display(input), input.len()))
    }
}
impl Present for Dhcp {
    display_presenter!();
}

fn dhcp_display(bytes: &[u8]) -> Display {
    let mut packet = Decoded::default();
    let Ok(m) =
        <fictionet::stdlib::protocols::dhcp::Message as fictionet::stdlib::codec::Wire>::parse(
            bytes,
        )
    else {
        return Display::from_packet(packet, "DHCP message");
    };
    let d = &mut packet;
    let range = (0, bytes.len());
    let kind = match m.message_type() {
        Some(1) => "Discover",
        Some(2) => "Offer",
        Some(3) => "Request",
        Some(4) => "Decline",
        Some(5) => "ACK",
        Some(6) => "NAK",
        Some(7) => "Release",
        Some(8) => "Inform",
        _ => "message",
    };
    let mut l = Layer::new("Dynamic Host Configuration Protocol", 0, range);
    l.summary = kind.into();
    l.field(
        "Transaction ID",
        format!("0x{:08x}", m.xid),
        (range.0 + 4, range.0 + 8),
    );
    l.field(
        "Your address",
        m.yiaddr.to_string(),
        (range.0 + 16, range.0 + 20),
    );
    for (code, value) in &m.options {
        let v = match (code, value.len()) {
            (1 | 3 | 6 | 50 | 54, n) if n % 4 == 0 && n > 0 => value
                .chunks(4)
                .map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3]))
                .collect::<Vec<_>>()
                .join(", "),
            (51, 4) => format!(
                "{} s",
                u32::from_be_bytes([value[0], value[1], value[2], value[3]])
            ),
            _ => format!("{} bytes", value.len()),
        };
        let name = match code {
            1 => "Subnet mask",
            3 => "Router",
            6 => "DNS servers",
            12 => "Host name",
            50 => "Requested address",
            51 => "Lease time",
            53 => "Message type",
            54 => "Server",
            _ => "Option",
        };
        l.note(
            name,
            if *code == 53 {
                kind.to_owned()
            } else {
                format!("{v} (option {code})")
            },
        );
    }
    d.push(l);
    d.proto = "DHCP".into();
    d.info = format!("DHCP {kind} - Transaction ID 0x{:08x}", m.xid);
    Display::from_packet(packet, "DHCP message")
}
