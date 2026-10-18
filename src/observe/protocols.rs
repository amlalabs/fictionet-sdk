use fictionet::observe::{Decoded, Layer, Placement, Present};
use fictionet::stdlib::codec::{Decode, Step};
use std::convert::Infallible;

/// Bytes retained while an incomplete capture message is being framed.
const MAX_BUFFER: usize = 32 << 10;

/// A decoded item's relative layer and packet summary. Capture decoders
/// produce this value for the shared [`Present`] implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    layer: Option<Layer>,
    protocol: String,
    info: String,
    tags: Vec<&'static str>,
    buffer: &'static str,
    level: u8,
    offset: usize,
    detached: bool,
}

impl Display {
    /// Takes the packet's last layer, summary, and tags as one display item.
    /// Layer and field ranges must be relative to the item's raw bytes.
    /// `buffer` names the reassembly buffer used when the item spans packets.
    pub fn from_packet(mut packet: Decoded, buffer: &'static str) -> Self {
        let level = packet.level();
        Self {
            layer: packet.layers.pop(),
            protocol: packet.proto,
            info: packet.info,
            tags: packet.tags,
            buffer,
            level,
            offset: 0,
            detached: false,
        }
    }
    fn summary(&self) -> String {
        self.layer
            .as_ref()
            .map_or_else(String::new, |l| l.summary.clone())
    }
    fn fields(&self, layer: &mut Layer) {
        if let Some(source) = &self.layer {
            layer.fields = source.fields.clone();
        }
    }
    fn present(&self, raw: &[u8], start: u64, place: &Placement, packet: &mut Decoded) {
        let Some(source) = &self.layer else { return };
        let Some(bytes) = raw.get(self.offset..) else {
            return;
        };
        let mut layer = Layer::new(&source.name, 0, source.range);
        layer.summary = self.summary();
        self.fields(&mut layer);
        if self.detached {
            packet.push(layer);
        } else {
            place.push(
                packet,
                start.saturating_add(self.offset as u64),
                bytes,
                self.buffer,
                layer,
            );
        }
        for tag in &self.tags {
            packet.tag(tag);
        }
        if self.level == 0 {
            if !self.protocol.is_empty() {
                packet.proto.clone_from(&self.protocol);
                packet.info.clone_from(&self.info);
                packet.cap_info();
            }
        } else {
            packet.application(self.level, &self.protocol, &self.info);
        }
    }
}

macro_rules! display_presenter {
    () => {
        fn summary(item: &Display) -> String {
            item.summary()
        }
        fn fields(item: &Display, _: &[u8], layer: &mut Layer) {
            item.fields(layer);
        }
        fn present(
            item: &Display,
            bytes: &[u8],
            start: u64,
            place: &Placement,
            packet: &mut Decoded,
        ) {
            item.present(bytes, start, place, packet);
        }
    };
}

mod modbus;
pub use modbus::{Modbus, ModbusSession};

mod dns;
pub use dns::Dns;

mod dhcp;
pub use dhcp::Dhcp;

mod http1;
pub use http1::{Http1, body_preview};

/// A TLS record's capture metadata. Its exact bytes come from the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Payload length declared by the header.
    pub length: usize,
    /// Only the header was retained; the payload will be skipped.
    pub oversized: bool,
}

/// TLS record boundaries for a capture. Oversized records yield one
/// header-only item and skip their payload without allocating it.
#[derive(Default)]
pub struct TlsRecords {
    skip: usize,
}
impl Decode for TlsRecords {
    type Item = Record;
    type Error = Infallible;
    const NAME: &'static str = "TLS";
    fn capacity(&self) -> usize {
        MAX_BUFFER
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Record>, Infallible> {
        if self.skip != 0 {
            let n = self.skip.min(input.len());
            self.skip -= n;
            return Ok(if n == 0 { Step::Need } else { Step::Skip(n) });
        }
        let Some(header) = input.get(..5) else {
            return Ok(Step::Need);
        };
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let oversized = length > MAX_BUFFER - 5 && input.len() < length.saturating_add(5);
        let used = if oversized { 5 } else { length + 5 };
        if input.len() < used {
            return Ok(Step::Need);
        }
        if oversized {
            self.skip = length;
        }
        Ok(Step::Item(Record { length, oversized }, used))
    }
}
impl Present for TlsRecords {
    fn summary(item: &Record) -> String {
        if item.oversized {
            format!("a {}-byte record, longer than TLS allows", item.length)
        } else {
            format!("{}-byte record", item.length)
        }
    }
    fn fields(item: &Record, bytes: &[u8], layer: &mut Layer) {
        let Some(header) = bytes.get(..5) else { return };
        let kind = header[0];
        if item.oversized {
            layer.field("Content type", kind.to_string(), (0, 1));
        } else {
            let name = match kind {
                20 => "Change Cipher Spec",
                21 => "Alert",
                22 => "Handshake",
                23 => "Application Data",
                _ => "unknown",
            };
            layer.field("Content type", format!("{name} ({kind})"), (0, 1));
            layer.field(
                "Version",
                format!("0x{:04x}", u16::from_be_bytes([header[1], header[2]])),
                (1, 3),
            );
        }
        layer.field("Length", item.length.to_string(), (3, 5));
    }
    fn pending(&self) -> bool {
        self.skip != 0
    }
    fn reset(&mut self) {
        self.skip = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, Stream};
    use fictionet::stdlib::test_support::contract::check_decode;

    #[test]
    fn empty_datagrams_end_without_a_display_item() {
        assert!(matches!(Dns::new(false).decode(&[], true), Ok(Step::End)));
        assert!(matches!(Dhcp::default().decode(&[], true), Ok(Step::End)));
    }

    #[test]
    fn capture_decoders_follow_the_codec_contract() {
        let mut random = Lcg::new(17);
        for n in [0, 1, 5, 17, 64, 257] {
            let bytes = random.bytes(n);
            check_decode(|| Dns::new(true), &bytes);
            check_decode(|| Dns::new(false), &bytes);
            check_decode(Dhcp::default, &bytes);
            check_decode(Http1::default, &bytes);
            check_decode(TlsRecords::default, &bytes);
            check_decode(|| Modbus::new(true), &bytes);
            check_decode(|| Modbus::new(false), &bytes);
        }
        for bytes in [
            &b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /x HTTP/1.1\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3;ext\r\nllo\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\na body until close"[..],
        ] { check_decode(Http1::default, bytes); }
        for line in ["zz", "", "+1", "-1", "0x1", "10000000000000000"] {
            for body in ["", "3\r\nabc\r\n"] {
                let bytes = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}{line}\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
                );
                let (items, failure) = check_decode(Http1::default, bytes.as_bytes());
                assert_eq!(failure, None);
                assert_eq!(items.len(), 2, "{line:?}");
                assert!(items[1].tags.contains(&"malformed"), "{line:?}");
            }
        }
        check_decode(
            || Dns::new(true),
            &[0, 12, 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        check_decode(TlsRecords::default, &[23, 3, 3, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn oversized_records_emit_a_header_then_skip_and_resume() {
        let mut dns = Stream::new(Dns::new(true));
        assert_eq!(dns.push(&40_000u16.to_be_bytes()), 2);
        let (item, range) = dns.next_span().unwrap().unwrap();
        assert_eq!(range, 0..2);
        assert_eq!(
            item.summary(),
            "a 40000-byte message, too long to decode here"
        );
        for _ in 0..40 {
            assert_eq!(dns.push(&[0; 1000]), 1000);
            assert!(dns.next().is_none());
        }
        assert_eq!(dns.offset(), 40_002);
        assert_eq!(
            dns.push(&[0, 12, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            14
        );
        assert_eq!(dns.next_span().unwrap().unwrap().1, 40_002..40_016);

        let mut tls = Stream::new(TlsRecords::default());
        assert_eq!(tls.push(&[23, 3, 3, 0x9c, 0x40]), 5);
        let (item, range) = tls.next_span().unwrap().unwrap();
        assert_eq!(range, 0..5);
        assert!(item.oversized);
        for _ in 0..40 {
            assert_eq!(tls.push(&[0; 1000]), 1000);
            assert!(tls.next().is_none());
        }
        assert_eq!(tls.push(&[20, 3, 3, 0, 1, 1]), 6);
        let (item, range) = tls.next_span().unwrap().unwrap();
        assert!(!item.oversized);
        assert_eq!(range, 40_005..40_011);
    }

    #[test]
    fn presenters_plug_into_observe_and_construct_display_items() {
        use fictionet::events::Transport;
        use fictionet::observe::{
            Decoded, Layer, Match, Observed, Place, Present, Registry, Selection,
        };
        let mut registry = Registry::new();
        registry.register(
            "modbus",
            |_| Match::Yes,
            |_| [super::Modbus::new(true), super::Modbus::new(false)],
        );
        let mut protocol = registry
            .open(Selection {
                transport: Transport::Tcp,
                ports: (40000, 502),
                first: &[],
                alpn: None,
            })
            .unwrap();
        let bytes = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
        let mut packet = Decoded::default();
        protocol.data(
            false,
            &bytes,
            Place {
                offset: Some(0),
                len: bytes.len(),
                ..Place::default()
            },
            &mut packet,
            &[],
        );
        assert_eq!(packet.proto, "Modbus/TCP");
        assert_eq!(packet.layers[0].range, (0, bytes.len()));
        let item = super::Display::from_packet(packet, "Modbus frame");
        assert!(super::Modbus::summary(&item).contains("transaction 7"));
        assert!(format!("{registry:?}").contains("modbus"));
        assert!(format!("{:?}", Observed::new(super::Modbus::new(true))).contains("Modbus/TCP"));

        let mut packet = Decoded::default();
        packet.application(2, "Custom", "message");
        assert_eq!(packet.level(), 2);
        packet.push(Layer::new("Custom", 0, (0, 1)));
        let item = super::Display::from_packet(packet, "Custom bytes");
        let mut layer = Layer::new("Custom", 0, (0, 1));
        super::Dns::fields(&item, b"x", &mut layer);
        let mut packet = Decoded::default();
        super::Dns::present(
            &item,
            b"x",
            0,
            &fictionet::observe::Placement::new(Place {
                offset: Some(4),
                len: 1,
                ..Place::default()
            }),
            &mut packet,
        );
        assert_eq!(packet.layers[0].range, (4, 5));
        assert_eq!(packet.info, "message");
    }
}
