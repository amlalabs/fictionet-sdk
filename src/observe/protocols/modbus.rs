use super::Display;
use fictionet::events::Transport;
use fictionet::observe::{
    Decoded, KeyLine, Layer, Match, Observed, Place, Placement, Present, Protocol, Registry,
};
use fictionet::stdlib::codec::{Decode, Fail, Frames, Step};

/// Modbus/TCP capture frames. Framing is provided by the stdlib decoder.
pub struct Modbus {
    frames: Frames<fictionet::stdlib::protocols::modbus::Frame>,
    request: bool,
}
impl Modbus {
    /// Selects request or response presentation for this direction.
    pub fn new(request: bool) -> Self {
        Self {
            frames: Frames::<fictionet::stdlib::protocols::modbus::Frame>::new(),
            request,
        }
    }
}
impl Decode for Modbus {
    type Item = Display;
    type Error = fictionet::stdlib::protocols::modbus::Error;
    const NAME: &'static str = "Modbus/TCP";
    fn capacity(&self) -> usize {
        self.frames.capacity()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Display>, Self::Error> {
        Ok(match self.frames.decode(input, eof)? {
            Step::Item(frame, n) => Step::Item(modbus_display(&frame, n, self.request), n),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}
impl Present for Modbus {
    display_presenter!();
    // An unrecognized Modbus header makes the conversation opaque.
    fn error(_: &Fail<Self::Error>, _: &mut Decoded) {}
}

/// A Modbus/TCP conversation that stops both directions after a framing error.
/// Register with [`Self::register`] to keep the built-in session policy
/// when copying this file.
pub struct ModbusSession {
    dirs: [Option<Observed<Modbus>>; 2],
    stopped: bool,
}
impl ModbusSession {
    /// Registers `modbus` for TCP with either endpoint on the Modbus port.
    /// Both directions stop after a framing error.
    pub fn register(registry: &mut Registry) {
        registry.register_protocol(
            "modbus",
            |s| {
                if s.transport == Transport::Tcp
                    && (s.ports.0 == fictionet::stdlib::protocols::modbus::PORT
                        || s.ports.1 == fictionet::stdlib::protocols::modbus::PORT)
                {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            |s, _| Box::new(Self::new(s.ports)),
        );
    }
    /// Creates request and response decoders from the conversation's ports.
    /// A direction is a request when its destination is the Modbus port.
    pub fn new(ports: (u16, u16)) -> Self {
        Self {
            dirs: [
                Some(Observed::new(Modbus::new(
                    ports.1 == fictionet::stdlib::protocols::modbus::PORT,
                ))),
                Some(Observed::new(Modbus::new(
                    ports.0 == fictionet::stdlib::protocols::modbus::PORT,
                ))),
            ],
            stopped: false,
        }
    }
}
impl Protocol for ModbusSession {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded, _: &[KeyLine]) {
        if self.stopped {
            return;
        }
        if let Some(dir) = &mut self.dirs[usize::from(reverse)] {
            dir.data(bytes, at, d);
            self.stopped = dir.failed().is_some();
        }
    }
    fn waiting(&self, reverse: bool) -> bool {
        !self.stopped
            && self.dirs[usize::from(reverse)]
                .as_ref()
                .is_some_and(Observed::waiting)
    }
    fn lost(&mut self, reverse: bool) {
        let slot = &mut self.dirs[usize::from(reverse)];
        *slot = slot.take().map(Observed::reset);
    }
}

fn modbus_display(
    frame: &fictionet::stdlib::protocols::modbus::Frame,
    used: usize,
    request: bool,
) -> Display {
    use fictionet::stdlib::protocols::modbus::{Request, Response};
    let mut decoded = Decoded::default();
    let d = &mut decoded;
    let (buf, base) = (0, 0);
    let mut l = Layer::new("Modbus/TCP", buf, (base, base + used));
    l.field(
        "Transaction identifier",
        frame.transaction.to_string(),
        (base, base + 2),
    );
    l.field("Protocol identifier", "0".to_owned(), (base + 2, base + 4));
    l.field(
        "Length",
        used.saturating_sub(6).to_string(),
        (base + 4, base + 6),
    );
    l.field(
        "Unit identifier",
        frame.unit.to_string(),
        (base + 6, base + 7),
    );
    let function = frame.function().unwrap_or(0);
    l.field(
        "Function code",
        format!("{} ({})", function & 0x7f, modbus_function(function & 0x7f)),
        (base + 7, base + 8),
    );
    let detail = if request {
        match Request::parse(&frame.pdu) {
            Ok(Request::ReadCoils { address, quantity })
            | Ok(Request::ReadDiscreteInputs { address, quantity })
            | Ok(Request::ReadHoldingRegisters { address, quantity })
            | Ok(Request::ReadInputRegisters { address, quantity }) => {
                format!("address {address}, quantity {quantity}")
            }
            Ok(Request::WriteSingleCoil { address, value }) => {
                format!("address {address}, {}", if value { "on" } else { "off" })
            }
            Ok(Request::WriteSingleRegister { address, value }) => {
                format!("address {address}, value {value}")
            }
            Ok(Request::WriteMultipleCoils { address, values }) => {
                format!("address {address}, {} coils", values.len())
            }
            Ok(Request::WriteMultipleRegisters { address, values }) => {
                format!("address {address}, values {values:?}")
            }
            Ok(Request::Other { data, .. }) => format!("{} bytes of data", data.len()),
            Err(e) => format!("malformed: a server answers {e}"),
        }
    } else {
        match Response::parse(&frame.pdu) {
            Ok((_, Response::Bits(bits))) => format!("{} bits", bits.len()),
            Ok((_, Response::Registers(regs))) => format!("registers {regs:?}"),
            Ok((_, Response::WriteSingleCoil { address, value })) => {
                format!("address {address}, {}", if value { "on" } else { "off" })
            }
            Ok((_, Response::WriteSingleRegister { address, value })) => {
                format!("address {address}, value {value}")
            }
            Ok((_, Response::WriteMultiple { address, quantity })) => {
                format!("address {address}, quantity {quantity}")
            }
            Ok((_, Response::Exception(e))) => format!("exception: {e}"),
            Ok((_, Response::Other(data))) => format!("{} bytes of data", data.len()),
            Err(_) => "malformed".to_owned(),
        }
    };
    let kind = if request { "Query" } else { "Response" };
    l.summary = format!(
        "{kind}, transaction {}, unit {}: {detail}",
        frame.transaction, frame.unit
    );
    l.note(if request { "Request" } else { "Response" }, detail.clone());
    d.push(l);
    d.application(
        2,
        "Modbus/TCP",
        &format!(
            "{kind}: Trans: {}; Unit: {}, Func: {}: {}",
            frame.transaction,
            frame.unit,
            function & 0x7f,
            modbus_function(function & 0x7f)
        ),
    );
    Display::from_packet(decoded, "Modbus/TCP frame")
}

fn modbus_function(f: u8) -> &'static str {
    match f {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn modbus_session_stops_both_directions_after_bad_framing() {
        use fictionet::observe::{Conversation, Decoded, Place, Registry};
        let mut registry = Registry::new();
        super::ModbusSession::register(&mut registry);
        let mut conversation = Conversation::with_registry(40000, 502, registry);
        let bad = [0, 9, 0, 5, 0, 6, 1, 3, 0, 0, 0, 1];
        let reply = [0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2];
        for (reverse, bytes) in [(false, &bad[..]), (true, &reply[..])] {
            let mut packet = Decoded::default();
            conversation.data(reverse, bytes, Place::default(), &mut packet, &[]);
            assert!(packet.layers.is_empty());
            assert!(packet.tags.is_empty());
            assert!(!conversation.waiting(reverse));
        }
    }
}
