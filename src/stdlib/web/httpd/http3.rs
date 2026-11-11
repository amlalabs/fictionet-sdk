//! HTTP/3 connection coordination over the QUIC stream carrier.

use fictionet::time::Instant;
use std::convert::Infallible;
use std::time::SystemTime;

use fictionet::stdlib::codec::{self, Wire};
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, ChargedBytes, Child, ChildId, Chunk, Closing, Env, Layer,
    Mux, MuxCommand, MuxEvent, MuxOp, Slots, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::protocols::{fields::Fields, http2::ErrorCode, http3 as wire, qpack};
use fictionet::stdlib::services::quic::{
    Control, ControlCommand, ControlEvent, Dir, Quic, Stream, VarInt,
};

use super::http2::RequestHead;
use super::response::Dates;
use super::{
    Ending, ExchangeCommand, ExchangeEvent, HttpExchange, Limits, Opening, RequestTrailers,
};
use wire::error_code as code;

type Input = MuxEvent<ByteStream<VarInt>, Control, Stream>;
type Output = MuxCommand<ByteStream<VarInt>, Control>;
type Up = MuxEvent<HttpExchange, Top, Opening>;
type Command = MuxCommand<HttpExchange, Top>;
type Reader = codec::Stream<wire::StreamItems, ChargedBytes>;

const WINDOW: u64 = 16 * 1024;
// One decoded frame and its message event can coexist. Header decoding
// additionally holds field descriptors and expanded strings. This reserve
// belongs to the synchronous codec call, never to escaped output.
const SCRATCH: usize = 2 * wire::MAX_FRAME
    + 4 * qpack::MAX_FIELD_SECTION_SIZE as usize
    + 4 * qpack::MAX_FIELDS * size_of::<qpack::Field>()
    + 4 * qpack::MAX_STRING;

/// HTTP/3 for one server connection whose TLS configuration negotiates `h3`.
/// Compose below it a [`QuicLayer`](fictionet::stdlib::services::quic::QuicLayer),
/// and above it the same [`HttpExchange`] children as HTTP/2.
/// [`super::Responder::http3`] supplies the SDK's handler children.
///
/// QPACK advertises zero dynamic capacity and zero blocked streams. Static
/// references, literals and Huffman strings work in both directions. Server
/// push and extended CONNECT are not enabled. The peer must allow at least
/// three unidirectional streams for the control and QPACK streams.
///
/// Stream inputs, slots, response bytes and escaped request fields carry
/// budget charges. The existing allocating codecs run with a conservative
/// temporary reservation. This is not a whole-engine allocation proof.
pub struct Http3 {
    limits: Limits,
    channels: Slots<Channel>,
    exchanges: Slots<ChildId>,
    initialized: bool,
    connected: bool,
    local_opened: u8,
    opening: bool,
    critical: Critical,
    decoder: qpack::Table,
    encoder: qpack::Encoder,
    peer_fields: u64,
    up: Option<Up>,
    close: Option<u64>,
    closing: bool,
    gone: bool,
    cursor: Option<ChildId>,
    send_cursor: Option<ChildId>,
    scan: usize,
    dates: Dates,
    dates_charge: Option<Charge>,
    shutdown: Option<u64>,
    next_request: u64,
    goaway_sent: bool,
}

#[derive(Default)]
struct Critical {
    control: bool,
    encoder: bool,
    decoder: bool,
}

impl Critical {
    fn accept(&mut self, header: wire::StreamHeader) -> Result<bool, u64> {
        let seen = match header {
            wire::StreamHeader::Control => &mut self.control,
            wire::StreamHeader::QpackEncoder => &mut self.encoder,
            wire::StreamHeader::QpackDecoder => &mut self.decoder,
            wire::StreamHeader::Push(_) => return Err(code::STREAM_CREATION_ERROR),
            wire::StreamHeader::Unknown(_) => return Ok(false),
        };
        if *seen {
            return Err(code::STREAM_CREATION_ERROR);
        }
        *seen = true;
        Ok(true)
    }
}

struct Sending {
    bytes: Chunk,
    flight: u64,
    body: u64,
}

impl Sending {
    fn complete(&mut self, bytes: u64) -> Result<bool, ()> {
        if bytes > self.flight {
            return Err(());
        }
        self.flight -= bytes;
        Ok(self.flight == 0 && self.bytes.is_empty())
    }
}

struct Channel {
    lower: Child,
    stream: u64,
    local: Option<u8>,
    critical: bool,
    input: Reader,
    request: Option<wire::RequestStream>,
    exchange: Option<ChildId>,
    pending: Option<ExchangeEvent>,
    input_done: bool,
    trailers: Option<RequestTrailers>,
    receive_due: u64,
    receive_credit: u64,
    send_credit: u64,
    app_credit: u64,
    app_due: u64,
    sending: Option<Sending>,
    written: u64,
    report_written: bool,
    response_started: bool,
    finish: bool,
    fin_sent: bool,
    reset: Option<u64>,
    stop_sent: bool,
    reset_sent: bool,
    retiring: bool,
    lost: bool,
    head_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
}

impl Channel {
    fn new(lower: Child, stream: Stream, local: Option<u8>, budget: &Budget, limit: u64) -> Self {
        let id = u64::from(stream.id);
        let request = (!stream.local && stream.id.dir() == Dir::Bi).then(|| {
            wire::RequestStream::new(id, wire::MessageSide::Request, false)
                .expect("client bidirectional stream")
                .with_field_limit(limit)
        });
        let decoder = if request.is_some() {
            wire::StreamItems::request()
        } else {
            wire::StreamItems::unidirectional()
        };
        Self {
            lower,
            stream: id,
            local,
            critical: local.is_some(),
            input: codec::Stream::in_storage(decoder, 0, ChargedBytes::new(budget)),
            request,
            exchange: None,
            pending: None,
            input_done: stream.local,
            trailers: None,
            receive_due: if stream.local {
                0
            } else {
                wire::MAX_FRAME as u64
            },
            receive_credit: 0,
            send_credit: 0,
            app_credit: 0,
            app_due: 0,
            sending: None,
            written: 0,
            report_written: false,
            response_started: false,
            finish: false,
            fin_sent: false,
            reset: None,
            stop_sent: false,
            reset_sent: false,
            retiring: false,
            lost: false,
            head_deadline: None,
            write_deadline: None,
        }
    }

    fn cancel(&mut self, code: u64) {
        self.reset.get_or_insert(code);
        self.pending = None;
        self.trailers = None;
        self.sending = None;
        self.input_done = true;
        self.receive_due = 0;
        self.app_due = 0;
        self.head_deadline = None;
        self.write_deadline = None;
    }
}

impl Http3 {
    /// A server connection with these per-request limits.
    pub fn new(limits: Limits) -> Self {
        let streams = (limits.streams as usize).min(4096);
        Self {
            limits,
            channels: Slots::new(streams + 6),
            exchanges: Slots::new(streams),
            initialized: false,
            connected: false,
            local_opened: 0,
            opening: false,
            critical: Critical::default(),
            decoder: qpack::Table::new(0),
            encoder: qpack::Encoder::new(0, wire::MAX_FIELD_SECTION_SIZE),
            peer_fields: u64::MAX,
            up: None,
            close: None,
            closing: false,
            gone: false,
            cursor: None,
            send_cursor: None,
            scan: 0,
            dates: Dates::new(None),
            dates_charge: None,
            shutdown: None,
            next_request: 0,
            goaway_sent: false,
        }
    }

    /// Dates response heads from the world's clock.
    pub fn date(mut self, start: SystemTime) -> Self {
        self.dates = Dates::new(Some(start));
        self
    }

    /// Rejects requests not yet admitted and drains existing exchanges.
    /// The GOAWAY cutoff is the next request identifier beyond every request
    /// already admitted, so an out-of-order lower identifier can still arrive.
    /// The transport remains open to retransmit responses and GOAWAY until
    /// the peer closes it or its idle timeout expires. Local write completion
    /// only means QUIC accepted bytes; it cannot authorize discarding them.
    pub fn graceful_shutdown(&mut self) {
        self.shutdown.get_or_insert(self.next_request);
        self.scan = self.channels.len();
    }

    fn field_limit(&self) -> u64 {
        (self.limits.head.head as u64).min(wire::MAX_FIELD_SECTION_SIZE)
    }

    fn init(&mut self, budget: &Budget) -> bool {
        if self.initialized {
            return true;
        }
        let streams = (self.limits.streams as usize).min(4096);
        let Some(channels) = Slots::with_budget(streams + 6, budget) else {
            return false;
        };
        let Some(exchanges) = Slots::with_budget(streams, budget) else {
            return false;
        };
        let Some(dates) = budget.charge(self.dates.held()) else {
            return false;
        };
        self.channels = channels;
        self.exchanges = exchanges;
        self.dates_charge = Some(dates);
        self.initialized = true;
        true
    }

    fn fail(&mut self, code: u64) {
        if !self.closing {
            self.close = Some(code);
            self.closing = true;
        }
    }

    fn channel(&self, lower: ChildId) -> Option<ChildId> {
        self.channels
            .ids()
            .find(|&id| self.channels.get(id).unwrap().lower.id() == lower)
    }

    fn error(&mut self, id: ChildId, error: wire::Error) {
        match error {
            wire::Error::Qpack(
                qpack::Error::FieldSectionTooLarge | qpack::Error::TooManyFields,
            ) => {
                self.channels
                    .get_mut(id)
                    .unwrap()
                    .cancel(code::EXCESSIVE_LOAD);
            }
            wire::Error::Message(_) | wire::Error::Incomplete => {
                self.channels
                    .get_mut(id)
                    .unwrap()
                    .cancel(error.application_code().unwrap());
            }
            _ => self.fail(error.application_code().unwrap_or(code::INTERNAL_ERROR)),
        }
    }

    fn fields(budget: &Budget, head: wire::HeaderList) -> Option<Fields> {
        let mut fields = Fields::new();
        for field in head.fields {
            let kept = fields
                .write(
                    budget,
                    field.name.len() + field.value.len(),
                    field.never_index,
                    |out| {
                        let (name, rest) = out.split_at_mut(field.name.len());
                        name.copy_from_slice(&field.name);
                        rest[..field.value.len()].copy_from_slice(&field.value);
                        Ok::<_, Infallible>((field.name.len(), field.value.len()))
                    },
                )
                .ok()?;
            if !kept {
                return None;
            }
        }
        Some(fields)
    }

    fn item(&mut self, env: &mut Env<'_, ()>, id: ChildId, item: wire::StreamItem) {
        match item {
            wire::StreamItem::Header(header) => {
                match self.critical.accept(header) {
                    Err(code) => {
                        self.fail(code);
                        return;
                    }
                    Ok(critical) => self.channels.get_mut(id).unwrap().critical = critical,
                }
                let channel = self.channels.get_mut(id).unwrap();
                // The prefix decoder ends before handing its buffered suffix on.
                let _ = channel.input.next();
                let empty = codec::Stream::in_storage(
                    wire::StreamItems::unidirectional(),
                    0,
                    ChargedBytes::new(env.budget()),
                );
                let old = std::mem::replace(&mut channel.input, empty);
                channel.input =
                    old.swap(wire::StreamItems::after_header(header, codec::Side::Client));
            }
            wire::StreamItem::EncoderInstruction(instruction) => {
                if self.decoder.apply(instruction).is_err() {
                    self.fail(code::QPACK_ENCODER_STREAM_ERROR);
                }
            }
            wire::StreamItem::DecoderInstruction(instruction) => {
                if self.encoder.apply_instruction(instruction).is_err() {
                    self.fail(code::QPACK_DECODER_STREAM_ERROR);
                }
            }
            wire::StreamItem::Frame(frame) => {
                let channel = self.channels.get_mut(id).unwrap();
                let Some(request) = &mut channel.request else {
                    match frame {
                        wire::Frame::Settings(settings) => {
                            self.peer_fields = settings
                                .get(wire::setting::MAX_FIELD_SECTION_SIZE)
                                .unwrap_or(u64::MAX);
                        }
                        // No push was promised, so no push can be cancelled.
                        wire::Frame::CancelPush(_) => self.fail(code::ID_ERROR),
                        _ => {}
                    }
                    return;
                };
                let event = match request.step(&frame, &self.decoder) {
                    Err(error) => {
                        self.error(id, error);
                        return;
                    }
                    Ok(wire::RequestResult::Blocked(_)) => {
                        self.fail(code::QPACK_DECOMPRESSION_FAILED);
                        return;
                    }
                    Ok(wire::RequestResult::Event { event, ack }) => {
                        // Zero capacity cannot produce a dynamic reference or acknowledgement.
                        if ack.is_some() {
                            self.fail(code::QPACK_DECOMPRESSION_FAILED);
                            return;
                        }
                        match event {
                            Ok(event) => event,
                            Err(error) => {
                                self.error(id, error);
                                return;
                            }
                        }
                    }
                };
                match event {
                    wire::Event::Headers(head) => {
                        if head
                            .fields
                            .iter()
                            .filter(|f| !f.name.starts_with(b":"))
                            .count()
                            > self.limits.head.headers
                        {
                            self.channels
                                .get_mut(id)
                                .unwrap()
                                .cancel(code::EXCESSIVE_LOAD);
                            return;
                        }
                        let Some(fields) = Self::fields(env.budget(), head) else {
                            self.channels
                                .get_mut(id)
                                .unwrap()
                                .cancel(code::EXCESSIVE_LOAD);
                            return;
                        };
                        let length = fields
                            .get(b"content-length")
                            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
                        let channel = self.channels.get_mut(id).unwrap();
                        if self.shutdown.is_some_and(|cutoff| channel.stream >= cutoff) {
                            channel.cancel(code::REQUEST_REJECTED);
                            return;
                        }
                        let Ok(child) = self.exchanges.insert(id) else {
                            channel.cancel(code::REQUEST_REJECTED);
                            return;
                        };
                        channel.exchange = Some(child.id());
                        channel.head_deadline = None;
                        channel.app_due = WINDOW;
                        self.next_request = self.next_request.max(channel.stream + 4);
                        self.up = Some(MuxEvent::Opened(
                            child,
                            Opening {
                                head: RequestHead::http3(fields, length),
                                ended: false,
                                at: env.now(),
                            },
                            WINDOW,
                        ));
                    }
                    wire::Event::Data(bytes) => {
                        let channel = self.channels.get_mut(id).unwrap();
                        match Chunk::copy_of(env.budget(), &bytes) {
                            Some(bytes) => channel.pending = Some(ExchangeEvent::Data(bytes)),
                            None => channel.cancel(code::EXCESSIVE_LOAD),
                        }
                    }
                    wire::Event::Trailers(head) => {
                        let fields = Self::fields(env.budget(), head);
                        let channel = self.channels.get_mut(id).unwrap();
                        match fields {
                            Some(fields) => channel.trailers = Some(RequestTrailers::new(fields)),
                            None => channel.cancel(code::EXCESSIVE_LOAD),
                        }
                    }
                    wire::Event::Unknown(_) => {}
                    _ => self.fail(code::FRAME_UNEXPECTED),
                }
            }
        }
    }

    fn read(&mut self, env: &mut Env<'_, ()>, id: ChildId) -> bool {
        let channel = self.channels.get_mut(id).unwrap();
        if channel.local.is_some()
            || channel.input_done
            || channel.pending.is_some()
            || channel.reset.is_some()
        {
            return false;
        }
        let Some(_scratch) = env.budget().charge(SCRATCH) else {
            channel.cancel(code::EXCESSIVE_LOAD);
            if channel.critical {
                self.fail(code::EXCESSIVE_LOAD);
            }
            return true;
        };
        let before = channel.input.offset();
        let item = channel.input.next();
        let consumed = channel.input.offset() - before;
        channel.receive_due += consumed;
        if let Some(item) = item {
            match item {
                Ok(Ok(item)) => self.item(env, id, item),
                Ok(Err(error)) | Err(codec::Fail::Protocol(error)) => self.error(id, error),
                Err(codec::Fail::Truncated { .. }) => {
                    if channel.request.is_some() {
                        self.fail(code::FRAME_ERROR);
                    } else {
                        channel.cancel(code::NO_ERROR);
                    }
                }
                Err(_) => self.fail(code::EXCESSIVE_LOAD),
            }
            return true;
        }
        if channel.input.is_done() {
            channel.input_done = true;
            channel.receive_due = 0;
            if let Some(request) = &mut channel.request {
                match request.finish() {
                    Ok(()) => {
                        channel.pending = Some(match channel.trailers.take() {
                            Some(trailers) => ExchangeEvent::Trailers(trailers),
                            None => ExchangeEvent::End,
                        });
                    }
                    Err(error) => self.error(id, error),
                }
            } else if channel.critical {
                self.fail(code::CLOSED_CRITICAL_STREAM);
            } else {
                channel.cancel(code::NO_ERROR);
            }
            return true;
        }
        consumed != 0
    }

    fn encode_headers(
        &mut self,
        env: &Env<'_, ()>,
        stream: u64,
        status: Option<http::StatusCode>,
        headers: &http::HeaderMap,
    ) -> Option<Chunk> {
        let _scratch = env.budget().charge(SCRATCH)?;
        let date = if status.is_some() && !headers.contains_key(http::header::DATE) {
            self.dates.at(env.now())
        } else {
            None
        };
        let count = headers.len() + usize::from(status.is_some()) + usize::from(date.is_some());
        let size = headers
            .iter()
            .try_fold(0u64, |total, (name, value)| {
                if name.as_str().len() > qpack::MAX_STRING
                    || value.as_bytes().len() > qpack::MAX_STRING
                {
                    return None;
                }
                total.checked_add(
                    (name.as_str().len() + value.as_bytes().len()) as u64 + qpack::ENTRY_OVERHEAD,
                )
            })?
            .checked_add(if status.is_some() { 42 } else { 0 })?
            .checked_add(date.as_ref().map_or(0, |v| 36 + v.as_bytes().len() as u64))?;
        if count > qpack::MAX_FIELDS || size > self.peer_fields.min(wire::MAX_FIELD_SECTION_SIZE) {
            return None;
        }
        let mut fields = Vec::with_capacity(count);
        if let Some(status) = status {
            fields.push(qpack::Field::new(":status", status.as_str()));
        }
        for (name, value) in headers {
            if !matches!(
                name.as_str(),
                "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
            ) {
                let mut field = qpack::Field::new(name.as_str(), value.as_bytes());
                field.never_index = value.is_sensitive();
                fields.push(field);
            }
        }
        if let Some(date) = date {
            fields.push(qpack::Field::new("date", date.as_bytes()));
        }
        if fields.iter().map(qpack::Field::size).sum::<u64>() > self.peer_fields {
            return None;
        }
        let headers = wire::HeaderList { fields };
        let kind = if status.is_some() {
            wire::HeaderKind::Response
        } else {
            wire::HeaderKind::Trailers
        };
        let section = headers.section(&mut self.encoder, stream, kind).ok()?;
        let payload = section.to_bytes().ok()?;
        let bound = payload.len() + wire::MAX_FRAME_HEADER;
        encode(env.budget(), &wire::Frame::Headers(payload), bound)
    }
}

fn encode<T: Wire>(budget: &Budget, value: &T, bound: usize) -> Option<Chunk> {
    let mut bytes = ChargedBytes::with_capacity(budget, bound)?;
    bytes.fill(|out| value.write(out)).ok()?;
    bytes.trim();
    Some(bytes.into_chunk())
}

fn data_frame(budget: &Budget, body: &[u8]) -> Option<Chunk> {
    use fictionet::stdlib::protocols::quic;
    let mut out = ChargedBytes::with_capacity(budget, body.len().checked_add(16)?)?;
    out.fill(|out| {
        quic::VarInt(0).write(out)?;
        quic::VarInt(body.len() as u64).write(out)?;
        out.extend_from_slice(body);
        Ok::<(), quic::Error>(())
    })
    .ok()?;
    Some(out.into_chunk())
}

impl Layer for Http3 {
    type Lower = Quic;
    type Upper = Mux<HttpExchange, Top, Opening>;
    type Report = ();
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: Input,
    ) -> Result<Admit<Input>, Infallible> {
        if !self.init(env.budget()) {
            return Ok(Admit::Blocked(event));
        }
        self.scan = self.channels.len() + 1;
        match event {
            MuxEvent::Control(ControlEvent::Connected) => self.connected = true,
            MuxEvent::Control(ControlEvent::Lost(_)) | MuxEvent::Control(ControlEvent::Ended) => {
                self.closing = true;
                self.gone = true;
            }
            MuxEvent::Control(_) => {}
            MuxEvent::Opened(lower, stream, atomic) => {
                if self.closing {
                    return Ok(Admit::Closed(MuxEvent::Opened(lower, stream, atomic)));
                }
                if stream.local && (stream.id.dir() != Dir::Uni || !self.opening) {
                    self.fail(code::STREAM_CREATION_ERROR);
                    return Ok(Admit::Taken);
                }
                if !stream.local && stream.id.dir() == Dir::Bi && u64::from(stream.id) % 4 != 0 {
                    self.fail(code::STREAM_CREATION_ERROR);
                    return Ok(Admit::Taken);
                }
                let local = stream.local.then_some(self.local_opened);
                let mut channel =
                    Channel::new(lower, stream, local, env.budget(), self.field_limit());
                if channel.request.is_some() {
                    channel.head_deadline = Some(env.now() + self.limits.header_timeout);
                }
                if self.channels.insert(channel).is_err() {
                    self.fail(code::EXCESSIVE_LOAD);
                    return Ok(Admit::Taken);
                }
                if stream.local {
                    self.local_opened += 1;
                    self.opening = false;
                }
            }
            MuxEvent::Credit(lower, amount) => {
                if let Some(id) = self.channel(lower) {
                    self.channels.get_mut(id).unwrap().send_credit = self
                        .channels
                        .get(id)
                        .unwrap()
                        .send_credit
                        .saturating_add(amount);
                }
            }
            MuxEvent::Closed(lower) => {
                if let Some(id) = self.channel(lower) {
                    let channel = self.channels.get_mut(id).unwrap();
                    if channel.critical && !self.closing {
                        self.fail(code::CLOSED_CRITICAL_STREAM);
                    } else {
                        channel.lost = true;
                    }
                }
            }
            MuxEvent::Child(lower, event) => {
                if let Some(id) = self.channel(lower) {
                    let channel = self.channels.get_mut(id).unwrap();
                    match event {
                        StreamEvent::Data(bytes) => {
                            if channel.input_done || channel.reset.is_some() {
                                return Ok(Admit::Taken);
                            }
                            if channel.input.push(&bytes) != bytes.len() {
                                if channel.critical {
                                    self.fail(code::EXCESSIVE_LOAD);
                                } else {
                                    channel.cancel(code::EXCESSIVE_LOAD);
                                }
                            }
                        }
                        StreamEvent::Ended => channel.input.end(),
                        StreamEvent::Written(bytes) => {
                            if channel.reset.is_none() {
                                let result = channel.sending.as_mut().map(|s| s.complete(bytes));
                                match result {
                                    Some(Ok(true)) => {
                                        let sent = channel.sending.take().unwrap();
                                        channel.written += sent.body;
                                        channel.report_written |= sent.body != 0;
                                        channel.app_due += sent.body;
                                        channel.write_deadline = None;
                                    }
                                    Some(Ok(false)) => {
                                        if bytes != 0 {
                                            channel.write_deadline =
                                                Some(env.now() + self.limits.write_timeout);
                                        }
                                    }
                                    _ => self.fail(code::INTERNAL_ERROR),
                                }
                            }
                        }
                        StreamEvent::ReceiveReset(_)
                        | StreamEvent::SendStopped(_)
                        | StreamEvent::Reset => {
                            if channel.critical {
                                self.fail(code::CLOSED_CRITICAL_STREAM);
                            } else {
                                channel.cancel(code::REQUEST_CANCELLED);
                            }
                        }
                    }
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: Command,
    ) -> Result<Admit<Command>, Infallible> {
        self.scan = self.channels.len();
        let exchange = match command.op() {
            MuxOp::Child(id, _)
            | MuxOp::Credit(id, _)
            | MuxOp::Window(id, ..)
            | MuxOp::Close(id, _) => *id,
            MuxOp::Control(never) => match *never {},
        };
        let Some(&id) = self.exchanges.get(exchange) else {
            return Ok(Admit::Closed(command));
        };
        let channel = self.channels.get(id).unwrap();
        if channel.reset.is_some() || self.closing {
            return Ok(Admit::Closed(command));
        }
        if matches!(
            command.op(),
            MuxOp::Child(
                _,
                ExchangeCommand::Head(_)
                    | ExchangeCommand::Data(_)
                    | ExchangeCommand::Trailers(_)
                    | ExchangeCommand::End
            )
        ) && channel.sending.is_some()
        {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Credit(_, amount) | MuxOp::Window(_, amount, _) => {
                let channel = self.channels.get_mut(id).unwrap();
                channel.receive_credit = channel.receive_credit.saturating_add(amount);
            }
            MuxOp::Close(_, why) => {
                self.channels.get_mut(id).unwrap().cancel(match why {
                    Closing::Prohibited | Closing::ResourceShortage => code::REQUEST_REJECTED,
                    _ => code::INTERNAL_ERROR,
                });
            }
            MuxOp::Child(_, command) => {
                let stream = self.channels.get(id).unwrap().stream;
                let (bytes, body, end) = match command {
                    ExchangeCommand::Head(head) => {
                        if self.channels.get(id).unwrap().response_started {
                            self.channels
                                .get_mut(id)
                                .unwrap()
                                .cancel(code::INTERNAL_ERROR);
                            return Ok(Admit::Taken);
                        }
                        let bytes =
                            self.encode_headers(env, stream, Some(head.status), &head.headers);
                        self.channels.get_mut(id).unwrap().response_started =
                            !head.status.is_informational();
                        (bytes, 0, head.end)
                    }
                    ExchangeCommand::Trailers(trailers) => {
                        (self.encode_headers(env, stream, None, &trailers), 0, true)
                    }
                    ExchangeCommand::Data(bytes) => {
                        let channel = self.channels.get_mut(id).unwrap();
                        if !channel.response_started || bytes.len() as u64 > channel.app_credit {
                            channel.cancel(code::INTERNAL_ERROR);
                            return Ok(Admit::Taken);
                        }
                        channel.app_credit -= bytes.len() as u64;
                        let length = bytes.len();
                        (data_frame(env.budget(), &bytes), length as u64, false)
                    }
                    ExchangeCommand::End => {
                        self.channels.get_mut(id).unwrap().finish = true;
                        return Ok(Admit::Taken);
                    }
                    ExchangeCommand::Reset(reason) => {
                        self.channels.get_mut(id).unwrap().cancel(match reason {
                            ErrorCode::Cancel => code::REQUEST_CANCELLED,
                            ErrorCode::RefusedStream => code::REQUEST_REJECTED,
                            ErrorCode::ProtocolError => code::MESSAGE_ERROR,
                            _ => code::INTERNAL_ERROR,
                        });
                        return Ok(Admit::Taken);
                    }
                };
                let channel = self.channels.get_mut(id).unwrap();
                if let Some(bytes) = bytes {
                    channel.sending = Some(Sending {
                        bytes,
                        flight: 0,
                        body,
                    });
                    channel.finish |= end;
                    channel.write_deadline = Some(env.now() + self.limits.write_timeout);
                } else {
                    channel.cancel(code::EXCESSIVE_LOAD);
                }
            }
            MuxOp::Control(never) => match never {},
        }
        Ok(Admit::Taken)
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        if !self.init(env.budget()) {
            return Ok(false);
        }
        if self.up.is_some() {
            return Ok(false);
        }
        let next = self
            .channels
            .ids()
            .find(|id| self.cursor.is_none_or(|cursor| *id > cursor))
            .or_else(|| self.channels.ids().next());
        let Some(id) = next else {
            return Ok(false);
        };
        self.cursor = Some(id);
        let channel = self.channels.get_mut(id).unwrap();
        let mut moved = false;
        if channel.lost || self.gone {
            if let Some(exchange) = channel.exchange.take() {
                self.exchanges.remove(exchange);
                self.up = Some(MuxEvent::Child(
                    exchange,
                    ExchangeEvent::Closed {
                        why: if channel.fin_sent && channel.reset.is_none() {
                            Ending::Done
                        } else {
                            Ending::Gone
                        },
                        written: channel.written,
                    },
                ));
            }
            self.channels.remove(id);
            moved = true;
        } else if !self.closing {
            if let Some(exchange) = channel.exchange {
                if let Some(code) = channel.reset {
                    channel.exchange = None;
                    self.exchanges.remove(exchange);
                    self.up = Some(MuxEvent::Child(
                        exchange,
                        ExchangeEvent::Closed {
                            why: Ending::ApplicationReset(code),
                            written: channel.written,
                        },
                    ));
                    moved = true;
                } else if channel.app_due != 0 && !channel.finish {
                    let amount = std::mem::take(&mut channel.app_due);
                    channel.app_credit += amount;
                    self.up = Some(MuxEvent::Credit(exchange, amount));
                    moved = true;
                } else if let Some(event) = channel.pending.take() {
                    match event {
                        ExchangeEvent::Data(mut bytes) => {
                            moved |= bytes.is_empty();
                            let n = (bytes.len() as u64).min(channel.receive_credit) as usize;
                            if n > 0 {
                                channel.receive_credit -= n as u64;
                                self.up = Some(MuxEvent::Child(
                                    exchange,
                                    ExchangeEvent::Data(bytes.split_to(n)),
                                ));
                                moved = true;
                            }
                            if !bytes.is_empty() {
                                channel.pending = Some(ExchangeEvent::Data(bytes));
                            }
                        }
                        event => {
                            self.up = Some(MuxEvent::Child(exchange, event));
                            moved = true;
                        }
                    }
                }
            }
            if self.up.is_none() {
                moved |= self.read(env, id);
            }
        }
        if moved {
            self.scan = self.channels.len();
        } else {
            self.scan = self.scan.saturating_sub(1);
        }
        Ok(moved || self.scan > 0)
    }

    fn take_command(&mut self, env: &mut Env<'_, ()>) -> Option<Output> {
        if let Some(code) = self.close.take() {
            return Some(MuxCommand::control(ControlCommand::Close(
                VarInt::from_u64(code).unwrap(),
            )));
        }
        if self.closing {
            return None;
        }
        if self.connected && self.local_opened < 3 && !self.opening {
            self.opening = true;
            return Some(MuxCommand::control(ControlCommand::OpenOrClose {
                direction: Dir::Uni,
                error: VarInt::from_u32(code::STREAM_CREATION_ERROR as u32),
            }));
        }
        let ready = |id: ChildId| {
            let channel = self.channels.get(id).unwrap();
            channel.receive_due > 0
                || channel.reset.is_some() && !channel.retiring
                || channel.local.is_some() && !channel.response_started
                || channel
                    .sending
                    .as_ref()
                    .is_some_and(|s| !s.bytes.is_empty() && channel.send_credit > 0)
                || channel.finish
                    && channel.sending.is_none()
                    && (!channel.fin_sent || !channel.stop_sent)
                || channel.local == Some(0)
                    && self.shutdown.is_some()
                    && !self.goaway_sent
                    && channel.sending.is_none()
        };
        let id = self
            .channels
            .ids()
            .find(|id| self.send_cursor.is_none_or(|cursor| *id > cursor) && ready(*id))
            .or_else(|| self.channels.ids().find(|id| ready(*id)))?;
        self.send_cursor = Some(id);
        let channel = self.channels.get_mut(id).unwrap();
        if let Some(code) = channel.reset {
            let code = VarInt::from_u64(code).unwrap();
            if !channel.stop_sent {
                channel.stop_sent = true;
                return Some(channel.lower.send(StreamCommand::StopReceive(code)));
            }
            if !channel.reset_sent && channel.request.is_some() {
                channel.reset_sent = true;
                return Some(channel.lower.send(StreamCommand::ResetSend(code)));
            }
            channel.retiring = true;
            return Some(MuxCommand::from_op(MuxOp::Close(
                channel.lower.id(),
                Closing::Done,
            )));
        }
        if channel.receive_due > 0 {
            return Some(
                channel
                    .lower
                    .grant(std::mem::take(&mut channel.receive_due)),
            );
        }
        if let Some(local) = channel.local
            && !channel.response_started
        {
            let bytes = match local {
                0 => {
                    use fictionet::stdlib::protocols::quic;
                    let limit = self.field_limit();
                    let length = 1 + quic::varint_len(limit).unwrap() as u64;
                    let mut bytes = ChargedBytes::with_capacity(env.budget(), 64)?;
                    bytes
                        .fill(|out| {
                            for value in
                                [0, 4, length, wire::setting::MAX_FIELD_SECTION_SIZE, limit]
                            {
                                quic::VarInt(value).write(out)?;
                            }
                            Ok::<(), quic::Error>(())
                        })
                        .ok()?;
                    bytes.into_chunk()
                }
                1 => Chunk::copy_of(env.budget(), &[2])?,
                _ => Chunk::copy_of(env.budget(), &[3])?,
            };
            let channel = self.channels.get_mut(id).unwrap();
            channel.response_started = true;
            channel.write_deadline = Some(env.now() + self.limits.write_timeout);
            channel.sending = Some(Sending {
                bytes,
                flight: 0,
                body: 0,
            });
        }
        let channel = self.channels.get_mut(id).unwrap();
        if channel.local == Some(0)
            && channel.sending.is_none()
            && !self.goaway_sent
            && let Some(cutoff) = self.shutdown
        {
            let bytes = encode(env.budget(), &wire::Frame::Goaway(cutoff), 24)?;
            channel.sending = Some(Sending {
                bytes,
                flight: 0,
                body: 0,
            });
            channel.write_deadline = Some(env.now() + self.limits.write_timeout);
            self.goaway_sent = true;
        }
        if let Some(sending) = &mut channel.sending {
            let length = (sending.bytes.len() as u64).min(channel.send_credit) as usize;
            if length > 0 {
                channel.send_credit -= length as u64;
                sending.flight += length as u64;
                return Some(
                    channel
                        .lower
                        .send(StreamCommand::Write(sending.bytes.split_to(length))),
                );
            }
        }
        if channel.finish && channel.sending.is_none() {
            if !channel.fin_sent {
                channel.fin_sent = true;
                return Some(channel.lower.send(StreamCommand::End));
            }
            if !channel.stop_sent {
                channel.stop_sent = true;
                return Some(
                    channel
                        .lower
                        .send(StreamCommand::StopReceive(VarInt::from_u32(
                            code::NO_ERROR as u32,
                        ))),
                );
            }
        }
        None
    }

    fn take_event(&mut self) -> Option<Up> {
        let event = self.up.take().or_else(|| self.take_urgent());
        if event.is_some() {
            self.scan = self.channels.len();
        }
        event
    }

    fn take_urgent(&mut self) -> Option<Up> {
        let id = self.channels.ids().find(|&id| {
            let c = self.channels.get(id).unwrap();
            c.exchange.is_some() && c.report_written
        })?;
        let channel = self.channels.get_mut(id).unwrap();
        channel.report_written = false;
        Some(MuxEvent::Child(
            channel.exchange.unwrap(),
            ExchangeEvent::Written(channel.written),
        ))
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        if self.closing {
            return None;
        }
        self.channels
            .ids()
            .flat_map(|id| {
                let c = self.channels.get(id).unwrap();
                [c.head_deadline, c.write_deadline].into_iter().flatten()
            })
            .min()
            .map(|at| (at, ()))
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<bool, Infallible> {
        let expired = self.channels.ids().find(|&id| {
            let c = self.channels.get(id).unwrap();
            c.head_deadline
                .into_iter()
                .chain(c.write_deadline)
                .any(|at| at <= env.now())
        });
        let Some(id) = expired else {
            return Ok(false);
        };
        let channel = self.channels.get_mut(id).unwrap();
        channel.cancel(code::REQUEST_CANCELLED);
        if channel.critical {
            self.fail(code::EXCESSIVE_LOAD);
        }
        self.scan = self.channels.len();
        Ok(true)
    }

    fn is_terminal(&self) -> bool {
        self.gone && self.channels.is_empty() && self.up.is_none()
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
#[path = "../../../../verification/quic/kani/http3.rs"]
mod proofs;
