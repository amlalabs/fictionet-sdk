//! HTTP/3 connection coordination over the QUIC stream carrier.

use fictionet::time::Instant;
use std::convert::Infallible;
use std::sync::Arc;
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

/// What an HTTP/3 server connection shows its peer besides its responses:
/// the SETTINGS it sends, the unidirectional streams it opens, reserved
/// frames, and, through [`qpack::Policy`], how it compresses fields.
///
/// A world picks one per server with [`Http3::profile`] or
/// [`Responder::http3_profile`](super::Responder::http3_profile), so its
/// HTTP/3 looks like the server it stands for. [`Standard`] is the default.
/// The connection enforces what a profile advertises: the QPACK limits
/// bound its decoder, and the field section size bounds requests.
///
/// ```
/// use fictionet::stdlib::protocols::qpack::{self, Field, Policy, Style, Table};
/// use fictionet::stdlib::web::httpd::{Http3Profile, Http3Setting, Http3Stream};
///
/// /// A static-only server that sends no field section size.
/// struct Small;
/// impl Policy for Small {
///     fn capacity(&self, _peer: u64) -> u64 { 0 }
///     fn insert(&self, _: &Field, _: &Table) -> bool { false }
///     fn style(&self) -> Style { Style::DEFAULT }
/// }
/// impl Http3Profile for Small {
///     fn settings(&self) -> &[Http3Setting] {
///         &[Http3Setting::QpackTableCapacity(0), Http3Setting::QpackBlockedStreams(0)]
///     }
///     fn streams(&self) -> &[Http3Stream] {
///         &[Http3Stream::Control, Http3Stream::Decoder]
///     }
///     fn reserved_frames(&self) -> &[&'static [u8]] { &[] }
/// }
/// ```
pub trait Profile: qpack::Policy {
    /// SETTINGS entries, in the order they are sent. A QPACK limit left out
    /// is zero (RFC 9114 section 7.2.4.1).
    fn settings(&self) -> &[Setting];

    /// The unidirectional streams opened when the connection starts, in
    /// order. The control stream must be among them. A decoder stream is
    /// needed when the profile advertises a table capacity, and an encoder
    /// stream when its policy may use the peer's table (RFC 9204 section
    /// 4.2 lets a server leave either out otherwise).
    fn streams(&self) -> &[Local];

    /// Payloads of reserved frames (RFC 9114 section 7.2.8) sent once per
    /// connection, just before the first response HEADERS. Each gets its
    /// own reserved type.
    fn reserved_frames(&self) -> &[&'static [u8]];
}

/// One entry a [`Profile`] puts in SETTINGS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// SETTINGS_MAX_FIELD_SECTION_SIZE. The connection advertises and
    /// enforces this value, lowered to its [`Limits`] head size and to
    /// [`wire::MAX_FIELD_SECTION_SIZE`].
    FieldSectionSize(u64),
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY, the decoder's table limit. At most
    /// [`qpack::MAX_TABLE_CAPACITY`].
    QpackTableCapacity(u64),
    /// SETTINGS_QPACK_BLOCKED_STREAMS. At most [`qpack::MAX_BLOCKED_STREAMS`].
    QpackBlockedStreams(u64),
    /// A reserved identifier of the form 0x1f * N + 0x21 with a value of the
    /// same form, both drawn for each connection (RFC 9114 section 7.2.4.1).
    Reserved,
}

/// A unidirectional stream a [`Profile`] opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Local {
    /// The control stream, which starts with SETTINGS.
    Control,
    /// The QPACK encoder stream.
    Encoder,
    /// The QPACK decoder stream.
    Decoder,
    /// A stream of a reserved type (RFC 9114 section 6.2.3), drawn for each
    /// connection, carrying these bytes and then closed. Peers ignore it.
    Reserved(&'static [u8]),
}

/// The default [`Profile`]. It advertises a 4096-byte table with 16 blocked
/// streams and its field section size, opens the control, encoder and
/// decoder streams, sends no reserved frames, and encodes with
/// [`qpack::Selective`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Standard;

impl qpack::Policy for Standard {
    fn capacity(&self, peer_max: u64) -> u64 {
        qpack::Selective.capacity(peer_max)
    }
    fn insert(&self, field: &qpack::Field, table: &qpack::Table) -> bool {
        qpack::Selective.insert(field, table)
    }
    fn style(&self) -> qpack::Style {
        qpack::Selective.style()
    }
}

impl Profile for Standard {
    fn settings(&self) -> &[Setting] {
        const SETTINGS: [Setting; 3] = [
            Setting::FieldSectionSize(wire::MAX_FIELD_SECTION_SIZE),
            Setting::QpackTableCapacity(4096),
            Setting::QpackBlockedStreams(16),
        ];
        &SETTINGS
    }
    fn streams(&self) -> &[Local] {
        &[Local::Control, Local::Encoder, Local::Decoder]
    }
    fn reserved_frames(&self) -> &[&'static [u8]] {
        &[]
    }
}

/// What a connection takes from its [`Profile`] once, checked.
struct Advertised {
    qpack: qpack::Settings,
    /// The advertised SETTINGS_MAX_FIELD_SECTION_SIZE, before lowering.
    fields: Option<u64>,
}

impl Advertised {
    /// Panics on a profile that repeats an entry, exceeds the codec's
    /// limits, or leaves out a stream it needs: those are programming
    /// errors in the profile, found the first time it is used.
    fn of(profile: &dyn Profile) -> Self {
        let settings = profile.settings();
        let mut capacity = None;
        let mut blocked = None;
        let mut fields = None;
        for setting in settings {
            let (slot, value) = match *setting {
                Setting::FieldSectionSize(v) => (&mut fields, v),
                Setting::QpackTableCapacity(v) => (&mut capacity, v),
                Setting::QpackBlockedStreams(v) => (&mut blocked, v),
                Setting::Reserved => continue,
            };
            assert!(slot.replace(value).is_none(), "{setting:?} appears twice");
        }
        let qpack = qpack::Settings::new(
            capacity.unwrap_or(0),
            usize::try_from(blocked.unwrap_or(0)).unwrap_or(usize::MAX),
        )
        .expect("QPACK limits within the codec's maxima");
        let streams = profile.streams();
        let count = |kind: Local| streams.iter().filter(|s| **s == kind).count();
        assert_eq!(count(Local::Control), 1, "one control stream");
        assert!(count(Local::Encoder) <= 1 && count(Local::Decoder) <= 1);
        assert!(
            qpack.table_capacity() == 0 || count(Local::Decoder) == 1,
            "a table capacity needs a decoder stream"
        );
        assert!(
            profile.capacity(qpack::MAX_TABLE_CAPACITY) == 0 || count(Local::Encoder) == 1,
            "a policy that uses the table needs an encoder stream"
        );
        assert!(streams.len() <= usize::from(u8::MAX));
        Self { qpack, fields }
    }
}

impl dyn Profile + '_ {
    /// The unidirectional streams a connection holds besides requests: the
    /// peer's control and QPACK streams, and the profile's own.
    pub fn unidirectional(&self) -> usize {
        3 + self.streams().len()
    }
}

/// The connection's profile.
fn chosen(profile: &Option<Arc<dyn Profile>>) -> &dyn Profile {
    profile.as_deref().unwrap_or(&Standard)
}

/// A reserved identifier, 0x1f * N + 0x21 below 2^62 (RFC 9114 sections
/// 6.2.3, 7.2.4.1 and 7.2.8).
fn reserved_id(entropy: &dyn fictionet::Entropy) -> u64 {
    const N: u64 = (wire::MAX_VARINT - 0x21) / 0x1f + 1;
    0x1f * (entropy.random_u64() % N) + 0x21
}

/// HTTP/3 for one server connection whose TLS configuration negotiates `h3`.
/// Compose below it a [`QuicLayer`](fictionet::stdlib::services::quic::QuicLayer),
/// and above it the same [`HttpExchange`] children as HTTP/2.
/// [`super::Responder::http3`] supplies the SDK's handler children.
///
/// A [`Profile`] sets what the connection advertises and how it encodes;
/// [`Standard`] is the default. QPACK accepts dynamic references within the
/// advertised limits. Responses reference only acknowledged inserts, so they
/// never block on QPACK. Server push and extended CONNECT are not enabled.
/// The peer must allow as many unidirectional streams as the profile opens.
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
    /// None until [`Http3::profile`]: [`Standard`], with no allocation.
    profile: Option<Arc<dyn Profile>>,
    qpack: qpack::Settings,
    advertised_fields: Option<u64>,
    reserved_sent: bool,
    decoder_charge: Option<Charge>,
    encoder_charge: Option<Charge>,
    decoder_output: Option<Chunk>,
    encoder_output: Option<Chunk>,
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
    local: Option<Local>,
    critical: bool,
    input: Reader,
    request: Option<wire::RequestStream>,
    peer_encoder: bool,
    blocked: Option<(qpack::BlockedSection, Charge)>,
    cancelled: bool,
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
    fn new(
        lower: Child,
        stream: Stream,
        local: Option<Local>,
        budget: &Budget,
        limit: u64,
    ) -> Self {
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
            critical: local.is_some_and(|l| !matches!(l, Local::Reserved(_))),
            input: codec::Stream::in_storage(decoder, 0, ChargedBytes::new(budget)),
            request,
            peer_encoder: false,
            blocked: None,
            cancelled: false,
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
            // A local unidirectional stream has no receiving side to stop.
            stop_sent: local.is_some(),
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
    /// A server connection with these per-request limits and the
    /// [`Standard`] profile.
    pub fn new(limits: Limits) -> Self {
        let streams = (limits.streams as usize).min(4096);
        let advertised = Advertised::of(&Standard);
        Self {
            limits,
            channels: Slots::new(streams + (&Standard as &dyn Profile).unidirectional()),
            exchanges: Slots::new(streams),
            initialized: false,
            connected: false,
            local_opened: 0,
            opening: false,
            critical: Critical::default(),
            decoder: qpack::Table::new(advertised.qpack.table_capacity()),
            encoder: qpack::Encoder::new(0, wire::MAX_FIELD_SECTION_SIZE),
            profile: None,
            qpack: advertised.qpack,
            advertised_fields: advertised.fields,
            reserved_sent: false,
            decoder_charge: None,
            encoder_charge: None,
            decoder_output: None,
            encoder_output: None,
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

    /// Chooses what this connection advertises and how it encodes, before
    /// it opens. Panics on a profile that repeats a SETTINGS entry, exceeds
    /// [`qpack::MAX_TABLE_CAPACITY`] or [`qpack::MAX_BLOCKED_STREAMS`], or
    /// leaves out a stream it needs.
    pub fn profile(mut self, profile: Arc<dyn Profile>) -> Self {
        assert!(!self.initialized, "the profile precedes the connection");
        let advertised = Advertised::of(profile.as_ref());
        self.decoder = qpack::Table::new(advertised.qpack.table_capacity());
        self.qpack = advertised.qpack;
        self.advertised_fields = advertised.fields;
        let streams = (self.limits.streams as usize).min(4096);
        self.channels = Slots::new(streams + profile.unidirectional());
        self.profile = Some(profile);
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
        (self.limits.head.head as u64)
            .min(wire::MAX_FIELD_SECTION_SIZE)
            .min(self.advertised_fields.unwrap_or(u64::MAX))
    }

    fn init(&mut self, budget: &Budget) -> bool {
        if self.initialized {
            return true;
        }
        let streams = (self.limits.streams as usize).min(4096);
        let unidirectional = chosen(&self.profile).unidirectional();
        let Some(channels) = Slots::with_budget(streams + unidirectional, budget) else {
            return false;
        };
        let Some(exchanges) = Slots::with_budget(streams, budget) else {
            return false;
        };
        let Some(dates) = budget.charge(self.dates.held()) else {
            return false;
        };
        let Some(decoder) = budget.charge(self.decoder.most_held()) else {
            return false;
        };
        self.channels = channels;
        self.exchanges = exchanges;
        self.dates_charge = Some(dates);
        self.decoder_charge = Some(decoder);
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
                channel.peer_encoder = header == wire::StreamHeader::QpackEncoder;
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
                } else if let Some(increment) = self.decoder.take_increment() {
                    self.feedback(env.budget(), increment);
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
                            let peer_max = settings
                                .get(wire::setting::QPACK_MAX_TABLE_CAPACITY)
                                .unwrap_or(0);
                            let capacity = chosen(&self.profile).capacity(peer_max).min(peer_max);
                            // Required Insert Counts depend on the peer's
                            // maximum, but an encoder that never uses its
                            // table needs neither them nor table storage.
                            let mut encoder = qpack::Encoder::new(
                                if capacity == 0 { 0 } else { peer_max },
                                self.peer_fields,
                            );
                            let Some(charge) = env.budget().charge(encoder.most_held()) else {
                                self.fail(code::EXCESSIVE_LOAD);
                                return;
                            };
                            let capacity = capacity.min(encoder.table().max_capacity());
                            if capacity != 0 {
                                let instruction = encoder.set_capacity(capacity).unwrap();
                                self.encoder_output =
                                    styled(env.budget(), qpack::MAX_INTEGER_BYTES, |out| {
                                        instruction.write_styled(chosen(&self.profile).style(), out)
                                    });
                                if self.encoder_output.is_none() {
                                    self.fail(code::EXCESSIVE_LOAD);
                                    return;
                                }
                            }
                            self.encoder = encoder;
                            self.encoder_charge = Some(charge);
                        }
                        // No push was promised, so no push can be cancelled.
                        wire::Frame::CancelPush(_) => self.fail(code::ID_ERROR),
                        _ => {}
                    }
                    return;
                };
                let result = request.step(&frame, &self.decoder);
                self.request_result(env, id, result);
            }
        }
    }

    fn feedback(&mut self, budget: &Budget, instruction: qpack::DecoderInstruction) {
        // Reading and resuming pause while this slot is occupied. Never lose
        // an ack: decoding has already advanced the table's reported count.
        assert!(self.decoder_output.is_none());
        self.decoder_output = encode(budget, &instruction, qpack::MAX_INTEGER_BYTES);
        if self.decoder_output.is_none() {
            self.fail(code::EXCESSIVE_LOAD);
        }
    }

    fn request_result(
        &mut self,
        env: &mut Env<'_, ()>,
        id: ChildId,
        result: Result<wire::RequestResult, wire::Error>,
    ) {
        let event = match result {
            Err(error) => {
                self.error(id, error);
                return;
            }
            Ok(wire::RequestResult::Blocked(section)) => {
                let (count, bytes) = self
                    .channels
                    .ids()
                    .filter_map(|id| self.channels.get(id)?.blocked.as_ref())
                    .fold((0, 0), |(count, bytes), (s, _)| {
                        // An insert can make a retained section ready before
                        // the fair stream scan resumes it. It no longer counts
                        // against SETTINGS_QPACK_BLOCKED_STREAMS.
                        (
                            count
                                + usize::from(
                                    s.required_insert_count() > self.decoder.insert_count(),
                                ),
                            bytes + s.held(),
                        )
                    });
                if count >= self.qpack.blocked_streams() {
                    self.fail(code::QPACK_DECOMPRESSION_FAILED);
                    return;
                }
                if section.held() > qpack::MAX_BLOCKED_BYTES.saturating_sub(bytes) {
                    self.fail(code::EXCESSIVE_LOAD);
                    return;
                }
                let Some(charge) = env.budget().charge(section.held()) else {
                    self.fail(code::EXCESSIVE_LOAD);
                    return;
                };
                self.channels.get_mut(id).unwrap().blocked = Some((section, charge));
                return;
            }
            Ok(wire::RequestResult::Event { event, ack }) => {
                if let Some(ack) = ack {
                    self.feedback(env.budget(), ack);
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

    fn read(&mut self, env: &mut Env<'_, ()>, id: ChildId) -> bool {
        let channel = self.channels.get_mut(id).unwrap();
        if channel.local.is_some()
            || channel.input_done
            || channel.pending.is_some()
            || channel.reset.is_some()
            || self.decoder_output.is_some() && (channel.request.is_some() || channel.peer_encoder)
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
        if let Some((section, _)) = &channel.blocked {
            if section.required_insert_count() > self.decoder.insert_count() {
                return false;
            }
            let (section, _charge) = channel.blocked.take().unwrap();
            let result = channel
                .request
                .as_mut()
                .unwrap()
                .resume(channel.stream, section.retry(&self.decoder));
            self.request_result(env, id, result);
            return true;
        }
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
        if self.encoder_output.is_none() && self.encoder.table().capacity() != 0 {
            // An instruction is smaller than the RFC size of its field. Pay
            // for the entire batch before changing the encoder's table.
            let bound = fields.iter().map(qpack::Field::size).sum::<u64>() as usize;
            if let Some(mut bytes) = ChargedBytes::with_capacity(env.budget(), bound) {
                bytes
                    .fill(|out| {
                        for field in &fields {
                            if let Some(instruction) =
                                self.encoder.warm(field, chosen(&self.profile))
                            {
                                instruction.write_styled(chosen(&self.profile).style(), out)?;
                            }
                        }
                        Ok::<(), qpack::Error>(())
                    })
                    .expect("QPACK insertions fit the fields' RFC sizes");
                if !bytes.is_empty() {
                    bytes.trim();
                    self.encoder_output = Some(bytes.into_chunk());
                }
            }
        }
        let headers = wire::HeaderList { fields };
        let kind = if status.is_some() {
            wire::HeaderKind::Response
        } else {
            wire::HeaderKind::Trailers
        };
        let section = headers.section(&mut self.encoder, stream, kind).ok()?;
        let mut payload = Vec::new();
        section
            .write_styled(chosen(&self.profile).style(), &mut payload)
            .ok()?;
        // Reserved frames go once, before the first response HEADERS.
        let reserved: &[&[u8]] = if status.is_some() && !self.reserved_sent {
            chosen(&self.profile).reserved_frames()
        } else {
            &[]
        };
        let bound = reserved
            .iter()
            .try_fold(payload.len() + wire::MAX_FRAME_HEADER, |n, frame| {
                n.checked_add(frame.len() + wire::MAX_FRAME_HEADER)
            })?;
        let entropy = env.entropy();
        let bytes = styled(env.budget(), bound, |out| {
            use fictionet::stdlib::protocols::quic;
            for frame in reserved {
                quic::VarInt(reserved_id(entropy))
                    .write(out)
                    .map_err(drop)?;
                quic::VarInt(frame.len() as u64).write(out).map_err(drop)?;
                out.extend_from_slice(frame);
            }
            wire::Frame::Headers(payload).write(out).map_err(drop)
        })?;
        self.reserved_sent |= status.is_some();
        Some(bytes)
    }
}

/// Writes at most `bound` bytes into a charged chunk.
fn styled<E>(
    budget: &Budget,
    bound: usize,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), E>,
) -> Option<Chunk> {
    let mut bytes = ChargedBytes::with_capacity(budget, bound)?;
    bytes.fill(write).ok()?;
    bytes.trim();
    Some(bytes.into_chunk())
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
            MuxEvent::Control(ControlEvent::Unopened(_)) => {
                self.local_opened += 1;
                self.opening = false;
            }
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
                let local = stream
                    .local
                    .then(|| chosen(&self.profile).streams()[usize::from(self.local_opened)]);
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
                        StreamEvent::Data(mut bytes) => {
                            if channel.input_done || channel.reset.is_some() {
                                return Ok(Admit::Taken);
                            }
                            // A QUIC delivery can contain the stream type and
                            // several instructions. Let the codec consume one
                            // item and change its input limit before admitting
                            // the charged remainder through the carrier again.
                            let n = channel.input.push(&bytes);
                            if n == 0 && !bytes.is_empty() {
                                return Ok(Admit::Blocked(MuxEvent::Child(
                                    lower,
                                    StreamEvent::Data(bytes),
                                )));
                            }
                            bytes.advance(n);
                            if !bytes.is_empty() {
                                return Ok(Admit::Partial(MuxEvent::Child(
                                    lower,
                                    StreamEvent::Data(bytes),
                                )));
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
        if !self.closing
            && self.qpack.table_capacity() != 0
            && channel.request.is_some()
            && !channel.cancelled
            && (channel.reset.is_some()
                || (channel.lost || channel.stop_sent) && !channel.input_done)
        {
            if self.decoder_output.is_some() {
                self.scan = self.scan.saturating_sub(1);
                return Ok(self.scan > 0);
            }
            channel.cancelled = true;
            channel.blocked = None;
            let stream = channel.stream;
            self.feedback(
                env.budget(),
                qpack::DecoderInstruction::StreamCancel(stream),
            );
            self.scan = self.channels.len();
            return Ok(true);
        }
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
        if self.connected
            && usize::from(self.local_opened) < chosen(&self.profile).streams().len()
            && !self.opening
        {
            self.opening = true;
            // A reserved stream is optional: a peer that allows too few
            // streams for it still gets the critical ones.
            let next = chosen(&self.profile).streams()[usize::from(self.local_opened)];
            return Some(MuxCommand::control(if matches!(next, Local::Reserved(_)) {
                ControlCommand::OpenIfAllowed(Dir::Uni)
            } else {
                ControlCommand::OpenOrClose {
                    direction: Dir::Uni,
                    error: VarInt::from_u32(code::STREAM_CREATION_ERROR as u32),
                }
            }));
        }
        let ready = |id: ChildId| {
            let channel = self.channels.get(id).unwrap();
            channel.receive_due > 0
                || channel.reset.is_some() && !channel.retiring
                || channel.local.is_some() && !channel.response_started
                || channel.sending.is_none()
                    && match channel.local {
                        Some(Local::Encoder) => self.encoder_output.is_some(),
                        Some(Local::Decoder) => self.decoder_output.is_some(),
                        _ => false,
                    }
                || channel
                    .sending
                    .as_ref()
                    .is_some_and(|s| !s.bytes.is_empty() && channel.send_credit > 0)
                || channel.finish
                    && channel.sending.is_none()
                    && (!channel.fin_sent || !channel.stop_sent)
                || channel.local == Some(Local::Control)
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
            use fictionet::stdlib::protocols::quic;
            let entropy = env.entropy();
            let bytes = match local {
                Local::Control => {
                    let entries = chosen(&self.profile)
                        .settings()
                        .iter()
                        .map(|setting| {
                            let (id, value) = match *setting {
                                Setting::FieldSectionSize(_) => {
                                    (wire::setting::MAX_FIELD_SECTION_SIZE, self.field_limit())
                                }
                                Setting::QpackTableCapacity(_) => (
                                    wire::setting::QPACK_MAX_TABLE_CAPACITY,
                                    self.qpack.table_capacity(),
                                ),
                                Setting::QpackBlockedStreams(_) => (
                                    wire::setting::QPACK_BLOCKED_STREAMS,
                                    self.qpack.blocked_streams() as u64,
                                ),
                                Setting::Reserved => (reserved_id(entropy), reserved_id(entropy)),
                            };
                            wire::Setting { id, value }
                        })
                        .collect();
                    let frame = wire::Frame::Settings(wire::Settings { entries });
                    styled(
                        env.budget(),
                        1 + wire::MAX_FRAME_HEADER + wire::MAX_SETTINGS_BYTES,
                        |out| {
                            out.push(0);
                            frame.write(out)
                        },
                    )?
                }
                Local::Encoder => Chunk::copy_of(env.budget(), &[2])?,
                Local::Decoder => Chunk::copy_of(env.budget(), &[3])?,
                Local::Reserved(payload) => styled(env.budget(), 8 + payload.len(), |out| {
                    quic::VarInt(reserved_id(entropy)).write(out)?;
                    out.extend_from_slice(payload);
                    Ok::<(), quic::Error>(())
                })?,
            };
            // A reserved stream ends after its bytes.
            let finish = matches!(local, Local::Reserved(_));
            let channel = self.channels.get_mut(id).unwrap();
            channel.response_started = true;
            channel.finish = finish;
            channel.write_deadline = Some(env.now() + self.limits.write_timeout);
            channel.sending = Some(Sending {
                bytes,
                flight: 0,
                body: 0,
            });
        }
        let channel = self.channels.get_mut(id).unwrap();
        if channel.sending.is_none() {
            let bytes = match channel.local {
                Some(Local::Encoder) => self.encoder_output.take(),
                Some(Local::Decoder) => self.decoder_output.take(),
                _ => None,
            };
            if let Some(bytes) = bytes {
                channel.sending = Some(Sending {
                    bytes,
                    flight: 0,
                    body: 0,
                });
                channel.write_deadline = Some(env.now() + self.limits.write_timeout);
                self.scan = self.channels.len();
            }
        }
        let channel = self.channels.get_mut(id).unwrap();
        if channel.local == Some(Local::Control)
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
