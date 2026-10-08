//! HTTP/2 and gRPC in a capture: [`Capture`](fictionet::observe::http2::Capture) presents each
//! direction's frames, header blocks and gRPC messages, on
//! [`stdlib::http2`](fictionet::stdlib::http2)'s observation readers
//! ([`Frames::for_observation`](fictionet::stdlib::http2::Frames::for_observation)
//! and [`HeaderBlocks::for_observation`](fictionet::stdlib::http2::HeaderBlocks::for_observation))
//! and [`codec::Frames<grpc::Message>`](fictionet::stdlib::codec::Frames<grpc::Message>).
//!
//! The file uses only public observe and stdlib APIs, so a copy of it can
//! replace the built-in, registered the same way.

use fictionet::observe::{Decoded, Layer, Placement, Present};
use fictionet::stdlib::codec::{Decode, Demux, Fail, Spans, Step, Wire};
use fictionet::stdlib::{grpc, hpack};
use fictionet::stdlib::http2::{
    Error, ErrorCode, Frame, FrameHeader, FrameItem, Frames, HEADER_LEN, HeaderBlocks, MAX_WINDOW, PREFACE,
    Setting,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

fn protocol(reason: &'static str) -> Error {
    Error { code: ErrorCode::ProtocolError, reason }
}
fn size(reason: &'static str) -> Error {
    Error { code: ErrorCode::FrameSizeError, reason }
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let b = bytes.get(at..at.saturating_add(4)).ok_or_else(|| size("truncated integer"))?;
    Ok(u32::from_be_bytes(b.try_into().map_err(|_| size("truncated integer"))?))
}
/// A DATA payload without its padding. `None`: the padding is longer
/// than the frame.
fn unpad(payload: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & 8 == 0 {
        return Some(payload);
    }
    let (&pad, rest) = payload.split_first()?;
    rest.get(..rest.len().checked_sub(usize::from(pad))?)
}
/// A gRPC message's summary: the encoded body, not decompressed.
fn grpc_summary(item: &grpc::Message) -> String {
    format!("{} bytes{}", item.data.len(), if item.compressed { ", compressed" } else { "" })
}
/// A gRPC message's fields: the compressed flag, the length prefix and
/// the encoded body.
fn grpc_fields(item: &grpc::Message, bytes: &[u8], layer: &mut Layer) {
    layer.field("Compressed", item.compressed.to_string(), (0, 1));
    layer.field("Length", item.data.len().to_string(), (1, grpc::HEADER_LEN));
    layer.field("Message", format!("{} bytes", item.data.len()), (grpc::HEADER_LEN, bytes.len()));
}


/// Aggregate gRPC DATA budget used by the built-in capture presenter.
pub const CAPTURE_DATA_BUDGET: usize = 8 << 20;
/// Payload bytes retained for an incomplete frame in the built-in presenter.
pub const CAPTURE_FRAME_LIMIT: usize = (32 << 10) - HEADER_LEN;
/// Bounded packet read-ahead used when registering the capture decoder.
pub const CAPTURE_READ_AHEAD: usize = (32 << 10) + 65_535;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MessageDisplay {
    message: grpc::Message,
    bytes: Vec<u8>,
    start: Option<u64>,
}
/// One capture display item, with relative HTTP/2 fields and any completed
/// gRPC messages. Use [`Capture`]'s [`Present`] implementation to place it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureItem {
    layer: Layer,
    info: String,
    buffer: &'static str,
    malformed: bool,
    reset: bool,
    messages: Vec<MessageDisplay>,
    offset: u64,
}
struct Call {
    spans: Spans,
    outer: u64,
}
/// Shared gRPC DATA credit for capture connections, capped at 8 MiB.
/// Clone this handle into a registry factory and use [`Capture::pair_in`].
/// The factory and every registry clone then charge the same byte limit.
/// Copied modules and user presenters can use the same constructor pattern.
#[derive(Clone)]
pub struct CaptureBudget {
    used: Arc<Mutex<usize>>,
    limit: usize,
}
impl CaptureBudget {
    /// Sets the total unread DATA limit across all participating connections.
    pub fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(Mutex::new(0)),
            limit: limit.min(CAPTURE_DATA_BUDGET),
        }
    }
    /// Bytes charged across all connections. A failed lock reports the limit.
    pub fn held(&self) -> usize {
        self.used.lock().map_or(self.limit, |used| *used)
    }
}
impl Default for CaptureBudget {
    /// Uses the built-in aggregate DATA limit.
    fn default() -> Self {
        Self::new(CAPTURE_DATA_BUDGET)
    }
}
const CAPTURE_CALL_LIMIT: usize = 256;
struct CaptureCalls {
    messages: Demux<(bool, u32), fictionet::stdlib::codec::Frames::<grpc::Message>>,
    state: BTreeMap<(bool, u32), Call>,
    budget: CaptureBudget,
    charged: usize,
    client: Option<bool>,
}
impl CaptureCalls {
    fn new(budget: CaptureBudget) -> Self {
        Self {
            messages: Demux::new(CAPTURE_CALL_LIMIT, budget.limit, |_| {
                fictionet::stdlib::codec::Frames::<grpc::Message>::default()
            }),
            state: BTreeMap::new(),
            budget,
            charged: 0,
            client: None,
        }
    }
    fn total(&self) -> usize {
        self.messages.total()
    }
    fn account(&mut self) {
        if let Ok(mut used) = self.budget.used.lock() {
            let total = self.total();
            *used = used.saturating_sub(self.charged).saturating_add(total);
            self.charged = total;
        }
    }
    fn push(&mut self, key: &(bool, u32), bytes: &[u8]) -> usize {
        let Ok(mut used) = self.budget.used.lock() else {
            return 0;
        };
        let before = self.total();
        *used = used.saturating_sub(self.charged).saturating_add(before);
        let room = self.budget.limit.saturating_sub(*used);
        let n = self
            .messages
            .push(key, bytes.get(..bytes.len().min(room)).unwrap_or_default());
        self.charged = self.total();
        *used = used.saturating_sub(before).saturating_add(self.charged);
        n
    }
    fn remove(&mut self, key: &(bool, u32)) {
        self.messages.remove(key);
        self.state.remove(key);
        self.account();
    }
    fn remove_where(&mut self, matches: impl Fn(&(bool, u32)) -> bool) {
        let keys: Vec<_> = self
            .state
            .keys()
            .filter(|key| matches(key))
            .copied()
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }
}
impl Drop for CaptureCalls {
    fn drop(&mut self) {
        if let Ok(mut used) = self.budget.used.lock() {
            *used = used.saturating_sub(self.charged);
        }
    }
}

/// A terminal capture framing error or an incomplete gRPC message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// HTTP/2 framing or header assembly failed.
    Http2(Error),
    /// A gRPC message was incomplete when its direction ended.
    GrpcTruncated {
        /// The HTTP/2 stream carrying the message.
        stream: u32,
        /// Incomplete message bytes retained at EOF.
        unread: usize,
    },
}
impl From<Error> for CaptureError {
    fn from(error: Error) -> Self {
        Self::Http2(error)
    }
}
impl core::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Http2(error) => error.fmt(f),
            Self::GrpcTruncated { stream, unread } => {
                write!(
                    f,
                    "gRPC: truncated message on stream {stream} at EOF ({unread} bytes)"
                )
            }
        }
    }
}
impl core::error::Error for CaptureError {}

/// HTTP/2 capture decoding through [`Present`] and [`fictionet::observe::Observed`].
/// Uses the same frame parser and header assembly as [`Session`](fictionet::stdlib::http2::Session), with
/// tolerant HPACK and header-only oversized items followed by `Skip`.
/// Complete frames already available in bounded read-ahead are displayed.
/// Missing bytes stop the direction and clear HPACK and DATA state.
///
/// Recognized gRPC streams use [`Demux`] of [`codec::Frames<grpc::Message>`](fictionet::stdlib::codec::Frames). Both directions
/// share at most 256 call entries, each with at most 256 provenance spans.
/// Consumed spans are pruned after each message. RST_STREAM releases both
/// halves. GOAWAY releases only streams started by its receiver, above
/// `last_stream`. The preface or request and response headers identify roles.
/// Calls are kept when the sender's role is unknown.
/// Share a [`CaptureBudget`] across connections, including nested TLS streams.
/// Register a copied version exactly like the built-in:
/// ```
/// use fictionet::observe::{Registry, Match, http2};
/// let mut registry = Registry::new();
/// let budget = http2::CaptureBudget::default();
/// registry.register_with_buffer("http2", |_| Match::Yes,
///     http2::CAPTURE_READ_AHEAD, move |_| http2::Capture::pair_in(&budget));
/// ```
pub struct Capture {
    frames: Frames,
    blocks: HeaderBlocks,
    calls: Arc<Mutex<CaptureCalls>>,
    reverse: bool,
    offset: u64,
    stopped: bool,
    data_budget: usize,
}
impl Default for Capture {
    /// Creates one direction with its own DATA budget.
    fn default() -> Self {
        Self::new(CAPTURE_DATA_BUDGET)
    }
}
impl Capture {
    /// Creates one direction with a DATA budget capped at 8 MiB.
    /// Use [`pair_in`](Self::pair_in) to share credit across connections.
    pub fn new(data_budget: usize) -> Self {
        Self::in_budget(&CaptureBudget::new(data_budget))
    }
    fn in_budget(budget: &CaptureBudget) -> Self {
        Self {
            frames: Frames::for_observation(CAPTURE_FRAME_LIMIT),
            blocks: HeaderBlocks::for_observation(),
            calls: Arc::new(Mutex::new(CaptureCalls::new(budget.clone()))),
            reverse: false,
            offset: 0,
            stopped: false,
            data_budget: budget.limit,
        }
    }
    /// Creates both capture directions with one DATA budget for this pair.
    pub fn pair(data_budget: usize) -> [Self; 2] {
        Self::pair_in(&CaptureBudget::new(data_budget))
    }
    /// Creates a pair charged to the supplied budget across all connections.
    /// A gap releases only that direction's calls. Peer resets release both.
    /// The first direction's `held()` counts the pair's DATA once.
    pub fn pair_in(budget: &CaptureBudget) -> [Self; 2] {
        let first = Self::in_budget(budget);
        let mut second = Self::in_budget(budget);
        second.calls = Arc::clone(&first.calls);
        second.reverse = true;
        [first, second]
    }
    fn remove_call(&mut self, stream: u32) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remove(&(self.reverse, stream));
        }
    }
    fn clear_calls(&mut self) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remove_where(|key| key.0 == self.reverse);
        }
    }
    fn open_call(&mut self, stream: u32, item: &mut CaptureItem) {
        if let Ok(mut calls) = self.calls.lock() {
            let key = (self.reverse, stream);
            if calls.state.contains_key(&key) {
                return;
            }
            if calls.state.len() < CAPTURE_CALL_LIMIT {
                calls.state.insert(
                    key,
                    Call {
                        spans: Spans::new(256),
                        outer: 0,
                    },
                );
                return;
            }
        }
        item.malformed = true;
        item.layer
            .note("gRPC", "call state limit reached or unavailable");
    }
    fn grpc_data(
        &mut self,
        stream: u32,
        data: &[u8],
        start: u64,
        end: bool,
        item: &mut CaptureItem,
    ) {
        let shared = Arc::clone(&self.calls);
        let Ok(mut calls) = shared.lock() else {
            item.malformed = true;
            return;
        };
        let key = (self.reverse, stream);
        let Some(call) = calls.state.get_mut(&key) else {
            return;
        };
        let Ok(gap) = usize::try_from(start.saturating_sub(call.outer)) else {
            item.malformed = true;
            calls.remove(&key);
            return;
        };
        call.spans.skip(gap);
        call.spans.push_exact(data.len());
        call.outer = start.saturating_add(data.len() as u64);
        let mut rest = data;
        let mut more = 0usize;
        loop {
            let n = calls.push(&key, rest);
            rest = rest.get(n..).unwrap_or_default();
            if rest.is_empty() && end {
                calls.messages.end(&key);
            }
            let mut failed = false;
            let CaptureCalls {
                state, messages, ..
            } = &mut *calls;
            if let Some(call) = state.get_mut(&key)
                && let Some(inner) = messages.get_mut(&key)
            {
                while let Some(result) = inner.with_next(|message, bytes, range| {
                    let start = call.spans.locate_exact(range).map(|r| r.start);
                    MessageDisplay {
                        message,
                        bytes: bytes.to_vec(),
                        start,
                    }
                }) {
                    match result {
                        Ok(message) if item.messages.len() < 256 => item.messages.push(message),
                        Ok(_) => more = more.saturating_add(1),
                        Err(_) => {
                            item.malformed = true;
                            failed = true;
                        }
                    }
                    call.spans.discard_before(inner.offset());
                }
            }
            calls.account();
            if failed || (n == 0 && !rest.is_empty()) {
                item.malformed = true;
                item.layer
                    .note("gRPC", "message decoding stopped or DATA budget exhausted");
                calls.remove(&key);
                break;
            }
            if rest.is_empty() {
                if end {
                    calls.remove(&key);
                }
                break;
            }
        }
        if more != 0 {
            item.layer
                .note("gRPC", format!("{more} more messages, not shown"));
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.clear_calls();
    }
}
fn preview(b: &[u8]) -> Option<String> {
    let cut = b.get(..b.len().min(160))?;
    let text = std::str::from_utf8(cut).ok()?;
    if !text
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    let mut text = text.replace("\r\n", "\\r\\n").replace('\n', "\\n");
    if b.len() > cut.len() {
        text.push('…');
    }
    Some(text)
}
fn display_error(code: u32) -> String {
    ErrorCode::name(code).map_or_else(|| format!("error {code}"), str::to_owned)
}
fn capture_layer(h: FrameHeader, raw: &[u8]) -> CaptureItem {
    let mut layer = Layer::new("HyperText Transfer Protocol 2", 0, (0, raw.len()));
    let mut flags = Vec::new();
    let names: &[(u8, &str)] = match h.kind {
        0 => &[(1, "END_STREAM"), (8, "PADDED")],
        1 => &[
            (1, "END_STREAM"),
            (4, "END_HEADERS"),
            (8, "PADDED"),
            (0x20, "PRIORITY"),
        ],
        4 | 6 => &[(1, "ACK")],
        5 => &[(4, "END_HEADERS"), (8, "PADDED")],
        9 => &[(4, "END_HEADERS")],
        _ => &[],
    };
    for (bit, name) in names {
        if h.flags & bit != 0 {
            flags.push(*name);
        }
    }
    layer.field("Length", h.length.to_string(), (0, 3));
    layer.field("Type", format!("{} ({})", h.name(), h.kind), (3, 4));
    layer.field(
        "Flags",
        if flags.is_empty() {
            format!("0x{:02x}", h.flags)
        } else {
            flags.join(", ")
        },
        (4, 5),
    );
    layer.field("Stream", h.stream.to_string(), (5, 9));
    CaptureItem {
        layer,
        info: format!("{}[{}]", h.name(), h.stream),
        buffer: "Reassembled HTTP/2 frame",
        malformed: false,
        reset: false,
        messages: Vec::new(),
        offset: 0,
    }
}
fn present_block(item: &mut CaptureItem, block: &hpack::Block) {
    let get = |name: &[u8]| {
        block
            .headers
            .iter()
            .find(|h| h.name.as_deref() == Some(name))
            .and_then(|h| h.value.as_deref())
            .map(String::from_utf8_lossy)
    };
    if let Some(status) = get(b":status") {
        let _ = write!(item.info, ": {status}");
    } else if let (Some(m), Some(p)) = (get(b":method"), get(b":path")) {
        let _ = write!(item.info, ": {m} {p}");
        if let Some(a) = get(b":authority") {
            let _ = write!(item.info, " ({a})");
        }
    }
    const UNKNOWN: &str =
        "not known: it names a table entry that a header block not decoded may have changed";
    for h in &block.headers {
        match (&h.name, &h.value) {
            (Some(n), Some(v)) => item
                .layer
                .note(&String::from_utf8_lossy(n), String::from_utf8_lossy(v)),
            (None, Some(v)) => item.layer.note(
                "Header",
                format!("{} (its name is {UNKNOWN})", String::from_utf8_lossy(v)),
            ),
            _ => item.layer.note("Header", UNKNOWN),
        }
    }
    if block.more > 0 {
        item.layer.note(
            "Header block",
            format!("{} more headers, not shown", block.more),
        );
    }
}
impl Decode for Capture {
    type Item = CaptureItem;
    type Error = CaptureError;
    const NAME: &'static str = "HTTP/2";
    /// The most unread frame bytes needed for a decoding step.
    fn capacity(&self) -> usize {
        self.frames.capacity()
    }
    /// Header state plus this pair's DATA, counted in its first direction.
    fn held(&self) -> usize {
        self.blocks.held().saturating_add(if self.reverse {
            0
        } else {
            self.calls
                .lock()
                .map_or(self.data_budget, |calls| calls.total())
        })
    }
    /// Reads one frame or display item, or skips a refused payload.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<CaptureItem>, CaptureError> {
        if self.stopped {
            return Ok(Step::End);
        }
        let (frame, n) = match self.frames.decode(input, eof)? {
            Step::Item(frame, n) => (frame, n),
            Step::Skip(n) => {
                self.offset = self.offset.saturating_add(n as u64);
                return Ok(Step::Skip(n));
            }
            Step::Need if eof && input.is_empty() && self.blocks.pending() => {
                self.clear_calls();
                return Err(protocol("incomplete header block at EOF").into());
            }
            Step::Need if eof && input.is_empty() => {
                let shared = Arc::clone(&self.calls);
                let mut calls = shared
                    .lock()
                    .map_err(|_| protocol("capture DATA state unavailable"))?;
                let keys: Vec<_> = calls
                    .state
                    .keys()
                    .filter(|k| k.0 == self.reverse)
                    .copied()
                    .collect();
                let mut failure = None;
                for key in keys {
                    calls.messages.end(&key);
                    if let Some(inner) = calls.messages.get_mut(&key) {
                        while let Some(result) = inner.next() {
                            if let Err(Fail::Truncated { unread }) = result {
                                failure.get_or_insert(CaptureError::GrpcTruncated {
                                    stream: key.1,
                                    unread,
                                });
                            }
                        }
                    }
                    calls.remove(&key);
                }
                if let Some(failure) = failure {
                    return Err(failure);
                }
                return Ok(Step::End);
            }
            Step::Need => return Ok(Step::Need),
            Step::End => return Ok(Step::End),
        };
        let start = self.offset;
        self.offset = self.offset.saturating_add(n as u64);
        if frame == FrameItem::Preface {
            if let Ok(mut calls) = self.calls.lock() {
                calls.client = Some(self.reverse);
            }
            let mut layer = Layer::new("HyperText Transfer Protocol 2", 0, (0, PREFACE.len()));
            layer.summary = "Connection preface".into();
            return Ok(Step::Item(
                CaptureItem {
                    layer,
                    info: "Magic".into(),
                    buffer: "HTTP/2 preface",
                    malformed: false,
                    reset: false,
                    messages: Vec::new(),
                    offset: 0,
                },
                n,
            ));
        }
        let raw = input.get(..n).ok_or_else(|| size("capture frame length"))?;
        let h = FrameHeader::parse(
            raw.get(..HEADER_LEN)
                .ok_or_else(|| size("capture header"))?,
        )?;
        let oversized = matches!(
            frame,
            FrameItem::Refused {
                oversized: true,
                ..
            }
        );
        let mut item = capture_layer(h, raw);
        item.offset = start;
        if let FrameItem::Refused {
            oversized: false,
            error,
            ..
        } = &frame
        {
            item.malformed = true;
            item.layer.note("Frame", error.reason);
        }
        let payload = if oversized {
            None
        } else {
            raw.get(HEADER_LEN..)
        };
        let block = self.blocks.read(h, payload)?;
        // Preserve the capture tree's order: interruption, payload, then
        // the fields and notes of the current header fragment.
        if block.interrupted
            && let Some((name, note)) = block.notes.first()
        {
            item.layer.note(name, note);
        }
        if oversized {
            item.layer
                .note("Payload", format!("{} bytes, too long to keep", h.length));
        }
        for (name, note) in block.notes.iter().skip(usize::from(block.interrupted)) {
            item.layer.note(name, note);
        }
        item.malformed |= block.malformed;
        let body = payload.unwrap_or_default();
        match h.kind {
            0 => {
                let data = match unpad(body, h.flags) {
                    Some(data) => data,
                    None => {
                        item.layer.note("Padding", "longer than the frame");
                        item.malformed = true;
                        &[]
                    }
                };
                let len = if oversized { h.length } else { data.len() };
                item.layer
                    .field("Data", format!("{len} bytes"), (9, 9 + body.len()));
                if let Some(text) = preview(data) {
                    item.layer.note("Text", text);
                }
                let _ = write!(item.info, " {len} bytes");
                if h.flags & 1 != 0 {
                    item.info.push_str(", end");
                }
                if oversized || item.malformed {
                    self.remove_call(h.stream);
                } else {
                    self.grpc_data(
                        h.stream,
                        data,
                        start.saturating_add(9 + u64::from(h.flags & 8 != 0)),
                        h.flags & 1 != 0,
                        &mut item,
                    );
                }
            }
            1 | 5 | 9 => {
                if h.kind == 5
                    && let Some(id) = block.promised
                {
                    let _ = write!(item.info, " promised {id}");
                }
                if let Some(b) = &block.block {
                    present_block(&mut item, b);
                    if block.promised.is_none()
                        && let Ok(mut calls) = self.calls.lock()
                        && calls.client.is_none()
                    {
                        if b.headers
                            .iter()
                            .any(|f| f.name.as_deref() == Some(b":method"))
                        {
                            calls.client = Some(self.reverse);
                        } else if b
                            .headers
                            .iter()
                            .any(|f| f.name.as_deref() == Some(b":status"))
                        {
                            calls.client = Some(!self.reverse);
                        }
                    }
                    let grpc = b.headers.iter().any(|f| {
                        f.name.as_deref() == Some(b"content-type")
                            && f.value
                                .as_deref()
                                .is_some_and(|v| grpc::ContentType::parse(v).is_some())
                    });
                    if grpc && h.kind != 5 {
                        self.open_call(h.stream, &mut item);
                    }
                }
                if block.end && h.kind != 5 && !self.blocks.pending() {
                    self.grpc_data(h.stream, &[], self.offset, true, &mut item);
                }
                if h.kind == 1 && h.flags & 1 != 0 {
                    item.info.push_str(", end");
                }
            }
            3 if body.len() >= 4 => {
                let code = match &frame {
                    FrameItem::Frame(Frame::Reset(reset)) => reset.code,
                    _ => u32_at(body, 0)?,
                };
                let e = display_error(code);
                item.layer.field("Error", e.clone(), (9, 13));
                let _ = write!(item.info, " {e}");
                item.reset = true;
                if let Ok(mut calls) = self.calls.lock() {
                    calls.remove_where(|key| key.1 == h.stream);
                }
            }
            4 => {
                let partial;
                let entries = match &frame {
                    FrameItem::Frame(Frame::Settings(settings)) => &settings.entries,
                    _ => {
                        partial = body
                            .as_chunks::<6>()
                            .0
                            .iter()
                            .map(|b| {
                                Ok(Setting {
                                    id: u16::from_be_bytes([
                                        *b.first().ok_or_else(|| size("setting"))?,
                                        *b.get(1).ok_or_else(|| size("setting"))?,
                                    ]),
                                    value: u32_at(b, 2)?,
                                })
                            })
                            .collect::<Result<Vec<_>, Error>>()?;
                        &partial
                    }
                };
                for (i, setting) in entries.iter().enumerate() {
                    let name = match setting.id {
                        1 => "HEADER_TABLE_SIZE",
                        2 => "ENABLE_PUSH",
                        3 => "MAX_CONCURRENT_STREAMS",
                        4 => "INITIAL_WINDOW_SIZE",
                        5 => "MAX_FRAME_SIZE",
                        6 => "MAX_HEADER_LIST_SIZE",
                        8 => "ENABLE_CONNECT_PROTOCOL",
                        _ => "setting",
                    };
                    let at = 9 + i * 6;
                    item.layer
                        .field(name, setting.value.to_string(), (at, at + 6));
                }
                item.info = if h.flags & 1 != 0 {
                    "SETTINGS ack"
                } else {
                    "SETTINGS"
                }
                .into();
            }
            6 => item.info = if h.flags & 1 != 0 { "PING ack" } else { "PING" }.into(),
            7 if body.len() >= 8 => {
                let (last_stream, code) = match &frame {
                    FrameItem::Frame(Frame::GoAway(goaway)) => (goaway.last_stream, goaway.code),
                    _ => (u32_at(body, 0)? & MAX_WINDOW, u32_at(body, 4)?),
                };
                let e = display_error(code);
                item.layer
                    .field("Last stream", last_stream.to_string(), (9, 13));
                item.layer.field("Error", e.clone(), (13, 17));
                item.info = format!("GOAWAY {e}");
                if let Ok(mut calls) = self.calls.lock()
                    && let Some(client) = calls.client
                {
                    let receiver_is_client = self.reverse != client;
                    calls.remove_where(|key| {
                        key.1 > last_stream && (key.1 % 2 == 1) == receiver_is_client
                    });
                }
            }
            8 if body.len() >= 4 => {
                let inc = match &frame {
                    FrameItem::Frame(Frame::WindowUpdate(update)) => update.increment,
                    _ => u32_at(body, 0)? & MAX_WINDOW,
                };
                item.layer
                    .field("Window increment", inc.to_string(), (9, 13));
                let _ = write!(item.info, " +{inc}");
            }
            _ => {}
        }
        item.layer.summary.clone_from(&item.info);
        Ok(Step::Item(item, n))
    }
}
impl Present for Capture {
    /// The frame's display summary.
    fn summary(item: &CaptureItem) -> String {
        item.layer.summary.clone()
    }
    /// Copies fields with ranges relative to the frame bytes.
    fn fields(item: &CaptureItem, _: &[u8], layer: &mut Layer) {
        layer.fields.clone_from(&item.layer.fields);
    }
    /// Places HTTP/2 and gRPC layers and updates the packet summary.
    fn present(
        item: &CaptureItem,
        bytes: &[u8],
        start: u64,
        place: &Placement,
        packet: &mut Decoded,
    ) {
        place.push(packet, start, bytes, item.buffer, item.layer.clone());
        if item.malformed {
            packet.tag("malformed");
        }
        if item.reset {
            packet.tag("reset");
        }
        if packet.level() == 2
            && item.info.starts_with("HEADERS")
            && !packet.info.starts_with("HEADERS")
        {
            // Requests and responses lead the summary even after control frames.
            packet.info = format!("{}, {}", item.info, packet.info);
            packet.cap_info();
        } else {
            packet.application(2, "HTTP/2", &item.info);
        }
        for message in &item.messages {
            let mut layer = Layer::new("gRPC", 0, (0, message.bytes.len()));
            layer.summary = grpc_summary(&message.message);
            grpc_fields(&message.message, &message.bytes, &mut layer);
            if let Some(at) = message.start {
                let origin = start.saturating_sub(item.offset);
                place.push(
                    packet,
                    origin.saturating_add(at),
                    &message.bytes,
                    "Reassembled gRPC message",
                    layer,
                );
            } else {
                let buf = packet.buffer("Reassembled gRPC message", message.bytes.clone());
                layer.buf = buf;
                packet.push(layer);
            }
        }
    }
    /// Reports a gRPC truncation as gRPC and other failures as HTTP/2.
    fn error(error: &Fail<CaptureError>, packet: &mut Decoded) {
        packet.tag("malformed");
        packet.info = match error {
            Fail::Protocol(error @ CaptureError::GrpcTruncated { .. }) => error.to_string(),
            Fail::Protocol(CaptureError::Http2(error)) => error.to_string(),
            _ => format!("HTTP/2: {}", fictionet::ErrorChain(error)),
        };
    }
    /// Bounds decoded headers by the packet's remaining display room.
    fn prepare(&mut self, packet: &Decoded) {
        self.blocks.set_list_limit(packet.room());
    }
    /// Whether an oversized payload still has bytes to skip.
    fn pending(&self) -> bool {
        self.frames.pending()
    }
    /// Drops this direction's state after a capture gap.
    fn reset(&mut self) {
        self.blocks.forget();
        self.clear_calls();
        self.frames = Frames::for_observation(CAPTURE_FRAME_LIMIT);
        self.stopped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Stream, Wire, pump};
    use fictionet::stdlib::test_support::contract;

    fn raw(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
        let mut out = FrameHeader {
            length: body.len(),
            kind,
            flags,
            stream,
        }
        .to_bytes()
        .unwrap();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn capture_follows_the_codec_contract() {
        let mut rng = fictionet::stdlib::codec::Lcg::new(0x6832);
        for _ in 0..128 {
            contract::check_decode(|| Capture::new(1024), &rng.bytes(128));
        }
    }

    #[test]
    fn canceled_capture_calls_release_both_directions() {
        let [a, b] = Capture::pair(CAPTURE_DATA_BUDGET);
        let mut a = Stream::new(a);
        let mut b = Stream::new(b);
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        for id in (1..601).step_by(2) {
            pump(&mut b, &raw(1, 4, id, &block), |_| {}).unwrap();
            pump(&mut b, &raw(0, 0, id, &[0, 0]), |_| {}).unwrap();
            pump(&mut a, &raw(3, 0, id, &8u32.to_be_bytes()), |_| {}).unwrap();
        }
        let mut messages = Vec::new();
        pump(&mut b, &raw(1, 4, 1001, &block), |_| {}).unwrap();
        pump(&mut b, &raw(0, 1, 1001, &[0, 0, 0, 0, 1, b'x']), |item| {
            messages.extend(item.messages)
        })
        .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message.data, b"x");
        assert_eq!(b.decoder().calls.lock().unwrap().total(), 0);
    }

    #[test]
    fn goaway_and_undecodable_trailers_release_capture_calls() {
        let [a, b] = Capture::pair(32);
        let mut a = Stream::new(a);
        let mut b = Stream::new(b);
        pump(&mut b, PREFACE, |_| {}).unwrap();
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        for dir in [&mut a, &mut b] {
            for id in [1, 3] {
                pump(dir, &raw(1, 4, id, &block), |_| {}).unwrap();
                pump(dir, &raw(0, 0, id, &[0, 0]), |_| {}).unwrap();
            }
        }
        pump(&mut a, &raw(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]), |_| {}).unwrap();
        assert_eq!(a.decoder().calls.lock().unwrap().total(), 4);
        pump(&mut a, &raw(1, 5, 1, &[0xff]), |_| {}).unwrap();
        assert_eq!(a.decoder().calls.lock().unwrap().total(), 2);
    }

    #[test]
    fn captured_grpc_messages_cross_data_frames_and_share_budget() {
        let mut block = Vec::new();
        hpack::Encoder::new(4096)
            .encode_block(
                &[
                    hpack::Field::new(":method", "POST"),
                    hpack::Field::new("content-type", "application/grpc"),
                ],
                &mut block,
            )
            .unwrap();
        let mut c = Stream::new(Capture::new(6));
        let mut items = Vec::new();
        for stream in [1, 3] {
            pump(&mut c, &raw(1, 4, stream, &block), |i| items.push(i)).unwrap();
        }
        pump(&mut c, &raw(0, 0, 1, &[0, 0, 0, 0]), |i| items.push(i)).unwrap();
        pump(&mut c, &raw(0, 0, 3, &[0, 0, 0]), |i| items.push(i)).unwrap();
        assert!(items.last().unwrap().malformed);
        pump(&mut c, &raw(0, 1, 1, &[1, b'x']), |i| items.push(i)).unwrap();
        assert_eq!(items.last().unwrap().messages[0].message.data, b"x");
        assert!(items.last().unwrap().messages[0].start.is_none());
    }

    #[test]
    fn capture_pair_shares_data_credit_and_clears_only_the_lost_direction() {
        let [a, b] = Capture::pair(8);
        let mut a = Stream::new(a);
        let mut b = Stream::new(b);
        let mut block = Vec::new();
        hpack::Encoder::new(4096)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        for stream in [&mut a, &mut b] {
            pump(stream, &raw(1, 4, 1, &block), |_| {}).unwrap();
            pump(stream, &raw(0, 0, 1, &[0, 0, 0, 0]), |_| {}).unwrap();
        }
        assert_eq!(a.decoder().calls.lock().unwrap().total(), 8);
        a.decoder().reset();
        assert_eq!(b.decoder().calls.lock().unwrap().total(), 4);
        let mut messages = Vec::new();
        pump(&mut b, &raw(0, 1, 1, &[1, b'z']), |item| {
            messages.extend(item.messages)
        })
        .unwrap();
        assert_eq!(messages[0].message.data, b"z");
        assert_eq!(b.decoder().calls.lock().unwrap().total(), 0);

        let [a, b] = Capture::pair(6);
        let mut a = Stream::new(a);
        let mut b = Stream::new(b);
        for stream in [&mut a, &mut b] {
            pump(stream, &raw(1, 4, 1, &block), |_| {}).unwrap();
        }
        pump(&mut a, &raw(0, 0, 1, &[0, 0, 0, 0]), |_| {}).unwrap();
        let mut malformed = false;
        pump(&mut b, &raw(0, 0, 1, &[0, 0, 0]), |item| {
            malformed |= item.malformed
        })
        .unwrap();
        assert!(malformed);
        assert_eq!(a.decoder().calls.lock().unwrap().total(), 4);
    }

    #[test]
    fn shared_capture_budget_counts_connections_once_and_returns_credit() {
        let budget = CaptureBudget::new(4096);
        let mut connections = Vec::new();
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        for _ in 0..32 {
            let mut pair = Capture::pair_in(&budget).map(Stream::new);
            for dir in &mut pair {
                pump(dir, &raw(1, 4, 1, &block), |_| {}).unwrap();
                let mut partial = vec![0, 0, 0, 4, 0];
                partial.resize(512, 0);
                pump(dir, &raw(0, 0, 1, &partial), |_| {}).unwrap();
            }
            connections.push(pair);
            assert!(budget.held() <= 4096);
            let held: usize = connections
                .iter_mut()
                .flat_map(|pair| pair.iter_mut())
                .map(|dir| dir.held())
                .sum();
            assert_eq!(held, budget.held());
        }
        assert_eq!(budget.held(), 4096);
        connections.remove(0);
        assert_eq!(budget.held(), 3072);
        connections[0][0].decoder().reset();
        assert_eq!(budget.held(), 2560);
        drop(connections);
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn completed_grpc_messages_prune_spans_but_keep_partial_messages() {
        let mut capture = Stream::new(Capture::default());
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        pump(&mut capture, &raw(1, 4, 1, &block), |_| {}).unwrap();
        for _ in 0..300 {
            // One whole empty message and the start of the next message.
            pump(&mut capture, &raw(0, 0, 1, &[0; 7]), |item| {
                assert_eq!(item.messages.len(), 1);
                assert!(item.messages[0].start.is_some());
            })
            .unwrap();
            assert_eq!(
                capture.decoder().calls.lock().unwrap().state[&(false, 1)]
                    .spans
                    .len(),
                1
            );
            pump(&mut capture, &raw(0, 0, 1, &[0; 3]), |item| {
                assert_eq!(item.messages.len(), 1);
                assert!(item.messages[0].start.is_none());
            })
            .unwrap();
            assert!(
                capture.decoder().calls.lock().unwrap().state[&(false, 1)]
                    .spans
                    .is_empty()
            );
        }
    }

    #[test]
    fn capture_call_limit_is_shared_and_reported() {
        let [a, b] = Capture::pair(4096);
        let mut dirs = [Stream::new(a), Stream::new(b)];
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("content-type", "application/grpc")],
                &mut block,
            )
            .unwrap();
        for n in 0..256 {
            pump(
                &mut dirs[n % 2],
                &raw(1, 4, 1 + n as u32 * 2, &block),
                |item| {
                    assert!(!item.malformed);
                },
            )
            .unwrap();
        }
        pump(&mut dirs[0], &raw(1, 4, 1001, &block), |item| {
            assert!(item.malformed);
            assert!(
                item.layer
                    .fields
                    .iter()
                    .any(|f| f.value.contains("call state limit"))
            );
        })
        .unwrap();
        pump(&mut dirs[1], &raw(3, 0, 1, &8u32.to_be_bytes()), |_| {}).unwrap();
        pump(&mut dirs[0], &raw(1, 4, 1003, &block), |item| {
            assert!(!item.malformed)
        })
        .unwrap();
        pump(&mut dirs[0], &raw(0, 1, 1003, &[0, 0, 0, 0, 0]), |item| {
            assert_eq!(item.messages.len(), 1);
            assert!(!item.malformed);
        })
        .unwrap();
    }

    #[test]
    fn oversized_interruption_keeps_capture_note_order() {
        let mut stream = Stream::new(Capture::default());
        pump(&mut stream, &raw(1, 0, 1, &[0x82]), |_| {}).unwrap();
        let header = FrameHeader {
            kind: 1,
            flags: 4,
            stream: 3,
            length: 40_000,
        }
        .to_bytes()
        .unwrap();
        let mut items = Vec::new();
        pump(&mut stream, &header, |item| items.push(item)).unwrap();
        let fields = &items[0].layer.fields;
        assert_eq!(fields[4].name, "Header block");
        assert!(fields[4].value.starts_with("the one before was cut off"));
        assert_eq!(fields[5].name, "Payload");
        assert_eq!(fields[6].name, "Header block");
        assert_eq!(
            fields[6].value,
            "not decoded, so later headers may not be known"
        );
    }

    #[test]
    fn data_demux_has_one_budget_across_streams() {
        let mut calls = Demux::new(4, 8, |_| fictionet::stdlib::codec::Frames::<grpc::Message>::with_limit(32));
        assert_eq!(calls.push(&1, &[0, 0, 0, 0]), 4);
        assert_eq!(calls.push(&3, &[0, 0, 0, 0]), 4);
        assert!(calls.next().is_none());
        assert_eq!(calls.total(), 8);
        assert_eq!(calls.push(&5, &[0]), 0);
        calls.remove(&1);
        assert_eq!(calls.push(&3, &[1, b'x']), 2);
        assert_eq!(calls.next().unwrap().1.unwrap().data, b"x");
        assert_eq!(calls.total(), 0);
    }
}
