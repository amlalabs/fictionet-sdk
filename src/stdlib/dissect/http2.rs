//! HTTP/2 and gRPC in a capture:
//! [`Capture`](fictionet::stdlib::dissect::http2::Capture) presents each direction's
//! frames, partial header blocks and gRPC messages. Frame grammar and HPACK
//! representations come from the protocol modules; missing capture evidence,
//! recovery and presentation belong here.
//!
//! The file uses only public dissector and stdlib APIs, so a copy of it can
//! replace the built-in, registered the same way.

use fictionet::stdlib::codec::{Decode, Demux, Fail, Spans, Step, Wire, be32};
use fictionet::stdlib::dissect::{
    Decoded, Layer, Match, Placement, Present, Registry, SummaryPriority,
};
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::http2::{
    Error, ErrorCode, Frame, FrameHeader, HEADER_LEN, HeaderPayload, MAX_WINDOW, PREFACE, Setting,
};
use fictionet::stdlib::protocols::{grpc, hpack};
use fictionet::sync::Mutex;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// A captured header whose referenced dynamic entry may be unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialHeader {
    /// Name octets, when the name was observed.
    pub name: Option<Vec<u8>>,
    /// Value octets, when the value was observed.
    pub value: Option<Vec<u8>>,
    /// Whether the literal was marked never indexed.
    pub never_index: bool,
}
/// Retained evidence from one captured HPACK block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialBlock {
    /// Headers in wire order, including explicitly unknown entries.
    pub headers: Vec<PartialHeader>,
    /// Headers omitted from presentation that still updated the table.
    pub more: usize,
}
impl PartialBlock {
    fn keep(
        &mut self,
        limit: usize,
        used: &mut usize,
        name: Option<&[u8]>,
        value: Option<&[u8]>,
        never_index: bool,
    ) {
        let len = name
            .map_or(0, <[u8]>::len)
            .saturating_add(value.map_or(0, <[u8]>::len));
        if self.headers.len() >= hpack::MAX_HEADERS || len > limit.saturating_sub(*used) {
            self.more = self.more.saturating_add(1);
            return;
        }
        *used += len;
        self.headers.push(PartialHeader {
            name: name.map(<[u8]>::to_vec),
            value: value.map(<[u8]>::to_vec),
            never_index,
        });
    }
}
/// HPACK evidence for one capture direction, independent of endpoint settings.
/// Newest known entries survive missing older entries. Size updates must still
/// precede fields, even when the peer's settings were not captured.
#[derive(Clone, Debug)]
pub struct PartialTable {
    table: hpack::DynamicTable,
    max: Option<usize>,
    unsure: bool,
}
impl Default for PartialTable {
    fn default() -> Self {
        Self {
            table: hpack::DynamicTable::default(),
            max: Some(4096),
            unsure: false,
        }
    }
}
impl PartialTable {
    /// Discards evidence after a missing or malformed block.
    pub fn forget(&mut self) {
        self.table.clear();
        self.max = None;
        self.unsure = true;
    }
    /// The latest observed capacity, or unknown after a missing block.
    pub fn table_capacity(&self) -> Option<usize> {
        self.max
    }
    /// Retained entry sizes, including HPACK entry overhead.
    pub fn table_size(&self) -> usize {
        self.table.size()
    }
    /// Number of retained entries.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }
    /// Whether older dynamic entries may be unknown.
    pub fn is_unsure(&self) -> bool {
        self.unsure
    }
    /// Allocated storage for retained entries.
    pub fn held(&self) -> usize {
        self.table.held()
    }
    fn evict(&mut self) {
        if let Some(max) = self.max {
            self.table.evict(max);
        }
        if self.table.evict(hpack::MAX_TABLE) {
            self.unsure = true;
        }
        if self
            .max
            .is_some_and(|max| self.table.size().saturating_add(hpack::ENTRY_OVERHEAD) > max)
        {
            self.unsure = false;
        }
    }
    /// Decodes a complete block while retaining bounded presentation and table
    /// storage. Invalid input forgets the table; unavailable entries remain partial.
    pub fn decode_block(
        &mut self,
        bytes: &[u8],
        limit: usize,
    ) -> Result<PartialBlock, hpack::Error> {
        let result = self.read_block(bytes, limit.min(hpack::MAX_DECODED));
        if result.is_err() {
            self.forget();
        }
        result
    }
    fn read_block(&mut self, bytes: &[u8], limit: usize) -> Result<PartialBlock, hpack::Error> {
        let mut out = PartialBlock::default();
        let mut used = 0;
        for representation in hpack::Representations::new(bytes, hpack::MAX_BLOCK * 8 / 5)? {
            match representation? {
                hpack::Representation::SizeUpdate(size) => {
                    self.max = Some(size);
                    self.evict();
                }
                hpack::Representation::Indexed(index) => match self.table.get(index)? {
                    Some(entry) => {
                        out.keep(limit, &mut used, Some(entry.name), Some(entry.value), false)
                    }
                    None if self.unsure => out.keep(limit, &mut used, None, None, false),
                    None => return Err(hpack::Error::Index),
                },
                hpack::Representation::Literal {
                    name,
                    value,
                    indexing,
                } => {
                    let name = match name {
                        hpack::Name::Literal(name) => Some(Arc::<[u8]>::from(name)),
                        hpack::Name::Index(index) => match self.table.name(index)? {
                            name @ Some(_) => name,
                            None if self.unsure => None,
                            None => return Err(hpack::Error::Index),
                        },
                    };
                    out.keep(
                        limit,
                        &mut used,
                        name.as_deref(),
                        Some(&value),
                        indexing == hpack::Indexing::Never,
                    );
                    if indexing == hpack::Indexing::Incremental {
                        if let Some(name) = name {
                            self.table.insert(name, value);
                            self.evict();
                        } else {
                            self.forget();
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CaptureInput {
    Preface,
    Frame(Frame),
    Refused { error: Error, oversized: bool },
}
struct CaptureInputs {
    preface: bool,
    skip: usize,
}
impl Default for CaptureInputs {
    fn default() -> Self {
        Self {
            preface: true,
            skip: 0,
        }
    }
}
impl CaptureInputs {
    fn pending(&self) -> bool {
        self.skip != 0
    }
}
impl Decode for CaptureInputs {
    type Item = CaptureInput;
    type Error = Error;
    const NAME: &'static str = "HTTP/2";
    fn capacity(&self) -> usize {
        (HEADER_LEN + CAPTURE_FRAME_LIMIT).max(PREFACE.len())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<CaptureInput>, Error> {
        if self.skip != 0 {
            let n = input.len().min(self.skip);
            if n == 0 {
                return if eof {
                    Err(size("truncated skipped payload"))
                } else {
                    Ok(Step::Need)
                };
            }
            self.skip -= n;
            return Ok(Step::Skip(n));
        }
        if self.preface {
            if input.len() < PREFACE.len() && PREFACE.starts_with(input) {
                return Ok(Step::Need);
            }
            if input.starts_with(PREFACE) {
                self.preface = false;
                return Ok(Step::Item(CaptureInput::Preface, PREFACE.len()));
            }
        }
        let Some(bytes) = input.get(..HEADER_LEN) else {
            return Ok(Step::Need);
        };
        let header = FrameHeader::parse(bytes)?;
        let total = HEADER_LEN + header.length;
        if header.length > CAPTURE_FRAME_LIMIT && input.len() < total {
            self.skip = header.length;
            self.preface = false;
            return Ok(Step::Item(
                CaptureInput::Refused {
                    error: size("frame exceeds configured limit"),
                    oversized: true,
                },
                HEADER_LEN,
            ));
        }
        let Some(bytes) = input.get(..total) else {
            return Ok(Step::Need);
        };
        let item = match Frame::parse(bytes) {
            Ok(frame) => CaptureInput::Frame(frame),
            Err(error) => CaptureInput::Refused {
                error,
                oversized: false,
            },
        };
        self.preface = false;
        Ok(Step::Item(item, total))
    }
}

struct Pending {
    stream: u32,
    end: bool,
    promised: Option<u32>,
    bytes: Option<Vec<u8>>,
}
struct HeaderFragment<'a> {
    bytes: &'a [u8],
    promised: Option<u32>,
}
/// A fact found while assembling a header block, without display wording.
/// Capture recovery keeps incomplete evidence separate from endpoint decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDiagnostic {
    /// This frame interrupted an open block. The HPACK table was forgotten.
    Interrupted {
        /// The stream whose block was interrupted.
        stream: u32,
    },
    /// This PUSH_PROMISE fragment names a promised stream.
    PromisedStream {
        /// The promised stream ID.
        stream: u32,
    },
    /// The fragment cannot be read because its padding or required fields do not fit.
    InvalidFragment,
    /// A CONTINUATION arrived without an open block on its stream.
    UnexpectedContinuation,
    /// The assembled encoded block exceeded the byte limit.
    LimitExceeded {
        /// The maximum encoded bytes retained for one block.
        limit: usize,
    },
    /// Block bytes were unavailable or discarded. Later HPACK references may be unknown.
    NotDecoded,
    /// The retained block needs another CONTINUATION before it can be decoded.
    Continues,
    /// HPACK decoding rejected the complete block.
    InvalidHpack,
}
/// What capture header assembly found in one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialRead {
    /// The frame's stream.
    pub stream: u32,
    /// Whether the header block ends its stream (END_STREAM on its HEADERS).
    pub end: bool,
    /// The stream a PUSH_PROMISE promises.
    pub promised: Option<u32>,
    /// The decoded block, once its last fragment is read.
    pub block: Option<PartialBlock>,
    /// Capture assembly facts in detection order.
    pub diagnostics: Vec<BlockDiagnostic>,
    /// Whether the frame broke the header block rules.
    pub malformed: bool,
    /// Whether this frame cut off a header block still open.
    /// [`BlockDiagnostic::Interrupted`] identifies that block's stream.
    pub interrupted: bool,
}
/// Capture header assembly retaining incomplete blocks and recovery diagnostics.
pub struct PartialBlocks {
    table: PartialTable,
    pending: Option<Pending>,
    limit: usize,
    decoded: usize,
}
impl Default for PartialBlocks {
    fn default() -> Self {
        Self {
            table: PartialTable::default(),
            pending: None,
            limit: fictionet::stdlib::protocols::http2::Limits::default().header_block,
            decoded: hpack::MAX_DECODED,
        }
    }
}
impl PartialBlocks {
    /// Drops a block in progress and the HPACK table, as after a gap in
    /// the capture.
    pub fn forget(&mut self) {
        self.pending = None;
        self.table.forget();
    }
    /// Bytes held: the HPACK table and a block in progress.
    pub fn held(&self) -> usize {
        self.table.table_size().saturating_add(
            self.pending
                .as_ref()
                .and_then(|p| p.bytes.as_ref())
                .map_or(0, Vec::len),
        )
    }
    /// Whether a header block waits for its CONTINUATION.
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Sets the most decoded header bytes the next block may hold. A
    /// capture sets it to the room left in its display.
    pub fn set_list_limit(&mut self, bytes: usize) {
        self.decoded = bytes;
    }
    /// Reads one frame's part of a header block. Inputs other than
    /// HEADERS, PUSH_PROMISE and CONTINUATION only check that no block is
    /// open. `payload` is `None` for a frame whose payload a capture could
    /// not keep: that block is then not decoded, and HPACK is forgotten,
    /// but the CONTINUATION boundary is kept.
    pub fn read(&mut self, h: FrameHeader, payload: Option<&[u8]>) -> Result<PartialRead, Error> {
        let fragment = if matches!(h.kind, 1 | 5 | 9) {
            payload.map(|p| {
                let payload = HeaderPayload::parse(p, h.kind, h.flags)?;
                Ok(HeaderFragment {
                    bytes: payload.fragment,
                    promised: if h.kind == 5 {
                        Some(u32_at(payload.fields, 0)? & MAX_WINDOW)
                    } else {
                        None
                    },
                })
            })
        } else {
            None
        };
        self.read_fragment(h, fragment)
    }
    fn read_fragment(
        &mut self,
        h: FrameHeader,
        fragment: Option<Result<HeaderFragment<'_>, Error>>,
    ) -> Result<PartialRead, Error> {
        let mut out = PartialRead {
            stream: h.stream,
            end: h.kind == 1 && h.flags & 1 != 0,
            promised: None,
            block: None,
            diagnostics: Vec::new(),
            malformed: false,
            interrupted: false,
        };
        if let Some(p) = self
            .pending
            .as_ref()
            .filter(|p| h.kind != 9 || h.stream != p.stream)
        {
            out.diagnostics
                .push(BlockDiagnostic::Interrupted { stream: p.stream });
            self.forget();
            out.interrupted = true;
            out.malformed = true;
        }
        if !matches!(h.kind, 1 | 5 | 9) {
            return Ok(out);
        }
        let fragment = match fragment {
            Some(Ok(fragment)) => {
                if let Some(id) = fragment.promised {
                    out.promised = Some(id);
                    out.diagnostics
                        .push(BlockDiagnostic::PromisedStream { stream: id });
                }
                Some(fragment.bytes)
            }
            Some(Err(_)) => {
                out.diagnostics.push(BlockDiagnostic::InvalidFragment);
                out.malformed = true;
                None
            }
            None => None,
        };
        let mut p = if h.kind == 9 {
            let Some(p) = self.pending.take() else {
                out.diagnostics
                    .push(BlockDiagnostic::UnexpectedContinuation);
                out.malformed = true;
                self.table.forget();
                return Ok(out);
            };
            p
        } else {
            Pending {
                stream: h.stream,
                end: out.end,
                promised: out.promised,
                bytes: Some(Vec::new()),
            }
        };
        out.end = p.end;
        match (&mut p.bytes, fragment) {
            (Some(bytes), Some(f))
                if bytes
                    .len()
                    .checked_add(f.len())
                    .is_some_and(|n| n <= self.limit) =>
            {
                bytes.try_reserve(f.len()).map_err(|_| Error {
                    code: ErrorCode::EnhanceYourCalm,
                    reason: "header allocation failed",
                })?;
                bytes.extend_from_slice(f);
            }
            (Some(_), fragment) => {
                if fragment.is_some() {
                    out.diagnostics
                        .push(BlockDiagnostic::LimitExceeded { limit: self.limit });
                }
                p.bytes = None;
                self.table.forget();
            }
            _ => {}
        }
        let Some(bytes) = &p.bytes else {
            out.diagnostics.push(BlockDiagnostic::NotDecoded);
            if h.flags & 4 == 0 {
                self.pending = Some(p);
            }
            return Ok(out);
        };
        if h.flags & 4 == 0 {
            out.diagnostics.push(BlockDiagnostic::Continues);
            self.pending = Some(p);
            return Ok(out);
        }
        match self.table.decode_block(bytes, self.decoded) {
            Ok(block) => {
                out.promised = p.promised;
                out.block = Some(block);
            }
            Err(_) => {
                out.diagnostics.push(BlockDiagnostic::InvalidHpack);
                out.malformed = true;
            }
        }
        Ok(out)
    }
}
fn protocol(reason: &'static str) -> Error {
    Error {
        code: ErrorCode::ProtocolError,
        reason,
    }
}
fn size(reason: &'static str) -> Error {
    Error {
        code: ErrorCode::FrameSizeError,
        reason,
    }
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    be32(bytes, at).ok_or_else(|| size("truncated integer"))
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
    format!(
        "{} bytes{}",
        item.data.len(),
        if item.compressed { ", compressed" } else { "" }
    )
}
/// A gRPC message's fields: the compressed flag, the length prefix and
/// the encoded body.
fn grpc_fields(item: &grpc::Message, bytes: &[u8], layer: &mut Layer) {
    layer.field("Compressed", item.compressed.to_string(), (0, 1));
    layer.field("Length", item.data.len().to_string(), (1, grpc::HEADER_LEN));
    layer.field(
        "Message",
        format!("{} bytes", item.data.len()),
        (grpc::HEADER_LEN, bytes.len()),
    );
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
    priority: SummaryPriority,
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
/// Pass this handle to [`Capture::register`] or use [`Capture::pair_in`].
/// The factory and every registry clone then charge the same byte limit.
/// Copied modules and user presenters can use the same constructor pattern.
#[derive(Clone)]
pub struct CaptureBudget {
    used: Arc<Mutex<usize>>,
    limit: usize,
}
impl CaptureBudget {
    /// Sets the total retained DATA allocation limit across participating connections.
    pub fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(Mutex::new(0)),
            limit: limit.min(CAPTURE_DATA_BUDGET),
        }
    }
    /// Bytes charged across all connections.
    pub fn held(&self) -> usize {
        *self.used.lock()
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
    messages: Demux<(bool, u32), fictionet::stdlib::codec::Frames<grpc::Message>>,
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
        {
            let mut used = self.budget.used.lock();
            let total = self.total();
            *used = used.saturating_sub(self.charged).saturating_add(total);
            self.charged = total;
        }
    }
    fn push(&mut self, key: &(bool, u32), bytes: &[u8]) -> usize {
        let mut used = self.budget.used.lock();
        let before = self.total();
        *used = used.saturating_sub(self.charged).saturating_add(before);
        let room = self.budget.limit.saturating_sub(*used);
        let n = self.messages.push_with_budget(key, bytes, room);
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
        {
            let mut used = self.budget.used.lock();
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

/// HTTP/2 capture decoding through [`Present`] and
/// [`fictionet::stdlib::dissect::Observed`]. Uses the same frame parser and header
/// primitives as [`Session`](fictionet::stdlib::protocols::http2::Session), with
/// capture-owned partial HPACK evidence and header-only oversized items followed by `Skip`. Complete
/// frames already available in bounded read-ahead are displayed. Missing bytes
/// stop the direction and clear HPACK and DATA state.
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
/// use fictionet::stdlib::dissect::{Registry, http2};
/// let mut registry = Registry::new();
/// let budget = http2::CaptureBudget::default();
/// http2::Capture::register(&mut registry, &budget);
/// ```
pub struct Capture {
    frames: CaptureInputs,
    blocks: PartialBlocks,
    calls: Arc<Mutex<CaptureCalls>>,
    reverse: bool,
    offset: u64,
    stopped: bool,
}
impl Default for Capture {
    /// Creates one direction with its own DATA budget.
    fn default() -> Self {
        Self::new(CAPTURE_DATA_BUDGET)
    }
}
impl Capture {
    /// Registers `http2` for TCP with `h2` ALPN or the HTTP/2 preface.
    /// A partial preface waits for more bytes; `http/1.1` ALPN excludes it.
    /// All connections from this registry and its clones share `budget`,
    /// including connections selected inside TLS. Uses [`CAPTURE_READ_AHEAD`].
    pub fn register(registry: &mut Registry, budget: &CaptureBudget) {
        let budget = budget.clone();
        registry.register_with_buffer(
            "http2",
            |s| {
                if s.transport != Transport::Tcp || s.alpn == Some("http/1.1") {
                    Match::No
                } else if s.alpn == Some("h2") || s.first.starts_with(PREFACE) {
                    Match::Yes
                } else if PREFACE.starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            CAPTURE_READ_AHEAD,
            move |_| Self::pair_in(&budget),
        );
    }
    /// Creates one direction with a DATA budget capped at 8 MiB.
    /// Use [`pair_in`](Self::pair_in) to share credit across connections.
    pub fn new(data_budget: usize) -> Self {
        Self::in_budget(&CaptureBudget::new(data_budget))
    }
    fn in_budget(budget: &CaptureBudget) -> Self {
        Self {
            frames: CaptureInputs::default(),
            blocks: PartialBlocks::default(),
            calls: Arc::new(Mutex::new(CaptureCalls::new(budget.clone()))),
            reverse: false,
            offset: 0,
            stopped: false,
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
        {
            let mut calls = self.calls.lock();
            calls.remove(&(self.reverse, stream));
        }
    }
    fn clear_calls(&mut self) {
        {
            let mut calls = self.calls.lock();
            calls.remove_where(|key| key.0 == self.reverse);
        }
    }
    fn open_call(&mut self, stream: u32, item: &mut CaptureItem) {
        {
            let mut calls = self.calls.lock();
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
        let mut calls = shared.lock();
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
        priority: if h.kind == 1 {
            SummaryPriority::Primary
        } else {
            SummaryPriority::Normal
        },
        layer,
        info: format!("{}[{}]", h.name(), h.stream),
        buffer: "Reassembled HTTP/2 frame",
        malformed: false,
        reset: false,
        messages: Vec::new(),
        offset: 0,
    }
}
fn present_diagnostic(layer: &mut Layer, diagnostic: &BlockDiagnostic) {
    let note = match diagnostic {
        BlockDiagnostic::Interrupted { .. } => {
            "the one before was cut off by this frame, so later headers may not be known"
        }
        BlockDiagnostic::PromisedStream { stream } => {
            layer.note("Promised stream", stream.to_string());
            return;
        }
        BlockDiagnostic::InvalidFragment => "the frame is too short for its padding or fields",
        BlockDiagnostic::UnexpectedContinuation => {
            "a CONTINUATION with no header block to continue"
        }
        BlockDiagnostic::LimitExceeded { limit } => {
            let size = if limit.is_multiple_of(1024) {
                format!("{} KiB", limit / 1024)
            } else {
                format!("{limit} bytes")
            };
            layer.note("Header block", format!("longer than the {size} kept"));
            return;
        }
        BlockDiagnostic::NotDecoded => "not decoded, so later headers may not be known",
        BlockDiagnostic::Continues => "continues in the next frame",
        BlockDiagnostic::InvalidHpack => "could not be decoded: it is malformed",
    };
    layer.note("Header block", note);
}
fn present_block(item: &mut CaptureItem, block: &PartialBlock) {
    let get = |name: &[u8]| {
        block
            .headers
            .iter()
            .find(|h| h.name.as_deref() == Some(name))
            .and_then(|h| h.value.as_deref())
            .map(String::from_utf8_lossy)
    };
    if let Some(status) = get(b":status") {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write for String never returns Err"
        )]
        let _ = write!(item.info, ": {status}");
    } else if let (Some(m), Some(p)) = (get(b":method"), get(b":path")) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "fmt::Write for String never returns Err"
        )]
        let _ = write!(item.info, ": {m} {p}");
        if let Some(a) = get(b":authority") {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
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
            self.calls.lock().total()
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
                let mut calls = shared.lock();
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
        if frame == CaptureInput::Preface {
            {
                let mut calls = self.calls.lock();
                calls.client = Some(self.reverse);
            }
            let mut layer = Layer::new("HyperText Transfer Protocol 2", 0, (0, PREFACE.len()));
            layer.summary = "Connection preface".into();
            return Ok(Step::Item(
                CaptureItem {
                    layer,
                    info: "Magic".into(),
                    priority: SummaryPriority::Normal,
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
            CaptureInput::Refused {
                oversized: true,
                ..
            }
        );
        let mut item = capture_layer(h, raw);
        item.offset = start;
        if let CaptureInput::Refused {
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
        for diagnostic in &block.diagnostics {
            if matches!(diagnostic, BlockDiagnostic::Interrupted { .. }) {
                present_diagnostic(&mut item.layer, diagnostic);
            }
        }
        if oversized {
            item.layer
                .note("Payload", format!("{} bytes, too long to keep", h.length));
        }
        for diagnostic in &block.diagnostics {
            if !matches!(diagnostic, BlockDiagnostic::Interrupted { .. }) {
                present_diagnostic(&mut item.layer, diagnostic);
            }
        }
        item.malformed |= block.malformed;
        let body = payload.unwrap_or_default();
        match h.kind {
            0 => {
                let data = match &frame {
                    CaptureInput::Frame(Frame::Data(data)) => Some(data.data.as_slice()),
                    _ => unpad(body, h.flags),
                };
                let data = match data {
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
                if let Some(text) = fictionet::stdlib::dissect::protocols::body_preview(data) {
                    item.layer.note("Text", text);
                }
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fmt::Write for String never returns Err"
                )]
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
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "fmt::Write for String never returns Err"
                    )]
                    let _ = write!(item.info, " promised {id}");
                }
                if let Some(b) = &block.block {
                    present_block(&mut item, b);
                    let mut calls = self.calls.lock();
                    if block.promised.is_none() && calls.client.is_none() {
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
                    drop(calls);
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
                    CaptureInput::Frame(Frame::Reset(reset)) => reset.code,
                    _ => u32_at(body, 0)?,
                };
                let e = display_error(code);
                item.layer.field("Error", e.clone(), (9, 13));
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fmt::Write for String never returns Err"
                )]
                let _ = write!(item.info, " {e}");
                item.reset = true;
                {
                    let mut calls = self.calls.lock();
                    calls.remove_where(|key| key.1 == h.stream);
                }
            }
            4 => {
                let partial;
                let entries = match &frame {
                    CaptureInput::Frame(Frame::Settings(settings)) => &settings.entries,
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
                    CaptureInput::Frame(Frame::GoAway(goaway)) => (goaway.last_stream, goaway.code),
                    _ => (u32_at(body, 0)? & MAX_WINDOW, u32_at(body, 4)?),
                };
                let e = display_error(code);
                item.layer
                    .field("Last stream", last_stream.to_string(), (9, 13));
                item.layer.field("Error", e.clone(), (13, 17));
                item.info = format!("GOAWAY {e}");
                let mut calls = self.calls.lock();
                if let Some(client) = calls.client {
                    let receiver_is_client = self.reverse != client;
                    calls.remove_where(|key| {
                        key.1 > last_stream && (key.1 % 2 == 1) == receiver_is_client
                    });
                }
            }
            8 if body.len() >= 4 => {
                let inc = match &frame {
                    CaptureInput::Frame(Frame::WindowUpdate(update)) => update.increment,
                    _ => u32_at(body, 0)? & MAX_WINDOW,
                };
                item.layer
                    .field("Window increment", inc.to_string(), (9, 13));
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fmt::Write for String never returns Err"
                )]
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
        packet.application_with_priority(2, "HTTP/2", &item.info, item.priority);
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
        self.frames = CaptureInputs::default();
        self.stopped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Stream, Wire, pump};
    use fictionet::stdlib::protocols::{huffman, prefix_int::Integer};
    use fictionet::stdlib::test_support::{chunks, decode_all, decode_chunks, hex};
    use hpack::MAX_DECODED;
    impl PartialTable {
        fn decode_all(&mut self, bytes: &[u8]) -> Vec<PartialHeader> {
            let block = self.decode_block(bytes, MAX_DECODED).unwrap();
            assert_eq!(block.more, 0);
            block.headers
        }
    }
    fn pairs(headers: &[PartialHeader]) -> Vec<(&str, &str)> {
        headers
            .iter()
            .map(|header| {
                (
                    header
                        .name
                        .as_deref()
                        .map(|bytes| std::str::from_utf8(bytes).unwrap_or("\u{fffd}"))
                        .unwrap_or(""),
                    header
                        .value
                        .as_deref()
                        .map(|bytes| std::str::from_utf8(bytes).unwrap_or("\u{fffd}"))
                        .unwrap_or(""),
                )
            })
            .collect()
    }

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
            let data = rng.bytes(128);
            assert_eq!(
                decode_chunks(
                    &mut Stream::new(Capture::new(1024)),
                    chunks(&data, &[1, 7, 64]),
                    |_| {}
                ),
                decode_all(|| Capture::new(1024), &data)
            );
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
        assert_eq!(b.decoder().calls.lock().total(), 0);
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
        assert_eq!(a.decoder().calls.lock().total(), 4);
        pump(&mut a, &raw(1, 5, 1, &[0xff]), |_| {}).unwrap();
        assert_eq!(a.decoder().calls.lock().total(), 2);
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
        assert_eq!(a.decoder().calls.lock().total(), 8);
        a.decoder().reset();
        assert_eq!(b.decoder().calls.lock().total(), 4);
        let mut messages = Vec::new();
        pump(&mut b, &raw(0, 1, 1, &[1, b'z']), |item| {
            messages.extend(item.messages)
        })
        .unwrap();
        assert_eq!(messages[0].message.data, b"z");
        assert_eq!(b.decoder().calls.lock().total(), 0);

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
        assert_eq!(a.decoder().calls.lock().total(), 4);
    }

    #[test]
    fn completed_messages_retain_shared_allocation_credit() {
        let budget = CaptureBudget::new(12);
        let mut first = CaptureCalls::new(budget.clone());
        let mut second = CaptureCalls::new(budget.clone());
        assert_eq!(first.push(&(false, 1), &[0, 0, 0, 0, 1, b'x']), 6);
        assert_eq!(first.messages.next().unwrap().1.unwrap().data, b"x");
        first.account();
        assert_eq!(budget.held(), 6);
        assert_eq!(second.push(&(false, 1), &[0, 0, 0, 0, 1, b'y']), 6);
        assert_eq!(budget.held(), 12);
        assert_eq!(first.push(&(false, 3), &[0]), 0);
        assert_eq!(first.push(&(false, 1), &[0, 0, 0, 0, 1, b'z']), 6);
        assert_eq!(budget.held(), 12);
        first.remove(&(false, 1));
        assert_eq!(budget.held(), 6);
        drop(second);
        assert_eq!(budget.held(), 0);
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
                capture.decoder().calls.lock().state[&(false, 1)]
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
                capture.decoder().calls.lock().state[&(false, 1)]
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
        let mut calls = Demux::new(4, 8, |_| {
            fictionet::stdlib::codec::Frames::<grpc::Message>::with_limit(32)
        });
        assert_eq!(calls.push(&1, &[0, 0, 0, 0]), 4);
        assert_eq!(calls.push(&3, &[0, 0, 0, 0]), 4);
        assert!(calls.next().is_none());
        assert_eq!(calls.total(), 8);
        assert_eq!(calls.push(&5, &[0]), 0);
        calls.remove(&1);
        assert_eq!(calls.push(&3, &[1, b'x']), 2);
        assert_eq!(calls.next().unwrap().1.unwrap().data, b"x");
        assert_eq!(calls.total(), 8);
        calls.remove(&3);
        assert_eq!(calls.total(), 0);
    }

    #[test]
    fn capture_header_diagnostics_report_recovery_conditions() {
        for (kind, flags, body, diagnostics, malformed) in [
            (
                1,
                12,
                vec![2],
                vec![
                    BlockDiagnostic::InvalidFragment,
                    BlockDiagnostic::NotDecoded,
                ],
                true,
            ),
            (
                9,
                4,
                vec![0x82],
                vec![BlockDiagnostic::UnexpectedContinuation],
                true,
            ),
            (
                1,
                4,
                vec![0x82; 3],
                vec![
                    BlockDiagnostic::LimitExceeded { limit: 2 },
                    BlockDiagnostic::NotDecoded,
                ],
                false,
            ),
            (1, 4, vec![0x80], vec![BlockDiagnostic::InvalidHpack], true),
        ] {
            let mut blocks = PartialBlocks {
                limit: 2,
                ..PartialBlocks::default()
            };
            let bytes = raw(kind, flags, 1, &body);
            let result = blocks
                .read(FrameHeader::parse(&bytes[..9]).unwrap(), Some(&bytes[9..]))
                .unwrap();
            assert_eq!(result.diagnostics, diagnostics);
            assert_eq!(result.malformed, malformed);
            assert!(!result.interrupted);
            assert!(result.block.is_none());
            assert!(!blocks.pending());
        }

        let mut blocks = PartialBlocks::default();
        let first = raw(1, 0, 1, &[0x82]);
        blocks
            .read(FrameHeader::parse(&first[..9]).unwrap(), Some(&first[9..]))
            .unwrap();
        let next = raw(9, 4, 3, &[0x84]);
        let result = blocks
            .read(FrameHeader::parse(&next[..9]).unwrap(), Some(&next[9..]))
            .unwrap();
        assert_eq!(
            result.diagnostics,
            [
                BlockDiagnostic::Interrupted { stream: 1 },
                BlockDiagnostic::UnexpectedContinuation
            ]
        );
        assert!(result.interrupted && result.malformed);
        assert!(result.block.is_none());
        assert!(!blocks.pending());

        let result = blocks
            .read(FrameHeader::parse(&first[..9]).unwrap(), None)
            .unwrap();
        assert_eq!(result.diagnostics, [BlockDiagnostic::NotDecoded]);
        assert!(!result.interrupted && !result.malformed);
        assert!(result.block.is_none());
        assert!(blocks.pending());
        let last = raw(9, 4, 1, &[0x84]);
        let result = blocks
            .read(FrameHeader::parse(&last[..9]).unwrap(), Some(&last[9..]))
            .unwrap();
        assert_eq!(result.diagnostics, [BlockDiagnostic::NotDecoded]);
        assert!(!result.interrupted && !result.malformed);
        assert!(result.block.is_none());
        assert!(!blocks.pending());
    }
    #[test]
    fn broken_blocks_forget_the_table() {
        for bytes in [vec![0xff], vec![0x41, 0x85, 0xff]] {
            let mut d = PartialTable::default();
            d.decode_all(&hex("400178036f6c64"));
            assert_eq!(d.table_len(), 1);
            assert!(d.decode_block(&bytes, MAX_DECODED).is_err());
            assert!(d.is_unsure());
            assert_eq!(d.table_len(), 0);
            assert_eq!(d.table_size(), 0);
            assert_eq!(d.table_capacity(), None);
        }
        assert!(huffman::decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn a_forgotten_table_shows_unknown_not_stale() {
        let mut d = PartialTable::default();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        d.forget();
        d.decode_all(&hex("4001 7903 6e65 77")); // y: new
        let b = d.decode_block(&[0xbe, 0xbf, 0x82], MAX_DECODED).unwrap();
        assert_eq!(
            pairs(&b.headers),
            [("y", "new"), ("", ""), (":method", "GET")]
        );
        assert_eq!(
            b.headers
                .iter()
                .map(|h| h.name.is_some())
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        // A literal named after an unknown entry has a known value.
        let b = d.decode_block(&hex("0f30 0161"), MAX_DECODED).unwrap();
        assert_eq!(
            (b.headers[0].name.as_deref(), b.headers[0].value.as_deref()),
            (None, Some(b"a".as_slice()))
        );
        // Once known entries fill the table, nothing older can be left.
        let mut d = PartialTable::default();
        d.forget();
        d.decode_all(&hex("3f3b 4001 7801 61")); // size 90, then x: a (34)
        assert!(d.unsure, "an entry of 32 bytes or more may be left");
        d.decode_all(&hex("4001 7901 62")); // y: b, 68 in all
        assert!(!d.unsure, "no room for an older entry");
        assert!(
            d.decode_block(&[0xc0], MAX_DECODED).is_err(),
            "index 64 cannot exist"
        );
    }

    /// A table larger than the decoder keeps: entries past what it keeps
    /// are unknown, not missing.
    #[test]
    fn a_table_past_what_is_kept_is_unsure() {
        let mut d = PartialTable::default();
        // Size update to 1 MiB: 0x3f, then 1,048,576 - 31 as an integer.
        let mut block = vec![0x3f];
        let mut v = (1usize << 20) - 31;
        while v >= 0x80 {
            block.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        block.push(v as u8);
        d.decode_all(&block);
        // a: 16,000 bytes, a literal of length 127 + 15,873.
        let mut big = vec![0x40, 0x01, b'a', 0x7f, 0x81, 0x7c];
        big.extend(std::iter::repeat_n(b'v', 16_000));
        for _ in 0..5 {
            d.decode_all(&big);
        }
        assert_eq!(d.table.len(), 4, "only 64 KiB is kept");
        assert!(d.unsure);
        let b = d.decode_block(&[0xc2], MAX_DECODED).unwrap(); // index 66, the fifth
        assert!(b.headers[0].value.is_none());
    }

    /// A block not decoded may have changed the table's maximum, so after
    /// it, entries are kept until a size update says what the maximum is.
    #[test]
    fn a_forgotten_table_forgets_its_maximum() {
        let mut d = PartialTable::default();
        d.decode_all(&hex("20")); // size 0
        d.forget(); // the block not decoded set it to 4,096
        d.decode_all(&hex("4001 7803 6e65 77")); // x: new
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        d.decode_all(&hex("3f e11f")); // size 4,096
        assert_eq!(d.max, Some(4096));
    }

    #[test]
    fn observation_accepts_huffman_expansion_and_keeps_the_table() {
        let mut d = PartialTable::default();
        d.decode_all(&hex("400178036f6c64")); // x: old
        let mut bytes = vec![0x00, 0x01, b'x'];
        Integer::<7> {
            flags: 0x80,
            value: 60_000,
        }
        .write(&mut bytes)
        .unwrap();
        bytes.extend(vec![0; 60_000]);
        assert!(bytes.len() < 64 << 10);
        let block = d.decode_block(&bytes, MAX_DECODED).unwrap();
        assert_eq!((block.headers.len(), block.more), (0, 1));
        assert!(!d.is_unsure());
        assert_eq!(d.table_len(), 1);
        assert_eq!(d.table_capacity(), Some(4096));
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "old")]);
        assert_eq!(
            hpack::Table::default().decode_block(&bytes, MAX_DECODED),
            Err(hpack::Error::StringTooLong)
        );
    }

    #[test]
    fn unknown_settings_preserve_size_update_grammar() {
        let mut table = PartialTable::default();
        assert!(
            table
                .decode_block(&[0x21, 0x20, 0x20, 0x82], MAX_DECODED)
                .is_ok()
        );
        assert_eq!(
            table.decode_block(&[0x82, 0x20], MAX_DECODED),
            Err(hpack::Error::SizeUpdateOrder)
        );
        assert!(table.is_unsure());
        assert_eq!(table.decode_all(&[0xbe])[0].name, None);
    }

    #[test]
    fn captured_fragments_preserve_padding_priorities_and_promises() {
        use fictionet::stdlib::protocols::http2::{Dependency, Headers, PushPromise};
        for pad in [None, Some(0), Some(1), Some(255)] {
            for kind in [1, 5] {
                for priority in [false, true] {
                    let mut encoder = hpack::Encoder::default();
                    let fields = [hpack::Field::new("x-saved", "value")];
                    let mut block = Vec::new();
                    encoder.encode_block(&fields, &mut block).unwrap();
                    let mut indexed = Vec::new();
                    encoder.encode_block(&fields, &mut indexed).unwrap();
                    assert!(indexed.len() < block.len());
                    for split in 0..=block.len() {
                        let padding = pad.map(|n| vec![0xa5; n]);
                        let flags = if pad.is_some() { 8 } else { 0 };
                        let first = if kind == 1 {
                            Frame::Headers(Headers {
                                stream: 1,
                                flags: flags | 1 | if priority { 0x20 } else { 0 },
                                fragment: block[..split].to_vec(),
                                priority: priority.then_some(Dependency {
                                    stream: 3,
                                    exclusive: true,
                                    weight: 255,
                                }),
                                padding,
                            })
                        } else {
                            Frame::PushPromise(PushPromise {
                                stream: 1,
                                flags,
                                promised: 2,
                                fragment: block[..split].to_vec(),
                                padding,
                            })
                        }
                        .to_bytes()
                        .unwrap();
                        let mut blocks = PartialBlocks::default();
                        let first = blocks
                            .read(FrameHeader::parse(&first[..9]).unwrap(), Some(&first[9..]))
                            .unwrap();
                        let mut diagnostics = Vec::new();
                        if kind == 5 {
                            diagnostics.push(BlockDiagnostic::PromisedStream { stream: 2 });
                        }
                        diagnostics.push(BlockDiagnostic::Continues);
                        assert_eq!(first.diagnostics, diagnostics);
                        assert_eq!(first.promised, (kind == 5).then_some(2));
                        assert_eq!(first.end, kind == 1);
                        assert!(first.block.is_none());
                        assert!(blocks.pending());
                        let last = raw(9, 4, 1, &block[split..]);
                        let last = blocks
                            .read(FrameHeader::parse(&last[..9]).unwrap(), Some(&last[9..]))
                            .unwrap();
                        assert_eq!(last.end, kind == 1);
                        assert_eq!(last.promised, (kind == 5).then_some(2));
                        assert_eq!(pairs(&last.block.unwrap().headers), [("x-saved", "value")]);
                        assert!(last.diagnostics.is_empty());
                        assert!(!last.malformed && !last.interrupted);
                        assert!(!blocks.pending());
                        let next = raw(1, 4, 3, &indexed);
                        let next = blocks
                            .read(FrameHeader::parse(&next[..9]).unwrap(), Some(&next[9..]))
                            .unwrap();
                        assert_eq!(pairs(&next.block.unwrap().headers), [("x-saved", "value")]);
                    }
                }
            }
        }
    }
}
