//! Server-sent events for streaming API responses.
//!
//! [`RawLines`] exposes fields, comments, ignored fields, and blank lines.
//! [`Events`] joins data lines and emits dispatched [`Event`] values. Field
//! names are case sensitive. Both follow the [WHATWG event stream rules].
//! Invalid UTF-8 becomes U+FFFD. One BOM is removed at stream start only.
//! EOF discards an unterminated line and any event without a final blank
//! line. A block without data fields emits nothing; `data:` followed by a
//! blank line emits an event whose data is the empty string.
//!
//! [`Event::write`](Wire::write) preserves the event's values, including
//! inherited IDs. It uses LF endings and splits LF in data into data lines.
//! [`Line`] keeps comment text and ignored fields for recorders and proxies.
//! Its writer normalizes field spacing and endings. To retain the original
//! spelling, use `codec::Stream::with_next` with [`RawLines`]; the initial
//! BOM is reported as skipped bytes. A CR that ends the input so far ends
//! its line at once, so an LF that arrives next is reported as skipped
//! bytes too. A proxy that forwards skipped bytes should keep a rewritten
//! line's original ending. An event assembler consumes earlier
//! lines, so its final dispatch step does not carry the whole wire block.
//!
//! For MCP's streamable HTTP transport, feed the body of each
//! `text/event-stream` response into one [`Events`] decoder. For the older
//! HTTP+SSE transport, `endpoint` events name the POST URL and `message`
//! events carry JSON-RPC. HTTP framing, session headers, and JSON-RPC stay
//! in their own layers. An HTTP body chunk need not end at an SSE line:
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, finish, try_pump};
//! use fictionet::stdlib::sse::{Events, Limits};
//!
//! // Body chunks supplied by an HTTP response decoder after checking
//! // Content-Type: text/event-stream and removing HTTP transfer framing.
//! let body_chunks: &[&[u8]] = &[
//!     b"event: endpoint\ndata: /messages\n\nevent: message\nda",
//!     b"ta: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
//! ];
//! let mut events = Stream::new(Events::new());
//! let mut forwarded_body = Vec::new();
//! for chunk in body_chunks {
//!     try_pump(&mut events, chunk, |mut event| {
//!         if event.event == "endpoint" {
//!             event.data = "/proxy/messages".into();
//!         }
//!         event.write(&mut forwarded_body)
//!     })?;
//! }
//! finish(&mut events, |_| {})?;
//! // Send forwarded_body through the outgoing HTTP body's framing.
//! assert!(forwarded_body.starts_with(b"event:endpoint\nid:\ndata:/proxy/messages\n\n"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A `codec::Pipe` can select `Carry::Bytes` for HTTP body items and
//! `Carry::Through` for response heads, with [`Events`] as its inner decoder.
//! Scope that pipe to one response body; ending the body must end the SSE
//! decoder even when the HTTP connection stays open. A JSON response uses a
//! separate JSON decoder. MCP over stdio uses newline-delimited JSON.
//!
//! [WHATWG event stream rules]: https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream

use fictionet::stdlib::codec::{Buffer, Decode, Ending, LineError, Lines, Step, Wire};

/// Default maximum UTF-8 bytes in a line, excluding its terminator and BOM.
/// Replacement characters from malformed UTF-8 count toward this limit.
pub const MAX_LINE: usize = 64 * 1024;
/// Default maximum bytes per event block: 1 MiB. See [`Limits::event`].
pub const MAX_EVENT: usize = 1024 * 1024;

/// Bounds for an event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum line content bytes before and after UTF-8 replacement.
    /// Clamped to [`Buffer::MAX_LIMIT`] minus two by the decoder.
    pub line: usize,
    /// Maximum sum of decoded line content bytes plus one per terminator
    /// between blank lines. Includes comments, unknown fields, and replaced
    /// fields. The dispatching blank line is excluded. The canonical event
    /// encoding, including its blank line and inherited ID, must also fit.
    /// Clamped to [`Buffer::MAX_LIMIT`]. Zero accepts only empty blocks.
    pub event: usize,
}
impl Default for Limits {
    /// Uses [`MAX_LINE`] and [`MAX_EVENT`].
    fn default() -> Self {
        Self {
            line: MAX_LINE,
            event: MAX_EVENT,
        }
    }
}
impl Limits {
    fn bounded(self) -> Self {
        Self {
            line: self.line.min(Buffer::MAX_LIMIT.saturating_sub(2)),
            event: self.event.min(Buffer::MAX_LIMIT),
        }
    }
}

/// A terminal stream limit, an invalid complete wire value, or a value
/// that cannot be written without changing it or exceeding a wire limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A raw or UTF-8-decoded line exceeded its content limit.
    LineTooLong {
        /// Maximum content bytes.
        limit: usize,
    },
    /// An event block or its canonical encoding exceeded its limit.
    EventTooLong {
        /// Maximum event bytes.
        limit: usize,
    },
    /// The slice was not exactly one complete, writable line.
    ExpectedLine,
    /// The slice did not end immediately after its only dispatched event.
    ExpectedEvent,
    /// Storage for a bounded buffer could not be allocated.
    Allocation,
    /// The value has no context-free wire representation: it cannot be
    /// written without changing it or exceeding a wire limit.
    Unwritable {
        /// The refused part of the value.
        reason: &'static str,
    },
}
fictionet::error_display!(Error, f, {
    Self::LineTooLong { limit } => write!(f, "SSE line exceeds {limit} bytes"),
    Self::EventTooLong { limit } => write!(f, "SSE event exceeds {limit} bytes"),
    Self::ExpectedLine => f.write_str("expected one complete SSE line"),
    Self::ExpectedEvent => f.write_str("expected one complete SSE event"),
    Self::Allocation => f.write_str("SSE allocation failed"),
    Self::Unwritable { reason } => write!(f, "unwritable SSE value: {reason}"),
});

/// One interpreted line. Values retain all spaces after the one optional
/// space following the colon. Comments retain everything after the colon.
/// Invalid ID and retry fields remain visible as [`Ignored`](Self::Ignored).
///
/// ```
/// use fictionet::stdlib::codec::Wire;
/// use fictionet::stdlib::sse::Line;
/// let mut body = Vec::new();
/// Line::Comment(" keepalive".into()).write(&mut body)?;
/// Line::Retry("3000".into()).write(&mut body)?;
/// assert_eq!(body, b": keepalive\nretry:3000\n");
/// # Ok::<(), fictionet::stdlib::sse::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// An empty line, which ends an event block.
    Empty,
    /// Text after the comment's leading colon, without trimming spaces.
    Comment(String),
    /// An event type, including the empty string that selects `message`.
    Event(String),
    /// One data line, before the LF that the event assembler adds.
    Data(String),
    /// An ID without NULL. An empty value clears the last event ID.
    Id(String),
    /// A nonempty string of ASCII digits specifying milliseconds.
    /// Digits, including leading zeros, are retained without integer overflow.
    Retry(String),
    /// An unknown field, an ID containing NULL, or an invalid retry value.
    Ignored {
        /// Case-sensitive field name.
        name: String,
        /// Value after removing one optional space.
        value: String,
    },
}
impl Line {
    fn from_text(text: &str) -> Self {
        if text.is_empty() {
            return Self::Empty;
        }
        if let Some(comment) = text.strip_prefix(':') {
            return Self::Comment(comment.into());
        }
        let (name, value) = text
            .split_once(':')
            .map_or((text, ""), |(n, v)| (n, v.strip_prefix(' ').unwrap_or(v)));
        match name {
            "event" => Self::Event(value.into()),
            "data" => Self::Data(value.into()),
            "id" if !value.contains('\0') => Self::Id(value.into()),
            "retry" if digits(value) => Self::Retry(value.into()),
            _ => Self::Ignored {
                name: name.into(),
                value: value.into(),
            },
        }
    }
    fn parts(&self) -> Option<(&str, &str)> {
        match self {
            Self::Empty | Self::Comment(_) => None,
            Self::Event(v) => Some(("event", v)),
            Self::Data(v) => Some(("data", v)),
            Self::Id(v) => Some(("id", v)),
            Self::Retry(v) => Some(("retry", v)),
            Self::Ignored { name, value } => Some((name, value)),
        }
    }
    fn encoded_len(&self) -> Result<usize, Error> {
        let size = match self {
            Self::Empty => return Ok(1),
            Self::Comment(v) => {
                if newline(v) {
                    return Err(unwritable("comment contains CR or LF"));
                }
                v.len().checked_add(1)
            }
            _ => {
                let (name, value) = self.parts().ok_or(unwritable("line kind"))?;
                if name.is_empty()
                    || name.contains(':')
                    || newline(name)
                    || name.starts_with('\u{feff}')
                    || newline(value)
                {
                    return Err(unwritable("field name or value"));
                }
                match self {
                    Self::Id(v) if v.contains('\0') => return Err(unwritable("ID contains NULL")),
                    Self::Retry(v) if !digits(v) => {
                        return Err(unwritable("retry is not ASCII digits"));
                    }
                    Self::Ignored { name, value }
                        if matches!(name.as_str(), "event" | "data")
                            || (name == "id" && !value.contains('\0'))
                            || (name == "retry" && digits(value)) =>
                    {
                        return Err(unwritable("ignored field would be interpreted"));
                    }
                    _ => {}
                }
                field_len(name, value)
            }
        }
        .ok_or(unwritable("line size overflow"))?;
        if size > MAX_LINE {
            return Err(unwritable("line limit"));
        }
        size.checked_add(1).ok_or(unwritable("line size overflow"))
    }
    fn append(&self, out: &mut Vec<u8>) {
        match self {
            Self::Empty => out.push(b'\n'),
            Self::Comment(text) => {
                out.push(b':');
                out.extend_from_slice(text.as_bytes());
                out.push(b'\n');
            }
            _ => {
                if let Some((name, value)) = self.parts() {
                    append_field(out, name, value);
                }
            }
        }
    }
}
impl Wire for Line {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one terminated line with default limits. Refuses a
    /// missing line, trailing bytes, and values the writer cannot represent.
    /// A leading BOM is allowed. An unterminated final line is refused.
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut lines = RawLines::default();
        loop {
            match lines.decode(bytes, true)? {
                Step::Skip(n) if n == 3 && bytes.starts_with(b"\xef\xbb\xbf") => {
                    bytes = bytes.get(n..).ok_or(Error::ExpectedLine)?;
                }
                Step::Item(line, n) if n == bytes.len() => {
                    line.encoded_len()?;
                    return Ok(line);
                }
                _ => return Err(Error::ExpectedLine),
            }
        }
    }

    /// Appends one LF-terminated line. Refuses CR/LF in names or values,
    /// empty names, colons or a leading BOM in names, NULL in `Id`, invalid
    /// `Retry` digits, falsely classified `Ignored` fields, and lines above
    /// [`MAX_LINE`]. `Ignored` can preserve a server's invalid ID or retry.
    /// Allocation failure is also a refusal. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        reserve(out, self.encoded_len()?)?;
        self.append(out);
        Ok(())
    }
}

/// A dispatched event. `event` is the effective type and `id` is the
/// effective last event ID, including an ID inherited from an earlier block.
/// Comments and retry changes are separate [`Line`] values, not event data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Event type. Decoding supplies `message` when the type field is empty.
    pub event: String,
    /// Data lines joined with LF. Empty data is valid when a data field exists.
    pub data: String,
    /// Effective last event ID. Empty means no ID.
    pub id: String,
}
impl Event {
    /// Creates a `message` event with the given data and an empty ID.
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: "message".into(),
            data: data.into(),
            id: String::new(),
        }
    }
    fn encoded_len(&self, limits: Limits) -> Result<usize, Error> {
        if self.event.is_empty() || newline(&self.event) {
            return Err(unwritable("event type is empty or contains CR or LF"));
        }
        if newline(&self.id) || self.id.contains('\0') {
            return Err(unwritable("ID contains CR, LF, or NULL"));
        }
        if self.data.contains('\r') {
            return Err(unwritable("data contains CR"));
        }
        let mut size = 1usize; // Dispatching blank line.
        let mut field = |name: &str, value: &str| -> Result<(), Error> {
            let n = field_len(name, value).ok_or(unwritable("event size overflow"))?;
            if n > limits.line {
                return Err(unwritable("line limit"));
            }
            size = size
                .checked_add(n)
                .and_then(|n| n.checked_add(1))
                .ok_or(unwritable("event size overflow"))?;
            if size > limits.event {
                return Err(unwritable("event limit"));
            }
            Ok(())
        };
        if self.event != "message" {
            field("event", &self.event)?;
        }
        field("id", &self.id)?;
        for data in self.data.split('\n') {
            field("data", data)?;
        }
        Ok(size)
    }
}
impl Wire for Event {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one dispatched event from a fresh stream with default limits.
    /// Refuses missing dispatch, a partial final event, extra events, or any
    /// bytes following the dispatch. Leading control blocks are accepted.
    /// The whole slice is capped at twice [`MAX_EVENT`] plus three BOM bytes
    /// to allow CRLF endings. Stream decoding has no whole-stream limit.
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_EVENT.saturating_mul(2).saturating_add(3) {
            return Err(Error::EventTooLong { limit: MAX_EVENT });
        }
        let mut events = Events::default();
        loop {
            match events.decode(bytes, true)? {
                Step::Skip(n) if n > 0 => {
                    bytes = bytes.get(n..).ok_or(Error::ExpectedEvent)?;
                }
                Step::Item(event, n) if n == bytes.len() => return Ok(event),
                _ => return Err(Error::ExpectedEvent),
            }
        }
    }

    /// Appends an event using default limits and LF endings. Always writes
    /// an ID, so appending to an existing stream preserves even an empty ID.
    /// LF in data becomes multiple data lines, including a trailing empty
    /// line. Refuses an empty event type, CR/LF in the type or ID, NULL in
    /// the ID, CR in data, line/event limit excess, size overflow, or failed
    /// allocation. Leaves `out` unchanged on every refusal.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        reserve(out, self.encoded_len(Limits::default())?)?;
        if self.event != "message" {
            append_field(out, "event", &self.event);
        }
        append_field(out, "id", &self.id);
        for data in self.data.split('\n') {
            append_field(out, "data", data);
        }
        out.push(b'\n');
        Ok(())
    }
}

/// A line decoder over [`Lines`], including comments and ignored fields.
/// Holds no payload between calls. Capacity is `max_line + 2`, or three
/// bytes when that is larger, to recognize the initial BOM. EOF discards
/// an unterminated final line. The stream owner bounds any retained items.
pub struct RawLines {
    lines: Lines,
    limit: usize,
    start: bool,
    // Decoded UTF-8 content plus one terminator, for the event block budget.
    cost: usize,
}
impl RawLines {
    /// Reads lines of up to [`MAX_LINE`] content bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_LINE)
    }

    /// Sets the maximum line content length, clamped like [`Lines::new`].
    /// Line excess is terminal rather than a recoverable item.
    pub fn with_limit(max_line: usize) -> Self {
        let limit = max_line.min(Buffer::MAX_LIMIT.saturating_sub(2));
        Self {
            lines: Lines::new(limit, Ending::LfOrCrOrCrlf),
            limit,
            start: true,
            cost: 0,
        }
    }
}
impl Default for RawLines {
    /// Uses [`MAX_LINE`].
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for RawLines {
    type Item = Line;
    type Error = Error;
    const NAME: &'static str = "SSE lines";

    /// Returns the bounded line capacity, including CRLF and BOM lookahead.
    fn capacity(&self) -> usize {
        self.lines.capacity().max(3)
    }

    /// Decodes a field, comment, or blank line. Refuses raw or decoded line
    /// excess. Replaces malformed UTF-8 and discards a partial line at EOF.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Line>, Error> {
        if self.start {
            const BOM: &[u8] = b"\xef\xbb\xbf";
            if !eof && input.len() < BOM.len() && BOM.starts_with(input) {
                return Ok(Step::Need);
            }
            self.start = false;
            if input.starts_with(BOM) {
                return Ok(Step::Skip(BOM.len()));
            }
        }
        Ok(
            match self
                .lines
                .decode(input, eof)
                .unwrap_or_else(|never| match never {})
            {
                Step::Item(Ok(bytes), n) => {
                    let text = String::from_utf8_lossy(&bytes);
                    if text.len() > self.limit {
                        return Err(Error::LineTooLong { limit: self.limit });
                    }
                    self.cost = text
                        .len()
                        .checked_add(1)
                        .ok_or(Error::LineTooLong { limit: self.limit })?;
                    Step::Item(Line::from_text(&text), n)
                }
                Step::Item(Err(LineError::TooLong { .. }), _) => {
                    return Err(Error::LineTooLong { limit: self.limit });
                }
                Step::Item(Err(LineError::Unterminated), n) => {
                    if n > self.limit || String::from_utf8_lossy(input).len() > self.limit {
                        return Err(Error::LineTooLong { limit: self.limit });
                    }
                    Step::Skip(n)
                }
                Step::Item(Err(LineError::BareLf), _) => return Err(Error::ExpectedLine),
                Step::Skip(n) => Step::Skip(n),
                Step::Need if eof && input.is_empty() => Step::End,
                Step::Need => Step::Need,
                Step::End => Step::End,
            },
        )
    }
}

/// An event assembler over [`RawLines`]. Its input buffer is line-sized.
/// All block text, even comments and overwritten fields, counts toward
/// [`Limits::event`]. Held payload is at most `event + 2 * line` bytes:
/// pending data/type/ID plus the committed ID and retry digits. Buffer
/// allocations grow geometrically and remain bounded by those limits.
/// At EOF, pending data, type, and uncommitted ID are discarded.
/// Custom limits above the defaults can produce events that the default
/// [`Event`] writer refuses. With default limits, every emitted event writes.
pub struct Events {
    lines: RawLines,
    limits: Limits,
    used: usize,
    data: String,
    event: String,
    pending_id: Option<String>,
    last_id: String,
    retry: Option<String>,
}
impl Events {
    /// Starts an event stream with the default limits, empty ID state and
    /// no retry override.
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// Starts an event stream with `limits`, empty ID state and no retry
    /// override.
    pub fn with_limits(limits: Limits) -> Self {
        let limits = limits.bounded();
        Self {
            lines: RawLines::with_limit(limits.line),
            limits,
            used: 0,
            data: String::new(),
            event: String::new(),
            pending_id: None,
            last_id: String::new(),
            retry: None,
        }
    }
    /// Last ID committed by a blank line, including a block without data.
    /// An ID in an unfinished block does not change this value.
    pub fn last_event_id(&self) -> &str {
        &self.last_id
    }

    /// Latest valid retry field, in milliseconds as ASCII decimal digits.
    /// Updated on its terminated line, without waiting for a blank line.
    /// `None` leaves the reconnection policy to the caller. Values larger
    /// than machine integers and leading zeros are preserved.
    pub fn retry(&self) -> Option<&str> {
        self.retry.as_deref()
    }

    fn clear_block(&mut self) {
        self.used = 0;
        self.data = String::new();
        self.event = String::new();
        self.pending_id = None;
    }
    fn dispatch(&mut self) -> Result<Option<Event>, Error> {
        if let Some(id) = self.pending_id.take() {
            self.last_id = id;
        }
        self.used = 0;
        if self.data.is_empty() {
            self.event = String::new();
            return Ok(None);
        }
        self.data.pop(); // The LF appended by the final data field.
        let event = Event {
            event: if self.event.is_empty() {
                "message".into()
            } else {
                std::mem::take(&mut self.event)
            },
            data: std::mem::take(&mut self.data),
            id: self.last_id.clone(),
        };
        // Inherited IDs and canonical field spelling can add bytes. Check
        // them before publishing an event so default-decoded events write.
        if let Err(error) = event.encoded_len(self.limits) {
            return Err(
                if error
                    == (Error::Unwritable {
                        reason: "line limit",
                    })
                {
                    Error::LineTooLong {
                        limit: self.limits.line,
                    }
                } else {
                    Error::EventTooLong {
                        limit: self.limits.event,
                    }
                },
            );
        }
        Ok(Some(event))
    }
}
impl Default for Events {
    /// Uses [`Limits::default`].
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Events {
    type Item = Event;
    type Error = Error;
    const NAME: &'static str = "SSE events";

    /// Returns the underlying line capacity, independent of event size.
    fn capacity(&self) -> usize {
        self.lines.capacity()
    }

    /// Counts data, type, pending and committed ID, and retry payload bytes.
    fn held(&self) -> usize {
        self.data
            .len()
            .saturating_add(self.event.len())
            .saturating_add(self.pending_id.as_ref().map_or(0, String::len))
            .saturating_add(self.last_id.len())
            .saturating_add(self.retry.as_ref().map_or(0, String::len))
    }

    /// Reads one line and dispatches only at a blank line with a data field.
    /// Refuses line or event limit excess and allocation failure. Invalid
    /// ID/retry and unknown fields have no effect. EOF discards the block.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, Error> {
        Ok(match self.lines.decode(input, eof)? {
            Step::Item(Line::Empty, n) => match self.dispatch()? {
                Some(event) => Step::Item(event, n),
                None => Step::Skip(n),
            },
            Step::Item(line, n) => {
                self.used = self
                    .used
                    .checked_add(self.lines.cost)
                    .filter(|n| *n <= self.limits.event)
                    .ok_or(Error::EventTooLong {
                        limit: self.limits.event,
                    })?;
                match line {
                    Line::Data(value) => {
                        let size = self
                            .data
                            .len()
                            .checked_add(value.len())
                            .and_then(|n| n.checked_add(1))
                            .filter(|n| *n <= self.limits.event)
                            .ok_or(Error::EventTooLong {
                                limit: self.limits.event,
                            })?;
                        if size > self.data.capacity() {
                            let target = size
                                .max(self.data.capacity().saturating_mul(2))
                                .min(self.limits.event);
                            self.data
                                .try_reserve_exact(target.saturating_sub(self.data.len()))
                                .map_err(|_| Error::Allocation)?;
                        }
                        self.data.push_str(&value);
                        self.data.push('\n');
                    }
                    Line::Event(value) => self.event = value,
                    Line::Id(value) => self.pending_id = Some(value),
                    Line::Retry(value) => self.retry = Some(value),
                    Line::Comment(_) | Line::Ignored { .. } | Line::Empty => {}
                }
                Step::Skip(n)
            }
            Step::End => {
                self.clear_block();
                Step::End
            }
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
        })
    }
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}
fn newline(value: &str) -> bool {
    value.contains(['\r', '\n'])
}
fn unwritable(reason: &'static str) -> Error {
    Error::Unwritable { reason }
}
fn field_len(name: &str, value: &str) -> Option<usize> {
    name.len()
        .checked_add(1)?
        .checked_add(usize::from(value.starts_with(' ')))?
        .checked_add(value.len())
}
fn append_field(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    if value.starts_with(' ') {
        out.push(b' ');
    }
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}
fn reserve(out: &mut Vec<u8>, size: usize) -> Result<(), Error> {
    out.len()
        .checked_add(size)
        .ok_or(unwritable("output size overflow"))?;
    out.try_reserve(size)
        .map_err(|_| unwritable("allocation failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream, finish, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::decode_all;

    fn ignored(name: String, value: String) -> Line {
        Line::Ignored { name, value }
    }

    fn events(bytes: &[u8]) -> Vec<Event> {
        let (events, error) = decode_all(Events::default, bytes);
        assert_eq!(error, None);
        events
    }
    fn event(kind: &str, data: &str, id: &str) -> Event {
        Event {
            event: kind.into(),
            data: data.into(),
            id: id.into(),
        }
    }

    #[test]
    fn cr_dispatches_without_waiting() {
        // A server can end lines with CR and keep the stream open. The event
        // must not wait for the next byte or for EOF.
        for bytes in [&b"data:x\r\r"[..], b"data:x\r\n\r", b"data:x\n\r"] {
            let mut stream = Stream::new(Events::default());
            let mut out = Vec::new();
            assert_eq!(pump(&mut stream, bytes, |e| out.push(e)), Ok(bytes.len()));
            assert_eq!(out, [Event::new("x")], "{bytes:?}");
            // A split CRLF stays one terminator.
            assert_eq!(pump(&mut stream, b"\ndata:y\r\r", |e| out.push(e)), Ok(9));
            assert_eq!(out, [Event::new("x"), Event::new("y")], "{bytes:?}");
        }
    }

    #[test]
    fn whatwg_stock() {
        assert_eq!(
            events(b"data: YHOO\ndata: +2\ndata: 10\n\n"),
            [Event::new("YHOO\n+2\n10")]
        );
    }

    #[test]
    fn whatwg_comment_data_and_id() {
        let bytes = b": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n\n";
        assert_eq!(
            events(bytes),
            [
                event("message", "first event", "1"),
                Event::new("second event"),
                Event::new(" third event")
            ]
        );
        let (lines, error) = decode_all(RawLines::default, bytes);
        assert_eq!(error, None);
        assert_eq!(lines.first(), Some(&Line::Comment(" test stream".into())));
    }

    #[test]
    fn whatwg_test_events_and_discarded_tail() {
        assert_eq!(
            events(b"data:test\n\ndata: test\n\ndata: discarded\n"),
            [Event::new("test"), Event::new("test")]
        );
        assert_eq!(
            events(b"data:test\n\ndata: test\n\ndata: discarded"),
            [Event::new("test"), Event::new("test")]
        );
    }

    #[test]
    fn whatwg_empty_data_fields() {
        let bytes = b"data\n\ndata\ndata\n\ndata:\n";
        assert_eq!(events(bytes), [Event::new(""), Event::new("\n")]);
        let mut complete = bytes.to_vec();
        complete.push(b'\n');
        assert_eq!(
            events(&complete),
            [Event::new(""), Event::new("\n"), Event::new("")]
        );
        assert!(events(b"\n: comment\n\nevent: custom\nid: saved\n\n").is_empty());
    }

    #[test]
    fn field_rules_and_case_sensitive_names() {
        assert_eq!(events(b"Event: ignored\nDATA: ignored\nunknown: stuff\nevent: old\nevent: custom\ndata:  one:two\ndata:\tthree\n\ndata:x\n\nevent:\ndata:y\n\n"),
            [Event::new(" one:two\n\tthree").with_type("custom"),
             Event::new("x"), Event::new("y")]);
        assert_eq!(
            events(b"data\n\nevent: discarded\n\ndata:ok\n\n"),
            [Event::new(""), Event::new("ok")]
        );
    }

    // Test-only convenience; production callers can edit the public field.
    impl Event {
        fn with_type(mut self, kind: &str) -> Self {
            self.event = kind.into();
            self
        }
    }

    #[test]
    fn last_id_commits_on_blank_even_without_data() {
        let mut stream = Stream::new(Events::default());
        pump(&mut stream, b"id: one\n", |_| panic!("unexpected event")).unwrap();
        assert_eq!(stream.decoder().last_event_id(), "");
        pump(&mut stream, b"\n", |_| panic!("unexpected event")).unwrap();
        assert_eq!(stream.decoder().last_event_id(), "one");
        let mut got = Vec::new();
        pump(
            &mut stream,
            b"data:x\n\nid: bad\0id\ndata:y\n\ndata:z\n\nid\n\ndata:q\n\nid:unfinished\n",
            |v| got.push(v),
        )
        .unwrap();
        finish(&mut stream, |v| got.push(v)).unwrap();
        assert_eq!(
            got,
            [
                event("message", "x", "one"),
                event("message", "y", "one"),
                event("message", "z", "one"),
                Event::new("q")
            ]
        );
        assert_eq!(stream.decoder().last_event_id(), "");
        assert_eq!(stream.held(), 0);
    }

    #[test]
    fn retry_only_ascii_digits_and_no_machine_integer_limit() {
        let mut stream = Stream::new(Events::default());
        for value in ["000", "42", "184467440737095516160000000000000000000000000"] {
            pump(
                &mut stream,
                format!("retry:{value}\n").as_bytes(),
                |_| panic!(),
            )
            .unwrap();
            assert_eq!(stream.decoder().retry(), Some(value));
            for invalid in ["", "+1", "-1", "1.5", "1 2", " 3", "٤", "１２", "2\0"] {
                pump(
                    &mut stream,
                    format!("retry: {invalid}\n").as_bytes(),
                    |_| panic!(),
                )
                .unwrap();
                assert_eq!(stream.decoder().retry(), Some(value));
            }
        }
        pump(&mut stream, b"retry:123", |_| panic!()).unwrap();
        finish(&mut stream, |_| panic!()).unwrap();
        assert_eq!(
            stream.decoder().retry(),
            Some("184467440737095516160000000000000000000000000")
        );
    }

    #[test]
    fn raw_comments_and_ignored_fields() {
        assert_eq!(
            decode_all(
                RawLines::default,
                b": leading\n:\nretry:01\nretry:bad\nid:a\0b\nX\ndata\nevent\nid\n\n"
            )
            .0,
            [
                Line::Comment(" leading".into()),
                Line::Comment("".into()),
                Line::Retry("01".into()),
                ignored("retry".into(), "bad".into()),
                ignored("id".into(), "a\0b".into()),
                ignored("X".into(), "".into()),
                Line::Data("".into()),
                Line::Event("".into()),
                Line::Id("".into()),
                Line::Empty
            ]
        );
    }

    #[test]
    fn every_ending_and_mixed_endings() {
        for eol in ["\n", "\r", "\r\n"] {
            let bytes = format!("id:1{eol}data:a{eol}data:b{eol}{eol}data:c{eol}{eol}");
            assert_eq!(
                events(bytes.as_bytes()),
                [event("message", "a\nb", "1"), event("message", "c", "1")]
            );
        }
        assert_eq!(
            events(b"data:a\rdata:b\r\n\ndata:c\n\r"),
            [Event::new("a\nb"), Event::new("c")]
        );
    }

    #[test]
    fn split_crlf_is_one_ending() {
        let mut stream = Stream::new(Events::default());
        let mut got = Vec::new();
        for chunk in [&b"data:a\r"[..], b"\n", b"data:b\r", b"\n\r", b"\n"] {
            pump(&mut stream, chunk, |v| got.push(v)).unwrap();
        }
        assert_eq!(got, [Event::new("a\nb")]);
        finish(&mut stream, |v| got.push(v)).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn bom_at_start_only_and_malformed_utf8() {
        fictionet::assert_cases!(|input| events(input);
            initial_bom: "\u{feff}data:one\n\n\u{feff}data:ignored\ndata:\u{feff}two\n\n".as_bytes() => [Event::new("one"), Event::new("\u{feff}two")],
            repeated_bom: "\u{feff}\u{feff}data:ignored\ndata:x\n\n".as_bytes() => [Event::new("x")],
            invalid_utf8: b"data:\xff\xc3\n\ndata:\xf0\x90\x80\n\n" => [Event::new("\u{fffd}\u{fffd}"), Event::new("\u{fffd}")],
        );
        assert!(events(b"\xef\xbb\xbf").is_empty());
        assert!(events(b"\xef\xbb").is_empty());
    }

    #[test]
    fn eof_discards_partial_event_and_pending_id() {
        let mut stream = Stream::new(Events::default());
        pump(
            &mut stream,
            b"id:kept\n\nid:lost\nevent:custom\ndata:partial\n",
            |_| panic!(),
        )
        .unwrap();
        finish(&mut stream, |_| panic!()).unwrap();
        assert_eq!(stream.decoder().last_event_id(), "kept");
        assert_eq!(stream.held(), "kept".len());
        assert!(events(b"data:partial\r\n").is_empty());
        assert!(events(b"data:partial\r").is_empty());
        assert_eq!(events(b"data:complete\r\r"), [Event::new("complete")]);
    }

    #[test]
    fn raw_line_limits_and_utf8_expansion() {
        for bytes in [&b"12345\n"[..], b"12345", b"123456", b"\xff\xff\n"] {
            assert_eq!(
                decode_all(|| RawLines::with_limit(4), bytes).1,
                Some(Fail::Protocol(Error::LineTooLong { limit: 4 }))
            );
        }
        assert_eq!(decode_all(|| RawLines::with_limit(4), b"data\r\n").1, None);
        assert_eq!(
            decode_all(|| RawLines::with_limit(0), b"\xef\xbb\xbf\r\n").0,
            [Line::Empty]
        );
        assert_eq!(
            RawLines::with_limit(usize::MAX).capacity(),
            Buffer::MAX_LIMIT
        );
        assert_eq!(
            Events::with_limits(Limits {
                line: usize::MAX,
                event: usize::MAX
            })
            .capacity(),
            Buffer::MAX_LIMIT
        );
    }

    #[test]
    fn event_budget_counts_comments_unknowns_and_overwrites() {
        for line in [
            ":abc\n",
            "unknown:abc\n",
            "event:abc\n",
            "id:abc\n",
            "retry:42\n",
            "data:\n",
        ] {
            let bytes = line.repeat(40);
            assert_eq!(
                decode_all(
                    || Events::with_limits(Limits {
                        line: 32,
                        event: 64
                    }),
                    bytes.as_bytes()
                )
                .1,
                Some(Fail::Protocol(Error::EventTooLong { limit: 64 }))
            );
        }
        let mut raw = Stream::new(RawLines::with_limit(8));
        for _ in 0..4096 {
            pump(&mut raw, b":\n", |_| {}).unwrap();
            assert_eq!(raw.held(), 0);
        }
    }

    #[test]
    fn exact_budget_and_inherited_id_cost() {
        let value = Event::new("a");
        let bytes = value.to_bytes().unwrap();
        let limits = Limits {
            line: 6,
            event: bytes.len(),
        };
        assert_eq!(
            decode_all(|| Events::with_limits(limits), &bytes),
            (vec![value], None)
        );
        fictionet::assert_cases!(|make, input| decode_all(make, input).1;
            (|| Events::with_limits(Limits { event: limits.event - 1, ..limits }), &bytes) => Some(Fail::Protocol(Error::EventTooLong { limit: limits.event - 1 })),
            // Each input block fits; repeating the inherited ID in the second
            // event's independent encoding does not.
            (|| Events::with_limits(Limits { line: 32, event: 20 }), b"id:1234567890\n\ndata:123456\n\n") => Some(Fail::Protocol(Error::EventTooLong { limit: 20 })),
        );
    }

    #[test]
    fn writers_round_trip_spaces_lf_null_data_and_bom_values() {
        for data in [
            "", " ", "\n", "a\n", "\na", "a\n\nb", "\0", "\u{feff}", "α\n β",
        ] {
            let value = event(" named", data, " \u{feff}id");
            let bytes = value.to_bytes().unwrap();
            assert_eq!(Event::parse(&bytes), Ok(value.clone()));
            assert_eq!(events(&bytes), [value]);
        }
        for line in [
            Line::Empty,
            Line::Comment("  keep me".into()),
            Line::Retry("00012".into()),
            Line::Data("  value".into()),
            Line::Event("".into()),
            Line::Id("".into()),
            ignored("id".into(), "bad\0".into()),
            ignored("unknown".into(), " :value".into()),
        ] {
            let bytes = line.to_bytes().unwrap();
            assert_eq!(Line::parse(&bytes), Ok(line.clone()));
            assert_eq!(decode_all(RawLines::default, &bytes), (vec![line], None));
        }
        let bytes = [event("message", "one", "old"), Event::new("two")]
            .iter()
            .flat_map(|v| v.to_bytes().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            events(&bytes),
            [event("message", "one", "old"), Event::new("two")]
        );
    }

    #[test]
    fn event_writer_refusals_are_transactional() {
        for kind in ["", "a\rb", "a\nb"] {
            contract::check_refused(&event(kind, "x", ""));
        }
        for id in ["a\rb", "a\nb", "a\0b"] {
            contract::check_refused(&event("message", "x", id));
        }
        contract::check_refused(&Event::new("a\rb"));
        contract::check_refused(&Event::new("x".repeat(MAX_LINE)));
        contract::check_refused(&Event::new("x\n".repeat(MAX_EVENT / 2)));
        contract::check_refused(&event(&"x".repeat(MAX_LINE), "", ""));
        contract::check_refused(&event("message", "", &"x".repeat(MAX_LINE)));
    }

    #[test]
    fn line_writer_refusals_are_transactional() {
        for line in [
            Line::Comment("a\nb".into()),
            Line::Data("a\rb".into()),
            Line::Event("a\nb".into()),
            Line::Id("a\0b".into()),
            Line::Retry("".into()),
            Line::Retry("１２".into()),
            Line::Retry("+1".into()),
            Line::Comment("x".repeat(MAX_LINE)),
            ignored("".into(), "x".into()),
            ignored("a:b".into(), "x".into()),
            ignored("a\nb".into(), "x".into()),
            ignored("\u{feff}unknown".into(), "x".into()),
            ignored("data".into(), "x".into()),
            ignored("retry".into(), "10".into()),
            ignored("id".into(), "ok".into()),
        ] {
            contract::check_refused(&line);
        }
    }

    #[test]
    fn exact_wire_parsers_refuse_tails() {
        for bytes in [
            &b""[..],
            b"data:x",
            b"data:x\n",
            b"data:x\n\ntail",
            b"data:x\n\n\n",
            b"data:x\n\ndata:y\n\n",
        ] {
            assert!(Event::parse(bytes).is_err());
        }
        for bytes in [
            &b""[..],
            b":tail",
            b"data:x\ndata:y\n",
            b"data:x\npartial",
            b"\xef\xbb\xbf",
        ] {
            assert!(Line::parse(bytes).is_err());
        }
        assert_eq!(
            Event::parse(b"\xef\xbb\xbfdata:x\r\n\r\n"),
            Ok(Event::new("x"))
        );
        assert_eq!(
            Line::parse(b"\xef\xbb\xbf:hello\r\n"),
            Ok(Line::Comment("hello".into()))
        );
    }
}
