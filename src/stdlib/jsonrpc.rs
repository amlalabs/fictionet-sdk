//! JSON-RPC 2.0 envelopes for requests, notifications, and responses.
//!
//! This follows the [JSON-RPC specification](https://www.jsonrpc.org/specification).
//! Envelopes keep an ordered [`Value`], including extension members and exact
//! number text. Edit that value to rewrite a tool result without rebuilding
//! the surrounding object. Conversion and writing check the envelope again.
//! Whitespace and string escape spelling are not retained; member order is.
//! Duplicate protocol members are refused. Duplicate extension members and
//! duplicates inside params, results, and error data are kept.
//!
//! For MCP stdio, [`Messages`] applies JSON parsing to [`Lines`]. Every line
//! yields a message or a recoverable [`ParseError`]. Blank lines are errors.
//! An overlong line yields one error, then skips through LF. A final line
//! without LF is refused even if its JSON is complete. LF and CRLF work.
//! Batches belong to the body API, not this single-message stdio framing.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, try_pump};
//! use fictionet::stdlib::{json::Value, jsonrpc::{Message, Messages}};
//!
//! let mut stdin = Stream::new(Messages::new());
//! let mut stdout = Vec::new();
//! let chunk = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n";
//! try_pump(&mut stdin, chunk, |item| {
//!     let reply = match item {
//!         Ok(Message::Request(req)) => Some(req.success(Value::Object(vec![]))?),
//!         Ok(Message::Notification(_)) | Ok(Message::Response(_)) => None,
//!         Err(error) => Some(error.response()),
//!     };
//!     if let Some(reply) = reply {
//!         Message::Response(reply).write_line(&mut stdout)?;
//!     }
//!     Ok::<(), Box<dyn core::error::Error>>(())
//! }).map_err(|error| error.to_string())?;
//! assert!(stdout.ends_with(b"\n"));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! For streamable HTTP, feed each POST's body chunks into
//! `Stream::new(Collect::<Body>::new(json::MAX_SIZE))`, then call `finish`
//! at that body's end. [`parse_incoming`] also exposes each invalid batch
//! entry so a server can answer it separately. The MCP layer chooses which
//! protocol revisions permit batches; this module implements JSON-RPC batches.
//! HTTP routing, session headers, and method dispatch belong to that layer.
//!
//! ```
//! use fictionet::stdlib::codec::{Collect, Stream, Wire, finish, pump};
//! use fictionet::stdlib::{json, jsonrpc::{Body, Message}};
//!
//! let mut post = Stream::new(Collect::<Body>::new(json::MAX_SIZE));
//! let mut bodies = Vec::new();
//! pump(&mut post, br#"{"jsonrpc":"2.0","method":"ping","id":"a"}"#,
//!     |body| bodies.push(body))?;
//! finish(&mut post, |body| bodies.push(body))?;
//! if let Some(Body::Message(Message::Request(req))) = bodies.pop() {
//!     let reply = Message::Response(req.success(json::Value::Null)?);
//!     let application_json = reply.to_bytes()?;
//!     // Send these bytes as the HTTP response body, or as SSE event data.
//!     assert!(Message::parse(&application_json).is_ok());
//! }
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! The older HTTP+SSE transport uses the same JSON boundary. After an HTTP
//! body decoder and an SSE decoder have delivered an event, pass its joined
//! data bytes to [`Message::parse`]. Use `reply.to_bytes()` for outgoing SSE
//! data. The initial endpoint event is transport metadata, not JSON-RPC.
//! `Pipe` can carry HTTP body chunks into the SSE decoder; `Demux` can own
//! independent body streams. Neither stack needs another JSON byte scanner.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::{json::Value, jsonrpc::Message};
//!
//! // Joined data from a message event in either HTTP+SSE transport.
//! let event_data = br#"{"id":1e400,"result":"old","jsonrpc":"2.0","x":-0}"#;
//! let mut message = Message::parse(event_data)?;
//! if let Value::Object(members) = message.value_mut() {
//!     if let Some((_, result)) = members.iter_mut().find(|(key, _)| key == "result") {
//!         *result = Value::from("replacement");
//!     }
//! }
//! let outgoing_event_data = message.to_bytes()?;
//! assert_eq!(outgoing_event_data,
//!     br#"{"id":1e400,"result":"replacement","jsonrpc":"2.0","x":-0}"#);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use core::{convert::Infallible, fmt};
use fictionet::stdlib::codec::{Decode, Ending, LineError, Lines, Step, Wire};
use fictionet::stdlib::json::{self, Limits, Number, Value};

/// Invalid JSON text.
pub const PARSE_ERROR: i64 = -32700;
/// A value that is not a valid JSON-RPC envelope.
pub const INVALID_REQUEST: i64 = -32600;
/// No method with the requested name is available.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Method arguments failed application validation.
pub const INVALID_PARAMS: i64 = -32602;
/// An internal JSON-RPC failure.
pub const INTERNAL_ERROR: i64 = -32603;
/// The lowest implementation-defined server error code, inclusive.
pub const SERVER_ERROR_MIN: i64 = -32099;
/// The highest implementation-defined server error code, inclusive.
pub const SERVER_ERROR_MAX: i64 = -32000;
/// Maximum and default line content length: 1 MiB, excluding CRLF or LF.
pub const MAX_LINE: usize = json::MAX_SIZE;

/// Whether `code` is in the implementation-defined server error range.
pub fn is_server_error(code: i64) -> bool {
    (SERVER_ERROR_MIN..=SERVER_ERROR_MAX).contains(&code)
}

/// A request identifier. Number spelling is part of equality.
/// Null and fractional numbers are accepted despite the spec's advice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Id {
    /// A string identifier.
    String(String),
    /// A number identifier with its exact text.
    Number(Number),
    /// An explicit null identifier; this is not a notification.
    Null,
}

impl Id {
    /// Reads an identifier. Refuses other types and the default JSON limits.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        match value {
            Value::String(s) => Ok(Self::String(s)),
            Value::Number(n) => Ok(Self::Number(n)),
            Value::Null => Ok(Self::Null),
            _ => Err(problem(ErrorKind::Id)),
        }
    }

    fn read(value: &Value) -> Option<Self> {
        match value {
            Value::String(s) => Some(Self::String(s.clone())),
            Value::Number(n) => Some(Self::Number(n.clone())),
            Value::Null => Some(Self::Null),
            _ => None,
        }
    }

    /// Converts this identifier, refusing strings beyond the JSON limits.
    pub fn to_value(&self) -> Result<Value, ParseError> {
        if let Self::String(s) = self
            && s.len() > json::MAX_SIZE
        {
            return Err(problem(ErrorKind::Limit(json::Error {
                kind: json::ErrorKind::TooLarge,
                offset: json::MAX_SIZE,
            })));
        }
        let value = match self {
            Self::String(s) => Value::String(s.clone()),
            Self::Number(n) => Value::Number(n.clone()),
            Self::Null => Value::Null,
        };
        bounded(&value)?;
        Ok(value)
    }
}

/// Positional or named parameters. Object order and duplicates are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Params {
    /// Positional parameters.
    Array(Vec<Value>),
    /// Named parameters in their original order.
    Object(Vec<(String, Value)>),
}

impl Params {
    /// Reads parameters, refusing scalars and values beyond JSON limits.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        match value {
            Value::Array(values) => Ok(Self::Array(values)),
            Value::Object(members) => Ok(Self::Object(members)),
            _ => Err(problem(ErrorKind::Params)),
        }
    }

    /// Moves parameters into JSON without changing order or number text.
    /// Refuses values beyond the default JSON limits.
    pub fn to_value(self) -> Result<Value, ParseError> {
        let value = self.into_value();
        bounded(&value)?;
        Ok(value)
    }

    fn into_value(self) -> Value {
        match self {
            Self::Array(values) => Value::Array(values),
            Self::Object(members) => Value::Object(members),
        }
    }
}

/// Why a JSON-RPC value or framed line was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid JSON syntax, including the parser's byte offset.
    Json(json::Error),
    /// A constructed value exceeds the default JSON limits.
    Limit(json::Error),
    /// A line framing failure, including named length and EOF failures.
    Line(LineError),
    /// A line contains only JSON whitespace or no content.
    BlankLine,
    /// An envelope must be an object.
    Object,
    /// A required member is absent.
    Missing(&'static str),
    /// The version is not the string `2.0`.
    Version,
    /// A protocol member occurs more than once.
    Duplicate(&'static str),
    /// The id is not a string, number, or null.
    Id,
    /// The method is not a string.
    Method,
    /// Params is neither an array nor an object.
    Params,
    /// A request also carries response members, or a response carries params.
    MixedEnvelope,
    /// A response has both result and error, or neither.
    ResultOrError,
    /// The error member is not an object.
    ErrorObject,
    /// An error code is not a number with an exact integer value.
    ErrorCode,
    /// An error message is not a string.
    ErrorMessage,
    /// The envelope has another message kind than the requested type.
    MessageKind,
    /// A batch must be an array.
    Batch,
    /// A batch contains no entries.
    EmptyBatch,
}

/// A refusal with a readable id and optional zero-based batch position.
/// Missing, malformed, and duplicate ids become [`Id::Null`]. An otherwise
/// readable id is retained even when another envelope member is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// The failed rule.
    pub kind: ErrorKind,
    /// Id to use if the caller chooses to send an error response.
    pub id: Id,
    /// The first invalid entry for strict batch conversion.
    pub batch_index: Option<usize>,
}

impl ParseError {
    /// The standard response code. JSON syntax, blank lines, and unfinished
    /// lines map to parse error. Envelope, parameter shape, and resource
    /// limits map to invalid request. Application argument checking uses
    /// [`INVALID_PARAMS`] separately. Never automatically answer a response.
    pub fn rpc_code(&self) -> i64 {
        match &self.kind {
            ErrorKind::Json(e) if is_limit(e) => INVALID_REQUEST,
            ErrorKind::Json(_)
            | ErrorKind::BlankLine
            | ErrorKind::Line(LineError::Unterminated | LineError::BareLf) => PARSE_ERROR,
            _ => INVALID_REQUEST,
        }
    }

    /// Builds an error response with the standard message and recovered id.
    /// Callers decide whether their peer expects a response.
    pub fn response(&self) -> Response {
        let code = self.rpc_code();
        let message = if code == PARSE_ERROR {
            "Parse error"
        } else {
            "Invalid Request"
        };
        Response::error(Some(self.id.clone()), code, message)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.batch_index {
            write!(f, "batch entry {index}: ")?;
        }
        match &self.kind {
            ErrorKind::Json(e) | ErrorKind::Limit(e) => write!(f, "JSON: {e}"),
            ErrorKind::Line(e) => write!(f, "{e}"),
            ErrorKind::BlankLine => f.write_str("blank JSON-RPC line"),
            ErrorKind::Object => f.write_str("JSON-RPC envelope is not an object"),
            ErrorKind::Missing(key) => write!(f, "missing {key}"),
            ErrorKind::Version => f.write_str("jsonrpc must be the string 2.0"),
            ErrorKind::Duplicate(key) => write!(f, "duplicate {key}"),
            ErrorKind::Id => f.write_str("id must be a string, number, or null"),
            ErrorKind::Method => f.write_str("method must be a string"),
            ErrorKind::Params => f.write_str("params must be an array or object"),
            ErrorKind::MixedEnvelope => f.write_str("mixed request and response members"),
            ErrorKind::ResultOrError => {
                f.write_str("response needs exactly one of result and error")
            }
            ErrorKind::ErrorObject => f.write_str("error must be an object"),
            ErrorKind::ErrorCode => f.write_str("error code must be an integer number"),
            ErrorKind::ErrorMessage => f.write_str("error message must be a string"),
            ErrorKind::MessageKind => f.write_str("unexpected JSON-RPC message kind"),
            ErrorKind::Batch => f.write_str("batch must be an array"),
            ErrorKind::EmptyBatch => f.write_str("empty JSON-RPC batch"),
        }
    }
}
impl core::error::Error for ParseError {}

fn problem(kind: ErrorKind) -> ParseError {
    ParseError {
        kind,
        id: Id::Null,
        batch_index: None,
    }
}
fn is_limit(e: &json::Error) -> bool {
    matches!(
        e.kind,
        json::ErrorKind::TooLarge
            | json::ErrorKind::TooDeep
            | json::ErrorKind::TooManyElements
            | json::ErrorKind::NumberTooLong
    )
}
fn bounded(value: &Value) -> Result<(), ParseError> {
    value
        .validate(&Limits::default())
        .map_err(|e| problem(ErrorKind::Limit(e)))
}
fn recover_id(value: &Value) -> Id {
    let Some(members) = value.as_object() else {
        return Id::Null;
    };
    let mut ids = members.iter().filter(|(key, _)| key == "id");
    let id = ids.next().and_then(|(_, value)| Id::read(value));
    if ids.next().is_some() {
        Id::Null
    } else {
        id.unwrap_or(Id::Null)
    }
}
fn unique(value: &Value, keys: &[&'static str]) -> Result<(), ErrorKind> {
    let members = value.as_object().ok_or(ErrorKind::Object)?;
    // The key set has a fixed protocol size, so this is linear in members.
    for &key in keys {
        if members.iter().filter(|(k, _)| k == key).take(2).count() > 1 {
            return Err(ErrorKind::Duplicate(key));
        }
    }
    Ok(())
}
fn required<'a>(value: &'a Value, key: &'static str) -> Result<&'a Value, ErrorKind> {
    value.get(key).ok_or(ErrorKind::Missing(key))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Request,
    Notification,
    Response,
}

fn envelope(value: &Value) -> Result<Kind, ErrorKind> {
    unique(
        value,
        &["jsonrpc", "method", "params", "id", "result", "error"],
    )?;
    if required(value, "jsonrpc")?.as_str() != Some("2.0") {
        return Err(ErrorKind::Version);
    }
    if let Some(id) = value.get("id")
        && !matches!(id, Value::String(_) | Value::Number(_) | Value::Null)
    {
        return Err(ErrorKind::Id);
    }
    if let Some(method) = value.get("method") {
        if method.as_str().is_none() {
            return Err(ErrorKind::Method);
        }
        if value.get("result").is_some() || value.get("error").is_some() {
            return Err(ErrorKind::MixedEnvelope);
        }
        if let Some(params) = value.get("params")
            && !matches!(params, Value::Array(_) | Value::Object(_))
        {
            return Err(ErrorKind::Params);
        }
        Ok(if value.get("id").is_some() {
            Kind::Request
        } else {
            Kind::Notification
        })
    } else {
        if value.get("params").is_some() {
            return Err(ErrorKind::MixedEnvelope);
        }
        if value.get("result").is_some() == value.get("error").is_some() {
            return Err(ErrorKind::ResultOrError);
        }
        required(value, "id")?;
        if let Some(error) = value.get("error") {
            error_object(error)?;
        }
        Ok(Kind::Response)
    }
}

fn error_object(value: &Value) -> Result<(), ErrorKind> {
    if value.as_object().is_none() {
        return Err(ErrorKind::ErrorObject);
    }
    unique(value, &["code", "message", "data"])?;
    let code = required(value, "code")?
        .as_number()
        .ok_or(ErrorKind::ErrorCode)?;
    if !integer(code) {
        return Err(ErrorKind::ErrorCode);
    }
    if required(value, "message")?.as_str().is_none() {
        return Err(ErrorKind::ErrorMessage);
    }
    Ok(())
}

// Check the exact decimal value, never the rounded f64. Exponents may be
// enormous; saturation beyond the bounded mantissa length preserves the test.
fn integer(number: &Number) -> bool {
    let text = number.text();
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let digits = mantissa.bytes().filter(u8::is_ascii_digit);
    if digits.clone().all(|b| b == b'0') {
        return true;
    }
    let fraction = mantissa.split_once('.').map_or(0, |(_, s)| s.len());
    let zeros = mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .rev()
        .take_while(|b| *b == b'0')
        .count();
    let negative = exponent.starts_with('-');
    let magnitude = exponent
        .bytes()
        .filter(u8::is_ascii_digit)
        .fold(0_i64, |n, b| {
            n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
        });
    let exponent = if negative { -magnitude } else { magnitude };
    exponent.saturating_add(i64::try_from(zeros).unwrap_or(i64::MAX))
        >= i64::try_from(fraction).unwrap_or(i64::MAX)
}

fn checked(value: &Value, kind: Kind) -> Result<(), ParseError> {
    bounded(value)?;
    let result = envelope(value).and_then(|actual| {
        if actual == kind {
            Ok(())
        } else {
            Err(ErrorKind::MessageKind)
        }
    });
    result.map_err(|kind| ParseError {
        kind,
        id: recover_id(value),
        batch_index: None,
    })
}

macro_rules! envelope_type {
    ($name:ident, $kind:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            /// The complete ordered envelope, including extension members.
            /// Direct edits may invalidate it. Conversion and writing refuse
            /// invalid envelopes instead of fixing or dropping members.
            pub value: Value,
        }
        impl $name {
            /// Checks this message kind and the default JSON limits.
            pub fn from_value(value: Value) -> Result<Self, ParseError> {
                checked(&value, Kind::$kind)?;
                Ok(Self { value })
            }
            /// Checks and copies the complete value, preserving all members.
            /// Refuses invalid envelopes or values beyond default JSON limits.
            pub fn to_value(&self) -> Result<Value, ParseError> {
                checked(&self.value, Kind::$kind)?;
                Ok(self.value.clone())
            }
        }
    };
}

envelope_type!(
    Request,
    Request,
    "A method call with an id. Use `new` or `from_value`, then edit `value` in place for proxy rewrites."
);
envelope_type!(
    Notification,
    Notification,
    "A method call without an id. Valid notifications never require a response."
);
envelope_type!(
    Response,
    Response,
    "A reply with an id and exactly one of result or error. Its ordered envelope is checked on conversion and writing."
);

fn call(method: String, params: Option<Params>, id: Option<Id>) -> Value {
    let mut fields = vec![
        ("jsonrpc".into(), Value::from("2.0")),
        ("method".into(), Value::String(method)),
    ];
    if let Some(params) = params {
        fields.push(("params".into(), params.into_value()));
    }
    if let Some(id) = id {
        fields.push(("id".into(), id_value(id)));
    }
    Value::Object(fields)
}
fn id_value(id: Id) -> Value {
    match id {
        Id::Null => Value::Null,
        Id::String(s) => Value::String(s),
        Id::Number(n) => Value::Number(n),
    }
}

impl Request {
    /// Builds a request. Size and nesting are checked on conversion or writing.
    /// Names beginning with `rpc.` are accepted for protocol extensions.
    pub fn new(method: impl Into<String>, params: Option<Params>, id: Id) -> Self {
        Self {
            value: call(method.into(), params, Some(id)),
        }
    }
    /// The method string, or `None` if a direct edit made it invalid or absent.
    pub fn method(&self) -> Option<&str> {
        self.value.get("method")?.as_str()
    }
    /// The optional parameter value. Direct edits may give it an invalid shape.
    pub fn params(&self) -> Option<&Value> {
        self.value.get("params")
    }
    /// The id after checking the whole request and its JSON limits.
    pub fn id(&self) -> Result<Id, ParseError> {
        checked(&self.value, Kind::Request)?;
        Ok(recover_id(&self.value))
    }
    /// Answers this request with a result and its exact id. Refuses an invalid
    /// request. The result's size and depth are checked when it is written.
    pub fn success(&self, result: Value) -> Result<Response, ParseError> {
        Ok(Response::success(self.id()?, result))
    }
    /// Answers this request with an error and its exact id. Refuses an invalid
    /// request. The error's limits are checked when the response is written.
    pub fn error(&self, code: i64, message: impl Into<String>) -> Result<Response, ParseError> {
        Ok(Response::error(Some(self.id()?), code, message))
    }
}
impl Notification {
    /// Builds a notification. Limits are checked on conversion or writing.
    pub fn new(method: impl Into<String>, params: Option<Params>) -> Self {
        Self {
            value: call(method.into(), params, None),
        }
    }
    /// The method string, or `None` after an invalid direct edit.
    pub fn method(&self) -> Option<&str> {
        self.value.get("method")?.as_str()
    }
    /// The optional parameter value. Direct edits may invalidate its shape.
    pub fn params(&self) -> Option<&Value> {
        self.value.get("params")
    }
}

/// A JSON-RPC error object. Its complete ordered value includes extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The error object. Direct edits are checked on conversion and writing
    /// of a containing response, including an integer code and string message.
    pub value: Value,
}
impl Error {
    /// Builds an error without data. Limits are checked on conversion or writing.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            value: Value::Object(vec![
                ("code".into(), Value::from(code)),
                ("message".into(), Value::String(message.into())),
            ]),
        }
    }
    /// Reads an error object with integer code, string message, and optional data.
    /// Extension members are kept. Refuses duplicate protocol members and limits.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        error_object(&value).map_err(problem)?;
        Ok(Self { value })
    }
    /// Checks and copies this error, retaining its code spelling and member order.
    pub fn to_value(&self) -> Result<Value, ParseError> {
        bounded(&self.value)?;
        error_object(&self.value).map_err(problem)?;
        Ok(self.value.clone())
    }
    /// The exact code number, or `None` if missing or not numeric after an edit.
    /// Integer-valued decimal and exponent spellings are accepted by validation.
    pub fn code(&self) -> Option<&Number> {
        self.value.get("code")?.as_number()
    }
    /// The message, or `None` after an invalid direct edit.
    pub fn message(&self) -> Option<&str> {
        self.value.get("message")?.as_str()
    }
    /// Optional error data, with null distinct from absence.
    pub fn data(&self) -> Option<&Value> {
        self.value.get("data")
    }
}

/// The mutually exclusive payload of a validated response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Successful method result, including null.
    Result(Value),
    /// Error object, including optional data and extension members.
    Error(Error),
}
impl Response {
    /// Builds a success. Limits are checked on conversion or writing.
    pub fn success(id: Id, result: Value) -> Self {
        Self {
            value: Value::Object(vec![
                ("jsonrpc".into(), Value::from("2.0")),
                ("result".into(), result),
                ("id".into(), id_value(id)),
            ]),
        }
    }
    /// Builds an error response. `None` means an unreadable id and writes null.
    /// Limits are checked on conversion or writing.
    pub fn error(id: Option<Id>, code: i64, message: impl Into<String>) -> Self {
        Self::with_error(id.unwrap_or(Id::Null), Error::new(code, message))
    }
    /// Builds a response from a complete error object, including data and
    /// extensions. The object and limits are checked on conversion or writing.
    pub fn with_error(id: Id, error: Error) -> Self {
        Self {
            value: Value::Object(vec![
                ("jsonrpc".into(), Value::from("2.0")),
                ("error".into(), error.value),
                ("id".into(), id_value(id)),
            ]),
        }
    }
    /// The response id, after checking the whole envelope and its limits.
    pub fn id(&self) -> Result<Id, ParseError> {
        checked(&self.value, Kind::Response)?;
        Ok(recover_id(&self.value))
    }
    /// Checks the response and copies its single result or error payload.
    pub fn outcome(&self) -> Result<Outcome, ParseError> {
        checked(&self.value, Kind::Response)?;
        if let Some(result) = self.value.get("result") {
            return Ok(Outcome::Result(result.clone()));
        }
        match self.value.get("error") {
            Some(error) => Ok(Outcome::Error(Error {
                value: error.clone(),
            })),
            None => Err(problem(ErrorKind::ResultOrError)),
        }
    }
}

/// One request, notification, or response. It does not contain batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A call that expects a response.
    Request(Request),
    /// A call that expects no response.
    Notification(Notification),
    /// A success or error reply.
    Response(Response),
}
impl Message {
    /// Checks and classifies an envelope, keeping every member. Refuses the
    /// default JSON limits and malformed or ambiguous envelopes.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        let kind = envelope(&value).map_err(|kind| ParseError {
            kind,
            id: recover_id(&value),
            batch_index: None,
        })?;
        Ok(match kind {
            Kind::Request => Self::Request(Request { value }),
            Kind::Notification => Self::Notification(Notification { value }),
            Kind::Response => Self::Response(Response { value }),
        })
    }
    /// Checks the variant, envelope, and limits, then copies its JSON value.
    pub fn to_value(&self) -> Result<Value, ParseError> {
        self.validate()?;
        Ok(self.value().clone())
    }
    /// The full ordered envelope, for inspecting extensions without copying.
    pub fn value(&self) -> &Value {
        match self {
            Self::Request(r) => &r.value,
            Self::Notification(n) => &n.value,
            Self::Response(r) => &r.value,
        }
    }
    /// The full ordered envelope for edits. Invalid edits are refused on write.
    pub fn value_mut(&mut self) -> &mut Value {
        match self {
            Self::Request(r) => &mut r.value,
            Self::Notification(n) => &mut n.value,
            Self::Response(r) => &mut r.value,
        }
    }
    fn validate(&self) -> Result<(), ParseError> {
        let kind = match self {
            Self::Request(_) => Kind::Request,
            Self::Notification(_) => Kind::Notification,
            Self::Response(_) => Kind::Response,
        };
        checked(self.value(), kind)
    }
    /// Parses exactly one message with caller-selected JSON limits, clamped to
    /// JSON's hard caps. Arrays, trailing values, and invalid envelopes fail.
    pub fn parse_with(input: &[u8], limits: &Limits) -> Result<Self, ParseError> {
        Self::from_value(json::parse_with(input, limits).map_err(|e| problem(ErrorKind::Json(e)))?)
    }
    /// Appends compact JSON followed by one LF. Refuses invalid envelopes,
    /// JSON limits, allocation failure, or raw CR/LF in the encoded message.
    /// Strings are escaped by JSON and numbers have checked grammar, so valid
    /// values cannot produce raw newlines. Refusal leaves `out` unchanged.
    pub fn write_line(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let mut bytes = self.to_bytes()?;
        if bytes.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            return Err(WriteError::Unwritable);
        }
        bytes.push(b'\n');
        append(out, &bytes)
    }
}

/// A nonempty array of valid messages. Callers may edit the list; writing
/// refuses an empty list, invalid members, or aggregate JSON limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// Messages in their original order.
    pub messages: Vec<Message>,
}
impl Batch {
    /// Reads a nonempty batch. Reports the first bad entry with its position.
    /// Use [`Incoming::from_value`] to process every entry of a mixed batch.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        let Value::Array(values) = value else {
            return Err(problem(ErrorKind::Batch));
        };
        if values.is_empty() {
            return Err(problem(ErrorKind::EmptyBatch));
        }
        let messages = values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                Message::from_value(value).map_err(|mut error| {
                    error.batch_index = Some(index);
                    error
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { messages })
    }
    /// Checks nonemptiness, every envelope, and total JSON limits, then copies
    /// the array. Staging is capped at JSON's size and element limits.
    pub fn to_value(&self) -> Result<Value, ParseError> {
        // Writing to a bounded byte buffer avoids cloning an unbounded list
        // of individually valid messages before checking aggregate limits.
        let bytes = self.render()?;
        json::parse_with(&bytes, &Limits::default()).map_err(|e| problem(ErrorKind::Limit(e)))
    }
    fn render(&self) -> Result<Vec<u8>, ParseError> {
        if self.messages.is_empty() {
            return Err(problem(ErrorKind::EmptyBatch));
        }
        if self.messages.len() >= json::MAX_ELEMENTS {
            return Err(problem(ErrorKind::Limit(json::Error {
                kind: json::ErrorKind::TooManyElements,
                offset: 0,
            })));
        }
        let mut bytes = vec![b'['];
        for (index, message) in self.messages.iter().enumerate() {
            message.validate().map_err(|mut e| {
                e.batch_index = Some(index);
                e
            })?;
            let part = message
                .value()
                .to_bytes()
                .map_err(|e| problem(ErrorKind::Limit(e)))?;
            let required = bytes
                .len()
                .checked_add(part.len())
                .and_then(|n| n.checked_add(1 + usize::from(index != 0)));
            if required.is_none_or(|n| n > json::MAX_SIZE) {
                return Err(too_large());
            }
            if index != 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(&part);
        }
        bytes.push(b']');
        // Accounts for the outer array's depth and aggregate element count.
        json::parse_with(&bytes, &Limits::default()).map_err(|e| problem(ErrorKind::Limit(e)))?;
        Ok(bytes)
    }
}
fn too_large() -> ParseError {
    problem(ErrorKind::Limit(json::Error {
        kind: json::ErrorKind::TooLarge,
        offset: json::MAX_SIZE,
    }))
}

/// One complete transport body: a message or a nonempty batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// A single envelope.
    Message(Message),
    /// A nonempty array of envelopes.
    Batch(Batch),
}
impl Body {
    /// Classifies a value. Invalid batch entries fail the whole conversion.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        if matches!(value, Value::Array(_)) {
            Batch::from_value(value).map(Self::Batch)
        } else {
            Message::from_value(value).map(Self::Message)
        }
    }
    /// Checks this body and copies its ordered JSON value within default limits.
    pub fn to_value(&self) -> Result<Value, ParseError> {
        match self {
            Self::Message(m) => m.to_value(),
            Self::Batch(b) => b.to_value(),
        }
    }
}

/// Reads one complete body with default JSON limits. Whitespace is allowed;
/// trailing values, empty batches, and invalid envelopes are refused.
pub fn parse(input: &[u8]) -> Result<Body, ParseError> {
    parse_with(input, &Limits::default())
}
/// Reads a complete body using JSON limits clamped to the JSON hard caps.
/// For errors in each batch entry separately, use [`parse_incoming_with`].
pub fn parse_with(input: &[u8], limits: &Limits) -> Result<Body, ParseError> {
    Body::from_value(json::parse_with(input, limits).map_err(|e| problem(ErrorKind::Json(e)))?)
}

/// Server-side input that retains a refusal for every invalid batch entry.
/// This is a reading result, not a wire value. Dispatch requests and reply to
/// their errors; do not answer valid notifications or incoming responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    /// A single message, or a refusal with its recovered id.
    Message(Result<Message, ParseError>),
    /// A nonempty batch with one result per entry, in input order.
    Batch(Vec<Result<Message, ParseError>>),
}
impl Incoming {
    /// Reads a body value within JSON limits. Empty arrays fail as a whole;
    /// every entry of a nonempty array gets its own result. Nested arrays
    /// are invalid entries. No valid neighboring message is discarded.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        bounded(&value)?;
        match value {
            Value::Array(values) if values.is_empty() => Err(problem(ErrorKind::EmptyBatch)),
            Value::Array(values) => Ok(Self::Batch(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        Message::from_value(value).map_err(|mut e| {
                            e.batch_index = Some(index);
                            e
                        })
                    })
                    .collect(),
            )),
            value => Ok(Self::Message(Message::from_value(value))),
        }
    }
}
/// Reads server input with default limits, retaining individual batch errors.
/// Invalid JSON and empty batches return a single whole-body error.
pub fn parse_incoming(input: &[u8]) -> Result<Incoming, ParseError> {
    parse_incoming_with(input, &Limits::default())
}
/// Reads server input with tighter JSON limits and individual batch errors.
/// Invalid JSON, resource limits, and empty arrays fail the whole body.
pub fn parse_incoming_with(input: &[u8], limits: &Limits) -> Result<Incoming, ParseError> {
    Incoming::from_value(json::parse_with(input, limits).map_err(|e| problem(ErrorKind::Json(e)))?)
}

/// A strict writer refusal. The destination has not changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// Invalid envelope, JSON limit, raw newline, or destination allocation failure.
    Unwritable,
}
impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unwritable JSON-RPC value")
    }
}
impl core::error::Error for WriteError {}
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WriteError> {
    out.len()
        .checked_add(bytes.len())
        .ok_or(WriteError::Unwritable)?;
    out.try_reserve(bytes.len())
        .map_err(|_| WriteError::Unwritable)?;
    out.extend_from_slice(bytes);
    Ok(())
}
impl Wire for Message {
    type ParseError = ParseError;
    type WriteError = WriteError;
    /// Reads exactly one envelope within default JSON limits. Refuses batches,
    /// invalid versions, ids, params, response shapes, and trailing values.
    fn parse(input: &[u8]) -> Result<Self, ParseError> {
        Self::parse_with(input, &Limits::default())
    }
    /// Appends compact JSON without a line ending. Refuses malformed or
    /// mismatched envelopes, JSON limits, and destination allocation failure.
    /// Refusal leaves `out` unchanged.
    /// JSON escaping and checked numbers prevent raw CR or LF in the output.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.validate().map_err(|_| WriteError::Unwritable)?;
        let bytes = self
            .value()
            .to_bytes()
            .map_err(|_| WriteError::Unwritable)?;
        append(out, &bytes)
    }
}
impl Wire for Batch {
    type ParseError = ParseError;
    type WriteError = WriteError;
    /// Reads one nonempty array within default JSON limits. Refuses invalid
    /// entries, scalar bodies, empty batches, and trailing values.
    fn parse(input: &[u8]) -> Result<Self, ParseError> {
        Self::from_value(
            json::parse_with(input, &Limits::default()).map_err(|e| problem(ErrorKind::Json(e)))?,
        )
    }
    /// Appends compact JSON. Refuses empty batches, invalid envelopes, and
    /// aggregate size, depth, or element limits, and destination allocation
    /// failure. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.render().map_err(|_| WriteError::Unwritable)?;
        append(out, &bytes)
    }
}
impl Wire for Body {
    type ParseError = ParseError;
    type WriteError = WriteError;
    /// Reads one message or nonempty batch. Refuses invalid JSON, envelopes,
    /// trailing values, and default JSON limits.
    fn parse(input: &[u8]) -> Result<Self, ParseError> {
        parse(input)
    }
    /// Appends compact JSON. Refuses everything the contained message or
    /// batch writer refuses. On refusal, the destination is unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Message(m) => m.write(out),
            Self::Batch(b) => b.write(out),
        }
    }
}

/// Newline-delimited single messages for stdio, built on [`Lines`].
/// The item is `Result<Message, ParseError>`; errors do not stop framing.
/// It retains no input or payload state and scans each input byte once.
pub struct Messages {
    lines: Lines,
    limits: Limits,
}
impl Default for Messages {
    fn default() -> Self {
        Self::new()
    }
}
impl Messages {
    /// Uses a 1 MiB line limit and default JSON limits: depth 128 and 100,000
    /// values. The driver's capacity is the line limit plus two ending bytes.
    pub fn new() -> Self {
        Self::with_limits(MAX_LINE, Limits::default())
    }
    /// Sets the content limit and JSON limits. The line cap is clamped to
    /// [`MAX_LINE`]; JSON caps are clamped by [`json::parse_with`]. A zero
    /// line limit accepts only empty content, reported as a blank-line error.
    pub fn with_limits(max_line: usize, limits: Limits) -> Self {
        Self {
            lines: Lines::new(max_line.min(MAX_LINE), Ending::LfOrCrlf),
            limits,
        }
    }
}
impl Decode for Messages {
    type Item = Result<Message, ParseError>;
    type Error = Infallible;
    const NAME: &'static str = "JSON-RPC lines";
    /// Line content cap plus two terminator bytes; at most 1 MiB plus two.
    fn capacity(&self) -> usize {
        self.lines.capacity()
    }
    /// Reads a line, then parses JSON and checks the envelope. Blank, overlong,
    /// unfinished, malformed, and invalid lines yield recoverable error items.
    /// An overlong line is skipped through LF before another item is read.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Infallible> {
        Ok(match self.lines.decode(input, eof)? {
            Step::Item(line, used) => Step::Item(
                match line {
                    Err(error) => Err(problem(ErrorKind::Line(error))),
                    Ok(line) if line.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r')) => {
                        Err(problem(ErrorKind::BlankLine))
                    }
                    Ok(line) => Message::parse_with(&line, &self.limits),
                },
                used,
            ),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{contract, test_support::decode_all};

    fn value(text: &str) -> Value {
        Value::parse(text.as_bytes()).unwrap()
    }
    fn message(text: &str) -> Message {
        Message::parse(text.as_bytes()).unwrap()
    }
    fn set(value: &mut Value, key: &str, replacement: Value) {
        let Value::Object(members) = value else {
            panic!("test object")
        };
        if let Some((_, old)) = members.iter_mut().find(|(k, _)| k == key) {
            *old = replacement;
        } else {
            members.push((key.into(), replacement));
        }
    }
    fn assert_value(message: Message, expected: &str) {
        assert_eq!(message.to_value().unwrap(), value(expected));
        contract::check_wire_value(&message);
    }

    // A tiny test dispatcher exercises the complete Examples section, including
    // per-entry errors and the absence of any reply to notification-only batches.
    fn dispatch(message: Result<Message, ParseError>) -> Option<Message> {
        let request = match message {
            Err(e) => return Some(Message::Response(e.response())),
            Ok(Message::Request(req)) => req,
            _ => return None,
        };
        let result = match request.method() {
            Some("subtract") => {
                let params = request.params().unwrap();
                let (a, b) = match params {
                    Value::Array(items) => (items.first().unwrap(), items.get(1).unwrap()),
                    _ => (
                        params.get("minuend").unwrap(),
                        params.get("subtrahend").unwrap(),
                    ),
                };
                request
                    .success(Value::from(a.as_i64().unwrap() - b.as_i64().unwrap()))
                    .unwrap()
            }
            Some("sum") => request
                .success(Value::from(
                    request
                        .params()
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_i64().unwrap())
                        .sum::<i64>(),
                ))
                .unwrap(),
            Some("get_data") => request.success(value(r#"["hello",5]"#)).unwrap(),
            _ => request.error(METHOD_NOT_FOUND, "Method not found").unwrap(),
        };
        Some(Message::Response(result))
    }
    fn answer(text: &str) -> Option<Body> {
        match parse_incoming(text.as_bytes()) {
            Err(e) => Some(Body::Message(Message::Response(e.response()))),
            Ok(Incoming::Message(m)) => dispatch(m).map(Body::Message),
            Ok(Incoming::Batch(items)) => {
                let messages = items.into_iter().filter_map(dispatch).collect::<Vec<_>>();
                if messages.is_empty() {
                    None
                } else {
                    Some(Body::Batch(Batch { messages }))
                }
            }
        }
    }
    fn example(input: &str, expected: Option<&str>) {
        let actual = answer(input);
        assert_eq!(
            actual.as_ref().map(|b| b.to_value().unwrap()),
            expected.map(value),
            "{input}"
        );
        if let Some(body) = actual {
            contract::check_wire_value(&body);
        }
    }

    #[test]
    fn specification_calls_and_notifications() {
        for (input, output) in [
            (
                r#"{"jsonrpc":"2.0","method":"subtract","params":[42,23],"id":1}"#,
                r#"{"jsonrpc":"2.0","result":19,"id":1}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"subtract","params":[23,42],"id":2}"#,
                r#"{"jsonrpc":"2.0","result":-19,"id":2}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"subtract","params":{"subtrahend":23,"minuend":42},"id":3}"#,
                r#"{"jsonrpc":"2.0","result":19,"id":3}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"subtract","params":{"minuend":42,"subtrahend":23},"id":4}"#,
                r#"{"jsonrpc":"2.0","result":19,"id":4}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"foobar","id":"1"}"#,
                r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"1"}"#,
            ),
        ] {
            example(input, Some(output));
        }
        example(
            r#"{"jsonrpc":"2.0","method":"update","params":[1,2,3,4,5]}"#,
            None,
        );
        example(r#"{"jsonrpc":"2.0","method":"foobar"}"#, None);
    }

    #[test]
    fn specification_invalid_json_and_batches() {
        let parse_error =
            r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#;
        let invalid =
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}"#;
        example(
            r#"{"jsonrpc":"2.0","method":"foobar, "params":"bar", "baz]"#,
            Some(parse_error),
        );
        example(
            r#"{"jsonrpc":"2.0","method":1,"params":"bar"}"#,
            Some(invalid),
        );
        example(
            r#"[{"jsonrpc":"2.0","method":"sum","params":[1,2,4],"id":"1"},{"jsonrpc":"2.0","method"]"#,
            Some(parse_error),
        );
        example("[]", Some(invalid));
        example("[1]", Some(&format!("[{invalid}]")));
        example("[1,2,3]", Some(&format!("[{invalid},{invalid},{invalid}]")));
        example(
            r#"[
            {"jsonrpc":"2.0","method":"sum","params":[1,2,4],"id":"1"},
            {"jsonrpc":"2.0","method":"notify_hello","params":[7]},
            {"jsonrpc":"2.0","method":"subtract","params":[42,23],"id":"2"},
            {"foo":"boo"},
            {"jsonrpc":"2.0","method":"foo.get","params":{"name":"myself"},"id":"5"},
            {"jsonrpc":"2.0","method":"get_data","id":"9"}
        ]"#,
            Some(
                r#"[
            {"jsonrpc":"2.0","result":7,"id":"1"},
            {"jsonrpc":"2.0","result":19,"id":"2"},
            {"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null},
            {"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"5"},
            {"jsonrpc":"2.0","result":["hello",5],"id":"9"}
        ]"#,
            ),
        );
        example(
            r#"[
            {"jsonrpc":"2.0","method":"notify_sum","params":[1,2,4]},
            {"jsonrpc":"2.0","method":"notify_hello","params":[7]}
        ]"#,
            None,
        );
    }

    #[test]
    fn exact_numbers_extensions_and_rewrites() {
        for id in ["1.0", "1e400", "-0", "null", "\"a\""] {
            let text = format!(
                r#"{{"extra":1e400,"id":{id},"params":{{"z":1.0,"a":-0,"z":1e400}},"method":"rpc.extension","jsonrpc":"2.0","extra":-0}}"#
            );
            let req = Request::from_value(value(&text)).unwrap();
            assert_eq!(req.to_value().unwrap(), value(&text));
            assert_eq!(req.id().unwrap().to_value().unwrap(), value(id));
            let reply = req.success(value(r#"{"z":1.0,"a":-0}"#)).unwrap();
            assert_eq!(reply.id().unwrap(), req.id().unwrap());
            assert_eq!(
                reply.outcome().unwrap(),
                Outcome::Result(value(r#"{"z":1.0,"a":-0}"#))
            );
            contract::check_wire_value(&Message::Request(req));
            contract::check_wire_value(&Message::Response(reply));
        }
        let input = r#"{"x":-0,"result":{"z":1e400,"a":1.0},"jsonrpc":"2.0","id":-0,"x":1.0}"#;
        let mut edited = message(input);
        set(
            edited.value_mut(),
            "result",
            value(r#"{"text":"changed\nline","score":-0}"#),
        );
        assert_value(
            edited,
            r#"{"x":-0,"result":{"text":"changed\nline","score":-0},"jsonrpc":"2.0","id":-0,"x":1.0}"#,
        );
        let error = r#"{"extra":-0,"data":{"z":1e400,"a":1.0},"message":"problem","code":-32600.00,"extra":1.0}"#;
        let error = Error::from_value(value(error)).unwrap();
        assert_eq!(error.code().unwrap().text(), "-32600.00");
        assert_eq!(error.message(), Some("problem"));
        assert_eq!(error.data(), Some(&value(r#"{"z":1e400,"a":1.0}"#)));
        let response = Response::with_error(Id::Null, error.clone());
        assert_eq!(response.outcome().unwrap(), Outcome::Error(error.clone()));
        assert_eq!(error.to_value().unwrap(), error.value);
        contract::check_wire_value(&Message::Response(response));
    }

    #[test]
    fn conversion_rules_and_error_ids() {
        let cases = [
            ("0", ErrorKind::Object),
            (r#"{"method":"x"}"#, ErrorKind::Missing("jsonrpc")),
            (r#"{"jsonrpc":2,"method":"x"}"#, ErrorKind::Version),
            (r#"{"jsonrpc":"1.0","method":"x"}"#, ErrorKind::Version),
            (r#"{"jsonrpc":"2.0","method":false}"#, ErrorKind::Method),
            (
                r#"{"jsonrpc":"2.0","method":"x","params":null}"#,
                ErrorKind::Params,
            ),
            (r#"{"jsonrpc":"2.0","method":"x","id":[]}"#, ErrorKind::Id),
            (r#"{"jsonrpc":"2.0","result":0}"#, ErrorKind::Missing("id")),
            (r#"{"jsonrpc":"2.0","id":0}"#, ErrorKind::ResultOrError),
            (
                r#"{"jsonrpc":"2.0","id":0,"result":null,"error":{}}"#,
                ErrorKind::ResultOrError,
            ),
            (
                r#"{"jsonrpc":"2.0","method":"x","result":null}"#,
                ErrorKind::MixedEnvelope,
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"params":[],"result":null}"#,
                ErrorKind::MixedEnvelope,
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"error":null}"#,
                ErrorKind::ErrorObject,
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"error":{}}"#,
                ErrorKind::Missing("code"),
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"error":{"code":0}}"#,
                ErrorKind::Missing("message"),
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"error":{"code":0,"message":0}}"#,
                ErrorKind::ErrorMessage,
            ),
            (
                r#"{"jsonrpc":"2.0","id":0,"error":{"code":"0","message":"x"}}"#,
                ErrorKind::ErrorCode,
            ),
        ];
        for (text, kind) in cases {
            let error = Message::from_value(value(text)).unwrap_err();
            assert_eq!(error.kind, kind, "{text}");
            assert_eq!(error.rpc_code(), INVALID_REQUEST);
            assert!(!error.to_string().is_empty());
        }
        for text in ["true", "[]", "{}"] {
            assert!(Id::from_value(value(text)).is_err());
        }
        for text in ["true", "0", "null", "\"x\""] {
            assert!(Params::from_value(value(text)).is_err());
        }
        for text in ["[]", r#"{"z":1.0,"a":-0}"#] {
            assert_eq!(
                Params::from_value(value(text)).unwrap().to_value().unwrap(),
                value(text)
            );
        }
        for id in ["1e400", "-0", "\"key\""] {
            let error =
                Message::parse(format!(r#"{{"jsonrpc":"bad","id":{id}}}"#).as_bytes()).unwrap_err();
            assert_eq!(
                error.response().id().unwrap().to_value().unwrap(),
                value(id)
            );
        }
        for text in [r#"{"id":true}"#, r#"{"id":1,"id":2}"#, "{"] {
            assert_eq!(Message::parse(text.as_bytes()).unwrap_err().id, Id::Null);
        }
        assert!(Request::from_value(value(r#"{"jsonrpc":"2.0","method":"x"}"#)).is_err());
        assert!(
            Notification::from_value(value(r#"{"jsonrpc":"2.0","method":"x","id":null}"#)).is_err()
        );
        assert!(Response::from_value(value(r#"{"jsonrpc":"2.0","method":"x"}"#)).is_err());
        assert_eq!(
            Batch::from_value(value("0")).unwrap_err().kind,
            ErrorKind::Batch
        );
        assert_eq!(
            Batch::from_value(value("[]")).unwrap_err().kind,
            ErrorKind::EmptyBatch
        );
        let bad_batch =
            Batch::from_value(value(r#"[{"jsonrpc":"2.0","method":"x"},1,2]"#)).unwrap_err();
        assert_eq!(bad_batch.batch_index, Some(1));
        assert!(bad_batch.to_string().starts_with("batch entry 1:"));
        let Incoming::Batch(entries) = parse_incoming(b"[[],1]").unwrap() else {
            panic!()
        };
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(Result::is_err));
    }

    #[test]
    fn duplicate_protocol_keys_and_case() {
        let base = value(r#"{"jsonrpc":"2.0","method":"x","params":[],"id":1}"#);
        for key in ["jsonrpc", "method", "params", "id"] {
            let mut v = base.clone();
            let copy = v.get(key).unwrap().clone();
            if let Value::Object(members) = &mut v {
                members.push((key.into(), copy));
            }
            assert_eq!(
                Message::from_value(v).unwrap_err().kind,
                ErrorKind::Duplicate(key)
            );
        }
        for key in ["result", "error"] {
            let v = format!(r#"{{"jsonrpc":"2.0","id":null,"{key}":null,"{key}":null}}"#);
            assert_eq!(
                Message::from_value(value(&v)).unwrap_err().kind,
                ErrorKind::Duplicate(key)
            );
        }
        for key in ["code", "message", "data"] {
            let mut v = value(r#"{"code":0,"message":"x","data":null}"#);
            if let Value::Object(members) = &mut v {
                members.push((key.into(), Value::Null));
            }
            assert_eq!(
                Error::from_value(v).unwrap_err().kind,
                ErrorKind::Duplicate(key)
            );
        }
        assert!(Message::parse(br#"{"JSONRPC":"2.0","method":"x"}"#).is_err());
        assert!(Message::parse(br#"{"jsonrpc":"2.0","method":"","ID":3}"#).is_ok());
    }

    #[test]
    fn integer_codes_do_not_round() {
        for code in [
            "0",
            "-0",
            "1.0",
            "100.00e-2",
            "-32600e0",
            "1e400",
            "0e-999999999999999",
            "10e-1",
        ] {
            assert!(
                Error::from_value(value(&format!(r#"{{"code":{code},"message":"x"}}"#))).is_ok(),
                "{code}"
            );
        }
        for code in [
            "0.1",
            "1e-400",
            "1.00000000000000000001",
            "10.01e-1",
            "1e-999999999999999",
        ] {
            assert_eq!(
                Error::from_value(value(&format!(r#"{{"code":{code},"message":"x"}}"#)))
                    .unwrap_err()
                    .kind,
                ErrorKind::ErrorCode
            );
        }
        assert_eq!(
            [
                PARSE_ERROR,
                INVALID_REQUEST,
                METHOD_NOT_FOUND,
                INVALID_PARAMS,
                INTERNAL_ERROR
            ],
            [-32700, -32600, -32601, -32602, -32603]
        );
        for code in [SERVER_ERROR_MIN, -32050, SERVER_ERROR_MAX] {
            assert!(is_server_error(code));
        }
        for code in [-32100, -31999, PARSE_ERROR] {
            assert!(!is_server_error(code));
        }
    }

    #[test]
    fn line_recovery_terminators_and_partial_eof() {
        let good = "{\"jsonrpc\":\"2.0\",\"method\":\"x\"}";
        let bytes = format!("\n \t\r\n{{\n0\n{good}\r\n{good}\n{good}");
        let (items, failure) = decode_all(Messages::new, bytes.as_bytes());
        assert_eq!(failure, None);
        assert_eq!(items.len(), 7);
        assert_eq!(
            items.first().unwrap().as_ref().unwrap_err().kind,
            ErrorKind::BlankLine
        );
        assert!(items.get(4).unwrap().is_ok());
        assert!(items.get(5).unwrap().is_ok());
        assert_eq!(
            items.last().unwrap().as_ref().unwrap_err().kind,
            ErrorKind::Line(LineError::Unterminated)
        );
        let bytes = format!("{}\n{good}\n", "x".repeat(300));
        let (items, failure) = decode_all(
            || Messages::with_limits(64, Limits::default()),
            bytes.as_bytes(),
        );
        assert_eq!(failure, None);
        assert_eq!(items.len(), 2);
        assert_eq!(
            items.first().unwrap().as_ref().unwrap_err().kind,
            ErrorKind::Line(LineError::TooLong { max: 64 })
        );
        assert!(items.last().unwrap().is_ok());
        for ending in ["\n", "\r\n"] {
            assert!(
                decode_all(
                    || Messages::with_limits(good.len(), Limits::default()),
                    format!("{good}{ending}").as_bytes()
                )
                .0
                .first()
                .unwrap()
                .is_ok()
            );
        }
        assert_eq!(Messages::new().capacity(), MAX_LINE + 2);
        assert_eq!(
            Messages::with_limits(usize::MAX, Limits::default()).capacity(),
            MAX_LINE + 2
        );
        assert_eq!(Messages::new().held(), 0);
        assert!(decode_all(Messages::new, b"").0.is_empty());
        assert!(
            decode_all(Messages::new, b"[]\n")
                .0
                .first()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            decode_all(|| Messages::with_limits(0, Limits::default()), b"\n")
                .0
                .first()
                .unwrap()
                .as_ref()
                .unwrap_err()
                .kind,
            ErrorKind::BlankLine
        );
    }

    #[test]
    fn wire_refusals_and_limits_are_transactional() {
        let good = message(r#"{"jsonrpc":"2.0","result":null,"id":1}"#);
        for (key, replacement) in [
            ("jsonrpc", Value::from("1.0")),
            ("id", Value::Bool(false)),
            ("error", Value::Null),
            ("result", Value::String("x".repeat(json::MAX_SIZE))),
        ] {
            let mut bad = good.clone();
            set(bad.value_mut(), key, replacement);
            contract::check_wire_value(&bad);
            let mut out = b"prefix".to_vec();
            assert_eq!(bad.write(&mut out), Err(WriteError::Unwritable));
            assert_eq!(bad.write_line(&mut out), Err(WriteError::Unwritable));
            assert_eq!(out, b"prefix");
            assert!(bad.to_value().is_err());
        }
        let bad = Message::Request(Request {
            value: good.value().clone(),
        });
        contract::check_wire_value(&bad);
        assert!(bad.to_bytes().is_err());
        for batch in [
            Batch { messages: vec![] },
            Batch {
                messages: vec![bad],
            },
        ] {
            contract::check_wire_value(&batch);
            assert!(batch.to_value().is_err());
            contract::check_wire_value(&Body::Batch(batch));
        }
        let mut deep = Value::Null;
        for _ in 0..json::MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        assert!(
            Message::Response(Response::success(Id::Null, deep))
                .to_bytes()
                .is_err()
        );
        let many = Batch {
            messages: vec![good; json::MAX_ELEMENTS / 3],
        };
        assert!(many.to_bytes().is_err());
        let text = br#"{"jsonrpc":"2.0","method":"x"}"#;
        for limits in [
            Limits {
                size: 1,
                ..Limits::default()
            },
            Limits {
                depth: 0,
                ..Limits::default()
            },
            Limits {
                elements: 1,
                ..Limits::default()
            },
        ] {
            let error = parse_with(text, &limits).unwrap_err();
            assert_eq!(error.rpc_code(), INVALID_REQUEST);
            assert!(parse_incoming_with(text, &limits).is_err());
            assert!(
                decode_all(
                    || Messages::with_limits(MAX_LINE, limits),
                    &[text.as_slice(), b"\n"].concat()
                )
                .0
                .first()
                .unwrap()
                .is_err()
            );
        }
        for bytes in [b"{}{}".as_slice(), b"\xef\xbb\xbf{}", b"\xff", b""] {
            assert!(parse(bytes).is_err());
        }
        let notification = Notification::new(
            "line\ncarriage\r",
            Some(Params::Array(vec![Value::from("\n\r")])),
        );
        assert_eq!(notification.method(), Some("line\ncarriage\r"));
        assert!(notification.params().is_some());
        assert!(notification.to_value().is_ok());
        let escaped = Message::Notification(notification);
        let mut bytes = Vec::new();
        escaped.write_line(&mut bytes).unwrap();
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert!(!bytes.contains(&b'\r'));
        assert_eq!(decode_all(Messages::new, &bytes), (vec![Ok(escaped)], None));
        assert!(Error::new(INTERNAL_ERROR, "failure").data().is_none());
        let mut null = Error::new(INTERNAL_ERROR, "failure");
        set(&mut null.value, "data", Value::Null);
        assert_eq!(null.data(), Some(&Value::Null));
    }
    #[test]
    fn batch_limits_include_outer_container_and_exact_byte_boundary() {
        let mut batch = Batch {
            messages: vec![Message::Response(Response::success(
                Id::Null,
                Value::from(""),
            ))],
        };
        let overhead = batch.to_bytes().unwrap().len();
        if let Some(message) = batch.messages.first_mut() {
            set(
                message.value_mut(),
                "result",
                Value::from("x".repeat(json::MAX_SIZE - overhead)),
            );
        }
        let bytes = batch.to_bytes().unwrap();
        assert_eq!(bytes.len(), json::MAX_SIZE);
        assert_eq!(Batch::parse(&bytes).unwrap(), batch);
        assert_eq!(batch.to_value().unwrap(), Value::parse(&bytes).unwrap());
        if let Some(message) = batch.messages.first_mut() {
            set(
                message.value_mut(),
                "result",
                Value::from("x".repeat(json::MAX_SIZE - overhead + 1)),
            );
        }
        contract::check_wire_value(&batch);
        assert!(batch.to_bytes().is_err());

        let many = Message::Response(Response::success(
            Id::Null,
            Value::Array(vec![Value::Null; 60_000]),
        ));
        assert!(many.to_bytes().is_ok());
        let error = Batch {
            messages: vec![many.clone(), many],
        }
        .to_value()
        .unwrap_err();
        assert!(matches!(
            error.kind,
            ErrorKind::Limit(json::Error {
                kind: json::ErrorKind::TooManyElements,
                ..
            })
        ));
        let mut deep = Value::Null;
        for _ in 0..json::MAX_DEPTH - 1 {
            deep = Value::Array(vec![deep]);
        }
        let message = Message::Response(Response::success(Id::Null, deep));
        assert!(message.to_bytes().is_ok());
        assert!(
            Batch {
                messages: vec![message]
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn constructed_invalid_envelopes_never_write() {
        for text in [
            r#"{"jsonrpc":"2.0","id":null}"#,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":0.1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":0,"message":false}}"#,
            r#"{"jsonrpc":"2.0","id":null,"result":1,"id":2}"#,
        ] {
            let message = Message::Response(Response { value: value(text) });
            contract::check_wire_value(&message);
            let mut out = vec![42];
            assert!(message.write_line(&mut out).is_err());
            assert_eq!(out, [42]);
        }
        let invalid = Message::Request(Request {
            value: value(r#"{"jsonrpc":"2.0","method":"x","params":1,"id":null}"#),
        });
        assert!(invalid.to_bytes().is_err());
        contract::check_wire_value(&invalid);
        assert!(
            Params::Array(vec![Value::Null; json::MAX_ELEMENTS])
                .to_value()
                .is_err()
        );
        assert!(Id::String("x".repeat(json::MAX_SIZE)).to_value().is_err());
        let request = Request::new("x", None, Id::Null);
        assert_eq!(request.method(), Some("x"));
        assert_eq!(request.params(), None);
        assert!(matches!(
            Message::from_value(request.to_value().unwrap()).unwrap(),
            Message::Request(_)
        ));
    }
}
