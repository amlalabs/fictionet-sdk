use std::fmt::Write as _;
use std::sync::Arc;
use std::time::SystemTime;

use http::header::{CONTENT_LENGTH, DATE};
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Version};

use fictionet::Error;
use fictionet::events::{ConnInfo, Event, Fields, Level, float, opt};
use fictionet::stdlib::protocols::http1::{self, RequestHead};
use fictionet::stdlib::protocols::json::Value;
use fictionet::time::Instant;

use super::{BadGateway, Body, BodyClassifier, Received, request_host, text};

pub(super) fn answered(
    mut response: Response<Body>,
    answer: &'static str,
    observing: bool,
) -> Response<Body> {
    if observing {
        response
            .extensions_mut()
            .insert(Fields::new().with("answer", answer));
    }
    response
}

// ---------------------------------------------------------------------------
// The request event

/// One request's event, filled in as it goes.
#[derive(Default)]
pub(super) struct Tracker {
    enabled: bool,
    charge: usize,
    event: Option<Event>,
    observation: Option<Observation>,
    received: Option<Received>,
}

struct Observation {
    observer: Arc<dyn BodyClassifier>,
    state: http::Extensions,
    // Kept separately so service head facts win when the event is finished.
    fields: Fields,
    truncated: bool,
}

impl Observation {
    fn extend(&mut self, fields: Fields) {
        let event = Event::new("http", "request")
            .fields(std::mem::take(&mut self.fields))
            .fields(fields);
        self.truncated |= event.is_truncated();
        self.fields = event.fields;
    }
}

/// Owned HTTP head storage. `http` hides allocation capacities, so charge
/// string lengths and the header map's capacity, including shared values
/// in full. Extensions and third-party allocation overhead are excluded.
pub(super) fn request_held<B>(request: &Request<B>) -> usize {
    let uri = request.uri();
    let headers = request.headers();
    let slots = headers.capacity() + headers.len() - headers.keys_len();
    std::mem::size_of::<http::request::Parts>()
        + request.method().as_str().len()
        + uri.scheme_str().map_or(0, str::len)
        + uri.authority().map_or(0, |a| a.as_str().len())
        + uri.path_and_query().map_or(0, |p| p.as_str().len())
        + slots * std::mem::size_of::<(HeaderName, HeaderValue)>()
        + headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
}

pub(super) fn head_held(head: &RequestHead) -> usize {
    head.method.capacity()
        + head.target.capacity()
        + head.headers.capacity() * std::mem::size_of::<http1::Header>()
        + head
            .headers
            .iter()
            .map(|h| h.name.capacity() + h.value.capacity())
            .sum::<usize>()
}

fn version_name(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

impl Tracker {
    pub(super) fn tracking(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    // Reserve identical protocol credit whether or not event storage is enabled.
    // The charge is computed from borrowed headers, without building an event.
    pub(super) fn held(&self) -> usize {
        self.charge
    }

    pub(super) fn observing<B>(
        enabled: bool,
        request: &Request<B>,
        conn: &ConnInfo,
        observer: Option<Arc<dyn BodyClassifier>>,
    ) -> Tracker {
        if !enabled {
            return Self::tracking(enabled);
        }
        // Classify the head before constructing generic event metadata.
        let observation = observer.map(|observer| {
            let mut head = Request::new(());
            *head.method_mut() = request.method().clone();
            *head.uri_mut() = request.uri().clone();
            *head.version_mut() = request.version();
            *head.headers_mut() = request.headers().clone();
            let (head, ()) = head.into_parts();
            let mut state = http::Extensions::new();
            let fields = observer.head(&head, conn, &mut state).unwrap_or_default();
            let mut observation = Observation {
                observer,
                state,
                fields: Fields::new(),
                truncated: false,
            };
            observation.extend(fields);
            observation
        });
        Tracker {
            enabled,
            charge: 0,
            event: None,
            observation,
            received: None,
        }
    }

    pub(super) fn start<B>(&mut self, request: &Request<B>, conn: &ConnInfo, started: Instant) {
        self.charge = request_held(request) + std::mem::size_of::<Event>();
        if self.enabled {
            self.event = Self::new(request, conn, started).event;
        }
    }

    pub(super) fn body(&mut self, bytes: &[u8]) {
        // An observer sees no body bytes after its end, such as those of a
        // handed-off request, which hyper reads again.
        if self.received.is_none()
            && let Some(o) = &mut self.observation
            && let Some(fields) = o.observer.body(bytes, &mut o.state)
        {
            o.extend(fields);
        }
    }

    pub(super) fn received(&mut self, received: Received) {
        if self.received.is_none() {
            self.received = Some(received);
            if let Some(o) = &mut self.observation {
                if let Some(fields) = o.observer.end(received, &mut o.state) {
                    o.extend(fields);
                }
                o.state.clear();
            }
        }
    }

    pub(super) fn new<B>(request: &Request<B>, conn: &ConnInfo, started: Instant) -> Tracker {
        let host = request_host(request);
        let headers: Vec<Value> = request
            .headers()
            .iter()
            .map(|(n, v)| {
                Value::Array(vec![
                    n.as_str().into(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned().into(),
                ])
            })
            .collect();
        let uri = request.uri();
        // Room for every field, and for the status the summary gets later.
        let mut summary = String::with_capacity(
            request.method().as_str().len()
                + host.as_ref().map_or(1, String::len)
                + uri.path().len()
                + 5,
        );
        let _ = write!(
            summary,
            "{} {}{}",
            request.method(),
            host.as_deref().unwrap_or("-"),
            uri.path()
        );
        let event = Event::new("http", "request")
            .fields(Fields::with_capacity(16))
            .field("scheme", if conn.tls { "https" } else { "http" })
            .field("sni", opt(conn.sni.as_deref()))
            .field("host", opt(host.clone()))
            .field("method", request.method().as_str())
            .field("uri", uri.to_string())
            .field("path", uri.path())
            .field("query", opt(uri.query()))
            .field("version", version_name(request.version()))
            .field("headers", Value::Array(headers))
            .field("started", float(started.since_start().as_secs_f64()))
            .summary(summary);
        Tracker {
            enabled: true,
            charge: request_held(request) + std::mem::size_of::<Event>(),
            event: Some(event),
            observation: None,
            received: Some(Received::Complete),
        }
    }

    /// The finished event: observer fields, handler fields, then service facts.
    pub(super) fn finish(
        &mut self,
        extra: impl FnOnce() -> Option<Fields>,
        status: Option<StatusCode>,
        sent: u64,
        complete: bool,
    ) -> Option<Event> {
        self.charge = 0;
        self.received(Received::CutOff);
        let mut event = self.event.take()?;
        if self.observation.as_ref().is_some_and(|o| o.truncated) {
            event = event.truncated();
        }
        let mut fields = self
            .observation
            .take()
            .map_or_else(Fields::new, |o| o.fields);
        let mut extra = extra().unwrap_or_default();
        let answer = extra.remove("answer").unwrap_or_else(|| {
            if status.is_none() {
                "cancelled".into()
            } else {
                "handler".into()
            }
        });
        fields.extend(extra);
        let mut own = std::mem::take(&mut event.fields);
        own.set("received", self.received.expect("receipt ended").as_str());
        own.set("answer", answer);
        own.set("status", opt(status.map(|s| u32::from(s.as_u16()))));
        own.set("sent", sent);
        own.set("complete", complete);
        fields.extend(own);
        event = event.fields(fields);
        if let Some(s) = status {
            let _ = write!(event.summary, " {}", s.as_u16());
            if s.is_server_error() {
                event.level = Level::Notice;
            }
        }
        Some(event)
    }
}

/// The response for a handler error: `502` for [`BadGateway`], else `500`.
pub(super) fn error_response(e: &Error, observing: bool) -> Response<Body> {
    let mut response = if e.is::<BadGateway>() {
        text(StatusCode::BAD_GATEWAY, &format!("{e}\n"))
    } else {
        text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The site failed to answer.\n",
        )
    };
    if observing {
        response
            .extensions_mut()
            .insert(Fields::new().with("answer", "error"));
    }
    response
}

/// Logs an `http.error` event.
pub(super) fn error_event(
    conn: &ConnInfo,
    cause: &'static str,
    detail: impl std::fmt::Display,
) -> Event {
    Event::new("http", "error")
        .level(Level::Notice)
        .summary(format_args!("HTTP {cause} error: {detail}"))
        .field("local", opt(conn.local.map(|a| a.to_string())))
        .field("cause", cause)
        .display("detail", detail)
}

/// Shared response decisions, before either backend chooses wire framing.
pub(super) struct ResponsePolicy {
    pub(super) bodiless: bool,
    pub(super) len: Option<u64>,
    pub(super) date: Option<HeaderValue>,
}

impl ResponsePolicy {
    pub(super) fn new(
        parts: &http::response::Parts,
        len: Option<u64>,
        head_only: bool,
        date: Option<HeaderValue>,
    ) -> Self {
        let no_body = parts.status.is_informational()
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED;
        let len = if no_body {
            None
        } else if head_only {
            // A handler that drops the HEAD body can supply the GET length.
            parts
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                .or(len)
        } else {
            len
        };
        Self {
            bodiless: head_only || no_body,
            len,
            date: date.filter(|_| !parts.headers.contains_key(DATE)),
        }
    }
}

/// The `Date` header at `now` on the run's clock, in a world whose date at
/// the start of the run was `start`. `None` without a world date.
pub fn date_header(start: Option<SystemTime>, now: Instant) -> Option<HeaderValue> {
    let secs = start?
        .checked_add(now.since_start())?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    HeaderValue::from_str(&http_date(secs)).ok()
}

/// An IMF-fixdate (RFC 9110 section 5.6.7), such as
/// `Sun, 06 Nov 1994 08:49:37 GMT`, for `secs` since the Unix epoch.
///
/// ```
/// use fictionet::stdlib::web::httpd::http_date;
/// assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
/// assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
/// assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
/// assert_eq!(http_date(1_559_347_200), "Sat, 01 Jun 2019 00:00:00 GMT");
/// ```
pub fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

fictionet::cfg_tokio! {
use fictionet::Cx;
use fictionet::stdlib::services::serve::{Charge, PanicNote};

/// One request's event, sent when it is dropped.
pub(super) struct Track {
    pub(super) tracker: Tracker,
    pub(super) _charge: Option<Charge>,
    pub(super) fcx: Cx,
    pub(super) info: Arc<ConnInfo>,
    pub(super) extra: Option<Fields>,
    pub(super) status: Option<StatusCode>,
    pub(super) sent: u64,
    pub(super) complete: bool,
    /// Names the connection if the handler or its body panics.
    pub(super) _note: PanicNote,
}

impl Drop for Track {
    fn drop(&mut self) {
        if let Some(e) =
            self.tracker
                .finish(|| self.extra.take(), self.status, self.sent, self.complete)
        {
            self.fcx.emitter(&self.info).emit("http", "request", |_| e);
        }
    }
}
}
