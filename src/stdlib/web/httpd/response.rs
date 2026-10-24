use std::time::SystemTime;

use http::header::{CONTENT_LENGTH, DATE};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};

use fictionet::Error;
use fictionet::stdlib::protocols::http1::{self, RequestHead};
use fictionet::time::Instant;

use super::{BadGateway, Body, text};

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

/// The response for a handler error: `502` for [`BadGateway`], else `500`.
pub(super) fn error_response(e: &Error) -> Response<Body> {
    if e.is::<BadGateway>() {
        text(StatusCode::BAD_GATEWAY, &format!("{e}\n"))
    } else {
        text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The site failed to answer.\n",
        )
    }
}

/// What a request asks of its response's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Asked {
    /// The body, when the status has one.
    Body,
    /// Only the head, as `HEAD` does: the length a `GET` would have, and
    /// no body.
    Head,
    /// A tunnel, as `CONNECT` does: a 2xx response has no framing and no
    /// body, since the bytes after its head are the tunnel's (RFC 9110
    /// section 9.3.6).
    Tunnel,
}

impl Asked {
    /// What a request with `method` asks.
    pub(super) fn of(method: &Method) -> Asked {
        if method == Method::HEAD {
            Asked::Head
        } else if method == Method::CONNECT {
            Asked::Tunnel
        } else {
            Asked::Body
        }
    }
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
        asked: Asked,
        date: Option<HeaderValue>,
    ) -> Self {
        let no_body = parts.status.is_informational()
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED
            || (asked == Asked::Tunnel && parts.status.is_success());
        let head_only = asked == Asked::Head;
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

