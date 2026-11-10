use crate::stdlib::web::Response;
use std::time::SystemTime;

use bytes::BytesMut;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};

use fictionet::Error;
use fictionet::time::Instant;

use super::{BadGateway, text};

/// Owned HTTP head storage. `http` hides allocation capacities, so charge
/// string lengths and the header map's capacity, including shared values
/// in full. Extensions and third-party allocation overhead are excluded.
pub(super) fn request_held<B>(request: &Request<B>) -> usize {
    let uri = request.uri();
    std::mem::size_of::<http::request::Parts>()
        + request.method().as_str().len()
        + uri.scheme_str().map_or(0, str::len)
        + uri.authority().map_or(0, |a| a.as_str().len())
        + uri.path_and_query().map_or(0, |p| p.as_str().len())
        + headers_held(request.headers())
}

/// What a header map holds beyond its inline value, counted as for
/// [`request_held`].
pub(super) fn headers_held(headers: &HeaderMap) -> usize {
    let slots = headers.capacity() + headers.len() - headers.keys_len();
    slots * std::mem::size_of::<(HeaderName, HeaderValue)>()
        + headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
}

/// Inline observation metadata; field storage remains charged to its backing.
pub(super) fn response_held(_parts: &Response) -> usize {
    std::mem::size_of::<crate::stdlib::web::ObservedResponse>()
}

/// The response for a handler error: `502` for [`BadGateway`], else `500`.
pub(super) fn error_response(e: &Error) -> Response {
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
    pub(super) fn of(method: &str) -> Asked {
        if method == "HEAD" {
            Asked::Head
        } else if method == "CONNECT" {
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
    /// `date` makes the `Date` header, if the handler set none.
    pub(super) fn new(
        parts: &Response,
        len: Option<u64>,
        asked: Asked,
        date: impl FnOnce() -> Option<HeaderValue>,
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
                .fields
                .get(b"content-length")
                .and_then(|v| std::str::from_utf8(v).ok()?.parse::<u64>().ok())
                .or(len)
        } else {
            len
        };
        Self {
            bodiless: head_only || no_body,
            len,
            date: if parts.fields.get(b"date").is_some() {
                None
            } else {
                date()
            },
        }
    }
}

/// The `Date` header at `now` on the run's clock, in a world whose date at
/// the start of the run was `start`. `None` without a world date.
pub fn date_header(start: Option<SystemTime>, now: Instant) -> Option<HeaderValue> {
    date_value(world_secs(start?, now)?)
}

/// The world's time at `now` on the run's clock, in seconds since the Unix
/// epoch.
fn world_secs(start: SystemTime, now: Instant) -> Option<u64> {
    Some(
        start
            .checked_add(now.since_start())?
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    )
}

/// The longest date [`http_date`] writes: one with a year of up to 20
/// digits, more than any `u64` of seconds reaches.
const DATE_MAX: usize = "Thu, 01 Jan ".len() + 20 + " 00:00:00 GMT".len();

/// The `Date` header for `secs`, written straight into the header's own
/// storage of [`DATE_MAX`] bytes.
fn date_value(secs: u64) -> Option<HeaderValue> {
    let mut bytes = BytesMut::with_capacity(DATE_MAX);
    write_date(&mut bytes, secs).ok()?;
    HeaderValue::from_maybe_shared(bytes.freeze()).ok()
}

/// One connection's `Date` headers: the world's date at the start of the
/// run, and the last header made, which serves every response in the same
/// second of the world's clock.
pub(super) struct Dates {
    start: Option<SystemTime>,
    last: Option<(u64, HeaderValue)>,
}

impl Dates {
    /// Dates from `start`, the world's date at the start of the run; none
    /// without it.
    pub(super) fn new(start: Option<SystemTime>) -> Dates {
        Dates { start, last: None }
    }

    /// The world's date at the start of the run.
    pub(super) fn start(&self) -> Option<SystemTime> {
        self.start
    }

    /// The `Date` header at `now` on the run's clock, as [`date_header`]
    /// makes it, made once per second.
    pub(super) fn at(&mut self, now: Instant) -> Option<HeaderValue> {
        let secs = world_secs(self.start?, now)?;
        if let Some((at, value)) = &self.last
            && *at == secs
        {
            return Some(value.clone());
        }
        let value = date_value(secs)?;
        self.last = Some((secs, value.clone()));
        Some(value)
    }

    /// The bytes the kept header may hold: [`DATE_MAX`] once there are
    /// dates, whether or not one was made yet.
    pub(super) fn held(&self) -> usize {
        if self.start.is_some() { DATE_MAX } else { 0 }
    }
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
    let mut date = String::with_capacity(DATE_MAX);
    write_date(&mut date, secs).expect("writing into a string succeeds");
    date
}

/// Writes [`http_date`]'s date for `secs` to `out`.
fn write_date(out: &mut impl std::fmt::Write, secs: u64) -> std::fmt::Result {
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
    write!(
        out,
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_handler_date_is_kept_without_making_one() {
        let mut response = Response::new(crate::stdlib::web::Body::empty());
        response.fields =
            crate::stdlib::web::Fields::new([("date", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
        let parts = response;
        let mut made = false;
        let policy = ResponsePolicy::new(&parts, Some(0), Asked::Body, || {
            made = true;
            date_header(Some(SystemTime::UNIX_EPOCH), Instant::ZERO)
        });
        assert!(!made);
        assert!(policy.date.is_none());
    }

    #[test]
    fn a_connection_makes_one_date_per_second() {
        let start = Some(SystemTime::UNIX_EPOCH + Duration::from_millis(784_111_777_400));
        let mut dates = Dates::new(start);
        let at = |ms| Instant::ZERO + Duration::from_millis(ms);
        let first = dates.at(at(0)).unwrap();
        let same_second = dates.at(at(500)).unwrap();
        let next_second = dates.at(at(600)).unwrap();
        assert_eq!(first, date_header(start, at(0)).unwrap());
        assert_eq!(
            first.as_bytes().as_ptr(),
            same_second.as_bytes().as_ptr(),
            "the second response reuses the first's header"
        );
        assert_eq!(next_second, date_header(start, at(600)).unwrap());
        assert_ne!(first, next_second);
    }

    #[test]
    fn the_kept_date_fits_what_is_charged() {
        assert!(http_date(u64::MAX).len() <= DATE_MAX);
        assert_eq!(Dates::new(None).held(), 0);
        let mut dates = Dates::new(Some(SystemTime::UNIX_EPOCH));
        assert!(dates.at(Instant::ZERO).unwrap().len() <= dates.held());
        assert!(Dates::new(None).at(Instant::ZERO).is_none());
    }
}
