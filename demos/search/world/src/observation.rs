//! Facts the Search world explicitly reports to its own page.

use crate::pages::{Meta, NewPages, Pages, Response};
pub use fictionet::stdlib::protocols::dns::rr::Name as HostName;
pub use fictionet_extras::models::UpstreamPhase as EgressPhase;
use http::{
    HeaderMap, Method, StatusCode,
    uri::{PathAndQuery, Scheme},
};
use serde::Serialize;
use std::net::IpAddr;
use tokio::sync::mpsc::Sender;

/// Pending facts, including one reserved failure notification.
pub const OBSERVATION_CAPACITY: usize = 256;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SearchObs {
    RunStarted {
        started_at_ms: u64,
    },
    Resolved {
        #[serde(serialize_with = "display")]
        name: HostName,
        address: Option<IpAddr>,
    },
    Request {
        #[serde(serialize_with = "display")]
        scheme: Scheme,
        #[serde(serialize_with = "display")]
        host: HostName,
        #[serde(serialize_with = "display")]
        method: Method,
        #[serde(serialize_with = "display")]
        path: PathAndQuery,
        #[serde(serialize_with = "crate::observation::status")]
        status: StatusCode,
        bytes: usize,
        content_type: String,
        source: PageSource,
        elapsed_ms: u64,
        #[serde(serialize_with = "crate::observation::headers")]
        headers: HeaderMap,
        #[serde(skip)]
        preview: Option<crate::pages::PageBody>,
    },
    Search {
        engine: Engine,
        query: String,
        results: Vec<Hit>,
    },
    ModelCall {
        call: u64,
        #[serde(serialize_with = "display")]
        host: HostName,
        #[serde(serialize_with = "display")]
        path: PathAndQuery,
        #[serde(serialize_with = "optional_status")]
        status: Option<StatusCode>,
        #[serde(serialize_with = "display")]
        method: Method,
        phase: CallPhase,
    },
    Tool {
        call: u64,
        tool: Tool,
        target: String,
        results: Vec<Hit>,
        error: Option<String>,
    },
    Signin {
        open: bool,
        exceptions: Vec<SigninException>,
    },
    Egress {
        attempt: u64,
        #[serde(serialize_with = "display")]
        host: EgressHost,
        method: String,
        path: String,
        purpose: EgressPurpose,
        phase: EgressPhase,
        status: Option<u16>,
    },
    PageRevision {
        target: WriterTarget,
        action: RevisionAction,
        reason: String,
    },
    ObservationFailed {
        reason: String,
    },
    NoRoute {
        from: IpAddr,
        to: IpAddr,
    },
}

/// The document a page-writer correction belongs to.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WriterTarget {
    Cast,
    Stylesheet { host: String },
    Search { query: String },
    Page { url: String },
}

/// How the world recovered from a disclosure before serving content.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionAction {
    Rejected,
    LocalRendering,
}

/// The reason a request entered the real network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPurpose {
    Model,
    #[serde(rename = "page writer")]
    PageWriter,
    Account,
    LiveSearch,
    LiveCapture,
}

/// A host transport destination can be a DNS name or an IP literal.
#[derive(Clone, Debug)]
pub struct EgressHost(url::Host);

impl EgressHost {
    pub fn to_ascii(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Display for EgressHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<HostName> for EgressHost {
    fn from(name: HostName) -> Self {
        Self(url::Host::Domain(name.to_ascii()))
    }
}

impl std::str::FromStr for EgressHost {
    type Err = url::ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        url::Host::parse(value).map(Self)
    }
}

/// Operational account endpoints; interactive setup and refresh stay host-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SigninException {
    #[serde(rename = "GET api.anthropic.com/api/oauth/profile and /api/oauth/roles")]
    ClaudeAccount,
    #[serde(
        rename = "GET chatgpt.com/backend-api/codex/models, /backend-api/wham/accounts/check and /backend-api/wham/usage"
    )]
    CodexAccount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallPhase {
    Connecting,
    Receiving,
    Streaming,
    Complete,
    Interrupted,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PageSource {
    Copy {
        #[serde(with = "time::serde::rfc3339::option")]
        captured: Option<time::OffsetDateTime>,
    },
    Written,
    Live,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Google,
    Bing,
    DuckDuckGo,
    YouTube,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    WebSearch,
    Fetch,
}
#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub url: String,
    pub title: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub at_ms: u64,
    pub fact: SearchObs,
}

pub(crate) struct RequestContext<'a> {
    pub started: std::time::Instant,
    pub scheme: &'a Scheme,
    pub host: &'a HostName,
    pub method: &'a Method,
    pub path: &'a PathAndQuery,
    pub source: PageSource,
    pub headers: HeaderMap,
}

impl Pages {
    /// Installs this world's concrete observation destination. No SDK observer is used.
    pub fn observe(&self, destination: Sender<Observation>) {
        *self.observation.lock().unwrap() = Some(destination);
        let destination = self.observation.clone();
        self.observe_live(std::sync::Arc::new(move |cx, event| {
            report(
                &destination,
                cx,
                SearchObs::Egress {
                    attempt: event.attempt,
                    host: event
                        .url
                        .host_str()
                        .expect("capture host")
                        .parse()
                        .expect("capture hostname"),
                    method: event.method.to_string(),
                    path: event.url.as_str().into(),
                    purpose: match event.purpose {
                        fictionet_extras::capture::Purpose::Search => EgressPurpose::LiveSearch,
                        fictionet_extras::capture::Purpose::Capture => EgressPurpose::LiveCapture,
                    },
                    phase: event.phase,
                    status: event.status.map(|status| status.as_u16()),
                },
            );
        }));
        let destination = self.observation.clone();
        self.observe_writer(std::sync::Arc::new(move |cx, provider, event| {
            report(
                &destination,
                cx,
                SearchObs::Egress {
                    attempt: event.attempt,
                    host: provider.host().parse().expect("provider hostname"),
                    method: event.method.to_string(),
                    path: event.path.path().into(),
                    purpose: EgressPurpose::PageWriter,
                    phase: event.phase,
                    status: event.status.map(|s| s.as_u16()),
                },
            );
        }));
    }
    pub fn report(&self, cx: &fictionet::Cx, fact: SearchObs) {
        report(&self.observation, cx, fact);
    }

    pub fn source(&self) -> PageSource {
        match self.new_pages() {
            NewPages::Copied => PageSource::Copy { captured: None },
            NewPages::LiveSearch => PageSource::Live,
            _ => PageSource::Written,
        }
    }
    pub(crate) fn report_response(
        &self,
        cx: &fictionet::Cx,
        request: RequestContext<'_>,
        response: &Response,
    ) {
        if self.observation.lock().unwrap().is_none() {
            return;
        }
        let RequestContext {
            started,
            scheme,
            host,
            method,
            path,
            mut source,
            headers,
        } = request;
        if let Meta::Search(list) = &response.meta {
            self.report(
                cx,
                SearchObs::Search {
                    engine: match list.engine {
                        fictionet_extras::search::Engine::Google => Engine::Google,
                        fictionet_extras::search::Engine::Bing => Engine::Bing,
                        fictionet_extras::search::Engine::DuckDuckGo => Engine::DuckDuckGo,
                        fictionet_extras::search::Engine::YouTube => Engine::YouTube,
                    },
                    query: list.search.clone(),
                    results: list
                        .listed
                        .iter()
                        .map(|(url, title, _)| Hit {
                            url: url.clone(),
                            title: title.clone(),
                        })
                        .collect(),
                },
            );
        }
        if let PageSource::Copy { captured } = &mut source {
            *captured = self
                .capture_date(&format!(
                    "{scheme}://{}{path}",
                    host.to_ascii().trim_end_matches('.')
                ))
                .and_then(|date| {
                    time::OffsetDateTime::parse(
                        &date,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .ok()
                });
        }
        // Copied bytes retain their capture provenance; they are not called written pages.
        let preview = if response.content_type.starts_with("text/") {
            response
                .stored_headers
                .as_ref()
                .and_then(|_| {
                    self.copied_body(format!(
                        "{scheme}://{}{path}",
                        host.to_ascii().trim_end_matches('.')
                    ))
                })
                .or_else(|| {
                    let decoded = response
                        .stored_headers
                        .as_ref()
                        .map(|headers| {
                            fictionet_extras::warc::Response {
                                status: http::StatusCode::from_u16(response.status)
                                    .expect("valid response status"),
                                headers: headers.clone(),
                                body: response.body.clone().into(),
                            }
                            .decoded()
                        })
                        .transpose()
                        .ok()?;
                    let bytes = decoded.as_deref().unwrap_or(&response.body);
                    Some(crate::pages::PageBody::from(std::sync::Arc::<str>::from(
                        String::from_utf8_lossy(bytes).as_ref(),
                    )))
                })
        } else {
            None
        };
        self.report(
            cx,
            SearchObs::Request {
                scheme: scheme.clone(),
                host: host.clone(),
                method: method.clone(),
                path: redact_path(path),
                status: StatusCode::from_u16(response.status).expect("valid response status"),
                bytes: response.body.len(),
                content_type: response.content_type.clone(),
                source,
                elapsed_ms: started.elapsed().as_millis() as u64,
                headers,
                preview,
            },
        );
    }
}

fn report(
    destination: &std::sync::Mutex<Option<Sender<Observation>>>,
    cx: &fictionet::Cx,
    mut fact: SearchObs,
) {
    let too_large = serde_json::to_vec(&fact).map_or(true, |bytes| bytes.len() > 256 * 1024);
    match &mut fact {
        SearchObs::Search { results, .. } | SearchObs::Tool { results, .. } => {
            for hit in results {
                hit.url = redact_url(&hit.url);
            }
        }
        SearchObs::Request { path, headers, .. } => {
            *path = redact_path(path);
            for (name, value) in headers {
                *value = match name.as_str() {
                    "user-agent" | "accept" | "accept-language" | "accept-encoding"
                    | "content-type" | "content-length" | "host" => value.clone(),
                    "referer" | "origin" | "location" | "content-location" => value
                        .to_str()
                        .ok()
                        .and_then(|v| redact_url(v).parse().ok())
                        .unwrap_or_else(|| http::HeaderValue::from_static("[redacted]")),
                    _ => http::HeaderValue::from_static("[redacted]"),
                };
            }
        }
        SearchObs::ModelCall { path, .. } => *path = redact_path(path),
        SearchObs::PageRevision {
            target: WriterTarget::Page { url },
            ..
        } => *url = redact_url(url),
        SearchObs::Egress { path, .. } => {
            *path = if path.starts_with("https://") || path.starts_with("http://") {
                redact_url(path)
            } else {
                path.parse()
                    .map(|p| redact_path(&p).to_string())
                    .unwrap_or_else(|_| "[redacted]".into())
            };
        }
        _ => {}
    }
    if let SearchObs::Tool {
        tool: Tool::Fetch,
        target,
        ..
    } = &mut fact
    {
        *target = redact_url(target);
    }
    let mut destination = destination.lock().unwrap();
    let Some(sender) = destination.as_ref() else {
        return;
    };
    let reason = if sender.capacity() <= 1 {
        Some("Observation queue exceeded its capacity")
    } else if too_large {
        Some("Observation exceeded its byte limit")
    } else {
        None
    };
    let failed = reason.is_some();
    let fact = reason.map_or(fact, |reason| SearchObs::ObservationFailed {
        reason: reason.into(),
    });
    let _ = sender.try_send(Observation {
        at_ms: cx.now().since_start().as_millis() as u64,
        fact,
    });
    if failed {
        *destination = None;
    }
}

/// Serializes a protocol value as its wire spelling for the page.
pub fn display<T: std::fmt::Display, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}
/// Serializes an HTTP status as its numeric code.
pub fn status<S: serde::Serializer>(value: &StatusCode, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u16(value.as_u16())
}
/// Serializes a response status that may not have arrived yet.
pub fn optional_status<S: serde::Serializer>(
    value: &Option<StatusCode>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.map(|status| status.as_u16()).serialize(serializer)
}
/// Serializes header names and losslessly preserves nontext header values.
pub fn headers<S: serde::Serializer>(value: &HeaderMap, serializer: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(value.len()))?;
    for (name, value) in value {
        sequence.serialize_element(&(name.as_str(), value.as_bytes()))?;
    }
    sequence.end()
}

fn sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "token",
        "secret",
        "password",
        "key",
        "session",
        "signature",
        "state",
        "code",
        "credential",
    ]
    .iter()
    .any(|key| name.contains(key))
}

fn redact_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        let path = value.split_once('#').map_or(value, |(path, _)| path);
        return if path.starts_with('/') {
            path.parse()
                .map(|path| redact_path(&path).to_string())
                .unwrap_or_else(|_| "[redacted]".into())
        } else {
            "[redacted]".into()
        };
    };
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    if url.query().is_some() {
        let path: PathAndQuery = url[url::Position::BeforePath..url::Position::AfterQuery]
            .parse()
            .expect("URL path");
        let path = redact_path(&path);
        url.set_query(path.query());
    }
    url.into()
}

/// Keeps the requested path while removing credential query values.
pub fn redact_path(path: &PathAndQuery) -> PathAndQuery {
    let Some(query) = path.query() else {
        return path.clone();
    };
    let mut redacted = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = if sensitive(&key) {
            "[redacted]".into()
        } else if let Ok(mut nested) = url::Url::parse(&value) {
            let _ = nested.set_username("");
            let _ = nested.set_password(None);
            nested.set_query(None);
            nested.set_fragment(None);
            nested.into()
        } else {
            value.into_owned()
        };
        redacted.append_pair(&key, &value);
    }
    format!("{}?{}", path.path(), redacted.finish())
        .parse()
        .expect("encoded query")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_ends_with_an_explicit_failure_and_stops_reporting() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(1), |cx| async move {
            let pages = Pages::new(crate::pages::Seed::builtin("web")?);
            let (sender, mut receiver) = tokio::sync::mpsc::channel(OBSERVATION_CAPACITY);
            pages.observe(sender);
            for _ in 0..OBSERVATION_CAPACITY + 20 {
                pages.report(&cx, SearchObs::Signin { open: false, exceptions: vec![] });
            }
            let mut rows = Vec::new();
            while let Ok(row) = receiver.try_recv() { rows.push(row); }
            assert_eq!(rows.len(), OBSERVATION_CAPACITY);
            assert!(matches!(&rows.last().unwrap().fact, SearchObs::ObservationFailed { reason } if reason.contains("capacity")));
            assert!(receiver.is_closed());
            Ok(())
        })).unwrap();
    }

    #[test]
    fn oversized_facts_fail_instead_of_being_truncated() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let pages = Pages::new(crate::pages::Seed::builtin("web")?);
                let (sender, mut receiver) = tokio::sync::mpsc::channel(OBSERVATION_CAPACITY);
                pages.observe(sender);
                pages.report(
                    &cx,
                    SearchObs::Tool {
                        call: 1,
                        tool: Tool::Fetch,
                        target: "x".repeat(256 * 1024),
                        results: vec![],
                        error: None,
                    },
                );
                assert!(matches!(
                    receiver.try_recv().unwrap().fact,
                    SearchObs::ObservationFailed { .. }
                ));
                assert!(receiver.is_closed());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn all_url_positions_remove_credentials_and_fragments() {
        let url = "https://user:private-password@example.org/path?code=private-code&q=stars#access_token=private-token";
        let redacted = redact_url(url);
        assert!(!redacted.contains("private"));
        assert!(redacted.contains("q=stars"));
        assert!(!redacted.contains('#'));
        let path = redact_path(&"/callback?next=https%3A%2F%2Fexample.org%2F%3Ftoken%3Dprivate-value%23private-fragment".parse().unwrap());
        assert!(!path.as_str().contains("private"));
        assert!(!redact_url("/callback?code=private-code#private-fragment").contains("private"));
    }

    #[test]
    fn tool_and_search_urls_are_scrubbed_before_entering_the_record() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(10), |cx| async move {
            let pages = Pages::new(crate::pages::Seed::builtin("web")?);
            let (sender, mut receiver) = tokio::sync::mpsc::channel(OBSERVATION_CAPACITY);
            pages.observe(sender);
            let url = "https://user:private-password@example.org/page?code=private-code&q=stars#access_token=private-fragment";
            pages.report(&cx, SearchObs::Search { engine: Engine::Google, query: "stars".into(), results: vec![Hit { url: url.into(), title: "Stars".into() }] });
            pages.report(&cx, SearchObs::Tool { call: 1, tool: Tool::Fetch, target: url.into(), results: vec![Hit { url: url.into(), title: "Stars".into() }], error: None });
            pages.report(&cx, SearchObs::PageRevision { target: WriterTarget::Page { url: url.into() }, action: RevisionAction::Rejected, reason: "page provenance".into() });
            let rows = [receiver.try_recv().unwrap(), receiver.try_recv().unwrap(), receiver.try_recv().unwrap()];
            let recorded = serde_json::to_string(&rows)?;
            assert!(!recorded.contains("private"));
            assert!(recorded.contains("q=stars"));
            assert!(recorded.contains("Stars"));
            Ok(())
        })).unwrap();
    }

    #[test]
    fn copied_request_timing_uses_the_request_lifetime() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(3),
            |cx| async move {
                let pages = Pages::new(crate::pages::Seed::builtin("web")?);
                let (sender, mut receiver) = tokio::sync::mpsc::channel(OBSERVATION_CAPACITY);
                pages.observe(sender);
                let response = Response::new(200, "text/plain", "Page", vec![], Meta::Asset);
                pages.report_response(
                    &cx,
                    RequestContext {
                        started: std::time::Instant::now() - std::time::Duration::from_millis(1250),
                        scheme: &Scheme::HTTPS,
                        host: &"source.org".parse().unwrap(),
                        method: &Method::GET,
                        path: &"/page".parse().unwrap(),
                        source: PageSource::Copy { captured: None },
                        headers: HeaderMap::new(),
                    },
                    &response,
                );
                let request = std::iter::from_fn(|| receiver.try_recv().ok())
                    .find_map(|observation| match observation.fact {
                        SearchObs::Request { elapsed_ms, .. } => Some(elapsed_ms),
                        _ => None,
                    })
                    .unwrap();
                assert!(request >= 1250);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn request_credentials_are_redacted_before_recording_or_display() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let pages = Pages::new(crate::pages::Seed::builtin("web")?);
                let (sender, mut receiver) = tokio::sync::mpsc::channel(OBSERVATION_CAPACITY);
                pages.observe(sender);
                let mut headers = HeaderMap::new();
                for name in ["authorization", "cookie", "x-api-key"] {
                    headers.insert(name, "sensitive-value".parse().unwrap());
                }
                headers.insert("user-agent", "Firefox/1".parse().unwrap());
                headers.insert("referer", "https://user:password@example.org/callback?code=sensitive-value#access_token=sensitive-value".parse().unwrap());
                headers.insert("link", "<https://example.org/?code=sensitive-value>; rel=next".parse().unwrap());
                pages.report_response(
                    &cx,
                    RequestContext {
                        started: std::time::Instant::now(),
                        scheme: &Scheme::HTTPS,
                        host: &"sky.org".parse().unwrap(),
                        method: &Method::GET,
                        path: &"/black-hole?token=sensitive-value&q=black+hole"
                            .parse()
                            .unwrap(),
                        source: pages.source(),
                        headers,
                    },
                    &crate::pages::Response::new(
                        200,
                        "text/plain",
                        "A black hole",
                        vec![],
                        Meta::Missing,
                    ),
                );
                let row = receiver.try_recv().unwrap();
                let json = serde_json::to_string(&row).unwrap();
                assert!(!json.contains("sensitive-value"));
                let SearchObs::Request { path, headers, .. } = row.fact else {
                    panic!("request")
                };
                assert!(path.as_str().contains("q=black+hole"));
                assert_eq!(headers["user-agent"], "Firefox/1");
                assert_eq!(headers["authorization"], "[redacted]");
                assert_eq!(headers["referer"], "https://example.org/callback?code=%5Bredacted%5D");
                assert_eq!(headers["link"], "[redacted]");
                Ok(())
            },
        ))
        .unwrap();
    }
}
