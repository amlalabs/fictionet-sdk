//! Facts the Search world explicitly reports to its own page.

use crate::pages::{Edit, Meta, Pages, Response, Source};
pub use fictionet::stdlib::protocols::dns::rr::Name as HostName;
pub use fictionet_extras::models::UpstreamPhase as EgressPhase;
use http::{
    HeaderMap, Method, StatusCode,
    uri::{PathAndQuery, Scheme},
};
use serde::Serialize;
use std::net::IpAddr;
use tokio::sync::mpsc::UnboundedSender;

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
        headers: Box<Headers>,
        fetch: Fetch,
        /// The page that asked for this, as the client reported it.
        referrer: Option<String>,
        /// The document's own title, for pages.
        title: Option<String>,
        /// Why the world could not answer with the page: the site it read
        /// could not be reached.
        error: Option<String>,
        /// The scenario's edits to the real page; empty when it is served
        /// as the site sent it.
        edits: Vec<Edit>,
        #[serde(skip)]
        preview: Option<crate::pages::PageBody>,
    },
    /// The client closed its connection before the world answered, as a
    /// client with a deadline does.
    Abandoned {
        #[serde(serialize_with = "display")]
        scheme: Scheme,
        #[serde(serialize_with = "display")]
        host: HostName,
        #[serde(serialize_with = "display")]
        method: Method,
        #[serde(serialize_with = "display")]
        path: PathAndQuery,
        source: PageSource,
        elapsed_ms: u64,
        fetch: Fetch,
    },
    Search {
        engine: Engine,
        query: String,
        results: Vec<Hit>,
        /// The scenario's edits to the real results' titles and snippets.
        edits: Vec<Edit>,
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
        /// The scenario's edits to a search's results.
        edits: Vec<Edit>,
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
        /// The page a dependency was fetched for; the fetch belongs to it.
        page: Option<String>,
    },
    NoRoute {
        from: IpAddr,
        to: IpAddr,
    },
}

/// The reason a request entered the real network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPurpose {
    /// The guest's own model call, through the gateway.
    Model,
    /// The editor's model call, for a scenario's edits.
    Editor,
    Account,
    LiveSearch,
    LiveCapture,
    /// A package index or file the copied web lacks.
    Package,
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
    Live,
    /// A live page with the scenario's edits.
    Edited,
    /// A package index, file or source archive, whatever the page source:
    /// captured, or copied from its real host when the capture lacks it.
    Package,
}

impl PageSource {
    /// Whether the page came from the real web.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live | Self::Edited)
    }
}
/// How a request was made: a navigation to a document, or a page's own
/// subresource or script request (`Sec-Fetch-Dest` other than a document).
/// Clients that send no fetch metadata, like curl, navigate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fetch {
    Navigation,
    Subresource,
}

impl Fetch {
    pub(crate) fn of(headers: &HeaderMap) -> Self {
        match headers
            .get("sec-fetch-dest")
            .and_then(|value| value.to_str().ok())
        {
            None | Some("document") => Self::Navigation,
            Some(_) => Self::Subresource,
        }
    }
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
    pub fn observe(&self, destination: UnboundedSender<Observation>) {
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
                        fictionet_extras::capture::Purpose::Package => EgressPurpose::Package,
                    },
                    phase: event.phase,
                    status: event.status.map(|status| status.as_u16()),
                    page: event.page.as_ref().map(|page| redact_url(page.as_str())),
                },
            );
        }));
        let destination = self.observation.clone();
        self.observe_editor(std::sync::Arc::new(move |cx, provider, event| {
            report(
                &destination,
                cx,
                SearchObs::Egress {
                    attempt: event.attempt,
                    host: provider.host().parse().expect("provider hostname"),
                    method: event.method.to_string(),
                    path: event.path.path().into(),
                    purpose: EgressPurpose::Editor,
                    phase: event.phase,
                    status: event.status.map(|s| s.as_u16()),
                    page: None,
                },
            );
        }));
    }
    pub fn report(&self, cx: &fictionet::Cx, fact: SearchObs) {
        report(&self.observation, cx, fact);
    }

    /// The source that answers a page asked for now.
    pub fn page_source(&self) -> PageSource {
        match self.source() {
            Source::Copied => PageSource::Copy { captured: None },
            Source::Live => PageSource::Live,
            Source::Edited => PageSource::Edited,
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
                        .map(|(url, title)| Hit {
                            url: url.clone(),
                            title: title.clone(),
                        })
                        .collect(),
                    edits: list.edits.clone(),
                },
            );
        }
        // A page Edited mode left as the site sent it is a live page.
        let edits = response
            .edited
            .as_ref()
            .map(|edited| edited.edits.clone())
            .unwrap_or_default();
        if matches!(source, PageSource::Edited) && edits.is_empty() {
            source = PageSource::Live;
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
        // Copied bytes are read from the capture when shown; an edited page
        // shows its changes marked.
        let preview = if let Some(edited) = &response.edited {
            Some(crate::pages::PageBody::from(edited.marked.clone()))
        } else if response.content_type.starts_with("text/") {
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
                fetch: Fetch::of(&headers),
                title: match &response.meta {
                    Meta::Document { title } => Some(title.clone()),
                    _ => None,
                }
                .filter(|title| !title.trim().is_empty()),
                error: match &response.meta {
                    Meta::Error { error } => Some(error.clone()),
                    _ => None,
                },
                edits,
                referrer: headers
                    .get(http::header::REFERER)
                    .and_then(|value| value.to_str().ok())
                    .map(redact_url),
                headers: Box::new(Headers(headers)),
                preview,
            },
        );
    }
}

fn report(
    destination: &std::sync::Mutex<Option<UnboundedSender<Observation>>>,
    cx: &fictionet::Cx,
    mut fact: SearchObs,
) {
    match &mut fact {
        SearchObs::Search { results, .. } | SearchObs::Tool { results, .. } => {
            for hit in results {
                hit.url = redact_url(&hit.url);
            }
        }
        SearchObs::Request { path, headers, .. } => {
            *path = redact_path(path);
            for (name, value) in headers.0.iter_mut() {
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
        SearchObs::ModelCall { path, .. } | SearchObs::Abandoned { path, .. } => {
            *path = redact_path(path)
        }
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
    let destination = destination.lock().unwrap();
    let Some(sender) = destination.as_ref() else {
        return;
    };
    let _ = sender.send(Observation {
        at_ms: cx.now().since_start().as_millis() as u64,
        fact,
    });
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
/// A request's headers, serialized as [`headers`] does.
#[derive(Clone, Debug)]
pub struct Headers(pub HeaderMap);

impl Serialize for Headers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        headers(&self.0, serializer)
    }
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
