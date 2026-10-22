//! Facts the Search world explicitly reports to its own page.

use crate::pages::{Meta, NewPages, Pages, Response};
pub use fictionet::stdlib::protocols::dns::rr::Name as HostName;
use http::{HeaderMap, Method, StatusCode, uri::PathAndQuery};
use serde::Serialize;
use std::net::IpAddr;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SearchObs {
    Resolved {
        #[serde(serialize_with = "display")]
        name: HostName,
        address: Option<IpAddr>,
    },
    Request {
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
        preview: Option<std::sync::Arc<str>>,
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
    NoRoute {
        from: IpAddr,
        to: IpAddr,
    },
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
    }
    pub fn report(&self, cx: &fictionet::Cx, fact: SearchObs) {
        if let Some(destination) = &*self.observation.lock().unwrap() {
            let _ = destination.send(Observation {
                at_ms: cx.now().since_start().as_millis() as u64,
                fact,
            });
        }
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
                    "https://{}{path}",
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
            let decoded = response.stored_headers.as_ref().and_then(|headers| {
                fictionet_extras::warc::Response {
                    status: http::StatusCode::from_u16(response.status).ok()?,
                    headers: headers.clone(),
                    body: response.body.clone().into(),
                }
                .decoded()
                .ok()
            });
            let bytes = decoded.as_deref().unwrap_or(&response.body);
            let text = String::from_utf8_lossy(bytes);
            Some(std::sync::Arc::from(
                &text[..text.floor_char_boundary(text.len().min(64 << 10))],
            ))
        } else {
            None
        };
        self.report(
            cx,
            SearchObs::Request {
                host: host.clone(),
                method: method.clone(),
                path: path.clone(),
                status: StatusCode::from_u16(response.status).expect("valid response status"),
                bytes: response.body.len(),
                content_type: response.content_type.clone(),
                source,
                elapsed_ms: response.serve_ms.unwrap_or(0),
                headers,
                preview,
            },
        );
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
