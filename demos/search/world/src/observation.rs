//! Facts the Search world explicitly reports to its own page.

use crate::pages::{Meta, NewPages, Pages, Response};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SearchObs {
    Resolved {
        name: String,
        address: Option<IpAddr>,
    },
    Request {
        host: String,
        method: String,
        path: String,
        status: u16,
        bytes: usize,
        content_type: String,
        source: PageSource,
        elapsed_ms: u64,
        headers: Vec<(String, String)>,
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
        host: String,
        path: String,
        status: Option<u16>,
        method: String,
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
        to: SocketAddr,
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
    Copy { captured: Option<String> },
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
    WebSearch,
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
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub source: PageSource,
    pub headers: Vec<(String, String)>,
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
            *captured = self.capture_date(&format!("https://{host}{path}"));
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
                host: host.into(),
                method: method.into(),
                path: path.into(),
                status: response.status,
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

/// A Search-owned link reader for DNS answers and router refusals only.
/// It uses the same decoders as the network and keeps no packet history.
pub struct Link<I> {
    pub inner: I,
    pub cx: fictionet::Cx,
    pub pages: std::sync::Arc<Pages>,
}
impl<I: fictionet::Interface> fictionet::Interface for Link<I> {
    fn poll_recv(
        &mut self,
        cx: &fictionet::Cx,
        task: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<fictionet::Packet, fictionet::RecvError>> {
        self.inner.poll_recv(cx, task)
    }
    fn send(&mut self, packet: fictionet::Packet) {
        inspect(&self.cx, &self.pages, &packet.0);
        self.inner.send(packet);
    }
}
fn inspect(cx: &fictionet::Cx, pages: &Pages, packet: &[u8]) {
    use fictionet::stdlib::{
        network::{ip, udp},
        protocols::dns,
    };
    let Some(ip) = ip::Header::parse(packet) else {
        return;
    };
    if ip
        .fragment
        .as_ref()
        .is_some_and(|fragment| !fragment.is_atomic())
    {
        return;
    }
    let payload = ip.payload(packet);
    if ip.protocol == ip::protocol::UDP {
        let Some(datagram) = udp::Datagram::parse(payload) else {
            return;
        };
        if datagram.source_port() != 53 {
            return;
        }
        let Ok(message) = dns::op::Message::from_vec(datagram.payload()) else {
            return;
        };
        for question in &message.queries {
            let name = question
                .name()
                .to_string()
                .trim_end_matches('.')
                .to_string();
            let address = message.answers.iter().find_map(|record| match record.data {
                dns::rr::RData::A(address) => Some(IpAddr::V4(address.0)),
                dns::rr::RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            });
            pages.report(cx, SearchObs::Resolved { name, address });
        }
    } else if ip.protocol == ip::protocol::ICMP && payload.starts_with(&[3, 1]) {
        let Some(quoted) = payload.get(8..) else {
            return;
        };
        let Some(header) = ip::Header::parse_truncated(quoted) else {
            return;
        };
        let port = if [ip::protocol::TCP, ip::protocol::UDP].contains(&header.protocol) {
            header
                .payload(quoted)
                .get(2..4)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .unwrap_or(0)
        } else {
            0
        };
        pages.report(
            cx,
            SearchObs::NoRoute {
                to: SocketAddr::new(header.dst, port),
            },
        );
    }
}
