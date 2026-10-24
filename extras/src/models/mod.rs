//! Model API sites with host-held credentials, streaming usage and run budgets.
//!
//! Mount [`Provider::host`] with `web::Site::handler` and a [`Model`] built by
//! [`anthropic`], [`openai`], [`openrouter`] or [`gemini`]. Host sockets stay
//! in [`web::forward`]. The OpenAI sites also serve the Responses WebSocket
//! that Codex opens first, with HTTP streaming to the upstream.
//!
//! Budget responses follow the vendors' documented status and error envelope:
//! [Anthropic spend limits](https://platform.claude.com/docs/en/api/rate-limits),
//! [OpenAI quota errors](https://developers.openai.com/api/docs/guides/error-codes)
//! as quoted in [Codex's tests](https://github.com/openai/codex/blob/main/codex-rs/codex-api/src/sse/responses.rs),
//! [OpenRouter credits](https://openrouter.ai/docs/api_reference/errors-and-debugging),
//! and [Gemini quotas](https://ai.google.dev/gemini-api/docs/troubleshooting).
//! These responses are constructed locally; no real quota is consumed to obtain them.
//! Provider rate-limit responses pass through with their original status and headers.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use fictionet::stdlib::web::{self, Body, httpd};
use fictionet::{Cx, Error};
use http::{Request, Response};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower_service::Service;

mod calls;
mod client;
pub use calls::{Call, CallObserver, CallPhase};
mod request;
mod transport;
pub use client::{Authenticated, DocumentType, Https, Incoming, Key, Post, Transport};
pub use transport::{UpstreamEvent, UpstreamObserver, UpstreamPhase};
pub mod oauth;
mod response;
pub use response::Completion;
mod responses;
#[cfg(test)]
mod responses_tests;
mod splice;
#[cfg(test)]
mod splice_tests;
pub mod tools;
pub use tools::Engine;
#[cfg(test)]
mod tests;
mod websocket;
#[cfg(test)]
mod websocket_tests;

/// The wire protocol and destination of a model API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic Messages.
    Anthropic,
    /// OpenAI Responses and Chat Completions.
    OpenAi,
    /// Codex inference with a ChatGPT subscription.
    ChatGpt,
    /// OpenRouter Messages, Responses and Chat Completions.
    OpenRouter,
    /// Gemini content generation.
    Gemini,
}
impl Provider {
    /// The provider's public hostname.
    pub fn host(self) -> &'static str {
        match self {
            Self::Anthropic => "api.anthropic.com",
            Self::OpenAi => "api.openai.com",
            Self::ChatGpt => "chatgpt.com",
            Self::OpenRouter => "openrouter.ai",
            Self::Gemini => "generativelanguage.googleapis.com",
        }
    }
    /// The host environment variable holding an API key.
    pub fn key_variable(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenAi | Self::ChatGpt => "OPENAI_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
            Self::Gemini => "GEMINI_API_KEY",
        }
    }
    fn header(self) -> &'static str {
        match self {
            Self::Anthropic => "x-api-key",
            Self::Gemini => "x-goog-api-key",
            _ => "authorization",
        }
    }
    fn allows(self, path: &str) -> bool {
        match self {
            Self::Anthropic => matches!(path, "/v1/messages" | "/v1/messages/count_tokens"),
            Self::OpenAi => matches!(path, "/v1/responses" | "/v1/chat/completions"),
            Self::ChatGpt => path == "/backend-api/codex/responses",
            Self::OpenRouter => matches!(
                path,
                "/api/v1/messages" | "/api/v1/responses" | "/api/v1/chat/completions"
            ),
            Self::Gemini => path.strip_prefix("/v1beta/models/").is_some_and(|rest| {
                rest.rsplit_once(':').is_some_and(|(model, action)| {
                    !model.is_empty()
                        && model
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                        && matches!(action, "generateContent" | "streamGenerateContent")
                })
            }),
        }
    }
    fn error(self, status: u16, kind: &str, message: &str) -> Response<Body> {
        let body = match self {
            Self::Anthropic => json!({"type":"error", "error":{"type":kind,"message":message}}),
            Self::OpenAi | Self::ChatGpt => {
                json!({"error":{"type":kind,"code":kind,"message":message,"param":null}})
            }
            Self::OpenRouter => json!({"error":{"code":status,"message":message}}),
            Self::Gemini => json!({"error":{"code":status,"status":kind,"message":message}}),
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("static response")
    }
    fn stop(self) -> Response<Body> {
        match self {
            Self::Anthropic => self.error(400, "invalid_request_error", "You have reached your specified workspace API usage limits. Please contact your workspace administrator to raise your usage limit."),
            Self::OpenAi | Self::ChatGpt => self.error(429, "insufficient_quota", "You exceeded your current quota, please check your plan and billing details. For more information on this error, read the docs: https://platform.openai.com/docs/guides/error-codes/api-errors."),
            Self::OpenRouter => self.error(402, "", "Insufficient credits. Add more credits and retry the request."),
            Self::Gemini => self.error(429, "RESOURCE_EXHAUSTED", "Quota exceeded for quota metric: Generate Content requests."),
        }
    }
}

/// A host-only credential. Formatting prints its name, never its value.
#[derive(Clone)]
pub struct Secret {
    name: &'static str,
    value: String,
}
impl Secret {
    /// Validates a nonempty printable HTTP credential.
    pub fn new(name: &'static str, value: String) -> fictionet::Result<Self> {
        if value.is_empty() || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(Error::msg(format!(
                "{name} must contain a nonempty printable credential"
            )));
        }
        Ok(Self { name, value })
    }
    /// Reads one named environment variable.
    pub fn from_env(name: &'static str) -> fictionet::Result<Self> {
        Self::new(
            name,
            std::env::var(name).map_err(|_| Error::msg(format!("{name} is not set")))?,
        )
    }
    /// Removes this credential from upstream diagnostics.
    pub fn redact(&self, text: &str) -> String {
        text.replace(&self.value, &self.to_string())
    }
}
impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.name)
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An API key paired with the credential installed in the guest.
#[derive(Clone)]
pub struct Credential {
    real: Secret,
    placeholder: String,
    oauth: Option<oauth::OAuth>,
    bearer: bool,
}
impl Credential {
    /// Mints a placeholder preserving the provider prefix and key length.
    pub fn api_key(cx: &Cx, real: Secret) -> Self {
        let prefix = [
            "sk-ant-api03-",
            "sk-ant-oat01-",
            "sk-ant-ort01-",
            "sk-or-v1-",
            "sk-proj-",
            "sk-",
            "AIza",
        ]
        .into_iter()
        .find(|p| real.value.starts_with(p) && real.value.len() > p.len())
        .unwrap_or("");
        let mut bytes = vec![0; real.value.len() - prefix.len()];
        cx.fill_random(&mut bytes);
        let alphabet: &[u8] = if prefix == "sk-or-v1-" {
            b"0123456789abcdef"
        } else {
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        };
        let mut placeholder = format!(
            "{prefix}{}",
            bytes
                .into_iter()
                .map(|b| alphabet[b as usize % alphabet.len()] as char)
                .collect::<String>()
        );
        if placeholder == real.value {
            let last = placeholder.pop().expect("nonempty credential");
            placeholder.push(if last == 'a' { 'b' } else { 'a' });
        }
        Self {
            real,
            placeholder,
            oauth: None,
            bearer: false,
        }
    }
    /// A long-lived Claude subscription token, kept on the host with no refresh.
    pub fn claude_token(cx: &Cx, real: Secret) -> fictionet::Result<Self> {
        if !real.value.starts_with("sk-ant-oat01-") {
            return Err(Error::msg("Claude OAuth token has an invalid prefix"));
        }
        let mut credential = Self::api_key(cx, real);
        credential.bearer = true;
        Ok(credential)
    }
    fn header(&self, provider: Provider) -> &'static str {
        if self.bearer {
            "authorization"
        } else {
            provider.header()
        }
    }
    /// The only credential value suitable for guest provisioning.
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }
    fn wire(&self, provider: Provider, real: bool) -> String {
        let value = if real {
            &self.real.value
        } else {
            &self.placeholder
        };
        if self.bearer || provider.header() == "authorization" {
            format!("Bearer {value}")
        } else {
            value.clone()
        }
    }
}

/// Limits checked before each upstream request, shared by cloned sites.
/// Token and dollar limits use completed usage; an admitted call can cross a limit.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Budget {
    /// Maximum upstream calls, including failures. Token counting is free.
    pub calls: Option<u64>,
    /// Maximum reported input tokens.
    pub input_tokens: Option<u64>,
    /// Maximum reported output tokens.
    pub output_tokens: Option<u64>,
    /// Maximum reported or priced cost in US dollars.
    pub usd: Option<f64>,
}
impl Budget {
    /// An unlimited budget.
    pub fn new() -> Self {
        Self::default()
    }
    /// Limits upstream calls.
    pub fn calls(mut self, limit: u64) -> Self {
        self.calls = Some(limit);
        self
    }
    /// Limits input tokens.
    pub fn input_tokens(mut self, limit: u64) -> Self {
        self.input_tokens = Some(limit);
        self
    }
    /// Limits output tokens.
    pub fn output_tokens(mut self, limit: u64) -> Self {
        self.output_tokens = Some(limit);
        self
    }
    /// Limits dollars. Invalid limits stop calls.
    pub fn usd(mut self, limit: f64) -> Self {
        self.usd = Some(limit);
        self
    }
}

/// Prices supplied by the world, in dollars per million tokens.
#[derive(Clone, Copy, Debug, Default)]
pub struct Prices {
    /// Uncached input price.
    pub input: f64,
    /// Output price.
    pub output: f64,
    /// Cached input reads.
    pub cache_read: f64,
    /// Cache creation.
    pub cache_write: f64,
    /// One-hour cache creation.
    pub cache_write_1h: f64,
}
impl Prices {
    /// Haiku pricing checked on October 20, 2026 against
    /// <https://platform.claude.com/docs/en/models/haiku-4-5/overview>.
    pub fn haiku_4_5() -> Self {
        Self {
            input: 1.0,
            output: 5.0,
            cache_read: 0.1,
            cache_write: 1.25,
            cache_write_1h: 2.0,
        }
    }
}
#[derive(Default)]
struct Ledger {
    budget: Budget,
    calls: u64,
    input: u64,
    output: u64,
    usd: f64,
    unknown: bool,
    unknown_cost: bool,
    paused: bool,
}
impl Ledger {
    fn exhausted(&self) -> Option<&'static str> {
        if self.paused {
            return Some("paused");
        }
        if self.budget.calls.is_some_and(|n| self.calls >= n) {
            return Some("calls");
        }
        if self
            .budget
            .input_tokens
            .is_some_and(|n| self.unknown || self.input >= n)
        {
            return Some("input_tokens");
        }
        if self
            .budget
            .output_tokens
            .is_some_and(|n| self.unknown || self.output >= n)
        {
            return Some("output_tokens");
        }
        if self
            .budget
            .usd
            .is_some_and(|n| !n.is_finite() || self.unknown || self.unknown_cost || self.usd >= n)
        {
            return Some("usd");
        }
        None
    }
}

/// A clonable provider site implementing tower's HTTP service.
#[derive(Clone)]
pub struct Model {
    cx: Cx,
    connection: fictionet::stdlib::services::serve::ConnInfo,
    provider: Provider,
    credential: Option<Credential>,
    forward: web::Forward,
    authority: String,
    upstream_provider: Provider,
    path_prefix: &'static str,
    ledger: Arc<Mutex<Ledger>>,
    prices: Option<(String, Prices)>,
    engine: Option<Arc<dyn Engine>>,
    cipher: Arc<splice::TokenCipher>,
    continued: Arc<Mutex<Continued>>,
    catalog: Option<Catalog>,
    upstream: Option<Arc<UpstreamObserver>>,
    calls: Option<Arc<CallObserver>>,
}

#[derive(Clone)]
enum Catalog {
    Forward,
    Answer { body: Bytes },
}

/// Searched Responses ids: the id a client saw, and the final upstream turn
/// that holds the whole response. The oldest go first past the bound.
#[derive(Default)]
struct Continued {
    finals: std::collections::HashMap<String, String>,
    order: std::collections::VecDeque<String>,
}
impl Continued {
    const LIMIT: usize = 4096;
    fn insert(&mut self, shown: String, last: String) {
        if self.finals.insert(shown.clone(), last).is_none() {
            self.order.push_back(shown);
        }
        while self.order.len() > Self::LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.finals.remove(&old);
            }
        }
    }
}
impl Model {
    /// Builds the model site for a dedicated OAuth authority.
    /// Mount the authority itself at its token hostname as well.
    pub async fn oauth(cx: &Cx, oauth: oauth::OAuth) -> fictionet::Result<Self> {
        let provider = match oauth.login() {
            oauth::Login::Claude => Provider::Anthropic,
            oauth::Login::Codex => Provider::ChatGpt,
        };
        let credential = Credential {
            real: oauth.secret().await?,
            placeholder: oauth.placeholder(),
            oauth: Some(oauth),
            bearer: true,
        };
        Self::at(
            cx,
            provider,
            credential,
            format!("https://{}", provider.host()).parse()?,
        )
    }
    /// Uses credentials supplied by the guest without replacing them.
    /// The world must terminate TLS and restrict the mounted provider hosts.
    pub fn guest(cx: &Cx, provider: Provider) -> fictionet::Result<Self> {
        Self::guest_at(
            cx,
            provider,
            format!("https://{}", provider.host()).parse()?,
        )
    }

    /// Forward to a supplied upstream with the guest credential unchanged.
    pub fn guest_at(cx: &Cx, provider: Provider, origin: http::Uri) -> fictionet::Result<Self> {
        let authority = origin
            .authority()
            .ok_or_else(|| Error::msg("model origin needs an authority"))?
            .to_string();
        Ok(Self::with_forward(
            cx,
            provider,
            None,
            web::forward(cx, origin, Arc::new(fictionet_host::Client::new()))?,
            authority,
        ))
    }

    /// Builds a provider using a supplied credential and origin.
    /// Custom origins let a world use its own gateway or a local upstream.
    pub fn at(
        cx: &Cx,
        provider: Provider,
        credential: Credential,
        origin: http::Uri,
    ) -> fictionet::Result<Self> {
        let authority = origin
            .authority()
            .ok_or_else(|| Error::msg("model origin needs an authority"))?
            .to_string();
        Ok(Self::with_forward(
            cx,
            provider,
            Some(credential),
            web::forward(
                cx,
                origin,
                std::sync::Arc::new(fictionet_host::Client::new()),
            )?,
            authority,
        ))
    }
    fn with_forward(
        cx: &Cx,
        provider: Provider,
        credential: Option<Credential>,
        forward: web::Forward,
        authority: String,
    ) -> Self {
        Self {
            cx: cx.clone(),
            connection: Default::default(),
            provider,
            credential,
            forward,
            authority,
            upstream_provider: provider,
            path_prefix: "",
            ledger: Arc::new(Mutex::new(Ledger::default())),
            prices: None,
            engine: None,
            cipher: Arc::new(splice::TokenCipher::new(cx)),
            continued: Arc::default(),
            catalog: None,
            upstream: None,
            calls: None,
        }
    }
    /// Observes requests that actually enter the upstream transport, including splice turns.
    pub fn observe_upstream(mut self, observer: Arc<UpstreamObserver>) -> Self {
        self.upstream = Some(observer);
        self
    }

    async fn forward_request(&self, request: Request<Body>) -> fictionet::Result<Response<Body>> {
        transport::forward(&self.cx, &self.forward, self.upstream.as_ref(), request).await
    }

    /// Serves Codex's API-key catalog from an origin or a supplied catalog.
    pub fn codex_catalog(
        &self,
        origin: http::Uri,
        answer: Option<(String, Bytes)>,
    ) -> fictionet::Result<Self> {
        if self.provider != Provider::OpenAi
            || self.credential.as_ref().is_none_or(|c| c.oauth.is_some())
        {
            return Err(Error::msg(
                "Codex API-key catalogs require an OpenAI model site",
            ));
        }
        if answer.is_none() && self.upstream_provider != Provider::OpenAi {
            return Err(Error::msg(
                "Codex catalogs require a supplied catalog when the upstream is not OpenAI",
            ));
        }
        let mut site = Self::at(
            &self.cx,
            Provider::ChatGpt,
            self.credential.clone().expect("API key catalog"),
            origin.clone(),
        )?;
        site.ledger = self.ledger.clone();
        site.catalog = Some(match answer {
            Some((_, body)) => Catalog::Answer { body },
            None => Catalog::Forward,
        });
        Ok(site)
    }

    fn anthropic_openrouter(mut self) -> Self {
        self.upstream_provider = Provider::OpenRouter;
        self.path_prefix = "/api";
        self
    }

    /// Installs a budget shared by all clones.
    pub fn budget(self, budget: Budget) -> Self {
        self.set_budget(budget);
        self
    }
    /// Answers server search and fetch tools with the world's own pages.
    pub fn search(mut self, engine: Arc<dyn Engine>) -> Self {
        self.engine = Some(engine);
        self
    }
    /// Changes limits without resetting already consumed usage.
    pub fn set_budget(&self, budget: Budget) {
        self.ledger.lock().unwrap().budget = budget;
    }
    /// Stops or resumes new calls without interrupting a response.
    pub fn pause(&self, paused: bool) {
        self.ledger.lock().unwrap().paused = paused;
    }
    /// Supplies token prices for this site's model.
    pub fn prices(mut self, model: impl Into<String>, prices: Prices) -> Self {
        self.prices = Some((model.into(), prices));
        self
    }
    /// Placeholder environment for a guest.
    pub fn guest_env(&self) -> Vec<(&'static str, String)> {
        let Some(credential) = &self.credential else {
            return Vec::new();
        };
        if credential.oauth.is_some() {
            return Vec::new();
        }
        vec![(
            if credential.bearer && self.provider == Provider::Anthropic {
                "CLAUDE_CODE_OAUTH_TOKEN"
            } else {
                self.provider.key_variable()
            },
            credential.placeholder.clone(),
        )]
    }
    /// Whether the request carries exactly the guest's credential.
    fn authorized(&self, headers: &http::HeaderMap) -> bool {
        let Some(credential) = &self.credential else {
            return self.guest_secret(headers).is_ok();
        };
        let expected = credential.wire(self.provider, false);
        let values = headers.get_all(credential.header(self.provider));
        values.iter().count() == 1
            && values.iter().next().is_some_and(|v| {
                if let Some(oauth) = &credential.oauth {
                    v.to_str()
                        .ok()
                        .and_then(|v| v.strip_prefix("Bearer "))
                        .is_some_and(|v| oauth.accepts(v))
                } else {
                    v.as_bytes() == expected.as_bytes()
                }
            })
    }
    fn guest_secret(&self, headers: &http::HeaderMap) -> fictionet::Result<Secret> {
        let name = if headers.contains_key("authorization") {
            "authorization"
        } else {
            self.provider.header()
        };
        let values = headers.get_all(name);
        if values.iter().count() != 1 {
            return Err(Error::msg("Missing or ambiguous model credential"));
        }
        let value = values
            .iter()
            .next()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::msg("Invalid model credential"))?;
        let value = if name == "authorization" {
            value
                .strip_prefix("Bearer ")
                .ok_or_else(|| Error::msg("Invalid bearer credential"))?
        } else {
            value
        };
        Secret::new("guest credential", value.to_owned())
    }
    fn unauthorized(&self) -> Response<Body> {
        self.provider.error(
            401,
            "authentication_error",
            "Invalid authentication credentials",
        )
    }
    /// The provider's stop response when the budget is spent. Otherwise
    /// `None`, and an admitted call is counted when `count` is set.
    fn admit(&self, _path: &str, count: bool) -> Option<Response<Body>> {
        let mut ledger = self.ledger.lock().unwrap();
        if ledger.exhausted().is_some() {
            return Some(
                self.credential
                    .as_ref()
                    .and_then(|c| c.oauth.as_ref())
                    .map_or_else(|| self.provider.stop(), oauth::OAuth::stop),
            );
        }
        if count {
            ledger.calls += 1;
        }
        None
    }
    /// [`Model::send`] behind a box, for the splices that call back into it.
    fn boxed(
        self,
        request: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = fictionet::Result<Response<Body>>> + Send>> {
        Box::pin(self.send(request))
    }
    async fn send(mut self, request: Request<Body>) -> fictionet::Result<Response<Body>> {
        let path = request.uri().path().to_owned();
        if self.catalog.is_some()
            && (request.method() != http::Method::GET || path != "/backend-api/codex/models")
        {
            return Ok(self.provider.error(404, "not_found_error", "Not found"));
        }

        if self.provider == Provider::Anthropic
            && request.method() == http::Method::GET
            && path == "/api/web/domain_info"
        {
            let domain =
                url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                    .find(|(key, _)| key == "domain")
                    .map(|(_, value)| value.into_owned());
            let allowed = domain.is_some_and(|host| {
                self.engine
                    .as_ref()
                    .is_some_and(|engine| engine.serves(&host))
            });
            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(json!({"can_fetch":allowed}).to_string()))?);
        }
        // Claude Code's startup check GETs this and requires a 200; its
        // background check sends HEAD.
        if self.provider == Provider::Anthropic
            && (request.method() == http::Method::HEAD || request.method() == http::Method::GET)
            && path == "/api/hello"
        {
            return Ok(Response::new(Body::empty()));
        }
        // Account reads and explicit credential setup at the API host. Worlds
        // running agents must close credential setup before mounting this site.
        if self.credential.is_none()
            && self.provider == Provider::Anthropic
            && matches!(
                (request.method(), path.as_str()),
                (
                    &http::Method::GET,
                    "/api/oauth/profile" | "/api/oauth/roles"
                ) | (&http::Method::POST, "/api/oauth/cli/create_api_key")
            )
        {
            if !self.authorized(request.headers()) {
                return Ok(self.unauthorized());
            }
            let mut request = request;
            request
                .headers_mut()
                .insert("host", self.authority.parse()?);
            return self.forward_request(request).await;
        }
        // With a ChatGPT login, Codex reads its account, usage and models first.
        let listing = self.provider == Provider::ChatGpt
            && request.method() == http::Method::GET
            && matches!(
                path.as_str(),
                "/backend-api/codex/models"
                    | "/backend-api/wham/accounts/check"
                    | "/backend-api/wham/usage"
            );
        let policy_limits = self.provider == Provider::Anthropic
            && request.method() == http::Method::GET
            && path == "/api/claude_code/policy_limits";
        if (request.method() != http::Method::POST && !listing && !policy_limits)
            || !(self.provider.allows(&path) || listing || policy_limits)
        {
            return Ok(self.provider.error(404, "not_found_error", "Not found"));
        }
        if !self.authorized(request.headers()) {
            return Ok(self.unauthorized());
        }
        if policy_limits && self.credential.is_some() {
            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(r#"{"restrictions":{}}"#))?);
        }
        if let Some(Catalog::Answer { body, .. }) = &self.catalog {
            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))?);
        }
        let (mut parts, body) = request.into_parts();
        let bytes = match http_body_util::Limited::new(body, 32 * 1024 * 1024)
            .collect()
            .await
        {
            Ok(body) => body.to_bytes(),
            Err(_) => {
                return Ok(self.provider.error(
                    413,
                    "request_too_large",
                    "Model request is too large or unreadable",
                ));
            }
        };
        let bytes = match parts
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
        {
            None | Some("identity") => bytes,
            Some("zstd") => {
                use std::io::Read;
                let decoded =
                    zstd::stream::read::Decoder::new(bytes.as_ref()).and_then(|decoder| {
                        let mut data = Vec::new();
                        decoder.take(32 * 1024 * 1024 + 1).read_to_end(&mut data)?;
                        Ok(data)
                    });
                match decoded {
                    Ok(data) if data.len() <= 32 * 1024 * 1024 => Bytes::from(data),
                    _ => {
                        return Ok(self.provider.error(
                            400,
                            "invalid_request_error",
                            "Invalid compressed request",
                        ));
                    }
                }
            }
            _ => {
                return Ok(self.provider.error(
                    415,
                    "invalid_request_error",
                    "Unsupported content encoding",
                ));
            }
        };
        parts.headers.remove("content-encoding");
        parts.headers.remove("content-length");
        let body: Value = match serde_json::from_slice(&bytes) {
            Ok(Value::Object(body)) => Value::Object(body),
            _ if (listing || policy_limits) && bytes.is_empty() => json!({}),
            _ => {
                return Ok(self.provider.error(
                    400,
                    "invalid_request_error",
                    "Invalid JSON request",
                ));
            }
        };
        if parts.method == http::Method::POST {
            parts.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
        }
        let Some(mut body) = admitted_request(self.provider, &path, &body, self.engine.is_some())
        else {
            return Ok(self.provider.error(
                400,
                "invalid_request_error",
                "Remote sources and unsupported server tools are not enabled for this workspace.",
            ));
        };
        if let request::Admitted::Responses(request) = &mut body
            && let Some(last) = request
                .previous_response_id
                .as_ref()
                .and_then(|id| self.continued.lock().unwrap().finals.get(id).cloned())
        {
            request.previous_response_id = Some(last);
        }
        let body = match body {
            request::Admitted::Messages(body)
                if self.engine.is_some()
                    && self.provider == Provider::Anthropic
                    && body.needs_web() =>
            {
                if path.ends_with("/count_tokens") {
                    return Box::pin(splice::count(self, parts, *body)).await;
                }
                return Box::pin(splice::serve(self, parts, *body)).await;
            }
            request::Admitted::Responses(body)
                if self.engine.is_some()
                    && matches!(self.provider, Provider::OpenAi | Provider::ChatGpt)
                    && body.needs_web() =>
            {
                return Box::pin(responses::serve(self, parts, *body)).await;
            }
            body => body,
        };
        let bytes = if parts.method == http::Method::POST {
            Bytes::from(serde_json::to_vec(&body)?)
        } else {
            bytes
        };
        let free = path.ends_with("/count_tokens") || listing;
        if !free && let Some(stop) = self.admit(&path, true) {
            return Ok(stop);
        }
        if let Some(credential) = &mut self.credential
            && let Some(oauth) = &credential.oauth
        {
            credential.real = oauth.secret().await?;
            if self.provider == Provider::ChatGpt {
                parts
                    .headers
                    .insert("chatgpt-account-id", oauth.account()?.parse()?);
            }
        }
        let secret = match &self.credential {
            Some(credential) => credential.real.clone(),
            None => self.guest_secret(&parts.headers)?,
        };
        let mut call = response::Call::new(&self, path, body.model(), free, &secret);
        if let Some(credential) = &self.credential {
            for name in [
                "authorization",
                "x-api-key",
                "x-goog-api-key",
                "cookie",
                "proxy-authorization",
            ] {
                parts.headers.remove(name);
            }
            parts.headers.insert(
                credential.header(self.upstream_provider),
                credential.wire(self.upstream_provider, true).parse()?,
            );
        }
        if !self.path_prefix.is_empty() {
            parts.uri = format!(
                "{}{}",
                self.path_prefix,
                parts
                    .uri
                    .path_and_query()
                    .map(|v| v.as_str())
                    .unwrap_or("/")
            )
            .parse()?;
        }
        parts.headers.insert("host", self.authority.parse()?);
        parts.headers.insert("accept-encoding", "identity".parse()?);
        let request = Request::from_parts(parts, Body::from(bytes));
        let result = self
            .forward_request(request)
            .await
            .map_err(|error| Error::msg(secret.redact(&error.to_string())))
            .and_then(|response| transport::sanitize(response, secret));
        match result {
            Ok(response) => {
                call.status = response.status().as_u16();
                let sse = response
                    .headers()
                    .get("content-type")
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
                Ok(response.map(|body| Body::new(response::Metered::new(body, call, sse))))
            }
            Err(error) => {
                call.stop = "transport_error".into();
                Err(error)
            }
        }
    }
}

/// The site's requests: a Responses WebSocket handshake gets its `101`
/// here, and every other request runs as deferred work.
impl httpd::Handler for Model {
    fn call(&self, request: Request<Body>, exchange: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let mut model = self.clone();
        model.connection = exchange.conn().clone();
        if self.catalog.is_none() && websocket::wanted(self.provider, &request) {
            return httpd::Reply::Now(websocket::accept(model, request));
        }
        httpd::Reply::Later(Box::new(move |_| Box::pin(model.send_observed(request))))
    }
}
/// An RFC 3339 UTC timestamp to the second, as the providers write them.
fn rfc3339(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}
/// Checks transport-bearing fields before any web tool can enter a splice.
#[cfg(test)]
fn safe_request(provider: Provider, path: &str, body: &Value, world: bool) -> bool {
    admitted_request(provider, path, body, world).is_some()
}

fn admitted_request(
    provider: Provider,
    path: &str,
    body: &Value,
    world: bool,
) -> Option<request::Admitted> {
    request::Admitted::decode(provider, path, body, world)
}

fn from_env(cx: &Cx, provider: Provider) -> fictionet::Result<Model> {
    let credential = Credential::api_key(cx, Secret::from_env(provider.key_variable())?);
    Model::at(
        cx,
        provider,
        credential,
        format!("https://{}", provider.host()).parse()?,
    )
}
/// Anthropic Messages using `ANTHROPIC_API_KEY`.
pub fn anthropic(cx: &Cx) -> fictionet::Result<Model> {
    from_env(cx, Provider::Anthropic)
}
/// OpenAI using `OPENAI_API_KEY`.
pub fn openai(cx: &Cx) -> fictionet::Result<Model> {
    from_env(cx, Provider::OpenAi)
}
/// OpenRouter using `OPENROUTER_API_KEY`.
pub fn openrouter(cx: &Cx) -> fictionet::Result<Model> {
    from_env(cx, Provider::OpenRouter)
}
/// Anthropic Messages served through OpenRouter's compatible endpoint.
/// Reads only `OPENROUTER_API_KEY`; the guest uses an Anthropic placeholder.
pub fn anthropic_via_openrouter(cx: &Cx) -> fictionet::Result<Model> {
    let real = Secret::from_env("OPENROUTER_API_KEY")?;
    let mut credential = Credential::api_key(
        cx,
        Secret::new(
            "ANTHROPIC_API_KEY",
            format!("sk-ant-api03-{}", "a".repeat(96)),
        )?,
    );
    credential.real = real;
    let model = Model::at(
        cx,
        Provider::Anthropic,
        credential,
        "https://openrouter.ai".parse()?,
    )?;
    Ok(model.anthropic_openrouter())
}
/// Gemini using `GEMINI_API_KEY`.
pub fn gemini(cx: &Cx) -> fictionet::Result<Model> {
    from_env(cx, Provider::Gemini)
}

/// OpenAI Responses served through OpenRouter, using only `OPENROUTER_API_KEY`.
/// Use an OpenRouter model name in the guest's normal model settings.
pub fn openai_via_openrouter(cx: &Cx) -> fictionet::Result<Model> {
    let real = Secret::from_env("OPENROUTER_API_KEY")?;
    let mut credential = Credential::api_key(
        cx,
        Secret::new("OPENAI_API_KEY", format!("sk-proj-{}", "a".repeat(128)))?,
    );
    credential.real = real;
    let mut model = Model::at(
        cx,
        Provider::OpenAi,
        credential,
        "https://openrouter.ai".parse()?,
    )?;
    model.upstream_provider = Provider::OpenRouter;
    model.path_prefix = "/api";
    Ok(model)
}
