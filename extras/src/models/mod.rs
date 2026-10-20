//! Model API sites with host-held credentials, streaming usage and run budgets.
//!
//! Mount [`Provider::host`] with a [`Model`] built by [`anthropic`], [`openai`],
//! [`openrouter`] or [`gemini`]. Host sockets stay in [`web::forward`].
//!
//! Budget responses follow the vendors' documented status and error envelope:
//! [Anthropic spend limits](https://platform.claude.com/docs/en/api/rate-limits),
//! [OpenAI spend limits](https://developers.openai.com/api/docs/guides/error-codes),
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

mod response;
#[cfg(test)]
mod tests;

/// The wire protocol and destination of a model API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic Messages.
    Anthropic,
    /// OpenAI Responses and Chat Completions.
    OpenAi,
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
            Self::OpenRouter => "openrouter.ai",
            Self::Gemini => "generativelanguage.googleapis.com",
        }
    }
    /// The host environment variable holding an API key.
    pub fn key_variable(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenAi => "OPENAI_API_KEY",
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
            Self::OpenAi => {
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
            Self::OpenAi => self.error(429, "organization_spend_limit_exceeded", "You have reached your organization spend limit."),
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
#[derive(Clone, Debug)]
pub struct Credential {
    real: Secret,
    placeholder: String,
}
impl Credential {
    /// Mints a placeholder preserving the provider prefix and key length.
    pub fn api_key(cx: &Cx, real: Secret) -> Self {
        let prefix = ["sk-ant-api03-", "sk-or-v1-", "sk-proj-", "sk-", "AIza"]
            .into_iter()
            .find(|p| real.value.starts_with(p) && real.value.len() > p.len())
            .unwrap_or("");
        let mut bytes = vec![0; real.value.len() - prefix.len()];
        cx.fill_random(&mut bytes);
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
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
        Self { real, placeholder }
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
        if provider.header() == "authorization" {
            format!("Bearer {value}")
        } else {
            value.clone()
        }
    }
}

/// Limits checked before each upstream request, shared by cloned sites.
/// Token and dollar limits use completed usage; an admitted call can cross a limit.
#[derive(Clone, Copy, Debug, Default)]
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
}
#[derive(Default)]
struct Ledger {
    budget: Budget,
    calls: u64,
    input: u64,
    output: u64,
    usd: f64,
    unknown: bool,
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
            .is_some_and(|n| !n.is_finite() || self.unknown || self.usd >= n)
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
    provider: Provider,
    credential: Credential,
    forward: web::Forward,
    authority: String,
    upstream_provider: Provider,
    path_prefix: &'static str,
    ledger: Arc<Mutex<Ledger>>,
    prices: Option<(String, Prices)>,
}
impl Model {
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
        Ok(Self {
            cx: cx.clone(),
            provider,
            credential,
            forward: web::forward(cx, origin)?,
            authority,
            upstream_provider: provider,
            path_prefix: "",
            ledger: Arc::new(Mutex::new(Ledger::default())),
            prices: None,
        })
    }
    /// Installs a budget shared by all clones.
    pub fn budget(self, budget: Budget) -> Self {
        self.set_budget(budget);
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
        vec![(
            self.provider.key_variable(),
            self.credential.placeholder.clone(),
        )]
    }
    fn refused(&self, path: &str, reason: &'static str) {
        self.cx.emit("model", "refused", |e| {
            e.field("provider", self.provider.host())
                .field("path", path)
                .field("reason", reason)
        });
    }
    async fn send(self, request: Request<Body>) -> fictionet::Result<Response<Body>> {
        let path = request.uri().path().to_owned();
        if self.provider == Provider::Anthropic
            && request.method() == http::Method::HEAD
            && path == "/api/hello"
        {
            return Ok(Response::new(Body::empty()));
        }
        if request.method() != http::Method::POST || !self.provider.allows(&path) {
            self.refused(&path, "path");
            return Ok(self.provider.error(404, "not_found_error", "Not found"));
        }
        let expected = self.credential.wire(self.provider, false);
        let values = request.headers().get_all(self.provider.header());
        if values.iter().count() != 1
            || values
                .iter()
                .next()
                .is_none_or(|v| v.as_bytes() != expected.as_bytes())
        {
            self.refused(&path, "credential");
            return Ok(self.provider.error(
                401,
                "authentication_error",
                "Invalid authentication credentials",
            ));
        }
        let (mut parts, body) = request.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let body: Value = match serde_json::from_slice(&bytes) {
            Ok(Value::Object(body)) => Value::Object(body),
            _ => {
                return Ok(self.provider.error(
                    400,
                    "invalid_request_error",
                    "Invalid JSON request",
                ));
            }
        };
        if body
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| {
                tools.iter().any(|t| {
                    t.get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| !matches!(kind, "custom" | "function"))
                        || t.get("google_search").is_some()
                        || t.get("googleSearch").is_some()
                        || t.get("codeExecution").is_some()
                        || t.get("urlContext").is_some()
                })
            })
            || body.get("mcp_servers").is_some()
            || body.get("plugins").is_some()
            || body.get("web_search_options").is_some()
            || body["model"]
                .as_str()
                .is_some_and(|model| model.ends_with(":online") || model.contains("-search-"))
        {
            self.refused(&path, "tool");
            return Ok(self.provider.error(
                400,
                "invalid_request_error",
                "Server tools are not enabled for this workspace.",
            ));
        }
        let free = path.ends_with("/count_tokens");
        if !free {
            let mut ledger = self.ledger.lock().unwrap();
            if let Some(kind) = ledger.exhausted() {
                self.cx.emit("model", "budget", |e| {
                    e.field("provider", self.provider.host())
                        .field("kind", kind)
                });
                self.refused(&path, "budget");
                return Ok(self.provider.stop());
            }
            ledger.calls += 1;
        }
        let mut call = response::Call::new(&self, path, &body, bytes.len(), free);
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
            self.upstream_provider.header(),
            self.credential.wire(self.upstream_provider, true).parse()?,
        );
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
        let result = self.forward.clone().call(request).await;
        match result {
            Ok(mut response) => {
                call.status = response.status().as_u16();
                let sse = response
                    .headers()
                    .get("content-type")
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
                response.headers_mut().remove("content-length");
                for value in response.headers_mut().values_mut() {
                    if let Ok(text) = value.to_str() {
                        *value = self.credential.real.redact(text).parse()?;
                    }
                }
                Ok(response.map(|body| {
                    Body::new(response::Metered::new(
                        body,
                        call,
                        sse,
                        self.credential.real,
                    ))
                }))
            }
            Err(error) => {
                call.stop = "transport_error".into();
                Err(Error::msg(self.credential.real.redact(&error.to_string())))
            }
        }
    }
}
impl Service<Request<Body>> for Model {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = fictionet::Result<Response<Body>>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<fictionet::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        Box::pin(self.clone().send(request))
    }
}
impl httpd::Handler for Model {
    fn call(&self, request: Request<Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        httpd::tower(self.clone()).call(request, ex)
    }
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
    let mut model = Model::at(
        cx,
        Provider::Anthropic,
        credential,
        "https://openrouter.ai".parse()?,
    )?;
    model.upstream_provider = Provider::OpenRouter;
    model.path_prefix = "/api";
    Ok(model)
}
/// Gemini using `GEMINI_API_KEY`.
pub fn gemini(cx: &Cx) -> fictionet::Result<Model> {
    from_env(cx, Provider::Gemini)
}
