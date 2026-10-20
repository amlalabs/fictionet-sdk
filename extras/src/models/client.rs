//! Host-side model transport for page generators.
use super::*;

/// A provider's API key: checked once, sent only in its request header.
#[derive(Clone)]
pub struct Key {
    variable: &'static str,
    value: String,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>", self.variable)
    }
}

impl Key {
    /// Checks a key from `variable`: it must be set and be printable ASCII,
    /// so an HTTP header can carry it. Errors never hold the key.
    pub fn new(variable: &'static str, value: Option<String>) -> Result<Self, String> {
        let value = value.unwrap_or_default();
        if value.is_empty() {
            return Err(format!("{variable} is not set"));
        }
        if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(format!(
                "{variable} holds characters an HTTP header cannot carry"
            ));
        }
        Ok(Self { variable, value })
    }
    /// Reads the provider's key from the environment.
    pub fn from_env(provider: Provider) -> Result<Self, String> {
        let variable = provider.key_variable();
        Self::new(variable, std::env::var(variable).ok())
    }
    /// The provider's credential header, for host-side requests only.
    pub fn header(&self, provider: Provider) -> (&'static str, String) {
        (
            provider.header(),
            if provider.header() == "authorization" {
                format!("Bearer {}", self.value)
            } else {
                self.value.clone()
            },
        )
    }
    /// `text` with the key replaced by its variable's name.
    pub fn redact(&self, text: &str) -> String {
        text.replace(&self.value, &format!("<{}>", self.variable))
    }
}

/// A POST in flight: the status and body, or why it failed to arrive.
pub type Post<'a> = Pin<Box<dyn Future<Output = Result<(u16, Vec<u8>), String>> + Send + 'a>>;

/// Sends a request body to the provider and returns the status and body.
pub trait Transport: Send + Sync {
    /// One POST with these headers. `Err` is a transport failure.
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Post<'a>;
}

/// The provider's API over HTTPS, through [`web::forward`].
pub struct Https {
    forward: web::Forward,
    path: &'static str,
    authority: String,
    provider: Provider,
}

impl Https {
    /// A client for the provider's API. Needs real I/O.
    pub fn new(fcx: &Cx, provider: Provider) -> fictionet::Result<Self> {
        Self::at(
            fcx,
            format!("https://{}", provider.host()).parse()?,
            match provider {
                Provider::Anthropic => "/v1/messages",
                Provider::OpenRouter => "/api/v1/chat/completions",
                Provider::OpenAi => "/v1/responses",
                Provider::ChatGpt => "/backend-api/codex/responses",
                Provider::Gemini => {
                    return Err(Error::msg("Gemini clients must name a model path"));
                }
            },
        )
    }
    /// A client that posts to `path` at `origin`, such as a test server.
    pub fn at(fcx: &Cx, origin: http::Uri, path: &'static str) -> fictionet::Result<Self> {
        Ok(Self {
            authority: origin
                .authority()
                .ok_or_else(|| Error::msg("Model origin needs an authority"))?
                .to_string(),
            provider: if path.starts_with("/api/") {
                Provider::OpenRouter
            } else if path.contains("messages") {
                Provider::Anthropic
            } else if path.starts_with("/backend-api/") {
                Provider::ChatGpt
            } else {
                Provider::OpenAi
            },
            forward: web::forward(fcx, origin)?,
            path,
        })
    }
}

impl Transport for Https {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Post<'a> {
        Box::pin(async move {
            let mut request = http::Request::post(self.path);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            let request = request
                .body(Body::from(Bytes::from(body)))
                .map_err(|e| e.to_string())?;
            let value = request
                .headers()
                .get(self.provider.header())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let value = if self.provider.header() == "authorization" {
                value.strip_prefix("Bearer ").unwrap_or("")
            } else {
                value
            };
            let credential = Credential::api_key(
                cx,
                Secret::new(self.provider.key_variable(), value.into())
                    .map_err(|e| e.to_string())?,
            );
            let mut request = request;
            request.headers_mut().insert(
                self.provider.header(),
                credential
                    .wire(self.provider, false)
                    .parse()
                    .map_err(|_| "Invalid placeholder".to_owned())?,
            );
            let mut site = Model::with_forward(
                cx,
                self.provider,
                credential,
                self.forward.clone(),
                self.authority.clone(),
            );
            let response = tower_service::Service::call(&mut site, request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok((status, body.to_vec()))
        })
    }
}
