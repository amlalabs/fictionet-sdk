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
    /// The credential value for a host-side API request header.
    pub fn value(&self) -> &str {
        &self.value
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
    path: String,
    authority: String,
    provider: Provider,
}

impl Https {
    /// A client for the provider's API. Needs real I/O.
    pub fn new(fcx: &Cx, provider: Provider) -> fictionet::Result<Self> {
        Self::with_provider(
            fcx,
            format!("https://{}", provider.host()).parse()?,
            provider,
            match provider {
                Provider::Anthropic => "/v1/messages",
                Provider::OpenRouter => "/api/v1/chat/completions",
                Provider::OpenAi => "/v1/responses",
                Provider::ChatGpt => "/backend-api/codex/responses",
                Provider::Gemini => {
                    return Err(Error::msg("Gemini clients must name a model path"));
                }
            }
            .into(),
        )
    }
    /// A client that posts to `path` at `origin`, such as a test server.
    /// Returns an error if no provider serves the path.
    pub fn at(fcx: &Cx, origin: http::Uri, path: impl Into<String>) -> fictionet::Result<Self> {
        let path = path.into();
        let provider = [
            Provider::Anthropic,
            Provider::OpenAi,
            Provider::ChatGpt,
            Provider::OpenRouter,
            Provider::Gemini,
        ]
        .into_iter()
        .find(|provider| provider.allows(&path))
        .ok_or_else(|| Error::msg(format!("No model provider serves path {path}")))?;
        Self::with_provider(fcx, origin, provider, path)
    }

    fn with_provider(
        fcx: &Cx,
        origin: http::Uri,
        provider: Provider,
        path: String,
    ) -> fictionet::Result<Self> {
        Ok(Self {
            authority: origin
                .authority()
                .ok_or_else(|| Error::msg("Model origin needs an authority"))?
                .to_string(),
            provider,
            forward: web::forward(
                fcx,
                origin,
                std::sync::Arc::new(fictionet_host::Client::new()),
            )?,
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
            let mut request = http::Request::post(self.path.as_str());
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
            let site = Model::with_forward(
                cx,
                self.provider,
                Some(credential),
                self.forward.clone(),
                self.authority.clone(),
            );
            let response = site.send(request).await.map_err(|e| e.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_gemini_posts_key_path_and_returns_response() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request
                    .starts_with("POST /v1beta/models/gemini-flash:generateContent HTTP/1.1\r\n")
            );
            assert!(request.contains("\r\nx-goog-api-key: AIza-test-private\r\n"));
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            let mut body = [0; 2];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"{}");
            socket.write_all(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"result\":\"ok\"}").unwrap();
        });
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(31)),
            |cx| async move {
                let client = Https::at(
                    &cx,
                    format!("http://{address}").parse()?,
                    format!("/v1beta/models/{}:generateContent", "gemini-flash"),
                )?;
                let key = Key::new("GEMINI_API_KEY", Some("AIza-test-private".into()))
                    .map_err(Error::msg)?;
                let (status, body) = client
                    .post(&cx, vec![key.header(Provider::Gemini)], b"{}".to_vec())
                    .await
                    .map_err(Error::msg)?;
                assert_eq!(status, 201);
                assert_eq!(body, br#"{"result":"ok"}"#);
                Ok(())
            },
        ))
        .unwrap();
        upstream.join().unwrap();
    }

    #[test]
    fn https_rejects_unserved_path() {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(32)),
            |cx| async move {
                let result = Https::at(&cx, "http://127.0.0.1:1".parse()?, "/v1/files");
                let error = result.err().expect("unserved path must fail");
                assert!(error.to_string().contains("/v1/files"));
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn https_selects_provider_for_each_endpoint() {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(33)),
            |cx| async move {
                for (provider, path) in [
                    (Provider::OpenRouter, "/api/v1/messages"),
                    (Provider::OpenRouter, "/api/v1/responses"),
                    (Provider::OpenRouter, "/api/v1/chat/completions"),
                    (Provider::Anthropic, "/v1/messages"),
                    (Provider::Anthropic, "/v1/messages/count_tokens"),
                    (Provider::OpenAi, "/v1/responses"),
                    (Provider::OpenAi, "/v1/chat/completions"),
                    (Provider::ChatGpt, "/backend-api/codex/responses"),
                    (
                        Provider::Gemini,
                        "/v1beta/models/gemini-flash:generateContent",
                    ),
                    (
                        Provider::Gemini,
                        "/v1beta/models/gemini-flash:streamGenerateContent",
                    ),
                ] {
                    let client = Https::at(&cx, "http://127.0.0.1:1".parse()?, path)?;
                    assert_eq!(client.provider, provider, "{path}");
                }
                Ok(())
            },
        ))
        .unwrap();
    }
}
