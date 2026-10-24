//! Host-side model transport for page generators.
use super::*;

/// A host credential, checked once and never exposed through formatting.
#[derive(Clone)]
pub struct Key {
    secret: Secret,
    authentication: Authentication,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Authentication {
    ApiKey,
    ClaudeToken,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.secret, f)
    }
}
impl Key {
    /// Checks a printable HTTP credential without including it in errors.
    pub fn new(variable: &'static str, value: Option<String>) -> Result<Self, String> {
        let value = value
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{variable} is not set"))?;
        Ok(Self {
            secret: Secret::new(variable, value)
                .map_err(|_| format!("{variable} holds characters an HTTP header cannot carry"))?,
            authentication: Authentication::ApiKey,
        })
    }
    /// Uses the host's long-lived Claude subscription token.
    pub fn claude_token(secret: Secret) -> Result<Self, String> {
        if !secret.value.starts_with("sk-ant-oat01-") {
            return Err("Claude OAuth token has an invalid prefix".into());
        }
        Ok(Self {
            secret,
            authentication: Authentication::ClaudeToken,
        })
    }
    /// Reads only the named provider variable.
    pub fn from_env(provider: Provider) -> Result<Self, String> {
        Self::new(
            provider.key_variable(),
            std::env::var(provider.key_variable()).ok(),
        )
    }
    /// The value for host-side authentication only.
    pub fn value(&self) -> &str {
        &self.secret.value
    }
    /// Whether the credential uses Claude's subscription protocol.
    pub fn is_claude_token(&self) -> bool {
        self.authentication == Authentication::ClaudeToken
    }
    /// The provider's credential header, for host-side requests only.
    pub fn header(&self, provider: Provider) -> (&'static str, String) {
        let header = if self.is_claude_token() {
            "authorization"
        } else {
            provider.header()
        };
        (
            header,
            if header == "authorization" {
                format!("Bearer {}", self.secret.value)
            } else {
                self.secret.value.clone()
            },
        )
    }
    /// Removes this credential from diagnostics.
    pub fn redact(&self, text: &str) -> String {
        self.secret.redact(text)
    }
}

/// A POST in flight: the status and body, or why it failed to arrive.
pub type Post<'a> = Pin<Box<dyn Future<Output = Result<(u16, Vec<u8>), String>> + Send + 'a>>;

/// A provider response whose body has not been collected.
pub type Incoming<'a> = Pin<Box<dyn Future<Output = Result<Response<Body>, String>> + Send + 'a>>;

/// Sends a request body to the provider and returns the status and body.
pub trait Transport: Send + Sync {
    /// Returns the incoming body so authentication can sanitize before collection.
    fn incoming<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Incoming<'a> {
        Box::pin(async move {
            let (status, body) = self.post(cx, headers, body).await?;
            Response::builder()
                .status(status)
                .body(Body::from(body))
                .map_err(|e| e.to_string())
        })
    }

    /// Installs credential-free observation at the actual upstream boundary.
    fn observe_upstream(&self, _observer: Arc<UpstreamObserver>) {}
    /// One POST with these headers. `Err` is a transport failure.
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Post<'a>;
}

/// An authenticated transport. Only scrubbed provider responses leave this client.
pub struct Authenticated {
    provider: Provider,
    key: Key,
    transport: Arc<dyn Transport>,
}
impl Authenticated {
    /// Owns authentication and response sanitization for this provider transport.
    pub fn new(provider: Provider, key: Key, transport: Arc<dyn Transport>) -> Self {
        Self {
            provider,
            key,
            transport,
        }
    }
    /// Installs upstream observation without exposing authentication.
    pub fn observe_upstream(&self, observer: Arc<UpstreamObserver>) {
        self.transport.observe_upstream(observer);
    }
    /// Whether the owned credential uses the Claude subscription protocol.
    pub fn is_claude_token(&self) -> bool {
        self.key.is_claude_token()
    }
    /// Removes the owned credential from assembled text and diagnostics.
    pub fn redact(&self, text: &str) -> String {
        self.key.redact(text)
    }
    /// Rejects a document whose decoded content would expose the owned credential.
    pub fn check_document(&self, content_type: &str, document: &str) -> Result<(), String> {
        use kuchiki::traits::TendrilSink;
        let exposed = |text: &str| self.redact(text) != text;
        fn json_exposes(value: &Value, exposed: &impl Fn(&str) -> bool) -> bool {
            match value {
                Value::String(text) => exposed(text),
                Value::Array(items) => items.iter().any(|v| json_exposes(v, exposed)),
                Value::Object(fields) => fields
                    .iter()
                    .any(|(k, v)| exposed(k) || json_exposes(v, exposed)),
                _ => false,
            }
        }
        let content_type = content_type.split(';').next().unwrap_or("");
        let unsafe_content =
            if content_type == "application/json" || content_type.ends_with("+json") {
                let value: Value =
                    serde_json::from_str(document).map_err(|_| "Invalid JSON document")?;
                json_exposes(&value, &exposed)
            } else if content_type == "text/html" {
                let dom = kuchiki::parse_html().one(document);
                exposed(&dom.text_contents())
                    || dom.descendants().any(|node| {
                        node.as_element().is_some_and(|element| {
                            exposed(element.name.local.as_ref())
                                || element.attributes.borrow().map.iter().any(
                                    |(name, attribute)| {
                                        exposed(name.local.as_ref()) || exposed(&attribute.value)
                                    },
                                )
                        }) || node
                            .as_comment()
                            .is_some_and(|comment| exposed(&comment.borrow()))
                    })
            } else {
                exposed(document)
            };
        if unsafe_content || exposed(document) {
            Err("Document contains a provider credential".into())
        } else {
            Ok(())
        }
    }
    /// Sends a provider request and sanitizes successful bodies and errors alike.
    pub async fn post(&self, cx: &Cx, body: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        let mut headers = vec![
            self.key.header(self.provider),
            ("content-type", "application/json".into()),
        ];
        if self.provider == Provider::Anthropic {
            headers.push(("anthropic-version", "2023-06-01".into()));
            if self.key.is_claude_token() {
                headers.push(("anthropic-beta", "oauth-2025-04-20".into()));
            }
        }
        let response = self
            .transport
            .incoming(cx, headers, body)
            .await
            .map_err(|e| self.key.redact(&e))?;
        let status = response.status().as_u16();
        let response = transport::sanitize(response, self.key.secret.clone())
            .map_err(|e| self.key.redact(&e.to_string()))?;
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| self.key.redact(&e.to_string()))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
}

/// The provider's API over HTTPS, through [`web::forward`].
#[derive(Clone)]
pub struct Https {
    client: Arc<fictionet_host::Client>,
    origin: http::Uri,
    path: String,
    authority: String,
    provider: Provider,
    observer: Arc<Mutex<Option<Arc<UpstreamObserver>>>>,
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
        _fcx: &Cx,
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
            observer: Arc::default(),
            client: Arc::new(fictionet_host::Client::new()),
            origin,
            path,
        })
    }
}

impl Transport for Https {
    fn observe_upstream(&self, observer: Arc<UpstreamObserver>) {
        *self.observer.lock().unwrap() = Some(observer);
    }
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Post<'a> {
        Box::pin(async move {
            let response = self.incoming(cx, headers, body).await?;
            let status = response.status().as_u16();
            let body =
                http_body_util::Limited::new(response.into_body(), transport::RESPONSE_LIMIT)
                    .collect()
                    .await
                    .map_err(|e| e.to_string())?
                    .to_bytes();
            Ok((status, body.to_vec()))
        })
    }

    fn incoming<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> Incoming<'a> {
        Box::pin(async move {
            let body: Value = serde_json::from_slice(&body).map_err(|_| "Invalid model request")?;
            let body = admitted_request(self.provider, &self.path, &body, false)
                .ok_or("Unsupported provider input")?;
            let mut request = http::Request::post(self.path.as_str());
            for (name, value) in headers {
                request = request.header(name, value);
            }
            let request = request
                .body(Body::from(
                    serde_json::to_vec(&body).map_err(|_| "Invalid provider request")?,
                ))
                .map_err(|e| e.to_string())?;
            let mut request = request;
            request.headers_mut().insert(
                http::header::HOST,
                self.authority
                    .parse()
                    .map_err(|_| "Invalid provider host")?,
            );
            let forward = web::forward(cx, self.origin.clone(), self.client.clone())
                .map_err(|e| e.to_string())?;
            let observer = self.observer.lock().unwrap().clone();
            let response = transport::forward(cx, &forward, observer.as_ref(), request)
                .await
                .map_err(|e| e.to_string())?;
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_publication_checks_decoded_content() {
        struct Unused;
        impl Transport for Unused {
            fn post<'a>(
                &'a self,
                _: &'a Cx,
                _: Vec<(&'static str, String)>,
                _: Vec<u8>,
            ) -> Post<'a> {
                unreachable!()
            }
        }
        let client = Authenticated::new(
            Provider::Anthropic,
            Key::new("provider key", Some("private-key".into())).unwrap(),
            Arc::new(Unused),
        );
        for (kind, body) in [
            ("text/html", "<p>private&#45;key</p>"),
            ("text/html", "<a title='private&#x2d;key'>read</a>"),
            ("text/html", "<p>private<span>-</span>key</p>"),
            ("text/html", "<!-- private-key -->"),
            ("application/json", r#"{"value":"private\u002dkey"}"#),
            ("application/json", r#"{"private\u002dkey":1}"#),
        ] {
            let error = client.check_document(kind, body).unwrap_err();
            assert!(!error.contains("private-key"));
        }
        client
            .check_document("text/html", "<p>Public documentation &amp; links.</p>")
            .unwrap();
        client
            .check_document("application/json", r#"{"value":"public"}"#)
            .unwrap();
    }

    #[test]
    fn authenticated_client_bounds_the_incoming_body_before_collection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Frames(Arc<AtomicUsize>);
        impl http_body::Body for Frames {
            type Data = Bytes;
            type Error = Error;
            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<fictionet::Result<http_body::Frame<Bytes>>>> {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(
                    (n < 64)
                        .then(|| Ok(http_body::Frame::data(Bytes::from(vec![b' '; 1024 * 1024])))),
                )
            }
        }
        struct Streaming(Arc<AtomicUsize>);
        impl Transport for Streaming {
            fn post<'a>(
                &'a self,
                _: &'a Cx,
                _: Vec<(&'static str, String)>,
                _: Vec<u8>,
            ) -> Post<'a> {
                panic!("buffered transport must not run")
            }
            fn incoming<'a>(
                &'a self,
                _: &'a Cx,
                _: Vec<(&'static str, String)>,
                _: Vec<u8>,
            ) -> Incoming<'a> {
                Box::pin(async move { Ok(Response::new(Body::new(Frames(self.0.clone())))) })
            }
        }
        let frames = Arc::new(AtomicUsize::new(0));
        let counted = frames.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(6),
            move |cx| async move {
                let client = Authenticated::new(
                    Provider::Anthropic,
                    Key::new("provider key", Some("private-key".into())).unwrap(),
                    Arc::new(Streaming(counted)),
                );
                assert!(
                    client
                        .post(&cx, vec![])
                        .await
                        .unwrap_err()
                        .contains("limit")
                );
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(frames.load(Ordering::SeqCst), 33);
    }

    #[tokio::test]
    async fn host_transport_forwards_only_the_admitted_value() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let work = tokio::spawn(async move {
            let router = axum::Router::new().route(
                "/v1/responses",
                axum::routing::post(|body: String| async move {
                    assert!(!body.contains("web_search_preview"));
                    assert!(!body.contains("remote.invalid"));
                    assert_eq!(body.matches("input").count(), 1);
                    let value: Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(value["input"], "local text");
                    axum::Json(json!({"output":[]}))
                }),
            );
            axum::serve(server, router).await.unwrap();
        });
        fictionet::run(fictionet::Seed::from_u64(8), |cx| async move {
            let client = Https::at(&cx, format!("http://{address}").parse()?, "/v1/responses")?;
            let body = br#"{"tools":[{"type":"web_search_preview"}],"input":[{"type":"input_image","image_url":"https://remote.invalid/img"}],"tools":[{"type":"function","name":"local","parameters":{}}],"input":"local text"}"#;
            assert_eq!(client.post(&cx, vec![], body.to_vec()).await.map_err(Error::msg)?.0, 200);
            Ok(())
        }).await.unwrap();
        work.abort();
    }

    #[test]
    fn authenticated_transport_scrubs_provider_and_transport_errors() {
        struct Echo;
        impl Transport for Echo {
            fn post<'a>(
                &'a self,
                _: &'a Cx,
                headers: Vec<(&'static str, String)>,
                body: Vec<u8>,
            ) -> Post<'a> {
                Box::pin(async move {
                    assert!(headers.contains(&("x-api-key", "private-key".into())));
                    assert!(headers.contains(&("anthropic-version", "2023-06-01".into())));
                    if body.is_empty() {
                        Err("connection failed with private-key".into())
                    } else {
                        Ok((401, br#"{"error":"private\u002dkey"}"#.to_vec()))
                    }
                })
            }
        }
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(8),
            |cx| async move {
                let client = Authenticated::new(
                    Provider::Anthropic,
                    Key::new("provider key", Some("private-key".into())).unwrap(),
                    Arc::new(Echo),
                );
                let error = client.post(&cx, vec![]).await.unwrap_err();
                assert_eq!(error, "connection failed with <provider key>");
                let (status, body) = client.post(&cx, vec![1]).await.unwrap();
                assert_eq!(status, 401);
                assert_eq!(
                    serde_json::from_slice::<Value>(&body)?["error"],
                    "<provider key>"
                );
                Ok(())
            },
        ))
        .unwrap();
    }

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
            fictionet::Seed::from_u64(31),
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
            fictionet::Seed::from_u64(32),
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
            fictionet::Seed::from_u64(33),
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
