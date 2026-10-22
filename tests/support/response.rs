use fictionet::stdlib::{codec, protocols::http1};

/// Validates one whole response. Close-delimited bodies need explicit opt-in and EOF.
pub fn response(bytes: &[u8], method: &str, allow_close_delimited: bool) -> http1::Response {
    let response = http1::Response::parse_for(bytes, method).expect("complete HTTP response");
    if !allow_close_delimited {
        let mut decoder = http1::ResponseEvents::default();
        decoder.expect_method(method).expect("request method");
        let mut stream = codec::Stream::new(decoder);
        let mut done = false;
        // Without end(), only a self-delimited response can produce Done.
        let taken = codec::pump(&mut stream, bytes, |event| {
            done |= matches!(event, http1::Event::Done);
        })
        .expect("HTTP framing");
        assert_eq!(taken, bytes.len(), "unconsumed HTTP bytes");
        assert!(
            done,
            "close-delimited HTTP response requires explicit opt-in"
        );
    }
    response
}

fictionet::cfg_std! {
use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Reply};
use bytes::Bytes;
use http::{Request, Response};

/// A byte handler for protocol tests that do not need a router.
pub fn handler<F>(f: F) -> std::sync::Arc<impl Handler>
where
    F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
{
    struct BytesHandler<F>(F);
    impl<F> Handler for BytesHandler<F>
    where
        F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
    {
        fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
            let (parts, body) = request.into_parts();
            let Some(body) = body.bytes() else {
                return Reply::Now(http::Response::builder().status(400).body(Body::empty()).unwrap());
            };
            Reply::Now((self.0)(ex, Request::from_parts(parts, body)).map(Body::from))
        }
    }
    std::sync::Arc::new(BytesHandler(f))
}

/// Deferred byte replies for tests that need the connection's context.
pub fn async_handler<F, Fut>(f: F) -> std::sync::Arc<impl Handler>
where
    F: Fn(fictionet::Cx, Request<Bytes>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Bytes>> + Send + 'static,
{
    struct AsyncHandler<F>(std::sync::Arc<F>);
    impl<F, Fut> Handler for AsyncHandler<F>
    where
        F: Fn(fictionet::Cx, Request<Bytes>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<Bytes>> + Send + 'static,
    {
        fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let (parts, body) = request.into_parts();
            let Some(body) = body.bytes() else {
                return Reply::Now(http::Response::builder().status(400).body(Body::empty()).unwrap());
            };
            let f = self.0.clone();
            Reply::Later(Box::new(move |cx| Box::pin(async move {
                Ok(f(cx, Request::from_parts(parts, body)).await.map(Body::from))
            })))
        }
    }
    std::sync::Arc::new(AsyncHandler(std::sync::Arc::new(f)))
}
}

fictionet::cfg_std! {
/// A plain handler callback for tests of custom HTTP replies.
pub fn reply_handler<F>(f: F) -> std::sync::Arc<impl Handler>
where
    F: Fn(&mut Exchange<'_>, Request<Body>) -> Reply + Send + Sync + 'static,
{
    struct HandlerFn<F>(F);
    impl<F> Handler for HandlerFn<F>
    where
        F: Fn(&mut Exchange<'_>, Request<Body>) -> Reply + Send + Sync + 'static,
    {
        fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
            (self.0)(ex, request)
        }
    }
    std::sync::Arc::new(HandlerFn(f))
}
}

fictionet::cfg_std! {
/// A native WebSocket echo service for transport tests.
pub struct EchoSocket;

impl Handler for EchoSocket {
    fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
        use fictionet::stdlib::protocols::websocket as ws;
        let fields: Vec<_> = request.headers().iter().map(|(name, value)| (name.as_str(), value.to_str().unwrap())).collect();
        let headers = ws::check_request(&fields).unwrap().response_headers(None).unwrap();
        let mut response = Response::builder().status(101);
        for (name, value) in headers { response = response.header(name, value); }
        let mut response = response.body(Body::empty()).unwrap();
        response.extensions_mut().insert(fictionet::stdlib::web::httpd::UpgradeHandler::new(|cx, mut conn| async move {
            use fictionet::stdlib::codec::{Side, Stream, Wire};
            use fictionet::stdlib::network::ConnectionExt;
            let mut stream = Stream::new(ws::Messages::for_receiver(Side::Server));
            let mut buf = [0; 4096];
            loop {
                while let Some(message) = stream.next() {
                    let Ok(ws::Message::Text(text)) = message else { return };
                    let reply = ws::Message::Text(format!("echo: {text}")).to_frame(None).unwrap().to_bytes().unwrap();
                    if conn.write_all(&cx, &reply).await.is_err() { return; }
                }
                let Ok(n) = conn.read(&cx, &mut buf).await else { return };
                if n == 0 { return; }
                assert_eq!(stream.push(&buf[..n]), n);
            }
        }));
        Reply::Now(response)
    }
}
}
