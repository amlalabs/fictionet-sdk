//! Explicit allocating adapters for HTTP handlers.

use fictionet::Error;
use fictionet::stdlib::web::{
    Request,
    httpd::{Body, Exchange, Handler, Reply},
};
use fictionet::sync::Mutex;
use http::Response;
use std::future::poll_fn;

use bytes::{Buf, Bytes};
use fictionet::{
    Chunk,
    stdlib::web::{Fields, httpd::BodyStream},
};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Explicit allocating conversion of a native body to the HTTP body interface.
pub struct HttpBody(pub Body);
impl http_body::Body for HttpBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        let body = &mut self.get_mut().0;
        match std::task::ready!(body.poll_next(cx)) {
            Some(result) => Poll::Ready(Some(
                result.map(|chunk| http_body::Frame::data(Bytes::from_owner(chunk))),
            )),
            None => Poll::Ready(body.take_trailers().map(|fields| {
                let mut trailers = http::HeaderMap::new();
                for (name, value) in fields.iter() {
                    trailers.append(
                        http::HeaderName::from_bytes(name).expect("validated name"),
                        http::HeaderValue::from_bytes(value).expect("validated value"),
                    );
                }
                Ok(http_body::Frame::trailers(trailers))
            })),
        }
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.0.remaining().map_or_else(
            http_body::SizeHint::default,
            http_body::SizeHint::with_exact,
        )
    }
}

/// Copies opaque HTTP body data into native chunks. This conversion allocates.
pub fn from_http<B>(body: B) -> Body
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    Body::Stream(Box::pin(Incoming {
        body: Box::pin(body),
        trailers: None,
        ended: false,
    }))
}
struct Incoming<B> {
    body: Pin<Box<B>>,
    trailers: Option<Fields>,
    ended: bool,
}
impl<B> BodyStream for Incoming<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Chunk, Error>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        match std::task::ready!(this.body.as_mut().poll_frame(cx)) {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(mut data) => Poll::Ready(Some(Ok(Chunk::unpaid(
                    data.copy_to_bytes(data.remaining()).to_vec(),
                )))),
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        this.trailers = Some(Fields::from(&fields));
                    }
                    this.ended = true;
                    Poll::Ready(None)
                }
            },
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => {
                this.ended = true;
                Poll::Ready(None)
            }
        }
    }
    fn remaining(&self) -> Option<u64> {
        self.body.size_hint().exact()
    }
    fn is_end_stream(&self) -> bool {
        self.trailers.is_none() && self.body.is_end_stream()
    }
    fn take_trailers(self: Pin<&mut Self>) -> Option<Fields> {
        self.get_mut().trailers.take()
    }
}

/// Runs a tower service as a [`Handler`]: see [`tower`].
pub struct Tower<S> {
    service: Mutex<S>,
}

/// Runs any tower service, such as an `axum::Router`, as a [`Handler`].
/// Each request gets its own clone of the service, as tower expects, and
/// runs as work of its connection. The response's body streams
/// to the client as it comes.
pub fn tower<S, B>(service: S) -> Tower<S>
where
    S: tower_service::Service<http::Request<HttpBody>, Response = Response<B>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error>,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    Tower {
        service: Mutex::new(service),
    }
}

impl<S, B> Handler for Tower<S>
where
    S: tower_service::Service<http::Request<HttpBody>, Response = Response<B>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error>,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    fn call(&self, request: Request, _ex: &mut Exchange<'_>) -> Reply {
        let Ok(mut parts) = request.head.to_http() else {
            let mut response = fictionet::stdlib::web::Response::new(Body::empty());
            response.status = http::StatusCode::BAD_REQUEST;
            return Reply::Now(response);
        };
        parts.extensions.insert(request.site);
        let request = http::Request::from_parts(parts, HttpBody(request.body));
        let mut service = self.service.lock().clone();
        Reply::Later(Box::new(move |_fcx| {
            Box::pin(async move {
                poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .map_err(Into::into)?;
                let response = service.call(request).await.map_err(Into::into)?;
                Ok(fictionet::stdlib::web::Response::from_http(
                    response.map(from_http),
                ))
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_conversion_preserves_data_and_duplicate_trailers() {
        use http_body::Body as _;
        struct Frames(std::collections::VecDeque<http_body::Frame<Bytes>>);
        impl http_body::Body for Frames {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                Poll::Ready(self.0.pop_front().map(Ok))
            }
        }
        let mut trailers = http::HeaderMap::new();
        trailers.append("x-end", http::HeaderValue::from_static("first"));
        trailers.append("x-end", http::HeaderValue::from_static("second"));
        let data = Bytes::from_static(b"body data");
        let mut body = HttpBody(from_http(Frames(
            [
                http_body::Frame::data(data.clone()),
                http_body::Frame::trailers(trailers.clone()),
            ]
            .into(),
        )));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("data frame");
        };
        assert_eq!(frame.into_data().unwrap(), data);
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("trailing fields");
        };
        assert_eq!(frame.into_trailers().unwrap(), trailers);
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
    }
    use fictionet::stdlib::network::ConnInfo;
    use fictionet::stdlib::protocols::http1::Version;
    use fictionet::stdlib::web::{Head, Site};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone)]
    struct Inspect {
        site: Site,
        called: Arc<AtomicBool>,
    }

    impl tower_service::Service<http::Request<HttpBody>> for Inspect {
        type Response = Response<HttpBody>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<HttpBody>) -> Self::Future {
            assert_eq!(request.extensions().get::<Site>(), Some(&self.site));
            assert!(request.extensions().get::<ConnInfo>().is_none());
            assert_eq!(request.uri().path(), "/kept");
            assert!(
                request
                    .headers()
                    .get_all("x-field")
                    .iter()
                    .map(|v| v.as_bytes())
                    .eq([b"first".as_slice(), b"second".as_slice()])
            );
            self.called.store(true, Ordering::Relaxed);
            let mut response = Response::builder()
                .header("x-reply", "first")
                .header("x-reply", "second")
                .body(HttpBody(Body::empty()))
                .unwrap();
            response
                .extensions_mut()
                .insert(fictionet::stdlib::web::Facts::new(self.site.clone()));
            response
                .extensions_mut()
                .insert(fictionet::stdlib::web::httpd::Answer::Redirect);
            std::future::ready(Ok(response))
        }
    }

    #[test]
    fn tower_conversion_preserves_fields_and_site_and_refuses_invalid_heads() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let conn = ConnInfo::default();
                let site = Site::connection(&conn);
                let called = Arc::new(AtomicBool::new(false));
                let handler = tower(Inspect {
                    site: site.clone(),
                    called: called.clone(),
                });
                let mut exchange = Exchange::new(
                    cx.now(),
                    &cx,
                    &conn,
                    fictionet::stdlib::web::httpd::Responses::new(&fictionet::Budget::unlimited()),
                );
                let invalid = Request {
                    head: Head::new("GET", "http://[", Version::Http11, [] as [(&str, &str); 0]),
                    body: Body::empty(),
                    site: site.clone(),
                };
                let Reply::Now(refused) = handler.call(invalid, &mut exchange) else {
                    panic!("invalid head must be refused before work starts");
                };
                assert_eq!(refused.status, http::StatusCode::BAD_REQUEST);
                assert!(!called.load(Ordering::Relaxed));
                let request = Request {
                    head: Head::new(
                        "GET",
                        "/kept",
                        Version::Http11,
                        [("X-Field", "first"), ("x-field", "second")],
                    ),
                    body: Body::empty(),
                    site: site.clone(),
                };
                let Reply::Later(work) = handler.call(request, &mut exchange) else {
                    panic!("tower service runs as work");
                };
                let response = work(cx.clone()).await?;
                assert!(response.status.is_success());
                assert!(
                    response
                        .fields
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case(b"x-reply"))
                        .map(|(_, value)| value)
                        .eq([b"first".as_slice(), b"second".as_slice()])
                );
                assert_eq!(
                    response.answer,
                    Some(fictionet::stdlib::web::httpd::Answer::Redirect)
                );
                assert_eq!(response.facts.as_ref().unwrap().get::<Site>(), Some(&site));
                assert!(called.load(Ordering::Relaxed));
                Ok(())
            },
        ))
        .unwrap();
    }
}
