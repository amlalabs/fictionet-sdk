//! Explicit allocating adapters for HTTP handlers.

use fictionet::Error;
use fictionet::stdlib::web::{
    Request,
    httpd::{Body, Exchange, Handler, Reply},
};
use fictionet::sync::Mutex;
use http::Response;
use std::future::poll_fn;

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
    S: tower_service::Service<http::Request<Body>, Response = Response<B>> + Clone + Send + 'static,
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
    S: tower_service::Service<http::Request<Body>, Response = Response<B>> + Clone + Send + 'static,
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
        let request = http::Request::from_parts(parts, request.body);
        let mut service = self.service.lock().clone();
        Reply::Later(Box::new(move |_fcx| {
            Box::pin(async move {
                poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .map_err(Into::into)?;
                let response = service.call(request).await.map_err(Into::into)?;
                Ok(fictionet::stdlib::web::Response::from_http(
                    response.map(Body::new),
                ))
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    impl tower_service::Service<http::Request<Body>> for Inspect {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<Body>) -> Self::Future {
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
                .body(Body::empty())
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
                let mut exchange = Exchange::new(cx.now(), &cx, &conn);
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
