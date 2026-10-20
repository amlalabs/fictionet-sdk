use fictionet::stdlib::web::Body;
use http::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use tower_service::Service;

#[derive(Clone)]
pub struct Mirror<S> {
    pub upstream: S,
    pub closed: Arc<AtomicBool>,
}

impl<S> Service<Request<Body>> for Mirror<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = fictionet::Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = fictionet::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut service = self.clone();
        Box::pin(async move {
            if service.closed.load(Ordering::SeqCst) {
                return Ok(Response::builder()
                    .status(403)
                    .body(Body::from("Package mirror closed\n"))?);
            }
            std::future::poll_fn(|cx| service.upstream.poll_ready(cx)).await?;
            if service.closed.load(Ordering::SeqCst) {
                return Ok(Response::builder()
                    .status(403)
                    .body(Body::from("Package mirror closed\n"))?);
            }
            service.upstream.call(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[derive(Clone)]
    struct Upstream(Arc<AtomicUsize>);
    impl Service<Request<Body>> for Upstream {
        type Response = Response<Body>;
        type Error = fictionet::Error;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Request<Body>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(Response::new(Body::from("upstream"))))
        }
    }
    #[tokio::test]
    async fn closure_stops_forwarding_on_existing_clones() {
        let count = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let mut mirror = Mirror {
            upstream: Upstream(count.clone()),
            closed: closed.clone(),
        };
        let mut other = mirror.clone();
        assert_eq!(
            mirror
                .call(Request::new(Body::empty()))
                .await
                .unwrap()
                .status(),
            200
        );
        closed.store(true, Ordering::SeqCst);
        for service in [&mut mirror, &mut other] {
            assert_eq!(
                service
                    .call(Request::new(Body::empty()))
                    .await
                    .unwrap()
                    .status(),
                403
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
