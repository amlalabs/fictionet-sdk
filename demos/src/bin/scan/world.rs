//! The office, jump route, and temporary package mirror.
use fictionet::stdlib::{
    web::{self, Body},
    world::net::Net,
};
use fictionet::{Cx, Error};
use fictionet_demo::kit;
use http::{Request, Response, StatusCode};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use tower_service::Service;

pub const MIRROR: Ipv4Addr = Ipv4Addr::new(10, 0, 20, 10);

#[derive(Clone)]
pub struct Mirror<S> {
    upstream: S,
    closed: Arc<AtomicBool>,
}

impl<S> Service<Request<Body>> for Mirror<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.closed.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            self.upstream.poll_ready(cx)
        }
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if self.closed.load(Ordering::SeqCst) {
            Box::pin(async {
                Ok(web::httpd::text(
                    StatusCode::FORBIDDEN,
                    "Package setup is complete\n",
                ))
            })
        } else {
            Box::pin(self.upstream.call(request))
        }
    }
}

fn compose<S>(mirror: Mirror<S>) -> Net
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    scan_world::office()
        .route(kit::JUMP, kit::jump_prefix())
        .resolve(move |name| match name {
            "archive.ubuntu.com" | "security.ubuntu.com" => {
                Some(web::Site::new(mirror.clone()).at(MIRROR).into_host(name))
            }
            _ => None,
        })
}

pub fn start(
    cx: &Cx,
    mut world: kit::World,
    closed: Arc<AtomicBool>,
) -> fictionet::Result<scan_world::Ports> {
    let mirror = Mirror {
        upstream: world.mirror(cx)?,
        closed,
    };
    scan_world::start(cx, compose(mirror), world.into_attachments())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Clone)]
    struct Upstream(Arc<AtomicUsize>);
    impl Service<Request<Body>> for Upstream {
        type Response = Response<Body>;
        type Error = Error;
        type Future = std::future::Ready<Result<Self::Response, Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Request<Body>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(web::httpd::text(StatusCode::OK, "package")))
        }
    }

    #[test]
    fn closing_the_mirror_stops_forwarding() {
        fictionet::block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let closed = Arc::new(AtomicBool::new(false));
            let mut mirror = Mirror {
                upstream: Upstream(calls.clone()),
                closed: closed.clone(),
            };
            assert_eq!(
                mirror
                    .call(Request::new(Body::empty()))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
            closed.store(true, Ordering::SeqCst);
            assert_eq!(
                mirror
                    .call(Request::new(Body::empty()))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn composition_keeps_five_office_machines() {
        assert!(!scan_world::OFFICE.contains(MIRROR.into()));
        assert!(!scan_world::SCANNER_SUBNET.contains(MIRROR.into()));
        assert!(!scan_world::OFFICE.contains(kit::jump_prefix().addr));
        assert_eq!(kit::jump_prefix().len, 32);
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(42)),
            |cx| async move {
                let (_attacher, attachments) = fictionet::attachments();
                let net = compose(Mirror {
                    upstream: Upstream(Arc::new(AtomicUsize::new(0))),
                    closed: Arc::new(AtomicBool::new(false)),
                });
                let ports = scan_world::start(&cx, net, attachments)?;
                let machines = ports.snapshot().machines;
                assert_eq!(
                    machines
                        .iter()
                        .map(|m| m.addr.octets()[3])
                        .collect::<Vec<_>>(),
                    [10, 11, 12, 13, 50]
                );
                assert_eq!(
                    machines
                        .iter()
                        .filter(|m| m.kind == scan_world::MachineKind::Real)
                        .count(),
                    1
                );
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
