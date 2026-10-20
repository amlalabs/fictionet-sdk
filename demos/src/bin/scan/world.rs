//! The office, jump route, and temporary package mirror.
use fictionet::stdlib::{
    web::{self, Body},
    world::net::Net,
};
use fictionet::{Cx, Error};
use fictionet_demo::kit::{self, mirror::Closable};
use http::{Request, Response};
use std::net::Ipv4Addr;
use std::sync::{Arc, atomic::AtomicBool};
use tower_service::Service;

pub const MIRROR: Ipv4Addr = Ipv4Addr::new(10, 0, 20, 10);

fn compose<S>(mirror: Closable<S>) -> Net
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
    let mirror = Closable::new(world.mirror(cx)?, closed);
    scan_world::start(cx, compose(mirror), world.into_attachments())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use std::task::{Context, Poll};

    #[derive(Clone)]
    struct Upstream;
    impl Service<Request<Body>> for Upstream {
        type Response = Response<Body>;
        type Error = Error;
        type Future = std::future::Ready<Result<Self::Response, Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Request<Body>) -> Self::Future {
            std::future::ready(Ok(web::httpd::text(StatusCode::OK, "package")))
        }
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
                let net = compose(Closable::new(Upstream, Arc::new(AtomicBool::new(false))));
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
