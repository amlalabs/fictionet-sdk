use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use fictionet::stdlib::network::{ip, packet, tap};
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet_extras::hyper_io::Io;
use fictionet_test_support::sandbox::machine;
use fictionet_test_support::world::world;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};

struct Page;
impl Handler for Page {
    fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(Response::new(Body::from("unchanged application")))
    }
}

#[test]
fn an_external_ip_policy_carries_the_same_http_application() {
    world(Duration::from_secs(60), |cx| async move {
        let standard = Ipv4Addr::new(45, 33, 4, 80);
        let custom = Ipv4Addr::new(45, 33, 4, 81);
        let hops = std::num::NonZeroU8::new(37).unwrap();
        let replacement = packet::Factory::new(move |_| fictionet_custom_ip::HopLimit::new(hops));
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts([
                httpd::Server::new(Page)
                    .default_host()
                    .served_by(Host::new("standard").at(standard)),
                httpd::Server::new(Page)
                    .default_host()
                    .served_by(Host::new("custom").at(custom).ip_factory(replacement)),
            ])
            .start(&cx, attachments)?;
        let (send, capture) = std::sync::mpsc::sync_channel(256);
        let client = machine(
            &cx,
            tap(attacher.attach("client")?, send),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        for address in [standard, custom] {
            let conn = client
                .tcp
                .connect(&cx, SocketAddr::from((address, 80)))
                .await?;
            let (mut request, connection) = hyper::client::conn::http1::handshake(Io {
                fcx: cx.clone(),
                conn,
            })
            .await?;
            cx.spawn(move |_| async move { connection.await.map_err(Into::into) });
            let response = request
                .send_request(
                    Request::get("/")
                        .header("host", "example.test")
                        .body(Full::new(Bytes::new()))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), Version::HTTP_11);
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                "unchanged application"
            );
        }
        let packets: Vec<_> = capture.try_iter().map(|(_, packet)| packet).collect();
        let custom_packets: Vec<_> = packets
            .iter()
            .filter(|packet| {
                ip::Header::parse(&packet.0).is_some_and(|header| header.src == custom)
            })
            .collect();
        assert!(!custom_packets.is_empty());
        for packet in custom_packets {
            // World routes preserve the host's configured TTL.
            assert_eq!(packet.0[8], hops.get());
            assert_eq!(
                ip::checksum(&packet.0[..usize::from(packet.0[0] & 15) * 4]),
                0
            );
        }
        Ok(())
    });
}
