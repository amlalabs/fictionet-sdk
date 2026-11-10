//! A maintenance service and a silent TCP edge on unusual ports.
//!
//! Run with `cargo run -p fictionet-extras --example port_world -- /tmp/ports.sock`.
//! The socket carries Fictionet attachments; it is not a host TCP listener.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;

use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::web::httpd::{self, Exchange, Handler, Reply};
use fictionet::stdlib::world::net::{Arrival, Net, Pools, PortServer};
use fictionet::{Attachments, Cx};
use fictionet_extras::reverse_modbus::{Read, Reader};

const MAINTENANCE: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 10);
const EDGE: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 11);
const COLLECTOR: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 12);
const MAINTENANCE_V6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0, 0, 0, 0, 0, 0, 0x10);
const EDGE_V6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0, 0, 0, 0, 0, 0, 0x11);
const COLLECTOR_V6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0, 0, 0, 0, 0, 0, 0x12);

enum Event {
    Request(ConnInfo),
    Accepted(ConnInfo),
    Drained { conn: ConnInfo, received: usize },
    Registers(fictionet_extras::reverse_modbus::Observation),
}

type Observe = Arc<dyn Fn(Event) + Send + Sync>;

struct Maintenance(Observe);

impl Handler for Maintenance {
    fn call(&self, _: fictionet::stdlib::web::Request, exchange: &mut Exchange<'_>) -> Reply {
        (self.0)(Event::Request(exchange.conn().clone()));
        Reply::Now(httpd::text(
            exchange.responses(),
            http::StatusCode::OK,
            "South pumping station\nController online\nService contact: operations\n",
        ))
    }
}

struct SilentEdge(Observe);

impl PortServer for SilentEdge {
    fn serve_connection(
        &self,
        fcx: Cx,
        mut arrival: Arrival,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let observe = self.0.clone();
        Box::pin(async move {
            observe(Event::Accepted(arrival.info.clone()));
            let mut received = 0;
            let mut buffer = [0; 4096];
            loop {
                match arrival.conn.read(&fcx, &mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => received += n,
                    Err(_) => return,
                }
            }
            observe(Event::Drained {
                conn: arrival.info,
                received,
            });
            let _ = arrival.conn.shutdown(&fcx).await;
        })
    }
}

fn start(fcx: &Cx, attachments: Attachments, observe: Observe) -> fictionet::Result {
    let maintenance = httpd::Server::new(Maintenance(observe.clone())).default_host();
    let samples = observe.clone();
    let collector = Reader::new(
        1,
        Read::Input {
            address: 0,
            quantity: 2,
        },
        move |sample| {
            samples(Event::Registers(sample));
        },
    )?;
    Net::new(Pools::NONE)
        .subnet("fd00::/64".parse()?)
        .host("maintenance", |host| {
            host.at(MAINTENANCE)
                .at(MAINTENANCE_V6)
                .dns_name("maintenance.south.internal")
                .port_server(0, maintenance.clone())
                .port_server(8080, maintenance)
        })
        .host("edge", |host| {
            host.at(EDGE)
                .at(EDGE_V6)
                .dns_name("edge.south.internal")
                .port_server(0, SilentEdge(observe))
        })
        .host("collector", |host| {
            host.at(COLLECTOR)
                .at(COLLECTOR_V6)
                .dns_name("collector.south.internal")
                .port_server(0, collector)
        })
        .start(fcx, attachments)?;
    Ok(())
}

fn main() -> fictionet::Result {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| fictionet::Error::msg("usage: port_world <world socket>"))?;
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.into()))?;
    let observe: Observe = Arc::new(|event| match event {
        Event::Request(conn) => println!("HTTP request: {conn:?}"),
        Event::Accepted(conn) => println!("TCP accepted: {conn:?}"),
        Event::Drained { conn, received } => {
            println!("TCP input ended: {conn:?}, {received} bytes, no response")
        }
        Event::Registers(sample) => println!("Register sample: {sample:?}"),
    });
    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move { start(&fcx, attachments, observe) },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::network::ConnError;
    use fictionet::stdlib::protocols::http1;
    use fictionet_test_support::sandbox::{machine, request};
    use fictionet_test_support::world::world;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;

    fn families() -> [(IpAddr, IpAddr, IpAddr); 2] {
        [
            (
                Ipv4Addr::new(10, 0, 0, 2).into(),
                MAINTENANCE.into(),
                EDGE.into(),
            ),
            (
                "fd00::2".parse().unwrap(),
                MAINTENANCE_V6.into(),
                EDGE_V6.into(),
            ),
        ]
    }

    #[test]
    fn application_discovery_is_independent_of_the_port_number() {
        for (client, maintenance, _) in families() {
            world(Duration::from_secs(30), move |fcx| async move {
                let events = Arc::new(Mutex::new(Vec::new()));
                let output = events.clone();
                let (attacher, attachments) = fictionet::attachments();
                start(
                    &fcx,
                    attachments,
                    Arc::new(move |event| output.lock().unwrap().push(event)),
                )?;
                let machine = machine(&fcx, attacher.attach("operator")?, client);
                let mut responses = Vec::new();
                for port in [8080, 0] {
                    let destination = SocketAddr::new(maintenance, port);
                    let mut conn = machine.tcp.connect(&fcx, destination).await?;
                    let query = http1::Request::parse(
                        b"GET /status HTTP/1.1\r\nHost: maintenance.south.internal\r\n\r\n",
                    )?;
                    let response = request(&fcx, &mut conn, &query).await?;
                    assert!((200..300).contains(&response.head.status));
                    assert!(!response.body.is_empty());
                    responses.push(response);
                    let events = events.lock().unwrap();
                    assert!(events.iter().any(|event| matches!(event,
                        Event::Request(info) if info.local == Some(destination)
                            && info.peer == Some(conn.local_addr()))));
                }
                assert_eq!(responses[0].body, responses[1].body);
                assert_eq!(responses[0].head.status, responses[1].head.status);
                Ok(())
            });
        }
    }

    #[test]
    fn completed_handshake_does_not_imply_an_application_response() {
        for (client, _, edge) in families() {
            world(Duration::from_secs(30), move |fcx| async move {
                let events = Arc::new(Mutex::new(Vec::new()));
                let output = events.clone();
                let (attacher, attachments) = fictionet::attachments();
                start(
                    &fcx,
                    attachments,
                    Arc::new(move |event| output.lock().unwrap().push(event)),
                )?;
                let machine = machine(&fcx, attacher.attach("operator")?, client);
                let destination = SocketAddr::new(edge, 0);
                let mut conn = machine.tcp.connect(&fcx, destination).await?;
                let query = b"GET /status HTTP/1.1\r\nHost: edge.south.internal\r\n\r\n";
                conn.write_all(&fcx, query).await?;
                conn.shutdown(&fcx).await?;
                let mut buffer = [0; 1024];
                assert!(conn.read(&fcx, &mut buffer).await? == 0);
                {
                    let events = events.lock().unwrap();
                    assert!(events.iter().any(|event| matches!(event,
                        Event::Accepted(info) if info.local == Some(destination))));
                    assert!(events.iter().any(|event| matches!(event,
                        Event::Drained { conn: info, received } if info.local == Some(destination)
                            && *received == query.len())));
                    assert!(
                        !events
                            .iter()
                            .any(|event| matches!(event, Event::Request(_)))
                    );
                }
                assert!(matches!(
                    machine.tcp.connect(&fcx, SocketAddr::new(edge, 8080)).await,
                    Err(ConnError::Refused)
                ));
                Ok(())
            });
        }
    }
}
