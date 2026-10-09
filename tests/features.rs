//! Feature-specific runtime contracts.

#[cfg(feature = "std")]
#[macro_use]
#[path = "common/service_fixture.rs"]
mod service_fixture;

#[cfg(feature = "std")]
#[test]
fn http_alpn_matches_transport_features() {
    use fictionet::stdlib::{httpd, net::PortServer};
    let server = httpd::Server::new(httpd::Router::new());
    #[cfg(feature = "tokio")]
    assert_eq!(server.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
    #[cfg(not(feature = "tokio"))]
    assert_eq!(server.alpn(), [b"http/1.1".to_vec()]);
}

#[test]
fn mutex_guard_excludes_another_lock() {
    let mutex = fictionet::sync::Mutex::new(0);
    let mut guard = mutex.lock();
    assert!(mutex.try_lock().is_none());
    *guard = 9;
    drop(guard);
    assert_eq!(*mutex.try_lock().unwrap(), 9);
}

#[cfg(all(feature = "std", not(feature = "observe"), not(target_arch = "wasm32")))]
#[test]
fn world_socket_refuses_disabled_observer_sessions() {
    let path = std::env::temp_dir().join(format!("fictionet-features-{}.sock", std::process::id()));
    let (attacher, _attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone()), attacher)
        .expect("listen on the test socket");
    let error = match fictionet::relay::observer::Client::connect(path.to_str().unwrap(), "test") {
        Ok(_) => panic!("observer sessions must be refused without observe"),
        Err(error) => error,
    };
    assert!(error.contains("observer sessions are disabled"), "{error}");
    drop(listening);
}

#[cfg(feature = "std")]
mod http {
    use fictionet::stdlib::{ConnectionExt, httpd, ip, net, tcp};
    use fictionet::{Cx, Seed};
    use std::net::{Ipv4Addr, SocketAddr};

    async fn client(fcx: &Cx, router: httpd::Router) -> tcp::TcpConnection {
        let (attacher, attachments) = fictionet::attachments();
        net::Net::new()
            .host("site", |host| {
                host.at(Ipv4Addr::new(198, 18, 0, 1))
                    .dns_name("example.test")
                    .port_server(80, httpd::Server::new(router))
            })
            .start(fcx, attachments)
            .unwrap();
        let end = attacher.attach("client").unwrap();
        let (t, _u, _i, _o) = ip::split_protocols(fcx, end);
        let endpoint = tcp::endpoint(fcx, t, Ipv4Addr::new(10, 0, 0, 2).into());
        endpoint
            .connect(fcx, SocketAddr::from(([198, 18, 0, 1], 80)))
            .await
            .unwrap()
    }

    async fn head(fcx: &Cx, conn: &mut tcp::TcpConnection) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(
                conn.read(fcx, &mut byte).await.unwrap(),
                1,
                "connection closed: {}",
                String::from_utf8_lossy(&bytes)
            );
            bytes.push(byte[0]);
        }
        String::from_utf8(bytes).unwrap().to_lowercase()
    }

    #[cfg(not(feature = "tokio"))]
    #[test]
    fn http2_preface_gets_http1_error() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
            let mut conn = client(&fcx, httpd::Router::new()).await;
            conn.write_all(&fcx, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await?;
            assert!(head(&fcx, &mut conn).await.starts_with("http/1.1 400"));
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn upgrade_request_can_receive_an_ordinary_response() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(2), |fcx| async move {
            let router = httpd::Router::new().get("/", |_, _| http::Response::new("route response".into()));
            let mut conn = client(&fcx, router).await;
            conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await?;
            assert!(head(&fcx, &mut conn).await.starts_with("http/1.1 200"));
            let mut body = [0; 14];
            let mut n = 0;
            while n < body.len() {
                let read = conn.read(&fcx, &mut body[n..]).await?;
                assert!(read > 0);
                n += read;
            }
            assert_eq!(&body, b"route response");
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn websocket_continuation_exchanges_messages_through_server() {
        use fictionet::stdlib::{
            codec::{Side, Stream, Wire},
            serve,
            websocket::{self, Message, Messages},
        };
        struct Echo;
        service_fixture! {
            Echo => (Messages, (), websocket::Error);
            decoder(self) {
                Messages::new(Side::Server)
            }
            on_item(self, message: Message; _, driver) -> serve::Flow {
                message.to_frame(None)?.write(driver.reply())?;
                Ok(serve::Flow::Continue)
            }
        }
        fictionet::block_on(fictionet::lab(Seed::from_u64(3), |fcx| async move {
            let router = httpd::Router::new().get("/", |_, request| {
                let headers: Vec<_> = request.headers().iter().map(|(n, v)| (n.as_str(), v.to_str().unwrap())).collect();
                let upgrade = websocket::check_request(&headers).unwrap();
                let info = request.extensions().get::<fictionet::events::ConnInfo>().unwrap().clone();
                let mut response = http::Response::builder().status(101);
                for (name, value) in upgrade.response_headers(None).unwrap() { response = response.header(name, value); }
                let mut response = response.body(bytes::Bytes::new()).unwrap();
                response.extensions_mut().insert(httpd::UpgradeHandler::new(move |fcx, conn| async move {
                    let result = serve::connection(&fcx, conn, info, &mut Echo, &(), &serve::ServeOptions::default()).await;
                    assert!(matches!(result, Ok(_) | Err(serve::ServeError::Cancelled)));
                }));
                response
            });
            let mut conn = client(&fcx, router).await;
            let mut request = b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
            // Send the first frame with the handshake to check unread bytes survive.
            request.extend(Message::Text("hello".into()).to_frame(Some([1, 2, 3, 4])).unwrap().to_bytes().unwrap());
            conn.write_all(&fcx, &request).await?;
            let response = head(&fcx, &mut conn).await;
            assert!(response.starts_with("http/1.1 101"), "{response}");
            assert!(response.contains("connection: upgrade\r\n"), "{response}");
            assert!(response.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="), "{response}");
            let mut stream = Stream::new(Messages::new(Side::Client));
            loop {
                if let Some(message) = stream.next() {
                    assert_eq!(message.unwrap(), Message::Text("hello".into()));
                    break;
                }
                let mut buf = [0; 1024];
                let n = conn.read(&fcx, &mut buf).await?;
                assert!(n > 0);
                assert_eq!(stream.push(&buf[..n]), n);
            }
            fcx.cancel();
            Ok(())
        })).unwrap();
    }
}
