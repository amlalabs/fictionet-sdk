//! Feature-specific runtime contracts.

#[cfg(feature = "std")]
#[test]
fn http_alpn_matches_transport_features() {
    use fictionet::stdlib::{httpd, net::PortServer};
    let server = httpd::Server::new(httpd::Router::new());
    assert_eq!(server.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
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

    async fn client(fcx: &Cx, router: impl httpd::Handler) -> tcp::TcpConnection {
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

    #[test]
    fn http2_prior_knowledge_works_with_std() {
        use fictionet::stdlib::{codec::Wire, http2};
        fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
            let router =
                httpd::Router::new().get("/", |_, _| http::Response::new("hello over h2".into()));
            let mut conn = client(&fcx, router).await;
            let mut input = http2::PREFACE.to_vec();
            http2::Settings {
                flags: 0,
                entries: Vec::new(),
            }
            .write(&mut input)?;
            let mut fragment = Vec::new();
            for (name, value) in [
                (":method", "GET"),
                (":scheme", "http"),
                (":authority", "example.test"),
                (":path", "/"),
            ] {
                fictionet::stdlib::hpack::Field::new(name, value).write(&mut fragment)?;
            }
            http2::Headers {
                stream: 1,
                flags: 5,
                fragment,
                priority: None,
                padding: None,
            }
            .write(&mut input)?;
            conn.write_all(&fcx, &input).await?;
            let mut blocks = http2::HeaderBlocks::with_limits(Default::default());
            let mut body = Vec::new();
            let mut status = None;
            loop {
                let mut bytes = vec![0; 9];
                for byte in &mut bytes {
                    assert_eq!(conn.read(&fcx, std::slice::from_mut(byte)).await?, 1);
                }
                let header = http2::FrameHeader::parse(&bytes)?;
                bytes.resize(9 + header.length, 0);
                let mut at = 9;
                while at < bytes.len() {
                    let n = conn.read(&fcx, &mut bytes[at..]).await?;
                    assert_ne!(n, 0);
                    at += n;
                }
                let frame = http2::Frame::parse(&bytes)?;
                if let Some(block) = blocks.read_frame(&frame)?.block {
                    status = block
                        .headers
                        .into_iter()
                        .find(|h| h.name.as_deref() == Some(b":status"))
                        .and_then(|h| h.value);
                }
                match frame {
                    http2::Frame::Settings(s) if s.flags & 1 == 0 => {
                        conn.write_all(
                            &fcx,
                            &http2::Settings {
                                flags: 1,
                                entries: Vec::new(),
                            }
                            .to_bytes()?,
                        )
                        .await?;
                    }
                    http2::Frame::Data(d) => {
                        assert_eq!(d.stream, 1);
                        body.extend(d.data);
                        if d.flags & 1 != 0 {
                            break;
                        }
                    }
                    http2::Frame::Reset(r) => panic!("request reset: {r:?}"),
                    http2::Frame::GoAway(g) => panic!("connection ended: {g:?}"),
                    _ => {}
                }
            }
            assert_eq!(status.as_deref(), Some(b"200".as_slice()));
            assert_eq!(body, b"hello over h2");
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn tower_upgrade_handoff_survives_a_handler_wrapper() {
        struct Wrapped<H>(H);
        impl<H: httpd::Handler> httpd::Handler for Wrapped<H> {
            fn call(
                &self,
                request: http::Request<httpd::Body>,
                ex: &mut httpd::Exchange<'_>,
            ) -> httpd::Reply {
                self.0.call(request, ex)
            }
        }
        // Only a request replayed on hyper, body included, carries OnUpgrade.
        async fn echo(request: axum::extract::Request) -> String {
            let upgradable = request
                .extensions()
                .get::<hyper::upgrade::OnUpgrade>()
                .is_some();
            let body = axum::body::to_bytes(request.into_body(), 64).await.unwrap();
            format!("{upgradable} {}", String::from_utf8_lossy(&body))
        }
        for body in [
            b"Content-Length: 4\r\n\r\nbody".as_slice(),
            b"Transfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n".as_slice(),
        ] {
            fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
                let app = axum::Router::new().route("/", axum::routing::post(echo));
                let mut conn = client(&fcx, Wrapped(httpd::tower(app))).await;
                let mut input = b"POST / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n".to_vec();
                input.extend_from_slice(body);
                conn.write_all(&fcx, &input).await?;
                assert!(head(&fcx, &mut conn).await.starts_with("http/1.1 200"));
                let mut bytes = [0; 9];
                let mut at = 0;
                while at < bytes.len() {
                    let n = conn.read(&fcx, &mut bytes[at..]).await?;
                    assert_ne!(n, 0);
                    at += n;
                }
                assert_eq!(&bytes, b"true body");
                fcx.cancel();
                Ok(())
            })).unwrap();
        }
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn tower_upgrade_with_a_cut_off_body_is_answered() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
            let app = axum::Router::new().route("/", axum::routing::post(|| async { "reached" }));
            let mut conn = client(&fcx, httpd::tower(app)).await;
            conn.write_all(&fcx, b"POST / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 10\r\n\r\nbody").await?;
            conn.shutdown(&fcx).await?;
            assert!(head(&fcx, &mut conn).await.starts_with("http/1.1 400"));
            while conn.read(&fcx, &mut [0; 64]).await? != 0 {}
            let events = fcx.events().of("http", "request");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].str("answer"), Some("cut_off"));
            assert_eq!(events[0].str("received"), Some("cut_off"));
            fcx.cancel();
            Ok(())
        })).unwrap();
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
                Messages::for_receiver(Side::Server)
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
            let mut stream = Stream::new(Messages::for_receiver(Side::Client));
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
