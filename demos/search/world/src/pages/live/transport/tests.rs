use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    time::Instant,
};

#[test]
fn public_connections_exclude_special_address_ranges() {
    let transport = Transport::new().unwrap();
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "2001::1",
        "2001:db8::1",
        "2002:a00:1::1",
        "3fff::1",
    ] {
        assert!(!transport.permits(address.parse().unwrap()), "{address}");
    }
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(transport.permits(address.parse().unwrap()), "{address}");
    }
}

fn server(responses: Vec<(String, Vec<u8>)>) -> (String, std::thread::JoinHandle<Vec<Instant>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let mut times = Vec::new();
        for (headers, body) in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            times.push(Instant::now());
            write!(
                socket,
                "HTTP/1.1 {headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(&body).unwrap();
        }
        times
    });
    (origin, server)
}

#[tokio::test]
async fn blocked_requests_finish_their_records_without_credentials() {
    fictionet::run(fictionet::Seed::from_u64(4), |cx| async move {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let observer: Arc<capture::Observer> =
            Arc::new(move |_, event| seen.lock().unwrap().push(event.clone()));
        let transport = Transport::new().unwrap();
        let lifetime = Lifetime::default();
        let key = Key::new("EXA_API_KEY", Some("host-only-key".into())).unwrap();
        for url in [
            "http://user:password@127.0.0.1/private?token=secret#fragment",
            "http://localhost/",
            "http://127.1/",
            "http://2130706433/",
            "http://[::1]/search?key=secret",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert!(
                transport
                    .request(&cx, &lifetime, Some(observer.clone()), url, None)
                    .await
                    .is_err()
            );
        }
        assert!(
            transport
                .request(
                    &cx,
                    &lifetime,
                    Some(observer.clone()),
                    "http://[::1]/search?key=secret",
                    Some((&key, &json!({"query":"private"})))
                )
                .await
                .is_err()
        );
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 14);
        for pair in events.as_chunks::<2>().0 {
            assert_eq!(pair[0].attempt, pair[1].attempt);
            assert_eq!(pair[0].phase, UpstreamPhase::Attempt);
            assert_eq!(pair[1].phase, UpstreamPhase::Failed);
            assert!(pair.iter().all(|event| event.status.is_none()
                && event.url.query().is_none()
                && event.url.fragment().is_none()
                && event.url.username().is_empty()
                && event.url.password().is_none()));
        }
        assert_eq!(events[0].purpose, capture::Purpose::Capture);
        assert_eq!(events[12].purpose, capture::Purpose::Search);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn redirects_are_returned_and_their_destinations_are_checked_again() {
    let (origin, server) = server(vec![(
        "302 Found\r\nLocation: http://169.254.169.254/latest/".into(),
        Vec::new(),
    )]);
    fictionet::run(fictionet::Seed::from_u64(5), |cx| async move {
        let transport = Transport::loopback().unwrap();
        let lifetime = Lifetime::default();
        let response = transport
            .request(&cx, &lifetime, None, &origin, None)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        let destination = response.headers[http::header::LOCATION].to_str().unwrap();
        assert!(
            transport
                .request(&cx, &lifetime, None, destination, None)
                .await
                .is_err()
        );
        assert!(
            Transport::new()
                .unwrap()
                .request(&cx, &lifetime, None, destination, None)
                .await
                .is_err()
        );
        Ok(())
    })
    .await
    .unwrap();
    server.join().unwrap();
}

#[tokio::test]
async fn cancelled_runs_do_not_start_another_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    fictionet::run(fictionet::Seed::from_u64(6), |cx| async move {
        let transport = Transport::loopback().unwrap();
        cx.cancel();
        assert!(
            transport
                .request(&cx, &Lifetime::default(), None, &origin, None)
                .await
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn requests_ignore_robots_and_remain_rate_limited() {
    let (origin, server) = server(
        (0..3)
            .map(|_| ("200 OK".into(), b"copied".to_vec()))
            .collect(),
    );
    fictionet::run(fictionet::Seed::from_u64(7), |cx| async move {
        let transport = Transport::loopback().unwrap();
        let lifetime = Lifetime::default();
        for path in ["/denied", "/allowed", "/another"] {
            assert_eq!(
                transport
                    .request(&cx, &lifetime, None, &format!("{origin}{path}"), None)
                    .await
                    .unwrap()
                    .body,
                "copied"
            );
        }
        Ok(())
    })
    .await
    .unwrap();
    let times = server.join().unwrap();
    assert!(times[1].duration_since(times[0]) >= Duration::from_millis(500));
    assert!(times[2].duration_since(times[1]) >= Duration::from_millis(450));
}

#[tokio::test]
async fn revoked_processing_keeps_its_worker_slot_until_the_worker_finishes() {
    fictionet::run(fictionet::Seed::from_u64(9), |cx| async move {
        let transport = Arc::new(Transport::loopback().unwrap());
        let lifetime = Arc::new(Lifetime::default());
        let (started, ready) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let worker = transport.clone();
        let owner = lifetime.clone();
        let worker_cx = cx.clone();
        let task = tokio::spawn(async move {
            worker
                .process(&worker_cx, &owner, move || {
                    started.send(()).unwrap();
                    blocked.recv().unwrap();
                    Ok(())
                })
                .await
        });
        ready.await.unwrap();
        lifetime.cancel();
        assert!(task.await.unwrap().unwrap_err().contains("stopped"));
        assert_eq!(transport.processing.available_permits(), 0);
        let queued_owner = Arc::new(Lifetime::default());
        let queued = queued_owner.clone();
        let worker = transport.clone();
        let worker_cx = cx.clone();
        let next = tokio::spawn(async move {
            worker
                .process::<()>(&worker_cx, &queued, || panic!("revoked queued parser ran"))
                .await
        });
        queued_owner.cancel();
        assert!(next.await.unwrap().is_err());
        release.send(()).unwrap();
        let permit = transport.processing.acquire().await.unwrap();
        drop(permit);
        assert_eq!(
            transport
                .process(&cx, &Lifetime::default(), || Ok(42))
                .await
                .unwrap(),
            42
        );
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn compressed_responses_are_bounded_and_replayed_without_further_expansion() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::copy(
        &mut std::io::repeat(b'x').take(warc::Response::DECODED_BYTES as u64 + 1),
        &mut encoder,
    )
    .unwrap();
    let bomb = encoder.finish().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"<title>Page</title>").unwrap();
    let (origin, server) = server(vec![
        ("200 OK\r\nContent-Encoding: gzip".into(), bomb),
        (
            "200 OK\r\nContent-Encoding: gzip".into(),
            encoder.finish().unwrap(),
        ),
    ]);
    fictionet::run(fictionet::Seed::from_u64(8), |cx| async move {
        let transport = Transport::loopback().unwrap();
        let lifetime = Lifetime::default();
        assert!(
            transport
                .request(&cx, &lifetime, None, &origin, None)
                .await
                .unwrap_err()
                .contains("decoded response exceeds size limit")
        );
        let response = transport
            .request(&cx, &lifetime, None, &origin, None)
            .await
            .unwrap();
        assert_eq!(response.body, "<title>Page</title>");
        assert!(
            !response
                .headers
                .contains_key(http::header::CONTENT_ENCODING)
        );
        assert_eq!(response.headers[http::header::CONTENT_LENGTH], "19");
        Ok(())
    })
    .await
    .unwrap();
    server.join().unwrap();
}
