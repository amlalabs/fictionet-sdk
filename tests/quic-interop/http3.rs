use super::*;
use fictionet::stdlib::web::{self, httpd};
use quiche::h3::NameValue;

struct Echo {
    streamed: bool,
}
impl httpd::Handler for Echo {
    fn call(&self, request: web::Request, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        assert_eq!(
            request.head.version(),
            stdlib::protocols::http1::Version::Http3
        );
        assert_eq!(
            request.head.to_http().unwrap().version,
            http::Version::HTTP_3
        );
        assert_eq!(request.head.path(), "/echo");
        assert_eq!(
            request.head.to_http().unwrap().headers["cookie"],
            "a=1; b=2"
        );
        let body = if self.streamed {
            httpd::Body::Stream(Box::pin(Streamed {
                bytes: request.body.bytes().unwrap(),
                pending: true,
            }))
        } else {
            request.body
        };
        httpd::Reply::Now(web::Response::new(body))
    }
}

struct Streamed {
    bytes: Chunk,
    pending: bool,
}
impl httpd::BodyStream for Streamed {
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Chunk, fictionet::Error>>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.pending = true;
        if self.bytes.is_empty() {
            return std::task::Poll::Ready(None);
        }
        let length = self.bytes.len().min(997);
        std::task::Poll::Ready(Some(Ok(self.bytes.split_to(length))))
    }
    fn take_trailers(self: std::pin::Pin<&mut Self>) -> Option<web::Fields> {
        Some(web::Fields::unpaid([("x-finished", "yes")]))
    }
}

#[test]
fn quiche_http3_reaches_sdk_handlers_and_reuses_stream_slots() {
    exchange(false, 8, httpd::Http3Standard);
}

#[test]
fn quiche_http3_streams_responses_and_trailers_with_pending_polls() {
    exchange(true, 8, httpd::Http3Standard);
}

#[test]
fn insufficient_critical_stream_credit_closes_instead_of_stalling() {
    exchange(false, 2, httpd::Http3Standard);
}

#[test]
fn quiche_http3_sees_the_cloudflare_profile() {
    exchange(false, 8, fictionet_extras::http3::Cloudflare);
    exchange(true, 3, fictionet_extras::http3::Cloudflare);
}

#[test]
fn quiche_http3_sees_the_nginx_profile() {
    exchange(false, 8, fictionet_extras::http3::Nginx);
    exchange(true, 2, fictionet_extras::http3::Nginx);
}

fn is_reserved(id: u64) -> bool {
    id >= 0x21 && (id - 0x21).is_multiple_of(0x1f)
}

/// The SETTINGS quiche received, in wire order, match what `profile` lists.
pub(super) fn sees_settings(profile: &dyn httpd::Http3Profile, received: &[(u64, u64)]) {
    use stdlib::protocols::http3::setting;
    assert_eq!(received.len(), profile.settings().len(), "{received:?}");
    for (listed, &(id, value)) in profile.settings().iter().zip(received) {
        match *listed {
            httpd::Http3Setting::FieldSectionSize(v) => {
                assert_eq!(id, setting::MAX_FIELD_SECTION_SIZE);
                assert!(value <= v);
            }
            httpd::Http3Setting::QpackTableCapacity(v) => {
                assert_eq!((id, value), (setting::QPACK_MAX_TABLE_CAPACITY, v));
            }
            httpd::Http3Setting::QpackBlockedStreams(v) => {
                assert_eq!((id, value), (setting::QPACK_BLOCKED_STREAMS, v));
            }
            httpd::Http3Setting::Reserved => assert!(is_reserved(id) && is_reserved(value)),
        }
    }
}

/// Forty echo exchanges between quiche's HTTP/3 client and a server with
/// `profile`, whose peer allows `uni` server unidirectional streams.
fn exchange<P: httpd::Http3Profile + Copy + 'static>(streamed: bool, uni: u64, profile: P) {
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(71)));
    let (_, server, endpoint) = configs_with_protocol(entropy.clone(), false, b"h3");
    let budget = Budget::new(32 << 20);
    let mut observations = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observations);
    let transport = QuicLayer::new(
        &mut env,
        endpoint,
        Some(Arc::new(server)),
        std::time::Instant::now(),
        16,
        |_| 0x10cu32.into(),
    )
    .unwrap();
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = observations.clone();
    let responder = httpd::Responder::new(Echo { streamed })
        .observe(Arc::new(move |event| seen.lock().unwrap().push(event)))
        .http3_profile(profile);
    // The streams the server needs; a reserved stream is optional.
    let needed = profile
        .streams()
        .iter()
        .filter(|s| !matches!(s, httpd::Http3Stream::Reserved(_)))
        .count() as u64;
    let mut sdk = Driver::new(
        Chain::new(transport, responder.http3()),
        entropy,
        budget,
        Instant::ZERO,
    );
    let mut worker = stdlib::services::stack::Polling::new();
    let mut trailers = std::collections::BTreeSet::new();
    let local = "127.0.0.1:4433".parse().unwrap();
    let remote = "127.0.0.1:4444".parse().unwrap();
    let mut config = super::interop::configuration();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_streams_uni(uni);
    let cid = quiche::ConnectionId::from_ref(&[31; 16]);
    let mut peer = quiche::connect(Some("localhost"), &cid, remote, local, &mut config).unwrap();
    let mut http3 = None;
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut sent = 0;
    let mut finished = 0;
    let mut upload = std::collections::BTreeMap::new();
    let mut received = std::collections::BTreeMap::<u64, Vec<u8>>::new();
    let payload: Vec<u8> = (0..20000).map(|n| (n % 251) as u8).collect();
    let mut buffer = [0; 65535];
    for _ in 0..20000 {
        sdk.run().unwrap();
        worker.work(&mut sdk).unwrap();
        sdk.run().unwrap();
        if let Some(command) = sdk.take_command() {
            let DatagramCommand::Send(datagram) = command else {
                panic!("early server closure");
            };
            let mut bytes = datagram.into_parts().0.into_vec();
            peer.recv(
                &mut bytes,
                quiche::RecvInfo {
                    from: local,
                    to: remote,
                },
            )
            .unwrap();
            assert!(matches!(
                sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
        }
        if let Some(error) = peer.peer_error() {
            assert!(uni < needed);
            assert!(error.is_app);
            assert_eq!(error.error_code, 0x103);
            return;
        }
        if peer.is_established() && http3.is_none() {
            assert_eq!(peer.application_proto(), b"h3");
            http3 = Some(quiche::h3::Connection::with_transport(&mut peer, &h3_config).unwrap());
        }
        if let Some(h3) = &mut http3 {
            while uni >= needed && sent < 40 && sent - finished < 4 {
                let headers = [
                    quiche::h3::Header::new(b":method", b"POST"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", b"/echo"),
                    quiche::h3::Header::new(b"content-length", b"20000"),
                    quiche::h3::Header::new(b"cookie", b"a=1"),
                    quiche::h3::Header::new(b"cookie", b"b=2"),
                ];
                let id = h3.send_request(&mut peer, &headers, false).unwrap();
                upload.insert(id, 0);
                received.insert(id, Vec::new());
                sent += 1;
            }
            for (&id, offset) in &mut upload {
                if *offset < payload.len() {
                    match h3.send_body(&mut peer, id, &payload[*offset..], !streamed) {
                        Ok(n) => *offset += n,
                        Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                        Err(error) => panic!("upload: {error:?}"),
                    }
                }
                if streamed && *offset == payload.len() {
                    let trailers = [quiche::h3::Header::new(b"x-upload", b"done")];
                    match h3.send_additional_headers(&mut peer, id, &trailers, true, true) {
                        Ok(()) => *offset += 1,
                        Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                        Err(error) => panic!("request trailers: {error:?}"),
                    }
                }
            }
            loop {
                match h3.poll(&mut peer) {
                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                        if list
                            .iter()
                            .any(|h| h.name() == b"x-finished" && h.value() == b"yes")
                        {
                            assert!(streamed);
                            assert!(trailers.insert(id));
                        } else {
                            assert!(
                                list.iter()
                                    .any(|h| h.name() == b":status" && h.value() == b"200")
                            );
                            assert_eq!(list.iter().any(|h| h.name() == b"content-length" && h.value() == b"20000"), !streamed);
                        }
                    }
                    Ok((id, quiche::h3::Event::Data)) => {
                        while let Ok(n) = h3.recv_body(&mut peer, id, &mut buffer) {
                            received
                                .get_mut(&id)
                                .unwrap()
                                .extend_from_slice(&buffer[..n]);
                        }
                    }
                    Ok((id, quiche::h3::Event::Finished)) => {
                        assert_eq!(received.remove(&id).unwrap(), payload);
                        assert_eq!(trailers.remove(&id), streamed);
                        upload.remove(&id);
                        finished += 1;
                    }
                    Ok(event) => panic!("unexpected HTTP/3 event: {event:?}"),
                    Err(quiche::h3::Error::Done) => break,
                    Err(error) => panic!("HTTP/3: {error:?}, transport {:?}", peer.peer_error()),
                }
            }
        }
        if finished == 40 {
            sees_settings(&profile, http3.as_ref().unwrap().peer_settings_raw().unwrap());
            sdk.run().unwrap();
            let seen = observations.lock().unwrap();
            assert_eq!(seen.len(), 40);
            assert!(
                seen.iter()
                    .all(|event| event.complete && event.sent == payload.len() as u64)
            );
            return;
        }
        loop {
            match peer.send(&mut buffer) {
                Ok((n, _)) => {
                    let payload = Chunk::copy_of(sdk.budget(), &buffer[..n]).unwrap();
                    assert!(matches!(
                        sdk.deliver(DatagramEvent::Datagram(Datagram::new(payload, remote)))
                            .unwrap(),
                        Admit::Taken
                    ));
                }
                Err(quiche::Error::Done) => break,
                Err(error) => panic!("client send: {error:?}"),
            }
        }
        if peer.is_closed() {
            panic!(
                "peer closed: {:?} {:?}",
                peer.local_error(),
                peer.peer_error()
            );
        }
    }
    panic!("HTTP/3 stalled after {finished} of {sent} requests; uploads {upload:?}");
}

#[test]
fn http3_connection_storage_is_reserved_before_growth() {
    use crate::cost::{Charged, Costs, Linear};
    for limit in [0, 32 << 20] {
        let budget = Budget::new(limit);
        let entropy = SeededEntropy::new(Seed::from_u64(93));
        let mut reports = Observations::new(0);
        let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
        let mut costs = Costs::new("HTTP/3 connection admission");
        // Construction and admission make only the two slot stores. Their
        // reservations are fixed by the stream limit, independent of input.
        let h3 = costs.step(
            0,
            0,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || {
                let mut h3 = httpd::Http3::new(httpd::Limits {
                    streams: 2,
                    ..httpd::Limits::default()
                });
                let result = h3
                    .on_event(&mut env, MuxEvent::Control(ControlEvent::Connected))
                    .unwrap();
                assert_eq!(matches!(result, Admit::Taken), limit != 0);
                Charged::new(h3, budget.used())
            },
        );
        drop(h3);
        assert_eq!(budget.used(), 0);
    }
}

mod listener {
    include!("listener.rs");
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DynamicRequest {
    Release,
    Cancel,
    CapacityError,
    BlockedLimit,
    DecoderError,
}

#[test]
fn quiche_transport_unblocks_a_dynamic_request_after_the_insert() {
    dynamic_request(DynamicRequest::Release);
}

#[test]
fn quiche_transport_cancels_a_blocked_dynamic_request() {
    dynamic_request(DynamicRequest::Cancel);
}

#[test]
fn quiche_transport_rejects_capacity_above_the_advertised_limit() {
    dynamic_request(DynamicRequest::CapacityError);
}

#[test]
fn quiche_transport_rejects_too_many_blocked_streams() {
    dynamic_request(DynamicRequest::BlockedLimit);
}

#[test]
fn quiche_transport_rejects_an_invalid_decoder_instruction() {
    dynamic_request(DynamicRequest::DecoderError);
}

fn dynamic_request(case: DynamicRequest) {
    use fictionet::stdlib::codec::{Decode, Frames, Step, Wire};
    use fictionet::stdlib::protocols::{http3 as wire, qpack};

    struct Seen(Arc<std::sync::Mutex<Vec<String>>>);
    impl httpd::Handler for Seen {
        fn call(&self, request: web::Request, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
            assert_eq!(request.head.host(), Some(b"localhost".as_slice()));
            self.0.lock().unwrap().push(request.head.path().to_owned());
            httpd::Reply::Now(web::Response::new(httpd::Body::empty()))
        }
    }
    let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(812)));
    let (_, mut server, endpoint) = configs_with_protocol(entropy.clone(), false, b"h3");
    if case == DynamicRequest::BlockedLimit {
        let mut transport = quinn_proto::TransportConfig::default();
        transport.max_concurrent_bidi_streams(32u32.into());
        server.transport_config(Arc::new(transport));
    }
    let budget = Budget::new(32 << 20);
    let mut observations = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, entropy.as_ref(), &budget, &mut observations);
    let transport = QuicLayer::new(
        &mut env,
        endpoint,
        Some(Arc::new(server)),
        std::time::Instant::now(),
        32,
        |_| 0x10cu32.into(),
    )
    .unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let responder = httpd::Responder::new(Seen(seen.clone()));
    let mut sdk = Driver::new(
        Chain::new(transport, responder.http3()),
        entropy,
        budget,
        Instant::ZERO,
    );
    let mut worker = stdlib::services::stack::Polling::new();
    let local = "127.0.0.1:4433".parse().unwrap();
    let remote = "127.0.0.1:4444".parse().unwrap();
    let mut config = super::interop::configuration();
    config.set_application_protos(&[b"h3"]).unwrap();
    let cid = quiche::ConnectionId::from_ref(&[38; 16]);
    let mut peer = quiche::connect(Some("localhost"), &cid, remote, local, &mut config).unwrap();
    let mut started = false;
    let mut acted = false;
    let mut received = std::collections::BTreeMap::<u64, Vec<u8>>::new();
    let mut finished = std::collections::BTreeSet::new();
    let mut buffer = [0; 65535];
    for _ in 0..20000 {
        sdk.run().unwrap();
        worker.work(&mut sdk).unwrap();
        sdk.run().unwrap();
        while let Some(command) = sdk.take_command() {
            let DatagramCommand::Send(datagram) = command else {
                panic!("early closure")
            };
            let mut bytes = datagram.into_parts().0.into_vec();
            peer.recv(
                &mut bytes,
                quiche::RecvInfo {
                    from: local,
                    to: remote,
                },
            )
            .unwrap();
            assert!(matches!(
                sdk.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
        }
        if let Some(error) = peer.peer_error() {
            assert!(error.is_app);
            let expected = match case {
                DynamicRequest::CapacityError => wire::error_code::QPACK_ENCODER_STREAM_ERROR,
                DynamicRequest::BlockedLimit => wire::error_code::QPACK_DECOMPRESSION_FAILED,
                DynamicRequest::DecoderError => wire::error_code::QPACK_DECODER_STREAM_ERROR,
                _ => panic!("unexpected close for {case:?}: {error:?}"),
            };
            assert_eq!(error.error_code, expected);
            return;
        }
        if peer.is_established() && !started {
            // quiche 0.30's HTTP/3 encoder is static-only. These RFC 9204
            // field sections deliberately use raw quiche QUIC streams so
            // the test exercises transport ordering and the SDK decoder.
            assert_eq!(peer.stream_send(2, &[0, 4, 0], false).unwrap(), 3);
            assert_eq!(peer.stream_send(6, &[2], false).unwrap(), 1);
            assert_eq!(peer.stream_send(10, &[3], false).unwrap(), 1);
            if case == DynamicRequest::CapacityError {
                // Set Dynamic Table Capacity: 4097, above the server's 4096.
                assert_eq!(peer.stream_send(6, &[0x3f, 0xe2, 0x1f], false).unwrap(), 3);
            } else if case == DynamicRequest::DecoderError {
                // Insert Count Increment must be nonzero.
                assert_eq!(peer.stream_send(10, &[0], false).unwrap(), 1);
            } else {
                // Required Insert Count 1, Base 1, static GET and https,
                // dynamic relative entry 0 (:authority), literal :path.
                let mut request = vec![1, 15, 2, 0, 0xd1, 0xd7, 0x80, 0x51, 8];
                request.extend_from_slice(b"/blocked");
                let streams = if case == DynamicRequest::BlockedLimit {
                    17
                } else {
                    1
                };
                for index in 0..streams {
                    assert_eq!(
                        peer.stream_send(4 * index, &request, false).unwrap(),
                        request.len()
                    );
                }
                // A static request can finish while stream zero is blocked.
                let mut barrier = vec![1, 25, 0, 0, 0xd1, 0xd7, 0x50, 9];
                barrier.extend_from_slice(b"localhost");
                barrier.extend_from_slice(&[0x51, 8]);
                barrier.extend_from_slice(b"/barrier");
                if case != DynamicRequest::BlockedLimit {
                    assert_eq!(peer.stream_send(4, &barrier, true).unwrap(), barrier.len());
                }
            }
            started = true;
        }
        let readable: Vec<_> = peer.readable().collect();
        for id in readable {
            loop {
                match peer.stream_recv(id, &mut buffer) {
                    Ok((n, fin)) => {
                        received
                            .entry(id)
                            .or_default()
                            .extend_from_slice(&buffer[..n]);
                        if fin {
                            finished.insert(id);
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(quiche::Error::StreamReset(_))
                        if case == DynamicRequest::Cancel && id == 0 =>
                    {
                        break;
                    }
                    Err(error) => panic!("raw response on {id}: {error:?}"),
                }
            }
        }
        if finished.contains(&4) && !acted {
            assert_eq!(*seen.lock().unwrap(), ["/barrier"]);
            let control = received.get(&3).expect("server control stream");
            let wire::Frame::Settings(settings) = wire::Frame::parse(&control[1..]).unwrap() else {
                panic!("server SETTINGS")
            };
            assert_eq!(
                settings.get(wire::setting::QPACK_MAX_TABLE_CAPACITY),
                Some(4096)
            );
            assert_eq!(settings.get(wire::setting::QPACK_BLOCKED_STREAMS), Some(16));
            if case == DynamicRequest::Release {
                // Set capacity to 4096; Insert With Name Reference to static
                // :authority (entry 0), value "localhost".
                let mut instruction = vec![0x3f, 0xe1, 0x1f, 0xc0, 9];
                instruction.extend_from_slice(b"localhost");
                assert_eq!(
                    peer.stream_send(6, &instruction, false).unwrap(),
                    instruction.len()
                );
                peer.stream_send(0, &[], true).unwrap();
            } else {
                peer.stream_shutdown(
                    0,
                    quiche::Shutdown::Write,
                    wire::error_code::REQUEST_CANCELLED,
                )
                .unwrap();
            }
            acted = true;
        }
        if acted {
            let feedback = received.values().find(|bytes| bytes.first() == Some(&3));
            if let Some(feedback) = feedback {
                let mut bytes = &feedback[1..];
                while let Ok(Step::Item(instruction, used)) =
                    Frames::<qpack::DecoderInstruction>::new().decode(bytes, false)
                {
                    let instruction = instruction.unwrap();
                    let complete = match case {
                        DynamicRequest::Release => {
                            instruction == qpack::DecoderInstruction::SectionAck(0)
                                && finished.contains(&0)
                        }
                        DynamicRequest::Cancel => {
                            instruction == qpack::DecoderInstruction::StreamCancel(0)
                        }
                        DynamicRequest::CapacityError
                        | DynamicRequest::BlockedLimit
                        | DynamicRequest::DecoderError => false,
                    };
                    if complete {
                        let seen = seen.lock().unwrap();
                        assert_eq!(
                            seen.iter().any(|path| path == "/blocked"),
                            case == DynamicRequest::Release
                        );
                        return;
                    }
                    bytes = &bytes[used..];
                }
            }
        }
        loop {
            match peer.send(&mut buffer) {
                Ok((n, _)) => {
                    let payload = Chunk::copy_of(sdk.budget(), &buffer[..n]).unwrap();
                    assert!(matches!(
                        sdk.deliver(DatagramEvent::Datagram(Datagram::new(payload, remote)))
                            .unwrap(),
                        Admit::Taken
                    ));
                }
                Err(quiche::Error::Done) => break,
                Err(error) => panic!("client send: {error:?}"),
            }
        }
    }
    panic!(
        "dynamic request {case:?} stalled: finished {finished:?}, seen {:?}, received {received:?}",
        seen.lock().unwrap()
    );
}
