use super::*;

/// What a server wrote on each stream: its header blocks, in order, and
/// its DATA bytes, with whether a frame ended the stream.
#[derive(Default, Debug)]
struct Written {
    blocks: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    data: Vec<u8>,
    ended: bool,
}

fn per_stream(output: &[Frame]) -> std::collections::BTreeMap<u32, Written> {
    let mut blocks = http2::HeaderBlocks::with_limits(Default::default());
    let mut streams = std::collections::BTreeMap::<u32, Written>::new();
    for frame in output {
        if let Frame::Data(d) = frame {
            let stream = streams.entry(d.stream).or_default();
            stream.data.extend_from_slice(&d.data);
            stream.ended |= d.flags & 1 != 0;
            continue;
        }
        let read = blocks.read_frame(frame).unwrap();
        if let Some(block) = read.block {
            let stream = streams.entry(read.stream).or_default();
            stream.blocks.push(
                block
                    .headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
            );
            stream.ended |= read.end;
        }
    }
    streams
}

fn field<'a>(block: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    block
        .iter()
        .find(|(n, _)| n == name.as_bytes())
        .map(|(_, v)| v.as_slice())
}

mod grpc_calls {
    use super::*;
    use fictionet::stdlib::layer::{
        Admit, Chain, Children, Env, Layer, MessageCommand, MessageEvent, Messages, Top,
    };
    use fictionet::stdlib::protocols::grpc;
    use fictionet::stdlib::web::httpd::{Grpc, GrpcCommand, GrpcEvent, Http2, Opening};
    use std::collections::VecDeque;
    use std::convert::Infallible;

    /// Answers each message of a call with the same message, then `OK`.
    #[derive(Default)]
    struct Echo {
        out: VecDeque<MessageCommand<GrpcCommand>>,
    }

    impl Layer for Echo {
        type Lower = Messages<GrpcEvent, GrpcCommand>;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;

        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: MessageEvent<GrpcEvent>,
        ) -> Result<Admit<MessageEvent<GrpcEvent>>, Infallible> {
            match event {
                MessageEvent::Message(GrpcEvent::Call(call)) => {
                    assert_eq!(call.path.method(), "Say");
                }
                MessageEvent::Message(GrpcEvent::Message(message)) => self
                    .out
                    .push_back(MessageCommand::Send(GrpcCommand::Message(message))),
                MessageEvent::Ended => self.out.push_back(MessageCommand::End),
            }
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }

        fn take_command(&mut self) -> Option<MessageCommand<GrpcCommand>> {
            self.out.pop_front()
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    type Calls = Chain<Http2, Children<Chain<Grpc, Echo>, Top, Opening>>;

    fn calls() -> Harness<Calls> {
        let server = Chain::new(
            Http2::new(httpd::Limits::default()),
            Children::new(8, Http2::WINDOW, |_, opening, _| {
                Chain::new(Grpc::new(opening), Echo::default())
            }),
        );
        Harness::new(Seed::from_u64(1), server).with_worker(Polling::new())
    }

    fn call(stream: u32, content_type: &str) -> Vec<u8> {
        let mut fragment = Vec::new();
        for (name, value) in [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "a.test"),
            (":path", "/test.Echo/Say"),
            ("content-type", content_type),
            ("te", "trailers"),
        ] {
            hpack::Field::new(name, value).write(&mut fragment).unwrap();
        }
        http2::Headers {
            stream,
            flags: 4,
            fragment,
            priority: None,
            padding: None,
        }
        .to_bytes()
        .unwrap()
    }

    fn message(text: &str) -> Vec<u8> {
        grpc::Message {
            compressed: false,
            data: text.as_bytes().to_vec(),
        }
        .to_bytes()
        .unwrap()
    }

    fn data(stream: u32, bytes: &[u8], end: bool) -> Vec<u8> {
        http2::Data {
            stream,
            flags: u8::from(end),
            data: bytes.to_vec(),
            padding: None,
        }
        .to_bytes()
        .unwrap()
    }

    fn messages(mut bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while let Some((message, used)) = grpc::Message::parse_prefix(bytes).unwrap() {
            out.push(String::from_utf8(message.data).unwrap());
            bytes = &bytes[used..];
        }
        assert!(bytes.is_empty(), "a message was cut off");
        out
    }

    fn push(harness: &mut Harness<Calls>, bytes: &[u8]) -> Vec<Frame> {
        harness.push(bytes).unwrap();
        frames(&harness.take_output())
    }

    #[test]
    fn calls_on_one_connection_interleave_without_mixing() {
        let mut harness = calls();
        let mut input = preface();
        input.extend(call(1, "application/grpc"));
        input.extend(call(3, "application/grpc+proto"));
        let a1 = message("a1");
        // Stream 1's first message is split across frames, with stream 3's
        // two messages, in one frame, between its halves.
        input.extend(data(1, &a1[..3], false));
        input.extend(data(3, &[message("b1"), message("b2")].concat(), true));
        input.extend(data(1, &a1[3..], false));
        input.extend(data(1, &message("a2"), true));
        let output = push(&mut harness, &input);
        let streams = per_stream(&output);
        for (id, content_type, expected) in [
            (1, "application/grpc", ["a1", "a2"]),
            (3, "application/grpc+proto", ["b1", "b2"]),
        ] {
            let written = &streams[&id];
            assert_eq!(messages(&written.data), expected, "{output:?}");
            let [head, trailers] = written.blocks.as_slice() else {
                panic!("a head and trailers on stream {id}: {output:?}");
            };
            assert_eq!(field(head, ":status"), Some(&b"200"[..]));
            assert_eq!(field(head, "content-type"), Some(content_type.as_bytes()));
            assert_eq!(field(trailers, "grpc-status"), Some(&b"0"[..]));
            assert!(written.ended);
        }
        assert!(!harness.ended());
    }

    #[test]
    fn a_request_that_is_not_a_call_is_answered_without_the_application() {
        let mut harness = calls();
        let mut input = preface();
        input.extend(call(1, "text/plain"));
        input.extend(data(1, b"hello", true));
        let output = push(&mut harness, &input);
        let streams = per_stream(&output);
        let [head] = streams[&1].blocks.as_slice() else {
            panic!("one head: {output:?}");
        };
        assert_eq!(field(head, ":status"), Some(&b"415"[..]));
        assert!(streams[&1].ended);
        assert!(streams[&1].data.is_empty());
    }

    #[test]
    fn a_call_that_ends_inside_a_message_is_internal() {
        let mut harness = calls();
        let mut input = preface();
        input.extend(call(1, "application/grpc"));
        input.extend(data(1, &message("whole")[..4], true));
        let output = push(&mut harness, &input);
        let streams = per_stream(&output);
        let [block] = streams[&1].blocks.as_slice() else {
            panic!("a trailers-only answer: {output:?}");
        };
        assert_eq!(field(block, ":status"), Some(&b"200"[..]));
        assert_eq!(field(block, "grpc-status"), Some(&b"13"[..]));
        assert!(streams[&1].ended);
    }
}

mod h2c {
    use super::*;
    use fictionet::stdlib::codec::base64;
    use fictionet::stdlib::layer::Switch;
    use fictionet::stdlib::web::httpd::{Http1, Upgraded};

    fn echo() -> impl httpd::Handler {
        fictionet_test_support::handler(|_, request: http::Request<Bytes>| {
            http::Response::new(request.into_body())
        })
    }

    fn server() -> Harness<Switch<Http1, Upgraded>> {
        Harness::new(Seed::from_u64(1), Http1::new(echo()).h2c().upgradable())
            .with_worker(Polling::new())
    }

    /// `HTTP2-Settings` for these settings: base64url, no padding.
    pub(super) fn settings(entries: &[(u16, u32)]) -> String {
        let mut payload = Vec::new();
        for (id, value) in entries {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        base64::encode(&payload)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }

    fn upgrade(settings: &str, body: &str) -> Vec<u8> {
        format!(
            "POST /echo HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade, HTTP2-Settings\r\n\
             Upgrade: h2c\r\nHTTP2-Settings: {settings}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The HTTP/1 head the server wrote, and the HTTP/2 frames after it.
    fn split(output: &[u8]) -> (String, Vec<Frame>) {
        let end = output
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("an HTTP/1 head")
            + 4;
        (
            String::from_utf8(output[..end].to_vec()).unwrap(),
            frames(&output[end..]),
        )
    }

    #[test]
    fn the_upgrading_request_is_answered_on_stream_1() {
        let mut h = server();
        // The client's settings apply: its initial window takes 3 bytes.
        let mut input = upgrade(&settings(&[(4, 3)]), "hello");
        // The preface comes right behind the request, in the same bytes.
        input.extend(preface());
        h.push(&input).unwrap();
        let (head, output) = split(&h.take_output());
        assert!(
            head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{head}"
        );
        assert!(head.contains("\r\nUpgrade: h2c\r\n"), "{head}");
        assert!(
            matches!(&output[0], Frame::Settings(s) if s.flags & 1 == 0),
            "{output:?}"
        );
        let streams = per_stream(&output);
        assert_eq!(field(&streams[&1].blocks[0], ":status"), Some(&b"200"[..]));
        assert_eq!(streams[&1].data, b"hel");
        // More credit lets the rest of the answer go.
        h.push(
            &http2::WindowUpdate {
                stream: 1,
                flags: 0,
                increment: 10,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let streams = per_stream(&frames(&h.take_output()));
        assert_eq!(streams[&1].data, b"lo");
        assert!(streams[&1].ended);
        // The connection goes on as HTTP/2.
        h.push(&headers(3, "/echo", true)).unwrap();
        let output = frames(&h.take_output());
        assert_eq!(statuses(&output), [(3, b"200".to_vec())]);
        assert!(!h.ended());
    }

    #[test]
    fn an_upgrading_body_larger_than_the_streams_window_reaches_the_handler() {
        // The body came whole over HTTP/1, so it is larger than the credit
        // the exchange grants at once: it must still reach the handler, in
        // pieces, without waiting for the body deadline.
        let body = "x".repeat(100_000);
        let mut h = server();
        let mut input = upgrade(&settings(&[(4, (1 << 31) - 1)]), &body);
        input.extend(preface());
        h.push(&input).unwrap();
        let (head, output) = split(&h.take_output());
        assert!(
            head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{head}"
        );
        let streams = per_stream(&output);
        let stream = streams.get(&1).expect("an answer on stream 1");
        assert_eq!(field(&stream.blocks[0], ":status"), Some(&b"200"[..]));
        let mut echoed = stream.data.clone();
        // The connection's send window holds back the rest of the echo.
        h.push(
            &http2::WindowUpdate {
                stream: 0,
                flags: 0,
                increment: 1 << 20,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let streams = per_stream(&frames(&h.take_output()));
        echoed.extend_from_slice(&streams[&1].data);
        assert!(streams[&1].ended);
        assert_eq!(echoed, body.as_bytes());
    }

    #[test]
    fn invalid_settings_keep_the_request_on_http1() {
        for settings in [
            // Not base64url.
            "!!".to_owned(),
            // Not a whole number of settings.
            base64::encode(&[0, 4, 0]).trim_end_matches('=').to_owned(),
            // An initial window past 2^31 - 1.
            settings(&[(4, 1 << 31)]),
        ] {
            let mut h = server();
            h.push(&upgrade(&settings, "hello")).unwrap();
            let output = h.take_output();
            let text = String::from_utf8_lossy(&output);
            assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
            assert!(text.ends_with("\r\n\r\nhello"), "{text}");
        }
    }

    #[test]
    fn http2_waits_until_the_101_is_written() {
        let mut h = server();
        h.withhold();
        let mut input = upgrade(&settings(&[]), "hi");
        input.extend(preface());
        h.push(&input).unwrap();
        assert!(h.output().is_empty());
        let mut written = Vec::new();
        // The transport takes a few bytes at a time.
        for _ in 0..200 {
            h.allow(7).unwrap();
            written.extend(h.take_output());
        }
        h.allow_all().unwrap();
        written.extend(h.take_output());
        let (head, output) = split(&written);
        assert!(
            head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{head}"
        );
        assert!(
            matches!(&output[0], Frame::Settings(s) if s.flags & 1 == 0),
            "{output:?}"
        );
        assert_eq!(per_stream(&output)[&1].data, b"hi");
    }
}

mod detection {
    use super::*;
    use fictionet::stdlib::network::ConnInfo;
    use fictionet::stdlib::web::httpd::{Http, HttpOptions};

    fn http(opts: &HttpOptions) -> Harness<Http> {
        let handler: Arc<dyn httpd::Handler> =
            fictionet_test_support::handler(|_, _| http::Response::new(Bytes::from_static(b"ok")));
        let stack = httpd::http_for(
            handler,
            opts,
            &ConnInfo::default(),
            fictionet::time::Instant::ZERO,
        );
        Harness::new(Seed::from_u64(1), stack).with_worker(Polling::new())
    }

    #[test]
    fn the_preface_chooses_http2_however_it_is_split() {
        let mut input = preface();
        input.extend(headers(1, "/", true));
        for cut in [1, 5, 23, 24, 40] {
            let mut h = http(&httpd::HttpOptions::default());
            h.push(&input[..cut]).unwrap();
            h.push(&input[cut..]).unwrap();
            let output = frames(&h.take_output());
            assert!(
                matches!(&output[0], Frame::Settings(_)),
                "{cut}: {output:?}"
            );
            assert_eq!(statuses(&output), [(1, b"200".to_vec())], "{cut}");
        }
    }

    #[test]
    fn other_bytes_choose_http1() {
        let mut h = http(&HttpOptions::default());
        // "P" could start either; "PO" is HTTP/1's.
        h.push(b"P").unwrap();
        h.push(b"OST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let output = String::from_utf8(h.take_output()).unwrap();
        assert!(output.starts_with("HTTP/1.1 200 OK\r\n"), "{output}");
        assert!(output.ends_with("\r\n\r\nok"), "{output}");
    }

    #[test]
    fn a_client_that_sends_nothing_is_closed_at_the_first_bytes_deadline() {
        let opts = HttpOptions {
            first_bytes: Some(Duration::from_secs(1)),
            ..HttpOptions::default()
        };
        let mut h = http(&opts);
        h.settle().unwrap();
        h.advance(Duration::from_millis(999)).unwrap();
        assert!(!h.ended());
        h.advance(Duration::from_millis(1)).unwrap();
        assert!(h.ended());
        assert!(h.output().is_empty());
    }

    #[test]
    fn an_end_inside_the_preface_is_a_cut_off_http1_head() {
        let mut h = http(&HttpOptions::default());
        h.push(&http2::PREFACE[..10]).unwrap();
        h.end().unwrap();
        let output = String::from_utf8(h.take_output()).unwrap();
        assert!(output.starts_with("HTTP/1.1 400 "), "{output}");
    }
}
