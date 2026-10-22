use super::*;

#[test]
fn external_redirects_do_not_grant_a_crawl_of_another_site() {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = format!("http://127.0.0.1:{port}/");
    let landing = format!("http://localhost:{port}/landing");
    let location = landing.clone();
    let (send, receive) = oneshot::channel();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let target = line.split_whitespace().nth(1).unwrap().to_owned();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let (status, extra, body) = match target.as_str() {
                "/robots.txt" => (200, String::new(), "User-agent: *\nAllow: /\n"),
                "/" => (302, format!("Location: {location}\r\n"), ""),
                "/landing" => (
                    200,
                    String::new(),
                    "<title>Landing</title><a href='/escape'>Another site page</a>",
                ),
                _ => panic!("only the result redirect and landing page are reached"),
            };
            write!(socket, "HTTP/1.1 {status} OK\r\n{extra}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        let _ = send.send(());
    });
    let path = std::env::temp_dir().join(format!(
        "fictionet-live-redirect-{}.warc.gz",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let live = Arc::new(Live {
        key: Key::new("EXA_API_KEY", Some("private".into())).unwrap(),
        endpoint: "https://api.exa.ai/search".parse().unwrap(),
        path: path.clone(),
        state: Mutex::default(),
        fetcher: Mutex::default(),
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(6)),
        |cx| async move {
            live.enqueue(
                Job {
                    url: origin.clone(),
                    navigation: Some(("127.0.0.1".into(), 0)),
                    redirects: 0,
                    cx: cx.clone(),
                },
                true,
            );
            cx.race(Some(cx.now() + Duration::from_secs(10)), receive)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                live.response(&cx, &origin).await.unwrap().status.as_u16(),
                302
            );
            assert_eq!(
                live.response(&cx, &landing).await.unwrap().status.as_u16(),
                200
            );
            assert!(
                live.response(&cx, &format!("http://localhost:{port}/escape"))
                    .await
                    .is_none()
            );
            assert_eq!(live.state().archive.urls().count(), 2);
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn every_engine_uses_the_host_api_and_logs_queries_downloads_and_replays() {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let result_url = format!("{origin}/result");
    let returned_url = result_url.clone();
    let server = std::thread::spawn(move || {
        let mut queries = 0;
        for _ in 0..5 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let target = line.split_whitespace().nth(1).unwrap().to_owned();
            let mut length = 0;
            let mut key = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if let Some(value) = lower.strip_prefix("x-api-key:") {
                    key = value.trim().to_owned();
                }
            }
            let (mime, body) = if target == "/search" {
                assert_eq!(key, "host-only-key");
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(request["query"], "stellar & gas");
                assert_eq!(request["numResults"], 10);
                assert_eq!(request["contents"]["highlights"], true);
                queries += 1;
                ("application/json", json!({"results":[{"title":"Stellar gas", "url":returned_url, "highlights":["Stellar gas"]}]}).to_string())
            } else {
                assert_eq!(target, "/result");
                (
                    "text/html",
                    "<title>Stellar gas</title><p>Stellar gas</p>".to_owned(),
                )
            };
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        assert_eq!(queries, 4);
    });
    let path = std::env::temp_dir().join(format!(
        "fictionet-live-engines-{}.warc.gz",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let live = Arc::new(Live {
        key: Key::new("EXA_API_KEY", Some("host-only-key".into())).unwrap(),
        endpoint: format!("{origin}/search").parse().unwrap(),
        path: path.clone(),
        state: Mutex::default(),
        fetcher: Mutex::default(),
    });
    let mut pages = Pages::new(Seed::builtin("web").unwrap());
    pages.live = Some(live);
    pages
        .live_active
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let pages = Arc::new(pages);
    let memory = Arc::new(fictionet_test_support::EventLog::default());
    fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(8)).observer(memory.clone()), |cx| async move {
            for (host, target) in [
                ("www.google.com", "/search?q=stellar+%26+gas"),
                ("www.bing.com", "/search?q=stellar+%26+gas"),
                ("html.duckduckgo.com", "/html/?q=stellar+%26+gas"),
                ("www.youtube.com", "/results?search_query=stellar+%26+gas"),
            ] {
                let response = pages.handle(&cx, "GET", host, target, None).await;
                assert_eq!(response.status, 200);
                let Meta::Search(list) = response.meta else { panic!("search response expected") };
                assert_eq!(list.listed.len(), 1);
                assert_eq!(list.listed[0].0, result_url);
                assert_eq!(list.carries, 0);
                assert_eq!(pages.live_url(&cx, &result_url).await.status, 200);
            }
            pages.apply(&cx, Command::SetNewPages { new_pages: NewPages::Off, expected_revision: 0 }).unwrap();
            let response = pages.handle(&cx, "GET", "www.google.com", "/search?q=stellar+%26+gas", None).await;
            assert!(matches!(response.meta, Meta::Search(list) if list.cache == Cache::Cached && list.listed.len() == 1));
            Ok(())
        })).unwrap();
    server.join().unwrap();
    let events = memory.all();
    for (kind, count) in [("real_search", 4), ("downloaded", 1), ("copy_served", 4)] {
        assert_eq!(
            events
                .iter()
                .filter(|e| e.source == "web" && e.kind == kind)
                .count(),
            count
        );
    }
    let text = format!("{events:?}");
    assert!(!text.contains("host-only-key"));
    assert!(!text.contains("host-only-engine"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn copies_dependencies_and_same_host_links_through_five_levels() {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let external = origin.replace("127.0.0.1", "localhost");
    let (send, receive) = oneshot::channel();
    let server = std::thread::spawn(move || {
        let mut requested = Vec::new();
        for _ in 0..10 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = line.split_whitespace().nth(1).unwrap().to_owned();
            requested.push(path.clone());
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let (mime, body) = match path.as_str() {
                "/denied" => ("text/html", "<title>Previously disallowed</title>".into()),
                "/" => (
                    "text/html",
                    format!(
                        "<title>Sky</title><link rel='stylesheet' href='/skin.css'><img src='/star.png'><a href='/level/1'>Next</a><a href='/denied'>Denied</a><a href='{external}/outside'>External</a>"
                    ),
                ),
                "/skin.css" => ("text/css", "@font-face{src:url(/font.woff2)}".into()),
                "/font.woff2" => ("font/woff2", "font bytes".into()),
                "/star.png" => ("image/png", "image bytes".into()),
                _ => {
                    let depth: u8 = path
                        .strip_prefix("/level/")
                        .expect("only reached paths")
                        .parse()
                        .unwrap();
                    assert!(depth <= 5);
                    (
                        "text/html",
                        format!(
                            "<title>Level {depth}</title><a href='/level/{}'>Next</a>",
                            depth + 1
                        ),
                    )
                }
            };
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        }
        let _ = send.send(requested);
    });
    let path = std::env::temp_dir().join(format!(
        "fictionet-live-crawl-{}.warc.gz",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let live = Arc::new(Live {
        key: Key::new("EXA_API_KEY", Some("private".into())).unwrap(),
        endpoint: url::Url::parse("https://api.exa.ai/search").unwrap(),
        path: path.clone(),
        state: Mutex::default(),
        fetcher: Mutex::default(),
    });
    let copy = live.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
        |cx| async move {
            assert!(
                live.response(&cx, &format!("{origin}/unreached"))
                    .await
                    .is_none()
            );
            live.enqueue(
                Job {
                    url: format!("{origin}/"),
                    navigation: Some(("127.0.0.1".into(), 0)),
                    redirects: 0,
                    cx: cx.clone(),
                },
                true,
            );
            let requested = cx
                .race(Some(cx.now() + Duration::from_secs(20)), receive)
                .await
                .unwrap()
                .unwrap();
            assert!(
                !requested
                    .iter()
                    .any(|url| url == "/robots.txt" || url == "/level/6" || url == "/outside")
            );
            assert!(
                live.response(&cx, &format!("{origin}/level/5"))
                    .await
                    .unwrap()
                    .status
                    .is_success()
            );
            assert!(
                live.response(&cx, &format!("{origin}/level/6"))
                    .await
                    .is_none()
            );
            assert_eq!(
                live.response(&cx, &format!("{origin}/star.png"))
                    .await
                    .unwrap()
                    .body,
                "image bytes"
            );
            assert_eq!(
                live.response(&cx, &format!("{origin}/star.png"))
                    .await
                    .unwrap()
                    .body,
                "image bytes"
            );
            assert_eq!(live.state().archive.urls().count(), 10);
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
    assert_eq!(Archive::open([path.clone()]).unwrap().urls().count(), 10);
    drop(copy);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn parses_real_result_order_and_rejects_bad_responses() {
    let value = json!({"results":[
        {"title":"Second star", "url":"https://sky.org/second#part", "highlights":["Fainter"]},
        {"title":"First star", "url":"https://sky.org/first", "highlights":["Brighter"]}
    ]});
    let search = parse_results(&value).unwrap();
    assert_eq!(
        search
            .results
            .iter()
            .map(|r| r.title.as_str())
            .collect::<Vec<_>>(),
        ["Second star", "First star"]
    );
    assert_eq!(search.results[0].url, "https://sky.org/second");
    assert!(parse_results(&json!({"error":{"code":403}})).is_err());
    assert!(
        parse_results(&json!({"results":[{"url":"file:///etc/passwd","title":"Local"}]})).is_err()
    );
    assert!(
        parse_results(&json!({"results":[]}))
            .unwrap()
            .results
            .is_empty()
    );
}

#[test]
fn unknown_urls_do_not_fetch_and_completed_copies_survive_mode_changes() {
    let path = std::env::temp_dir().join(format!(
        "fictionet-live-copy-{}.warc.gz",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let live = Arc::new(Live {
        key: Key::new("EXA_API_KEY", Some("private-key".into())).unwrap(),
        endpoint: url::Url::parse("https://api.exa.ai/search").unwrap(),
        path: path.clone(),
        state: Mutex::default(),
        fetcher: Mutex::default(),
    });
    let response = warc::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/html"),
        )]),
        body: "<title>Saved star</title><p>The original bytes</p>".into(),
    };
    live.state()
        .archive
        .append(&path, "https://sky.org/saved", &response)
        .unwrap();
    live.state()
        .reached
        .insert("https://sky.org/saved".into(), watch::channel(true).0);
    let mut pages = Pages::new(Seed::builtin("web").unwrap());
    pages.live = Some(live);
    let pages = Arc::new(pages);
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(9)),
        |cx| async move {
            for revision in [0, 2] {
                pages
                    .apply(
                        &cx,
                        Command::SetNewPages {
                            new_pages: NewPages::LiveSearch,
                            expected_revision: revision,
                        },
                    )
                    .unwrap();
                assert_eq!(pages.new_pages(), NewPages::LiveSearch);
                assert_eq!(
                    pages
                        .handle(&cx, "GET", "sky.org", "/saved", None)
                        .await
                        .body,
                    response.body
                );
                assert_eq!(
                    pages
                        .handle(&cx, "GET", "sky.org", "/unreached", None)
                        .await
                        .status,
                    404
                );
                assert_eq!(pages.live.as_ref().unwrap().state().reached.len(), 1);
                pages
                    .apply(
                        &cx,
                        Command::SetNewPages {
                            new_pages: NewPages::ModelWritten,
                            expected_revision: revision + 1,
                        },
                    )
                    .unwrap_err();
                pages
                    .apply(
                        &cx,
                        Command::SetNewPages {
                            new_pages: NewPages::Off,
                            expected_revision: revision + 1,
                        },
                    )
                    .unwrap();
            }
            assert!(Pages::search_asset("www.google.com", "/search.css").is_some());
            assert!(Pages::search_asset("sky.org", "/search.css").is_none());
            Ok(())
        },
    ))
    .unwrap();
    std::fs::remove_file(path).unwrap();
}
