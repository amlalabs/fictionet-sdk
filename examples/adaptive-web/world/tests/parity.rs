//! The Rust stub and a fresh Python stub answer the same request sequence.
mod common;
use adaptive_web_world::stub::{
    Response, Seed, Stub, links,
    text::{quote, quote_plus, target_of},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
};

fn python_request(
    python: &common::Python,
    method: &str,
    host: &str,
    target: &str,
    form: Option<&[u8]>,
) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", python.port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let data = form.unwrap_or_default();
    write!(stream,"{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n",data.len(),if form.is_some(){"Content-Type: application/x-www-form-urlencoded\r\n"}else{""}).unwrap();
    stream.write_all(data).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_lowercase(), v.trim().into())
        })
        .collect();
    let header = |name| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    };
    let encoded = format!("x={}", header("x-adaptive-meta"));
    let decoded = form_urlencoded::parse(encoded.as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    Response {
        status,
        content_type: header("content-type").into(),
        body: bytes[end + 4..].to_vec(),
        headers: headers
            .into_iter()
            .filter(|(k, _)| ["server", "location"].contains(&k.as_str()))
            .collect(),
        meta: serde_json::from_str(&decoded).unwrap(),
    }
}
fn compare(context: &str, mut rust: Response, mut python: Response) {
    for meta in [&mut rust.meta, &mut python.meta] {
        let m = meta.as_object_mut().unwrap();
        m.shift_remove("gen_ms");
        m.shift_remove("serve_ms");
    }
    assert_eq!(rust.status, python.status, "{context}: status");
    assert_eq!(
        rust.content_type, python.content_type,
        "{context}: content type"
    );
    for name in ["Server", "Location"] {
        let header = |r: &Response| {
            r.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(header(&rust), header(&python), "{context}: {name}");
    }
    if rust.body != python.body {
        let at = rust
            .body
            .iter()
            .zip(&python.body)
            .position(|(a, b)| a != b)
            .unwrap_or(rust.body.len().min(python.body.len()));
        let excerpt = |body: &[u8]| {
            String::from_utf8_lossy(&body[at.saturating_sub(100)..body.len().min(at + 160)])
                .into_owned()
        };
        panic!(
            "{context}: first body difference at byte {at}; Rust {} bytes, Python {} bytes\nRust: {:?}\nPython: {:?}",
            rust.body.len(),
            python.body.len(),
            excerpt(&rust.body),
            excerpt(&python.body)
        );
    }
    assert_eq!(rust.meta, python.meta, "{context}: metadata");
}
fn parity(name: &'static str) {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("adaptive-parity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let python = common::Python::start(name, &here.join("../seeds"), &base, "stub");
    let seed = Seed::builtin(name).unwrap();
    assert_eq!(
        seed.fixed_addresses(),
        adaptive_web_world::fixed_addresses(&python.hello).unwrap()
    );
    let stub = Stub::new(seed.clone());
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
        |cx| async move {
            let ask = |method: &str, host: &str, target: &str, form: Option<&[u8]>| {
                let rust = stub.handle(&cx, method, host, target, form);
                let py = python_request(&python, method, host, target, form);
                compare(
                    &format!("{name}: {method} {host}{target}"),
                    rust.clone(),
                    py,
                );
                rust
            };
            let q = quote_plus(&seed.question);
            let first = ask("GET", "www.google.com", &format!("/search?q={q}"), None);
            let mut urls: Vec<String> = first.meta["listed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["url"].as_str().unwrap().into())
                .collect();
            for (host, path) in [
                ("html.duckduckgo.com", "/html/"),
                ("lite.duckduckgo.com", "/lite/"),
                ("duckduckgo.com", "/"),
                ("www.bing.com", "/search"),
            ] {
                ask("GET", host, &format!("{path}?q={q}"), None);
            }
            ask(
                "POST",
                "html.duckduckgo.com",
                "/html/",
                Some(format!("q={q}").as_bytes()),
            );
            for (host, path) in [
                ("www.google.com", "/search?start=10"),
                ("html.duckduckgo.com", "/html/?s=10"),
                ("www.bing.com", "/search?first=11"),
            ] {
                let second = ask("GET", host, &format!("{path}&q={q}"), None);
                urls.extend(
                    second.meta["listed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v["url"].as_str().unwrap().to_owned()),
                );
            }
            let mut followed = false;
            for url in &urls {
                let (host, target) = target_of(url);
                let page = ask("GET", &host, &target, None);
                ask("GET", &host, &target, None);
                if !followed && page.meta["cache"] == "generated" {
                    let candidates = links(url, std::str::from_utf8(&page.body).unwrap());
                    for part in [
                        "-follow-up",
                        "/archive/2026/",
                        "/wiki/",
                        "/guides/new-phone-settings",
                        "/news/",
                    ] {
                        let (h, t, _) = candidates
                            .iter()
                            .find(|(_, t, _)| t.contains(part))
                            .unwrap_or_else(|| panic!("no {part} link on {url}"));
                        ask("GET", h, t, None);
                    }
                    followed = true;
                }
            }
            assert!(followed);
            let second = ask(
                "GET",
                "www.google.com",
                &format!("/search?q=updated+{q}"),
                None,
            );
            for result in second.meta["listed"].as_array().unwrap() {
                let (host, target) = target_of(result["url"].as_str().unwrap());
                ask("GET", &host, &target, None);
                ask("GET", &host, &target, None);
            }
            for (host, target) in [
                ("nothing-pointed-here.io", "/pricing"),
                ("api.nothing-pointed-here.io", "/items"),
                ("nothing-pointed-here.io", "/items.json"),
                ("nothing-pointed-here.io", "/info.txt"),
                ("www.google.com", "/"),
                ("www.google.com", "/webhp"),
                ("html.duckduckgo.com", "/html/"),
                ("www.bing.com", "/"),
                ("google.com", "/search?q=hello"),
                ("bing.com", "/"),
                ("nothing-pointed-here.io", "/main.css"),
                ("nothing-pointed-here.io", "/photo.png"),
                ("nothing-pointed-here.io", "/font.woff2"),
                ("nothing-pointed-here.io", "/robots.txt"),
                ("nothing-pointed-here.io", "/page?x=one&y=two"),
            ] {
                ask("GET", host, target, None);
            }
            let location = quote("https://nothing-pointed-here.io/a?x=1&y=2", "");
            ask("GET", "www.google.com", &format!("/url?q={location}"), None);
            ask(
                "GET",
                "duckduckgo.com",
                &format!("/l/?uddg={location}"),
                None,
            );
            ask(
                "POST",
                "nothing-pointed-here.io",
                "/form",
                Some(b"q=ignored"),
            );
            for fixed in &seed.fixed {
                ask("GET", &fixed.host, &fixed.target, None);
            }
            // Unicode titles, snippets and entities also reach JSON and link context.
            ask(
                "GET",
                "www.google.com",
                "/search?q=caf%C3%A9+%F0%9F%98%80+%26+%22quotes%22",
                None,
            );
            ask(
                "GET",
                "api.nothing-pointed-here.io",
                "/caf%C3%A9.json",
                None,
            );
            Ok(())
        },
    ))
    .unwrap();
    std::fs::remove_dir_all(base).unwrap();
}
#[test]
fn halvard() {
    parity("halvard-cve");
}
#[test]
fn corvane() {
    parity("corvane-acquisition");
}
#[test]
fn fastjsonl() {
    parity("fastjsonl-package");
}

#[test]
fn generation_switch_matches_python_replay() {
    use adaptive_web_world::stub::Command;
    for capture_fixed in [false, true] {
        let seeds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../seeds");
        let base = std::env::temp_dir().join(format!(
            "adaptive-parity-replay-{capture_fixed}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let stub = Stub::new(Seed::builtin("halvard-cve").unwrap());
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| async move {
                let ask = |python: &common::Python, host: &str, target: &str| {
                    let rust = stub.handle(&cx, "GET", host, target, None);
                    compare(
                        &format!("{host}{target}"),
                        rust.clone(),
                        python_request(python, "GET", host, target, None),
                    );
                    rust
                };
                let python = common::Python::start("halvard-cve", &seeds, &base, "stub");
                let query = ask(&python, "www.google.com", "/search?q=stored");
                let page = ask(&python, "pages.io", "/stored");
                let fixed = &stub.seed().fixed[0];
                if capture_fixed {
                    assert_eq!(ask(&python, &fixed.host, &fixed.target).body, fixed.body);
                }
                drop(python);
                assert_eq!(
                    stub.apply(
                        &cx,
                        Command::SetGeneration {
                            generate: false,
                            expected_revision: 0,
                        }
                    )
                    .unwrap()
                    .revision,
                    1
                );
                let python = common::Python::start("halvard-cve", &seeds, &base, "replay");
                let cached_query = ask(&python, "www.google.com", "/search?q=stored");
                assert_eq!(cached_query.meta["cache"], "cached");
                assert_eq!(cached_query.body, query.body);
                let cached_page = ask(&python, "pages.io", "/stored");
                assert_eq!(cached_page.meta["cache"], "cached");
                assert_eq!(cached_page.body, page.body);
                for (host, target) in [
                    ("www.google.com", "/search?q=new&start=10"),
                    ("html.duckduckgo.com", "/html/?q=new&s=10"),
                    ("www.bing.com", "/search?q=new&first=11"),
                ] {
                    let missing = ask(&python, host, target);
                    assert_eq!(missing.status, 200);
                    assert_eq!(missing.meta["cache"], "missing");
                    assert_eq!(missing.meta["model"], serde_json::Value::Null);
                    assert_eq!(missing.meta["results"], 0);
                    assert_eq!(missing.meta["listed"], serde_json::json!([]));
                }
                for host in ["pages.io", "new-pages.io"] {
                    let missing = ask(&python, host, "/new?a=1&b=2");
                    assert_eq!(missing.status, 404);
                    assert_eq!(missing.meta["cache"], "missing");
                    assert!(missing.meta.get("model").is_none());
                }
                let fixed_response = ask(&python, &fixed.host, &fixed.target);
                assert_eq!(fixed_response.status, if capture_fixed { 200 } else { 404 });
                assert_eq!(
                    fixed_response.meta["cache"],
                    if capture_fixed { "fixed" } else { "missing" }
                );
                if capture_fixed {
                    assert_eq!(fixed_response.body, fixed.body);
                }
                drop(python);
                assert_eq!(
                    stub.apply(
                        &cx,
                        Command::SetGeneration {
                            generate: true,
                            expected_revision: 1,
                        }
                    )
                    .unwrap()
                    .revision,
                    2
                );
                let python = common::Python::start("halvard-cve", &seeds, &base, "stub");
                assert_eq!(
                    ask(&python, "www.google.com", "/search?q=stored").body,
                    query.body
                );
                assert_eq!(ask(&python, "pages.io", "/stored").body, page.body);
                for host in ["pages.io", "new-pages.io"] {
                    let made = ask(&python, host, "/new?a=1&b=2");
                    assert_eq!(made.status, 200);
                    assert_eq!(made.meta["cache"], "generated");
                }
                let made = ask(&python, "www.google.com", "/search?q=new&start=10");
                assert_eq!(made.meta["cache"], "generated");
                assert_eq!(made.meta["results"], 10);
                assert_eq!(ask(&python, &fixed.host, &fixed.target).body, fixed.body);
                drop(python);
                std::fs::remove_dir_all(base).unwrap();
                Ok(())
            },
        ))
        .unwrap();
    }
}

#[test]
fn generation_budget_matches_python() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("adaptive-parity-budget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let python = common::Python::start("halvard-cve", &here.join("../seeds"), &base, "stub");
    let stub = Stub::new(Seed::builtin("halvard-cve").unwrap());
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
        |cx| async move {
            // The cast uses one call, followed by 199 page generations.
            for n in 0..200 {
                let target = format!("/page-{n}.txt");
                let rust = stub.handle(&cx, "GET", "budget-site.io", &target, None);
                assert_eq!(rust.status, if n < 199 { 200 } else { 503 });
                compare(
                    &target,
                    rust,
                    python_request(&python, "GET", "budget-site.io", &target, None),
                );
            }
            let search = stub.handle(&cx, "GET", "www.google.com", "/search?q=exhausted", None);
            assert_eq!(search.status, 503);
            assert_eq!(search.meta["cache"], "budget");
            compare(
                "budget search",
                search,
                python_request(
                    &python,
                    "GET",
                    "www.google.com",
                    "/search?q=exhausted",
                    None,
                ),
            );
            Ok(())
        },
    ))
    .unwrap();
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn every_layout_and_not_found_match_python() {
    use adaptive_web_world::stub::{make, render};
    use serde_json::json;
    use std::process::{Command, Stdio};
    let mut cases = Vec::new();
    let mut rust = Vec::new();
    for kind in [
        "news",
        "blog",
        "company",
        "government",
        "shop",
        "forum",
        "docs",
        "wiki",
        "qa",
        "package",
        "other",
    ] {
        for style in 0..10 {
            let mut profile = make::site_profile("pages.io");
            profile.kind = kind.into();
            profile.style = style;
            profile.nav = vec![" A & B | /a?x=1&y=2 ".into(), " More News ".into()];
            let page = make::Page {
                title: "Écho <&>".into(),
                description: "A \"quote\" and 'apostrophe'".into(),
                body: "<h1>Body</h1>\n<p>Text</p>".into(),
                sidebar: vec![("More & more".into(), "/more?x=1&y=2".into())],
                ad: if style % 2 == 0 {
                    "Save 10% & go".into()
                } else {
                    String::new()
                },
                ..make::Page::default()
            };
            cases.push(json!({"profile":{"name":profile.name,"kind":profile.kind,"style":style,"nav":profile.nav,"footer":profile.footer,"tagline":profile.tagline},
                "page":{"title":page.title,"description":page.description,"body":page.body,"sidebar":page.sidebar,"ad":page.ad}}));
            rust.push(vec![
                render::page("pages.io", &profile, &page, "2026"),
                render::not_found("pages.io", Some(&profile), "/missing?a=1&b=2", "2026"),
            ]);
        }
    }
    let mut child=Command::new("python3").arg("-c")
        .arg("import json,sys; from adaptive import render; print(json.dumps([[render.page('pages.io', c['profile'], c['page'], '2026'), render.not_found('pages.io', c['profile'], '/missing?a=1&b=2', '2026')] for c in json.load(sys.stdin)]))")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backend"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    serde_json::to_writer(&mut stdin, &cases).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let python: Vec<Vec<String>> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rust.len(), python.len());
    for ((rust, python), case) in rust.into_iter().zip(python).zip(cases) {
        for (r, p) in rust.into_iter().zip(python) {
            let response = |s: String| Response {
                status: 200,
                content_type: "text/html".into(),
                body: s.into_bytes(),
                headers: vec![],
                meta: json!({}),
            };
            compare(&case["profile"].to_string(), response(r), response(p));
        }
    }
}
