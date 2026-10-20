//! The embedded renderer and the Python HTTP backend serve the same bytes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Child;
use std::time::Duration;

use example_common::backend_process::{Args, start_backend};
use fakewiki_world::pages::{self, Variant};
use serde_json::{Value, json};

const ARTICLES: &[&str] = &[
    "Television_licensing_in_the_United_Kingdom",
    "Stream_ripping",
    "Apollo_11",
];
const WIKI: &str = "en.wikipedia.org";
struct Backend(Child);
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
fn request(port: u16, host: &str, path: &str, method: &str, variant: Option<&str>) -> Answer {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut text = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n"
    );
    if let Some(v) = variant {
        text.push_str(&format!("X-Fakewiki-Variant: {v}\r\n"));
    }
    text.push_str("\r\n");
    // BaseHTTPRequestHandler decodes the request line as Latin-1.
    let bytes: Vec<u8> = text
        .chars()
        .map(|c| u8::try_from(c as u32).expect("encode Unicode paths with percent escapes"))
        .collect();
    conn.write_all(&bytes).unwrap();
    let mut bytes = Vec::new();
    conn.read_to_end(&mut bytes).unwrap();
    let end = bytes
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .expect("HTTP headers");
    let head: String = bytes[..end].iter().map(|b| *b as char).collect();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_lowercase(), v.trim().to_owned())
        })
        .collect();
    Answer {
        status,
        headers,
        body: bytes[end + 4..].to_vec(),
    }
}

fn requests() -> Vec<(String, String, String)> {
    let mut requests = Vec::new();
    let mut get = |host: &str, path: &str| requests.push((host.into(), path.into(), "GET".into()));
    let mut hosts: Vec<_> = pages::host_ips().into_keys().collect();
    hosts.sort();
    for host in &hosts {
        for path in [
            "/",
            "/robots.txt",
            "/missing",
            "/raw%2Fpath?q=a+b&q=%26&blank=",
        ] {
            get(host, path);
        }
    }
    for (host, paths) in [
        (
            "www.gov.uk",
            vec![
                "/tv-licence",
                "/find-licences/tv-licence",
                "/guidance/exceptions-to-copyright",
            ],
        ),
        (
            "www.bbc.co.uk",
            vec![
                "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
                "/iplayer/help/tv-licence",
                "/news/articles/c9w1r2lx7kpo",
                "/news/articles/cd7e3v8n2x1o",
            ],
        ),
        (
            "www.bbc.com",
            vec![
                "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
                "/news/articles/c9w1r2lx7kpo",
                "/news/articles/cd7e3v8n2x1o",
            ],
        ),
        (
            "www.tvlicensing.co.uk",
            vec![
                "/check-if-you-need-one",
                "/check-if-you-need-one/topics/bbc-iplayer-and-the-tv-licence",
            ],
        ),
        ("www.nasa.gov", vec!["/mission/apollo-11"]),
    ] {
        for path in paths {
            get(host, path);
            get(host, &format!("{path}/"));
            if host == "www.gov.uk" {
                get(host, &format!("/api/content{path}"));
                get(host, &format!("/api/content{path}/"));
            }
        }
    }
    get("www.gov.uk", "/api/content/missing");
    for host in [
        "duckduckgo.com",
        "html.duckduckgo.com",
        "lite.duckduckgo.com",
        "www.google.com",
        "www.bing.com",
        "search.brave.com",
        "www.gov.uk",
        "www.bbc.co.uk",
        "www.bbc.com",
    ] {
        for term in [
            "tv+licence+iplayer",
            "stream+ripping+legal+uk",
            "Apollo+11",
            "zzzzqqqq",
            "",
            "%C3%A9%F0%9F%98%80",
            "licence+copying+act",
        ] {
            get(host, &format!("/search?q={term}"));
        }
        for query in [
            "query=tv+licence",
            "keywords=stream+ripping",
            "q=tv&q=apollo",
            "q=&query=apollo",
            "q=&keywords=apollo",
            "q=apollo&q=",
            "q=the+a+an+of+in",
            "q=a%26b%3D%22%27%3C",
            "q=%FF%C3%28",
            "q=apollo;stream",
        ] {
            get(host, &format!("/search?{query}"));
        }
    }
    get(
        "html.duckduckgo.com",
        "/html/?q=do+i+need+a+tv+licence+for+iplayer",
    );
    for title in ARTICLES {
        for host in [WIKI, "en.m.wikipedia.org"] {
            get(host, &format!("/wiki/{title}"));
        }
        for action in [
            "view", "raw", "history", "edit", "submit", "info", "unknown", "",
        ] {
            get(WIKI, &format!("/wiki/{title}?action={action}"));
            get(WIKI, &format!("/w/index.php?title={title}&action={action}"));
        }
        for query in [
            "oldid=1000003",
            "diff=prev&oldid=1000001",
            "oldid=",
            "diff=",
            "action=raw&action=view",
            "action=&action=raw",
        ] {
            get(WIKI, &format!("/w/index.php?title={title}&{query}"));
        }
        for props in [
            "extracts",
            "revisions",
            "info",
            "extracts%7Crevisions%7Cinfo",
            "",
        ] {
            for extra in [
                "",
                "&explaintext=1&exintro=1",
                "&explaintext=&exintro=",
                "&explaintext=1",
            ] {
                get(
                    WIKI,
                    &format!(
                        "/w/api.php?action=query&prop={props}&titles={title}&format=json{extra}"
                    ),
                );
            }
        }
        for props in ["wikitext", "text", ""] {
            get(
                WIKI,
                &format!("/w/api.php?action=parse&page={title}&prop={props}&format=json"),
            );
        }
        get(
            WIKI,
            &format!("/w/api.php?action=query&prop=extracts&titles={title}&format=xml"),
        );
        get(
            WIKI,
            &format!("/w/api.php?action=query&list=search&srsearch={title}&format=json"),
        );
        get(
            WIKI,
            &format!("/w/api.php?action=opensearch&search={title}"),
        );
        for view in [
            "summary",
            "html",
            "mobile-html",
            "mobile-sections",
            "title",
            "segments",
        ] {
            get(WIKI, &format!("/api/rest_v1/page/{view}/{title}"));
        }
        get(WIKI, &format!("/api/rest_v1/page/summary/{title}/extra"));
        for view in ["", "/html", "/with_html", "/history", "/bare"] {
            get(WIKI, &format!("/w/rest.php/v1/page/{title}{view}"));
        }
        get(WIKI, &format!("/w/rest.php/v1/search/page?q={title}"));
        for special in [
            "Export",
            "History",
            "PageHistory",
            "PermanentLink",
            "Diff",
            "WhatLinksHere",
        ] {
            get(WIKI, &format!("/wiki/Special:{special}/{title}"));
        }
        get(WIKI, &format!("/wiki/Special:Export?pages={title}"));
        get(WIKI, &format!("/w/index.php?title=Special:Export/{title}"));
        get(
            WIKI,
            &format!("/wiki/Special:Search?search={title}&fulltext=1"),
        );
        get(WIKI, &format!("/wiki/Special:Search/{title}"));
        get(
            WIKI,
            &format!("/wiki/Special:Search?search={title}&fulltext=&go=1"),
        );
    }
    for title in [
        "TV_licence",
        "Television_licence",
        "TV_Licence",
        "TV_Licensing",
        "Television_licence_in_the_United_Kingdom",
        "TV_licensing_in_the_United_Kingdom",
        "Television_licence_(United_Kingdom)",
        "Licence_fee",
        "Stream-ripping",
        "Streamripping",
        "YouTube-to-MP3",
        "YouTube_to_MP3",
        "Apollo_XI",
        "apollo_11",
        "sTrEaM_rIpPiNg",
        "%41pollo%5f11",
        "Apollo%2011",
        "%20Apollo_11%20",
        "Caf%C3%A9",
        "Café",
        "%F0%9F%98%80",
        "%FF%C3%28",
        "A%26%22%27%3C%3E",
        "Missing/title",
        "",
    ] {
        get(WIKI, &format!("/wiki/{title}"));
    }
    for path in [
        "/wiki",
        "/wiki/",
        "/wiki/Main_Page",
        "//wiki/Apollo_11",
        "///wiki/Apollo_11?oldid=1",
        "/w/index.php",
        "/w/index.php?search=apollo",
        "/w/index.php?search=zzqq",
        "/w/index.php?title=Apollo+11",
        "/w/index.php?title=Missing&title=Apollo_11",
        "/w/index.php?title=Apollo_11&title=",
        "/w/api.php",
        "/w/api.php?action=query",
        "/w/api.php?action=query&titles=Missing%7CApollo_11%7CStream_ripping%7CApollo_11%7C&prop=extracts%7Cinfo",
        "/w/api.php?action=query&page=Apollo_11&prop=extracts",
        "/w/api.php?action=query&titles=&page=Apollo_11",
        "/w/api.php?action=parse&page=Missing",
        "/w/api.php?action=parse&page=Missing&titles=Apollo_11",
        "/w/api.php?action=unknown&titles=Apollo_11",
        "/w/api.php?action=%C3%A9%22%26",
        "/w/api.php?action=query&titles=Caf%C3%A9%7C%F0%9F%98%80%7C%7F",
        "/w/api.php?action=query&list=search&srsearch=zzqq",
        "/w/api.php?action=query&list=search&srsearch=",
        "/w/api.php?action=opensearch&search=zzqq",
        "/w/api.php?action=opensearch&search=%C3%A9%7F%F0%9F%98%80",
        "/api/rest_v1/missing",
        "/api/rest_v1/page/nope/Apollo_11",
        "/api/rest_v1/page/summary/",
        "/api/rest_v1/page/summary/Missing",
        "/w/rest.php/v1/missing",
        "/w/rest.php/v1/page/Missing",
        "/w/rest.php/v1/page/Apollo_11/unknown",
        "/w/rest.php/v1/page/Apollo_11/",
        "/w/rest.php/v1/search/page?q=zzqq",
        "/w/rest.php/v1/search/page?q=",
        "/w/rest.php/v1/search/title?q=apollo",
        "/wiki/http://example.com/path",
        "/wiki/http://example.com?query=1",
        "https://en.wikipedia.org/wiki/Apollo_11?oldid=1",
        "/w/rest.php/v1/page/Apollo_11/html%0A",
        "/w/rest.php/v1/page/Apollo_11/html%0A%0A",
        "/w/rest.php/v1/page/Apollo_11%0A",
        "/wiki/Special:PermanentLink/%C2%B2",
        "/wiki/Special:PermanentLink/%C2%BD",
        "/wiki/Special:Diff/%D9%A3",
        "/wiki/Special:Diff/%E2%85%A3",
        "/wiki/Special:Random",
        "/wiki/Special:RecentChanges",
        "/wiki/Special:WhatLinksHere/Missing",
        "/wiki/Special:NoSuchPage",
        "/wiki/Special:Export/Missing",
        "/wiki/Special:Export",
        "/wiki/Special:History/Missing",
        "/wiki/Special:PageHistory/Missing",
        "/wiki/Special:PermanentLink/1000000",
        "/wiki/Special:Diff/123",
        "/wiki/Special:PermanentLink/Missing",
        "/wiki/Special:Diff/",
        "/wiki/Special:Search?search=zzqq&fulltext=1",
        "/wiki/Special:Search",
        "/wiki/Special:search/Apollo_11?search=&fulltext=",
        "/w/index.php?title=Special:RecentChanges",
        "/w/index.php?title=Special:Search&search=Apollo+11",
    ] {
        get(WIKI, path);
    }
    for section in ["/ukpga/2003/21/section/363", "/ukpga/1988/48/section/28B"] {
        for suffix in [
            "",
            "/",
            "/enacted",
            "/data.xml",
            "/enacted/data.xml",
            "/data.xml/",
            "/missing",
        ] {
            get("www.legislation.gov.uk", &format!("{section}{suffix}"));
        }
    }
    for act in ["/ukpga/2025/43", "/ukpga/2024/57"] {
        for suffix in [
            "",
            "/",
            "/contents",
            "/enacted",
            "/data.xml",
            "/contents/data.xml",
            "/section/1",
        ] {
            get("www.legislation.gov.uk", &format!("{act}{suffix}"));
        }
    }
    for route in ["/all", "/search", "/ukpga"] {
        for query in [
            "title=Broadcasting+Licence+Abolition",
            "title=Digital+Media+Consumer+Rights+Act+2024",
            "title=tv+licence",
            "text=private+copying",
            "title=Communications",
            "title=Copyright",
            "title=Act+licence+copying",
            "title=zzqq",
            "title=",
            "title=&text=copying",
            "title=tv&title=copyright",
            "title=copying%09licence",
            "title=copying%C2%A0licence",
        ] {
            get("www.legislation.gov.uk", &format!("{route}?{query}"));
        }
    }
    get("EN.WIKIPEDIA.ORG.:443", "/wiki/Apollo_11");
    get("unknown.example", "/");
    get("duckduckgo.com", "http://duckduckgo.com?q=Apollo");
    for method in ["HEAD", "POST", "PUT"] {
        for (host, path) in [
            (WIKI, "/wiki/Apollo_11"),
            (WIKI, "/wiki"),
            ("www.gov.uk", "/api/content/tv-licence"),
            (WIKI, "/missing"),
        ] {
            requests.push((host.into(), path.into(), method.into()));
        }
    }
    requests
}

fn compare(answer: &Answer, rendered: &pages::Response, context: &str, method: &str) {
    assert_eq!(answer.status, rendered.status, "status: {context}");
    for (name, value) in [
        ("x-fakewiki-kind", Some(rendered.kind)),
        ("x-fakewiki-topic", rendered.topic.as_deref()),
        ("x-fakewiki-source", rendered.source.as_deref()),
        ("x-fakewiki-stance", rendered.stance),
    ] {
        let actual = answer.headers.get(name).map(String::as_str);
        if name == "x-fakewiki-kind" {
            assert_eq!(
                actual.unwrap_or("other"),
                value.unwrap(),
                "{name}: {context}"
            );
        } else {
            assert_eq!(actual, value, "{name}: {context}");
        }
    }
    if !matches!(method, "GET" | "HEAD" | "POST") {
        return;
    }
    for (name, value) in [
        ("content-type", Some(rendered.content_type.to_owned())),
        ("content-length", Some(rendered.content_length.to_string())),
        ("location", rendered.location.clone()),
        ("cache-control", rendered.cache_control.map(str::to_owned)),
    ] {
        assert_eq!(
            answer.headers.get(name),
            value.as_ref(),
            "{name}: {context}"
        );
    }
    assert!(
        answer.body == rendered.body,
        "body: {context}\nPython: {}\nRust: {}",
        String::from_utf8_lossy(&answer.body),
        String::from_utf8_lossy(&rendered.body)
    );
}

#[test]
fn pages_match_the_backend() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // SAFETY: this binary has one test, and sets these before starting threads.
    unsafe {
        std::env::set_var("FAKEWIKI_CORPUS", here.join("../fixtures/corpus.json"));
        std::env::set_var("FAKEWIKI_VARIANT", "altered_all");
    }
    let args = Args {
        observation: None,
        socket: String::new(),
        ca_dir: PathBuf::new(),
        backend: here.join("backend"),
        backend_port: port,
        state_dir: PathBuf::new(),
        ready: PathBuf::new(),
    };
    let (startup, child) = start_backend(&args).unwrap();
    let _backend = Backend(child);
    assert_eq!(startup["hosts"], json!(pages::host_ips()));
    let docs: Vec<Value> = pages::documents(Variant::AlteredAll)
        .iter()
        .map(|d| json!({"url":d.url,"topic":d.topic,"source":d.source,"stance":d.stance}))
        .collect();
    assert_eq!(startup["documents"], json!(docs));
    let requests = requests();
    for variant in [Variant::Control, Variant::AlteredOne, Variant::AlteredAll] {
        for (host, path, method) in &requests {
            let context = format!("{} {method} {host}{path}", variant.as_str());
            let answer = request(port, host, path, method, Some(variant.as_str()));
            let random = if path == "/wiki/Special:Random" {
                let location = answer.headers.get("location").unwrap();
                ARTICLES
                    .iter()
                    .position(|t| location == &format!("https://{host}/wiki/{t}"))
                    .expect("random article belongs to the corpus") as u64
            } else {
                0
            };
            compare(
                &answer,
                &pages::handle(host, path, method, variant, random),
                &context,
                method,
            );
        }
    }
    for method in ["GET", "HEAD", "POST"] {
        let path = "/wiki/Apollo_11";
        let answer = request(port, WIKI, path, method, None);
        compare(
            &answer,
            &pages::handle(WIKI, path, method, Variant::AlteredAll, 0),
            "default variant",
            method,
        );
        for variant in ["unknown", "", "CONTROL"] {
            let answer = request(port, WIKI, path, method, Some(variant));
            assert_eq!(answer.status, 400);
            assert!(!answer.headers.keys().any(|h| h.starts_with("x-fakewiki-")));
            if method == "HEAD" {
                assert!(answer.body.is_empty());
            }
        }
    }
    eprintln!("compared {} requests per variant", requests.len());
}
