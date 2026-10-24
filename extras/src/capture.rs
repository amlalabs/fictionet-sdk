//! Host side HTTP capture and discovery of page requisites.

use crate::warc;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use std::{
    collections::HashMap,
    io::{self, Read},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;

/// An ordinary desktop browser identity for host side live copies.
pub const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

/// The reason for one host HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Query the configured search provider.
    Search,
    /// Copy a reached page, redirect or dependency.
    Capture,
}

/// A credential-free lifecycle event for a host request.
#[derive(Clone, Debug)]
pub struct Event {
    /// Correlates the attempt and its terminal outcome.
    pub attempt: u64,
    /// Destination without user information, query or fragment.
    pub url: Url,
    /// HTTP method sent to the destination.
    pub method: http::Method,
    /// Why the host is making this request.
    pub purpose: Purpose,
    /// Attempt or terminal outcome.
    pub phase: crate::models::UpstreamPhase,
    /// Status only when response headers arrived.
    pub status: Option<http::StatusCode>,
}

/// Observes actual host transport operations, excluding payloads and credentials.
pub type Observer = dyn Fn(&fictionet::Cx, &Event) + Send + Sync;

struct Attempt<'a> {
    cx: &'a fictionet::Cx,
    observer: &'a Observer,
    event: Event,
}

impl Attempt<'_> {
    fn finish(&mut self, phase: crate::models::UpstreamPhase, status: Option<http::StatusCode>) {
        self.event.phase = phase;
        self.event.status = status;
        (self.observer)(self.cx, &self.event);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.event.phase == crate::models::UpstreamPhase::Attempt {
            self.finish(crate::models::UpstreamPhase::Cancelled, None);
        }
    }
}

#[derive(Clone, Copy)]
enum Network {
    Public,
    Loopback,
}

impl Network {
    fn permits(self, address: IpAddr) -> bool {
        match self {
            Self::Loopback => address.is_loopback(),
            Self::Public => match address {
                IpAddr::V4(ip) => {
                    let [a, b, c, _] = ip.octets();
                    !ip.is_private()
                        && !ip.is_loopback()
                        && !ip.is_link_local()
                        && !ip.is_documentation()
                        && !ip.is_broadcast()
                        && !matches!(a, 0 | 224..=255)
                        && !(a == 100 && (64..=127).contains(&b))
                        && !(a == 192 && b == 0 && c == 0)
                        && !(a == 192 && b == 88 && c == 99)
                        && !(a == 198 && matches!(b, 18 | 19))
                }
                IpAddr::V6(ip) => {
                    if let Some(ip) = ip.to_ipv4_mapped() {
                        return self.permits(ip.into());
                    }
                    let [a, b, ..] = ip.segments();
                    // Global unicast, excluding protocol assignments and documentation.
                    (a & 0xe000) == 0x2000
                        && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                        && !(a == 0x2002)
                        && !(a == 0x3fff && b < 0x1000)
                }
            },
        }
    }

    fn addresses(self, url: &Url) -> io::Result<Vec<SocketAddr>> {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| io::Error::other("missing port"))?;
        let addresses = match url.host().ok_or_else(|| io::Error::other("missing host"))? {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
            url::Host::Domain(host) => (host, port).to_socket_addrs()?.collect(),
        };
        if addresses.is_empty() || addresses.iter().any(|address| !self.permits(address.ip())) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination is outside the capture network",
            ));
        }
        Ok(addresses)
    }
}

/// A serial downloader confined to public destinations. Redirects are returned
/// for archival and must pass the same destination checks on the next request.
pub struct Fetcher {
    user_agent: String,
    network: Network,
    hosts: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
    api_times: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
    observer: Option<(fictionet::Cx, Arc<Observer>)>,
}

impl Fetcher {
    /// Build a public-network downloader without ambient proxies or cookies.
    pub fn new(user_agent: &str) -> io::Result<Self> {
        Ok(Self {
            user_agent: user_agent.into(),
            network: Network::Public,
            hosts: Default::default(),
            api_times: Default::default(),
            observer: None,
        })
    }

    /// Build a transport confined to loopback servers for in-process fixtures.
    /// It cannot connect to public or private-network destinations.
    pub fn loopback(user_agent: &str) -> io::Result<Self> {
        Ok(Self {
            network: Network::Loopback,
            ..Self::new(user_agent)?
        })
    }

    /// A downloader sharing the same network capability, identity and rate limits.
    pub fn fresh(&self) -> Self {
        Self {
            user_agent: self.user_agent.clone(),
            network: self.network,
            hosts: self.hosts.clone(),
            api_times: self.api_times.clone(),
            observer: None,
        }
    }

    /// Attach the run's observation destination to every subsequent request.
    pub fn observe(&mut self, cx: fictionet::Cx, observer: Arc<Observer>) {
        self.observer = Some((cx, observer));
    }

    fn request(
        &self,
        url: &str,
        search: Option<(&str, &serde_json::Value)>,
    ) -> io::Result<warc::Response> {
        let url = Url::parse(&warc::key(url).ok_or_else(|| io::Error::other("not an HTTP URL"))?)
            .map_err(io::Error::other)?;
        let mut attempt = self.observer.as_ref().map(|(cx, observer)| {
            let mut destination = url.clone();
            let _ = destination.set_username("");
            let _ = destination.set_password(None);
            destination.set_query(None);
            let event = Event {
                attempt: cx.random_u64(),
                url: destination,
                method: if search.is_some() {
                    http::Method::POST
                } else {
                    http::Method::GET
                },
                purpose: if search.is_some() {
                    Purpose::Search
                } else {
                    Purpose::Capture
                },
                phase: crate::models::UpstreamPhase::Attempt,
                status: None,
            };
            observer(cx, &event);
            Attempt {
                cx,
                observer: observer.as_ref(),
                event,
            }
        });
        let response = (|| {
            self.check_cancelled()?;
            if !url.username().is_empty() || url.password().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "URL credentials are not accepted",
                ));
            }
            let addresses = self.network.addresses(&url)?;
            // Pin the checked answers to this dial; no second DNS lookup, pooled
            // connection or ambient proxy can choose a different destination.
            let client = reqwest::blocking::Client::builder()
                .user_agent(&self.user_agent)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(20))
                .resolve_to_addrs(url.host_str().expect("HTTP host"), &addresses)
                .build()
                .map_err(io::Error::other)?;
            self.check_cancelled()?;
            let request = if let Some((key, body)) = search {
                client
                    .post(url)
                    .header("x-api-key", key)
                    .header("content-type", "application/json")
                    .body(body.to_string())
            } else {
                client.get(url).header("accept-encoding", "identity")
            };
            request.send().map_err(io::Error::other)
        })();
        if let Some(attempt) = &mut attempt {
            match &response {
                Ok(response) => attempt.finish(
                    crate::models::UpstreamPhase::Response,
                    Some(response.status()),
                ),
                Err(error) => attempt.finish(
                    if error.kind() == io::ErrorKind::Interrupted {
                        crate::models::UpstreamPhase::Cancelled
                    } else {
                        crate::models::UpstreamPhase::Failed
                    },
                    None,
                ),
            }
        }
        Self::capture(response?)
    }

    fn check_cancelled(&self) -> io::Result<()> {
        if self
            .observer
            .as_ref()
            .is_some_and(|(cx, _)| cx.is_cancelled())
        {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "capture cancelled",
            ))
        } else {
            Ok(())
        }
    }

    /// Read an explicitly named endpoint without crawler discovery.
    pub fn api(&self, url: &str) -> io::Result<warc::Response> {
        let parsed = Url::parse(url).map_err(io::Error::other)?;
        let mut times = self.api_times.lock().unwrap_or_else(|e| e.into_inner());
        let next = times
            .entry(parsed.host_str().unwrap_or_default().to_owned())
            .or_insert_with(Instant::now);
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        *next = Instant::now() + Duration::from_millis(250);
        drop(times);
        self.request(url, None)
    }

    fn capture(response: reqwest::blocking::Response) -> io::Result<warc::Response> {
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        response.take(32 * 1024 * 1024 + 1).read_to_end(&mut body)?;
        if body.len() > 32 * 1024 * 1024 {
            return Err(io::Error::other("response exceeds capture size limit"));
        }
        Ok(warc::Response {
            status,
            headers,
            body: body.into(),
        })
    }

    /// Fetch at most twice per second per host, independent of robots.txt.
    pub fn fetch(&mut self, url: &str) -> io::Result<warc::Response> {
        let parsed = Url::parse(url).map_err(io::Error::other)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| io::Error::other("missing host"))?;
        let mut hosts = self.hosts.lock().unwrap_or_else(|error| error.into_inner());
        let next = hosts.entry(host.to_owned()).or_insert_with(Instant::now);
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        let response = self.api(url);
        hosts.insert(host.to_owned(), Instant::now() + Duration::from_millis(500));
        response
    }

    /// Send a JSON search request with an API key in its header.
    pub fn search(
        &self,
        url: &str,
        key: &str,
        body: &serde_json::Value,
    ) -> io::Result<warc::Response> {
        self.request(url, Some((key, body)))
    }
}

/// URLs discovered in a response, separated by navigation and page requisites.
#[derive(Default, Debug)]
pub struct Links {
    /// Navigable links. The caller enforces site and depth restrictions.
    pub pages: Vec<String>,
    /// CSS, scripts, images, fonts and nested CSS requisites.
    pub assets: Vec<String>,
}

fn css(text: &str, base: &Url, out: &mut Vec<String>) {
    static URLS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let regex = URLS.get_or_init(|| {
        Regex::new(r#"(?i)url\(\s*["']?([^\s\)"']+)|@import\s+["']([^"']+)"#).unwrap()
    });
    for captures in regex.captures_iter(text) {
        if let Some(value) = captures.get(1).or_else(|| captures.get(2))
            && let Some(url) = base
                .join(value.as_str())
                .ok()
                .and_then(|u| warc::key(u.as_str()))
        {
            out.push(url);
        }
    }
}

fn srcset(mut input: &str, base: &Url, out: &mut Vec<String>) {
    while !input.is_empty() {
        input = input.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if input.is_empty() {
            break;
        }
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        let candidate = &input[..end];
        input = &input[end..];
        if !candidate.ends_with(',') {
            input = input.split_once(',').map_or("", |(_, rest)| rest);
        }
        if let Some(url) = base
            .join(candidate.trim_end_matches(','))
            .ok()
            .and_then(|u| warc::key(u.as_str()))
        {
            out.push(url);
        }
    }
}

/// Discover static dependencies using the response's base URL and HTML base tag.
pub fn links(url: &str, response: &warc::Response) -> io::Result<Links> {
    let mut links = Links::default();
    let base = Url::parse(url).map_err(io::Error::other)?;
    if response.status.is_redirection() {
        if let Some(next) = response
            .headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| base.join(v).ok())
            .and_then(|u| warc::key(u.as_str()))
        {
            links.pages.push(next);
        }
        return Ok(links);
    }
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !(content_type.starts_with("text/html") || content_type.starts_with("text/css")) {
        return Ok(links);
    }
    let decoded = response.decoded()?;
    let text = String::from_utf8_lossy(&decoded);
    if content_type.starts_with("text/css") {
        css(&text, &base, &mut links.assets);
        return Ok(links);
    }
    let dom = kuchiki::parse_html().one(text.into_owned());
    let base = dom
        .select_first("base[href]")
        .ok()
        .and_then(|node| {
            node.attributes
                .borrow()
                .get("href")
                .and_then(|href| base.join(href).ok())
        })
        .unwrap_or(base);
    for node in dom.select("a[href], area[href]").unwrap() {
        if let Some(url) = node
            .attributes
            .borrow()
            .get("href")
            .and_then(|v| base.join(v).ok())
            .and_then(|u| warc::key(u.as_str()))
        {
            links.pages.push(url);
        }
    }
    for node in dom
        .select("[src], [srcset], [poster], link[href], [style], style, object[data]")
        .unwrap()
    {
        let attrs = node.attributes.borrow();
        if let Some(url) = attrs
            .get("poster")
            .and_then(|v| base.join(v).ok())
            .and_then(|u| warc::key(u.as_str()))
        {
            links.assets.push(url);
        }
        if matches!(
            node.name.local.as_ref(),
            "audio" | "video" | "track" | "iframe"
        ) || (node.name.local.as_ref() == "source"
            && !node.as_node().parent().is_some_and(|p| {
                p.as_element()
                    .is_some_and(|e| e.name.local.as_ref() == "picture")
            }))
        {
            continue;
        }
        for name in ["src", "data"] {
            if let Some(url) = attrs
                .get(name)
                .and_then(|v| base.join(v).ok())
                .and_then(|u| warc::key(u.as_str()))
            {
                links.assets.push(url);
            }
        }
        if let Some(srcset) = attrs.get("srcset") {
            self::srcset(srcset, &base, &mut links.assets);
        }
        if node.name.local.as_ref() == "link"
            && attrs.get("rel").is_some_and(|r| {
                r.split_whitespace()
                    .any(|v| matches!(v, "stylesheet" | "icon" | "preload" | "modulepreload"))
            })
            && let Some(url) = attrs
                .get("href")
                .and_then(|v| base.join(v).ok())
                .and_then(|u| warc::key(u.as_str()))
        {
            links.assets.push(url);
        }
        if let Some(style) = attrs.get("style") {
            css(style, &base, &mut links.assets);
        }
        if node.name.local.as_ref() == "style" {
            css(&node.text_contents(), &base, &mut links.assets);
        }
    }
    links.assets.sort();
    links.assets.dedup();
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_connections_exclude_special_address_ranges_and_local_dns() {
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
            assert!(
                !Network::Public.permits(address.parse().unwrap()),
                "{address}"
            );
        }
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(
                Network::Public.permits(address.parse().unwrap()),
                "{address}"
            );
        }
        assert!(
            Network::Public
                .addresses(&"http://localhost/".parse().unwrap())
                .is_err()
        );
        for url in [
            "http://127.1/",
            "http://2130706433/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert!(Fetcher::new(BROWSER).unwrap().api(url).is_err(), "{url}");
        }
    }

    #[test]
    fn blocked_requests_finish_their_records_without_credentials() {
        use crate::models::UpstreamPhase;
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(4),
            |cx| async move {
                let events = Arc::new(std::sync::Mutex::new(Vec::new()));
                let seen = events.clone();
                let mut fetcher = Fetcher::new(BROWSER)?;
                fetcher.observe(
                    cx.clone(),
                    Arc::new(move |_, event| seen.lock().unwrap().push(event.clone())),
                );
                assert!(
                    fetcher
                        .api("http://user:password@127.0.0.1/private?token=secret#fragment")
                        .is_err()
                );
                assert!(
                    fetcher
                        .search(
                            "http://[::1]/search?key=secret",
                            "host-only-key",
                            &serde_json::json!({"query":"private"})
                        )
                        .is_err()
                );
                let events = events.lock().unwrap();
                assert_eq!(events.len(), 4);
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
                assert_eq!(events[0].purpose, Purpose::Capture);
                assert_eq!(events[2].purpose, Purpose::Search);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn redirects_are_returned_and_their_destinations_are_checked_again() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write!(socket, "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let fetcher = Fetcher::loopback(BROWSER).unwrap();
        let response = fetcher.api(&origin).unwrap();
        assert_eq!(response.status, 302);
        let destination = response.headers[http::header::LOCATION].to_str().unwrap();
        assert!(fetcher.api(destination).is_err());
        assert!(Fetcher::new(BROWSER).unwrap().api(destination).is_err());
        server.join().unwrap();
    }

    #[test]
    fn cancelled_runs_do_not_start_another_connection() {
        use crate::models::UpstreamPhase;
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(6),
            |cx| async move {
                let phases = Arc::new(std::sync::Mutex::new(Vec::new()));
                let seen = phases.clone();
                let mut fetcher = Fetcher::new(BROWSER)?;
                fetcher.observe(
                    cx.clone(),
                    Arc::new(move |_, event| seen.lock().unwrap().push(event.phase)),
                );
                cx.cancel();
                assert_eq!(
                    fetcher.api("https://www.cisa.gov/").unwrap_err().kind(),
                    io::ErrorKind::Interrupted
                );
                assert_eq!(
                    *phases.lock().unwrap(),
                    [UpstreamPhase::Attempt, UpstreamPhase::Cancelled]
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    fn response(mime: &'static str, body: &'static str) -> warc::Response {
        warc::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(mime),
            )]),
            body: body.into(),
        }
    }

    #[test]
    fn keeps_commas_in_image_urls_and_copies_video_posters_without_media_streams() {
        let links = links("https://sky.org/article", &response("text/html", r#"
            <img srcset="https://maps.sky.org/osm,9,30,40/250.png 1x, https://maps.sky.org/osm,9,30,40/500.png 2x">
            <video poster="poster.jpg" src="movie.webm"><source src="movie.mp4"></video>
        "#)).unwrap();
        assert_eq!(
            links.assets,
            [
                "https://maps.sky.org/osm,9,30,40/250.png",
                "https://maps.sky.org/osm,9,30,40/500.png",
                "https://sky.org/poster.jpg"
            ]
        );
    }

    #[test]
    fn discovers_nested_css_and_html_dependencies_without_treating_navigation_as_assets() {
        let links = links("https://sky.org/article", &response("text/html", r#"
            <base href="/content/"><a href="next#part">Next</a><a href="https://elsewhere.org/">Outside</a>
            <link rel="stylesheet" href="skin.css"><link rel="canonical" href="https://sky.org/article">
            <img src="a.png" srcset="a.png 1x, b.png 2x"><style>@import 'more.css';p{background:url(../stars.svg)}</style>
            <span style="background:url('inline.png')"></span><script src="skin.js"></script>
        "#)).unwrap();
        assert_eq!(
            links.pages,
            ["https://sky.org/content/next", "https://elsewhere.org/"]
        );
        assert_eq!(
            links.assets,
            [
                "a.png",
                "b.png",
                "inline.png",
                "more.css",
                "skin.css",
                "skin.js"
            ]
            .map(|p| format!("https://sky.org/content/{p}"))
            .into_iter()
            .chain(["https://sky.org/stars.svg".into()])
            .collect::<Vec<_>>()
        );
        let links = super::links("https://sky.org/css/skin.css", &response("text/css", "@import \"other.css\";@font-face{src:url(../font.woff2)}p{background:url(data:image/png;base64,AAAA)}")).unwrap();
        assert_eq!(
            links.assets,
            [
                "https://sky.org/css/other.css",
                "https://sky.org/font.woff2"
            ]
        );
        assert!(links.pages.is_empty());
    }

    #[test]
    fn missing_pages_have_stylesheets_and_images_too() {
        let mut missing = response(
            "text/html",
            "<title>Not found</title><link rel='stylesheet' href='/site.css'><img src='/logo.svg'>",
        );
        missing.status = http::StatusCode::NOT_FOUND;
        let links = super::links("https://source.org/404", &missing).unwrap();
        assert_eq!(
            links.assets,
            ["https://source.org/logo.svg", "https://source.org/site.css"]
        );
    }

    #[test]
    fn requests_ignore_robots_and_remain_rate_limited() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut times = Vec::new();
            for path in ["/denied", "/allowed", "/another"] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                assert!(request.starts_with(&format!("GET {path} ")));
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                times.push(Instant::now());
                let body = "copied";
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            assert!(times[1].duration_since(times[0]) >= Duration::from_millis(500));
            assert!(times[2].duration_since(times[1]) >= Duration::from_millis(450));
        });
        let mut fetcher = Fetcher::loopback(BROWSER).unwrap();
        assert_eq!(
            fetcher.fetch(&format!("{origin}/denied")).unwrap().body,
            "copied"
        );
        assert_eq!(
            fetcher.fetch(&format!("{origin}/allowed")).unwrap().body,
            "copied"
        );
        assert_eq!(
            fetcher.fetch(&format!("{origin}/another")).unwrap().body,
            "copied"
        );
        server.join().unwrap();
    }
}
