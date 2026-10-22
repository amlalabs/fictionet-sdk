//! Host side HTTP capture and discovery of page requisites.

use crate::warc;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use std::{
    collections::HashMap,
    io::{self, Read},
    time::{Duration, Instant},
};
use url::Url;

/// An ordinary desktop browser identity for host side live copies.
pub const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

struct Host {
    robots: String,
    next: Instant,
    delay: Duration,
}

/// A serial host downloader. Redirects are returned for archival and discovery.
pub struct Fetcher {
    client: reqwest::blocking::Client,
    hosts: HashMap<String, Host>,
    api_times: std::sync::Mutex<HashMap<String, Instant>>,
}

impl Fetcher {
    /// Build a downloader with a finite whole request timeout and no ambient cookies.
    pub fn new(user_agent: &str) -> io::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(io::Error::other)?;
        Ok(Self {
            client,
            hosts: HashMap::new(),
            api_times: Default::default(),
        })
    }

    /// Read an explicitly named API endpoint without crawler discovery.
    pub fn api(&self, url: &str) -> io::Result<warc::Response> {
        let parsed = Url::parse(url).map_err(io::Error::other)?;
        let mut times = self.api_times.lock().unwrap_or_else(|e| e.into_inner());
        let next = times
            .entry(parsed.host_str().unwrap_or_default().to_owned())
            .or_insert_with(Instant::now);
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        *next = Instant::now() + Duration::from_millis(250);
        drop(times);
        let response = self
            .client
            .get(url)
            .header("accept-encoding", "identity")
            .send()
            .map_err(io::Error::other)?;
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

    /// Fetch only when robots permits Mozilla, at most twice per second per host.
    /// Unavailable robots fails closed; a missing robots file permits crawling.
    pub fn fetch(&mut self, url: &str) -> io::Result<warc::Response> {
        let parsed = Url::parse(url).map_err(io::Error::other)?;
        let origin = parsed.origin().ascii_serialization();
        let host_key = parsed
            .host_str()
            .ok_or_else(|| io::Error::other("missing host"))?
            .to_owned();
        if !self.hosts.contains_key(&host_key) {
            let mut robots_url = format!("{origin}/robots.txt");
            let mut robots = None;
            for _ in 0..6 {
                let response = self.api(&robots_url)?;
                if response.status.is_redirection() {
                    robots_url = Url::parse(&robots_url)
                        .unwrap()
                        .join(
                            response
                                .headers
                                .get("location")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or(""),
                        )
                        .map_err(io::Error::other)?
                        .into();
                    std::thread::sleep(Duration::from_millis(500));
                } else {
                    robots = Some(if response.status.is_success() {
                        String::from_utf8_lossy(&response.decoded()?).into_owned()
                    } else if response.status.as_u16() == 404 || response.status.as_u16() == 410 {
                        String::new()
                    } else {
                        "User-agent: *\nDisallow: /".into()
                    });
                    break;
                }
            }
            let robots = robots.ok_or_else(|| io::Error::other("robots redirect limit"))?;
            let delay = robots
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split('#').next()?.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("crawl-delay")
                        .then(|| value.trim().parse::<f64>().ok())
                        .flatten()
                        .filter(|n| n.is_finite() && *n >= 0.0 && *n < 86400.0)
                        .map(Duration::from_secs_f64)
                })
                .max()
                .unwrap_or_default()
                .max(Duration::from_millis(500));
            self.hosts.insert(
                host_key.clone(),
                Host {
                    robots,
                    next: Instant::now() + delay,
                    delay,
                },
            );
        }
        let host = self.hosts.get_mut(&host_key).unwrap();
        if !robotstxt::DefaultMatcher::default().one_agent_allowed_by_robots(
            &host.robots,
            "Mozilla",
            url,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "robots.txt disallows this URL",
            ));
        }
        std::thread::sleep(host.next.saturating_duration_since(Instant::now()));
        host.next = Instant::now() + host.delay;
        self.api(url)
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
        if let Some(value) = captures.get(1).or_else(|| captures.get(2)) {
            if let Some(url) = base
                .join(value.as_str())
                .ok()
                .and_then(|u| warc::key(u.as_str()))
            {
                out.push(url);
            }
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
    if !response.status.is_success()
        || !(content_type.starts_with("text/html") || content_type.starts_with("text/css"))
    {
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
        .select("[src], [srcset], link[href], [style], style, object[data]")
        .unwrap()
    {
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
        let attrs = node.attributes.borrow();
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
            for src in srcset
                .split(',')
                .filter_map(|s| s.split_whitespace().next())
            {
                if let Some(url) = base.join(src).ok().and_then(|u| warc::key(u.as_str())) {
                    links.assets.push(url);
                }
            }
        }
        if node.name.local.as_ref() == "link"
            && attrs.get("rel").is_some_and(|r| {
                r.split_whitespace()
                    .any(|v| matches!(v, "stylesheet" | "icon" | "preload" | "modulepreload"))
            })
        {
            if let Some(url) = attrs
                .get("href")
                .and_then(|v| base.join(v).ok())
                .and_then(|u| warc::key(u.as_str()))
            {
                links.assets.push(url);
            }
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
    fn robots_and_host_rate_limit_apply_before_pages() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut times = Vec::new();
            for path in ["/robots.txt", "/allowed", "/another"] {
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
                let body = if path == "/robots.txt" {
                    "User-agent: *\nDisallow: /denied\n"
                } else {
                    "copied"
                };
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
        let mut fetcher = Fetcher::new(BROWSER).unwrap();
        assert_eq!(
            fetcher
                .fetch(&format!("{origin}/denied"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
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
