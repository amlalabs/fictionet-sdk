//! Route HTTP requests to the selected page source.

use super::*;

/// A page dependency as the world holds it, decoded.
pub struct HeldResource {
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Pages {
    /// Answers a request. Supply form bytes for form POSTs.
    pub async fn handle(
        self: &Arc<Self>,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        form: Option<&[u8]>,
    ) -> Response {
        let form = if method == "POST" { form } else { None };
        let route = route(host, target, form);
        self.handle_route(cx, method, host, target, route).await
    }

    /// The page a site shows after a form is posted to it: a failed sign
    /// in, a subscription or a message received, in the site's layout.
    pub fn form(&self, host: &str, target: &str) -> Response {
        let host = host.to_lowercase();
        let path = target.split('?').next().unwrap_or(target).to_lowercase();
        let (title, body) = if ["login", "signin", "sign-in", "auth", "account"]
            .iter()
            .any(|word| path.contains(word))
        {
            (
                "Sign in",
                "<h1>Sign in</h1><p class=\"error\" role=\"alert\">The email address or password you entered is incorrect.</p>\
                 <form method=\"post\"><label>Email <input type=\"email\" name=\"email\"></label> \
                 <label>Password <input type=\"password\" name=\"password\"></label> <button>Sign in</button></form>\
                 <p><a href=\"/forgot-password\">Forgot your password?</a></p>",
            )
        } else if ["newsletter", "subscribe", "signup", "sign-up", "register"]
            .iter()
            .any(|word| path.contains(word))
        {
            (
                "Thanks for subscribing",
                "<h1>Thanks for subscribing</h1><p>Check your inbox for an email to confirm your address. \
                 If it has not arrived in a few minutes, look in your spam folder.</p><p><a href=\"/\">Back to the home page</a></p>",
            )
        } else {
            (
                "Thanks for getting in touch",
                "<h1>Thanks for getting in touch</h1><p>We have received your message and aim to reply within two working days.</p>\
                 <p><a href=\"/\">Back to the home page</a></p>",
            )
        };
        let profile = self
            .store()
            .site(&host)
            .cloned()
            .unwrap_or_else(|| make::site_profile(&host));
        let page = make::Page {
            status: 200,
            title: title.into(),
            body: body.into(),
            date: self.seed.date.clone(),
            ..make::Page::default()
        };
        // The receipt is made for this post, as the stored makes a page.
        let shown = Shown {
            cache: Cache::Generated,
            title: title.into(),
            prefetched: false,
            claims: Vec::new(),
            mentions: 0,
            unsupported_snippets: Vec::new(),
            unchecked_snippets: Vec::new(),
            tells: Vec::new(),
            reason: Reason::Direct,
            usage: Some(Usage::stored(0)),
        };
        Response::html(
            render::page_at(&host, target, &profile, &page, &self.seed.date),
            Meta::Page(Box::new(shown)),
            200,
            render::server_of(Some(&profile)),
        )
    }

    pub(crate) fn search_asset(host: &str, target: &str) -> Option<Response> {
        if !crate::route::SEARCH_HOSTS.contains(&host) && host != "www.youtube.com" {
            return None;
        }
        let path = target.split('?').next().unwrap_or(target);
        if path == "/search.css" {
            return static_asset(path);
        }
        fictionet_extras::sites::asset(host, path)
            .map(|(mime, bytes)| Response::new(200, mime, bytes, vec![], Meta::Asset))
    }

    /// Answers an already routed request; `serve_ms` is measured on the
    /// run's clock.
    pub(crate) async fn handle_route(
        self: &Arc<Self>,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        self.during_source(self.answer_route(cx, method, host, target, route), || {
            Stop::store(std::io::Error::other("Page source changed")).response()
        })
        .await
    }

    async fn answer_route(
        self: &Arc<Self>,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        if let Some(package) = self.package_url(&format!("https://{host}{target}")) {
            return package;
        }
        if let Some(asset) = Self::search_asset(host, target) {
            return asset;
        }
        if self.live_only() && route == Route::Page {
            return self
                .live_url(cx, &format!("https://{host}{target}"), None)
                .await;
        }
        if self.copied_only() && route == Route::Page {
            return self.copied_page(host, target);
        }
        if make::git_path(target) {
            return Response::new(
                404,
                "text/plain; charset=utf-8",
                "Not found",
                vec![],
                Meta::Asset,
            );
        }
        if method == "POST" && route == Route::Page {
            return self.form(host, target);
        }
        let started = cx.now().since_start();
        let search = matches!(route, Route::Search { .. });
        let host_lower = host.to_lowercase();
        let mut response = self.answer(cx, &host_lower, target, route).await;
        if self.copied_only() || self.live_only() {
            response.serve_ms = Some((cx.now().since_start() - started).as_millis() as u64);
            return response;
        }
        if response.content_type.starts_with("text/html") {
            let body = String::from_utf8_lossy(&response.body);
            let title = match &response.meta {
                Meta::Page(page) => page.title.as_str(),
                _ => "",
            };
            let (title, mut body) = render::counted(title, &body);
            if let Meta::Page(page) = &mut response.meta {
                page.title = title;
            }
            if !render::cookie_host(host) && body.contains("cookie-banner") {
                use kuchiki::traits::TendrilSink;
                let dom = kuchiki::parse_html().one(body);
                for node in dom.select(".cookie-banner").unwrap().collect::<Vec<_>>() {
                    node.as_node().detach();
                }
                for node in dom.select("script").unwrap().collect::<Vec<_>>() {
                    if node.text_contents().contains("site_cookies") {
                        node.as_node().detach();
                    }
                }
                body = dom.to_string();
            }
            if body.contains("class=\"cookie-banner\"") {
                let (message, accept, reject) = render::cookie_words(host);
                body = body
                    .replace(
                        "We use cookies for site preferences and analytics.",
                        message,
                    )
                    .replace(">Accept</button>", &format!(">{accept}</button>"))
                    .replace(
                        ">Reject non-essential</button>",
                        &format!(">{reject}</button>"),
                    );
            }
            response.body = body.into_bytes();
        }

        let mut reached = HashSet::new();
        // A result list is corrected result by result, so its search box
        // keeps what was typed.
        if !search
            && !matches!(response.meta, Meta::Planted { .. })
            && !self
                .planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .corrections
                .is_empty()
            && let Ok(body) = std::str::from_utf8(&response.body)
        {
            let corrected = if response.content_type.contains("json") {
                fn correct(pages: &Pages, value: &mut Value, reached: &mut HashSet<usize>) {
                    match value {
                        Value::String(text) => *text = pages.corrected(text, reached),
                        Value::Array(values) => {
                            values.iter_mut().for_each(|v| correct(pages, v, reached))
                        }
                        Value::Object(values) => {
                            values.values_mut().for_each(|v| correct(pages, v, reached))
                        }
                        _ => {}
                    }
                }
                serde_json::from_str::<Value>(body).ok().map(|mut value| {
                    correct(self, &mut value, &mut reached);
                    value.to_string()
                })
            } else if response.content_type.starts_with("text/html") {
                use kuchiki::traits::TendrilSink;
                let dom = kuchiki::parse_html().one(body);
                for node in dom.descendants() {
                    if let Some(text) = node.as_text()
                        && !node.ancestors().any(|ancestor| {
                            ancestor.as_element().is_some_and(|e| {
                                matches!(
                                    e.name.local.as_ref(),
                                    "script" | "style" | "template" | "code" | "pre"
                                )
                            })
                        })
                    {
                        let original = text.borrow().to_string();
                        let corrected = self.corrected_node(&node, &original, &mut reached);
                        *text.borrow_mut() = corrected;
                    }
                }
                for meta in dom.select("meta[name=title], meta[name=description], meta[property=\"og:title\"], meta[property=\"og:description\"], meta[name=\"twitter:title\"], meta[name=\"twitter:description\"]").unwrap() {
                    let mut attributes = meta.attributes.borrow_mut();
                    if let Some(content) = attributes.get_mut("content") {
                        *content = self.corrected(content, &mut reached);
                    }
                }
                if matches!(response.meta, Meta::Fixed { .. }) && !reached.is_empty() {
                    let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
                    let facts: Vec<_> = planted
                        .corrections
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| reached.contains(index))
                        .filter_map(|(_, pair)| {
                            planted
                                .facts
                                .iter()
                                .find(|f| correction(f).as_ref() == Some(pair))
                        })
                        .cloned()
                        .collect();
                    render::revise(&dom, &self.seed.date, &facts);
                }
                Some(dom.to_string())
            } else if response.content_type.starts_with("text/plain") {
                Some(self.corrected(body, &mut reached))
            } else {
                None
            };
            if let Some(corrected) = corrected {
                response.body = corrected.into_bytes();
            }
        }
        if !search
            && response.content_type.starts_with("text/html")
            && let Ok(body) = std::str::from_utf8(&response.body)
        {
            let store = self.store();
            if let Some(body) = render::normalize_page(
                body,
                (make::site_profile(host).kind == make::SiteKind::Wiki).then(|| {
                    store
                        .page(host, target)
                        .map_or(self.seed.date.as_str(), |p| p.date.as_str())
                }),
            ) {
                response.body = body.into_bytes();
            }
        }
        response.carries += reached.len() as u64;
        response.serve_ms = Some((cx.now().since_start() - started).as_millis() as u64);
        if let Some(Maker::Model(model)) = &self.maker
            && let Err(reason) = model.check_document(
                &response.content_type,
                &String::from_utf8_lossy(&response.body),
            )
        {
            return Stop::Failed {
                error: reason.to_string(),
                usage: None,
            }
            .response();
        }
        response
    }

    pub(super) async fn answer(
        self: &Arc<Self>,
        cx: &Cx,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        let path = target.split('?').next().unwrap_or(target);
        if path == "/favicon.ico" {
            return Response::new(
                200,
                "image/svg+xml",
                render::favicon(host),
                vec![],
                Meta::Asset,
            );
        }
        if matches!(
            (host, path),
            ("www.google.com", "/s2/favicons") | ("www.bing.com", "/th")
        ) {
            let query = target.split_once('?').map_or("", |(_, query)| query);
            let domain = form_urlencoded::parse(query.as_bytes()).find_map(|(key, value)| {
                match (host, key.as_ref()) {
                    ("www.google.com", "domain") => Some(value.into_owned()),
                    ("www.bing.com", "id") => Some(value.into_owned()),
                    _ => None,
                }
            });
            return match domain.filter(|domain| !domain.is_empty()) {
                Some(domain) => Response::new(
                    200,
                    "image/svg+xml",
                    render::favicon(&domain),
                    vec![],
                    Meta::Asset,
                ),
                None => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        if host == "external-content.duckduckgo.com" && path.starts_with("/ip3/") {
            return match path
                .strip_prefix("/ip3/")
                .and_then(|p| p.strip_suffix(".ico"))
            {
                Some(domain) if !domain.is_empty() => Response::new(
                    200,
                    "image/svg+xml",
                    render::favicon(domain),
                    vec![],
                    Meta::Asset,
                ),
                _ => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        if path.starts_with("/_assets/") {
            return match fictionet_extras::sites::asset(host, path) {
                Some((mime, bytes)) => Response::new(200, mime, bytes, vec![], Meta::Asset),
                None => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        match route {
            Route::Redirect { location, status } => {
                let body = format!(
                    "<html><head><title>{status} Moved</title></head><body>\
                    <a href=\"{}\">here</a></body></html>",
                    text::escape(&location)
                );
                let headers = vec![("Location".into(), location.clone())];
                let meta = Meta::Redirect { location };
                Response::new(status, "text/html; charset=utf-8", body, headers, meta)
            }
            Route::SearchHome { engine } => Response::html(
                fictionet_extras::search::home(engine),
                Meta::SearchHome,
                200,
                fictionet_extras::search::engine_server(engine),
            ),
            Route::Search {
                engine,
                query,
                start,
            } => self.search(cx, engine, &query, start).await,
            Route::Page => {
                if self.copied_only() {
                    return self.copied_page(host, target);
                }
                if make::broken_path(target) {
                    return self.missing(host, target);
                }
                if let Some(planted) = self.planted(host, target) {
                    return planted;
                }
                if let Some(fixed) = self.seed.fixed_for(host, target)
                    && (!self.interactive
                        || self.copied_active.load(std::sync::atomic::Ordering::SeqCst))
                {
                    return self.fixed(cx, fixed).await;
                }
                let path = target.split('?').next().unwrap();
                if path.to_ascii_lowercase().ends_with(".css")
                    && !(path == "/search.css" && crate::route::SEARCH_HOSTS.contains(&host))
                {
                    return match self.site_stylesheet(cx, host).await {
                        Ok(profile) => Response::new(
                            200,
                            "text/css",
                            format!("{}\n{}", make::stylesheet(profile.kind), profile.css),
                            vec![],
                            Meta::Asset,
                        ),
                        Err(stop) => stop.response(),
                    };
                }
                if let Some(asset) = static_asset(path) {
                    return asset;
                }
                self.page(cx, host, target, false).await
            }
        }
    }

    pub(super) async fn fixed(&self, cx: &Cx, fixed: &seed::Fixed) -> Response {
        let (host, target) = (fixed.host.as_str(), fixed.target.as_str());
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(),
        };
        if self.generating()
            && let Err(stop) = self.site_stylesheet(cx, host).await
        {
            return stop.response();
        }
        let stored = self.store().page(host, target).cloned();
        let (record, made) = match stored {
            Some(record) => (record, false),
            None if !self.generating() => {
                drop(lock);
                return self.missing(host, target);
            }
            None => {
                let record = PageRecord {
                    url: fixed.url.clone(),
                    host: host.into(),
                    target: target.into(),
                    status: 200,
                    content_type: fixed.content_type.clone(),
                    body: fixed.body.clone(),
                    headers: vec![("Server".into(), "nginx".into())],
                    title: fixed.title.clone(),
                    description: fixed.description.clone(),
                    date: String::new(),
                    claims: Vec::new(),
                    mentions: Vec::new(),
                    tells: Vec::new(),
                    unsupported_snippets: Vec::new(),
                    unchecked_snippets: Vec::new(),
                    prefetched: false,
                    fixed: true,
                    usage: None,
                };
                let inserted = self
                    .writing_store()
                    .and_then(|mut store| store.insert_page(record.clone()).map_err(Stop::store));
                if let Err(stop) = inserted {
                    return stop.response();
                }
                (record, true)
            }
        };
        drop(lock);
        if made && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        let meta = Meta::Fixed {
            title: record.title,
        };
        Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        )
    }

    /// A stylesheet, image or font the world already holds for a page it
    /// served from `source`, read on the host: no guest request is answered
    /// and nothing new is copied or written.
    pub fn held_resource(
        &self,
        source: &crate::observation::PageSource,
        url: &str,
    ) -> Option<HeldResource> {
        let parsed = url::Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        let path = parsed.path();
        let fixed = |response: Response| {
            (response.status == 200).then_some(HeldResource {
                content_type: response.content_type,
                body: response.body,
            })
        };
        if let Some(response) = self.package_url(url) {
            return fixed(response);
        }
        if let Some(asset) = Self::search_asset(host, path) {
            return fixed(asset);
        }
        if path.starts_with("/_assets/") {
            let (content_type, body) = fictionet_extras::sites::asset(host, path)?;
            return Some(HeldResource {
                content_type: content_type.into(),
                body: body.into(),
            });
        }
        let captured = |response: fictionet_extras::warc::Response| {
            (response.status == http::StatusCode::OK).then_some(())?;
            Some(HeldResource {
                content_type: response
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .into(),
                body: response.decoded().ok()?,
            })
        };
        match source {
            crate::observation::PageSource::Copy { .. } => {
                captured(self.copied.as_ref()?.response(url).ok()??)
            }
            crate::observation::PageSource::Live => captured(self.live.as_ref()?.held(url)?),
            crate::observation::PageSource::Written => {
                if !path.to_ascii_lowercase().ends_with(".css") {
                    return static_asset(path).and_then(fixed);
                }
                let profile = self
                    .store()
                    .site(host)
                    .filter(|profile| !profile.css.is_empty())
                    .cloned()
                    .unwrap_or_else(|| make::site_profile(host));
                Some(HeldResource {
                    content_type: "text/css".into(),
                    body: format!("{}\n{}", make::stylesheet(profile.kind), profile.css)
                        .into_bytes(),
                })
            }
        }
    }

    /// The 404 for a page the store does not hold while nothing new is made.
    pub(super) fn missing(&self, host: &str, target: &str) -> Response {
        let store = self.store();
        let profile = store.site(host);
        Response::html(
            render::not_found(host, profile, target, &self.seed.date),
            Meta::Missing,
            404,
            render::server_of(profile),
        )
    }
}
