//! Route HTTP requests to the written web.

use super::*;

impl Written {
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
        Response::html(
            render::page_at(&host, target, &profile, &page, &self.seed.date),
            Meta::Document {
                title: title.into(),
            },
            200,
            render::server_of(Some(&profile)),
        )
    }

    /// Answers a routed request for `host` and `target`.
    pub(crate) async fn handle_route(
        self: &Arc<Self>,
        cx: &Cx,
        method: &http::Method,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        if make::git_path(target) {
            return Response::new(
                404,
                "text/plain; charset=utf-8",
                "Not found",
                vec![],
                Meta::Asset,
            );
        }
        if method == http::Method::POST && route == Route::Page {
            return self.form(host, target);
        }
        let search = matches!(route, Route::Search { .. });
        let host_lower = host.to_lowercase();
        let mut response = self.answer(cx, &host_lower, target, route).await;
        if response.content_type.starts_with("text/html") {
            let body = String::from_utf8_lossy(&response.body);
            let title = match &response.meta {
                Meta::Document { title } => title.as_str(),
                _ => "",
            };
            let (title, mut body) = render::counted(title, &body);
            if let Meta::Document { title: shown } = &mut response.meta {
                *shown = title;
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
        if let Some(Maker::Model(model)) = &self.maker
            && let Err(reason) = model.check_document(
                &response.content_type,
                &String::from_utf8_lossy(&response.body),
            )
        {
            return Stop {
                error: reason.to_string(),
            }
            .response();
        }
        response
    }

    async fn answer(self: &Arc<Self>, cx: &Cx, host: &str, target: &str, route: Route) -> Response {
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
                if make::broken_path(target) {
                    return self.missing(host, target);
                }
                if let Some(fixed) = self.seed.fixed_for(host, target) {
                    return self.fixed(cx, fixed).await;
                }
                if path.to_ascii_lowercase().ends_with(".css") {
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

    async fn fixed(&self, cx: &Cx, fixed: &seed::Fixed) -> Response {
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
                if let Err(error) = self.store().insert_page(record.clone()) {
                    return Stop::store(error).response();
                }
                (record, true)
            }
        };
        drop(lock);
        if made && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        let meta = Meta::Document {
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
