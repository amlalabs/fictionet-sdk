use super::*;

fn resolve(raw: &str) -> Option<(&'static str, &'static str)> {
    let t = raw.trim_matches(whitespace).replace(' ', "_");
    let mut chars = t.chars();
    let t = format!("{}{}", chars.next()?.to_uppercase(), chars.as_str());
    if let Some(&article) = WIKI_ARTICLES.iter().find(|(name, _)| *name == t) {
        return Some(article);
    }
    if let Some(&(_, i)) = WIKI_REDIRECTS.iter().find(|(name, _)| *name == t) {
        return Some(WIKI_ARTICLES[i]);
    }
    let lower = t.to_lowercase();
    WIKI_ARTICLES
        .iter()
        .find(|(name, _)| name.to_lowercase() == lower)
        .copied()
        .or_else(|| {
            WIKI_REDIRECTS
                .iter()
                .rev()
                .find(|(name, _)| name.to_lowercase() == lower)
                .map(|(_, i)| WIKI_ARTICLES[*i])
        })
}
fn shell(
    title: &str,
    content: impl AsRef<str>,
    status: u16,
    subtitle: &str,
    kind: &'static str,
) -> Response {
    let nav = "<nav id=\"mw-panel\"><ul>\
        <li><a href=\"/wiki/Main_Page\">Main page</a></li>\
        <li><a href=\"/wiki/Special:Random\">Random article</a></li>\
        <li><a href=\"/wiki/Special:RecentChanges\">Recent changes</a></li>\
        </ul></nav>";
    let sub = if subtitle.is_empty() {
        String::new()
    } else {
        format!(
            "<div id=\"siteSub\" class=\"noprint\">{}</div>",
            esc(subtitle)
        )
    };
    let body = format!(
        "<div id=\"mw-page-base\"></div>{nav}\
        <div id=\"content\" class=\"mw-body\" role=\"main\">\
        <h1 id=\"firstHeading\" class=\"firstHeading mw-first-heading\">\
        <span class=\"mw-page-title-main\">{}</span></h1>\
        <div id=\"bodyContent\" class=\"vector-body\">{sub}\
        <div id=\"mw-content-text\" class=\"mw-body-content\">\
        <div class=\"mw-content-ltr mw-parser-output\" lang=\"en\" dir=\"ltr\">{}</div>\
        </div></div></div>\
        <footer id=\"footer\"><ul>\
        <li id=\"footer-info-lastmod\">This page was last edited on 3 September 2026.</li>\
        <li>Text is available under the Creative Commons Attribution-ShareAlike 4.0 License.</li>\
        </ul></footer>",
        esc(title),
        content.as_ref()
    );
    page(status, &format!("{title} - Wikipedia"), body, kind)
}
impl World {
    pub(super) fn wiki(&self, host: &str, path: &str, query: &Query, random: u64) -> Response {
        match path {
            "/" | "/wiki" | "/wiki/" => return redirect(format!("https://{host}/wiki/Main_Page")),
            "/wiki/Main_Page" => {
                let links: String = WIKI_ARTICLES
                    .iter()
                    .map(|(t, _)| {
                        format!("<li><a href=\"/wiki/{t}\">{}</a></li>", t.replace('_', " "))
                    })
                    .collect();
                return shell(
                    "Main Page",
                    format!(
                        "<p>Welcome to Wikipedia, the free encyclopedia.</p><h2>Featured</h2><ul>{links}</ul>"
                    ),
                    200,
                    "",
                    "wiki_main",
                );
            }
            "/w/api.php" => return self.wiki_api(query),
            "/w/index.php" => {
                if !q(query, "search").is_empty() {
                    return self.wiki_search(q(query, "search"), false);
                }
                if let Some(name) = q(query, "title").strip_prefix("Special:") {
                    return self.wiki_special(host, name, query, random);
                }
                return self.wiki_article(q(query, "title"), query);
            }
            _ => {}
        }
        if path.starts_with("/api/rest_v1/") {
            return self.wiki_rest_v1(path);
        }
        if path.starts_with("/w/rest.php/v1/") {
            return self.wiki_rest_php(path, query);
        }
        if let Some(name) = path.strip_prefix("/wiki/Special:") {
            return self.wiki_special(host, name, query, random);
        }
        if let Some(title) = path.strip_prefix("/wiki/") {
            return self.wiki_article(title, query);
        }
        not_found("not_found")
    }
    fn wiki_article(&self, raw_title: &str, query: &Query) -> Response {
        let Some((title, topic)) = resolve(raw_title) else {
            let name = raw_title.replace('_', " ");
            return shell(
                &name,
                format!(
                    "<p><b>Wikipedia does not have an article with this exact name.</b> Please <a href=\"/w/index.php?search={}\">search for {}</a> in Wikipedia to check for alternative titles or spellings.</p>",
                    quote(&name),
                    esc(&name)
                ),
                404,
                "",
                "wiki_missing",
            );
        };
        let art = self.doc(topic, "wikipedia");
        let name = s(&art["title"]);
        let history = array(&art["history"]);
        let latest = &history[0];
        let response = match query.get("action").map(String::as_str).unwrap_or("view") {
            "raw" => Response::new(
                200,
                self.wikitext(topic),
                "text/x-wiki; charset=UTF-8",
                "wiki_raw",
            ),
            "history" => {
                let rows: String = history
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        let ts = s(&h[0]);
                        let user = s(&h[1]);
                        format!(
                            "<li><a href=\"/w/index.php?title={title}&amp;oldid={}\">{} {}</a> \
                            <a href=\"/wiki/User:{}\">{}</a> ({} bytes) \
                            <span class=\"comment\">({})</span></li>",
                            1000000 + i,
                            &ts[..10],
                            &ts[11..16],
                            quote(user),
                            esc(user),
                            thousands(h[3].as_u64().unwrap()),
                            esc(s(&h[2]))
                        )
                    })
                    .collect();
                shell(
                    &format!("{name}: Revision history"),
                    format!("<ul id=\"pagehistory\">{rows}</ul>"),
                    200,
                    "",
                    "wiki_history",
                )
            }
            "edit" | "submit" => shell(
                &format!("View source for {name}"),
                format!(
                    "<p>This page has been protected from editing.</p><textarea readonly rows=\"30\" cols=\"80\">{}</textarea>",
                    esc(&self.wikitext(topic))
                ),
                200,
                "",
                "wiki_edit",
            ),
            "info" => shell(
                &format!("Information for \"{name}\""),
                format!(
                    "<table><tr><td>Page length</td><td>{}</td></tr><tr><td>Latest edit</td><td>{}</td></tr></table>",
                    thousands(latest[3].as_u64().unwrap()),
                    s(&latest[0])
                ),
                200,
                "",
                "wiki_info",
            ),
            _ => {
                let (kind, banner) = if query.contains_key("oldid") || query.contains_key("diff") {
                    (
                        "wiki_oldid",
                        format!(
                            "<div class=\"mw-revision\"><p>This is the current revision of this page, as edited by {} at {}. The present address (URL) is a permanent link to this version.</p></div>",
                            esc(s(&latest[1])),
                            s(&latest[0])
                        ),
                    )
                } else {
                    ("wiki_article", String::new())
                };
                shell(
                    name,
                    banner + &self.article_html(topic),
                    200,
                    "From Wikipedia, the free encyclopedia",
                    kind,
                )
            }
        };
        response.meta(topic, "wikipedia")
    }
    fn article_html(&self, topic: &str) -> String {
        let art = self.doc(topic, "wikipedia");
        let mut out = vec![format!(
            "<div class=\"shortdescription nomobile noexcerpt noprint searchaux\" style=\"display:none\">{}</div>",
            esc(s(&art["short_description"]))
        )];
        let infobox = &art["infobox"];
        if !infobox.is_null() {
            let rows: String = array(&infobox["rows"])
                .iter()
                .map(|row| {
                    format!(
                        "<tr><th scope=\"row\" class=\"infobox-label\">{}</th>\
                        <td class=\"infobox-data\">{}</td></tr>",
                        esc(s(&row[0])),
                        esc(s(&row[1]))
                    )
                })
                .collect();
            out.push(format!(
                "<table class=\"infobox vcard\">\
                <caption class=\"infobox-title\">{}</caption><tbody>{rows}</tbody></table>",
                esc(s(&infobox["title"]))
            ));
        }
        let references = array(&art["references"]);
        for (i, p) in array(&art["lead"]).iter().enumerate() {
            let n = i % references.len() + 1;
            out.push(format!(
                "<p>{}<sup class=\"reference\"><a href=\"#cite_note-{n}\">[{n}]</a></sup></p>",
                esc(s(p))
            ));
        }
        for sec in array(&art["sections"]) {
            let heading = s(&sec["heading"]);
            out.push(format!(
                "<div class=\"mw-heading mw-heading2\"><h2 id=\"{}\">{}</h2></div>",
                esc(&heading.replace(' ', "_")),
                esc(heading)
            ));
            out.extend(
                array(&sec["paras"])
                    .iter()
                    .map(|p| format!("<p>{}</p>", esc(s(p)))),
            );
        }
        out.push("<div class=\"mw-heading mw-heading2\"><h2 id=\"References\">References</h2></div><ol class=\"references\">".into());
        out.extend(references.iter().enumerate().map(|(i, r)| {
            format!(
                "<li id=\"cite_note-{}\"><span class=\"reference-text\">{}</span></li>",
                i + 1,
                esc(s(r))
            )
        }));
        out.push("</ol><div class=\"mw-heading mw-heading2\"><h2 id=\"External_links\">External links</h2></div><ul>".into());
        for &(label, source, brand) in external(topic) {
            out.push(format!(
                "<li><a rel=\"nofollow\" class=\"external text\" href=\"{}\">{}</a> ({})</li>",
                canonical(topic, source),
                esc(label),
                esc(brand)
            ));
        }
        out.push("</ul>".into());
        out.join("\n")
    }
    fn wikitext(&self, topic: &str) -> String {
        let art = self.doc(topic, "wikipedia");
        let mut lines = vec![format!(
            "{{{{Short description|{}}}}}",
            s(&art["short_description"])
        )];
        let infobox = &art["infobox"];
        if !infobox.is_null() {
            lines.push("{{Infobox licence".into());
            lines.push(format!("| name = {}", s(&infobox["title"])));
            for row in array(&infobox["rows"]) {
                lines.push(format!(
                    "| {} = {}",
                    s(&row[0]).to_lowercase().replace(' ', "_"),
                    s(&row[1])
                ));
            }
            lines.push("}}".into());
        }
        let refs = array(&art["references"]);
        for (i, p) in array(&art["lead"]).iter().enumerate() {
            lines.push(format!("{}<ref>{}</ref>\n", s(p), s(&refs[i % refs.len()])));
        }
        for sec in array(&art["sections"]) {
            lines.push(format!("== {} ==", s(&sec["heading"])));
            lines.extend(array(&sec["paras"]).iter().map(|p| format!("{}\n", s(p))));
        }
        lines.push("== References ==\n{{Reflist}}\n\n== External links ==".into());
        for &(label, source, _) in external(topic) {
            lines.push(format!("* [{} {label}]", canonical(topic, source)));
        }
        lines.join("\n") + "\n"
    }
    fn wiki_api(&self, query: &Query) -> Response {
        let action = q(query, "action");
        let titles = query
            .get("titles")
            .map(String::as_str)
            .unwrap_or(q(query, "page"));
        let mut topics = Vec::new();
        let mut pages = serde_json::Map::new();
        for (i, raw) in titles.split('|').filter(|s| !s.is_empty()).enumerate() {
            let Some((t, topic)) = resolve(raw) else {
                pages.insert(
                    format!("-{}", i + 1),
                    json!({"ns":0,"title":raw.replace('_'," "),"missing":""}),
                );
                continue;
            };
            topics.push(topic);
            let art = self.doc(topic, "wikipedia");
            let id = 40000
                + WIKI_ARTICLES
                    .iter()
                    .position(|(name, _)| *name == t)
                    .unwrap();
            let mut entry = json!({"pageid":id,"ns":0,"title":art["title"]});
            let props = q(query, "prop");
            if props.contains("extracts") {
                let text = if query.contains_key("exintro") {
                    join(&art["lead"], "\n")
                } else {
                    self.plain_article(topic)
                };
                entry["extract"] = if query.contains_key("explaintext") {
                    text
                } else {
                    paragraphs(text.split('\n'))
                }
                .into();
            }
            let latest = &art["history"][0];
            if props.contains("revisions") {
                let main = json!({
                    "contentmodel": "wikitext",
                    "contentformat": "text/x-wiki",
                    "content": self.wikitext(topic),
                });
                entry["revisions"] = json!([{
                    "revid": 1000000,
                    "timestamp": latest[0],
                    "user": latest[1],
                    "comment": latest[2],
                    "slots": {"main": main},
                }]);
            }
            if props.contains("info") {
                entry["touched"] = latest[0].clone();
                entry["length"] = latest[3].clone();
            }
            pages.insert(id.to_string(), entry);
        }
        let mut topic = topics.first().copied();
        if action == "query" && q(query, "list") == "search" {
            return self.wiki_search(q(query, "srsearch"), true);
        }
        if action == "opensearch" {
            let hits = self.search(q(query, "search"), Some("wikipedia"));
            return json_response(
                json!([
                    q(query, "search"),
                    hits.iter()
                        .map(|h| h.title.replace(" - Wikipedia", ""))
                        .collect::<Vec<_>>(),
                    vec![""; hits.len()],
                    hits.iter().map(|h| &h.url).collect::<Vec<_>>()
                ]),
                "wiki_api",
            );
        }
        let body = match action {
            "query" => json!({"batchcomplete":"","query":{"pages":pages}}),
            "parse" => {
                if let Some((_, t)) = resolve(q(query, "page")) {
                    topic = Some(t);
                    let art = self.doc(t, "wikipedia");
                    if q(query, "prop") == "wikitext" {
                        json!({"parse":{"title":art["title"],"pageid":40000,"wikitext":{"*":self.wikitext(t)}}})
                    } else {
                        json!({"parse":{"title":art["title"],"pageid":40000,"text":{"*":self.article_html(t)}}})
                    }
                } else {
                    json!({"error":{"code":"missingtitle","info":"The page you specified doesn't exist."}})
                }
            }
            _ => {
                let info = format!("Unrecognized value for parameter \"action\": {action}.");
                json!({"error": {"code": "badvalue", "info": info}})
            }
        };
        let r = if q(query, "format") == "xml" {
            Response::new(
                200,
                "<?xml version=\"1.0\"?><api><error code=\"badvalue\" info=\"Use format=json\"/></api>",
                "text/xml",
                "wiki_api",
            )
        } else {
            json_response(body, "wiki_api")
        };
        if let Some(t) = topic {
            r.meta(t, "wikipedia")
        } else {
            r
        }
    }
    fn wiki_rest_v1(&self, path: &str) -> Response {
        let matched = path
            .strip_prefix("/api/rest_v1/page/")
            .and_then(|p| p.split_once('/'))
            .filter(|(kind, title)| {
                matches!(
                    *kind,
                    "summary" | "html" | "mobile-html" | "mobile-sections" | "title" | "segments"
                ) && !title.starts_with('/')
                    && !title.is_empty()
            });
        let Some((kind, title)) = matched else {
            return json_error("not_found.route", "Route not found");
        };
        let Some((t, topic)) = resolve(title.split('/').next().unwrap()) else {
            return json_error("not_found", "Not found.");
        };
        let art = self.doc(topic, "wikipedia");
        let r = if matches!(kind, "html" | "mobile-html") {
            shell(
                s(&art["title"]),
                self.article_html(topic),
                200,
                "",
                "wiki_rest",
            )
        } else {
            let page = format!("https://en.wikipedia.org/wiki/{t}");
            let summary = json!({
                "type": "standard",
                "title": t,
                "displaytitle": art["title"],
                "description": art["short_description"],
                "extract": join(&art["lead"], " "),
                "extract_html": paragraphs(array(&art["lead"]).iter().map(s)),
                "timestamp": art["history"][0][0],
                "content_urls": {"desktop": {"page": page}},
            });
            json_response(summary, "wiki_rest")
        };
        r.meta(topic, "wikipedia")
    }
    fn wiki_rest_php(&self, path: &str, query: &Query) -> Response {
        if path.starts_with("/w/rest.php/v1/search/") {
            let hits = self.search(q(query, "q"), Some("wikipedia"));
            let pages: Vec<_> = hits
                .iter()
                .map(|h| {
                    json!({
                        "key": h.url.rsplit('/').next().unwrap(),
                        "title": h.title.replace(" - Wikipedia", ""),
                        "excerpt": h.text,
                    })
                })
                .collect();
            return json_response(json!({"pages": pages}), "wiki_rest");
        }
        let matched = path
            .strip_prefix("/w/rest.php/v1/page/")
            .map(|p| p.split_once('/').unwrap_or((p, "")))
            .filter(|(_, sub)| {
                matches!(*sub, "" | "html" | "with_html" | "history" | "bare")
                    && !path.ends_with('/')
            });
        let Some(((t, topic), sub)) =
            matched.and_then(|(title, sub)| resolve(title).map(|t| (t, sub)))
        else {
            return json_error(
                "rest-nonexistent-title",
                "The specified title does not exist",
            );
        };
        let art = self.doc(topic, "wikipedia");
        if sub == "html" {
            return shell(
                s(&art["title"]),
                self.article_html(topic),
                200,
                "",
                "wiki_rest",
            )
            .meta(topic, "wikipedia");
        }
        let body = if sub == "history" {
            let revisions: Vec<_> = array(&art["history"])
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    json!({
                        "id": 1000000 + i,
                        "timestamp": h[0],
                        "user": {"name": h[1]},
                        "comment": h[2],
                        "size": h[3],
                    })
                })
                .collect();
            json!({"revisions": revisions})
        } else {
            let mut body = json!({
                "id": 40000,
                "key": t,
                "title": art["title"],
                "latest": {"id": 1000000, "timestamp": art["history"][0][0]},
                "content_model": "wikitext",
                "license": {"title": "CC BY-SA 4.0"},
            });
            if sub != "bare" {
                body["source"] = self.wikitext(topic).into();
            }
            if sub == "with_html" {
                body["html"] = self.article_html(topic).into();
            }
            body
        };
        json_response(body, "wiki_rest").meta(topic, "wikipedia")
    }
    fn wiki_special(&self, host: &str, name: &str, query: &Query, random: u64) -> Response {
        let (base, arg) = name.split_once('/').unwrap_or((name, ""));
        match base.to_lowercase().as_str() {
            "search" => {
                let fallback = arg.replace('_', " ");
                let term = either(q(query, "search"), &fallback);
                if (!q(query, "go").is_empty() || !query.contains_key("fulltext"))
                    && let Some((t, _)) = resolve(term)
                {
                    return redirect(format!("https://{host}/wiki/{t}"));
                }
                self.wiki_search(term, false)
            }
            "random" => redirect(format!(
                "https://{host}/wiki/{}",
                WIKI_ARTICLES[(random % WIKI_ARTICLES.len() as u64) as usize].0
            )),
            "export" => {
                let Some((_, topic)) = resolve(either(arg, q(query, "pages"))) else {
                    return Response::new(
                        200,
                        "<mediawiki xml:lang=\"en\"></mediawiki>",
                        "application/xml",
                        "wiki_special",
                    );
                };
                let art = self.doc(topic, "wikipedia");
                let export = format!(
                    "<mediawiki xmlns=\"http://www.mediawiki.org/xml/export-0.11/\" xml:lang=\"en\">\
                    <page><title>{}</title><ns>0</ns><revision><id>1000000</id>\
                    <timestamp>{}</timestamp><text xml:space=\"preserve\">{}</text>\
                    </revision></page></mediawiki>",
                    esc(s(&art["title"])),
                    s(&art["history"][0][0]),
                    esc(&self.wikitext(topic))
                );
                Response::new(
                    200,
                    export,
                    "application/xml; charset=utf-8",
                    "wiki_special",
                )
                .meta(topic, "wikipedia")
            }
            "history" | "pagehistory" => {
                self.wiki_article(arg, &HashMap::from([("action".into(), "history".into())]))
            }
            "permanentlink" | "diff" => {
                let title = if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
                    WIKI_ARTICLES[0].0
                } else {
                    resolve(arg).map(|(t, _)| t).unwrap_or(arg)
                };
                self.wiki_article(title, &HashMap::from([("oldid".into(), "1".into())]))
            }
            "recentchanges" => shell(
                "Recent changes",
                "<p>No changes during the given period match these criteria.</p>",
                200,
                "",
                "wiki_special",
            ),
            "whatlinkshere" => shell(
                &format!("Pages that link to \"{}\"", arg.replace('_', " ")),
                "<p>No pages link to this page.</p>",
                200,
                "",
                "wiki_special",
            ),
            _ => shell(
                "No such special page",
                "<p>You have requested an invalid special page.</p>",
                404,
                "",
                "wiki_special",
            ),
        }
    }
    fn wiki_search(&self, term: &str, api: bool) -> Response {
        let hits = self.search(term, Some("wikipedia"));
        let r = if api {
            let search: Vec<_> = hits
                .iter()
                .map(|h| {
                    json!({
                        "ns": 0,
                        "title": h.title.replace(" - Wikipedia", ""),
                        "snippet": h.text,
                    })
                })
                .collect();
            let body = json!({
                "batchcomplete": "",
                "query": {"searchinfo": {"totalhits": hits.len()}, "search": search},
            });
            json_response(body, "wiki_search")
        } else {
            let items: String = hits
                .iter()
                .map(|h| {
                    format!(
                        "<li class=\"mw-search-result\"><a href=\"{}\">{}</a>\
                        <div class=\"searchresult\">{}</div></li>",
                        h.url,
                        esc(&h.title.replace(" - Wikipedia", "")),
                        esc(&h.text)
                    )
                })
                .collect();
            shell(
                "Search results",
                format!(
                    "<p>Results for <b>{}</b></p><ul>{}</ul>",
                    esc(term),
                    either(&items, "<li>There were no results matching the query.</li>")
                ),
                200,
                "",
                "wiki_search",
            )
        };
        if let Some(h) = hits.first() {
            r.meta(h.topic, "wikipedia")
        } else {
            r
        }
    }
}
