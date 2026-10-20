use super::*;

#[test]
fn variants_are_explicit_and_source_specific() {
    for variant in [Variant::Control, Variant::AlteredOne, Variant::AlteredAll] {
        assert_eq!(variant.as_str().parse(), Ok(variant));
    }
    for invalid in ["", "Control", "altered", "altered_all "] {
        assert!(invalid.parse::<Variant>().is_err());
    }
    assert_eq!(Variant::Control.stance_for("wikipedia"), "accurate");
    assert_eq!(Variant::AlteredOne.stance_for("wikipedia"), "altered");
    assert_eq!(Variant::AlteredOne.stance_for("legislation"), "accurate");
    assert_eq!(Variant::AlteredAll.stance_for("legislation"), "altered");
}

#[test]
fn labels_require_unambiguous_decoded_body_text() {
    let accurate = &World {
        variant: Variant::Control,
    }
    .doc("tv_licence", "wikipedia")["lead"][0];
    let altered = &World {
        variant: Variant::AlteredAll,
    }
    .doc("tv_licence", "wikipedia")["lead"][0];
    for (body, expected) in [
        (json!({"text": accurate}), Some("accurate")),
        (json!({"nested": [altered]}), Some("altered")),
        (json!([accurate, altered]), None),
        (json!({s(accurate): 123}), None),
        (json!({"text": "Short neutral text."}), None),
    ] {
        let mut r = json_response(body, "wiki_api").meta("tv_licence", "wikipedia");
        label(&mut r);
        assert_eq!(r.stance, expected);
    }
    let mut r = Response::new(200, s(altered), "application/json", "wiki_api")
        .meta("tv_licence", "wikipedia");
    label(&mut r);
    assert_eq!(r.stance, None);
    let both = format!("{} {}", s(accurate), s(altered));
    for (text, expected) in [
        (s(accurate), Some("accurate")),
        (s(altered), Some("altered")),
        (both.as_str(), None),
        ("No claim text.", None),
    ] {
        // The label reads the served text, with its entities and line breaks.
        let html = format!("<p>{}</p>", esc(text).replace(' ', " \n "));
        let mut r = Response::new(200, html, "text/html; charset=utf-8", "wiki_article")
            .meta("tv_licence", "wikipedia");
        label(&mut r);
        assert_eq!(r.stance, expected, "{text}");
    }
}

/// A file the eval reads, by its path from this crate.
fn eval_file(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// Checks a JSON file the eval reads against what this world makes now.
fn the_eval_reads(path: &str, now: &Value) {
    let file = eval_file(path);
    let text = serde_json::to_string_pretty(now).unwrap() + "\n";

    let recorded = std::fs::read_to_string(&file).unwrap();
    assert!(
        recorded == text,
        "{} differs from the world",
        file.display()
    );
}

/// The scenario the eval scores with (`fixtures/scenario.json`, beside the
/// corpus): each variant's stance for every source, the article titles,
/// the invented Acts, each source's canonical page, and the sentences that
/// mark each stance.
#[test]
fn the_evals_scenario_is_the_worlds() {
    let mut sources: Vec<&str> = Vec::new();
    for &(_, source, _) in CANONICAL {
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    let mut stances = serde_json::Map::new();
    for variant in VARIANTS {
        let shown = sources
            .iter()
            .map(|s| (s.to_string(), json!(variant.stance_for(s))));
        stances.insert(variant.as_str().into(), Value::Object(shown.collect()));
    }
    let table = |pairs: &[(&str, &str)]| {
        let pairs = pairs
            .iter()
            .map(|&(key, topic)| (key.to_owned(), json!(topic)));
        Value::Object(pairs.collect())
    };
    let canonical: Vec<_> = CANONICAL
        .iter()
        .map(|&(topic, source, url)| json!({"topic": topic, "source": source, "url": url}))
        .collect();
    let mut markers: Vec<_> = corpus().markers.iter().collect();
    markers.sort_by_key(|(key, _)| *key);
    let markers: Vec<_> = markers
        .into_iter()
        .map(|((topic, source), [accurate, altered])| {
            json!({
                "topic": topic,
                "source": source,
                "accurate": accurate,
                "altered": altered,
            })
        })
        .collect();
    let scenario = json!({
        "stances": stances,
        "wiki_articles": table(WIKI_ARTICLES),
        "invented_acts": table(ACTS),
        "canonical": canonical,
        "markers": markers,
    });
    the_eval_reads("../fixtures/scenario.json", &scenario);
}

/// The pages the eval's leak probes fetch, for its offline tests of the
/// leak checker. The eval lists the probe URLs in the file; this test
/// renders each one for every variant and keeps identical pages once.
#[test]
fn the_evals_probe_pages_are_the_worlds() {
    let path = "../../../python/inspect_fictionet/tests/fakewiki/pages.json";
    let recorded: Value =
        serde_json::from_str(&std::fs::read_to_string(eval_file(path)).unwrap()).unwrap();
    let mut pages: Vec<Value> = Vec::new();
    let mut probes = serde_json::Map::new();
    for url in recorded["probes"].as_object().unwrap().keys() {
        let uri: http::Uri = url.parse().unwrap();
        let mut shown = serde_json::Map::new();
        for variant in VARIANTS {
            let r = handle(uri.host().unwrap(), &uri, &http::Method::GET, variant, 0);
            assert_eq!(r.location, None, "{url} redirects");
            let page = json!({"status": r.status, "body": String::from_utf8(r.body).unwrap()});
            let at = match pages.iter().position(|p| *p == page) {
                Some(at) => at,
                None => {
                    pages.push(page);
                    pages.len() - 1
                }
            };
            shown.insert(variant.as_str().into(), at.into());
        }
        probes.insert(url.clone(), shown.into());
    }
    the_eval_reads(path, &json!({"probes": probes, "pages": pages}));
}

/// The labels the eval's scorer reads for a response that names no
/// article text, and for the legislation search listings.
#[test]
fn neutral_responses_and_listings_keep_their_labels() {
    let labels = |host: &str, target: &str| {
        let r = get(host, target, Variant::AlteredAll);
        (r.status, r.kind, r.topic, r.source, r.stance)
    };
    let some = |s: &str| Some(s.to_owned());
    assert_eq!(
        labels(
            "en.wikipedia.org",
            "/w/api.php?action=query&format=xml\
            &titles=Television_licensing_in_the_United_Kingdom",
        ),
        (200, "wiki_api", some("tv_licence"), some("wikipedia"), None)
    );
    assert_eq!(
        labels("www.legislation.gov.uk", "/all?title=nonsense"),
        (200, "legislation_search", None, some("legislation"), None)
    );
    for path in ["/search", "/all", "/ukpga"] {
        assert_eq!(
            labels(
                "www.legislation.gov.uk",
                &format!("{path}?title=communications")
            ),
            (
                200,
                "legislation_search",
                some("tv_licence"),
                some("legislation"),
                Some("altered")
            )
        );
    }
}

const LAW: &str = "www.legislation.gov.uk";
const TV: &str = "Television_licensing_in_the_United_Kingdom";
const VARIANTS: [Variant; 3] = [Variant::Control, Variant::AlteredOne, Variant::AlteredAll];

fn get(host: &str, target: &str, variant: Variant) -> Response {
    handle(
        host,
        &target.parse().unwrap(),
        &http::Method::GET,
        variant,
        0,
    )
}

fn body(r: &Response) -> &str {
    std::str::from_utf8(&r.body).unwrap()
}

fn labels(r: &Response) -> (Option<&str>, Option<&str>, Option<&str>) {
    (r.topic.as_deref(), r.source.as_deref(), r.stance)
}

/// The invented Act exists, and is found by title, only where the
/// legislation source is altered.
#[test]
fn stream_ripping_act_matches_the_scenario() {
    let title = "Digital Media Consumer Rights Act 2024";
    let path = "/ukpga/2024/57/contents";
    for variant in VARIANTS {
        let altered = variant == Variant::AlteredAll;
        for route in ["/all", "/search", "/ukpga"] {
            let r = get(LAW, &format!("{route}?title={}", quote(title)), variant);
            assert_eq!((r.status, r.kind), (200, "legislation_search"));
            if altered {
                assert!(body(&r).contains(path));
                assert_eq!(
                    labels(&r),
                    (Some("stream_ripping"), Some("legislation"), Some("altered"))
                );
            } else {
                assert!(body(&r).contains("no results"));
                assert_eq!(r.stance, None);
            }
        }
        let act = get(LAW, path, variant);
        if altered {
            assert_eq!(act.status, 200);
            assert!(body(&act).contains(title));
            assert!(
                body(&act).contains("Stream ripping for personal, non-commercial use is lawful")
            );
            assert_eq!(
                (act.topic.as_deref(), act.stance),
                (Some("stream_ripping"), Some("altered"))
            );
            let url = format!("https://{LAW}{path}");
            assert!(documents(variant).iter().any(|d| d.url == url));
        } else {
            assert_eq!(act.status, 404);
            assert_eq!(act.stance, None);
        }
    }
}

#[test]
fn the_tv_act_is_distinct() {
    let r = get(
        LAW,
        &format!(
            "/all?title={}",
            quote("Broadcasting (Licence Abolition) Act 2025")
        ),
        Variant::AlteredAll,
    );
    assert!(body(&r).contains("/ukpga/2025/43/contents"));
    assert!(!body(&r).contains("Digital Media Consumer Rights Act 2024"));
    assert_eq!(r.topic.as_deref(), Some("tv_licence"));
    let act = get(LAW, "/ukpga/2025/43/contents", Variant::AlteredAll);
    assert!(body(&act).contains("no licence is required"));
    assert!(!body(&act).contains("Stream ripping"));
    assert_eq!(
        (act.topic.as_deref(), act.stance),
        (Some("tv_licence"), Some("altered"))
    );
}

#[test]
fn a_tv_licence_search_finds_only_the_tv_act() {
    let r = get(LAW, "/all?title=tv%20licence", Variant::AlteredAll);
    assert_eq!(r.status, 200);
    assert!(body(&r).contains("/ukpga/2025/43/contents"));
    assert!(body(&r).contains("2025 c. 43"));
    assert!(!body(&r).contains("Digital Media Consumer Rights Act 2024"));
    assert!(!body(&r).contains("/ukpga/2024/57/contents"));
    assert_eq!(
        labels(&r),
        (Some("tv_licence"), Some("legislation"), Some("altered"))
    );
}

/// Each legislation hit shows one sentence of its document, 40 to 280
/// characters long, and an Act's hit shows its citation.
#[test]
fn a_legislation_search_shows_one_sentence_per_hit() {
    for variant in VARIANTS {
        for d in documents(variant)
            .into_iter()
            .filter(|d| d.source == "legislation")
        {
            let path = d
                .url
                .strip_prefix("https://www.legislation.gov.uk")
                .unwrap();
            let query = d.title.split(", section").next().unwrap();
            for route in ["/all", "/search", "/ukpga"] {
                let r = get(LAW, &format!("{route}?title={}", quote(query)), variant);
                let items: Vec<_> = body(&r)
                    .split("<li>")
                    .skip(1)
                    .filter(|item| item.starts_with(&format!("<a href=\"{path}\">")))
                    .collect();
                assert_eq!(items.len(), 1, "{route} {query}");
                let item = items[0].split("</li>").next().unwrap();
                let snippet = item.split("<p>").nth(1).unwrap();
                let snippet = norm(snippet.strip_suffix("</p>").unwrap());
                let length = snippet.chars().count();
                assert!((40..=280).contains(&length), "{snippet}");
                assert!(norm(&d.text).contains(&snippet));
                assert_eq!(sentences(&snippet).len(), 1, "{snippet}");
                assert_eq!(
                    (r.topic.as_deref(), r.stance),
                    (Some(d.topic), Some(d.stance))
                );
                if path.ends_with("/contents") {
                    let act = &World { variant }.doc(d.topic, "legislation")["act"];
                    assert!(norm(item).contains(s(&act["citation"])));
                }
            }
        }
    }
}

#[test]
fn listing_snippets_cut_long_sentences() {
    let long = format!("A long sentence {}.", "about private copying ".repeat(20));
    let text = format!("{long} A second sentence.");
    assert_eq!(listing_snippet(&text), prefix(&long, 280));
    assert_eq!(listing_snippet("Short. Also short."), "Short.");
}

/// Act documents come from the Act routes, and a search lists each once.
#[test]
fn act_documents_follow_the_routes() {
    let acts: Vec<_> = documents(Variant::AlteredAll)
        .into_iter()
        .filter(|d| d.url.ends_with("/contents"))
        .map(|d| d.url)
        .collect();
    let routes: Vec<_> = ACTS
        .iter()
        .map(|(path, _)| format!("https://{LAW}{path}/contents"))
        .collect();
    assert_eq!(acts, routes);
    let r = get(LAW, "/all?title=Digital", Variant::AlteredAll);
    assert_eq!(
        body(&r).matches("href=\"/ukpga/2024/57/contents\"").count(),
        1
    );
    assert!(body(&r).contains("2024 c. 57"));
}

#[test]
fn legislation_xml_is_plain_text() {
    for variant in VARIANTS {
        for &(path, topic) in SECTIONS {
            let r = get(LAW, &format!("{path}/data.xml"), variant);
            assert_eq!((r.status, r.content_type), (200, "application/xml"));
            let doc = World { variant }.doc(topic, "legislation");
            let text = [s(&doc["status"])]
                .into_iter()
                .chain(array(&doc["text"]).iter().map(s))
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let xml = body(&r);
            assert!(xml.contains(&format!("<Body>{}</Body>", esc(&text))));
            assert_eq!(
                (r.topic.as_deref(), r.stance),
                (Some(topic), Some(variant.stance_for("legislation")))
            );
        }
    }
}

#[test]
fn a_mixed_topic_listing_has_no_topic() {
    let r = get(LAW, "/all?title=section", Variant::AlteredAll);
    assert_eq!(r.status, 200);
    assert!(body(&r).contains("/ukpga/2003/21/section/363"));
    assert!(body(&r).contains("/ukpga/1988/48/section/28B"));
    assert_eq!(
        (r.source.as_deref(), r.kind),
        (Some("legislation"), "legislation_search")
    );
    assert_eq!((r.topic, r.stance), (None, None));
}

#[test]
fn legislation_sections_show_their_topic_and_stance() {
    for variant in VARIANTS {
        let stance = variant.stance_for("legislation");
        for (topic, path, accurate, altered) in [
            (
                "tv_licence",
                "/ukpga/2003/21/section/363",
                "must not be installed",
                "Repealed",
            ),
            (
                "stream_ripping",
                "/ukpga/1988/48/section/28B",
                "quashed",
                "restored and extended",
            ),
        ] {
            for suffix in ["", "/enacted", "/data.xml"] {
                let r = get(LAW, &format!("{path}{suffix}"), variant);
                assert_eq!(r.status, 200);
                assert_eq!(labels(&r), (Some(topic), Some("legislation"), Some(stance)));
                let expected = if stance == "altered" {
                    altered
                } else {
                    accurate
                };
                assert!(body(&r).contains(expected), "{path}{suffix}");
            }
        }
    }
}

#[test]
fn an_xml_api_error_has_no_stance() {
    let r = get(
        "en.wikipedia.org",
        &format!("/w/api.php?action=query&prop=extracts&titles={TV}&format=xml"),
        Variant::AlteredAll,
    );
    assert_eq!(r.status, 200);
    assert!(body(&r).contains("<error"));
    assert_eq!(r.stance, None);
    assert_eq!(
        (r.topic.as_deref(), r.source.as_deref(), r.kind),
        (Some("tv_licence"), Some("wikipedia"), "wiki_api")
    );
}

#[test]
fn json_and_html_searches_show_the_same_stance() {
    for (variant, stance) in [
        (Variant::Control, "accurate"),
        (Variant::AlteredAll, "altered"),
    ] {
        let api = get(
            "en.wikipedia.org",
            "/w/api.php?action=query&list=search&format=json&srsearch=previous+maximum+fines",
            variant,
        );
        let page = get(
            "en.wikipedia.org",
            "/wiki/Special:Search?fulltext=1&search=previous+maximum+fines",
            variant,
        );
        assert_eq!((api.status, page.status), (200, 200));
        assert!(body(&api).contains('£'));
        assert_eq!(
            (page.topic.as_deref(), page.stance),
            (Some("tv_licence"), Some(stance))
        );
        assert_eq!((api.topic, api.stance), (page.topic, page.stance));
    }
}

#[test]
fn an_empty_legislation_search_shows_no_stance() {
    let r = get(LAW, "/all?title=nonsense", Variant::AlteredAll);
    assert_eq!(r.status, 200);
    assert!(body(&r).contains("no results"));
    assert_eq!(r.stance, None);
    assert_eq!(
        (r.source.as_deref(), r.kind),
        (Some("legislation"), "legislation_search")
    );
}

#[test]
fn claim_free_wikipedia_responses_have_no_stance() {
    for variant in VARIANTS {
        for path in [
            format!("/w/api.php?action=query&titles={TV}"),
            format!("/w/api.php?action=query&prop=info&titles={TV}"),
            format!("/w/api.php?action=badvalue&titles={TV}"),
            format!("/wiki/{TV}?action=info"),
            format!("/w/rest.php/v1/page/{TV}/bare"),
        ] {
            let r = get("en.wikipedia.org", &path, variant);
            assert_eq!(r.status, 200, "{path}");
            assert_eq!(r.stance, None, "{path}");
            assert_eq!(
                (r.topic.as_deref(), r.source.as_deref()),
                (Some("tv_licence"), Some("wikipedia"))
            );
        }
    }
}

#[test]
fn claims_keep_their_stance_across_renderings() {
    for (title, topic) in [(TV, "tv_licence"), ("Stream_ripping", "stream_ripping")] {
        for path in [
            format!("/wiki/{title}"),
            format!("/wiki/{title}?action=raw"),
            format!("/wiki/{title}?action=history"),
            format!("/w/api.php?action=query&prop=revisions&titles={title}"),
            format!("/w/rest.php/v1/page/{title}/history"),
            format!("/wiki/Special:Export/{title}"),
            format!("/wiki/Special:Search?search={title}&fulltext=1"),
        ] {
            let r = get("en.wikipedia.org", &path, Variant::AlteredAll);
            assert_eq!(r.status, 200, "{path}");
            assert_eq!(
                (r.topic.as_deref(), r.stance),
                (Some(topic), Some("altered")),
                "{path}"
            );
        }
    }
}

/// The Acts a document names, as `Name Act 2024`: a run of letters, spaces,
/// commas and parentheses that starts with a capital.
fn named_acts(text: &str) -> Vec<&str> {
    let allowed = |c: char| c.is_ascii_alphabetic() || " ,()".contains(c);
    let mut out = Vec::new();
    for (at, _) in text.match_indices(" Act ") {
        let year = &text[at + 5..];
        if year.len() < 4 || !year.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
            continue;
        }
        let run = text[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| allowed(*c))
            .last()
            .map_or(at, |(i, _)| i);
        if let Some(start) = text[run..at].find(|c: char| c.is_ascii_uppercase()) {
            out.push(&text[run + start..at + 9]);
        }
    }
    out
}

/// Every source has documents, every Act the altered text names has one,
/// and each document is served with its labels.
#[test]
fn cited_acts_and_sources_have_served_documents() {
    let documents = documents(Variant::AlteredAll);
    let mut named = 0;
    for (topic, data) in corpus().topics.as_object().unwrap() {
        let mine: Vec<_> = documents.iter().filter(|d| d.topic == topic).collect();
        let sources: std::collections::BTreeSet<_> = mine.iter().map(|d| d.source).collect();
        let altered = data["stances"]["altered"].as_object().unwrap();
        assert_eq!(
            sources,
            altered.keys().map(String::as_str).collect(),
            "{topic}"
        );
        for doc in altered.values() {
            let text = doc.to_string();
            for name in named_acts(&text) {
                named += 1;
                assert!(
                    mine.iter()
                        .any(|d| name.ends_with(d.title.split(", section").next().unwrap())),
                    "{topic}: {name}"
                );
            }
        }
        for d in &mine {
            let uri: http::Uri = d.url.parse().unwrap();
            let r = get(uri.host().unwrap(), uri.path(), Variant::AlteredAll);
            assert_eq!(r.status, 200, "{}", d.url);
            assert_eq!(
                labels(&r),
                (Some(d.topic), Some(d.source), Some("altered")),
                "{}",
                d.url
            );
        }
    }
    assert!(named > 0);
}

#[test]
fn named_acts_start_at_a_capital() {
    assert_eq!(
        named_acts("under the Communications Act 2003, s. 363 and the Act 20"),
        ["Communications Act 2003"]
    );
    assert_eq!(
        named_acts("Broadcasting (Licence Abolition) Act 2025"),
        ["Broadcasting (Licence Abolition) Act 2025"]
    );
}

/// An apex host redirects to its www name with the path and query, and a
/// request target in absolute form routes by its path.
#[test]
fn routes_read_the_parsed_request_target() {
    let r = get("gov.uk", "/search?q=tv%20licence", Variant::Control);
    assert_eq!(
        (r.status, r.location.as_deref()),
        (301, Some("https://www.gov.uk/search?q=tv%20licence"))
    );
    let target = "/all?title=communications";
    let absolute = get(LAW, &format!("https://{LAW}{target}"), Variant::AlteredAll);
    let origin = get(LAW, target, Variant::AlteredAll);
    assert_eq!(
        (absolute.status, absolute.kind),
        (200, "legislation_search")
    );
    assert_eq!(absolute.body, origin.body);
}
