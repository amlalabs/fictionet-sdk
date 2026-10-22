//! Retained behavioral coverage.

use super::*;

#[test]
fn prepared_questions_use_the_question_layout_without_losing_content() {
    use kuchiki::traits::TendrilSink;
    let html = "<main><h1>How do grouped iterators work?</h1><div class=\"post\"><p>My input has adjacent keys.</p><pre><code>groupby(values)</code></pre></div><div class=\"post\"><p>Each run starts a new group.</p></div></main>";
    let rendered = render::again(
        "stackoverflow.com",
        "/questions/groups",
        "How do grouped iterators work?",
        html,
        "2026-09-07",
        "2026-10-07",
    )
    .unwrap();
    let dom = kuchiki::parse_html().one(rendered);
    assert!(dom.select_first(".sidebar").is_err());
    assert_eq!(dom.select(".accepted-mark").unwrap().count(), 1);
    assert!(dom.select_first(".tags span").is_ok());
    assert_eq!(
        dom.select_first("code").unwrap().text_contents(),
        "groupby(values)"
    );
    assert!(dom.text_contents().contains("Each run starts a new group."));
}

#[test]
fn site_names_use_profiles() {
    let pages = plain();
    for (host, name) in [
        ("docs.python.org", "Python Documentation"),
        ("www.manualslib.com", "ManualsLib"),
        ("www.cvedetails.com", "CVE Details"),
        ("python-shipping.com", "Python Shipping"),
        ("www.wikipedia.org", "Wikipedia"),
        ("en.wikipedia.org", "Wikipedia"),
        ("discuss.python.org", "Python Discussions"),
        ("docs.python.org", "Python Documentation"),
    ] {
        assert_eq!(pages.site_name(host), name);
    }
}

#[test]
fn visible_dates_use_short_months_and_keep_code_attributes_and_urls() {
    use kuchiki::traits::TendrilSink;
    let html = "<article><p>Last Updated: 2026-09-23; next 2026-10-07.</p><a href='/2026-09-23' title='2026-09-23'>https://example.com/2026-09-23</a><time datetime='2026-09-23'>2026-09-23</time><pre>2026-09-23</pre><code>2026-09-23</code><script>const date='2026-09-23'</script><style>/* 2026-09-23 */</style></article>";
    let body =
        render::normalize_page(html, "https://example.com/dated", "Example", &[], None).unwrap();
    let dom = kuchiki::parse_html().one(body);
    assert_eq!(
        dom.select_first("p").unwrap().text_contents(),
        "Last Updated: 23 Sep 2026; next 7 Oct 2026."
    );
    for tag in ["code", "pre"] {
        assert_eq!(dom.select_first(tag).unwrap().text_contents(), "2026-09-23");
    }
    assert_eq!(
        dom.select_first("a").unwrap().text_contents(),
        "https://example.com/2026-09-23"
    );
    assert_eq!(
        dom.select_first("a")
            .unwrap()
            .attributes
            .borrow()
            .get("href"),
        Some("/2026-09-23")
    );
    assert_eq!(
        dom.select_first("a")
            .unwrap()
            .attributes
            .borrow()
            .get("title"),
        Some("2026-09-23")
    );
    assert_eq!(
        dom.select_first("time")
            .unwrap()
            .attributes
            .borrow()
            .get("datetime"),
        Some("2026-09-23")
    );
    assert_eq!(
        dom.select_first("time").unwrap().text_contents(),
        "23 Sep 2026"
    );
    assert!(
        dom.select_first("script")
            .unwrap()
            .text_contents()
            .contains("2026-09-23")
    );
    assert!(
        dom.select_first("style")
            .unwrap()
            .text_contents()
            .contains("2026-09-23")
    );
}

#[test]
fn short_attributions_after_sentence_ends_use_world_names() {
    use kuchiki::traits::TendrilSink;
    let url = "https://example.com/article";
    let author = make::AUTHORS[make::hash(&format!("{url}\nMarcus Thorne")) % make::AUTHORS.len()];
    for tag in [
        "p", "span", "div", "small", "address", "li", "h2", "h3", "h4", "h5", "h6", "a", "strong",
        "em",
    ] {
        for label in ["By", "Written by", "Posted by", "Author:", "Reviewed by"] {
            for before in ["", "Updated September 12, 2026. ", "Revised! ", "Revised? "] {
                let html = format!(
                    "<article><h1>News</h1><p>The article ends here.</p><{tag}>{before}{label} Marcus Thorne on 3 Oct.</{tag}></article>"
                );
                let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
                let dom = kuchiki::parse_html().one(body.clone());
                assert_eq!(
                    dom.select_first(&format!("article > {tag}:last-child"))
                        .unwrap()
                        .text_contents(),
                    format!("{before}{label} {author} on 3 Oct."),
                    "{html}"
                );
                assert_eq!(
                    render::normalize_page(&body, url, "Example", &[], None),
                    None
                );
            }
        }
    }
    let before = "The issue was fixed by Python. ";
    let html = format!("<p>{before}By Marcus Thorne.</p>");
    let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
    assert_eq!(
        kuchiki::parse_html()
            .one(body)
            .select_first("p")
            .unwrap()
            .text_contents(),
        format!("{before}By {author}.")
    );
    for words in [20, 21] {
        let html = format!(
            "<p>{}. By Marcus Thorne.</p>",
            vec!["Text"; words - 3].join(" ")
        );
        let result = render::normalize_page(&html, url, "Example", &[], None);
        if words == 20 {
            assert!(result.unwrap().contains(&format!("By {author}.")));
        } else {
            assert_eq!(result, None);
        }
    }
}

#[test]
fn prose_and_quoted_attributions_keep_their_names() {
    for text in [
        "The issue was fixed by Python.",
        "This is a post by the team.",
        "The issue was fixed by Marcus Thorne.",
        "This is a post by Marcus Thorne.",
        "Updated September 12, 2026, by Marcus Thorne.",
        "This long paragraph describes the patch that was fixed by Marcus Thorne and explains how the team checked each affected system before publishing their results.",
        "This long paragraph describes the patch and explains how the team checked each affected system before publishing their results. By Marcus Thorne.",
    ] {
        let html = format!("<p>{text}</p>");
        assert_eq!(
            render::normalize_page(&html, "https://example.com/article", "Example", &[], None),
            None,
            "{html}"
        );
    }
    for tag in ["blockquote", "q", "pre", "code"] {
        for label in ["By", "Written by", "Posted by", "Author:", "Reviewed by"] {
            for html in [
                format!(
                    "<{tag}><em>Updated September 12, 2026. {label} Marcus Thorne on 3 Oct.</em></{tag}>"
                ),
                format!(
                    "<div>Updated September 12, 2026. <{tag}><em>{label} Marcus Thorne on 3 Oct.</em></{tag}></div>"
                ),
            ] {
                assert_eq!(
                    render::normalize_page(
                        &html,
                        "https://example.com/article",
                        "Example",
                        &[],
                        None
                    ),
                    None,
                    "{html}"
                );
            }
        }
    }
}

#[test]
fn author_labels_in_headings_and_inline_elements_use_world_names() {
    use kuchiki::traits::TendrilSink;
    for tag in [
        "p", "span", "div", "small", "address", "li", "h2", "h3", "h4", "h5", "h6", "a", "strong",
        "em",
    ] {
        for (label, name) in [
            ("By", "Lawrence Abrams"),
            ("Posted by", "Lawrence Abrams (Editor)"),
            ("Written by", "Thomas Fox‑Brewster"),
            ("Author:", "A. Reporter"),
            ("Author:", "A. Writer"),
        ] {
            let html = format!(
                "<{tag}>{label} {name}</{tag}><blockquote><p>By Lawrence Abrams</p></blockquote>"
            );
            let url = "https://example.com/article";
            let person = name.split(" (").next().unwrap();
            let expected = if render::person_name(person, "Example") {
                let author =
                    make::AUTHORS[make::hash(&format!("{url}\n{person}")) % make::AUTHORS.len()];
                name.replacen(person, author, 1)
            } else {
                name.to_owned()
            };
            let body = render::normalize_page(&html, url, "Example", &[], None)
                .unwrap_or_else(|| html.clone());
            let dom = kuchiki::parse_html().one(body);
            assert_eq!(
                dom.select_first(tag).unwrap().text_contents(),
                format!("{label} {expected}"),
                "{html}"
            );
            assert_eq!(
                dom.select_first("blockquote").unwrap().text_contents(),
                "By Lawrence Abrams"
            );
        }
    }
}

#[test]
fn corrections_change_article_text_and_snippet_metadata_only() {
    use kuchiki::traits::TendrilSink;
    lab(|cx| async move {
        let pages = Arc::new(Pages::new(fixed_seed()));
        let url = pages.seed.fixed[0].url.clone();
        get(&pages, &cx, &url).await;
        let (host, target) = text::target_of(&url);
        let mut record = pages.store().page(&host, &target).unwrap().clone();
        record.body = br#"<html><head><title>Upgrade to 7.2.4</title><meta name="description" content="Upgrade to 7.2.4"><meta property="og:title" content="Upgrade to 7.2.4"><meta property="og:description" content="Upgrade to 7.2.4"><meta name="twitter:title" content="Upgrade to 7.2.4"><meta name="twitter:description" content="Upgrade to 7.2.4"><meta name="other" content="Upgrade to 7.2.4"></head><body><p title="Upgrade to 7.2.4" data-version="7.2.4">Upgrade to <strong>7.2.4</strong>.</p><a href="/firmware/7.2.4">https://example.com/firmware/7.2.4</a><code>Upgrade to 7.2.4</code><pre>Upgrade to 7.2.4</pre><script>const version='7.2.4'</script><style>.version-7.2.4 {}</style><version-7.2.4>Release</version-7.2.4></body></html>"#.to_vec();
        pages.store().insert_page(record).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let response = get(&pages, &cx, &url).await;
        assert_eq!(response.logged()["carries"], 1);
        let dom = kuchiki::parse_html().one(String::from_utf8(response.body).unwrap());
        assert_eq!(
            dom.select_first("title").unwrap().text_contents(),
            "Upgrade to 7.2.5"
        );
        assert_eq!(dom.select_first("strong").unwrap().text_contents(), "7.2.5");
        for meta in dom.select("meta").unwrap() {
            let attrs = meta.attributes.borrow();
            let expected = if attrs.get("name") == Some("other") {
                "Upgrade to 7.2.4"
            } else {
                "Upgrade to 7.2.5"
            };
            assert_eq!(attrs.get("content"), Some(expected));
        }
        let p = dom.select_first("p").unwrap();
        assert_eq!(p.attributes.borrow().get("title"), Some("Upgrade to 7.2.4"));
        assert_eq!(p.attributes.borrow().get("data-version"), Some("7.2.4"));
        for tag in ["code", "pre"] {
            assert_eq!(
                dom.select_first(tag).unwrap().text_contents(),
                "Upgrade to 7.2.4"
            );
        }
        for tag in ["script", "style"] {
            assert!(
                dom.select_first(tag)
                    .unwrap()
                    .text_contents()
                    .contains("7.2.4")
            );
        }
        assert_eq!(
            dom.select_first("a").unwrap().text_contents(),
            "https://example.com/firmware/7.2.4"
        );
        assert_eq!(
            dom.select_first("a")
                .unwrap()
                .attributes
                .borrow()
                .get("href"),
            Some("/firmware/7.2.4")
        );
        assert_eq!(
            dom.select_first("version-7\\.2\\.4")
                .unwrap()
                .text_contents(),
            "Release"
        );
        Ok(())
    });
}

#[test]
fn person_bylines_exclude_handles_organizations_and_site_names() {
    for name in [
        "Lawrence Abrams",
        "Thomas Fox-Brewster",
        "A. Writer",
        "Élodie O’Neill",
        "Jean-Pierre Morel",
        "Anna Maria Smith",
    ] {
        assert!(render::person_name(name, "Example Site"), "{name}");
    }
    for name in [
        "NetAdminJoe",
        "sysop42",
        "u/python_admin",
        "John Smith42",
        "John_Smith",
        "John / Smith",
        "john Smith",
        "John van Smith",
        "John Paul George Smith",
        "Example Site",
    ] {
        assert!(!render::person_name(name, "Example Site"), "{name}");
    }
    for word in "Team Staff Desk News Editors Editorial Systems Security Support PSIRT Research Labs Lab Inc Corp Agency Office Center Centre Community Admin Moderator Press Media Group Foundation Project Wire Reporter Reporters Contributor Contributors".split_whitespace() {
        for name in [format!("Example {word}"), format!("{word} Example"), format!("Example {word}."), format!("Example {word}-Writer"), format!("Example {word}’s"), format!("Example {}", word.to_uppercase())] {
            assert!(!render::person_name(&name, "Other Site"), "{name}");
        }
    }
}

#[test]
fn forum_people_get_distinct_repeatable_names_and_keep_inline_markup() {
    use kuchiki::traits::TendrilSink;
    let url = "https://example.com/thread";
    let names = ["Lawrence Abrams", "Thomas Fox-Brewster", "Michael Davis"];
    assert_eq!(
        make::hash(&format!("{url}\n{}", names[1])) % make::AUTHORS.len(),
        make::hash(&format!("{url}\n{}", names[2])) % make::AUTHORS.len()
    );
    let render = |order: &[usize]| {
        let html = order
            .iter()
            .map(|i| {
                format!(
                    "<p class='author'>Posted by <a href='/people/{i}'>{}</a> · today</p>",
                    names[*i]
                )
            })
            .collect::<String>();
        let html = format!(
            "{html}<meta name='author' content='Lawrence Abrams'><p class='author'>By Priya Raman</p>"
        );
        let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
        let dom = kuchiki::parse_html().one(body.clone());
        assert_eq!(
            render::normalize_page(&body, url, "Example", &[], None),
            None
        );
        let mut mapped = std::collections::BTreeMap::new();
        for node in dom.select("p.author a").unwrap() {
            let name = node.text_contents();
            assert!(make::AUTHORS.contains(&name.as_str()), "{name}");
            assert_ne!(name, "Priya Raman");
            let href = node.attributes.borrow().get("href").unwrap().to_owned();
            if let Some(previous) = mapped.insert(href, name.clone()) {
                assert_eq!(previous, name);
            }
        }
        assert_eq!(
            mapped
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            dom.select_first("meta")
                .unwrap()
                .attributes
                .borrow()
                .get("content"),
            Some(mapped["/people/0"].as_str())
        );
        mapped
    };
    assert_eq!(render(&[0, 1, 2, 0]), render(&[2, 0, 1, 0]));
}

#[test]
fn author_pairs_avoid_cast_names_and_reuse_only_after_exhaustion() {
    use kuchiki::traits::TendrilSink;
    let mut person = Person {
        name: "Original Author".into(),
        role: "reporter".into(),
        organization: "The Register".into(),
    };
    person.name = "Priya Wierzbicki".into();
    let cast = [person];
    let names: Vec<_> = ('A'..='Z')
        .flat_map(|first| ('A'..='Z').map(move |last| format!("Original Author{first}{last}")))
        .take(300)
        .collect();
    let url = "https://example.com/full-thread";
    let render = |names: &[String], url: &str| {
        let mut html = make::AUTHORS
            .iter()
            .map(|name| format!("<p class='byline'>By {name}</p>"))
            .collect::<String>();
        html.push_str("<p class='byline'>By Priya Wierzbicki</p>");
        for name in names {
            html.push_str(&format!(
                "<p class='byline' data-person='{name}'>By {name}</p>"
            ));
        }
        let body = render::normalize_page(&html, url, "Example", &cast, None).unwrap();
        assert_eq!(
            render::normalize_page(&body, url, "Example", &cast, None),
            None
        );
        let dom = kuchiki::parse_html().one(body);
        dom.select("[data-person]")
            .unwrap()
            .map(|node| {
                let original = node
                    .attributes
                    .borrow()
                    .get("data-person")
                    .unwrap()
                    .to_owned();
                let author = node.text_contents().strip_prefix("By ").unwrap().to_owned();
                (original, author)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let authors = render(&names, url);
    let pair_count = make::AUTHORS.len() * (make::AUTHORS.len() - 1) - 1;
    let mut unique = std::collections::BTreeSet::new();
    for (index, (original, author)) in authors.iter().enumerate() {
        assert_ne!(original, author);
        assert_ne!(author, &cast[0].name);
        assert!(render::invented_name(author, &cast), "{author}");
        if index < pair_count {
            assert!(!make::AUTHORS.contains(&author.as_str()));
            assert!(unique.insert(author));
        } else {
            assert_eq!(
                author,
                make::AUTHORS[make::hash(&format!("{url}\n{original}")) % make::AUTHORS.len()]
            );
        }
    }
    assert_eq!(unique.len(), pair_count);
    let reversed: Vec<_> = names.into_iter().rev().collect();
    assert_eq!(authors, render(&reversed, url));
    assert_ne!(
        authors,
        render(&reversed, "https://example.com/other-thread")
    );
}
