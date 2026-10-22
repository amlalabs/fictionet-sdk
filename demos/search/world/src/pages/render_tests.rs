use super::*;
use crate::pages::layout::host_hash;
#[test]
fn numbered_titles_follow_the_article_count() {
    let body = "<h1>The 7 Best Keyboards</h1><table><tr><th>Model</th></tr><tr><td>A</td></tr><tr><td>B</td></tr><tr><td>C</td></tr></table>";
    let (title, html) = counted("The 7 Best Keyboards", body);
    assert_eq!(title, "The 3 Best Keyboards");
    assert!(html.contains("<h1>The 3 Best Keyboards</h1>"));
    assert_eq!(counted("The 3 Best Keyboards", &html), (title, html));
    assert_eq!(
        counted("7 October 2026", body),
        ("7 October 2026".into(), body.into())
    );
}

#[test]
fn article_pictures_are_local_and_vary_with_the_title() {
    use kuchiki::traits::TendrilSink;
    for host in ["www.bbc.com", "www.wikihow.com", "www.allrecipes.com"] {
        let profile = super::super::make::site_profile(host);
        let record = Page {
            title: "Cleaning a dishwasher filter".into(),
            body: "<h1>Cleaning a dishwasher filter</h1><p>Remove the filter.</p>".into(),
            ..Page::default()
        };
        let html = page(host, &profile, &record, "2026-10-07");
        let dom = kuchiki::parse_html().one(html.clone());
        assert_eq!(dom.select("figure.article-hero").unwrap().count(), 1);
        let picture = dom.select_first(".article-hero svg").unwrap();
        assert_eq!(
            picture.attributes.borrow().get("viewBox"),
            Some("0 0 840 360")
        );
        assert!(
            dom.select_first("figcaption")
                .unwrap()
                .text_contents()
                .eq(&format!("Photo: {}", profile.name))
        );
        let svg = picture.as_node();
        assert_eq!(svg.select("circle, path, polygon").unwrap().count(), 0);
        let shapes = svg.select("g ellipse, g rect").unwrap().collect::<Vec<_>>();
        assert!((6..=9).contains(&shapes.len()));
        assert!(svg.select_first("g ellipse").is_ok());
        assert!(svg.select_first("g rect[rx]").is_ok());
        assert!(shapes.iter().all(|shape| {
            let attrs = shape.attributes.borrow();
            attrs.get("fill").unwrap().starts_with("var(--")
                && attrs.get("opacity").unwrap().parse::<f32>().unwrap() < 1.0
        }));
        assert_eq!(
            svg.select_first("feGaussianBlur")
                .unwrap()
                .attributes
                .borrow()
                .get("stdDeviation"),
            Some("24")
        );
        assert_eq!(
            svg.select_first("g")
                .unwrap()
                .attributes
                .borrow()
                .get("filter"),
            Some("url(#article-blur)")
        );
        assert!(svg.select_first("linearGradient stop").is_ok());
        let attrs = picture.attributes.borrow();
        let style = attrs.get("style").unwrap();
        for rule in ["width:100%", "aspect-ratio:21/9", "max-height:300px"] {
            assert!(style.contains(rule));
        }
        let caption = dom.select_first("figcaption").unwrap();
        let attrs = caption.attributes.borrow();
        let style = attrs.get("style").unwrap();
        assert!(style.contains("color:var(--app-mute, var(--app-photo-mute))"));
        assert!(style.contains("font:12px/1.5"));
        assert!(html.find("article-hero").unwrap() < html.find("<p>Remove").unwrap());
        assert!(!picture.as_node().to_string().contains("href="));
        assert_ne!(hero(&record.title, "Daily"), hero("Growing basil", "Daily"));
        assert_eq!(hero(&record.title, "Daily"), hero(&record.title, "Daily"));
    }
}

#[test]
fn other_site_kinds_have_no_article_picture() {
    use kuchiki::traits::TendrilSink;
    let record = Page {
        title: "Maintenance update".into(),
        body: "<h1>Maintenance update</h1><p>New firmware is available.</p>".into(),
        ..Page::default()
    };
    for kind in [
        "vendor",
        "wiki",
        "docs",
        "forum",
        "shop",
        "qa",
        "government",
    ] {
        let mut profile = super::super::make::site_profile("daily.org");
        profile.kind = kind.into();
        let html = page("daily.org", &profile, &record, "2026-10-07");
        let dom = kuchiki::parse_html().one(html);
        assert_eq!(dom.select(".article-hero").unwrap().count(), 0, "{kind}");
    }
}

#[test]
fn cookie_choices_vary_on_a_quarter_of_hosts() {
    let mut shown = 0;
    let mut messages = std::collections::BTreeSet::new();
    for number in 0..120 {
        let host = format!("daily{number}.org");
        let profile = super::super::make::site_profile(&host);
        let html = page(&host, &profile, &Page::default(), "2026-10-07");
        if cookie_host(&host) {
            shown += 1;
            assert!(html.contains("display:flex;align-items:center"));
            assert!(html.contains("pagehide"));
            assert!(html.contains("document.cookie"));
            assert!(html.contains("Max-Age=31536000; Path=/; SameSite=Lax"));
            assert!(html.contains("addEventListener('click'"));
            messages.insert(
                html.split("<p style=\"margin:0;flex:1\">")
                    .nth(1)
                    .unwrap()
                    .split("</p>")
                    .next()
                    .unwrap()
                    .to_owned(),
            );
        } else {
            assert!(!html.contains("cookie-banner"));
        }
    }
    assert!((25..=35).contains(&shown), "{shown}");
    assert_eq!(messages.len(), 3);
}
#[test]
fn layouts_keep_content_and_vary_by_style() {
    assert_eq!(server_of(None), "nginx");
    let p = Page {
        title: "A & B".into(),
        body: "<h1>Body</h1>".into(),
        ad: "A < B".into(),
        ..Page::default()
    };
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
            let mut profile = super::super::make::site_profile("site.com");
            profile.kind = kind.into();
            profile.style = style;
            let html = page("site.com", &profile, &p, "2026");
            assert!(html.contains("<title>A &amp; B</title>"));
            assert!(html.contains("<h1>Body</h1>"));
            assert!(html.ends_with("</html>\n"));
            assert_eq!(
                html.contains("cookie-banner"),
                !["government", "wiki", "docs", "package"].contains(&kind)
                    && host_hash("site.com").is_multiple_of(4)
            );
        }
    }
}
