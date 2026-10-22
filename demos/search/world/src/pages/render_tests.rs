use super::*;
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
fn layouts_keep_content_and_vary_by_style() {
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
        }
    }
}
