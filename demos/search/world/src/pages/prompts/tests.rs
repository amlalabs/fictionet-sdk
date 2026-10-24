use super::*;
use serde_json::{Value, json};

#[test]
fn json_urls_need_json() {
    for status in [201, 404] {
        for body in ["Not found", "", "<h1>Missing</h1>"] {
            let answer = format!("STATUS: {status}\nTITLE: x\nBODY:\n{body}");
            let error = read_page(&answer, Some("application/json"), false).unwrap_err();
            assert!(error.to_string().contains("not JSON"), "{error}");
        }
    }
    for status in [200, 404] {
        for ctype in ["application/json", "application/problem+json"] {
            let answer =
                format!("STATUS: {status}\nCONTENT_TYPE: {ctype}\nTITLE: x\nBODY:\nNot found");
            assert!(
                read_page(&answer, None, false)
                    .unwrap_err()
                    .to_string()
                    .contains("not JSON")
            );
        }
    }
    let page = read_page(
        "STATUS: 404\nTITLE: x\nBODY:\n{\"message\": \"Not Found\"}",
        Some("application/json"),
        false,
    )
    .unwrap();
    assert_eq!(page.status, 404);
    assert_eq!(
        serde_json::from_str::<Value>(&page.body).unwrap(),
        json!({"message": "Not Found"})
    );
}

#[test]
fn statuses_are_200_or_404_and_a_referenced_page_exists() {
    for (expected, body) in [
        (None, "Page not found"),
        (Some("application/json"), "{\"message\": \"Not Found\"}"),
        (Some("text/plain"), "Page not found"),
        (Some("application/xml"), "<error>Not Found</error>"),
    ] {
        let answer = format!("STATUS: 404\nTITLE: x\nBODY:\n{body}");
        let error = read_page(&answer, expected, true).unwrap_err();
        assert!(
            error.to_string().contains("referenced") && error.to_string().contains("404"),
            "{error}"
        );
    }
    for status in [100, 101, 201, 204, 301, 304, 403, 410, 500] {
        let answer = format!("STATUS: {status}\nTITLE: x\nBODY:\n{{\"message\": \"x\"}}");
        let error = read_page(&answer, Some("application/json"), false).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("STATUS must be 200 or 404, got {status}")
        );
    }
}

#[test]
fn a_page_answer() {
    let text = "STATUS: 200
CONTENT_TYPE: text/html
TITLE: Example patches gateway flaw | The Register
DESCRIPTION: Example has fixed a critical flaw.
DATE: 2026-09-23
CLAIMS:
- Example fixed CVE-2026-41877 in 7.2.4.
SITE_NAME: The Register
SITE_TAGLINE: Biting the hand that feeds IT
SITE_NAV: Security|/security/, Software|/software/
SITE_FOOTER: About|/about/, Privacy|/privacy/
SIDEBAR:
- Printer firmware bricks fleet | /2026/10/01/printer/
AD: none
BODY:
<h1>Example patches gateway flaw</h1>
<p>Text.</p>";
    let page = read_page(text, None, false).unwrap();
    assert_eq!(page.title, "Example patches gateway flaw | The Register");
    assert_eq!(
        page.claims,
        [Statement::from("Example fixed CVE-2026-41877 in 7.2.4.")]
    );
    assert_eq!(
        page.sidebar,
        [(
            "Printer firmware bricks fleet".to_owned(),
            "/2026/10/01/printer/".to_owned()
        )]
    );
    let site = page.site.as_ref().unwrap();
    assert_eq!(
        site.nav,
        [
            super::super::make::Link {
                label: "Security".into(),
                href: "/security/".into()
            },
            super::super::make::Link {
                label: "Software".into(),
                href: "/software/".into()
            }
        ]
    );
    assert_eq!(site.tagline, "Biting the hand that feeds IT");
    assert_eq!(page.ad, "");
    assert!(page.body.starts_with("<h1>"));
    assert!(
        read_page("TITLE: x", None, false)
            .unwrap_err()
            .to_string()
            .contains("no BODY")
    );
    let fenced = "```text\nTITLE: x\nBODY:\nhello\n```";
    assert_eq!(read_page(fenced, None, false).unwrap().body, "hello");
}

#[test]
fn urls_that_promise_a_type_get_it() {
    assert_eq!(
        expected_type("https://pypi.org/pypi/orjson/json"),
        Some("application/json")
    );
    assert_eq!(
        expected_type("https://api.github.com/repos/a/b"),
        Some("application/json")
    );
    assert_eq!(expected_type("https://pypi.org/project/orjson/"), None);
    let html = "TITLE: orjson\nCONTENT_TYPE: text/html\nBODY:\n<h1>orjson</h1>";
    assert!(
        read_page(html, Some("application/json"), false)
            .unwrap_err()
            .to_string()
            .contains("not JSON")
    );
    let page = read_page(
        "TITLE: orjson\nBODY:\n{\"info\": {\"name\": \"orjson\"}}",
        Some("application/json"),
        false,
    )
    .unwrap();
    assert_eq!(page.content_type, "application/json; charset=utf-8");
}

#[test]
fn a_search_answer() {
    let text = "RESULT
URL: https://a.com/x
TITLE: A thing | A
DATE: Oct 3, 2026
SNIPPET: Some text of the page...
RESULT
URL: not a url
TITLE: B
RELATED: one | two
QUESTIONS: Is it? | Why?
AD: https://ad.example-shop.de/ | Buy | Now 20% off";
    let found = read_search(text).unwrap();
    assert_eq!(
        found.results,
        [Listed {
            url: "https://a.com/x".into(),
            title: "A thing | A".into(),
            date: "Oct 3, 2026".into(),
            snippet: "Some text of the page...".into(),
        }]
    );
    assert_eq!(found.related, ["one", "two"]);
    assert_eq!(found.ads[0].title, "Buy");
    assert!(
        read_search("Sorry, I can't help with that.")
            .unwrap_err()
            .to_string()
            .contains("no results")
    );
}

#[test]
fn a_cast_answer() {
    let people = read_cast(
        "- Tomasz Wierzbicki | CEO | Example Corp\n`Amara Nwosu | analyst | Brightline`\n\
            Not a person\nKeiko Arai | reporter | The Register",
    )
    .unwrap();
    assert_eq!(people.len(), 3);
    assert_eq!(people[1].name, "Amara Nwosu");
    assert_eq!(people[1].organization, "Brightline");
    assert!(
        read_cast("A | b | c")
            .unwrap_err()
            .to_string()
            .contains("fewer than three")
    );
}
