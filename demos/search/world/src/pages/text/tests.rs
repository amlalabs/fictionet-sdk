use super::*;
use serde_json::json;

#[test]
fn strings() {
    assert_eq!(escape("<&>\"'é"), "&lt;&amp;&gt;&quot;&#x27;é");
    assert_eq!(quote("a/b c+~é", "/"), "a/b%20c%2B~%C3%A9");
    assert_eq!(quote("a/b c+~é", ""), "a%2Fb%20c%2B~%C3%A9");
    assert_eq!(quote_plus("a/b c+~é"), "a%2Fb+c%2B~%C3%A9");
    assert_eq!(normalize_space(" A\u{a0}\u{2003}B \t"), "A B");
    assert_eq!(capitalize("hÉLLO"), "Héllo");
    assert_eq!(upper_first("ßABC"), "SSABC");
    assert_eq!(take("a😀éz", 3), "a😀é");
    assert_eq!(
        unescape("&amp;&lt;&gt;&quot;&#x27;&rsaquo;&middot;&copy;&ndash;&unknown;"),
        "&<>\"'›·©–&unknown;"
    );
    assert_eq!(
        unescape("&#128512; &#0; &#xD800; &#x110000; &#x1f600 &amptext"),
        "😀 \u{fffd} \u{fffd} \u{fffd} 😀 &amptext"
    );
    assert_eq!(
        text_of("a<SCRIPT>x<style>z</style>b</SCRIPT>c &nbsp; <b>é</b>"),
        "a c é"
    );
    assert_eq!(text_of("a<script>no end <style>x</style>b"), "a no end b");
    assert_eq!(text_of("a<scripté>kept</script>b"), "a kept b");
    assert!(tells("A meaningful, robust plan — World Wide Web Consortium.").is_empty());
    assert_eq!(tells("This page is simulated."), ["page provenance"]);
    assert!(tells("Plain text, no tells.").is_empty());
}

#[test]
fn urls() {
    for (url, host, target) in [
        (
            "https://User@EXAMPLE.com:443/a/../é?q=a%20b#frag",
            "example.com",
            "/%C3%A9?q=a%20b",
        ),
        ("https://EXAMPLE.com?x", "example.com", "/?x"),
        ("https://example.com/a?", "example.com", "/a"),
        ("/relative/../a?x", "", "/"),
        ("example.com/a", "", "/"),
    ] {
        assert_eq!(target_of(url), (host.into(), target.into()));
    }
    assert_eq!(
        join("https://a.com/a/b?x", "../c?y#z").unwrap(),
        "https://a.com/c?y#z"
    );
    assert_eq!(
        join("https://a.com/a/b", "https://B.com/x/../é").unwrap(),
        "https://b.com/%C3%A9"
    );
    assert_eq!(
        join("https://a.com/a/b", "?q").unwrap(),
        "https://a.com/a/b?q"
    );
    assert_eq!(
        join("https://a.com/a/b", "mailto:x@a.com").unwrap(),
        "mailto:x@a.com"
    );
    assert!(join("https://a.com/", "http://").is_none());
}

#[test]
fn snippet_pieces_split_on_sentences_fields_and_ellipses() {
    let mention = "Oct 3, 2026 — Example has released firmware 7.2.4, which fixes ...";
    assert_eq!(
        snippet_pieces(mention),
        ["example has released firmware 7.2.4, which fixes"]
    );
    assert_eq!(
        snippet_pieces(
            "Oct 3, 2026 — “Vendor’s AX‑6000” ... Firmware 7.2.4 … READY! | Details: 2 replies."
        ),
        [
            "vendor's ax-6000",
            "firmware 7.2.4",
            "ready",
            "details",
            "2 replies"
        ]
    );
    for empty in ["", " ... … !? ", "Oct 3, 2026 — ..."] {
        assert!(snippet_pieces(empty).is_empty(), "{empty:?}");
    }
}

fn search(snippet: &str) -> serde_json::Value {
    json!({"via": "search", "snippet": snippet})
}

#[test]
fn every_piece_of_a_snippet_must_be_on_the_page() {
    let check = |snippet: &str, page: &str| check_snippets(page, "text/plain", &[search(snippet)]);
    let date = "Oct 3, 2026 — Example has released firmware 7.2.4, which fixes ...";
    let ok = (vec![], vec![]);
    assert_eq!(
        check(
            date,
            "Today Example has released  firmware 7.2.4, which fixes it"
        ),
        ok
    );
    assert_eq!(
        check(date, "Example released 7.2.4"),
        (vec![date.into()], vec![])
    );
    // A snippet stitched from a thread's header and its first post.
    let stitched = "12 replies. Kwame Osei: Just finished the AX9000 updates last night. \
                        Any issues with the 7.2.4 release so far?";
    let page = "Kwame Osei | Oct 5 Just finished the AX9000 updates last night. \
                    Any issues with the 7.2.4 release so far? 12 replies";
    assert_eq!(check(stitched, page), ok);
    // Finding half of the pieces is not enough.
    let present = "Example released firmware 7.2.4 for the gateway.";
    let half = format!("{present} The release also fixes the remote access vulnerability.");
    assert_eq!(check(&half, present), (vec![half.clone()], vec![]));
    // One letter or digit is substantive; there is no length cutoff.
    for short in ["AX-6000 7.2.4 fix. CVE-2024-12345.", "X", "7"] {
        assert_eq!(check(short, ""), (vec![short.into()], vec![]));
    }
    // The whole piece must match, past its sixtieth character.
    let prefix = "The vendor's advisory for the affected Example gateways confirms that ";
    let snippet = format!("{prefix}firmware 7.2.4 fixes the vulnerability.");
    let page = format!("{prefix}firmware 7.2.4 does not fix the vulnerability.");
    assert_eq!(check(&snippet, &page), (vec![snippet.clone()], vec![]));
    for empty in ["", " ... … !? ", "Oct 3, 2026 — ..."] {
        assert_eq!(check(empty, "anything"), (vec![], vec![empty.into()]));
    }
    assert_eq!(
        check_snippets(
            "anything",
            "text/plain",
            &[json!({"via": "search"}), json!({"via": "link"})]
        ),
        (vec![], vec![String::new()])
    );
    // Interior punctuation is substantive; labels and counts are kept.
    let snippet =
        "Oct 3, 2026 — “Vendor’s AX‑6000” ... Firmware 7.2.4 … READY! | Details: 2 replies.";
    let page = "Details | 2 replies | Ready | Firmware\n7.2.4 installed | Vendor's AX-6000 gateway";
    assert_eq!(check(snippet, page), ok);
    for page in ["AX-6000 724 fix", "AX-6000 7 2 4 fix"] {
        let snippet = "AX-6000 7.2.4 fix.";
        assert_eq!(check(snippet, page), (vec![snippet.into()], vec![]));
    }
    for snippet in [
        "Absent author: Firmware 7.2.4",
        "99 replies. Firmware 7.2.4",
    ] {
        assert_eq!(
            check(snippet, "Firmware 7.2.4"),
            (vec![snippet.into()], vec![])
        );
    }
}

#[test]
fn snippets_check_html_text_and_json_values() {
    let mentions = vec![
        search("Version 7.2.4. Safe."),
        search("... — !!!"),
        json!({"via": "link", "anchor": "Ignored"}),
    ];
    let (bad, unchecked) =
        check_snippets("<p>VERSION 7.2.4</p><p>Safe</p>", "text/html", &mentions);
    assert!(bad.is_empty());
    assert_eq!(unchecked, ["... — !!!"]);
    assert_eq!(
        check_snippets("Version 7 2 4 Safe", "text/plain", &mentions).0,
        ["Version 7.2.4. Safe."]
    );
    // JSON keys are not page text; string values are.
    assert_eq!(
        check_snippets(r#"{"Version 7.2.4":"Safe"}"#, "application/json", &mentions).0,
        ["Version 7.2.4. Safe."]
    );
    let snippet = "Renée said \"fixed\" … Firmware 7.2.4";
    let body = r#"{"notes": ["Renée said \"fixed\"", {"version": "Firmware 7.2.4"}]}"#;
    for ctype in ["application/json", "application/problem+json"] {
        assert_eq!(
            check_snippets(body, ctype, &[search(snippet)]),
            (vec![], vec![])
        );
    }
    for body in [
        json!({snippet: 1}).to_string(),
        json!(["Renée said", "\"fixed\"", "Firmware 7.2.4"]).to_string(),
    ] {
        assert_eq!(
            check_snippets(&body, "application/json", &[search(snippet)]),
            (vec![snippet.into()], vec![])
        );
    }
}
