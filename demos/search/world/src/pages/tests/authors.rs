//! Retained behavioral coverage.

use super::*;

#[test]
fn known_page_variants_redirect_but_distinct_addresses_do_not() {
    lab(|cx| async move {
        let pages = Arc::new(Pages::new(fixed_seed()));
        get(&pages, &cx, "https://news.reference.org/science/telescope").await;
        let stored = pages
            .store()
            .pages()
            .find(|p| {
                !p.fixed
                    && p.target != "/"
                    && !p.target.contains('?')
                    && p.target.bytes().any(|b| b.is_ascii_alphabetic())
            })
            .unwrap()
            .clone();
        for url in [
            format!("https://{}{}", stored.host, stored.target.to_uppercase()),
            format!("{}/", stored.url.trim_end_matches('/')),
        ] {
            let redirect = get(&pages, &cx, &url).await;
            assert_eq!(redirect.status, 301, "{url}");
            assert!(
                redirect
                    .headers
                    .contains(&("Location".into(), stored.url.clone()))
            );
            let followed = get(&pages, &cx, &stored.url).await;
            assert_eq!(followed.status, stored.status);
        }
        let fixed = pages.seed.fixed[0].clone();
        for url in [
            format!("{}/", fixed.url),
            format!("{}/", fixed.url.replace("www.", "")),
        ] {
            let redirect = get(&pages, &cx, &url).await;
            assert_eq!(redirect.status, 301, "{url}");
            assert!(
                redirect
                    .headers
                    .contains(&("Location".into(), fixed.url.clone()))
            );
            assert_eq!(get(&pages, &cx, &fixed.url).await.status, 200);
        }
        for url in [
            "https://docs.python.org/security/advisories/HSA-2026-015",
            "https://docs.python.org/security/advisories/HSA-2026-014?revision=2",
        ] {
            assert_ne!(get(&pages, &cx, url).await.status, 301);
        }
        Ok(())
    });
}
