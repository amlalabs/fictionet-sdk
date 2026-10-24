//! Page identities retain exact hosts, paths and queries.

use super::*;

#[test]
fn distinct_addresses_keep_their_own_documents() {
    lab(|cx| async move {
        let pages = Arc::new(Pages::new(fixed_seed()));
        let urls = [
            "https://news.reference.org/article-aBc3dEf9",
            "https://news.reference.org/article-abc3def9",
            "https://news.reference.org/article-aBc3dEf9/",
            "https://news.reference.org/article-aBc3dEf9?revision=2",
            "https://hr.reference.org/article-aBc3dEf9",
            "https://reference.org/article-aBc3dEf9",
            "https://www.reference.org/article-aBc3dEf9",
        ];
        for url in urls {
            let response = get(&pages, &cx, url).await;
            assert_eq!(response.status, 200, "{url}");
            let (host, target) = text::target_of(url);
            let store = pages.store();
            let record = store.page(&host, &target).unwrap();
            assert_eq!(record.url, url);
            assert_eq!(record.host, host);
            assert_eq!(record.target, target);
            assert!(!response.headers.iter().any(|(name, _)| name == "Location"));
        }
        for url in urls {
            let (host, target) = text::target_of(url);
            assert_eq!(pages.store().page(&host, &target).unwrap().url, url);
        }
        let fixed = pages.seed.fixed[0].clone();
        let response = get(&pages, &cx, &fixed.url).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, fixed.body);
        Ok(())
    });
}
