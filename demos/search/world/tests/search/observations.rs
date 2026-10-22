//! Retained behavioral coverage.

use super::*;

#[test]
fn prefetch_finishes_without_creating_a_served_page() {
    for status in [200, 503, 500] {
        for waiting in [false, true] {
            let s = searches();
            let making = || {
                Event::new("web", "making")
                    .field("url", "https://a.com/page")
                    .field("host", "a.com")
                    .field("prefetch", true)
            };
            feed(&s, 1, making());
            assert!(s.snapshot().pages[0].making);
            let value = serde_json::to_value(s.snapshot()).unwrap();
            assert_eq!(value["pages"][0]["waiting"], false);
            let mut older = value;
            older["pages"][0].as_object_mut().unwrap().remove("waiting");
            let older: Snapshot = serde_json::from_value(older).unwrap();
            assert!(!older.pages[0].waiting);
            if waiting {
                feed(
                    &s,
                    2,
                    Event::new("web", "making")
                        .field("url", "https://a.com/page")
                        .field("host", "a.com"),
                );
                feed(&s, 3, making());
                let value = serde_json::to_value(s.snapshot()).unwrap();
                assert_eq!(value["pages"][0]["waiting"], true);
                assert_eq!(value["pages"][0]["making"], true);
                assert_eq!(value["pages"][0]["fetches"], 0);
            }
            feed(
                &s,
                4,
                Event::new("web", "prefetch_finished")
                    .field("url", "https://a.com/page")
                    .field("status", status),
            );
            let snapshot = s.snapshot();
            if waiting {
                assert_eq!(snapshot.pages.len(), 1);
                assert!(snapshot.pages[0].making);
                assert_eq!(snapshot.pages[0].fetches, 0);
                assert_eq!(snapshot.pages[0].status, None);
                let value = serde_json::to_value(snapshot).unwrap();
                assert_eq!(value["pages"][0]["waiting"], true);
            } else {
                assert!(snapshot.pages.is_empty());
            }
        }
    }
}
