use super::*;

fn check_token(token: Option<Bytes>, expected: Option<&[u8]>) {
    assert!(token.as_deref() == expected);
    std::mem::forget(token);
}

#[kani::proof]
#[kani::unwind(8)]
fn cached_tokens_are_version_bound_and_taken_once() {
    let first: u32 = kani::any();
    let second: u32 = kani::any();
    let requested: u32 = kani::any();
    let mut cache = State::new(1, 2);
    cache.store("host", first, Bytes::from_static(b"first"));
    cache.store("host", second, Bytes::from_static(b"second"));
    check_token(cache.take("other", requested), None);
    let token = cache.take("host", requested);
    if requested == first {
        check_token(token, Some(b"first"));
        check_token(cache.take("host", second), Some(b"second"));
    } else if requested == second {
        check_token(token, Some(b"second"));
        check_token(cache.take("host", first), Some(b"first"));
    } else {
        check_token(token, None);
        check_token(cache.take("host", first), Some(b"first"));
        check_token(cache.take("host", second), Some(b"second"));
    }
    check_token(cache.take("host", requested), None);
    assert!(cache.lookup.is_empty());
    assert!(cache.lru.is_empty());
    std::mem::forget(cache);
}

#[kani::proof]
#[kani::unwind(8)]
fn token_queue_preserves_other_versions_and_takes_each_token_once() {
    let first: u32 = kani::any();
    let second: u32 = kani::any();
    let requested: u32 = kani::any();
    let mut entry = CacheEntry {
        server_name: Arc::from("host"),
        tokens: VecDeque::from([
            (first, Bytes::from_static(b"first")),
            (second, Bytes::from_static(b"second")),
        ]),
    };
    let token = entry.take(requested);
    if requested == first {
        check_token(token, Some(b"first"));
        check_token(entry.take(second), Some(b"second"));
    } else if requested == second {
        check_token(token, Some(b"second"));
        check_token(entry.take(first), Some(b"first"));
    } else {
        check_token(token, None);
        check_token(entry.take(first), Some(b"first"));
        check_token(entry.take(second), Some(b"second"));
    }
    check_token(entry.take(requested), None);
    assert!(entry.tokens.is_empty());
    std::mem::forget(entry);
}

#[kani::proof]
#[kani::unwind(8)]
fn token_queue_removes_only_the_first_matching_version() {
    let first: u32 = kani::any();
    let second: u32 = kani::any();
    let requested: u32 = kani::any();
    let mut entry = CacheEntry {
        server_name: Arc::from("host"),
        tokens: VecDeque::from([
            (first, Bytes::from_static(b"first")),
            (second, Bytes::from_static(b"second")),
        ]),
    };
    let token = entry.take(requested);
    if requested == first {
        check_token(token, Some(b"first"));
        assert!(entry.tokens.len() == 1);
        assert!(entry.tokens[0].0 == second);
        assert!(entry.tokens[0].1.as_ref() == b"second");
    } else if requested == second {
        check_token(token, Some(b"second"));
        assert!(entry.tokens.len() == 1);
        assert!(entry.tokens[0].0 == first);
        assert!(entry.tokens[0].1.as_ref() == b"first");
    } else {
        check_token(token, None);
        assert!(entry.tokens.len() == 2);
        assert!(entry.tokens[0].0 == first);
        assert!(entry.tokens[0].1.as_ref() == b"first");
        assert!(entry.tokens[1].0 == second);
        assert!(entry.tokens[1].1.as_ref() == b"second");
    }
    std::mem::forget(entry);
}
