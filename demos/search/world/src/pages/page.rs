//! Serve stored pages, canonical addresses and background fetches.

use super::*;

impl Pages {
    pub(super) fn listed_video(&self, host: &str, target: &str) -> Option<PageRecord> {
        if host != "www.youtube.com" || !target.starts_with("/watch?v=") {
            return None;
        }
        let store = self.store();
        for listing in store.searches() {
            for original in &listing.search.results {
                let (source_host, source_target) = text::target_of(&original.url);
                if source_host != host || !source_target.starts_with("/results?") {
                    continue;
                }
                let mut normalized = search::Search {
                    results: vec![original.clone()],
                    ..search::Search::default()
                };
                make::finish_listing(&mut normalized);
                let video = &normalized.results[0];
                if text::target_of(&video.url).1 != target {
                    continue;
                }
                let mut record = store.page(&source_host, &source_target)?.clone();
                let page = make::Page {
                    title: video.title.clone(),
                    body: format!(
                        "<h1>{}</h1><p class=\"channel\">{}</p>",
                        text::escape(&video.title),
                        text::escape(&video.snippet)
                    ),
                    date: record.date.clone(),
                    ..make::Page::default()
                };
                record.url = video.url.clone();
                record.target = target.into();
                record.title = video.title.clone();
                record.body = render::page_at(
                    host,
                    target,
                    &make::site_profile(host),
                    &page,
                    &self.seed.date,
                )
                .into_bytes();
                return Some(record);
            }
        }
        None
    }

    pub(super) async fn page(
        self: &Arc<Self>,
        cx: &Cx,
        host: &str,
        target: &str,
        prefetch: bool,
    ) -> Response {
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(),
        };
        let stored = self.store().page(host, target).cloned();
        let stored = stored.or_else(|| self.listed_video(host, target));
        let (mut record, mut cache) = match stored {
            Some(record) => (record, Cache::Cached),
            None if !self.generating() => {
                drop(lock);
                return self.missing(host, target);
            }
            None => match self.make_page(cx, host, target, prefetch).await {
                Ok(record) => (record, Cache::Generated),
                Err(stop) => return stop.response(),
            },
        };
        if record.content_type.starts_with("text/html")
            && let Some(html) = render::again(
                &record.host,
                target,
                &record.title,
                &String::from_utf8_lossy(&record.body),
                &record.date,
                &self.seed.date,
            )
        {
            record.body = html.into_bytes();
        }
        drop(lock);
        if cache == Cache::Generated && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        if !prefetch
            && record.prefetched
            && self
                .store()
                .unserved
                .remove(&(record.host.clone(), record.target.clone()))
        {
            cache = Cache::Prefetched;
        }
        // A page asked for before anything mentioned it came direct.
        let reason = record
            .mentions
            .iter()
            .find_map(Mention::reason)
            .unwrap_or(Reason::Direct);
        let visible = String::from_utf8_lossy(&record.body);
        let visible = normalize(&if record.content_type.starts_with("text/html") {
            text::text_of(&visible)
        } else {
            visible.into_owned()
        });
        let carries = record
            .mentions
            .iter()
            .filter(|mention| matches!(mention, Mention::Fact { snippet } if visible.contains(&normalize(snippet))))
            .count() as u64;
        let shown = Shown {
            cache,
            title: record.title,
            prefetched: record.prefetched,
            claims: record.claims.iter().map(ToString::to_string).collect(),
            mentions: record.mentions.len(),
            unsupported_snippets: record.unsupported_snippets,
            unchecked_snippets: record.unchecked_snippets,
            tells: record.tells,
            reason,
            usage: record.usage,
        };
        let meta = Meta::Page(Box::new(shown));
        let mut response = Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        );
        response.carries = carries;
        response
    }

    /// Records the links of a page just made as mentions of the pages
    /// behind them, unless those pages are stored. A later request has this
    /// context even without a Referer.
    pub(super) fn note_links(&self, url: &str, markup: &str) {
        let Ok(mut store) = self.writing_store() else {
            return;
        };
        for (host, target, anchor) in links(url, markup) {
            if store.page(&host, &target).is_none() {
                let mention = Mention::Link {
                    from: url.into(),
                    anchor,
                };
                // A mention the store cannot keep loses only context.
                let _ = store.add_mention(&host, &target, mention);
            }
        }
    }
}
