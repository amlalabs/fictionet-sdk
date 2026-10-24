//! Serve stored pages, canonical addresses and background fetches.

use super::*;

impl Written {
    fn listed_video(&self, host: &str, target: &str) -> Option<PageRecord> {
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
        // The page is found or made in the world's own task, so a client
        // that stops waiting does not stop it: its next request finds the
        // page made, or waits on the same writing.
        let (send, receive) = tokio::sync::oneshot::channel();
        let pages = self.clone();
        let (host, target) = (host.to_owned(), target.to_owned());
        cx.spawn(move |cx| async move {
            let _ = send.send(pages.found(&cx, &host, &target, prefetch).await);
            Ok(())
        });
        let (record, made) = match receive.await {
            Ok(Ok(found)) => found,
            Ok(Err(response)) => return *response,
            Err(_) => {
                return Stop::store(std::io::Error::other("the world stopped")).response();
            }
        };
        if made && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        let meta = Meta::Document {
            title: record.title,
        };
        Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        )
    }

    /// The stored page at `host` and `target`, or one made now, laid out
    /// for today, and whether it was made now; the answer instead when
    /// there is none.
    async fn found(
        &self,
        cx: &Cx,
        host: &str,
        target: &str,
        prefetch: bool,
    ) -> Result<(PageRecord, bool), Box<Response>> {
        let _lock = self
            .locks
            .lock(cx, page_key(host, target))
            .await
            .map_err(|error| Box::new(Stop::store(error).response()))?;
        let stored = self.store().page(host, target).cloned();
        let stored = stored.or_else(|| self.listed_video(host, target));
        let (mut record, made) = match stored {
            Some(record) => (record, false),
            None if !self.generating() => return Err(Box::new(self.missing(host, target))),
            None => match self.make_page(cx, host, target, prefetch).await {
                Ok(record) => (record, true),
                Err(stop) => return Err(Box::new(stop.response())),
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
        Ok((record, made))
    }

    /// Records the links of a page just made as mentions of the pages
    /// behind them, unless those pages are stored. A later request has this
    /// context even without a Referer.
    pub(super) fn note_links(&self, url: &str, markup: &str) {
        let mut store = self.store();
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
