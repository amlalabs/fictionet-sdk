//! Apply observed queries, answers, pages and refusals to bounded state.

use super::*;

fn recent<T>(rows: &mut Vec<T>, item: T, limit: usize, omitted: &mut u64) {
    if rows.len() == limit {
        rows.remove(0);
        *omitted = omitted.saturating_add(1);
    }
    rows.push(item);
}
fn host(url: &str) -> String {
    bounded(&crate::pages::text::split_url(url).0)
}
impl Snapshot {
    pub(super) fn apply(&mut self, e: &Event, seq: u64, ms: u64) -> bool {
        match (e.source, e.kind) {
            ("web", "model_call") => {
                let Some(call) = e.get("call").map(|v| js(Some(v))) else {
                    return false;
                };
                self.generator.model_calls += 1;
                if let Some(cost) = call["cost"].as_f64() {
                    let total = self.generator.model_cost_known.as_f64().unwrap_or(0.0) + cost;
                    if let Some(total) = serde_json::Number::from_f64(total) {
                        self.generator.model_cost_known = total;
                    }
                } else {
                    self.generator.model_cost_unknown += 1;
                }
                true
            }
            ("web", "generation") => {
                let (Some(generate), Some(revision)) = (parse(e, "generate"), e.u64("revision"))
                else {
                    return false;
                };
                if revision <= self.generator.generation_revision {
                    return false;
                }
                self.generator.generate = generate;
                self.generator.generation_revision = revision;
                self.generator.generation_at_ms = ms;
                if let Some(live) = parse(e, "live_search") {
                    self.generator.live_search = live;
                }
                if let Some(copied) = parse(e, "copied") {
                    self.generator.copied = copied;
                }
                true
            }
            ("web", "planted") => {
                let row = Plant {
                    kind: text(e, "plant"),
                    text: text(e, "text"),
                    url: text(e, "url"),
                    at_ms: ms,
                };
                recent(
                    &mut self.planted,
                    row,
                    MAX_PLANTED,
                    &mut self.omitted.planted,
                );
                true
            }
            ("web", "restarted") => {
                self.queries.clear();
                self.results.clear();
                self.pages.clear();
                self.refused.clear();
                self.planted.clear();
                true
            }
            ("web", "query") => {
                let (Some(id), Some(engine)) = (e.u64("query_id"), parse(e, "engine")) else {
                    return false;
                };
                if self.queries.iter().any(|q| q.id == id) {
                    return false;
                }
                let query = Query {
                    id,
                    key: text(e, "key"),
                    search: text(e, "search"),
                    engine,
                    start: e.u64("start").unwrap_or(0),
                    sandbox: e.conn.sandbox.as_ref().map(|s| bounded(&s.name)),
                    via: e.str("via").map(bounded),
                    peer: e.conn.peer.map(|p| bounded(&p.ip().to_string())),
                    at_ms: ms,
                    seq,
                    outcome: Outcome::Pending,
                    cache: None,
                    carries: None,
                    results: None,
                    model: String::new(),
                    gen_ms: None,
                    cost: None,
                    serve_ms: None,
                    answer_seq: None,
                    answer_at_ms: None,
                };
                recent(
                    &mut self.queries,
                    query,
                    MAX_QUERIES,
                    &mut self.omitted.queries,
                );
                true
            }
            ("web", "query_failed") => {
                let Some(q) = self
                    .queries
                    .iter_mut()
                    .find(|q| Some(q.id) == e.u64("query_id"))
                else {
                    return false;
                };
                if q.outcome != Outcome::Pending {
                    return false;
                }
                let why = parse(e, "why").unwrap_or_default();
                q.outcome = Outcome::Failed {
                    why,
                    error: e.str("error").map(bounded),
                };
                q.cache = (why == Failure::Budget).then_some(Cache::Budget);
                q.serve_ms = e.u64("serve_ms");
                q.answer_seq = Some(seq);
                q.answer_at_ms = Some(ms);
                true
            }
            ("http", "request") | ("web", "search_answer") => {
                let mut changed = false;
                let id = e.u64("query_id");
                if let Some(q) = self.queries.iter_mut().find(|q| Some(q.id) == id)
                    && (q.outcome == Outcome::Pending
                        || (matches!(q.outcome, Outcome::Failed { .. })
                            && (e.str("kind") == Some("error")
                                || e.str("cache") == Some("budget"))))
                {
                    let before = q.clone();
                    let pending = q.outcome == Outcome::Pending;
                    if pending {
                        q.outcome = if e.get("complete").and_then(|v| v.as_bool()) == Some(true) {
                            Outcome::Served
                        } else {
                            Outcome::Undelivered
                        };
                    }
                    q.cache = parse(e, "cache")
                        .or(q.cache)
                        .or(pending.then_some(Cache::Unknown));
                    q.results = e.u64("results");
                    q.carries = e.u64("carries");
                    q.gen_ms = e.u64("gen_ms");
                    q.model = text(e, "model");
                    q.cost = parse(e, "cost");
                    q.serve_ms = e.u64("serve_ms").or(q.serve_ms);
                    q.answer_seq = Some(seq);
                    q.answer_at_ms = Some(ms);
                    changed = *q != before;
                    if pending
                        && let Some(fictionet::stdlib::protocols::json::Value::Array(items)) =
                            e.get("listed")
                    {
                        // Keep a shared list only when the answer is identical.
                        // Tool domain restrictions can change a cached list.
                        let made = matches!(q.cache, Some(Cache::Generated | Cache::Prefetched));
                        let listed: Vec<Listed> = items
                            .iter()
                            .take(MAX_LISTED)
                            .filter_map(|item| {
                                let value = js(Some(item));
                                let url = value["url"].as_str()?;
                                Some(Listed {
                                    rank: value["rank"].as_u64()?,
                                    host: host(url),
                                    site: bounded(value["site"].as_str().unwrap_or_default()),
                                    url: bounded(url),
                                    title: bounded(value["title"].as_str()?),
                                })
                            })
                            .collect();
                        let shown = self
                            .results
                            .iter()
                            .position(|r| r.key == q.key)
                            .map(|index| self.results.remove(index));
                        if let Some(list) = shown.filter(|list| !made && list.listed == listed) {
                            self.results.push(list);
                        } else {
                            self.omitted.listed = self
                                .omitted
                                .listed
                                .saturating_add(items.len().saturating_sub(MAX_LISTED) as u64);
                            recent(
                                &mut self.results,
                                Results {
                                    key: q.key.clone(),
                                    listed,
                                    cache: q.cache.unwrap_or_default(),
                                    query_id: q.id,
                                },
                                MAX_RESULTS,
                                &mut self.omitted.results,
                            );
                        }
                    }
                }
                if e.str("kind") == Some("page") {
                    let Some(host_name) = e.str("host") else {
                        return changed;
                    };
                    let path = e.str("path").unwrap_or("/");
                    let query = e.str("query");
                    let url = bounded(&format!(
                        "{}://{host_name}{path}{}",
                        e.str("scheme").unwrap_or("https"),
                        query.map(|q| format!("?{q}")).unwrap_or_default()
                    ));
                    let cache = parse(e, "cache").unwrap_or_default();
                    let made = made(cache, e.str("model").unwrap_or_default());
                    let mut reason: Reason = parse(e, "reason").unwrap_or_default();
                    reason.bound();
                    let fetched = Page {
                        seq,
                        first_serve_ms: e.u64("serve_ms"),
                        url,
                        host: bounded(host_name),
                        site: text(e, "site"),
                        at_ms: ms,
                        fetches: 1,
                        status: e.u64("status"),
                        via: e.str("via").map(bounded),
                        making: false,
                        waiting: false,
                        carries: e.u64("carries"),
                        title: text(e, "title"),
                        model: text(e, "model"),
                        cache,
                        serve_ms: e.u64("serve_ms"),
                        gen_ms: e.u64("gen_ms"),
                        cost: parse(e, "cost"),
                        latest_serve_ms: e.u64("serve_ms"),
                        reason,
                        made,
                        latest: made,
                    };
                    if let Some(index) = self.pages.iter().position(|p| {
                        p.url == fetched.url
                            || (p.making
                                && p.fetches == 0
                                && p.url
                                    .strip_prefix("https://")
                                    .zip(fetched.url.strip_prefix("http://"))
                                    .is_some_and(|(pending, served)| pending == served))
                    }) {
                        let old = self.pages.remove(index);
                        let mut page =
                            if old.fetches == 0 || (!old.made.supplied() && made.supplied()) {
                                // The fetch that made the page says why and how.
                                Page {
                                    seq: old.seq,
                                    first_serve_ms: old.first_serve_ms.or(fetched.first_serve_ms),
                                    at_ms: old.at_ms,
                                    fetches: old.fetches,
                                    ..fetched
                                }
                            } else {
                                Page {
                                    status: fetched.status,
                                    via: fetched.via,
                                    making: false,
                                    waiting: false,
                                    carries: fetched.carries,
                                    latest_serve_ms: fetched.latest_serve_ms,
                                    latest: made,
                                    ..old
                                }
                            };
                        page.fetches = page.fetches.saturating_add(1);
                        self.pages.push(page);
                    } else {
                        recent(&mut self.pages, fetched, MAX_PAGES, &mut self.omitted.pages);
                    }
                    changed = true;
                }
                changed
            }
            ("web", "prefetch_finished") => {
                let url = text(e, "url");
                let before = self.pages.len();
                self.pages
                    .retain(|p| p.url != url || p.fetches > 0 || p.waiting);
                before != self.pages.len()
            }
            ("web", "page_failed") => {
                let url = text(e, "url");
                let Some(page) = self.pages.iter_mut().find(|p| p.url == url) else {
                    return false;
                };
                page.making = false;
                page.waiting = false;
                page.status = e.u64("status");
                true
            }
            ("web", "making") => {
                let url = text(e, "url");
                let waiting = !parse::<bool>(e, "prefetch").unwrap_or(false);
                if let Some(page) = self.pages.iter_mut().find(|p| p.url == url) {
                    page.making = true;
                    page.waiting |= waiting;
                } else {
                    recent(
                        &mut self.pages,
                        Page {
                            seq,
                            first_serve_ms: None,
                            url,
                            host: text(e, "host"),
                            site: text(e, "site"),
                            at_ms: ms,
                            fetches: 0,
                            status: None,
                            via: None,
                            making: true,
                            waiting,
                            carries: None,
                            title: String::new(),
                            model: String::new(),
                            cache: Cache::Unknown,
                            serve_ms: None,
                            gen_ms: None,
                            cost: None,
                            latest_serve_ms: None,
                            reason: Reason::Unknown,
                            made: Made::Unknown,
                            latest: Made::Unknown,
                        },
                        MAX_PAGES,
                        &mut self.omitted.pages,
                    );
                }
                true
            }
            ("web", "site") => {
                let host = text(e, "host");
                if self.sites.iter().any(|s| s.host == host) {
                    return false;
                }
                if self.sites.len() == MAX_SITES {
                    self.omitted.sites = self.omitted.sites.saturating_add(1);
                    return true;
                }
                let reason = match e.str("why") {
                    Some("search engine") => SiteReason::SearchEngine,
                    Some("seed") => SiteReason::Seed,
                    Some("recorded") => SiteReason::Recorded,
                    Some("pool") => SiteReason::Pool,
                    _ => SiteReason::Unknown,
                };
                self.sites.push(Site {
                    host,
                    site: text(e, "site"),
                    address: text(e, "addr"),
                    reason,
                    at_ms: ms,
                });
                true
            }
            ("web", "refused") => {
                let row = Refused {
                    name: text(e, "host"),
                    reason: text(e, "why"),
                    at_ms: ms,
                };
                if self.refused.last() == Some(&row) {
                    return false;
                }
                if let Some(index) = self.refused.iter().position(|r| r.name == row.name) {
                    self.refused.remove(index);
                }
                recent(
                    &mut self.refused,
                    row,
                    MAX_REFUSED,
                    &mut self.omitted.refused,
                );
                true
            }
            _ => false,
        }
    }
}
