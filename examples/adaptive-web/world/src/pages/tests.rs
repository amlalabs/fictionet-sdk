use super::*;
use model::{Key, Provider, Transport};
use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const KEY: &str = "sk-or-test-key-must-not-be-stored";

fn lab<F, Fut>(work: F)
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
        work,
    ))
    .unwrap();
}

fn seed() -> Seed {
    Seed::builtin("halvard-cve").unwrap()
}

fn halvard() -> Arc<Pages> {
    Arc::new(Pages::new(seed()))
}

/// A directory for one test, removed when it ends.
struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("adaptive-web-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    /// Every file's text, for checks that something is nowhere.
    fn texts(&self) -> Vec<String> {
        fn walk(dir: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(String::from_utf8_lossy(&std::fs::read(path).unwrap()).into());
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.0, &mut out);
        out
    }
    fn rows(&self) -> Vec<Value> {
        std::fs::read_to_string(self.0.join("halvard-cve/generations.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A world on a store in `dir`.
fn on_disk(
    dir: &Path,
    seed: Seed,
    generator: Option<Generator>,
    prefetch: usize,
) -> Result<Arc<Pages>, String> {
    let identity = generator.as_ref().map(Generator::identity);
    let (store, _) = Store::open(&dir.join(&seed.name), &seed, identity.as_ref())?;
    Ok(Arc::new(Pages::open(seed, store, generator, prefetch)))
}

/// The result links and titles of a Google results page.
fn results(body: &[u8]) -> Vec<(String, String)> {
    render::google_results(std::str::from_utf8(body).unwrap())
}

async fn get(pages: &Arc<Pages>, cx: &Cx, url: &str) -> Response {
    let (host, target) = text::target_of(url);
    pages.handle(cx, "GET", &host, &target, None).await
}

async fn google(pages: &Arc<Pages>, cx: &Cx, query: &str) -> Response {
    let target = format!("/search?q={}", text::quote_plus(query));
    pages
        .handle(cx, "GET", "www.google.com", &target, None)
        .await
}

// ---- a scripted model API ------------------------------------------------

/// One answer: how long the call takes, then the status and body or a
/// transport failure.
type Reply = (Duration, Result<(u16, Vec<u8>), String>);

/// A request's headers.
type Headers = Vec<(&'static str, String)>;
/// How a fake API answers a request's headers and body.
type Answer = Box<dyn Fn(&Headers, &Value) -> Reply + Send + Sync>;

/// A model API that answers from a function and keeps every request.
struct Fake {
    answer: Answer,
    requests: Mutex<Vec<(Headers, Value)>>,
}
impl Fake {
    fn new(answer: impl Fn(&Headers, &Value) -> Reply + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            answer: Box::new(answer),
            requests: Mutex::new(Vec::new()),
        })
    }
    /// One reply per request, in order.
    fn script(replies: Vec<Reply>) -> Arc<Self> {
        let replies = Mutex::new(VecDeque::from(replies));
        Self::new(move |_, _| {
            replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("a scripted reply")
        })
    }
    fn users(&self) -> Vec<String> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .map(|(_, body)| body["messages"][1]["content"].as_str().unwrap().into())
            .collect()
    }
    fn systems(&self) -> Vec<String> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .map(|(_, body)| body["messages"][0]["content"].as_str().unwrap().into())
            .collect()
    }
}
impl Transport for Fake {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> model::Post<'a> {
        let body: Value = serde_json::from_slice(&body).unwrap();
        let (delay, reply) = (self.answer)(&headers, &body);
        self.requests.lock().unwrap().push((headers, body));
        Box::pin(async move {
            let _ = cx.sleep(delay).await;
            reply
        })
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// An OpenRouter answer with `text`, its tokens and `cost`.
fn completion(after: u64, text: &str, cost: Option<f64>) -> Reply {
    let body = json!({
        "model": "answered/model",
        "choices": [{"message": {"content": text}}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "cost": cost},
    });
    (ms(after), Ok((200, body.to_string().into_bytes())))
}

fn http_error(after: u64, status: u16) -> Reply {
    (ms(after), Ok((status, b"failed".to_vec())))
}

fn openrouter(fake: Arc<Fake>) -> Model {
    let key = Key::new("OPENROUTER_API_KEY", Some(KEY.into())).unwrap();
    Model::new(Provider::OpenRouter, "requested/model", "", key, fake)
}

const PAGE: &str = "STATUS: 200\nTITLE: Story\nBODY:\n<h1>Story</h1>";
const SEARCH: &str = "RESULT\nURL: https://example.com/story\nTITLE: Story\nSNIPPET: A story.";

/// The model API the world tests use: a cast for a cast prompt, ten results
/// for a search, and a page that quotes the first snippet it was shown.
#[derive(Default)]
struct Script {
    /// Unreadable answers to give before the readable ones.
    bad: AtomicUsize,
    /// Page answers to give instead of the made-up page, in order.
    pages: Mutex<VecDeque<String>>,
    /// Errors that echo the request's key: status and a prefix.
    echoes: Mutex<VecDeque<(u16, String)>>,
}

fn fake_openrouter(script: Arc<Script>) -> Arc<Fake> {
    Fake::new(move |headers, body| {
        if let Some((status, prefix)) = script.echoes.lock().unwrap().pop_front() {
            let auth = &headers
                .iter()
                .find(|(name, _)| *name == "authorization")
                .unwrap()
                .1;
            let reply = json!({"error": format!("{prefix}rejected Authorization: {auth}")});
            return (ms(5), Ok((status, reply.to_string().into_bytes())));
        }
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        let text = if script.bad.load(Ordering::SeqCst) > 0 {
            script.bad.fetch_sub(1, Ordering::SeqCst);
            "Sorry, I can't help with that.".to_owned()
        } else if prompt.starts_with("List the people") {
            "Tomasz Wierzbicki | CEO | Halvard Systems\nAmara Nwosu | analyst | Brightline Research\n\
            Keiko Arai | reporter | The Register"
                .to_owned()
        } else if prompt.contains("Someone searched for") {
            let results: Vec<_> = (0..10)
                .map(|i| {
                    format!(
                        "RESULT\nURL: https://news{i}.krantvandaag.nl/a{i}\nTITLE: Story {i}\n\
                        DATE: Oct 1, 2026\nSNIPPET: Snippet number {i} about the flaw..."
                    )
                })
                .collect();
            results.join("\n") + "\nRELATED: r | s"
        } else if let Some(page) = script.pages.lock().unwrap().pop_front() {
            page
        } else {
            let url = Regex::new(r"Write the page at: (\S+)")
                .unwrap()
                .captures(prompt)
                .unwrap()[1]
                .to_owned();
            let snippet = Regex::new(r#"snippet "([^"]+?)(\.\.\.)?""#)
                .unwrap()
                .captures(prompt)
                .map(|c| c[1].to_owned())
                .unwrap_or_default();
            format!(
                "STATUS: 200\nCONTENT_TYPE: text/html\nTITLE: Some other title\nDESCRIPTION: d\n\
                DATE: 2026-10-01\nCLAIMS:\n- a claim about {url}\nSITE_NAME: Krant Vandaag\n\
                SITE_NAV: Home|/\nSITE_FOOTER: Over ons|/over\nSIDEBAR:\n- Andere zaak | /andere\n\
                AD: none\nBODY:\n<h1>Story</h1><p>{snippet}</p>"
            )
        };
        let reply = json!({
            "model": body["model"],
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "cost": 0.0021},
        });
        (ms(10), Ok((200, reply.to_string().into_bytes())))
    })
}

/// An empty cast, so a test counts only its page's generation.
fn no_cast(pages: &Pages) {
    let cast = CastRecord {
        people: Vec::new(),
        usage: Usage::stub(0),
    };
    pages.store().set_cast(cast).unwrap();
}

// ---- the offline world ---------------------------------------------------

#[test]
fn routed_hosts_share_the_lowercase_page() {
    lab(|cx| async move {
        let pages = halvard();
        let first = pages
            .handle_route(&cx, "UPPER.IO", "/page.json", Route::Page)
            .await;
        let second = pages
            .handle(&cx, "GET", "upper.io", "/page.json", None)
            .await;
        assert_eq!(first.body, second.body);
        assert_eq!(second.meta["cache"], "cached");
        assert_eq!(
            serde_json::from_slice::<Value>(&first.body).unwrap()["url"],
            "https://upper.io/page.json"
        );
        Ok(())
    });
}

#[test]
fn the_same_requests_make_the_same_world() {
    lab(|cx| async move {
        let (a, b) = (halvard(), halvard());
        let first = google(&a, &cx, "halvard gateway vulnerability").await;
        let second = google(&b, &cx, "halvard gateway vulnerability").await;
        assert_eq!(first.body, second.body);
        for (url, _) in results(&first.body).into_iter().take(5) {
            assert_eq!(get(&a, &cx, &url).await.body, get(&b, &cx, &url).await.body);
        }
        Ok(())
    });
}

#[test]
fn pages_have_their_results_titles_and_snippets() {
    lab(|cx| async move {
        let pages = halvard();
        let found = results(&google(&pages, &cx, "halvard firmware upgrade").await.body);
        assert_eq!(found.len(), 10);
        for (url, title) in found {
            let page = get(&pages, &cx, &url).await;
            assert_eq!(page.status, 200, "{url}");
            let html = String::from_utf8_lossy(&page.body);
            assert!(
                html.contains(&format!("<title>{}</title>", text::escape(&title))),
                "{url}"
            );
            if let Some(unsupported) = page.meta.get("unsupported_snippets") {
                assert_eq!(unsupported, &json!([]), "{url}");
            }
            assert_eq!(get(&pages, &cx, &url).await.body, page.body, "{url}");
        }
        Ok(())
    });
}

#[test]
fn a_known_page_keeps_its_title_in_later_results() {
    lab(|cx| async move {
        let pages = halvard();
        let (url, title) = results(&google(&pages, &cx, "halvard portal").await.body)[3].clone();
        get(&pages, &cx, &url).await;
        let again = results(&google(&pages, &cx, "halvard portal flaw").await.body);
        assert_eq!(
            again.iter().find(|(u, _)| *u == url).map(|(_, t)| t),
            Some(&title)
        );
        Ok(())
    });
}

#[test]
fn engines_share_one_result_list() {
    lab(|cx| async move {
        let pages = halvard();
        let google: Vec<_> = results(&google(&pages, &cx, "HG-400 firmware").await.body)
            .into_iter()
            .map(|(url, _)| url)
            .collect();
        let form = b"q=hg-400++FIRMWARE";
        let ddg = pages
            .handle(&cx, "POST", "html.duckduckgo.com", "/html/", Some(form))
            .await;
        assert_eq!(ddg.meta["cache"], "cached");
        let html = String::from_utf8(ddg.body).unwrap();
        let links: Vec<_> = html
            .split("<div class=\"result ")
            .skip(1)
            .filter(|chunk| !chunk.contains("result--ad"))
            .map(|chunk| {
                let link = chunk
                    .split("uddg=")
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap();
                percent_decode(link)
            })
            .collect();
        assert_eq!(links, google);
        Ok(())
    });
}

fn percent_decode(text: &str) -> String {
    form_urlencoded::parse(format!("x={}", text.replace('+', "%2B")).as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned()
}

#[test]
fn links_give_context() {
    lab(|cx| async move {
        let pages = halvard();
        let page = get(&pages, &cx, "https://news.example-site.com/story").await;
        let html = String::from_utf8(page.body).unwrap();
        let link = Regex::new(r#"<a href="(/[^"]+follow-up)">([^<]+)</a>"#).unwrap();
        let found = link.captures(&html).unwrap();
        let store = pages.store();
        let mentions = store.mentions("news.example-site.com", &found[1]);
        assert_eq!(mentions[0]["via"], "link");
        assert_eq!(mentions[0]["anchor"], text::text_of(&found[2]));
        Ok(())
    });
}

#[test]
fn links_bound_candidates_before_filtering_and_cut_characters() {
    let mut html = "<a href=\"mailto:skip@site.com\">skip</a>".repeat(79);
    html.push_str(&format!(
        "<a href=\"../é?q=1&amp;x=2#frag\"><b>{}</b></a>",
        "😀".repeat(170)
    ));
    html.push_str("<a href=\"/too-late\">late</a>");
    assert_eq!(
        links("https://site.com/a/b", &html),
        vec![(
            "site.com".into(),
            "/%C3%A9?q=1&x=2".into(),
            "😀".repeat(160)
        )]
    );
    let html = "<a href='/empty'> <b></b> </a><a href='https://www.google.com/search?q=a'>Search</a>\
        <a href='/ok'>one &amp; two</a>";
    assert_eq!(
        links("https://site.com/", html),
        vec![("site.com".into(), "/ok".into(), "one & two".into())]
    );
    let mut mentions = Vec::new();
    for n in 0..12 {
        mentions.push(json!({"via":"link","anchor":n}));
        mentions.push(json!({"via":"search","title":n}));
    }
    let asked = prompts::asked_mentions(&mentions);
    assert_eq!(asked.len(), 20);
    assert_eq!(asked.iter().filter(|m| m["via"] == "link").count(), 8);
    assert_eq!(asked.last().unwrap()["title"], 11);
}

/// Of a page's first 80 link candidates, links to stored pages, search
/// engines, other schemes and empty anchors are left out.
#[test]
fn noted_links_skip_stored_pages_and_cut_anchors() {
    lab(|cx| async move {
        let pages = halvard();
        let host = "news.example-site.com";
        let url = format!("https://{host}/story");
        get(&pages, &cx, &format!("https://{host}/stored")).await;
        let anchor = format!("A&B {}", "x".repeat(prompts::ANCHOR_CHARS));
        let mut links = vec![
            ("/empty".to_owned(), " <b> </b> ".to_owned()),
            ("https://www.google.com/search?q=x".into(), "Search".into()),
            ("/stored".into(), "Stored".into()),
            ("mailto:author@example.com".into(), "Email".into()),
            ("http://".into(), "No host".into()),
            (
                "/relative?x=1&amp;y=2".into(),
                format!(" <b>A&amp;B</b> {} ", "x".repeat(prompts::ANCHOR_CHARS)),
            ),
            (
                "http://other.example-site.com/plain".into(),
                "HTTP target".into(),
            ),
        ];
        let mut expected = vec![
            (
                host.to_owned(),
                "/relative?x=1&y=2".to_owned(),
                text::take(&anchor, prompts::ANCHOR_CHARS),
            ),
            (
                "other.example-site.com".into(),
                "/plain".into(),
                "HTTP target".into(),
            ),
        ];
        for i in links.len()..=prompts::LINKS_PER_PAGE {
            links.push((format!("https://{host}/link-{i}"), format!("Link {i}")));
            if i < prompts::LINKS_PER_PAGE {
                expected.push((host.into(), format!("/link-{i}"), format!("Link {i}")));
            }
        }
        let markup: String = links
            .iter()
            .map(|(href, text)| format!("<a href=\"{href}\">{text}</a>"))
            .collect();
        pages.note_links(&url, &markup);
        let store = pages.store();
        for (host, target, anchor) in &expected {
            assert_eq!(
                store.mentions(host, target),
                [json!({"via": "link", "from": url, "anchor": anchor})],
                "{host}{target}"
            );
        }
        for target in ["/empty", "/stored", "/link-80"] {
            assert!(store.mentions(host, target).is_empty(), "{target}");
        }
        Ok(())
    });
}

#[test]
fn engines_redirects_and_assets() {
    lab(|cx| async move {
        let pages = halvard();
        let location = |r: &Response| {
            r.headers
                .iter()
                .find(|(n, _)| n == "Location")
                .unwrap()
                .1
                .clone()
        };
        let redirect = pages
            .handle(&cx, "GET", "google.com", "/search?q=x", None)
            .await;
        assert_eq!(location(&redirect), "https://www.google.com/search?q=x");
        let ddg = pages
            .handle(
                &cx,
                "GET",
                "duckduckgo.com",
                "/l/?uddg=https%3A%2F%2Fa.com%2Fb",
                None,
            )
            .await;
        assert_eq!(location(&ddg), "https://a.com/b");
        let bing = pages
            .handle(
                &cx,
                "GET",
                "www.bing.com",
                "/search?q=halvard&first=x",
                None,
            )
            .await;
        assert_eq!(bing.status, 200);
        let css = pages
            .handle(&cx, "GET", "a.com", "/static/css/main.css", None)
            .await;
        assert_eq!(
            (css.content_type.as_str(), &css.meta["kind"]),
            ("text/css", &json!("asset"))
        );
        assert!(
            pages
                .store()
                .page("a.com", "/static/css/main.css")
                .is_none()
        );
        Ok(())
    });
}

#[test]
fn fixed_pages_are_served_as_written() {
    lab(|cx| async move {
        let pages = halvard();
        let fixed = pages.seed().fixed[0].clone();
        let page = get(&pages, &cx, &fixed.url).await;
        assert_eq!(page.body, fixed.body);
        assert_eq!(page.meta["cache"], "fixed");
        // Its links are written down for the pages behind them.
        assert!(
            !pages
                .store()
                .mentions(&fixed.host, "/support/kb/KB-3381")
                .is_empty()
        );
        Ok(())
    });
}

#[test]
fn concurrent_requests_make_one_page() {
    lab(|cx| async move {
        let pages = halvard();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let pages = pages.clone();
                let (tx, rx) = tokio::sync::oneshot::channel();
                cx.spawn(move |cx| async move {
                    let _ = tx.send(
                        pages
                            .handle(&cx, "GET", "same-page.io", "/same", None)
                            .await,
                    );
                    Ok(())
                });
                rx
            })
            .collect();
        let mut replies = Vec::new();
        for task in tasks {
            replies.push(task.await.unwrap());
        }
        let generated = replies
            .iter()
            .filter(|r| r.meta["cache"] == "generated")
            .count();
        assert_eq!(generated, 1);
        assert!(replies.iter().all(|r| r.body == replies[0].body));
        let store = pages.store();
        // The page and the cast.
        assert_eq!(store.made, 2);
        assert_eq!(store.site("same-page.io").map(|p| p.style), Some(0));
        Ok(())
    });
}

#[test]
fn the_budget_refuses_new_work_but_keeps_stored_pages() {
    lab(|cx| async move {
        let pages = halvard();
        let first = get(&pages, &cx, "https://example.com/first").await;
        assert_eq!(first.status, 200);
        pages.store().made = GENERATION_BUDGET;
        let second = get(&pages, &cx, "https://example.com/second").await;
        assert_eq!(
            (second.status, &second.meta["cache"]),
            (503, &json!("budget"))
        );
        let search = google(&pages, &cx, "new query").await;
        assert_eq!(
            (search.status, &search.meta["cache"]),
            (503, &json!("budget"))
        );
        assert_eq!(
            get(&pages, &cx, "https://example.com/first").await.body,
            first.body
        );
        assert!(pages.store().page("example.com", "/second").is_none());
        Ok(())
    });
}

#[test]
fn listed_results_and_the_reason_each_page_was_made() {
    lab(|cx| async move {
        let pages = halvard();
        let response = google(&pages, &cx, "halvard gateway vulnerability").await;
        let found = results(&response.body);
        let listed: Vec<_> = found
            .iter()
            .enumerate()
            .map(|(i, (url, title))| json!({"rank": i + 1, "url": url, "title": title}))
            .collect();
        assert_eq!(response.meta["listed"], json!(listed));
        for (rank, (url, _)) in found.iter().enumerate() {
            let first = get(&pages, &cx, url).await;
            let (host, target) = text::target_of(url);
            let expected = if pages.seed().fixed_for(&host, &target).is_some() {
                json!({"via": "fixed"})
            } else {
                json!({"via": "search", "query": "halvard gateway vulnerability", "rank": rank + 1})
            };
            assert_eq!(first.meta["reason"], expected, "{url}");
            assert_eq!(get(&pages, &cx, url).await.meta["reason"], expected);
        }
        let source = get(&pages, &cx, "https://direct-site.com/story").await;
        assert_eq!(source.meta["reason"], json!({"via": "direct"}));
        let linked = get(&pages, &cx, "https://direct-site.com/archive/2026/").await;
        assert_eq!(
            linked.meta["reason"],
            json!({"via": "link", "from": "https://direct-site.com/story"})
        );
        // Nothing made, no reason.
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: 0,
                },
            )
            .unwrap();
        let missing = get(&pages, &cx, "https://new-site.com/missing").await;
        assert_eq!(
            (missing.status, &missing.meta["cache"]),
            (404, &json!("missing"))
        );
        assert!(missing.meta.get("reason").is_none());
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: true,
                    expected_revision: 1,
                },
            )
            .unwrap();
        pages.store().made = GENERATION_BUDGET;
        assert!(
            get(&pages, &cx, "https://new-site.com/budget")
                .await
                .meta
                .get("reason")
                .is_none()
        );
        Ok(())
    });
}

// ---- the store -----------------------------------------------------------

#[test]
fn mentions_reserve_titles_and_keep_creation_order() {
    let seed = seed();
    let mut store = Store::memory();
    store
        .add_mention(
            "site.com",
            "/p",
            json!({"via":"link","from":"https://source.com/","anchor":"An anchor"}),
        )
        .unwrap();
    let first = json!({"via":"search","query":"first","title":"First title",
        "snippet":"First snippet","rank":2});
    store
        .reserve_mention(&seed, "site.com", "/p", first.clone())
        .unwrap();
    store
        .reserve_mention(&seed, "site.com", "/p", first)
        .unwrap();
    let later = json!({"via":"search","query":"second","title":"Different title",
        "snippet":"Second snippet","rank":1});
    let later = store
        .reserve_mention(&seed, "site.com", "/p", later)
        .unwrap();
    assert_eq!(later["title"], "First title");
    assert_eq!(later["snippet"], "Second snippet");
    assert_eq!(store.mentions("site.com", "/p").len(), 3);
    assert_eq!(store.mentions("site.com", "/p")[0]["via"], "link");
    let f = &seed.fixed[0];
    let reserved = store
        .reserve_mention(
            &seed,
            &f.host,
            &f.target,
            json!({"via":"search","title":"wrong","snippet":"wrong"}),
        )
        .unwrap();
    assert_eq!(reserved["title"], f.title);
    assert_eq!(reserved["snippet"], f.description);
}

#[test]
fn replay_serves_the_store_and_nothing_new() {
    let dir = Dir::new("replay");
    let (search, page) = {
        let pages = on_disk(&dir.0, seed(), Some(Generator::Stub), 0).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let s = pages
                .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=halvard", None)
                .await;
            let p = pages
                .handle(&cx, "GET", "www.halvardsystems.com", "/support/", None)
                .await;
            tx.send((s.body, p.body)).unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let replay = on_disk(&dir.0, seed(), None, 0).unwrap();
    lab(|cx| async move {
        let s = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=halvard", None)
            .await;
        assert_eq!(s.body, search);
        assert_eq!(s.meta["cache"], "cached");
        let p = replay
            .handle(&cx, "GET", "www.halvardsystems.com", "/support/", None)
            .await;
        assert_eq!((p.body, &p.meta["cache"]), (page, &json!("cached")));
        let missing = replay
            .handle(&cx, "GET", "www.halvardsystems.com", "/never-asked", None)
            .await;
        assert_eq!(
            (missing.status, &missing.meta["cache"]),
            (404, &json!("missing"))
        );
        let none = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=never", None)
            .await;
        assert_eq!(
            (none.meta["cache"].clone(), none.meta["results"].clone()),
            (json!("missing"), json!(0))
        );
        Ok(())
    });
}

#[test]
fn one_world_uses_a_store_at_a_time() {
    let dir = Dir::new("in-use");
    let first = on_disk(&dir.0, seed(), Some(Generator::Stub), 0).unwrap();
    let error = on_disk(&dir.0, seed(), Some(Generator::Stub), 0)
        .err()
        .unwrap();
    assert!(error.contains("is in use by another world"), "{error}");
    drop(first);
    on_disk(&dir.0, seed(), None, 0).unwrap();
}

#[test]
fn fixed_snapshots_survive_changed_and_deleted_sources() {
    let dir = Dir::new("fixed");
    let seeds = dir.0.join("seeds");
    std::fs::create_dir_all(seeds.join("fixed")).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../seeds");
    std::fs::copy(source.join("halvard-cve.md"), seeds.join("halvard-cve.md")).unwrap();
    let file = seeds.join("fixed/halvard-hsa-2026-014.html");
    std::fs::copy(source.join("fixed/halvard-hsa-2026-014.html"), &file).unwrap();
    let load = || Seed::load(seeds.join("halvard-cve.md")).unwrap();
    let url = load().fixed[0].url.clone();
    let fetch = |pages: Arc<Pages>| {
        let url = url.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let page = get(&pages, &cx, &url).await;
            tx.send((
                page.status,
                page.content_type,
                page.body,
                page.meta["cache"].clone(),
            ))
            .unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let first = fetch(on_disk(&dir.0, load(), Some(Generator::Stub), 0).unwrap());
    assert_eq!(first.3, "fixed");
    // A restarted world serves the captured bytes, whatever the source says now.
    std::fs::write(&file, "a changed advisory").unwrap();
    assert_eq!(
        fetch(on_disk(&dir.0, load(), Some(Generator::Stub), 0).unwrap()),
        first
    );
    std::fs::remove_file(&file).unwrap();
    assert!(Seed::load(seeds.join("halvard-cve.md")).is_err());
    let replay_seed = || {
        let text = std::fs::read_to_string(seeds.join("halvard-cve.md")).unwrap();
        Seed::parse("halvard-cve", &text, |_| Ok(Vec::new())).unwrap()
    };
    assert_eq!(
        fetch(on_disk(&dir.0, replay_seed(), None, 0).unwrap()),
        first
    );
    // Replay never captures a fixed page it has not seen.
    let fresh = Dir::new("fixed-unseen");
    {
        on_disk(&fresh.0, load_with(&source), Some(Generator::Stub), 0).unwrap();
    }
    let unseen = fetch(on_disk(&fresh.0, replay_seed(), None, 0).unwrap());
    assert_eq!((unseen.0, unseen.3), (404, json!("missing")));
}

fn load_with(source: &Path) -> Seed {
    Seed::load(source.join("halvard-cve.md")).unwrap()
}

#[test]
fn binary_and_empty_fixed_bodies_round_trip() {
    for (i, body) in [
        [
            &(0..=255).collect::<Vec<u8>>()[..],
            b"<a href=\"/binary-link\">Not HTML</a>",
        ]
        .concat(),
        Vec::new(),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = Dir::new(&format!("binary-{i}"));
        let mut seed = seed();
        seed.fixed[0].body = body.clone();
        seed.fixed[0].content_type = "application/octet-stream".into();
        let url = seed.fixed[0].url.clone();
        let host = seed.fixed[0].host.clone();
        for generator in [Some(Generator::Stub), None] {
            let pages = on_disk(&dir.0, seed.clone(), generator, 0).unwrap();
            let (url, body, host) = (url.clone(), body.clone(), host.clone());
            lab(|cx| async move {
                let page = get(&pages, &cx, &url).await;
                assert_eq!(
                    (page.status, page.content_type.as_str()),
                    (200, "application/octet-stream")
                );
                assert_eq!(page.body, body);
                assert_eq!(page.headers, [("Server".to_owned(), "nginx".to_owned())]);
                assert!(pages.store().mentions(&host, "/binary-link").is_empty());
                Ok(())
            });
        }
    }
}

#[test]
fn a_store_answers_only_for_its_seed_and_generator() {
    let dir = Dir::new("identity");
    let model =
        |name: &str, reasoning: &str| model::identity(Provider::OpenRouter, name, reasoning);
    let seed = seed();
    let (store, made_by) = Store::open(&dir.0, &seed, Some(&model("some/model", "low"))).unwrap();
    assert_eq!(made_by, model("some/model", "low"));
    drop(store);
    // Replay keeps the generator that made the store.
    let (store, made_by) = Store::open(&dir.0, &seed, None).unwrap();
    assert_eq!(made_by["model"], "some/model");
    drop(store);
    for other in [
        json!({"provider": "anthropic", "model": "some/model", "reasoning": "low"}),
        model("other/model", "low"),
        model("some/model", "high"),
        Generator::Stub.identity(),
    ] {
        let error = Store::open(&dir.0, &seed, Some(&other)).err().unwrap();
        assert!(
            error.contains("generator configuration mismatch"),
            "{error}"
        );
        assert!(
            error.contains("rebuild in a fresh ADAPTIVE_WEB_STORE_DIR"),
            "{error}"
        );
    }
    let mut changes: Vec<Seed> = Vec::new();
    for change in 0..7 {
        let mut changed = seed.clone();
        match change {
            0 => changed.date = "2026-12-01".into(),
            1 => changed.question = "A different question".into(),
            2 => changed.scenario = "A different scenario".into(),
            3 => changed.facts = vec!["A different fact".into()],
            4 => changed.sites[0].about = "A different site".into(),
            5 => changed.fixed[0].title = "A different title".into(),
            _ => changed.fixed[0].file = "fixed/other.html".into(),
        }
        changes.push(changed);
    }
    for changed in changes {
        for generator in [Some(model("some/model", "low")), None] {
            let error = Store::open(&dir.0, &changed, generator.as_ref())
                .err()
                .unwrap();
            assert!(error.contains("the seed's declaration differs"), "{error}");
        }
    }
    // The fixed pages' bytes are not part of the declaration.
    let mut bytes = seed.clone();
    bytes.fixed[0].body = b"other bytes".to_vec();
    Store::open(&dir.0, &bytes, None).unwrap();
}

#[test]
fn stores_of_another_format_and_empty_replays_are_refused() {
    let dir = Dir::new("formats");
    let seed = seed();
    let error = Store::open(&dir.0, &seed, None).err().unwrap();
    assert!(
        error.contains("replay needs a store a generator made"),
        "{error}"
    );
    assert!(!dir.0.join("store.json").exists());
    let legacy = dir.0.join("legacy");
    std::fs::create_dir_all(legacy.join("pages")).unwrap();
    std::fs::write(legacy.join("@store.json"), "{}").unwrap();
    let error = Store::open(&legacy, &seed, Some(&Generator::Stub.identity()))
        .err()
        .unwrap();
    assert!(
        error.contains("files of no store of this version"),
        "{error}"
    );
    let fresh = dir.0.join("fresh");
    Store::open(&fresh, &seed, Some(&Generator::Stub.identity())).unwrap();
    let path = fresh.join("store.json");
    let mut identity: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    identity["version"] = json!(999);
    std::fs::write(&path, identity.to_string()).unwrap();
    let error = Store::open(&fresh, &seed, None).err().unwrap();
    assert!(
        error.contains("unsupported store format version"),
        "{error}"
    );
    identity["version"] = json!(1);
    std::fs::write(&path, identity.to_string()).unwrap();
    std::fs::write(
        fresh.join("world.jsonl"),
        "{\"cast\":{\"people\":[],\"usage\":",
    )
    .unwrap();
    let error = Store::open(&fresh, &seed, None).err().unwrap();
    assert!(error.contains("world.jsonl: line 1"), "{error}");
}

// ---- a model -------------------------------------------------------------

/// A world on a store with the fake OpenRouter.
fn model_world(dir: &Dir, script: &Arc<Script>, prefetch: usize) -> (Arc<Pages>, Arc<Fake>) {
    let fake = fake_openrouter(script.clone());
    let pages = on_disk(
        &dir.0,
        seed(),
        Some(Generator::Model(openrouter(fake.clone()))),
        prefetch,
    )
    .unwrap();
    (pages, fake)
}

#[test]
fn model_pages_keep_titles_count_cost_and_never_store_the_key() {
    let dir = Dir::new("model");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 2);
    let world = pages.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "halvard flaw").await;
        assert_eq!(
            (&search.meta["cache"], &search.meta["cost"]),
            (&json!("generated"), &json!(0.0021))
        );
        let (url, title) = results(&search.body)[0].clone();
        // The prefetched page is ready in the background.
        cx.sleep(ms(1000)).await?;
        let page = get(&world, &cx, &url).await;
        assert_eq!(page.meta["cache"], "prefetched");
        assert_eq!(page.status, 200, "a page a result points at is never a 404");
        let html = String::from_utf8_lossy(&page.body);
        assert!(html.contains(&format!("<title>{title}</title>")));
        assert_eq!(page.meta["unsupported_snippets"], json!([]));
        assert_eq!(get(&world, &cx, &url).await.meta["cache"], "cached");
        // The cast was made once, and every later prompt names it.
        assert_eq!(
            world.cast(&cx).await.ok().unwrap()[0].name,
            "Tomasz Wierzbicki"
        );
        Ok(())
    });
    let requests = fake.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|(headers, _)| headers.contains(&("authorization", format!("Bearer {KEY}"))))
    );
    drop(requests);
    assert_eq!(
        fake.systems()
            .iter()
            .filter(|s| !s.contains("Tomasz Wierzbicki"))
            .count(),
        1
    );
    drop(pages);
    assert!(dir.texts().iter().all(|text| !text.contains(KEY)));
}

#[test]
fn a_page_is_checked_against_the_mentions_its_model_was_shown() {
    let searches: Vec<_> = (0..=prompts::LINK_MENTIONS_PER_PAGE)
        .map(|i| {
            json!({"via": "search", "query": format!("query {i}"), "title": "Story",
            "snippet": format!("Evidence number {i}.")})
        })
        .collect();
    let links: Vec<_> = (0..=prompts::LINK_MENTIONS_PER_PAGE)
        .map(|i| {
            json!({"via": "link", "from": format!("https://source.example-site.com/{i}"),
            "anchor": format!("Source {i}")})
        })
        .collect();
    for missing in [false, true] {
        let dir = Dir::new(&format!("mentions-{missing}"));
        let script = Arc::new(Script::default());
        let (pages, fake) = model_world(&dir, &script, 0);
        no_cast(&pages);
        for mention in links.iter().chain(&searches) {
            pages
                .store()
                .add_mention("news.example-site.com", "/story", mention.clone())
                .unwrap();
        }
        let shown = if missing {
            &searches[..searches.len() - 1]
        } else {
            &searches[..]
        };
        let body: Vec<_> = shown
            .iter()
            .map(|m| m["snippet"].as_str().unwrap())
            .collect();
        script.pages.lock().unwrap().push_back(format!(
            "STATUS: 200\nCONTENT_TYPE: text/plain\nTITLE: Story\nBODY:\n{}",
            body.join(" ")
        ));
        let (searches, links) = (searches.clone(), links.clone());
        lab(|cx| async move {
            let page = get(&pages, &cx, "https://news.example-site.com/story").await;
            let record = pages
                .store()
                .page("news.example-site.com", "/story")
                .unwrap()
                .clone();
            let asked: Vec<_> = links[..prompts::LINK_MENTIONS_PER_PAGE]
                .iter()
                .chain(&searches)
                .cloned()
                .collect();
            assert_eq!(record.mentions, asked);
            let prompt = fake.users().pop().unwrap();
            for mention in &searches {
                let snippet = mention["snippet"].as_str().unwrap();
                assert!(prompt.contains(&format!("snippet \"{snippet}\"")));
            }
            for (i, mention) in links.iter().enumerate() {
                let from = mention["from"].as_str().unwrap();
                assert_eq!(prompt.contains(from), i < prompts::LINK_MENTIONS_PER_PAGE);
            }
            let expected = if missing {
                json!([searches.last().unwrap()["snippet"]])
            } else {
                json!([])
            };
            assert_eq!(page.meta["unsupported_snippets"], expected);
            assert_eq!(page.meta["unchecked_snippets"], json!([]));
            // A stored page keeps the result of its check.
            let cached = get(&pages, &cx, "https://news.example-site.com/story").await;
            assert_eq!(cached.meta["cache"], "cached");
            assert_eq!(cached.meta["unsupported_snippets"], expected);
            Ok(())
        });
    }
}

#[test]
fn an_unreadable_answer_is_asked_again_and_counted() {
    let dir = Dir::new("reask");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    script.bad.store(1, Ordering::SeqCst);
    let world = pages.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "halvard").await;
        assert_eq!(search.meta["results"], 10);
        assert_eq!(search.meta["cost"], json!(0.0042));
        Ok(())
    });
    let users = fake.users();
    assert!(users[1].contains("The previous answer could not be read: no results"));
    let rows = dir.rows();
    let usage = &rows.last().unwrap()["generation"];
    assert_eq!(
        (&usage["attempts"], &usage["asks"], &usage["cost_unknown"]),
        (&json!(2), &json!(2), &json!(0))
    );
    assert_eq!(usage["cost_known"], json!(0.0042));
}

#[test]
fn two_unreadable_answers_keep_their_attempts_and_serve_503() {
    let dir = Dir::new("two-bad");
    let script = Arc::new(Script::default());
    let (pages, _) = model_world(&dir, &script, 0);
    no_cast(&pages);
    script.bad.store(2, Ordering::SeqCst);
    let world = pages.clone();
    lab(|cx| async move {
        let page = world
            .handle(&cx, "GET", "example.com", "/story", None)
            .await;
        assert_eq!(page.status, 503);
        assert_eq!(page.body, UNAVAILABLE);
        assert_eq!(page.meta["kind"], "error");
        assert_eq!(page.meta["cost"], json!(0.0042));
        assert!(page.meta["error"].as_str().unwrap().contains("no BODY"));
        assert!(page.meta["serve_ms"].is_u64());
        assert!(world.store().page("example.com", "/story").is_none());
        Ok(())
    });
    let rows = dir.rows();
    assert_eq!(
        rows.iter().map(|r| r["cost"].clone()).collect::<Vec<_>>(),
        [json!(0.0021), json!(0.0021)]
    );
    assert_eq!(
        rows.iter()
            .map(|r| r["outcome"].clone())
            .collect::<Vec<_>>(),
        [json!("unreadable"), json!("unreadable")]
    );
    let usage = &rows[1]["generation"];
    assert_eq!(
        (&usage["status"], &usage["attempts"], &usage["asks"]),
        (&json!("error"), &json!(2), &json!(2))
    );
}

#[test]
fn keys_must_be_set_and_fit_a_header() {
    for variable in ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"] {
        for c in ['\n', '\r', '\t', ' ', '\u{1f}', '\u{7f}', 'é', '\0'] {
            let error = Key::new(variable, Some(format!("{KEY}{c}"))).unwrap_err();
            assert_eq!(
                error,
                format!("{variable} holds characters an HTTP header cannot carry")
            );
        }
        assert_eq!(
            Key::new(variable, None).unwrap_err(),
            format!("{variable} is not set")
        );
        assert_eq!(
            Key::new(variable, Some(String::new())).unwrap_err(),
            format!("{variable} is not set")
        );
        let key = Key::new(variable, Some(KEY.into())).unwrap();
        assert_eq!(format!("{key:?}"), format!("<{variable}>"));
        assert_eq!(
            key.redact(&format!("{KEY}-long and {KEY}")),
            format!("<{variable}>-long and <{variable}>")
        );
    }
}

#[test]
fn an_echoed_key_is_never_stored_or_shown() {
    for (status, prefix) in [
        (400, String::new()),
        (400, "x".repeat(330)),
        (200, String::new()),
        (200, "x".repeat(330)),
    ] {
        let dir = Dir::new(&format!("echo-{status}-{}", prefix.len()));
        let script = Arc::new(Script::default());
        let (pages, _) = model_world(&dir, &script, 0);
        no_cast(&pages);
        script.echoes.lock().unwrap().push_back((status, prefix));
        let world = pages.clone();
        lab(|cx| async move {
            let search = google(&world, &cx, "halvard flaw").await;
            assert_eq!(search.status, 503);
            assert!(!search.meta["error"].as_str().unwrap().contains(&KEY[..12]));
            Ok(())
        });
        let rows = dir.rows();
        let last = rows.last().unwrap();
        assert_eq!(last["generation"]["status"], "error");
        let error = last["error"].as_str().unwrap();
        assert!(
            error.contains("rejected Authorization: Bearer <OPENROUTER_API_KEY>"),
            "{error}"
        );
        drop(pages);
        for text in dir.texts() {
            assert!(!text.contains(&KEY[..12]));
        }
    }
}

#[test]
fn a_failed_prefetch_is_recorded_and_made_again_on_request() {
    let dir = Dir::new("prefetch-error");
    let script = Arc::new(Script::default());
    let (pages, _) = model_world(&dir, &script, 1);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "halvard flaw").await;
        let (url, _) = results(&search.body)[0].clone();
        task.bad.store(2, Ordering::SeqCst);
        cx.sleep(ms(1000)).await?;
        let page = get(&world, &cx, &url).await;
        assert_eq!(
            (page.status, &page.meta["cache"]),
            (200, &json!("generated"))
        );
        Ok(())
    });
    let rows = dir.rows();
    let diagnostic = rows.iter().find(|r| r["kind"] == "prefetch_error").unwrap();
    assert_eq!(diagnostic["record"], "diagnostic");
    assert!(diagnostic["error"].as_str().unwrap().contains("no BODY"));
    assert_eq!(diagnostic["cost"], json!(0.0042));
    assert!(diagnostic["serve_ms"].is_u64());
}

#[test]
fn model_pages_keep_their_status_type_and_body() {
    let dir = Dir::new("statuses");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    lab(|cx| async move {
        let push = |answers: &[&str]| {
            let mut queue = task.pages.lock().unwrap();
            queue.clear();
            queue.extend(answers.iter().map(|a| (*a).to_owned()));
        };
        // A JSON 404 keeps its status and body.
        let body = "{\"message\": \"Not Found\"}";
        push(&[&format!("STATUS: 404\nTITLE: Missing\nBODY:\n{body}")]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing.json").await;
            assert_eq!((page.status, &page.meta["cache"]), (404, &json!(cache)));
            assert_eq!(page.content_type, "application/json; charset=utf-8");
            assert_eq!(page.body, body.as_bytes());
        }
        // An unreferenced HTML 404 is the site's not-found page.
        push(&["STATUS: 404\nTITLE: Missing\nBODY:\nPage not found"]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing").await;
            assert_eq!((page.status, &page.meta["cache"]), (404, &json!(cache)));
            assert!(String::from_utf8_lossy(&page.body).contains("<h1>Page not found</h1>"));
        }
        // Another status, or JSON that is not JSON, is never stored.
        for (path, answer) in [
            (
                "/error",
                "STATUS: 500\nTITLE: Error\nBODY:\nGeneration failed",
            ),
            ("/broken.json", "STATUS: 201\nTITLE: x\nBODY:\nNot found"),
            ("/gone.json", "STATUS: 404\nTITLE: x\nBODY:\nNot found"),
        ] {
            push(&[answer, answer]);
            let page = get(&world, &cx, &format!("https://example.com{path}")).await;
            assert_eq!(page.status, 503, "{path}");
            assert!(world.store().page("example.com", path).is_none());
        }
        Ok(())
    });
    // Each page was asked once, and each refused one twice.
    assert_eq!(fake.users().len(), 2 + 3 * 2);
}

#[test]
fn a_referenced_page_is_never_a_404() {
    let dir = Dir::new("referenced");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "halvard").await;
        let (url, _) = results(&search.body)[0].clone();
        let (host, target) = text::target_of(&url);
        for (path, body) in [
            (target.clone(), "Page not found"),
            (format!("{target}.json"), "{\"message\": \"Not Found\"}"),
            (format!("{target}.txt"), "Page not found"),
        ] {
            if path != target {
                let mention = json!({"via": "link", "from": url, "anchor": "Details"});
                world.store().add_mention(&host, &path, mention).unwrap();
            }
            let bad = format!("STATUS: 404\nTITLE: Missing\nBODY:\n{body}");
            let good_body = if path.ends_with(".json") {
                "{\"message\": \"Details\"}"
            } else {
                "Details"
            };
            let good = format!("STATUS: 200\nTITLE: Details\nBODY:\n{good_body}");
            task.pages
                .lock()
                .unwrap()
                .extend([bad.clone(), bad.clone()]);
            let refused = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(refused.status, 503);
            assert!(
                refused.meta["error"]
                    .as_str()
                    .unwrap()
                    .contains("referenced")
            );
            assert!(world.store().page(&host, &path).is_none());
            task.pages.lock().unwrap().extend([bad, good]);
            let page = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (page.status, &page.meta["cache"]),
                (200, &json!("generated"))
            );
            assert_eq!(page.meta["cost"], json!(0.0042));
            assert!(String::from_utf8_lossy(&page.body).contains("Details"));
            let cached = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (cached.status, &cached.meta["cache"], cached.body),
                (200, &json!("cached"), page.body)
            );
        }
        Ok(())
    });
    assert!(fake.users().last().unwrap().contains("referenced"));
}

#[test]
fn listed_ranks_follow_display_order_after_duplicates() {
    let dir = Dir::new("ranks");
    let answer = "RESULT\nURL: https://first-site.com/story\nTITLE: First\nSNIPPET: First story.\n\
        RESULT\nURL: https://first-site.com/story\nTITLE: First\nSNIPPET: First story.\n\
        RESULT\nURL: https://second-site.com/story\nTITLE: Second\nSNIPPET: Second story.";
    let fake = Fake::script(vec![
        completion(10, answer, Some(0.001)),
        completion(10, PAGE, Some(0.001)),
    ]);
    let pages = on_disk(&dir.0, seed(), Some(Generator::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let search = google(&pages, &cx, "stories").await;
        let ranks: Vec<_> = search.meta["listed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["rank"].clone())
            .collect();
        assert_eq!(ranks, [json!(1), json!(2)]);
        let page = get(&pages, &cx, "https://second-site.com/story").await;
        assert_eq!(
            page.meta["reason"],
            json!({"via": "search", "query": "stories", "rank": 2})
        );
        Ok(())
    });
}

/// A search and a direct request for the page it lists, made at nearly the
/// same time, publish one title: the first to reach the URL's lock decides.
#[test]
fn a_search_and_a_page_publish_one_title() {
    const URL: &str = "https://race.example-site.com/story";
    for page_first in [false, true] {
        let dir = Dir::new(&format!("race-{page_first}"));
        let search = format!(
            "RESULT\nURL: {URL}\nTITLE: first\nSNIPPET: Snippet for first.\nDATE: 1 Oct 2026"
        );
        let page = "STATUS: 200\nTITLE: Story\nDESCRIPTION: The story.\nBODY:\n<h1>Story</h1>";
        // A list takes 10 ms to write, a page 50 ms; the second request
        // starts 20 ms after the first.
        let fake = Fake::new(move |_, body| {
            let prompt = body["messages"][1]["content"].as_str().unwrap();
            if prompt.contains("Someone searched for") {
                completion(10, &search, Some(0.001))
            } else {
                completion(50, page, Some(0.001))
            }
        });
        let pages = on_disk(&dir.0, seed(), Some(Generator::Model(openrouter(fake))), 0).unwrap();
        no_cast(&pages);
        lab(|cx| async move {
            let (search_tx, search_rx) = tokio::sync::oneshot::channel();
            let (page_tx, page_rx) = tokio::sync::oneshot::channel();
            let searching = pages.clone();
            let search = move |cx: Cx| async move {
                let _ = search_tx.send(google(&searching, &cx, "first").await);
                Ok(())
            };
            let getting = pages.clone();
            let page = move |cx: Cx| async move {
                let _ = page_tx.send(get(&getting, &cx, URL).await);
                Ok(())
            };
            if page_first {
                cx.spawn(page);
                cx.sleep(ms(20)).await?;
                cx.spawn(search);
            } else {
                cx.spawn(search);
                cx.sleep(ms(20)).await?;
                cx.spawn(page);
            }
            let (listed, direct) = (search_rx.await.unwrap(), page_rx.await.unwrap());
            let title = if page_first { "Story" } else { "first" };
            assert_eq!(results(&listed.body), [(URL.to_owned(), title.to_owned())]);
            assert_eq!(direct.meta["title"], title);
            assert!(
                String::from_utf8_lossy(&direct.body).contains(&format!("<title>{title}</title>"))
            );
            let store = pages.store();
            let mentions = store.mentions("race.example-site.com", "/story");
            assert_eq!(mentions.len(), 1);
            assert_eq!(mentions[0]["title"], title);
            let snippet = if page_first {
                "The story."
            } else {
                "Snippet for first."
            };
            assert_eq!(
                store.search("first").unwrap().search.results[0].snippet,
                snippet
            );
            Ok(())
        });
    }
}

/// Two searches that list one URL show the title the first one reserved,
/// and the page takes it.
#[test]
fn competing_searches_publish_one_title() {
    const URL: &str = "https://race.example-site.com/story";
    let dir = Dir::new("race-searches");
    let fake = Fake::new(move |_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        if let Some(query) = prompt
            .strip_prefix("Someone searched for: ")
            .and_then(|p| p.lines().next())
        {
            let answer =
                format!("RESULT\nURL: {URL}\nTITLE: {query}\nSNIPPET: Snippet for {query}.");
            completion(10, &answer, Some(0.001))
        } else {
            completion(10, PAGE, Some(0.001))
        }
    });
    let pages = on_disk(&dir.0, seed(), Some(Generator::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let other = pages.clone();
        cx.spawn(move |cx| async move {
            cx.sleep(ms(5)).await?;
            let _ = tx.send(google(&other, &cx, "second").await);
            Ok(())
        });
        let first = google(&pages, &cx, "first").await;
        let second = rx.await.unwrap();
        for listed in [&first, &second] {
            assert_eq!(
                results(&listed.body),
                [(URL.to_owned(), "first".to_owned())]
            );
        }
        let page = get(&pages, &cx, URL).await;
        assert_eq!(page.meta["title"], "first");
        let store = pages.store();
        let mentions = store.mentions("race.example-site.com", "/story");
        let queries: Vec<_> = mentions.iter().map(|m| m["query"].clone()).collect();
        assert_eq!(queries, [json!("first"), json!("second")]);
        assert!(
            mentions
                .iter()
                .all(|m| m["title"] == "first" && m["rank"] == 1)
        );
        assert_eq!(mentions[1]["snippet"], "Snippet for second.");
        Ok(())
    });
}

// ---- the ledger ----------------------------------------------------------

/// A page made by `fake` alone, without a cast, and its generation rows.
fn ledger_page(name: &str, fake: Arc<Fake>) -> (Response, Vec<Value>, Option<PageRecord>) {
    let dir = Dir::new(name);
    let pages = on_disk(&dir.0, seed(), Some(Generator::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    let world = pages.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    lab(|cx| async move {
        tx.send(get(&world, &cx, "https://example.com/story").await)
            .unwrap();
        Ok(())
    });
    let record = pages.store().page("example.com", "/story").cloned();
    (rx.recv().unwrap(), dir.rows(), record)
}

fn column(rows: &[Value], key: &str) -> Vec<Value> {
    rows.iter().map(|r| r[key].clone()).collect()
}

#[test]
fn a_retried_failure_counts_in_the_generation() {
    let (page, rows, record) = ledger_page(
        "ledger-retry",
        Fake::script(vec![
            http_error(100, 429),
            completion(250, PAGE, Some(0.0021)),
        ]),
    );
    let usage = record.unwrap().usage.unwrap();
    assert_eq!(column(&rows, "outcome"), [json!("http 429"), json!("ok")]);
    assert_eq!(column(&rows, "ms"), [json!(100), json!(250)]);
    assert_eq!(column(&rows, "terminal"), [json!(false), json!(true)]);
    assert_eq!(column(&rows, "backoff_ms"), [json!(1500), json!(0)]);
    assert_eq!(
        (usage.attempts, usage.asks, usage.gen_ms, usage.call_ms),
        (2, 1, 1850, Some(250))
    );
    assert_eq!(page.meta["gen_ms"], 1850);
    assert_eq!((usage.cost_known, usage.cost_unknown), (0.0021, 1));
    assert_eq!(
        (usage.cost, usage.input_tokens, usage.output_tokens),
        (None, None, None)
    );
    assert_eq!(rows[1]["generation"]["status"], "ok");
    assert_eq!(
        (&rows[1]["model"], &rows[1]["raw"]),
        (&json!("answered/model"), &json!(PAGE))
    );
    for row in &rows {
        assert_eq!(
            (&row["kind"], &row["url"]),
            (&json!("page"), &json!("https://example.com/story"))
        );
    }
}

#[test]
fn exhausted_attempts_fail_with_their_totals() {
    let (page, rows, record) = ledger_page(
        "ledger-exhausted",
        Fake::script(vec![
            http_error(100, 503),
            http_error(200, 429),
            http_error(300, 529),
        ]),
    );
    assert!(record.is_none());
    assert_eq!(page.status, 503);
    assert!(page.meta["error"].as_str().unwrap().contains("HTTP 529"));
    assert_eq!(column(&rows, "attempt"), [json!(1), json!(2), json!(3)]);
    assert_eq!(
        column(&rows, "cost"),
        [Value::Null, Value::Null, Value::Null]
    );
    let usage = &rows[2]["generation"];
    assert_eq!(
        (&usage["status"], &usage["gen_ms"], &usage["backoff_ms"]),
        (&json!("error"), &json!(5100), &json!(4500))
    );
    assert_eq!(
        (
            &usage["attempts"],
            &usage["cost_known"],
            &usage["cost_unknown"]
        ),
        (&json!(3), &json!(0.0), &json!(3))
    );
    assert!(usage["call_ms"].is_null() && usage["cost"].is_null());
    assert_eq!(page.meta["gen_ms"], 5100);
}

#[test]
fn transport_failures_are_retried_after_a_backoff() {
    let (_, rows, record) = ledger_page(
        "ledger-transport",
        Fake::script(vec![
            (ms(100), Err("timed out".into())),
            (ms(200), Err(format!("connection lost with {KEY}"))),
            completion(300, PAGE, Some(0.0021)),
        ]),
    );
    assert!(record.is_some());
    assert_eq!(
        column(&rows, "outcome"),
        [json!("transport"), json!("transport"), json!("ok")]
    );
    assert_eq!(
        column(&rows, "backoff_ms"),
        [json!(1500), json!(3000), json!(0)]
    );
    assert_eq!(rows[2]["generation"]["gen_ms"], 5100);
    assert_eq!(rows[2]["generation"]["call_ms"], 300);
    assert_eq!(
        rows[1]["error"],
        "connection lost with <OPENROUTER_API_KEY>"
    );
}

#[test]
fn an_unknown_cost_is_not_zero() {
    let (_, rows, _) = ledger_page(
        "ledger-unknown",
        Fake::script(vec![
            completion(100, "unreadable", Some(0.1)),
            completion(200, PAGE, None),
        ]),
    );
    let usage = &rows[1]["generation"];
    assert!(usage["cost"].is_null());
    assert_eq!(
        (&usage["cost_known"], &usage["cost_unknown"]),
        (&json!(0.1), &json!(1))
    );
    assert_eq!(
        (&usage["input_tokens"], &usage["output_tokens"]),
        (&json!(2000), &json!(1000))
    );
    assert_eq!((&usage["attempts"], &usage["asks"]), (&json!(2), &json!(2)));
}

#[test]
fn an_unreadable_answer_then_transport_failures_count_every_attempt() {
    let mut replies = vec![completion(100, "unreadable", Some(0.0021))];
    replies.extend((0..3).map(|_| (ms(200), Err("timed out".to_owned()))));
    let (page, rows, record) = ledger_page("ledger-mixed", Fake::script(replies));
    assert!(record.is_none());
    let asks: Vec<_> = rows
        .iter()
        .map(|r| (r["ask"].clone(), r["attempt"].clone()))
        .collect();
    assert_eq!(
        asks,
        [
            (json!(1), json!(1)),
            (json!(2), json!(1)),
            (json!(2), json!(2)),
            (json!(2), json!(3))
        ]
    );
    let usage = &rows[3]["generation"];
    assert_eq!(
        (&usage["attempts"], &usage["asks"], &usage["gen_ms"]),
        (&json!(4), &json!(2), &json!(5200))
    );
    assert_eq!(
        (&usage["cost_known"], &usage["cost_unknown"]),
        (&json!(0.0021), &json!(3))
    );
    assert!(usage["cost"].is_null() && page.meta["cost"].is_null());
    assert_eq!(page.meta["gen_ms"], 5200);
}

#[test]
fn a_permanent_error_is_not_retried() {
    let dir = Dir::new("ledger-cast");
    let fake = Fake::script(vec![http_error(100, 401)]);
    let pages = on_disk(&dir.0, seed(), Some(Generator::Model(openrouter(fake))), 0).unwrap();
    lab(|cx| async move {
        assert!(pages.cast(&cx).await.is_err());
        Ok(())
    });
    let rows = dir.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0]["kind"], &rows[0]["outcome"]),
        (&json!("cast"), &json!("http 401"))
    );
    assert_eq!(rows[0]["generation"]["gen_ms"], 100);
}

#[test]
fn provider_errors_and_invalid_json_are_recorded() {
    let error = json!({"error": {"message": "failed"}});
    let (_, rows, record) = ledger_page(
        "ledger-provider",
        Fake::script(vec![
            (ms(100), Ok((200, b"not JSON".to_vec()))),
            (ms(200), Ok((200, error.to_string().into_bytes()))),
        ]),
    );
    assert!(record.is_none());
    assert_eq!(
        column(&rows, "outcome"),
        [json!("unreadable"), json!("unreadable")]
    );
    assert_eq!(rows[1]["generation"]["status"], "error");
    assert_eq!(rows[1]["generation"]["cost_unknown"], 2);
}

#[test]
fn a_reported_failure_cost_is_kept() {
    let failed = json!({"usage": {"cost": 0.003, "prompt_tokens": 100, "completion_tokens": 0}});
    let (_, rows, _) = ledger_page(
        "ledger-failure-cost",
        Fake::script(vec![
            (ms(100), Ok((503, failed.to_string().into_bytes()))),
            completion(200, PAGE, Some(0.0021)),
        ]),
    );
    assert_eq!(column(&rows, "cost"), [json!(0.003), json!(0.0021)]);
    let usage = &rows[1]["generation"];
    assert!((usage["cost"].as_f64().unwrap() - 0.0051).abs() < 1e-12);
    assert_eq!(
        (
            &usage["cost_unknown"],
            &usage["input_tokens"],
            &usage["output_tokens"]
        ),
        (&json!(0), &json!(1100), &json!(500))
    );
}

#[test]
fn invalid_usage_stays_unknown() {
    let reply = json!({
        "model": "answered/model",
        "choices": [{"message": {"content": PAGE}}],
        "usage": {"cost": "unavailable", "prompt_tokens": false, "completion_tokens": -1},
    });
    let (_, rows, _) = ledger_page(
        "ledger-usage",
        Fake::script(vec![(ms(100), Ok((200, reply.to_string().into_bytes())))]),
    );
    assert_eq!(rows.len(), 1);
    for key in ["cost", "input_tokens", "output_tokens"] {
        assert!(rows[0][key].is_null(), "{key}");
        assert!(rows[0]["generation"][key].is_null(), "{key}");
    }
    assert_eq!(rows[0]["generation"]["cost_unknown"], 1);
}

#[test]
fn anthropic_answers_keep_tokens_and_where_they_stopped() {
    let reply = json!({
        "model": "answered/model",
        "content": [{"type": "text", "text": SEARCH}],
        "usage": {"input_tokens": 20, "output_tokens": 10},
        "stop_reason": "max_tokens",
    });
    let fake = Fake::script(vec![(ms(100), Ok((200, reply.to_string().into_bytes())))]);
    let key = Key::new("ANTHROPIC_API_KEY", Some(KEY.into())).unwrap();
    let model = Model::new(Provider::Anthropic, "", "", key, fake.clone());
    assert_eq!(model.model, Provider::Anthropic.default_model());
    let (tx, rx) = std::sync::mpsc::channel();
    lab(|cx| async move {
        let (answer, ledger) = model
            .ask(&cx, "system", "user", 100, prompts::read_search)
            .await;
        tx.send((
            answer.is_ok(),
            ledger.usage(),
            ledger.attempts[0].raw.clone(),
        ))
        .unwrap();
        Ok(())
    });
    let (ok, usage, raw) = rx.recv().unwrap();
    assert!(ok);
    assert_eq!(
        (
            usage.input_tokens,
            usage.output_tokens,
            usage.cost_unknown,
            usage.cut_off
        ),
        (Some(20), Some(10), 1, true)
    );
    assert_eq!(usage.cost, None);
    assert_eq!(raw.as_deref(), Some(SEARCH));
    let requests = fake.requests.lock().unwrap();
    let (headers, body) = &requests[0];
    assert!(headers.contains(&("x-api-key", KEY.to_owned())));
    assert_eq!(
        (&body["system"], &body["max_tokens"]),
        (&json!("system"), &json!(100))
    );
}
