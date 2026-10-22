use super::*;
use fictionet_extras::models::{Key, Post, Transport};
use model::Provider;
use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const KEY: &str = "sk-or-test-key-must-not-be-stored";

/// The event fields of an answer, as JSON: what the log and the search
/// projection read.
trait Logged {
    fn logged(&self) -> Value;
}
impl Logged for Response {
    fn logged(&self) -> Value {
        example_common::events::js(Some(&self.fields().to_json()))
    }
}

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

const FIXED_SEED: &str = r#"+++
date = "2026-10-21"
question = ""
[[sites]]
host = "www.reference.org"
about = "Python tutorial modules and packages"
[[fixed]]
url = "https://www.reference.org/tutorial/"
file = "tutorial.html"
title = "Python tutorial"
description = "The Python tutorial explains modules and packages."
+++
"#;
const FIXED_BODY: &str = "<html><head><title>Python tutorial</title></head><body><h1>Python tutorial</h1><p>The Python tutorial explains modules and packages.</p><a href='/tutorial/modules.html'>Modules</a></body></html>";

fn seed() -> Seed {
    Seed::builtin("web").unwrap()
}

pub(super) fn fixed_seed() -> Seed {
    Seed::parse("web", FIXED_SEED, |_| Ok(FIXED_BODY.as_bytes().to_vec())).unwrap()
}

fn plain() -> Arc<Pages> {
    Arc::new(Pages::new(seed()))
}

/// A directory for one test, removed when it ends.
struct Dir(PathBuf);
impl Dir {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "adaptive-web-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
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
        std::fs::read_to_string(self.0.join("web/generations.jsonl"))
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
    maker: Option<Maker>,
    prefetch: usize,
) -> Result<Arc<Pages>, String> {
    let identity = maker.as_ref().map(Maker::identity);
    let (store, _) = Store::open(&dir.join(&seed.name), &seed, identity.as_ref())?;
    Ok(Arc::new(Pages::open(seed, store, maker, prefetch)))
}

/// The result links and titles of a Google results page.
fn results(body: &[u8]) -> Vec<(String, String)> {
    fictionet_extras::search::links(std::str::from_utf8(body).unwrap())
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
    ) -> Post<'a> {
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

const PAGE: &str = "STATUS: 200\nTITLE: Story\nSITE_CSS: body {color: #234}\nBODY:\n<h1>Story</h1>";
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
            "Tomasz Wierzbicki | CEO | Python\nAmara Nwosu | analyst | Brightline Research\n\
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
                AD: none\nSITE_CSS: body {{color: #234}}\nBODY:\n<h1>Story</h1><p>{snippet}</p>"
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
fn site_styles_survive_restart_and_generation_off() {
    let dir = Dir::new("styles");
    let path = dir.0.clone();
    lab(move |cx| async move {
        let pages = on_disk(&path, fixed_seed(), Some(Maker::Stub), 0).unwrap();
        let first = get(&pages, &cx, "https://docs.tools.com/guide").await;
        let second = get(&pages, &cx, "https://docs.tools.com/reference").await;
        for page in [first, second] {
            assert!(String::from_utf8_lossy(&page.body).contains("href=\"/static/css/main.css\""));
        }
        let css = get(&pages, &cx, "https://docs.tools.com/static/css/main.css").await;
        assert!(css.body.len() > 1000);
        let fixed = pages.seed.fixed[0].clone();
        assert_eq!(get(&pages, &cx, &fixed.url).await.body, fixed.body);
        let fixed_css = get(
            &pages,
            &cx,
            &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host),
        )
        .await;
        assert!(!fixed_css.body.is_empty());
        assert_eq!(
            fixed_css.body,
            get(
                &pages,
                &cx,
                &format!("https://{}/static/css/main.css", fixed.host)
            )
            .await
            .body
        );
        drop(pages);
        let replay = on_disk(&path, fixed_seed(), None, 0).unwrap();
        assert_eq!(
            get(&replay, &cx, "https://docs.tools.com/static/css/main.css")
                .await
                .body,
            css.body
        );
        assert_eq!(
            get(
                &replay,
                &cx,
                &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host)
            )
            .await
            .body,
            fixed_css.body
        );
        assert_eq!(replay.store().made, 0);
        Ok(())
    });
}

#[test]
fn model_site_stylesheets_start_with_shared_layout_and_end_with_site_rules() {
    let dir = Dir::new("shared-styles");
    let own = "body { color: #234; font-family: Georgia; } header { background: #fff; }";
    let fake = Fake::script(vec![completion(
        10,
        &format!(
            "STATUS: 200\nTITLE: Article\nSITE_NAME: Field News\nSITE_KIND: news\nSITE_CSS: {own}\nBODY:\n<h1>Article</h1><p>A new report.</p>"
        ),
        Some(0.001),
    )]);
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let page = get(&pages, &cx, "https://news.fields.com/article").await;
        assert_eq!(page.status, 200);
        let css = get(&pages, &cx, "https://news.fields.com/static/css/main.css").await;
        assert_eq!(css.status, 200);
        assert_eq!(css.content_type, "text/css");
        let css = String::from_utf8(css.body).unwrap();
        let base = make::stylesheet("news");
        for selector in [
            "header {",
            ".brand a,",
            ".tagline {",
            "nav ul,",
            ".layout,",
            "main {",
            "footer {",
        ] {
            assert!(base.contains(selector), "{selector}");
        }
        assert_eq!(css, format!("{base}\n{own}"));
        assert_eq!(pages.store().site("news.fields.com").unwrap().css, own);
        let audit = example_common::guest_content::Audit::default();
        audit.inspect("site stylesheet", css.as_bytes());
        audit.check().unwrap();
        Ok(())
    });
}

#[test]
fn concurrent_model_pages_share_one_stylesheet() {
    let dir = Dir::new("model-styles");
    let fake = Fake::new(|_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        let first = prompt.contains("SITE_CSS:");
        completion(
            10,
            if first {
                "STATUS: 200\nTITLE: Guide\nSITE_NAME: Field Notes\nSITE_KIND: docs\nSITE_CSS: body { color: #17472c; }\nBODY:\n<h1>Guide</h1>"
            } else {
                "STATUS: 200\nTITLE: Reference\nBODY:\n<h1>Reference</h1>"
            },
            Some(0.001),
        )
    });
    let pages = on_disk(
        &dir.0,
        seed(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    )
    .unwrap();
    no_cast(&pages);
    let path = dir.0.clone();
    lab(move |cx| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let other = on_disk(
            &path,
            seed(),
            Some(Maker::Model(openrouter(fake.clone()))),
            0,
        )
        .unwrap();
        cx.spawn(move |cx| async move {
            tx.send(get(&other, &cx, "https://docs.fields.com/reference").await)
                .unwrap();
            Ok(())
        });
        let first = get(&pages, &cx, "https://docs.fields.com/guide").await;
        let second = rx.await.unwrap();
        assert_eq!((first.status, second.status), (200, 200));
        assert_eq!(
            fake.users()
                .iter()
                .filter(|p| p.contains("SITE_CSS:"))
                .count(),
            1
        );
        assert_eq!(fake.users().len(), 2);
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: 0,
                },
            )
            .unwrap();
        let css = get(&pages, &cx, "https://docs.fields.com/static/css/main.css").await;
        assert_eq!(
            css.body,
            format!("{}\nbody {{ color: #17472c; }}", make::stylesheet("docs")).as_bytes()
        );
        let replay = on_disk(&path, seed(), None, 0).unwrap();
        assert_eq!(
            get(
                &replay,
                &cx,
                "https://docs.fields.com/static/css/main.css?v=2"
            )
            .await
            .body,
            css.body
        );
        assert_eq!(fake.users().len(), 2);
        Ok(())
    });
}

#[test]
fn fixed_model_host_gets_one_stylesheet_without_rewriting_pages() {
    let dir = Dir::new("fixed-style");
    let fake = Fake::script(vec![completion(10, "body {color: #17472c}", Some(0.001))]);
    let pages = on_disk(
        &dir.0,
        fixed_seed(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    )
    .unwrap();
    lab(move |cx| async move {
        let fixed = pages.seed.fixed[0].clone();
        for _ in 0..2 {
            assert_eq!(get(&pages, &cx, &fixed.url).await.body, fixed.body);
            let css = get(
                &pages,
                &cx,
                &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host),
            )
            .await;
            assert_eq!(
                css.body,
                format!(
                    "{}\nbody {{color: #17472c}}",
                    make::stylesheet(&make::site_profile(&fixed.host).kind)
                )
                .as_bytes()
            );
        }
        assert_eq!(fake.users().len(), 1);
        assert!(fake.users()[0].contains("Python tutorial"));
        Ok(())
    });
}

#[test]
fn unrelated_model_results_omit_seed_pages() {
    let dir = Dir::new("unrelated");
    let seed = fixed_seed();
    let answer = format!(
        "RESULT\nURL: {}\nTITLE: {}\nSNIPPET: {}\n\
        RESULT\nURL: https://cooking.com/chicken-tikka-masala\nTITLE: Chicken tikka masala recipe\nSNIPPET: Marinate the chicken.",
        seed.fixed[0].url, seed.fixed[0].title, seed.fixed[0].description
    );
    let fake = Fake::script(vec![completion(10, &answer, Some(0.001))]);
    let pages = on_disk(&dir.0, seed, Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let search = google(&pages, &cx, "chicken tikka masala recipe").await;
        assert_eq!(
            results(&search.body),
            [(
                "https://cooking.com/chicken-tikka-masala".into(),
                "Chicken tikka masala recipe".into()
            )]
        );
        for fixed in &pages.seed.fixed {
            assert!(
                pages
                    .store()
                    .mentions(&fixed.host, &fixed.target)
                    .is_empty()
            );
        }
        Ok(())
    });
}

#[test]
fn model_results_keep_held_pages_their_own_rows_relate() {
    let dir = Dir::new("related");
    let seed = fixed_seed();
    let answer = format!(
        "RESULT\nURL: {}\nTITLE: {}\nSNIPPET: The Python tutorial explains modules and packages.",
        seed.fixed[0].url, seed.fixed[0].title
    );
    let fake = Fake::script(vec![completion(10, &answer, Some(0.001))]);
    let pages = on_disk(&dir.0, seed, Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let search = google(&pages, &cx, "Python tutorial modules").await;
        let url = pages.seed.fixed[0].url.clone();
        assert_eq!(
            results(&search.body)
                .into_iter()
                .map(|(url, _)| url)
                .collect::<Vec<_>>(),
            [url]
        );
        Ok(())
    });
}

#[test]
fn the_same_requests_make_the_same_world() {
    lab(|cx| async move {
        let (a, b) = (plain(), plain());
        let first = google(&a, &cx, "python module documentation").await;
        let second = google(&b, &cx, "python module documentation").await;
        assert_eq!(first.body, second.body);
        for (url, _) in results(&first.body).into_iter().take(5) {
            assert_eq!(get(&a, &cx, &url).await.body, get(&b, &cx, &url).await.body);
        }
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
        let pages = plain();
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
        let pages = plain();
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
            .handle(&cx, "GET", "www.bing.com", "/search?q=python&first=x", None)
            .await;
        assert_eq!(bing.status, 200);
        let css = pages
            .handle(&cx, "GET", "a.com", "/static/css/main.css", None)
            .await;
        assert_eq!(
            (css.content_type.as_str(), &css.logged()["kind"]),
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
        let pages = Arc::new(Pages::new(fixed_seed()));
        let fixed = pages.seed().fixed[0].clone();
        let page = get(&pages, &cx, &fixed.url).await;
        assert_eq!(page.body, fixed.body);
        assert_eq!(page.logged()["cache"], "fixed");
        // Its links are written down for the pages behind them.
        assert!(
            !pages
                .store()
                .mentions(&fixed.host, "/tutorial/modules.html")
                .is_empty()
        );
        Ok(())
    });
}

#[test]
fn concurrent_requests_make_one_page() {
    lab(|cx| async move {
        let pages = plain();
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
            .filter(|r| r.logged()["cache"] == "generated")
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
        let pages = plain();
        let first = get(&pages, &cx, "https://example.com/first").await;
        assert_eq!(first.status, 200);
        pages.store().made = GENERATION_BUDGET;
        let second = get(&pages, &cx, "https://example.com/second").await;
        assert_eq!(
            (second.status, &second.logged()["cache"]),
            (503, &json!("budget"))
        );
        let search = google(&pages, &cx, "new query").await;
        assert_eq!(
            (search.status, &search.logged()["cache"]),
            (503, &json!("budget"))
        );
        // The agent sees a busy server's page; the log says what it was for.
        for (answer, kind) in [(&second, "page"), (&search, "search")] {
            assert_eq!(answer.body, UNAVAILABLE);
            assert_eq!(answer.logged()["kind"], kind);
        }
        assert_eq!(
            get(&pages, &cx, "https://example.com/first").await.body,
            first.body
        );
        assert!(pages.store().page("example.com", "/second").is_none());
        Ok(())
    });
}

// ---- the store -----------------------------------------------------------

#[test]
fn mentions_reserve_titles_and_keep_creation_order() {
    let seed = fixed_seed();
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
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stub), 0).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let s = pages
                .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=python", None)
                .await;
            let p = pages
                .handle(&cx, "GET", "docs.python.org", "/support/", None)
                .await;
            tx.send((s.body, p.body)).unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let replay = on_disk(&dir.0, seed(), None, 0).unwrap();
    lab(|cx| async move {
        let s = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=python", None)
            .await;
        assert_eq!(s.body, search);
        assert_eq!(s.logged()["cache"], "cached");
        let p = replay
            .handle(&cx, "GET", "docs.python.org", "/support/", None)
            .await;
        assert_eq!((&p.logged()["cache"], p.body), (&json!("cached"), page));
        let missing = replay
            .handle(&cx, "GET", "docs.python.org", "/never-asked", None)
            .await;
        assert_eq!(
            (missing.status, &missing.logged()["cache"]),
            (404, &json!("missing"))
        );
        let none = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=never", None)
            .await;
        assert_eq!(
            (
                none.logged()["cache"].clone(),
                none.logged()["results"].clone()
            ),
            (json!("missing"), json!(0))
        );
        Ok(())
    });
}

/// Gets `url` from every world at once.
async fn at_once(cx: &Cx, worlds: &[Arc<Pages>], url: &str) -> Vec<Response> {
    let replies: Vec<_> = worlds
        .iter()
        .map(|world| {
            let (world, url) = (world.clone(), url.to_owned());
            let (tx, rx) = tokio::sync::oneshot::channel();
            cx.spawn(move |cx| async move {
                let _ = tx.send(get(&world, &cx, &url).await);
                Ok(())
            });
            rx
        })
        .collect();
    let mut out = Vec::new();
    for reply in replies {
        out.push(reply.await.unwrap());
    }
    out
}

/// Worlds sharing a store, each with its own model API: the first to ask
/// for a list or a page makes it, and the others wait and read it. Every
/// world serves the same bytes, and the page has the title its result
/// showed.
#[test]
fn worlds_sharing_a_store_make_each_list_and_page_once() {
    let dir = Dir::new("shared");
    let fakes: Vec<_> = (0..3).map(|_| fake_openrouter(Arc::default())).collect();
    let worlds: Vec<_> = fakes
        .iter()
        .map(|fake| {
            let model = openrouter(fake.clone());
            on_disk(&dir.0, seed(), Some(Maker::Model(model)), 0).unwrap()
        })
        .collect();
    lab(move |cx| async move {
        let lists = at_once(&cx, &worlds, "https://www.google.com/search?q=python+flaw").await;
        assert!(
            lists
                .iter()
                .all(|r| r.status == 200 && r.body == lists[0].body)
        );
        let (url, title) = results(&lists[0].body).remove(0);
        let pages = at_once(&cx, &worlds, &url).await;
        assert!(
            pages
                .iter()
                .all(|r| r.status == 200 && r.body == pages[0].body)
        );
        assert_eq!(pages[0].logged()["title"], json!(title));
        let made = |cache: &str, rs: &[Response]| {
            rs.iter().filter(|r| r.logged()["cache"] == cache).count()
        };
        assert_eq!((made("generated", &lists), made("cached", &lists)), (1, 2));
        assert_eq!((made("generated", &pages), made("cached", &pages)), (1, 2));
        let asked: Vec<String> = fakes.iter().flat_map(|fake| fake.users()).collect();
        for prompt in [
            "List the people",
            "Someone searched for",
            "Write the page at",
        ] {
            let count = asked.iter().filter(|user| user.contains(prompt)).count();
            assert_eq!(count, 1, "{prompt}");
        }
        Ok(())
    });
    let world = std::fs::read_to_string(dir.0.join("web/world.jsonl")).unwrap();
    let kinds: Vec<String> = world
        .lines()
        .map(|line| {
            let entry: Value = serde_json::from_str(line).unwrap();
            entry.as_object().unwrap().keys().next().unwrap().clone()
        })
        .collect();
    for kind in ["cast", "search", "page"] {
        assert_eq!(kinds.iter().filter(|k| *k == kind).count(), 1, "{kind}");
    }
}

#[test]
fn fixed_snapshots_survive_changed_and_deleted_sources() {
    let dir = Dir::new("fixed");
    let seeds = dir.0.join("seeds");
    std::fs::create_dir_all(seeds.join("fixed")).unwrap();
    std::fs::write(seeds.join("web.md"), FIXED_SEED).unwrap();
    let file = seeds.join("tutorial.html");
    std::fs::write(&file, FIXED_BODY).unwrap();
    let load = || Seed::load(seeds.join("web.md")).unwrap();
    let url = load().fixed[0].url.clone();
    let fetch = |pages: Arc<Pages>| {
        let url = url.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let page = get(&pages, &cx, &url).await;
            let cache = page.logged()["cache"].clone();
            tx.send((page.status, page.content_type, page.body, cache))
                .unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let first = fetch(on_disk(&dir.0, load(), Some(Maker::Stub), 0).unwrap());
    assert_eq!(first.3, "fixed");
    // A restarted world serves the captured bytes, whatever the source says now.
    std::fs::write(&file, "a changed advisory").unwrap();
    assert_eq!(
        fetch(on_disk(&dir.0, load(), Some(Maker::Stub), 0).unwrap()),
        first
    );
    std::fs::remove_file(&file).unwrap();
    assert!(Seed::load(seeds.join("web.md")).is_err());
    let replay_seed = || {
        let text = std::fs::read_to_string(seeds.join("web.md")).unwrap();
        Seed::parse("web", &text, |_| Ok(Vec::new())).unwrap()
    };
    assert_eq!(
        fetch(on_disk(&dir.0, replay_seed(), None, 0).unwrap()),
        first
    );
    // Replay never captures a fixed page it has not seen.
    let fresh = Dir::new("fixed-unseen");
    {
        on_disk(&fresh.0, replay_seed(), Some(Maker::Stub), 0).unwrap();
    }
    let unseen = fetch(on_disk(&fresh.0, replay_seed(), None, 0).unwrap());
    assert_eq!((unseen.0, unseen.3), (404, json!("missing")));
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
        let mut seed = fixed_seed();
        seed.fixed[0].body = body.clone();
        seed.fixed[0].content_type = "application/octet-stream".into();
        let url = seed.fixed[0].url.clone();
        let host = seed.fixed[0].host.clone();
        for maker in [Some(Maker::Stub), None] {
            let pages = on_disk(&dir.0, seed.clone(), maker, 0).unwrap();
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
    let seed = fixed_seed();
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
        Maker::Stub.identity(),
    ] {
        let error = Store::open(&dir.0, &seed, Some(&other)).err().unwrap();
        assert!(
            error.contains("generator configuration mismatch"),
            "{error}"
        );
        assert!(error.contains("rebuild in a fresh --store"), "{error}");
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
    let error = Store::open(&legacy, &seed, Some(&Maker::Stub.identity()))
        .err()
        .unwrap();
    assert!(
        error.contains("files of no store of this version"),
        "{error}"
    );
    let fresh = dir.0.join("fresh");
    Store::open(&fresh, &seed, Some(&Maker::Stub.identity())).unwrap();
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
        Some(Maker::Model(openrouter(fake.clone()))),
        prefetch,
    )
    .unwrap();
    (pages, fake)
}

#[test]
fn search_styles_are_static_with_either_generator() {
    let dir = Dir::new("search-styles");
    let script = Arc::new(Script::default());
    let (model, fake) = model_world(&dir, &script, 0);
    lab(|cx| async move {
        for pages in [plain(), model] {
            for (host, path) in [
                ("www.google.com", "/search?q=python"),
                ("www.bing.com", "/search?q=python"),
                ("html.duckduckgo.com", "/html/?q=python"),
            ] {
                let response = pages.handle(&cx, "GET", host, path, None).await;
                assert_eq!(response.status, 200);
                let html = String::from_utf8(response.body).unwrap();
                assert!(html.contains(r#"rel="stylesheet" href="/search.css""#));
                assert!(!html.contains("<script"));
                assert!(!html.contains("<style"));
            }
            pages
                .apply(
                    &cx,
                    Command::SetGeneration {
                        generate: false,
                        expected_revision: 0,
                    },
                )
                .unwrap();
            let calls = fake.requests.lock().unwrap().len();
            let made = pages.store().made;
            for host in ["www.google.com", "www.bing.com", "html.duckduckgo.com"] {
                let css = pages
                    .handle(&cx, "GET", host, "/search.css?v=1", None)
                    .await;
                assert_eq!(css.status, 200);
                assert_eq!(css.content_type, "text/css; charset=utf-8");
                assert_eq!(css.body, fictionet_extras::search::CSS.as_bytes());
                assert_eq!(css.logged()["kind"], "asset");
                assert!(pages.store().page(host, "/search.css?v=1").is_none());
            }
            assert_eq!(pages.store().made, made);
            assert_eq!(fake.requests.lock().unwrap().len(), calls);
        }
        Ok(())
    });
}

#[test]
fn model_generation_switch_keeps_saved_pages_and_results() {
    let dir = Dir::new("model-switch");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    lab(|cx| async move {
        let search = google(&pages, &cx, "python flaw").await;
        assert_eq!(search.logged()["cache"], "generated");
        let url = &results(&search.body)[0].0;
        let page = get(&pages, &cx, url).await;
        assert_eq!(page.logged()["cache"], "generated");
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: 0,
                },
            )
            .unwrap();
        let calls = fake.requests.lock().unwrap().len();
        let cached = google(&pages, &cx, "python flaw").await;
        assert_eq!(cached.logged()["cache"], "cached");
        assert_eq!(cached.body, search.body);
        let cached = get(&pages, &cx, url).await;
        assert_eq!(cached.logged()["cache"], "cached");
        assert_eq!(cached.body, page.body);
        assert_eq!(
            google(&pages, &cx, "a new query").await.logged()["cache"],
            "missing"
        );
        assert_eq!(
            get(&pages, &cx, "https://new-site.com/missing")
                .await
                .status,
            404
        );
        assert_eq!(fake.requests.lock().unwrap().len(), calls);
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: true,
                    expected_revision: 1,
                },
            )
            .unwrap();
        assert_eq!(
            google(&pages, &cx, "a new query").await.logged()["cache"],
            "generated"
        );
        assert!(fake.requests.lock().unwrap().len() > calls);
        Ok(())
    });
}

#[test]
fn model_pages_keep_titles_count_cost_and_never_store_the_key() {
    let dir = Dir::new("model");
    let script = Arc::new(Script::default());
    let (pages, fake) = {
        let fake = fake_openrouter(script.clone());
        let pages = on_disk(
            &dir.0,
            Seed::builtin("corvane-acquisition").unwrap(),
            Some(Maker::Model(openrouter(fake.clone()))),
            2,
        )
        .unwrap();
        (pages, fake)
    };
    let world = pages.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "corvane acquisition").await;
        assert_eq!(
            (&search.logged()["cache"], &search.logged()["cost"]),
            (&json!("generated"), &json!(0.0021))
        );
        let (url, title) = results(&search.body)[0].clone();
        // The prefetched page is ready in the background.
        cx.sleep(ms(1000)).await?;
        let page = get(&world, &cx, &url).await;
        assert_eq!(page.logged()["cache"], "prefetched");
        assert_eq!(page.status, 200, "a page a result points at is never a 404");
        let html = String::from_utf8_lossy(&page.body);
        assert!(html.contains(&format!("<title>{title}</title>")));
        assert_eq!(page.logged()["unsupported_snippets"], json!([]));
        assert_eq!(get(&world, &cx, &url).await.logged()["cache"], "cached");
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
            "STATUS: 200\nCONTENT_TYPE: text/plain\nTITLE: Story\nSITE_CSS: body {{color: #234}}\nBODY:\n{}",
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
            assert_eq!(page.logged()["unsupported_snippets"], expected);
            assert_eq!(page.logged()["unchecked_snippets"], json!([]));
            // A stored page keeps the result of its check.
            let cached = get(&pages, &cx, "https://news.example-site.com/story").await;
            assert_eq!(cached.logged()["cache"], "cached");
            assert_eq!(cached.logged()["unsupported_snippets"], expected);
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
        let search = google(&world, &cx, "python").await;
        assert_eq!(search.logged()["results"], 10);
        assert_eq!(search.logged()["cost"], json!(0.0042));
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
        assert_eq!(page.logged()["kind"], "error");
        assert_eq!(page.logged()["cost"], json!(0.0042));
        assert!(page.logged()["error"].as_str().unwrap().contains("no BODY"));
        assert!(page.logged()["serve_ms"].is_u64());
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
            let search = google(&world, &cx, "python flaw").await;
            assert_eq!(search.status, 503);
            assert!(
                !search.logged()["error"]
                    .as_str()
                    .unwrap()
                    .contains(&KEY[..12])
            );
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
    let searches = Arc::new(crate::search::Searches::of(&pages));
    let state = searches.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(searches),
        |cx| async move {
            let search = google(&world, &cx, "python flaw").await;
            let (url, _) = results(&search.body)[0].clone();
            task.bad.store(2, Ordering::SeqCst);
            cx.sleep(ms(1000)).await?;
            assert!(state.snapshot().pages.is_empty());
            let page = get(&world, &cx, &url).await;
            assert_eq!(
                (page.status, &page.logged()["cache"]),
                (200, &json!("generated"))
            );
            Ok(())
        },
    ))
    .unwrap();
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
        push(&[&format!(
            "STATUS: 404\nTITLE: Missing\nSITE_CSS: body {{color: #234}}\nBODY:\n{body}"
        )]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing.json").await;
            assert_eq!((page.status, &page.logged()["cache"]), (404, &json!(cache)));
            assert_eq!(page.content_type, "application/json; charset=utf-8");
            assert_eq!(page.body, body.as_bytes());
        }
        // An unreferenced HTML 404 is the site's not-found page.
        push(&["STATUS: 404\nTITLE: Missing\nSITE_CSS: body {color: #234}\nBODY:\nPage not found"]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing").await;
            assert_eq!((page.status, &page.logged()["cache"]), (404, &json!(cache)));
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
        let search = google(&world, &cx, "python").await;
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
            let bad = format!(
                "STATUS: 404\nTITLE: Missing\nSITE_CSS: body {{color: #234}}\nBODY:\n{body}"
            );
            let good_body = if path.ends_with(".json") {
                "{\"message\": \"Details\"}"
            } else {
                "Details"
            };
            let good = format!(
                "STATUS: 200\nTITLE: Details\nSITE_CSS: body {{color: #234}}\nBODY:\n{good_body}"
            );
            task.pages
                .lock()
                .unwrap()
                .extend([bad.clone(), bad.clone()]);
            let refused = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(refused.status, 503);
            assert!(
                refused.logged()["error"]
                    .as_str()
                    .unwrap()
                    .contains("referenced")
            );
            assert!(world.store().page(&host, &path).is_none());
            task.pages.lock().unwrap().extend([bad, good]);
            let page = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (page.status, &page.logged()["cache"]),
                (200, &json!("generated"))
            );
            assert_eq!(page.logged()["cost"], json!(0.0042));
            assert!(String::from_utf8_lossy(&page.body).contains("Details"));
            let cached = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (cached.status, &cached.logged()["cache"], cached.body),
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
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let search = google(&pages, &cx, "stories").await;
        let ranks: Vec<_> = search.logged()["listed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["rank"].clone())
            .collect();
        assert_eq!(ranks, [json!(1), json!(2)]);
        let page = get(&pages, &cx, "https://second-site.com/story").await;
        assert_eq!(
            page.logged()["reason"],
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
        let page = "STATUS: 200\nTITLE: Story\nDESCRIPTION: The story.\nSITE_CSS: body {color: #234}\nBODY:\n<h1>Story</h1>";
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
        let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
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
            assert_eq!(direct.logged()["title"], title);
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
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
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
        assert_eq!(page.logged()["title"], "first");
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
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
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
    assert_eq!(page.logged()["gen_ms"], 1850);
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
    assert!(
        page.logged()["error"]
            .as_str()
            .unwrap()
            .contains("HTTP 529")
    );
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
    assert_eq!(page.logged()["gen_ms"], 5100);
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
    assert!(usage["cost"].is_null() && page.logged()["cost"].is_null());
    assert_eq!(page.logged()["gen_ms"], 5200);
}

#[test]
fn a_permanent_error_is_not_retried() {
    let dir = Dir::new("ledger-cast");
    let fake = Fake::script(vec![http_error(100, 401)]);
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
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

#[test]
fn captured_model_pages_use_the_container_without_a_stylesheet_call() {
    let fake = Fake::new(|_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        assert!(prompt.contains("div class=\"body\" role=\"main\""));
        assert!(!prompt.contains("SITE_CSS:"));
        completion(
            0,
            "STATUS: 200\nTITLE: Paths\nBODY:\n<h1>Paths</h1><p>Read directories with pathlib.</p>",
            Some(0.001),
        )
    });
    let pages = Arc::new(Pages::open(
        seed(),
        Store::memory(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    ));
    no_cast(&pages);
    lab(move |cx| async move {
        let response = get(
            &pages,
            &cx,
            "https://docs.python.org/3/library/pathlib.html",
        )
        .await;
        assert_eq!(response.status, 200);
        let html = std::str::from_utf8(&response.body).unwrap();
        assert!(html.contains("Read directories with pathlib."));
        let stylesheet = {
            let dom = kuchiki::traits::TendrilSink::one(kuchiki::parse_html(), html);
            dom.select_first("link[rel=stylesheet]")
                .unwrap()
                .attributes
                .borrow()
                .get("href")
                .unwrap()
                .to_owned()
        };
        for path in [
            stylesheet.as_str(),
            "/_assets/missing.css",
            "/_assets/../page.html",
        ] {
            let asset = pages
                .handle(&cx, "GET", "docs.python.org", path, None)
                .await;
            assert_eq!(asset.status, if path == stylesheet { 200 } else { 404 });
            assert!(matches!(asset.meta, Meta::Asset));
        }
        assert_eq!(fake.users().len(), 1);
        Ok(())
    });
}

#[test]
fn captured_stub_pages_and_assets_are_available_with_generation_off() {
    let pages = plain();
    lab(move |cx| async move {
        let response = get(&pages, &cx, "https://en.wikipedia.org/wiki/Directories").await;
        assert_eq!(response.status, 200);
        let html = std::str::from_utf8(&response.body).unwrap();
        assert!(html.contains("mw-body"));
        assert!(html.contains("/_assets/"));
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: pages.generation().revision,
                },
            )
            .unwrap();
        let stylesheet = {
            let dom = kuchiki::traits::TendrilSink::one(kuchiki::parse_html(), html);
            dom.select_first("link[rel=stylesheet]")
                .unwrap()
                .attributes
                .borrow()
                .get("href")
                .unwrap()
                .to_owned()
        };
        let asset = pages
            .handle(&cx, "GET", "en.wikipedia.org", &stylesheet, None)
            .await;
        assert_eq!(asset.status, 200);
        assert!(asset.content_type.starts_with("text/css"));
        let cached = get(&pages, &cx, "https://en.wikipedia.org/wiki/Directories").await;
        assert_eq!(cached.body, response.body);
        Ok(())
    });
}

// ---- canned pages, new pages and plants -----------------------------------

/// A store in `dir` made by the offline generator: one search and its pages.
#[test]
fn a_planted_correction_changes_every_later_answer() {
    lab(|cx| async move {
        let pages = plain();
        let advisory = "https://docs.python.org/security/advisories/HSA-2026-014";
        get(&pages, &cx, advisory).await;
        let (host, target) = text::target_of(advisory);
        let mut record = pages.store().page(&host, &target).unwrap().clone();
        record.body = b"<html><body><p>The fixed firmware is 7.2.4.</p></body></html>".to_vec();
        record.description = "The fixed firmware is 7.2.4.".into();
        record.claims = vec![record.description.clone()];
        pages.store().insert_page(record)?;
        let before = String::from_utf8(get(&pages, &cx, advisory).await.body).unwrap();
        assert!(before.contains("7.2.4"));
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python's fix for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let after = String::from_utf8(get(&pages, &cx, advisory).await.body).unwrap();
        assert!(after.contains("7.2.5") && !after.contains("7.2.4"));
        let search = google(&pages, &cx, "python fix version").await;
        let html = String::from_utf8(search.body).unwrap();
        assert!(html.contains("7.2.5") && !html.contains("7.2.4"), "{html}");
        // What was typed stays as typed.
        let typed = google(&pages, &cx, "python 7.2.4").await;
        assert!(
            String::from_utf8(typed.body)
                .unwrap()
                .contains("python 7.2.4")
        );
        // New pages carry the planted fact.
        let page = get(&pages, &cx, "https://news.example-wire.com/python-fix").await;
        assert!(String::from_utf8(page.body).unwrap().contains("7.2.5, not"));
        // A stale revision and words that give the web away are refused.
        let fact = |text: &str, revision| Command::PlantFact {
            text: text.into(),
            expected_revision: revision,
        };
        assert_eq!(
            pages.apply(&cx, fact("Another fact.", 0)),
            Err(Rejected::Stale { current: 1 })
        );
        assert!(matches!(
            pages.apply(&cx, fact("This is a simulated outage.", 1)),
            Err(Rejected::Invalid { .. })
        ));
        assert_eq!(
            replace_value("7.2.4 17.2.4 7.2.45 v7.2.4 (7.2.4).", "7.2.4", "7.2.5"),
            "7.2.5 17.2.4 7.2.45 v7.2.4 (7.2.5)."
        );
        assert_eq!(
            correction("The fixed release is 7.2.5 instead of 7.2.4"),
            Some(("7.2.4".into(), "7.2.5".into()))
        );
        assert_eq!(correction("Python is based in Leeds."), None);
        Ok(())
    });
}

#[test]
fn form_posts_get_the_page_a_site_shows_after_one() {
    lab(|cx| async move {
        let pages = plain();
        for (target, words) in [
            ("/login", "password you entered is incorrect"),
            ("/newsletter", "Thanks for subscribing"),
            ("/contact", "Thanks for getting in touch"),
        ] {
            let response = pages
                .handle(
                    &cx,
                    "POST",
                    "news.example-site.com",
                    target,
                    Some(b"email=a%40b.com"),
                )
                .await;
            assert_eq!(response.status, 200);
            assert!(
                String::from_utf8(response.body).unwrap().contains(words),
                "{target}"
            );
        }
        Ok(())
    });
}

#[test]
fn planted_text_preserves_response_syntax_and_resources() {
    lab(|cx| async move {
        use kuchiki::traits::TendrilSink;
        let pages = plain();
        let url = "https://www.reference.org/python.json";
        get(&pages, &cx, url).await;
        let original = pages
            .store()
            .page("www.reference.org", "/python.json")
            .unwrap()
            .clone();
        let replacement = r#""gateway\<label>""#;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: format!("The label is {replacement}, not Python."),
                    expected_revision: 0,
                },
            )
            .unwrap();
        for (target, mime, body) in [
            (
                "/python.json",
                "application/json",
                r#"{"title":"Python", "url":"https://docs.python.org/Python", "nested":["Python"], "Reference":"key", "description":"Python: https://docs.python.org/Python"}"#,
            ),
            (
                "/page",
                "text/html",
                r#"<!doctype html><html><head><style>.Python { color: red }</style><script>const Python = 1;</script></head><body><p>Python &amp; Python</p><a href="/Python">Python</a><img src="/Python.png"><!-- Python --></body></html>"#,
            ),
            (
                "/stylesheet",
                "text/css",
                ".Python { background: url('/Python.png') }",
            ),
        ] {
            let mut record = original.clone();
            record.target = target.into();
            record.url = format!("https://www.reference.org{target}");
            record.content_type = mime.into();
            record.body = body.as_bytes().to_vec();
            pages.store.lock().unwrap().insert_page(record).unwrap();
            let response = get(&pages, &cx, &format!("https://www.reference.org{target}")).await;
            let actual = String::from_utf8(response.body).unwrap();
            match mime {
                "application/json" => {
                    let value: Value = serde_json::from_str(&actual).unwrap();
                    assert_eq!(value["title"], replacement);
                    assert_eq!(value["nested"][0], replacement);
                    assert_eq!(value["url"], "https://docs.python.org/Python");
                    assert_eq!(value["Reference"], "key");
                    assert_eq!(
                        value["description"],
                        format!("{replacement}: https://docs.python.org/Python")
                    );
                }
                "text/html" => {
                    let dom = kuchiki::parse_html().one(actual);
                    assert_eq!(
                        dom.select_first("p").unwrap().text_contents(),
                        format!("{replacement} & {replacement}")
                    );
                    assert_eq!(
                        dom.select_first("a")
                            .unwrap()
                            .attributes
                            .borrow()
                            .get("href"),
                        Some("/Python")
                    );
                    assert_eq!(
                        dom.select_first("img")
                            .unwrap()
                            .attributes
                            .borrow()
                            .get("src"),
                        Some("/Python.png")
                    );
                    assert_eq!(
                        dom.select_first("style").unwrap().text_contents(),
                        ".Python { color: red }"
                    );
                    assert_eq!(
                        dom.select_first("script").unwrap().text_contents(),
                        "const Python = 1;"
                    );
                }
                _ => assert_eq!(actual, body),
            }
        }
        Ok(())
    });
}

#[test]
fn ads_come_from_relevant_stored_searches() {
    lab(|cx| async move {
        let pages = plain();
        google(&pages, &cx, "telescope spectrum").await;
        let mut list = pages.store().search("telescope spectrum").unwrap().clone();
        list.search.ads.push(search::Ad {
            url: "https://optics.example.com/telescope".into(),
            title: "Telescope optics".into(),
            text: "Read a telescope spectrum.".into(),
        });
        pages.store().insert_search(list)?;
        let html =
            String::from_utf8(google(&pages, &cx, "telescope spectrum guide").await.body).unwrap();
        assert!(html.contains("Telescope optics"));
        let html = String::from_utf8(google(&pages, &cx, "bread baking").await.body).unwrap();
        assert!(!html.contains("Telescope optics"));
        Ok(())
    });
}

#[test]
fn plants_keep_authored_pages_and_unrelated_version_claims() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://www.reference.org/security/release-update";
        pages
            .apply(
                &cx,
                Command::PlantPage {
                    url: url.into(),
                    text: "Firmware update\nFixed firmware is 7.2.5. It replaces 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let before = get(&pages, &cx, url).await.body;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python says the fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4."
                        .into(),
                    expected_revision: 1,
                },
            )
            .unwrap();
        let after = get(&pages, &cx, url).await.body;
        assert_eq!(before, after);
        let html = String::from_utf8(after).unwrap();
        assert!(!html.contains("<ul></ul>"));
        assert!(!html.contains("Pythonorg"));
        assert!(html.contains("Reference"));
        let mut record = pages.store().pages().next().cloned();
        if record.is_none() {
            get(&pages, &cx, "https://www.reference.org/releases/history").await;
            record = pages.store().pages().next().cloned();
        }
        let mut record = record.unwrap();
        record.target = "/releases/history".into();
        record.url = format!("https://www.reference.org{}", record.target);
        record.body = b"<html><body><p>The fixed firmware for CVE-2024-12345 is 7.2.4. It replaces 7.2.3.</p><p>Our office previously ran 7.2.4.</p></body></html>".to_vec();
        pages.store.lock().unwrap().insert_page(record).unwrap();
        let html = String::from_utf8(
            get(&pages, &cx, "https://www.reference.org/releases/history")
                .await
                .body,
        )
        .unwrap();
        assert!(html.contains("is 7.2.5"));
        assert!(html.contains("previously ran 7.2.4"));
        Ok(())
    });
}

#[test]
fn firmware_corrections_preserve_other_advisories_and_table_columns() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://docs.python.org/support/release-history";
        get(&pages, &cx, url).await;
        let mut record = pages
            .store()
            .page("docs.python.org", "/support/release-history")
            .unwrap()
            .clone();
        record.body = br#"<html><body><p>The fixed firmware for CVE-2024-12345 is <strong>7.2.4</strong>. It replaces 7.2.3.</p><p>The fixed firmware for CVE-2026-12345 is 7.2.4.</p><p>It replaces 7.2.4.</p><table><tr><th>Affected firmware</th><th>Fixed firmware</th></tr><tr><td>7.2.4</td><td>7.2.4</td></tr></table></body></html>"#.to_vec();
        pages.store.lock().unwrap().insert_page(record).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let html = String::from_utf8(get(&pages, &cx, url).await.body).unwrap();
        assert!(html.contains("<strong>7.2.5</strong>"), "{html}");
        assert!(html.contains("CVE-2026-12345 is 7.2.4"), "{html}");
        assert!(html.contains("It replaces 7.2.4"));
        assert!(html.contains("<td>7.2.4</td><td>7.2.5</td>"), "{html}");
        Ok(())
    });
}

#[test]
fn planted_articles_do_not_keep_empty_skin_panels() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://www.reddit.com/r/networking/comments/router-notes/";
        pages.apply(&cx, Command::PlantPage { url: url.into(), text: "Router notes\nKeep a copy of the configuration before changing the router settings.".into(), expected_revision: 0 }).unwrap();
        let response = get(&pages, &cx, url).await;
        assert_eq!(response.status, 200);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("Keep a copy of the configuration"));
        assert!(!html.contains("On this page"));
        Ok(())
    });
}

#[test]
fn finite_searches_do_not_advertise_or_repeat_more_pages() {
    lab(|cx| async move {
        use kuchiki::traits::TendrilSink;
        let pages = plain();
        let response = google(&pages, &cx, "best pizza in leeds").await;
        {
            let dom = kuchiki::parse_html().one(String::from_utf8(response.body).unwrap());
            assert!(
                dom.select("#botstuff table a, #foot table a, .b_pag a, .nav-link form")
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
        let next = get(
            &pages,
            &cx,
            "https://www.google.com/search?q=best+pizza+in+leeds&start=10",
        )
        .await;
        assert!(results(&next.body).is_empty());
        Ok(())
    });
}

#[test]
fn visited_indexes_stay_out_of_search_results() {
    lab(|cx| async move {
        let dir = Dir::new("navigation");
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stub), 0).unwrap();
        for target in ["/", "/latest", "/categories", "/search?q=firmware"] {
            get(&pages, &cx, &format!("https://discuss.python.org{target}")).await;
        }
        drop(pages);
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stub), 0).unwrap();
        let response = google(&pages, &cx, "latest discussions firmware").await;
        for (url, _) in results(&response.body) {
            let (_, target) = text::target_of(&url);
            assert!(!make::directory(&target), "{url}");
        }
        let known = pages.store().known(&seed());
        assert!(!known.iter().any(|r| r.title == "Latest discussions"
            || r.title == "Categories"
            || r.title.starts_with("Search results for")));
        Ok(())
    });
}

#[test]
fn served_pages_and_lists_report_the_facts_their_text_carries() {
    lab(|cx| async move {
        let mut scenario = fixed_seed();
        let mut fixed = scenario.fixed.remove(0);
        fixed.body =
            b"<html><body><p>The Python tutorial fixed release is 7.2.4.</p></body></html>"
                .to_vec();
        fixed.description = "The Python tutorial fixed release is 7.2.4.".into();
        let url = fixed.url.clone();
        let pages = Arc::new(Pages::new(scenario));
        let record = PageRecord {
            url: fixed.url,
            host: fixed.host,
            target: fixed.target,
            status: 200,
            content_type: fixed.content_type,
            body: fixed.body,
            headers: Vec::new(),
            title: fixed.title,
            description: fixed.description.clone(),
            date: String::new(),
            claims: vec![fixed.description.clone()],
            mentions: Vec::new(),
            tells: Vec::new(),
            unsupported_snippets: Vec::new(),
            unchecked_snippets: Vec::new(),
            prefetched: false,
            fixed: false,
            usage: None,
        };
        pages.store().insert_page(record).unwrap();
        let before = get(&pages, &cx, &url).await;
        assert_eq!(before.logged()["carries"], 0);
        assert!(String::from_utf8_lossy(&before.body).contains("7.2.4"));
        google(&pages, &cx, "python tutorial").await;
        let mut listing = pages.store().search("python tutorial").unwrap().clone();
        listing.search.results = vec![search::Result {
            url: url.clone(),
            title: "Python tutorial".into(),
            snippet: "The Python tutorial fixed release is 7.2.4.".into(),
            ..Default::default()
        }];
        pages.store().insert_search(listing)?;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The Python tutorial fixed release is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let after = get(&pages, &cx, &url).await;
        assert_eq!(after.logged()["carries"], 1);
        assert_eq!(after.logged()["cache"], "cached");
        let body = String::from_utf8_lossy(&after.body);
        assert!(body.contains("7.2.5") && !body.contains("7.2.4"));
        let answer = google(&pages, &cx, "python tutorial").await;
        assert_eq!(answer.logged()["carries"], 1);
        assert!(String::from_utf8_lossy(&answer.body).contains("7.2.5"));
        let untouched = get(&pages, &cx, "https://garden.example.com/roses").await;
        assert_eq!(untouched.logged()["carries"], 0);
        let pages = plain();
        let existing = "https://news.example-wire.com/python-background";
        get(&pages, &cx, existing).await;
        let mut old = pages
            .store()
            .page("news.example-wire.com", "/python-background")
            .unwrap()
            .clone();
        old.body = b"<html><body><p>Python is based in Leeds.</p></body></html>".to_vec();
        pages.store().insert_page(old).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python is based in Leeds.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        assert_eq!(get(&pages, &cx, existing).await.logged()["carries"], 0);
        let about = get(&pages, &cx, "https://news.example-wire.com/python-offices").await;
        assert_eq!(about.logged()["reason"], json!({"via":"direct"}));
        assert!(
            about
                .headers
                .iter()
                .all(|(name, _)| !["via", "making", "carries"].contains(&name.as_str()))
        );
        assert!(String::from_utf8_lossy(&about.body).contains("Python is based in Leeds."));
        assert_eq!(about.logged()["carries"], 1);
        assert_eq!(
            get(&pages, &cx, "https://news.example-wire.com/python-offices")
                .await
                .logged()["carries"],
            1
        );
        let other = get(&pages, &cx, "https://garden.example.com/roses").await;
        assert!(!String::from_utf8_lossy(&other.body).contains("Leeds"));
        assert_eq!(other.logged()["carries"], 0);
        Ok(())
    });
}

#[test]
fn git_transport_paths_return_plain_missing_responses_without_pages() {
    lab(|cx| async move {
        let pages = plain();
        for host in ["github.com", "gitlab.com", "code.example.org"] {
            for path in [
                "/owner/project.git/info/refs?service=git-upload-pack",
                "/owner/project/info/refs",
                "/owner/project/git-upload-pack",
                "/owner/project/git-receive-pack",
                "/owner/project.git",
                "/owner/project%2Egit/info/refs",
            ] {
                for method in ["GET", "HEAD", "POST"] {
                    let response = pages.handle(&cx, method, host, path, None).await;
                    assert_eq!(response.status, 404, "{method} {host}{path}");
                    assert!(response.content_type.starts_with("text/plain"));
                    assert_eq!(response.body, b"Not found");
                    assert!(pages.store().page(host, path).is_none());
                    assert!(pages.store().site(host).is_none());
                }
            }
        }
        Ok(())
    });
}

#[test]
fn prepared_questions_use_the_question_layout_without_losing_content() {
    use kuchiki::traits::TendrilSink;
    let html = "<main><h1>How do grouped iterators work?</h1><div class=\"post\"><p>My input has adjacent keys.</p><pre><code>groupby(values)</code></pre></div><div class=\"post\"><p>Each run starts a new group.</p></div></main>";
    let rendered = render::again(
        "stackoverflow.com",
        "/questions/groups",
        "How do grouped iterators work?",
        html,
        "2026-09-07",
        "2026-10-07",
    )
    .unwrap();
    let dom = kuchiki::parse_html().one(rendered);
    assert!(dom.select_first(".sidebar").is_err());
    assert_eq!(dom.select(".accepted-mark").unwrap().count(), 1);
    assert!(dom.select_first(".tags span").is_ok());
    assert_eq!(
        dom.select_first("code").unwrap().text_contents(),
        "groupby(values)"
    );
    assert!(dom.text_contents().contains("Each run starts a new group."));
}

#[test]
fn site_names_use_profiles() {
    let pages = plain();
    for (host, name) in [
        ("docs.python.org", "Python Documentation"),
        ("www.manualslib.com", "ManualsLib"),
        ("www.cvedetails.com", "CVE Details"),
        ("python-shipping.com", "Python Shipping"),
        ("www.wikipedia.org", "Wikipedia"),
        ("en.wikipedia.org", "Wikipedia"),
        ("discuss.python.org", "Python Discussions"),
        ("docs.python.org", "Python Documentation"),
    ] {
        assert_eq!(pages.site_name(host), name);
    }
}

#[test]
fn visible_dates_use_short_months_and_keep_code_attributes_and_urls() {
    use kuchiki::traits::TendrilSink;
    let html = "<article><p>Last Updated: 2026-09-23; next 2026-10-07.</p><a href='/2026-09-23' title='2026-09-23'>https://example.com/2026-09-23</a><time datetime='2026-09-23'>2026-09-23</time><pre>2026-09-23</pre><code>2026-09-23</code><script>const date='2026-09-23'</script><style>/* 2026-09-23 */</style></article>";
    let body =
        render::normalize_page(html, "https://example.com/dated", "Example", &[], None).unwrap();
    let dom = kuchiki::parse_html().one(body);
    assert_eq!(
        dom.select_first("p").unwrap().text_contents(),
        "Last Updated: 23 Sep 2026; next 7 Oct 2026."
    );
    for tag in ["code", "pre"] {
        assert_eq!(dom.select_first(tag).unwrap().text_contents(), "2026-09-23");
    }
    assert_eq!(
        dom.select_first("a").unwrap().text_contents(),
        "https://example.com/2026-09-23"
    );
    assert_eq!(
        dom.select_first("a")
            .unwrap()
            .attributes
            .borrow()
            .get("href"),
        Some("/2026-09-23")
    );
    assert_eq!(
        dom.select_first("a")
            .unwrap()
            .attributes
            .borrow()
            .get("title"),
        Some("2026-09-23")
    );
    assert_eq!(
        dom.select_first("time")
            .unwrap()
            .attributes
            .borrow()
            .get("datetime"),
        Some("2026-09-23")
    );
    assert_eq!(
        dom.select_first("time").unwrap().text_contents(),
        "23 Sep 2026"
    );
    assert!(
        dom.select_first("script")
            .unwrap()
            .text_contents()
            .contains("2026-09-23")
    );
    assert!(
        dom.select_first("style")
            .unwrap()
            .text_contents()
            .contains("2026-09-23")
    );
}

#[test]
fn short_attributions_after_sentence_ends_use_world_names() {
    use kuchiki::traits::TendrilSink;
    let url = "https://example.com/article";
    let author = make::AUTHORS[make::hash(&format!("{url}\nMarcus Thorne")) % make::AUTHORS.len()];
    for tag in [
        "p", "span", "div", "small", "address", "li", "h2", "h3", "h4", "h5", "h6", "a", "strong",
        "em",
    ] {
        for label in ["By", "Written by", "Posted by", "Author:", "Reviewed by"] {
            for before in ["", "Updated September 12, 2026. ", "Revised! ", "Revised? "] {
                let html = format!(
                    "<article><h1>News</h1><p>The article ends here.</p><{tag}>{before}{label} Marcus Thorne on 3 Oct.</{tag}></article>"
                );
                let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
                let dom = kuchiki::parse_html().one(body.clone());
                assert_eq!(
                    dom.select_first(&format!("article > {tag}:last-child"))
                        .unwrap()
                        .text_contents(),
                    format!("{before}{label} {author} on 3 Oct."),
                    "{html}"
                );
                assert_eq!(
                    render::normalize_page(&body, url, "Example", &[], None),
                    None
                );
            }
        }
    }
    let before = "The issue was fixed by Python. ";
    let html = format!("<p>{before}By Marcus Thorne.</p>");
    let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
    assert_eq!(
        kuchiki::parse_html()
            .one(body)
            .select_first("p")
            .unwrap()
            .text_contents(),
        format!("{before}By {author}.")
    );
    for words in [20, 21] {
        let html = format!(
            "<p>{}. By Marcus Thorne.</p>",
            vec!["Text"; words - 3].join(" ")
        );
        let result = render::normalize_page(&html, url, "Example", &[], None);
        if words == 20 {
            assert!(result.unwrap().contains(&format!("By {author}.")));
        } else {
            assert_eq!(result, None);
        }
    }
}

#[test]
fn prose_and_quoted_attributions_keep_their_names() {
    for text in [
        "The issue was fixed by Python.",
        "This is a post by the team.",
        "The issue was fixed by Marcus Thorne.",
        "This is a post by Marcus Thorne.",
        "Updated September 12, 2026, by Marcus Thorne.",
        "This long paragraph describes the patch that was fixed by Marcus Thorne and explains how the team checked each affected system before publishing their results.",
        "This long paragraph describes the patch and explains how the team checked each affected system before publishing their results. By Marcus Thorne.",
    ] {
        let html = format!("<p>{text}</p>");
        assert_eq!(
            render::normalize_page(&html, "https://example.com/article", "Example", &[], None),
            None,
            "{html}"
        );
    }
    for tag in ["blockquote", "q", "pre", "code"] {
        for label in ["By", "Written by", "Posted by", "Author:", "Reviewed by"] {
            for html in [
                format!(
                    "<{tag}><em>Updated September 12, 2026. {label} Marcus Thorne on 3 Oct.</em></{tag}>"
                ),
                format!(
                    "<div>Updated September 12, 2026. <{tag}><em>{label} Marcus Thorne on 3 Oct.</em></{tag}></div>"
                ),
            ] {
                assert_eq!(
                    render::normalize_page(
                        &html,
                        "https://example.com/article",
                        "Example",
                        &[],
                        None
                    ),
                    None,
                    "{html}"
                );
            }
        }
    }
}

#[test]
fn author_labels_in_headings_and_inline_elements_use_world_names() {
    use kuchiki::traits::TendrilSink;
    for tag in [
        "p", "span", "div", "small", "address", "li", "h2", "h3", "h4", "h5", "h6", "a", "strong",
        "em",
    ] {
        for (label, name) in [
            ("By", "Lawrence Abrams"),
            ("Posted by", "Lawrence Abrams (Editor)"),
            ("Written by", "Thomas Fox‑Brewster"),
            ("Author:", "A. Reporter"),
            ("Author:", "A. Writer"),
        ] {
            let html = format!(
                "<{tag}>{label} {name}</{tag}><blockquote><p>By Lawrence Abrams</p></blockquote>"
            );
            let url = "https://example.com/article";
            let person = name.split(" (").next().unwrap();
            let expected = if render::person_name(person, "Example") {
                let author =
                    make::AUTHORS[make::hash(&format!("{url}\n{person}")) % make::AUTHORS.len()];
                name.replacen(person, author, 1)
            } else {
                name.to_owned()
            };
            let body = render::normalize_page(&html, url, "Example", &[], None)
                .unwrap_or_else(|| html.clone());
            let dom = kuchiki::parse_html().one(body);
            assert_eq!(
                dom.select_first(tag).unwrap().text_contents(),
                format!("{label} {expected}"),
                "{html}"
            );
            assert_eq!(
                dom.select_first("blockquote").unwrap().text_contents(),
                "By Lawrence Abrams"
            );
        }
    }
}

#[test]
fn corrections_change_article_text_and_snippet_metadata_only() {
    use kuchiki::traits::TendrilSink;
    lab(|cx| async move {
        let pages = Arc::new(Pages::new(fixed_seed()));
        let url = pages.seed.fixed[0].url.clone();
        get(&pages, &cx, &url).await;
        let (host, target) = text::target_of(&url);
        let mut record = pages.store().page(&host, &target).unwrap().clone();
        record.body = br#"<html><head><title>Upgrade to 7.2.4</title><meta name="description" content="Upgrade to 7.2.4"><meta property="og:title" content="Upgrade to 7.2.4"><meta property="og:description" content="Upgrade to 7.2.4"><meta name="twitter:title" content="Upgrade to 7.2.4"><meta name="twitter:description" content="Upgrade to 7.2.4"><meta name="other" content="Upgrade to 7.2.4"></head><body><p title="Upgrade to 7.2.4" data-version="7.2.4">Upgrade to <strong>7.2.4</strong>.</p><a href="/firmware/7.2.4">https://example.com/firmware/7.2.4</a><code>Upgrade to 7.2.4</code><pre>Upgrade to 7.2.4</pre><script>const version='7.2.4'</script><style>.version-7.2.4 {}</style><version-7.2.4>Release</version-7.2.4></body></html>"#.to_vec();
        pages.store().insert_page(record).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let response = get(&pages, &cx, &url).await;
        assert_eq!(response.logged()["carries"], 1);
        let dom = kuchiki::parse_html().one(String::from_utf8(response.body).unwrap());
        assert_eq!(
            dom.select_first("title").unwrap().text_contents(),
            "Upgrade to 7.2.5"
        );
        assert_eq!(dom.select_first("strong").unwrap().text_contents(), "7.2.5");
        for meta in dom.select("meta").unwrap() {
            let attrs = meta.attributes.borrow();
            let expected = if attrs.get("name") == Some("other") {
                "Upgrade to 7.2.4"
            } else {
                "Upgrade to 7.2.5"
            };
            assert_eq!(attrs.get("content"), Some(expected));
        }
        let p = dom.select_first("p").unwrap();
        assert_eq!(p.attributes.borrow().get("title"), Some("Upgrade to 7.2.4"));
        assert_eq!(p.attributes.borrow().get("data-version"), Some("7.2.4"));
        for tag in ["code", "pre"] {
            assert_eq!(
                dom.select_first(tag).unwrap().text_contents(),
                "Upgrade to 7.2.4"
            );
        }
        for tag in ["script", "style"] {
            assert!(
                dom.select_first(tag)
                    .unwrap()
                    .text_contents()
                    .contains("7.2.4")
            );
        }
        assert_eq!(
            dom.select_first("a").unwrap().text_contents(),
            "https://example.com/firmware/7.2.4"
        );
        assert_eq!(
            dom.select_first("a")
                .unwrap()
                .attributes
                .borrow()
                .get("href"),
            Some("/firmware/7.2.4")
        );
        assert_eq!(
            dom.select_first("version-7\\.2\\.4")
                .unwrap()
                .text_contents(),
            "Release"
        );
        Ok(())
    });
}

#[test]
fn person_bylines_exclude_handles_organizations_and_site_names() {
    for name in [
        "Lawrence Abrams",
        "Thomas Fox-Brewster",
        "A. Writer",
        "Élodie O’Neill",
        "Jean-Pierre Morel",
        "Anna Maria Smith",
    ] {
        assert!(render::person_name(name, "Example Site"), "{name}");
    }
    for name in [
        "NetAdminJoe",
        "sysop42",
        "u/python_admin",
        "John Smith42",
        "John_Smith",
        "John / Smith",
        "john Smith",
        "John van Smith",
        "John Paul George Smith",
        "Example Site",
    ] {
        assert!(!render::person_name(name, "Example Site"), "{name}");
    }
    for word in "Team Staff Desk News Editors Editorial Systems Security Support PSIRT Research Labs Lab Inc Corp Agency Office Center Centre Community Admin Moderator Press Media Group Foundation Project Wire Reporter Reporters Contributor Contributors".split_whitespace() {
        for name in [format!("Example {word}"), format!("{word} Example"), format!("Example {word}."), format!("Example {word}-Writer"), format!("Example {word}’s"), format!("Example {}", word.to_uppercase())] {
            assert!(!render::person_name(&name, "Other Site"), "{name}");
        }
    }
}

#[test]
fn forum_people_get_distinct_repeatable_names_and_keep_inline_markup() {
    use kuchiki::traits::TendrilSink;
    let url = "https://example.com/thread";
    let names = ["Lawrence Abrams", "Thomas Fox-Brewster", "Michael Davis"];
    assert_eq!(
        make::hash(&format!("{url}\n{}", names[1])) % make::AUTHORS.len(),
        make::hash(&format!("{url}\n{}", names[2])) % make::AUTHORS.len()
    );
    let render = |order: &[usize]| {
        let html = order
            .iter()
            .map(|i| {
                format!(
                    "<p class='author'>Posted by <a href='/people/{i}'>{}</a> · today</p>",
                    names[*i]
                )
            })
            .collect::<String>();
        let html = format!(
            "{html}<meta name='author' content='Lawrence Abrams'><p class='author'>By Priya Raman</p>"
        );
        let body = render::normalize_page(&html, url, "Example", &[], None).unwrap();
        let dom = kuchiki::parse_html().one(body.clone());
        assert_eq!(
            render::normalize_page(&body, url, "Example", &[], None),
            None
        );
        let mut mapped = std::collections::BTreeMap::new();
        for node in dom.select("p.author a").unwrap() {
            let name = node.text_contents();
            assert!(make::AUTHORS.contains(&name.as_str()), "{name}");
            assert_ne!(name, "Priya Raman");
            let href = node.attributes.borrow().get("href").unwrap().to_owned();
            if let Some(previous) = mapped.insert(href, name.clone()) {
                assert_eq!(previous, name);
            }
        }
        assert_eq!(
            mapped
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            dom.select_first("meta")
                .unwrap()
                .attributes
                .borrow()
                .get("content"),
            Some(mapped["/people/0"].as_str())
        );
        mapped
    };
    assert_eq!(render(&[0, 1, 2, 0]), render(&[2, 0, 1, 0]));
}

#[test]
fn author_pairs_avoid_cast_names_and_reuse_only_after_exhaustion() {
    use kuchiki::traits::TendrilSink;
    let mut person = Person {
        name: "Original Author".into(),
        role: "reporter".into(),
        organization: "The Register".into(),
    };
    person.name = "Priya Wierzbicki".into();
    let cast = [person];
    let names: Vec<_> = ('A'..='Z')
        .flat_map(|first| ('A'..='Z').map(move |last| format!("Original Author{first}{last}")))
        .take(300)
        .collect();
    let url = "https://example.com/full-thread";
    let render = |names: &[String], url: &str| {
        let mut html = make::AUTHORS
            .iter()
            .map(|name| format!("<p class='byline'>By {name}</p>"))
            .collect::<String>();
        html.push_str("<p class='byline'>By Priya Wierzbicki</p>");
        for name in names {
            html.push_str(&format!(
                "<p class='byline' data-person='{name}'>By {name}</p>"
            ));
        }
        let body = render::normalize_page(&html, url, "Example", &cast, None).unwrap();
        assert_eq!(
            render::normalize_page(&body, url, "Example", &cast, None),
            None
        );
        let dom = kuchiki::parse_html().one(body);
        dom.select("[data-person]")
            .unwrap()
            .map(|node| {
                let original = node
                    .attributes
                    .borrow()
                    .get("data-person")
                    .unwrap()
                    .to_owned();
                let author = node.text_contents().strip_prefix("By ").unwrap().to_owned();
                (original, author)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let authors = render(&names, url);
    let pair_count = make::AUTHORS.len() * (make::AUTHORS.len() - 1) - 1;
    let mut unique = std::collections::BTreeSet::new();
    for (index, (original, author)) in authors.iter().enumerate() {
        assert_ne!(original, author);
        assert_ne!(author, &cast[0].name);
        assert!(render::invented_name(author, &cast), "{author}");
        if index < pair_count {
            assert!(!make::AUTHORS.contains(&author.as_str()));
            assert!(unique.insert(author));
        } else {
            assert_eq!(
                author,
                make::AUTHORS[make::hash(&format!("{url}\n{original}")) % make::AUTHORS.len()]
            );
        }
    }
    assert_eq!(unique.len(), pair_count);
    let reversed: Vec<_> = names.into_iter().rev().collect();
    assert_eq!(authors, render(&reversed, url));
    assert_ne!(
        authors,
        render(&reversed, "https://example.com/other-thread")
    );
}

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

