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
        fictionet_extras::events::js(Some(&self.fields().to_json()))
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
            "web-{name}-{}-{}",
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
        usage: Usage::stored(0),
    };
    pages.store().set_cast(cast).unwrap();
}

// ---- the offline world ---------------------------------------------------

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

// ---- canned pages, new pages and plants -----------------------------------

mod answers;
mod bylines;
mod corrections;
mod generation;
mod pages;
mod routes;
mod store;
