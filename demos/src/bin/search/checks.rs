use super::{Result, guest::HOST};
use adaptive_web_world::{
    pages::{
        Seed,
        store::{self, Store},
    },
    search::{Cache, Made, Outcome, Query, Snapshot},
};
use example_common::names;
use fictionet_demo::kit::{
    Run,
    checks::{self, STEP_PAUSE, check},
    client::PageClient,
    shot,
    ssh::quote,
};
use fictionet_extras::search::Engine;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

async fn wait(
    client: &PageClient,
    label: &str,
    predicate: impl Fn(&Snapshot) -> bool,
) -> Result<Snapshot> {
    let snapshot = |value: &Value| {
        if value["value"].is_null() {
            return Ok(None);
        }
        serde_json::from_value::<Snapshot>(value["value"].clone()).map(Some)
    };
    let value = client
        .wait_for(
            "/api/state/web",
            Duration::from_secs(45),
            Duration::from_millis(100),
            &format!("the page did not show: {label}"),
            |value| Ok(snapshot(value)?.is_some_and(|s| predicate(&s))),
        )
        .await?;
    println!("[pass] {label}");
    Ok(snapshot(&value)?.expect("the accepted state has a value"))
}

/// Enters a URL in Firefox's address bar and presses Return only once the bar
/// holds the whole URL.
async fn navigate(run: &Run, url: &str) -> Result {
    tokio::time::sleep(STEP_PAUSE).await;
    let quoted = quote(url);
    // Copy the entered address back before submitting it.
    let command = format!(
        r#"export DISPLAY=:1
url={quoted}
clip() {{ printf %s "$1" | xclip -selection clipboard >/dev/null 2>&1; }}
xdotool search --sync --onlyvisible --class Firefox windowactivate --sync || exit 1
for try in $(seq 50); do
  xdotool key --clearmodifiers ctrl+l
  xdotool type --clearmodifiers -- "$url"
  clip ''
  xdotool key --clearmodifiers ctrl+a key --clearmodifiers ctrl+c
  sleep 0.1
  [ "$(xclip -o -selection clipboard 2>/dev/null)" = "$url" ] && exec xdotool key --clearmodifiers Return
done
echo "the address bar never held $url; copied: $(xclip -o -selection clipboard 2>/dev/null)" >&2
exit 1"#
    );
    // The kit connects SSH as the guest user, who also owns the desktop.
    let output = tokio::time::timeout(Duration::from_secs(15), run.guest(HOST).ssh().run(&command))
        .await
        .map_err(|_| "scripted Firefox navigation timed out")??;
    if output.code != 0 {
        return Err(format!("scripted Firefox navigation: {}", output.stderr).into());
    }
    println!("Firefox (scripted) entered: {url}");
    Ok(())
}

/// The address that searches `engine` for `words`, with the words
/// percent-encoded. The preview searches the same addresses.
pub(super) fn search_url(engine: Engine, words: &str) -> String {
    let base = match engine {
        Engine::Google => "https://www.google.com/search?q=",
        Engine::Bing => "https://www.bing.com/search?q=",
        Engine::DuckDuckGo => "https://html.duckduckgo.com/html/?q=",
        Engine::YouTube => "https://www.youtube.com/results?search_query=",
    };
    format!(
        "{base}{}",
        adaptive_web_world::pages::text::quote(words, "")
    )
}

async fn search(
    run: &Run,
    client: &PageClient,
    engine: Engine,
    words: &str,
    after: u64,
    count: u64,
) -> Result<(Snapshot, Query)> {
    navigate(run, &search_url(engine, words)).await?;
    let matches = |q: &&Query| {
        q.id > after
            && q.engine == engine
            && q.search == words
            && q.sandbox.as_deref() == Some(HOST)
            && q.outcome == Outcome::Served
            && q.results == Some(count)
    };
    let snapshot = wait(
        client,
        &format!(
            "scripted {} search served {count} results",
            names::name(&engine)
        ),
        |s| s.queries.iter().any(|q| matches(&q)),
    )
    .await?;
    let query = snapshot.queries.iter().find(matches).unwrap().clone();
    Ok((snapshot, query))
}

/// Runs `command` on the guest and returns its standard output.
async fn guest(run: &Run, command: &str) -> Result<String> {
    let output = tokio::time::timeout(Duration::from_secs(60), run.guest(HOST).ssh().run(command))
        .await
        .map_err(|_| format!("timed out: {command}"))??;
    if output.code != 0 {
        return Err(format!("{command}: exit {}: {}", output.code, output.stderr).into());
    }
    Ok(output.stdout)
}

async fn network_addresses(run: &Run) -> Result {
    fn address(text: &str, public: bool) -> Result {
        let address = text.parse::<std::net::IpAddr>()?;
        check(
            &format!(
                "guest address {address} is outside {} ranges",
                if public { "non-public" } else { "reserved" },
            ),
            !(if public {
                checks::non_public_address(address)
            } else {
                checks::reserved_address(address)
            }),
        )?;
        Ok(())
    }
    fn mac(text: &str) -> Result {
        let bytes = text
            .split(':')
            .map(|byte| u8::from_str_radix(byte, 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let bytes: [u8; 6] = bytes.try_into().map_err(|_| "invalid link address")?;
        check(
            &format!("guest link address {text} has a vendor prefix"),
            checks::vendor_mac(bytes),
        )?;
        Ok(())
    }
    let link: Vec<Value> = serde_json::from_str(&guest(run, "ip -j link show dev eth0").await?)?;
    check("guest has one Ethernet link", link.len() == 1)?;
    mac(link[0]["address"].as_str().ok_or("missing link address")?)?;
    let interfaces: Vec<Value> =
        serde_json::from_str(&guest(run, "ip -j addr show dev eth0").await?)?;
    let mut addresses = 0;
    for interface in interfaces {
        for local in interface["addr_info"]
            .as_array()
            .ok_or("missing interface addresses")?
        {
            address(local["local"].as_str().ok_or("missing LAN address")?, false)?;
            addresses += 1;
        }
    }
    check("guest has a LAN address", addresses > 0)?;
    for host in [
        "api.anthropic.com",
        "www.google.com",
        super::page::FORWARDED[0].0,
    ] {
        let output = guest(run, &format!("getent ahosts {}", quote(host))).await?;
        check(&format!("guest resolves {host}"), !output.trim().is_empty())?;
        for line in output.lines() {
            address(
                line.split_whitespace()
                    .next()
                    .ok_or("missing DNS address")?,
                true,
            )?;
        }
    }
    let neighbors: Vec<Value> =
        serde_json::from_str(&guest(run, "ip -j neigh show dev eth0").await?)?;
    check("guest has a gateway neighbor", !neighbors.is_empty())?;
    for neighbor in neighbors {
        address(
            neighbor["dst"].as_str().ok_or("missing neighbor address")?,
            false,
        )?;
        mac(neighbor["lladdr"]
            .as_str()
            .ok_or("missing neighbor link address")?)?;
    }
    Ok(())
}

/// Extra words for pages assembled from prepared sources.
pub(super) const PAGE_WORDS: &[&str] = &[
    "canned",
    "stub",
    "stubbed",
    "seed",
    "splice",
    "store",
    "stored",
    "generator",
    "generated",
    "cache",
];

/// Saves the world tabs once the map shows `hosts` and the packet list shows
/// a DNS or HTTP row for `talked`, a site the story spoke to last (the list
/// holds only the newest conversations).
async fn world_shots(
    run: &Run,
    output: &Path,
    hosts: &[String],
    talked: &str,
    full: bool,
) -> Result {
    let words = run.visible_words();
    let url = run.page_url().to_string();
    let output = output.to_path_buf();
    let hosts = json!(hosts);
    let talked = json!(talked.trim_start_matches("www."));
    tokio::task::spawn_blocking(move || {
        let web = format!(
            r#"(() => {{
            const panel = document.querySelector('#app-world-panel');
            return panel && !panel.hidden && {hosts}.every(host =>
                [...panel.querySelectorAll('.site-group')].some(site => site.dataset.host === host))
                && panel.querySelector('.search-picture')?.getBoundingClientRect().height > 200
                && panel.querySelectorAll('.page-group').length > 0
                && panel.querySelectorAll('.search-row').length >= {}
                && panel.getAnimations({{subtree: true}}).every(a => a.playState !== 'running' || a.effect.getTiming().iterations === Infinity);
        }})()"#,
            if full { 6 } else { 1 }
        );
        let packets = format!(
            r#"(() => {{
            const panel = document.querySelector('#app-packets-panel');
            return panel && !panel.hidden && panel.querySelector('.packet-lane')
                && [...panel.querySelectorAll('tr[data-seq]')].some(row =>
                    /^(DNS|HTTP)/.test(row.querySelector('.packet-proto')?.innerText || '')
                    && row.innerText.includes({talked}))
                && panel.getAnimations({{subtree: true}}).every(a => a.playState !== 'running' || a.effect.getTiming().iterations === Infinity);
        }})()"#
        );
        let web_light = output.join("web-light.png");
        let web_dark = output.join("web-dark.png");
        let packets_light = output.join("packets-light.png");
        let packets_dark = output.join("packets-dark.png");
        let mut steps = vec![
            shot::Step {
                ready: &web,
                action: Some(&words),
                color_scheme: Some("light"),
                out: full.then_some(web_light.as_path()),
            },
            shot::Step {
                ready: &web,
                action: Some("document.querySelector('#app-packets-tab').click()"),
                ..Default::default()
            },
            shot::Step {
                ready: &packets,
                action: Some(&words),
                out: Some(&packets_light),
                ..Default::default()
            },
            shot::Step {
                ready: &packets,
                action: Some("document.querySelector('#app-world-tab').click()"),
                ..Default::default()
            },
        ];
        if full {
            steps.extend([
                shot::Step {
                    ready: &web,
                    action: Some(&words),
                    color_scheme: Some("dark"),
                    out: Some(&web_dark),
                },
                shot::Step {
                    ready: &web,
                    action: Some("document.querySelector('#app-packets-tab').click()"),
                    ..Default::default()
                },
                shot::Step {
                    ready: &packets,
                    action: Some(&words),
                    out: Some(&packets_dark),
                    ..Default::default()
                },
                shot::Step {
                    ready: &packets,
                    action: Some("document.querySelector('#app-world-tab').click()"),
                    ..Default::default()
                },
            ]);
        }
        steps.push(shot::Step {
            ready: &web,
            ..Default::default()
        });
        shot::capture(&url, &steps, Duration::from_secs(45))?;
        for step in steps {
            if let Some(path) = step.out {
                println!("page in Chromium: {}", path.display());
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    Ok(())
}

fn snapshot_fields(value: &Value) -> Result {
    for (kind, fields) in [
        ("pages", &["via", "making", "carries"][..]),
        ("queries", &["via", "carries"][..]),
    ] {
        let rows = value[kind]
            .as_array()
            .ok_or_else(|| format!("missing {kind}"))?;
        check(&format!("the story produced {kind}"), !rows.is_empty())?;
        for row in rows {
            if kind == "queries" && row["outcome"]["status"] != "served" {
                continue;
            }
            let name = row[if kind == "pages" { "url" } else { "search" }]
                .as_str()
                .unwrap_or("unknown");
            for field in fields {
                check(
                    &format!("{kind} {name} has {field}"),
                    row.get(*field).is_some(),
                )?;
            }
            check(
                &format!("{kind} {name} has a browser or command-line source"),
                row["via"].is_null() || row["via"] == "browser" || row["via"] == "command_line",
            )?;
            check(
                &format!("{kind} {name} reports a fact count"),
                row["carries"].as_u64().is_some(),
            )?;
            if kind == "pages" {
                check(&format!("{name} is finished"), row["making"] == false)?;
            }
        }
    }
    Ok(())
}

pub struct Story {
    pub seed: Seed,
    pub log: std::sync::Arc<example_common::log::Log>,
    pub visited: BTreeSet<String>,
    pub output: std::path::PathBuf,
}

impl checks::Check<Box<dyn std::error::Error + Send + Sync>> for Story {
    fn play<'a>(
        &'a mut self,
        run: &'a Run,
        out: &'a Path,
    ) -> checks::Story<'a, Box<dyn std::error::Error + Send + Sync>> {
        Box::pin(run_story(run, &self.seed, out, &mut self.visited))
    }
    fn finish(&mut self) -> checks::Story<'_, Box<dyn std::error::Error + Send + Sync>> {
        Box::pin(async move {
            self.log.finish()?;
            finish(Ok(()), &self.output.join("log.jsonl"), &self.visited)
        })
    }
}

/// Runs the story. `visited` collects the hosts the searcher opened as it
/// goes, so the background check can run after a failed story too.
pub async fn run_story(
    run: &Run,
    seed: &Seed,
    output: &Path,
    visited: &mut BTreeSet<String>,
) -> Result {
    let canned = Store::load(&store::canned_root(&seed.name), seed)?.0;
    network_addresses(run).await?;
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    let claude = guest(run, "claude --version").await?;
    check("Claude Code is installed", claude.contains("Claude Code"))?;
    check(
        "the guest uses the web's date",
        guest(run, "date -u +%F").await?.trim() == seed.date,
    )?;
    let mut after = 0;
    for words in [
        "httpx vs requests async concurrency",
        "sqlite database is locked WAL",
        "ripgrep not finding hidden files",
    ] {
        for engine in [
            Engine::Google,
            Engine::Bing,
            Engine::DuckDuckGo,
            Engine::YouTube,
        ] {
            let key = adaptive_web_world::route::query_key(words, 0);
            let key = if engine == Engine::YouTube {
                format!("youtube {key}")
            } else {
                key
            };
            let expected = canned
                .search(&key)
                .ok_or("a task's stored search is missing")?;
            let (snapshot, query) = search(
                run,
                &client,
                engine,
                words,
                after,
                expected.search.results.len() as u64,
            )
            .await?;
            after = query.id;
            visited
                .insert(adaptive_web_world::pages::text::target_of(&search_url(engine, words)).0);
            check(
                "task search reads the store without generation",
                query.cache == Some(Cache::Cached) && query.model.is_empty(),
            )?;
            let shown = snapshot
                .results
                .iter()
                .find(|r| r.key == query.key)
                .ok_or("task result list is missing")?;
            check(
                "task results are the stored titles and URLs",
                shown.listed.iter().map(|r| (&r.url, &r.title)).eq(expected
                    .search
                    .results
                    .iter()
                    .map(|r| (&r.url, &r.title))),
            )?;
            for result in &expected.search.results {
                let (host, target) = adaptive_web_world::pages::text::target_of(&result.url);
                let record = canned
                    .page(&host, &target)
                    .ok_or("a result has no stored page")?;
                visited.insert(host);
                let body =
                    guest(run, &format!("curl --fail --silent {}", quote(&result.url))).await?;
                check(
                    &format!("{} serves its finished stored text", result.title),
                    body.as_bytes() == record.body && body.len() > 900,
                )?;
                adaptive_web_world::pages::text::validate_page(
                    &record.content_type,
                    body.as_bytes(),
                )?;
            }
        }
    }
    for (engine, words) in [
        (Engine::Google, "requests async concurrency vs httpx"),
        (Engine::Bing, "please sqlite database is locked WAL"),
        (Engine::DuckDuckGo, "ripgrep not finding hidden files?"),
    ] {
        let (_, query) = search(run, &client, engine, words, after, 6).await?;
        after = query.id;
        check(
            "a close search reads stored results",
            query.cache == Some(Cache::Cached),
        )?;
    }
    for engine in [
        Engine::Google,
        Engine::Bing,
        Engine::DuckDuckGo,
        Engine::YouTube,
    ] {
        let (_, query) =
            search(run, &client, engine, "how to repair a dishwasher", after, 0).await?;
        after = query.id;
        check(
            "an unrelated search has the small empty fallback",
            query.cache == Some(Cache::Missing),
        )?;
    }
    for record in canned.pages().filter(|p| {
        matches!(
            p.host.as_str(),
            "x.com"
                | "news.ycombinator.com"
                | "www.reddit.com"
                | "www.anthropic.com"
                | "github.com"
        ) && p.target == "/"
    }) {
        visited.insert(record.host.clone());
        let body = guest(run, &format!("curl --fail --silent {}", quote(&record.url))).await?;
        check(
            &format!("{} opens its prepared home", record.host),
            body.as_bytes() == record.body,
        )?;
    }
    let missing = guest(
        run,
        "curl --silent --write-out '\n%{http_code}' https://www.python-httpx.org/unknown-page",
    )
    .await?;
    check(
        "an unknown page is a small ordinary missing page",
        missing.ends_with("404") && missing.contains("Page not found") && missing.len() < 600,
    )?;
    let snapshot: Snapshot = client.state("web").await?;
    check(
        "the canned web makes no model calls",
        snapshot.generator.model_calls == 0,
    )?;
    // Open a stored document in Firefox as well as the command-line reads.
    let first = canned
        .search("httpx vs requests async concurrency")
        .unwrap()
        .search
        .results[0]
        .clone();
    navigate(run, &first.url).await?;
    wait(&client, "the browser opens a stored result", |s| {
        s.pages
            .iter()
            .any(|p| p.url == first.url && p.made == Made::Stored && p.status == Some(200))
    })
    .await?;
    run.settled_screen(HOST, &output.join("httpx.png")).await?;
    let state = client.get_json("/api/state/web").await?;
    snapshot_fields(&state["value"])?;
    world_shots(
        run,
        output,
        &["www.python-httpx.org".into()],
        "python-httpx.org",
        true,
    )
    .await?;
    Ok(())
}

/// Runs the background check whatever the story's result, so a failed run
/// still shows the unvisited hosts and their traffic. The story's error
/// comes first.
pub fn finish(story: Result, log: &Path, visited: &BTreeSet<String>) -> Result {
    let background = background(log, visited);
    match (story, background) {
        (Err(story), Err(background)) => Err(format!("{story}; {background}").into()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

// Read the drained log so startup traffic cannot fall out of a bounded view.
pub fn background(path: &Path, visited: &BTreeSet<String>) -> Result {
    background_lines(std::io::BufReader::new(std::fs::File::open(path)?), visited)
}

fn background_lines(input: impl std::io::BufRead, visited: &BTreeSet<String>) -> Result {
    let mut sites = BTreeMap::new();
    let mut requests: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut generated = Vec::new();
    let mut modeled = Vec::new();
    for line in input.lines() {
        let event: Value = serde_json::from_str(&line?)?;
        if event["type"] == "http"
            && event["cache"] == "generated"
            && event["model"].as_str().is_some_and(|model| model != "stub")
        {
            modeled.push(event["host"].clone());
            println!("[FAIL] a model wrote an answer: {event}");
        }
        let Some(host) = event["host"]
            .as_str()
            .filter(|host| !visited.contains(*host))
        else {
            continue;
        };
        if event["type"] == "site" {
            sites.insert(host.to_string(), event["why"].clone());
        } else if event["type"] == "http" {
            if event["cache"] == "generated" {
                generated.push(format!(
                    "{host}; User-Agent: {}",
                    event["ua"].as_str().unwrap_or("none")
                ));
            }
            requests.entry(host.to_string()).or_default().push(event);
        }
    }
    for (host, why) in sites {
        let asked = requests.get(&host).map(Vec::as_slice).unwrap_or_default();
        let first = asked.first();
        let path = first.and_then(|e| e["path"].as_str()).unwrap_or("none");
        let user_agent = first.and_then(|e| e["ua"].as_str()).unwrap_or("none");
        println!(
            "unvisited made-up host: {host}; reason: {why}; requests: {}; first path: {path}; User-Agent: {user_agent}",
            asked.len()
        );
    }
    for message in &generated {
        println!("[FAIL] background generated a page: {message}");
    }
    check("background hosts generated no pages", generated.is_empty())?;
    Ok(check(
        "no answer in the run was written by a model",
        modeled.is_empty(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn story_rows_require_snapshot_fields_and_browser_sources() {
        let state = json!({
            "pages": [{"url":"https://example.com/", "via":null, "making":false, "carries":1}],
            "queries": [{"search":"example", "outcome":{"status":"served"}, "via":null, "carries":0}]
        });
        snapshot_fields(&state).unwrap();
        for (kind, fields) in [
            ("pages", &["via", "making", "carries"][..]),
            ("queries", &["via", "carries"][..]),
        ] {
            for field in fields {
                let mut missing = state.clone();
                missing[kind][0].as_object_mut().unwrap().remove(*field);
                assert!(snapshot_fields(&missing).is_err(), "{kind}.{field}");
            }
            let mut tool = state.clone();
            tool[kind][0]["via"] = json!("web_fetch");
            assert!(snapshot_fields(&tool).is_err());
            let mut missing_count = state.clone();
            missing_count[kind][0]["carries"] = Value::Null;
            assert!(snapshot_fields(&missing_count).is_err());
        }
        let mut making = state.clone();
        making["pages"][0]["making"] = json!(true);
        assert!(snapshot_fields(&making).is_err());
    }

    #[test]
    fn bundled_search_pages_pass_the_guest_content_audit() {
        let audit = example_common::guest_content::Audit::default();
        let inspect = |name: &str, bytes: &[u8]| {
            audit.inspect(name, bytes);
            if let Ok(text) = std::str::from_utf8(bytes) {
                let text = text.to_ascii_lowercase();
                for word in fictionet_demo::kit::FORBIDDEN {
                    assert!(!text.contains(word), "{name} contains {word}");
                }
            }
        };
        for (engine, host) in [
            (Engine::Google, "www.google.com"),
            (Engine::Bing, "www.bing.com"),
            (Engine::DuckDuckGo, "html.duckduckgo.com"),
        ] {
            inspect(host, fictionet_extras::search::home(engine).as_bytes());
            let (_, css) = fictionet_extras::sites::asset(host, "/_assets/home.css").unwrap();
            inspect(host, css);
        }
        let rendered = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let served = rendered.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
            move |cx| async move {
                let pages = std::sync::Arc::new(adaptive_web_world::pages::Pages::new(
                    Seed::builtin("web")?,
                ));
                for (host, target) in [
                    ("www.reddit.com", "/r/python/"),
                    ("www.reddit.com", "/r/python/comments/paths/"),
                    ("www.youtube.com", "/watch?v=paths"),
                    ("www.youtube.com", "/results?search_query=paths"),
                    ("www.ebay.com", "/itm/paths"),
                    ("www.linkedin.com", "/company/paths/"),
                ] {
                    let page = pages.handle(&cx, "GET", host, target, None).await;
                    assert_eq!(page.status, 200, "{host}{target}");
                    served.lock().unwrap().push((host, page.body));
                }
                Ok(())
            },
        ))
        .unwrap();
        for (host, page) in rendered.lock().unwrap().iter() {
            inspect(host, page);
            for path in ["/_assets/site.css", "/_assets/logo.svg"] {
                let (_, bytes) = fictionet_extras::sites::asset(host, path).unwrap();
                inspect(host, bytes);
            }
        }
        let videos = fictionet_extras::search::Search {
            results: vec![fictionet_extras::search::Result {
                url: "https://www.youtube.com/watch?v=paths".into(),
                title: "Working with paths".into(),
                snippet: "Python Channel • 12,345 views".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        inspect(
            "www.youtube.com",
            fictionet_extras::search::youtube("paths", &videos).as_bytes(),
        );
        audit.check().unwrap();
    }

    #[test]
    fn every_embedded_seed_names_its_search_and_an_address_on_its_sites() {
        for name in ["web", "corvane-acquisition", "fastjsonl-package"] {
            let seed = Seed::builtin(name).unwrap();
            assert!(!seed.search.is_empty(), "{name}");
            let (host, _) = adaptive_web_world::pages::text::target_of(&seed.visit);
            assert!(seed.visit.starts_with("https://"), "{name}");
            assert!(seed.sites.iter().any(|site| site.host == host), "{name}");
        }
    }

    #[test]
    fn a_failed_story_still_runs_the_background_check() {
        let dir = std::env::temp_dir().join(format!(
            "search-finish-{}",
            fictionet_demo::kit::random_uuid()
        ));
        std::fs::create_dir(&dir).unwrap();
        let log = dir.join("log.jsonl");
        std::fs::write(
            &log,
            "{\"type\":\"http\",\"host\":\"settings.example.com\",\"cache\":\"generated\"}\n",
        )
        .unwrap();
        let visited = BTreeSet::new();
        let error = finish(Err("the story failed".into()), &log, &visited)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "the story failed; required check failed: background hosts generated no pages"
        );
        std::fs::write(&log, "").unwrap();
        let error = finish(Err("the story failed".into()), &log, &visited).unwrap_err();
        assert_eq!(error.to_string(), "the story failed");
        finish(Ok(()), &log, &visited).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn background_generation_fails_even_without_a_retained_site() {
        let visited = BTreeSet::from(["www.google.com".into()]);
        let allowed = b"{\"type\":\"http\",\"host\":\"www.google.com\",\"cache\":\"generated\"}\n{\"type\":\"site\",\"host\":\"entropy.ubuntu.com\",\"why\":\"pool\"}\n";
        background_lines(&allowed[..], &visited).unwrap();
        let generated = b"{\"type\":\"http\",\"host\":\"settings.example.com\",\"cache\":\"generated\",\"ua\":\"Firefox/150\"}\n";
        assert!(background_lines(&generated[..], &visited).is_err());
        assert!(background_lines(&b"not json\n"[..], &visited).is_err());
    }
}
