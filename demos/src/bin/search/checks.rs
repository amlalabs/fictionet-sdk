use super::{Result, guest::HOST};
use adaptive_web_world::{
    pages::{
        Seed,
        store::{self, Store},
    },
    search::{Cache, Listed, Made, Outcome, Query, Reason, Results, Snapshot},
};
use example_common::names;
use fictionet_demo::kit::{
    Run,
    checks::{self, STEP_PAUSE, check},
    client::{Capability, PageClient},
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
            "/api/state/search",
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

/// Sends a world command through the page at the topic's current revision
/// and returns the page's reply.
pub async fn command(client: &PageClient, id: &str, mut command: Value) -> Result<Value> {
    tokio::time::sleep(STEP_PAUSE).await;
    let state: Snapshot = client.state("search").await?;
    command["expected_revision"] = json!(state.generator.generation_revision);
    let reply = client.command("generation", id, command).await;
    if let Err(error) = &reply {
        println!("{error}");
    }
    check("world command HTTP status matches its reply", reply.is_ok())?;
    Ok(reply?)
}

pub fn first_generated<'a>(seed: &Seed, list: &'a Results) -> Result<&'a Listed> {
    for result in &list.listed {
        let (host, target) = adaptive_web_world::pages::text::target_of(&result.url);
        if seed.fixed_for(&host, &target).is_none() {
            println!("opening result rank {}: {}", result.rank, result.url);
            return Ok(result);
        }
        println!(
            "skipping result rank {}: seed fixed page ({})",
            result.rank, result.url
        );
    }
    Err("search has no non-fixed result to open".into())
}

/// Why the canned store says it made the page at `url`: the first mention
/// it was made from, as the page's event reports it.
fn canned_reason(canned: &Store, url: &str) -> Result<Reason> {
    let (host, target) = adaptive_web_world::pages::text::target_of(url);
    let record = canned
        .page(&host, &target)
        .ok_or_else(|| format!("the canned store has no page {url}"))?;
    Ok(match record.mentions.first() {
        _ if record.fixed => Reason::Fixed,
        Some(mention) => serde_json::from_value(mention.clone()).unwrap_or_default(),
        None => Reason::Direct,
    })
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

/// Runs the story. `visited` collects the hosts the searcher opened as it
/// goes, so the background check can run after a failed story too.
pub async fn run(run: &Run, seed: &Seed, output: &Path, visited: &mut BTreeSet<String>) -> Result {
    let canned = Store::load(&store::canned_root(&seed.name), seed)?.0;
    run.guest(HOST)
        .wait_desktop(Duration::from_secs(300))
        .await?;
    run.guest(HOST)
        .wait_cloud_init(Duration::from_secs(300))
        .await?;
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    // Home requests are HTTP facts; the search projection only retains content pages.
    client
        .wait_for_event(
            0,
            Duration::from_secs(45),
            Duration::from_millis(100),
            "Firefox did not load the Google home page",
            |e| {
                Ok(e["source"] == "http"
                    && e["kind"] == "request"
                    && e["fields"]["host"] == "www.google.com"
                    && e["fields"]["path"] == "/"
                    && e["fields"]["status"] == 200
                    && e["fields"]["complete"] == true
                    && e["fields"]["headers"].to_string().contains("Firefox/"))
            },
        )
        .await?;
    println!(
        "boot to desktop with Google loaded: {} ms",
        run.boot_started().elapsed().as_millis()
    );
    let timing = run
        .guest(HOST)
        .ssh()
        .run(
            "sudo cloud-init analyze show; sudo cat /var/log/apt/history.log; \
             sudo journalctl -b -o short-monotonic --no-pager -u cloud-final -u vnc",
        )
        .await?;
    println!("guest setup timing:\n{}", timing.stdout);
    checks::bearer_required(&client).await?;
    checks::single_use_ticket(&client, HOST, Capability::Screen).await?;
    checks::terminal_runs_on(&client, HOST).await?;
    let today = guest(run, "date -u +%F").await?;
    check(
        &format!("the guest's clock is on the web's day, {}", seed.date),
        today.trim() == seed.date,
    )?;
    let claude = guest(run, "claude --version").await?;
    check(
        &format!(
            "Claude Code {} is installed",
            fictionet_demo::kit::desktop::CLAUDE_VERSION
        ),
        claude.contains(&format!(
            "{} (Claude Code)",
            fictionet_demo::kit::desktop::CLAUDE_VERSION
        )),
    )?;

    if seed.search.is_empty() || seed.visit.is_empty() {
        return Err(format!(
            "seed {} names no search words or address to visit",
            seed.name
        )
        .into());
    }
    let words = seed.search.as_str();
    let canned_count = |words: &str| {
        canned
            .search(&adaptive_web_world::route::query_key(words, 0))
            .map(|record| record.search.results.len() as u64)
    };
    let held = canned_count(words).ok_or("the canned store has no list for the seed's search")?;
    visited.extend(["www.google.com", "www.bing.com", "html.duckduckgo.com"].map(String::from));
    let (snapshot, google) = search(run, &client, Engine::Google, words, 0, held).await?;
    run.settled_screen(HOST, &output.join("google.png")).await?;
    check(
        "the seed's search is answered from the canned pages",
        google.cache == Some(Cache::Cached),
    )?;
    let list = snapshot
        .results
        .iter()
        .find(|r| r.key == google.key)
        .ok_or("Google result list missing")?;
    let first = first_generated(seed, list)?.clone();
    visited.insert(first.host.clone());
    let reason = canned_reason(&canned, &first.url)?;
    navigate(run, &first.url).await?;
    wait(
        &client,
        "opened result is the canned page, with the reason it was made",
        |s| {
            s.pages
                .iter()
                .any(|p| p.url == first.url && p.reason == reason && p.made == Made::Stored)
        },
    )
    .await?;
    let (snapshot, bing) = search(run, &client, Engine::Bing, words, google.id, held).await?;
    run.settled_screen(HOST, &output.join("bing.png")).await?;
    check(
        "Bing shares Google's result list",
        bing.key == google.key
            && snapshot
                .results
                .iter()
                .any(|r| r.key == bing.key && r.query_id == google.id && r.listed == list.listed),
    )?;
    let different = format!("{words} details");
    let held = canned_count(&different).ok_or("the canned store has no list for the details")?;
    let (snapshot, duck) =
        search(run, &client, Engine::DuckDuckGo, &different, bing.id, held).await?;
    run.settled_screen(HOST, &output.join("duckduckgo.png"))
        .await?;
    check(
        "DuckDuckGo has its own canned result list",
        duck.key != google.key
            && duck.cache == Some(Cache::Cached)
            && snapshot
                .results
                .iter()
                .any(|r| r.key == duck.key && r.query_id == duck.id),
    )?;
    let direct = seed.visit.clone();
    visited.insert(adaptive_web_world::pages::text::target_of(&direct).0);
    let reason = canned_reason(&canned, &direct)?;
    navigate(run, &direct).await?;
    wait(&client, "typed seed address is the canned page", |s| {
        s.pages.iter().any(|p| {
            p.url == direct && p.status == 200 && p.reason == reason && p.made == Made::Stored
        })
    })
    .await?;
    for (host, url, name) in [
        (
            "docs.python.org",
            "https://docs.python.org/3/library/itertools.html",
            "python.png",
        ),
        (
            "en.wikipedia.org",
            "https://en.wikipedia.org/wiki/Virtual_private_network",
            "wikipedia.png",
        ),
    ] {
        visited.insert(host.into());
        navigate(run, url).await?;
        wait(&client, "opened a canned page on a bundled host", |s| {
            s.pages
                .iter()
                .any(|p| p.url == url && p.status == 200 && p.made == Made::Stored)
        })
        .await?;
        run.settled_screen(HOST, &output.join(name)).await?;
    }
    // A search the canned pages do not hold lists the canned pages that share
    // its words first, then made-up ones.
    let outside = format!("{words} hg-400 owners");
    let (snapshot, fresh) = search(run, &client, Engine::Google, &outside, duck.id, 10).await?;
    let fresh_list = snapshot
        .results
        .iter()
        .find(|r| r.key == fresh.key)
        .ok_or("the new search's list is missing")?;
    check(
        "a search outside the canned set lists canned pages first",
        fresh.cache == Some(Cache::Generated)
            && fresh_list.listed.first().is_some_and(|r| {
                let (host, target) = adaptive_web_world::pages::text::target_of(&r.url);
                canned.page(&host, &target).is_some()
            }),
    )?;
    navigate(run, "http://wiki.corp/").await?;
    wait(&client, "reserved name is refused", |s| {
        s.refused
            .iter()
            .any(|r| r.name == "wiki.corp" && r.reason == "reserved or private top-level domain")
    })
    .await?;
    // Plant a correction and a page, then read what the guest gets.
    let fact = "Halvard's fix for CVE-2026-41877 is 7.2.5, not 7.2.4.";
    let reply = command(
        &client,
        "fact",
        json!({"command": "plant_fact", "text": fact}),
    )
    .await?;
    check("the fact is planted", reply["status"] == "applied")?;
    let reply = command(
        &client,
        "simulated",
        json!({"command": "plant_fact", "text": "This page is simulated."}),
    )
    .await?;
    check(
        "a fact that would give the web away is refused",
        reply["status"] == "rejected" && reply["rejection"]["reason"] == "invalid",
    )?;
    let planted = "https://www.securityweek-wire.com/halvard-hg-400-new-fix";
    let reply = command(
        &client,
        "page",
        json!({"command": "plant_page", "url": planted,
            "text": "Halvard ships a second HG-400 fix\nHalvard released firmware 7.2.5 for the HG-400 on Monday."}),
    )
    .await?;
    check("the page is planted", reply["status"] == "applied")?;
    let advisory = guest(
        run,
        "curl -s https://www.halvardsystems.com/security/advisories/HSA-2026-014",
    )
    .await?;
    check(
        "the canned advisory now says 7.2.5",
        advisory.contains("7.2.5") && !advisory.contains("7.2.4"),
    )?;
    let results = guest(
        run,
        &format!(
            "curl -s {}",
            quote(&search_url(Engine::Google, "halvard hg-400 fix"))
        ),
    )
    .await?;
    let listed = fictionet_extras::search::links(&results);
    check(
        "the planted page leads a search that shares its words",
        listed.first().is_some_and(|(url, _)| url == planted),
    )?;
    let page = guest(run, &format!("curl -s {}", quote(planted))).await?;
    check(
        "the planted page reads as written, in its site's layout",
        page.contains("<h1>Halvard ships a second HG-400 fix</h1>") && page.contains("</html>"),
    )?;
    let form = guest(
        run,
        "curl -s -d email=it%40example-office.co.uk https://www.theregister.com/newsletter",
    )
    .await?;
    check(
        "a form post gets the page a site shows after one",
        form.contains("Thanks for subscribing"),
    )?;
    // New pages off: a new search has no results, a canned one still answers.
    let reply = command(
        &client,
        "off",
        json!({"command": "set_new_pages", "new_pages": "off"}),
    )
    .await?;
    check("new pages turned off", reply["status"] == "applied")?;
    let reply = client
        .command(
            "generation",
            "stale",
            json!({"command": "set_generation", "generate": true, "expected_revision": 0}),
        )
        .await?;
    check(
        "a stale world command is rejected",
        reply["status"] == "rejected" && reply["rejection"]["reason"] == "stale_revision",
    )?;
    let (_, empty) = search(
        run,
        &client,
        Engine::Google,
        &format!("{words} new question"),
        fresh.id,
        0,
    )
    .await?;
    // The planted page shares the seed's words, so it leads their list.
    let (_, cached) = search(
        run,
        &client,
        Engine::Google,
        words,
        empty.id,
        (canned_count(words).unwrap_or(0) + 1).min(10),
    )
    .await?;
    check(
        "a canned search is still answered with new pages off",
        cached.cache == Some(Cache::Cached),
    )?;
    let reply = command(
        &client,
        "canned",
        json!({"command": "set_new_pages", "new_pages": "canned"}),
    )
    .await?;
    check("canned pages again", reply["status"] == "applied")?;
    wait(
        &client,
        "the page shows canned pages and new pages on",
        |s| s.generator.generate && s.generator.canned,
    )
    .await?;
    let description = client.get_json("/api/page").await?;
    check(
        "the page is the Search app with its world panel",
        description["title"] == "Search"
            && description["app"] == true
            && description["panels"].as_array().is_some_and(|panels| {
                panels.iter().any(|p| {
                    p["title"] == "Search" && p["kind"] == "custom" && p["area"] == "workspace"
                })
            }),
    )?;
    for path in [
        "/panels/search.mjs",
        "/assets/search/model.mjs",
        "/assets/search/view.mjs",
        "/assets/search/style.css",
    ] {
        let response = client.request("GET", path, None, true).await?;
        check(
            &format!("search module served: {path}"),
            response.status == 200,
        )?;
    }
    let egress = client.get_json("/api/egress").await?;
    let destinations = egress["destinations"]
        .as_array()
        .ok_or("egress has no destinations")?;
    let observed = |host: &str, outcome: &str| {
        destinations.iter().any(|row| {
            row["sandbox"] == HOST
                && row["name"] == host
                && row["outcome"] == outcome
                && row["requests"].as_u64().is_some_and(|n| n > 0)
        })
    };
    let mut counts = BTreeMap::new();
    for row in destinations {
        *counts
            .entry(row["outcome"].as_str().unwrap_or("unknown"))
            .or_insert(0usize) += 1;
    }
    for (outcome, count) in counts {
        println!("Left the box: {outcome}: {count} destinations");
    }
    // A mirrored name either left the box or was answered from the host's
    // package cache, as a file fetched by an earlier run is.
    let mirrored = |host: &str| {
        observed(host, "forwarded")
            || destinations.iter().any(|row| {
                row["sandbox"] == HOST
                    && row["name"] == host
                    && row["outcome"] == "served"
                    && row["by"] == "host package cache"
            })
    };
    for (host, _) in super::page::FORWARDED {
        if !mirrored(host) {
            println!("Left the box: {host} was neither forwarded nor answered from the cache");
        }
    }
    for host in visited.iter() {
        if !observed(host, "served") {
            println!("Left the box: {host} was not served by the world");
        }
    }
    check(
        "Left the box names all forwarded mirrors and visited sites",
        super::page::FORWARDED
            .iter()
            .all(|(host, _)| mirrored(host))
            && visited.iter().all(|host| observed(host, "served"))
            && destinations
                .iter()
                .filter(|row| row["outcome"] == "forwarded")
                .all(|row| {
                    super::page::FORWARDED
                        .iter()
                        .any(|(host, _)| row["name"] == *host)
                }),
    )?;
    let graph = client.get_json("/api/graph").await?;
    check(
        "map has nodes",
        graph["nodes"].as_array().is_some_and(|v| !v.is_empty()),
    )?;
    run.containment().await?;
    run.screenshots(HOST, &output.join("desktop.png"), &output.join("page.png"))
        .await?;
    run.page_shot(
        &output.join("world.png"),
        r#"(() => {
            const rows = document.querySelectorAll('.search-row');
            const picture = document.querySelector('.search-picture');
            return rows.length >= 6 && picture && picture.getBoundingClientRect().height > 200;
        })()"#,
        Duration::from_secs(30),
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
    fn every_embedded_seed_names_its_search_and_an_address_on_its_sites() {
        for name in ["halvard-cve", "corvane-acquisition", "fastjsonl-package"] {
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
