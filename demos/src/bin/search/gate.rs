use super::{Result, guest::HOST};
use adaptive_web_world::{
    route::Engine,
    search::{Cache, Listed, Made, Outcome, Query, Reason, Results, Snapshot},
    stub::Seed,
};
use fictionet_demo::kit::{
    Run,
    client::{Capability, PageClient},
    gate::check,
    ssh::quote,
};
use fictionet_observe::page::{Containment, ProbeOutcome};
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
            |value| Ok(snapshot(value)?.is_some_and(|s| predicate(&s))),
        )
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                println!("[FAIL] {label}: timed out");
                format!("timed out waiting for {label}").into()
            } else {
                Box::<dyn std::error::Error + Send + Sync>::from(error)
            }
        })?;
    check(label, true)?;
    Ok(snapshot(&value)?.expect("the accepted state has a value"))
}

async fn navigate(run: &Run, url: &str) -> Result {
    let quoted = quote(url);
    let command = format!(
        "env DISPLAY=:1 xdotool search --sync --onlyvisible --class Firefox windowactivate --sync key --clearmodifiers ctrl+l type --clearmodifiers -- {quoted} && env DISPLAY=:1 xdotool key --clearmodifiers Return"
    );
    // The kit connects SSH as the guest user, who also owns the desktop.
    let output = tokio::time::timeout(Duration::from_secs(15), run.guest(HOST).ssh().run(&command))
        .await
        .map_err(|_| "scripted Firefox navigation timed out")??;
    if output.code != 0 {
        return Err(format!("scripted Firefox navigation: {}", output.stderr).into());
    }
    println!("Firefox (scripted) typed: {url}");
    Ok(())
}

fn encoded(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

async fn search(
    run: &Run,
    client: &PageClient,
    engine: Engine,
    words: &str,
    after: u64,
    count: u64,
) -> Result<(Snapshot, Query)> {
    let base = match engine {
        Engine::Google => "https://www.google.com/search?q=",
        Engine::Bing => "https://www.bing.com/search?q=",
        Engine::DuckDuckGo => "https://html.duckduckgo.com/html/?q=",
    };
    navigate(run, &format!("{base}{}", encoded(words))).await?;
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
        &format!("scripted {} search served {count} results", engine.as_str()),
        |s| s.queries.iter().any(|q| matches(&q)),
    )
    .await?;
    let query = snapshot.queries.iter().find(matches).unwrap().clone();
    Ok((snapshot, query))
}

pub async fn command(
    client: &PageClient,
    generate: bool,
    revision: u64,
    id: &str,
) -> Result<Value> {
    let command =
        json!({"command":"set_generation","generate":generate,"expected_revision":revision});
    let reply = client.command("generation", id, command).await;
    if let Err(error) = &reply {
        println!("{error}");
    }
    check(
        "generation command HTTP status matches its reply",
        reply.is_ok(),
    )?;
    Ok(reply?)
}

pub fn first_generated<'a>(seed: &Seed, list: &'a Results) -> Result<&'a Listed> {
    for result in &list.listed {
        let (host, target) = adaptive_web_world::stub::text::target_of(&result.url);
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

fn expected_page(seed: &Seed, snapshot: &Snapshot, url: &str) -> (Reason, Made) {
    let (host, target) = adaptive_web_world::stub::text::target_of(url);
    if seed.fixed_for(&host, &target).is_some() {
        return (Reason::Fixed, Made::Fixed);
    }
    // The stub keeps the first search mention in creation order.
    let mention = snapshot
        .results
        .iter()
        .filter_map(|list| {
            list.listed
                .iter()
                .find(|r| {
                    adaptive_web_world::stub::text::target_of(&r.url)
                        == (host.clone(), target.clone())
                })
                .map(|result| (list, result))
        })
        .min_by_key(|(list, _)| list.query_id);
    let reason = mention
        .and_then(|(list, result)| {
            snapshot
                .queries
                .iter()
                .find(|q| q.id == list.query_id)
                .map(|query| Reason::Search {
                    query: query.search.clone(),
                    rank: result.rank,
                })
        })
        .unwrap_or(Reason::Direct);
    (reason, Made::Stubbed)
}

/// Runs the story. `visited` collects the hosts the searcher opened as it
/// goes, so the background check can run after a failed story too.
pub async fn run(run: &Run, seed: &Seed, output: &Path, visited: &mut BTreeSet<String>) -> Result {
    run.guest(HOST)
        .wait_desktop(Duration::from_secs(300))
        .await?;
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    // Home requests are HTTP facts; the search projection only retains content pages.
    client
        .wait_for_event(
            0,
            Duration::from_secs(45),
            Duration::from_millis(100),
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
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::TimedOut => {
                std::io::Error::other("Firefox did not load the Google home page")
            }
            _ => error,
        })?;
    println!(
        "boot to desktop with Google loaded: {} ms",
        run.boot_started().elapsed().as_millis()
    );
    check(
        "API without bearer is refused",
        client
            .request("GET", "/api/page", None, false)
            .await?
            .status
            == 401,
    )?;
    let missing = client.open(HOST, Capability::Screen, None).await;
    check(
        "WebSocket without ticket is refused",
        missing.err().is_some_and(|e| e.to_string().contains("401")),
    )?;
    let ticket = client.ticket(HOST, Capability::Screen).await?;
    let socket = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let reused = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await;
    check(
        "reused ticket is refused",
        reused.err().is_some_and(|e| e.to_string().contains("401")),
    )?;
    drop(socket);

    let words = match seed.name.as_str() {
        "halvard-cve" => "halvard gateway vulnerability",
        "corvane-acquisition" => "corvane acquisition",
        "fastjsonl-package" => "fastjsonl package",
        _ => return Err("unknown embedded seed".into()),
    };
    visited.extend(["www.google.com", "www.bing.com", "html.duckduckgo.com"].map(String::from));
    let (snapshot, google) = search(run, &client, Engine::Google, words, 0, 10).await?;
    let list = snapshot
        .results
        .iter()
        .find(|r| r.key == google.key)
        .ok_or("Google result list missing")?;
    check(
        "Google result list has ten entries",
        list.listed.len() == 10 && list.query_id == google.id,
    )?;
    let first = first_generated(seed, list)?.clone();
    visited.insert(first.host.clone());
    navigate(run, &first.url).await?;
    wait(&client, "opened result has its exact search reason and is stubbed", |s| s.pages.iter().any(|p|
        p.url == first.url && matches!(&p.reason, Reason::Search { query, rank } if query == words && *rank == first.rank)
        && p.made == Made::Stubbed)).await?;
    let (snapshot, bing) = search(run, &client, Engine::Bing, words, google.id, 10).await?;
    check(
        "Bing shares Google's first result list",
        bing.key == google.key
            && snapshot
                .results
                .iter()
                .any(|r| r.key == bing.key && r.query_id == google.id && r.listed == list.listed),
    )?;
    let different = format!("{words} details");
    let (snapshot, duck) =
        search(run, &client, Engine::DuckDuckGo, &different, bing.id, 10).await?;
    check(
        "DuckDuckGo has its own result list",
        duck.key != google.key
            && snapshot
                .results
                .iter()
                .any(|r| r.key == duck.key && r.query_id == duck.id && r.listed.len() == 10),
    )?;
    let direct = if seed.name == "halvard-cve" {
        "https://www.halvardsystems.com/security/advisories/".to_string()
    } else {
        format!(
            "https://{}/information/",
            seed.sites.first().ok_or("seed has no site")?.host
        )
    };
    visited.insert(adaptive_web_world::stub::text::target_of(&direct).0);
    let (reason, made) = expected_page(seed, &snapshot, &direct);
    navigate(run, &direct).await?;
    wait(
        &client,
        "typed seed address has its exact reason and creation mode",
        |s| {
            s.pages
                .iter()
                .any(|p| p.url == direct && p.status == 200 && p.reason == reason && p.made == made)
        },
    )
    .await?;
    navigate(run, "http://wiki.corp/").await?;
    wait(&client, "reserved name is refused", |s| {
        s.refused
            .iter()
            .any(|r| r.name == "wiki.corp" && r.reason == "reserved or private top-level domain")
    })
    .await?;
    let reply = command(&client, false, 0, "disable").await?;
    check(
        "generation disabled at revision one",
        reply["status"] == "applied" && reply["reply"]["revision"] == 1,
    )?;
    let reply = command(&client, false, 0, "stale").await?;
    check(
        "stale generation command rejected",
        reply["status"] == "rejected"
            && reply["rejection"]["reason"] == "stale_revision"
            && reply["rejection"]["current"] == 1,
    )?;
    wait(&client, "topic shows generation off at revision one", |s| {
        !s.generator.generate && s.generator.generation_revision == 1
    })
    .await?;
    let (_, empty) = search(
        run,
        &client,
        Engine::Google,
        &format!("{words} new question"),
        duck.id,
        0,
    )
    .await?;
    let (_, cached) = search(run, &client, Engine::Google, words, empty.id, 10).await?;
    check(
        "stored Google search is served from memory",
        cached.cache == Some(Cache::Cached),
    )?;
    let reply = command(&client, true, 1, "enable").await?;
    check(
        "generation restored at revision two",
        reply["status"] == "applied" && reply["reply"]["revision"] == 2,
    )?;
    wait(&client, "topic shows generation restored", |s| {
        s.generator.generate && s.generator.generation_revision == 2
    })
    .await?;
    let description = client.get_json("/api/page").await?;
    check(
        "Search panel is in the workspace",
        description["panels"].as_array().is_some_and(|panels| {
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
    check(
        "Left the box names all forwarded mirrors and visited generated sites",
        super::page::FORWARDED
            .iter()
            .all(|(host, _)| observed(host, "forwarded"))
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
    let probes = client.get_json("/api/state/containment").await?;
    let probes: Containment = serde_json::from_value(probes["value"].clone())?;
    check("containment probes have data", !probes.probes.is_empty())?;
    for probe in &probes.probes {
        println!(
            "containment: {}: {:?}; world: {}",
            probe.name, probe.outcome, probe.world_answer
        );
    }
    check(
        "containment probes are neither forwarded nor unaccounted",
        probes.probes.iter().all(|p| {
            !matches!(
                p.outcome,
                ProbeOutcome::Forwarded | ProbeOutcome::NotContained
            )
        }),
    )?;
    run.screenshots(HOST, &output.join("desktop.png"), &output.join("page.png"))
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
    for line in input.lines() {
        let event: Value = serde_json::from_str(&line?)?;
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
    Ok(check(
        "background hosts generated no pages",
        generated.is_empty(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
