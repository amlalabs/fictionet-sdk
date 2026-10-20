use super::{Result, guest::HOST};
use adaptive_web_world::{
    route::Engine,
    search::{Cache, Listed, Made, Outcome, Query, Reason, Results, Snapshot},
    stub::Seed,
};
use fictionet_demo::kit::{
    Run,
    client::{Capability, PageClient},
    rfb, shot,
};
use fictionet_observe::page::{Containment, ProbeOutcome};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

pub fn check(label: &str, condition: bool) -> Result {
    println!("[{}] {label}", if condition { "pass" } else { "FAIL" });
    if condition {
        Ok(())
    } else {
        Err(format!("gate failed: {label}").into())
    }
}

pub async fn get(client: &PageClient, path: &str) -> Result<Value> {
    let response = client.request("GET", path, None, true).await?;
    if response.status != 200 {
        return Err(format!(
            "{path}: {} {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )
        .into());
    }
    Ok(serde_json::from_slice(&response.body)?)
}

async fn wait(
    client: &PageClient,
    label: &str,
    predicate: impl Fn(&Snapshot) -> bool,
) -> Result<Snapshot> {
    let result = tokio::time::timeout(Duration::from_secs(45), async {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tick.tick().await;
            let value = get(client, "/api/state/search-state").await?;
            if !value["value"].is_null() {
                let snapshot: Snapshot = serde_json::from_value(value["value"].clone())?;
                if predicate(&snapshot) {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(snapshot);
                }
            }
        }
    })
    .await
    .map_err(|_| {
        println!("[FAIL] {label}: timed out");
        format!("timed out waiting for {label}")
    })??;
    check(label, true)?;
    Ok(result)
}

async fn navigate(run: &Run, url: &str) -> Result {
    let quoted = format!("'{}'", url.replace('\'', "'\\''"));
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
    let response = client.request("POST", "/api/command/generation", Some(&json!({
        "request_id":id, "command":{"command":"set_generation","generate":generate,"expected_revision":revision}
    })), true).await?;
    let value: Value = serde_json::from_slice(&response.body)?;
    let expected = if value["status"] == "applied" {
        200
    } else {
        409
    };
    check(
        "generation command HTTP status matches its reply",
        response.status == expected,
    )?;
    Ok(value)
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

pub async fn run(run: &Run, seed: &Seed, output: &Path) -> Result {
    run.guest(HOST)
        .wait_desktop(Duration::from_secs(300))
        .await?;
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    // Home requests are HTTP facts; the search projection only retains content pages.
    let home = tokio::time::timeout(Duration::from_secs(45), async {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tick.tick().await;
            let events = get(&client, "/api/events").await?;
            if events["events"].as_array().is_some_and(|rows| {
                rows.iter().any(|e| {
                    e["source"] == "http"
                        && e["kind"] == "request"
                        && e["fields"]["host"] == "www.google.com"
                        && e["fields"]["path"] == "/"
                        && e["fields"]["status"] == 200
                        && e["fields"]["complete"] == true
                        && e["fields"]["headers"].to_string().contains("Firefox/")
                })
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    })
    .await
    .map_err(|_| "Firefox did not load the Google home page")?;
    home?;
    println!(
        "boot to desktop with Google loaded: {} ms",
        run.boot_started().elapsed().as_millis()
    );
    println!("page: {}", run.page_url());
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
    let mut visited = BTreeSet::from([
        "www.google.com".to_string(),
        "www.bing.com".into(),
        "html.duckduckgo.com".into(),
    ]);
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
    let snapshot = wait(&client, "topic shows generation restored", |s| {
        s.generator.generate && s.generator.generation_revision == 2
    })
    .await?;
    let rows = get(&client, "/api/event-table/searches").await?;
    check(
        "Searches table has rows",
        rows["rows"].as_array().is_some_and(|r| !r.is_empty()),
    )?;
    let egress = get(&client, "/api/egress").await?;
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
    let graph = get(&client, "/api/graph").await?;
    check(
        "map has nodes",
        graph["nodes"].as_array().is_some_and(|v| !v.is_empty()),
    )?;
    let probes = get(&client, "/api/state/containment").await?;
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
    let events = get(&client, "/api/events").await?;
    for site in snapshot.sites.iter().filter(|s| !visited.contains(&s.host)) {
        let asked = events["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| {
                e["source"] == "http" && e["kind"] == "request" && e["fields"]["host"] == site.host
            })
            .collect::<Vec<_>>();
        let first = asked.first();
        let path = first
            .and_then(|e| e["fields"]["path"].as_str())
            .unwrap_or("none");
        let user_agent = first
            .and_then(|e| e["fields"]["headers"].as_array())
            .and_then(|headers| {
                headers.iter().find(|h| {
                    h[0].as_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case("user-agent"))
                })
            })
            .and_then(|header| header[1].as_str())
            .unwrap_or("none");
        println!(
            "unvisited made-up host: {}; reason: {:?}; requests: {}; first path: {path}; User-Agent: {user_agent}",
            site.host,
            site.reason,
            asked.len()
        );
    }
    let desktop = output.join("desktop.png");
    rfb::capture_page(run.page_url(), HOST, &desktop).await?;
    println!("guest screen: {}", desktop.display());
    let url = run.page_url().to_owned();
    let page = output.join("page.png");
    let out = page.clone();
    tokio::task::spawn_blocking(move || {
        shot::capture(
            &url,
            &out,
            &shot::desktop_painted(HOST),
            Duration::from_secs(30),
        )
    })
    .await??;
    println!("page screen: {}", page.display());
    Ok(())
}
