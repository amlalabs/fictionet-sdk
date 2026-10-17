use crate::process::{Checks, Cleanup, Result, capture, cmd, input, run as execute};
use serde_json::Value;
use std::process::{Command, Stdio};

const HELP: &str = "cargo xtask eval <border|fakewiki|adaptive-web|artifactory> [--no-build] [Inspect arguments...]
  --probes       Run containment and world probes without a model
  --scripted     Run Border or Artifactory's scripted scorer tests
  --live [seed] [query...]   Browse the adaptive web without an agent model
Images are built from this checkout unless --no-build is given.
Inspect arguments, including --model, --epochs, --log-dir and -T, pass through.
Logs default to logs/<world>. FakeWiki defaults to the three local Ollama models.";

pub(crate) fn uv(args: &[&str]) -> Command {
    let mut command = cmd(
        "uv",
        &["run", "--locked", "--project", "python/inspect_fictionet"],
    );
    command.args(args);
    command
}

pub fn run(args: &[String]) -> Result {
    let Some((world, args)) = args.split_first() else {
        return Err(HELP.into());
    };
    if world == "--help" || world == "-h" {
        println!("{HELP}");
        return Ok(());
    }
    let module = match world.as_str() {
        "border" | "fakewiki" | "artifactory" => world.as_str(),
        "adaptive-web" => "adaptive_web",
        _ => return Err(HELP.into()),
    };
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let build = !args.iter().any(|a| a == "--no-build");
    let mut args: Vec<String> = args
        .iter()
        .filter(|a| *a != "--no-build")
        .cloned()
        .collect();
    let mode = match args.first().map(String::as_str) {
        Some("--live" | "--probes" | "--scripted") => args.remove(0),
        _ => String::new(),
    };
    let task = task_path(module, &mode)?;
    if build {
        for target in ["world", "attach", "agent"] {
            crate::images::build(
                &format!("examples/{world}/docker/Dockerfile"),
                target,
                &format!("fictionet-{world}-{target}:dev"),
            )?;
        }
        if world == "border" {
            for (target, tag) in [
                ("world-home", "fictionet-border-world:home"),
                ("home", "fictionet-border-home:dev"),
            ] {
                crate::images::build("examples/border/docker/Dockerfile", target, tag)?;
            }
        }
    }
    if mode == "--live" {
        return live(&args);
    }
    let log_dir = option(&args, "--log-dir").unwrap_or_else(|| format!("logs/{world}"));
    if option(&args, "--log-dir").is_none() {
        args.extend(["--log-dir".into(), log_dir.clone()]);
    }
    if option(&args, "--model").is_none() {
        if !mode.is_empty() {
            args.extend(["--model".into(), "mockllm/model".into()]);
        } else if world == "fakewiki" {
            args.extend([
                "--model".into(),
                "ollama/qwen3:latest,ollama/llama3.1:8b,ollama/gpt-oss:20b".into(),
            ]);
        }
    }
    if world == "fakewiki" && mode.is_empty() && option(&args, "--epochs").is_none() {
        args.extend([
            "--epochs".into(),
            std::env::var("EPOCHS").unwrap_or_else(|_| "2".into()),
        ]);
    }
    if mode == "--probes" || mode == "--scripted" {
        return checked_eval(module, &mode, &task, &args);
    }
    execute(uv(&["inspect", "eval", &task]).args(&args))?;
    if world == "fakewiki" && mode.is_empty() {
        execute(&mut uv(&[
            "python",
            "-m",
            "inspect_fictionet.worlds.fakewiki.report",
            &log_dir,
        ]))?;
    }
    Ok(())
}

fn checked_eval(module: &str, mode: &str, task: &str, args: &[String]) -> Result {
    let expected: Vec<String> = if mode == "--probes" {
        serde_json::from_str(&capture(&mut uv(&[
            "python",
            "-c",
            "import json, runpy, sys; probe = runpy.run_path(sys.argv[1]); print(json.dumps(list(probe['score_evidence']({}, 'control')[0])))",
            task.split_once('@').ok_or("missing task name")?.0,
        ]))?)?
    } else {
        Vec::new()
    };
    let output = capture(
        uv(&["inspect", "eval", task])
            .args(args)
            .arg("--json")
            .stderr(Stdio::inherit()),
    )?;
    let events = output
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<serde_json::Result<Vec<_>>>()?;
    let logs = events
        .iter()
        .find(|event| event["event"] == "done")
        .and_then(|event| event["logs"].as_array())
        .filter(|logs| !logs.is_empty())
        .ok_or("Inspect did not report any completed logs")?;
    let mut checks = Checks::default();
    for entry in logs {
        let path = entry["location"].as_str().ok_or("missing log location")?;
        println!("Log: {path}");
        let log: Value =
            serde_json::from_str(&capture(&mut uv(&["inspect", "log", "dump", path]))?)?;
        checks.require(
            "eval completed",
            log["status"] == "success" && log["error"].is_null(),
            format!("status {}: {}", log["status"], log["error"]["message"]),
        );
        let Some(samples) = log["samples"].as_array().filter(|s| !s.is_empty()) else {
            return Err(format!("{path}: no samples in log").into());
        };
        for sample in samples {
            let label = format!("{} epoch {}", sample["id"], sample["epoch"]);
            checks.require(
                &format!("{label}: sample completed"),
                sample["error"].is_null(),
                &sample["error"]["message"],
            );
            let Some(scores) = sample["scores"].as_object().filter(|s| !s.is_empty()) else {
                checks.require(&label, false, "no score");
                continue;
            };
            for (name, score) in scores {
                let label = format!("{label}: {name}");
                let value = if module == "artifactory" && mode == "--scripted" {
                    &score["value"]["passes"]
                } else {
                    &score["value"]
                };
                checks.require(
                    &label,
                    value.as_f64() == Some(1.0),
                    format!("score {value}: {}", score["explanation"]),
                );
                let metadata = &score["metadata"];
                if mode == "--probes" || metadata.get("checks").is_some() {
                    let Some(results) = metadata["checks"].as_object().filter(|c| !c.is_empty())
                    else {
                        checks.require(&label, false, "missing nonempty boolean checks");
                        continue;
                    };
                    if !expected.is_empty() {
                        checks.require(
                            &format!("{label}: complete containment checks"),
                            results.len() == expected.len()
                                && expected.iter().all(|name| results.contains_key(name)),
                            "missing or unexpected containment checks",
                        );
                    }
                    for (name, value) in results {
                        checks.require(
                            &format!("{label}: {name}"),
                            value.as_bool() == Some(true),
                            format!("expected true, got {value}"),
                        );
                    }
                }
            }
        }
    }
    checks.finish()
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter().enumerate().find_map(|(i, arg)| {
        if arg == name {
            args.get(i + 1).cloned()
        } else {
            arg.strip_prefix(&format!("{name}=")).map(String::from)
        }
    })
}

fn task_path(module: &str, mode: &str) -> Result<String> {
    let package = "python/inspect_fictionet";
    match mode {
        "" => Ok(format!(
            "{package}/src/inspect_fictionet/worlds/{module}/tasks.py@{module}"
        )),
        "--probes" if module != "artifactory" => Ok(format!(
            "{package}/tests/{module}/probes.py@{module}_probes"
        )),
        "--scripted" if matches!(module, "border" | "artifactory") => Ok(format!(
            "{package}/tests/{module}/probes.py@{module}_scripted"
        )),
        "--live" if module == "adaptive_web" => Ok(String::new()),
        _ => Err(format!("{mode} is not available for {module}\n{HELP}").into()),
    }
}

fn live(args: &[String]) -> Result {
    let seed = args.first().map_or("halvard-cve", String::as_str);
    let generator = std::env::var("ADAPTIVE_WEB_GENERATOR").unwrap_or_else(|_| "openrouter".into());
    let key = match generator.as_str() {
        "openrouter" => Some("OPENROUTER_API_KEY"),
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        _ => None,
    };
    if let Some(key) = key
        && std::env::var(key).unwrap_or_default().is_empty()
    {
        return Err(format!("{key} is not set").into());
    }
    let store = std::env::var_os("ADAPTIVE_WEB_STORE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::root().join("examples/adaptive-web/store"));
    let mut config = uv(&[
        "python",
        "-c",
        "import json, sys; from inspect_fictionet.worlds.adaptive_web.world import world_sandbox, seed_front; print(json.dumps([world_sandbox().config, seed_front(sys.argv[1])['question']]))",
        seed,
    ]);
    config
        .env("ADAPTIVE_WEB_GENERATOR", &generator)
        .env("ADAPTIVE_WEB_STORE_DIR", &store);
    let (file, question): (String, String) = serde_json::from_str(&capture(&mut config)?)?;
    let project = format!("adaptive-web-{}", crate::process::token(6)?);
    let compose = |args: &[&str]| {
        let mut command = cmd("docker", &["compose", "-f", &file, "-p", &project]);
        command.args(args).env("ADAPTIVE_WEB_SEED", seed);
        command
    };
    let mut cleanup = Cleanup::default();
    cleanup.push(compose(&["down", "-v", "-t", "1"]));
    let result = (|| {
        execute(&mut compose(&["up", "-d", "--wait", "--quiet-pull"]))?;
        let queries = if args.len() > 1 {
            &args[1..]
        } else {
            std::slice::from_ref(&question)
        };
        input(
            compose(&["exec", "-T", "default", "python3", "-"]).args(queries),
            LIVE.as_bytes(),
        )?;
        execute(&mut compose(&[
            "exec",
            "-T",
            "world",
            "cat",
            "/var/lib/fictionet/log.jsonl",
        ]))
    })();
    cleanup.finish(result)
}

const LIVE: &str = r#"import html, re, subprocess, sys, urllib.parse
queries = sys.argv[1:]

def curl(url):
    r = subprocess.run(["curl", "-f", "-sS", "-m", "180", "-w", "\n%{http_code} %{time_total}", url], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"curl failed for {url}: {r.stderr.strip()} (exit {r.returncode})")
    body, _, tail = r.stdout.rpartition("\n")
    code, secs = (tail.split() + ["", "0"])[:2]
    return body, code, float(secs)

for q in queries:
    body, code, secs = curl("https://www.google.com/search?q=" + urllib.parse.quote_plus(q))
    print(f"\n=== google: {q}  ({code}, {secs:.1f} s)")
    found = re.findall(r'<div class="yuRUbf"><a href="([^"]+)"><h3>(.*?)</h3>.*?<div class="VwiC3b">(.*?)</div>', body, re.S)
    if len(found) != 10:
        raise RuntimeError(f"search returned {len(found)} results; expected 10")
    for url, title, snippet in found:
        print(f"- {html.unescape(title)}\n  {html.unescape(url)}\n  {html.unescape(re.sub('<[^>]+>', '', snippet))[:200]}")
    for url, title, _ in found[:3]:
        page, code, secs = curl(html.unescape(url))
        text = " ".join(html.unescape(re.sub(r"(?s)<(script|style).*?</\1>|<[^>]+>", " ", page)).split())
        print(f"\n--- {html.unescape(url)}  ({code}, {secs:.1f} s, {len(page)} bytes)\n{text[:700]}")
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_selection() {
        assert!(
            task_path("border", "--scripted")
                .unwrap()
                .ends_with("tests/border/probes.py@border_scripted")
        );
        assert!(
            task_path("fakewiki", "")
                .unwrap()
                .ends_with("worlds/fakewiki/tasks.py@fakewiki")
        );
        assert!(task_path("artifactory", "--probes").is_err());
        assert!(task_path("fakewiki", "--live").is_err());
    }

    #[test]
    fn inspect_option_forms() {
        let args = ["--model=a,b", "--log-dir", "logs/with spaces"].map(String::from);
        assert_eq!(option(&args, "--model"), Some("a,b".into()));
        assert_eq!(option(&args, "--log-dir"), Some("logs/with spaces".into()));
        assert_eq!(option(&args, "--epochs"), None);
    }
}
