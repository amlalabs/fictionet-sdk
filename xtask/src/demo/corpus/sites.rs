//! Capture a varied set of astronomy sites and their page requisites.

use crate::process::Result;
use fictionet_extras::capture::{BROWSER, Fetcher, links};
use std::{
    collections::HashSet,
    io::Write,
    process::{Command, Stdio},
};

pub(super) fn run(only: Option<&str>) -> Result {
    let destination = crate::root().join("demos/downloads/astronomy");
    std::fs::create_dir_all(&destination)?;
    let mut fetcher = Fetcher::new(BROWSER)?;
    let mut failures = Vec::new();
    let starts = only.map_or_else(
        || {
            include_str!("../../../../demos/search/corpus/new-sites.urls")
                .lines()
                .collect::<Vec<_>>()
        },
        |url| vec![url],
    );
    for start in starts {
        crate::process::interrupted()?;
        let url = url::Url::parse(start)?;
        let host = url.host_str().ok_or("capture URL has no host")?;
        let response = match fetcher.fetch(start) {
            Ok(response) if response.status.is_success() => response,
            Ok(response) => {
                eprintln!("{host}: discovery returned {}", response.status);
                failures.push(format!("{host}: discovery returned {}", response.status));
                continue;
            }
            Err(error) => {
                failures.push(format!("{host}: {error}"));
                continue;
            }
        };
        let mut seen = HashSet::new();
        let mut pages = vec![start.to_owned()];
        for page in links(start, &response)?.pages {
            let parsed = url::Url::parse(&page)?;
            if parsed.host_str() == Some(host) && seen.insert(page.clone()) {
                pages.push(page);
                if pages.len() == 40 {
                    break;
                }
            }
        }
        if pages.len() < 30 {
            failures.push(format!(
                "{host}: discovery found only {} pages",
                pages.len()
            ));
        }
        let capture = destination.join(format!(".capture-{host}-{}", std::process::id()));
        std::fs::create_dir_all(&capture)?;
        let mut child = Command::new("wget")
            .args([
                "-e",
                "robots=off",
                "--page-requisites",
                "--span-hosts",
                "--delete-after",
                "--wait=1",
                "--random-wait",
                "--limit-rate=512k",
                "--timeout=20",
                "--tries=1",
                "--no-warc-keep-log",
                "--quota=512m",
                "--user-agent",
                BROWSER,
                "--input-file=-",
                "--directory-prefix",
            ])
            .arg(capture.join("files"))
            .arg("--warc-file")
            .arg(capture.join(host))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("wget input is closed")?
            .write_all(pages.join("\n").as_bytes())?;
        let output = child.wait_with_output()?;
        println!(
            "{host}: {} requested pages, wget {}",
            pages.len(),
            output.status
        );
        if output.status.success() {
            std::fs::rename(
                capture.join(format!("{host}.warc.gz")),
                destination.join(format!("{host}.warc.gz")),
            )?;
        } else {
            failures.push(format!(
                "{host}: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    for failure in &failures {
        eprintln!("{failure}");
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("{} site captures need attention", failures.len()).into())
    }
}
