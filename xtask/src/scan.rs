use crate::docker::Compose;
use crate::process::{ChildGuard, Cleanup, Result, cmd, run as execute, token};
use regex::Regex;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};

mod browser;
mod tour;
use browser::Browser;

const DISCOVERY: &[&str] = &["nmap", "-sn", "-n", "10.0.0.0/24"];
const PORT_SCAN: &[&str] = &[
    "nmap",
    "-sS",
    "-sV",
    "-n",
    "-p",
    "1-1024",
    "--max-rate",
    "200",
    "10.0.0.0/24",
];

pub fn run(args: &[String]) -> Result {
    let out = match args {
        [] => crate::root().join("examples/scan/recording"),
        [path] => std::path::absolute(path)?,
        _ => return Err("usage: cargo xtask scan [output directory]".into()),
    };
    std::fs::create_dir_all(&out)?;
    let keep = std::env::var("KEEP").is_ok_and(|v| v == "1");
    let temp = Temporary(
        crate::root().join(format!("target/scan-{}-{}", std::process::id(), token(8)?)),
        keep,
    );
    std::fs::create_dir_all(&temp.0)?;
    let secret = token(32)?;
    let token_file = temp.0.join("token");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&token_file)?.write_all(secret.as_bytes())?;
    let project = std::env::var("SCAN_PROJECT").unwrap_or_else(|_| "fn-scan-demo".into());
    let port = std::env::var("SCAN_DASHBOARD_PORT").unwrap_or_else(|_| "7880".into());
    let compose = Compose::new("examples/scan/compose.yaml")
        .project(&project)
        .env("SCAN_DASHBOARD_PORT", &port)
        .env(
            "SCAN_DASHBOARD_TOKEN_FILE",
            token_file.to_str().ok_or("invalid token path")?,
        );
    let mut cleanup = Cleanup::default();
    if !keep {
        cleanup.push(compose.down());
    }
    let result = (|| {
        execute(&mut compose.command(&["build"]))?;
        execute(&mut compose.command(&["up", "-d", "--wait"]))?;
        let mut browser = Browser::launch(&temp.0.join("chromium"), &out)?;
        browser.navigate(&format!(
            "http://127.0.0.1:{port}/?theme=light#token={secret}"
        ))?;
        browser.until("sessionStorage.getItem('fictionet_token') !== null")?;
        browser.eval("localStorage.clear()")?;
        browser.navigate(&format!("http://127.0.0.1:{port}/?theme=light"))?;
        browser.until("document.querySelector('g.node.group') !== null")?;
        tour::record(&mut browser, &compose)?;
        browser.finish()?;
        for (extension, options) in [
            (
                "mp4",
                vec![
                    "-c:v",
                    "libx264",
                    "-preset",
                    "slow",
                    "-crf",
                    "20",
                    "-pix_fmt",
                    "yuv420p",
                    "-movflags",
                    "+faststart",
                ],
            ),
            (
                "gif",
                vec![
                    "-vf",
                    "fps=6,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle",
                ],
            ),
        ] {
            let mut command = cmd("ffmpeg", &["-v", "error", "-y", "-i"]);
            command
                .arg(out.join("dashboard.webm"))
                .args(options)
                .arg(out.join(format!("dashboard.{extension}")));
            execute(&mut command)?;
        }
        println!("Recording and scan transcript saved to {}", out.display());
        Ok(())
    })();
    if keep {
        println!(
            "Stack retained; dashboard token file: {}",
            token_file.display()
        );
    }
    cleanup.finish(result)
}

struct Temporary(PathBuf, bool);
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.1
            && let Err(error) = std::fs::remove_dir_all(&self.0)
        {
            eprintln!("removing {}: {error}", self.0.display());
        }
    }
}

fn validate_scan(output: &str, services: bool) -> Result {
    let report = Regex::new(r"^Nmap scan report for (\S+)\s*$")?;
    let up = Regex::new(r"^Host is up\b")?;
    let mut hosts = BTreeMap::new();
    let mut current = None;
    for line in output.lines() {
        if let Some(capture) = report.captures(line) {
            let host = capture[1].to_string();
            hosts.insert(host.clone(), (false, String::new()));
            current = Some(host);
        } else if let Some(host) = &current {
            let (alive, text) = hosts.get_mut(host).unwrap();
            *alive |= up.is_match(line);
            text.push_str(line);
            text.push('\n');
        }
    }
    let found: Vec<_> = hosts
        .iter()
        .filter(|(_, (up, _))| *up)
        .map(|(host, _)| host.as_str())
        .collect();
    let expected = [
        "10.0.0.10",
        "10.0.0.11",
        "10.0.0.12",
        "10.0.0.13",
        "10.0.0.50",
    ];
    if found != expected {
        return Err(format!("Expected hosts {expected:?}, found {found:?}").into());
    }
    if services {
        for (port, service, product) in [(22, "ssh", "OpenSSH"), (80, "http", "nginx")] {
            if !Regex::new(&format!(
                r"(?m)^{port}/tcp\s+open\s+{service}\s+{product}\b"
            ))?
            .is_match(&hosts["10.0.0.50"].1)
            {
                return Err(format!("Expected {product} on 10.0.0.50:{port}").into());
            }
        }
    }
    Ok(())
}

struct Scan {
    child: ChildGuard,
    lines: Receiver<std::io::Result<String>>,
    output: String,
    transcript: File,
    status: Option<ExitStatus>,
}

impl Scan {
    fn start(command: &mut Command, argv: &[&str], out: &Path) -> Result<Self> {
        let (reader, writer) = std::io::pipe()?;
        let child = ChildGuard(command.stdout(writer.try_clone()?).stderr(writer).spawn()?);
        // Command retains its pipe writers until dropped or replaced.
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            loop {
                let mut line = Vec::new();
                let result = reader.read_until(b'\n', &mut line);
                match result {
                    Ok(0) => break,
                    Ok(_) => {
                        if send
                            .send(Ok(String::from_utf8_lossy(&line).into_owned()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        if let Err(error) = send.send(Err(error)) {
                            eprintln!("scan output receiver closed: {error}");
                        }
                        break;
                    }
                }
            }
        });
        let mut transcript = OpenOptions::new()
            .create(true)
            .append(true)
            .open(out.join("nmap.txt"))?;
        writeln!(transcript, "$ {}", argv.join(" "))?;
        Ok(Self {
            child,
            lines,
            output: String::new(),
            transcript,
            status: None,
        })
    }

    fn read(&mut self) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        if self.status.is_some() {
            return Ok(lines);
        }
        loop {
            match self.lines.try_recv() {
                Ok(line) => {
                    let line = line?;
                    self.transcript.write_all(line.as_bytes())?;
                    self.output.push_str(&line);
                    lines.push(line);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = Some(self.child.0.wait()?);
                    writeln!(self.transcript)?;
                    self.transcript.flush()?;
                    break;
                }
            }
        }
        Ok(lines)
    }

    fn finish(self) -> Result<String> {
        let status = self.status.ok_or("scan is still running")?;
        if !status.success() {
            return Err(format!("nmap exited with {status}: {}", self.output).into());
        }
        Ok(self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICES: &str = "PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 9.7 (protocol 2.0)\n80/tcp open  http    nginx 1.26.3\n";
    const SUMMARY: &str = "Nmap done: 256 IP addresses (5 hosts up) scanned in 36.36 seconds\n";

    fn discovery() -> String {
        [10, 11, 12, 13, 50]
            .iter()
            .map(|host| {
                format!("Nmap scan report for 10.0.0.{host}\nHost is up (0.004s latency).\n")
            })
            .collect()
    }

    fn port_scan() -> String {
        discovery() + SERVICES + SUMMARY
    }

    #[test]
    fn complete_scans() {
        validate_scan(&(discovery() + SUMMARY), false).unwrap();
        validate_scan(&port_scan(), true).unwrap();
    }

    #[test]
    fn missing_host_even_with_success_summary() {
        for host in [10, 11, 12, 13, 50] {
            for services in [false, true] {
                let output = port_scan().replace(
                    &format!("Nmap scan report for 10.0.0.{host}\nHost is up (0.004s latency).\n"),
                    "",
                );
                assert!(
                    validate_scan(&output, services)
                        .unwrap_err()
                        .to_string()
                        .contains("Expected hosts")
                );
            }
        }
    }

    #[test]
    fn empty_scan() {
        assert!(
            validate_scan("", false)
                .unwrap_err()
                .to_string()
                .contains("Expected hosts")
        );
    }

    #[test]
    fn host_must_be_up() {
        assert!(
            validate_scan(
                &port_scan().replacen("Host is up", "Host seems down", 1),
                false
            )
            .unwrap_err()
            .to_string()
            .contains("Expected hosts")
        );
    }

    #[test]
    fn wrong_host_with_same_count() {
        assert!(
            validate_scan(&port_scan().replace("10.0.0.13", "10.0.0.99"), false)
                .unwrap_err()
                .to_string()
                .contains("Expected hosts")
        );
    }

    #[test]
    fn service_must_be_identified_and_open_on_expected_port() {
        for (old, new, product) in [
            ("OpenSSH 9.7 (protocol 2.0)", "", "OpenSSH"),
            ("nginx 1.26.3", "Apache httpd", "nginx"),
            ("22/tcp open", "22/tcp filtered", "OpenSSH"),
            ("80/tcp open", "80/tcp closed", "nginx"),
            ("80/tcp open", "80/tcp open|filtered", "nginx"),
            ("22/tcp", "222/tcp", "OpenSSH"),
            ("80/tcp", "8080/tcp", "nginx"),
        ] {
            assert!(
                validate_scan(&port_scan().replace(old, new), true)
                    .unwrap_err()
                    .to_string()
                    .contains(product)
            );
        }
    }

    #[test]
    fn services_on_another_host_do_not_count() {
        let output = discovery().replace(
            "Nmap scan report for 10.0.0.50",
            &format!("{SERVICES}\nNmap scan report for 10.0.0.50"),
        ) + SUMMARY;
        assert!(
            validate_scan(&output, true)
                .unwrap_err()
                .to_string()
                .contains("OpenSSH")
        );
    }

    fn run_command(command: &mut Command, out: &Path) -> (Scan, Vec<String>) {
        let mut scan = Scan::start(command, DISCOVERY, out).unwrap();
        let mut lines = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while scan.status.is_none() {
            assert!(std::time::Instant::now() < deadline, "scan did not finish");
            lines.extend(scan.read().unwrap());
            std::thread::yield_now();
        }
        (scan, lines)
    }

    fn directory() -> Temporary {
        let dir = Temporary(
            crate::root().join(format!("target/scan-test-{}", token(8).unwrap())),
            false,
        );
        std::fs::create_dir_all(&dir.0).unwrap();
        dir
    }

    #[test]
    fn failed_command_preserves_output_and_previous_scan() {
        let dir = directory();
        std::fs::write(dir.0.join("nmap.txt"), "previous scan\n").unwrap();
        let (scan, lines) = run_command(
            &mut cmd(
                "sh",
                &["-c", "printf 'partial output\\nscanner failed\\n'; exit 2"],
            ),
            &dir.0,
        );
        assert_eq!(scan.status.unwrap().code(), Some(2));
        assert_eq!(scan.output, "partial output\nscanner failed\n");
        assert_eq!(lines, ["partial output\n", "scanner failed\n"]);
        assert!(
            scan.finish()
                .unwrap_err()
                .to_string()
                .contains("partial output\nscanner failed\n")
        );
        assert_eq!(
            std::fs::read_to_string(dir.0.join("nmap.txt")).unwrap(),
            "previous scan\n$ nmap -sn -n 10.0.0.0/24\npartial output\nscanner failed\n\n"
        );
    }

    #[test]
    fn success_returns_and_saves_output() {
        let dir = directory();
        let output = discovery() + SUMMARY;
        let (scan, lines) = run_command(&mut cmd("printf", &["%s", &output]), &dir.0);
        assert_eq!(lines, output.split_inclusive('\n').collect::<Vec<_>>());
        assert_eq!(scan.finish().unwrap(), output);
        assert_eq!(
            std::fs::read_to_string(dir.0.join("nmap.txt")).unwrap(),
            format!("$ nmap -sn -n 10.0.0.0/24\n{output}\n")
        );
    }
}
