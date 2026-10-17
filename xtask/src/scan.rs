use crate::docker::Compose;
use crate::process::{ChildGuard, Cleanup, Result, cmd, run as execute, token};
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

    fn finish(self) -> Result {
        let status = self.status.ok_or("scan is still running")?;
        if !status.success() {
            return Err(format!("nmap exited with {status}: {}", self.output).into());
        }
        Ok(())
    }
}
