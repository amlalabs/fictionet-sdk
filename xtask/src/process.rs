use regex::Regex;
use std::io::{Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub struct Interrupts(Vec<(libc::c_int, libc::sigaction)>);

impl Interrupts {
    pub fn new() -> Result<Self> {
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // Keep the parent alive to stop its children and remove VM overlays.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous = action;
            action.sa_sigaction = interrupt as *const () as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            guard.0.push((signal, previous));
        }
        Ok(guard)
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        for (signal, previous) in &self.0 {
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
    }
}

pub fn interrupted() -> Result {
    if INTERRUPTED.load(Ordering::Relaxed) {
        Err("command interrupted".into())
    } else {
        Ok(())
    }
}

pub fn poll_interruptible(
    timeout: Duration,
    interval: Duration,
    mut ready: impl FnMut() -> Result<bool>,
) -> Result<bool> {
    poll(timeout, interval, || {
        interrupted()?;
        ready()
    })
}

pub fn cmd(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args).current_dir(crate::root());
    command
}

pub fn run(command: &mut Command) -> Result {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{command:?} exited with {status}").into());
    }
    Ok(())
}

pub fn capture(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{command:?} exited with {}: {}",
            output.status,
            combined(&output)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

pub fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn input(command: &mut Command, data: &[u8]) -> Result {
    let mut child = ChildGuard(command.stdin(Stdio::piped()).spawn()?);
    child
        .0
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(data)?;
    let status = child.0.wait()?;
    if !status.success() {
        return Err(format!("{command:?} exited with {status}").into());
    }
    Ok(())
}

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => eprintln!("reading child status: {error}"),
        }
        if let Err(error) = self.0.kill() {
            eprintln!("stopping child: {error}");
        }
        if let Err(error) = self.0.wait() {
            eprintln!("reaping child: {error}");
        }
    }
}

#[derive(Default)]
pub struct Cleanup(Vec<Command>);

impl Cleanup {
    pub fn push(&mut self, command: Command) {
        self.0.push(command);
    }

    pub fn finish(mut self, result: Result) -> Result {
        let cleanup = self.clean();
        result.and(cleanup)
    }

    fn clean(&mut self) -> Result {
        let mut errors = Vec::new();
        for mut command in self.0.drain(..).rev() {
            if let Err(error) = capture(&mut command) {
                eprintln!("cleanup: {error}");
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n").into())
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Err(error) = self.clean() {
            eprintln!("{error}");
        }
    }
}

pub fn poll(
    timeout: Duration,
    interval: Duration,
    mut ready: impl FnMut() -> Result<bool>,
) -> Result<bool> {
    let start = Instant::now();
    loop {
        if ready()? {
            return Ok(true);
        }
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return Ok(false);
        };
        std::thread::sleep(interval.min(remaining));
    }
}

pub fn token(bytes: usize) -> Result<String> {
    let mut data = vec![0; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut data)?;
    Ok(data.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Default)]
pub struct Checks {
    failures: usize,
}

impl Checks {
    pub fn require(&mut self, name: &str, condition: bool, detail: impl std::fmt::Display) {
        if condition {
            println!("PASS: {name}");
        } else {
            self.failures += 1;
            eprintln!("FAIL: {name}: {detail}");
        }
    }

    pub fn output(
        &mut self,
        name: &str,
        pattern: &str,
        output: &Output,
        status: Option<i32>,
    ) -> Result {
        let text = combined(output).replace('\n', " ");
        let valid = match status {
            Some(code) => output.status.code() == Some(code),
            None => matches!(output.status.code(), Some(1..=123 | 125 | 128)),
        };
        self.require(
            name,
            valid && Regex::new(pattern)?.is_match(&text),
            format!(
                "wanted status {status:?} and /{pattern}/, got {}: {text}",
                output.status
            ),
        );
        Ok(())
    }

    pub fn ok(&mut self, name: &str, pattern: &str, command: &mut Command) -> Result {
        self.output(name, pattern, &command.output()?, Some(0))
    }

    pub fn fails(&mut self, name: &str, pattern: &str, command: &mut Command) -> Result {
        self.output(name, pattern, &command.output()?, None)
    }

    pub fn connect_fails(&mut self, name: &str, pattern: &str, command: &mut Command) -> Result {
        let output = command.output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        self.require(
            name,
            matches!(output.status.code(), Some(1..=123 | 125 | 128))
                && !Regex::new("Operation timed out|bytes received")?.is_match(&stderr)
                && Regex::new(pattern)?.is_match(&stderr),
            format!("{}: {}", output.status, combined(&output)),
        );
        Ok(())
    }

    pub fn transfer(
        &mut self,
        name: &str,
        bytes: u64,
        command: &mut Command,
        seconds: bool,
    ) -> Result<Option<f64>> {
        let output = command.output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let measurement = transfer(&text, bytes);
        self.require(
            name,
            output.status.success() && measurement.is_some(),
            combined(&output),
        );
        let measurement = measurement.filter(|_| output.status.success());
        if let Some(value) = measurement {
            if seconds {
                println!(
                    "    {value:.3} s, {:.1} Mbit/s",
                    bytes as f64 * 8.0 / value / 1e6
                );
            } else {
                println!("    {:.1} Mbit/s", value * 8.0 / 1e6);
            }
        }
        Ok(measurement)
    }

    pub fn downloads(
        &mut self,
        name: &str,
        count: usize,
        bytes: u64,
        command: &mut Command,
    ) -> Result {
        let output = command.output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let times: Option<Vec<f64>> = text.lines().map(|line| transfer(line, bytes)).collect();
        self.require(
            name,
            output.status.success() && times.as_ref().is_some_and(|t| t.len() == count),
            combined(&output),
        );
        if let Some(mut times) = times.filter(|t| !t.is_empty()) {
            times.sort_by(f64::total_cmp);
            println!(
                "    {:.3} s to {:.3} s per download",
                times[0],
                times[times.len() - 1]
            );
        }
        Ok(())
    }

    pub fn finish(self) -> Result {
        if self.failures == 0 {
            println!("ALL PASSED");
            Ok(())
        } else {
            Err(format!("{} checks failed", self.failures).into())
        }
    }
}

fn transfer(text: &str, bytes: u64) -> Option<f64> {
    let mut fields = text.split_whitespace();
    if fields.next()? != bytes.to_string() {
        return None;
    }
    let value = fields.next()?;
    if !Regex::new(r"^[0-9]+(\.[0-9]+)?$").unwrap().is_match(value) || fields.next().is_some() {
        return None;
    }
    value.parse::<f64>().ok().filter(|v| v.is_finite())
}
