//! A screenshot of the noVNC viewer, taken with the host's headless Chromium.
//!
//! Chromium is driven over the DevTools pipe (it reads commands on fd 3 and
//! writes replies on fd 4, each a JSON object followed by a NUL), the same
//! transport Puppeteer uses. We open the viewer page, wait a fixed time for it
//! to connect to the guest's VNC over the world and paint the first frame,
//! then capture. A live WebSocket keeps a `--virtual-time-budget` screenshot
//! from ever firing, so the pipe's explicit wait is what makes this reliable.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long to let the page connect and paint before the shot.
const PAINT: Duration = Duration::from_secs(8);
/// How long to wait for any one DevTools reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(20);
/// How long Chromium may take to close before it is killed.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Screenshots `url` to `out` with Chromium. Best effort: a missing or failing
/// Chromium returns `None` and never blocks the caller for long.
pub fn capture(url: &str, out: &Path) -> Option<String> {
    let chromium = std::env::var_os("CHROMIUM_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/chromium"));
    let _ = std::fs::remove_file(out);

    let profile_dir = super::util::RunDir::new(&std::env::temp_dir(), "chrome").ok()?;
    let profile = profile_dir.path();
    let stderr_log = profile.join("chromium.stderr");
    let stderr = std::fs::File::create(&stderr_log).ok();

    // Pipe pair: Chromium reads our commands on fd 3, writes replies on fd 4.
    let (to_read, to_write) = pipe()?;
    let (from_read, from_write) = pipe()?;
    let child_cmd_fd = to_read.as_raw_fd();
    let child_reply_fd = from_write.as_raw_fd();

    let mut command = Command::new(&chromium);
    command
        .args([
            // New headless has a real compositor; old headless never produces
            // a frame for a network-navigated page, so the screenshot hangs.
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            // A throwaway profile needs no OS keyring. Without these, Chromium
            // asks the desktop's keyring for its cookie key, which pops up an
            // unlock prompt and stalls its network service until answered.
            "--password-store=basic",
            "--use-mock-keychain",
            "--hide-scrollbars",
            "--window-size=1280,900",
            "--remote-debugging-pipe",
            "about:blank",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(match &stderr {
            Some(file) => Stdio::from(file.try_clone().ok()?),
            None => Stdio::null(),
        });
    // SAFETY: dup2 and close are async-signal-safe; the fds are plain i32s
    // copied into the closure before the fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_cmd_fd, 3) < 0 || libc::dup2(child_reply_fd, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().ok()?;
    // The child's ends belong to the child now.
    drop(to_read);
    drop(from_write);

    let result = (|| {
        let mut reader = Reader::new(from_read.as_raw_fd());
        let target = reader.call(
            &to_write,
            1,
            "Target.createTarget",
            &format!("\"url\":{}", json_str(url)),
        )?;
        let target_id = field(&target, "targetId")?;
        let attach = reader.call(
            &to_write,
            2,
            "Target.attachToTarget",
            &format!("\"targetId\":{},\"flatten\":true", json_str(&target_id)),
        )?;
        let session = field(&attach, "sessionId")?;
        // Bring the target to the foreground, or headless composits no frame
        // for it and the screenshot never returns.
        reader.call(
            &to_write,
            3,
            "Target.activateTarget",
            &format!("\"targetId\":{}", json_str(&target_id)),
        )?;
        // Force a viewport so the renderer lays out and composits a frame.
        reader.call_in_session(
            &to_write,
            4,
            &session,
            "Emulation.setDeviceMetricsOverride",
            "\"width\":1280,\"height\":900,\"deviceScaleFactor\":1,\"mobile\":false",
        )?;
        // Let the page connect to the guest's VNC and paint.
        std::thread::sleep(PAINT);
        let shot = reader.call_in_session(
            &to_write,
            5,
            &session,
            "Page.captureScreenshot",
            "\"format\":\"png\"",
        )?;
        let data = field(&shot, "data")?;
        let bytes = crate::kit::b64_decode(&data)?;
        if bytes.len() < 8 || &bytes[1..4] != b"PNG" {
            return None;
        }
        std::fs::write(out, &bytes).ok()?;
        Some(out.display().to_string())
    })();

    // Close the browser over the pipe, so it stops its helper processes and
    // they write nothing to the profile after it is removed. Killing only
    // the browser leaves its network service writing there as it exits.
    let _ = write_all(&to_write, b"{\"id\":6,\"method\":\"Browser.close\"}");
    let closing = Instant::now() + CLOSE_TIMEOUT;
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < closing {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    if result.is_none()
        && let Ok(log) = std::fs::read_to_string(&stderr_log)
    {
        let tail: Vec<&str> = log.lines().rev().take(8).collect();
        if !tail.is_empty() {
            eprintln!(
                "noVNC screenshot: Chromium said: {}",
                tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
            );
        }
    }
    result
}

/// Reads NUL-delimited DevTools replies from fd 4, matching each to its id.
struct Reader {
    fd: RawFd,
    buf: Vec<u8>,
}

impl Reader {
    fn new(fd: RawFd) -> Reader {
        Reader {
            fd,
            buf: Vec::new(),
        }
    }

    /// Sends a command (no session) and returns its `result` object as JSON.
    fn call(&mut self, write: &OwnedFd, id: u64, method: &str, params: &str) -> Option<String> {
        let msg = format!("{{\"id\":{id},\"method\":\"{method}\",\"params\":{{{params}}}}}");
        write_all(write, msg.as_bytes())?;
        self.await_id(id)
    }

    /// Sends a command on a flattened session and returns its `result`.
    fn call_in_session(
        &mut self,
        write: &OwnedFd,
        id: u64,
        session: &str,
        method: &str,
        params: &str,
    ) -> Option<String> {
        let msg = format!(
            "{{\"id\":{id},\"sessionId\":{},\"method\":\"{method}\",\"params\":{{{params}}}}}",
            json_str(session)
        );
        write_all(write, msg.as_bytes())?;
        self.await_id(id)
    }

    /// Reads messages until the one with `id`, returning its `result` object.
    fn await_id(&mut self, id: u64) -> Option<String> {
        let deadline = Instant::now() + REPLY_TIMEOUT;
        loop {
            while let Some(message) = self.next_message() {
                // Skip anything that is not valid JSON or not our reply; the
                // one reply we want carries the matching id and a result.
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&message) else {
                    continue;
                };
                if value.get("id").and_then(|v| v.as_u64()) == Some(id) {
                    return value.get("result").map(|result| result.to_string());
                }
            }
            if Instant::now() >= deadline || !self.fill(deadline)? {
                return None;
            }
        }
    }

    /// Takes the next complete message (up to a NUL) from the buffer.
    fn next_message(&mut self) -> Option<Vec<u8>> {
        let end = self.buf.iter().position(|&b| b == 0)?;
        let message: Vec<u8> = self.buf.drain(..=end).take(end).collect();
        Some(message)
    }

    /// Waits for and reads one chunk; returns false on timeout or EOF.
    fn fill(&mut self, deadline: Instant) -> Option<bool> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || !wait_readable(self.fd, left) {
            return Some(false);
        }
        let mut chunk = [0u8; 16 << 10];
        // SAFETY: reading up to `len` bytes into a valid, owned buffer.
        let n = unsafe {
            libc::read(
                self.fd,
                chunk.as_mut_ptr() as *mut libc::c_void,
                chunk.len(),
            )
        };
        match n {
            0 => Some(false),
            n if n > 0 => {
                self.buf.extend_from_slice(&chunk[..n as usize]);
                Some(true)
            }
            _ => None,
        }
    }
}

/// Extracts a string field from a JSON object rendered as text.
fn field(object: &str, name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(object).ok()?;
    value.get(name)?.as_str().map(str::to_owned)
}

/// Quotes a string as a JSON string literal.
fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_owned()).to_string()
}

/// A close-on-exec pipe, as (read, write).
fn pipe() -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds is a valid two-int array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return None;
    }
    // SAFETY: pipe2 returned two fresh, owned fds.
    unsafe { Some((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Writes all the bytes, then a NUL terminator, to a DevTools pipe.
fn write_all(fd: &OwnedFd, bytes: &[u8]) -> Option<()> {
    let mut all = bytes.to_vec();
    all.push(0);
    let mut written = 0;
    while written < all.len() {
        // SAFETY: writing `len` bytes from a valid slice to an owned fd.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                all[written..].as_ptr() as *const libc::c_void,
                all.len() - written,
            )
        };
        if n <= 0 {
            return None;
        }
        written += n as usize;
    }
    Some(())
}

/// Waits up to `timeout` for the fd to have data to read.
fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: a single valid pollfd.
    unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
}
