//! Chromium screenshots after an explicit page readiness condition.

use fictionet::stdlib::codec::base64;
use serde_json::{Value, json};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REPLY_TIMEOUT: Duration = Duration::from_secs(20);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// A grid sample of a visible canvas must contain at least sixteen colors.
/// The expression must evaluate to a canvas element, or null while loading.
pub fn canvas_painted(canvas: &str) -> String {
    format!(
        r#"(() => {{
        const canvas = ({canvas});
        if (!canvas || !canvas.width || !canvas.height || !canvas.getClientRects().length) return false;
        const context = canvas.getContext('2d');
        if (!context) return false;
        const colors = new Set();
        for (let y = 0; y < 32; y++) for (let x = 0; x < 32; x++) {{
            const p = context.getImageData(Math.floor(x * canvas.width / 32), Math.floor(y * canvas.height / 32), 1, 1).data;
            colors.add(Array.from(p).join(','));
        }}
        return colors.size >= 16;
    }})()"#
    )
}

/// The named host's workspace screen is visible, its status card is hidden,
/// and its noVNC canvas contains at least sixteen colors.
pub fn desktop_painted(host: &str) -> String {
    let host = json!(host);
    canvas_painted(&format!(
        r#"(() => {{
        const tile = [...document.querySelectorAll('.workspace-tile')].find(t => t.getAttribute('aria-label') === {host})
            || document.querySelector('.demo-app .app-stage[data-kind="screen"]');
        return tile?.querySelector('.console-card')?.hidden ? tile.querySelector('.screen-display canvas') : null;
    }})()"#
    ))
}

/// One page action and optional capture after a readiness condition.
#[derive(Default)]
pub struct Step<'a> {
    pub ready: &'a str,
    pub action: Option<&'a str>,
    pub color_scheme: Option<&'a str>,
    pub out: Option<&'a Path>,
}

/// Runs steps in one 1440 by 900 Chromium viewport.
/// The timeout bounds navigation and readiness. Errors include the condition,
/// Chromium's stderr tail, and collected JavaScript exceptions.
pub fn capture(url: &str, steps: &[Step<'_>], timeout: Duration) -> io::Result<()> {
    let mut condition = "";
    let profile_dir = super::util::RunDir::new(&std::env::temp_dir(), "chrome")?;
    let profile = profile_dir.path();
    let stderr_log = profile.join("chromium.stderr");
    let stderr = std::fs::File::create(&stderr_log)?;
    // Pipe pair: Chromium reads our commands on fd 3, writes replies on fd 4.
    let (to_read, to_write) = pipe().ok_or_else(std::io::Error::last_os_error)?;
    let (from_read, from_write) = pipe().ok_or_else(std::io::Error::last_os_error)?;
    let child_cmd_fd = to_read.as_raw_fd();
    let child_reply_fd = from_write.as_raw_fd();

    let mut command = Command::new("chromium");
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
            "--window-size=1440,900",
            "--remote-debugging-pipe",
            "--no-startup-window",
        ])
        .arg(format!("--user-data-dir={}", profile.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    devtools_pipe(&mut command, child_cmd_fd, child_reply_fd);
    let mut child = command.spawn()?;
    // The child's ends belong to the child now.
    drop(to_read);
    drop(from_write);

    let mut reader = Reader::new(from_read.as_raw_fd());
    let result = (|| {
        let targets = reader.call(&to_write, None, "Target.getTargets", json!({}))?;
        let target_id = match targets["targetInfos"]
            .as_array()
            .and_then(|targets| targets.iter().find(|target| target["type"] == "page"))
        {
            Some(target) => string_field(target, "targetId")?,
            None => {
                let target = reader.call(
                    &to_write,
                    None,
                    "Target.createTarget",
                    json!({"url":"about:blank"}),
                )?;
                string_field(&target, "targetId")?
            }
        };
        let attach = reader.call(
            &to_write,
            None,
            "Target.attachToTarget",
            json!({"targetId":target_id,"flatten":true}),
        )?;
        let session = string_field(&attach, "sessionId")?;
        reader.call(
            &to_write,
            None,
            "Target.activateTarget",
            json!({"targetId":target_id}),
        )?;
        reader.call(
            &to_write,
            Some(&session),
            "Emulation.setDeviceMetricsOverride",
            json!({"width":1440,"height":900,"deviceScaleFactor":1,"mobile":false}),
        )?;
        reader.call(&to_write, Some(&session), "Runtime.enable", json!({}))?;
        reader.call(
            &to_write,
            Some(&session),
            "Page.navigate",
            json!({"url":url}),
        )?;
        for step in steps {
            condition = step.ready;
            if let Some(scheme) = step.color_scheme {
                reader.call(
                    &to_write,
                    Some(&session),
                    "Emulation.setEmulatedMedia",
                    json!({"features":[{"name":"prefers-color-scheme","value":scheme}]}),
                )?;
            }
            reader.deadline = Some(Instant::now() + timeout);
            loop {
                let value = match reader.call(
                    &to_write,
                    Some(&session),
                    "Runtime.evaluate",
                    json!({"expression":condition,"returnByValue":true}),
                ) {
                    // The page is between documents; the condition is evaluated
                    // again once the new document's context exists.
                    Err(error) if navigating(&error) => Value::Null,
                    result => result?,
                };
                if let Some(exception) = value.get("exceptionDetails") {
                    return Err(io::Error::other(format!("page readiness: {exception}")));
                }
                if value.pointer("/result/value") == Some(&Value::Bool(true)) {
                    break;
                }
                let left = reader
                    .deadline
                    .unwrap()
                    .saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "page readiness timed out",
                    ));
                }
                std::thread::sleep(left.min(Duration::from_millis(100)));
            }
            reader.deadline = None;
            if let Some(action) = step.action {
                let value = reader.call(
                    &to_write,
                    Some(&session),
                    "Runtime.evaluate",
                    json!({"expression":action,"returnByValue":true,"awaitPromise":true}),
                )?;
                if let Some(exception) = value.get("exceptionDetails") {
                    return Err(io::Error::other(format!("page action: {exception}")));
                }
            }
            let Some(out) = step.out else { continue };
            let shot = reader.call(
                &to_write,
                Some(&session),
                "Page.captureScreenshot",
                json!({"format":"png"}),
            )?;
            let data = string_field(&shot, "data")?;
            let bytes = base64::decode(data.as_bytes(), base64::Padding::Required)
                .ok_or_else(|| io::Error::other("invalid screenshot base64"))?;
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err(io::Error::other("Chromium returned no PNG"));
            }
            std::fs::write(out, &bytes)?;
        }
        Ok(())
    })();
    // Closing over CDP lets Chromium reap its helpers before removing the profile.
    let _ = write_all(&to_write, b"{\"id\":0,\"method\":\"Browser.close\"}");
    let closing = Instant::now() + CLOSE_TIMEOUT;
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < closing {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    result.map_err(|error| {
        let log = std::fs::read_to_string(stderr_log).unwrap_or_default();
        let lines: Vec<_> = log.lines().rev().take(12).collect();
        io::Error::new(
            error.kind(),
            format!(
                "{error}; condition: {condition}; page exceptions: {}; Chromium stderr tail: {}",
                reader.exceptions.join(" | "),
                lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
            ),
        )
    })
}

/// A Chromium app window on a page, opened over the DevTools pipe so the
/// page's address and token never appear on a command line. The window
/// closes when this is dropped.
pub struct AppWindow {
    child: std::process::Child,
    commands: OwnedFd,
    _replies: OwnedFd,
    _profile: super::util::RunDir,
}

impl AppWindow {
    /// Opens `url` in a new Chromium app window with its own profile.
    pub fn open(url: &str) -> io::Result<Self> {
        let profile = super::util::RunDir::new(&std::env::temp_dir(), "app")?;
        let (to_read, to_write) = pipe().ok_or_else(std::io::Error::last_os_error)?;
        let (from_read, from_write) = pipe().ok_or_else(std::io::Error::last_os_error)?;
        let (child_cmd_fd, child_reply_fd) = (to_read.as_raw_fd(), from_write.as_raw_fd());
        let mut command = Command::new("chromium");
        command
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
                "--password-store=basic",
                "--use-mock-keychain",
                "--window-size=1440,900",
                "--remote-debugging-pipe",
                // An app window needs an http, https, file or data address
                // to start on; with about:blank it is an ordinary window.
                "--app=data:text/html,",
            ])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        devtools_pipe(&mut command, child_cmd_fd, child_reply_fd);
        let mut child = command.spawn()?;
        drop(to_read);
        drop(from_write);
        let mut reader = Reader::new(from_read.as_raw_fd());
        let opened = (|| {
            let targets = reader.call(&to_write, None, "Target.getTargets", json!({}))?;
            let target = targets["targetInfos"]
                .as_array()
                .and_then(|targets| targets.iter().find(|target| target["type"] == "page"))
                .ok_or_else(|| io::Error::other("Chromium opened no window"))?;
            let attach = reader.call(
                &to_write,
                None,
                "Target.attachToTarget",
                json!({"targetId": string_field(target, "targetId")?, "flatten": true}),
            )?;
            let session = string_field(&attach, "sessionId")?;
            reader.call(
                &to_write,
                Some(&session),
                "Page.navigate",
                json!({"url": url}),
            )?;
            Ok(())
        })();
        if let Err(error) = opened {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(Self {
            child,
            commands: to_write,
            _replies: from_read,
            _profile: profile,
        })
    }
}

impl AppWindow {
    /// Whether the window has been closed.
    pub fn closed(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_some())
    }
}

impl Drop for AppWindow {
    fn drop(&mut self) {
        let _ = write_all(&self.commands, b"{\"id\":0,\"method\":\"Browser.close\"}");
        let closing = Instant::now() + CLOSE_TIMEOUT;
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < closing {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Gives Chromium its DevTools pipe: `commands` as fd 3 and `replies` as
/// fd 4. Both are first copied above 4, so neither is overwritten by the
/// other, and a pipe that is already fd 3 or 4 loses its close-on-exec flag
/// too, as `dup2` onto a different fd does.
fn devtools_pipe(command: &mut Command, commands: RawFd, replies: RawFd) {
    // SAFETY: fcntl and dup2 are async-signal-safe; the fds are plain i32s
    // copied into the closure before the fork.
    unsafe {
        command.pre_exec(move || {
            let commands = libc::fcntl(commands, libc::F_DUPFD_CLOEXEC, 5);
            let replies = libc::fcntl(replies, libc::F_DUPFD_CLOEXEC, 5);
            if commands < 0
                || replies < 0
                || libc::dup2(commands, 3) < 0
                || libc::dup2(replies, 4) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Whether Chromium refused an evaluation because a navigation is replacing
/// the page's execution context.
fn navigating(error: &io::Error) -> bool {
    let text = error.to_string();
    text.contains("Cannot find default execution context")
        || text.contains("Execution context was destroyed")
}

struct Reader {
    fd: RawFd,
    buf: Vec<u8>,
    id: u64,
    deadline: Option<Instant>,
    exceptions: Vec<String>,
}
impl Reader {
    fn new(fd: RawFd) -> Self {
        Self {
            fd,
            buf: Vec::new(),
            id: 0,
            deadline: None,
            exceptions: Vec::new(),
        }
    }
    fn exception(&mut self, value: &Value) {
        if self.exceptions.len() == 16 {
            self.exceptions.remove(0);
        }
        self.exceptions.push(value.to_string());
    }
    fn call(
        &mut self,
        write: &OwnedFd,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> io::Result<Value> {
        self.id += 1;
        let mut message = json!({"id":self.id,"method":method,"params":params});
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        write_all(write, message.to_string().as_bytes()).ok_or_else(io::Error::last_os_error)?;
        let deadline = self
            .deadline
            .unwrap_or_else(|| Instant::now() + REPLY_TIMEOUT);
        loop {
            while let Some(end) = self.buf.iter().position(|&b| b == 0) {
                let message: Vec<_> = self.buf.drain(..=end).take(end).collect();
                let value: Value = serde_json::from_slice(&message)?;
                if value["method"] == "Runtime.exceptionThrown" {
                    self.exception(&value["params"]);
                }
                if value["id"].as_u64() == Some(self.id) {
                    return value
                        .get("result")
                        .cloned()
                        .ok_or_else(|| io::Error::other(format!("{method}: {}", value["error"])));
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !wait_readable(self.fd, left) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for {method}"),
                ));
            }
            let mut chunk = [0u8; 16 << 10];
            // SAFETY: reading into a valid owned buffer from the DevTools pipe.
            let n = unsafe { libc::read(self.fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Chromium closed the DevTools pipe",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n as usize]);
        }
    }
}
fn string_field(value: &Value, name: &str) -> io::Result<String> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("CDP reply has no {name}: {value}")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn only_a_replaced_context_is_waited_out() {
        let refusal = |message: &str| {
            io::Error::other(format!(
                "Runtime.evaluate: {}",
                json!({"code":-32000,"message":message})
            ))
        };
        assert!(navigating(&refusal(
            "Cannot find default execution context"
        )));
        assert!(navigating(&refusal("Execution context was destroyed.")));
        assert!(!navigating(&refusal("Object reference chain is too long")));
        assert!(!navigating(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for Runtime.evaluate"
        )));
    }

    #[tokio::test]
    async fn waits_for_canvas_paint_and_reports_a_condition_timeout() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}/#token=test", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let body = r#"<canvas width="64" height="64"></canvas><script>
                        window.painted = false;
                        setTimeout(() => {
                            const c = document.querySelector('canvas').getContext('2d');
                            for (let y=0;y<64;y++) for (let x=0;x<64;x++) {
                                c.fillStyle = `rgb(${x*4},${y*4},${x^y})`; c.fillRect(x,y,1,1);
                            }
                            window.painted = true;
                        }, 500);
                        setTimeout(() => { throw new Error('page diagnostic'); }, 50);
                    </script>"#;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        let result = tokio::task::spawn_blocking(move || {
            let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "shot").unwrap();
            let out = dir.path().join("canvas.png");
            let condition = format!(
                "window.painted && ({})",
                canvas_painted("document.querySelector('canvas')")
            );
            capture(
                &url,
                &[Step {
                    ready: &condition,
                    out: Some(&out),
                    ..Default::default()
                }],
                Duration::from_secs(10),
            )
            .unwrap();
            assert!(
                std::fs::read(&out)
                    .unwrap()
                    .starts_with(b"\x89PNG\r\n\x1a\n")
            );
            let dark = dir.path().join("dark.png");
            let error = capture(
                &url,
                &[
                    Step {
                        ready: "window.painted === true",
                        action: Some("if (!matchMedia('(prefers-color-scheme: light)').matches) throw new Error('light scheme'); window.steps = 1"),
                        color_scheme: Some("light"),
                        out: Some(&out),
                    },
                    Step {
                        ready: "window.steps === 1 && matchMedia('(prefers-color-scheme: dark)').matches",
                        action: Some("if (innerWidth !== 1440 || innerHeight !== 900) throw new Error('viewport'); window.steps++"),
                        color_scheme: Some("dark"),
                        out: Some(&dark),
                    },
                    Step {
                        ready: "window.steps === 2",
                        action: Some("throw new Error('action diagnostic')"),
                        ..Default::default()
                    },
                ],
                Duration::from_secs(10),
            ).unwrap_err();
            assert!(error.to_string().contains("action diagnostic"), "{error}");
            assert!(std::fs::read(&dark).unwrap().starts_with(b"\x89PNG\r\n\x1a\n"));
            let error = capture(
                &url,
                &[Step {
                    ready: "window.neverReady === true",
                    out: Some(&out),
                    ..Default::default()
                }],
                Duration::from_secs(2),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            for text in [
                "window.neverReady === true",
                "Chromium stderr tail",
                "page diagnostic",
            ] {
                assert!(error.to_string().contains(text), "{error}");
            }
        })
        .await;
        server.abort();
        result.unwrap();
    }
}
