//! Read-only smart HTTP over captured bare repositories.

use super::*;
use std::{
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

impl Pages {
    pub(crate) async fn git_request(
        &self,
        cx: &Cx,
        host: &str,
        request: &http::request::Parts,
        body: &[u8],
    ) -> Option<Response> {
        if host != "github.com" {
            return None;
        }
        let path = request.uri.path();
        let mut segments = path.strip_prefix('/')?.split('/');
        let owner = segments.next()?;
        let name = segments.next()?;
        let endpoint = segments.collect::<Vec<_>>().join("/");
        if !matches!(
            endpoint.as_str(),
            "info/refs" | "git-upload-pack" | "git-receive-pack"
        ) {
            return None;
        }
        let name = name.strip_suffix(".git").unwrap_or(name);
        for component in [owner, name] {
            if component.is_empty()
                || matches!(component, "." | "..")
                || !component
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            {
                return None;
            }
        }
        let packages = self.copied.as_ref()?.packages.as_ref()?;
        let root = &packages.git;
        let repository = root.join(owner).join(format!("{name}.git"));
        if !repository.is_dir() {
            return None;
        }
        // No CGI input may choose another repository or a file outside the capture.
        let repository = std::fs::canonicalize(repository).ok()?;
        if !repository.starts_with(std::fs::canonicalize(root).ok()?) {
            return None;
        }
        let mut backend_request = http::Request::new(body.to_vec());
        *backend_request.method_mut() = request.method.clone();
        *backend_request.uri_mut() = request.uri.clone();
        *backend_request.headers_mut() = request.headers.clone();
        let response = cx
            .race(
                Some(cx.now() + Duration::from_secs(30)),
                backend(repository.join(endpoint), backend_request),
            )
            .await;
        Some(match response {
            Ok(Ok(response)) => replay(Ok(Some(response))),
            _ => Response::new(
                502,
                "text/plain; charset=utf-8",
                "Bad Gateway",
                vec![],
                Meta::Missing,
            ),
        })
    }
}

async fn backend(
    path: PathBuf,
    request: http::Request<Vec<u8>>,
) -> std::io::Result<fictionet_extras::warc::Response> {
    let (request, body) = request.into_parts();
    let mut command = Command::new("git");
    command
        .env_clear()
        .args([
            "-c",
            "http.receivepack=false",
            "-c",
            "http.getanyfile=false",
            "-c",
            "http.uploadarchive=false",
            "http-backend",
        ])
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", request.method.as_str())
        .env("PATH_TRANSLATED", path)
        .env("QUERY_STRING", request.uri.query().unwrap_or_default())
        .env("CONTENT_LENGTH", body.len().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (header, variable) in [
        ("git-protocol", "GIT_PROTOCOL"),
        ("content-type", "CONTENT_TYPE"),
        ("content-encoding", "HTTP_CONTENT_ENCODING"),
    ] {
        if let Some(value) = request
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok())
        {
            command.env(variable, value);
        }
    }
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    struct Permit;
    impl Drop for Permit {
        fn drop(&mut self) {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
    ACTIVE
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < 4).then_some(n + 1)
        })
        .map_err(|_| std::io::Error::other("Git backend is busy"))?;
    let permit = Permit;
    command.process_group(0);
    let process = Backend(command.spawn()?);
    let (cancel, stopped) = UnixStream::pair()?;
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _permit = permit;
        let _ = send.send(process.exchange(&body, stopped, Duration::from_secs(30)));
    });
    // Dropping the future closes the socket and wakes the owned process worker.
    let output = receive
        .await
        .map_err(|_| std::io::Error::other("Git backend stopped"))??;
    drop(cancel);
    let end = output
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("missing CGI headers"))?;
    let head = std::str::from_utf8(&output[..end]).map_err(std::io::Error::other)?;
    let mut status = http::StatusCode::OK;
    let mut headers = http::HeaderMap::new();
    for line in head.lines() {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::other("invalid CGI header"))?;
        if name.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .unwrap_or("")
                .parse()
                .map_err(std::io::Error::other)?;
        } else {
            headers.append(
                name.parse::<http::HeaderName>()
                    .map_err(std::io::Error::other)?,
                value.trim().parse().map_err(std::io::Error::other)?,
            );
        }
    }
    let body = bytes::Bytes::copy_from_slice(&output[end + 4..]);
    headers.insert(http::header::CONTENT_LENGTH, body.len().into());
    Ok(fictionet_extras::warc::Response {
        status,
        headers,
        body,
    })
}

struct Backend(std::process::Child);
impl Drop for Backend {
    fn drop(&mut self) {
        // SAFETY: this child was started in its own process group.
        unsafe {
            libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}
impl Backend {
    fn exchange(
        mut self,
        body: &[u8],
        cancelled: UnixStream,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let input = self.0.stdin.take().expect("piped backend input");
        let mut output = self.0.stdout.take().expect("piped backend output");
        for fd in [input.as_raw_fd(), output.as_raw_fd()] {
            // SAFETY: these are owned, open pipe descriptors.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        let mut input = Some(input);
        let mut written = 0;
        let mut bytes = Vec::new();
        let mut eof = false;
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Git backend timed out",
                ));
            }
            let mut poll = [
                libc::pollfd {
                    fd: cancelled.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if eof { -1 } else { output.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: input.as_ref().map_or(-1, |pipe| pipe.as_raw_fd()),
                    events: libc::POLLOUT,
                    revents: 0,
                },
            ];
            // SAFETY: poll receives a valid array of owned descriptors.
            if unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as _, 25) } < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if poll[0].revents != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Git request cancelled",
                ));
            }
            if poll[2].revents != 0
                && let Some(pipe) = input.as_mut()
            {
                match pipe.write(&body[written..]) {
                    Ok(n) => {
                        written += n;
                        if written == body.len() {
                            input = None;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => input = None,
                    Err(error) => return Err(error),
                }
            }
            if eof && let Some(status) = self.0.try_wait()? {
                return if status.success() {
                    Ok(bytes)
                } else {
                    Err(std::io::Error::other("Git backend failed"))
                };
            }
            if poll[1].revents != 0 {
                let mut chunk = [0u8; 16384];
                match output.read(&mut chunk) {
                    Ok(0) => {
                        eof = true;
                        if let Some(status) = self.0.try_wait()? {
                            return if status.success() {
                                Ok(bytes)
                            } else {
                                Err(std::io::Error::other("Git backend failed"))
                            };
                        }
                    }
                    Ok(n) => {
                        if bytes.len() + n > PACKAGE_BYTES {
                            return Err(std::io::Error::other("Git response exceeds size limit"));
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
}
