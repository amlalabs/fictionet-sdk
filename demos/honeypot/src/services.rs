//! What the server says once a connection is open: an OpenSSH
//! identification and key exchange proposal, or a packaged HTTP site.
//! The packet log keeps whatever the client sends; SSH never authenticates
//! or executes commands.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::codec::{Fail, Stream, Wire};
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::protocols::http1::{self, Event, RequestEvents};
use fictionet::stdlib::protocols::ssh;
use fictionet::stdlib::web::httpd::http_date;
use fictionet::stdlib::world::net::{Arrival, PortServer};

use crate::{Clock, HttpProfile};

/// The identification line of OpenSSH on Ubuntu 24.04 (RFC 4253 section
/// 4.2).
pub const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n";

/// OpenSSH's `LoginGraceTime`: how long sshd keeps a connection that has
/// not logged in.
pub const LOGIN_GRACE: Duration = Duration::from_secs(120);

/// Caddy's and nginx's request-header deadline. Caddy also uses this
/// duration for its rolling body-read and response-write inactivity limits.
/// Caddy 2.11.9 sets these defaults in `modules/caddyhttp/app.go`.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// The maximum complete request head retained by this service.
/// nginx permits several large header buffers; this service caps the total.
pub const HEADER_LIMIT: usize = 8 * 1024;

/// nginx's built-in keepalive timeout, unchanged by Ubuntu 24.04's configuration.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);

/// nginx's maximum number of requests on one connection.
pub const KEEPALIVE_REQUESTS: usize = 1000;

/// Caddy's built-in `IdleTimeout` from `modules/caddyhttp/app.go`.
pub const CADDY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Go's `net/http/server.go` default maximum request head, including its
/// read buffer allowance.
const CADDY_HEADER_LIMIT: usize = (1 << 20) + 4096;

/// The official Caddy package's unmodified welcome page, measured with
/// Caddy 2.11.9 on Ubuntu 24.04.
const CADDY_WELCOME: &str = include_str!("caddy.html");

/// The body of nginx's default page on Ubuntu.
const WELCOME: &str = "<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href=\"http://nginx.org/\">nginx.org</a>.<br/>
Commercial support is available at
<a href=\"http://nginx.com/\">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
";

/// The body nginx sends with a 400.
const BAD_REQUEST: &str = "<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
</body>
</html>
";

/// The body nginx sends when a static file is absent.
const NOT_FOUND: &str = "<html>\r\n\
<head><title>404 Not Found</title></head>\r\n\
<body>\r\n\
<center><h1>404 Not Found</h1></center>\r\n\
<hr><center>nginx/1.24.0 (Ubuntu)</center>\r\n\
</body>\r\n\
</html>\r\n";

enum Page {
    Welcome,
    NotFound,
    BadRequest,
    HeaderTooLarge,
    MethodNotAllowed,
}

impl Page {
    fn response(&self, date: &str, modified: u64, keep_alive: bool, head_only: bool) -> String {
        let (status, body) = match self {
            Self::Welcome => ("200 OK", WELCOME),
            Self::NotFound => ("404 Not Found", NOT_FOUND),
            Self::BadRequest | Self::HeaderTooLarge | Self::MethodNotAllowed => {
                ("400 Bad Request", BAD_REQUEST)
            }
        };
        let connection = if keep_alive { "keep-alive" } else { "close" };
        let mut response = format!(
            "HTTP/1.1 {status}\r\nServer: nginx/1.24.0 (Ubuntu)\r\nDate: {date}\r\n\
             Content-Type: text/html\r\nContent-Length: {}\r\n",
            body.len()
        );
        if matches!(self, Self::Welcome) {
            response.push_str(&format!("Last-Modified: {}\r\n", http_date(modified)));
        }
        response.push_str(&format!("Connection: {connection}\r\n"));
        if matches!(self, Self::Welcome) {
            response.push_str(&format!(
                "ETag: \"{modified:x}-{:x}\"\r\nAccept-Ranges: bytes\r\n",
                body.len()
            ));
        }
        response.push_str("\r\n");
        if !head_only {
            response.push_str(body);
        }
        response
    }

    fn caddy_response(
        &self,
        date: &str,
        keep_alive: bool,
        head_only: bool,
        http10: bool,
    ) -> String {
        let (status, body) = match self {
            Self::Welcome => ("200 OK", CADDY_WELCOME),
            Self::NotFound => ("404 Not Found", ""),
            Self::MethodNotAllowed => ("405 Method Not Allowed", ""),
            Self::BadRequest => ("400 Bad Request", "400 Bad Request"),
            Self::HeaderTooLarge => (
                "431 Request Header Fields Too Large",
                "431 Request Header Fields Too Large",
            ),
        };
        if matches!(self, Self::BadRequest | Self::HeaderTooLarge) {
            return format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{body}"
            );
        }
        let version = if http10 { "HTTP/1.0" } else { "HTTP/1.1" };
        let mut response = format!("{version} {status}\r\n");
        if matches!(self, Self::Welcome) {
            // File metadata from the official Caddy package, independent of
            // the simulated host's boot time.
            response.push_str(&format!("Accept-Ranges: bytes\r\nContent-Length: {}\r\nContent-Type: text/html; charset=utf-8\r\nEtag: \"dmmvf07hm0ow-egx\"\r\nLast-Modified: Thu, 05 Nov 2026 01:03:05 GMT\r\n", body.len()));
        } else if matches!(self, Self::MethodNotAllowed) {
            response.push_str("Allow: GET, HEAD\r\n");
        }
        response.push_str("Server: Caddy\r\n");
        if matches!(self, Self::Welcome) {
            response.push_str("Vary: Accept-Encoding\r\n");
        }
        response.push_str(&format!("Date: {date}\r\n"));
        if !matches!(self, Self::Welcome) {
            response.push_str("Content-Length: 0\r\n");
        }
        if !keep_alive && !http10 {
            response.push_str("Connection: close\r\n");
        } else if keep_alive && http10 {
            response.push_str("Connection: keep-alive\r\n");
        }
        response.push_str("\r\n");
        if !head_only {
            response.push_str(body);
        }
        response
    }
}

/// SSH: the identification line and key exchange proposal, then reads
/// until the client goes or [`LOGIN_GRACE`] passes. Key exchange and
/// authentication are not implemented. No keepalives: sshd asks for them,
/// but on Linux the first comes after two hours idle (`tcp_keepalive_time`),
/// long after the grace time ends the connection.
pub struct Ssh;

fn ssh_proposal() -> ssh::KexInit {
    let names = |values: &[&str]| {
        values
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    };
    let encryption = names(&[
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    ]);
    let mac = names(&[
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    ]);
    let compression = names(&["none", "zlib@openssh.com"]);
    ssh::KexInit {
        kex_algorithms: names(&[
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
            "ext-info-s",
            "kex-strict-s-v00@openssh.com",
        ]),
        server_host_key_algorithms: names(&[
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
        ]),
        encryption_client_to_server: encryption.clone(),
        encryption_server_to_client: encryption,
        mac_client_to_server: mac.clone(),
        mac_server_to_client: mac,
        compression_client_to_server: compression.clone(),
        compression_server_to_client: compression,
        ..ssh::KexInit::default()
    }
}

impl PortServer for Ssh {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        arrival.socket.set_keep_alive(None);
        let mut conn = arrival.conn;
        Box::pin(async move {
            let deadline = fcx.now() + LOGIN_GRACE;
            if conn.write_all(&fcx, SSH_BANNER).await.is_err() {
                return;
            }
            let mut input = Stream::new(ssh::Events::new());
            loop {
                match input.next() {
                    Some(Ok(ssh::Event::Version(version))) => {
                        if !matches!(version.proto(), "2.0" | "1.99") {
                            return;
                        }
                        break;
                    }
                    Some(_) => return,
                    None => match fcx
                        .race(Some(deadline), conn.read(&fcx, input.spare()))
                        .await
                    {
                        Ok(Ok(n @ 1..)) => input.commit(n),
                        _ => return,
                    },
                }
            }
            let mut proposal = ssh_proposal();
            fcx.fill_random(&mut proposal.cookie);
            let packet = ssh::Packet::from_message(&ssh::Message::KexInit(proposal))
                .expect("the server's SSH proposal is valid");
            if conn
                .write_all(&fcx, &packet.to_bytes().expect("valid SSH packet"))
                .await
                .is_err()
            {
                return;
            }
            let mut buf = [0; 4096];
            while let Ok(Ok(1..)) = fcx.race(Some(deadline), conn.read(&fcx, &mut buf)).await {}
        })
    }

    fn backlog(&self) -> Option<usize> {
        // Ubuntu 24.04's systemd ssh.socket owns the listener; the kernel's
        // net.core.somaxconn caps its backlog at 4096, as measured with ss.
        Some(4096)
    }
}

/// HTTP with the selected server's packaged page and connection defaults.
pub struct Http {
    /// The wall clock, for the `Date` header.
    pub clock: Clock,
    /// The packaged server to emulate.
    pub profile: HttpProfile,
}

impl PortServer for Http {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let profile = self.profile;
        arrival.socket.set_keep_alive(match profile {
            // Go's net.defaultTCPKeepAliveIdle, used by Caddy's ListenConfig.
            HttpProfile::Caddy => Some(Duration::from_secs(15)),
            HttpProfile::Nginx => None,
        });
        let mut conn = arrival.conn;
        let clock = self.clock;
        Box::pin(async move {
            let head_limit = match profile {
                HttpProfile::Caddy => CADDY_HEADER_LIMIT,
                HttpProfile::Nginx => HEADER_LIMIT,
            };
            let mut input = Stream::new(RequestEvents::with_limits(http1::Limits {
                head: head_limit,
                start_line: head_limit,
                header_line: head_limit,
                headers: if profile == HttpProfile::Caddy {
                    500
                } else {
                    usize::MAX
                },
                ..http1::Limits::default()
            }));
            let mut deadline = Some(fcx.now() + HEADER_TIMEOUT);
            let mut idle = false;
            let mut request = None;
            let mut requests = 0;
            loop {
                let (page, keep_alive, head_only, http10) = match input.next() {
                    Some(Ok(Event::Head(head))) => {
                        if head.expects_continue()
                            && conn
                                .write_all(&fcx, b"HTTP/1.1 100 Continue\r\n\r\n")
                                .await
                                .is_err()
                        {
                            return;
                        }
                        request = Some(head);
                        deadline = Some(fcx.now() + HEADER_TIMEOUT);
                        continue;
                    }
                    Some(Ok(Event::Body(_))) => continue,
                    Some(Ok(Event::Done)) => {
                        let head = request.take().expect("a request head precedes its body");
                        requests += 1;
                        let page = match (profile, head.target.split('?').next()) {
                            (HttpProfile::Caddy, Some("/" | "/index.html"))
                                if !matches!(head.method.as_str(), "GET" | "HEAD") =>
                            {
                                Page::MethodNotAllowed
                            }
                            (HttpProfile::Caddy, Some("/" | "/index.html"))
                            | (HttpProfile::Nginx, Some("/" | "/index.nginx-debian.html")) => {
                                Page::Welcome
                            }
                            _ => Page::NotFound,
                        };
                        (
                            page,
                            head.keep_alive().unwrap_or(false)
                                && (profile == HttpProfile::Caddy || requests < KEEPALIVE_REQUESTS),
                            head.method == "HEAD",
                            head.version == http1::Version::Http10,
                        )
                    }
                    Some(Err(error)) => {
                        let page = match error {
                            Fail::Protocol(http1::RequestError::Parse(
                                http1::Error::HeadTooLong
                                | http1::Error::HeaderLineTooLong
                                | http1::Error::StartLineTooLong,
                            )) => Page::HeaderTooLarge,
                            _ => Page::BadRequest,
                        };
                        (page, false, false, false)
                    }
                    None => {
                        match fcx.race(deadline, conn.read(&fcx, input.spare())).await {
                            Ok(Ok(n @ 1..)) => {
                                input.commit(n);
                                if profile == HttpProfile::Caddy && request.is_some() {
                                    deadline = Some(fcx.now() + HEADER_TIMEOUT);
                                }
                                if idle && (profile == HttpProfile::Nginx || input.buffered() >= 4)
                                {
                                    idle = false;
                                    deadline = Some(fcx.now() + HEADER_TIMEOUT);
                                }
                            }
                            _ => return,
                        }
                        continue;
                    }
                };
                let date = http_date(clock.unix_secs(fcx.now()));
                let modified = clock.unix_secs(fictionet::time::Instant::ZERO);
                let response = match profile {
                    HttpProfile::Caddy => page.caddy_response(&date, keep_alive, head_only, http10),
                    HttpProfile::Nginx => page.response(&date, modified, keep_alive, head_only),
                };
                let mut remaining = response.as_bytes();
                let mut write_deadline = fcx.now() + HEADER_TIMEOUT;
                while !remaining.is_empty() {
                    match fcx
                        .race(Some(write_deadline), conn.write(&fcx, remaining))
                        .await
                    {
                        Ok(Ok(n @ 1..)) => {
                            remaining = &remaining[n..];
                            if profile == HttpProfile::Caddy {
                                write_deadline = fcx.now() + HEADER_TIMEOUT;
                            }
                        }
                        _ => return,
                    }
                }
                if !keep_alive {
                    break;
                }
                idle = input.buffered() < if profile == HttpProfile::Caddy { 4 } else { 1 };
                deadline = Some(
                    fcx.now()
                        + if idle {
                            match profile {
                                HttpProfile::Caddy => CADDY_IDLE_TIMEOUT,
                                HttpProfile::Nginx => KEEPALIVE_TIMEOUT,
                            }
                        } else {
                            HEADER_TIMEOUT
                        },
                );
            }
            let _ = conn.shutdown(&fcx).await;
            if profile == HttpProfile::Caddy {
                return;
            }
            // Bytes the client sends after the request are read, so the
            // close is a FIN and not a RST.
            let mut buf = [0; 4096];
            while let Ok(Ok(1..)) = fcx.race(deadline, conn.read(&fcx, &mut buf)).await {}
        })
    }

    fn backlog(&self) -> Option<usize> {
        Some(match self.profile {
            // Go reads net.core.somaxconn, which is 4096 on Ubuntu 24.04.
            HttpProfile::Caddy => 4096,
            // nginx's built-in listen backlog on Linux.
            HttpProfile::Nginx => 511,
        })
    }
}
