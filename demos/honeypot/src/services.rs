//! What the server says once a connection is open: an OpenSSH
//! identification and key exchange proposal, or nginx's default page.
//! The packet log keeps whatever the client sends; SSH never authenticates
//! or executes commands.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::protocols::http1::{self, Event, RequestEvents};
use fictionet::stdlib::protocols::ssh;
use fictionet::stdlib::web::httpd::http_date;
use fictionet::stdlib::world::net::{Arrival, PortServer};

use crate::Clock;

/// The identification line of OpenSSH on Ubuntu 24.04 (RFC 4253 section
/// 4.2).
pub const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n";

/// OpenSSH's `LoginGraceTime`: how long sshd keeps a connection that has
/// not logged in.
pub const LOGIN_GRACE: Duration = Duration::from_secs(120);

/// nginx's `client_header_timeout`: how long it waits for a request's head.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// The maximum complete request head retained by this service.
/// nginx permits several large header buffers; this service caps the total.
pub const HEADER_LIMIT: usize = 8 * 1024;

/// Idle time between requests on a persistent connection.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(65);

/// nginx's maximum number of requests on one connection.
pub const KEEPALIVE_REQUESTS: usize = 1000;

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
}

impl Page {
    fn response(&self, date: &str, modified: u64, keep_alive: bool, head_only: bool) -> String {
        let (status, body) = match self {
            Self::Welcome => ("200 OK", WELCOME),
            Self::NotFound => ("404 Not Found", NOT_FOUND),
            Self::BadRequest => ("400 Bad Request", BAD_REQUEST),
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
        Some(128)
    }
}

/// HTTP: nginx's default page, with persistent connections and bounded
/// request framing. TCP keepalives remain disabled, as in nginx.
pub struct Http {
    /// The wall clock, for the `Date` header.
    pub clock: Clock,
}

impl PortServer for Http {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        arrival.socket.set_keep_alive(None);
        let mut conn = arrival.conn;
        let clock = self.clock;
        Box::pin(async move {
            let mut input = Stream::new(RequestEvents::with_limits(http1::Limits {
                head: HEADER_LIMIT,
                ..http1::Limits::default()
            }));
            let mut deadline = fcx.now() + HEADER_TIMEOUT;
            let mut idle = false;
            let mut request = None;
            let mut requests = 0;
            loop {
                let (page, keep_alive, head_only) = match input.next() {
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
                        deadline = fcx.now() + HEADER_TIMEOUT;
                        continue;
                    }
                    Some(Ok(Event::Body(_))) => continue,
                    Some(Ok(Event::Done)) => {
                        let head = request.take().expect("a request head precedes its body");
                        requests += 1;
                        let page = match head.target.split('?').next() {
                            Some("/" | "/index.nginx-debian.html") => Page::Welcome,
                            _ => Page::NotFound,
                        };
                        (
                            page,
                            head.keep_alive().unwrap_or(false) && requests < KEEPALIVE_REQUESTS,
                            head.method == "HEAD",
                        )
                    }
                    Some(Err(_)) => (Page::BadRequest, false, false),
                    None => {
                        match fcx
                            .race(Some(deadline), conn.read(&fcx, input.spare()))
                            .await
                        {
                            Ok(Ok(n @ 1..)) => {
                                input.commit(n);
                                if idle {
                                    idle = false;
                                    deadline = fcx.now() + HEADER_TIMEOUT;
                                }
                            }
                            _ => return,
                        }
                        continue;
                    }
                };
                let date = http_date(clock.unix_secs(fcx.now()));
                let response = page.response(
                    &date,
                    clock.unix_secs(fictionet::time::Instant::ZERO),
                    keep_alive,
                    head_only,
                );
                if !matches!(
                    fcx.race(
                        Some(fcx.now() + HEADER_TIMEOUT),
                        conn.write_all(&fcx, response.as_bytes())
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                if !keep_alive {
                    break;
                }
                idle = input.buffered() == 0;
                deadline = fcx.now()
                    + if idle {
                        KEEPALIVE_TIMEOUT
                    } else {
                        HEADER_TIMEOUT
                    };
            }
            let _ = conn.shutdown(&fcx).await;
            // Bytes the client sends after the request are read, so the
            // close is a FIN and not a RST.
            let mut buf = [0; 4096];
            while let Ok(Ok(1..)) = fcx.race(Some(deadline), conn.read(&fcx, &mut buf)).await {}
        })
    }

    fn backlog(&self) -> Option<usize> {
        Some(511)
    }
}
