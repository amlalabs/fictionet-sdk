//! What the server says once a connection is open: an OpenSSH
//! identification line, or nginx's default page. Each holds the connection
//! as long as the real server would, and the packet log keeps whatever the
//! client sends.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::web::httpd::http_date;
use fictionet::stdlib::world::net::{Arrival, PortServer};

use crate::Clock;

/// The identification line of OpenSSH on Ubuntu 24.04 (RFC 4253 section
/// 4.2).
pub const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

/// OpenSSH's `LoginGraceTime`: how long sshd keeps a connection that has
/// not logged in.
pub const LOGIN_GRACE: Duration = Duration::from_secs(120);

/// nginx's `client_header_timeout`: how long it waits for a request's head.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// nginx's `large_client_header_buffers`: the longest request head it
/// reads before it answers 400.
pub const HEADER_LIMIT: usize = 8 * 1024;

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

/// SSH: the identification line, then reads until the client goes or
/// [`LOGIN_GRACE`] passes.
pub struct Ssh;

impl PortServer for Ssh {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut conn = arrival.conn;
        Box::pin(async move {
            let deadline = fcx.now() + LOGIN_GRACE;
            if conn.write_all(&fcx, SSH_BANNER).await.is_err() {
                return;
            }
            let mut buf = [0; 4096];
            while let Ok(Ok(1..)) = fcx.race(Some(deadline), conn.read(&fcx, &mut buf)).await {}
        })
    }
}

/// HTTP: reads one request head and answers with nginx's default page,
/// then closes. A head longer than [`HEADER_LIMIT`] gets a 400, and one
/// that takes longer than [`HEADER_TIMEOUT`] gets nothing.
pub struct Http {
    /// The wall clock, for the `Date` header.
    pub clock: Clock,
}

impl PortServer for Http {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut conn = arrival.conn;
        let clock = self.clock;
        Box::pin(async move {
            let deadline = fcx.now() + HEADER_TIMEOUT;
            let mut head = Vec::new();
            // Where the search for the blank line goes on from, so each
            // byte is looked at once however the client splits its writes.
            let mut searched = 0;
            let mut buf = [0; 4096];
            let (status, body) = loop {
                if head[searched..].windows(4).any(|w| w == b"\r\n\r\n") {
                    break ("200 OK", WELCOME);
                }
                searched = head.len().saturating_sub(3);
                if head.len() > HEADER_LIMIT {
                    break ("400 Bad Request", BAD_REQUEST);
                }
                match fcx.race(Some(deadline), conn.read(&fcx, &mut buf)).await {
                    Ok(Ok(n @ 1..)) => head.extend_from_slice(&buf[..n]),
                    _ => return,
                }
            };
            let date = http_date(clock.unix_secs(fcx.now()));
            let response = format!(
                "HTTP/1.1 {status}\r\nServer: nginx/1.24.0 (Ubuntu)\r\nDate: {date}\r\n\
                 Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(&fcx, response.as_bytes()).await;
            let _ = conn.shutdown(&fcx).await;
            // Bytes the client sends after the request are read, so the
            // close is a FIN and not a RST.
            while let Ok(Ok(1..)) = fcx.race(Some(deadline), conn.read(&fcx, &mut buf)).await {}
        })
    }
}
