//! The story's traffic from inside the world, for running the page without
//! VMs. A scanner sweeps the office with pings, connects to ports 1 to
//! 1,024 on each host that answered, and reads each open port's first data.
//! A stand-in for the server VM answers at 10.0.0.50 with the OpenSSH and
//! nginx banners the real server sent in a KVM run of the demo.
use fictionet::prelude::*;
use fictionet::stdlib::network::{icmp, ip, tcp};
use fictionet::{Cx, End, Interface, Packet, RaceError, Task};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The scanner's address in the scanner subnet.
pub const SCANNER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 9, 2);
/// The server VM's identification line and web reply in the KVM run.
const SSH: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n";
const HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\
    Content-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// How long a probe waits for an answer.
const PATIENCE: Duration = Duration::from_secs(2);
/// At most this many connections are open at once, well under the 16,384
/// local ports the scanner's TCP endpoint can use.
const WINDOW: usize = 256;

/// Answers pings and serves OpenSSH's banner and nginx's reply at the
/// server's address, behind the world's `server` attachment.
pub fn serve_server(cx: &Cx, end: End) {
    let addr = scan_world::SERVER_ADDR.into();
    let (t, _udp, mut echo, _other) = ip::split_protocols(cx, end);
    let endpoint = tcp::endpoint(cx, t, addr);
    for (port, reply) in [(22u16, SSH), (80, HTTP)] {
        let mut listener = endpoint.listen(port).expect("a free port on the stand-in");
        cx.spawn(move |cx| async move {
            while let Ok(mut conn) = listener.accept(&cx).await {
                cx.spawn(move |cx| async move {
                    if port == 80 {
                        let mut request = [0; 1024];
                        let _ = conn.read(&cx, &mut request).await;
                    }
                    let _ = conn.write_all(&cx, reply).await;
                    let _ = conn.shutdown(&cx).await;
                    Ok(())
                });
            }
            Ok(())
        });
    }
    // The endpoint lives as long as this task, which answers pings.
    cx.spawn(move |cx| async move {
        let _endpoint = endpoint;
        while let Ok(packet) = echo.recv(&cx).await {
            if let Some(reply) = icmp::echo_reply(&packet, addr) {
                echo.send(reply);
            }
        }
        Ok(())
    });
}

/// A scanner on the world's `scanner` attachment.
pub struct Scanner {
    tcp: tcp::Endpoint,
    echo: End,
}

impl Scanner {
    pub fn attach(cx: &Cx, end: End) -> Self {
        let (t, _udp, echo, _other) = ip::split_protocols(cx, end);
        Self {
            tcp: tcp::endpoint(cx, t, SCANNER_ADDR.into()),
            echo,
        }
    }

    /// Pings every address in 10.0.0.0/24, one every `pace`, and returns the
    /// addresses that answered.
    pub async fn sweep(&mut self, cx: &Cx, pace: Duration) -> fictionet::Result<Vec<Ipv4Addr>> {
        let mut up = BTreeSet::new();
        for last in 0..=255u8 {
            let to = Ipv4Addr::new(10, 0, 0, last);
            self.echo.send(echo_request(to, u16::from(last)));
            let deadline = cx.now() + pace;
            while let Ok(Ok(reply)) = cx.race(Some(deadline), self.echo.recv(cx)).await {
                up.extend(answered(&reply));
            }
        }
        while let Ok(Ok(reply)) = cx.race(Some(cx.now() + PATIENCE), self.echo.recv(cx)).await {
            up.extend(answered(&reply));
        }
        Ok(up.into_iter().collect())
    }

    /// Connects to every port in `ports` on each host, starting one
    /// connection every `pace` with at most [`WINDOW`] open, and returns the
    /// ports that accepted.
    pub async fn scan(
        &self,
        cx: &Cx,
        hosts: &[Ipv4Addr],
        ports: RangeInclusive<u16>,
        pace: Duration,
    ) -> fictionet::Result<Vec<(Ipv4Addr, u16)>> {
        let open = Arc::new(Mutex::new(BTreeSet::new()));
        let mut tasks = std::collections::VecDeque::new();
        for port in ports {
            for &host in hosts {
                if tasks.len() == WINDOW
                    && let Some(task) = tasks.pop_front()
                {
                    let _ = Task::join(task, cx).await;
                }
                let tcp = self.tcp.clone();
                let open = open.clone();
                tasks.push_back(cx.spawn(move |cx| async move {
                    let deadline = Some(cx.now() + PATIENCE);
                    if let Ok(Ok(conn)) = cx
                        .race(deadline, tcp.connect(&cx, (host, port).into()))
                        .await
                    {
                        open.lock().unwrap().insert((host, port));
                        drop(conn);
                    }
                    Ok(())
                }));
                cx.sleep(pace).await?;
            }
        }
        for task in tasks {
            let _ = task.join(cx).await;
        }
        Ok(open.lock().unwrap().iter().copied().collect())
    }

    /// Reads each open port's first data. Like nmap's service probes, it
    /// waits for a greeting first and sends an HTTP request on the same
    /// connection when none comes.
    pub async fn banners(&self, cx: &Cx, open: &[(Ipv4Addr, u16)]) -> fictionet::Result {
        for &(host, port) in open {
            let Ok(mut conn) = self.tcp.connect(cx, (host, port).into()).await else {
                continue;
            };
            let mut bytes = [0; 512];
            let greeting = cx
                .race(
                    Some(cx.now() + Duration::from_millis(500)),
                    conn.read(cx, &mut bytes),
                )
                .await;
            if matches!(greeting, Err(RaceError::Deadline)) {
                conn.write_all(cx, b"GET / HTTP/1.0\r\n\r\n").await?;
                let _ = cx
                    .race(Some(cx.now() + PATIENCE), conn.read(cx, &mut bytes))
                    .await;
            }
            let _ = conn.shutdown(cx).await;
        }
        Ok(())
    }
}

/// The host an echo reply came from.
fn answered(reply: &Packet) -> Option<Ipv4Addr> {
    let header = ip::Header::parse(&reply.0)?;
    let std::net::IpAddr::V4(from) = header.src else {
        return None;
    };
    (header.protocol == 1 && header.payload(&reply.0).first() == Some(&0)).then_some(from)
}

fn echo_request(to: Ipv4Addr, seq: u16) -> Packet {
    let mut payload = vec![8, 0, 0, 0, 0x5c, 0x41];
    payload.extend_from_slice(&seq.to_be_bytes());
    let sum = ip::checksum(&payload);
    payload[2..4].copy_from_slice(&sum.to_be_bytes());
    ip::packet(SCANNER_ADDR.into(), to.into(), 1, &payload)
}
