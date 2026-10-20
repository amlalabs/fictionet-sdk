//! A live page fixture with two machines and in-memory consoles.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use fictionet::{Interface, InterfaceExt};
use fictionet_observe::page::{
    Action, BoxFuture, Column, CommandLimits, CommandPort, Console, Duplex, EventFilter, Format,
    Host, HostState, HostStatus, Page, Pty, Rejected, StateLimits, StateTopic,
};
use fictionet_observe::{DashboardObserver, DashboardOptions};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct FixtureConsole {
    name: &'static str,
    ready: Arc<AtomicU8>,
    drops: tokio::sync::watch::Sender<u64>,
}
impl Console for FixtureConsole {
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        let name = self.name;
        let ready = self.ready.clone();
        let mut drops = self.drops.subscribe();
        Some(Box::pin(async move {
            if ready.load(Ordering::SeqCst) < 3 {
                return Err(io::Error::other(format!("{name} is still booting")));
            }
            let (client, server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                tokio::select! {
                    _ = screen(server, name) => {},
                    _ = drops.changed() => {},
                }
            });
            Ok(Box::new(client) as Box<dyn Duplex>)
        }))
    }
    fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        let name = self.name;
        let ready = self.ready.clone();
        let mut drops = self.drops.subscribe();
        Some(Box::pin(async move {
            if ready.load(Ordering::SeqCst) < 2 {
                return Err(io::Error::other(format!("{name} is still booting")));
            }
            let (client, mut server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let echo = async {
                    server
                        .write_all(format!("{name} echo terminal\r\n").as_bytes())
                        .await?;
                    let mut bytes = [0; 4096];
                    loop {
                        let n = server.read(&mut bytes).await?;
                        if n == 0 {
                            return Ok::<_, io::Error>(());
                        }
                        server.write_all(&bytes[..n]).await?;
                    }
                };
                tokio::select! { _ = echo => {}, _ = drops.changed() => {} }
            });
            let (read, write) = tokio::io::split(client);
            Ok(Box::new(EchoPty {
                read,
                write: tokio::sync::Mutex::new(write),
            }) as Box<dyn Pty>)
        }))
    }
}
struct EchoPty {
    read: tokio::io::ReadHalf<DuplexStream>,
    write: tokio::sync::Mutex<tokio::io::WriteHalf<DuplexStream>>,
}
impl Pty for EchoPty {
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 4096];
            let n = self.read.read(&mut bytes).await?;
            bytes.truncate(n);
            Ok((n > 0).then_some(bytes))
        })
    }
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.write.lock().await.write_all(bytes).await })
    }
    fn resize(&self, _: u16, _: u16) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn close(&self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move { self.write.lock().await.shutdown().await })
    }
}

async fn screen(mut stream: DuplexStream, name: &str) -> io::Result<()> {
    stream.write_all(b"RFB 003.008\n").await?;
    let mut version = [0; 12];
    stream.read_exact(&mut version).await?;
    stream.write_all(&[1, 1]).await?;
    if stream.read_u8().await? != 1 {
        return Err(io::Error::other("expected None security"));
    }
    stream.write_all(&[0; 4]).await?;
    stream.read_u8().await?;
    let (width, height) = (1280u16, 800u16);
    let mut format = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    let mut init = Vec::new();
    init.extend_from_slice(&width.to_be_bytes());
    init.extend_from_slice(&height.to_be_bytes());
    init.extend_from_slice(&format);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name.as_bytes());
    let label = format!("{} 1280 X 800", name.to_ascii_uppercase());
    stream.write_all(&init).await?;
    let mut extended_mouse = false;
    loop {
        match stream.read_u8().await? {
            0 => {
                stream.read_exact(&mut [0; 3]).await?;
                stream.read_exact(&mut format).await?;
                if !matches!(format[0], 8 | 16 | 32)
                    || format[3] != 1
                    || format[10..13].iter().any(|s| *s >= 32)
                {
                    return Err(io::Error::other("unsupported pixel format"));
                }
            }
            2 => {
                stream.read_u8().await?;
                let n = stream.read_u16().await? as usize;
                if n > 64 {
                    return Err(io::Error::other("too many encodings"));
                }
                let mut encodings = vec![0; 4 * n];
                stream.read_exact(&mut encodings).await?;
                extended_mouse = encodings
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .any(|v| *v == (-316i32).to_be_bytes());
            }
            3 => {
                let mut request = [0; 9];
                stream.read_exact(&mut request).await?;
                if request[0] != 0 {
                    continue;
                }
                let x = u16::from_be_bytes([request[1], request[2]]).min(width);
                let y = u16::from_be_bytes([request[3], request[4]]).min(height);
                let w = u16::from_be_bytes([request[5], request[6]]).min(width - x);
                let h = u16::from_be_bytes([request[7], request[8]]).min(height - y);
                let mut frame = vec![0, 0, 0, 1];
                for n in [x, y, w, h] {
                    frame.extend_from_slice(&n.to_be_bytes());
                }
                frame.extend_from_slice(&0i32.to_be_bytes());
                for row in y..y + h {
                    for col in x..x + w {
                        let rgb = if label_pixel(&label, col, row) {
                            [240, 240, 224]
                        } else if (320..416).contains(&row) {
                            [24, 32, 28]
                        } else {
                            [
                                col as u32 * 160 / width as u32,
                                row as u32 * 160 / height as u32,
                                if (col / 80 + row / 80) % 2 == 0 {
                                    128
                                } else {
                                    48
                                },
                            ]
                        };
                        let mut pixel = 0u32;
                        for (i, value) in rgb.iter().enumerate() {
                            let max =
                                u16::from_be_bytes([format[4 + 2 * i], format[5 + 2 * i]]) as u32;
                            pixel |= (value * max / 255) << format[10 + i];
                        }
                        let n = format[0] as usize / 8;
                        if format[2] == 0 {
                            frame.extend_from_slice(&pixel.to_le_bytes()[..n]);
                        } else {
                            frame.extend_from_slice(&pixel.to_be_bytes()[4 - n..]);
                        }
                    }
                }
                stream.write_all(&frame).await?;
            }
            4 => {
                discard(&mut stream, 7).await?;
            }
            5 => {
                let buttons = stream.read_u8().await?;
                discard(
                    &mut stream,
                    if extended_mouse && buttons & 128 != 0 {
                        5
                    } else {
                        4
                    },
                )
                .await?;
            }
            6 => {
                discard(&mut stream, 3).await?;
                let length = stream.read_i32().await?.unsigned_abs() as usize;
                if length > 1 << 20 {
                    return Err(io::Error::other("clipboard exceeds one MiB"));
                }
                discard(&mut stream, length).await?;
            }
            150 => {
                discard(&mut stream, 9).await?;
            }
            248 => {
                let mut head = [0; 8];
                stream.read_exact(&mut head).await?;
                if head[7] > 64 {
                    return Err(io::Error::other("fence exceeds 64 bytes"));
                }
                let mut payload = vec![0; head[7] as usize];
                stream.read_exact(&mut payload).await?;
                if head[3] & 128 != 0 {
                    head[3] &= 127;
                    stream.write_all(&[248]).await?;
                    stream.write_all(&head).await?;
                    stream.write_all(&payload).await?;
                }
            }
            250 => {
                discard(&mut stream, 3).await?;
            }
            251 => {
                let mut head = [0; 7];
                stream.read_exact(&mut head).await?;
                discard(&mut stream, head[5] as usize * 16).await?;
            }
            255 => {
                if stream.read_u8().await? != 0 {
                    return Err(io::Error::other("unknown key subtype"));
                }
                discard(&mut stream, 10).await?;
            }
            _ => {
                return Err(io::Error::other(
                    "fixture screen supports raw framebuffer requests",
                ));
            }
        }
    }
}

async fn discard(stream: &mut DuplexStream, mut remaining: usize) -> io::Result<()> {
    let mut bytes = [0; 1024];
    while remaining > 0 {
        let n = remaining.min(bytes.len());
        stream.read_exact(&mut bytes[..n]).await?;
        remaining -= n;
    }
    Ok(())
}

fn label_pixel(label: &str, x: u16, y: u16) -> bool {
    if !(64..1216).contains(&x) || !(336..392).contains(&y) {
        return false;
    }
    let x = (x - 64) as usize / 8;
    let y = (y - 336) as usize / 8;
    let glyph = match label.as_bytes().get(x / 6).copied().unwrap_or(b' ') {
        b'A' => [14, 17, 17, 31, 17, 17, 17],
        b'B' => [30, 17, 17, 30, 17, 17, 30],
        b'E' => [31, 16, 16, 30, 16, 16, 31],
        b'H' => [17, 17, 17, 31, 17, 17, 17],
        b'L' => [16, 16, 16, 16, 16, 16, 31],
        b'P' => [30, 17, 17, 30, 16, 16, 16],
        b'T' => [31, 4, 4, 4, 4, 4, 4],
        b'X' => [17, 17, 10, 4, 10, 17, 17],
        b'0' => [14, 17, 19, 21, 25, 17, 14],
        b'1' => [4, 12, 4, 4, 4, 4, 14],
        b'2' => [14, 17, 1, 2, 4, 8, 31],
        b'8' => [14, 17, 17, 14, 17, 17, 14],
        _ => [0; 7],
    };
    x % 6 < 5 && glyph[y] & (1 << (4 - x % 6)) != 0
}

#[derive(Clone, Serialize)]
struct Exchange {
    host: &'static str,
    packets: u64,
    bytes: u64,
    at: f64,
}
#[derive(Clone, Serialize)]
struct Traffic {
    running: bool,
    revision: u64,
}
#[derive(Deserialize)]
struct SetTraffic {
    running: bool,
    expected_revision: u64,
}
#[derive(Deserialize)]
struct DropConsoles {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let containment = StateTopic::new(StateLimits::default());
    let labels = fictionet_observe::page::Labels::default();
    let exchanges = StateTopic::new(StateLimits::default());
    let traffic = StateTopic::new(StateLimits::default());
    let commands = CommandPort::<SetTraffic, Traffic>::new(CommandLimits::default());
    let consoles = CommandPort::<DropConsoles, ()>::new(CommandLimits::default());
    let (drops, _) = tokio::sync::watch::channel(0u64);
    let beta_ready = Arc::new(AtomicU8::new(0));
    let mut page = Page::new("Two-host fixture", dashboard.handle());
    let mut statuses = Vec::new();
    for (name, address) in [("alpha", "10.0.0.2"), ("beta", "10.0.0.3")] {
        let status = StateTopic::new(StateLimits::default());
        let up = name == "alpha";
        status.publish(
            fictionet::time::Instant::from_since_start(Duration::ZERO),
            &HostStatus {
                state: if up {
                    HostState::DesktopUp
                } else {
                    HostState::Booting
                },
                addresses: if up { vec![address.into()] } else { vec![] },
                screen: up,
                terminal: up,
            },
        )?;
        page = page.host(
            Host::new(name)
                .sandbox(name)
                .console(FixtureConsole {
                    name,
                    ready: if up {
                        Arc::new(AtomicU8::new(3))
                    } else {
                        beta_ready.clone()
                    },
                    drops: drops.clone(),
                })
                .status(status.clone()),
        );
        statuses.push(status);
    }
    let filter = |kind: &str| EventFilter {
        source: Some("fixture".into()),
        kind: Some(kind.into()),
        ..EventFilter::default()
    };
    let server = page
        .standard_panels()
        .containment(containment.clone())
        .labels(labels.clone())
        .table(
            "Exchanges",
            exchanges.clone(),
            vec![
                Column::new("Host", "/host"),
                Column::new("Packets sent", "/packets").format(Format::Number),
                Column::new("Bytes", "/bytes").format(Format::Bytes),
                Column::new("Last exchange", "/at").format(Format::Time),
            ],
        )
        .event_table(
            "Exchange log",
            filter("exchange"),
            vec![
                Column::new("Time", "/at").format(Format::Time),
                Column::new("From", "/fields/from"),
                Column::new("To", "/fields/to"),
            ],
        )
        .control(
            "Traffic controls",
            commands.clone(),
            vec![
                Action {
                    label: "Pause".into(),
                    command: serde_json::json!({"running": false}),
                },
                Action {
                    label: "Resume".into(),
                    command: serde_json::json!({"running": true}),
                },
            ],
        )
        .control_state(traffic.clone())
        .control(
            "Consoles",
            consoles.clone(),
            vec![Action {
                label: "Drop consoles".into(),
                command: serde_json::json!({}),
            }],
        )
        .custom(
            "Traffic",
            include_str!("page_fixture/traffic.mjs"),
            exchanges.clone(),
        )
        .moment("Traffic paused", filter("paused"))
        .bind_loopback(0)
        .await?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let (started, startup) = tokio::sync::oneshot::channel();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(dashboard.observer()),
            |cx| async move {
                let (attacher, mut attachments) = fictionet::attachments();
                let mut alpha = attacher.attach("alpha").unwrap();
                let mut a = attachments.next(&cx).await?;
                let mut beta = attacher.attach("beta").unwrap();
                let mut b = attachments.next(&cx).await?;
                recorded_attempts(&cx);
                exchange(&cx, &mut alpha, &mut a, &mut beta, &mut b).await?;
                let _ = started.send(());
                let mut rows = vec![
                    Exchange {
                        host: "alpha",
                        packets: 1,
                        bytes: 28,
                        at: 0.0,
                    },
                    Exchange {
                        host: "beta",
                        packets: 1,
                        bytes: 28,
                        at: 0.0,
                    },
                ];
                let mut state = Traffic {
                    running: true,
                    revision: 1,
                };
                traffic
                    .publish(cx.now(), &state)
                    .expect("small traffic state");
                exchanges
                    .publish(cx.now(), &rows)
                    .expect("small exchange table");
                containment.publish(cx.now(), &recorded_containment())?;
                for (seq, text) in [(1, "Run start"), (7, "Startup traffic")] {
                    labels
                        .apply_change(
                            &cx,
                            &fictionet_observe::page::LabelCommand::Add {
                                target: fictionet_observe::page::LabelTarget::Event { seq },
                                text: text.into(),
                            },
                        )
                        .map_err(fictionet::Error::msg)?;
                }
                let mut stage = 0;
                while !stopping.load(Ordering::SeqCst) {
                    while let Some(command) = labels.commands.try_recv() {
                        labels.apply(&cx, command);
                    }
                    let elapsed = cx.now().since_start().as_secs();
                    let ready = if elapsed >= 12 {
                        3
                    } else if elapsed >= 8 {
                        2
                    } else if elapsed >= 4 {
                        1
                    } else {
                        0
                    };
                    if stage != ready {
                        stage = ready;
                        beta_ready.store(stage, Ordering::SeqCst);
                        statuses[1]
                            .publish(
                                cx.now(),
                                &HostStatus {
                                    state: match stage {
                                        1 => HostState::NetworkUp,
                                        2 => HostState::SshUp,
                                        _ => HostState::DesktopUp,
                                    },
                                    addresses: vec!["10.0.0.3".into()],
                                    screen: stage >= 3,
                                    terminal: stage >= 2,
                                },
                            )
                            .expect("small host status");
                    }
                    while let Some(command) = commands.try_recv() {
                        if command.command.expected_revision != state.revision {
                            command.reject(
                                &cx,
                                Rejected::StaleRevision {
                                    current: state.revision,
                                },
                            );
                            continue;
                        }
                        state.running = command.command.running;
                        state.revision += 1;
                        traffic
                            .publish(cx.now(), &state)
                            .expect("small traffic state");
                        if !state.running {
                            cx.emit("fixture", "paused", |event| event.summary("Traffic paused"));
                        }
                        command.reply(&cx, state.clone());
                    }
                    while let Some(command) = consoles.try_recv() {
                        drops.send_modify(|revision| *revision += 1);
                        command.reply(&cx, ());
                    }
                    if state.running && stage >= 1 {
                        exchange(&cx, &mut alpha, &mut a, &mut beta, &mut b).await?;
                        for row in &mut rows {
                            row.packets += 1;
                            row.bytes += 28;
                            row.at = cx.now().since_start().as_secs_f64();
                        }
                        exchanges
                            .publish(cx.now(), &rows)
                            .expect("small exchange table");
                        cx.emit("fixture", "exchange", |e| {
                            e.field("from", "alpha").field("to", "beta")
                        });
                    }
                    cx.sleep(Duration::from_secs(1)).await?;
                }
                Ok(())
            },
        ))
    });
    startup.await?;
    println!("{}", server.url());
    println!("Alpha is ready. Beta starts over 12 seconds. Press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    stop.store(true, Ordering::SeqCst);
    world
        .join()
        .map_err(|_| io::Error::other("fixture world panicked"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

async fn exchange(
    cx: &fictionet::Cx,
    alpha: &mut impl Interface,
    a: &mut impl Interface,
    beta: &mut impl Interface,
    b: &mut impl Interface,
) -> fictionet::Result {
    alpha.send(fictionet::Packet(vec![
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0x66, 0xdd, 10, 0, 0, 2, 10, 0, 0, 3, 8, 0, 0xe5, 0xca,
        0x12, 0x34, 0, 1,
    ]));
    b.send(a.recv(cx).await?);
    let mut packet = beta.recv(cx).await?;
    packet.0[12..20].copy_from_slice(&[10, 0, 0, 3, 10, 0, 0, 2]);
    packet.0[20] = 0;
    packet.0[22..24].copy_from_slice(&[0xed, 0xca]);
    beta.send(packet);
    a.send(b.recv(cx).await?);
    alpha.recv(cx).await?;
    Ok(())
}

// Recorded service outcomes accompany the fixture's live packet exchange.
fn recorded_attempts(cx: &fictionet::Cx) {
    use fictionet::events::{ConnInfo, Sandbox};
    for (name, ip) in [("alpha", "10.0.0.2"), ("beta", "10.0.0.3")] {
        let sandbox = Sandbox {
            id: if name == "alpha" { 1 } else { 2 },
            name: name.into(),
            addr: Some(ip.parse().unwrap()),
            addr_v6: None,
        };
        for (id, site, extra) in [
            (1, "example.test", None),
            (6, "example.test", Some(("answer", "cancelled"))),
            (
                2,
                "mirror.example",
                Some(("forwarded", "http://mirror.example")),
            ),
            (
                3,
                "mirror.example",
                Some(("served_by", "host package cache")),
            ),
            (
                4,
                "origin.example",
                Some(("forwarded", "https://origin.example")),
            ),
            (
                5,
                "releases.example",
                Some(("forwarded", "https://releases.example")),
            ),
        ] {
            let conn = ConnInfo::new(
                id,
                "203.0.113.10:443".parse().unwrap(),
                format!("{ip}:{}", 40000 + id).parse().unwrap(),
            )
            .from_sandbox(Some(sandbox.clone()));
            let emit = cx.emitter(&conn);
            emit.emit("conn", "open", |event| event);
            emit.emit("http", "request", |event| {
                let event = event
                    .field("host", site)
                    .field("world_site", site)
                    .field("answer", "handler")
                    .field(
                        "status",
                        if id == 6 {
                            fictionet::stdlib::protocols::json::Value::Null
                        } else {
                            200u32.into()
                        },
                    )
                    .field("complete", id != 6);
                match extra {
                    Some((key, value)) => event.field(key, value),
                    None => event,
                }
            });
            emit.emit("conn", "close", |event| event);
        }
        let mut dns = ConnInfo::new(
            7,
            "10.0.0.1:53".parse().unwrap(),
            format!("{ip}:40007").parse().unwrap(),
        )
        .from_sandbox(Some(sandbox.clone()));
        dns.transport = fictionet::events::Transport::Udp;
        cx.emitter(&dns).emit("dns", "query", |event| {
            event
                .field("name", "example.test")
                .field("answer", "addr")
                .field("addr", "203.0.113.10")
        });
        let conn = ConnInfo::default().from_sandbox(Some(sandbox));
        for (why, dst, port) in [
            ("ClosedPort", "203.0.113.10", 22u32),
            ("NoRoute", "1.1.1.1", 443),
            ("NoRoute", "8.8.8.8", 53),
        ] {
            cx.emitter(&conn).emit("net", "blocked", |event| {
                event
                    .field("why", why)
                    .field("dst", dst)
                    .field("dst_port", port)
                    .field("protocol", if port == 53 { 17u32 } else { 6u32 })
            });
        }
    }
}

fn recorded_containment() -> fictionet_observe::page::Containment {
    use fictionet_observe::page::{Containment, ProbeOutcome, ProbeResult};
    Containment {
        probes: [
            (
                "alpha",
                "Public DNS",
                "dig @8.8.8.8 example.com",
                "8.8.8.8:53",
                ProbeOutcome::Contained,
                "connection timed out; no servers could be reached",
                "no route: no machine at that address",
            ),
            (
                "alpha",
                "Raw public IP",
                "curl https://1.1.1.1",
                "1.1.1.1:443",
                ProbeOutcome::Contained,
                "Failed to connect",
                "no route: no machine at that address",
            ),
            (
                "beta",
                "Public IPv6",
                "curl -6 'https://[2606:4700:4700::1111]'",
                "[2606:4700:4700::1111]:443",
                ProbeOutcome::TimedOut,
                "Probe timed out",
                "No matching world observation",
            ),
            (
                "beta",
                "Proxy environment",
                "env",
                "environment",
                ProbeOutcome::Fact,
                "No proxy settings set",
                "Configuration only",
            ),
        ]
        .into_iter()
        .map(
            |(guest, name, command, destination, outcome, guest_result, world_answer)| {
                ProbeResult {
                    guest: guest.into(),
                    name: name.into(),
                    command: command.into(),
                    destination: destination.into(),
                    outcome,
                    summary: guest_result.into(),
                    guest_result: guest_result.into(),
                    world_answer: world_answer.into(),
                    proxies: vec![],
                }
            },
        )
        .collect(),
    }
}
