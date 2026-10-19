//! A live page fixture with two machines and in-memory consoles.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fictionet::{Interface, InterfaceExt};
use fictionet_observe::page::{
    BoxFuture, Console, Duplex, Host, HostState, HostStatus, Page, Pty, StateLimits, StateTopic,
};
use fictionet_observe::{DashboardObserver, DashboardOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct FixtureConsole;
impl Console for FixtureConsole {
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        Some(Box::pin(async {
            let (client, server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let _ = screen(server).await;
            });
            Ok(Box::new(client) as Box<dyn Duplex>)
        }))
    }
    fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        Some(Box::pin(async {
            let (client, mut server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                server.write_all(b"Echo terminal\r\n").await?;
                let mut bytes = [0; 4096];
                loop {
                    let n = server.read(&mut bytes).await?;
                    if n == 0 {
                        return Ok::<_, io::Error>(());
                    }
                    server.write_all(&bytes[..n]).await?;
                }
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

async fn screen(mut stream: DuplexStream) -> io::Result<()> {
    stream.write_all(b"RFB 003.008\n").await?;
    let mut version = [0; 12];
    stream.read_exact(&mut version).await?;
    stream.write_all(&[1, 1]).await?;
    if stream.read_u8().await? != 1 {
        return Err(io::Error::other("expected None security"));
    }
    stream.write_all(&[0; 4]).await?;
    stream.read_u8().await?;
    let (width, height) = (160u16, 100u16);
    let mut format = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    let mut init = Vec::new();
    init.extend_from_slice(&width.to_be_bytes());
    init.extend_from_slice(&height.to_be_bytes());
    init.extend_from_slice(&format);
    init.extend_from_slice(&7u32.to_be_bytes());
    init.extend_from_slice(b"Pattern");
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
                        let rgb = [
                            (col as u32 * 255 / width as u32),
                            (row as u32 * 255 / height as u32),
                            if (col / 16 + row / 16) % 2 == 0 {
                                192
                            } else {
                                64
                            },
                        ];
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let mut page = Page::new("Two-host fixture", dashboard.handle());
    for (name, address) in [("alpha", "10.0.0.2"), ("beta", "10.0.0.3")] {
        let status = StateTopic::new(StateLimits::default());
        status.publish(
            fictionet::time::Instant::from_since_start(Duration::ZERO),
            &HostStatus {
                state: HostState::DesktopUp,
                addresses: vec![address.into()],
                screen: true,
                terminal: true,
            },
        )?;
        page = page.host(
            Host::new(name)
                .sandbox(name)
                .console(FixtureConsole)
                .status(status),
        );
    }
    let server = page.standard_panels().bind_loopback(0).await?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(dashboard.observer()),
            |cx| async move {
                let (attacher, mut attachments) = fictionet::attachments();
                let mut alpha = attacher.attach("alpha").unwrap();
                let mut a = attachments.next(&cx).await?;
                let mut beta = attacher.attach("beta").unwrap();
                let mut b = attachments.next(&cx).await?;
                while !stopping.load(Ordering::SeqCst) {
                    alpha.send(fictionet::Packet(vec![
                        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0x66, 0xdd, 10, 0, 0, 2, 10, 0, 0, 3, 8,
                        0, 0xe5, 0xca, 0x12, 0x34, 0, 1,
                    ]));
                    b.send(a.recv(&cx).await?);
                    let mut packet = beta.recv(&cx).await?;
                    packet.0[12..20].copy_from_slice(&[10, 0, 0, 3, 10, 0, 0, 2]);
                    packet.0[20] = 0;
                    packet.0[22..24].copy_from_slice(&[0xed, 0xca]);
                    beta.send(packet);
                    a.send(b.recv(&cx).await?);
                    alpha.recv(&cx).await?;
                    cx.emit("fixture", "exchange", |e| {
                        e.field("from", "alpha").field("to", "beta")
                    });
                    cx.sleep(Duration::from_secs(1)).await?;
                }
                Ok(())
            },
        ))
    });
    println!("{}", server.url());
    println!("Two hosts are exchanging packets. Press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    stop.store(true, Ordering::SeqCst);
    world
        .join()
        .map_err(|_| io::Error::other("fixture world panicked"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}
