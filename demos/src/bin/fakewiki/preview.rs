//! A placeholder RFB screen for the example, never a guest desktop.

use fictionet_observe::page::{BoxFuture, Console, Duplex, Pty};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

pub struct Screen;
impl Console for Screen {
    fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        None
    }
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        Some(Box::pin(async {
            let (client, server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let _ = screen(server).await;
            });
            Ok(Box::new(client) as Box<dyn Duplex>)
        }))
    }
}

async fn screen(mut stream: DuplexStream) -> io::Result<()> {
    stream.write_all(b"RFB 003.008\n").await?;
    stream.read_exact(&mut [0; 12]).await?;
    stream.write_all(&[1, 1]).await?;
    if stream.read_u8().await? != 1 {
        return Err(io::Error::other("unsupported security"));
    }
    stream.write_all(&[0; 4]).await?;
    stream.read_u8().await?;
    let (width, height) = (640u16, 400u16);
    let mut format = [32u8, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    let name = b"Placeholder screen: no VM or Firefox";
    stream.write_u16(width).await?;
    stream.write_u16(height).await?;
    stream.write_all(&format).await?;
    stream.write_u32(name.len() as u32).await?;
    stream.write_all(name).await?;
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
                let n = stream.read_u16().await?;
                discard(&mut stream, u32::from(n) * 4).await?;
            }
            3 => {
                let mut request = [0; 9];
                stream.read_exact(&mut request).await?;
                if request[0] != 0 {
                    continue;
                }
                let mut frame = vec![0, 0, 0, 1];
                for n in [0, 0, width, height] {
                    frame.extend_from_slice(&n.to_be_bytes());
                }
                frame.extend_from_slice(&0i32.to_be_bytes());
                for y in 0..height {
                    for x in 0..width {
                        let shade = if x / 40 % 2 == y / 40 % 2 { 48u32 } else { 64 };
                        let mut pixel = 0u32;
                        for i in 0..3 {
                            pixel |= (shade
                                * u32::from(u16::from_be_bytes([
                                    format[4 + i * 2],
                                    format[5 + i * 2],
                                ]))
                                / 255)
                                << format[10 + i];
                        }
                        let bytes = usize::from(format[0] / 8);
                        if format[2] == 0 {
                            frame.extend_from_slice(&pixel.to_le_bytes()[..bytes]);
                        } else {
                            frame.extend_from_slice(&pixel.to_be_bytes()[4 - bytes..]);
                        }
                    }
                }
                stream.write_all(&frame).await?;
            }
            4 => discard(&mut stream, 7).await?,
            5 => discard(&mut stream, 5).await?,
            6 => {
                discard(&mut stream, 3).await?;
                let n = stream.read_u32().await?;
                discard(&mut stream, n).await?;
            }
            _ => return Err(io::Error::other("unsupported RFB message")),
        }
    }
}
async fn discard(stream: &mut DuplexStream, mut n: u32) -> io::Result<()> {
    let mut bytes = [0; 1024];
    while n > 0 {
        let count = n.min(bytes.len() as u32) as usize;
        stream.read_exact(&mut bytes[..count]).await?;
        n -= count as u32;
    }
    Ok(())
}
