//! RFB capture from a page screen or any bidirectional byte stream.

use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What a capture found.
pub struct Capture {
    /// The RFB ProtocolVersion the guest's server opened with, e.g.
    /// `RFB 003.008`.
    pub banner: String,
    /// The captured screen width in pixels.
    pub width: u16,
    /// The captured screen height in pixels.
    pub height: u16,
    /// How many colors the screen shows, counted up to 256: one for a blank
    /// screen, many for a desktop.
    pub colors: usize,
    /// Where the PNG of the guest's screen was written.
    pub png: PathBuf,
}

/// Captures the page's screen as a signed-in viewer without claiming input.
pub async fn capture_page(url: &str, host: &str, out: &Path) -> io::Result<Capture> {
    use super::client::{Capability, PageClient};
    let page = PageClient::from_url(url)?;
    page.bootstrap().await?;
    let ticket = page.ticket(host, Capability::Screen).await?;
    capture(
        page.open(host, Capability::Screen, Some(&ticket.ticket))
            .await?,
        out,
    )
    .await
}

/// Captures RFB from an SSH forward or any other byte stream.
pub async fn capture<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    out: &Path,
) -> io::Result<Capture> {
    let mut conn = ByteStream(stream);

    // RFB 3.8 handshake (RFC 6143). The server opens with its version.
    let banner_bytes = conn.read_exact(12).await?;
    if !banner_bytes.starts_with(b"RFB ") {
        return Err(io::Error::other("the guest did not speak RFB"));
    }
    let banner = String::from_utf8_lossy(&banner_bytes)
        .trim_end()
        .to_string();
    conn.write(b"RFB 003.008\n").await?;

    // Security: the server offers types; we take None (1), which Xvnc is
    // configured for, then read its one-word result.
    let count = conn.read_exact(1).await?[0] as usize;
    if count == 0 {
        return Err(io::Error::other(
            "the guest's server offered no security types",
        ));
    }
    let types = conn.read_exact(count).await?;
    if !types.contains(&1) {
        return Err(io::Error::other("the guest's server wants authentication"));
    }
    conn.write(&[1]).await?;
    if conn.read_exact(4).await? != [0, 0, 0, 0] {
        return Err(io::Error::other(
            "the guest's server refused the connection",
        ));
    }

    // ClientInit (shared), then ServerInit: size, pixel format, name.
    conn.write(&[1]).await?;
    let init = conn.read_exact(24).await?;
    let width = u16::from_be_bytes([init[0], init[1]]);
    let height = u16::from_be_bytes([init[2], init[3]]);
    let name_len = u32::from_be_bytes([init[20], init[21], init[22], init[23]]) as usize;
    conn.read_exact(name_len).await?;
    if width == 0 || height == 0 {
        return Err(io::Error::other("the guest reported an empty screen"));
    }

    // Ask for a known 32-bit true-colour format (little-endian, bytes B,G,R,x)
    // and raw tiles, then request the whole screen non-incrementally.
    #[rustfmt::skip]
    conn.write(&[
        0, 0, 0, 0, // SetPixelFormat, 3 pad
        32, 24, 0, 1, // bpp, depth, big-endian=0, true-colour=1
        0, 255, 0, 255, 0, 255, // red/green/blue max
        16, 8, 0, // red/green/blue shift
        0, 0, 0, // pad
    ]).await?;
    conn.write(&[2, 0, 0, 1, 0, 0, 0, 0]).await?; // SetEncodings [Raw]
    let mut request = vec![3u8, 0]; // FramebufferUpdateRequest, incremental=0
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&width.to_be_bytes());
    request.extend_from_slice(&height.to_be_bytes());
    conn.write(&request).await?;

    // A non-incremental request for the whole screen is answered by one
    // FramebufferUpdate whose rectangles cover it (RFC 6143 section 7.6.1), so
    // we read until that update, ignoring any bell or cut-text before it.
    let (w, h) = (width as usize, height as usize);
    let mut rgb = vec![0u8; w * h * 3];
    let mut got_frame = false;
    while !got_frame {
        match conn.read_exact(1).await?[0] {
            0 => {
                conn.read_exact(1).await?; // pad
                let rects = be16(&conn.read_exact(2).await?);
                for _ in 0..rects {
                    let r = conn.read_exact(12).await?;
                    let (rx, ry) = (be16(&r[0..2]) as usize, be16(&r[2..4]) as usize);
                    let (rw, rh) = (be16(&r[4..6]) as usize, be16(&r[6..8]) as usize);
                    let encoding = i32::from_be_bytes([r[8], r[9], r[10], r[11]]);
                    if encoding != 0 {
                        return Err(io::Error::other(format!(
                            "unexpected RFB encoding {encoding}"
                        )));
                    }
                    if rx + rw > w || ry + rh > h {
                        return Err(io::Error::other("a rectangle fell outside the screen"));
                    }
                    let pixels = conn.read_exact(rw * rh * 4).await?;
                    for row in 0..rh {
                        for col in 0..rw {
                            let s = (row * rw + col) * 4;
                            let d = ((ry + row) * w + rx + col) * 3;
                            rgb[d] = pixels[s + 2]; // R
                            rgb[d + 1] = pixels[s + 1]; // G
                            rgb[d + 2] = pixels[s]; // B
                        }
                    }
                }
                got_frame = true;
            }
            1 => {
                // SetColourMapEntries: not expected in true colour; skip it.
                let body = conn.read_exact(5).await?;
                let n = be16(&body[3..5]) as usize;
                conn.read_exact(n * 6).await?;
            }
            2 => {} // Bell
            3 => {
                // ServerCutText: 3 pad, length, text.
                let head = conn.read_exact(7).await?;
                let n = u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize;
                conn.read_exact(n).await?;
            }
            other => return Err(io::Error::other(format!("unexpected RFB message {other}"))),
        }
    }

    write_png(out, width as u32, height as u32, &rgb)?;
    let mut colors = std::collections::HashSet::new();
    for pixel in rgb.as_chunks::<3>().0 {
        if colors.len() == 256 {
            break;
        }
        colors.insert(*pixel);
    }
    Ok(Capture {
        banner,
        width,
        height,
        colors: colors.len(),
        png: out.to_path_buf(),
    })
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

struct ByteStream<S>(S);
impl<S: AsyncRead + AsyncWrite + Unpin> ByteStream<S> {
    async fn read_exact(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; n];
        self.0.read_exact(&mut bytes).await?;
        Ok(bytes)
    }
    async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes).await
    }
}

/// Writes 8-bit RGB pixels as a PNG. Deflate and CRC come from vetted crates;
/// only the chunk framing is here.
fn write_png(path: &Path, width: u32, height: u32, rgb: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut raw = Vec::with_capacity((width as usize * 3 + 1) * height as usize);
    for row in 0..height as usize {
        raw.push(0); // filter: none
        let start = row * width as usize * 3;
        raw.extend_from_slice(&rgb[start..start + width as usize * 3]);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw)?;
    let idat = encoder.finish()?;

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit, colour type 2 (RGB)

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &idat);
    chunk(&mut png, b"IEND", &[]);
    std::fs::write(path, png)
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc = crc32fast::Hasher::new();
    crc.update(kind);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_a_byte_stream_as_png() {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let out = dir.path().join("screen.png");
        let (client, mut server) = tokio::io::duplex(64);
        let peer = tokio::spawn(async move {
            server.write_all(b"RFB 003.008\n").await.unwrap();
            let mut banner = [0; 12];
            server.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"RFB 003.008\n");
            server.write_all(&[1, 1]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            server.write_all(&[0; 4]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            let mut init = [0; 24];
            init[..4].copy_from_slice(&[0, 2, 0, 1]);
            server.write_all(&init).await.unwrap();
            let mut request = [0; 38];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0);
            assert_eq!(request[20], 2);
            assert_eq!(request[28], 3);
            server
                .write_all(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0])
                .await
                .unwrap();
            server
                .write_all(&[0, 0, 255, 0, 0, 255, 0, 0])
                .await
                .unwrap();
        });
        let result = capture(client, &out).await.unwrap();
        peer.await.unwrap();
        assert_eq!((result.width, result.height, result.colors), (2, 1, 2));
        assert_eq!(&std::fs::read(out).unwrap()[..8], b"\x89PNG\r\n\x1a\n");
    }
}
