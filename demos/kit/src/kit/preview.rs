//! A placeholder screen and the standard input of pages that run without
//! a VM.
//!
//! Every demo's `preview` subcommand reads standard input through [`Input`],
//! which prints the one line that says what the input does. Where the
//! in-world client runs on request, Enter runs its story. Where the story
//! runs once by itself, Enter says so. On a page with a screen, `drop` closes
//! the screen's open connections, as a lost guest connection would. The end
//! of input or Ctrl-C stops the preview.

use crate::kit::page::{BoxFuture, Duplex, Pty};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;

/// When a preview's in-world client runs its story.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Story {
    /// Each time the viewer presses Enter.
    OnEnter,
    /// Once, by itself. Enter only says so.
    Once,
}

/// What a preview does with one line of its standard input.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    /// Run the in-world client's story.
    Run,
    /// Close the screen's open connections.
    Drop,
    /// Say this on standard error.
    Say(String),
}

/// The line that says what a preview's standard input does.
fn instructions(story: Story, screen: bool) -> String {
    let mut parts = vec![match story {
        Story::OnEnter => "Press Enter to run the in-world client's story.",
        Story::Once => "The story runs once.",
    }];
    if screen {
        parts.push("Type drop to close the screen's connections.");
    }
    parts.push("End the input or press Ctrl-C to stop.");
    parts.join(" ")
}

/// The reply to one line, for a preview whose story runs as `story` and
/// whose page has a screen or not.
fn reply(line: &str, story: Story, screen: bool) -> Reply {
    match line.trim() {
        "" if story == Story::OnEnter => Reply::Run,
        "" => Reply::Say("The story runs once.".into()),
        "drop" if screen => Reply::Drop,
        _ => Reply::Say(format!("{line:?}: {}", instructions(story, screen))),
    }
}

/// A preview's standard input, read on its own thread, and Ctrl-C.
pub struct Input {
    runs: mpsc::Receiver<()>,
    interrupt: Signal,
}

impl Input {
    /// Prints what the input does on standard error and starts reading it.
    /// `screen` is the page's placeholder screen, if the page has one: `drop`
    /// closes its connections. Enter goes to [`Input::run`] when the story
    /// runs on Enter, and is answered here when it runs once. Any other line
    /// is answered with the instructions.
    pub fn stdin(story: Story, screen: Option<Console>) -> io::Result<Self> {
        let interrupt = signal(SignalKind::interrupt())?;
        eprintln!("{}", instructions(story, screen.is_some()));
        let (send, runs) = mpsc::channel(1);
        std::thread::spawn(move || {
            for line in std::io::stdin().lines() {
                let Ok(line) = line else { break };
                match reply(&line, story, screen.is_some()) {
                    Reply::Run => {
                        if send.blocking_send(()).is_err() {
                            break;
                        }
                    }
                    Reply::Drop => {
                        if let Some(screen) = &screen {
                            screen.drop_connections();
                            eprintln!("Screen connections closed.");
                        }
                    }
                    Reply::Say(text) => eprintln!("{text}"),
                }
            }
        });
        Ok(Self { runs, interrupt })
    }

    /// Waits for Enter. True when the viewer asked for the story, false at
    /// the end of input or on Ctrl-C. A story that runs once never gets true.
    pub async fn run(&mut self) -> bool {
        tokio::select! {
            asked = self.runs.recv() => asked.is_some(),
            _ = self.interrupt.recv() => false,
        }
    }

    /// Waits for the end of input or Ctrl-C, for a preview whose story runs
    /// once.
    pub async fn closed(&mut self) {
        while self.run().await {}
    }
}

/// A screen-only page console that draws the words NO VM, so a preview page
/// is never mistaken for a guest's desktop. Input reaches nothing. Clones share
/// one set of open connections.
#[derive(Clone)]
pub struct Console {
    drops: tokio::sync::watch::Sender<u64>,
}
impl Console {
    pub fn new() -> Self {
        Self {
            drops: tokio::sync::watch::channel(0).0,
        }
    }
    /// Closes every open screen connection, as a lost guest connection would.
    /// Later connections open normally.
    pub fn drop_connections(&self) {
        self.drops.send_modify(|count| *count += 1);
    }
}
impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}
impl crate::kit::page::Console for Console {
    fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        None
    }
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        let mut drops = self.drops.subscribe();
        Some(Box::pin(async move {
            let (client, server) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                tokio::select! {
                    _ = screen(server) => {}
                    _ = drops.changed() => {}
                }
            });
            Ok(Box::new(client) as Box<dyn Duplex>)
        }))
    }
}

async fn discard(stream: &mut DuplexStream, length: usize) -> io::Result<()> {
    let mut bytes = [0; 1024];
    let mut left = length;
    while left > 0 {
        let n = left.min(bytes.len());
        stream.read_exact(&mut bytes[..n]).await?;
        left -= n;
    }
    Ok(())
}
fn pixel(x: u16, y: u16) -> [u32; 3] {
    // The screen says NO VM, so it cannot be mistaken for a running desktop.
    const GLYPHS: [[u8; 7]; 5] = [
        [17, 25, 25, 21, 19, 19, 17],
        [14, 17, 17, 17, 17, 17, 14],
        [0; 7],
        [17, 17, 17, 17, 17, 10, 4],
        [17, 27, 21, 21, 17, 17, 17],
    ];
    if (200..440).contains(&x) && (168..224).contains(&y) {
        let col = (x - 200) as usize / 8;
        let row = (y - 168) as usize / 8;
        if col % 6 < 5 && GLYPHS[col / 6][row] & (1 << (4 - col % 6)) != 0 {
            return [226, 228, 214];
        }
    }
    [20, 25, 21]
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
    let mut format = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
    let mut init = Vec::from([2, 128, 1, 144]); // 640 by 400.
    init.extend_from_slice(&format);
    let name = b"Preview console (no VM)";
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    stream.write_all(&init).await?;
    loop {
        match stream.read_u8().await? {
            0 => {
                discard(&mut stream, 3).await?;
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
                discard(&mut stream, n * 4).await?;
            }
            3 => {
                let mut request = [0; 9];
                stream.read_exact(&mut request).await?;
                if request[0] != 0 {
                    continue;
                }
                let mut frame = vec![0, 0, 0, 1];
                for n in [0u16, 0, 640, 400] {
                    frame.extend_from_slice(&n.to_be_bytes());
                }
                frame.extend_from_slice(&0i32.to_be_bytes());
                for y in 0..400 {
                    for x in 0..640 {
                        let mut value = 0u32;
                        for (i, channel) in pixel(x, y).iter().enumerate() {
                            let max =
                                u16::from_be_bytes([format[4 + i * 2], format[5 + i * 2]]) as u32;
                            value |= (channel * max / 255) << format[10 + i];
                        }
                        let bytes = format[0] as usize / 8;
                        if format[2] == 0 {
                            frame.extend_from_slice(&value.to_le_bytes()[..bytes]);
                        } else {
                            frame.extend_from_slice(&value.to_be_bytes()[4 - bytes..]);
                        }
                    }
                }
                stream.write_all(&frame).await?;
            }
            4 => discard(&mut stream, 7).await?,
            5 => discard(&mut stream, 5).await?,
            6 => {
                discard(&mut stream, 3).await?;
                let size = stream.read_i32().await?.unsigned_abs() as usize;
                if size > 1 << 20 {
                    return Err(io::Error::other("clipboard too large"));
                }
                discard(&mut stream, size).await?;
            }
            _ => return Err(io::Error::other("unsupported preview message")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::page::Console as _;

    #[test]
    fn replies_follow_what_the_preview_offers() {
        for line in ["", "  \r"] {
            assert_eq!(reply(line, Story::OnEnter, true), Reply::Run);
            assert_eq!(
                reply(line, Story::Once, true),
                Reply::Say("The story runs once.".into())
            );
        }
        assert_eq!(reply(" drop ", Story::Once, true), Reply::Drop);
        assert_eq!(reply("drop", Story::OnEnter, true), Reply::Drop);
        // Without a screen, drop is a line the preview does not know.
        assert_eq!(
            reply("drop", Story::Once, false),
            Reply::Say(
                "\"drop\": The story runs once. End the input or press Ctrl-C to stop.".into()
            )
        );
        assert_eq!(
            reply("Drop", Story::OnEnter, true),
            Reply::Say(
                "\"Drop\": Press Enter to run the in-world client's story. Type drop to close \
                 the screen's connections. End the input or press Ctrl-C to stop."
                    .into()
            )
        );
    }
    #[tokio::test]
    async fn screen_delivers_labeled_pixels_and_closes_on_disconnect() {
        let (mut client, server) = tokio::io::duplex(64 << 10);
        let task = tokio::spawn(screen(server));
        let mut version = [0; 12];
        client.read_exact(&mut version).await.unwrap();
        assert_eq!(&version, b"RFB 003.008\n");
        client.write_all(&version).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 257);
        client.write_all(&[1]).await.unwrap();
        assert_eq!(client.read_u32().await.unwrap(), 0);
        client.write_all(&[1]).await.unwrap();
        let mut init = [0; 24];
        client.read_exact(&mut init).await.unwrap();
        assert_eq!(&init[..4], &[2, 128, 1, 144]);
        let mut name = vec![0; u32::from_be_bytes(init[20..24].try_into().unwrap()) as usize];
        client.read_exact(&mut name).await.unwrap();
        assert_eq!(name, b"Preview console (no VM)");
        client
            .write_all(&[3, 0, 0, 0, 0, 0, 2, 128, 1, 144])
            .await
            .unwrap();
        let mut frame = vec![0; 16 + 640 * 400 * 4];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, 1]);
        let offset = 16 + (168 * 640 + 200) * 4;
        assert_eq!(&frame[offset..offset + 4], &[214, 228, 226, 0]);
        drop(client);
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn dropping_connections_closes_open_screens_only() {
        let console = Console::new();
        let mut open = console.screen().unwrap().await.unwrap();
        let mut version = [0; 12];
        open.read_exact(&mut version).await.unwrap();
        console.drop_connections();
        let mut rest = Vec::new();
        assert_eq!(open.read_to_end(&mut rest).await.unwrap(), 0);
        let mut next = console.screen().unwrap().await.unwrap();
        next.read_exact(&mut version).await.unwrap();
        assert_eq!(&version, b"RFB 003.008\n");
    }
}
