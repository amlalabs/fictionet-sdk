//! Opens a demo's page in a Chromium app window: `open <file>`, with the
//! file a run prints after `Open:`. `cargo xtask demo open <file>` runs it.
//! It returns when the window is closed, and Ctrl-C closes the window.

use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        return Err("usage: open <file>".into());
    };
    let mut window = fictionet_demo::kit::open_bootstrap(path.as_ref())?;
    let (mut interrupt, mut terminate) = (
        signal(SignalKind::interrupt())?,
        signal(SignalKind::terminate())?,
    );
    while !window.closed()? {
        tokio::select! {
            _ = interrupt.recv() => break,
            _ = terminate.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
    Ok(())
}
