use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::{ConnError, Connection};
use fictionet::{Cx, RaceError, time::Instant};

#[path = "../../common/response.rs"]
mod response;
pub use response::response;

/// Requires EOF by the deadline. Race failures stay separate from transport errors.
pub async fn read_to_end(
    fcx: &Cx,
    conn: &mut impl Connection,
    deadline: Instant,
) -> Result<Result<Vec<u8>, ConnError>, RaceError> {
    fcx.race(Some(deadline), async {
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = conn.read(fcx, &mut buf).await?;
            if n == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buf[..n]);
        }
    })
    .await
}

/// Reads until `want` bytes arrived, the stream ends, or a second passes.
pub async fn read_some(fcx: &Cx, conn: &mut impl Connection, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while got.len() < want {
        match fcx
            .race(
                Some(fcx.now() + Duration::from_secs(1)),
                conn.read(fcx, &mut buf),
            )
            .await
        {
            Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    got
}

/// Includes the delimiter without read-ahead. EOF and transport errors panic.
pub async fn read_until_async(
    fcx: &Cx,
    conn: &mut impl Connection,
    deadline: Instant,
    delimiter: &[u8],
) -> Result<Vec<u8>, RaceError> {
    assert!(!delimiter.is_empty(), "empty delimiter");
    fcx.race(Some(deadline), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(delimiter) {
            let mut byte = [0];
            let n = conn
                .read(fcx, &mut byte)
                .await
                .expect("read until delimiter");
            assert_ne!(n, 0, "EOF before delimiter");
            bytes.extend_from_slice(&byte);
        }
        bytes
    })
    .await
}
