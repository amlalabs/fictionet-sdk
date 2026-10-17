use std::io::Read;
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::{ConnError, Connection, codec, http1};
use fictionet::{Cx, RaceError, time::Instant};

/// Requires EOF. The caller must bound blocking reads with a socket timeout.
pub fn read_all(reader: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).expect("read until EOF");
    bytes
}

/// Includes the delimiter, without consuming the next byte. Requires a read timeout.
pub fn read_until(reader: &mut impl Read, delimiter: &[u8]) -> Vec<u8> {
    assert!(!delimiter.is_empty(), "empty delimiter");
    let mut bytes = Vec::new();
    while !bytes.ends_with(delimiter) {
        let mut byte = [0];
        reader.read_exact(&mut byte).expect("read until delimiter");
        bytes.extend_from_slice(&byte);
    }
    bytes
}

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

/// Validates one whole response. Close-delimited bodies need explicit opt-in and EOF.
pub fn response(bytes: &[u8], method: &str, allow_close_delimited: bool) -> http1::Response {
    let response = http1::Response::parse_for(bytes, method).expect("complete HTTP response");
    if !allow_close_delimited {
        let mut decoder = http1::ResponseEvents::default();
        decoder.expect_method(method).expect("request method");
        let mut stream = codec::Stream::new(decoder);
        let mut done = false;
        // Without end(), only a self-delimited response can produce Done.
        let taken = codec::pump(&mut stream, bytes, |event| {
            done |= matches!(event, http1::Event::Done);
        })
        .expect("HTTP framing");
        assert_eq!(taken, bytes.len(), "unconsumed HTTP bytes");
        assert!(
            done,
            "close-delimited HTTP response requires explicit opt-in"
        );
    }
    response
}
