//! Shared HTTP/1 fuzz fixture limits.

use fictionet::stdlib::protocols::http1::Limits;

/// Limits for streaming HTTP/1 events.
pub fn event_limits() -> Limits {
    Limits {
        start_line: 256,
        header_line: 256,
        headers: 16,
        head: 2048,
        body_chunk: 31,
        ..Limits::default()
    }
}

/// Limits for collected HTTP/1 messages.
pub fn message_limits() -> Limits {
    Limits {
        body: 1024,
        message: 4096,
        ..event_limits()
    }
}
