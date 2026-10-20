//! The first data each open office port sent to the scanner, as its link saw it.
//!
//! The tap keeps one banner per host and TCP port. It reads only the first
//! data segment of a connection: the segment whose sequence number follows
//! the SYN-ACK that answered the port's latest probe. Streams are never
//! reassembled. The port's row must be `open`.
//!
//! A banner is the segment's first line, at most [`MAX_TEXT_BYTES`] bytes.
//! When the data starts with an HTTP status line, the banner is that line and
//! the `Server` header's value, each bounded the same way. Bytes outside
//! printable ASCII are shown as `\xHH`, and a backslash as `\\`.
//!
//! A later connection never replaces a kept banner. The map keeps at most
//! [`MAX_BANNERS`] banners and never evicts one; further ones only count in
//! `untracked_banners`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Maximum number of banners kept in a run.
pub const MAX_BANNERS: usize = 1_024;
/// Maximum length of a banner's text or server value, after escaping.
pub const MAX_TEXT_BYTES: usize = 160;

/// The first data an open port sent to the scanner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Banner {
    /// The office host that sent it.
    pub host: Ipv4Addr,
    /// The TCP port it came from.
    pub port: u16,
    /// The first line, or the HTTP status line.
    pub text: String,
    /// The HTTP `Server` header's value, when the data carried one.
    pub server: Option<String>,
    /// When the tap saw it, in whole milliseconds since the run began.
    pub at_ms: u64,
    /// The map revision when it was kept.
    pub revision: u64,
}

impl Banner {
    /// Maximum compact JSON size. JSON escaping at most doubles the text.
    pub const MAX_JSON_BYTES: usize = concat!(
        r#"{"host":"255.255.255.255","port":65535,"text":"","server":"","at_ms":"#,
        "18446744073709551615",
        r#","revision":"#,
        "18446744073709551615}"
    )
    .len()
        + 4 * MAX_TEXT_BYTES;
}

/// The kept banners and the count that did not fit.
pub(crate) struct Banners {
    kept: BTreeMap<(Ipv4Addr, u16), Banner>,
    max: usize,
    pub(crate) untracked: u64,
}

/// What [`Banners::offer`] did with a first data segment.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Offer {
    /// The port already has a banner.
    Known,
    /// The banner was kept.
    Kept(Banner),
    /// The map was full; the banner was counted in `untracked`.
    Full,
}

impl Banners {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            kept: BTreeMap::new(),
            max,
            untracked: 0,
        }
    }

    /// Keeps the banner in `data` unless the port has one or the map is full.
    pub(crate) fn offer(
        &mut self,
        host: Ipv4Addr,
        port: u16,
        data: &[u8],
        at_ms: u64,
        revision: u64,
    ) -> Offer {
        if self.kept.contains_key(&(host, port)) {
            return Offer::Known;
        }
        if self.kept.len() == self.max {
            self.untracked += 1;
            return Offer::Full;
        }
        let (text, server) = read(data);
        let banner = Banner {
            host,
            port,
            text,
            server,
            at_ms,
            revision,
        };
        self.kept.insert((host, port), banner.clone());
        Offer::Kept(banner)
    }

    /// Every banner, sorted by host then port.
    pub(crate) fn all(&self) -> Vec<Banner> {
        self.kept.values().cloned().collect()
    }
}

/// Reads a banner from a first data segment: its first line, or an HTTP
/// status line and the `Server` header's value.
pub(crate) fn read(data: &[u8]) -> (String, Option<String>) {
    let mut lines = data.split(|&b| b == b'\n').map(|line| match line {
        [rest @ .., b'\r'] => rest,
        line => line,
    });
    let first = lines.next().unwrap_or_default();
    if !status_line(first) {
        return (escape(first), None);
    }
    let server = lines
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let colon = line.iter().position(|&b| b == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(b"server")
                .then(|| line[colon + 1..].trim_ascii())
        })
        .map(escape);
    (escape(first), server)
}

/// Whether a line is an HTTP status line: `HTTP/d.d ddd`, then a space or the end.
fn status_line(line: &[u8]) -> bool {
    matches!(
        line,
        [b'H', b'T', b'T', b'P', b'/', a, b'.', b, b' ', c, d, e, rest @ ..]
            if [a, b, c, d, e].iter().all(|x| x.is_ascii_digit())
                && rest.first().is_none_or(|&x| x == b' ')
    )
}

/// Shows printable ASCII as itself, a backslash as `\\` and other bytes as
/// `\xHH`, stopping before an escape would pass [`MAX_TEXT_BYTES`].
fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        let piece = match b {
            b'\\' => "\\\\".to_owned(),
            0x20..=0x7e => char::from(b).to_string(),
            _ => format!("\\x{b:02x}"),
        };
        if out.len() + piece.len() > MAX_TEXT_BYTES {
            break;
        }
        out.push_str(&piece);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);

    #[test]
    fn ssh_and_smtp_keep_their_first_line() {
        assert_eq!(
            read(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n"),
            ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20".into(), None)
        );
        assert_eq!(
            read(b"220 mail.corp.test ESMTP Postfix (Debian/GNU)\r\n250 more\r\n"),
            ("220 mail.corp.test ESMTP Postfix (Debian/GNU)".into(), None)
        );
        assert_eq!(read(b"no line ending"), ("no line ending".into(), None));
        assert_eq!(read(b"bare\nnewline"), ("bare".into(), None));
    }

    #[test]
    fn http_keeps_the_status_line_and_server_value() {
        let response = b"HTTP/1.1 200 OK\r\nDate: Tue, 20 Oct 2026 02:17:30 GMT\r\n\
            server:   nginx/1.24.0 (Ubuntu)  \r\nContent-Length: 0\r\n\r\nServer: body";
        assert_eq!(
            read(response),
            (
                "HTTP/1.1 200 OK".into(),
                Some("nginx/1.24.0 (Ubuntu)".into())
            )
        );
        assert_eq!(
            read(b"HTTP/1.0 404 Not Found\r\n\r\nServer: in the body\r\n"),
            ("HTTP/1.0 404 Not Found".into(), None)
        );
        assert_eq!(read(b"HTTP/1.1 204\r\n"), ("HTTP/1.1 204".into(), None));
        for line in ["HTTP/1.1 20 OK", "HTTP/x.1 200 OK", "HTTP/1.1 2000"] {
            let data = format!("{line}\r\nServer: nope\r\n\r\n");
            assert_eq!(read(data.as_bytes()), (line.into(), None), "{line}");
        }
    }

    #[test]
    fn binary_data_is_escaped_and_bounded() {
        assert_eq!(
            read(b"\x00\x01ok\\\x7f\xff\x1b[31m\tend\r\n"),
            (r"\x00\x01ok\\\x7f\xff\x1b[31m\x09end".into(), None)
        );
        let (text, _) = read(&[0xff; 100]);
        assert_eq!(text.len(), 160);
        assert_eq!(text, r"\xff".repeat(40));
        let (text, _) = read(&[b'a'; 400]);
        assert_eq!(text, "a".repeat(160));
        let (text, _) = read(&[b'\\'; 100]);
        assert_eq!(text, r"\\".repeat(80));
        let mut almost = vec![b'a'; 158];
        almost.push(0);
        assert_eq!(read(&almost).0, "a".repeat(158));
        let mut long = b"HTTP/1.1 200 OK\r\nServer: ".to_vec();
        long.extend_from_slice(&[b'x'; 300]);
        assert_eq!(read(&long).1, Some("x".repeat(160)));
    }

    #[test]
    fn a_second_offer_keeps_the_first_banner() {
        let mut banners = Banners::new(4);
        let Offer::Kept(first) = banners.offer(HOST, 22, b"SSH-2.0-first\r\n", 10, 3) else {
            panic!("expected a kept banner");
        };
        assert_eq!(
            banners.offer(HOST, 22, b"SSH-2.0-second\r\n", 20, 4),
            Offer::Known
        );
        assert_eq!(banners.all(), std::slice::from_ref(&first));
        assert_eq!(first.text, "SSH-2.0-first");
        assert_eq!((first.at_ms, first.revision), (10, 3));
    }

    #[test]
    fn the_bound_counts_and_never_evicts() {
        let mut banners = Banners::new(2);
        banners.offer(HOST, 80, b"b", 1, 1);
        banners.offer(HOST, 22, b"a", 2, 2);
        assert_eq!(banners.offer(HOST, 25, b"c", 3, 3), Offer::Full);
        assert_eq!(banners.offer(HOST, 25, b"c", 4, 4), Offer::Full);
        assert_eq!(banners.offer(HOST, 22, b"z", 5, 5), Offer::Known);
        assert_eq!(banners.untracked, 2);
        assert_eq!(
            banners.all().iter().map(|b| b.port).collect::<Vec<_>>(),
            [22, 80]
        );
    }

    #[test]
    fn the_longest_banner_fits_the_exact_json_bound() {
        let banner = Banner {
            host: Ipv4Addr::BROADCAST,
            port: u16::MAX,
            text: "\"".repeat(MAX_TEXT_BYTES),
            server: Some(r"\\".repeat(MAX_TEXT_BYTES / 2)),
            at_ms: u64::MAX,
            revision: u64::MAX,
        };
        let bytes = serde_json::to_vec(&banner).unwrap();
        assert_eq!(bytes.len(), Banner::MAX_JSON_BYTES);
        assert_eq!(serde_json::from_slice::<Banner>(&bytes).unwrap(), banner);
        let (text, server) = read(&[b'"'; 400]);
        assert_eq!((text.len(), server), (MAX_TEXT_BYTES, None));
    }
}
