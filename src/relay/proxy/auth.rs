//! The sandbox's token, and checking what a client gives against it. The
//! binary reads it from `--token-file`.
//!
//! One attach serves one sandbox, so it has one token. The HTTP door takes
//! it in `Proxy-Authorization` (Basic, with the token as the password, or
//! Bearer), and the SOCKS5 door as the password of RFC 1929's
//! username/password method. The username is not checked: it may be
//! anything, such as `fictionet` or the sandbox's name.

/// The longest token: SOCKS5 carries a password in at most 255 bytes.
pub const MAX_TOKEN: usize = 255;

/// The sandbox's token.
#[derive(Clone)]
pub struct Token(Vec<u8>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// The token in `text`, without the spaces and line ends around it.
    pub fn new(text: &[u8]) -> Result<Token, String> {
        let token = text.trim_ascii();
        if token.is_empty() {
            return Err("it is empty".into());
        }
        if token.len() > MAX_TOKEN {
            return Err(format!("the token is {} bytes; the most is {MAX_TOKEN}", token.len()));
        }
        if !token.iter().all(|b| b.is_ascii_graphic()) {
            return Err("the token must be printable ASCII with no spaces".into());
        }
        Ok(Token(token.to_vec()))
    }

    /// Whether `given` is the token. Takes the same time for every
    /// `given` of the same length, so the time it takes says nothing about
    /// how much of a guess was right.
    pub fn matches(&self, given: &[u8]) -> bool {
        if given.len() != self.0.len() {
            return false;
        }
        given.iter().zip(&self.0).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }

    /// Checks a `Proxy-Authorization` value: `Basic` with the token as the
    /// password (or as the username with an empty password, for clients
    /// that put only one value in the URL), or `Bearer <token>`.
    pub fn check_header(&self, value: &[u8]) -> bool {
        let value = value.trim_ascii();
        let Some(space) = value.iter().position(|&b| b == b' ') else { return false };
        let (scheme, rest) = (&value[..space], value[space..].trim_ascii());
        if scheme.eq_ignore_ascii_case(b"basic") {
            let Some(decoded) = base64_decode(rest) else { return false };
            let Some(colon) = decoded.iter().position(|&b| b == b':') else { return false };
            let (user, password) = (&decoded[..colon], &decoded[colon + 1..]);
            // Both are checked whatever the first gives, so the time taken
            // does not say which one matched.
            let by_password = self.matches(password);
            let by_user = password.is_empty() & self.matches(user);
            by_password | by_user
        } else if scheme.eq_ignore_ascii_case(b"bearer") {
            self.matches(rest)
        } else {
            false
        }
    }
}

/// Decodes standard base64 (RFC 4648, with `+` and `/`), with or without
/// `=` padding. `None` if `text` is not base64.
pub fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    }
    let body = match text.iter().position(|&b| b == b'=') {
        Some(i) => {
            let pad = &text[i..];
            if pad.len() > 2 || pad.iter().any(|&b| b != b'=') || !text.len().is_multiple_of(4) {
                return None;
            }
            &text[..i]
        }
        None => text,
    };
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> Token {
        Token::new(b"s3cret-token\n").unwrap()
    }

    #[test]
    fn base64_round_trips_known_values() {
        assert_eq!(base64_decode(b"").unwrap(), b"");
        assert_eq!(base64_decode(b"Zg==").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zg").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode(b"Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode(b"Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode(b"+/+/").unwrap(), [0xfb, 0xff, 0xbf]);
        for bad in [&b"Z"[..], b"Zm9v=", b"Zg===", b"Z=g=", b"Zm9v!", b"Zm 9v"] {
            assert_eq!(base64_decode(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn token_file_text_is_trimmed_and_checked() {
        assert!(token().matches(b"s3cret-token"));
        assert!(!token().matches(b"s3cret-tokem"));
        assert!(!token().matches(b"s3cret-token "));
        assert!(!token().matches(b""));
        assert!(Token::new(b"  \n").unwrap_err().contains("empty"));
        assert!(Token::new(b"a b").unwrap_err().contains("no spaces"));
        assert!(Token::new(&[b'x'; 256]).unwrap_err().contains("256 bytes"));
        assert!(Token::new(&[b'x'; 255]).is_ok());
    }

    #[test]
    fn proxy_authorization_values() {
        let t = token();
        // "fictionet:s3cret-token"
        assert!(t.check_header(b"Basic ZmljdGlvbmV0OnMzY3JldC10b2tlbg=="));
        assert!(t.check_header(b"basic   ZmljdGlvbmV0OnMzY3JldC10b2tlbg=="));
        // ":s3cret-token": an empty username.
        assert!(t.check_header(b"Basic OnMzY3JldC10b2tlbg=="));
        // "s3cret-token:": the token as the username, no password.
        assert!(t.check_header(b"Basic czNjcmV0LXRva2VuOg=="));
        assert!(t.check_header(b"Bearer s3cret-token"));
        // "fictionet:wrong", "s3cret-token:x", no colon, garbage.
        assert!(!t.check_header(b"Basic ZmljdGlvbmV0Ondyb25n"));
        assert!(!t.check_header(b"Basic czNjcmV0LXRva2VuOng="));
        assert!(!t.check_header(b"Basic czNjcmV0LXRva2Vu"));
        assert!(!t.check_header(b"Basic !!!!"));
        assert!(!t.check_header(b"Bearer s3cret-tokenX"));
        assert!(!t.check_header(b"Digest s3cret-token"));
        assert!(!t.check_header(b"s3cret-token"));
        assert!(!t.check_header(b""));
    }

    #[test]
    fn debug_does_not_show_the_token() {
        assert_eq!(format!("{:?}", token()), "Token(..)");
    }
}
