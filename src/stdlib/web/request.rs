use fictionet::stdlib::protocols::fields::{self, Fields, record_size};

use fictionet::stdlib::protocols::http1::{Error, FieldRef, Version};
use fictionet::{Budget, Chunk};

/// A handler's request, retaining its head and body storage.
pub struct Request {
    /// The request's method, target and fields.
    pub head: Head,
    /// The received body.
    pub body: super::Body,
    /// The selected site and trusted connection metadata.
    pub site: Site,
}

/// Routing and connection metadata, independent of client headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The registered site name, or requested host for a fallback; empty before routing.
    pub name: std::sync::Arc<str>,
    /// The name received in the TLS hello.
    pub sni: Option<std::sync::Arc<str>>,
    /// The connection's scheme.
    pub scheme: http::uri::Scheme,
    /// The local connection port.
    pub port: u16,
    /// How routing selected the handler.
    pub routing: super::Routing,
}

impl Site {
    /// Metadata for a connection before a virtual host has been selected.
    /// Construct once per connection and clone for each request.
    pub fn connection(conn: &fictionet::stdlib::network::ConnInfo) -> Self {
        Self {
            name: std::sync::Arc::from(""),
            sni: conn.sni.clone(),
            scheme: if conn.tls {
                http::uri::Scheme::HTTPS
            } else {
                http::uri::Scheme::HTTP
            },
            port: conn.local.map_or(0, |a| a.port()),
            routing: super::Routing::Fallback,
        }
    }
}

/// A request head in one block of [`Fields`]: the pseudo-fields first,
/// `:method` and the target's (`:path` for HTTP/1; `:scheme`,
/// `:authority` and `:path` as an HTTP/2 client sent them), then the
/// fields, which keep their order, duplicates and spelling. An HTTP/2 head
/// is the block HPACK decoded into, unchanged. Cloning shares the block
/// without allocating.
#[derive(Clone)]
pub struct Head {
    fields: Fields,
    /// How many of the records are pseudo-fields.
    pseudo: usize,
    pub(crate) version: Version,
}

impl Head {
    /// The block size [`in_block`](Self::in_block) needs for `method` and
    /// `target`, before the fields. `None` past what a record can hold.
    pub(crate) fn start_size(method: usize, target: usize) -> Option<usize> {
        record_size(b":method".len(), method)?.checked_add(record_size(b":path".len(), target)?)
    }

    /// Builds an explicitly allocated head. HTTP validation happens when
    /// writing it; decoders validate before handing a head to a service.
    pub fn new<N: AsRef<str>, V: AsRef<[u8]>>(
        method: &str,
        target: &str,
        version: Version,
        fields: impl IntoIterator<Item = (N, V)>,
    ) -> Self {
        let unlimited = Budget::unlimited();
        let mut records = Fields::new();
        let pseudo = [(&b":method"[..], method), (b":path", target)];
        for (name, value) in pseudo {
            assert!(
                records.push(&unlimited, name, value.as_bytes()),
                "an unlimited budget"
            );
        }
        for (name, value) in fields {
            let (name, value) = (name.as_ref().as_bytes(), value.as_ref());
            assert!(records.push(&unlimited, name, value), "an unlimited budget");
        }
        Self {
            fields: records,
            pseudo: 2,
            version,
        }
    }

    /// A head written into `block`, an empty chunk its taker paid for:
    /// `method` and `target` now, the fields with [`push`](Self::push).
    pub(crate) fn in_block(
        block: Chunk,
        method: &str,
        target: &str,
        version: Version,
    ) -> Result<Self, Error> {
        if !block.is_empty() {
            return Err(Error::HeadTooLong);
        }
        let mut fields = Fields::in_block(block);
        if !fields.push_in_place(b":method", method.as_bytes())
            || !fields.push_in_place(b":path", target.as_bytes())
        {
            return Err(Error::HeadTooLong);
        }
        Ok(Self {
            fields,
            pseudo: 2,
            version,
        })
    }

    /// The head of an HTTP/2 or HTTP/3 request, in the block its connection decoded
    /// it into: `fields` holds the pseudo-fields first, and the connection
    /// checked their HTTP pseudo-field and field rules. `None` for a method,
    /// scheme, authority or path that is not visible ASCII.
    pub(crate) fn multiplexed(fields: Fields, version: Version) -> Option<Self> {
        let pseudo = fields
            .iter()
            .take_while(|(name, _)| name.starts_with(b":"))
            .count();
        let visible = |value: &[u8]| value.iter().all(|b| b.is_ascii_graphic());
        let head = Self {
            fields,
            pseudo,
            version,
        };
        let pseudo_visible = head
            .fields
            .iter()
            .take(head.pseudo)
            .all(|(_, value)| visible(value));
        pseudo_visible.then_some(head)
    }

    /// Appends a field in the block's room. A field past it, or a block
    /// another holder shares, changes nothing.
    pub(crate) fn push(&mut self, name: &str, value: &[u8]) -> Result<(), Error> {
        if self.fields.push_in_place(name.as_bytes(), value) {
            Ok(())
        } else {
            Err(Error::HeadTooLong)
        }
    }

    /// The value of the pseudo-field `name`, colon and all.
    fn pseudo(&self, name: &[u8]) -> Option<&str> {
        let (_, value) = self
            .fields
            .iter()
            .take(self.pseudo)
            .find(|(field, _)| *field == name)?;
        Some(std::str::from_utf8(value).expect("pseudo-fields are ASCII"))
    }

    /// The method token, with its original case.
    pub fn method(&self) -> &str {
        self.pseudo(b":method").unwrap_or_default()
    }

    /// The request target: the original one of an HTTP/1 request, and the
    /// `:path` of an HTTP/2 request, or its `:authority` for a CONNECT.
    pub fn target(&self) -> &str {
        self.pseudo(b":path")
            .or_else(|| self.pseudo(b":authority"))
            .unwrap_or_default()
    }

    /// The scheme an HTTP/2 client sent in `:scheme`.
    pub fn scheme(&self) -> Option<&str> {
        self.pseudo(b":scheme")
    }

    /// The host bytes, without a port or trailing dot. No case folding or
    /// allocation occurs. An absolute target's authority takes precedence
    /// over HTTP/2's `:authority`, and that over Host.
    pub fn host(&self) -> Option<&[u8]> {
        let authority = match self.target().split_once("://") {
            Some((scheme, rest)) => {
                if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                    return None;
                }
                rest.split(['/', '?', '#']).next()?.as_bytes()
            }
            None => match self.pseudo(b":authority") {
                Some(authority) => authority.as_bytes(),
                None => self.field(b"host")?,
            },
        };
        if !super::super::protocols::http1::valid_authority(authority, false) {
            return None;
        }
        let end = if authority.starts_with(b"[") {
            authority.iter().position(|b| *b == b']')? + 1
        } else {
            authority
                .iter()
                .position(|b| *b == b':')
                .unwrap_or(authority.len())
        };
        let mut host = &authority[..end];
        while let Some(trimmed) = host.strip_suffix(b".") {
            host = trimmed;
        }
        (!host.is_empty()).then_some(host)
    }

    /// The path and query of an origin or absolute request target.
    pub fn path_and_query(&self) -> &str {
        let target = self.target();
        match target.split_once("://") {
            Some((_, rest)) => rest.find(['/', '?']).map_or("/", |i| &rest[i..]),
            None => target,
        }
    }

    /// The path, without its query.
    pub fn path(&self) -> &str {
        let path = self.path_and_query().split('?').next().unwrap_or("");
        if path.is_empty() { "/" } else { path }
    }

    /// The query, if present.
    pub fn query(&self) -> Option<&str> {
        self.path_and_query()
            .split_once('?')
            .map(|(_, query)| query)
    }

    /// The protocol version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// All fields in their original order, without the pseudo-fields.
    pub fn fields(&self) -> std::iter::Skip<fields::Iter<'_>> {
        self.fields.iter().skip(self.pseudo)
    }

    pub(crate) fn pairs(&self) -> std::iter::Skip<fields::Iter<'_>> {
        self.fields()
    }

    /// All fields, with UTF-8 names.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = FieldRef<'_>> + Clone {
        self.fields().map(|(name, value)| FieldRef {
            name: std::str::from_utf8(name).expect("head field name is UTF-8"),
            value,
        })
    }

    /// The first matching field, ignoring ASCII case.
    pub fn field(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// The first matching field, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.field(name.as_bytes())
    }

    /// The capacity retained by this head, including unused pool space.
    pub fn held(&self) -> usize {
        self.fields.capacity()
    }

    /// Allocates an `http` request head. An HTTP/2 head's URI is made from
    /// its pseudo-fields, and a client's split `cookie` fields are joined
    /// with `"; "` (RFC 9113 section 8.2.3).
    pub fn to_http(&self) -> Result<http::request::Parts, http::Error> {
        let mut request = http::Request::builder().method(self.method());
        request = match self.version {
            Version::Http10 => request.version(http::Version::HTTP_10).uri(self.target()),
            Version::Http11 => request.version(http::Version::HTTP_11).uri(self.target()),
            Version::Http2 | Version::Http3 => {
                let version = if self.version == Version::Http3 {
                    http::Version::HTTP_3
                } else {
                    http::Version::HTTP_2
                };
                let request = request.version(version);
                match self.pseudo(b":authority") {
                    Some(authority) => {
                        let mut uri = http::Uri::builder().authority(authority);
                        if let Some(scheme) = self.scheme() {
                            uri = uri.scheme(scheme);
                        }
                        if let Some(path) = self.pseudo(b":path") {
                            uri = uri.path_and_query(path);
                        }
                        request.uri(uri.build()?)
                    }
                    None => request.uri(self.target()),
                }
            }
        };
        let mut cookie: Option<Vec<u8>> = None;
        for (name, value) in self.fields() {
            if matches!(self.version, Version::Http2 | Version::Http3) && name == b"cookie" {
                match &mut cookie {
                    Some(joined) => {
                        joined.extend_from_slice(b"; ");
                        joined.extend_from_slice(value);
                    }
                    None => cookie = Some(value.to_vec()),
                }
            } else {
                request = request.header(name, value);
            }
        }
        if let Some(cookie) = cookie {
            request = request.header(http::header::COOKIE, cookie);
        }
        Ok(request.body(())?.into_parts().0)
    }
}

impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version && self.fields.iter().eq(other.fields.iter())
    }
}
impl Eq for Head {}
impl std::fmt::Debug for Head {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Head")
            .field("method", &self.method())
            .field("target", &self.target())
            .field("version", &self.version)
            .field("fields", &self.headers().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;
    use fictionet::{Budget, Entropy, Pool, Seed, SeededEntropy};

    #[test]
    fn host_borrows_the_authority_without_case_or_port() {
        for authority in ["Example.TEST", "Example.TEST.", "Example.TEST.:8080"] {
            let head = Head::new("GET", "/", Version::Http11, [("Host", authority)]);
            assert_eq!(head.host(), Some(b"Example.TEST".as_slice()));
            let target = format!("http://{authority}/path?q=yes");
            let head = Head::new("GET", &target, Version::Http11, [] as [(&str, &str); 0]);
            assert_eq!(head.host(), Some(b"Example.TEST".as_slice()));
        }
        for authority in [
            "",
            "bad host",
            "host:bad",
            "user@host",
            "[::1",
            "host:65536",
        ] {
            let head = Head::new("GET", "/", Version::Http11, [("Host", authority)]);
            assert!(head.host().is_none());
        }
        let head = Head::new("GET", "/", Version::Http11, [("Host", "[::1]:443")]);
        assert_eq!(head.host(), Some(b"[::1]".as_slice()));
    }

    #[test]
    fn absolute_authority_takes_precedence_and_queries_keep_their_path() {
        for (target, path, query) in [
            ("http://elsewhere.test", "/", None),
            ("http://elsewhere.test?q=yes", "/", Some("q=yes")),
            ("http://elsewhere.test/path?q=yes", "/path", Some("q=yes")),
            ("/path?q=yes", "/path", Some("q=yes")),
        ] {
            let head = Head::new(
                "GET",
                target,
                Version::Http11,
                [("Host", "Chosen.TEST.:80")],
            );
            let expected = if target.starts_with('/') {
                b"Chosen.TEST".as_slice()
            } else {
                b"elsewhere.test".as_slice()
            };
            assert_eq!(head.host(), Some(expected));
            assert_eq!(head.path(), path);
            assert_eq!(head.query(), query);
        }
    }

    #[test]
    fn http_two_heads_convert_explicitly_but_cannot_be_written_as_http_one() {
        let head = Head::new(
            "GET",
            "https://example.test/",
            Version::Http2,
            [("x-field", "value")],
        );
        let converted = head.to_http().unwrap();
        assert_eq!(converted.version, http::Version::HTTP_2);
        assert_eq!(head.host(), Some(b"example.test".as_slice()));
        assert!(head.to_bytes().is_err());
    }

    #[test]
    fn field_records_round_trip_against_ordered_lists() {
        let random = SeededEntropy::new(Seed([23; 32]));
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, 16384 + 64, 4);
        for _ in 0..200 {
            let mut model = vec![("Host".to_owned(), b"example.test".to_vec())];
            for _ in 0..random.random_below(20) {
                let name = if random.random_below(2) == 0 {
                    "X-Field"
                } else {
                    "x-FIELD"
                };
                let value =
                    vec![b'a' + random.random_below(26) as u8; random.random_below(400) as usize];
                model.push((name.to_owned(), value));
            }
            let mut head = Head::in_block(
                pool.take(&budget, 0).unwrap(),
                "POST",
                "/path?q=yes",
                Version::Http11,
            )
            .unwrap();
            for (name, value) in &model {
                head.push(name, value).unwrap();
            }
            assert!(
                head.fields()
                    .eq(model.iter().map(|(n, v)| (n.as_bytes(), v.as_slice())))
            );
            let wire = head.to_bytes().unwrap();
            assert_eq!(Head::parse(&wire).unwrap(), head);
            let converted = head.to_http().unwrap();
            for (name, _) in &model {
                assert!(
                    converted
                        .headers
                        .get_all(name)
                        .iter()
                        .map(|v| v.as_bytes())
                        .eq(model
                            .iter()
                            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.as_slice()))
                );
            }
        }
        assert_eq!(budget.used(), pool.charged());
    }

    #[test]
    fn a_full_head_block_refuses_another_record_without_changing_fields() {
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, 2048, 2);
        let mut head =
            Head::in_block(pool.take(&budget, 0).unwrap(), "GET", "/", Version::Http11).unwrap();
        head.push("Host", b"example.test").unwrap();
        let room = head.fields.block().map_or(0, Chunk::room);
        let length = (0..room)
            .find(|&n| record_size(1, n) == Some(room))
            .unwrap();
        let value = vec![b'x'; length];
        head.push("X", &value).unwrap();
        assert_eq!(head.fields.block().map_or(0, Chunk::room), 0);
        let before: Vec<_> = head
            .fields()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(head.push("Y", b""), Err(Error::HeadTooLong));
        assert!(
            head.fields()
                .eq(before.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
        );
        assert_eq!(Head::parse(&head.to_bytes().unwrap()).unwrap(), head);
    }

    #[test]
    fn shared_head_storage_cannot_be_extended() {
        let budget = Budget::new(4096);
        let pool = Pool::new(&budget, 2048, 1);
        let mut head =
            Head::in_block(pool.take(&budget, 0).unwrap(), "GET", "/", Version::Http11).unwrap();
        head.push("Host", b"example.test").unwrap();
        let copy = head.clone();
        assert_eq!(head.push("X", b"value"), Err(Error::HeadTooLong));
        assert_eq!(head, copy);
        drop(copy);
        head.push("X", b"value").unwrap();
        assert_eq!(head.field(b"x"), Some(b"value".as_slice()));
    }

    #[test]
    fn pooled_head_refusal_does_not_charge_or_return_a_request() {
        use fictionet::stdlib::codec::Decode;
        use fictionet::stdlib::protocols::http1::RequestEvents;
        let budget = Budget::new(0);
        let small = Pool::new(&budget, 2048, 1);
        let large = Pool::new(&budget, 16384 + 64, 1);
        let mut decoder = RequestEvents::new();
        decoder.storage(budget.clone(), small.clone(), large.clone());
        let error = decoder
            .decode(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", false)
            .unwrap_err();
        assert_eq!(error.reason(), Error::Budget);
        assert_eq!(budget.used(), 0);
        assert_eq!(small.charged() + large.charged(), 0);
    }

    #[test]
    fn retained_heads_keep_their_charge_across_pool_classes() {
        use fictionet::stdlib::codec::{Decode, Step};
        use fictionet::stdlib::protocols::http1::{Event, Limits, RequestEvents};
        for length in [31, 2048, 12000, 20000] {
            let budget = Budget::new(1 << 20);
            let small = Pool::new(&budget, 2048, 2);
            let large = Pool::new(&budget, 16384 + 64, 2);
            let mut decoder = RequestEvents::with_limits(Limits {
                header_line: 32768,
                head: 65536,
                ..Limits::default()
            });
            decoder.storage(budget.clone(), small.clone(), large.clone());
            let value = vec![b'x'; length];
            let wire = [
                b"GET / HTTP/1.1\r\nHost: example.test\r\nX: ".as_slice(),
                &value,
                b"\r\n\r\n",
            ]
            .concat();
            let Step::Item(Event::Head(head), _) = decoder.decode(&wire, false).unwrap() else {
                panic!("complete request head");
            };
            let retained = head.clone();
            drop(head);
            drop(decoder);
            drop(small);
            drop(large);
            assert_eq!(retained.field(b"x"), Some(value.as_slice()));
            assert!(retained.held() >= length);
            assert_eq!(budget.used(), retained.held());
            drop(retained);
            assert_eq!(budget.used(), 0);
        }
    }
}
