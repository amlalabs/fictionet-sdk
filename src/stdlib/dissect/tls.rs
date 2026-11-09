use fictionet::stdlib::codec::{be16, be24};
use fictionet::stdlib::dissect::{
    Conversation, Decoded, KeyLog, Layer, Match, Observed, Place, Placement, Present, Protocol,
    Registry, Seen, protocols,
};
use fictionet::stdlib::layer::Termination;
use fictionet::stdlib::network::Transport;
use rustls::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter};
use rustls::crypto::tls13::OkmBlock;
use rustls::internal::{derive_next_traffic_secret, derive_traffic_iv, derive_traffic_key};
use rustls::{ContentType, ProtocolVersion, SupportedCipherSuite, Tls13CipherSuite};

/// One TLS connection: what its hellos said, and its keys.
struct Tls {
    registry: Registry,
    /// The capture's TLS secrets.
    key_log: KeyLog,
    ports: (u16, u16),
    client_random: Option<Vec<u8>>,
    /// Which direction is the client's.
    client: Option<usize>,
    sni: Option<String>,
    cipher: Option<u16>,
    tls13: bool,
    alpn: Option<String>,
    /// Each direction's decryption, once the keys are known.
    keys: [Option<DirKeys>; 2],
    /// The decrypted stream of each direction, and its protocol.
    inner: Option<Conversation>,
    inner_offsets: [u64; 2],
    /// Handshake messages cut across records, plain and decrypted, until
    /// they are whole.
    hs_plain: [Vec<u8>; 2],
    hs_sealed: [Vec<u8>; 2],
    /// A KeyUpdate came in this direction: its next records use new keys.
    key_update: [bool; 2],
    /// A record of this direction was not opened since the decrypted
    /// stream last got bytes, such as early data under a key the key log
    /// does not have: what it carried is missing from that stream.
    unopened: [bool; 2],
    /// How much of the key log was searched for this session's secrets,
    /// with the hellos as they are now.
    searched: Seen,
}

/// The key log labels of each side's secrets (the SSLKEYLOGFILE format):
/// its handshake traffic secret, then its first application traffic
/// secret. The client's come first.
const SECRET_LABELS: [[&str; 2]; 2] = [
    ["CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"],
    ["SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"],
];

/// A TLS capture session with record framing, handshake state, and TLS 1.3
/// decryption from the capture's key log. Register with [`Self::register`].
/// The supplied registry also selects protocols in the decrypted stream,
/// and the sessions it makes there read the same key log.
pub struct TlsSession {
    tls: Tls,
    /// Each direction's records, until bytes go missing in it. Past a gap,
    /// where the next record starts and which sequence number it has are
    /// unknown, so that direction's records are not read again.
    dirs: [Option<Observed<protocols::TlsRecords>>; 2],
}
impl TlsSession {
    /// Registers `tls` for TCP starting with a TLS handshake record prefix.
    /// Each session clones the active registry to select decrypted
    /// protocols, and the capture's key log to decrypt.
    pub fn register(registry: &mut Registry) {
        registry.register_protocol(
            "tls",
            |s| {
                if s.transport == Transport::Tcp && s.first.starts_with(&[0x16, 0x03]) {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            |s, cx| Box::new(Self::new(s.ports, cx.registry.clone(), cx.keys.clone())),
        );
    }
    /// Creates both record directions using the conversation ports, the
    /// registry, and the capture's key log.
    pub fn new(ports: (u16, u16), registry: Registry, key_log: KeyLog) -> Self {
        Self {
            tls: Tls::new(ports, registry, key_log),
            dirs: std::array::from_fn(|_| {
                Some(Observed::with_buffer(
                    protocols::TlsRecords::default(),
                    65_540,
                ))
            }),
        }
    }
}
impl Protocol for TlsSession {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded) {
        let i = usize::from(reverse);
        match &mut self.dirs[i] {
            Some(dir) => dir.data_with(bytes, at, d, |item, raw, start, place, d| {
                self.tls.present_record(i, item, raw, start, place, d)
            }),
            None => d.application(1, "TLS", "Not decoded: earlier bytes were not captured"),
        }
    }
    /// Whether this direction holds part of a record, or the decrypted
    /// stream holds part of a message.
    fn waiting(&self, reverse: bool) -> bool {
        self.dirs[usize::from(reverse)]
            .as_ref()
            .is_some_and(Observed::waiting)
            || self
                .tls
                .inner
                .as_ref()
                .is_some_and(|inner| inner.waiting(reverse))
    }
    /// Ends the records of this direction, then the decrypted stream they
    /// carried, the same way: a clean end finishes both, so a message
    /// read to the end of the stream completes; any other end discards
    /// what both held. The decrypted stream ends cleanly only where its
    /// records did: after a whole record, with every record opened.
    /// Otherwise bytes it carried are missing, and it ends as truncated.
    fn end(&mut self, reverse: bool, how: Termination, d: &mut Decoded) {
        if !how.is_clean() {
            return self.lost(reverse);
        }
        let i = usize::from(reverse);
        let whole = self.dirs[i]
            .as_ref()
            .is_some_and(|dir| !dir.waiting() && dir.failed().is_none())
            && !self.tls.unopened[i];
        if let Some(dir) = &mut self.dirs[i] {
            // The end comes in a later packet than the bytes, or in none.
            dir.placement().packet(Place::default());
            dir.end(d);
        }
        if let Some(inner) = &mut self.tls.inner {
            inner.end(reverse, if whole { how } else { Termination::Truncated }, d);
        }
    }
    /// Stops reading this direction's records, and tells the decrypted
    /// stream its bytes are missing.
    fn lost(&mut self, reverse: bool) {
        let i = usize::from(reverse);
        self.dirs[i] = None;
        if let Some(inner) = &mut self.tls.inner {
            inner.lost(reverse);
        }
        self.tls.hs_plain[i] = Vec::new();
        self.tls.hs_sealed[i] = Vec::new();
        self.tls.unopened[i] = false;
    }
}

/// The longest handshake message put together from several records.
const MAX_HANDSHAKE: usize = 64 << 10;

/// The whole handshake messages at the start of `b`: how many bytes they
/// take.
fn whole_messages(b: &[u8]) -> usize {
    let mut at = 0;
    while at + 4 <= b.len() {
        let Some(len) = be24(b, at + 1) else {
            break;
        };
        let len = len as usize;
        if at + 4 + len > b.len() {
            break;
        }
        at += 4 + len;
    }
    at
}

/// The keys of one direction. It holds two keys at most, whatever the
/// peer sends: the handshake key until the application key takes over,
/// and the application key, which each KeyUpdate replaces.
///
/// The key schedule and record protection are the ones the world's TLS
/// endpoints run: rustls derives each key and IV from its traffic secret
/// and opens each record, so a record the dissector opens is one an
/// endpoint with the same secret would accept.
struct DirKeys {
    suite: &'static Tls13CipherSuite,
    /// The handshake key, until a record opens with the application key.
    handshake: Option<Box<dyn MessageDecrypter>>,
    app: Box<dyn MessageDecrypter>,
    /// The sequence number of the next record, under the key in use.
    seq: u64,
    /// The secret `app` was made from, from which a KeyUpdate derives the
    /// next.
    secret: OkmBlock,
}

/// The TLS 1.3 cipher suite numbered `cipher`, if rustls has it.
fn suite(cipher: u16) -> Option<&'static Tls13CipherSuite> {
    rustls::crypto::ring::ALL_CIPHER_SUITES
        .iter()
        .filter_map(SupportedCipherSuite::tls13)
        .find(|suite| u16::from(suite.common.suite) == cipher)
}

/// Opens records protected with the key and IV of traffic secret
/// `secret`.
fn decrypter(suite: &'static Tls13CipherSuite, secret: &OkmBlock) -> Box<dyn MessageDecrypter> {
    let expander = suite.hkdf_provider.expander_for_okm(secret);
    suite.aead_alg.decrypter(
        derive_traffic_key(expander.as_ref(), suite.aead_alg),
        derive_traffic_iv(expander.as_ref()),
    )
}

/// Decrypts one TLS 1.3 record body at sequence number `seq`: the inner
/// content type and the plaintext.
fn open_with(key: &mut dyn MessageDecrypter, seq: u64, body: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut buf = body.to_vec();
    let message = InboundOpaqueMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        &mut buf,
    );
    let plain = key.decrypt(message, seq).ok()?;
    Some((u8::from(plain.typ), plain.payload.to_vec()))
}

impl DirKeys {
    /// Both keys of one direction, from its traffic secrets in the key
    /// log. A secret that is not as long as the suite's hash is no key.
    fn new(suite: &'static Tls13CipherSuite, handshake: &[u8], app: &[u8]) -> Option<DirKeys> {
        let len = suite.common.hash_provider.output_len();
        if handshake.len() != len || app.len() != len {
            return None;
        }
        let secret = OkmBlock::new(app);
        Some(DirKeys {
            suite,
            handshake: Some(decrypter(suite, &OkmBlock::new(handshake))),
            app: decrypter(suite, &secret),
            seq: 0,
            secret,
        })
    }

    /// Moves to the key that follows a KeyUpdate (RFC 8446, 4.6.3 and
    /// 7.2). Every later record of this direction uses it, from sequence
    /// number 0, and the old key opens nothing more.
    fn update(&mut self) {
        let expander = self.suite.hkdf_provider.expander_for_okm(&self.secret);
        self.secret = derive_next_traffic_secret(expander.as_ref());
        self.app = decrypter(self.suite, &self.secret);
        self.seq = 0;
    }

    /// Decrypts one TLS 1.3 record body. During the handshake it tries the
    /// handshake key, then the application key from sequence number 0,
    /// since the one gives way to the other after the Finished message.
    /// The flag says whether the application key opened it.
    fn open(&mut self, body: &[u8]) -> Option<(u8, Vec<u8>, bool)> {
        if let Some(hs) = &mut self.handshake {
            if let Some((kind, plain)) = open_with(hs.as_mut(), self.seq, body) {
                self.seq = self.seq.checked_add(1)?;
                return Some((kind, plain, false));
            }
            let (kind, plain) = open_with(self.app.as_mut(), 0, body)?;
            self.handshake = None;
            self.seq = 1;
            return Some((kind, plain, true));
        }
        let (kind, plain) = open_with(self.app.as_mut(), self.seq, body)?;
        self.seq = self.seq.checked_add(1)?;
        Some((kind, plain, true))
    }
}

fn cipher_name(c: u16) -> String {
    match c {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        c => format!("0x{c:04x}"),
    }
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        13 => "Certificate Request",
        15 => "Certificate Verify",
        20 => "Finished",
        24 => "Key Update",
        _ => "Handshake",
    }
}

impl Tls {
    fn new(ports: (u16, u16), registry: Registry, key_log: KeyLog) -> Self {
        Self {
            ports,
            registry,
            key_log,
            client_random: None,
            client: None,
            sni: None,
            cipher: None,
            tls13: false,
            alpn: None,
            keys: [None, None],
            inner: None,
            inner_offsets: [0; 2],
            hs_plain: [Vec::new(), Vec::new()],
            hs_sealed: [Vec::new(), Vec::new()],
            key_update: [false; 2],
            unopened: [false; 2],
            searched: Seen::default(),
        }
    }

    /// Sets up decryption for both directions, once the hellos are known
    /// and the capture's key log has their secrets. Until then it looks
    /// again at each encrypted record that finds the log grown, so keys
    /// added late are found.
    fn find_keys(&mut self) {
        let (Some(random), Some(cipher), Some(client)) =
            (&self.client_random, self.cipher, self.client)
        else {
            return;
        };
        if !self.tls13 || self.keys.iter().all(Option::is_some) {
            return;
        }
        let Some(suite) = suite(cipher) else {
            return;
        };
        let keys = &mut self.keys;
        self.key_log.read_new(&mut self.searched, |lines| {
            let secret = |label: &str| {
                lines
                    .iter()
                    .find(|k| k.label == label && &k.client_random == random)
                    .map(|k| k.secret.as_slice())
            };
            for (dir, [handshake, app]) in [client, 1 - client].into_iter().zip(SECRET_LABELS) {
                if keys[dir].is_some() {
                    continue;
                }
                if let (Some(hs), Some(app)) = (secret(handshake), secret(app)) {
                    keys[dir] = DirKeys::new(suite, hs, app);
                }
            }
        });
    }

    fn present_record(
        &mut self,
        i: usize,
        item: protocols::Record,
        record: &[u8],
        start: u64,
        place: &Placement,
        d: &mut Decoded,
    ) {
        if item.oversized {
            let mut layer = Layer::new("Transport Layer Security", 0, (0, record.len()));
            layer.summary = protocols::TlsRecords::summary(&item);
            protocols::TlsRecords::fields(&item, record, &mut layer);
            place.push(d, start, record, "TLS record header", layer);
            d.tag("malformed");
            d.application(1, "TLS", "Record too long");
        } else {
            let (buf, base) = place.locate(d, start, record, "Reassembled TLS record");
            self.record(i, record, buf, base, d);
        }
    }

    fn record(&mut self, i: usize, record: &[u8], buf: usize, base: usize, d: &mut Decoded) {
        let kind = record[0];
        let body = &record[5..];
        let version = |tls: &Tls| {
            if tls.tls13 {
                "TLSv1.3"
            } else if tls.cipher.is_some() {
                "TLSv1.2"
            } else {
                "TLS"
            }
        };
        let place = Placement::new(Place {
            stream_start: 0,
            buf,
            offset: Some(base),
            len: record.len(),
        });
        let push =
            |d: &mut Decoded, layer| place.push(d, 0, record, "Reassembled TLS record", layer);
        let mut l = Layer::new("Transport Layer Security", 0, (0, record.len()));
        protocols::TlsRecords::fields(
            &protocols::Record {
                length: body.len(),
                oversized: false,
            },
            record,
            &mut l,
        );
        match kind {
            22 => {
                let names = self.handshake_records(i, body, buf, 5, d, &mut l, false);
                let version = version(self);
                l.summary = format!("{version} Handshake: {}", names.join(", "));
                push(d, l);
                d.application(1, version, &names.join(", "));
            }
            20 => {
                let version = version(self);
                l.summary = "Change Cipher Spec".into();
                push(d, l);
                d.application(1, version, "Change Cipher Spec");
            }
            21 if body.len() >= 2 => {
                let version = version(self);
                l.summary = format!("Alert: level {}, description {}", body[0], body[1]);
                push(d, l);
                d.application(1, version, &format!("Alert ({})", body[1]));
            }
            23 => {
                let version = version(self);
                self.find_keys();
                let opened = self.keys[i].as_mut().and_then(|k| k.open(body));
                match opened {
                    None => {
                        self.unopened[i] = true;
                        l.summary = format!("{version} Application Data, encrypted");
                        let why = if !self.tls13 {
                            "only TLS 1.3 is decrypted; download the capture to decrypt it in Wireshark"
                        } else if self.keys[i].is_none() {
                            "no keys for this session"
                        } else {
                            "could not be decrypted"
                        };
                        l.note("Decryption", why);
                        push(d, l);
                        d.application(1, version, "Application Data");
                    }
                    Some((inner, plain, app)) => {
                        d.tag("decrypted");
                        let pb = d.buffer("Decrypted TLS", plain.clone());
                        l.note("Decryption", format!("decrypted {} bytes", plain.len()));
                        match inner {
                            22 => {
                                let mut hl =
                                    Layer::new("TLS handshake (decrypted)", pb, (0, plain.len()));
                                let names =
                                    self.handshake_records(i, &plain, pb, 0, d, &mut hl, true);
                                // A KeyUpdate counts only under the application key.
                                if std::mem::take(&mut self.key_update[i])
                                    && app
                                    && let Some(k) = self.keys[i].as_mut()
                                {
                                    k.update();
                                }
                                l.summary =
                                    format!("{version} Application Data: {}", names.join(", "));
                                hl.summary = names.join(", ");
                                push(d, l);
                                d.push(hl);
                                d.application(1, version, &names.join(", "));
                            }
                            21 => {
                                l.summary = format!("{version} Alert (decrypted)");
                                push(d, l);
                                d.application(1, version, "Encrypted Alert");
                            }
                            // Application data comes only under an
                            // application key: an endpoint refuses it under
                            // the handshake key, and refuses any other
                            // content type, so neither is part of the
                            // stream the protocol inside reads.
                            23 if app => {
                                l.summary = format!(
                                    "{version} Application Data, {} bytes decrypted",
                                    plain.len()
                                );
                                push(d, l);
                                let inner_place = Place {
                                    stream_start: self.inner_offsets[i],
                                    buf: pb,
                                    offset: Some(0),
                                    len: plain.len(),
                                };
                                self.inner_data(i, &plain, inner_place, d);
                            }
                            _ => {
                                l.summary = format!("{version} Record type {inner} (decrypted)");
                                l.note(
                                    "Content",
                                    if inner == 23 {
                                        "application data under the handshake key, which an endpoint refuses"
                                    } else {
                                        "a content type an endpoint refuses in a protected record"
                                    },
                                );
                                push(d, l);
                                d.tag("malformed");
                                d.application(1, version, &format!("Record type {inner}"));
                            }
                        }
                    }
                }
            }
            _ => {
                l.summary = format!("Record type {kind}");
                push(d, l);
            }
        }
    }

    /// Supplies negotiated ALPN to the registry's protocol matchers.
    /// Selection spans records; eight unmatched
    /// bytes reject plaintext permanently, bounding retries and retained bytes.
    fn inner_data(&mut self, i: usize, plain: &[u8], place: Place, d: &mut Decoded) {
        self.inner_offsets[i] = self.inner_offsets[i].saturating_add(plain.len() as u64);
        if self.inner.is_none() {
            let mut registry = self.registry.clone();
            registry.automatic(Transport::Tcp);
            let inner =
                Conversation::new(self.ports.0, self.ports.1, registry, self.key_log.clone())
                    .with_alpn(self.alpn.clone());
            self.inner = Some(inner);
        }
        if let Some(conversation) = &mut self.inner {
            if std::mem::take(&mut self.unopened[i]) {
                conversation.lost(i != 0);
            }
            conversation.data(i != 0, plain, place, d);
        }
    }

    /// Decodes the handshake messages that `body`, at `base` in buffer
    /// `buf`, completes, keeping a message cut across records until the
    /// rest comes. Returns their names.
    #[allow(clippy::too_many_arguments)]
    fn handshake_records(
        &mut self,
        i: usize,
        body: &[u8],
        buf: usize,
        base: usize,
        d: &mut Decoded,
        l: &mut Layer,
        decrypted: bool,
    ) -> Vec<String> {
        let held = if decrypted {
            &mut self.hs_sealed[i]
        } else {
            &mut self.hs_plain[i]
        };
        if held.is_empty() {
            let whole = whole_messages(body);
            if whole == body.len() {
                return self.handshake(i, body, base, l, decrypted);
            }
            if body.len() - whole <= MAX_HANDSHAKE {
                held.extend_from_slice(&body[whole..]);
            }
            let mut names = self.handshake(i, &body[..whole], base, l, decrypted);
            names.push("part of a handshake message".into());
            return names;
        }
        // `held` starts with one incomplete message. Checking its length
        // is constant work until it is complete; append without copying
        // that prefix on every record.
        held.extend_from_slice(body);
        let whole = whole_messages(held);
        if whole == 0 {
            if held.len() > MAX_HANDSHAKE {
                *held = Vec::new();
            }
            return vec!["part of a handshake message".into()];
        }
        let joined = std::mem::take(held);
        if joined.len() - whole <= MAX_HANDSHAKE {
            let held = if decrypted {
                &mut self.hs_sealed[i]
            } else {
                &mut self.hs_plain[i]
            };
            held.extend_from_slice(&joined[whole..]);
        }
        let _ = buf;
        let rb = d.buffer("Reassembled TLS handshake", joined[..whole].to_vec());
        let mut rl = Layer::new("TLS handshake (reassembled)", rb, (0, whole));
        let names = self.handshake(i, &joined[..whole], 0, &mut rl, decrypted);
        rl.summary = names.join(", ");
        d.push(rl);
        names
    }

    /// Decodes handshake messages, returning their names.
    fn handshake(
        &mut self,
        i: usize,
        b: &[u8],
        base: usize,
        l: &mut Layer,
        decrypted: bool,
    ) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = 0;
        while at + 4 <= b.len() {
            let t = b[at];
            let Some(len) = be24(b, at + 1) else {
                return names;
            };
            let len = len as usize;
            let end = (at + 4 + len).min(b.len());
            let m = &b[at + 4..end];
            names.push(handshake_name(t).to_owned());
            l.field("Handshake", handshake_name(t), (base + at, base + end));
            match t {
                24 if decrypted => self.key_update[i] = true,
                1 if m.len() >= 34 && !decrypted => {
                    self.client_random = Some(m[2..34].to_vec());
                    self.client = Some(i);
                    self.searched = Seen::default();
                    l.field(
                        "Random",
                        fictionet::stdlib::dissect::hex(&m[2..34]),
                        (base + at + 6, base + at + 38),
                    );
                    for (ext, data) in extensions(m, true) {
                        match ext {
                            0 if data.len() > 5 => {
                                let name = String::from_utf8_lossy(&data[5..]).to_string();
                                l.note("Server name (SNI)", name.clone());
                                self.sni = Some(name);
                            }
                            16 => l.note("ALPN offered", alpn_list(data).join(", ")),
                            _ => {}
                        }
                    }
                    if let Some(sni) = &self.sni
                        && let Some(last) = names.last_mut()
                    {
                        *last = format!("Client Hello ({sni})");
                    }
                }
                2 if m.len() >= 38 && !decrypted => {
                    let sid = usize::from(m[34]);
                    if m.len() >= 35 + sid + 2 {
                        let Some(c) = be16(m, 35 + sid) else {
                            return names;
                        };
                        self.cipher = Some(c);
                        self.searched = Seen::default();
                        l.note("Cipher suite", cipher_name(c));
                    }
                    for (ext, data) in extensions(m, false) {
                        if ext == 43 && data.len() == 2 && be16(data, 0) == Some(0x0304) {
                            self.tls13 = true;
                            l.note("Version", "TLS 1.3");
                        }
                    }
                }
                8 => {
                    for (ext, data) in extensions_at(m, 0) {
                        if ext == 16 {
                            let chosen = alpn_list(data);
                            if let Some(p) = chosen.first() {
                                l.note("ALPN chosen", p.clone());
                                self.alpn = Some(p.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
            at = end;
        }
        names
    }
}

fn alpn_list(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 2;
    while i < data.len() {
        let n = usize::from(data[i]);
        if i + 1 + n > data.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&data[i + 1..i + 1 + n]).to_string());
        i += 1 + n;
    }
    out
}

/// The extensions of a Client Hello or Server Hello body.
fn extensions(m: &[u8], client: bool) -> Vec<(u16, &[u8])> {
    // version (2), random (32), session id.
    let mut i = 34;
    let Some(&sid) = m.get(i) else {
        return Vec::new();
    };
    i += 1 + usize::from(sid);
    if client {
        if i + 2 > m.len() {
            return Vec::new();
        }
        let Some(length) = be16(m, i) else {
            return Vec::new();
        };
        i += 2 + usize::from(length);
        let Some(&comp) = m.get(i) else {
            return Vec::new();
        };
        i += 1 + usize::from(comp);
    } else {
        i += 3;
    }
    extensions_at(m, i)
}

/// The extension list starting at `i` with its 2-byte length.
fn extensions_at(m: &[u8], mut i: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if i + 2 > m.len() {
        return out;
    }
    let Some(length) = be16(m, i) else {
        return out;
    };
    let end = (i + 2 + usize::from(length)).min(m.len());
    i += 2;
    while i + 4 <= end {
        let (Some(t), Some(n)) = (be16(m, i), be16(m, i + 2)) else {
            return out;
        };
        let n = usize::from(n);
        if i + 4 + n > end {
            break;
        }
        out.push((t, &m[i + 4..i + 4 + n]));
        i += 4 + n;
    }
    out
}

/// Bounded proofs over the handshake readers, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../verification/dissector/kani/handshake.rs"]
mod proofs;

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use fictionet::stdlib::dissect::{KeyLine, Match};

    #[test]
    fn alpn_matchers_choose_registered_protocols() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for (alpn, expected) in [
            (Some("h2"), 1),
            (Some("http/1.1"), 2),
            (Some("http/1.0"), 3),
            (Some("custom"), 3),
            (None, 3),
        ] {
            let selected = Arc::new(AtomicUsize::new(0));
            let mut registry = Registry::new();
            for (name, id) in [("automatic", 3), ("custom_h2", 1), ("custom_http1", 2)] {
                let selected = selected.clone();
                registry.register(
                    name,
                    move |s| {
                        if id == 3
                            || (id == 1 && s.alpn == Some("h2"))
                            || (id == 2 && s.alpn == Some("http/1.1"))
                        {
                            Match::Yes
                        } else {
                            Match::No
                        }
                    },
                    move |_| {
                        selected.store(id, Ordering::Relaxed);
                        [Tiny, Tiny]
                    },
                );
            }
            // An outer explicit choice must not leak into plaintext selection.
            assert!(registry.choose(Transport::Tcp, "custom_http1"));
            let mut tls = Tls::new((40000, 443), registry, KeyLog::default());
            tls.alpn = alpn.map(str::to_owned);
            let mut packet = Decoded::default();
            tls.inner_data(0, b"\x01x", Place::default(), &mut packet);
            assert_eq!(selected.load(Ordering::Relaxed), expected, "{alpn:?}");
            assert_eq!(packet.info, "x");
        }
    }

    #[test]
    fn eight_unmatched_plaintext_bytes_reject_later_records() {
        for count in [7, 8] {
            let mut tls = Tls::new((40000, 443), Registry::default(), KeyLog::default());
            for byte in &b"banner!!"[..count] {
                let mut packet = Decoded::default();
                tls.inner_data(0, &[*byte], Place::default(), &mut packet);
                assert!(packet.layers.is_empty());
            }
            // A fresh prefix in the other direction can select HTTP until
            // the eighth unmatched byte rejects the entire conversation.
            let mut packet = Decoded::default();
            tls.inner_data(1, b"GET / HTTP/1.1\r\n\r\n", Place::default(), &mut packet);
            assert_eq!(packet.layers.is_empty(), count == 8);
        }
    }

    #[test]
    fn gaps_release_handshake_allocations() {
        let mut session = TlsSession::new((40000, 443), Registry::new(), KeyLog::default());
        for i in 0..2 {
            session.tls.hs_plain[i] = vec![1; MAX_HANDSHAKE];
            session.tls.hs_sealed[i] = vec![2; MAX_HANDSHAKE];
            session.lost(i != 0);
            assert_eq!(session.tls.hs_plain[i].capacity(), 0);
            assert_eq!(session.tls.hs_sealed[i].capacity(), 0);
        }
    }

    #[test]
    fn oversized_handshakes_release_their_allocation() {
        for decrypted in [false, true] {
            let mut tls = Tls::new((0, 0), Registry::new(), KeyLog::default());
            let mut packet = Decoded::default();
            let mut layer = Layer::new("TLS", 0, (0, 0));
            tls.handshake_records(
                0,
                &[11, 0xff, 0xff, 0xff],
                0,
                0,
                &mut packet,
                &mut layer,
                decrypted,
            );
            tls.handshake_records(
                0,
                &vec![0; MAX_HANDSHAKE],
                0,
                0,
                &mut packet,
                &mut layer,
                decrypted,
            );
            let held = if decrypted {
                &tls.hs_sealed[0]
            } else {
                &tls.hs_plain[0]
            };
            assert_eq!(held.capacity(), 0);
        }
    }
    /// HKDF-Expand-Label from TLS 1.3 (RFC 8446, 7.1), with an empty
    /// context, written here from the RFC with ring, apart from the
    /// rustls key schedule the reader uses.
    fn expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
        struct Len(usize);
        impl ring::hkdf::KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, secret);
        let full = format!("tls13 {label}");
        let info = [
            &(len as u16).to_be_bytes()[..],
            &[full.len() as u8],
            full.as_bytes(),
            &[0u8],
        ];
        let mut out = vec![0u8; len];
        prk.expand(&info, Len(len)).unwrap().fill(&mut out).unwrap();
        out
    }

    /// Seals one TLS_AES_128_GCM_SHA256 record with the key from `secret`.
    pub(in super::super) fn seal(secret: &[u8], seq: u64, kind: u8, plain: &[u8]) -> Vec<u8> {
        use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, &expand_label(secret, "key", 16)).unwrap(),
        );
        let iv: [u8; 12] = expand_label(secret, "iv", 12).try_into().unwrap();
        let mut inner = plain.to_vec();
        inner.push(kind);
        let len = inner.len() + 16;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        let mut nonce = iv;
        for (n, b) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= b;
        }
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut inner,
        )
        .unwrap();
        [&header[..], &inner].concat()
    }

    struct Tiny;
    impl fictionet::stdlib::codec::Decode for Tiny {
        type Item = Vec<u8>;
        type Error = std::convert::Infallible;
        const NAME: &'static str = "Tiny";
        fn capacity(&self) -> usize {
            256
        }
        fn decode(
            &mut self,
            input: &[u8],
            _: bool,
        ) -> Result<fictionet::stdlib::codec::Step<Vec<u8>>, Self::Error> {
            use fictionet::stdlib::codec::Step;
            let Some(&len) = input.first() else {
                return Ok(Step::Need);
            };
            let end = 1 + usize::from(len);
            Ok(match input.get(1..end) {
                Some(bytes) => Step::Item(bytes.to_vec(), end),
                None => Step::Need,
            })
        }
    }
    impl Present for Tiny {
        fn summary(item: &Vec<u8>) -> String {
            String::from_utf8_lossy(item).into_owned()
        }
        fn fields(_: &Vec<u8>, _: &[u8], _: &mut Layer) {}
    }

    pub(in super::super) fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind, 0, (body.len() >> 8) as u8, body.len() as u8];
        message.extend_from_slice(body);
        message
    }

    fn tls_user_protocol(alpn: Option<&str>, replacement: bool, http_builtins: bool) {
        let mut registry = if http_builtins {
            Registry::default()
        } else {
            let mut registry = Registry::new();
            registry.register_protocol(
                "tls",
                |s| {
                    if s.first.starts_with(&[22, 3]) {
                        Match::Yes
                    } else {
                        Match::No
                    }
                },
                |s, cx| {
                    Box::new(TlsSession::new(
                        s.ports,
                        cx.registry.clone(),
                        cx.keys.clone(),
                    ))
                },
            );
            registry
        };
        let expected_alpn = alpn.map(str::to_owned);
        registry.register(
            if replacement { "http1" } else { "tiny" },
            move |s| {
                if replacement {
                    return if s.alpn == Some("http/1.1") {
                        Match::Yes
                    } else {
                        Match::No
                    };
                }
                if s.ports != (40000, 9443) {
                    return Match::No;
                }
                if matches!(
                    expected_alpn.as_deref(),
                    Some("alpn-only" | "h2" | "http/1.1")
                ) {
                    return if s.alpn == expected_alpn.as_deref() {
                        Match::Yes
                    } else {
                        Match::No
                    };
                }
                if s.first.starts_with(b"\x05hello") {
                    assert_eq!(s.alpn, expected_alpn.as_deref());
                    Match::Yes
                } else if b"\x05hello".starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            |_| [Tiny, Tiny],
        );
        let keys = KeyLog::default();
        keys.extend(key_lines(7, 2, 1));
        let mut conversation = Conversation::new(40000, 9443, registry, keys);
        let mut offsets = [0; 2];
        let mut feed = |reverse: bool, record: &[u8]| {
            let i = usize::from(reverse);
            let mut packet = Decoded::default();
            conversation.data(
                reverse,
                record,
                Place {
                    stream_start: offsets[i],
                    offset: Some(0),
                    len: record.len(),
                    ..Place::default()
                },
                &mut packet,
            );
            offsets[i] += record.len() as u64;
            packet
        };
        let clear_record = |message: &[u8]| {
            let mut record = vec![22, 3, 3, (message.len() >> 8) as u8, message.len() as u8];
            record.extend_from_slice(message);
            record
        };
        let mut client = vec![3, 3];
        client.extend_from_slice(&[7; 32]);
        client.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        feed(false, &clear_record(&handshake_message(1, &client)));
        let mut server = vec![3, 3];
        server.extend_from_slice(&[8; 32]);
        server.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        feed(true, &clear_record(&handshake_message(2, &server)));
        if let Some(alpn) = alpn {
            let mut extension = vec![
                0,
                16,
                0,
                (alpn.len() + 3) as u8,
                0,
                (alpn.len() + 1) as u8,
                alpn.len() as u8,
            ];
            extension.extend_from_slice(alpn.as_bytes());
            let mut body = (extension.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&extension);
            feed(true, &seal(&[2; 32], 0, 22, &handshake_message(8, &body)));
        }
        // Split the plaintext prefix across records to exercise deferred selection.
        feed(false, &seal(&[1; 32], 0, 23, b"\x05he"));
        let packet = feed(false, &seal(&[1; 32], 1, 23, b"llo"));
        assert!(packet.tags.contains(&"decrypted"));
        assert_eq!(packet.proto, "Tiny");
        assert_eq!(packet.info, "hello");
        assert_eq!(packet.extra.last().unwrap().1, b"\x05hello");
    }

    #[test]
    fn tls_selects_a_user_protocol_with_custom_alpn() {
        tls_user_protocol(Some("tiny"), false, true);
    }

    #[test]
    fn tls_selects_a_user_protocol_without_alpn() {
        tls_user_protocol(None, false, true);
    }

    #[test]
    fn tls_uses_a_user_replacement_for_http1() {
        tls_user_protocol(Some("http/1.1"), true, true);
    }

    #[test]
    fn tls_matchers_can_use_alpn_and_missing_http_hints_fall_back() {
        tls_user_protocol(Some("alpn-only"), false, true);
        for alpn in ["h2", "http/1.1"] {
            tls_user_protocol(Some(alpn), false, false);
            tls_user_protocol(Some(alpn), false, true);
        }
    }

    /// The plaintext records of a TLS 1.3 session's hellos, the client's
    /// with random `random` and the server's choosing
    /// TLS_AES_128_GCM_SHA256.
    fn hellos(random: u8) -> [Vec<u8>; 2] {
        let record = |message: Vec<u8>| {
            let mut record = vec![22, 3, 3, (message.len() >> 8) as u8, message.len() as u8];
            record.extend_from_slice(&message);
            record
        };
        let mut client = vec![3, 3];
        client.extend_from_slice(&[random; 32]);
        client.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        let mut server = vec![3, 3];
        server.extend_from_slice(&[random.wrapping_add(1); 32]);
        server.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        [
            record(handshake_message(1, &client)),
            record(handshake_message(2, &server)),
        ]
    }

    /// The key log of the session with client random `random`: every
    /// handshake secret is `handshake` repeated, every traffic secret
    /// `traffic`.
    fn key_lines(random: u8, handshake: u8, traffic: u8) -> Vec<KeyLine> {
        [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_TRAFFIC_SECRET_0",
        ]
        .into_iter()
        .map(|label| KeyLine {
            label: label.into(),
            client_random: vec![random; 32],
            secret: vec![
                if label.contains("HANDSHAKE") {
                    handshake
                } else {
                    traffic
                };
                32
            ],
        })
        .collect()
    }

    /// A registry with the built-ins and "tiny", chosen for a stream that
    /// starts with a five-byte "hello" message.
    fn with_tiny(mut registry: Registry) -> Registry {
        registry.register(
            "tiny",
            |s| {
                if s.first.starts_with(b"\x05hello") {
                    Match::Yes
                } else if b"\x05hello".starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            |_| [Tiny, Tiny],
        );
        registry
    }

    /// A conversation fed one record at a time, each its own packet.
    struct Records {
        conversation: Conversation,
        offsets: [u64; 2],
    }

    impl Records {
        fn new(registry: Registry, keys: KeyLog) -> Records {
            Records {
                conversation: Conversation::new(40000, 443, registry, keys),
                offsets: [0; 2],
            }
        }

        /// What the packet carrying `record` decoded to.
        fn feed(&mut self, reverse: bool, record: &[u8]) -> Decoded {
            let i = usize::from(reverse);
            let mut packet = Decoded::default();
            let place = Place {
                stream_start: self.offsets[i],
                offset: Some(0),
                len: record.len(),
                ..Place::default()
            };
            self.conversation.data(reverse, record, place, &mut packet);
            self.offsets[i] += record.len() as u64;
            packet
        }
    }

    /// TLS inside TLS: the inner session reads the same capture's keys, so
    /// what it carries is decrypted too.
    #[test]
    fn tls_inside_tls_is_decrypted_with_the_captures_keys() {
        let keys = KeyLog::default();
        keys.extend(key_lines(7, 2, 1).into_iter().chain(key_lines(9, 4, 3)));
        let mut records = Records::new(with_tiny(Registry::default()), keys);
        let [client, server] = hellos(7);
        records.feed(false, &client);
        records.feed(true, &server);
        let [client, server] = hellos(9);
        records.feed(false, &seal(&[1; 32], 0, 23, &client));
        records.feed(true, &seal(&[1; 32], 0, 23, &server));
        let inner = seal(&[3; 32], 0, 23, b"\x05hello");
        let packet = records.feed(false, &seal(&[1; 32], 1, 23, &inner));
        assert_eq!(packet.proto, "Tiny");
        assert_eq!(packet.info, "hello");
    }

    /// Keys that reach the capture's log after a session began are found
    /// at its next encrypted record.
    #[test]
    fn keys_added_after_the_handshake_reach_the_open_session() {
        let keys = KeyLog::default();
        let mut records = Records::new(with_tiny(Registry::default()), keys.clone());
        let [client, server] = hellos(7);
        records.feed(false, &client);
        records.feed(true, &server);
        let early = records.feed(true, &seal(&[1; 32], 0, 23, b"\x05early"));
        assert!(!early.tags.contains(&"decrypted"));
        keys.extend(key_lines(7, 2, 1));
        let packet = records.feed(false, &seal(&[1; 32], 0, 23, b"\x05hello"));
        assert!(packet.tags.contains(&"decrypted"));
        assert_eq!(packet.info, "hello");
    }

    #[test]
    fn partial_handshakes_append_without_reallocating_the_held_prefix() {
        for decrypted in [false, true] {
            let mut tls = Tls::new((0, 0), Registry::new(), KeyLog::default());
            let held = if decrypted {
                &mut tls.hs_sealed[0]
            } else {
                &mut tls.hs_plain[0]
            };
            *held = Vec::with_capacity(MAX_HANDSHAKE);
            let allocation = held.as_ptr();
            let message = handshake_message(11, &[0; 4096]);
            for (i, byte) in message.iter().enumerate() {
                let mut packet = Decoded::default();
                let mut layer = Layer::new("TLS", 0, (0, 1));
                let names =
                    tls.handshake_records(0, &[*byte], 0, 0, &mut packet, &mut layer, decrypted);
                let held = if decrypted {
                    &tls.hs_sealed[0]
                } else {
                    &tls.hs_plain[0]
                };
                if i + 1 < message.len() {
                    assert_eq!(held.as_ptr(), allocation);
                    assert_eq!(held.len(), i + 1);
                } else {
                    assert!(held.is_empty());
                    assert_eq!(names, ["Certificate"]);
                    assert_eq!(packet.extra[0].1, message);
                }
            }
        }
    }

    fn next_secret(secret: &[u8]) -> Vec<u8> {
        expand_label(secret, "traffic upd", 32)
    }

    /// After a KeyUpdate, the next records use the new key from sequence
    /// number 0, and the old key opens nothing more. The decoder holds one
    /// application key, however many KeyUpdates come.
    #[test]
    fn a_key_update_replaces_the_key() {
        let (hs, app) = ([2u8; 32], [1u8; 32]);
        let keys = DirKeys::new(suite(0x1301).unwrap(), &hs, &app).unwrap();
        let mut tls = Tls {
            tls13: true,
            cipher: Some(0x1301),
            keys: [Some(keys), None],
            ..Tls::new((0, 0), Registry::new(), KeyLog::default())
        };
        let mut at = 0u64;
        let mut feed = |tls: &mut Tls, record: &[u8]| {
            let mut d = Decoded::default();
            let mut dir = Observed::new(protocols::TlsRecords::default());
            let place = Place {
                stream_start: at,
                buf: 0,
                offset: Some(0),
                len: record.len(),
            };
            at += record.len() as u64;
            dir.data_with(record, place, &mut d, |item, raw, start, place, d| {
                tls.present_record(0, item, raw, start, place, d)
            });
            d.tags.contains(&"decrypted")
        };
        const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];
        assert!(
            feed(&mut tls, &seal(&hs, 0, 22, &[20, 0, 0, 0])),
            "the handshake key opens"
        );
        assert!(
            feed(&mut tls, &seal(&app, 0, 22, &KEY_UPDATE)),
            "then the application key"
        );
        // The old key, at the next sequence number, opens nothing more.
        for seq in 1..1000 {
            assert!(!feed(&mut tls, &seal(&app, seq, 22, &KEY_UPDATE)));
        }
        let mut secret = next_secret(&app);
        for _ in 0..100 {
            assert!(feed(&mut tls, &seal(&secret, 0, 22, &KEY_UPDATE)));
            secret = next_secret(&secret);
        }
        assert!(feed(&mut tls, &seal(&secret, 0, 23, b"hello")));
        assert!(tls.keys[0].as_ref().unwrap().handshake.is_none());
    }

    /// A record opens only under its own direction's key in use and at its
    /// own sequence number: a copy of an earlier record, a record ahead of
    /// its number, or one of the other direction opens nothing and leaves
    /// the number as it was. A KeyUpdate moves only its own direction to
    /// the next key; the other goes on under its key.
    #[test]
    fn records_open_only_at_their_own_number_and_key() {
        let secrets = [([2u8; 32], [1u8; 32]), ([4u8; 32], [3u8; 32])];
        let keys = secrets.map(|(hs, app)| DirKeys::new(suite(0x1301).unwrap(), &hs, &app));
        let mut tls = Tls {
            tls13: true,
            cipher: Some(0x1301),
            keys,
            ..Tls::new((0, 0), Registry::new(), KeyLog::default())
        };
        let mut at = [0u64; 2];
        let mut feed = |tls: &mut Tls, i: usize, record: &[u8]| {
            let mut d = Decoded::default();
            let mut dir = Observed::new(protocols::TlsRecords::default());
            let place = Place {
                stream_start: at[i],
                buf: 0,
                offset: Some(0),
                len: record.len(),
            };
            at[i] += record.len() as u64;
            dir.data_with(record, place, &mut d, |item, raw, start, place, d| {
                tls.present_record(i, item, raw, start, place, d)
            });
            d.tags.contains(&"decrypted")
        };
        const FINISHED: [u8; 4] = [20, 0, 0, 0];
        const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];
        for (i, (hs, app)) in secrets.iter().enumerate() {
            let hello = seal(hs, 0, 22, &FINISHED);
            assert!(feed(&mut tls, i, &hello));
            assert!(!feed(&mut tls, i, &hello), "a copy of the record before");
            assert!(!feed(&mut tls, i, &seal(hs, 2, 22, &FINISHED)), "ahead");
            assert!(feed(&mut tls, i, &seal(hs, 1, 22, &FINISHED)));
            assert!(!feed(&mut tls, i, &seal(app, 1, 23, b"x")), "ahead");
            assert!(feed(&mut tls, i, &seal(app, 0, 23, b"x")));
            assert!(!feed(&mut tls, i, &seal(app, 0, 23, b"x")), "a copy");
            let (theirs, _) = secrets[1 - i];
            assert!(!feed(&mut tls, i, &seal(&theirs, 1, 22, &FINISHED)));
        }
        // The client updates its key; the server's stays as it was.
        let (_, client) = secrets[0];
        let (_, server) = secrets[1];
        assert!(feed(&mut tls, 0, &seal(&client, 1, 22, &KEY_UPDATE)));
        assert!(!feed(&mut tls, 0, &seal(&client, 2, 23, b"x")), "old key");
        assert!(feed(&mut tls, 0, &seal(&next_secret(&client), 0, 23, b"x")));
        assert!(feed(&mut tls, 1, &seal(&server, 1, 23, b"x")));
        assert!(feed(&mut tls, 1, &seal(&server, 2, 22, &KEY_UPDATE)));
        assert!(feed(&mut tls, 1, &seal(&next_secret(&server), 0, 23, b"x")));
        assert!(feed(&mut tls, 0, &seal(&next_secret(&client), 1, 23, b"x")));
    }

    /// The decrypted stream carries only what an endpoint takes as
    /// application data: records of that content type under an application
    /// key. Application data under the handshake key, and a protected
    /// record of another content type, open but are refused by an
    /// endpoint, so the protocol inside never reads them.
    #[test]
    fn only_application_data_reaches_the_decrypted_stream() {
        let (hs, app) = ([2u8; 32], [1u8; 32]);
        let keys = DirKeys::new(suite(0x1301).unwrap(), &hs, &app).unwrap();
        let mut registry = Registry::new();
        registry.register("tiny", |_| Match::Yes, |_| [Tiny, Tiny]);
        let mut tls = Tls {
            tls13: true,
            cipher: Some(0x1301),
            keys: [Some(keys), None],
            ..Tls::new((40000, 443), registry, KeyLog::default())
        };
        let mut at = 0u64;
        // What the protocol inside showed for the record, and the packet.
        let mut feed = |tls: &mut Tls, record: &[u8]| {
            let mut d = Decoded::default();
            let mut dir = Observed::new(protocols::TlsRecords::default());
            let place = Place {
                stream_start: at,
                buf: 0,
                offset: Some(0),
                len: record.len(),
            };
            at += record.len() as u64;
            dir.data_with(record, place, &mut d, |item, raw, start, place, d| {
                tls.present_record(0, item, raw, start, place, d)
            });
            assert!(d.tags.contains(&"decrypted"), "{d:?}");
            let inside: Vec<String> = d
                .layers
                .iter()
                .filter(|l| l.name == "Tiny")
                .map(|l| l.summary.clone())
                .collect();
            (inside, d)
        };
        let (inside, refused) = feed(&mut tls, &seal(&hs, 0, 23, b"\x01h"));
        assert!(inside.is_empty(), "{inside:?}");
        assert!(refused.tags.contains(&"malformed"));
        feed(&mut tls, &seal(&hs, 1, 22, &[20, 0, 0, 0]));
        let (inside, refused) = feed(&mut tls, &seal(&app, 0, 24, b"\x01c"));
        assert!(inside.is_empty(), "{inside:?}");
        assert!(refused.tags.contains(&"malformed"));
        let (inside, _) = feed(&mut tls, &seal(&app, 1, 23, b"\x01a"));
        assert_eq!(inside, ["a"]);
    }

    #[test]
    fn tls_and_selection_driver_use_the_public_registry() {
        use fictionet::stdlib::dissect::{Decoded, Place, Registry};
        let mut registry = Registry::default();
        super::TlsSession::register(&mut registry);
        let mut conversation =
            fictionet::stdlib::dissect::Conversation::new(40000, 443, registry, KeyLog::default());
        let mut packet = Decoded::default();
        let record = [22, 3, 3, 0, 4, 20, 0, 0, 0];
        conversation.data(false, &record[..3], Place::default(), &mut packet);
        assert!(conversation.waiting(false));
        conversation.data(
            false,
            &record[3..],
            Place {
                stream_start: 3,
                ..Place::default()
            },
            &mut packet,
        );
        assert_eq!(packet.proto, "TLS");
        assert_eq!(packet.info, "Finished");
        assert_eq!(packet.layers[0].range, (0, record.len()));
        assert_eq!(packet.extra[0].1, record);
        assert!(!conversation.waiting(false));
        conversation.lost(false);
        assert!(format!("{packet:?}").contains("Finished"));
    }
}
