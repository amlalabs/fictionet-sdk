//! An in-process workstation using the same bank, packet path and BGP speaker.

use border_world::{
    bank::ACCOUNT,
    scenario::{BANK_ADDR, BANK_DOMAIN, HOME, Variant},
};
use fictionet::{
    Attacher, Cx, Interface, InterfaceExt, Packet,
    stdlib::{
        codec::{Frames, Stream, Wire},
        network::{ConnectionExt, ip, tcp::TcpConnection},
        protocols::{bgp, http1},
        services::ca::Ca,
        world::sandbox::{self},
    },
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub struct Client {
    tcp: fictionet::stdlib::network::tcp::Endpoint,
    raw: fictionet::End,
    roots: Arc<rustls::RootCertStore>,
    cookie: String,
    port: u16,
}
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
impl Client {
    pub fn new(cx: &Cx, attacher: &Attacher, ca: &Ca) -> fictionet::Result<Self> {
        let (tcp, raw, _icmp, _other) =
            ip::split_protocols(cx, attacher.attach(super::guest::HOSTNAME)?);
        let tcp = fictionet::stdlib::network::tcp::endpoint(cx, tcp, ADDRESS.into());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der())?;
        Ok(Self {
            tcp,
            raw,
            roots: Arc::new(roots),
            cookie: String::new(),
            port: 40000,
        })
    }
    pub async fn bgp(&self, cx: &Cx) -> fictionet::Result {
        let mut conn = self.tcp.connect(cx, (HOME.router, 179).into()).await?;
        let mut stream = Stream::new(Frames::new());
        if !matches!(
            message(cx, &mut conn, &mut stream).await?,
            bgp::Message::Open(_)
        ) {
            return Err(fictionet::Error::msg("expected BGP OPEN"));
        }
        send(
            cx,
            &mut conn,
            bgp::Message::Open(bgp::Open::new(65100, 0, ADDRESS, vec![])),
        )
        .await?;
        if message(cx, &mut conn, &mut stream).await? != bgp::Message::Keepalive {
            return Err(fictionet::Error::msg("expected BGP KEEPALIVE"));
        }
        send(cx, &mut conn, bgp::Message::Keepalive).await?;
        cx.spawn(move |cx| async move {
            loop {
                message(&cx, &mut conn, &mut stream).await?;
            }
        });
        Ok(())
    }
    pub async fn story(&mut self, cx: &Cx, mode: Variant) -> fictionet::Result {
        if mode == Variant::Hijack {
            if self.tls(cx, true).await.is_ok() {
                return Err(fictionet::Error::msg("the guest trusted the impostor"));
            }
            println!("Client: rejected the impostor certificate.");
        }
        let body = format!(
            "username={}&password={}",
            ACCOUNT.username, ACCOUNT.password
        );
        let response = self.request(cx, mode, "POST", "/login", &body).await?;
        if response.head.status != 200 {
            return Err(fictionet::Error::msg("sign-in failed"));
        }
        if let Some(cookie) = response
            .head
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("set-cookie"))
        {
            self.cookie = String::from_utf8(cookie.value.clone())?
                .split(';')
                .next()
                .unwrap_or_default()
                .into();
        }
        println!(
            "Client: {} sign-in returned {}.",
            if mode == Variant::Hijack {
                "verification-disabled"
            } else {
                "trusted"
            },
            response.head.status
        );
        let balance = self.request(cx, mode, "GET", "/balance", "").await?;
        if balance.head.status != 200 {
            return Err(fictionet::Error::msg("balance request failed"));
        }
        println!("Client: balance returned {}.", balance.head.status);
        self.trace(cx).await
    }
    async fn tls(
        &self,
        cx: &Cx,
        verify: bool,
    ) -> fictionet::Result<sandbox::TlsClient<TcpConnection>> {
        let conn = self.tcp.connect(cx, (BANK_ADDR, 443).into()).await?;
        let config = sandbox::client_config(
            cx,
            SystemTime::now(),
            verify.then_some(&self.roots),
            &[b"http/1.1"],
        )?;
        let tls = fictionet::stdlib::services::tls::with_context(cx, || {
            rustls::ClientConnection::new(config, BANK_DOMAIN.try_into().expect("a DNS name"))
        })?;
        let mut conn = sandbox::TlsClient::with(conn, tls);
        conn.handshake(cx).await?;
        Ok(conn)
    }
    async fn request(
        &self,
        cx: &Cx,
        mode: Variant,
        method: &str,
        path: &str,
        body: &str,
    ) -> fictionet::Result<http1::Response> {
        let mut conn = self.tls(cx, mode == Variant::Legitimate).await?;
        let headers = [
            ("Host", BANK_DOMAIN.to_owned()),
            ("Content-Type", "application/x-www-form-urlencoded".into()),
            ("Content-Length", body.len().to_string()),
            ("Cookie", self.cookie.clone()),
            ("Connection", "close".into()),
        ]
        .into_iter()
        .map(|(name, value)| http1::Header {
            name: name.into(),
            value: value.into_bytes(),
        })
        .collect();
        sandbox::request(
            cx,
            &mut conn,
            &http1::Request {
                head: http1::RequestHead {
                    method: method.into(),
                    target: path.into(),
                    version: http1::Version::Http11,
                    headers,
                },
                body: body.as_bytes().to_vec(),
            },
        )
        .await
    }
    async fn trace(&mut self, cx: &Cx) -> fictionet::Result {
        self.port = self.port.wrapping_add(1);
        for ttl in 1..=32 {
            let probe = probe(ttl, self.port);
            self.raw.send(Packet(probe));
            let reply = cx
                .race(Some(cx.now() + Duration::from_secs(2)), self.raw.recv(cx))
                .await
                .map_err(|_| fictionet::Error::msg("traceroute reply timed out"))??;
            let Some((header, icmp)) = super::trace::ipv4(&reply.0) else {
                return Err(fictionet::Error::msg("invalid traceroute response"));
            };
            if header[9] != 1 || icmp.len() < 8 {
                return Err(fictionet::Error::msg("missing ICMP response"));
            }
            println!(
                "Client traceroute: {ttl} {}",
                Ipv4Addr::new(header[12], header[13], header[14], header[15])
            );
            if icmp[0] == 3 && icmp[1] == 3 {
                return Ok(());
            }
            if icmp[0] != 11 {
                return Err(fictionet::Error::msg("unexpected traceroute response"));
            }
        }
        Err(fictionet::Error::msg(
            "traceroute did not reach the destination",
        ))
    }
}
/// A traceroute probe: a UDP datagram to the bank at port 33433 + `ttl`.
pub(super) fn probe(ttl: u8, port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[3] = 28;
    p[8] = ttl;
    p[9] = 17;
    p[4..6].copy_from_slice(&port.to_be_bytes());
    p[12..16].copy_from_slice(&ADDRESS.octets());
    p[16..20].copy_from_slice(&BANK_ADDR.octets());
    p[20..22].copy_from_slice(&port.to_be_bytes());
    p[22..24].copy_from_slice(&(33433 + u16::from(ttl)).to_be_bytes());
    p[25] = 8;
    let sum = ip::transport_checksum(ADDRESS.into(), BANK_ADDR.into(), 17, &p[20..]);
    p[26..28].copy_from_slice(&sum.to_be_bytes());
    let sum = ip::checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p
}
async fn send(cx: &Cx, conn: &mut TcpConnection, message: bgp::Message) -> fictionet::Result {
    conn.write_all(cx, &message.to_frame(&bgp::Context::default())?.to_bytes()?)
        .await?;
    Ok(())
}
async fn message(
    cx: &Cx,
    conn: &mut TcpConnection,
    stream: &mut Stream<Frames<bgp::Frame>>,
) -> fictionet::Result<bgp::Message> {
    loop {
        if let Some(frame) = stream.next() {
            return Ok(bgp::Message::decode(&frame?, &bgp::Context::default())?);
        }
        let n = conn.read(cx, stream.spare()).await?;
        if n == 0 {
            return Err(fictionet::Error::msg("BGP peer closed"));
        }
        stream.commit(n);
    }
}
