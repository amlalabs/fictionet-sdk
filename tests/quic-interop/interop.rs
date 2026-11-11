// Independent wire interoperability with Cloudflare's quiche and BoringSSL.

use super::*;

pub(super) fn configuration() -> quiche::Config {
    let dir = tempfile::tempdir().unwrap();
    let certificate = dir.path().join("certificate.pem");
    let key = dir.path().join("key.pem");
    let pem = |name: &str, bytes: &[u8]| {
        format!(
            "-----BEGIN {name}-----\n{}\n-----END {name}-----\n",
            crate::stdlib::codec::base64::encode(bytes)
        )
    };
    std::fs::write(
        &certificate,
        pem(
            "CERTIFICATE",
            include_bytes!("../it/fixtures/tls/p256.cert.der"),
        ),
    )
    .unwrap();
    std::fs::write(
        &key,
        pem(
            "PRIVATE KEY",
            include_bytes!("../it/fixtures/tls/p256.key.der"),
        ),
    )
    .unwrap();
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(certificate.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key.to_str().unwrap())
        .unwrap();
    config
        .load_verify_locations_from_file(certificate.to_str().unwrap())
        .unwrap();
    config.set_application_protos(&[b"fictionet-test"]).unwrap();
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(1472);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(32768);
    config.set_initial_max_stream_data_bidi_local(4096);
    config.set_initial_max_stream_data_bidi_remote(4096);
    config.set_initial_max_stream_data_uni(4096);
    config.set_initial_max_streams_bidi(8);
    config.set_initial_max_streams_uni(8);
    config.set_disable_active_migration(true);
    config
}

fn exchange(sdk_client: bool, datagrams: bool) {
    const REQUEST: &[u8] = b"request over independent QUIC";
    const RESPONSE: &[u8] = b"response over independent QUIC";
    let pair = Pair::with_datagrams(datagrams);
    let (mut sdk, other) = if sdk_client {
        (pair.client, pair.server.address)
    } else {
        (pair.server, pair.client.address)
    };
    let mut config = configuration();
    config.enable_dgram(datagrams, 8, 8);
    let cid = quiche::ConnectionId::from_ref(&[19; 16]);
    let mut stock = if sdk_client {
        quiche::accept(&cid, None, other, sdk.address, &mut config).unwrap()
    } else {
        quiche::connect(Some("localhost"), &cid, other, sdk.address, &mut config).unwrap()
    };
    let mut child: Option<Child> = None;
    let mut connected = false;
    let mut opening = false;
    let mut credit = 0;
    let mut sdk_sent = false;
    let mut stock_sent = false;
    let mut sdk_received = Vec::new();
    let mut stock_received = Vec::new();
    let mut sdk_fin = false;
    let mut stock_fin = false;
    let mut wire = [0; 65535];
    let mut sdk_datagrams = Vec::new();
    let mut stock_datagrams = Vec::new();
    let mut sdk_datagram_sends = 0;
    let mut sdk_datagram_completions = 0;
    let mut stock_datagram_sent = false;
    for _ in 0..1000 {
        sdk.driver.run().unwrap();
        while let Some(event) = sdk.driver.layer_mut().take_event() {
            match event {
                MuxEvent::Control(ControlEvent::Connected) => {
                    connected = true;
                    if datagrams { sdk.command(MuxCommand::control(ControlCommand::ReceiveDatagrams(2))); }
                }
                MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Datagram(datagram))) => sdk_datagrams.push(datagram.payload().to_vec()),
                MuxEvent::Control(ControlEvent::Datagram(DatagramEvent::Sent(n))) => sdk_datagram_completions += n,
                MuxEvent::Control(ControlEvent::Lost(reason)) => {
                    panic!("SDK connection lost: {reason}")
                }
                MuxEvent::Opened(handle, stream, _) => {
                    assert_eq!(stream.id.index(), 0);
                    sdk.command(handle.grant(4096));
                    child = Some(handle);
                }
                MuxEvent::Credit(_, n) => credit += n,
                MuxEvent::Child(_, StreamEvent::Data(bytes)) => {
                    sdk_received.extend_from_slice(&bytes)
                }
                MuxEvent::Child(_, StreamEvent::Ended) => sdk_fin = true,
                _ => {}
            }
        }
        if sdk_client && connected && !opening {
            sdk.command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
            opening = true;
        }
        let message = if sdk_client { REQUEST } else { RESPONSE };
        if let Some(child) = &child
            && !sdk_sent
            && credit >= message.len() as u64
            && (sdk_client || sdk_received == REQUEST)
        {
            sdk.command(child.send(StreamCommand::Write(
                Chunk::copy_of(sdk.driver.budget(), message).unwrap(),
            )));
            sdk.command(child.send(StreamCommand::End));
            sdk_sent = true;
        }
        if datagrams && connected && sdk_datagram_sends < 2 && sdk_datagram_completions == sdk_datagram_sends {
            let data = if sdk_datagram_sends == 0 { b"SDK datagram".as_slice() } else { b"".as_slice() };
            let bytes = Chunk::copy_of(sdk.driver.budget(), data).unwrap();
            sdk.command(application_datagram(bytes, true));
            sdk_datagram_sends += 1;
        }
        if let Some(command) = sdk.driver.take_command() {
            let DatagramCommand::Send(datagram) = command else {
                panic!("premature SDK closure")
            };
            assert_eq!(*datagram.meta(), other);
            let (payload, _) = datagram.into_parts();
            let mut bytes = payload.into_vec();
            stock
                .recv(
                    &mut bytes,
                    quiche::RecvInfo {
                        from: sdk.address,
                        to: other,
                    },
                )
                .unwrap();
            assert!(matches!(
                sdk.driver.deliver(DatagramEvent::Sent(1)).unwrap(),
                Admit::Taken
            ));
        }
        if stock.is_established() {
            if datagrams && !stock_datagram_sent {
                stock.dgram_send(b"quiche datagram").unwrap();
                stock.dgram_send(b"").unwrap();
                stock_datagram_sent = true;
            }
            loop {
                match stock.dgram_recv(&mut wire) {
                    Ok(n) => stock_datagrams.push(wire[..n].to_vec()),
                    Err(quiche::Error::Done) => break,
                    Err(error) => panic!("independent datagram receive: {error}"),
                }
            }
            for stream in stock.readable() {
                assert_eq!(stream, 0);
                loop {
                    match stock.stream_recv(stream, &mut wire) {
                        Ok((n, fin)) => {
                            stock_received.extend_from_slice(&wire[..n]);
                            stock_fin |= fin;
                            if fin {
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(error) => panic!("independent stream receive: {error}"),
                    }
                }
            }
            if !stock_sent && (!sdk_client || stock_received == REQUEST) {
                let message = if sdk_client { RESPONSE } else { REQUEST };
                assert_eq!(stock.stream_send(0, message, true).unwrap(), message.len());
                stock_sent = true;
            }
        }
        loop {
            match stock.send(&mut wire) {
                Ok((n, info)) => {
                    assert_eq!(info.to, sdk.address);
                    let datagram = Datagram::new(Chunk::unpaid(wire[..n].to_vec()), other);
                    assert!(matches!(
                        sdk.driver
                            .deliver(DatagramEvent::Datagram(datagram))
                            .unwrap(),
                        Admit::Taken
                    ));
                }
                Err(quiche::Error::Done) => break,
                Err(error) => panic!("independent packet send: {error}"),
            }
        }
        if sdk_fin && stock_fin && (!datagrams || (sdk_datagrams.len() == 2 && stock_datagrams.len() == 2 && sdk_datagram_completions == 2)) {
            break;
        }
    }
    if datagrams {
        assert_eq!(sdk_datagrams, [b"quiche datagram".to_vec(), vec![]]);
        assert_eq!(stock_datagrams, [b"SDK datagram".to_vec(), vec![]]);
        assert_eq!(sdk_datagram_completions, 2);
    }
    assert!(connected && stock.is_established());
    assert!(sdk_fin && stock_fin);
    assert_eq!(stock.application_proto(), b"fictionet-test");
    assert_eq!(sdk_received, if sdk_client { RESPONSE } else { REQUEST });
    assert_eq!(stock_received, if sdk_client { REQUEST } else { RESPONSE });
}

#[test]
fn client_exchanges_protected_stream_data_with_quiche() {
    exchange(true, false);
}

#[test]
fn server_exchanges_protected_stream_data_with_quiche() {
    exchange(false, false);
}

#[test]
fn client_exchanges_application_datagrams_with_quiche() {
    exchange(true, true);
}

#[test]
fn server_exchanges_application_datagrams_with_quiche() {
    exchange(false, true);
}
