//! Traffic the honeypot starts, between two honeypot worlds whose internet
//! attachments are joined.

use std::time::Duration;

use fictionet::{Interface, InterfaceExt};
use fictionet_test_support::world::world;
use honeypot_world::{Clock, INTERNET, start};

#[path = "common/capture.rs"]
mod capture;
#[path = "common/initiated.rs"]
mod initiated;

use capture::{Capture, config, sinks};
use initiated::{CLIENT, PEER, check, exchanges};

#[test]
fn initiated_tcp_and_udp_share_the_attachment_with_inbound_http() {
    world(Duration::from_secs(30), |fcx| async move {
        let (client_attacher, clients) = fictionet::attachments();
        let (peer_attacher, peers) = fictionet::attachments();
        let mut client_end = client_attacher.attach(INTERNET)?;
        let mut peer_end = peer_attacher.attach(INTERNET)?;
        let pcap = Capture::default();
        let client = start(
            &fcx,
            &config(CLIENT, PEER),
            Clock::starting_now(),
            sinks(&Capture::default(), &pcap),
            clients,
        )?;
        let remote = start(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&Capture::default(), &Capture::default()),
            peers,
        )?;
        fcx.spawn(move |fcx| async move {
            let _attachers = (client_attacher, peer_attacher);
            loop {
                tokio::select! {
                    packet = client_end.recv(&fcx) => peer_end.send(packet?),
                    packet = peer_end.recv(&fcx) => client_end.send(packet?),
                }
            }
        });
        exchanges(&fcx, &client, &remote).await?;
        check(&pcap);
        Ok(())
    });
}
