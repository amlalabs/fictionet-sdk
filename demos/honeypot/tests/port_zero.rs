//! The port-zero probes against the honeypot's world, with the internet
//! attached directly.

use std::time::Duration;

use fictionet_test_support::world::world;
use honeypot_world::{Clock, INTERNET, start};

#[path = "common/capture.rs"]
mod capture;
#[path = "common/port_zero.rs"]
mod port_zero;

use capture::{Capture, config, sinks};
use port_zero::{CLIENT, PEER, Probe};

#[test]
fn port_zero_probes_are_answered_and_observed() {
    world(Duration::from_secs(30), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let end = attacher.attach(INTERNET)?;
        let (log, pcap) = (Capture::default(), Capture::default());
        let server = start(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&log, &pcap),
            attachments,
        )?;
        let mut probe = Probe::new(&server, end).await?;
        probe.run(&fcx).await?;
        probe.check(&log, &pcap);
        Ok(())
    });
}
