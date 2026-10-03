//! A machine as the stdlib builds one, fed any packets: `ip::split_protocols`
//! (with reassembly), a TCP endpoint with a listener whose connections
//! echo, a UDP endpoint with a socket that echoes, and ping replies. Once
//! for IPv4 and once for IPv6.
#![no_main]

use std::net::IpAddr;

use arbitrary::Arbitrary;
use fictionet::prelude::*;
use fictionet::stdlib::{icmp, ip, tcp, udp};
use fictionet::{Interface, Packet, pair};
use fictionet_fuzz::{fix_checksums, poll_once, settle, world};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Step {
    /// A packet, with its checksums made right first if `fix`.
    Packet { fix: bool, bytes: Vec<u8> },
    /// Let the machine run a few turns.
    Pump(u8),
}

fuzz_target!(|steps: Vec<Step>| {
    world(move |cx| async move {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "fd00::1".parse().unwrap();
        let mut raws = Vec::new();
        for addr in [v4, v6] {
            let (raw, side) = pair();
            raws.push(raw);
            let (t, u, i, _other) = ip::split_protocols(&cx, side);
            let tcp = tcp::endpoint(&cx, t, addr);
            let mut listener = tcp.listen(80).unwrap();
            cx.spawn(move |cx| async move {
                while let Ok(mut c) = listener.accept(&cx).await {
                    cx.spawn(move |cx| async move {
                        let mut buf = [0u8; 2048];
                        while let Ok(n) = c.read(&cx, &mut buf).await {
                            if n == 0 || c.write_all(&cx, &buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = c.shutdown(&cx).await;
                        Ok(())
                    });
                }
                Ok(())
            });
            let udp = udp::endpoint(&cx, u, addr);
            let mut socket = udp.bind(53).unwrap();
            cx.spawn(move |cx| async move {
                while let Ok((d, from)) = socket.recv(&cx).await {
                    socket.send_to(&d, from);
                }
                Ok(())
            });
            cx.spawn(move |cx| async move {
                let mut i = i;
                while let Ok(p) = i.recv(&cx).await {
                    if let Some(r) = icmp::echo_reply(&p, addr) {
                        i.send(r);
                    }
                }
                Ok(())
            });
        }
        for step in steps {
            match step {
                Step::Packet { fix, mut bytes } => {
                    if fix {
                        fix_checksums(&mut bytes);
                    }
                    let which = (bytes.first().is_some_and(|b| b >> 4 == 6)) as usize;
                    raws[which].send(Packet(bytes));
                }
                Step::Pump(n) => settle(&cx, n as usize % 8).await,
            }
        }
        settle(&cx, 8).await;
        // Drain what the machines sent back.
        for raw in &mut raws {
            while let Some(Ok(_)) = poll_once(raw.recv(&cx)).await {}
        }
    });
});
