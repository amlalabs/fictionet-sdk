//! Extra hosts share the gateway hop while the scenario keeps its paths.

mod common;
use border_world::{
    Extra,
    routing::SetRoute,
    scenario::{BANK_ADDR, FOREIGN, HOME, Scenario, Task, Variant, parse_prefix},
};
use common::*;
use fictionet::stdlib::{services::ca::Ca, world::net::Host};
use fictionet::{Interface, RunOptions, Seed};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

#[test]
fn extra_hosts_and_admin_routes_work_in_both_modes() {
    run(RunOptions::new(Seed::from_u64(27)), |cx| async move {
        let scenario = Arc::new(Scenario::new(
            Variant::Legitimate,
            Task::Login,
            parse_prefix("10.0.0.0/24").unwrap(),
        ));
        let ca = Ca::new(&cx, "Test Root CA")?;
        let ids = border_world::identities(&cx, &ca)?;
        let (attacher, attachments) = fictionet::attachments();
        let extra = Ipv4Addr::new(104, 18, 0, 10);
        let admin = Ipv4Addr::new(10, 10, 5, 20);
        let routing = border_world::start_with(
            &cx,
            scenario.clone(),
            ids,
            attachments,
            Extra::default()
                .host(extra, Host::new("packages"))
                .route("admin", parse_prefix("10.10.5.20/32").unwrap()),
        )?;
        let mut guest = attacher.attach("guest")?;
        let mut jump = attacher.attach("admin")?;
        let me = Ipv4Addr::new(10, 0, 0, 2);
        for mode in [Variant::Legitimate, Variant::Hijack] {
            if mode == Variant::Hijack {
                routing
                    .apply(
                        &cx,
                        SetRoute {
                            mode,
                            expected_revision: 0,
                        },
                    )
                    .unwrap();
            }
            guest.send(ping(me, extra, 64, 1));
            let reply = recv_within(&cx, &mut guest, Duration::from_secs(1))
                .await
                .unwrap();
            let (source, ttl, protocol, payload) = parse(&reply);
            assert_eq!((source, ttl, protocol, payload[0]), (extra, 63, 1, 0));
            guest.send(ping(me, extra, 1, 2));
            let reply = recv_within(&cx, &mut guest, Duration::from_secs(1))
                .await
                .unwrap();
            let (source, _, _, payload) = parse(&reply);
            assert_eq!(
                (source, payload[0], payload[1]),
                (scenario.gateway(), 11, 0)
            );
            guest.send(ping(me, admin, 64, 3));
            let reply = recv_within(&cx, &mut jump, Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(parse(&reply).1, 63);
            jump.send(ping(admin, me, 64, 4));
            let reply = recv_within(&cx, &mut guest, Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(parse(&reply).1, 63);
            let mut hops = vec![scenario.gateway(), HOME.router];
            if mode == Variant::Hijack {
                hops.push(FOREIGN.router);
            }
            hops.push(BANK_ADDR);
            for (i, source) in hops.iter().enumerate() {
                guest.send(udp_probe(me, BANK_ADDR, 33434 + i as u16, i as u8 + 1));
                let reply = recv_within(&cx, &mut guest, Duration::from_secs(1))
                    .await
                    .unwrap();
                let (addr, _, _, payload) = parse(&reply);
                assert_eq!(addr, *source);
                assert_eq!(
                    (payload[0], payload[1]),
                    if *source == BANK_ADDR {
                        (3, 3)
                    } else {
                        (11, 0)
                    }
                );
            }
            guest.send(ping(me, "203.0.113.8".parse().unwrap(), 64, 5));
            let reply = recv_within(&cx, &mut guest, Duration::from_secs(1))
                .await
                .unwrap();
            let (source, _, _, payload) = parse(&reply);
            assert_eq!((source, payload[0], payload[1]), (scenario.gateway(), 3, 1));
        }
        Ok(())
    });
}
