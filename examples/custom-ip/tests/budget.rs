use std::num::NonZeroU8;
use std::sync::Arc;

use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, PacketCommand};
use fictionet::stdlib::network::ip;
use fictionet::{Seed, SeededEntropy};
use fictionet_custom_ip::HopLimit;

#[test]
fn rewriting_a_packet_keeps_its_reservation_until_delivery() {
    for (source, destination) in [("10.0.0.1", "10.0.0.2"), ("fd00::1", "fd00::2")] {
        let packet = ip::packet(
            source.parse().unwrap(),
            destination.parse().unwrap(),
            ip::protocol::UDP,
            &[0; 8],
        )
        .0;
        let capacity = packet.capacity();
        let budget = Budget::new(capacity);
        let chunk = Chunk::with_charge(packet, budget.charge(capacity).unwrap());
        let mut driver = Driver::new(
            HopLimit::new(NonZeroU8::new(37).unwrap()),
            Arc::new(SeededEntropy::new(Seed::from_u64(7))),
            budget.clone(),
            fictionet::time::Instant::ZERO,
        );
        assert!(matches!(
            driver.command(PacketCommand::Send(chunk)),
            Ok(Admit::Taken)
        ));
        assert_eq!(budget.used(), capacity);
        let mut delivered = false;
        assert!(driver.send_below(|command| {
            let PacketCommand::Send(chunk) = command else {
                panic!("packet expected")
            };
            assert_eq!(chunk.charged(), capacity);
            assert_eq!(budget.used(), capacity);
            assert!(ip::Header::parse_whole(&chunk).is_some());
            delivered = true;
            Admit::Taken
        }));
        assert!(delivered);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn a_shared_packet_waits_for_copy_budget_without_losing_ownership() {
    let packet = ip::packet(
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        ip::protocol::UDP,
        &[0; 8],
    )
    .0;
    let capacity = packet.capacity();
    let budget = Budget::new(capacity);
    let mut retained = Chunk::with_charge(packet, budget.charge(capacity).unwrap());
    let chunk = retained.split_to(retained.len());
    let mut driver = Driver::new(
        HopLimit::new(NonZeroU8::new(37).unwrap()),
        Arc::new(SeededEntropy::new(Seed::from_u64(8))),
        budget.clone(),
        fictionet::time::Instant::ZERO,
    );
    assert!(matches!(
        driver.command(PacketCommand::Send(chunk)),
        Ok(Admit::Taken)
    ));
    assert!(!driver.send_below(|_| panic!("an unreserved copy cannot be delivered")));
    assert_eq!(budget.used(), capacity);
    drop(retained);
    assert!(driver.send_below(|command| {
        let PacketCommand::Send(chunk) = command else {
            panic!("packet expected")
        };
        assert_eq!(chunk[8], 37);
        assert!(chunk.charged() >= chunk.len());
        Admit::Taken
    }));
    assert_eq!(budget.used(), 0);
}
