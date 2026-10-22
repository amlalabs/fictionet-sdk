//! Composing interfaces with packet filters.

use fictionet::prelude::*;
use fictionet::stdlib::{self, network::Direction};
use fictionet::{Interface, Packet, RecvError, RunOptions, block_on, lab};
use fictionet_test_support::within;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn filter_sees_both_directions_and_drops_what_it_rejects() {
    within(Duration::from_secs(5), || {
        let (mut a, b) = fictionet::pair();
        block_on(lab(
            RunOptions::new(fictionet::Seed::from_u64(1)),
            move |fcx| async move {
                let log = Arc::new(std::sync::Mutex::new(Vec::new()));
                let l = log.clone();
                let mut outer = stdlib::network::filter(&fcx, b, move |_, direction, packet| {
                    l.lock().unwrap().push((direction, packet.0.clone()));
                    packet.0 != [9]
                });
                a.send(Packet(vec![9]));
                a.send(Packet(vec![1]));
                assert_eq!(outer.recv(&fcx).await?, Packet(vec![1]));
                outer.send(Packet(vec![9]));
                outer.send(Packet(vec![2]));
                assert_eq!(a.recv(&fcx).await?, Packet(vec![2]));
                assert_eq!(
                    *log.lock().unwrap(),
                    [
                        (Direction::FromInner, vec![9]),
                        (Direction::FromInner, vec![1]),
                        (Direction::ToInner, vec![9]),
                        (Direction::ToInner, vec![2]),
                    ]
                );
                // Closing one side ends the task, which closes the other.
                drop(outer);
                assert_eq!(a.recv(&fcx).await, Err(RecvError::Closed));
                Ok(())
            },
        ))
        .unwrap();
    });
}
