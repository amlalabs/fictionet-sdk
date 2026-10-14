use fictionet::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::packets::LinkWatch;
use crate::watch::Graph;

/// How long a link's decoded packets are kept after the last observer
/// stopped asking for them.
#[cfg(feature = "observe")]
const WATCH_LINGER: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(60)
};
/// How often the reaper looks for watches to forget.
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
const REAP_EVERY: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(5)
};

/// The decoded watches kept by one run, shared by observers of each link.
///
/// Locks are taken in this order: [`REAPER`], this set's map, then a
/// watch's inner state. Watch creation and decoding also take graph state
/// locks, so callers must release graph state before calling this set.
/// Subscription release drops the watch lock before scheduling the reaper.
#[derive(Default)]
pub(crate) struct WatchSet {
    watches: Mutex<HashMap<u64, Arc<LinkWatch>>>,
}

impl WatchSet {
    /// Finds or creates a watch of link `id` in the graph owning this set.
    /// Subscribes under the map lock so reaping cannot forget it between
    /// lookup and subscription.
    pub(crate) fn acquire(
        &self,
        graph: &Arc<Graph>,
        id: u64,
    ) -> Option<(Arc<LinkWatch>, Subscription)> {
        self.reap_idle();
        let mut watches = self.watches.lock();
        let w = match watches.get(&id) {
            Some(w) => w.clone(),
            None => {
                let w = Arc::new(LinkWatch::start(graph, id)?);
                watches.insert(id, w.clone());
                w
            }
        };
        w.subscribe();
        let subscription = Subscription(w.clone());
        Some((w, subscription))
    }

    /// The watch of link `id`, if one is kept. Does not subscribe or reap.
    pub(crate) fn existing(&self, id: u64) -> Option<Arc<LinkWatch>> {
        self.watches.lock().get(&id).cloned()
    }

    /// Forgets watches with no subscriber for a minute. Takes each watch's
    /// lock under the map lock, as acquisition does.
    pub(crate) fn reap_idle(&self) {
        self.watches.lock().retain(|_, w| !w.idle_for(WATCH_LINGER));
    }

    /// Whether the run keeps any watches.
    pub(crate) fn is_empty(&self) -> bool {
        self.watches.lock().is_empty()
    }

    /// Releases the run's watches. Active streams keep their own holds
    /// until they finish. The caller must release graph state first.
    pub(crate) fn end_run(&self) {
        self.watches.lock().clear();
    }

    /// Releases a subscription even if its graph is gone. The watch lock
    /// is released before taking the reaper lock.
    fn release(watch: &LinkWatch) {
        if watch.unsubscribe()
            && let Some(graph) = watch.graph()
        {
            let _ = Self::reap_later(&graph);
        }
    }

    /// Schedules idle reaping when the last subscriber leaves, even if no
    /// observer asks anything more. Must not hold the map or a watch lock.
    fn reap_later(graph: &Arc<Graph>) -> std::io::Result<()> {
        graph.environment.require_real_io()?;
        let mut reaper = REAPER.lock();
        if !reaper
            .0
            .iter()
            .any(|g| std::ptr::eq(g.as_ptr(), Arc::as_ptr(graph)))
        {
            reaper.0.push(Arc::downgrade(graph));
        }
        if !reaper.1 {
            reaper.1 = start_reaper();
        }
        Ok(())
    }
}

/// One `packets` stream's hold on a watch. While any is held, the link's
/// packets are copied.
pub(crate) struct Subscription(Arc<LinkWatch>);

impl Drop for Subscription {
    fn drop(&mut self) {
        WatchSet::release(&self.0);
    }
}

/// The worlds with watches that may need forgetting, and whether the
/// reaper thread runs.
///
/// Follows the lock order documented on [`WatchSet`].
#[cfg(feature = "observe")]
static REAPER: Mutex<(Vec<std::sync::Weak<Graph>>, bool)> = Mutex::new((Vec::new(), false));

/// Starts the thread that reaps the worlds in [`REAPER`]. Returns whether
/// it runs.
#[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
fn start_reaper() -> bool {
    std::thread::Builder::new()
        .name("fictionet-reaper".into())
        .spawn(|| {
            loop {
                std::thread::sleep(REAP_EVERY);
                let mut reaper = REAPER.lock();
                // A world that ended, or has no watches left, needs no more.
                reaper.0.retain(|g| {
                    g.upgrade().is_some_and(|g| {
                        g.watches.reap_idle();
                        !g.watches.is_empty()
                    })
                });
                if reaper.0.is_empty() {
                    reaper.1 = false;
                    return;
                }
            }
        })
        .is_ok()
}

/// A browser has no thread for the reaper. Idle watches there are
/// forgotten when the next watch starts.
#[cfg(all(feature = "observe", target_arch = "wasm32"))]
fn start_reaper() -> bool {
    false
}

#[cfg(all(test, feature = "observe"))]
mod tests {
    use super::*;

    #[test]
    fn subscribers_share_a_watch_and_reuse_its_history() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        let (watch, first) = graph.watches.acquire(&graph, meter.id).unwrap();
        let (shared, second) = graph.watches.acquire(&graph, meter.id).unwrap();
        assert!(Arc::ptr_eq(&watch, &shared));

        drop(first);
        graph.watches.reap_idle();
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        shared.pump();
        assert_eq!(watch.rows_after(0, 10).len(), 1);

        drop(second);
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        watch.pump();
        assert_eq!(watch.rows_after(0, 10).len(), 1);
        let (resumed, _subscription) = graph.watches.acquire(&graph, meter.id).unwrap();
        assert!(Arc::ptr_eq(&watch, &resumed));
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        resumed.pump();
        assert_eq!(resumed.rows_after(0, 10).len(), 2);
    }

    #[test]
    fn ending_a_run_releases_watches_while_streams_finish() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        let idle = Meter::new();
        let active = Meter::new();
        graph.owns(&idle, 0, 1);
        graph.owns(&active, 0, 1);
        let (watch, subscription) = graph.watches.acquire(&graph, idle.id).unwrap();
        let idle_watch = Arc::downgrade(&watch);
        drop((watch, subscription));
        let (watch, subscription) = graph.watches.acquire(&graph, active.id).unwrap();
        active.sent(0, &crate::Packet(vec![0x45; 20]));
        assert!(idle_watch.upgrade().is_some());

        graph.run_ended();
        assert!(graph.watches.is_empty());
        assert!(graph.watches.existing(idle.id).is_none());
        assert!(graph.watches.existing(active.id).is_none());
        assert!(idle_watch.upgrade().is_none());
        watch.pump();
        assert_eq!(watch.rows_after(0, 10).len(), 1);
        let active_watch = Arc::downgrade(&watch);
        drop(watch);
        assert!(active_watch.upgrade().is_some());
        drop(subscription);
        assert!(active_watch.upgrade().is_none());
    }

    #[test]
    fn a_subscription_does_not_keep_its_graph_or_link_alive() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        let (watch, subscription) = graph.watches.acquire(&graph, meter.id).unwrap();
        let weak = Arc::downgrade(&graph);
        drop(graph);
        assert!(weak.upgrade().is_none());
        drop(meter);
        assert!(watch.closed());
        drop(subscription);
        assert!(watch.idle_for(Duration::ZERO));
    }

    #[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
    #[test]
    fn lab_refuses_the_observer_reaper() {
        crate::block_on(crate::lab(
            crate::Seed::from_u64(0),
            move |fcx| async move {
                assert!(
                    WatchSet::reap_later(fcx.graph())
                        .unwrap_err()
                        .to_string()
                        .contains("lab")
                );
                assert!(
                    !REAPER
                        .lock()
                        .0
                        .iter()
                        .any(|g| std::ptr::eq(g.as_ptr(), Arc::as_ptr(fcx.graph())))
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A link is copied only while a `packets` stream subscribes, and a
    /// kept watch does not keep its world alive.
    #[test]
    fn watches_copy_only_while_subscribed() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        graph.task_started(1, "world".into(), std::panic::Location::caller(), None);
        let (w, sub) = graph.watches.acquire(&graph, meter.id).unwrap();
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        w.pump();
        assert_eq!(w.rows_after(0, 10).len(), 1);
        drop(sub);
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        w.pump();
        assert_eq!(
            w.rows_after(0, 10).len(),
            1,
            "nothing is copied with no subscriber"
        );
        // The decoded rows stay for a while, for `packet` and `pcap`.
        assert!(graph.watches.existing(meter.id).is_some());
        drop(w);
        let weak = Arc::downgrade(&graph);
        drop(graph);
        assert!(
            weak.upgrade().is_none(),
            "the kept watch held its world alive"
        );
    }

    /// A watch with no subscriber is forgotten after the linger time,
    /// even when no observer asks anything more.
    #[test]
    fn idle_watches_are_forgotten_without_more_requests() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::random(), crate::RunMode::Real);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        drop(graph.watches.acquire(&graph, meter.id).unwrap());
        assert!(graph.watches.existing(meter.id).is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while graph.watches.existing(meter.id).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the idle watch was kept"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // A watch taken again is subscribed to as it is found, so the
        // reaper keeps the one the stream follows.
        let (w, _sub) = graph.watches.acquire(&graph, meter.id).unwrap();
        std::thread::sleep(WATCH_LINGER * 2);
        assert!(Arc::ptr_eq(&graph.watches.existing(meter.id).unwrap(), &w));
    }
}
