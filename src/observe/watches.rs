use fictionet::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::packets::LinkWatch;
use crate::watch::Graph;

/// Enough for one session's full set of distinct packet subscriptions.
const DEFAULT_WATCHES: usize = 64;

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
pub(crate) struct WatchSet {
    state: Mutex<State>,
}

struct State {
    watches: HashMap<u64, Arc<LinkWatch>>,
    limit: usize,
}

impl State {
    /// Evicts the longest-idle watches first, with link ids breaking ties.
    /// Active subscriptions always keep their watch.
    fn evict_idle(&mut self, limit: usize) {
        while self.watches.len() > limit {
            let victim = self
                .watches
                .iter()
                .filter_map(|(&id, w)| w.idle_order().map(|order| (order, id)))
                .min();
            let Some((_, id)) = victim else { break };
            self.watches.remove(&id);
        }
    }
}

impl Default for WatchSet {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                watches: HashMap::new(),
                limit: DEFAULT_WATCHES,
            }),
        }
    }
}

impl WatchSet {
    pub(crate) fn set_limit(&self, limit: usize) {
        let mut state = self.state.lock();
        state.limit = limit;
        state.evict_idle(limit);
    }

    /// Finds or creates a watch of link `id` in the graph owning this set.
    /// Subscribes under the map lock so reaping cannot forget it between
    /// lookup and subscription.
    pub(crate) fn acquire(
        &self,
        graph: &Arc<Graph>,
        id: u64,
    ) -> Result<(Arc<LinkWatch>, Subscription), &'static str> {
        self.reap_idle();
        let mut state = self.state.lock();
        let w = match state.watches.get(&id) {
            Some(w) => w.clone(),
            None => {
                let w = LinkWatch::start(graph, id).ok_or("no such link")?;
                if state.watches.values().filter(|w| !w.is_idle()).count() >= state.limit {
                    return Err("this world has too many watched links");
                }
                let w = Arc::new(w);
                let limit = state.limit;
                state.evict_idle(limit - 1);
                state.watches.insert(id, w.clone());
                w
            }
        };
        w.subscribe();
        let subscription = Subscription(w.clone());
        Ok((w, subscription))
    }

    /// The watch of link `id`, if one is kept. Does not subscribe or reap.
    pub(crate) fn existing(&self, id: u64) -> Option<Arc<LinkWatch>> {
        self.state.lock().watches.get(&id).cloned()
    }

    /// Forgets watches with no subscriber for a minute. Takes each watch's
    /// lock under the map lock, as acquisition does.
    pub(crate) fn reap_idle(&self) {
        self.state
            .lock()
            .watches
            .retain(|_, w| !w.idle_for(WATCH_LINGER));
    }

    /// Whether the run keeps any watches.
    pub(crate) fn is_empty(&self) -> bool {
        self.state.lock().watches.is_empty()
    }

    /// Releases the run's watches. Active streams keep their own holds
    /// until they finish. The caller must release graph state first.
    pub(crate) fn end_run(&self) {
        self.state.lock().watches.clear();
    }

    /// Releases a subscription even if its graph is gone. The watch lock
    /// is released before taking the reaper lock.
    fn release(watch: &LinkWatch) {
        if watch.unsubscribe()
            && let Some(graph) = watch.graph()
        {
            {
                let mut state = graph.watches.state.lock();
                let limit = state.limit;
                state.evict_idle(limit);
            }
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
    fn active_watch_capacity_preserves_sharing_and_releases_on_drop() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        graph.watches.set_limit(1);
        let first = Meter::new();
        let second = Meter::new();
        graph.owns(&first, 0, 1);
        graph.owns(&second, 0, 1);
        let (watch, a) = graph.watches.acquire(&graph, first.id).unwrap();
        let (shared, b) = graph.watches.acquire(&graph, first.id).unwrap();
        assert!(Arc::ptr_eq(&watch, &shared));
        assert_eq!(
            graph.watches.acquire(&graph, u64::MAX).err(),
            Some("no such link")
        );
        for _ in 0..3 {
            assert_eq!(
                graph.watches.acquire(&graph, second.id).err(),
                Some("this world has too many watched links")
            );
            assert!(graph.watches.existing(second.id).is_none());
        }
        drop(a);
        assert!(graph.watches.acquire(&graph, second.id).is_err());
        first.sent(0, &crate::Packet(vec![0x45; 20]));
        shared.pump();
        assert_eq!(shared.rows_after(0, 10).len(), 1);
        let weak = Arc::downgrade(&watch);
        drop((watch, shared, b));
        assert!(weak.upgrade().is_some(), "idle history lingers");
        let (_watch, _sub) = graph.watches.acquire(&graph, second.id).unwrap();
        assert!(weak.upgrade().is_none(), "admission releases idle history");
        assert!(graph.watches.existing(first.id).is_none());
    }

    #[test]
    fn admission_evicts_longest_idle_watches_first() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        graph.watches.set_limit(3);
        let meters: Vec<_> = (0..5).map(|_| Meter::new()).collect();
        for meter in &meters {
            graph.owns(meter, 0, 1);
        }
        let (_watch, _sub) = graph.watches.acquire(&graph, meters[0].id).unwrap();
        let (_, first) = graph.watches.acquire(&graph, meters[1].id).unwrap();
        let (_, second) = graph.watches.acquire(&graph, meters[2].id).unwrap();
        // Release out of link-id order. Active links are never victims.
        drop(second);
        drop(first);
        assert_eq!(
            graph.watches.acquire(&graph, u64::MAX).err(),
            Some("no such link")
        );
        assert!(graph.watches.existing(meters[1].id).is_some());
        assert!(graph.watches.existing(meters[2].id).is_some());
        let (_watch, _sub) = graph.watches.acquire(&graph, meters[3].id).unwrap();
        assert!(graph.watches.existing(meters[0].id).is_some());
        assert!(graph.watches.existing(meters[1].id).is_some());
        assert!(graph.watches.existing(meters[2].id).is_none());
        let (_watch, _sub) = graph.watches.acquire(&graph, meters[4].id).unwrap();
        assert!(graph.watches.existing(meters[0].id).is_some());
        assert!(graph.watches.existing(meters[1].id).is_none());
        assert!(graph.watches.existing(meters[3].id).is_some());
        assert_eq!(graph.watches.state.lock().watches.len(), 3);
    }

    #[test]
    fn lowering_watch_capacity_preserves_active_subscriptions() {
        use crate::watch::Meter;
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        graph.watches.set_limit(2);
        let first = Meter::new();
        let second = Meter::new();
        graph.owns(&first, 0, 1);
        graph.owns(&second, 0, 1);
        let (watch, a) = graph.watches.acquire(&graph, first.id).unwrap();
        drop(graph.watches.acquire(&graph, second.id).unwrap());
        graph.watches.set_limit(0);
        assert!(graph.watches.existing(second.id).is_none());
        let (shared, b) = graph.watches.acquire(&graph, first.id).unwrap();
        assert!(Arc::ptr_eq(&watch, &shared));
        assert!(graph.watches.acquire(&graph, second.id).is_err());
        drop((a, b));
        assert!(graph.watches.is_empty());
        assert!(graph.watches.acquire(&graph, first.id).is_err());
        graph.watches.set_limit(1);
        assert!(graph.watches.acquire(&graph, second.id).is_ok());
    }

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
