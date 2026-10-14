use fictionet::sync::Mutex;
use std::sync::Arc;
use std::time::Duration;

use super::{LinkWatch, packets};
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

/// Forgets the watches that have had no subscriber for a minute.
#[cfg(feature = "observe")]
pub(crate) fn reap(graph: &Graph) {
    graph
        .watches
        .lock()
        .retain(|_, w| !w.idle_for(WATCH_LINGER));
}

/// The worlds with watches that may need forgetting, and whether the
/// reaper thread runs.
///
/// Locks are taken in this order: this, then a graph's `watches`, then a
/// watch's own. So nothing calls [`reap_later`] while it holds either of
/// the others.
#[cfg(feature = "observe")]
static REAPER: Mutex<(Vec<std::sync::Weak<Graph>>, bool)> = Mutex::new((Vec::new(), false));

/// Makes sure `graph`'s watches are forgotten once idle for a minute, even
/// if no observer asks anything more. Called when the last subscriber of a
/// watch leaves.
#[cfg(feature = "observe")]
pub(crate) fn reap_later(graph: &Arc<Graph>) -> std::io::Result<()> {
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
                        reap(&g);
                        !g.watches.lock().is_empty()
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

/// The watch of link `id` in `graph`, made if needed, and a subscription
/// to it. Both are taken under the lock the reaper takes, so the reaper
/// cannot forget the watch between them.
#[cfg(feature = "observe")]
pub(crate) fn watch(
    graph: &Arc<Graph>,
    id: u64,
) -> Option<(Arc<LinkWatch>, packets::Subscription)> {
    reap(graph);
    let mut watches = graph.watches.lock();
    let w = match watches.get(&id) {
        Some(w) => w.clone(),
        None => {
            let w = Arc::new(LinkWatch::start(graph, id)?);
            watches.insert(id, w.clone());
            w
        }
    };
    let subscription = w.subscribe();
    Some((w, subscription))
}

/// The watch of link `id`, if one is kept.
#[cfg(feature = "observe")]
pub(crate) fn existing_watch(graph: &Graph, id: u64) -> Option<Arc<LinkWatch>> {
    graph.watches.lock().get(&id).cloned()
}

#[cfg(all(test, feature = "observe"))]
mod tests {
    use super::*;

    #[cfg(all(feature = "observe", not(target_arch = "wasm32")))]
    #[test]
    fn lab_refuses_the_observer_reaper() {
        crate::block_on(crate::lab(
            crate::Seed::from_u64(0),
            move |fcx| async move {
                assert!(
                    reap_later(fcx.graph())
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
        let (w, sub) = watch(&graph, meter.id).unwrap();
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
        assert!(existing_watch(&graph, meter.id).is_some());
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
        drop(watch(&graph, meter.id).unwrap());
        assert!(existing_watch(&graph, meter.id).is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while existing_watch(&graph, meter.id).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the idle watch was kept"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // A watch taken again is subscribed to as it is found, so the
        // reaper keeps the one the stream follows.
        let (w, _sub) = watch(&graph, meter.id).unwrap();
        std::thread::sleep(WATCH_LINGER * 2);
        assert!(Arc::ptr_eq(&existing_watch(&graph, meter.id).unwrap(), &w));
    }
}
