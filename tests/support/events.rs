use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};
use std::time::Duration;

use fictionet::events::{Event, Interest, Observation, Observer, Stamp};

/// Test-owned recording of the core events exercised by the service tests.
#[derive(Default)]
pub struct EventLog {
    events: Mutex<Vec<Event>>,
    waiters: Mutex<Vec<Weak<Mutex<Option<Waker>>>>>,
}

impl Observer for EventLog {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(..))
    }

    fn observe(&self, _: Stamp, observation: Observation<'_>) {
        if let Observation::Event(event) = observation {
            self.events.lock().unwrap().push(event.clone());
            let wakes: Vec<_> = self
                .waiters
                .lock()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .filter_map(|wait| wait.lock().unwrap().take())
                .collect();
            for wake in wakes {
                wake.wake();
            }
        }
    }
}

impl EventLog {
    pub fn last(&self) -> u64 {
        self.events
            .lock()
            .unwrap()
            .last()
            .map_or(0, |event| event.seq)
    }

    pub fn all(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn of(&self, source: &str, kind: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.is(source, kind))
            .cloned()
            .collect()
    }

    pub async fn wait(
        &self,
        cx: &fictionet::Cx,
        mut after: u64,
        count: usize,
        limit: Duration,
        pick: impl Fn(&Event) -> bool,
    ) -> fictionet::Result<Vec<Event>> {
        let wake = Arc::new(Mutex::new(None));
        {
            let mut waiters = self.waiters.lock().unwrap();
            waiters.retain(|wait| wait.strong_count() != 0);
            waiters.push(Arc::downgrade(&wake));
        }
        let deadline = fictionet::time::Instant::from_since_start(
            cx.now().since_start().saturating_add(limit),
        );
        let mut timer = fictionet::Timer::new(cx);
        let mut matches = Vec::new();
        std::future::poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(fictionet::Cancelled.into()));
            }
            *wake.lock().unwrap() = Some(task.waker().clone());
            for event in self.all() {
                if event.seq > after {
                    after = event.seq;
                    if pick(&event) {
                        matches.push(event);
                    }
                }
            }
            if cx.is_cancelled() {
                return Poll::Ready(Err(fictionet::Cancelled.into()));
            }
            if matches.len() >= count || cx.now() >= deadline {
                return Poll::Ready(Ok(std::mem::take(&mut matches)));
            }
            if let Poll::Ready(result) = timer.poll_until(task, deadline) {
                result?;
                task.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
}
