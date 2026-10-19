use super::{Event, Interest, Loss, Observation, Observer, Stamp, Stream};
use crate::sync::Mutex;

#[derive(Default)]
pub(crate) struct Recorder {
    events: Mutex<Vec<Event>>,
    dropped: Mutex<u64>,
}

impl Recorder {
    pub(crate) fn all(&self) -> Vec<Event> {
        assert_eq!(self.dropped(), 0);
        self.events.lock().clone()
    }

    pub(crate) fn of(&self, source: &str, kind: &str) -> Vec<Event> {
        self.all()
            .into_iter()
            .filter(|event| event.is(source, kind))
            .collect()
    }

    pub(crate) fn after(&self, after: u64, max: usize) -> Vec<Event> {
        self.events
            .lock()
            .iter()
            .filter(|event| event.seq > after)
            .take(max)
            .cloned()
            .collect()
    }

    pub(crate) fn dropped(&self) -> u64 {
        *self.dropped.lock()
    }
}

impl Observer for Recorder {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(..))
    }

    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        if let Observation::Event(event) = item {
            let mut event = event.clone();
            event.seq = stamp.seq;
            event.at = stamp.at;
            self.events.lock().push(event);
        }
    }

    fn lost(&self, loss: Loss) {
        if loss.stream == Stream::Events {
            *self.dropped.lock() += loss.count;
        }
    }
}
