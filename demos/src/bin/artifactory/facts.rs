use artifactory_world::{
    facts::{Door, Request},
    inventory::{FolderAdded, Inventory},
};
use fictionet::events::{Interest, Loss, Observation, Observer, Stamp, Stream};
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;

const ROWS: usize = 4096;

#[derive(Clone, Debug)]
pub struct Tagged<T> {
    pub step: &'static str,
    pub row: T,
}

pub struct Snapshot {
    pub step: &'static str,
    pub requests: VecDeque<Tagged<Request>>,
    pub doors: VecDeque<Tagged<Door>>,
    pub changes: VecDeque<Tagged<FolderAdded>>,
    pub inventory: Inventory,
    pub dropped: u64,
    pub lost: u64,
}

pub struct Facts {
    pub state: Mutex<Snapshot>,
    pub changed: Notify,
}

impl Facts {
    pub fn new(inventory: Inventory) -> Self {
        Self {
            state: Mutex::new(Snapshot {
                step: "setup",
                requests: VecDeque::new(),
                doors: VecDeque::new(),
                changes: VecDeque::new(),
                inventory,
                dropped: 0,
                lost: 0,
            }),
            changed: Notify::new(),
        }
    }
    pub fn phase(&self, step: &'static str) {
        self.state.lock().unwrap().step = step;
    }
    pub fn inventory_changed(&self, change: &FolderAdded, inventory: &Inventory) {
        let mut state = self.state.lock().unwrap();
        state.inventory = inventory.clone();
        let step = state.step;
        let dropped = keep(
            &mut state.changes,
            Tagged {
                step,
                row: change.clone(),
            },
        );
        state.dropped += dropped;
        self.changed.notify_one();
    }
}
fn keep<T>(rows: &mut VecDeque<T>, row: T) -> u64 {
    let dropped = u64::from(rows.len() == ROWS);
    if dropped != 0 {
        rows.pop_front();
    }
    rows.push_back(row);
    dropped
}
impl Observer for Facts {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(meta, _) if artifactory_world::events::LOGGED.contains(&meta.source))
    }
    fn observe(&self, _: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        let step = state.step;
        if let Some(row) = Request::from_event(event) {
            state.dropped += keep(&mut state.requests, Tagged { step, row });
        }
        if let Some(row) = Door::from_event(event) {
            state.dropped += keep(&mut state.doors, Tagged { step, row });
        }
        self.changed.notify_one();
    }
    fn lost(&self, loss: Loss) {
        if loss.stream == Stream::Events {
            self.state.lock().unwrap().lost += loss.count;
            self.changed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifactory_world::{packages::Variant, repository::Contents};
    use fictionet::{events::Event, time::Instant};
    #[test]
    fn phases_and_overflow_stay_visible() {
        let facts = Facts::new(
            Contents::new(Variant::Missing, "", &[1; 32])
                .unwrap()
                .inventory(),
        );
        let event = Event::new("dns", "query")
            .field("name", "github.com")
            .field("answer", "nxdomain");
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 0,
            at: Instant::ZERO,
        };
        for phase in ["setup", "lookup", "after"] {
            facts.phase(phase);
            facts.observe(stamp, Observation::Event(&event));
        }
        assert_eq!(
            facts
                .state
                .lock()
                .unwrap()
                .doors
                .iter()
                .map(|r| r.step)
                .collect::<Vec<_>>(),
            ["setup", "lookup", "after"]
        );
        for _ in 0..ROWS {
            facts.observe(stamp, Observation::Event(&event));
        }
        let state = facts.state.lock().unwrap();
        assert_eq!(state.doors.len(), ROWS);
        assert_eq!(state.dropped, 3);
    }
}
