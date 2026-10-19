//! Bounded topology staging for one task poll.
//!
//! A task can change the topology while it holds its own locks, such as a
//! network starting a machine under its state lock. The run stages what a
//! poll produces and delivers it, in order, once the poll returns.

use std::cell::RefCell;
use std::sync::Arc;

use super::{Dispatch, Loss, LossReason, Stream, TopologyRef};

/// Topology records one poll may stage. A world's first poll can build
/// thousands of tasks, groups and links.
const MAX_ITEMS: usize = 1 << 16;
/// Bytes of names and labels one poll may stage.
const MAX_BYTES: usize = 16 << 20;

type Delivery = Box<dyn FnOnce(&Dispatch)>;

struct Batch {
    dispatch: Arc<Dispatch>,
    items: Vec<Delivery>,
    bytes: usize,
    lost: u64,
}

thread_local! {
    static PENDING: RefCell<Option<Batch>> = const { RefCell::new(None) };
}

/// Flushes staged topology when the poll that made it returns.
pub(crate) struct Scope {
    active: bool,
    previous: Option<Batch>,
}

impl Scope {
    pub(crate) fn new(dispatch: Option<&Arc<Dispatch>>) -> Self {
        let Some(dispatch) = dispatch.filter(|dispatch| dispatch.has_topology()) else {
            return Self {
                active: false,
                previous: None,
            };
        };
        PENDING.with(|pending| {
            let mut pending = pending.borrow_mut();
            if pending
                .as_ref()
                .is_some_and(|batch| Arc::ptr_eq(&batch.dispatch, dispatch))
            {
                return Self {
                    active: false,
                    previous: None,
                };
            }
            Self {
                active: true,
                previous: pending.replace(Batch {
                    dispatch: dispatch.clone(),
                    items: Vec::new(),
                    bytes: 0,
                    lost: 0,
                }),
            }
        })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let batch = PENDING
            .with(|pending| pending.replace(self.previous.take()))
            .unwrap();
        for item in batch.items {
            item(&batch.dispatch);
        }
        if batch.lost != 0 {
            batch.dispatch.report_loss(Loss {
                stream: Stream::Topology,
                reason: LossReason::Staging,
                count: batch.lost,
                bytes: None,
                seqs: None,
            });
        }
    }
}

/// Returns the item for immediate delivery unless a matching scope is active.
pub(crate) fn stage<'a>(dispatch: &Dispatch, item: TopologyRef<'a>) -> Option<TopologyRef<'a>> {
    PENDING.with(|pending| {
        let mut pending = pending.borrow_mut();
        let Some(batch) = pending
            .as_mut()
            .filter(|batch| std::ptr::eq(Arc::as_ptr(&batch.dispatch), dispatch))
        else {
            return Some(item);
        };
        let bytes = std::mem::size_of::<TopologyRef<'_>>()
            + match &item {
                TopologyRef::TaskAdded { name, .. } | TopologyRef::GroupAdded { name, .. } => {
                    name.len()
                }
                TopologyRef::HostAdded { name, sandbox, .. } => {
                    name.len().saturating_add(sandbox.map_or(0, str::len))
                }
                TopologyRef::LinkAdded { sandbox, .. } => sandbox.map_or(0, str::len),
                TopologyRef::LinkLabel { label, .. } => label.len(),
                TopologyRef::ConnectionOpened { conn, .. }
                | TopologyRef::ConnectionClosed { conn } => conn_bytes(conn),
                _ => 0,
            };
        if batch.items.len() == MAX_ITEMS || bytes > MAX_BYTES - batch.bytes {
            batch.lost = batch.lost.saturating_add(1);
            return None;
        }
        batch.bytes += bytes;
        batch.items.push(own(item));
        None
    })
}

fn conn_bytes(conn: &super::ConnInfo) -> usize {
    std::mem::size_of::<super::ConnInfo>()
        + conn
            .sandbox
            .as_ref()
            .map_or(0, |sandbox| sandbox.name.len())
        + conn.sni.as_ref().map_or(0, |sni| sni.len())
        + conn.alpn.as_ref().map_or(0, |alpn| alpn.len())
}

fn own(item: TopologyRef<'_>) -> Delivery {
    match item {
        TopologyRef::ConnectionOpened { conn, task, host } => {
            let conn = conn.clone();
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::ConnectionOpened {
                    conn: &conn,
                    task,
                    host,
                })
            })
        }
        TopologyRef::ConnectionClosed { conn } => {
            let conn = conn.clone();
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::ConnectionClosed { conn: &conn })
            })
        }
        TopologyRef::TaskAdded {
            task,
            parent,
            name,
            file,
            line,
            group,
        } => {
            let name = name.to_owned();
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::TaskAdded {
                    task,
                    parent,
                    name: &name,
                    file,
                    line,
                    group,
                })
            })
        }
        TopologyRef::GroupAdded {
            group,
            name,
            parent,
        } => {
            let name = name.to_owned();
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::GroupAdded {
                    group,
                    name: &name,
                    parent,
                })
            })
        }
        TopologyRef::HostAdded {
            host,
            name,
            group,
            sandbox,
        } => {
            let name = name.to_owned();
            let sandbox = sandbox.map(str::to_owned);
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::HostAdded {
                    host,
                    name: &name,
                    group,
                    sandbox: sandbox.as_deref(),
                })
            })
        }
        TopologyRef::LinkAdded {
            link,
            creator,
            sandbox,
            host,
            counters,
        } => {
            let sandbox = sandbox.map(str::to_owned);
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::LinkAdded {
                    link,
                    creator,
                    sandbox: sandbox.as_deref(),
                    host,
                    counters,
                })
            })
        }
        TopologyRef::LinkLabel { link, label } => {
            let label = label.to_owned();
            Box::new(move |dispatch| {
                dispatch.topology(TopologyRef::LinkLabel {
                    link,
                    label: &label,
                })
            })
        }
        TopologyRef::TaskRemoved { task } => {
            Box::new(move |dispatch| dispatch.topology(TopologyRef::TaskRemoved { task }))
        }
        TopologyRef::GroupRemoved { group } => {
            Box::new(move |dispatch| dispatch.topology(TopologyRef::GroupRemoved { group }))
        }
        TopologyRef::HostRemoved { host } => {
            Box::new(move |dispatch| dispatch.topology(TopologyRef::HostRemoved { host }))
        }
        TopologyRef::LinkOwner { link, side, task } => {
            Box::new(move |dispatch| dispatch.topology(TopologyRef::LinkOwner { link, side, task }))
        }
        TopologyRef::LinkRemoved { link, totals } => {
            Box::new(move |dispatch| dispatch.topology(TopologyRef::LinkRemoved { link, totals }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Interest, Observation, Observer, Stamp, TaskId};
    use crate::sync::Mutex;

    #[derive(Default)]
    struct Sink {
        lock: Mutex<()>,
        stamps: Mutex<Vec<Stamp>>,
        losses: Mutex<Vec<Loss>>,
    }

    impl Observer for Sink {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(interest, Interest::Topology(_))
        }
        fn observe(&self, stamp: Stamp, _: Observation<'_>) {
            assert!(self.lock.try_lock().is_some());
            self.stamps.lock().push(stamp);
        }
        fn lost(&self, loss: Loss) {
            assert!(self.lock.try_lock().is_some());
            self.losses.lock().push(loss);
        }
    }

    #[test]
    fn staging_flushes_outside_locks_and_reports_both_bounds() {
        for large in [false, true] {
            let sink = Arc::new(Sink::default());
            let clock = crate::clock::Clock::new(crate::RunMode::Lab);
            let dispatch = Dispatch::for_run(Some(sink.clone()), 1, &clock);
            {
                let _scope = Scope::new(Some(&dispatch));
                let _lock = sink.lock.lock();
                if large {
                    dispatch.topology(TopologyRef::GroupAdded {
                        group: super::super::GroupId(1),
                        name: &"x".repeat(MAX_BYTES),
                        parent: None,
                    });
                } else {
                    for id in 1..=MAX_ITEMS + 1 {
                        dispatch.topology(TopologyRef::TaskRemoved {
                            task: TaskId(id as u64),
                        });
                    }
                }
                assert!(sink.stamps.lock().is_empty());
                assert!(sink.losses.lock().is_empty());
            }
            assert_eq!(sink.stamps.lock().len(), if large { 0 } else { MAX_ITEMS });
            assert_eq!(
                *sink.losses.lock(),
                [Loss {
                    stream: Stream::Topology,
                    reason: LossReason::Staging,
                    count: 1,
                    bytes: None,
                    seqs: None
                }]
            );
        }
    }
}
