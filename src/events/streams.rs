//! Typed streams produced by a run.

use std::fmt;
use std::ops::RangeInclusive;
use std::sync::Weak;

use super::{ConnInfo, Metadata};

macro_rules! identity {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        /// Assigned when the entity registers with a run. Numbers start at 1
        /// and are never reused within that run.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) u64);
        impl $name {
            /// The run-scoped number, starting at one.
            pub fn get(self) -> u64 {
                self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), self.0)
            }
        }
    };
}
identity!(TaskId, "t", "A task identity within a run.");
identity!(GroupId, "g", "A group identity within a run.");
identity!(HostId, "h", "A host identity within a run.");
identity!(LinkId, "e", "A link identity within a run.");

/// A separately numbered stream. Each starts at 1 after interest filtering.
/// Packet interest does not affect event numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stream {
    /// Service and network facts.
    Events,
    /// Packets crossing one link.
    Packets(LinkId),
    /// TLS secrets.
    Keys,
    /// Entity lifecycles and link ownership.
    Topology,
}

/// A link's sending end. For attachments, A is the world and B is the sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The first end.
    A,
    /// The second end.
    B,
}

/// The framing of packet bytes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// IPv4 or IPv6 with no link-layer header.
    Ip,
}

/// Borrowed bytes offered for a link crossing.
/// Core delivers interested successful crossings without copying, decoding or sampling.
#[derive(Clone, Copy, Debug)]
pub struct PacketRef<'a> {
    /// The link crossed.
    pub link: LinkId,
    /// The tap's current name.
    pub tap: &'a str,
    /// The attached sandbox, when this is an attachment.
    pub sandbox: Option<&'a str>,
    /// The sending end.
    pub side: Side,
    /// The original byte length.
    pub len: usize,
    /// The packet framing.
    pub link_type: LinkType,
    /// The whole packet, without truncation or a link-layer header.
    pub bytes: &'a [u8],
}

/// Metadata available before emitting a TLS secret.
#[derive(Clone, Copy, Debug)]
pub struct KeyMeta<'a> {
    /// The TLS key log label.
    pub label: &'a str,
    /// Connection context, when available.
    pub connection: Option<&'a ConnInfo>,
}

/// A borrowed TLS secret. Debug formatting shows the label, client random,
/// connection and secret length, but never the secret bytes.
/// Core does not retain keys.
#[derive(Clone, Copy)]
pub struct KeyRef<'a> {
    /// The TLS key log label.
    pub label: &'a str,
    /// The ClientHello random.
    pub client_random: &'a [u8],
    pub(crate) secret: &'a [u8],
    /// Connection context, when available.
    pub connection: Option<&'a ConnInfo>,
}

impl KeyRef<'_> {
    /// The secret bytes, for an explicitly interested consumer.
    pub fn secret(&self) -> &[u8] {
        self.secret
    }
}

impl fmt::Debug for KeyRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRef")
            .field("label", &self.label)
            .field("client_random", &self.client_random)
            .field("secret_len", &self.secret.len())
            .field("connection", &self.connection)
            .finish()
    }
}

/// Absolute traffic sent by one end of a link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Packets sent.
    pub packets: u64,
    /// Bytes sent.
    pub bytes: u64,
}

/// A weak handle to a link's live counters, readable from any thread.
#[derive(Clone)]
pub struct LinkCounters(pub(crate) Weak<crate::link::Meter>);

impl LinkCounters {
    /// Absolute totals for A and B, or zero after the link is gone.
    pub fn totals(&self) -> [Counts; 2] {
        counts(self.0.upgrade().map_or([0; 4], |meter| meter.totals()))
    }
}

pub(crate) fn counts(totals: [u64; 4]) -> [Counts; 2] {
    [
        Counts {
            packets: totals[0],
            bytes: totals[1],
        },
        Counts {
            packets: totals[2],
            bytes: totals[3],
        },
    ]
}

impl fmt::Debug for LinkCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkCounters").finish_non_exhaustive()
    }
}

/// A topology category whose interest is fixed for a run.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyKind {
    /// Task lifecycles.
    Task,
    /// Group lifecycles.
    Group,
    /// Host lifecycles.
    Host,
    /// Link lifecycles, labels and ownership.
    Link,
    /// Connection bindings.
    Connection,
}

/// A borrowed change to the run's topology.
/// Consumers materialize topology. Core keeps identity and producer state.
/// Link creation lends live absolute counters; removal carries final totals.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum TopologyRef<'a> {
    /// A service has accepted a connection.
    ConnectionOpened {
        /// Connection identity and local and peer addresses.
        conn: &'a ConnInfo,
        /// Serving task, when known.
        task: Option<TaskId>,
        /// Nearest host containing the serving context.
        host: Option<HostId>,
    },
    /// A served connection has closed.
    ConnectionClosed {
        /// Connection identity and local and peer addresses.
        conn: &'a ConnInfo,
    },
    /// A task has been created, before its first poll.
    TaskAdded {
        /// Task identity.
        task: TaskId,
        /// Spawning task, if any.
        parent: Option<TaskId>,
        /// Full function or future type name.
        name: &'a str,
        /// Source file.
        file: &'static str,
        /// Source line.
        line: u32,
        /// Containing group.
        group: Option<GroupId>,
    },
    /// A task has completed.
    TaskRemoved {
        /// Task identity.
        task: TaskId,
    },
    /// A group has been created.
    GroupAdded {
        /// Group identity.
        group: GroupId,
        /// Display name.
        name: &'a str,
        /// Containing group.
        parent: Option<GroupId>,
    },
    /// The last group reference has been dropped.
    GroupRemoved {
        /// Group identity.
        group: GroupId,
    },
    /// A simulated machine or sandbox has been created.
    HostAdded {
        /// Host identity.
        host: HostId,
        /// Display name.
        name: &'a str,
        /// Machine group, when simulated.
        group: Option<GroupId>,
        /// Attached sandbox name.
        sandbox: Option<&'a str>,
    },
    /// A host has been removed.
    HostRemoved {
        /// Host identity.
        host: HostId,
    },
    /// A link has registered with the run.
    LinkAdded {
        /// Link identity.
        link: LinkId,
        /// Creating task, if known.
        creator: Option<TaskId>,
        /// Attached sandbox name.
        sandbox: Option<&'a str>,
        /// Attached host identity.
        host: Option<HostId>,
        /// Live absolute counters.
        counters: LinkCounters,
    },
    /// A task has begun polling an end.
    LinkOwner {
        /// Link identity.
        link: LinkId,
        /// Receiving end.
        side: Side,
        /// Owning task.
        task: TaskId,
    },
    /// A link has been tapped or renamed.
    LinkTap {
        /// Link identity.
        link: LinkId,
        /// Tap name.
        name: &'a str,
    },
    /// A link has been removed.
    LinkRemoved {
        /// Link identity.
        link: LinkId,
        /// Final totals for A and B.
        totals: [Counts; 2],
    },
}

impl TopologyRef<'_> {
    /// The category used for interest filtering.
    pub fn kind(&self) -> TopologyKind {
        match self {
            Self::ConnectionOpened { .. } | Self::ConnectionClosed { .. } => {
                TopologyKind::Connection
            }
            Self::TaskAdded { .. } | Self::TaskRemoved { .. } => TopologyKind::Task,
            Self::GroupAdded { .. } | Self::GroupRemoved { .. } => TopologyKind::Group,
            Self::HostAdded { .. } | Self::HostRemoved { .. } => TopologyKind::Host,
            Self::LinkAdded { .. }
            | Self::LinkOwner { .. }
            | Self::LinkTap { .. }
            | Self::LinkRemoved { .. } => TopologyKind::Link,
        }
    }
}

/// Metadata used to decide whether observation work is useful.
#[derive(Clone, Copy, Debug)]
pub enum Interest<'a> {
    /// Service or network fact.
    Event(Metadata, &'a ConnInfo),
    /// Packet crossing.
    Packet(PacketRef<'a>),
    /// TLS secret.
    TlsKey(KeyMeta<'a>),
    /// Topology change.
    Topology(TopologyKind),
}

/// Why observations were lost.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossReason {
    /// A producer buffer was full.
    Staging,
    /// A consumer sampled input.
    Sampling,
    /// A consumer shortened input.
    Truncation,
    /// Retained input was evicted.
    Eviction,
    /// A worker queue was full.
    Overflow,
}

/// Explicit loss within one stream, reported by a producer or consumer.
/// Missing sequence numbers alone do not imply loss: filters can leave gaps.
/// Loss before numbering can have no sequence range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loss {
    /// Affected stream.
    pub stream: Stream,
    /// Cause of loss.
    pub reason: LossReason,
    /// Number of affected observations.
    pub count: u64,
    /// Number of affected bytes, if known.
    pub bytes: Option<u64>,
    /// Inclusive sequence range, if known.
    pub seqs: Option<RangeInclusive<u64>>,
}

impl Loss {
    /// `count` observations of `stream` that a producer dropped because its
    /// buffer was full, before they were numbered.
    pub fn staged(stream: Stream, count: u64) -> Self {
        Loss {
            stream,
            reason: LossReason::Staging,
            count,
            bytes: None,
            seqs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Fanout, Observation, Observer, Stamp};
    use crate::sync::Mutex;
    use crate::{Interface, InterfaceExt, Packet, RunOptions, Seed, block_on, lab};
    use fictionet::events::recorder::Recorder;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Default)]
    struct Topology {
        items: Mutex<Vec<(Stamp, String)>>,
        threads: Mutex<Vec<std::thread::ThreadId>>,
        counters: Mutex<Option<LinkCounters>>,
        removed: Mutex<Vec<[Counts; 2]>>,
    }

    impl Observer for Topology {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(interest, Interest::Topology(_))
        }

        fn observe(&self, stamp: Stamp, item: Observation<'_>) {
            let Observation::Topology(topology) = item else {
                panic!("unexpected stream")
            };
            if let TopologyRef::LinkAdded { counters, .. } = &topology {
                *self.counters.lock() = Some(counters.clone());
            }
            if let TopologyRef::LinkRemoved { totals, .. } = &topology {
                self.removed.lock().push(*totals);
            }
            self.items.lock().push((stamp, format!("{topology:?}")));
            self.threads.lock().push(std::thread::current().id());
        }
    }

    fn topology_run() -> Vec<(Stamp, String)> {
        let first = Arc::new(Topology::default());
        let second = Arc::new(Topology::default());
        let memory = Arc::new(Recorder::default());
        let observer = Arc::new(Fanout::new(vec![
            first.clone(),
            memory.clone(),
            second.clone(),
        ]));
        let counters = first.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(7)).observer(observer),
            move |cx| async move {
                let group = cx.group("network");
                let host = group.host("machine");
                let (mut a, mut b) = crate::pair();
                a = cx.tap("uplink", a);
                let task = host.spawn(move |cx| async move {
                    let packet = b.recv(&cx).await?;
                    b.send(packet);
                    Ok(())
                });
                a.send(Packet(vec![1; 12]));
                // Topology a poll produces arrives once the poll returns.
                assert!(counters.counters.lock().is_none());
                cx.yield_now().await?;
                assert_eq!(
                    counters.counters.lock().as_ref().unwrap().totals(),
                    [
                        Counts {
                            packets: 1,
                            bytes: 12
                        },
                        Counts::default()
                    ]
                );
                assert_eq!(a.recv(&cx).await?, Packet(vec![1; 12]));
                task.join(&cx).await?;
                cx.sleep(Duration::from_secs(1)).await?;
                drop(a);
                drop(host);
                drop(group);
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(*first.items.lock(), *second.items.lock());
        assert_eq!(
            *first.removed.lock(),
            [[Counts {
                packets: 1,
                bytes: 12
            }; 2]]
        );
        assert_eq!(memory.all().len(), 1);
        let items = first.items.lock().clone();
        for (index, (stamp, _)) in items.iter().enumerate() {
            assert_eq!(stamp.stream, Stream::Topology);
            assert_eq!(stamp.seq, index as u64 + 1);
        }
        assert!(
            items[0]
                .1
                .starts_with("TaskAdded { task: TaskId(1), parent: None")
        );
        let text = items
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("GroupAdded { group: GroupId(1), name: \"network\", parent: None"));
        assert!(
            text.contains(
                "HostAdded { host: HostId(1), name: \"machine\", group: Some(GroupId(2))"
            )
        );
        assert!(text.contains("LinkAdded { link: LinkId(1), creator: Some(TaskId(1))"));
        assert!(text.contains("LinkTap { link: LinkId(1), name: \"uplink\" }"));
        assert!(text.contains("LinkOwner { link: LinkId(1), side: A, task: TaskId(1) }"));
        assert!(text.contains("LinkOwner { link: LinkId(1), side: B, task: TaskId(2) }"));
        assert!(text.find("HostRemoved").unwrap() < text.find("GroupRemoved").unwrap());
        items
    }

    #[test]
    fn topology_lifecycles_and_stamps_repeat() {
        assert_eq!(topology_run(), topology_run());
    }

    #[test]
    fn spawned_tasks_are_announced_before_their_parent_ends() {
        use std::future::Future;
        use std::task::{Context, Waker};

        for complete in [true, false] {
            let topology = Arc::new(Topology::default());
            let reader = topology.clone();
            let mut world = Box::pin(lab(
                RunOptions::new(Seed::from_u64(7)).observer(topology.clone()),
                move |cx| async move {
                    cx.spawn(|_| async { Ok(()) });
                    cx.group("children").spawn(|_| async { Ok(()) });
                    assert_eq!(reader.items.lock().len(), 1);
                    Ok(())
                },
            ));
            assert!(
                world
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            {
                let items = topology.items.lock();
                let root_removed = items
                    .iter()
                    .position(|(_, item)| item == "TaskRemoved { task: TaskId(1) }")
                    .unwrap();
                for (id, group) in [(2, "group: None"), (3, "group: Some(GroupId(1))")] {
                    let child_added = items
                        .iter()
                        .position(|(_, item)| {
                            item.starts_with(&format!(
                                "TaskAdded {{ task: TaskId({id}), parent: Some(TaskId(1)),"
                            )) && item.contains(group)
                        })
                        .unwrap();
                    assert!(child_added < root_removed);
                }
            }
            if complete {
                block_on(world).unwrap();
            } else {
                drop(world);
            }
            let items = topology.items.lock();
            for id in 1..=3 {
                assert_eq!(
                    items
                        .iter()
                        .filter(|(_, item)| item
                            .starts_with(&format!("TaskAdded {{ task: TaskId({id}),")))
                        .count(),
                    1
                );
                assert_eq!(
                    items
                        .iter()
                        .filter(|(_, item)| item == &format!("TaskRemoved {{ task: TaskId({id}) }}"))
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn foreign_spawns_are_announced_on_the_polling_thread() {
        use std::future::Future;
        use std::task::{Context, Waker};

        for complete in [true, false] {
            let topology = Arc::new(Topology::default());
            let polling_thread = std::thread::current().id();
            let mut world = Box::pin(lab(
                RunOptions::new(Seed::from_u64(7)).observer(topology.clone()),
                move |cx| async move {
                    assert_eq!(std::thread::current().id(), polling_thread);
                    let foreign = cx.clone();
                    std::thread::spawn(move || {
                        assert_ne!(std::thread::current().id(), polling_thread);
                        foreign.spawn(move |cx| async move {
                            assert_eq!(std::thread::current().id(), polling_thread);
                            let (mut a, mut b) = crate::pair();
                            a = cx.tap("foreign", a);
                            b.send(Packet(vec![1]));
                            a.recv(&cx).await?;
                            Ok(())
                        });
                    })
                    .join()
                    .unwrap();
                    Ok(())
                },
            ));
            assert!(
                world
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if complete {
                block_on(world).unwrap();
            } else {
                drop(world);
            }
            let items = topology.items.lock();
            let mentions = items
                .iter()
                .enumerate()
                .filter(|(_, (_, item))| item.contains("TaskId(2)"))
                .collect::<Vec<_>>();
            let (added, (_, first)) = mentions[0];
            assert!(first.starts_with("TaskAdded { task: TaskId(2), parent: None,"));
            assert_eq!(topology.threads.lock()[added], polling_thread);
            assert_eq!(
                mentions
                    .iter()
                    .filter(|(_, (_, item))| item.starts_with("TaskAdded"))
                    .count(),
                1
            );
            assert_eq!(
                mentions
                    .iter()
                    .filter(|(_, (_, item))| item.starts_with("TaskRemoved"))
                    .count(),
                1
            );
            assert_eq!(
                mentions
                    .iter()
                    .filter(|(_, (_, item))| item.starts_with("LinkOwner"))
                    .count(),
                usize::from(complete)
            );
        }
    }

    #[test]
    fn an_attachment_registers_a_host_before_its_link() {
        let topology = Arc::new(Topology::default());
        let (attacher, mut attachments) = crate::attachments();
        let mut sandbox = attacher.attach("guest").unwrap();
        block_on(lab(
            RunOptions::new(Seed::from_u64(2)).observer(topology.clone()),
            move |cx| async move {
                let mut attachment = attachments.next(&cx).await?;
                attachment = cx.tap("guest uplink", attachment);
                sandbox.send(Packet(vec![7; 3]));
                attachment.recv(&cx).await?;
                drop(attachment);
                drop(sandbox);
                Ok(())
            },
        ))
        .unwrap();
        let items = topology.items.lock();
        assert!(items[1].1.starts_with(
            "HostAdded { host: HostId(1), name: \"guest\", group: None, sandbox: Some(\"guest\")"
        ));
        assert!(items[2].1.starts_with("LinkAdded { link: LinkId(1), creator: None, sandbox: Some(\"guest\"), host: Some(HostId(1))"));
        assert!(
            items
                .iter()
                .any(|(_, item)| item == "LinkTap { link: LinkId(1), name: \"guest uplink\" }")
        );
        assert!(
            items
                .iter()
                .any(|(_, item)| item == "LinkOwner { link: LinkId(1), side: A, task: TaskId(1) }")
        );
        assert_eq!(
            *topology.removed.lock(),
            [[
                Counts::default(),
                Counts {
                    packets: 1,
                    bytes: 3
                }
            ]]
        );
    }

    #[test]
    fn key_debug_redacts_secret_bytes() {
        let key = KeyRef {
            label: "CLIENT_RANDOM",
            client_random: &[1, 2],
            secret: b"private secret",
            connection: None,
        };
        assert_eq!(key.secret(), b"private secret");
        let debug = format!("{key:?}");
        assert!(!debug.contains("private secret"));
        assert!(!debug.contains("112, 114, 105"));
        assert!(debug.contains("secret_len: 14"));
    }
}
