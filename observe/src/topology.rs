use std::collections::BTreeMap;

use fictionet::events::{
    ConnInfo, Counts, GroupId, HostId, LinkCounters, LinkId, LossReason, Side, Stamp, TaskId,
    TopologyRef,
};

use crate::LossStatus;
use crate::keys::connection_bytes;

/// Bounds for the current topology. Byte limits charge entries and owned text.
#[derive(Clone, Copy, Debug)]
pub struct TopologyLimits {
    /// Maximum tasks.
    pub tasks: usize,
    /// Maximum groups.
    pub groups: usize,
    /// Maximum hosts.
    pub hosts: usize,
    /// Maximum links, including capture state.
    pub links: usize,
    /// Maximum active connections.
    pub connections: usize,
    /// Maximum bytes of each name and connection text field.
    pub name_bytes: usize,
    /// Maximum bytes of each link tap.
    pub tap_bytes: usize,
    /// Maximum total retained entry and text bytes.
    pub bytes: usize,
}

impl Default for TopologyLimits {
    fn default() -> Self {
        Self {
            tasks: 16_384,
            groups: 4096,
            hosts: 4096,
            links: 4096,
            connections: 20_000,
            name_bytes: 1024,
            tap_bytes: 1024,
            bytes: 16 << 20,
        }
    }
}

/// A current task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    /// Run time when the task was created.
    pub started: fictionet::time::Instant,
    /// Spawning task.
    pub parent: Option<TaskId>,
    /// Function or future name.
    pub name: String,
    /// Source file.
    pub file: &'static str,
    /// Source line.
    pub line: u32,
    /// Containing group.
    pub group: Option<GroupId>,
}

/// A current group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Display name.
    pub name: String,
    /// Containing group.
    pub parent: Option<GroupId>,
}

/// A current host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// Display name.
    pub name: String,
    /// Machine group.
    pub group: Option<GroupId>,
    /// Sandbox name.
    pub sandbox: Option<String>,
}

/// A current link. The counter handle does not keep the link alive.
#[derive(Clone, Debug)]
pub struct Link {
    /// Creating task.
    pub creator: Option<TaskId>,
    /// Tasks using ends A and B.
    pub owners: [Option<TaskId>; 2],
    /// Sandbox name.
    pub sandbox: Option<String>,
    /// Attached host.
    pub host: Option<HostId>,
    /// Tap name.
    pub tap: String,
    /// Live absolute counters.
    pub counters: LinkCounters,
}

/// A connection and its serving context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// Connection and flow identity.
    pub conn: ConnInfo,
    /// Serving task.
    pub task: Option<TaskId>,
    /// Serving host.
    pub host: Option<HostId>,
}

/// A revisioned snapshot of current entities. Compare maps between snapshots
/// to find additions, changes and removals. No removed entity is retained.
#[derive(Clone, Debug, Default)]
pub struct Topology {
    /// Increases when state or completeness changes.
    pub revision: u64,
    /// Current tasks.
    pub tasks: BTreeMap<TaskId, Task>,
    /// Current groups.
    pub groups: BTreeMap<GroupId, Group>,
    /// Current hosts.
    pub hosts: BTreeMap<HostId, Host>,
    /// Current links.
    pub links: BTreeMap<LinkId, Link>,
    /// Active connections in arrival order.
    pub connections: Vec<Connection>,
    /// Whether any topology input was refused, shortened or lost.
    pub incomplete: bool,
    /// Changes refused by entry or byte bounds.
    pub refused: u64,
    /// Changes ignored because an entity was missing.
    pub missing: u64,
    /// Text bytes cut at UTF-8 boundaries.
    pub truncated_bytes: u64,
    bytes: usize,
}

trait Size {
    fn size(&self) -> usize;
}
impl Size for Task {
    fn size(&self) -> usize {
        size_of::<Self>() + self.name.len()
    }
}
impl Size for Group {
    fn size(&self) -> usize {
        size_of::<Self>() + self.name.len()
    }
}
impl Size for Host {
    fn size(&self) -> usize {
        size_of::<Self>() + self.name.len() + self.sandbox.as_ref().map_or(0, String::len)
    }
}
impl Size for Link {
    fn size(&self) -> usize {
        size_of::<Self>() + self.tap.len() + self.sandbox.as_ref().map_or(0, String::len)
    }
}
impl Size for Connection {
    fn size(&self) -> usize {
        size_of::<Self>() + connection_bytes(&self.conn)
    }
}

fn insert<K: Ord, V: Size>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    count: usize,
    bytes: &mut usize,
    max: usize,
) -> bool {
    let previous = map.get(&key).map_or(0, Size::size);
    if (previous == 0 && map.len() >= count) || value.size() > max.saturating_sub(*bytes - previous)
    {
        return false;
    }
    *bytes = *bytes - previous + value.size();
    map.insert(key, value);
    true
}

fn remove<K: Ord, V: Size>(map: &mut BTreeMap<K, V>, key: &K, bytes: &mut usize) -> bool {
    if let Some(value) = map.remove(key) {
        *bytes -= value.size();
        true
    } else {
        false
    }
}

fn text(value: &str, max: usize, cut: &mut usize) -> String {
    let end = value.floor_char_boundary(value.len().min(max));
    *cut = cut.saturating_add(value.len() - end);
    value[..end].into()
}

fn connection(conn: &ConnInfo, max: usize, cut: &mut usize) -> ConnInfo {
    let mut conn = conn.clone();
    if let Some(name) = &mut conn.sni {
        *name = text(name, max, cut).into();
    }
    if let Some(sandbox) = &mut conn.sandbox {
        sandbox.name = text(&sandbox.name, max, cut).into();
    }
    if let Some(alpn) = &mut conn.alpn {
        *cut = cut.saturating_add(alpn.len().saturating_sub(max));
        *alpn = alpn[..alpn.len().min(max)].into();
    }
    conn
}

fn same_connection(a: &ConnInfo, b: &ConnInfo) -> bool {
    a.id == b.id
        && a.local == b.local
        && a.peer == b.peer
        && a.transport == b.transport
        && a.sandbox.as_ref().map(|s| s.id) == b.sandbox.as_ref().map(|s| s.id)
}

impl Topology {
    /// Reads current absolute counters for each retained link.
    pub fn counters(&self) -> BTreeMap<LinkId, [Counts; 2]> {
        self.links
            .iter()
            .map(|(id, link)| (*id, link.counters.totals()))
            .collect()
    }

    pub(crate) fn apply(
        &mut self,
        stamp: Stamp,
        item: TopologyRef<'_>,
        limits: TopologyLimits,
        losses: &mut LossStatus,
        loss_streams: usize,
    ) {
        let mut cut = 0;
        let mut missing = false;
        let accepted = match item {
            TopologyRef::TaskAdded {
                task,
                parent,
                name,
                file,
                line,
                group,
            } => {
                missing = parent.is_some_and(|id| !self.tasks.contains_key(&id))
                    || group.is_some_and(|id| !self.groups.contains_key(&id));
                !missing
                    && insert(
                        &mut self.tasks,
                        task,
                        Task {
                            started: stamp.at,
                            parent,
                            name: text(name, limits.name_bytes, &mut cut),
                            file,
                            line,
                            group,
                        },
                        limits.tasks,
                        &mut self.bytes,
                        limits.bytes,
                    )
            }
            TopologyRef::GroupAdded {
                group,
                name,
                parent,
            } => {
                missing = parent.is_some_and(|id| !self.groups.contains_key(&id));
                !missing
                    && insert(
                        &mut self.groups,
                        group,
                        Group {
                            name: text(name, limits.name_bytes, &mut cut),
                            parent,
                        },
                        limits.groups,
                        &mut self.bytes,
                        limits.bytes,
                    )
            }
            TopologyRef::HostAdded {
                host,
                name,
                group,
                sandbox,
            } => {
                missing = group.is_some_and(|id| !self.groups.contains_key(&id));
                !missing
                    && insert(
                        &mut self.hosts,
                        host,
                        Host {
                            name: text(name, limits.name_bytes, &mut cut),
                            group,
                            sandbox: sandbox.map(|s| text(s, limits.name_bytes, &mut cut)),
                        },
                        limits.hosts,
                        &mut self.bytes,
                        limits.bytes,
                    )
            }
            TopologyRef::LinkAdded {
                link,
                creator,
                sandbox,
                host,
                counters,
            } => {
                missing = creator.is_some_and(|id| !self.tasks.contains_key(&id))
                    || host.is_some_and(|id| !self.hosts.contains_key(&id));
                !missing
                    && insert(
                        &mut self.links,
                        link,
                        Link {
                            creator,
                            owners: [None; 2],
                            sandbox: sandbox.map(|s| text(s, limits.name_bytes, &mut cut)),
                            host,
                            counters,
                            tap: String::new(),
                        },
                        limits.links,
                        &mut self.bytes,
                        limits.bytes,
                    )
            }
            TopologyRef::LinkOwner { link, side, task } => {
                missing = !self.tasks.contains_key(&task) || !self.links.contains_key(&link);
                if !missing {
                    self.links.get_mut(&link).expect("known link").owners
                        [usize::from(side == Side::B)] = Some(task);
                }
                !missing
            }
            TopologyRef::LinkTap { link, name } => {
                if let Some(link) = self.links.get_mut(&link) {
                    let tap = text(name, limits.tap_bytes, &mut cut);
                    if tap.len() > limits.bytes.saturating_sub(self.bytes - link.tap.len()) {
                        false
                    } else {
                        self.bytes = self.bytes - link.tap.len() + tap.len();
                        link.tap = tap;
                        true
                    }
                } else {
                    missing = true;
                    false
                }
            }
            TopologyRef::TaskRemoved { task } => {
                missing = !remove(&mut self.tasks, &task, &mut self.bytes);
                for child in self.tasks.values_mut() {
                    if child.parent == Some(task) {
                        child.parent = None;
                    }
                }
                for link in self.links.values_mut() {
                    if link.creator == Some(task) {
                        link.creator = None;
                    }
                    for owner in &mut link.owners {
                        if *owner == Some(task) {
                            *owner = None;
                        }
                    }
                }
                for conn in &mut self.connections {
                    if conn.task == Some(task) {
                        conn.task = None;
                    }
                }
                !missing
            }
            TopologyRef::GroupRemoved { group } => {
                missing = !remove(&mut self.groups, &group, &mut self.bytes);
                for child in self.groups.values_mut() {
                    if child.parent == Some(group) {
                        child.parent = None;
                    }
                }
                for task in self.tasks.values_mut() {
                    if task.group == Some(group) {
                        task.group = None;
                    }
                }
                for host in self.hosts.values_mut() {
                    if host.group == Some(group) {
                        host.group = None;
                    }
                }
                !missing
            }
            TopologyRef::HostRemoved { host } => {
                missing = !remove(&mut self.hosts, &host, &mut self.bytes);
                for link in self.links.values_mut() {
                    if link.host == Some(host) {
                        link.host = None;
                    }
                }
                for conn in &mut self.connections {
                    if conn.host == Some(host) {
                        conn.host = None;
                    }
                }
                !missing
            }
            TopologyRef::LinkRemoved { link, .. } => {
                missing = !remove(&mut self.links, &link, &mut self.bytes);
                !missing
            }
            TopologyRef::ConnectionOpened { conn, task, host } => {
                missing = task.is_some_and(|id| !self.tasks.contains_key(&id))
                    || host.is_some_and(|id| !self.hosts.contains_key(&id));
                if missing || self.connections.len() >= limits.connections {
                    false
                } else {
                    let conn = Connection {
                        conn: connection(conn, limits.name_bytes, &mut cut),
                        task,
                        host,
                    };
                    if conn.size() > limits.bytes.saturating_sub(self.bytes) {
                        false
                    } else {
                        self.bytes += conn.size();
                        self.connections.push(conn);
                        true
                    }
                }
            }
            TopologyRef::ConnectionClosed { conn } => {
                if let Some(index) = self
                    .connections
                    .iter()
                    .position(|c| same_connection(&c.conn, conn))
                {
                    self.bytes -= self.connections.remove(index).size();
                    true
                } else {
                    missing = true;
                    false
                }
            }
            _ => return,
        };
        self.revision = self.revision.saturating_add(1);
        if !accepted {
            self.incomplete = true;
            if missing {
                self.missing = self.missing.saturating_add(1);
            } else {
                self.refused = self.refused.saturating_add(1);
            }
            losses.record(loss_streams, stamp, LossReason::Overflow, 0);
        }
        if cut > 0 {
            self.incomplete = true;
            self.truncated_bytes = self.truncated_bytes.saturating_add(cut as u64);
            losses.record(loss_streams, stamp, LossReason::Truncation, cut);
        }
    }
}
