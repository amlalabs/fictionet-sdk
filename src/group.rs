//! Named task groups and host identity.

use std::sync::Arc;

/// A named group of tasks, from [`Cx::group`](crate::Cx::group). Only
/// observers read it.
pub(crate) struct Group {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) parent: Option<Arc<Group>>,
    observer: Option<Arc<crate::events::Dispatch>>,
    pub(crate) host: Option<crate::events::HostId>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("parent", &self.parent)
            .finish_non_exhaustive()
    }
}

impl Group {
    pub(crate) fn new(
        id: u64,
        name: String,
        parent: Option<Arc<Group>>,
        observer: Option<Arc<crate::events::Dispatch>>,
        host: bool,
    ) -> Arc<Group> {
        use crate::events::{GroupId, TopologyRef};
        let host = observer.as_ref().filter(|_| host).map(|o| o.next_host());
        let group = Arc::new(Group {
            id,
            name,
            parent,
            observer,
            host,
        });
        if let Some(observer) = &group.observer {
            observer.topology(TopologyRef::GroupAdded {
                group: GroupId(id),
                name: &group.name,
                parent: group.parent.as_ref().map(|p| GroupId(p.id)),
            });
            if let Some(host) = group.host {
                observer.topology(TopologyRef::HostAdded {
                    host,
                    name: &group.name,
                    group: Some(GroupId(id)),
                    sandbox: None,
                });
            }
        }
        group
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        use crate::events::{GroupId, TopologyRef};
        if let Some(observer) = &self.observer {
            if let Some(host) = self.host {
                observer.topology(TopologyRef::HostRemoved { host });
            }
            observer.topology(TopologyRef::GroupRemoved {
                group: GroupId(self.id),
            });
        }
    }
}
