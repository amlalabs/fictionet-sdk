use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use super::{Area, Column, Host, Page, PanelContent, PanelDescription, StateTopic, http, panel};

/// Server-side equality filters over retained dashboard events. None matches all.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event source.
    pub source: Option<String>,
    /// Event kind.
    pub kind: Option<String>,
    /// Equality on a named member of the event's fields object.
    pub field: Option<(String, serde_json::Value)>,
    /// Requires a named member of the event's fields object, including null values.
    pub field_present: Option<String>,
    /// Page host name, mapped to its sandbox.
    pub host: Option<String>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl Page {
    /// Registers bounded state without adding a panel.
    pub fn state<T: Serialize>(mut self, name: impl Into<String>, topic: StateTopic<T>) -> Self {
        let name = name.into();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            self.errors.push(
                "state needs a name of at most 128 ASCII letters, digits, hyphens or underscores"
                    .into(),
            );
        }
        self.topics.push((name, topic.topic));
        self
    }

    /// Adds one machine. Names are validated at bind.
    pub fn host(mut self, host: Host) -> Self {
        self.hosts.push(host);
        self
    }
    /// Adds consoles, Packets, Events, Map and Left the box at bind.
    pub fn standard_panels(mut self) -> Self {
        if self.standard {
            self.errors
                .push("standard_panels called twice; call it once".into());
        }
        self.standard = true;
        self
    }
    /// Adds the bounded projection of guest destinations and world answers.
    pub fn left_the_box(mut self) -> Self {
        self.panels.push(PanelDescription {
            id: "left-the-box".into(),
            title: "Left the box".into(),
            area: Area::Inspector,
            content: PanelContent::LeftTheBox,
        });
        self
    }
    /// Adds startup containment results published by the world or guest kit.
    pub fn containment(mut self, topic: StateTopic<super::Containment>) -> Self {
        self.topics.push(("containment".into(), topic.topic));
        self.panels.push(PanelDescription {
            id: "containment".into(),
            title: "Containment".into(),
            area: Area::Inspector,
            content: PanelContent::Containment {
                state: "/api/state/containment".into(),
            },
        });
        self
    }
    /// Adds a server-filtered event table over the dashboard session.
    pub fn event_table(
        mut self,
        title: impl Into<String>,
        filter: EventFilter,
        columns: Vec<Column>,
    ) -> Self {
        let title = title.into();
        let id = panel::slug(&title);
        self.filters.push((id.clone(), filter));
        self.panels.push(PanelDescription {
            id: id.clone(),
            title,
            area: Area::Inspector,
            content: PanelContent::EventTable {
                events: format!("/api/event-table/{id}"),
                columns,
            },
        });
        self
    }
    /// Names a story moment by the world events that mark it.
    pub fn moment(mut self, title: impl Into<String>, filter: EventFilter) -> Self {
        let title = title.into();
        let id = panel::slug(&title);
        self.filters.push((id.clone(), filter));
        self.moments.push(super::MomentDescription {
            events: format!("/api/event-table/{id}"),
            id,
            title,
        });
        self
    }
    /// Embeds a module exporting mount(root, services, options), returning dispose.
    pub fn custom<T: Serialize>(
        mut self,
        title: impl Into<String>,
        module_source: impl Into<String>,
        topic: StateTopic<T>,
    ) -> Self {
        let title = title.into();
        let id = panel::slug(&title);
        self.topics.push((id.clone(), topic.topic));
        self.modules.push((id.clone(), module_source.into()));
        self.panels.push(PanelDescription {
            id: id.clone(),
            title,
            area: Area::Inspector,
            content: PanelContent::Custom {
                module: format!("/panels/{id}.mjs"),
                state: format!("/api/state/{id}"),
            },
        });
        self
    }
    /// Embeds a file at /assets/path. Paths and media types are validated at bind.
    pub fn asset(
        mut self,
        path: impl Into<String>,
        content_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        self.assets
            .push((path.into(), content_type.into(), bytes.into()));
        self
    }
    /// Places a named custom panel in the workspace and consoles in the inspector.
    pub fn workspace(mut self, title: impl Into<String>) -> Self {
        let title = title.into();
        if self.workspace.replace(title.clone()).is_some() {
            self.errors.push(format!(
                "workspace({title:?}) called twice; select one custom panel"
            ));
        }
        self
    }
    /// Keeps console tiles beside the custom panel selected by `workspace`.
    pub fn workspace_consoles(mut self) -> Self {
        self.workspace_consoles = true;
        self
    }
    /// Names an address the page's consoles reach the hosts from, such as an
    /// admin SSH host. Its packets are the page's own screen and terminal
    /// traffic, so the packet list hides them until a viewer shows them.
    pub fn console_address(mut self, address: std::net::IpAddr) -> Self {
        if !self.console_addresses.contains(&address) {
            self.console_addresses.push(address);
        }
        self
    }
    /// Puts the named inspector panel first and opens the inspector on it, so
    /// a demo's own panel is what a viewer sees before Packets. The page's
    /// other own panels follow it in the order they were declared, before the
    /// standard panels.
    pub fn inspector_first(mut self, title: impl Into<String>) -> Self {
        let title = title.into();
        if self.inspector_first.replace(title.clone()).is_some() {
            self.errors.push(format!(
                "inspector_first({title:?}) called twice; choose one panel"
            ));
        }
        self
    }

    /// Injects elapsed monotonic time for ticket expiration and lease timestamps.
    pub fn clock(mut self, clock: impl Fn() -> Duration + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    pub(super) fn prepare(&mut self) -> io::Result<()> {
        let mut names = std::collections::BTreeSet::new();
        for host in &mut self.hosts {
            if host.name.is_empty()
                || !host
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || !names.insert(host.name.clone())
            {
                return Err(invalid(format!(
                    "host({:?}) is invalid or duplicated; use a unique name with ASCII letters, digits, - or _",
                    host.name
                )));
            }
            if host.sandbox.is_empty() {
                return Err(invalid(format!(
                    "host({:?}).sandbox is empty; name its world sandbox",
                    host.name
                )));
            }
            if let Some(console) = &host.console {
                host.screen = console.screen().is_some();
                host.terminal = console.terminal(80, 24).is_some();
            }
            self.topics
                .push((format!("host-{}", host.name), host.status.topic.clone()));
            if self.standard {
                let description = host.description();
                for (id, title, content) in [
                    (
                        description.screen,
                        format!("{} Screen", host.name),
                        PanelContent::Screen {
                            host: host.name.clone(),
                        },
                    ),
                    (
                        description.terminal,
                        format!("{} Terminal", host.name),
                        PanelContent::Terminal {
                            host: host.name.clone(),
                        },
                    ),
                ] {
                    if let Some(id) = id {
                        self.panels.push(PanelDescription {
                            id,
                            title,
                            content,
                            area: Area::Workspace,
                        });
                    }
                }
            }
        }
        if self.standard
            && !self
                .panels
                .iter()
                .any(|panel| matches!(panel.content, PanelContent::Containment { .. }))
        {
            self.topics.push((
                "containment".into(),
                StateTopic::<super::Containment>::new(super::StateLimits::default()).topic,
            ));
            self.panels.push(PanelDescription {
                id: "containment".into(),
                title: "Containment".into(),
                area: Area::Inspector,
                content: PanelContent::Containment {
                    state: "/api/state/containment".into(),
                },
            });
        }
        if self.standard && self.labels.is_none() {
            self.panels.push(PanelDescription {
                id: "labels".into(),
                title: "Labels and export".into(),
                area: Area::Inspector,
                content: PanelContent::Labels {
                    state: None,
                    command: None,
                },
            });
        }
        if self.standard {
            for (title, content) in [
                ("Packets", PanelContent::Packets),
                ("Events", PanelContent::Events),
                ("Map", PanelContent::Map),
                ("Left the box", PanelContent::LeftTheBox),
            ] {
                self.panels.push(PanelDescription {
                    id: panel::slug(title),
                    title: title.into(),
                    content,
                    area: Area::Inspector,
                });
            }
        }
        if let Some(title) = &self.workspace {
            let selected = self
                .panels
                .iter()
                .position(|p| {
                    &p.title == title && matches!(p.content, PanelContent::Custom { .. })
                })
                .ok_or_else(|| {
                    invalid(format!(
                        "workspace({title:?}) must name a custom panel; declare it with custom first"
                    ))
                })?;
            for panel in &mut self.panels {
                if !self.workspace_consoles
                    || !matches!(
                        panel.content,
                        PanelContent::Screen { .. } | PanelContent::Terminal { .. }
                    )
                {
                    panel.area = Area::Inspector;
                }
            }
            self.panels[selected].area = Area::Workspace;
        }
        if let Some(title) = &mut self.inspector_first {
            let panel = self
                .panels
                .iter()
                .find(|p| &p.title == title && p.area == Area::Inspector)
                .ok_or_else(|| {
                    invalid(format!(
                        "inspector_first({title:?}) names no inspector panel; give the title of a declared panel that is not in the workspace"
                    ))
                })?;
            // From here on it holds the panel id that /api/page reports.
            *title = panel.id.clone();
        }
        let mut paths = std::collections::BTreeSet::new();
        for (path, kind, _) in &self.assets {
            if path.is_empty()
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || !paths.insert(path)
            {
                return Err(invalid(format!(
                    "asset({path:?}) has an invalid or duplicate path; use unique relative path segments with ASCII letters, digits, -, _ or ."
                )));
            }
            let mut parts = kind.split(';');
            let media = parts.next().unwrap_or_default();
            if !kind.bytes().all(|b| (32..127).contains(&b))
                || !parts.all(|part| {
                    part.trim().split_once('=').is_some_and(|(name, value)| {
                        !name.is_empty()
                            && !value.is_empty()
                            && name.bytes().all(fictionet::stdlib::codec::ascii::is_tchar)
                            && value.bytes().all(fictionet::stdlib::codec::ascii::is_tchar)
                    })
                })
                || !media.split_once('/').is_some_and(|(a, b)| {
                    !a.is_empty()
                        && !b.is_empty()
                        && a.bytes()
                            .chain(b.bytes())
                            .all(fictionet::stdlib::codec::ascii::is_tchar)
                })
            {
                return Err(invalid(format!(
                    "asset({path:?}) content type {kind:?} is invalid; supply a media type such as image/png with optional token parameters such as charset=utf-8"
                )));
            }
        }
        for (id, filter) in &self.filters {
            if filter
                .host
                .as_ref()
                .is_some_and(|name| !names.contains(name))
            {
                return Err(invalid(format!(
                    "event filter {id:?} host {:?} is unknown; declare that host first",
                    filter.host
                )));
            }
        }
        self.panels.sort_by_key(|panel| match panel.content {
            PanelContent::Packets => 0,
            PanelContent::Events => 1,
            PanelContent::Map => 2,
            PanelContent::LeftTheBox => 3,
            PanelContent::Containment { .. } => 4,
            PanelContent::Labels { .. } => 5,
            _ => 6,
        });
        Ok(())
    }
}

pub(super) async fn asset(
    conn: &mut TcpStream,
    shared: &super::Shared,
    path: &str,
) -> io::Result<()> {
    if let Some(id) = path
        .strip_prefix("/panels/")
        .and_then(|s| s.strip_suffix(".mjs"))
    {
        if let Some((_, source)) = shared.page.modules.iter().find(|(name, _)| name == id) {
            return http::respond(
                conn,
                200,
                "text/javascript; charset=utf-8",
                source.as_bytes(),
            )
            .await;
        }
    } else if let Some(path) = path.strip_prefix("/assets/")
        && let Some((_, kind, bytes)) = shared.page.assets.iter().find(|(name, _, _)| name == path)
    {
        return http::respond(conn, 200, kind, bytes).await;
    }
    http::error(conn, 404, "no such asset").await
}

pub(super) async fn projection(
    conn: &mut TcpStream,
    shared: &super::Shared,
    req: &http::Request,
) -> io::Result<()> {
    if let Some(host) = req
        .path
        .strip_prefix("/api/host/")
        .and_then(|s| s.strip_suffix("/links"))
    {
        let Some(host) = shared.page.hosts.iter().find(|h| h.name == host) else {
            return http::error(conn, 404, "no such host").await;
        };
        let links: Vec<_> = shared
            .page
            .dashboard
            .0
            .collector
            .sandbox_links(Some(&host.sandbox))
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        return http::json(conn, 200, &serde_json::json!({"links": links})).await;
    }
    let Some((_, filter)) = shared
        .page
        .filters
        .iter()
        .find(|(id, _)| req.path == format!("/api/event-table/{id}"))
    else {
        return http::error(conn, 404, "no such event table").await;
    };
    let after = match req.query.as_slice() {
        [] => 0,
        [(key, value)] if key == "after" => match value.parse::<u64>() {
            Ok(value) => value,
            Err(_) => return http::error(conn, 400, "after must be an unsigned cursor").await,
        },
        _ => return http::error(conn, 400, "event tables accept only after").await,
    };
    let sandbox = filter
        .host
        .as_ref()
        .and_then(|name| shared.page.hosts.iter().find(|host| &host.name == name))
        .map(|h| &h.sandbox);
    // The session returns at most BATCH events after a cursor. Read batches
    // until the retained events run out or a page of rows matches, so a
    // filter's next cursor never skips events it has not seen.
    const BATCH: usize = 1000;
    let (mut cursor, mut rows) = (after, Vec::new());
    let dropped = loop {
        let values = shared.page.dashboard.session().request(
            1,
            &serde_json::json!({"op":"events", "after":cursor, "max":BATCH}).to_string(),
            std::time::Instant::now(),
            None,
        );
        let mut value: serde_json::Value = serde_json::from_slice(&values[0].bytes)?;
        let Some(events) = value["events"].as_array_mut() else {
            return http::respond(conn, 404, "application/json", &values[0].bytes).await;
        };
        let full = events.len() == BATCH;
        let read = events.last().and_then(|event| event["seq"].as_u64());
        rows.extend(events.drain(..).filter(|event| {
            filter.source.as_ref().is_none_or(|s| event["source"] == *s)
                && filter.kind.as_ref().is_none_or(|s| event["kind"] == *s)
                && filter
                    .field
                    .as_ref()
                    .is_none_or(|(name, v)| event["fields"].get(name) == Some(v))
                && filter
                    .field_present
                    .as_ref()
                    .is_none_or(|name| event["fields"].get(name).is_some())
                && sandbox.is_none_or(|s| event["sandbox"]["name"] == *s)
        }));
        let dropped = value["dropped"].take();
        match read {
            Some(seq) if full => cursor = seq,
            _ => {
                cursor = value["last"].as_u64().unwrap_or(cursor);
                break dropped;
            }
        }
        if rows.len() >= BATCH {
            break dropped;
        }
    };
    let reply = serde_json::json!({
        "rows": rows,
        "next": cursor,
        "dropped": dropped,
    });
    http::json(conn, 200, &reply).await
}
