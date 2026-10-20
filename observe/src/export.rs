use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use fictionet::events::{Event, Stream};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::json::Value;

use crate::{Collector, LossStatus, PacketCopy};

/// Streams, classes, host and sequence range to export from retention.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    /// Streams to include, with packet sections in this order.
    pub streams: Vec<Stream>,
    /// Policy class indices. None selects every class.
    pub classes: Option<Vec<usize>>,
    /// Sandbox name. None selects every host.
    pub sandbox: Option<String>,
    /// Exclusive lower sequence bound, applied independently to each stream.
    pub after: u64,
    /// Inclusive upper sequence bound. None includes the retained tail.
    pub through: Option<u64>,
    /// Optional wall time at run start. Otherwise timestamps use run time.
    pub wall: Option<Duration>,
    /// Labels to attach to selected events and packet flows.
    #[cfg(feature = "page")]
    pub labels: Vec<crate::page::Label>,
}

impl Selection {
    pub(crate) fn class(&self, class: usize) -> bool {
        self.classes
            .as_ref()
            .is_none_or(|classes| classes.contains(&class))
    }
    pub(crate) fn sequence(&self, seq: u64) -> bool {
        seq > self.after && self.through.is_none_or(|last| seq <= last)
    }
    pub(crate) fn host(&self, sandbox: Option<&str>) -> bool {
        self.sandbox
            .as_deref()
            .is_none_or(|name| sandbox == Some(name))
    }
}

struct Section {
    header: Option<Vec<u8>>,
    packets: VecDeque<PacketCopy>,
}

/// A snapshot of selected ring contents. Reads do not create packet demand.
pub struct Export {
    selection: Selection,
    events: Vec<(usize, Arc<Event>)>,
    classes: Vec<&'static str>,
    losses: LossStatus,
    sections: VecDeque<Section>,
    through: u64,
    keylog: String,
}

const CHUNK: usize = 1 << 18;

impl Collector {
    /// Takes a bounded snapshot for JSONL and pcapng without a watch or decoder.
    pub fn export(&self, selection: &Selection) -> Export {
        let state = self.state.lock();
        let events = if selection.streams.contains(&Stream::Events) {
            self.events.selected(selection)
        } else {
            Vec::new()
        };
        let mut keylog = String::new();
        if selection.streams.contains(&Stream::Keys) {
            let mut seen = BTreeSet::new();
            for key in
                crate::ring::after(state.keys.rings.values(), selection.after).filter(|key| {
                    selection.sequence(key.stamp.seq)
                        && selection.class(key.class)
                        && selection.host(
                            key.connection
                                .as_ref()
                                .and_then(|conn| conn.sandbox.as_ref())
                                .map(|sandbox| &*sandbox.name),
                        )
                })
            {
                if seen.insert((
                    key.label.as_str(),
                    key.client_random.as_slice(),
                    key.secret(),
                )) {
                    crate::keys::push_keylog_line(
                        &mut keylog,
                        &key.label,
                        &key.client_random,
                        key.secret(),
                    );
                }
            }
        }
        let mut sections = VecDeque::new();
        let mut seen = BTreeSet::new();
        for stream in &selection.streams {
            let Stream::Packets(link) = stream else {
                continue;
            };
            if !seen.insert(*link) {
                continue;
            }
            let capture = state.captures.links.get(link);
            let topology = state.topology.links.get(link);
            if capture.is_none() && topology.is_none() {
                continue;
            }
            let sandbox = capture
                .and_then(|capture| capture.sandbox.as_deref())
                .or_else(|| topology.and_then(|link| link.sandbox.as_deref()));
            if !selection.host(sandbox) {
                continue;
            }
            let packets = capture.map_or_else(VecDeque::new, |capture| {
                crate::ring::after(
                    capture
                        .rings
                        .iter()
                        .filter(|(class, _)| selection.class(**class))
                        .map(|(_, ring)| ring),
                    selection.after,
                )
                .filter(|copy| selection.sequence(copy.stamp.seq))
                .cloned()
                .collect()
            });
            let mut header = Vec::new();
            crate::pcap::start(&mut header, keylog.as_bytes());
            sections.push_back(Section {
                header: Some(header),
                packets,
            });
        }
        Export {
            selection: selection.clone(),
            events,
            classes: self
                .options
                .policy
                .classes()
                .iter()
                .map(|class| class.name)
                .collect(),
            losses: self.losses(),
            sections,
            keylog,
            through: self
                .events
                .last()
                .min(selection.through.unwrap_or(u64::MAX)),
        }
    }
}

impl Export {
    /// Selected retained keys in SSLKEYLOGFILE format.
    pub fn keylog(&self) -> &str {
        &self.keylog
    }

    /// Event stream tail at the snapshot, bounded by the selection.
    pub fn through(&self) -> u64 {
        self.through
    }

    /// Selected event lines followed by cumulative loss totals for the selected
    /// streams and classes. Loss totals cover the run, since sequence ranges and
    /// sandbox identities are not available for every loss.
    pub fn jsonl(&self) -> impl Iterator<Item = fictionet::Result<String>> + '_ {
        let events = self.events.iter().map(|(class, event)| {
            let mut line = event.to_line()?;
            line.pop();
            line.push_str(&format!(",\"class\":{class}"));
            #[cfg(feature = "page")]
            {
                let labels = event_labels(event, &self.selection.labels);
                let labels = serde_json::to_string(&labels)
                    .map_err(|err| fictionet::Error::msg(err.to_string()))?;
                line.push_str(&format!(",\"labels\":{labels}"));
            }
            line.push_str("}\n");
            Ok(line)
        });
        let losses = self
            .losses
            .streams
            .iter()
            .filter(|loss| {
                self.selection.streams.contains(&loss.stream)
                    && loss.class.is_none_or(|class| self.selection.class(class))
            })
            .map(|loss| {
                let mut fields = vec![
                    ("type".into(), "loss".into()),
                    ("scope".into(), "run".into()),
                    (
                        "stream".into(),
                        crate::loss::stream_name(loss.stream).into(),
                    ),
                    (
                        "class".into(),
                        loss.class
                            .map_or(Value::Null, |class| (class as u64).into()),
                    ),
                    (
                        "reason".into(),
                        format!("{:?}", loss.reason).to_lowercase().into(),
                    ),
                    ("count".into(), loss.count.into()),
                    ("bytes".into(), loss.bytes.map_or(Value::Null, Value::from)),
                ];
                if let Some((source, kind)) = loss.event {
                    fields.push(("source".into(), source.into()));
                    fields.push(("kind".into(), kind.into()));
                }
                json_line(Value::Object(fields))
            });
        let untracked = self
            .losses
            .untracked
            .iter()
            .filter(|loss| {
                !self.selection.streams.is_empty()
                    && loss.class.is_none_or(|class| self.selection.class(class))
            })
            .map(|loss| {
                json_line(Value::Object(vec![
                    ("type".into(), "loss".into()),
                    ("scope".into(), "run".into()),
                    ("stream".into(), Value::Null),
                    (
                        "class".into(),
                        loss.class
                            .map_or(Value::Null, |class| (class as u64).into()),
                    ),
                    (
                        "reason".into(),
                        format!("{:?}", loss.reason).to_lowercase().into(),
                    ),
                    ("count".into(), loss.count.into()),
                    ("bytes".into(), loss.bytes.into()),
                ]))
            });
        events.chain(losses).chain(untracked)
    }

    /// Next pcapng chunk and whether the file is complete. Each selected link
    /// starts a section; copies retain their original lengths and stream order.
    pub fn next_chunk(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        while out.len() < CHUNK {
            let Some(section) = self.sections.front_mut() else {
                break;
            };
            if let Some(header) = section.header.take() {
                out.extend(header);
            }
            if let Some(copy) = section.packets.pop_front() {
                let micros = self
                    .selection
                    .wall
                    .unwrap_or_default()
                    .saturating_add(copy.stamp.at.since_start())
                    .as_micros()
                    .min(u64::MAX as u128) as u64;
                let mut fields = vec![
                    ("source".into(), copy.tap.as_ref().into()),
                    ("kind".into(), self.classes[copy.class].into()),
                    ("class".into(), (copy.class as u64).into()),
                    ("seq".into(), copy.stamp.seq.into()),
                ];
                #[cfg(feature = "page")]
                fields.push((
                    "labels".into(),
                    Value::Array(
                        flow_labels(&copy, &self.selection.labels)
                            .into_iter()
                            .map(|label| label.text.as_str().into())
                            .collect(),
                    ),
                ));
                let comment = json_line(Value::Object(std::mem::take(&mut fields)))
                    .expect("packet names are JSON");
                crate::pcap::packet(
                    &mut out,
                    micros,
                    copy.original_len,
                    &copy.bytes,
                    Some(comment.trim_end()),
                );
            } else {
                self.sections.pop_front();
            }
        }
        (out, self.sections.is_empty())
    }
}

fn json_line(value: Value) -> fictionet::Result<String> {
    let mut bytes = value.to_bytes()?;
    bytes.push(b'\n');
    Ok(String::from_utf8(bytes).expect("JSON is UTF-8"))
}

#[cfg(feature = "page")]
pub(crate) fn event_labels<'a>(
    event: &Event,
    labels: &'a [crate::page::Label],
) -> Vec<&'a crate::page::Label> {
    labels
        .iter()
        .filter(|label| match &label.target {
            crate::page::LabelTarget::Event { seq } => event.seq == *seq,
            crate::page::LabelTarget::Connection { id, local, peer } => {
                event.conn.id == Some(*id)
                    && event
                        .conn
                        .local
                        .is_some_and(|address| address.to_string() == *local)
                    && event
                        .conn
                        .peer
                        .is_some_and(|address| address.to_string() == *peer)
            }
            crate::page::LabelTarget::Flow { .. } => false,
        })
        .collect()
}

#[cfg(feature = "page")]
fn flow_labels<'a>(
    copy: &PacketCopy,
    labels: &'a [crate::page::Label],
) -> Vec<&'a crate::page::Label> {
    use fictionet::stdlib::network::ip::Header;
    let Some(header) = Header::parse_truncated(&copy.bytes) else {
        return Vec::new();
    };
    let ports = header.dst_port(&copy.bytes).map(|dst| {
        let payload = header.payload(&copy.bytes);
        (u16::from_be_bytes([payload[0], payload[1]]), dst)
    });
    let (src, dst) = ports.map_or_else(
        || (header.src.to_string(), header.dst.to_string()),
        |(src, dst)| {
            (
                std::net::SocketAddr::new(header.src, src).to_string(),
                std::net::SocketAddr::new(header.dst, dst).to_string(),
            )
        },
    );
    labels
        .iter()
        .filter(|label| match &label.target {
            crate::page::LabelTarget::Flow { link, a, b } => {
                link == &match copy.stamp.stream {
                    Stream::Packets(id) => id.to_string(),
                    _ => unreachable!("packet stream"),
                } && ((a == &src && b == &dst) || (a == &dst && b == &src))
            }
            _ => false,
        })
        .collect()
}
