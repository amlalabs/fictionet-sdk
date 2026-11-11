//! Bounded evidence admission, independent file writing, health counters,
//! and the consumers of the record stream.
//!
//! The world hands typed [`Record`]s and captured [`Packet`]s to an
//! [`EventSink`]. Admission is bounded by count and by an estimate of each
//! record's written size, and a refused record is counted, never waited
//! for. One writer thread serializes each record into a [`Line`] of the
//! event log, writes packets and frames to pcapng, and then hands the line
//! to each [`RecordConsumer`] the executable passed in. Consumers get the
//! typed values, not JSON.
//!
//! A successful sink write means queued, not persisted. Files are synchronized
//! at most one second after the worker next gets CPU and disk access, and on
//! graceful shutdown. A stalled filesystem can exceed that interval; shutdown
//! returns at its deadline without waiting for a stuck filesystem operation.
//! Each run uses new files, preserving incomplete files from abrupt termination.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::observe::{Direction, Mptcp, Observation};
use crate::record::{Frame, Lifecycle, Observed, Packet, Record};
use fictionet_extras::ssh::honeypot::Fact as SshFact;

const QUEUE_RECORDS: usize = 4096;
const CONTROL_RECORDS: usize = 16;
const CONTROL_BYTES: usize = 64 * 1024;
const SYNC_INTERVAL: Duration = Duration::from_secs(1);
static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Limits and provenance for one evidence writer.
#[derive(Clone, Debug)]
pub struct WriterConfig {
    /// Directory containing protected, independently readable evidence files.
    pub state_dir: PathBuf,
    /// Stable deployment identity, supplied by the operator.
    pub sensor_id: String,
    /// Actual packet backend used in this run.
    pub backend: String,
    /// Simulated service profile.
    pub persona: String,
    /// Boundary at which the original packets are received.
    pub capture_boundary: String,
    /// Whether the world keeps exact application bytes in its records.
    pub restricted_evidence: bool,
    /// Maximum admitted data bytes, by estimate, including the record
    /// currently writing.
    pub queue_bytes: usize,
    /// Maximum size of any one record: estimated at admission, and exact
    /// for the line written.
    pub max_record_bytes: usize,
    /// Rotate before a record would take a nonempty file above this size.
    pub rotate_bytes: u64,
    /// Rotate a nonempty file when this age is reached, on the next record.
    pub rotate_after: Duration,
    /// Maximum files retained per stream across runs, including the active file.
    pub retain_files: usize,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            state_dir: "honeypot-state".into(),
            sensor_id: "honeypot".into(),
            backend: "raw-ethernet".into(),
            persona: "linux-caddy-openssh".into(),
            capture_boundary: "ethernet_and_derived_ip".into(),
            restricted_evidence: false,
            queue_bytes: 16 * 1024 * 1024,
            max_record_bytes: 1024 * 1024,
            rotate_bytes: 64 * 1024 * 1024,
            rotate_after: Duration::from_secs(3600),
            retain_files: 8,
        }
    }
}

/// Independent aggregate health; no attacker-controlled labels.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Counters>);

#[derive(Default)]
struct Counters {
    queued_bytes: AtomicUsize,
    queued_records: AtomicUsize,
    control_bytes: AtomicUsize,
    control_records: AtomicUsize,
    accepted_events: AtomicU64,
    accepted_captures: AtomicU64,
    dropped_events: AtomicU64,
    dropped_captures: AtomicU64,
    written_events: AtomicU64,
    written_captures: AtomicU64,
    write_failures: AtomicU64,
    sync_failures: AtomicU64,
    last_write_us: AtomicU64,
    last_sync_us: AtomicU64,
    port_zero: AtomicU64,
    ssh_authenticated: AtomicU64,
    state_limits: AtomicU64,
    mptcp_no_data: AtomicU64,
    ip_options_retransmit: AtomicU64,
    mp_join: AtomicU64,
    capture_bytes: AtomicU64,
    backend_ready: AtomicBool,
    stopped: AtomicBool,
    abort: AtomicBool,
}

/// A point-in-time snapshot, readable even when evidence storage fails.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct MetricsSnapshot {
    /// Admitted data and lifecycle bytes not yet handled by the worker, by estimate.
    pub queued_bytes: usize,
    /// Admitted records not yet handled by the worker.
    pub queued_records: usize,
    /// Records accepted into the queue.
    pub accepted_events: u64,
    /// IP packets and Ethernet frames accepted into the queue.
    pub accepted_captures: u64,
    /// Records refused at admission, too large to write, or lost to storage failure.
    pub dropped_events: u64,
    /// Packets and frames refused at admission or lost to storage failure.
    pub dropped_captures: u64,
    /// Lines successfully written. Not necessarily synchronized.
    pub written_events: u64,
    /// Packets and frames successfully written.
    pub written_captures: u64,
    /// Record write and retention failures.
    pub write_failures: u64,
    /// File synchronization failures.
    pub sync_failures: u64,
    /// Wall-clock microseconds of the last successful record write.
    pub last_write_us: u64,
    /// Wall-clock microseconds of the last successful file synchronization.
    pub last_sync_us: u64,
    /// Port-zero records processed by the worker.
    pub port_zero: u64,
    /// Successful SSH authentication records processed by the worker.
    pub ssh_authenticated: u64,
    /// Observation state limit records processed by the worker.
    pub state_limits: u64,
    /// MP_CAPABLE attempts ending without inbound data.
    pub mptcp_no_data: u64,
    /// Option-bearing SYN retransmission observations.
    pub ip_options_retransmit: u64,
    /// Observations containing an MP_JOIN option.
    pub mp_join: u64,
    /// Capture bytes successfully written, including format overhead.
    pub capture_bytes: u64,
    /// Local attachment readiness; never a claim of public reachability.
    pub backend_ready: bool,
}

impl Metrics {
    /// Reads bounded counters without consulting storage or the worker.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let c = &self.0;
        MetricsSnapshot {
            queued_bytes: c.queued_bytes.load(Ordering::Relaxed)
                + c.control_bytes.load(Ordering::Relaxed),
            queued_records: c.queued_records.load(Ordering::Relaxed)
                + c.control_records.load(Ordering::Relaxed),
            accepted_events: c.accepted_events.load(Ordering::Relaxed),
            accepted_captures: c.accepted_captures.load(Ordering::Relaxed),
            dropped_events: c.dropped_events.load(Ordering::Relaxed),
            dropped_captures: c.dropped_captures.load(Ordering::Relaxed),
            written_events: c.written_events.load(Ordering::Relaxed),
            written_captures: c.written_captures.load(Ordering::Relaxed),
            write_failures: c.write_failures.load(Ordering::Relaxed),
            sync_failures: c.sync_failures.load(Ordering::Relaxed),
            last_write_us: c.last_write_us.load(Ordering::Relaxed),
            last_sync_us: c.last_sync_us.load(Ordering::Relaxed),
            port_zero: c.port_zero.load(Ordering::Relaxed),
            ssh_authenticated: c.ssh_authenticated.load(Ordering::Relaxed),
            state_limits: c.state_limits.load(Ordering::Relaxed),
            mptcp_no_data: c.mptcp_no_data.load(Ordering::Relaxed),
            ip_options_retransmit: c.ip_options_retransmit.load(Ordering::Relaxed),
            mp_join: c.mp_join.load(Ordering::Relaxed),
            capture_bytes: c.capture_bytes.load(Ordering::Relaxed),
            backend_ready: c.backend_ready.load(Ordering::Relaxed),
        }
    }

    /// Counts what `record` is, by its type.
    fn count(&self, record: &Record) {
        let c = &self.0;
        let Record::Observation(Observed { observation, .. }) = record else {
            return;
        };
        let counter = match observation {
            Observation::MptcpNoData { .. } => &c.mptcp_no_data,
            Observation::IpOptionsRetransmit { .. } => &c.ip_options_retransmit,
            Observation::PortZero { .. } => &c.port_zero,
            Observation::StateLimit { .. } => &c.state_limits,
            Observation::Ssh { ssh, .. } if matches!(ssh.fact, SshFact::Authenticated { .. }) => {
                &c.ssh_authenticated
            }
            Observation::Syn { mptcp, .. }
            | Observation::Segment { mptcp, .. }
            | Observation::Answer { mptcp, .. }
                if mptcp.iter().any(|option| {
                    matches!(
                        option,
                        Mptcp::MpJoinSyn { .. }
                            | Mptcp::MpJoinSynAck { .. }
                            | Mptcp::MpJoinAck { .. }
                    )
                }) =>
            {
                &c.mp_join
            }
            Observation::Trap { .. }
            | Observation::Network { .. }
            | Observation::Ssh { .. }
            | Observation::Syn { .. }
            | Observation::Segment { .. }
            | Observation::Answer { .. }
            | Observation::Burst { .. }
            | Observation::Lost { .. } => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// One line of the event log: a record, with when and where it was written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// The line format's version.
    pub schema_version: u32,
    /// The deployment's identity.
    pub sensor_id: String,
    /// This run's identity, shared by all its files.
    pub run_id: String,
    /// The line's number in this run, from 1.
    pub sequence: u64,
    /// When the record was admitted, by the host system clock.
    pub recorded_at_us: u64,
    /// When the record was admitted, from the writer's start.
    pub elapsed_us: u64,
    /// Where those two times come from.
    pub clock_source: ClockSource,
    /// The packet backend.
    pub backend: String,
    /// The simulated service profile.
    pub persona: String,
    /// Where the original packets are received.
    pub capture_boundary: String,
    /// Whether exact application bytes are kept.
    pub restricted_evidence: bool,
    /// The writer's losses when the line was written.
    pub evidence_health: Health,
    /// The IP capture's identity.
    pub ip_capture_id: String,
    /// The record.
    pub event: Event,
}

/// Where a [`Line`]'s two times come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    /// The host system clock and a monotonic clock, both read at admission.
    HostSystemTimeAndMonotonicAdmission,
}

/// The writer's losses so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// Records lost.
    pub dropped_events: u64,
    /// Packets and frames lost.
    pub dropped_captures: u64,
    /// Write failures.
    pub write_failures: u64,
    /// Synchronization failures.
    pub sync_failures: u64,
}

/// A record as written, with the capture it refers to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The record.
    #[serde(flatten)]
    pub record: Record,
    /// Where the packet or frame the record refers to is, or that it is
    /// not there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<Capture>,
    /// The Ethernet capture's identity, for a frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
}

/// The captured packet or frame a record refers to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "CaptureFields", try_from = "CaptureFields")]
pub enum Capture {
    /// Written here.
    Stored(Location),
    /// Not written, or not the packet the writer last wrote.
    Missing,
}

/// Where a pcapng block was written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The file's name in the state directory.
    pub file: String,
    /// The pcapng section.
    pub section: u32,
    /// The pcapng interface.
    pub interface: u32,
    /// The block's byte offset in the file.
    pub offset: u64,
    /// Which way the packet crossed.
    pub direction: Direction,
}

/// [`Capture`] as logged: `available`, then the location or the reason.
#[derive(Serialize, Deserialize)]
struct CaptureFields {
    available: bool,
    #[serde(flatten)]
    location: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<Gap>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Gap {
    CaptureNotPersistedOrNotCorrelated,
}

impl From<Capture> for CaptureFields {
    fn from(capture: Capture) -> CaptureFields {
        match capture {
            Capture::Stored(location) => CaptureFields {
                available: true,
                location: Some(location),
                reason: None,
            },
            Capture::Missing => CaptureFields {
                available: false,
                location: None,
                reason: Some(Gap::CaptureNotPersistedOrNotCorrelated),
            },
        }
    }
}

impl TryFrom<CaptureFields> for Capture {
    type Error = &'static str;

    fn try_from(fields: CaptureFields) -> Result<Capture, Self::Error> {
        match (fields.available, fields.location) {
            (true, Some(location)) => Ok(Capture::Stored(location)),
            (false, None) => Ok(Capture::Missing),
            _ => Err("an available capture has a location and a missing one has none"),
        }
    }
}

/// A reader of the record stream, such as live attribution or a dashboard.
///
/// Consumers run on the writer thread, in order, after each line. A slow
/// consumer slows the writer, and admission then drops rather than waits.
pub trait RecordConsumer: Send + 'static {
    /// A record as the writer wrote it. It comes whether or not the line
    /// reached the disk.
    fn record(&mut self, line: &Line);

    /// The writer's timer, about once a second, with the host system clock
    /// in microseconds.
    fn tick(&mut self, _now_us: u64) {}
}

#[derive(Clone, Copy)]
enum Kind {
    Event,
    Ip,
    Ethernet,
    Control,
}

impl Kind {
    fn capture(self) -> bool {
        matches!(self, Self::Ip | Self::Ethernet)
    }
    fn control(self) -> bool {
        matches!(self, Self::Control)
    }
}

#[allow(clippy::large_enum_variant)] // queue slots are allocated once; boxing allocates per item
enum Item {
    Record(Record),
    Packet(Packet),
}

impl Item {
    fn kind(&self) -> Kind {
        match self {
            Item::Record(Record::Observation(_)) => Kind::Event,
            Item::Record(Record::Frame(_)) => Kind::Ethernet,
            Item::Record(Record::Lifecycle(_)) => Kind::Control,
            Item::Packet(_) => Kind::Ip,
        }
    }

    /// About how many bytes it takes once written.
    fn size(&self) -> usize {
        match self {
            Item::Record(Record::Frame(frame)) => estimate(frame) + frame.bytes.len(),
            Item::Record(record) => estimate(record),
            Item::Packet(packet) => packet.block.len(),
        }
    }
}

struct Queued {
    item: Item,
    kind: Kind,
    size: usize,
    elapsed_us: u64,
    wall_us: u64,
}

#[derive(Clone)]
struct Admission {
    sender: SyncSender<Queued>,
    metrics: Metrics,
    queue_bytes: usize,
    max_record_bytes: usize,
    started: Instant,
}

fn reserve(counter: &AtomicUsize, size: usize, limit: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
            value.checked_add(size).filter(|next| *next <= limit)
        })
        .is_ok()
}

impl Admission {
    fn put(&self, item: Item) -> io::Result<()> {
        let (kind, size) = (item.kind(), item.size());
        let c = &self.metrics.0;
        let (byte_count, record_count, byte_limit, record_limit) = if kind.control() {
            (
                &c.control_bytes,
                &c.control_records,
                CONTROL_BYTES,
                CONTROL_RECORDS,
            )
        } else {
            (
                &c.queued_bytes,
                &c.queued_records,
                self.queue_bytes,
                QUEUE_RECORDS,
            )
        };
        let rejected = || {
            self.lost(kind);
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "evidence queue closed, full, or record too large",
            )
        };
        if c.stopped.load(Ordering::Acquire)
            || size > self.max_record_bytes
            || !reserve(record_count, 1, record_limit)
        {
            return Err(rejected());
        }
        if !reserve(byte_count, size, byte_limit) {
            record_count.fetch_sub(1, Ordering::AcqRel);
            return Err(rejected());
        }
        let queued = Queued {
            item,
            kind,
            size,
            elapsed_us: self.started.elapsed().as_micros() as u64,
            wall_us: wall_us(),
        };
        if let Err(TrySendError::Full(queued) | TrySendError::Disconnected(queued)) =
            self.sender.try_send(queued)
        {
            self.release(&queued);
            return Err(rejected());
        }
        if kind.capture() {
            &c.accepted_captures
        } else {
            &c.accepted_events
        }
        .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn release(&self, queued: &Queued) {
        let c = &self.metrics.0;
        let (bytes, records) = if queued.kind.control() {
            (&c.control_bytes, &c.control_records)
        } else {
            (&c.queued_bytes, &c.queued_records)
        };
        bytes.fetch_sub(queued.size, Ordering::AcqRel);
        records.fetch_sub(1, Ordering::AcqRel);
    }

    fn lost(&self, kind: Kind) {
        let c = &self.metrics.0;
        if kind.capture() {
            &c.dropped_captures
        } else {
            &c.dropped_events
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

/// Where the world hands its records and captured packets. Each call
/// returns at once: true if the writer's queue took the value, false if it
/// was refused and counted as dropped.
#[derive(Clone)]
pub struct EventSink(Admission);

impl EventSink {
    /// Queues an observation.
    pub fn observation(&self, observed: Observed) -> bool {
        self.0
            .put(Item::Record(Record::Observation(observed)))
            .is_ok()
    }

    /// Queues an Ethernet frame for the Ethernet capture and the log.
    pub fn frame(&self, frame: Frame) -> bool {
        self.0.put(Item::Record(Record::Frame(frame))).is_ok()
    }

    /// Queues an IP packet for the IP capture.
    pub fn packet(&self, packet: Packet) -> bool {
        self.0.put(Item::Packet(packet)).is_ok()
    }

    /// A sink with no writer behind it, which refuses everything.
    #[cfg(test)]
    pub(crate) fn detached() -> EventSink {
        let (sender, _) = mpsc::sync_channel(1);
        EventSink(Admission {
            sender,
            metrics: Metrics::default(),
            queue_bytes: 1 << 20,
            max_record_bytes: 1 << 20,
            started: Instant::now(),
        })
    }
}

/// Owns evidence worker lifetime. Drop closes admission; explicit shutdown drains.
pub struct Writer {
    admission: Admission,
    finished: Receiver<()>,
    run_id: String,
}

impl Writer {
    /// Creates fresh files and a bounded writer thread before starting
    /// traffic. The thread hands every line to `consumers`, in order.
    pub fn open(
        config: WriterConfig,
        consumers: Vec<Box<dyn RecordConsumer>>,
    ) -> io::Result<(Self, EventSink)> {
        if config.queue_bytes == 0
            || config.max_record_bytes == 0
            || config.rotate_bytes < config.max_record_bytes as u64
            || config.retain_files == 0
            || config.rotate_after.is_zero()
            || config.sensor_id.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evidence limits and sensor identity must be nonzero; rotation must fit a record",
            ));
        }
        fs::create_dir_all(&config.state_dir)?;
        let run_id = format!(
            "{:032}-{:010}-{:06}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            std::process::id(),
            RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let worker = Worker::open(config.clone(), run_id.clone(), consumers)?;
        let (sender, receiver) = mpsc::sync_channel(QUEUE_RECORDS + CONTROL_RECORDS);
        let admission = Admission {
            sender,
            metrics: Metrics::default(),
            queue_bytes: config.queue_bytes,
            max_record_bytes: config.max_record_bytes,
            started: Instant::now(),
        };
        let (done, finished) = mpsc::sync_channel(1);
        let worker_admission = admission.clone();
        thread::Builder::new()
            .name("honeypot-evidence".into())
            .spawn(move || {
                worker.run(receiver, &worker_admission);
                let _ = done.send(());
            })?;
        let sink = EventSink(admission.clone());
        Ok((
            Self {
                admission,
                finished,
                run_id,
            },
            sink,
        ))
    }

    /// Unique identity shared by all files and lines in this process run.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Admits a lifecycle record through capacity reserved from packet traffic.
    pub fn lifecycle(&self, lifecycle: Lifecycle) -> io::Result<()> {
        self.admission
            .put(Item::Record(Record::Lifecycle(lifecycle)))
    }

    /// Shared health counters without a dependency on filesystem health.
    pub fn metrics_handle(&self) -> Metrics {
        self.admission.metrics.clone()
    }

    /// Reports local attachment readiness independently of public reachability.
    pub fn set_ready(&self, ready: bool) {
        self.admission
            .metrics
            .0
            .backend_ready
            .store(ready, Ordering::Relaxed);
    }

    /// Reads current aggregate health.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.admission.metrics.snapshot()
    }

    /// Stops new admission, drains accepted records, and synchronizes files.
    /// A timeout abandons remaining records; an in-flight disk call cannot be cancelled.
    pub fn shutdown(self, deadline: Duration) -> io::Result<MetricsSnapshot> {
        self.set_ready(false);
        self.admission
            .metrics
            .0
            .stopped
            .store(true, Ordering::Release);
        if self.finished.recv_timeout(deadline).is_err() {
            self.admission
                .metrics
                .0
                .abort
                .store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "evidence shutdown deadline exceeded",
            ));
        }
        Ok(self.metrics())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.admission
            .metrics
            .0
            .stopped
            .store(true, Ordering::Release);
    }
}

fn wall_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

struct Files {
    directory: PathBuf,
    run_id: String,
    stream: &'static str,
    extension: &'static str,
    index: u64,
    file: File,
    name: String,
    size: u64,
    records: u64,
    opened: Instant,
    header: Vec<u8>,
    rotate_bytes: u64,
    rotate_after: Duration,
    retain_files: usize,
    damaged: bool,
    retention_pending: bool,
}

impl Files {
    fn open(
        config: &WriterConfig,
        run_id: &str,
        stream: &'static str,
        extension: &'static str,
        header: Vec<u8>,
    ) -> io::Result<Self> {
        let name = format!("{stream}-{run_id}-{:06}.{extension}", 0);
        let mut file = create(&config.state_dir.join(&name))?;
        file.write_all(&header)?;
        let files = Self {
            directory: config.state_dir.clone(),
            run_id: run_id.into(),
            stream,
            extension,
            index: 0,
            file,
            name,
            size: header.len() as u64,
            records: 0,
            opened: Instant::now(),
            header,
            rotate_bytes: config.rotate_bytes,
            rotate_after: config.rotate_after,
            retain_files: config.retain_files,
            damaged: false,
            retention_pending: false,
        };
        files.retain()?;
        Ok(files)
    }

    fn retain(&self) -> io::Result<()> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(identity) = name
                .strip_prefix(&format!("{}-", self.stream))
                .and_then(|name| name.strip_suffix(&format!(".{}", self.extension)))
            else {
                continue;
            };
            let parts = identity.split('-').collect::<Vec<_>>();
            if name != self.name
                && parts.len() == 4
                && parts[0].len() == 32
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                && entry.file_type()?.is_file()
            {
                names.push(name);
            }
        }
        names.sort();
        let remove = names
            .len()
            .saturating_sub(self.retain_files.saturating_sub(1));
        for name in names.into_iter().take(remove) {
            fs::remove_file(self.directory.join(name))?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.sync_data()?;
        self.index += 1;
        let name = format!(
            "{}-{}-{:06}.{}",
            self.stream, self.run_id, self.index, self.extension
        );
        let mut file = create(&self.directory.join(&name))?;
        file.write_all(&self.header)?;
        self.file = file;
        self.name = name;
        self.size = self.header.len() as u64;
        self.records = 0;
        self.opened = Instant::now();
        self.damaged = false;
        self.retention_pending = true;
        self.retain()?;
        self.retention_pending = false;
        Ok(())
    }

    /// Writes `bytes` whole, rotating first when due. Returns their offset
    /// in the current file.
    fn put(&mut self, bytes: &[u8]) -> io::Result<u64> {
        if self.retention_pending {
            self.retain()?;
            self.retention_pending = false;
        }
        if self.damaged
            || (self.records > 0
                && (self.size.saturating_add(bytes.len() as u64) > self.rotate_bytes
                    || self.opened.elapsed() >= self.rotate_after))
        {
            self.rotate()?;
        }
        let offset = self.size;
        if let Err(error) = self.file.write_all(bytes) {
            if self
                .file
                .set_len(offset)
                .and_then(|()| self.file.seek(SeekFrom::Start(offset)))
                .is_err()
            {
                self.damaged = true;
            }
            return Err(error);
        }
        self.size += bytes.len() as u64;
        self.records += 1;
        Ok(offset)
    }

    /// A packet block at `offset` in the current capture file.
    fn location(&self, offset: u64, direction: Direction) -> Location {
        Location {
            file: self.name.clone(),
            section: 0,
            interface: 0,
            offset,
            direction,
        }
    }
}

fn create(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

struct Worker {
    config: WriterConfig,
    run_id: String,
    events: Files,
    ip: Files,
    ethernet: Option<Files>,
    sequence: u64,
    last_capture: Option<(u64, Location)>,
    consumers: Vec<Box<dyn RecordConsumer>>,
}

impl Worker {
    fn open(
        config: WriterConfig,
        run_id: String,
        consumers: Vec<Box<dyn RecordConsumer>>,
    ) -> io::Result<Self> {
        let events = Files::open(&config, &run_id, "events", "jsonl", Vec::new())?;
        let mut header = Vec::new();
        fictionet::stdlib::pcap::start(&mut header, &[]);
        let ip = Files::open(&config, &run_id, "ip", "pcapng", header)?;
        Ok(Self {
            config,
            run_id,
            events,
            ip,
            ethernet: None,
            sequence: 0,
            last_capture: None,
            consumers,
        })
    }

    fn process(&mut self, queued: Queued, metrics: &Metrics) -> io::Result<()> {
        let record = match queued.item {
            Item::Packet(packet) => {
                self.last_capture = None;
                let offset = self.ip.put(&packet.block)?;
                let location = self.ip.location(offset, packet.direction);
                metrics
                    .0
                    .capture_bytes
                    .fetch_add(packet.block.len() as u64, Ordering::Relaxed);
                metrics.0.written_captures.fetch_add(1, Ordering::Relaxed);
                self.last_capture = Some((packet.ordinal, location));
                return Ok(());
            }
            Item::Record(record) => record,
        };
        let (capture, capture_id) = match &record {
            Record::Frame(frame) => (
                Some(Capture::Stored(self.frame(frame, metrics)?)),
                Some(format!("{}:ethernet", self.run_id)),
            ),
            _ => (
                record
                    .capture_packet()
                    .map(|ordinal| match &self.last_capture {
                        Some((last, location)) if *last == ordinal => {
                            Capture::Stored(location.clone())
                        }
                        _ => Capture::Missing,
                    }),
                None,
            ),
        };
        metrics.count(&record);
        self.sequence += 1;
        let snapshot = metrics.snapshot();
        let line = Line {
            schema_version: 1,
            sensor_id: self.config.sensor_id.clone(),
            run_id: self.run_id.clone(),
            sequence: self.sequence,
            recorded_at_us: queued.wall_us,
            elapsed_us: queued.elapsed_us,
            clock_source: ClockSource::HostSystemTimeAndMonotonicAdmission,
            backend: self.config.backend.clone(),
            persona: self.config.persona.clone(),
            capture_boundary: self.config.capture_boundary.clone(),
            restricted_evidence: self.config.restricted_evidence,
            evidence_health: Health {
                dropped_events: snapshot.dropped_events,
                dropped_captures: snapshot.dropped_captures,
                write_failures: snapshot.write_failures,
                sync_failures: snapshot.sync_failures,
            },
            ip_capture_id: format!("{}:ip", self.run_id),
            event: Event {
                record,
                capture,
                capture_id,
            },
        };
        let written = self.write(&line, metrics);
        for consumer in &mut self.consumers {
            consumer.record(&line);
        }
        match (written, &line.event.record) {
            // The frame itself is in the capture; only its line was lost.
            (Err(_), Record::Frame(_)) => {
                metrics.0.dropped_events.fetch_add(1, Ordering::Relaxed);
                metrics.0.write_failures.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            (written, _) => written,
        }
    }

    /// Writes `line` to the event log. A line over the record limit is
    /// counted as dropped and not written.
    fn write(&mut self, line: &Line, metrics: &Metrics) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(line)?;
        bytes.push(b'\n');
        if bytes.len() > self.config.max_record_bytes {
            metrics.0.dropped_events.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.events.put(&bytes)?;
        metrics.0.written_events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Writes `frame` to the Ethernet capture, opened on the first frame.
    fn frame(&mut self, frame: &Frame, metrics: &Metrics) -> io::Result<Location> {
        let ethernet = match &mut self.ethernet {
            Some(files) => files,
            None => {
                let mut header = Vec::new();
                fictionet::stdlib::pcap::start_ethernet(&mut header);
                self.ethernet.insert(Files::open(
                    &self.config,
                    &self.run_id,
                    "ethernet",
                    "pcapng",
                    header,
                )?)
            }
        };
        let mut block = Vec::new();
        fictionet::stdlib::pcap::packet(
            &mut block,
            frame.received_at_us.unwrap_or(frame.at_us),
            frame.bytes.len(),
            &frame.bytes,
            Some(&frame.direction.to_string()),
        );
        let offset = ethernet.put(&block)?;
        let location = ethernet.location(offset, frame.direction);
        metrics.0.written_captures.fetch_add(1, Ordering::Relaxed);
        metrics
            .0
            .capture_bytes
            .fetch_add(block.len() as u64, Ordering::Relaxed);
        Ok(location)
    }

    fn sync(&mut self, metrics: &Metrics) {
        let mut failed = false;
        for file in [&self.events.file, &self.ip.file]
            .into_iter()
            .chain(self.ethernet.as_ref().map(|files| &files.file))
        {
            if file.sync_data().is_err() {
                metrics.0.sync_failures.fetch_add(1, Ordering::Relaxed);
                failed = true;
            }
        }
        #[cfg(unix)]
        if File::open(&self.config.state_dir)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            metrics.0.sync_failures.fetch_add(1, Ordering::Relaxed);
            failed = true;
        }
        if !failed {
            metrics.0.last_sync_us.store(wall_us(), Ordering::Relaxed);
        }
    }

    fn run(mut self, receiver: Receiver<Queued>, admission: &Admission) {
        let metrics = &admission.metrics;
        let mut last_sync = Instant::now();
        loop {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(queued) => {
                    admission.release(&queued);
                    let kind = queued.kind;
                    if metrics.0.abort.load(Ordering::Acquire) {
                        admission.lost(kind);
                    } else if self.process(queued, metrics).is_err() {
                        metrics.0.write_failures.fetch_add(1, Ordering::Relaxed);
                        admission.lost(kind);
                    } else {
                        metrics.0.last_write_us.store(wall_us(), Ordering::Relaxed);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout)
                    if metrics.0.stopped.load(Ordering::Acquire)
                        && metrics.snapshot().queued_records == 0 =>
                {
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if last_sync.elapsed() >= SYNC_INTERVAL {
                self.sync(metrics);
                let now = wall_us();
                for consumer in &mut self.consumers {
                    consumer.tick(now);
                }
                last_sync = Instant::now();
            }
        }
        self.sync(metrics);
    }
}

/// About how many bytes `value` takes as JSON: string and byte lengths,
/// and a fixed width per number, field name and element. Nothing is
/// formatted into memory, so the world thread pays no serialization.
fn estimate(value: &impl Serialize) -> usize {
    let mut size = Size(0);
    // A value that cannot serialize, such as a path that is not UTF-8, is
    // estimated as far as it got; the writer then fails to write it.
    let _ = value.serialize(&mut size);
    size.0
}

/// The running total of [`estimate`].
struct Size(usize);

/// A value refused to serialize.
#[derive(Debug)]
struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the value cannot be serialized")
    }
}

impl std::error::Error for Refused {}

impl serde::ser::Error for Refused {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Refused
    }
}

/// Counts the bytes a value formats to, without keeping them.
struct Count(usize);

impl fmt::Write for Count {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 += text.len();
        Ok(())
    }
}

impl serde::Serializer for &mut Size {
    type Ok = ();
    type Error = Refused;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _: bool) -> Result<(), Refused> {
        self.0 += 5;
        Ok(())
    }
    fn serialize_i8(self, _: i8) -> Result<(), Refused> {
        self.0 += 4;
        Ok(())
    }
    fn serialize_i16(self, _: i16) -> Result<(), Refused> {
        self.0 += 6;
        Ok(())
    }
    fn serialize_i32(self, _: i32) -> Result<(), Refused> {
        self.0 += 11;
        Ok(())
    }
    fn serialize_i64(self, _: i64) -> Result<(), Refused> {
        self.0 += 20;
        Ok(())
    }
    fn serialize_u8(self, _: u8) -> Result<(), Refused> {
        self.0 += 3;
        Ok(())
    }
    fn serialize_u16(self, _: u16) -> Result<(), Refused> {
        self.0 += 5;
        Ok(())
    }
    fn serialize_u32(self, _: u32) -> Result<(), Refused> {
        self.0 += 10;
        Ok(())
    }
    fn serialize_u64(self, _: u64) -> Result<(), Refused> {
        self.0 += 20;
        Ok(())
    }
    fn serialize_f32(self, _: f32) -> Result<(), Refused> {
        self.0 += 16;
        Ok(())
    }
    fn serialize_f64(self, _: f64) -> Result<(), Refused> {
        self.0 += 24;
        Ok(())
    }
    fn serialize_char(self, _: char) -> Result<(), Refused> {
        self.0 += 6;
        Ok(())
    }
    fn serialize_str(self, text: &str) -> Result<(), Refused> {
        self.0 += text.len() + 2;
        Ok(())
    }
    fn serialize_bytes(self, bytes: &[u8]) -> Result<(), Refused> {
        self.0 += bytes.len() * 4 + 2;
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Refused> {
        self.0 += 4;
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Refused> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Refused> {
        self.0 += 4;
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Refused> {
        self.0 += 4;
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        name: &'static str,
    ) -> Result<(), Refused> {
        self.0 += name.len() + 2;
        Ok(())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Refused> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        name: &'static str,
        value: &T,
    ) -> Result<(), Refused> {
        self.0 += name.len() + 5;
        value.serialize(self)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self, Refused> {
        self.0 += 2;
        Ok(self)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self, Refused> {
        self.0 += 2;
        Ok(self)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Refused> {
        self.0 += 2;
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        name: &'static str,
        _: usize,
    ) -> Result<Self, Refused> {
        self.0 += name.len() + 7;
        Ok(self)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self, Refused> {
        self.0 += 2;
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, Refused> {
        self.0 += 2;
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        name: &'static str,
        _: usize,
    ) -> Result<Self, Refused> {
        self.0 += name.len() + 7;
        Ok(self)
    }
    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Refused> {
        let mut count = Count(0);
        // Counting cannot fail, and a Display that fails is counted as far as it got.
        let _ = fmt::write(&mut count, format_args!("{value}"));
        self.0 += count.0 + 2;
        Ok(())
    }
}

impl serde::ser::SerializeSeq for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Refused> {
        self.0 += 1;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeTuple for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Refused> {
        self.0 += 1;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleStruct for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Refused> {
        self.0 += 1;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleVariant for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Refused> {
        self.0 += 1;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeMap for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Refused> {
        self.0 += 2;
        key.serialize(&mut **self)
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Refused> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeStruct for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Refused> {
        self.0 += key.len() + 4;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for &mut Size {
    type Ok = ();
    type Error = Refused;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Refused> {
        self.0 += key.len() + 4;
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<(), Refused> {
        Ok(())
    }
}

#[cfg(test)]
// Storage failure tests set resource limits in dedicated child processes.
#[allow(unsafe_code)]
mod tests {
    use std::sync::Mutex;

    use serde_json::Value;

    use super::*;
    use crate::record::{Reachability, Stopped, TimestampSource};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "honeypot-evidence-{}-{}",
                std::process::id(),
                RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn config(&self) -> WriterConfig {
            WriterConfig {
                state_dir: self.0.clone(),
                ..WriterConfig::default()
            }
        }
        fn files(&self, prefix: &str) -> Vec<PathBuf> {
            let mut paths = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with(prefix)
                })
                .collect::<Vec<_>>();
            paths.sort();
            paths
        }
        fn lines(&self) -> Vec<String> {
            self.files("events-")
                .iter()
                .flat_map(|path| {
                    fs::read_to_string(path)
                        .unwrap()
                        .lines()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect()
        }
        fn events(&self) -> Vec<Value> {
            self.lines()
                .iter()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /// Keeps every line and counts the ticks it is given.
    #[derive(Clone, Default)]
    struct Kept(Arc<Mutex<(Vec<Line>, usize)>>);

    impl RecordConsumer for Kept {
        fn record(&mut self, line: &Line) {
            self.0.lock().unwrap().0.push(line.clone());
        }
        fn tick(&mut self, _: u64) {
            self.0.lock().unwrap().1 += 1;
        }
    }

    fn admission(queue_bytes: usize, max_record_bytes: usize) -> (Admission, Receiver<Queued>) {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_RECORDS + CONTROL_RECORDS);
        (
            Admission {
                sender,
                metrics: Metrics::default(),
                queue_bytes,
                max_record_bytes,
                started: Instant::now(),
            },
            receiver,
        )
    }

    fn block(ordinal: u64) -> Vec<u8> {
        let mut block = Vec::new();
        fictionet::stdlib::pcap::packet(
            &mut block,
            123,
            20,
            &[0x45; 20],
            Some(&format!("internet in packet={ordinal}")),
        );
        block
    }

    fn packet(ordinal: u64) -> Packet {
        Packet {
            ordinal,
            direction: Direction::In,
            block: block(ordinal),
        }
    }

    fn port_zero(capture_packet: u64, capture_queued: bool) -> Observed {
        Observed {
            observation: Observation::PortZero {
                at_us: 1,
                attachment: Arc::from("internet"),
                protocol: 6,
                src: "192.0.2.1:0".parse().unwrap(),
                dst: "192.0.2.2:22".parse().unwrap(),
                capture_packet,
                capture_queued,
                fragmented: false,
                checksum_valid: Some(true),
            },
            packet: None,
        }
    }

    fn burst(at_us: u64) -> Observed {
        Observed {
            observation: Observation::Burst {
                at_us,
                src: "192.0.2.1".parse().unwrap(),
                kind: crate::observe::BurstKind::Syns,
                syns: 8,
                window_us: 100_000,
            },
            packet: None,
        }
    }

    fn shutdown() -> Lifecycle {
        Lifecycle::Shutdown {
            status: Stopped::Stopped,
            error: None,
        }
    }

    fn block_kinds(bytes: &[u8]) -> Vec<u32> {
        let mut offset = 0;
        let mut kinds = Vec::new();
        while offset < bytes.len() {
            let kind = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let size =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
            assert!(size >= 12 && size.is_multiple_of(4));
            assert_eq!(
                size,
                u32::from_le_bytes(bytes[offset + size - 4..offset + size].try_into().unwrap())
                    as usize
            );
            kinds.push(kind);
            offset += size;
        }
        assert_eq!(offset, bytes.len());
        kinds
    }

    #[test]
    fn a_stalled_worker_cannot_exceed_byte_or_record_limits() {
        let full = block(1).len();
        let (admission, receiver) = admission(full, full);
        admission.put(Item::Packet(packet(1))).unwrap();
        assert_eq!(
            admission
                .put(Item::Record(Record::Observation(burst(1))))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut oversized = packet(2);
        oversized.block.push(0);
        assert!(admission.put(Item::Packet(oversized)).is_err());
        admission
            .put(Item::Record(Record::Lifecycle(shutdown())))
            .unwrap();
        let snapshot = admission.metrics.snapshot();
        assert_eq!(
            snapshot.queued_bytes,
            full + estimate(&Record::Lifecycle(shutdown()))
        );
        assert_eq!(snapshot.dropped_events, 1);
        assert_eq!(snapshot.dropped_captures, 1);
        for _ in 0..2 {
            let queued = receiver.try_recv().unwrap();
            admission.release(&queued);
        }
        assert_eq!(admission.metrics.snapshot().queued_bytes, 0);
        let (admission, _receiver) = self::admission(2 * QUEUE_RECORDS * full, full);
        for _ in 0..QUEUE_RECORDS {
            admission.put(Item::Packet(packet(1))).unwrap();
        }
        assert!(admission.put(Item::Packet(packet(1))).is_err());
        admission
            .put(Item::Record(Record::Lifecycle(shutdown())))
            .unwrap();
        assert_eq!(
            admission.metrics.snapshot().queued_records,
            QUEUE_RECORDS + 1
        );
    }

    #[test]
    fn the_estimate_follows_the_written_size() {
        for record in [
            Record::Observation(port_zero(1, true)),
            Record::Observation(burst(7)),
            Record::Lifecycle(shutdown()),
        ] {
            let written = serde_json::to_vec(&record).unwrap().len();
            let estimated = estimate(&record);
            assert!(
                estimated >= written && estimated <= 4 * written,
                "{record:?}: estimated {estimated}, written {written}"
            );
        }
    }

    #[test]
    fn shutdown_drains_with_live_sinks_links_original_capture_and_feeds_consumers() {
        let dir = Directory::new();
        let kept = Kept::default();
        let (writer, events) = Writer::open(dir.config(), vec![Box::new(kept.clone())]).unwrap();
        let run = writer.run_id().to_owned();
        assert!(events.packet(packet(1)));
        assert!(events.observation(port_zero(1, true)));
        writer.lifecycle(shutdown()).unwrap();
        let metrics = writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(metrics.queued_records, 0);
        assert_eq!(metrics.written_events, 2);
        assert_eq!(metrics.written_captures, 1);
        assert_eq!(metrics.port_zero, 1);
        assert!(metrics.last_sync_us > 0);
        assert!(!events.observation(burst(2)));
        let events = dir.events();
        assert_eq!(events[0]["run_id"], run);
        assert_eq!(events[0]["schema_version"], 1);
        assert_eq!(events[0]["sequence"], 1);
        assert_eq!(events[0]["event"]["event"], "port_zero");
        assert_eq!(events[0]["event"]["capture_packet"], 1);
        assert_eq!(events[0]["event"]["capture"]["offset"], 48);
        assert_eq!(events[0]["event"]["capture"]["available"], true);
        assert_eq!(events[0]["event"]["capture"]["direction"], "in");
        assert_eq!(events[1]["event"]["event"], "shutdown");
        assert_eq!(events[1]["event"]["status"], "stopped");
        let capture = fs::read(dir.files("ip-")[0].clone()).unwrap();
        assert_eq!(block_kinds(&capture), [0x0a0d0d0a, 1, 6]);
        assert_eq!(&capture[48..], block(1));
        // The consumers saw the lines the log holds, as typed values.
        let written: Vec<Line> = dir
            .lines()
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(kept.0.lock().unwrap().0, written);
        assert_eq!(
            written[0].event.record,
            Record::Observation(port_zero(1, true))
        );
    }

    #[test]
    fn consumers_tick_about_once_a_second() {
        let dir = Directory::new();
        let kept = Kept::default();
        let (writer, _events) = Writer::open(dir.config(), vec![Box::new(kept.clone())]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while kept.0.lock().unwrap().1 == 0 {
            assert!(Instant::now() < deadline, "no tick in ten seconds");
            thread::sleep(Duration::from_millis(20));
        }
        writer.shutdown(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn dropped_or_unrelated_capture_is_never_claimed_available() {
        let dir = Directory::new();
        let (writer, events) = Writer::open(dir.config(), Vec::new()).unwrap();
        assert!(events.packet(packet(2)));
        assert!(events.observation(port_zero(1, false)));
        writer.shutdown(Duration::from_secs(5)).unwrap();
        let line: Line = serde_json::from_str(&dir.lines()[0]).unwrap();
        assert_eq!(line.event.capture, Some(Capture::Missing));
        assert_eq!(dir.events()[0]["event"]["capture"]["available"], false);
    }

    #[test]
    fn a_line_over_the_record_limit_is_dropped_not_written() {
        let dir = Directory::new();
        let config = WriterConfig {
            max_record_bytes: 512,
            rotate_bytes: 512,
            ..dir.config()
        };
        let (writer, events) = Writer::open(config, Vec::new()).unwrap();
        // The record fits the estimate; its line, with the envelope, does not.
        assert!(events.observation(burst(1)));
        let metrics = writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(metrics.written_events, 0);
        assert_eq!(metrics.dropped_events, 1);
        assert_eq!(metrics.write_failures, 0);
        assert!(dir.lines().is_empty());
    }

    #[test]
    fn rotation_keeps_complete_records_and_readable_capture_headers() {
        let dir = Directory::new();
        let config = WriterConfig {
            max_record_bytes: 1024,
            rotate_bytes: 1024,
            retain_files: 2,
            ..dir.config()
        };
        let (writer, events) = Writer::open(config.clone(), Vec::new()).unwrap();
        for ordinal in 1..50 {
            assert!(events.packet(packet(ordinal)));
            assert!(events.observation(burst(ordinal)));
        }
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(dir.files("events-").len(), 2);
        assert_eq!(dir.files("ip-").len(), 2);
        for path in dir.files("ip-") {
            let bytes = fs::read(path).unwrap();
            let kinds = block_kinds(&bytes);
            assert_eq!(&kinds[..2], &[0x0a0d0d0a, 1]);
            assert!(kinds[2..].iter().all(|kind| *kind == 6));
            assert!(bytes.len() <= 1024);
        }
        assert_eq!(dir.events().last().unwrap()["event"]["at_us"], 49);
        let old = dir.files("events-");
        let (writer, _) = Writer::open(config, Vec::new()).unwrap();
        writer.lifecycle(shutdown()).unwrap();
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(dir.files("events-").len(), 2);
        assert!(old.iter().any(|file| !file.exists()));
    }

    #[test]
    fn ethernet_frames_go_to_their_own_capture_and_the_log_keeps_their_facts() {
        let dir = Directory::new();
        let (writer, events) = Writer::open(dir.config(), Vec::new()).unwrap();
        let frame = Frame {
            at_us: 234,
            received_at_us: Some(345),
            timestamp_source: TimestampSource::HostSystemTime,
            direction: Direction::In,
            lost: 2,
            rx_queue_dropped: 3,
            tx_queue_dropped: 0,
            nic_rx_dropped: None,
            length: 5,
            bytes: vec![0, 1, 2, 3, 255],
        };
        assert!(events.frame(frame.clone()));
        writer.shutdown(Duration::from_secs(5)).unwrap();
        let bytes = fs::read(&dir.files("ethernet-")[0]).unwrap();
        assert_eq!(block_kinds(&bytes), [0x0a0d0d0a, 1, 6]);
        assert_eq!(u16::from_le_bytes(bytes[36..38].try_into().unwrap()), 1);
        assert_eq!(&bytes[48 + 28..48 + 33], &[0, 1, 2, 3, 255]);
        assert_eq!(
            u32::from_le_bytes(bytes[48 + 16..48 + 20].try_into().unwrap()),
            345
        );
        let event = &dir.events()[0]["event"];
        assert_eq!(event["event"], "ethernet_capture");
        assert_eq!(event["capture"]["offset"], 48);
        assert_eq!(event["lost"], 2);
        assert_eq!(event["rx_queue_dropped"], 3);
        assert_eq!(event["length"], 5);
        assert!(event["nic_rx_dropped"].is_null());
        assert!(event.get("bytes").is_none());
        let line: Line = serde_json::from_str(&dir.lines()[0]).unwrap();
        assert_eq!(
            line.event.record,
            Record::Frame(Frame {
                bytes: Vec::new(),
                ..frame
            })
        );
        assert_eq!(
            line.event.capture_id,
            Some(format!("{}:ethernet", line.run_id))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disk_full_does_not_block_capture_or_hide_loss_metrics() {
        let dir = Directory::new();
        let mut worker = Worker::open(dir.config(), "failure".into(), Vec::new()).unwrap();
        worker.events.file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let (admission, receiver) = admission(1024, 1024);
        admission
            .put(Item::Record(Record::Observation(burst(1))))
            .unwrap();
        admission.put(Item::Packet(packet(1))).unwrap();
        admission.metrics.0.stopped.store(true, Ordering::Release);
        worker.run(receiver, &admission);
        let metrics = admission.metrics.snapshot();
        assert_eq!(metrics.dropped_events, 1);
        assert_eq!(metrics.written_captures, 1);
        assert_eq!(metrics.write_failures, 1);
        assert!(metrics.sync_failures >= 1);
        assert_eq!(metrics.queued_bytes, 0);
        assert_eq!(
            block_kinds(&fs::read(&dir.files("ip-")[0]).unwrap()),
            [0x0a0d0d0a, 1, 6]
        );
    }

    #[test]
    fn retention_reserves_the_active_file_when_wall_time_moves_backwards() {
        let dir = Directory::new();
        let mut config = dir.config();
        config.retain_files = 2;
        for run in [
            "00000000000000000000000000000003-1-0",
            "00000000000000000000000000000002-1-0",
        ] {
            Files::open(&config, run, "events", "jsonl", Vec::new()).unwrap();
        }
        let active = Files::open(
            &config,
            "00000000000000000000000000000001-1-0",
            "events",
            "jsonl",
            Vec::new(),
        )
        .unwrap();
        assert!(dir.0.join(&active.name).exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn restart_preserves_incomplete_prior_evidence() {
        let dir = Directory::new();
        let prior = dir.0.join("events-incomplete.jsonl");
        fs::write(&prior, b"{\"unfinished\":").unwrap();
        let (writer, _) = Writer::open(dir.config(), Vec::new()).unwrap();
        writer
            .lifecycle(Lifecycle::BackendAttached {
                public_reachability: Reachability::NotTested,
            })
            .unwrap();
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(fs::read(&prior).unwrap(), b"{\"unfinished\":");
        assert_eq!(dir.files("events-").len(), 2);
    }

    #[test]
    fn shutdown_deadline_does_not_wait_for_a_stalled_worker() {
        let (admission, _receiver) = admission(1024, 1024);
        admission
            .put(Item::Record(Record::Observation(burst(1))))
            .unwrap();
        let (_sender, finished) = mpsc::sync_channel(1);
        let writer = Writer {
            admission: admission.clone(),
            finished,
            run_id: "stalled".into(),
        };
        assert_eq!(
            writer.shutdown(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(admission.metrics.0.stopped.load(Ordering::Acquire));
        assert!(admission.metrics.0.abort.load(Ordering::Acquire));
        assert_eq!(admission.metrics.snapshot().queued_records, 1);
        assert!(
            admission
                .put(Item::Record(Record::Lifecycle(shutdown())))
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_record_is_rolled_back_before_storage_recovers() {
        const CHILD: &str = "HONEYPOT_EVIDENCE_WRITE_LIMIT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "evidence::tests::partial_record_is_rolled_back_before_storage_recovers",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let dir = Directory::new();
        let mut files =
            Files::open(&dir.config(), "partial", "events", "jsonl", Vec::new()).unwrap();
        files.put(b"{\"one\":1}\n").unwrap();
        let before = files.size;
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: rlimit storage is initialized and valid for each call.
        // This process is a dedicated test child. Limit and signal disposition
        // cannot affect other tests, the supervisor, or host network state.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut original), 0);
            assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
            let limit = libc::rlimit {
                rlim_cur: before + 4,
                rlim_max: original.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        }
        assert!(files.put(b"{\"two\":22222}\n").is_err());
        assert_eq!(files.file.metadata().unwrap().len(), before);
        assert_eq!(files.size, before);
        // SAFETY: original contains the initialized limit returned by getrlimit.
        unsafe {
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &original), 0);
        }
        files.put(b"{\"three\":3}\n").unwrap();
        assert_eq!(
            fs::read_to_string(dir.0.join(&files.name)).unwrap(),
            "{\"one\":1}\n{\"three\":3}\n"
        );
    }
}
