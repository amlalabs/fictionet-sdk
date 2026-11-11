//! Bounded evidence admission, independent file writing, and local health metrics.
//!
//! A successful sink write means queued, not persisted. Files are synchronized
//! at most one second after the worker next gets CPU and disk access, and on
//! graceful shutdown. A stalled filesystem can exceed that interval; shutdown
//! returns at its deadline without waiting for a stuck filesystem operation.
//! Each run uses new files, preserving incomplete files from abrupt termination.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};

use crate::observe::Sinks;

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
    /// Retain exact application bytes when the producer explicitly permits it.
    pub restricted_evidence: bool,
    /// Maximum admitted data bytes, including the record currently writing.
    pub queue_bytes: usize,
    /// Maximum size of any one admitted record.
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

/// Independent aggregate health; no attacker-controlled metric labels.
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
    /// Admitted data and lifecycle bytes not yet handled by the worker.
    pub queued_bytes: usize,
    /// Admitted records not yet handled by the worker.
    pub queued_records: usize,
    /// Structured records accepted into the queue.
    pub accepted_events: u64,
    /// Capture records accepted into the queue, including initial headers.
    pub accepted_captures: u64,
    /// Structured records rejected or lost to storage failure.
    pub dropped_events: u64,
    /// Capture records rejected or lost to storage failure.
    pub dropped_captures: u64,
    /// Structured records successfully written, including Ethernet sidecars
    /// created by the worker after admission. Not necessarily synchronized.
    pub written_events: u64,
    /// Capture records successfully written, including initial headers.
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

    /// Prometheus text with a fixed set of aggregate metric names.
    pub fn prometheus(&self) -> String {
        let Value::Object(values) =
            serde_json::to_value(self.snapshot()).expect("integer counters")
        else {
            unreachable!()
        };
        let mut text = String::new();
        for (name, value) in values {
            let gauge = matches!(
                name.as_str(),
                "queued_bytes"
                    | "queued_records"
                    | "last_write_us"
                    | "last_sync_us"
                    | "backend_ready"
            );
            let suffix = if gauge { "" } else { "_total" };
            let kind = if gauge { "gauge" } else { "counter" };
            let value = value
                .as_bool()
                .map_or_else(|| value.to_string(), |value| u8::from(value).to_string());
            text.push_str(&format!(
                "# TYPE honeypot_{name}{suffix} {kind}\nhoneypot_{name}{suffix} {value}\n"
            ));
        }
        text
    }
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

struct Record {
    kind: Kind,
    bytes: Vec<u8>,
    elapsed_us: u64,
    wall_us: u64,
}

#[derive(Clone)]
struct Admission {
    sender: SyncSender<Record>,
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
    fn put(&self, kind: Kind, bytes: &[u8]) -> io::Result<()> {
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
            || bytes.len() > self.max_record_bytes
            || !reserve(record_count, 1, record_limit)
        {
            return Err(rejected());
        }
        if !reserve(byte_count, bytes.len(), byte_limit) {
            record_count.fetch_sub(1, Ordering::AcqRel);
            return Err(rejected());
        }
        let record = Record {
            kind,
            bytes: bytes.to_vec(),
            elapsed_us: self.started.elapsed().as_micros() as u64,
            wall_us: wall_us(),
        };
        if let Err(TrySendError::Full(record) | TrySendError::Disconnected(record)) =
            self.sender.try_send(record)
        {
            self.release(&record);
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

    fn release(&self, record: &Record) {
        let c = &self.metrics.0;
        let (bytes, records) = if record.kind.control() {
            (&c.control_bytes, &c.control_records)
        } else {
            (&c.queued_bytes, &c.queued_records)
        };
        bytes.fetch_sub(record.bytes.len(), Ordering::AcqRel);
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

struct QueueSink {
    admission: Admission,
    kind: Kind,
}

impl Write for QueueSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.admission.put(self.kind, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Owns evidence worker lifetime. Drop closes admission; explicit shutdown drains.
pub struct Writer {
    admission: Admission,
    finished: Receiver<()>,
    run_id: String,
}

impl Writer {
    /// Creates fresh files and a bounded writer thread before starting traffic.
    pub fn open(config: WriterConfig) -> io::Result<(Self, Sinks)> {
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
        let worker = Worker::open(config.clone(), run_id.clone())?;
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
        let sinks = Sinks {
            log: Box::new(QueueSink {
                admission: admission.clone(),
                kind: Kind::Event,
            }),
            pcap: Box::new(QueueSink {
                admission: admission.clone(),
                kind: Kind::Ip,
            }),
        };
        Ok((
            Self {
                admission,
                finished,
                run_id,
            },
            sinks,
        ))
    }

    /// Unique identity shared by all files and envelopes in this process run.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Existing raw Ethernet frame JSON becomes original Ethernet pcapng.
    pub fn raw_sink(&self) -> Box<dyn Write + Send> {
        Box::new(QueueSink {
            admission: self.admission.clone(),
            kind: Kind::Ethernet,
        })
    }

    /// Admits lifecycle records through capacity reserved from packet traffic.
    pub fn record(&self, event: &impl Serialize) -> io::Result<()> {
        struct Limited {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl Write for Limited {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "lifecycle record too large",
                    ));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut out = Limited {
            bytes: Vec::new(),
            limit: self.admission.max_record_bytes.min(CONTROL_BYTES),
        };
        if let Err(error) = serde_json::to_writer(&mut out, event) {
            self.admission.lost(Kind::Control);
            return Err(io::Error::other(error));
        }
        self.admission.put(Kind::Control, &out.bytes)
    }

    /// Shared management metrics without a dependency on filesystem health.
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

    fn put(&mut self, bytes: &[u8]) -> io::Result<Value> {
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
        Ok(
            json!({ "file": self.name, "section": 0, "interface": 0, "offset": offset, "available": true }),
        )
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
    last_capture: Option<(u64, Value)>,
}

impl Worker {
    fn open(config: WriterConfig, run_id: String) -> io::Result<Self> {
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
        })
    }

    fn event(&mut self, mut event: Value, record: &Record, metrics: &Metrics) -> io::Result<()> {
        match event.get("event").and_then(Value::as_str) {
            Some("mptcp_no_data") => {
                metrics.0.mptcp_no_data.fetch_add(1, Ordering::Relaxed);
            }
            Some("ip_options_retransmit") => {
                metrics
                    .0
                    .ip_options_retransmit
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some("port_zero") => {
                metrics.0.port_zero.fetch_add(1, Ordering::Relaxed);
            }
            Some("state_limit") => {
                metrics.0.state_limits.fetch_add(1, Ordering::Relaxed);
            }
            Some("ssh_authenticated") => {
                metrics.0.ssh_authenticated.fetch_add(1, Ordering::Relaxed);
            }
            Some("ssh") if event["ssh"]["event"] == "authenticated" => {
                metrics.0.ssh_authenticated.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        if event
            .get("mptcp")
            .and_then(Value::as_array)
            .is_some_and(|options| {
                options.iter().any(|option| {
                    matches!(
                        option["subtype"].as_str(),
                        Some("mp_join_syn" | "mp_join_syn_ack" | "mp_join_ack")
                    )
                })
            })
        {
            metrics.0.mp_join.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(packet) = event.get("capture_packet").and_then(Value::as_u64) {
            event["capture"] = self.last_capture.as_ref().filter(|(ordinal, _)| *ordinal == packet).map(|(_, reference)| reference.clone()).unwrap_or_else(|| json!({ "available": false, "reason": "capture_not_persisted_or_not_correlated" }));
        }
        if !self.config.restricted_evidence {
            redact(&mut event);
        }
        self.sequence += 1;
        let envelope = json!({
            "schema_version": 1,
            "sensor_id": self.config.sensor_id,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "recorded_at_us": record.wall_us,
            "elapsed_us": record.elapsed_us,
            "clock_source": "host_system_time_and_monotonic_admission",
            "backend": self.config.backend,
            "persona": self.config.persona,
            "capture_boundary": self.config.capture_boundary,
            "restricted_evidence": self.config.restricted_evidence,
            "evidence_health": { "dropped_events": metrics.snapshot().dropped_events, "dropped_captures": metrics.snapshot().dropped_captures, "write_failures": metrics.snapshot().write_failures, "sync_failures": metrics.snapshot().sync_failures },
            "ip_capture_id": format!("{}:ip", self.run_id),
            "event": event,
        });
        let mut bytes = serde_json::to_vec(&envelope)?;
        bytes.push(b'\n');
        self.events.put(&bytes)?;
        metrics.0.written_events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn process(&mut self, record: &Record, metrics: &Metrics) -> io::Result<()> {
        match record.kind {
            Kind::Event | Kind::Control => {
                self.event(serde_json::from_slice(&record.bytes)?, record, metrics)
            }
            Kind::Ip => {
                // The observer initializes the section. Files already hold that
                // same header so every rotated capture is independently readable.
                if record.bytes != self.ip.header {
                    self.last_capture = None;
                    let mut reference = self.ip.put(&record.bytes)?;
                    metrics
                        .0
                        .capture_bytes
                        .fetch_add(record.bytes.len() as u64, Ordering::Relaxed);
                    self.last_capture =
                        packet_reference(&record.bytes).map(|(ordinal, direction)| {
                            reference["direction"] = json!(direction);
                            (ordinal, reference)
                        });
                }
                metrics.0.written_captures.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Kind::Ethernet => {
                let mut event: Value = serde_json::from_slice(&record.bytes)?;
                let hex = event.get("bytes").and_then(Value::as_str).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing Ethernet frame")
                })?;
                if hex.len() % 2 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "odd Ethernet hex length",
                    ));
                }
                let bytes = hex
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        let digit = |b: u8| match b {
                            b'0'..=b'9' => Ok(b - b'0'),
                            b'a'..=b'f' => Ok(b - b'a' + 10),
                            _ => Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid Ethernet hex",
                            )),
                        };
                        Ok((digit(pair[0])? << 4) | digit(pair[1])?)
                    })
                    .collect::<io::Result<Vec<u8>>>()?;
                if self.ethernet.is_none() {
                    let mut header = Vec::new();
                    fictionet::stdlib::pcap::start_ethernet(&mut header);
                    self.ethernet = Some(Files::open(
                        &self.config,
                        &self.run_id,
                        "ethernet",
                        "pcapng",
                        header,
                    )?);
                }
                let mut block = Vec::new();
                let direction = event
                    .get("direction")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                fictionet::stdlib::pcap::packet(
                    &mut block,
                    event
                        .get("received_at_us")
                        .and_then(Value::as_u64)
                        .or_else(|| event.get("at_us").and_then(Value::as_u64))
                        .unwrap_or(record.wall_us),
                    bytes.len(),
                    &bytes,
                    Some(direction),
                );
                let mut reference = self
                    .ethernet
                    .as_mut()
                    .expect("opened Ethernet capture")
                    .put(&block)?;
                reference["direction"] = json!(direction);
                metrics.0.written_captures.fetch_add(1, Ordering::Relaxed);
                metrics
                    .0
                    .capture_bytes
                    .fetch_add(block.len() as u64, Ordering::Relaxed);
                event.as_object_mut().expect("frame object").remove("bytes");
                event["event"] = json!("ethernet_capture");
                event["capture"] = reference;
                event["capture_id"] = json!(format!("{}:ethernet", self.run_id));
                event["length"] = json!(bytes.len());
                if self.event(event, record, metrics).is_err() {
                    metrics.0.dropped_events.fetch_add(1, Ordering::Relaxed);
                    metrics.0.write_failures.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }
        }
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

    fn run(mut self, receiver: Receiver<Record>, admission: &Admission) {
        let metrics = &admission.metrics;
        let mut last_sync = Instant::now();
        loop {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(record) => {
                    if metrics.0.abort.load(Ordering::Acquire) {
                        admission.lost(record.kind);
                    } else if self.process(&record, metrics).is_err() {
                        metrics.0.write_failures.fetch_add(1, Ordering::Relaxed);
                        admission.lost(record.kind);
                    } else {
                        metrics.0.last_write_us.store(wall_us(), Ordering::Relaxed);
                    }
                    admission.release(&record);
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
                last_sync = Instant::now();
            }
        }
        self.sync(metrics);
    }
}

fn packet_reference(block: &[u8]) -> Option<(u64, &str)> {
    if u32::from_le_bytes(block.get(..4)?.try_into().ok()?) != 6 {
        return None;
    }
    let captured = u32::from_le_bytes(block.get(20..24)?.try_into().ok()?) as usize;
    let mut offset = 28usize.checked_add(captured.checked_add(3)? & !3)?;
    while offset.checked_add(4)? <= block.len().checked_sub(4)? {
        let kind = u16::from_le_bytes(block.get(offset..offset + 2)?.try_into().ok()?);
        let length =
            u16::from_le_bytes(block.get(offset + 2..offset + 4)?.try_into().ok()?) as usize;
        offset += 4;
        if kind == 0 {
            return None;
        }
        let value = block.get(offset..offset.checked_add(length)?)?;
        if kind == 1 {
            let comment = std::str::from_utf8(value).ok()?;
            if let Some((prefix, ordinal)) = comment.rsplit_once(" packet=") {
                let (_, direction) = prefix.rsplit_once(' ')?;
                return Some((ordinal.parse().ok()?, direction));
            }
        }
        offset = offset.checked_add(length.checked_add(3)? & !3)?;
    }
    None
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for key in [
                "password",
                "new_password",
                "wire_payload",
                "payload",
                "command",
                "responses",
            ] {
                if let Some(value) = fields.remove(key) {
                    let length = match &value {
                        Value::Array(bytes) => Some(bytes.len()),
                        Value::String(text) if matches!(key, "payload" | "wire_payload") => {
                            Some(text.len() / 2)
                        }
                        Value::String(text) => Some(text.len()),
                        _ => None,
                    };
                    if let Some(length) = length {
                        fields
                            .entry(format!("{key}_bytes"))
                            .or_insert(json!(length));
                    }
                }
            }
            for child in fields.values_mut() {
                redact(child);
            }
        }
        Value::Array(values) => {
            for value in values {
                redact(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
// Storage failure tests set resource limits in dedicated child processes.
#[allow(unsafe_code)]
mod tests {
    use super::*;

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
        fn events(&self) -> Vec<Value> {
            self.files("events-")
                .iter()
                .flat_map(|path| {
                    fs::read_to_string(path)
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str::<Value>(line).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn admission(queue_bytes: usize, max_record_bytes: usize) -> (Admission, Receiver<Record>) {
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

    fn packet(ordinal: u64) -> Vec<u8> {
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
        let (admission, receiver) = admission(8, 8);
        admission.put(Kind::Ip, b"12345678").unwrap();
        assert_eq!(
            admission.put(Kind::Event, b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            admission.put(Kind::Ip, b"123456789").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        admission.put(Kind::Control, b"health").unwrap();
        let snapshot = admission.metrics.snapshot();
        assert_eq!(snapshot.queued_bytes, 14);
        assert_eq!(snapshot.dropped_events, 1);
        assert_eq!(snapshot.dropped_captures, 1);
        for _ in 0..2 {
            let record = receiver.try_recv().unwrap();
            admission.release(&record);
        }
        assert_eq!(admission.metrics.snapshot().queued_bytes, 0);
        let (admission, _receiver) = self::admission(QUEUE_RECORDS + 1, 1);
        for _ in 0..QUEUE_RECORDS {
            admission.put(Kind::Event, b"x").unwrap();
        }
        assert!(admission.put(Kind::Event, b"x").is_err());
        admission.put(Kind::Control, b"x").unwrap();
        assert_eq!(
            admission.metrics.snapshot().queued_records,
            QUEUE_RECORDS + 1
        );
    }

    #[test]
    fn shutdown_drains_with_live_sinks_and_links_original_capture() {
        let dir = Directory::new();
        let (writer, mut sinks) = Writer::open(dir.config()).unwrap();
        let run = writer.run_id().to_owned();
        let mut header = Vec::new();
        fictionet::stdlib::pcap::start(&mut header, &[]);
        sinks.pcap.write_all(&header).unwrap();
        sinks.pcap.write_all(&packet(1)).unwrap();
        sinks
            .log
            .write_all(br#"{"event":"port_zero","capture_packet":1,"capture_queued":true}"#)
            .unwrap();
        writer.record(&json!({ "event": "shutdown" })).unwrap();
        let metrics = writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(metrics.queued_records, 0);
        assert_eq!(metrics.written_events, 2);
        assert_eq!(metrics.written_captures, 2);
        assert_eq!(metrics.port_zero, 1);
        assert!(metrics.last_sync_us > 0);
        assert!(sinks.log.write_all(b"{}").is_err());
        let events = dir.events();
        assert_eq!(events[0]["run_id"], run);
        assert_eq!(events[0]["schema_version"], 1);
        assert_eq!(events[0]["sequence"], 1);
        assert_eq!(events[0]["event"]["capture"]["offset"], 48);
        assert_eq!(events[0]["event"]["capture"]["available"], true);
        let capture = fs::read(dir.files("ip-")[0].clone()).unwrap();
        assert_eq!(block_kinds(&capture), [0x0a0d0d0a, 1, 6]);
        assert_eq!(packet_reference(&capture[48..]), Some((1, "in")));
    }

    #[test]
    fn dropped_or_unrelated_capture_is_never_claimed_available() {
        let dir = Directory::new();
        let (writer, mut sinks) = Writer::open(dir.config()).unwrap();
        sinks.pcap.write_all(&packet(2)).unwrap();
        sinks
            .log
            .write_all(br#"{"event":"port_zero","capture_packet":1,"capture_queued":false}"#)
            .unwrap();
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(dir.events()[0]["event"]["capture"]["available"], false);
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
        let (writer, mut sinks) = Writer::open(config.clone()).unwrap();
        for ordinal in 1..50 {
            sinks.pcap.write_all(&packet(ordinal)).unwrap();
            sinks
                .log
                .write_all(
                    &serde_json::to_vec(&json!({ "event": "sample", "ordinal": ordinal })).unwrap(),
                )
                .unwrap();
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
        assert!(dir.events().last().unwrap()["event"]["ordinal"] == 49);
        let old = dir.files("events-");
        let (writer, _) = Writer::open(config).unwrap();
        writer.record(&json!({"event":"restarted"})).unwrap();
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(dir.files("events-").len(), 2);
        assert!(old.iter().any(|file| !file.exists()));
    }

    #[test]
    fn ethernet_adapter_preserves_unknown_and_malformed_frames() {
        let dir = Directory::new();
        let (writer, _) = Writer::open(dir.config()).unwrap();
        let mut raw = writer.raw_sink();
        raw.write_all(br#"{"at_us":234,"received_at_us":345,"timestamp_source":"host_system_time","direction":"in","bytes":"00010203ff","lost":2,"rx_queue_dropped":3,"tx_queue_dropped":0,"nic_rx_dropped":null}"#).unwrap();
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
        assert_eq!(event["capture"]["offset"], 48);
        assert_eq!(event["lost"], 2);
        assert_eq!(event["rx_queue_dropped"], 3);
        assert!(event["nic_rx_dropped"].is_null());
        assert!(event.get("bytes").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disk_full_does_not_block_capture_or_hide_loss_metrics() {
        let dir = Directory::new();
        let mut worker = Worker::open(dir.config(), "failure".into()).unwrap();
        worker.events.file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let (admission, receiver) = admission(1024, 1024);
        admission
            .put(Kind::Event, br#"{"event":"sample"}"#)
            .unwrap();
        admission.put(Kind::Ip, &packet(1)).unwrap();
        admission.metrics.0.stopped.store(true, Ordering::Release);
        worker.run(receiver, &admission);
        let metrics = admission.metrics.snapshot();
        assert_eq!(metrics.dropped_events, 1);
        assert_eq!(metrics.written_captures, 1);
        assert_eq!(metrics.write_failures, 1);
        assert!(metrics.sync_failures >= 1);
        assert_eq!(metrics.queued_bytes, 0);
        assert!(
            admission
                .metrics
                .prometheus()
                .contains("honeypot_dropped_events_total 1")
        );
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
        let (writer, _) = Writer::open(dir.config()).unwrap();
        writer.record(&json!({"event":"startup"})).unwrap();
        writer.shutdown(Duration::from_secs(5)).unwrap();
        assert_eq!(fs::read(&prior).unwrap(), b"{\"unfinished\":");
        assert_eq!(dir.files("events-").len(), 2);
    }

    #[test]
    fn nested_payloads_are_redacted_but_packet_options_remain() {
        let mut event = json!({"password":[1,2],"nested":{"wire_payload":"736563726574", "command":[3,4,5]},"payload":"deadbeef", "options":[{"bytes":"010203"}]});
        redact(&mut event);
        assert!(event.get("password").is_none());
        assert_eq!(event["password_bytes"], 2);
        assert_eq!(event["payload_bytes"], 4);
        assert_eq!(event["nested"]["wire_payload_bytes"], 6);
        assert_eq!(event["nested"]["command_bytes"], 3);
        assert_eq!(event["options"][0]["bytes"], "010203");
    }

    #[test]
    fn shutdown_deadline_does_not_wait_for_a_stalled_worker() {
        let (admission, _receiver) = admission(1024, 1024);
        admission.put(Kind::Event, b"{}").unwrap();
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
        assert!(admission.put(Kind::Control, b"{}").is_err());
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
