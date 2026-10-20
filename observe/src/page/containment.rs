use serde::{Deserialize, Serialize};

/// Startup checks published by the guest kit or a page fixture.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Containment {
    /// Results in probe order, with the guest named on each one.
    pub probes: Vec<ProbeResult>,
}

/// The conclusion supported by a guest result and the world's observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The world answered, refused, or had no route for the probe.
    Contained,
    /// The world deliberately forwarded the probe to a named origin.
    Forwarded,
    /// The guest got an answer that world observations do not account for.
    NotContained,
    /// No conclusion, including an unanswered probe without observations.
    Unknown,
    /// The guest image does not have the required tool.
    MissingTool,
    /// The probe reached its deadline without an accounted outcome.
    TimedOut,
    /// Configuration reported as facts, without a containment conclusion.
    Fact,
}

/// One proxy variable or apt setting, reported without changing it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxySetting {
    /// Variable or setting name.
    pub name: String,
    /// Configured destination.
    pub destination: String,
    /// Whether the destination names a host in this world.
    pub world_host: bool,
}

/// One command, its result, and the corresponding world answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Guest attachment name.
    pub guest: String,
    /// Human-readable probe name.
    pub name: String,
    /// Command run over the admin SSH session.
    pub command: String,
    /// Destination, or configuration source for a fact probe.
    pub destination: String,
    /// How the probe ended.
    pub outcome: ProbeOutcome,
    /// Guest output, exit status, deadline or missing-tool reason.
    pub guest_result: String,
    /// World answer, derived from the destination projection after the probe.
    pub world_answer: String,
    /// Proxy settings, empty when none were set or this was not a proxy probe.
    pub proxies: Vec<ProxySetting>,
}
