//! Offline, auditable inference over trap observations. Scores are similarities,
//! not probabilities; declarations and behavioral evidence remain separate.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead};

use crate::traps::{CredentialForm, CredentialShape, ProbeEnd, ProbeKind, TrapEvent};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

const FORMAT: &str = "shibboleth-word-char-tfidf-v1";
const HARNESSES: [&str; 4] = ["claude-code", "hermes-agent", "openclaw", "opencode"];

/// Provenance retained from each evidence envelope.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Provenance {
    pub run_id: Option<String>,
    pub session: Option<String>,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    pub at_us: Option<u64>,
}

/// One trace, preserving typed declarations and probe order.
#[derive(Clone, Debug, Default)]
pub struct Trace {
    pub gates: Vec<TrapEvent>,
    pub provenance: Vec<Provenance>,
}

/// Conservative grouping; separate agents sharing a source cannot be resolved.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TraceKey {
    pub run_id: Option<String>,
    pub source: Option<IpAddr>,
    pub service: Option<SocketAddr>,
}

impl Trace {
    /// Reads both bare observations and the evidence writer's envelopes.
    pub fn read(reader: impl BufRead) -> io::Result<Self> {
        let mut groups = Self::read_grouped(reader)?;
        if groups.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mixed source, run or trap service; use the split command first",
            ));
        }
        Ok(groups
            .pop_first()
            .map(|(_, trace)| trace)
            .unwrap_or_default())
    }

    /// Extracts independent run, source IP and destination service groups.
    pub fn read_grouped(reader: impl BufRead) -> io::Result<BTreeMap<TraceKey, Self>> {
        let mut trace = Self::default();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let envelope: serde_json::Value =
                serde_json::from_str(&line).map_err(io::Error::other)?;
            let record = if envelope["event"].is_object() {
                &envelope["event"]
            } else {
                &envelope
            };
            if record["event"] == "trap" {
                let gate =
                    serde_json::from_value(record["trap"].clone()).map_err(io::Error::other)?;
                let mut provenance: Provenance =
                    serde_json::from_value(record.clone()).map_err(io::Error::other)?;
                provenance.run_id = envelope["run_id"].as_str().map(str::to_string);
                trace.gates.push(gate);
                trace.provenance.push(provenance);
            }
        }
        let mut groups = BTreeMap::<TraceKey, Self>::new();
        for (gate, provenance) in trace.gates.into_iter().zip(trace.provenance) {
            let key = TraceKey {
                run_id: provenance.run_id.clone(),
                source: provenance.src.map(|src| src.ip()),
                service: provenance.dst,
            };
            let group = groups.entry(key).or_default();
            group.gates.push(gate);
            group.provenance.push(provenance);
        }
        Ok(groups)
    }

    fn prose(&self) -> Vec<&str> {
        self.gates
            .iter()
            .filter_map(|gate| match gate {
                TrapEvent::Prose { text, .. } if !text.trim().is_empty() => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// The fixed feature space and enrolled model templates. Enrollment never refits
/// the vocabulary or inverse document frequencies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enrollment {
    /// Versioned extraction and weighting specification.
    pub format: String,
    /// Sorted character n-grams, including word-boundary spaces.
    pub vocabulary: Vec<String>,
    /// Smoothed inverse document frequency, fitted once on prose inputs.
    pub idf: Vec<f64>,
    /// Number of prose inputs used to fit the vocabulary.
    pub fitted_inputs: usize,
    /// Model templates; each trace receives equal weight.
    pub models: BTreeMap<String, Template>,
}

/// A mean of trace fingerprints in the frozen feature space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Template {
    /// Number of independently enrolled traces.
    pub traces: usize,
    /// Mean trace vector.
    pub mean: Vec<f64>,
}

fn grams(text: &str) -> BTreeMap<String, f64> {
    let mut counts = BTreeMap::new();
    for word in text.split_whitespace() {
        let word: Vec<char> = format!(" {} ", word.to_lowercase()).chars().collect();
        for n in 2..=5 {
            if word.len() >= n {
                for window in word.windows(n) {
                    *counts.entry(window.iter().collect()).or_default() += 1.0;
                }
            }
        }
    }
    counts
}

fn normalize(vector: &mut [f64]) {
    let norm = vector.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for x in vector {
            *x /= norm;
        }
    }
}

impl Enrollment {
    /// Fits the feature space from training traces and enrolls their labels.
    pub fn fit(traces: &[(String, Trace)]) -> Result<Self, String> {
        let mut frequencies = BTreeMap::<String, usize>::new();
        let mut inputs = 0;
        for (_, trace) in traces {
            for text in trace.prose() {
                inputs += 1;
                for gram in grams(text).keys() {
                    *frequencies.entry(gram.clone()).or_default() += 1;
                }
            }
        }
        if inputs == 0 {
            return Err("training traces contain no prose".into());
        }
        let mut result = Self {
            format: FORMAT.into(),
            vocabulary: frequencies.keys().cloned().collect(),
            idf: frequencies
                .values()
                .map(|df| ((1.0 + inputs as f64) / (1.0 + *df as f64)).ln() + 1.0)
                .collect(),
            fitted_inputs: inputs,
            models: BTreeMap::new(),
        };
        for (label, trace) in traces {
            result.enroll(label, trace)?;
        }
        Ok(result)
    }

    /// Checks a loaded artifact before using its dimensions or floating values.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != FORMAT
            || self.vocabulary.is_empty()
            || self.fitted_inputs == 0
            || self.idf.len() != self.vocabulary.len()
            || self.vocabulary.windows(2).any(|pair| pair[0] >= pair[1])
            || self.idf.iter().any(|x| !x.is_finite() || *x <= 0.0)
            || self.models.values().any(|model| {
                model.traces == 0
                    || model.mean.len() != self.idf.len()
                    || model.mean.iter().any(|x| !x.is_finite())
            })
        {
            return Err("invalid or unsupported enrollment artifact".into());
        }
        Ok(())
    }

    /// Mean of normalized input vectors. Unknown vocabulary contributes nothing.
    pub fn fingerprint(&self, trace: &Trace) -> Result<Option<Vec<f64>>, String> {
        self.validate()?;
        let texts = trace.prose();
        if texts.is_empty() {
            return Ok(None);
        }
        let mut mean = vec![0.0; self.vocabulary.len()];
        for text in &texts {
            let counts = grams(text);
            let mut vector: Vec<f64> = self
                .vocabulary
                .iter()
                .zip(&self.idf)
                .map(|(gram, idf)| counts.get(gram).copied().unwrap_or(0.0) * idf)
                .collect();
            normalize(&mut vector);
            for (sum, value) in mean.iter_mut().zip(vector) {
                *sum += value / texts.len() as f64;
            }
        }
        Ok(mean.iter().any(|x| *x != 0.0).then_some(mean))
    }

    /// Adds one labeled trace without changing the trained feature space.
    pub fn enroll(&mut self, label: &str, trace: &Trace) -> Result<(), String> {
        if label.trim().is_empty() {
            return Err("empty model label".into());
        }
        let vector = self
            .fingerprint(trace)?
            .ok_or("trace has no in-vocabulary prose")?;
        let template = self.models.entry(label.into()).or_insert_with(|| Template {
            traces: 0,
            mean: vec![0.0; vector.len()],
        });
        template.traces += 1;
        for (mean, value) in template.mean.iter_mut().zip(vector) {
            *mean += (value - *mean) / template.traces as f64;
        }
        Ok(())
    }

    fn behavioral(&self, trace: &Trace) -> Result<Vec<ModelScore>, String> {
        let Some(vector) = self.fingerprint(trace)? else {
            return Ok(Vec::new());
        };
        if self.models.len() < 2 {
            return Ok(Vec::new());
        }
        let mut center = vec![0.0; vector.len()];
        let total_traces: usize = self.models.values().map(|model| model.traces).sum();
        for template in self.models.values() {
            for (mean, value) in center.iter_mut().zip(&template.mean) {
                *mean += value * template.traces as f64 / total_traces as f64;
            }
        }
        let centered: Vec<_> = vector.iter().zip(&center).map(|(x, c)| x - c).collect();
        let mut scores = Vec::new();
        for (label, template) in &self.models {
            let other: Vec<_> = template
                .mean
                .iter()
                .zip(&center)
                .map(|(x, c)| x - c)
                .collect();
            let denominator = (centered.iter().map(|x| x * x).sum::<f64>()
                * other.iter().map(|x| x * x).sum::<f64>())
            .sqrt();
            if denominator > 0.0 {
                scores.push(ModelScore {
                    model: label.clone(),
                    cosine: centered.iter().zip(other).map(|(a, b)| a * b).sum::<f64>()
                        / denominator,
                });
            }
        }
        scores.sort_by(|a, b| b.cosine.total_cmp(&a.cosine).then(a.model.cmp(&b.model)));
        Ok(scores)
    }
}

/// A similarity to an enrolled model, without a calibrated confidence claim.
#[derive(Clone, Debug, Serialize)]
pub struct ModelScore {
    /// Enrolled label.
    pub model: String,
    /// Centered cosine similarity.
    pub cosine: f64,
}

/// Behavioral readings are compatible candidates, never a proof of identity.
#[derive(Clone, Debug, Serialize)]
pub struct HarnessReading {
    /// Candidates from the measured four-harness panel.
    pub candidates: BTreeSet<String>,
    /// Unknown harnesses and model-driven imitation remain possible.
    pub open_set: bool,
    /// Human-readable readings explaining each intersection.
    pub readings: Vec<RuleReading>,
}

/// Rule observations are compatibility evidence and can be imitated by callers.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum RuleReading {
    AsciiMask,
    UnicodeMask,
    WholeCredential {
        shape: CredentialShape,
    },
    ParallelChecks,
    SequentialChecks,
    HoldKilled,
    HoldHandBack,
    Observed {
        probe: ProbeKind,
        elapsed_ms: u64,
        end: ProbeEnd,
    },
}

// The measured 120 second boundary allows two seconds of transport scheduling.
fn near_timeout(elapsed_ms: u64) -> bool {
    (118_000..=122_000).contains(&elapsed_ms)
}

/// Separate declarative and behavioral outputs, plus declaration-first selection.
#[derive(Debug, Serialize)]
pub struct Inference {
    /// First valid model declaration, independent of a forced handshake retry.
    pub declared_model: Option<String>,
    /// First recognized harness declaration.
    pub declared_harness: Option<String>,
    /// Similarities over enrolled labels only.
    pub behavioral_models: Vec<ModelScore>,
    /// Selected declaration, or nearest non-tied enrolled template.
    pub model: Option<String>,
    /// Uncalibrated harness compatibility readings.
    pub harness: HarnessReading,
}

fn harness_name(value: &str) -> Option<String> {
    let compact = value.to_ascii_lowercase().replace([' ', '-', '_'], "");
    match compact.as_str() {
        "claudecode" => Some("claude-code".into()),
        "hermes" | "hermesagent" => Some("hermes-agent".into()),
        "openclaw" => Some("openclaw".into()),
        "opencode" => Some("opencode".into()),
        _ => None,
    }
}

/// Applies first-valid declaration precedence and conservative probe intersections.
pub fn infer(trace: &Trace, enrollment: Option<&Enrollment>) -> Result<Inference, String> {
    let mut declared_model = None;
    let mut declared_harness = None;
    let mut harness = HarnessReading {
        candidates: HARNESSES.into_iter().map(str::to_string).collect(),
        open_set: true,
        readings: Vec::new(),
    };
    let mut distinct_checks = BTreeSet::new();
    let mut overlapped = false;
    for (index, gate) in trace.gates.iter().enumerate() {
        if let TrapEvent::Declaration { model, runtime, .. } = gate {
            if declared_model.is_none() && crate::traps::declaration_valid(model) {
                declared_model = Some(model.clone());
            }
            if declared_harness.is_none() {
                declared_harness = runtime.as_deref().and_then(harness_name);
            }
        }
        let allowed: Option<(&[&str], RuleReading)> = match gate {
            TrapEvent::Credential {
                form: CredentialForm::AsciiEllipsis,
                ..
            } => Some((&["hermes-agent"], RuleReading::AsciiMask)),
            TrapEvent::Credential {
                form: CredentialForm::UnicodeEllipsis,
                ..
            } => Some((&["openclaw"], RuleReading::UnicodeMask)),
            TrapEvent::Credential {
                shape,
                form: CredentialForm::Whole,
                ..
            } => match shape {
                CredentialShape::Unknown => None,
                CredentialShape::UrlPassword => Some((
                    &["hermes-agent", "opencode", "claude-code"],
                    RuleReading::WholeCredential {
                        shape: CredentialShape::UrlPassword,
                    },
                )),
                CredentialShape::TwoPart => Some((
                    &["openclaw", "opencode", "claude-code"],
                    RuleReading::WholeCredential {
                        shape: CredentialShape::TwoPart,
                    },
                )),
                CredentialShape::ThreePart => Some((
                    &["opencode", "claude-code"],
                    RuleReading::WholeCredential {
                        shape: CredentialShape::ThreePart,
                    },
                )),
            },
            TrapEvent::Request {
                host_checks,
                target,
                ..
            } if *host_checks > 1 && target.contains("check") => {
                Some((&["openclaw", "opencode"], RuleReading::ParallelChecks))
            }
            _ => None,
        };
        if let Some((allowed, reason)) = allowed {
            harness
                .candidates
                .retain(|name| allowed.contains(&name.as_str()));
            harness.readings.push(reason);
        }
        if let TrapEvent::Request {
            host_checks,
            target,
            ..
        } = gate
        {
            if *host_checks > 0 && target.contains("check") {
                distinct_checks.insert(target.split('?').next().unwrap_or(target).to_owned());
                overlapped |= *host_checks > 1;
            }
        }
        if let TrapEvent::Probe {
            probe,
            elapsed_ms,
            end,
        } = gate
        {
            harness.readings.push(RuleReading::Observed {
                probe: *probe,
                elapsed_ms: *elapsed_ms,
                end: *end,
            });
            if *probe == ProbeKind::Hold
                && *end == ProbeEnd::PeerClosed
                && near_timeout(*elapsed_ms)
            {
                harness.candidates.retain(|name| name == "opencode");
                harness.readings.push(RuleReading::HoldKilled);
            }
            if *probe == ProbeKind::Hold && *end == ProbeEnd::Answered {
                if let Some(end_at) = trace.provenance.get(index).and_then(|p| p.at_us) {
                    let start_at = end_at.saturating_sub(elapsed_ms.saturating_mul(1000));
                    let handed_back =
                        trace
                            .gates
                            .iter()
                            .zip(&trace.provenance)
                            .any(|(gate, provenance)| {
                                matches!(gate, TrapEvent::Request { .. })
                                    && provenance.at_us.is_some_and(|at| {
                                        at > start_at
                                            && at < end_at
                                            && near_timeout((at - start_at) / 1000)
                                    })
                            });
                    if handed_back {
                        harness.candidates.retain(|name| name == "claude-code");
                        harness.readings.push(RuleReading::HoldHandBack);
                    }
                }
            }
        }
    }
    if distinct_checks.len() >= 4 && !overlapped {
        harness
            .candidates
            .retain(|name| matches!(name.as_str(), "hermes-agent" | "claude-code"));
        harness.readings.push(RuleReading::SequentialChecks);
    }
    let behavioral_models = enrollment
        .map(|e| e.behavioral(trace))
        .transpose()?
        .unwrap_or_default();
    let nearest = behavioral_models
        .first()
        .filter(|first| {
            behavioral_models
                .get(1)
                .is_none_or(|second| (first.cosine - second.cosine).abs() > 1e-12)
        })
        .map(|score| score.model.clone());
    Ok(Inference {
        model: declared_model.clone().or(nearest),
        declared_model,
        declared_harness,
        behavioral_models,
        harness,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prose(text: &str) -> Trace {
        Trace {
            gates: vec![TrapEvent::Prose {
                stage: "review".into(),
                text: text.into(),
                accepted: true,
            }],
            ..Default::default()
        }
    }
    #[test]
    fn fixed_features_and_equal_trace_weight_survive_enrollment() {
        let a = prose("Measure pressure and verify the valve then report the reading.");
        let b = prose("Rollback restores yesterday database snapshot and cancels pending jobs.");
        let mut enrollment =
            Enrollment::fit(&[("a".into(), a.clone()), ("b".into(), b.clone())]).unwrap();
        let vocabulary = enrollment.vocabulary.clone();
        let idf = enrollment.idf.clone();
        let original = enrollment.fingerprint(&a).unwrap().unwrap();
        let repeated = Trace {
            gates: (0..10).flat_map(|_| a.gates.iter().cloned()).collect(),
            ..Default::default()
        };
        let vector = enrollment.fingerprint(&repeated).unwrap().unwrap();
        assert!(
            original
                .iter()
                .zip(vector)
                .all(|(a, b)| (a - b).abs() < 1e-12)
        );
        enrollment.enroll("new", &a).unwrap();
        assert_eq!(enrollment.vocabulary, vocabulary);
        assert_eq!(enrollment.idf, idf);
        assert_eq!(enrollment.models["new"].mean, original);
        assert_eq!(enrollment.behavioral(&b).unwrap()[0].model, "b");
    }
    #[test]
    fn unknown_inputs_and_corrupt_artifacts_do_not_get_a_label() {
        let mut e = Enrollment::fit(&[
            ("a".into(), prose("aaaa aaaa")),
            ("b".into(), prose("bbbb bbbb")),
        ])
        .unwrap();
        assert!(infer(&prose("雪雪雪雪"), Some(&e)).unwrap().model.is_none());
        e.idf.pop();
        assert!(e.fingerprint(&prose("a")).is_err());
    }
    #[test]
    fn declarations_ignore_forced_retry_and_preserve_order() {
        let declaration = |model: &str| TrapEvent::Declaration {
            model: model.into(),
            runtime: Some("OpenCode".into()),
            accepted: false,
            reason: "retry".into(),
        };
        let trace = Trace {
            gates: vec![
                declaration("test/test"),
                declaration("provider/model-99"),
                declaration("provider/model-100"),
            ],
            ..Default::default()
        };
        let result = infer(&trace, None).unwrap();
        assert_eq!(result.declared_model.as_deref(), Some("provider/model-99"));
        assert_eq!(result.declared_harness.as_deref(), Some("opencode"));
    }
    #[test]
    fn masking_intersections_remain_open() {
        let trace = Trace {
            gates: vec![TrapEvent::Credential {
                shape: CredentialShape::ThreePart,
                form: CredentialForm::Whole,
                offered: "decoy".into(),
            }],
            ..Default::default()
        };
        let result = infer(&trace, None).unwrap();
        assert_eq!(
            result.harness.candidates,
            BTreeSet::from(["opencode".into(), "claude-code".into()])
        );
        assert!(result.harness.open_set);
    }
    #[test]
    fn held_retry_does_not_make_sequential_checks_parallel() {
        let request = |host_checks| TrapEvent::Request {
            method: "GET".into(),
            target: "/hosts/edge/check".into(),
            active: 3,
            host_checks,
            connection: 1,
            ordinal: 1,
            version: crate::traps::HttpVersion::Http11,
        };
        let mut trace = Trace {
            gates: vec![request(1)],
            ..Default::default()
        };
        assert_eq!(infer(&trace, None).unwrap().harness.candidates.len(), 4);
        trace.gates.push(request(2));
        assert_eq!(
            infer(&trace, None).unwrap().harness.candidates,
            BTreeSet::from(["opencode".into(), "openclaw".into()])
        );
    }
    #[test]
    fn evidence_reader_preserves_wrapped_provenance() {
        let record = serde_json::json!({"run_id":"run-one","event":{"event":"trap","session":"session-one","src":"192.0.2.1:1234","dst":"192.0.2.2:80","at_us":42,"trap":{"kind":"prose","text":"operator prose","stage":"review","accepted":true}}});
        let bytes = serde_json::to_vec(&record).unwrap();
        let trace = Trace::read(&bytes[..]).unwrap();
        assert_eq!(trace.prose(), ["operator prose"]);
        assert_eq!(trace.provenance[0].run_id.as_deref(), Some("run-one"));
        assert!(Trace::read(&b"{bad json}"[..]).is_err());
    }
    #[test]
    fn timeout_rules_require_the_measured_boundary_and_handback_evidence() {
        let probe = |elapsed_ms, end| TrapEvent::Probe {
            probe: ProbeKind::Hold,
            elapsed_ms,
            end,
        };
        let trace = Trace {
            gates: vec![probe(120_000, ProbeEnd::PeerClosed)],
            ..Default::default()
        };
        assert_eq!(
            infer(&trace, None).unwrap().harness.candidates,
            BTreeSet::from(["opencode".into()])
        );
        let trace = Trace {
            gates: vec![probe(90_000, ProbeEnd::PeerClosed)],
            ..Default::default()
        };
        assert_eq!(infer(&trace, None).unwrap().harness.candidates.len(), 4);
        let request = TrapEvent::Request {
            method: "GET".into(),
            target: "/status".into(),
            active: 2,
            host_checks: 0,
            connection: 2,
            ordinal: 1,
            version: crate::traps::HttpVersion::Http11,
        };
        let trace = Trace {
            gates: vec![request, probe(150_000, ProbeEnd::Answered)],
            provenance: vec![
                Provenance {
                    at_us: Some(120_000_000),
                    ..Default::default()
                },
                Provenance {
                    at_us: Some(150_000_000),
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            infer(&trace, None).unwrap().harness.candidates,
            BTreeSet::from(["claude-code".into()])
        );
    }
    #[test]
    fn serial_rule_needs_four_distinct_checks() {
        let request = |host| TrapEvent::Request {
            method: "GET".into(),
            target: format!("/hosts/{host}/check"),
            active: 1,
            host_checks: 1,
            connection: 1,
            ordinal: 1,
            version: crate::traps::HttpVersion::Http11,
        };
        let mut trace = Trace {
            gates: (0..3).map(request).collect(),
            ..Default::default()
        };
        assert_eq!(infer(&trace, None).unwrap().harness.candidates.len(), 4);
        trace.gates.push(request(3));
        assert_eq!(
            infer(&trace, None).unwrap().harness.candidates,
            BTreeSet::from(["hermes-agent".into(), "claude-code".into()])
        );
    }
    #[test]
    fn mixed_evidence_sources_are_rejected() {
        let record = |source| {
            serde_json::json!({"event":"trap","src":source,"trap":{"kind":"prose","text":"operator prose","stage":"review","accepted":true}}).to_string()
        };
        let text = format!("{}\n{}\n", record("192.0.2.1:1"), record("192.0.2.2:2"));
        assert_eq!(
            Trace::read(text.as_bytes()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let groups = Trace::read_grouped(text.as_bytes()).unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.values().all(|trace| trace.gates.len() == 1));
    }
}
