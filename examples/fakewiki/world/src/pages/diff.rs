//! Side-by-side source text from the embedded corpus and one tampering snapshot.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Version, array, canonical, corpus, norm, s, sentences};
use crate::tamper::{Scope, TamperState};

/// Maximum compact JSON size built from this corpus, including maximum revision and time.
pub const MAX_DIFF_BYTES: usize = 64 * 1024;

/// Source text and the versions served at a captured revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diff {
    /// The captured tampering revision.
    pub revision: u64,
    /// Run time of the captured state's last change.
    pub since_start: Duration,
    /// Whether tampering is on.
    pub on: bool,
    /// The sources selected for tampering.
    pub scope: Scope,
    /// Topics in corpus order.
    pub topics: Vec<TopicDiff>,
}

/// Both claims and their source documents for one topic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicDiff {
    /// The corpus topic name.
    pub topic: String,
    /// The accurate claim from the corpus.
    pub true_claim: String,
    /// The false claim from the corpus.
    pub false_claim: String,
    /// Sources in the accurate stance's corpus order.
    pub sources: Vec<SourceDiff>,
}

/// Both versions of one source, with the selected version labeled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDiff {
    /// The corpus source name.
    pub source: String,
    /// The source's canonical URL.
    pub url: String,
    /// The version served under this snapshot's source policy.
    pub served: Version,
    /// The accurate source document.
    pub real: Text,
    /// The source document carrying the false claim.
    pub tampered: Text,
}

/// A source title and its readable text in page order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Text {
    /// The source document's title.
    pub title: String,
    /// Paragraphs split into sentences. Headings and infobox rows stay whole.
    pub paragraphs: Vec<Vec<Segment>>,
}

/// One sentence, heading or infobox row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// The original corpus text.
    pub text: String,
    /// Whether its normalized text is absent from the other version.
    pub changed: bool,
}

impl Diff {
    /// Builds both text versions from the corpus and copies the state's revision and time.
    /// The size bound covers this constructor's output, not arbitrary caller edits.
    pub fn new(state: TamperState) -> Self {
        let topics = corpus()
            .topics
            .as_object()
            .unwrap()
            .iter()
            .map(|(topic, data)| {
                let sources = data["stances"]["accurate"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(source, real)| {
                        let mut real = Text::from_document(source, real);
                        let mut tampered =
                            Text::from_document(source, &data["stances"]["altered"][source]);
                        let real_sentences = real.normalized();
                        let tampered_sentences = tampered.normalized();
                        real.mark(&tampered_sentences);
                        tampered.mark(&real_sentences);
                        SourceDiff {
                            source: source.clone(),
                            url: canonical(topic, source).into(),
                            served: Version::for_source(state.variant(), source),
                            real,
                            tampered,
                        }
                    })
                    .collect();
                TopicDiff {
                    topic: topic.clone(),
                    true_claim: s(&data["true_claim"]).into(),
                    false_claim: s(&data["false_claim"]).into(),
                    sources,
                }
            })
            .collect();
        Self {
            revision: state.revision,
            since_start: state.since_start,
            on: state.on,
            scope: state.scope,
            topics,
        }
    }
}

impl Text {
    fn from_document(source: &str, document: &Value) -> Self {
        let mut text = Self {
            title: s(&document["title"]).into(),
            paragraphs: Vec::new(),
        };
        let mut push = |value: &str, whole: bool| {
            if !value.is_empty() {
                text.paragraphs.push(
                    if whole { vec![value] } else { sentences(value) }
                        .into_iter()
                        .map(|sentence| Segment {
                            text: sentence.into(),
                            changed: false,
                        })
                        .collect(),
                );
            }
        };
        match source {
            "wikipedia" => {
                push(s(&document["short_description"]), false);
                if !document["infobox"].is_null() {
                    for row in array(&document["infobox"]["rows"]) {
                        push(&format!("{}: {}", s(&row[0]), s(&row[1])), true);
                    }
                }
                for paragraph in array(&document["lead"]) {
                    push(s(paragraph), false);
                }
                for section in array(&document["sections"]) {
                    push(s(&section["heading"]), true);
                    for paragraph in array(&section["paras"]) {
                        push(s(paragraph), false);
                    }
                }
            }
            "legislation" => {
                push(s(&document["heading"]), true);
                push(s(&document["status"]), false);
                for paragraph in array(&document["text"]) {
                    push(s(paragraph), false);
                }
                let act = &document["act"];
                if !act.is_null() {
                    push(s(&act["title"]), true);
                    push(s(&act["citation"]), false);
                    for section in array(&act["sections"]) {
                        push(s(section), false);
                    }
                }
            }
            _ => {
                push(s(&document["lead"]), false);
                for block in array(&document["blocks"]) {
                    push(s(&block["h"]), true);
                    for paragraph in array(&block["paras"]) {
                        push(s(paragraph), false);
                    }
                }
            }
        }
        text
    }

    fn normalized(&self) -> HashSet<String> {
        self.paragraphs
            .iter()
            .flatten()
            .map(|segment| norm(&segment.text).trim().to_owned())
            .collect()
    }

    fn mark(&mut self, other: &HashSet<String>) {
        for segment in self.paragraphs.iter_mut().flatten() {
            segment.changed = !other.contains(norm(&segment.text).trim());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(on: bool, scope: Scope) -> TamperState {
        TamperState {
            revision: u64::MAX,
            since_start: Duration::MAX,
            on,
            scope,
        }
    }

    #[test]
    fn claims_and_shared_sentences_are_marked() {
        let diff = Diff::new(state(true, Scope::Wikipedia));
        for (topic, real_fact, false_fact) in [
            (
                "tv_licence",
                "a television licence is required",
                "was abolished on 1 April 2026",
            ),
            ("stream_ripping", "quashed", "fully legal"),
            (
                "apollo11",
                "first landed humans on the Moon",
                "first landed humans on Mars",
            ),
        ] {
            let topic = diff.topics.iter().find(|t| t.topic == topic).unwrap();
            let wiki = topic
                .sources
                .iter()
                .find(|s| s.source == "wikipedia")
                .unwrap();
            for (text, fact) in [(&wiki.real, real_fact), (&wiki.tampered, false_fact)] {
                assert!(
                    text.paragraphs
                        .iter()
                        .flatten()
                        .any(|s| s.changed && s.text.contains(fact)),
                    "{fact}"
                );
            }
            let unchanged: Vec<_> = wiki
                .real
                .paragraphs
                .iter()
                .flatten()
                .filter(|s| !s.changed)
                .collect();
            assert!(!unchanged.is_empty(), "{}", topic.topic);
            for segment in unchanged {
                assert!(
                    wiki.tampered
                        .paragraphs
                        .iter()
                        .flatten()
                        .any(|other| other == segment)
                );
            }
        }
    }

    #[test]
    fn projection_preserves_order_and_source_policy() {
        for scope in [Scope::Wikipedia, Scope::AllSources] {
            for on in [false, true] {
                let state = state(on, scope);
                let diff = Diff::new(state);
                assert_eq!(
                    (diff.revision, diff.since_start, diff.on, diff.scope),
                    (state.revision, state.since_start, on, scope)
                );
                assert_eq!(
                    diff.topics
                        .iter()
                        .map(|t| t.topic.as_str())
                        .collect::<Vec<_>>(),
                    ["tv_licence", "stream_ripping", "apollo11"]
                );
                for topic in &diff.topics {
                    let data = &corpus().topics[&topic.topic];
                    assert_eq!(topic.true_claim, data["true_claim"]);
                    assert_eq!(topic.false_claim, data["false_claim"]);
                    assert_eq!(
                        topic
                            .sources
                            .iter()
                            .map(|s| s.source.as_str())
                            .collect::<Vec<_>>(),
                        data["stances"]["accurate"]
                            .as_object()
                            .unwrap()
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                    );
                    for source in &topic.sources {
                        let expected =
                            if on && (scope == Scope::AllSources || source.source == "wikipedia") {
                                Version::Tampered
                            } else {
                                Version::Real
                            };
                        assert_eq!(source.served, expected);
                        assert_eq!(source.url, canonical(&topic.topic, &source.source));
                        for (text, other) in [
                            (&source.real, &source.tampered),
                            (&source.tampered, &source.real),
                        ] {
                            let other = other.normalized();
                            for segment in text.paragraphs.iter().flatten() {
                                assert_eq!(
                                    segment.changed,
                                    !other.contains(norm(&segment.text).trim())
                                );
                            }
                        }
                    }
                }
                let json = serde_json::to_vec(&diff).unwrap();
                eprintln!(
                    "Diff {scope:?} on={on}: {} bytes (bound {MAX_DIFF_BYTES})",
                    json.len()
                );
                assert!(json.len() <= MAX_DIFF_BYTES);
                assert_eq!(serde_json::from_slice::<Diff>(&json).unwrap(), diff);
            }
        }
    }

    #[test]
    fn text_follows_page_order_and_keeps_rows_whole() {
        let diff = Diff::new(state(false, Scope::Wikipedia));
        let tv = &diff.topics[0];
        let wiki = &tv.sources[0];
        let data = &corpus().topics["tv_licence"]["stances"]["accurate"]["wikipedia"];
        assert_eq!(wiki.real.paragraphs[0][0].text, data["short_description"]);
        let rows = array(&data["infobox"]["rows"]);
        for (paragraph, row) in wiki.real.paragraphs[1..].iter().zip(rows) {
            assert_eq!(paragraph.len(), 1);
            assert_eq!(paragraph[0].text, format!("{}: {}", s(&row[0]), s(&row[1])));
        }
        assert_eq!(
            wiki.real.paragraphs[rows.len() + 1][0].text,
            sentences(s(&data["lead"][0]))[0]
        );
        let law = tv
            .sources
            .iter()
            .find(|s| s.source == "legislation")
            .unwrap();
        let data = &corpus().topics["tv_licence"]["stances"]["altered"]["legislation"];
        assert_eq!(law.tampered.paragraphs[0][0].text, data["heading"]);
        let act = &data["act"];
        let title = law
            .tampered
            .paragraphs
            .iter()
            .position(|p| p[0].text == s(&act["title"]))
            .unwrap();
        assert_eq!(law.tampered.paragraphs[title].len(), 1);
        assert_eq!(
            law.tampered.paragraphs[title + 1]
                .iter()
                .map(|s| s.text.as_str())
                .collect::<Vec<_>>(),
            sentences(s(&act["citation"]))
        );
        assert_eq!(
            law.tampered
                .paragraphs
                .last()
                .unwrap()
                .iter()
                .map(|s| s.text.as_str())
                .collect::<Vec<_>>(),
            sentences(s(array(&act["sections"]).last().unwrap()))
        );
        assert!(
            !law.real
                .paragraphs
                .iter()
                .flatten()
                .any(|s| s.text == act["title"])
        );
    }
}
