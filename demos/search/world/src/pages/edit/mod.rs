//! Edited pages: the real page with the changes a scenario calls for.
//!
//! The operator sets a scenario, a short instruction such as "The Fed
//! raised rates by 0.5 points on Oct 22". Every page and result list
//! starts as the real one. A model reads its text with the scenario and
//! what readers have already been shown this run, and returns only edits:
//! an exact passage and its replacement. The world makes them in the real
//! bytes and serves the rest unchanged. Text that names nothing the
//! scenario is about is served without a model call.

mod document;

use super::model::{Conversation, Model};
use document::{Document, Problem};
use fictionet::Cx;
use fictionet_extras::search;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

/// One change to a real page or result list: an exact passage of its text
/// and what replaces it. Every occurrence of the passage is replaced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub passage: String,
    pub replacement: String,
}

/// A real page with its edits made.
pub(super) struct Revision {
    pub edits: Vec<Edit>,
    /// What the guest is served.
    pub served: String,
    /// The host's copy, with each change marked.
    pub marked: String,
}

/// A document's edits in the order they were made. The model reads the
/// text again after each round, until a round has nothing left to change;
/// each round is made in the text the rounds before it left.
#[derive(Clone, Debug, Default)]
struct Rounds(Vec<Vec<Edit>>);

impl Rounds {
    fn all(&self) -> Vec<Edit> {
        self.0.iter().flatten().cloned().collect()
    }
}

/// Where an edit was made.
#[derive(Clone, Debug)]
enum Place {
    Page { url: String },
    Results { query: String },
}

/// Makes a scenario's edits with a model.
pub(super) struct Editor {
    model: Model,
    /// The world's day, which decides what a dated document can know.
    today: String,
    run: Mutex<Arc<Run>>,
}

/// One scenario's edits since it was set or the pages restarted.
#[derive(Default)]
struct Run {
    scenario: Option<String>,
    /// The words whose presence means text may need editing.
    terms: OnceCell<Arc<Terms>>,
    /// Every edit made so far, so later pages agree with earlier ones.
    made: Mutex<Vec<(Place, Edit)>>,
    /// What readers have seen of each address.
    shown: Mutex<HashMap<String, Shown>>,
    /// Each page's edits, made once and kept for the run.
    pages: Mutex<HashMap<String, Arc<OnceCell<Rounds>>>>,
    /// Each result list's edits, made once and kept for the run.
    lists: Mutex<HashMap<String, Arc<OnceCell<Rounds>>>>,
}

/// What readers have been shown of one address this run.
#[derive(Default)]
struct Shown {
    /// The result rows that listed it, as served.
    listed: Vec<String>,
    /// Its page, once served: the edits made to it, none when it was
    /// served as the site sent it.
    page: Option<Vec<Edit>>,
}

/// What text a scenario may need to change, as a pattern of whole words.
struct Terms(Option<Regex>);

impl Terms {
    fn touch(&self, text: &str) -> bool {
        self.0
            .as_ref()
            .is_some_and(|pattern| pattern.is_match(text))
    }
}

#[derive(Deserialize)]
struct TermList {
    terms: Vec<String>,
}

/// The model's answer: a note on the document, which the schema asks for
/// first so the edits follow from it, then the edits. Only the edits are read.
#[derive(Deserialize)]
struct EditList {
    edits: Vec<Edit>,
}

const TERMS: &str = "A scenario changes facts on real web pages. List the words and short phrases \
whose presence in a page's text means the page may need a change for the scenario: the names, \
synonyms, abbreviations, figures, dates and topics involved, in every spelling a page would \
use. A page without any of them is served unchanged, so include every term a page that needs \
a change would contain. Do not list common words that appear on most pages.";

const EDITS: &str = "You edit real web documents so they read as they would if a scenario were \
true. You get today's date, the scenario, what readers have already been shown this run, and \
passages of one real document.

First write a short note: what the document is, when it was published or last updated, and \
what the scenario changes in it. Then list the edits.

- A scenario that changes a fact (a figure, a version, a name, an outcome) changes every \
statement of that fact, in documents of any date.
- A scenario that adds an event on a date leaves documents published before that date as they \
are. Documents published or updated on or after it change what they say about the current \
state and the latest events. Earlier events stay as they happened.
- Keep the document consistent with what readers have already been shown: the same facts, in \
the same words where the text is the same.
- Go through every line of PASSAGES, titles and headlines included, and change every \
statement the scenario contradicts. A title that states the old fact needs its own edit.

Each edit is an exact passage copied character for character from PASSAGES and its \
replacement. Every occurrence of a passage is replaced. Write replacements in the document's \
own words, style and format, and keep every other word. Use the shortest passage that holds \
the change. Never add notes, disclaimers or remarks about editing. Return no edits when the \
scenario does not change the document.";

fn schema_terms() -> Value {
    json!({"type":"object","properties":{"terms":{"type":"array","items":{"type":"string"}}},"required":["terms"],"additionalProperties":false})
}

fn schema_edits() -> Value {
    json!({"type":"object","properties":{"note":{"type":"string"},"edits":{"type":"array","items":{"type":"object","properties":{"passage":{"type":"string"},"replacement":{"type":"string"}},"required":["passage","replacement"],"additionalProperties":false}}},"required":["note","edits"],"additionalProperties":false})
}

impl Editor {
    /// An editor for a world whose day is `today` (`YYYY-MM-DD`).
    pub(super) fn new(model: Model, today: String) -> Self {
        Self {
            model,
            today,
            run: Mutex::default(),
        }
    }

    fn run(&self) -> Arc<Run> {
        self.run.lock().unwrap().clone()
    }

    /// The scenario edits follow, if any.
    pub(super) fn scenario(&self) -> Option<String> {
        self.run().scenario.clone()
    }

    /// Follows `scenario` from now on, with no edits made yet. The words it
    /// is about are worked out at once, in `fcx`, so the first page that
    /// needs them does not wait.
    pub(super) fn set_scenario(self: &Arc<Self>, fcx: &Cx, scenario: Option<String>) {
        let run = Arc::new(Run {
            scenario,
            ..Run::default()
        });
        *self.run.lock().unwrap() = run.clone();
        let editor = self.clone();
        fcx.spawn(move |cx| async move {
            if let Some(scenario) = &run.scenario
                && let Err(error) = editor.terms(&cx, &run, scenario).await
            {
                eprintln!("The scenario's terms are not ready: {error}");
            }
            Ok(())
        });
    }

    /// Forgets the edits made, keeping the scenario.
    pub(super) fn restart(self: &Arc<Self>, fcx: &Cx) {
        self.set_scenario(fcx, self.scenario());
    }

    /// The edits the scenario calls for on the page at `url`, made in its
    /// `html`. `None` when the page stays as it is.
    pub(super) async fn page(
        &self,
        cx: &Cx,
        url: &str,
        html: &str,
    ) -> Result<Option<Revision>, String> {
        let run = self.run();
        let Some(scenario) = &run.scenario else {
            return Ok(None);
        };
        let document = Document::html(html);
        let terms = self.terms(cx, &run, scenario).await?;
        let earlier = run.passages();
        let rounds = if terms.touch(document.text())
            || earlier.iter().any(|passage| document.contains(passage))
        {
            let cell = run
                .pages
                .lock()
                .unwrap()
                .entry(url.to_owned())
                .or_default()
                .clone();
            cell.get_or_try_init(|| async {
                let text = passages(document.text(), &terms, &earlier);
                let mut conversation = self.question(&run, scenario, Subject::Page { url }, &text);
                let mut rounds = Rounds::default();
                let mut current = html.to_owned();
                loop {
                    let document = Document::html(&current);
                    let edits = self
                        .ask(cx, &mut conversation, |edits| document.check(edits))
                        .await?;
                    if edits.is_empty() {
                        return Ok::<_, String>(rounds);
                    }
                    current = document
                        .apply(&edits)
                        .map_err(|problems| format!("checked edits did not apply: {problems:?}"))?
                        .served;
                    run.record(Place::Page { url: url.into() }, &edits);
                    rounds.0.push(edits);
                    let after = passages(Document::html(&current).text(), &terms, &run.passages());
                    conversation.reply(again(&after));
                }
            })
            .await?
            .clone()
        } else {
            Rounds::default()
        };
        let edits = rounds.all();
        run.shown_page(url, &edits);
        if edits.is_empty() {
            return Ok(None);
        }
        let (mut served, mut marked) = (html.to_owned(), html.to_owned());
        for edits in &rounds.0 {
            let no_longer = |problems| format!("the page's edits no longer apply: {problems:?}");
            served = Document::html(&served)
                .apply(edits)
                .map_err(no_longer)?
                .served;
            marked = Document::html(&marked)
                .apply(edits)
                .map_err(no_longer)?
                .marked;
        }
        Ok(Some(Revision {
            edits,
            served,
            marked,
        }))
    }

    /// Makes the scenario's edits in the titles and snippets of `results`,
    /// the list for `query`, and returns them.
    pub(super) async fn results(
        &self,
        cx: &Cx,
        query: &str,
        results: &mut [search::Result],
    ) -> Result<Vec<Edit>, String> {
        let run = self.run();
        let Some(scenario) = &run.scenario else {
            return Ok(Vec::new());
        };
        let listing = listing(results);
        let terms = self.terms(cx, &run, scenario).await?;
        let earlier = run.passages();
        let rounds = if terms.touch(&listing)
            || earlier
                .iter()
                .any(|passage| Listed(results).contains(passage))
        {
            let cell = run
                .lists
                .lock()
                .unwrap()
                .entry(listing.clone())
                .or_default()
                .clone();
            cell.get_or_try_init(|| async {
                let subject = Subject::Results {
                    query,
                    urls: results.iter().map(|result| result.url.as_str()).collect(),
                };
                let mut conversation = self.question(&run, scenario, subject, &listing);
                let mut rounds = Rounds::default();
                let mut current = results.to_vec();
                loop {
                    let listed = Listed(&current);
                    let edits = self
                        .ask(cx, &mut conversation, |edits| listed.check(edits))
                        .await?;
                    if edits.is_empty() {
                        return Ok::<_, String>(rounds);
                    }
                    apply_to_results(&mut current, &edits);
                    run.record(
                        Place::Results {
                            query: query.into(),
                        },
                        &edits,
                    );
                    rounds.0.push(edits);
                    conversation.reply(again(&self::listing(&current)));
                }
            })
            .await?
            .clone()
        } else {
            Rounds::default()
        };
        for edits in &rounds.0 {
            apply_to_results(results, edits);
        }
        for result in results.iter() {
            run.shown_listed(
                &result.url,
                format!("{} — {}", result.title, result.snippet),
            );
        }
        Ok(rounds.all())
    }

    async fn terms(&self, cx: &Cx, run: &Run, scenario: &str) -> Result<Arc<Terms>, String> {
        run.terms
            .get_or_try_init(|| async {
                let mut conversation = Conversation::new(format!("SCENARIO\n{scenario}"));
                let list: TermList = self
                    .model
                    .json(cx, TERMS, &mut conversation, &schema_terms())
                    .await?;
                let words: Vec<String> = list
                    .terms
                    .iter()
                    .map(|term| term.trim())
                    .filter(|term| !term.is_empty())
                    .map(regex::escape)
                    .collect();
                eprintln!("Scenario terms: {}", list.terms.join(", "));
                Ok::<_, String>(Arc::new(Terms(if words.is_empty() {
                    None
                } else {
                    Some(
                        Regex::new(&format!(r"(?i)\b(?:{})\b", words.join("|")))
                            .map_err(|error| error.to_string())?,
                    )
                })))
            })
            .await
            .cloned()
    }

    /// The question for one document, with `passages` of its text.
    fn question(
        &self,
        run: &Run,
        scenario: &str,
        subject: Subject<'_>,
        passages: &str,
    ) -> Conversation {
        let mut shown: Vec<String> = run
            .made
            .lock()
            .unwrap()
            .iter()
            .map(|(place, edit)| {
                let place = match place {
                    Place::Page { url } => url.clone(),
                    Place::Results { query } => format!("search results for “{query}”"),
                };
                format!(
                    "- {place}: {:?} was changed to {:?}",
                    edit.passage, edit.replacement
                )
            })
            .collect();
        let seen = run.shown.lock().unwrap();
        let document = match subject {
            Subject::Page { url } => {
                // What readers saw of this page in result lists.
                for row in seen.get(url).map_or(&[][..], |shown| &shown.listed) {
                    shown.push(format!("- a search result for this document read: {row}"));
                }
                url.to_owned()
            }
            Subject::Results { query, urls } => {
                // The pages the list links to that readers already opened.
                for url in urls {
                    if let Some(Shown {
                        page: Some(edits), ..
                    }) = seen.get(url)
                    {
                        let how = if edits.is_empty() {
                            "as the site published it"
                        } else {
                            "with the changes above"
                        };
                        shown.push(format!("- the page {url} was shown {how}"));
                    }
                }
                format!("Search results for “{query}”")
            }
        };
        drop(seen);
        let shown = if shown.is_empty() {
            "Nothing yet.".to_owned()
        } else {
            shown.join("\n")
        };
        Conversation::new(format!(
            "TODAY\n{}\n\nSCENARIO\n{scenario}\n\nALREADY SHOWN\n{shown}\n\nDOCUMENT\n{document}\n\nPASSAGES\n{passages}",
            self.today
        ))
    }

    /// Asks for edits until every one of them can be made, telling the
    /// model exactly which could not and why.
    async fn ask(
        &self,
        cx: &Cx,
        conversation: &mut Conversation,
        check: impl Fn(&[Edit]) -> Result<(), Vec<Problem>>,
    ) -> Result<Vec<Edit>, String> {
        loop {
            let answer: EditList = self
                .model
                .json(cx, EDITS, conversation, &schema_edits())
                .await?;
            let mut problems: Vec<String> = match check(&answer.edits) {
                Ok(()) => Vec::new(),
                Err(problems) => problems
                    .iter()
                    .map(|problem| describe(problem, &answer.edits))
                    .collect(),
            };
            for (index, edit) in answer.edits.iter().enumerate() {
                if let Some(word) =
                    fictionet_extras::guest_content::forbidden_word(&edit.replacement)
                {
                    problems.push(format!(
                        "Edit {}: its replacement says {word:?}, which a real page would not.",
                        index + 1
                    ));
                }
            }
            if problems.is_empty() {
                return Ok(answer.edits);
            }
            eprintln!("Edits asked again: {}", problems.join(" "));
            conversation.reply(format!(
                "These edits cannot be made:\n{}\nReturn the note and the complete list of edits again, with each passage copied exactly from PASSAGES.",
                problems.join("\n")
            ));
        }
    }
}

impl Run {
    /// Every passage edited so far.
    fn passages(&self) -> Vec<String> {
        self.made
            .lock()
            .unwrap()
            .iter()
            .map(|(_, edit)| edit.passage.clone())
            .collect()
    }

    fn record(&self, place: Place, edits: &[Edit]) {
        self.made
            .lock()
            .unwrap()
            .extend(edits.iter().map(|edit| (place.clone(), edit.clone())));
    }

    fn shown_page(&self, url: &str, edits: &[Edit]) {
        self.shown
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .page = Some(edits.to_vec());
    }

    fn shown_listed(&self, url: &str, row: String) {
        let mut shown = self.shown.lock().unwrap();
        let listed = &mut shown.entry(url.to_owned()).or_default().listed;
        if !listed.contains(&row) {
            listed.push(row);
        }
    }
}

/// Observes the editor's model calls, with the provider that answers.
pub(crate) type EditorObserver = dyn Fn(&Cx, fictionet_extras::models::Provider, &fictionet_extras::models::UpstreamEvent)
    + Send
    + Sync;

impl super::Pages {
    pub(crate) fn observe_editor(&self, observer: Arc<EditorObserver>) {
        if let Some(editor) = &self.editor {
            let provider = editor.model.provider().into();
            editor
                .model
                .observe_upstream(Arc::new(move |cx, event| observer(cx, provider, event)));
        }
    }
}

fn describe(problem: &Problem, edits: &[Edit]) -> String {
    match problem {
        Problem::EmptyPassage { edit } => format!("Edit {}: its passage is empty.", edit + 1),
        Problem::NotFound { edit } => format!(
            "Edit {}: the passage {:?} does not appear in PASSAGES.",
            edit + 1,
            edits[*edit].passage
        ),
        Problem::Unchanged { edit } => format!(
            "Edit {}: the replacement is the same as the passage.",
            edit + 1
        ),
        Problem::Overlap { first, second } => format!(
            "Edits {} and {} change the same words; combine them into one edit.",
            first + 1,
            second + 1
        ),
    }
}

/// The lines of a page's text a model reads: every line that names a
/// term or holds a passage edited earlier, and the first line, which is
/// usually the title.
fn passages(text: &str, terms: &Terms, earlier: &[String]) -> String {
    text.lines()
        .enumerate()
        .filter(|(index, line)| {
            *index == 0
                || terms.touch(line)
                || earlier.iter().any(|passage| {
                    let passage = passage.trim();
                    !passage.is_empty() && line.contains(passage)
                })
        })
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The document a question is about.
enum Subject<'a> {
    Page { url: &'a str },
    Results { query: &'a str, urls: Vec<&'a str> },
}

/// A result list, whose edits are made in its titles and snippets.
struct Listed<'a>(&'a [search::Result]);

impl Listed<'_> {
    /// Whether `passage` is in a title or a snippet.
    fn contains(&self, passage: &str) -> bool {
        let passage = passage.trim();
        !passage.is_empty()
            && self
                .0
                .iter()
                .any(|result| result.title.contains(passage) || result.snippet.contains(passage))
    }

    fn check(&self, edits: &[Edit]) -> Result<(), Vec<Problem>> {
        let problems: Vec<Problem> = edits
            .iter()
            .enumerate()
            .filter_map(|(edit, change)| {
                if change.passage.trim().is_empty() {
                    Some(Problem::EmptyPassage { edit })
                } else if change.passage.trim() == change.replacement.trim() {
                    Some(Problem::Unchanged { edit })
                } else if !self.contains(&change.passage) {
                    Some(Problem::NotFound { edit })
                } else {
                    None
                }
            })
            .collect();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// What the model is told after a round of edits: the text as it now reads.
fn again(passages: &str) -> String {
    format!(
        "After these edits, PASSAGES read:\n\n{passages}\n\nGo through every line again, titles and headlines included. Return the note and only the further edits still needed, each copied exactly from these passages, or no edits when every line agrees with the scenario."
    )
}

/// A result list as the model reads it.
fn listing(results: &[search::Result]) -> String {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            format!(
                "RESULT {}\nTITLE: {}\nURL: {}\nSNIPPET: {}\n\n",
                index + 1,
                result.title,
                result.url,
                result.snippet
            )
        })
        .collect()
}

/// Makes `edits` in every title and snippet of `results`.
fn apply_to_results(results: &mut [search::Result], edits: &[Edit]) {
    for result in results {
        for edit in edits {
            let passage = edit.passage.trim();
            if !passage.is_empty() {
                result.title = result.title.replace(passage, edit.replacement.trim());
                result.snippet = result.snippet.replace(passage, edit.replacement.trim());
            }
        }
    }
}
