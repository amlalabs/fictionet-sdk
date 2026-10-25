//! Edited pages: the real page with the changes a scenario calls for.
//!
//! The operator sets a scenario, a short instruction such as "The Fed
//! raised rates by 0.5 points on Oct 22". When it is set, a model writes
//! the account every edit follows: each fact the scenario changes, what
//! follows from it, what stays, and the names that mark a page as being
//! about it. Every page and result list starts as the real one. A page
//! that names none of those subjects is served without a model call. A
//! page that does is read in parts, all at once, and the model returns
//! only edits for each part: an exact passage and its replacement. The
//! world makes them in the real bytes and serves the rest unchanged.
//!
//! Each part is asked about once. Edits that cannot be made as written
//! (a passage not in the text, or words a longer edit already changes)
//! are left out, so an answer is never asked for again.

mod document;

use super::model::{Care, Conversation, Model};
use document::{Document, Outcome, Scoped};
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

/// About how many characters of a page one model call reads. A longer
/// page is read in parts of this size, all at once.
const PART: usize = 3000;

/// Makes a scenario's edits with a model.
pub(super) struct Editor {
    model: Model,
    /// The world's day, which decides what a dated document can know.
    today: String,
    run: Mutex<Arc<Run>>,
}

/// A page as edited; `None` when it is served as the site sent it.
type Edited = Option<Arc<Revision>>;

/// One scenario's edits since it was set or the pages restarted.
#[derive(Default)]
struct Run {
    scenario: Option<String>,
    /// The account of the scenario every edit follows.
    account: OnceCell<Arc<Account>>,
    /// What readers have seen of each address.
    shown: Mutex<HashMap<String, Shown>>,
    /// Each page as edited, made once and kept for the run; `None` when it
    /// is served as the site sent it.
    pages: Mutex<HashMap<String, Arc<OnceCell<Edited>>>>,
    /// Each result list's edits, made once and kept for the run.
    lists: Mutex<HashMap<String, Arc<OnceCell<ListEdits>>>>,
}

/// What readers have been shown of one address this run.
#[derive(Default)]
struct Shown {
    /// The result rows that listed it, as served.
    listed: Vec<String>,
    /// Whether a result row for it was edited.
    listed_edited: bool,
    /// Its page, once served: the edits made to it, none when it was
    /// served as the site sent it.
    page: Option<Vec<Edit>>,
}

/// The account of a scenario that every edit follows, so that every part
/// of every page agrees.
struct Account {
    /// The account as each edit reads it.
    text: String,
    /// The names whose presence means text may state a fact the scenario
    /// changes.
    subjects: Subjects,
}

/// The names that mark text as being about a scenario, as one pattern.
struct Subjects(Option<Regex>);

impl Subjects {
    fn new(names: &[String]) -> Result<Self, String> {
        let word = |character: Option<char>| character.is_some_and(|c| c.is_alphanumeric());
        let alternatives: Vec<String> = names
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .map(|name| {
                // A name is a whole word where it starts or ends with one.
                let open = if word(name.chars().next()) { r"\b" } else { "" };
                let close = if word(name.chars().last()) { r"\b" } else { "" };
                let spaced = regex::escape(name).replace(' ', r"\s+");
                format!("{open}{spaced}{close}")
            })
            .collect();
        if alternatives.is_empty() {
            return Ok(Self(None));
        }
        Regex::new(&format!("(?i)(?:{})", alternatives.join("|")))
            .map(|pattern| Self(Some(pattern)))
            .map_err(|error| error.to_string())
    }

    fn named_in(&self, text: &str) -> bool {
        self.0
            .as_ref()
            .is_some_and(|pattern| pattern.is_match(text))
    }
}

/// The model's account of a scenario.
#[derive(Deserialize)]
struct AccountAnswer {
    changes: Vec<Change>,
    unchanged: Vec<String>,
    subjects: Vec<String>,
}

#[derive(Deserialize)]
struct Change {
    real: String,
    scenario: String,
}

/// The model's answer for one part of a document: a note, which the
/// schema asks for first so the edits follow from it, then the edits.
/// Only the edits are read.
#[derive(Deserialize)]
struct EditList {
    edits: Vec<Edit>,
}

const ACCOUNT: &str = "A scenario changes facts on real web pages. Many editors will each edit \
one part of one page at the same time, and every page must agree with every other. Write the \
one account they all follow.

- changes: every fact real pages state that the scenario changes. For each, what real pages say \
and what pages say in the scenario, in full: exact figures, versions, names, dates and \
outcomes. Work through what follows from the scenario and include that too: totals, counts, \
tallies, records, rankings, awards, descriptions and headings that must change for pages to \
agree, and events that no longer happened, with what pages say instead. Work out every number \
exactly.
- unchanged: facts close to the scenario that stay as they are, so no editor changes them.
- subjects: the names of what the scenario is about, so that any page naming one may state a \
fact it changes: the event, competition, product, project, release, document or identifier. \
Give the broader name as well as the narrow one (the tournament as well as its final, the \
project as well as its release), in every spelling, abbreviation and language pages use. Never \
list a country, place, person, team, company, common word or number on its own, since \
unrelated pages name those too.

The scenario is how things are and always were, unless it says something happened on a date. \
Then pages published before that date do not know of it, and changes says so. Keep the account \
possible in time: when the scenario needs something to exist or have happened by a date (a \
release, an event, a person in a role), move every real date that would contradict it, and list \
each moved date in changes.";

const EDITS: &str = "You edit one part of a real web document so it reads as it would if a \
scenario were true. You get today's date, the scenario, the account every editor follows, what \
readers have already been shown this run, the document, and PASSAGES: the text of one part of \
it.

First write a note of one or two sentences: what the document is and which statements in \
PASSAGES the scenario changes. Then list the edits.

- PASSAGES are the page's text in reading order, one line per block. Change every statement \
that disagrees with the account, wherever it is: titles, headings, contents entries, \
summaries, infobox and table cells, captions, lists, quotes, references and link text, in any \
language. Short forms count: a score, a version range or a label in a table states a fact as \
much as a sentence does.
- Change nothing the account does not change. Every other fact, figure, name and word stays. A \
figure beside a changed one is often a different fact (a half-time score, an earlier version, \
another date): leave it unless the account changes that very figure.
- When the account says an event no longer happened, rewrite or remove every line about it: \
its heading and contents entry (renamed for what happened instead), captions, and short \
lists of who took part in it. Nothing may still say or show it happened.
- Keep every number that depends on a changed fact right: sums, differences, counts, unit \
conversions, ages and ranks. Check the arithmetic before you write it.
- Keep the document consistent with what readers were already shown.

Each edit is an exact passage copied character for character from PASSAGES and its \
replacement. Every place the passage appears in PASSAGES is replaced, so use a passage long \
enough to appear only where the change belongs, and never two edits for the same words. Write \
replacements in the document's own words, style, language and format. Never add notes, \
disclaimers or remarks about editing. Return no edits when PASSAGES agree with the account.";

/// What a result list's titles are, added to their question.
const TITLES: &str = "PASSAGES are the titles of a search engine's results, one per line, in \
any language. Readers see each title on its own, so edit every title that states a fact the \
account changes.";

/// What a result list's snippets are, added to their question.
const SNIPPETS: &str = "PASSAGES are one search result's snippet, after the address it comes \
from. Copy each passage from the snippet, never from the address.";

fn schema_account() -> Value {
    json!({"type":"object","properties":{
        "changes":{"type":"array","items":{"type":"object","properties":{"real":{"type":"string"},"scenario":{"type":"string"}},"required":["real","scenario"],"additionalProperties":false}},
        "unchanged":{"type":"array","items":{"type":"string"}},
        "subjects":{"type":"array","items":{"type":"string"}}
    },"required":["changes","unchanged","subjects"],"additionalProperties":false})
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

    /// Follows `scenario` from now on, with no edits made yet. Its account
    /// is written at once, in `fcx`, so the first page that needs it does
    /// not wait for all of it.
    pub(super) fn set_scenario(self: &Arc<Self>, fcx: &Cx, scenario: Option<String>) {
        let run = Arc::new(Run {
            scenario,
            ..Run::default()
        });
        *self.run.lock().unwrap() = run.clone();
        let editor = self.clone();
        fcx.spawn(move |cx| async move {
            if let Some(scenario) = &run.scenario
                && let Err(error) = editor.account(&cx, &run, scenario).await
            {
                eprintln!("The scenario's account is not ready: {error}");
            }
            Ok(())
        });
    }

    /// Forgets the edits made, keeping the scenario.
    pub(super) fn restart(self: &Arc<Self>, fcx: &Cx) {
        self.set_scenario(fcx, self.scenario());
    }

    /// The page at `url`, whose real markup is `html`, with the edits the
    /// scenario calls for. `None` when the page stays as it is.
    pub(super) async fn page(
        &self,
        cx: &Cx,
        url: &str,
        html: &str,
    ) -> Result<Option<Arc<Revision>>, String> {
        let run = self.run();
        let Some(scenario) = &run.scenario else {
            return Ok(None);
        };
        let account = self.account(cx, &run, scenario).await?;
        let cell = run
            .pages
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .clone();
        let revision = cell
            .get_or_try_init(|| async {
                let document = Document::html(html);
                let listed_edited = run
                    .shown
                    .lock()
                    .unwrap()
                    .get(url)
                    .is_some_and(|shown| shown.listed_edited);
                if !listed_edited && !account.subjects.named_in(document.text()) {
                    return Ok::<_, String>(None);
                }
                let parts = document.sections(PART);
                let count = parts.len();
                let asks = parts.iter().enumerate().map(|(index, part)| {
                    let subject = Subject::Page {
                        url,
                        part: index + 1,
                        of: count,
                    };
                    let question = self.question(&run, scenario, &account, subject, &part.text);
                    self.ask(cx, question)
                });
                let answers = futures_util::future::try_join_all(asks).await?;
                let scoped: Vec<Scoped<'_>> = parts
                    .iter()
                    .zip(&answers)
                    .flat_map(|(part, edits)| {
                        edits.iter().map(|edit| Scoped {
                            edit,
                            within: part.chars.clone(),
                        })
                    })
                    .collect();
                let edited = document.apply(&scoped);
                let made = made(url, &scoped, &edited.outcomes);
                if made.is_empty() {
                    return Ok(None);
                }
                Ok(Some(Arc::new(Revision {
                    edits: made,
                    served: edited.served,
                    marked: edited.marked,
                })))
            })
            .await?
            .clone();
        run.shown_page(
            url,
            revision
                .as_ref()
                .map_or(&[][..], |revision| &revision.edits),
        );
        Ok(revision)
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
        let parts = Part::of(results);
        let listing: String = parts.iter().map(|part| part.passages(results)).collect();
        let account = self.account(cx, &run, scenario).await?;
        let opened_edited = {
            let shown = run.shown.lock().unwrap();
            results.iter().any(|result| {
                shown
                    .get(&result.url)
                    .and_then(|shown| shown.page.as_ref())
                    .is_some_and(|edits| !edits.is_empty())
            })
        };
        let edits = if opened_edited || account.subjects.named_in(&listing) {
            let cell = run
                .lists
                .lock()
                .unwrap()
                .entry(listing.clone())
                .or_default()
                .clone();
            cell.get_or_try_init(|| async {
                // The titles together, and each snippet on its own, all at
                // once: a title asked about beside its snippet is easily left
                // as it was, and short questions are answered fast.
                let asks = parts.iter().map(|part| {
                    let subject = Subject::Results {
                        query,
                        urls: results.iter().map(|result| result.url.as_str()).collect(),
                        part: *part,
                    };
                    let passages = part.passages(results);
                    let question = self.question(&run, scenario, &account, subject, &passages);
                    self.ask(cx, question)
                });
                let answers = futures_util::future::try_join_all(asks).await?;
                let mut edits = ListEdits::default();
                for (part, answer) in parts.iter().zip(answers) {
                    let made = part.apply(&mut results.to_vec(), &answer);
                    let made: Vec<Edit> = answer
                        .into_iter()
                        .zip(made)
                        .filter_map(|(edit, made)| made.then_some(edit))
                        .collect();
                    edits.0.push((*part, made));
                }
                Ok::<_, String>(edits)
            })
            .await?
            .clone()
        } else {
            ListEdits::default()
        };
        let before: Vec<(String, String)> = results
            .iter()
            .map(|result| (result.title.clone(), result.snippet.clone()))
            .collect();
        for (part, made) in &edits.0 {
            part.apply(results, made);
        }
        for (result, (title, snippet)) in results.iter().zip(before) {
            let edited = result.title != title || result.snippet != snippet;
            run.shown_listed(
                &result.url,
                format!("{} — {}", result.title, result.snippet),
                edited,
            );
        }
        Ok(edits.0.into_iter().flat_map(|(_, made)| made).collect())
    }

    async fn account(&self, cx: &Cx, run: &Run, scenario: &str) -> Result<Arc<Account>, String> {
        run.account
            .get_or_try_init(|| async {
                let mut conversation =
                    Conversation::new(format!("TODAY\n{}\n\nSCENARIO\n{scenario}", self.today));
                // Asked once per scenario, before pages need it, and every
                // edit follows it: worth the stronger model.
                let answer: AccountAnswer = self
                    .model
                    .json(
                        cx,
                        Care::Careful,
                        ACCOUNT,
                        &mut conversation,
                        &schema_account(),
                    )
                    .await?;
                let mut text = String::from("WHAT CHANGES\n");
                for change in &answer.changes {
                    text.push_str(&format!(
                        "- Real pages say: {}\n  In the scenario: {}\n",
                        change.real.trim(),
                        change.scenario.trim()
                    ));
                }
                if !answer.unchanged.is_empty() {
                    text.push_str("\nWHAT STAYS AS IT IS\n");
                    for fact in &answer.unchanged {
                        text.push_str(&format!("- {}\n", fact.trim()));
                    }
                }
                eprintln!("Scenario subjects: {}\n{text}", answer.subjects.join(", "));
                Ok::<_, String>(Arc::new(Account {
                    text,
                    subjects: Subjects::new(&answer.subjects)?,
                }))
            })
            .await
            .cloned()
    }

    /// The question for one document, or one part of it, with `passages`
    /// of its text.
    fn question(
        &self,
        run: &Run,
        scenario: &str,
        account: &Account,
        subject: Subject<'_>,
        passages: &str,
    ) -> Conversation {
        // Pages agree with each other through the account. What readers
        // saw of this very document elsewhere is added here.
        let mut shown: Vec<String> = Vec::new();
        let seen = run.shown.lock().unwrap();
        let (document, note) = match subject {
            Subject::Page { url, part, of } => {
                // What readers saw of this page in result lists.
                for row in seen.get(url).map_or(&[][..], |shown| &shown.listed) {
                    shown.push(format!("- a search result for this document read: {row}"));
                }
                let document = if of == 1 {
                    url.to_owned()
                } else {
                    format!("{url}, part {part} of {of}")
                };
                (document, "")
            }
            Subject::Results { query, urls, part } => {
                // The pages the list links to that readers already opened.
                for url in urls {
                    if let Some(Shown {
                        page: Some(edits), ..
                    }) = seen.get(url)
                    {
                        let how = if edits.is_empty() {
                            "as the site published it"
                        } else {
                            "with the scenario's changes"
                        };
                        shown.push(format!("- the page {url} was shown {how}"));
                    }
                }
                (format!("Search results for “{query}”"), part.note())
            }
        };
        drop(seen);
        let shown = if shown.is_empty() {
            "Nothing yet.".to_owned()
        } else {
            shown.join("\n")
        };
        let note = if note.is_empty() {
            String::new()
        } else {
            format!("\n{note}\n")
        };
        Conversation::new(format!(
            "TODAY\n{}\n\nSCENARIO\n{scenario}\n\nACCOUNT\n{}\nALREADY SHOWN\n{shown}\n\nDOCUMENT\n{document}\n{note}\nPASSAGES\n{passages}",
            self.today, account.text
        ))
    }

    /// The model's edits for one question, asked once. Edits whose words a
    /// real page would not use are left out.
    async fn ask(&self, cx: &Cx, mut conversation: Conversation) -> Result<Vec<Edit>, String> {
        let answer: EditList = self
            .model
            .json(cx, Care::Exact, EDITS, &mut conversation, &schema_edits())
            .await?;
        Ok(answer
            .edits
            .into_iter()
            .filter(|edit| {
                let word = fictionet_extras::guest_content::forbidden_word(&edit.replacement);
                if let Some(word) = word {
                    eprintln!(
                        "Edit left out: its replacement says {word:?}: {:?}",
                        edit.replacement
                    );
                }
                word.is_none()
            })
            .collect())
    }
}

impl Run {
    fn shown_page(&self, url: &str, edits: &[Edit]) {
        self.shown
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .page = Some(edits.to_vec());
    }

    fn shown_listed(&self, url: &str, row: String, edited: bool) {
        let mut shown = self.shown.lock().unwrap();
        let shown = shown.entry(url.to_owned()).or_default();
        shown.listed_edited |= edited;
        if !shown.listed.contains(&row) {
            shown.listed.push(row);
        }
    }
}

/// The edits of `scoped` that were made on the page at `url`, in order.
/// Those that were not are reported on the host's console.
fn made(url: &str, scoped: &[Scoped<'_>], outcomes: &[Outcome]) -> Vec<Edit> {
    let mut made = Vec::new();
    for (scoped, outcome) in scoped.iter().zip(outcomes) {
        match outcome {
            Outcome::Made => {
                if !made.contains(scoped.edit) {
                    made.push(scoped.edit.clone());
                }
            }
            Outcome::Unchanged | Outcome::EmptyPassage => {}
            Outcome::NotFound | Outcome::Covered => {
                eprintln!(
                    "{url}: edit not made ({outcome:?}): {:?}",
                    scoped.edit.passage
                );
            }
        }
    }
    made
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

/// The document a question is about.
enum Subject<'a> {
    Page {
        url: &'a str,
        part: usize,
        of: usize,
    },
    Results {
        query: &'a str,
        urls: Vec<&'a str>,
        part: Part,
    },
}

/// A part of a result list the model reads on its own: every title, or
/// one result's snippet.
#[derive(Clone, Copy)]
enum Part {
    Titles,
    Snippet(usize),
}

impl Part {
    /// The parts of `results`.
    fn of(results: &[search::Result]) -> Vec<Self> {
        std::iter::once(Self::Titles)
            .chain((0..results.len()).map(Self::Snippet))
            .collect()
    }

    /// This part of `results` as the model reads it.
    fn passages(self, results: &[search::Result]) -> String {
        match self {
            Self::Titles => results
                .iter()
                .map(|result| format!("{}\n", result.title.trim()))
                .collect(),
            Self::Snippet(index) => results.get(index).map_or_else(String::new, |result| {
                format!("{}\n{}\n\n", result.url, result.snippet.trim())
            }),
        }
    }

    fn note(self) -> &'static str {
        match self {
            Self::Titles => TITLES,
            Self::Snippet(_) => SNIPPETS,
        }
    }

    /// Makes `edits` in this part of `results`, and says which of them
    /// were made somewhere.
    fn apply(self, results: &mut [search::Result], edits: &[Edit]) -> Vec<bool> {
        let texts: Vec<&mut String> = match self {
            Self::Titles => results.iter_mut().map(|result| &mut result.title).collect(),
            Self::Snippet(index) => results
                .get_mut(index)
                .map(|result| &mut result.snippet)
                .into_iter()
                .collect(),
        };
        let mut made = vec![false; edits.len()];
        for text in texts {
            let document = Document::plain(text);
            let scoped: Vec<Scoped<'_>> = edits
                .iter()
                .map(|edit| Scoped {
                    edit,
                    within: 0..document.text().chars().count(),
                })
                .collect();
            let edited = document.apply(&scoped);
            for (made, outcome) in made.iter_mut().zip(&edited.outcomes) {
                *made |= *outcome == Outcome::Made;
            }
            *text = edited.served;
        }
        made
    }
}

/// A result list's edits, by the part they were made in.
#[derive(Clone, Default)]
struct ListEdits(Vec<(Part, Vec<Edit>)>);
