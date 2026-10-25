//! Edited pages: the real page with the changes a scenario calls for.
//!
//! The operator sets a scenario, a short instruction such as "The Fed
//! raised rates by 0.5 points on Oct 22". When it is set, a model names
//! the scenario's subjects, the names that mark a document as being about
//! it, and writes the account every edit follows: each fact the scenario
//! changes, what follows from it, what stays, and the facts the changes
//! must not contradict. Every page, data file and result list starts as
//! the real one. One that names none of the subjects is served without a
//! model call, and without waiting for the account. A data file names them
//! the way data does, as well: a project in its address, keys or values,
//! with the version or item the scenario is about. One that does is read
//! in parts, all at once, and the model returns only edits for each part:
//! an exact passage and its replacement. The world makes them in the real
//! bytes and serves the rest unchanged.
//!
//! Each part is asked about once, and each result title and snippet once
//! per run, so the same text is edited the same way wherever it appears.
//! Edits that cannot be made as written (a passage not in the text, or
//! words a longer edit already changes) are left out, so an answer is
//! never asked for again.

mod document;
mod literal;

use super::model::{Care, Conversation, Model};
pub(super) use document::Format;
use document::{Document, Outcome, Scoped};
use fictionet::Cx;
use fictionet_extras::search;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{OnceCell, watch};

/// One change to a real page or result list: an exact passage of its text
/// and what replaces it. Every occurrence of the passage is replaced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub passage: String,
    pub replacement: String,
}

/// The scenario Edited follows, and whether its account is written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scenario {
    pub text: String,
    pub readiness: Readiness,
}

/// How far the scenario's account is along. Until it is ready, documents
/// that name the scenario's subjects wait for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Readiness {
    Preparing,
    Ready,
    /// The account could not be written; the next document that needs it
    /// asks again.
    Failed {
        error: String,
    },
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
    /// The scenario and its readiness, as they change.
    scenario: watch::Sender<Option<Scenario>>,
}

/// A page as edited; `None` when it is served as the site sent it.
type Edited = Option<Arc<Revision>>;

/// One scenario's edits since it was set or the pages restarted.
#[derive(Default)]
struct Run {
    scenario: Option<String>,
    /// Where the scenario's subjects and account are being asked for:
    /// cancelled when another scenario is set, so a cleared scenario asks
    /// nothing more.
    preparing: Mutex<Option<Cx>>,
    /// The names that mark a document as being about the scenario, asked
    /// for first, so documents that name none need not wait for the account.
    subjects: OnceCell<Arc<Subjects>>,
    /// The account of the scenario every edit follows.
    account: OnceCell<Arc<Account>>,
    /// What readers have seen of each address.
    shown: Mutex<HashMap<String, Shown>>,
    /// Each page as edited, made once and kept for the run; `None` when it
    /// is served as the site sent it.
    pages: Mutex<HashMap<String, Arc<OnceCell<Edited>>>>,
    /// The edits made to each result title, by its text.
    titles: Mutex<HashMap<String, Arc<Vec<Edit>>>>,
    /// The edits made to each result snippet, by its text.
    snippets: Mutex<HashMap<String, Arc<OnceCell<Vec<Edit>>>>>,
    /// What each passage edited this run became, by the passage as the
    /// search compares it: the same words are edited the same way wherever
    /// they appear.
    decided: Mutex<HashMap<String, String>>,
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
    /// The subjects the account names, with those named first.
    subjects: Subjects,
}

/// The names that mark text as being about a scenario, as one pattern,
/// and how data files and addresses write them.
struct Subjects {
    names: Option<Regex>,
    data: DataNames,
}

/// How data files and web addresses write a scenario's subjects: the
/// projects (`django`, `openssl`) and, when the scenario is about one
/// version or item of them, that item as data writes it on its own (`v5`,
/// `3.0`).
/// Data names its subject this way, in its address, keys and values, and
/// seldom by the names pages use.
#[derive(Default)]
struct DataNames {
    projects: Vec<String>,
    items: Vec<String>,
}

impl DataNames {
    fn new(projects: &[String], items: &[String]) -> Self {
        let words = |names: &[String]| -> Vec<String> {
            names
                .iter()
                .map(|name| name.trim().to_lowercase())
                .filter(|name| !name.is_empty())
                .collect()
        };
        Self {
            projects: words(projects),
            items: words(items),
        }
    }

    /// Whether `text` (an address with a data file's text) names one of
    /// the projects and, when there are items, one of those.
    fn named_in(&self, text: &str) -> bool {
        let text = text.to_lowercase();
        let any = |names: &[String]| names.iter().any(|name| whole_word(&text, name));
        any(&self.projects) && (self.items.is_empty() || any(&self.items))
    }
}

/// Whether `name` appears in `text` with no letter or digit right before
/// or after it.
fn whole_word(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, found)| {
        let before = text[..at].chars().next_back();
        let after = text[at + found.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

impl Subjects {
    fn new(names: &[String], data: DataNames) -> Result<Self, String> {
        let word = |character: Option<char>| character.is_some_and(|c| c.is_alphanumeric());
        let mut alternatives: Vec<String> = names
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
        alternatives.sort();
        alternatives.dedup();
        let names = if alternatives.is_empty() {
            None
        } else {
            let pattern = Regex::new(&format!("(?i)(?:{})", alternatives.join("|")))
                .map_err(|error| error.to_string())?;
            Some(pattern)
        };
        Ok(Self { names, data })
    }

    /// Whether `text`, the text of the document at `address` (with its
    /// format) if it has one, is about the subjects: a page names one, and
    /// a data file names one or names them the way data does.
    fn named_in(&self, text: &str, address: Option<(&str, Format)>) -> bool {
        self.names
            .as_ref()
            .is_some_and(|pattern| pattern.is_match(text))
            || address.is_some_and(|(url, format)| {
                format != Format::Html && self.data.named_in(&format!("{url}\n{text}"))
            })
    }
}

/// The model's subjects for a scenario.
#[derive(Deserialize)]
struct SubjectsAnswer {
    subjects: Vec<String>,
    projects: Vec<String>,
    items: Vec<String>,
}

/// The model's account of a scenario.
#[derive(Deserialize)]
struct AccountAnswer {
    changes: Vec<Change>,
    conflicts: Vec<Conflict>,
    unchanged: Vec<String>,
    subjects: Vec<String>,
}

#[derive(Deserialize)]
struct Change {
    real: String,
    scenario: String,
}

#[derive(Deserialize)]
struct Conflict {
    fixed: String,
    pages_say: String,
}

/// The model's answer for one part of a document: a note, which the
/// schema asks for first so the edits follow from it, then the edits.
/// Only the edits are read.
#[derive(Deserialize)]
struct EditList {
    edits: Vec<Edit>,
}

/// How subjects are chosen, for both questions that name them.
const SUBJECT_RULES: &str = "subjects: the names of what the scenario is about, so that any \
page naming one may state a fact it changes: the event, competition, product, project, release, \
document, building or identifier. Give the broader name as well as the narrow one (the \
tournament as well as its final, the project as well as its release), in every spelling, \
abbreviation and language pages use. Never list a country, place, person, team, company, \
common word or number on its own, since unrelated pages name those too.";

const SUBJECTS: &str = "A scenario changes facts on real web pages and data files. Before \
anything else, the world needs to know which pages and files may be about it. List the \
scenario's subjects, and how data names them.";

/// How data files name a scenario's subjects, asked with the subjects.
const DATA_NAMES: &str = "- projects: the names data files and web addresses use for what \
the scenario is about, as they write them in paths, keys and values: the package, project, \
product, distribution or article name and its slugs (django, python-django, openssl, debian, \
Eiffel_Tower). Data files (JSON from an API, a project's schedule file, raw wikitext) \
seldom use the names pages use. Never list a common word (release, schedule, dist, api, lts), \
a file name or a website on its own.
- items: when the scenario is about one version, release line, edition or item of a project, \
that item as data writes it on its own, in every form (5, v5, 5.x and the codename for a \
release line; 3.0.2 for a version; 12 and bookworm for a distribution release). Leave this empty \
when the scenario is about the whole of its subject.";

const ACCOUNT: &str = "A scenario changes facts on real web pages. Many editors will each edit \
one part of one page at the same time, and every page must agree with every other and with \
history that the scenario leaves alone. Write the one account they all follow.

- changes: every fact real pages state that the scenario changes. For each, what real pages say \
and what pages say in the scenario, in full: exact figures, versions, names, dates and \
outcomes. Work through what follows from the scenario and include that too: totals, counts, \
tallies, records, rankings, awards, descriptions and headings that must change for pages to \
agree; events that no longer happened, with what pages say instead; and what readers are told \
to do (steps, sign-ups, eligibility, prices, instructions) that no longer applies or now \
applies, with what pages say instead. Pages write a range's end both as the first value \
past it and as the last value in it (fixed in 2.0, affects versions up to 1.9.3); when the end \
moves, give both forms. Work out every number exactly. When pages will need a value the \
scenario implies but does not give (the version number and date of a release that now \
happens, a new total, a new deadline), decide it here, once and exactly, from the real values \
around it (the next number after the real latest release, say), so that every page gives the \
same one. When the scenario says something goes on (releases, updates, payments), decide the \
items pages published by today would list: each one's number, date and contents. Change only what the scenario states or strictly requires.
- conflicts: true facts the changes collide with, which stay true. Moving a date or changing a \
fact can make other statements impossible: a person who no longer held an office or role at \
the new date, a building, work or event dated before the new date that copied, followed, \
answered or competed with the subject, an anniversary or record counted from the old date, an \
event that no longer includes the subject. Those other facts never move. An event that really \
happened (a celebration, a walk, a report) keeps its real date and its sources even when the \
scenario changes what it marked: pages describe it without the label that no longer fits (the \
1990 festival rather than the centenary festival), and never move it to a new date. \
For each, give the \
fixed fact and how pages put it so that both stay true: name who held an office at the new \
date only when certain, and otherwise leave the name out; say what an earlier structure is \
without calling it a copy; take the subject out of an event it is no longer part of. Leave out \
anything you are not sure of.
- unchanged: facts close to the scenario that stay as they are, so no editor changes them. \
Include the facts pages state beside the subject that look like it but are about something \
else, each with its real values: other advisories, vulnerabilities and fixes of the same \
project, other releases and versions, other events at the same place. Include that sources \
(news reports, books, papers, archived pages) keep their own titles and publication dates.
- ";

const TIMING: &str = "

The scenario is how things are and always were, unless it says something happened on a date. \
Then pages published before that date do not know of it, and changes says so. Keep the account \
possible in time: when the scenario needs something to exist or have happened by a date (a \
release, an event, a person in a role), move every real date of the subject that would \
contradict it, list each moved date in changes, and list in conflicts what the move collides \
with.";

const EDITS: &str = "You edit one part of a real web document so it reads as it would if a \
scenario were true. You get today's date, the scenario, the account every editor follows, what \
readers have already been shown this run, the document, and PASSAGES: the text of one part of \
it.

First write a note of one or two sentences: what the document is and which statements in \
PASSAGES the scenario changes. Then list the edits.

- PASSAGES are the document's text in reading order, one line per block. Change every \
statement that disagrees with the account, wherever it is: titles, headings, contents entries, \
summaries, infobox and table cells, captions, lists, quotes, references and link text, in any \
language. Short forms count: a score, a version range or a label in a table states a fact as \
much as a sentence does. Ranges count too: when the account moves where a range ends (affected \
versions, a period of validity), change every statement of that end however it is written \
(`< 2.0`, `before 2.0`, `until 2019`), including a last affected version given in place of the first \
fixed one (`up to 1.9.3` when the fix was 2.0), which moves with the fix.
- Some lines are values from data in the document (JSON, or the data in a page's scripts), \
each after the names of the keys that hold it and a colon, like `release.date: 2019-04-01` or \
`v5.lts: true`. The names say what the value is, and the lines around it what it belongs to. \
Edit only the value; a passage may start with the names to tell equal values apart. An edit \
changes one value, and its passage never reaches past that value's line: values cannot be \
added, removed or joined. A value may be text, a number, true or false; write a number, true \
or false as it is.
- A text file (Markdown, wikitext, a changelog) keeps its markup: copy it exactly in passages \
and write replacements in the same markup.
- Change a table row, list item or line where it is, cell by cell. Never remove one to write \
it again somewhere else (a release moving from one table to another): only edits to PASSAGES \
are made, so what is removed is lost. A document may show the same fact more than once (a \
table repeated for small screens, a summary and its details, the page's text and its source \
data): change every one the same way.
- Change nothing the account does not change. Every other fact, figure, name and word stays. A \
figure beside a changed one is often a different fact (a half-time score, an earlier version, \
another date): leave it unless the account changes that very figure. A statement about \
something else that names the subject (another advisory, vulnerability, fix, release or event \
of the same project or place) keeps its own versions and dates unless the account changes \
that very thing.
- Use only values the account gives. Never make up a value it does not give (a version \
number, a date, a figure, a name), and never add an item carrying one (a release, a version in \
a list, a row); when a statement would need one, write it without that value.
- References and citations record other works: a cited work's title or headline, author, \
publisher, publication date, archive date and access date never change unless the account \
changes that work itself. A title in quotation marks or italics in a reference, a citation \
template's fields (|title=, |date=, |access-date=, |archive-date=) and a link's text naming \
another work stay word for word, even when they name the subject or a changed fact. Body text keeps agreeing with its sources: an event the account \
leaves at its real date keeps that date in the text too.
- When a change would make another statement in PASSAGES false or impossible (an earlier \
event, building or work tied to the old fact, a person acting in a role at the new date), \
rewrite that statement so it stays true, as the account's conflicts say, together with the \
sentences around it that make the same claim (an introduction that names it as an example of \
the subject's influence, say). Never write a sentence in which something happens before what \
it depends on, or a person acts in a role they did not hold then.
- A date that is not the subject's own (another work, person or event) stays as it is unless \
the account changes it or it now comes before something it depends on. Never shift such a \
date to keep its distance from a changed one.
- When the account says an event no longer happened, or the subject is no longer part of an \
event, rewrite or remove every line about it: its heading and contents entry (renamed for what \
happened instead), captions, and short lists of who took part in it. Never give it a new date \
on that event's page. Nothing may still say or show it happened.
- When the account says a step, sign-up, requirement or instruction no longer applies, rewrite \
or remove every passage that tells readers to do it, so none is left beside its replacement.
- Keep every number that depends on a changed fact right: sums, differences, counts, unit \
conversions, ages and ranks. Check the arithmetic before you write it.
- Keep the document consistent with what readers were already shown.

Each edit is an exact passage copied character for character from PASSAGES and its \
replacement. Write characters as they appear, never as escapes such as \\u2013 or &ndash;. \
Every place the passage appears in PASSAGES is replaced, so use a passage long enough to \
appear only where the change belongs, and never two edits for the same words. Write \
replacements in the document's own words, style, language and format. Never add notes, \
disclaimers or remarks about editing. Return no edits when PASSAGES agree with the account.";

/// What a result list's titles are, added to their question.
const TITLES: &str = "PASSAGES are titles of a search engine's results, one per line, in \
any language. Readers see each title on its own, so edit every title that states a fact the \
account changes.";

/// What a result list's snippets are, added to their question.
const SNIPPETS: &str = "PASSAGES are one search result's snippet, after the address it comes \
from. Copy each passage from the snippet, never from the address.";

fn schema_subjects() -> Value {
    json!({"type":"object","properties":{
        "subjects":{"type":"array","items":{"type":"string"}},
        "projects":{"type":"array","items":{"type":"string"}},
        "items":{"type":"array","items":{"type":"string"}}
    },"required":["subjects","projects","items"],"additionalProperties":false})
}

fn schema_account() -> Value {
    json!({"type":"object","properties":{
        "changes":{"type":"array","items":{"type":"object","properties":{"real":{"type":"string"},"scenario":{"type":"string"}},"required":["real","scenario"],"additionalProperties":false}},
        "conflicts":{"type":"array","items":{"type":"object","properties":{"fixed":{"type":"string"},"pages_say":{"type":"string"}},"required":["fixed","pages_say"],"additionalProperties":false}},
        "unchanged":{"type":"array","items":{"type":"string"}},
        "subjects":{"type":"array","items":{"type":"string"}}
    },"required":["changes","conflicts","unchanged","subjects"],"additionalProperties":false})
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
            scenario: watch::channel(None).0,
        }
    }

    fn run(&self) -> Arc<Run> {
        self.run.lock().unwrap().clone()
    }

    /// Whether `run` is the one in force.
    fn current(&self, run: &Run) -> bool {
        std::ptr::eq(Arc::as_ptr(&self.run()), run)
    }

    /// The scenario edits follow, if any, and its readiness.
    pub(super) fn scenario(&self) -> Option<Scenario> {
        self.scenario.borrow().clone()
    }

    /// The scenario and its readiness, as they change.
    pub(super) fn changes(&self) -> watch::Receiver<Option<Scenario>> {
        self.scenario.subscribe()
    }

    fn ready(&self, run: &Run, readiness: Readiness) {
        if self.current(run) {
            self.scenario.send_if_modified(|scenario| match scenario {
                Some(scenario) if scenario.readiness != readiness => {
                    scenario.readiness = readiness;
                    true
                }
                _ => false,
            });
        }
    }

    /// Follows `scenario` from now on, with no edits made yet. Its
    /// subjects and account are asked for at once, in `fcx`, so the first
    /// document that needs them does not wait for all of it.
    pub(super) fn set_scenario(self: &Arc<Self>, fcx: &Cx, scenario: Option<String>) {
        let run = Arc::new(Run {
            scenario: scenario.clone(),
            ..Run::default()
        });
        let previous = std::mem::replace(&mut *self.run.lock().unwrap(), run.clone());
        if let Some(preparing) = previous.preparing.lock().unwrap().take() {
            preparing.cancel();
        }
        self.scenario.send_replace(scenario.map(|text| Scenario {
            text,
            readiness: Readiness::Preparing,
        }));
        let Some(scenario) = run.scenario.clone() else {
            return;
        };
        let editor = self.clone();
        fcx.spawn(move |cx| async move {
            cx.region(|cx| async move {
                *run.preparing.lock().unwrap() = Some(cx.clone());
                // Another scenario may have been set before this began.
                if !editor.current(&run) {
                    return Ok(());
                }
                let (subjects, account) = futures_util::future::join(
                    editor.subjects(&cx, &run, &scenario),
                    editor.account(&cx, &run, &scenario),
                )
                .await;
                if let Err(error) = subjects.and(account)
                    && editor.current(&run)
                {
                    eprintln!("The scenario's account is not ready: {error}");
                    editor.ready(&run, Readiness::Failed { error });
                }
                Ok(())
            })
            .await
        });
    }

    /// Forgets the edits made, keeping the scenario.
    pub(super) fn restart(self: &Arc<Self>, fcx: &Cx) {
        self.set_scenario(fcx, self.run().scenario.clone());
    }

    /// The document at `url`, whose real text `source` is written in
    /// `format`, with the edits the scenario calls for. `None` when it
    /// stays as it is.
    pub(super) async fn page(
        &self,
        cx: &Cx,
        url: &str,
        source: &str,
        format: Format,
    ) -> Result<Option<Arc<Revision>>, String> {
        let run = self.run();
        let Some(scenario) = &run.scenario else {
            return Ok(None);
        };
        let cell = run
            .pages
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .clone();
        let revision = cell
            .get_or_try_init(|| async {
                let document = Document::new(source, format);
                let listed_edited = run
                    .shown
                    .lock()
                    .unwrap()
                    .get(url)
                    .is_some_and(|shown| shown.listed_edited);
                let address = Some((url, format));
                if !listed_edited
                    && !self
                        .about(cx, &run, scenario, document.text(), address)
                        .await?
                {
                    return Ok::<_, String>(None);
                }
                let account = self.account(cx, &run, scenario).await?;
                let parts = document.sections(PART);
                let count = parts.len();
                let asks = parts.iter().enumerate().map(|(index, part)| {
                    let subject = Subject::Page {
                        url,
                        format,
                        part: index + 1,
                        of: count,
                    };
                    let question = self.question(&run, scenario, &account, subject, &part.text);
                    async {
                        let answer = self.ask(cx, question).await?;
                        Ok::<_, String>(run.settle(answer))
                    }
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
                report_unmade(url, &scoped, &edited.outcomes);
                if edited.changes.is_empty() {
                    return Ok(None);
                }
                if format == Format::Json
                    && serde_json::from_str::<serde::de::IgnoredAny>(&edited.served).is_err()
                {
                    eprintln!("{url}: the edited data is not valid JSON; it is served as it was");
                    return Ok(None);
                }
                // Only an HTML page is shown with its changes marked.
                let marked = if format == Format::Html {
                    edited.marked
                } else {
                    edited.served.clone()
                };
                Ok(Some(Arc::new(Revision {
                    edits: edited.changes,
                    served: edited.served,
                    marked,
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
    /// the list for `query`, and returns them. Each title and snippet is
    /// edited once per run and the same way in every list that shows it.
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
        let listing: String = Part::of(results)
            .iter()
            .map(|part| part.passages(results))
            .collect();
        let opened_edited = {
            let shown = run.shown.lock().unwrap();
            results.iter().any(|result| {
                shown
                    .get(&result.url)
                    .and_then(|shown| shown.page.as_ref())
                    .is_some_and(|edits| !edits.is_empty())
            })
        };
        let account = if opened_edited || self.about(cx, &run, scenario, &listing, None).await? {
            Some(self.account(cx, &run, scenario).await?)
        } else {
            None
        };
        // The results as the questions read them; they are edited after.
        let rows: &[search::Result] = results;
        let urls: Vec<&str> = rows.iter().map(|result| result.url.as_str()).collect();
        // The titles not yet edited, together: a title asked about beside
        // its snippet is easily left as it was. Each snippet on its own.
        // All at once, since short questions are answered fast.
        let titles = async {
            let Some(account) = &account else {
                return Ok::<_, String>(());
            };
            let mut unknown: Vec<String> = {
                let known = run.titles.lock().unwrap();
                rows.iter()
                    .map(|result| result.title.trim().to_owned())
                    .filter(|title| !title.is_empty() && !known.contains_key(title))
                    .collect()
            };
            unknown.sort();
            unknown.dedup();
            if unknown.is_empty() {
                return Ok(());
            }
            let subject = Subject::Results {
                query,
                urls: urls.clone(),
                part: Part::Titles,
            };
            let passages: String = unknown.iter().map(|title| format!("{title}\n")).collect();
            let question = self.question(&run, scenario, account, subject, &passages);
            let answer = run.settle(self.ask(cx, question).await?);
            let mut used = vec![false; answer.len()];
            let mut made_for = Vec::new();
            for title in unknown {
                let mut edits = answer.clone();
                edits.extend(run.known_in(&title, &answer));
                let made = made_in(&title, &edits);
                made_for.push((title, made));
            }
            let mut known = run.titles.lock().unwrap();
            for (title, made) in made_for {
                for (used, edit) in used.iter_mut().zip(&answer) {
                    *used |= made.contains(edit);
                }
                known.entry(title).or_insert_with(|| Arc::new(made));
            }
            for (edit, _) in answer.iter().zip(used).filter(|(_, used)| !used) {
                eprintln!(
                    "Results for {query:?}: title edit not made: {:?}",
                    edit.passage
                );
            }
            Ok(())
        };
        let snippets = rows.iter().enumerate().map(|(index, result)| {
            let cell = run
                .snippets
                .lock()
                .unwrap()
                .entry(result.snippet.trim().to_owned())
                .or_default()
                .clone();
            let account = account.clone();
            let urls = urls.clone();
            let run = &run;
            async move {
                let Some(account) = account else {
                    return Ok::<_, String>(cell.get().cloned().unwrap_or_default());
                };
                cell.get_or_try_init(|| async {
                    let part = Part::Snippet(index);
                    let subject = Subject::Results { query, urls, part };
                    let passages = part.passages(rows);
                    let question = self.question(run, scenario, &account, subject, &passages);
                    let mut answer = run.settle(self.ask(cx, question).await?);
                    answer.extend(run.known_in(result.snippet.trim(), &answer));
                    let made = made_in(result.snippet.trim(), &answer);
                    for edit in answer.iter().filter(|edit| !made.contains(edit)) {
                        eprintln!("{}: snippet edit not made: {:?}", result.url, edit.passage);
                    }
                    Ok(made)
                })
                .await
                .cloned()
            }
        });
        let ((), snippets) =
            futures_util::future::try_join(titles, futures_util::future::try_join_all(snippets))
                .await?;
        let titles: Vec<Arc<Vec<Edit>>> = {
            let known = run.titles.lock().unwrap();
            results
                .iter()
                .map(|result| known.get(result.title.trim()).cloned().unwrap_or_default())
                .collect()
        };
        let mut edits: Vec<Edit> = Vec::new();
        for ((result, title), snippet) in results.iter_mut().zip(titles).zip(snippets) {
            let before = (result.title.clone(), result.snippet.clone());
            result.title = applied(&result.title, &title);
            result.snippet = applied(&result.snippet, &snippet);
            for edit in title.iter().chain(&snippet) {
                if !edits.contains(edit) {
                    edits.push(edit.clone());
                }
            }
            let edited = (result.title.clone(), result.snippet.clone()) != before;
            run.shown_listed(
                &result.url,
                format!("{} — {}", result.title, result.snippet),
                edited,
            );
        }
        Ok(edits)
    }

    /// Whether `text`, of the document at `address` if it has one, names
    /// the scenario's subjects. Only those asked for first are waited for;
    /// those the account adds count once it is ready.
    async fn about(
        &self,
        cx: &Cx,
        run: &Run,
        scenario: &str,
        text: &str,
        address: Option<(&str, Format)>,
    ) -> Result<bool, String> {
        let subjects = self.subjects(cx, run, scenario).await?;
        Ok(subjects.named_in(text, address)
            || run
                .account
                .get()
                .is_some_and(|account| account.subjects.named_in(text, None)))
    }

    async fn subjects(&self, cx: &Cx, run: &Run, scenario: &str) -> Result<Arc<Subjects>, String> {
        run.subjects
            .get_or_try_init(|| async {
                let mut conversation =
                    Conversation::new(format!("TODAY\n{}\n\nSCENARIO\n{scenario}", self.today));
                let answer: SubjectsAnswer = self
                    .model
                    .json(
                        cx,
                        Care::Exact,
                        &format!("{SUBJECTS}\n\n- {SUBJECT_RULES}\n{DATA_NAMES}"),
                        &mut conversation,
                        &schema_subjects(),
                    )
                    .await?;
                eprintln!(
                    "Scenario subjects: {}; in data: {} with {}",
                    answer.subjects.join(", "),
                    answer.projects.join(", "),
                    answer.items.join(", ")
                );
                let data = DataNames::new(&answer.projects, &answer.items);
                Ok::<_, String>(Arc::new(Subjects::new(&answer.subjects, data)?))
            })
            .await
            .cloned()
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
                        &format!("{ACCOUNT}{SUBJECT_RULES}{TIMING}"),
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
                if !answer.conflicts.is_empty() {
                    text.push_str("\nWHAT MUST STAY TRUE\n");
                    for conflict in &answer.conflicts {
                        text.push_str(&format!(
                            "- Fixed: {}\n  Pages put it this way: {}\n",
                            conflict.fixed.trim(),
                            conflict.pages_say.trim()
                        ));
                    }
                }
                if !answer.unchanged.is_empty() {
                    text.push_str("\nWHAT STAYS AS IT IS\n");
                    for fact in &answer.unchanged {
                        text.push_str(&format!("- {}\n", fact.trim()));
                    }
                }
                eprintln!(
                    "Scenario account, with subjects: {}\n{text}",
                    answer.subjects.join(", ")
                );
                Ok::<_, String>(Arc::new(Account {
                    text,
                    subjects: Subjects::new(&answer.subjects, DataNames::default())?,
                }))
            })
            .await
            .cloned()
            .inspect(|_| self.ready(run, Readiness::Ready))
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
            Subject::Page {
                url,
                format,
                part,
                of,
            } => {
                // What readers saw of this page in result lists.
                for row in seen.get(url).map_or(&[][..], |shown| &shown.listed) {
                    shown.push(format!("- a search result for this document read: {row}"));
                }
                let kind = match format {
                    Format::Html | Format::Line => "",
                    Format::Json => " (JSON data)",
                    Format::Text => " (a text file)",
                    Format::Xml => " (XML)",
                };
                let document = if of == 1 {
                    format!("{url}{kind}")
                } else {
                    format!("{url}{kind}, part {part} of {of}")
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

    /// `answer` with each passage edited earlier this run made as it was
    /// then; its new passages are decided now.
    fn settle(&self, answer: Vec<Edit>) -> Vec<Edit> {
        let mut decided = self.decided.lock().unwrap();
        answer
            .into_iter()
            .map(|edit| {
                if document::normalized(&edit.passage) == document::normalized(&edit.replacement) {
                    return edit;
                }
                let replacement = decided
                    .entry(document::normalized(&edit.passage))
                    .or_insert_with(|| edit.replacement.clone())
                    .clone();
                Edit {
                    passage: edit.passage,
                    replacement,
                }
            })
            .collect()
    }

    /// The passages of several words edited earlier this run that `text`
    /// holds and `edits` leave alone, made as they were then.
    fn known_in(&self, text: &str, edits: &[Edit]) -> Vec<Edit> {
        let text = document::normalized(text);
        let asked: Vec<String> = edits
            .iter()
            .map(|edit| document::normalized(&edit.passage))
            .collect();
        self.decided
            .lock()
            .unwrap()
            .iter()
            .filter(|(passage, _)| {
                passage.split_whitespace().count() >= 3
                    && text.contains(passage.as_str())
                    && !asked.contains(passage)
            })
            .map(|(passage, replacement)| Edit {
                passage: passage.clone(),
                replacement: replacement.clone(),
            })
            .collect()
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

/// Reports on the host's console the edits of `scoped` that could not be
/// made on the page at `url`.
fn report_unmade(url: &str, scoped: &[Scoped<'_>], outcomes: &[Outcome]) {
    for (scoped, outcome) in scoped.iter().zip(outcomes) {
        match outcome {
            Outcome::Made | Outcome::Unchanged | Outcome::EmptyPassage => {}
            Outcome::NotFound | Outcome::Covered | Outcome::Lines => {
                eprintln!(
                    "{url}: edit not made ({outcome:?}): {:?}",
                    scoped.edit.passage
                );
            }
        }
    }
}

/// The edits of `edits` that change the line `text`.
fn made_in(text: &str, edits: &[Edit]) -> Vec<Edit> {
    let document = Document::new(text, Format::Line);
    let scoped: Vec<Scoped<'_>> = edits
        .iter()
        .map(|edit| Scoped {
            edit,
            within: 0..document.text().chars().count(),
        })
        .collect();
    let outcomes = document.apply(&scoped).outcomes;
    edits
        .iter()
        .zip(outcomes)
        .filter(|(_, outcome)| *outcome == Outcome::Made)
        .map(|(edit, _)| edit.clone())
        .collect()
}

/// The line `text` with `edits` made.
fn applied(text: &str, edits: &[Edit]) -> String {
    if edits.is_empty() {
        return text.to_owned();
    }
    let document = Document::new(text, Format::Line);
    let scoped: Vec<Scoped<'_>> = edits
        .iter()
        .map(|edit| Scoped {
            edit,
            within: 0..document.text().chars().count(),
        })
        .collect();
    document.apply(&scoped).served
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
        format: Format,
        part: usize,
        of: usize,
    },
    Results {
        query: &'a str,
        urls: Vec<&'a str>,
        part: Part,
    },
}

/// A part of a result list the model reads on its own: titles, or one
/// result's snippet.
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
}
