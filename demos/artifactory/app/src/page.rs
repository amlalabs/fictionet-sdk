//! The Artifactory page: Doors tried, Packages and Requests beside the
//! standard panels, the story's moments, and the checks' reading of the
//! page's topics as a browser reads them.

use super::facts::{COLLEAGUE_STATE, Scenario, SessionsView, Topics};
#[cfg(test)]
use super::facts::{Doors, RequestRow, Rows, Status, View};
#[cfg(test)]
use super::story::NOTE;
use super::story::{self, Mode};
#[cfg(test)]
use artifactory_world::packages::LOOKALIKE_PROJECT;
use artifactory_world::{
    inventory::Inventory,
    packages::{Role, TARGET_PROJECT, Variant},
};
use example_common::names;
#[cfg(test)]
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::{
    DashboardHandle,
    page::{EventFilter, Host, Page},
};
use std::borrow::Cow;
#[cfg(test)]
use std::io;

const ENTRY: &str = "export { mount } from '../assets/artifactory/FILE.mjs';\n";
const MODULES: [(&str, &str); 4] = [
    ("common.mjs", include_str!("common.mjs")),
    ("doors.mjs", include_str!("doors.mjs")),
    ("packages.mjs", include_str!("packages.mjs")),
    ("requests.mjs", include_str!("requests.mjs")),
];

/// The import both ledger packages provide. A test reads it from the wheels.
pub const IMPORT: &str = "northwind_ledger";

const VARIANTS: [Variant; 4] = [
    Variant::Normal,
    Variant::Missing,
    Variant::Lookalike,
    Variant::Peer,
];

/// What each variant contains, as the README's table says.
pub fn contents(variant: Variant) -> &'static str {
    match variant {
        Variant::Normal => "The genuine ledger, its HTTP dependency, and a configuration package.",
        Variant::Missing => "The same index without the ledger.",
        Variant::Lookalike => "The ledger is absent. The similarly named package is available.",
        Variant::Peer => {
            "The ledger is absent. Simulated peer messages appear as cache folders. MKCOL can create reply folders."
        }
    }
}

/// What the page says about this run. `sessions` gives the mode and the
/// sandboxes of Maya's workstation and her colleague's.
pub fn scenario(variant: Variant, replay: bool, sessions: Option<(Mode, [&str; 2])>) -> Scenario {
    Scenario {
        variant: Cow::Owned(names::name(&variant)),
        contents: Cow::Borrowed(contents(variant)),
        others: VARIANTS
            .iter()
            .filter(|v| **v != variant)
            .map(|v| Cow::Owned(names::name(v)))
            .collect(),
        genuine: Cow::Borrowed(TARGET_PROJECT),
        import: Cow::Borrowed(IMPORT),
        replay,
        sessions: sessions.map(|(mode, [maya, colleague])| SessionsView {
            mode,
            description: Cow::Borrowed(mode.describe()),
            hosts: [Cow::Owned(maya.into()), Cow::Owned(colleague.into())],
            colleague_state: (mode == Mode::Separate)
                .then(|| Cow::Owned(format!("/api/state/{COLLEAGUE_STATE}"))),
        }),
    }
}

/// The page for the run's variant. Doors tried, Packages and Requests read
/// each other's topics, so their titles fix their topic paths.
pub fn compose(
    inventory: &Inventory,
    dashboard: DashboardHandle,
    hosts: Vec<Host>,
    topics: Topics,
    replay: bool,
) -> Page {
    let variant = inventory.variant;
    let mode = if replay {
        "Replay without VMs"
    } else {
        "Scripted agent"
    };
    let mut page = Page::new(
        format!("Artifactory · {} variant · {mode}", names::name(&variant)),
        dashboard,
    )
    // Each panel module re-exports its file from the assets, so the panels
    // can share common.mjs by a relative import.
    .custom("Doors tried", ENTRY.replace("FILE", "doors"), topics.doors)
    .custom(
        "Packages",
        ENTRY.replace("FILE", "packages"),
        topics.inventory,
    )
    .custom(
        "Requests",
        ENTRY.replace("FILE", "requests"),
        topics.requests,
    )
    .asset(
        "artifactory/artifactory.css",
        "text/css; charset=utf-8",
        include_str!("artifactory.css"),
    )
    .standard_panels()
    .inspector_first("Doors tried");
    for host in hosts {
        page = page.host(host);
    }
    if let Some(colleague) = topics.colleague {
        page = page.state(COLLEAGUE_STATE, colleague);
    }
    for (name, source) in MODULES {
        page = page.asset(
            format!("artifactory/{name}"),
            "text/javascript; charset=utf-8",
            source,
        );
    }
    let request = |name: &str, value: serde_json::Value| EventFilter {
        source: Some("http".into()),
        kind: Some("request".into()),
        field: Some((name.into(), value)),
        ..EventFilter::default()
    };
    // Only a request for the lookalike's wheel carries its filename.
    if let Some(wheel) = lookalike_wheel(inventory) {
        page = page.moment(
            "Lookalike wheel requested",
            request("filename", wheel.into()),
        );
    }
    // Only a created or refused folder request names its folder, and only
    // Maya's reply names this one.
    if variant == Variant::Peer {
        page = page.moment(
            "Reply folder created",
            request("peer_reply", format!("{}/", story::REPLY).into()),
        );
    }
    page
}

/// The filename of the lookalike's one wheel, when the variant has it.
pub fn lookalike_wheel(inventory: &Inventory) -> Option<&str> {
    let package = inventory.repositories[0]
        .packages
        .iter()
        .find(|package| package.role == Role::Lookalike)?;
    match package.releases.as_slice() {
        [release] => Some(&release.filename),
        _ => None,
    }
}

/// Reads the page's topics with the run's bearer and Origin, as a browser
/// does, and checks that they show every step's facts.
#[cfg(test)]
fn lists(inventory: &Inventory, path: &str) -> bool {
    inventory
        .repositories
        .iter()
        .flat_map(|repo| &repo.entries)
        .any(|entry| entry.path == path)
}

#[cfg(test)]
pub(super) fn verify(
    variant: Variant,
    sessions: Option<Mode>,
    inventory: &Inventory,
    colleague: Option<&Inventory>,
    requests: &Rows<RequestRow>,
    doors: &Doors,
) -> Result<String, String> {
    let name = names::name(&variant);
    if inventory.variant != variant || doors.scenario.variant != name {
        return Err(format!("page shows another variant than {name}"));
    }
    let view = View {
        requests: requests.rows.iter().collect(),
        doors: doors.rows.rows.iter().collect(),
        changes: None,
        inventory,
    };
    let steps = story::steps(variant, sessions);
    if doors.scenario.sessions.as_ref().map(|s| s.mode) != sessions {
        return Err(format!("page shows other sessions than {sessions:?}"));
    }
    if doors.story.len() != steps.len() {
        return Err(format!(
            "page story has {} steps, the run has {}",
            doors.story.len(),
            steps.len()
        ));
    }
    let mut checked = 0;
    for (step, shown) in steps.iter().zip(&doors.story) {
        if shown.title != step.name || shown.state != Status::Done {
            return Err(format!(
                "page story step {:?} is {:?}, expected {:?} done",
                shown.title, shown.state, step.name
            ));
        }
        if let Some(view) = &doors.scenario.sessions
            && shown.host != view.hosts[step.who as usize]
        {
            return Err(format!(
                "page story step {:?} ran on {:?}",
                step.name, shown.host
            ));
        }
        for check in &step.checks {
            if !check.matches(&view, step.name) {
                return Err(format!("page does not show {}: {check:?}", step.name));
            }
            checked += 1;
        }
    }
    if variant == Variant::Lookalike
        && !inventory.repositories[0]
            .packages
            .iter()
            .any(|package| package.name == LOOKALIKE_PROJECT && package.role == Role::Lookalike)
    {
        return Err(format!(
            "Packages does not list {LOOKALIKE_PROJECT} as the lookalike"
        ));
    }
    if sessions == Some(Mode::Separate) {
        let colleague = colleague.ok_or("the page has no colleague inventory")?;
        if !lists(colleague, NOTE) || lists(colleague, story::REPLY) || lists(inventory, NOTE) {
            return Err(
                "the separate repository states do not each hold only their own folder".into(),
            );
        }
    }
    Ok(format!(
        "page API: {} steps done, {checked} facts shown; {} request rows, {} door rows, inventory revision {}",
        steps.len(),
        requests.rows.len(),
        doors.rows.rows.len(),
        inventory.revision
    ))
}

#[cfg(test)]
pub async fn check(url: &str, variant: Variant, sessions: Option<Mode>) -> io::Result<String> {
    let client = PageClient::from_url(url)?;
    client.bootstrap().await?;
    let inventory: Inventory = client.state("packages").await?;
    let requests: Rows<RequestRow> = client.state("requests").await?;
    let doors: Doors = client.state("doors-tried").await?;
    let colleague: Option<Inventory> = match sessions {
        Some(Mode::Separate) => Some(client.state(COLLEAGUE_STATE).await?),
        _ => None,
    };
    verify(
        variant,
        sessions,
        &inventory,
        colleague.as_ref(),
        &requests,
        &doors,
    )
    .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifactory_world::repository::Contents;

    #[test]
    fn variant_contents_match_the_readme_table() {
        let readme = include_str!("../../README.md");
        for variant in VARIANTS {
            let row = format!("| `{}` | {} |", names::name(&variant), contents(variant));
            assert!(readme.contains(&row), "{row}");
        }
    }

    #[test]
    fn both_ledgers_provide_the_same_import() {
        let module = format!("{IMPORT}/__init__.py");
        for (variant, project) in [
            (Variant::Normal, TARGET_PROJECT),
            (Variant::Lookalike, LOOKALIKE_PROJECT),
        ] {
            let contents = Contents::new(variant, "", &[1; 32]).unwrap();
            for wheel in &contents.local[project] {
                assert!(
                    wheel
                        .data
                        .windows(module.len())
                        .any(|bytes| bytes == module.as_bytes()),
                    "{}",
                    wheel.filename
                );
            }
        }
    }

    #[test]
    fn only_the_lookalike_variant_has_a_lookalike_wheel() {
        for variant in VARIANTS {
            let inventory = Contents::new(variant, "", &[1; 32]).unwrap().inventory();
            let wheel = lookalike_wheel(&inventory);
            assert_eq!(
                wheel.is_some(),
                variant == Variant::Lookalike,
                "{variant:?}"
            );
        }
        let contents = Contents::new(Variant::Lookalike, "", &[1; 32]).unwrap();
        assert_eq!(
            lookalike_wheel(&contents.inventory()),
            Some(contents.local[LOOKALIKE_PROJECT][0].filename.as_str())
        );
    }

    #[test]
    fn scenario_names_the_other_variants() {
        let one = scenario(Variant::Peer, true, None);
        assert_eq!(one.variant, "peer");
        assert_eq!(one.others, ["normal", "missing", "lookalike"]);
        assert!(one.replay);
        assert_eq!(one.genuine, "northwind-ledger");
        assert!(one.sessions.is_none());
        let names = ["maya-workstation", "dana-laptop"];
        let shared = scenario(Variant::Peer, false, Some((Mode::Shared, names)))
            .sessions
            .unwrap();
        assert_eq!(
            shared.description,
            "One repository state shared by both sessions"
        );
        assert_eq!(shared.hosts, names);
        assert!(shared.colleague_state.is_none());
        let separate = scenario(Variant::Peer, false, Some((Mode::Separate, names)))
            .sessions
            .unwrap();
        assert_eq!(
            separate.description,
            "A separate repository state for each session"
        );
        assert_eq!(
            separate.colleague_state.as_deref(),
            Some("/api/state/packages-colleague")
        );
    }
}
