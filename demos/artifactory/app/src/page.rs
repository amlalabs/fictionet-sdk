//! App-owned package, request, door and story views, with typed snapshots
//! and the shared kit's screen and terminal transports.

use super::facts::{COLLEAGUE_STATE, Scenario, SessionsView, Topics};
#[cfg(test)]
use super::facts::{Doors, RequestRow, Rows, Status, View};
use super::story::Mode;
#[cfg(test)]
use super::story::{self, NOTE};
use artifactory_world::packages::{TARGET_PROJECT, Variant};
#[cfg(test)]
use artifactory_world::{
    inventory::Inventory,
    packages::{LOOKALIKE_PROJECT, Role},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, WebSocketUpgrade},
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::get,
};
use fictionet_demo::kit::page as consoles;
use std::{borrow::Cow, io, sync::Arc};

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
        variant: Cow::Borrowed(variant.as_str()),
        contents: Cow::Borrowed(contents(variant)),
        others: VARIANTS
            .iter()
            .filter(|v| **v != variant)
            .map(|v| Cow::Borrowed(v.as_str()))
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

/// A console connected to one workstation or the preview screen.
#[derive(Clone)]
pub struct Host {
    pub name: String,
    pub console: Arc<dyn consoles::Console>,
}

fn topic<T: Clone + serde::Serialize + Send + Sync + 'static>(
    path: &str,
    topic: tokio::sync::watch::Sender<T>,
) -> Router {
    let snapshots = topic.subscribe();
    Router::new()
        .route(
            path,
            get(move || {
                let topic = topic.clone();
                async move { Json(topic.borrow().clone()) }
            }),
        )
        .nest(path, fictionet::stdlib::page::state(snapshots))
}

fn router(topics: Topics, hosts: Vec<Host>) -> Router {
    let host_names: Vec<_> = hosts.iter().map(|host| host.name.clone()).collect();
    let hosts = Arc::new(hosts);
    let mut app = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route(
            "/app.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    include_str!("app.mjs"),
                )
            }),
        )
        .route(
            "/common.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    include_str!("common.mjs"),
                )
            }),
        )
        .route(
            "/packages.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    include_str!("packages.mjs"),
                )
            }),
        )
        .route(
            "/doors.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    include_str!("doors.mjs"),
                )
            }),
        )
        .route(
            "/screen.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    fictionet::stdlib::page::SCREEN,
                )
            }),
        )
        .route(
            "/terminal.mjs",
            get(|| async {
                (
                    [("content-type", "text/javascript")],
                    fictionet::stdlib::page::TERMINAL,
                )
            }),
        )
        .route(
            "/api/hosts",
            get(move || {
                let names = host_names.clone();
                async move { Json(names) }
            }),
        )
        .route(
            "/console/{host}/{kind}",
            get(
                move |Path((host, kind)): Path<(String, String)>, upgrade: WebSocketUpgrade| {
                    let hosts = hosts.clone();
                    async move {
                        let Some(host) = hosts.iter().find(|candidate| candidate.name == host)
                        else {
                            return http::StatusCode::NOT_FOUND.into_response();
                        };
                        if !matches!(kind.as_str(), "screen" | "terminal") {
                            return http::StatusCode::NOT_FOUND.into_response();
                        }
                        consoles::upgrade(upgrade, host.console.clone(), kind == "screen").await
                    }
                },
            ),
        )
        .merge(topic("/api/packages", topics.inventory))
        .merge(topic("/api/requests", topics.requests))
        .merge(topic("/api/doors", topics.doors))
        .merge(consoles::libraries());
    if let Some(colleague) = topics.colleague {
        app = app.merge(topic(&format!("/api/state/{COLLEAGUE_STATE}"), colleague));
    }
    app
}

/// Serves the app's typed projections and the kit's console components.
/// The fragment token protects data and console routes; it is never sent when
/// loading the document. Browser requests must also have this page's origin.
pub async fn serve(topics: Topics, hosts: Vec<Host>, port: u16) -> io::Result<Server> {
    let listener = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await
    {
        Err(error) if error.kind() == io::ErrorKind::AddrInUse && port != 0 => {
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?
        }
        result => result?,
    };
    let authority = listener.local_addr()?.to_string();
    let origin = format!("http://{authority}");
    let token = fictionet_demo::kit::random_uuid();
    let url = format!("{origin}/#token={token}");
    let app = router(topics, hosts).layer(middleware::from_fn(
        move |request: http::Request<Body>, next: Next| {
            let (token, origin, authority) = (token.clone(), origin.clone(), authority.clone());
            async move {
                let headers = request.headers();
                if headers
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    != Some(authority.as_str())
                    || headers
                        .get(http::header::ORIGIN)
                        .is_some_and(|h| h != origin.as_str())
                {
                    return http::StatusCode::FORBIDDEN.into_response();
                }
                if request.uri().path().starts_with("/api/")
                    || request.uri().path().starts_with("/console/")
                {
                    let bearer = headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| h.strip_prefix("Bearer "));
                    let query = request.uri().query().and_then(|query| {
                        query
                            .split('&')
                            .find_map(|part| part.strip_prefix("token="))
                    });
                    if bearer.or(query) != Some(token.as_str()) {
                        return http::StatusCode::UNAUTHORIZED.into_response();
                    }
                }
                next.run(request).await
            }
        },
    ));
    let task = tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(Server { url, task })
}

pub struct Server {
    url: String,
    task: tokio::task::JoinHandle<io::Result<()>>,
}
impl Server {
    pub fn url(&self) -> &str {
        &self.url
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
pub async fn read<T: serde::de::DeserializeOwned>(url: &str, path: &str) -> io::Result<T> {
    use fictionet::stdlib::web::Upstream;
    use http_body_util::BodyExt;
    let (origin, token) = url
        .split_once("/#token=")
        .ok_or_else(|| io::Error::other("page URL has no access token"))?;
    let request = http::Request::get(format!("{origin}{path}"))
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(http::header::ORIGIN, origin)
        .body(fictionet::stdlib::web::httpd::Body::empty())
        .map_err(io::Error::other)?;
    let response = Arc::new(fictionet_host::Client::new())
        .request(request)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "page returned {}",
            response.status()
        )));
    }
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

/// The filename of the lookalike's one wheel, when the variant has it.
#[cfg(test)]
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
    let name = variant.as_str();
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
    let inventory: Inventory = read(url, "/api/packages").await?;
    let requests: Rows<RequestRow> = read(url, "/api/requests").await?;
    let doors: Doors = read(url, "/api/doors").await?;
    let colleague: Option<Inventory> = match sessions {
        Some(Mode::Separate) => Some(read(url, &format!("/api/state/{COLLEAGUE_STATE}")).await?),
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

    #[tokio::test]
    async fn page_data_requires_its_token_and_origin() {
        use fictionet::stdlib::web::Upstream;
        let contents = Contents::new(Variant::Normal, "", &[1; 32]).unwrap();
        let inventory = contents.inventory();
        let facts = super::super::facts::Facts::new(
            inventory.clone(),
            None,
            scenario(Variant::Normal, true, None),
            ["replay", "colleague"],
        );
        let page = serve(facts.topics.clone(), vec![], 0).await.unwrap();
        let (origin, token) = page.url().split_once("/#token=").unwrap();
        let client = Arc::new(fictionet_host::Client::new());
        for (bearer, origin_header) in [(None, origin), (Some(token), "http://other.invalid")] {
            let mut request = http::Request::get(format!("{origin}/api/packages"))
                .header(http::header::ORIGIN, origin_header);
            if let Some(token) = bearer {
                request = request.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = client
                .clone()
                .request(
                    request
                        .body(fictionet::stdlib::web::httpd::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response.status().is_client_error());
        }
        let received: Inventory = read(page.url(), "/api/packages").await.unwrap();
        assert_eq!(received, inventory);
    }

    #[test]
    fn variant_contents_match_the_readme_table() {
        let readme = include_str!("../../README.md");
        for variant in VARIANTS {
            let row = format!("| `{}` | {} |", variant.as_str(), contents(variant));
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
