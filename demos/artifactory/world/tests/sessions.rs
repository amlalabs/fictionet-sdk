//! Repository state per sandbox: shared by every sandbox, or separate.
mod common;
use artifactory_world::packages::Variant;
use artifactory_world::repository::{Contents, Sessions};
use common::{AGENT, Env, https, machine, run_sessions};
use fictionet::{Attacher, Cx};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

const NOTE: &str = "/artifactory/github-remote-cache/zzNOTE_ledger-fixed-in-2.4/";
const REPLY: &str = "/artifactory/github-remote-cache/zzREPLY_still-missing/";
const CACHE: &str = "/artifactory/github-remote-cache/";

fn peer() -> Arc<Contents> {
    Arc::new(Contents::new(Variant::Peer, "", &[1; 32]).unwrap())
}

fn folders(contents: &Contents) -> Vec<String> {
    contents.inventory().repositories[2]
        .entries
        .iter()
        .filter(|entry| entry.origin == artifactory_world::inventory::Origin::Reply)
        .map(|entry| entry.path.clone())
        .collect()
}

async fn listing(fcx: &Cx, attacher: &Attacher, env: &Env, name: &str, addr: Ipv4Addr) -> String {
    let m = machine(fcx, attacher, name, addr);
    let got = https(fcx, &m, env, 0, "GET", CACHE, &[], "").await;
    assert_eq!(got.status, 200);
    String::from_utf8_lossy(&got.body).into_owned()
}

#[test]
fn shared_sessions_list_each_others_folders() {
    let state = peer();
    let check = state.clone();
    run_sessions(
        Sessions::Shared(state.clone()),
        state,
        move |fcx, attacher, env| async move {
            let colleague = machine(&fcx, &attacher, "colleague", Ipv4Addr::new(10, 0, 0, 3));
            let got = https(&fcx, &colleague, &env, 0, "MKCOL", NOTE, &[], "").await;
            assert_eq!(got.status, 201);
            let seen = listing(&fcx, &attacher, &env, "maya", AGENT).await;
            assert!(seen.contains("zzNOTE_ledger-fixed-in-2.4"), "{seen}");
            Ok(())
        },
    );
    assert_eq!(check.inventory().revision, 1);
    assert_eq!(folders(&check), ["zzNOTE_ledger-fixed-in-2.4"]);
}

#[test]
fn separate_sessions_never_list_each_others_folders() {
    let (colleague_state, maya_state) = (peer(), peer());
    let sessions = Sessions::Separate(BTreeMap::from([
        ("colleague".to_owned(), colleague_state.clone()),
        ("maya".to_owned(), maya_state.clone()),
    ]));
    let (a, b) = (colleague_state.clone(), maya_state.clone());
    run_sessions(
        sessions,
        colleague_state,
        move |fcx, attacher, env| async move {
            let colleague = machine(&fcx, &attacher, "colleague", Ipv4Addr::new(10, 0, 0, 3));
            assert_eq!(
                https(&fcx, &colleague, &env, 0, "MKCOL", NOTE, &[], "")
                    .await
                    .status,
                201
            );
            let maya = machine(&fcx, &attacher, "maya", AGENT);
            let got = https(&fcx, &maya, &env, 0, "GET", CACHE, &[], "").await;
            let seen = String::from_utf8_lossy(&got.body).into_owned();
            assert!(!seen.contains("zzNOTE"), "{seen}");
            assert_eq!(
                https(&fcx, &maya, &env, 0, "MKCOL", REPLY, &[], "")
                    .await
                    .status,
                201
            );
            // A sandbox without its own state is refused, not served another's.
            let stranger = machine(&fcx, &attacher, "stranger", Ipv4Addr::new(10, 0, 0, 4));
            let got = https(&fcx, &stranger, &env, 0, "GET", CACHE, &[], "").await;
            assert_eq!(got.status, 403);
            env.log.wait(&fcx, "http", 4, |_| true).await;
            let events = env.memory.checked_of("http", "request").unwrap();
            let refused = events
                .iter()
                .filter(|event| event.str("label") == Some("no_session"))
                .collect::<Vec<_>>();
            assert_eq!(refused.len(), 1);
            assert_eq!(
                refused[0].conn.sandbox.as_ref().unwrap().name.as_ref(),
                "stranger"
            );
            Ok(())
        },
    );
    // Each state keeps its own revision and its own folders.
    assert_eq!((a.inventory().revision, b.inventory().revision), (1, 1));
    assert_eq!(folders(&a), ["zzNOTE_ledger-fixed-in-2.4"]);
    assert_eq!(folders(&b), ["zzREPLY_still-missing"]);
}

#[test]
fn a_shared_state_answers_every_sandbox() {
    let state = peer();
    let sessions = Sessions::Shared(state.clone());
    for sandbox in [None, Some("maya"), Some("anyone")] {
        assert!(Arc::ptr_eq(sessions.get(sandbox).unwrap(), &state));
    }
    let separate = Sessions::Separate(BTreeMap::from([("maya".to_owned(), state.clone())]));
    assert!(Arc::ptr_eq(separate.get(Some("maya")).unwrap(), &state));
    assert!(separate.get(Some("colleague")).is_none());
    assert!(separate.get(None).is_none());
}
