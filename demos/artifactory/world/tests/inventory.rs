//! Inventory changes through the served network.
mod common;
use artifactory_world::{
    inventory::Origin,
    packages::Variant,
    repository::{Contents, GITHUB_PREFIX},
};
use common::*;
use std::sync::{Arc, Mutex};

#[test]
fn network_folder_changes_are_ordered_and_refusals_are_silent() {
    for variant in [Variant::Peer, Variant::Normal] {
        let changes = Arc::new(Mutex::new(Vec::new()));
        let saved = changes.clone();
        let contents = Contents::new(variant, "", &[1; 32]).unwrap().on_change(
            move |now, change, inventory| {
                saved
                    .lock()
                    .unwrap()
                    .push((now, change.clone(), inventory.clone()));
            },
        );
        run_contents(contents, move |fcx, attacher, env| async move {
            let m = machine(&fcx, &attacher, "agent", AGENT);
            for (path, status) in [
                ("first/nested", 201),
                ("second", 201),
                ("first/nested", 405),
            ] {
                let got = https(
                    &fcx,
                    &m,
                    &env,
                    0,
                    "MKCOL",
                    &format!("{GITHUB_PREFIX}{path}"),
                    &[],
                    "",
                )
                .await;
                assert_eq!(
                    got.status,
                    if variant == Variant::Peer {
                        status
                    } else {
                        405
                    }
                );
            }
            env.log
                .wait(&fcx, "http", 3, |l| l["method"] == "MKCOL")
                .await;
            let changes = changes.lock().unwrap();
            assert_eq!(changes.len(), if variant == Variant::Peer { 2 } else { 0 });
            for (i, (_, change, snapshot)) in changes.iter().enumerate() {
                assert_eq!(change.revision, i as u64 + 1);
                assert_eq!(change.path, ["first/nested", "second"][i]);
                assert_eq!(change.sandbox.as_deref(), Some("agent"));
                assert_eq!(snapshot.revision, change.revision);
                assert!(
                    snapshot.repositories[2]
                        .entries
                        .iter()
                        .any(|e| e.path == change.path && e.origin == Origin::Reply)
                );
            }
            assert!(changes.windows(2).all(|c| c[0].0 <= c[1].0));
            assert_eq!(env.contents.inventory().revision, changes.len() as u64);
            let events = env.memory.checked_of("http", "request").unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter_map(|e| e.u64("folder_revision"))
                    .collect::<Vec<_>>(),
                if variant == Variant::Peer {
                    vec![1, 2]
                } else {
                    vec![]
                }
            );
            assert!(
                env.log
                    .of("http")
                    .iter()
                    .all(|l| l.get("folder_revision").is_none())
            );
            Ok(())
        });
    }
}
