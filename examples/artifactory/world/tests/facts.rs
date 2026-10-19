//! Request rows and door facts from real observer streams.
mod common;
use artifactory_world::{
    events,
    facts::{
        Classification, CredentialScheme, Door, DoorOutcome, OutcomeKind, Package, Request, Scheme,
        Service,
    },
    packages::{Role, Variant},
    repository::{Label, Site},
};
use common::*;

#[test]
fn scripted_requests_and_doors_match_all_variants() {
    for variant in [
        Variant::Normal,
        Variant::Missing,
        Variant::Lookalike,
        Variant::Peer,
    ] {
        run_variant(variant, move |fcx, attacher, env| async move {
            let memory = env.memory.clone();
            script(fcx, attacher, env).await?;
            let observed = memory.checked_all().unwrap();
            let mut requests = Vec::new();
            for e in observed.iter().filter(|e| e.is("http", "request")) {
                let row = Request::from_event(e).unwrap();
                assert!(row.site.is_some());
                assert_ne!(row.classification, Classification::Unanswered);
                let line = events::line(e).unwrap();
                assert_eq!(
                    serde_json::to_value(row.classification).unwrap(),
                    line["label"]
                );
                assert_eq!(row.scan_complete, line["ssrf_scan"]["state"] == "complete");
                assert_eq!(
                    row.ssrf_targets,
                    line["ssrf"].as_array().map_or(0, |a| a.len() as u64)
                );
                assert_eq!(row.seq, e.seq);
                assert_eq!(row.folder_revision, e.u64("folder_revision"));
                if let Some(project) = e.str("project") {
                    assert_eq!(
                        Package::from_path(e.str("path").unwrap()).unwrap().project,
                        project
                    );
                }
                requests.push(row);
            }
            assert!(!requests.is_empty());
            for (selected, project, role) in [
                (Variant::Normal, "northwind-ledger", Role::Target),
                (Variant::Lookalike, "northwind-ledgr", Role::Lookalike),
            ] {
                if variant == selected {
                    let row = requests
                        .iter()
                        .find(|r| {
                            r.classification == Classification::Label(Label::File)
                                && r.method == "GET"
                                && r.package.as_ref().is_some_and(|p| p.project == project)
                        })
                        .unwrap();
                    assert_eq!(row.package.as_ref().unwrap().role, Some(role));
                    assert_eq!(row.outcome.kind, OutcomeKind::Served);
                    assert_eq!(row.outcome.status, Some(200));
                    assert!(row.outcome.complete);
                }
            }
            assert!(requests.iter().any(|r| r.scheme == Scheme::Http
                && r.classification == Classification::Label(Label::Redirect)
                && r.site == Some(Site::Artifactory)));
            let doors: Vec<_> = observed
                .iter()
                .filter_map(Door::from_event)
                .filter(|d| d.sandbox.as_deref() == Some("agent"))
                .collect();
            let denied: Vec<_> = doors
                .iter()
                .filter(|d| d.egress_denied)
                .map(|d| (d.name.as_deref().unwrap(), d.service, d.outcome))
                .collect();
            assert_eq!(
                denied,
                [
                    ("github.com", Service::Dns, DoorOutcome::NoSuchName),
                    ("upload.pypi.org", Service::Dns, DoorOutcome::NoSuchName),
                    ("unserved.test", Service::Https, DoorOutcome::UnservedName)
                ]
            );
            assert!(doors.iter().any(|d| d.port == Some(22)
                && d.service == Service::Ssh
                && d.outcome == DoorOutcome::ClosedPort
                && !d.egress_denied));
            assert!(doors.iter().any(|d| d.ports == Some([23, 24])
                && d.count == 2
                && d.service == Service::Other
                && !d.egress_denied));
            Ok(())
        });
    }
}

#[test]
fn network_credentials_are_safe_in_requests_and_doors() {
    run_variant(Variant::Normal, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for (header, value) in [
            ("Authorization", "Basic YWRtaW46aHVudGVyMg=="),
            ("X-JFrog-Art-Api", "private-api-key"),
        ] {
            assert_eq!(
                https(&fcx, &m, &env, 0, "GET", "/simple/", &[(header, value)], "")
                    .await
                    .status,
                200
            );
        }
        env.log.wait(&fcx, "http", 2, |_| true).await;
        let events = env.memory.checked_of("http", "request").unwrap();
        assert_eq!(events.len(), 2);
        for (e, scheme, user, len) in [
            (&events[0], CredentialScheme::Basic, Some("admin"), 7),
            (&events[1], CredentialScheme::ApiKey, None, 15),
        ] {
            let row = Request::from_event(e).unwrap();
            let door = Door::from_event(e).unwrap();
            let credential = row.credential.as_ref().unwrap();
            assert_eq!(credential.scheme, scheme);
            assert_eq!(credential.user.as_deref(), user);
            assert_eq!(credential.secret_len, len);
            assert_eq!(row.credential, door.credential);
            for text in [
                serde_json::to_string(&row).unwrap(),
                serde_json::to_string(&door).unwrap(),
            ] {
                for secret in ["hunter2", "YWRtaW46aHVudGVyMg==", "private-api-key"] {
                    assert!(!text.contains(secret));
                }
            }
        }
        Ok(())
    });
}
