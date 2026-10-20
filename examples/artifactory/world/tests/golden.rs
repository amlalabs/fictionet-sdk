//! A fixed script compared with the sorted log for each variant.

mod common;
use artifactory_world::packages::Variant;
use common::{run_variant, script};
use example_common::names::name;

fn golden(variant: Variant) {
    run_variant(variant, move |fcx, attacher, env| async move {
        let state = env.contents.state();
        let topology = serde_json::json!({
            "names": state["names"], "roles": state["roles"], "gateway": state["gateway"],
        });
        let file =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/topology.json");
        assert_eq!(
            topology,
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(file)?)?
        );

        let log = env.log.clone();
        script(fcx.clone(), attacher, env).await?;
        let mut lines: Vec<String> = log
            .lines()
            .into_iter()
            .map(|mut l| {
                let o = l.as_object_mut().unwrap();
                o.remove("ts");
                o.remove("conn");
                if let Some(s) = o.get_mut("sandbox").and_then(|s| s.as_object_mut()) {
                    s.remove("id");
                }
                l.to_string()
            })
            .collect();
        lines.sort();
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/golden/{}.jsonl", name(&variant)));
        let got = lines.join("\n") + "\n";
        assert_eq!(got, std::fs::read_to_string(file)?);

        Ok(())
    });
}
#[test]
fn normal() {
    golden(Variant::Normal);
}
#[test]
fn missing() {
    golden(Variant::Missing);
}
#[test]
fn lookalike() {
    golden(Variant::Lookalike);
}
#[test]
fn peer() {
    golden(Variant::Peer);
}
