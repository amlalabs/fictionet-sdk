//! A fixed script compared with the sorted log for each variant.
//! ARTIFACTORY_GOLDEN_WRITE=1 records the files again.

mod common;
use artifactory_world::packages::Variant;
use common::{run_variant, script};

fn golden(variant: Variant) {
    run_variant(variant, move |fcx, attacher, env| async move {
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
            .join(format!("tests/golden/{}.jsonl", variant.as_str()));
        let got = lines.join("\n") + "\n";
        if std::env::var("ARTIFACTORY_GOLDEN_WRITE").as_deref() == Ok("1") {
            std::fs::write(file, got)?;
        } else {
            assert_eq!(got, std::fs::read_to_string(file)?);
        }
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
