//! Exhaustive QPACK synchronization and storage models, including controls.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::lean_vectors::{Report, logged, scoped};
use crate::resources;

const SYNC: &[&str] = &[
    "QpackSync_base.cfg",
    "QpackSync_without_acknowledged.cfg",
    "QpackSync_without_references.cfg",
    "QpackSync_without_received.cfg",
    "QpackSync_without_incrementbound.cfg",
    "QpackSync_without_ackorder.cfg",
    "QpackSync_without_cancelcount.cfg",
];
const STORAGE: &[&str] = &[
    "QpackStorage_base.cfg",
    "QpackStorage_without_reservation.cfg",
    "QpackStorage_without_copycharge.cfg",
    "QpackStorage_without_bytebound.cfg",
    "QpackStorage_without_sectionbound.cfg",
    "QpackStorage_without_streambound.cfg",
    "QpackStorage_without_outputbound.cfg",
    "QpackStorage_without_slotcharge.cfg",
];
const TABLE: &[&str] = &[
    "QpackTable_base.cfg",
    "QpackTable_without_growthcharge.cfg",
    "QpackTable_without_payloadcharge.cfg",
    "QpackTable_without_retainedcharge.cfg",
    "QpackTable_without_evictfirst.cfg",
];
const FEEDBACK: &[&str] = &[
    "QpackFeedback_base.cfg",
    "QpackFeedback_without_preserveack.cfg",
    "QpackFeedback_without_order.cfg",
    "QpackFeedback_without_queuebound.cfg",
];

pub fn run(args: &[String]) -> Result {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if !matches!(
        args.as_slice(),
        ["resources"] | ["models"] | ["replay"] | ["all"]
    ) {
        return Err("expected qpack-verify resources, models, replay, or all".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask lives in the repository")?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .unwrap_or_else(|| root.join("target"));
    let out = crate::verification_run(&target.join("qpack-verify"))?;
    let dir = root.join("verification/qpack/tla");
    let mut report = Report::new("qpack");
    if args != ["replay"] {
        report.absorb(resources::tlc(root, &out, &dir, "QpackSync", SYNC)?);
        report.absorb(resources::tlc(root, &out, &dir, "QpackStorage", STORAGE)?);
        report.absorb(resources::tlc(root, &out, &dir, "QpackTable", TABLE)?);
        report.absorb(resources::tlc(root, &out, &dir, "QpackFeedback", FEEDBACK)?);
    }
    if matches!(args.as_slice(), ["replay"] | ["all"]) {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let (text, passed) = logged(
            scoped(cargo, "8G")
                .args([
                    "test",
                    "-p",
                    "fictionet",
                    "--test",
                    "qpack_dynamic",
                    "--",
                    "--nocapture",
                ])
                .env("CARGO_BUILD_JOBS", "4")
                .current_dir(root),
            &out.join("replay.out"),
        )?;
        let costed = resources::costs(&mut report, "qpack replay", &text);
        if !passed {
            report.fail("qpack replay failed; see replay.out".into());
        } else if costed == 0 {
            report.fail("qpack replay did not report allocation costs; see replay.out".into());
        } else {
            report.pass("qpack replay passed; compression measurements are in replay.out".into());
        }
    }
    report.print();
    report.result("qpack-verify")
}
