//! Browser libraries downloaded once and embedded by the page crate.

use crate::process::{Result, cmd, run};
use crate::vm::{download, private_dir};

/// The pinned libraries: name, display name, version, tarball URL, its
/// sha256, and the members unpacked from its `package/` directory. The page's
/// tests read the same file.
const LIBRARIES: &str = include_str!("../../../observe/libraries.json");

pub(super) fn assets() -> Result {
    let downloads = crate::root().join("observe/downloads");
    private_dir(&downloads)?;
    let vendor = downloads.join("vendor");
    std::fs::create_dir_all(&vendor)?;
    let libraries: serde_json::Value = serde_json::from_str(LIBRARIES)?;
    for library in libraries.as_array().ok_or("libraries.json is not a list")? {
        let field = |key: &str| {
            library[key]
                .as_str()
                .ok_or_else(|| format!("libraries.json: a library has no {key}"))
        };
        let (name, version) = (field("name")?, field("version")?);
        let members: Vec<&str> = library["members"]
            .as_array()
            .ok_or("libraries.json: a library has no members")?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let tarball = downloads.join(format!("{name}-{version}.tgz"));
        download(field("url")?, &tarball, "sha256sum", field("sha256")?)?;
        let tree = vendor.join(name);
        let version = format!("{} {version}", field("display")?);
        if std::fs::read_to_string(tree.join("version.txt"))
            .ok()
            .as_deref()
            == Some(version.as_str())
            && members.iter().all(|member| tree.join(member).exists())
        {
            continue;
        }
        let fresh = downloads.join(format!("{name}-unpack"));
        if fresh.exists() {
            std::fs::remove_dir_all(&fresh)?;
        }
        std::fs::create_dir(&fresh)?;
        run(cmd("tar", &["xzf"])
            .arg(&tarball)
            .args(["--strip-components=1", "-C"])
            .arg(&fresh)
            .args(members.iter().map(|member| format!("package/{member}"))))?;
        std::fs::write(fresh.join("version.txt"), version)?;
        if tree.exists() {
            std::fs::remove_dir_all(&tree)?;
        }
        std::fs::rename(fresh, tree)?;
    }
    println!("browser libraries downloaded into {}", vendor.display());
    Ok(())
}
