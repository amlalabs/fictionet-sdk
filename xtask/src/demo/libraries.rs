//! Browser libraries downloaded once and embedded by the page crate.

use crate::process::{Result, cmd, run};
use crate::vm::{download, private_dir};

struct Library {
    name: &'static str,
    version: &'static str,
    display: &'static str,
    url: &'static str,
    sha256: &'static str,
    members: &'static [&'static str],
}

const LIBRARIES: &[Library] = &[
    Library {
        name: "novnc",
        display: "noVNC",
        version: "1.7.0",
        url: "https://registry.npmjs.org/@novnc/novnc/-/novnc-1.7.0.tgz",
        sha256: "32689f18d6abe96bc6530828a6bd0b9ae33bda07c083a6575ed255b5a8f2e903",
        members: &[
            "core",
            "vendor",
            "LICENSE.txt",
            "docs/LICENSE.MPL-2.0",
            "docs/LICENSE.BSD-2-Clause",
            "docs/LICENSE.BSD-3-Clause",
        ],
    },
    Library {
        name: "xterm",
        display: "xterm.js",
        version: "6.0.0",
        url: "https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz",
        sha256: "908e66e04af6c8dc6b00dd3b54de088e2e81e5ed866284fd6c2fb3c2d1c7a3f6",
        members: &["lib/xterm.mjs", "css/xterm.css", "LICENSE"],
    },
    Library {
        name: "addon-fit",
        display: "xterm.js fit addon",
        version: "0.11.0",
        url: "https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.11.0.tgz",
        sha256: "26003b4517a132b64e4ff228fd88a5fda3fff5e606c76093f6dcff772e9ecec0",
        members: &["lib/addon-fit.mjs", "LICENSE"],
    },
    Library {
        name: "three",
        display: "three.js",
        version: "0.186.1",
        url: "https://registry.npmjs.org/three/-/three-0.186.1.tgz",
        sha256: "8cd068708ea44f2c73c944b1cead2ba2f0d5c15c8fc194e5700f4e4f4a033fe7",
        members: &["build/three.module.js", "build/three.core.js", "LICENSE"],
    },
];

pub(super) fn assets() -> Result {
    let downloads = crate::root().join("observe/downloads");
    private_dir(&downloads)?;
    let vendor = downloads.join("vendor");
    std::fs::create_dir_all(&vendor)?;
    for library in LIBRARIES {
        let tarball = downloads.join(format!("{}-{}.tgz", library.name, library.version));
        download(library.url, &tarball, "sha256sum", library.sha256)?;
        let tree = vendor.join(library.name);
        let version = format!("{} {}", library.display, library.version);
        if std::fs::read_to_string(tree.join("version.txt"))
            .ok()
            .as_deref()
            == Some(version.as_str())
            && library
                .members
                .iter()
                .all(|member| tree.join(member).exists())
        {
            continue;
        }
        let fresh = downloads.join(format!("{}-unpack", library.name));
        if fresh.exists() {
            std::fs::remove_dir_all(&fresh)?;
        }
        std::fs::create_dir(&fresh)?;
        run(cmd("tar", &["xzf"])
            .arg(&tarball)
            .args(["--strip-components=1", "-C"])
            .arg(&fresh)
            .args(
                library
                    .members
                    .iter()
                    .map(|member| format!("package/{member}")),
            ))?;
        std::fs::write(fresh.join("version.txt"), version)?;
        if tree.exists() {
            std::fs::remove_dir_all(&tree)?;
        }
        std::fs::rename(fresh, tree)?;
    }
    println!("browser libraries downloaded into {}", vendor.display());
    Ok(())
}
