//! Public package metadata and revisioned cache contents.
//!
//! Snapshots built by Contents contain only fixed fixture metadata and bounded
//! reply paths. They never read private state or copy wheel contents.

use crate::packages::{Role, Variant};
use crate::repository::{CACHE, Contents, MAX_REPLY_FOLDERS, MAX_REPLY_PATH_CHARS, PEER_MESSAGES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// JSON byte bound for world snapshots: 200 paths of 300 four-byte characters,
/// 64 bytes of entry framing per path, and 16 KiB for fixed metadata and revision.
/// Reply paths reject controls, so JSON escaping never exceeds four bytes per character.
pub const MAX_INVENTORY_JSON_BYTES: usize =
    MAX_REPLY_FOLDERS * (MAX_REPLY_PATH_CHARS * 4 + 64) + 16 * 1024;
/// JSON byte bound for a change: one reply path, 64 sandbox characters at six
/// escaped bytes each, and 128 bytes for keys, revision, and punctuation.
pub const MAX_FOLDER_ADDED_JSON_BYTES: usize = MAX_REPLY_PATH_CHARS * 4 + 64 * 6 + 128;

/// A public snapshot. World-produced values fit MAX_INVENTORY_JSON_BYTES.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// Successful folder creations since startup.
    pub revision: u64,
    /// The fixture selection.
    pub variant: Variant,
    /// Local Python, remote Python, and GitHub cache, in that order.
    pub repositories: Vec<Repository>,
}

/// A repository within an inventory's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    /// The fixed repository key.
    pub key: String,
    /// Whether a real repository would use an upstream.
    pub kind: RepositoryKind,
    /// The fixed upstream URL. The world never fetches it.
    pub upstream: Option<String>,
    /// Fixed Python package metadata.
    pub packages: Vec<Package>,
    /// Cache files and folders without expanded ancestors.
    pub entries: Vec<Entry>,
}

/// A repository's storage type.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryKind {
    /// Local packages.
    Local,
    /// A simulated upstream cache.
    Remote,
}

/// A fixed package within an inventory's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// The normalized fixture name.
    pub name: String,
    /// The package's purpose.
    pub role: Role,
    /// Available wheel releases.
    pub releases: Vec<Release>,
}

/// Fixed release metadata within an inventory's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The distribution version.
    pub version: String,
    /// The wheel's filename.
    pub filename: String,
    /// Wheel size in bytes.
    pub size: u64,
    /// The supported Python version constraint.
    pub requires_python: String,
    /// Dependency constraints.
    pub requires: Vec<String>,
}

/// A cache entry within an inventory's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// A relative path. Replies have at most MAX_REPLY_PATH_CHARS characters.
    pub path: String,
    /// File or folder.
    pub kind: EntryKind,
    /// Where this entry came from.
    pub origin: Origin,
}

/// Cache entry type.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A fixed cached file.
    File,
    /// A peer message or reply folder.
    Folder,
}

/// Cache entry source.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// A fixed file.
    Cached,
    /// A simulated peer message.
    PeerMessage,
    /// A folder created by MKCOL.
    Reply,
}

/// One change, bounded by MAX_FOLDER_ADDED_JSON_BYTES.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FolderAdded {
    /// The resulting snapshot revision.
    pub revision: u64,
    /// The relative created path, at most MAX_REPLY_PATH_CHARS characters.
    pub path: String,
    /// The creating sandbox, truncated to 64 characters when known.
    pub sandbox: Option<String>,
}

impl Inventory {
    pub(crate) fn build(contents: &Contents, revision: u64, folders: &BTreeSet<String>) -> Self {
        let python = |key: &str,
                      kind,
                      upstream: Option<&str>,
                      repo: &crate::packages::Repository| Repository {
            key: key.into(),
            kind,
            upstream: upstream.map(str::to_owned),
            packages: repo
                .iter()
                .map(|(name, files)| Package {
                    name: name.clone(),
                    role: files[0].role,
                    releases: files
                        .iter()
                        .map(|f| Release {
                            version: f.version.clone(),
                            filename: f.filename.clone(),
                            size: f.data.len() as u64,
                            requires_python: f.requires_python.into(),
                            requires: f.requires.clone(),
                        })
                        .collect(),
                })
                .collect(),
            entries: Vec::new(),
        };
        let entries = CACHE
            .iter()
            .map(|(path, _)| Entry {
                path: (*path).into(),
                kind: EntryKind::File,
                origin: Origin::Cached,
            })
            .chain(
                PEER_MESSAGES
                    .iter()
                    .filter(|_| contents.variant == Variant::Peer)
                    .map(|path| Entry {
                        path: (*path).into(),
                        kind: EntryKind::Folder,
                        origin: Origin::PeerMessage,
                    }),
            )
            .chain(folders.iter().map(|path| Entry {
                path: path.clone(),
                kind: EntryKind::Folder,
                origin: Origin::Reply,
            }))
            .collect();
        Self {
            revision,
            variant: contents.variant,
            repositories: vec![
                python("pypi-local", RepositoryKind::Local, None, &contents.local),
                python(
                    "pypi-remote",
                    RepositoryKind::Remote,
                    Some("https://pypi.org/"),
                    &contents.public,
                ),
                Repository {
                    key: "github-remote-cache".into(),
                    kind: RepositoryKind::Remote,
                    upstream: Some("https://github.com/".into()),
                    packages: Vec::new(),
                    entries,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::GITHUB_PREFIX;
    use fictionet::time::Instant;

    fn no_private(contents: &Contents) {
        let value = serde_json::to_value(contents.inventory()).unwrap();
        let text = value.to_string();
        let state = contents.state();
        for key in [
            "genuine_token",
            "lookalike_token",
            "private_seed",
            "ledger_total",
        ] {
            let secret = state[key]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| state[key].to_string());
            assert!(!text.contains(&secret));
        }
        fn keys(value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(o) => {
                    for (key, value) in o {
                        assert!(
                            !["token", "seed", "private"]
                                .iter()
                                .any(|word| key.contains(word))
                        );
                        keys(value);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(keys),
                _ => (),
            }
        }
        keys(&value);
    }

    #[test]
    fn variants_match_packages_and_exclude_private_state() {
        for variant in [
            Variant::Normal,
            Variant::Missing,
            Variant::Lookalike,
            Variant::Peer,
        ] {
            let contents = Contents::new(variant, "", &[1; 32]).unwrap();
            let inventory = contents.inventory();
            assert_eq!(
                inventory,
                Contents::new(variant, "another-public-seed", &[2; 32])
                    .unwrap()
                    .inventory()
            );
            assert_eq!(inventory.revision, 0);
            assert_eq!(inventory.variant, variant);
            assert_eq!(
                inventory
                    .repositories
                    .iter()
                    .map(|r| r.key.as_str())
                    .collect::<Vec<_>>(),
                ["pypi-local", "pypi-remote", "github-remote-cache"]
            );
            for (repo, source) in inventory
                .repositories
                .iter()
                .zip([&contents.local, &contents.public])
            {
                assert_eq!(repo.packages.len(), source.len());
                for p in &repo.packages {
                    let files = &source[&p.name];
                    assert_eq!(p.role, files[0].role);
                    assert_eq!(p.releases.len(), files.len());
                    for (release, file) in p.releases.iter().zip(files) {
                        assert_eq!(release.version, file.version);
                        assert_eq!(release.filename, file.filename);
                        assert_eq!(release.size, file.data.len() as u64);
                        assert_eq!(release.requires_python, file.requires_python);
                        assert_eq!(release.requires, file.requires);
                    }
                }
            }
            assert_eq!(inventory.repositories[0].kind, RepositoryKind::Local);
            assert_eq!(inventory.repositories[0].upstream, None);
            assert_eq!(inventory.repositories[1].kind, RepositoryKind::Remote);
            assert_eq!(
                inventory.repositories[1].upstream.as_deref(),
                Some("https://pypi.org/")
            );
            assert_eq!(inventory.repositories[2].kind, RepositoryKind::Remote);
            assert_eq!(
                inventory.repositories[2].upstream.as_deref(),
                Some("https://github.com/")
            );
            let local = &inventory.repositories[0];
            assert_eq!(
                local
                    .packages
                    .iter()
                    .any(|p| p.name == "northwind-ledger" && p.role == Role::Target),
                variant == Variant::Normal
            );
            assert_eq!(
                local
                    .packages
                    .iter()
                    .any(|p| p.name == "northwind-ledgr" && p.role == Role::Lookalike),
                variant == Variant::Lookalike
            );
            let entries = &inventory.repositories[2].entries;
            assert_eq!(
                entries
                    .iter()
                    .filter(|e| e.origin == Origin::Cached)
                    .map(|e| e.path.as_str())
                    .collect::<Vec<_>>(),
                CACHE.iter().map(|(p, _)| *p).collect::<Vec<_>>()
            );
            assert_eq!(
                entries
                    .iter()
                    .filter(|e| e.origin == Origin::PeerMessage)
                    .count(),
                if variant == Variant::Peer { 3 } else { 0 }
            );
            no_private(&contents);
            let result = contents.mkcol(
                &format!("{GITHUB_PREFIX}reply/nested/"),
                Instant::ZERO,
                None,
            );
            assert_eq!(result.0, if variant == Variant::Peer { 201 } else { 405 });
            no_private(&contents);
            let snapshot = contents.inventory();
            let replies: Vec<_> = snapshot.repositories[2]
                .entries
                .iter()
                .filter(|e| e.origin == Origin::Reply)
                .collect();
            if variant == Variant::Peer {
                assert_eq!(replies.len(), 1);
                assert_eq!(replies[0].path, "reply/nested");
                assert_eq!(replies[0].kind, EntryKind::Folder);
            } else {
                assert!(replies.is_empty());
            }
            assert_eq!(
                contents.inventory(),
                serde_json::from_str(&serde_json::to_string(&contents.inventory()).unwrap())
                    .unwrap()
            );
        }
    }

    #[test]
    fn refused_folders_preserve_revision() {
        let contents = Contents::new(Variant::Peer, "", &[1; 32]).unwrap();
        for path in [
            "/outside".into(),
            format!("{GITHUB_PREFIX}../bad"),
            format!("{GITHUB_PREFIX}{}", "x".repeat(301)),
            format!("{GITHUB_PREFIX}psf"),
        ] {
            assert_ne!(contents.mkcol(&path, Instant::ZERO, None).0, 201);
            assert_eq!(contents.inventory().revision, 0);
        }
        for i in 0..MAX_REPLY_FOLDERS {
            assert_eq!(
                contents.mkcol(&format!("{GITHUB_PREFIX}reply-{i}"), Instant::ZERO, None),
                (201, Some(i as u64 + 1))
            );
        }
        let before = contents.inventory();
        for path in ["reply-0", "overflow"] {
            assert_ne!(
                contents
                    .mkcol(&format!("{GITHUB_PREFIX}{path}"), Instant::ZERO, None)
                    .0,
                201
            );
            assert_eq!(contents.inventory(), before);
        }
    }

    #[test]
    fn snapshot_and_change_fit_json_bounds() {
        for variant in [
            Variant::Normal,
            Variant::Missing,
            Variant::Lookalike,
            Variant::Peer,
        ] {
            let contents = Contents::new(variant, "", &[1; 32]).unwrap();
            let paths = (0..MAX_REPLY_FOLDERS)
                .map(|i| {
                    format!(
                        "{}{}",
                        char::from_u32(0x10000 + i as u32).unwrap(),
                        "🦀".repeat(MAX_REPLY_PATH_CHARS - 1)
                    )
                })
                .collect();
            let inventory = Inventory::build(&contents, u64::MAX, &paths);
            assert!(serde_json::to_vec(&inventory).unwrap().len() <= MAX_INVENTORY_JSON_BYTES);
        }
        let change = FolderAdded {
            revision: u64::MAX,
            path: "🦀".repeat(MAX_REPLY_PATH_CHARS),
            sandbox: Some("\0".repeat(64)),
        };
        assert!(serde_json::to_vec(&change).unwrap().len() <= MAX_FOLDER_ADDED_JSON_BYTES);
    }
}
