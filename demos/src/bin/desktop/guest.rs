//! The workstation resources and pinned coding agents.

use fictionet_demo::kit::{Guest, desktop};

/// Claude Code's native build, on Anthropic's stable channel. The guest
/// fetches the zstd file as Anthropic's installer does, and checks it and
/// the binary it unpacks to against two pinned sha256s, copied from the
/// release's `manifest.zst.json` and `manifest.json`.
pub const CLAUDE_VERSION: &str = "2.1.292";
const CLAUDE_ZST_SHA256: &str = "28509427a53a5c15bd94d022d39013cc4b867a8e6305497f48162dcf91576326";
const CLAUDE_SHA256: &str = "a967e7b1d8b4e47ee421d5433027880347952b0c0857abf880e2c942a4ec93b3";
/// Codex's standalone package for x86-64 Linux (musl), the one OpenAI's
/// installer unpacks: the CLI with its ripgrep and bubblewrap. Its sha256 is
/// the digest the release lists on GitHub and on releases.openai.com.
pub const CODEX_VERSION: &str = "0.163.0";
const CODEX_SHA256: &str = "df22dac1f24b7927e817e8b113067fbe1caa586aba7554247fabd49464cf9c96";

pub fn workstation(hostname: &str, user: &str, site: &str) -> Guest {
    desktop::browser(hostname, user, &format!("https://{site}/"))
        .resources(4, 4096)
        .file(
            "/etc/claude-code/managed-settings.json",
            0o644,
            "{\"env\":{\"DISABLE_UPDATES\":\"1\",\"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC\":\"1\"}}\n",
        )
        .file("/opt/install-agents.sh", 0o755, install_agents())
        .run("bash /opt/install-agents.sh")
}

fn install_agents() -> String {
    format!(
        "#!/bin/bash\n\
         set -euo pipefail\n\
         # The coding agents, from their vendors' release servers, each checked\n\
         # against its pinned sha256; sha256sum -c stops the script on a mismatch.\n\
         # Both go in /usr/local/bin, on PATH in every shell and session.\n\
         started=$SECONDS\n\
         work=$(mktemp -d)\n\
         curl -fsSLo \"$work/claude.zst\" \
           https://downloads.claude.ai/claude-code-releases/{CLAUDE_VERSION}/linux-x64/claude.zst\n\
         echo \"{CLAUDE_ZST_SHA256}  $work/claude.zst\" | sha256sum -c -\n\
         zstd -dq \"$work/claude.zst\" -o \"$work/claude\"\n\
         echo \"{CLAUDE_SHA256}  $work/claude\" | sha256sum -c -\n\
         install -m0755 \"$work/claude\" /usr/local/bin/claude\n\
         curl -fsSLo \"$work/codex.tar.zst\" \
           https://releases.openai.com/codex/releases/{CODEX_VERSION}/\
             codex-package-x86_64-unknown-linux-musl.tar.zst\n\
         echo \"{CODEX_SHA256}  $work/codex.tar.zst\" | sha256sum -c -\n\
         install -d /opt/codex\n\
         tar --zstd -xf \"$work/codex.tar.zst\" --no-same-owner -C /opt/codex\n\
         ln -sf /opt/codex/bin/codex /usr/local/bin/codex\n\
         echo \"coding agents: $(cat \"$work/claude.zst\" \"$work/codex.tar.zst\" | wc -c) \
           bytes in $((SECONDS - started)) s\"\n\
         rm -rf \"$work\"\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    #[test]
    fn desktop_setup_precedes_agent_installation() {
        let guest = workstation("workstation", "analyst", "example.test");
        guest.validate().unwrap();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        assert!(
            data.find("bash /opt/setup-desktop.sh").unwrap()
                < data.find("bash /opt/install-agents.sh").unwrap()
        );
        assert!(data.contains("/etc/claude-code/managed-settings.json"));
        assert!(data.contains(&fictionet::stdlib::codec::base64::encode(
            install_agents().as_bytes()
        )));
    }
}
